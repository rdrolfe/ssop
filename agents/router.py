"""SSOP Alert Router — event-driven dispatch from Wazuh indexer to roles.

The router polls the indexer for NEW alerts since its last run, classifies each
by category, and dispatches to the owning role:

  infra-class    -> infra-manager (sense + heal, or escalate)
  security-class -> analyst (triage + verdict + case)
  pattern-class  -> hunt (investigate + file finding)
  compliance     -> logged (informational)
  cross-cutting  -> supervisory (adjudicate + reconcile)

Runs every 3 minutes via systemd timer. Tracks processed alerts via a cursor
state file so no alert is dispatched twice. Every dispatch lands on the case
spine and flows to the pane of glass.

Hygiene (per review): config-driven (config.py), shared client singletons via
registry (no per-dispatch instantiation), no load_dotenv here, imports at top,
logging, structured errors.
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()  # entry point — MUST run before config import (settings is frozen)

from config import settings
from logging_setup import get_logger
from tools.registry import (
    get_analyst,
    get_cases,
    get_escalation,
    get_hunt,
    get_indexer,
    get_selfheal,
)

logger = get_logger(__name__)


# --- Role dispatch: rule category map ---
# rule_id -> (category, role)
# Categories: infra, security, pattern, compliance, operational
RULE_MAP: dict[str, tuple[str, str | None]] = {
    # AppArmor denials (defense-evasion pattern)
    "52002": ("pattern", "hunt"),
    "52000": ("pattern", "hunt"),
    # Rootcheck (host integrity anomalies)
    "510":   ("security", "analyst"),
    # PAM / auth — session open/close are NOISE: log-only, no dispatch
    "5501":  ("operational", None),   # session open — filtered (log only)
    "5502":  ("operational", None),   # session close — filtered (log only)
    "5710":  ("security", "analyst"),    # sshd auth failure
    "5715":  ("security", "analyst"),    # sshd auth success (unusual)
    "5716":  ("security", "analyst"),    # sshd invalid user
    # SCA / compliance
    "19007": ("compliance", None),
    "19008": ("compliance", None),
    "19009": ("compliance", None),
    # Suricata IDS alerts
    "86601": ("security", "analyst"),    # generic suricata alert
    # Sudo
    "5402":  ("operational", "infra"),
    "5403":  ("operational", "infra"),
    # Low disk space
    "531":   ("infra", "infra"),
    "502":   ("infra", "infra"),
    "501":   ("infra", "infra"),
    # syscheck / FIM
    "550":   ("security", "analyst"),
    "553":   ("security", "analyst"),
    "554":   ("security", "analyst"),
}

NOISE_RULES: frozenset = settings.noise_rules
DEFAULT_CATEGORY = settings.default_category
DEFAULT_ROLE: str | None = None  # unclassified alerts are logged but not dispatched


def _transport_rule_map() -> dict[str, tuple[str, str | None]]:
    """Load the ACTIVE backend's rule map from transport.yaml, if present.

    The Wazuh RULE_MAP above is the default; when transport.yaml selects a
    different backend (securityonion), its backend-specific map overrides by
    rule id. This is the transport-agnostic seam: re-mapping for a new SIEM
    is a data edit, not a code change.
    """
    try:
        from pathlib import Path

        import yaml
        tpath = Path(__file__).resolve().parent / "transport.yaml"
        if not tpath.exists():
            return {}
        data = yaml.safe_load(tpath.read_text())
        backend = data.get("backend", "wazuh")
        key = f"{backend}_rules" if backend != "wazuh" else "rules"
        rules = data.get(key, {})
        out: dict[str, tuple[str, str | None]] = {}
        for rid, val in rules.items():
            if rid == "default":
                continue
            if isinstance(val, dict):
                out[str(rid)] = (val.get("category", DEFAULT_CATEGORY), val.get("role"))
        return out
    except Exception:  # noqa: BLE001 — transport load failure must never break dispatch
        return {}


# --- Cursor ---
class Cursor:
    """Tracks last-processed timestamp to avoid re-dispatching alerts."""

    def __init__(self, path: Path | None = None) -> None:
        self.path: Path = path or settings.router_state_file
        self.data: dict[str, Any] = {"last_ts": None, "seen_ids": set(), "bursts": {}}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                self.data["last_ts"] = raw.get("last_ts")
                self.data["seen_ids"] = set(raw.get("seen_ids", []))
                self.data["bursts"] = raw.get("bursts", {})
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("cursor load failed: %s", e)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.write_text(json.dumps({
                "last_ts": self.data["last_ts"],
                "seen_ids": list(self.data["seen_ids"])[-5000:],  # keep last 5k
                "bursts": self.data["bursts"],
            }, indent=2))
        except OSError as e:
            logger.error("cursor save failed: %s", e)

    def is_known(self, alert_id: str) -> bool:
        return alert_id in self.data["seen_ids"]

    def mark(self, alert_id: str, ts: str) -> None:
        self.data["seen_ids"].add(alert_id)
        if not self.data["last_ts"] or ts > self.data["last_ts"]:
            self.data["last_ts"] = ts

    # --- burst correlation ---
    def burst_count(self, key: str, ts: str, window_min: int | None = None) -> int:
        """Track repeats of a signature key (rule+agent) within a time window.

        Returns the count INCLUDING this occurrence. First call in the window
        returns 1 (dispatch once); repeats return >1 (dedupe).
        """
        window = window_min or settings.burst_window_min
        bursts = self.data["bursts"]
        now = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        entry = bursts.get(key)
        if entry:
            last = datetime.fromisoformat(entry["last_ts"].replace("Z", "+00:00"))
            if (now - last) <= timedelta(minutes=window):
                entry["count"] += 1
                entry["last_ts"] = ts
                return entry["count"]
        bursts[key] = {"count": 1, "last_ts": ts, "first_ts": ts}
        if len(bursts) > 2000:
            for k in list(bursts)[:500]:
                bursts.pop(k, None)
        return 1

    @property
    def last_ts(self) -> str | None:
        return self.data.get("last_ts")


# --- Classification ---
def classify(alert: dict[str, Any]) -> tuple[str, str | None]:
    """Return (category, role) for an alert."""
    rule = alert.get("rule") or {}  # tolerate rule=None (e.g. SO zeek.notice)
    rid = str(rule.get("id", ""))
    groups = rule.get("groups", [])
    if rid in NOISE_RULES:
        return "operational", None
    # Tuned rules (auto_fp / operational) are not dispatched — the analyst
    # noted them and a human confirmed; no role should re-engage. EXCEPT:
    # a tuned rule firing with strong true-positive evidence (threat-class
    # tokens / high severity) still dispatches so the analyst can apply the
    # tuning override (a tuned-FP rule must not blind the SOC to a real TP).
    try:
        from tools.tuning_tools import TuningLedger, strong_tp_evidence
        tuning = TuningLedger().lookup(rid)
        if tuning and tuning.get("decision") in ("auto_fp", "operational"):
            if not strong_tp_evidence(alert):
                return "operational", None
    except Exception as e:  # noqa: BLE001 — tuning lookup must never break dispatch
        import logging
        logging.getLogger(__name__).warning("tuning lookup failed for %s: %s", rid, e)
    # Transport-aware rule map: backend-specific overrides win (SO rules),
    # else the Wazuh RULE_MAP.
    _tmap = _transport_rule_map()
    if rid in _tmap:
        return _tmap[rid]
    if rid in RULE_MAP:
        return RULE_MAP[rid]
    groups_str = " ".join(groups)
    if "authentication_failed" in groups_str or "invalid_login" in groups_str:
        return "security", "analyst"
    if "rootcheck" in groups_str:
        return "security", "analyst"
    if "apparmor" in groups_str:
        return "pattern", "hunt"
    if "suricata" in groups_str or "ids" in groups_str:
        return "security", "analyst"
    if "low_diskspace" in groups_str:
        return "infra", "infra"
    if "syscheck" in groups_str or "fim" in groups_str:
        return "security", "analyst"
    return DEFAULT_CATEGORY, DEFAULT_ROLE


# --- Dispatch handlers ---

def _recommend_playbook(category: str, level: int, rule_id: str = "") -> str | None:
    """Attach the most-specific recommended playbook for category+level+rule."""
    try:
        from tools.playbook_loader import load_playbooks
        best: tuple[int, str] | None = None  # (min_level, name) — pick highest
        for pb in load_playbooks().values():
            # explicit rule-id trigger wins outright (highest specificity)
            if pb.trigger_rule_ids and rule_id:
                if str(rule_id) in [str(r) for r in pb.trigger_rule_ids]:
                    return pb.name
                continue
            # tier0 playbooks are legit recommendations (they auto-fire)
            if pb.trigger_category == category and level >= pb.trigger_min_level:
                if best is None or pb.trigger_min_level > best[0]:
                    best = (pb.trigger_min_level, pb.name)
        return best[1] if best else None
    except Exception:  # noqa: BLE001 — enrichment must never break dispatch
        return None

def dispatch_infra(alert: dict[str, Any]) -> dict[str, Any]:
    """Infra-class alert: sense the affected host, escalate if needed."""
    agent = alert.get("agent", {}).get("name", "unknown")
    rule = alert.get("rule") or {}  # tolerate rule=None (e.g. SO zeek.notice)
    rid = str(rule.get("id", ""))
    level = int(rule.get("level", 0))
    category, _ = classify(alert)
    result = {
        "action": "dispatched_to_infra", "agent": agent,
        "rule_id": rule.get("id"), "ts": datetime.now(timezone.utc).isoformat(),
    }
    # Enrichment: attach the recommended playbook for infra-class alerts
    result["recommended_playbook"] = _recommend_playbook(category, level, rid)
    try:
        sh = get_selfheal()
        try:
            sense = sh.sense(agent)
            issues = sh.decide(agent, sense)
            for issue in issues:
                if issue.get("fixable"):
                    sh.heal_one(agent, issue)
                else:
                    sh.escalate.escalate(tier=1, title=f"[ROUTER] infra on {agent}: {issue['issue']}",
                                         detail={"alert": alert, "issue": issue}, actor="router")
            result["healed"] = len([i for i in issues if i.get("fixable")])
            result["escalated"] = len([i for i in issues if not i.get("fixable")])
            logger.info("infra dispatch %s: %d healed, %d escalated", agent,
                        result["healed"], result["escalated"])
        except Exception as e:
            logger.exception("infra sense failed for %s", agent)
            result["error"] = f"sense failed: {e}"
    except Exception as e:
        logger.exception("infra dispatch setup failed")
        result["error"] = f"setup failed: {e}"
    return result


def dispatch_security(alert: dict[str, Any]) -> dict[str, Any]:
    """Security-class alert: classify, mint case, verdict, escalate if high."""
    result = {"action": "dispatched_to_analyst", "ts": datetime.now(timezone.utc).isoformat()}
    try:
        analyst = get_analyst()
        cases = get_cases()
        escalator = get_escalation()
        v = analyst.verdict(alert)
        result["verdict"] = v["verdict"]
        if v["verdict"] == "escalate" or v.get("existing_chain"):
            # Stateful: repeated entity pair with an open case ATTACHES to the
            # existing chain (evidence accumulation), never re-mints.
            if v.get("existing_chain"):
                case_id = v["existing_chain"]
                cases.append_event(case_id, "router", "dispatch", {
                    "verdict": "escalate", "rationale": v["rationale"],
                    "level": v["level"], "category": v["category"], "agent": v["agent"],
                })
                result["case_id"] = case_id
                result["attached"] = True
                result["escalated"] = True
                logger.info("router attached alert to existing chain %s (repeated entity)", case_id)
            else:
                case = cases.open_case(
                    source={"alert_id": v["alert_id"], "agent": v["agent"], "rule_desc": v["description"],
                            "category": v["category"], "level": v["level"],
                            "srcip": v.get("entity_srcip"), "dstip": v.get("entity_dstip")},
                    title=f"[ROUTER] {v['category'].upper()} alert lvl={v['level']} on {v['agent']}",
                )
                case_id = case["case_id"]
                cases.append_event(case_id, "router", "dispatch", {
                    "verdict": "escalate", "rationale": v["rationale"],
                    "level": v["level"], "category": v["category"], "agent": v["agent"],
                })
                result["case_id"] = case_id
                result["escalated"] = True
            escalator.escalate(tier=2, title=f"[ROUTER-ANALYST] {v['description'][:60]}",
                               detail={"case_id": case_id, "verdict": v}, actor="router")
            # SOAR enrichment loop: if the analyst recommended a playbook,
            # hand the alert + recommendation to the responder (it gates on
            # tier + approval; tier2 produces the approval ticket).
            if v.get("recommended_playbook"):
                try:
                    from responder import run as run_responder
                    resp = run_responder(
                        alert, case_id=case_id, dry_run=False,
                        recommended_playbook=v["recommended_playbook"],
                    )
                    result["responder"] = {
                        "playbook": resp.get("playbook"),
                        "tier": resp.get("tier"),
                        "blocked": resp.get("blocked", False),
                        "blocked_reason": resp.get("blocked_reason"),
                        "run_id": resp.get("run_id"),
                        "error": resp.get("error"),
                    }
                    logger.info("responder fired: %s (tier %s, blocked=%s)",
                                resp.get("playbook"), resp.get("tier"), resp.get("blocked"))
                except Exception as e:
                    logger.exception("responder invocation failed")
                    result["responder_error"] = str(e)
            logger.info("security dispatch escalated: case %s", case_id)
        else:
            result["action"] = "noted_no_escalate"
    except Exception as e:
        logger.exception("security dispatch failed")
        result["error"] = str(e)
    return result


def dispatch_pattern(alert: dict[str, Any]) -> dict[str, Any]:
    """Pattern-class alert: run the matching hunt, file finding."""
    result = {"action": "dispatched_to_hunt", "ts": datetime.now(timezone.utc).isoformat()}
    try:
        hunter = get_hunt()
        cases = get_cases()
        escalator = get_escalation()
        rule = alert.get("rule") or {}  # tolerate rule=None (e.g. SO zeek.notice)
        rid = str(rule.get("id", ""))
        name = rule.get("description", "unknown pattern")
        # Enrichment: attach the recommended playbook for pattern-class alerts
        level = int(rule.get("level", 0))
        result["recommended_playbook"] = _recommend_playbook("pattern", level, rid)
        if rid in ("52002", "52000"):
            hunt_id = "apparmor-denials"
        elif "rootcheck" in str(rule):
            hunt_id = "rootcheck-anomalies"
        else:
            hunt_id = "auth-success-from-unusual-src"
        r = hunter.run_hunt(hunt_id, days=7)
        result["hunt_id"] = hunt_id
        if r.get("finding") == "suspicious":
            case = cases.open_case(
                source={"hunt_id": hunt_id, "trigger_alert": rid, "finding": r["finding"]},
                title=f"[ROUTER] PATTERN: {name[:50]}",
            )
            cases.append_event(case["case_id"], "router", "pattern_finding", {
                "finding": r["finding"], "summary": r.get("summary", ""), "hunt_id": hunt_id,
            })
            if r.get("category") in ("lateral-movement", "defense-evasion", "privilege-escalation"):
                escalator.escalate(tier=2, title=f"[ROUTER-HUNT] {hunt_id}: {r.get('finding')}",
                                   detail={"case_id": case["case_id"], "hunt_id": hunt_id, "finding": r}, actor="router")
                result["escalated"] = True
                result["case_id"] = case["case_id"]
                logger.info("pattern dispatch escalated: case %s (%s)", case["case_id"], hunt_id)
            result["finding"] = r["finding"]
        else:
            result["action"] = "pattern_noted_clean"
    except Exception as e:
        logger.exception("pattern dispatch failed")
        result["error"] = str(e)
    return result


def dispatch(alert: dict[str, Any], burst_count: int = 1) -> dict[str, Any]:
    """Classify one alert and dispatch to the owning role.

    burst_count > 1 means this is a repeat of a known burst signature —
    the alert is deduped (counted, not re-dispatched) unless it's the first.
    """
    category, role = classify(alert)
    alert_id = alert.get("id") or str(uuid.uuid4())
    result = {"alert_id": alert_id, "category": category, "role": role, "burst": burst_count}
    if role is None:
        result["dispatch"] = {"action": "no_dispatch_needed", "reason": "unclassified or noise"}
        return result
    if burst_count > 1:
        result["dispatch"] = {"action": "burst_deduped", "reason": f"burst repeat #{burst_count}"}
        return result
    if role == "infra":
        result["dispatch"] = dispatch_infra(alert)
    elif role == "analyst":
        result["dispatch"] = dispatch_security(alert)
    elif role == "hunt":
        result["dispatch"] = dispatch_pattern(alert)
    else:
        result["dispatch"] = {"action": "no_dispatch_needed"}
    return result


# Pattern-hunt rate limit: hunt runs at most once per N minutes per category
_last_hunt_run: dict[str, str] = {}


def pattern_due(hunt_id: str, ts: str) -> bool:
    """True if this hunt should run (rate-limited)."""
    global _last_hunt_run
    now = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    last = _last_hunt_run.get(hunt_id)
    if not last or (now - datetime.fromisoformat(last.replace("Z", "+00:00"))) >= timedelta(
        minutes=settings.pattern_rate_minutes
    ):
        _last_hunt_run[hunt_id] = ts
        return True
    return False


def run(limit: int = 50, dry_run: bool = False) -> dict[str, Any]:
    """Main router run: fetch new alerts, classify, dispatch, persist cursor."""
    ix = get_indexer()
    cursor = Cursor()
    report = {"ts": datetime.now(timezone.utc).isoformat(), "processed": 0, "dispatched": 0, "results": []}

    must = [{"range": {"timestamp": {"gte": cursor.last_ts or "now-30m"}}}]
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": must}},
        "_source": ["timestamp", "rule.id", "rule.description", "rule.level", "rule.groups",
                    "agent.name", "agent.id", "data", "full_log", "decoder.name"],
    }
    try:
        data = ix.search(query)
        hits = data.get("hits", {}).get("hits", [])
        report["total_fetched"] = len(hits)
        for h in hits:
            source = h.get("_source", {})
            alert_id = h.get("_id") or str(uuid.uuid4())
            ts = source.get("timestamp", "")
            if cursor.is_known(alert_id):
                continue
            cursor.mark(alert_id, ts)
            rule = source.get("rule", {})
            burst_key = f"{rule.get('id')}|{source.get('agent', {}).get('name')}"
            burst = cursor.burst_count(burst_key, ts)
            if not dry_run:
                result = dispatch(source, burst_count=burst)
                if result.get("role") == "hunt" and result.get("dispatch", {}).get("action", "").startswith("dispatched_to"):
                    hunt_id = result.get("dispatch", {}).get("hunt_id") or "apparmor-denials"
                    if not pattern_due(hunt_id, ts):
                        result["dispatch"] = {"action": "hunt_rate_limited", "reason": f"{hunt_id} ran recently"}
            else:
                result = {"alert_id": alert_id, "category": classify(source)[0], "role": classify(source)[1],
                          "burst": burst, "dispatch": {"action": "dry_run_skip"}}
            report["results"].append(result)
            report["processed"] += 1
            if result.get("dispatch", {}).get("action", "").startswith("dispatched_to"):
                report["dispatched"] += 1
        cursor.save()
        logger.info("router run: %d processed, %d dispatched", report["processed"], report["dispatched"])
    except Exception as e:
        logger.exception("router run failed")
        report["error"] = str(e)
    report["summary"] = f"Processed {report['processed']} alerts, dispatched {report['dispatched']}"
    return report


def cli() -> None:
    dry = "--dry-run" in sys.argv
    r = run(limit=20 if dry else 50, dry_run=dry)
    out = json.dumps(r, indent=2)
    print(out[:3000] if len(out) > 3000 else out)
    if r.get("error"):
        sys.exit(1)


if __name__ == "__main__":
    cli()
