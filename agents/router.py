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
                # Stable pagination boundary (ts + doc id sort values).
                self.data["search_after"] = raw.get("search_after")
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("cursor load failed: %s", e)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.write_text(json.dumps({
                "last_ts": self.data["last_ts"],
                "seen_ids": list(self.data["seen_ids"])[-5000:],  # keep last 5k
                "bursts": self.data["bursts"],
                "search_after": self.data.get("search_after"),
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

        Two guards prevent indefinite suppression (issue: burst starvation):
          - HARD CAP: a burst lives at most `burst_max_min` minutes from its
            first_ts. After the cap the signature re-dispatches (fresh burst).
          - ENTITY EXEMPTION: the caller may pass entity keys; a burst entry
            stores them, and a NEW entity (never seen in this burst) breaks
            suppression — a different attacker/victim pair is material
            evidence, not sensor noise.
        """
        window = window_min or settings.burst_window_min
        max_min = getattr(settings, "burst_max_min", 60)
        bursts = self.data["bursts"]
        now = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        entry = bursts.get(key)
        if entry:
            first = datetime.fromisoformat(entry["first_ts"].replace("Z", "+00:00"))
            last = datetime.fromisoformat(entry["last_ts"].replace("Z", "+00:00"))
            age_min = (now - first).total_seconds() / 60.0
            if age_min > max_min:
                # Suppression cap expired — start a fresh burst for this key.
                bursts.pop(key, None)
                entry = None
            elif (now - last) <= timedelta(minutes=window):
                if self._burst_entity_exempts(entry):
                    # Material change (new entity) — dispatch this alert.
                    # The repeat counter stays where it was: the exempted
                    # alert is a NEW occurrence, not another suppressed echo.
                    entry["last_ts"] = ts
                    return 1
                entry["count"] += 1
                entry["last_ts"] = ts
                return entry["count"]
        bursts[key] = {"count": 1, "last_ts": ts, "first_ts": ts,
                       "entities": self._burst_pending_entities}
        self._burst_pending_entities = []
        if len(bursts) > 2000:
            for k in list(bursts)[:500]:
                bursts.pop(k, None)
        return 1

    _burst_pending_entities: list[str] = []  # set via burst_entities() before burst_count

    def burst_entities(self, entities: list[str]) -> "Cursor":
        """Declare the alert's entity identity (srcip/dstip/agent) for the
        NEXT burst_count() call. A repeat whose entities were never part of
        the burst is MATERIAL CHANGE — burst_count treats it as count=1."""
        self._burst_pending_entities = [e for e in entities if e]
        return self

    def _burst_entity_exempts(self, entry: dict[str, Any]) -> bool:
        """True when pending entities are all NEW to this burst (material
        change — suppress only equivalent evidence, never new entities)."""
        pending = getattr(self, "_burst_pending_entities", [])
        if not pending:
            return False
        seen = set(entry.get("entities") or [])
        fresh = [e for e in pending if e not in seen]
        self._burst_pending_entities = []
        if not fresh:
            return False
        entry.setdefault("entities", list(seen)).extend(fresh)
        return True

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
    # noted them and a human confirmed; no role should re-engage. EXCEPT: a
    # tuned rule firing with a MATERIAL fingerprint delta (new attack groups,
    # category became attack, threat-desc token, higher level) still dispatches
    # so the analyst applies the tuning override and the human re-adjudicates.
    try:
        from tools.tuning_tools import TuningLedger, tuned_rule_suppresses
        from tools.ontology import categorize_alert
        tuning = TuningLedger().lookup(rid)
        if tuning and tuning.get("decision") in ("auto_fp", "operational"):
            # Same shared decision helper the analyst uses — single source of
            # truth, so both paths reach the identical outcome on the same
            # alert (thread #1 + #2). Fingerprint-aware when the ledger stores
            # one; legacy entries fall back to the config-gated strong-TP gate.
            _cat = categorize_alert(alert)
            suppress, _reason = tuned_rule_suppresses(tuning, alert, category=_cat)
            if suppress:
                return "operational", None
            # Material delta on a tuned rule: the override MUST reach a human.
            # Falling through to the normal heuristics can DROP the override —
            # a dpkg/syslog rule (2902) with a delta ends up (operational,
            # None) and never dispatches, so the analyst never sees it. Force
            # the analyst route so dispatch_security applies the tuning
            # override and escalates for re-adjudication.
            return "security", "analyst"
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
    # Ontology fallback — the single source of truth (thread #1). Unmatched
    # rule ids/groups MUST NOT silently fall to (operational, None): the
    # analyst verdict() categorizes via tools.ontology.categorize_alert, so
    # a threat-category alert (e.g. sysmon/malware groups, ET MALWARE desc)
    # would be "threat" to the analyst but dropped here. Same input, same
    # outcome — map the ontology category to the dispatch role.
    try:
        from tools.ontology import categorize_alert
        cat = categorize_alert(alert)
        if cat in ("threat", "authentication", "integrity"):
            return "security", "analyst"
        if cat in ("compliance", "operational"):
            return DEFAULT_CATEGORY, DEFAULT_ROLE
    except Exception:  # noqa: BLE001 — ontology fallback must never break dispatch
        pass
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
                # Persist the extracted IOCs on the case (first-class observables,
                # adopted SO concept) so the supervisor/report/advisory/IRIS IOC
                # mapping all read real data. Mirror analyst.py's extraction.
                from tools.observables import extract_observables
                obs = extract_observables(alert)
                case = cases.open_case(
                    source={"alert_id": v["alert_id"], "agent": v["agent"], "rule_desc": v["description"],
                            "rule_id": v.get("rule_id"), "category": v["category"], "level": v["level"],
                            "srcip": v.get("entity_srcip"), "dstip": v.get("entity_dstip")},
                    title=f"[ROUTER] {v['category'].upper()} alert lvl={v['level']} on {v['agent']}",
                    observables=obs,
                    techniques=v.get("techniques") or [],
                    assignee="analyst",  # auto-assign like the analyst mint path
                )
                result["observables"] = obs
                case_id = case["case_id"]
                cases.append_event(case_id, "router", "dispatch", {
                    "verdict": "escalate", "rationale": v["rationale"],
                    "level": v["level"], "category": v["category"], "agent": v["agent"],
                })
                # Router-minted cases reach a human for review — persist the
                # FULL investigation (entity/evidence/severity) so the
                # report/advisory/panel have real data, not a hollow case.
                from analyst import _persist_investigation
                _persist_investigation(cases, case_id, alert, obs)
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
        # Rate limit the hunt BEFORE running it. The old code checked
        # pattern_due() in run() AFTER dispatch had already executed the
        # hunt and escalated — so the rate limit never gated anything, and
        # a repeatedly-firing pattern rule (e.g. apparmor DENIED, which
        # floods) minted a fresh case + tier-2 ticket every dispatch.
        if not pattern_due(hunt_id, datetime.now(timezone.utc).isoformat()):
            result["action"] = "hunt_rate_limited"
            result["hunt_id"] = hunt_id
            result["reason"] = f"{hunt_id} ran recently (pattern rate-limit)"
            return result
        r = hunter.run_hunt(hunt_id, days=7)
        result["hunt_id"] = hunt_id
        if r.get("finding") == "suspicious":
            # Hunt-level recidivism: a persistent finding ATTACHES a recheck
            # to an existing OPEN case for this hunt (same guard hunt.py
            # uses) — never re-mint + re-escalate the same signal every
            # dispatch. Without this, the once-per-hour rate-limited hunt
            # still minted a fresh case + tier-2 ticket each time.
            existing = cases.recent_hunt_cases(hunt_id, window_s=30 * 86400)
            if existing:
                cid = existing[0]["case_id"]
                cases.append_event(cid, "router", "pattern_recheck", {
                    "finding": r["finding"], "summary": r.get("summary", ""), "hunt_id": hunt_id,
                })
                result["case_id"] = cid
                result["attached"] = "true"
                result["finding"] = r["finding"]
                result["action"] = "pattern_attached_recheck"
                return result
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
    """Main router run: fetch new alerts, classify, dispatch, persist cursor.

    Intake contract (issues: backend fields, pagination, checkpointing):
      - Field names come from the ACTIVE TRANSPORT (field_timestamp), never
        hardcoded — the query, sort, and cursor all use the backend's field.
      - The source projection carries the fields the transport normalizer
        reads (SO: rule.name/uuid, event.severity, tags, source.ip,
        destination.ip) so backend mapping happens BEFORE intake.
      - Sort is [timestamp asc, _id asc] and pagination uses search_after
        (cursor ts + last doc id) — a full page sharing one timestamp can
        never strand the next alerts at that timestamp.
      - The cursor advances ONLY past alerts whose dispatch succeeded (or
        which were explicitly skipped/deduped); a failed dispatch is retried
        on the next run instead of being permanently checkpointed.
    """
    ix = get_indexer()
    cursor = Cursor()
    report: dict[str, Any] = {"ts": datetime.now(timezone.utc).isoformat(),
                              "processed": 0, "dispatched": 0, "results": []}

    # Transport-driven intake fields (issue: backend field mappings before
    # intake). `field_timestamp` is the ACTIVE backend's timestamp field.
    ts_field = getattr(ix, "field_timestamp", "timestamp")
    must = [{"range": {ts_field: {"gte": cursor.last_ts or "now-30m"}}}]
    query = {
        "size": limit,
        # Tie-break on _id: stable total order across pages/restarts.
        "sort": [{ts_field: {"order": "asc"}}, {"_id": {"order": "asc"}}],
        "query": {"bool": {"filter": must}},
        "_source": [
            ts_field, "rule.id", "rule.description", "rule.level", "rule.groups",
            # SO detection-schema fields the normalizer reads (parity intake).
            "rule.name", "rule.uuid", "rule.category", "event.severity", "tags",
            "agent.name", "agent.id", "data", "full_log", "decoder.name",
            # SO ECS entity pair — normalized into srcip/dstip before intake.
            "source.ip", "destination.ip", "source.domain", "destination.domain",
        ],
    }
    # Stable cursor: (timestamp, doc id) of the last processed doc.
    search_after = cursor.data.get("search_after") or None
    if search_after:
        query["search_after"] = search_after

    try:
        data = ix.search(query)
        hits = data.get("hits", {}).get("hits", [])
        report["total_fetched"] = len(hits)
        pending_cursor_ts: str | None = None   # highest ts SUCCESSFULLY passed
        pending_search_after: list | None = None
        for h in hits:
            source = h.get("_source", {})
            alert_id = h.get("_id") or str(uuid.uuid4())
            ts = source.get(ts_field) or source.get("timestamp", "")
            if cursor.is_known(alert_id):
                # Already handled on an earlier run — safe to advance past it.
                pending_cursor_ts = ts or pending_cursor_ts
                pending_search_after = h.get("sort")
                continue
            # Extract the entity identity for burst material-change checks.
            data_obj = source.get("data") or {}
            entities = [
                str(source.get("srcip") or data_obj.get("src_ip") or ""),
                str(source.get("dstip") or data_obj.get("dest_ip") or ""),
                str((source.get("agent") or {}).get("name") or ""),
            ]
            burst_key = f"{(source.get('rule') or {}).get('id')}|{(source.get('agent') or {}).get('name')}"
            burst = cursor.burst_entities(entities).burst_count(burst_key, ts)
            if not dry_run:
                result = dispatch(source, burst_count=burst)
            else:
                result = {"alert_id": alert_id, "category": classify(source)[0], "role": classify(source)[1],
                          "burst": burst, "dispatch": {"action": "dry_run_skip"}}
            report["results"].append(result)
            report["processed"] += 1
            # Checkpoint discipline (issue: failed dispatch): only a result
            # WITHOUT an error advances the durable cursor. A dispatch that
            # failed (case store down, role crash) is retried next run; it is
            # NOT marked seen, so nothing is silently lost.
            dispatch_result = result.get("dispatch") or {}
            if dispatch_result.get("error"):
                report["failed_dispatches"] = report.get("failed_dispatches", 0) + 1
                logger.warning("dispatch failed for %s — will retry next run: %s",
                               alert_id, dispatch_result.get("error"))
                continue
            cursor.mark(alert_id, ts)
            pending_cursor_ts = ts or pending_cursor_ts
            pending_search_after = h.get("sort")
            if dispatch_result.get("action", "").startswith("dispatched_to"):
                report["dispatched"] += 1
        # Persist ONLY the successfully-processed boundary.
        if pending_cursor_ts:
            cursor.data["last_ts"] = pending_cursor_ts
        if pending_search_after:
            cursor.data["search_after"] = pending_search_after
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
