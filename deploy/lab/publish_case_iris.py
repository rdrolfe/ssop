#!/usr/bin/env python3
"""Spine -> DFIR-IRIS case bridge.

Maps a fully-decided spine case onto an IRIS case (the human case surface
on the Wazuh host) via the IRIS API:

  1. Creates an IRIS case: case_soc_id = spine case_id, case_customer,
     name = spine title, description = title + source + decision chain.
  2. Appends a task log carrying the decision chain (investigation ->
     adjudication -> responder) so the IRIS timeline tells the ontology
     story, with a link back to the SSOP console.

Credentials: IRIS_API_KEY + IRIS_URL read from the runtime .env (host-only,
never in the repo). API shape verified against IRIS v2.4.29 live.

Usage: python3 deploy/lab/publish_case_iris.py <case_id> [--customer N]
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

# IRIS service-account key + endpoint live in the runtime .env (host-only).
# Per-role keys: IRIS_KEY_ANALYST / _SUPERVISOR / _RESPONDER / _HUNT
# (fall back to IRIS_API_KEY = the automation account).
_IRIS_URL = ""
_IRIS_KEY = ""
_ROLE = "automation"


def _load_env() -> None:
    global _IRIS_URL, _IRIS_KEY
    # Runtime .env (this host) wins; fall back to ~/iris-web/.env (IRIS host).
    for env in (Path.home() / "agent-runtime" / ".env",
                Path.home() / "iris-web" / ".env"):
        if not env.exists():
            continue
        for line in env.read_text().splitlines():
            if _ROLE != "automation" and line.startswith(f"IRIS_KEY_{_ROLE.upper()}="):
                _IRIS_KEY = line.split("=", 1)[1].strip()
            elif line.startswith("IRIS_API_KEY=") and not _IRIS_KEY:
                _IRIS_KEY = line.split("=", 1)[1].strip()
            elif line.startswith("IRIS_URL=") and not _IRIS_URL:
                _IRIS_URL = line.split("=", 1)[1].strip()
            elif line.startswith("INTERFACE_HTTPS_PORT=") and not _IRIS_URL:
                port = line.split("=", 1)[1].strip()
                _IRIS_URL = f"https://192.168.1.75:{port}"


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _req(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{_IRIS_URL}{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {_IRIS_KEY}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25, context=_ctx()) as r:
        return json.loads(r.read().decode())


def _chain_summary(case: dict) -> str:
    """One-block chain summary from the spine timeline."""
    lines = []
    for ev in case.get("timeline", []):
        role, typ = ev.get("role", "?"), ev.get("type", "?")
        d = ev.get("detail", {}) or {}
        if typ == "investigation":
            lines.append(f"[analyst/investigation] severity={d.get('severity_label')} "
                         f"({d.get('severity')}), kill-chain: "
                         f"{' -> '.join(d.get('kill_chain', []))}")
        elif typ in ("adjudication", "verdict") and role == "supervisory":
            lines.append(f"[supervisory/adjudication] decision={d.get('decision')} "
                         f"rationale={str(d.get('rationale', ''))[:100]}")
        elif typ == "escalated":
            lines.append("[hunt/escalated] finding escalated")
        elif typ == "assigned":
            lines.append(f"[{role}/assigned] -> {d.get('assignee')}")
        elif typ == "transition":
            lines.append(f"[{role}/transition] {d.get('from')} -> {d.get('to')}")
    return "\n".join(lines) if lines else "(no decision chain on timeline)"


# IRIS event-category ids (MITRE tactics, from event_category): map our
# kill-chain stages + event types onto them.
_KILLCHAIN_CATEGORY: dict[str, int] = {
    "INITIAL ACCESS": 4, "EXECUTION": 5, "PERSISTENCE": 6,
    "PRIVILEGE ESCALATION": 7, "DEFENSE EVASION": 8, "CREDENTIAL ACCESS": 9,
    "DISCOVERY": 10, "LATERAL MOVEMENT": 11, "COLLECTION": 12,
    "C2": 13, "C2/MALWARE": 13, "EXFILTRATION": 14, "IMPACT": 15,
    "NETWORK": 11, "RECON": 10, "RECONNAISSANCE": 10,
}
_DEFAULT_CATEGORY = 10  # Discovery — generic fallback
_ROLE_KEY_ENV = {"analyst": "IRIS_KEY_ANALYST", "supervisor": "IRIS_KEY_SUPERVISOR",
                 "supervisory": "IRIS_KEY_SUPERVISOR",  # spine timeline uses role='supervisory'
                 "responder": "IRIS_KEY_RESPONDER", "hunt": "IRIS_KEY_HUNT"}


def _stage_category(stage: str) -> int:
    key = str(stage).split(":", 1)[0].strip().upper()
    return _KILLCHAIN_CATEGORY.get(key, _DEFAULT_CATEGORY)


def _event_payload(ev: dict, case_id: str) -> dict | None:
    """Map a spine timeline event to an IRIS timeline-event payload."""
    typ = ev.get("type")
    role = ev.get("role", "?")
    d = ev.get("detail", {}) or {}
    if typ == "investigation":
        chain = " -> ".join(str(x) for x in d.get("kill_chain", []))
        cat = _stage_category((d.get("kill_chain") or [""])[0]) if d.get("kill_chain") else _DEFAULT_CATEGORY
        return {
            "event_title": "Investigation",
            "event_content": (f"severity={d.get('severity_label')} ({d.get('severity')})\n"
                              f"kill-chain: {chain}\nhypothesis: {d.get('hypothesis', '')}\n"
                              f"evidence sources: {d.get('evidence_count', 0)}"),
            "event_source": "analyst", "event_tags": "ssop",
            "event_category_id": cat,
        }
    if typ in ("adjudication", "verdict") and role == "supervisory":
        # Format the decision rationale as scannable labeled lines instead of
        # one dense run-on block. The spine rationale is a single string that
        # mixes rule evidence, agent context, corpus provenance and history.
        decision = str(d.get("decision", "")).upper()
        rationale = str(d.get("rationale", "")).strip()
        if rationale.lower().startswith(decision.lower() + ":"):
            # Strip the leading "APPROVE:" / "DENY:" echo already in the title.
            rationale = rationale[len(decision) + 1:].strip()
        # Key factoids (rule, corpus, agent, prior history) get pulled onto
        # their own labeled lines; the rest stays as the rationale paragraph.
        picks = []
        for label, needle in (("Rule", "ET MALWARE"), ("Corpus", "POC-feed synthetic"),
                              ("Agent", "ZERO alert traffic"), ("Prior cases", "prior case")):
            for bit in rationale.split(". "):
                if needle in bit and not any(needle in p for p in picks):
                    picks.append(f"{label}: {bit.strip().strip('.')}")
        content = "\n".join([f"Rationale: {rationale}"] + picks) if rationale \
            else "Rationale: (none)"
        return {
            "event_title": f"Supervisory decision: {decision}",
            "event_content": content,
            "event_source": "supervisory", "event_tags": "ssop",
            "event_category_id": _DEFAULT_CATEGORY,
        }
    if typ == "verdict" and role == "analyst":
        return {
            "event_title": f"Analyst verdict: {str(d.get('verdict', ''))}",
            "event_content": f"level={d.get('level')} category={d.get('category')} rationale={d.get('rationale', '')}",
            "event_source": "analyst", "event_tags": "ssop",
            "event_category_id": _DEFAULT_CATEGORY,
        }
    if typ == "assigned":
        return {
            "event_title": f"Assigned to {d.get('assignee')}",
            "event_content": f"previous: {d.get('previous')} note: {d.get('note', '')}",
            "event_source": role, "event_tags": "ssop",
            "event_category_id": _DEFAULT_CATEGORY,
        }
    if typ == "case_closed":
        return {
            "event_title": "Case closed",
            "event_content": f"reason: {d.get('reason', '')}",
            "event_source": role, "event_tags": "ssop",
            "event_category_id": _DEFAULT_CATEGORY,
        }
    if typ == "transition":
        return {
            "event_title": f"State: {d.get('from')} -> {d.get('to')}",
            "event_content": f"rationale: {d.get('rationale', '')}",
            "event_source": role, "event_tags": "ssop",
            "event_category_id": _DEFAULT_CATEGORY,
        }
    return None


def _role_key(role: str) -> str:
    """Look up the IRIS key for a spine role (fall back to automation)."""
    env_name = _ROLE_KEY_ENV.get(str(role).lower())
    if not env_name:
        return ""
    for env in (Path.home() / "agent-runtime" / ".env",
                Path.home() / "iris-web" / ".env"):
        if not env.exists():
            continue
        for line in env.read_text().splitlines():
            if line.startswith(f"{env_name}="):
                return line.split("=", 1)[1].strip()
    return ""


def enrich_case_timeline(case_id: str, iris_case_id: int, customer: int = 1) -> int:
    """Write each spine timeline event as an IRIS timeline event, attributed
    per role (the calling key determines event.user_id). Returns count."""
    global _IRIS_KEY
    from tools.case_tools import CaseStore
    case = CaseStore().get_case(case_id)
    if not case:
        return 0
    original = _IRIS_KEY
    added = 0
    for ev in case.get("timeline", []):
        payload = _event_payload(ev, case_id)
        if not payload:
            continue
        _IRIS_KEY = _role_key(ev.get("role", "")) or original
        try:
            payload["event_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
            payload["event_tz"] = "+00:00"
            payload["event_assets"] = []
            payload["event_iocs"] = []
            _req("POST", f"/case/timeline/events/add?cid={iris_case_id}", payload)
            added += 1
        except urllib.error.HTTPError as e:
            print(f"  timeline event failed ({ev.get('type')}): {e.code} {e.read().decode()[:150]}")
        finally:
            _IRIS_KEY = original
    return added


def main() -> int:
    global _ROLE
    # --role selects which IRIS service account attributes the write
    # (analyst|supervisor|responder|hunt|automation). Must be parsed BEFORE
    # _load_env() so the right key is picked.
    if "--role" in sys.argv:
        _ROLE = sys.argv[sys.argv.index("--role") + 1].lower()
    _load_env()
    if not _IRIS_KEY or not _IRIS_URL:
        print("IRIS_API_KEY / IRIS_URL not found (looked in ~/iris-web/.env)")
        return 1
    if len(sys.argv) < 2:
        print("usage: publish_case_iris.py <case_id> [--customer N] [--role analyst|supervisor|responder|hunt|automation]")
        return 1
    case_id = sys.argv[1]
    customer = 1
    if "--customer" in sys.argv:
        customer = int(sys.argv[sys.argv.index("--customer") + 1])

    from tools.case_tools import CaseStore
    case = CaseStore().get_case(case_id)
    if not case:
        print(f"case {case_id} not in spine")
        return 1

    src = case.get("source", {}) or {}
    desc = (f"{case.get('title', '')}\n\nsource: {src.get('rule_desc') or src.get('rule_id') or 'n/a'}\n"
            f"state: {case.get('state')} | assignee: {case.get('assignee')}\n\n{_chain_summary(case)}")
    payload = {
        "case_soc_id": case_id,
        "case_customer": customer,
        "case_name": case.get("title", case_id)[:60],
        "case_description": desc[:2000],
    }
    try:
        created = _req("POST", "/manage/cases/add", payload)
        data = created.get("data", {})
        iris_id = data.get("case_id")
        print(f"IRIS case created: id={iris_id} name={data.get('name')}")
    except urllib.error.HTTPError as e:
        print(f"case create failed: {e.code} {e.read().decode()[:300]}")
        return 1

    # Append the decision chain as a task log entry (the human timeline).
    # Tasklog is case-scoped: use the CREATED case's id, not the default.
    try:
        _req("POST", f"/case/tasklog/add?cid={iris_id}",
             {"log_content": f"SSOP chain: {_chain_summary(case)}"})
        print("task log appended")
    except urllib.error.HTTPError as e:
        print(f"tasklog failed: {e.code} {e.read().decode()[:200]}")

    # Write each spine timeline event as an IRIS timeline event, attributed
    # per role (the calling key determines event.user_id).
    added = enrich_case_timeline(case_id, iris_id, customer)
    print(f"timeline events added: {added}")

    print(f"IRIS case URL: {_IRIS_URL}/case?case_id={iris_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
