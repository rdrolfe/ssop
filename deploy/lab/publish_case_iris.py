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

import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from tools.tls import verified_ssl_context  # issue #29: verified TLS

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
    c = verified_ssl_context()  # issue #29: verified TLS (SSOP internal CA)
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


def _event_ts(ev: dict) -> str:
    """Occurrence time from the spine event (NOT publication time).

    Spine events carry `ts` (ISO-8601, case_tools.append_event). Reformat it
    for IRIS `event_date`; fall back to now only for legacy events without ts.
    """
    raw = ev.get("ts") or ""
    if raw:
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def _event_tag(ev: dict, payload: dict) -> str:
    """Deterministic identity for a mapped spine event (stable on republish)."""
    basis = f"{ev.get('type')}|{ev.get('role')}|{payload.get('event_title')}|" \
            f"{payload.get('event_content')}"
    return "ssop-" + hashlib.sha1(basis.encode()).hexdigest()[:12]


def _existing_event_tags(iris_case_id: int) -> set[str]:
    """Tags already on the IRIS timeline (for event dedupe)."""
    try:
        r = _req("GET", f"/case/timeline/events/list?cid={iris_case_id}")
        out = set()
        for e in r.get("data", []) or []:
            tags = e.get("event_tags") or ""
            out.update(t for t in str(tags).split(",") if t.startswith("ssop-"))
        return out
    except (urllib.error.HTTPError, urllib.error.URLError):
        return set()


def find_existing_case(case_id: str) -> int | None:
    """Look up the IRIS case mapped to this spine case (case_soc_id).

    One spine case maps to ONE IRIS case — republishing must reuse it, not
    mint a duplicate. Scans the case list client-side for our soc_id.
    """
    try:
        r = _req("GET", "/manage/cases/list?limit=1000")
        for c in r.get("data", []) or []:
            if str(c.get("case_soc_id", "")) == str(case_id) \
                    and not c.get("case_close_date"):
                return c.get("case_id")
    except urllib.error.HTTPError as e:
        print(f"case lookup failed (will create): {e.code}")
    return None


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
    seen_tags = _existing_event_tags(iris_case_id)
    for ev in case.get("timeline", []):
        payload = _event_payload(ev, case_id)
        if not payload:
            continue
        tag = _event_tag(ev, payload)
        if tag in seen_tags:
            continue  # already published — keep the IRIS timeline idempotent
        _IRIS_KEY = _role_key(ev.get("role", "")) or original
        try:
            # Occurrence time from the spine event; publication time is NOT
            # used (preserves historical chronology on republish).
            payload["event_date"] = _event_ts(ev)
            payload["event_tz"] = "+00:00"
            payload["event_assets"] = []
            payload["event_iocs"] = []
            payload["event_tags"] = f"{payload.get('event_tags', '')},{tag}".lstrip(",")
            _req("POST", f"/case/timeline/events/add?cid={iris_case_id}", payload)
            seen_tags.add(tag)
            added += 1
        except urllib.error.HTTPError as e:
            print(f"  timeline event failed ({ev.get('type')}): {e.code} {e.read().decode()[:150]}")
        finally:
            _IRIS_KEY = original
    return added


_IRIS_ALT = {"ip": "ip-src", "domain": "domain", "hash": "sha256",
             "url": "url", "hostname": "hostname", "uri": "uri"}
# Verified against a live IRIS 2.4.29 DB (ioc_type table).
_IOC_TYPE_IDS = {"ip-src": 79, "ip-dst": 77, "domain": 20, "hostname": 69,
                 "sha256": 113, "sha1": 111, "md5": 90, "uri": 140, "url": 141}


def _ioc_type_id(otype: str, hash_type: str | None = None) -> int | None:
    """Resolve an SSOP observable type to an IRIS ioc_type_id.

    Hashes are semantic (issue #25): an observable with hash_type=md5/sha1
    maps to the DISTINCT IRIS type instead of the blanket sha256 mapping.
    """
    name = _IRIS_ALT.get(str(otype).lower())
    if name == "sha256" and hash_type:
        name = {"md5": "md5", "sha1": "sha1"}.get(hash_type.lower(), "sha256")
    return _IOC_TYPE_IDS.get(name or "")


def _add_note(iris_id: int, title: str, content: str) -> bool:
    """Write a real IRIS note on the case (Notes tab). Returns success.

    IRIS notes require a directory_id that exists for the case (note_directory
    is NOT auto-seeded). Create an "SSOP" directory on first use and reuse it.
    """
    dir_id = None
    try:
        dirs = _req("GET", f"/case/notes/groups/list?cid={iris_id}")
        for d in dirs.get("data", []) or []:
            if (d.get("group_title") or d.get("name")) == "SSOP":
                dir_id = d.get("id")
                break
    except Exception:
        dir_id = None
    if not dir_id:
        try:
            r = _req("POST", f"/case/notes/directories/add?cid={iris_id}",
                     {"name": "SSOP", "parent_id": None})
            dir_id = (r.get("data") or {}).get("id")
        except urllib.error.HTTPError as e:
            print(f"  note dir create failed: {e.code} {e.read().decode()[:150]}")
            return False
    # Idempotency: skip if an identically-titled note already exists.
    try:
        notes = _req("GET", f"/case/notes/list?cid={iris_id}")
        for n in notes.get("data", []) or []:
            if n.get("note_title") == title[:155]:
                print("  note already present:", title[:50])
                return True
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass
    try:
        _req("POST", f"/case/notes/add?cid={iris_id}",
             {"note_title": title[:155], "note_content": content,
              "directory_id": dir_id})
        print("  note added:", title[:50])
        return True
    except urllib.error.HTTPError as e:
        print(f"  note failed: {e.code} {e.read().decode()[:150]}")
        return False


def _add_iocs(iris_id: int, case: dict) -> int:
    """Map spine observables -> IRIS IOCs. Returns count added."""
    obs = case.get("observables", []) or []
    added = 0
    # Idempotency: skip observables already on the case.
    existing = set()
    try:
        iocs = _req("GET", f"/case/ioc/list?cid={iris_id}")
        for i in iocs.get("data", []) or []:
            existing.add((str(i.get("ioc_value", "")), i.get("ioc_type_id")))
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass
    for o in obs:
        tid = _ioc_type_id(o.get("type", ""), o.get("hash_type"))
        if not tid:
            continue
        if (str(o.get("value", "")), tid) in existing:
            continue
        try:
            _req("POST", f"/case/ioc/add?cid={iris_id}",
                 {"ioc_value": o.get("value", ""), "ioc_type_id": tid,
                  "ioc_description": f"SSOP spine observable ({o.get('type')})"})
            added += 1
        except urllib.error.HTTPError as e:
            print(f"  ioc failed ({o.get('value')}): {e.code} {e.read().decode()[:120]}")
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
    # Phase 2 (case-list columns): surface engine/decision/playbook/agent in
    # the IRIS case's custom_attributes so manage_cases.js can render them.
    sup = case.get("supervisory") or {}
    decision = sup.get("decision")
    for e in reversed(case.get("timeline", []) or []):
        if decision:
            break
        if e.get("role") == "supervisory" and e.get("type") in ("adjudication", "verdict"):
            decision = (e.get("detail") or {}).get("decision")
    ssop_summary = {
        # Engine from EXPLICIT provenance (issue #25): the backend recorded
        # at case mint time. The old rule_id.isdigit() heuristic was wrong
        # for numeric SO signature IDs and every BOTS rule.
        "engine": src.get("backend") or "unknown",
        "decision": decision or "",
        "playbook": sup.get("recommended_playbook") or "",
        "agent": src.get("agent") or case.get("assignee") or "",
    }
    desc = (f"{case.get('title', '')}\n\nsource: {src.get('rule_desc') or src.get('rule_id') or 'n/a'}\n"
            f"state: {case.get('state')} | assignee: {case.get('assignee')}\n\n{_chain_summary(case)}")
    payload = {
        "case_soc_id": case_id,
        "case_customer": customer,
        "case_name": case.get("title", case_id)[:60],
        "case_description": desc[:2000],
    }
    # Idempotency: one spine case maps to ONE IRIS case. Reuse the existing
    # IRIS case on republish instead of minting a duplicate.
    iris_id = find_existing_case(case_id)
    if iris_id:
        print(f"IRIS case exists: id={iris_id} (case_soc_id={case_id}) — reusing")
    else:
        try:
            created = _req("POST", "/manage/cases/add", payload)
            data = created.get("data", {})
            iris_id = data.get("case_id")
            print(f"IRIS case created: id={iris_id} name={data.get('name')}")
        except urllib.error.HTTPError as e:
            print(f"case create failed: {e.code} {e.read().decode()[:300]}")
            return 1

    # Phase 2 (case-list columns): write the SSOP summary into the case's
    # custom_attributes via the SSOP meta endpoint (bypasses CaseSchema which
    # drops custom_attributes on create on this IRIS version).
    try:
        _req("POST", f"/case/ssop/meta?cid={iris_id}",
             {"custom_attributes": {"ssop": ssop_summary}})
        print("ssop meta saved")
    except urllib.error.HTTPError as e:
        print(f"ssop meta failed: {e.code} {e.read().decode()[:200]}")

    # Append the decision chain as a task log entry (the human timeline).
    # Tasklog is case-scoped: use the CREATED case's id, not the default.
    try:
        _req("POST", f"/case/tasklog/add?cid={iris_id}",
             {"log_content": f"SSOP chain: {_chain_summary(case)}"})
        print("task log appended")
    except urllib.error.HTTPError as e:
        print(f"tasklog failed: {e.code} {e.read().decode()[:200]}")

    # Phase 2: real IRIS note (Notes tab) carrying the decision chain.
    _add_note(iris_id,
              f"SSOP decision chain — {case.get('state')}",
              f"{case.get('title', '')}\n\n{_chain_summary(case)}")

    # Phase 2: map spine observables -> IRIS IOCs.
    n_ioc = _add_iocs(iris_id, case)
    if n_ioc:
        print(f"iocs added: {n_ioc}")

    # Write each spine timeline event as an IRIS timeline event, attributed
    # per role (the calling key determines event.user_id).
    added = enrich_case_timeline(case_id, iris_id, customer)
    print(f"timeline events added: {added}")

    print(f"IRIS case URL: {_IRIS_URL}/case?case_id={iris_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
