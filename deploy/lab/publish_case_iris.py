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
from pathlib import Path

sys.path.insert(0, ".")

# IRIS service-account key + endpoint live in the runtime .env (host-only).
_IRIS_URL = ""
_IRIS_KEY = ""


def _load_env() -> None:
    global _IRIS_URL, _IRIS_KEY
    # Runtime .env (this host) wins; fall back to ~/iris-web/.env (IRIS host).
    for env in (Path.home() / "agent-runtime" / ".env",
                Path.home() / "iris-web" / ".env"):
        if not env.exists():
            continue
        for line in env.read_text().splitlines():
            if line.startswith("IRIS_API_KEY=") and not _IRIS_KEY:
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


def main() -> int:
    _load_env()
    if not _IRIS_KEY or not _IRIS_URL:
        print("IRIS_API_KEY / IRIS_URL not found (looked in ~/iris-web/.env)")
        return 1
    if len(sys.argv) < 2:
        print("usage: publish_case_iris.py <case_id> [--customer N]")
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

    print(f"IRIS case URL: {_IRIS_URL}/case?case_id={iris_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
