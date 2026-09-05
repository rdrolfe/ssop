#!/usr/bin/env python3
"""Capture the IRIS case surface for the bake-off seed case (engine parity).

ADR-006 redefines the bake-off: parity = both detection engines (Wazuh + SO)
render the SAME decision chain in IRIS, the single human front-end — not UI
parity across three surfaces. The spine is the source of truth; IRIS is fed
from it via publish_case_iris.py, so a fully-decided case must render its
whole chain (investigation -> verdict -> adjudication -> assignment/close)
on the IRIS Timeline tab, plus the SSOP note + IOCs + the spine report.

This captures the IRIS representation for one spine case:
  - the IRIS case row (soc_id mapping, state, custom_attributes.ssop)
  - the IRIS timeline events (what the human sees on the Timeline tab)
  - the IRIS SSOP note (decision-chain summary)
  - the IRIS IOCs linked to the case
  - the spine /report?case_id= deliverable (engine-agnostic, axis 6)

Writes /tmp/iris_bakeoff_capture.json. Exit 0 on success.
"""
import json
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")

_IRIS_URL = ""
_IRIS_KEY = ""
from pathlib import Path as _Path


def _load_env() -> None:
    global _IRIS_URL, _IRIS_KEY
    for env in (_Path.home() / "agent-runtime" / ".env",
                _Path.home() / "iris-web" / ".env"):
        if not env.exists():
            continue
        for line in env.read_text().splitlines():
            if line.startswith("IRIS_API_KEY=") and not _IRIS_KEY:
                _IRIS_KEY = line.split("=", 1)[1].strip()
            elif line.startswith("IRIS_URL=") and not _IRIS_URL:
                _IRIS_URL = line.split("=", 1)[1].strip()
            elif line.startswith("INTERFACE_HTTPS_PORT=") and not _IRIS_URL:
                _IRIS_URL = f"https://192.168.1.75:{line.split('=', 1)[1].strip()}"


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _req(method: str, path: str) -> dict:
    req = urllib.request.Request(
        f"{_IRIS_URL}{path}", method=method,
        headers={"Authorization": f"Bearer {_IRIS_KEY}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25, context=_ctx()) as r:
        return json.loads(r.read().decode())


def _find_iris_case(soc_id: str) -> int | None:
    """Map a spine case_id to its IRIS case_id via soc_id."""
    page = 1
    while page < 20:
        d = _req("GET", f"/manage/cases/filter?page={page}&per_page=50")
        cases = (d.get("data") or {}).get("cases") or []
        if not cases:
            break
        for c in cases:
            if c.get("soc_id") == soc_id:
                return c.get("case_id")
        page += 1
    return None


def _timeline(cid: int) -> list:
    d = _req("GET", f"/case/timeline/events/list?cid={cid}")
    return d.get("data", {}).get("timeline") or []


def _notes(cid: int) -> list:
    """SSOP note(s) on the case (Notes tab). Response: data is a list."""
    try:
        d = _req("GET", f"/case/notes/search?cid={cid}&search_input=%25")
        data = d.get("data")
        return data if isinstance(data, list) else (data.get("notes", []) if isinstance(data, dict) else [])
    except Exception:  # noqa: BLE001
        return []


def _iocs(cid: int) -> list:
    try:
        d = _req("GET", f"/case/ioc/list?cid={cid}")
        data = d.get("data")
        return (data.get("ioc", []) if isinstance(data, dict) else []) or []
    except Exception:  # noqa: BLE001
        return []


def _report(case_id: str) -> str:
    try:
        req = urllib.request.Request(
            f"https://192.168.1.75:5602/report?case_id={case_id}",
            headers={"Accept": "text/markdown"})
        with urllib.request.urlopen(req, timeout=25, context=_ctx()) as r:
            return r.read().decode()
    except Exception as e:  # noqa: BLE001
        return f"(error: {type(e).__name__}: {e})"


def main() -> int:
    _load_env()
    if not _IRIS_KEY or not _IRIS_URL:
        print("IRIS_API_KEY / IRIS_URL not found in runtime .env")
        return 1
    case_id = sys.argv[1] if len(sys.argv) > 1 else "case-26b166ce32"
    iris_id = _find_iris_case(case_id)
    if not iris_id:
        print(f"IRIS case for {case_id} not found (publish first)")
        return 1
    out = {
        "case_id": case_id,
        "iris_case_id": iris_id,
        "captured_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "timeline": _timeline(iris_id),
        "notes": _notes(iris_id),
        "iocs": _iocs(iris_id),
        "report_spine_markdown": _report(case_id),
    }
    with open("/tmp/iris_bakeoff_capture.json", "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(json.dumps({
        "case_id": case_id, "iris_case_id": iris_id,
        "timeline_events": len(out["timeline"]),
        "notes": len(out["notes"]), "iocs": len(out["iocs"]),
        "report_len": len(out["report_spine_markdown"]),
    }, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
