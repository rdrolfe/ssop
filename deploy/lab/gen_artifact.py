#!/usr/bin/env python3
"""Generate the full artifact set for a decided case from BOTH surfaces:
  - spine report (markdown + html)
  - advisory (markdown + html)
  - SO-native report (the SOC human view)
and print key decision lines so we can verify parity after fixes.
Usage: gen_artifact.py <case_id> <outdir>"""
import base64
import json
import ssl
import sys
import urllib.request
import yaml
from pathlib import Path

sys.path.insert(0, ".")
from config import settings


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _so_target():
    with open("transport.yaml") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    user = b.get("user")
    pw = settings.so_indexer_password
    return host, port, user, pw


def _es(method, host, port, auth, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"https://{host}:{port}/{path}", data=data, method=method,
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25, context=_ctx()) as r:
        return json.loads(r.read().decode())


def main() -> int:
    case_id = sys.argv[1]
    outdir = Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)

    # refresh SO so read-back is current
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    try:
        _es("POST", host, port, auth, "so-case/_refresh")
        _es("POST", host, port, auth, "so-casehistory/_refresh")
    except Exception as e:  # noqa: BLE001
        print("refresh:", e)

    from tools.report_gen import render_case_report, render_so_case_report, _md_to_html
    from tools.advisory_gen import render_advisory, render_advisory_html

    spine_md = render_case_report(case_id)
    spine_html = _md_to_html(spine_md, f"Incident Report {case_id}")
    adv_md = render_advisory(case_id, backend="spine")
    adv_html = render_advisory_html(case_id, backend="spine")
    so_md = render_so_case_report(case_id)
    so_html = _md_to_html(so_md, f"SO-native Report {case_id}")

    (outdir / "report.md").write_text(spine_md)
    (outdir / "report.html").write_text(spine_html)
    (outdir / "advisory.md").write_text(adv_md)
    (outdir / "advisory.html").write_text(adv_html)
    (outdir / "so-report.md").write_text(so_md)
    (outdir / "so-report.html").write_text(so_html)

    print(f"wrote artifacts to {outdir}/")
    for name, md in (("REPORT", spine_md), ("ADVISORY", adv_md), ("SO-REPORT", so_md)):
        print(f"\n=== {name} — decision/summary lines ===")
        for ln in md.splitlines():
            if any(k in ln.lower() for k in ("decision:", "**deny**", "**approve**",
                                              "adjudicated as", "supervisory decision",
                                              "under review")):
                print(" ", ln[:180])
    return 0


if __name__ == "__main__":
    sys.exit(main())
