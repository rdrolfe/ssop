#!/usr/bin/env python3
"""SSOP daily health digest — one compact status block for the platform owner.

Runs on infra-ops (.29) inside the runtime venv (needs tools.registry etc.
and the transport config). Prints a markdown-ish block covering hosts,
timers, console API, queue, cases, boot-evidence, disk, backend, and the
verify matrix. Designed to be run by a scheduled delivery (Hermes cron) so
the owner gets the daily orientation review without going looking.
"""
import json
import socket
import subprocess
import sys
import datetime
from pathlib import Path


def sh(cmd: str, timeout: int = 25) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:  # noqa: BLE001 — a probe must never kill the digest
        return f"ERR {e}"


def port_open(host: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except Exception:
        return False


def main() -> int:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M %Z")
    lines = [f"**SSOP Daily Digest — {now}**", ""]

    # Backend
    try:
        import yaml
        tp = yaml.safe_load(Path("transport.yaml").read_text()) if Path("transport.yaml").exists() else {}
        backend = tp.get("backend", "?")
    except Exception:  # noqa: BLE001
        backend = "?"
    lines.append(f"**Backend:** {backend}")

    # Hosts / services (TCP reachability)
    # Qdrant note: kb-vec binds its API to 127.0.0.1, so the platform reaches it
    # through ssop-qdrant-tunnel.service (an SSH forward to 127.0.0.1:16333 on
    # this host). Probing 192.168.1.94:6333 directly is ALWAYS refused — it
    # reported a false "kb-vec DOWN" every day while the spine was perfectly
    # reachable. Probe the EFFECTIVE endpoint from settings, and surface the
    # tunnel unit, because THAT is what actually fails when the spine goes away.
    try:
        import urllib.parse as _urlparse

        from config import settings as _settings
        _p = _urlparse.urlparse(_settings.qdrant_url or "")
        qdrant_probe = (_p.hostname or "127.0.0.1",
                        int(_p.port or _settings.qdrant_port or 16333))
    except Exception:  # noqa: BLE001 — probe must never kill the digest
        qdrant_probe = ("127.0.0.1", 16333)
    hosts = {
        "infra-ops": ("192.168.1.29", [22]),
        "telemetry(Wazuh)": ("192.168.1.75", [22, 9200]),
        "securityonion": ("192.168.1.76", [22, 9200]),
        "network(Suricata)": ("192.168.1.13", [22]),
        f"qdrant({qdrant_probe[0]}:{qdrant_probe[1]})": (qdrant_probe[0], [qdrant_probe[1]]),
        "vault-secrets": ("192.168.1.90", [22]),
        "ubuntu-target": ("192.168.1.77", [22]),
        "win-target": ("192.168.1.78", [22]),
        "c2-sink": ("192.168.1.79", [22]),
        "proxmox": ("192.168.1.169", [8006]),
    }
    up = [h for h, (ip, ps) in hosts.items() if any(port_open(ip, p) for p in ps)]
    down = [h for h, (ip, ps) in hosts.items() if not any(port_open(ip, p) for p in ps)]
    lines.append(f"**Hosts:** {len(up)}/{len(hosts)} up"
                 + (f" | DOWN: {', '.join(down)}" if down else ""))

    # The tunnel is a single point of failure for every store-backed feature.
    qt = sh("systemctl is-active ssop-qdrant-tunnel.service 2>/dev/null")
    lines.append(f"**Qdrant tunnel:** {qt or 'n/a'}")

    # Timers
    t = sh("systemctl list-timers ssop-analyst.timer ssop-hunt.timer --no-pager 2>/dev/null | grep -E 'ssop-(analyst|hunt)' | awk '{print $NF}' | tr '\\n' ' '")
    lines.append(f"**Timers:** {' '.join(t.split()) if t else 'n/a'}")

    # Timer liveness (the 19h router-wedge guard)
    tl = sh("timeout 20 python3 -m verify.check_timers 2>&1", timeout=30)
    lines.append("**Timer health:** " + (tl.strip() if tl else "n/a"))

    # Console API
    lines.append("**Console API:** " + sh("systemctl is-active ssop-adjudicate-api"))

    # Queue
    try:
        from tools.registry import get_escalation
        from collections import Counter
        esc = get_escalation()
        tickets = esc.list_tickets()
        open_t = [t for t in tickets if t.get("status") == "open"]
        by_actor = dict(Counter(t.get("actor") for t in open_t))
        by_hunt = dict(Counter(t.get("hunt_id") for t in open_t if t.get("hunt_id")))
        lines.append(f"**Queue:** {len(open_t)} open / {len(tickets)} total | by actor: {by_actor}"
                     + (f" | by hunt: {by_hunt}" if by_hunt else ""))
        for t in open_t[:5]:
            lines.append(f"   - {t.get('actor')}: {t.get('title', '')[:60]}")
    except Exception as e:  # noqa: BLE001
        lines.append(f"**Queue:** ERR {e}")

    # Cases adjudicated in 24h + reconcile
    try:
        from tools.case_tools import CaseStore
        cs = CaseStore()
        cut = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
        adj = 0
        if cs.cases_file.exists():
            for line in cs.cases_file.read_text().splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("event") in ("adjudication",) and rec.get("ts", "") >= cut:
                        adj += 1
                except Exception:
                    pass
        lines.append(f"**Cases:** {adj} adjudicated (24h) | reconcile: {cs.reconcile().get('consistent')}")
    except Exception as e:  # noqa: BLE001
        lines.append(f"**Cases:** ERR {e}")

    # Decision coverage — the reporting end-goal's number. Of the cases on the
    # spine, how many carry a decision, and of those, how many compile into a
    # deliverable (advisory)? Rendered from the case dicts this scan already
    # holds (render_advisory(case=...)) so the check costs no extra store
    # round-trips — a per-case get_case is the pattern that stalled /reports.
    # A decided case that renders thin is a real defect, so it is named.
    try:
        from tools.advisory_gen import render_advisory
        from tools.case_tools import CASE_COLLECTION, CaseStore, case_decision
        cs2 = CaseStore()
        total = decided = rendered = thin = new_undecided = 0
        thin_ids: list[str] = []
        for r in cs2._get_memory().search_memory(
                CASE_COLLECTION, "case-", limit=5000, scroll_limit=20000):
            c = CaseStore._parse_content(r.get("content", ""))
            if not isinstance(c, dict):
                continue
            total += 1
            if case_decision(c)[0]:
                decided += 1
                try:
                    md = render_advisory(c.get("case_id", ""), case=c)
                except Exception:  # noqa: BLE001 — a render failure is the finding
                    md = ""
                if md and len(md) >= 300:
                    rendered += 1
                else:
                    thin += 1
                    if len(thin_ids) < 3:
                        thin_ids.append(str(c.get("case_id", "?")))
            elif str(c.get("state") or "") == "new":
                new_undecided += 1
        lines.append(
            f"**Coverage:** {decided}/{total} cases decided | advisories render: "
            f"{rendered}/{decided}"
            + (f" | THIN: {thin} {thin_ids}" if thin else "")
            + f" | undecided (state=new): {new_undecided}")
    except Exception as e:  # noqa: BLE001 — coverage must never kill the digest
        lines.append(f"**Coverage:** ERR {e}")

    # Boot evidence
    be = sh("tail -1 ~/.ssop/state/boot-evidence.log 2>/dev/null")
    lines.append("**Boot evidence:** " + (be if be else "n/a"))

    # Disk
    d = sh("df -h / | tail -1 | awk '{print $5\" used, \"$4\" avail\"}'")
    lines.append("**Disk (/):** " + d)

    # Matrix — MUST run in the runtime venv. The digest used to call the
    # system `python3`, which has no dotenv/langgraph, so the gate died in
    # 0.5s and the line printed "n/a" as though there were nothing to report:
    # an unrun check that looks like a passing check. Use the venv explicitly,
    # give it room under load, and say so when it genuinely did not run.
    m = sh("timeout 250 ./agent-env/bin/python3 -m verify.matrix 2>&1 | grep -E 'SSOP verify matrix'",
           timeout=280)
    lines.append("**Matrix:** " + ((m.split("=== ")[-1] if m else
                                    "n/a (did not run — check ./agent-env/bin/python3 -m verify.matrix)")))

    # Docs citations (ontology spec drift gate)
    dc = sh("timeout 20 python3 -m verify.check_docs 2>&1", timeout=30)
    lines.append("**Docs:** " + (dc.strip() if dc else "n/a"))

    # Purple-team drill (last receipt from drill.py)
    try:
        dp = Path.home() / ".ssop" / "state" / "drill-last.json"
        if dp.exists():
            rec = json.loads(dp.read_text())
            p1 = rec.get("phase1_live_fire", {})
            p2 = rec.get("phase2_ground_truth", {})
            lines.append(
                f"**Drill:** {'PASS' if rec.get('pass') else 'FAIL'} "
                f"({rec.get('backend')} | {rec.get('ts', '')[:16]}Z) — "
                f"live-fire: {p1.get('alert_count', 0)} sshd alerts landed, "
                f"analyst {sorted(set(p1.get('verdicts', []))) or 'n/a'}; "
                f"chain: {p2.get('detail', 'n/a')}")
        else:
            lines.append("**Drill:** n/a (no receipt yet)")
    except Exception as e:  # noqa: BLE001
        lines.append(f"**Drill:** ERR {e}")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
