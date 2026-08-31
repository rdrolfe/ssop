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
    hosts = {
        "infra-ops": ("192.168.1.29", [22]),
        "telemetry(Wazuh)": ("192.168.1.75", [22, 9200]),
        "securityonion": ("192.168.1.76", [22, 9200]),
        "network(Suricata)": ("192.168.1.13", [22]),
        "kb-vec(Qdrant)": ("192.168.1.94", [6333]),
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

    # Timers
    t = sh("systemctl list-timers ssop-analyst.timer ssop-hunt.timer --no-pager 2>/dev/null | grep -E 'ssop-(analyst|hunt)' | awk '{print $NF}' | tr '\\n' ' '")
    lines.append(f"**Timers:** {' '.join(t.split()) if t else 'n/a'}")

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

    # Boot evidence
    be = sh("tail -1 ~/.ssop/state/boot-evidence.log 2>/dev/null")
    lines.append("**Boot evidence:** " + (be if be else "n/a"))

    # Disk
    d = sh("df -h / | tail -1 | awk '{print $5\" used, \"$4\" avail\"}'")
    lines.append("**Disk (/):** " + d)

    # Matrix
    m = sh("timeout 115 python3 -m verify.matrix 2>&1 | grep -E 'SSOP verify matrix'", timeout=130)
    lines.append("**Matrix:** " + (m.split("=== ")[-1] if m else "n/a"))

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
