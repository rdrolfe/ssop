#!/usr/bin/env python3
"""SSOP daily health digest — one compact status block for the platform owner.

Runs on infra-ops (.29) inside the runtime venv (needs tools.registry etc.
and the transport config). Prints a markdown-ish block covering hosts,
timers, console API, queue, cases, boot-evidence, disk, backend, and the
verify matrix. Designed to be run by a scheduled delivery (Hermes cron) so
the owner gets the daily orientation review without going looking.
"""
import json
import os
import socket
import subprocess
import sys
import datetime
from pathlib import Path

# Shared state dir — NOT Path.home()/.ssop/state. The unattended units now run
# as `ssop-agent`, whose $HOME is the runtime tree, so a ~-derived path splits
# into two directories: the drill and boot-evidence writing in one, the digest
# reading the other (which is exactly how the drill line went silently stale).
# SSOP_STATE_DIR is pinned in the tree's .env so both planes agree.
import config  # noqa: E402 — the .env bootstrap: a pin in the tree's .env (SSOP_STATE_DIR)
STATE_DIR = Path(os.getenv("SSOP_STATE_DIR") or str(config.RUNTIME_DIR / ".ssop" / "state"))


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
        _rec = cs.reconcile()
        lines.append(
            f"**Cases:** {adj} adjudicated (24h) | reconcile: {_rec.get('consistent')}"
            f" | evidence: {_rec.get('verified_write', 0)} chained-at-write, "
            f"{_rec.get('verified_reattested', 0)} re-attested, "
            f"{len(_rec.get('unverified') or [])} unattested"
            + (f", **{len(_rec.get('drifted') or [])} DRIFTED**"
               if _rec.get('drifted') else ""))
    except Exception as e:  # noqa: BLE001
        lines.append(f"**Cases:** ERR {e}")

    # Tuning changes in the last 24h — the ADR-008 visibility control. A tuning
    # entry changes live detection: router.classify returns (operational, None)
    # for a tuned rule, so every alert of that shape stops reaching a role. On
    # 2026-09-14 an unattended triage run tuned rule 52002 + hunt:apparmor-denials
    # overnight and the ONLY thing that noticed was a verify-matrix fixture —
    # luck, not a control. This line is the control: a suppression now has to
    # appear on a surface a human reads, with its source and actor.
    try:
        from tools.tuning_tools import TuningLedger, pending_proposals
        entries = TuningLedger().list_all(limit=500)
        _cut = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
        recent: list[dict] = []
        for e in entries:
            try:
                ts = datetime.datetime.fromisoformat(
                    str(e.get("ts", "")).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            if ts >= _cut:
                recent.append(e)
        if recent:
            detail = "; ".join(
                f"{e.get('rule_id')}->{e.get('decision')} "
                f"({e.get('source') or '?'}/{e.get('tuned_by') or '-'})"
                for e in recent[:6])
            lines.append(f"**Tuning (24h):** {len(recent)} change(s) — {detail}")
        else:
            lines.append("**Tuning (24h):** none")

        # ADR-008: a PROPOSAL is inert — it does not suppress. A propose-only
        # boundary with no queue surface is just a silent suppression wearing a
        # different name, so the queue is reported here with its oldest age.
        # A proposal nobody looks at is the failure this line exists to prevent.
        # ADR-008 stage 3: proposals come in TWO shapes now — a bare proposal
        # (state=proposed) and one riding beside a committed decision
        # (pending_proposal). Deriving them here with a local filter is how the
        # second shape would go unreported, i.e. an automation judgement nobody
        # ever sees. One shared derivation, so this line and the console cannot
        # disagree about what is waiting for a human.
        pend = pending_proposals(entries)
        if pend:
            ages = []
            for e in pend:
                try:
                    ts = datetime.datetime.fromisoformat(
                        str(e.get("ts", "")).replace("Z", "+00:00"))
                    ages.append((datetime.datetime.now(datetime.timezone.utc)
                                 - ts).days)
                except (ValueError, TypeError):
                    continue
            who = ", ".join(sorted({str(e.get("proposed_by") or "unattributed")
                                    for e in pend}))
            lines.append(f"**Tuning proposals:** {len(pend)} PENDING (inert, not "
                         f"suppressing), oldest {max(ages) if ages else 0}d — "
                         f"proposed by {who} — commit in the console")
        else:
            lines.append("**Tuning proposals:** none pending")
    except Exception as e:  # noqa: BLE001 — a tuning read must not kill the digest
        lines.append(f"**Tuning (24h):** ERR {e}")

    # Decision coverage — the reporting end-goal's number. Of the cases on the
    # spine, how many carry a decision, and of those, how many compile into a
    # deliverable (advisory)? Rendered from the case dicts this scan already
    # holds (render_advisory(case=...)) so the check costs no extra store
    # round-trips — a per-case get_case is the pattern that stalled /reports.
    # A decided case that renders thin is a real defect, so it is named.
    try:
        from tools.advisory_gen import render_advisory
        from tools.case_tools import (
            CASE_COLLECTION, PROV_UNATTESTED, CaseStore, case_decision,
        )
        cs2 = CaseStore()
        # ONE provenance derivation for the whole sweep. render_advisory calls
        # provenance_for() when it is handed a case but no provenance, and
        # provenance_for(cid) delegates to provenance_map({cid}) — which
        # rebuilds the receipt index AND rescans every case point for that one
        # id. In an 887-case loop that was 887 full store scans: measured
        # 794s of the digest's ~13min run on 2026-09-27 (0.9s/case), which is
        # what pushed the job past its call timeouts and made it look hung.
        # One map build, then pass the value in — the shape render_advisory's
        # own docstring prescribes for callers that hold the case dicts.
        _prov = cs2.provenance_map()
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
                _cid = str(c.get("case_id", ""))
                try:
                    # Internal coverage metric: the question here is "does the
                    # advisory COMPILE", not "is the evidence attested" — with
                    # the publish gate in force, a pre-digest case would
                    # otherwise be counted as a render FAILURE and the coverage
                    # number would lie. Provenance is reported on its own line.
                    md = render_advisory(_cid, case=c, allow_unattested=True,
                                         provenance=_prov.get(_cid, PROV_UNATTESTED))
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
    be = sh(f"tail -1 {STATE_DIR}/boot-evidence.log 2>/dev/null")
    lines.append("**Boot evidence:** " + (be if be else "n/a"))

    # Disk
    d = sh("df -h / | tail -1 | awk '{print $5\" used, \"$4\" avail\"}'")
    lines.append("**Disk (/):** " + d)

    # The matrix used to run INLINE here, which made the whole digest unable
    # to finish inside one terminal call: the gate takes ~460s and the tool
    # caps at 420s, so the delivery path was structurally at risk. The matrix
    # now runs on its own schedule and publishes a result file
    # (deploy/lab/run_matrix_gate.py -> $SSOP_STATE_DIR/matrix-last.json);
    # the digest only READS it, so a slow gate can never delay the report
    # that has to reach a human.
    #
    # The read is honest about AGE. A gate result from yesterday rendered as
    # today's is precisely the failure this platform keeps earning: the
    # Sep 23 digest reported a stale boot-evidence line while the real
    # evidence had already been written. So the age is always shown, and a
    # result older than MATRIX_MAX_AGE_MIN is called STALE rather than
    # presented as current.
    MATRIX_MAX_AGE_MIN = 30 * 60  # the gate runs daily; 30h tolerates one missed run
    matrix_path = STATE_DIR / "matrix-last.json"
    mtxt = ""
    try:
        res = json.loads(matrix_path.read_text(encoding="utf-8"))
        ran = datetime.datetime.fromisoformat(res["ts"])
        age_min = (datetime.datetime.now(datetime.timezone.utc) - ran).total_seconds() / 60.0
        summary = res.get("summary") or "no summary line in the log"
        bits = [f"{summary} (exit {res.get('exit')}, {res.get('duration_s')}s, "
                f"ran {age_min:.0f}min ago)"]
        if res.get("timed_out"):
            bits.append("  TIMED OUT — the gate did not finish; raise the runner's budget")
        for p in (res.get("problems") or [])[:4]:
            bits.append("  " + p)
        for f in (res.get("fails") or [])[:4]:
            bits.append("  " + f)
        if age_min > MATRIX_MAX_AGE_MIN:
            bits.append(f"  STALE — result is {age_min/60:.1f}h old (limit "
                        f"{MATRIX_MAX_AGE_MIN/60:.0f}h); the gate has not reported recently")
        mtxt = "\n".join(bits)
    except FileNotFoundError:
        mtxt = "n/a (no matrix result yet — run deploy/lab/run_matrix_gate.py)"
    except Exception as e:  # noqa: BLE001 — an unreadable result must not kill the digest
        mtxt = f"n/a (matrix result unreadable: {e})"
    lines.append("**Matrix:** " + mtxt)

    # Docs citations (ontology spec drift gate). Same venv rule as the matrix:
    # a bare `python3` here is the trap named three lines up.
    dc = sh("timeout 20 ./agent-env/bin/python3 -m verify.check_docs 2>&1", timeout=30)
    lines.append("**Docs:** " + (dc.strip() if dc else "n/a"))

    # Purple-team drill (last receipt from drill.py)
    try:
        dp = STATE_DIR / "drill-last.json"
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
