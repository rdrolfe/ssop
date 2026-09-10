#!/usr/bin/env python3
"""Tier0/Tier1 responder live proof — read-only + recorded execution on the fleet.

Chain (recorded on the case spine end-to-end):
  1. Tier0-style read-only verification: service-impact-check against .13
     (network host, suricata) — the executor SSHes, runs systemctl is-active,
     records the receipt. Read-only, zero blast radius.
  2. Tier1 live execution: restart-flapping-service against a HARMLESS demo
     service on .13 — proves the whitelisted restart + verify recovery path.

Run on .29: PYTHONPATH=. ./agent-env/bin/python3 deploy/lab/prove_responder.py
"""
import json
import sys

sys.path.insert(0, ".")

from responder import run  # noqa: E402

NETWORK_HOST = "192.168.1.13"

# service name as the analyst-flattened context will see it
ALERT_CHECK = {
    "id": "resp-proof-check",
    "timestamp": "2026-09-09T21:00:00.000+0000",
    "rule": {"id": "40704", "level": 4,
             "description": "systemd unit state change (ops event)",
             "groups": ["systemd", "infra"]},
    "agent": {"name": NETWORK_HOST},
    "service": "suricata",
    "category": "infra",
}

ALERT_RESTART = {
    "id": "resp-proof-restart",
    "timestamp": "2026-09-09T21:05:00.000+0000",
    "rule": {"id": "541", "level": 5,
             "description": "Service flagged as crash-looping (synthetic)",
             "groups": ["systemd", "operational"]},
    "agent": {"name": NETWORK_HOST},
    "service": "ssop-demo-svc",
    "category": "operational",
}


def main() -> int:
    ok = True

    # ---- 1. tier1 read-only: service-impact-check on .13/suricata ----
    print("=== [1] tier1 READ-ONLY: service-impact-check (suricata on .13) ===",
          flush=True)
    r1 = run(dict(ALERT_CHECK), case_id="", dry_run=False,
             recommended_playbook="service-impact-check")
    print(json.dumps(r1, indent=1)[:900], flush=True)
    ok1 = (not r1.get("blocked") and r1.get("tier") == "tier1"
           and any(s.get("ok") for s in r1.get("results", [])))
    print(f"[{'PASS' if ok1 else 'FAIL'}] tier1 read-only execution", flush=True)
    ok = ok and ok1

    # ---- 2. tier1 mutating: restart-flapping-service on .13 demo service ----
    print("\n=== [2] tier1 EXECUTE: restart-flapping-service (ssop-demo-svc on .13) ===",
          flush=True)
    r2 = run(dict(ALERT_RESTART), case_id="", dry_run=False,
             recommended_playbook="restart-flapping-service")
    print(json.dumps(r2, indent=1)[:900], flush=True)
    ok2 = (not r2.get("blocked") and r2.get("tier") == "tier1"
           and all(s.get("ok") for s in r2.get("results", []))
           and len(r2.get("results", [])) == 2)
    print(f"[{'PASS' if ok2 else 'FAIL'}] tier1 restart+verify execution", flush=True)
    ok = ok and ok2

    print("\nRESPONDER PROOF: " + ("PASS" if ok else "FAIL"), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
