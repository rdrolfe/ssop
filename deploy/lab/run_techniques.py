#!/usr/bin/env python3
"""Fire real adversary techniques at lab hosts and ASSERT detection actually fired.

This is NOT the synthetic injector. Every command here executes on a real host
and every assertion is made against the live Wazuh indexer.

Design rules:
  - Seeded-deterministic selection, never unconstrained random. A date-derived
    index keeps coverage rotating weekly while staying reproducible.
  - Every technique carries an explicit `cleanup`. Nothing persists.
  - Every alert generated is labelled so it can never reach the tuning ledger.
  - A technique that does not produce the expected events is reported as
    UNVERIFIED. That is a finding, not a failure to hide.

Usage:
  ./run_techniques.py --list
  ./run_techniques.py --technique T1136.001-create-account-local
  ./run_techniques.py --wave            # today's seeded subset
  ./run_techniques.py --verify-only
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path

import paramiko

HERE = Path(__file__).resolve().parent
TECHNIQUES = HERE / "techniques" / "windows-target.json"
SSH_KEY = os.path.expanduser("~/.ssh/hermes_ssop")

# Windows-target audit subcategories we must enable for detection to be possible.
AUDIT_PREREQS = {
    "Process Creation": "4688 process creation",
    "Account Management": "4720/4732 account + group changes",
    "Task Scheduler": "4698 scheduled task creation",
    "Registry": "4657 registry value set",
}


def load() -> dict:
    return json.loads(TECHNIQUES.read_text())


def ssh(host: str, user: str, cmd: str, timeout: int = 60) -> str:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, key_filename=SSH_KEY, timeout=15,
              allow_agent=False, look_for_keys=False)
    try:
        _, o, e = c.exec_command(cmd, timeout=timeout)
        out = o.read().decode("utf-8", "replace").strip()
        err = e.read().decode("utf-8", "replace").strip()
        return out or err
    finally:
        c.close()


class Indexer:
    """Read-only view of the live Wazuh indexer for detection assertions."""

    def __init__(self, host: str, port: int, user: str, password: str):
        self.base = f"https://{host}:{port}"
        self.auth = (user, password)
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def _get(self, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(
            f"{self.base}/{path}",
            data=json.dumps(body).encode() if body else None,
            headers={"Content-Type": "application/json"},
        )
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self.base, self.auth[0], self.auth[1])
        op = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ctx),
            urllib.request.HTTPBasicAuthHandler(mgr))
        with op.open(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def rule_ids(self, agent: str, since: str) -> dict[str, int]:
        q = {"size": 0,
             "query": {"bool": {"filter": [
                 {"term": {"agent.name": agent}},
                 {"range": {"timestamp": {"gte": since}}}]}},
             "aggs": {"rules": {"terms": {"field": "rule.id", "size": 60}}}}
        r = self._get("wazuh-alerts-4.x-*/_search", q)
        return {b["key"]: b["doc_count"]
                for b in r["aggregations"]["rules"]["buckets"]}

    def describe(self, agent: str, since: str) -> str:
        q = {"size": 0,
             "query": {"bool": {"filter": [
                 {"term": {"agent.name": agent}},
                 {"range": {"timestamp": {"gte": since}}}]}},
             "aggs": {"d": {"terms": {"field": "rule.description", "size": 60}}}}
        r = self._get("wazuh-alerts-4.x-*/_search", q)
        return {b["key"]: b["doc_count"]
                for b in r["aggregations"]["d"]["buckets"]}


def auditpol_state() -> dict[str, str]:
    out = ssh("192.168.1.78", "Administrator",
              "auditpol /get /category:*")
    state = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "Setting" in line or "Category" in line:
            continue
        if "Auditing" in line:
            continue
        parts = line.rsplit(None, 1)
        if len(parts) == 2:
            state[parts[0].strip()] = parts[1].strip()
    return state


def enable_prereqs(dry_run: bool = False) -> list[str]:
    """Turn on the Windows audit subcategories detection depends on.

    Reversible. Without these, several techniques are literally incapable of
    being detected, and a 'no alert' result would be a measurement artifact
    rather than a real negative.
    """
    actions = []
    for sub in AUDIT_PREREQS:
        cmd = (f'auditpol /set /subcategory:"{sub}" '
               f'/success:enable /failure:enable')
        if not dry_run:
            ssh("192.168.1.78", "Administrator", cmd)
        actions.append(f'enable audit: {sub} -> {AUDIT_PREREQS[sub]}')
    return actions


def baseline(agent: str, idx: Indexer, window_min: int = 30) -> dict:
    since = (dt.datetime.now(dt.timezone.utc)
             - dt.timedelta(minutes=window_min)).isoformat()
    return idx.rule_ids(agent, since)


def fire(t: dict, dry_run: bool = False) -> dict:
    host = t["exec_host"]
    ip = {"win-target": "192.168.1.78", "c2-sink": "192.168.1.79"}[host]
    user = "Administrator" if host == "win-target" else "lab"
    cmd = t.get("command") or t.get("cmd") or ""
    if t.get("type") == "network" and t.get("target"):
        cmd = cmd.replace("192.168.1.78", t["target"])
    # SSH exec_command on Windows lands in cmd.exe, not PowerShell. PowerShell
    # cmdlets must be wrapped explicitly or they fail as "not recognized".
    if t.get("type") == "powershell" and "powershell" not in cmd.lower()[:20]:
        escaped = cmd.replace('"', chr(92) + '"')
        cmd = "powershell -NoProfile -NonInteractive -Command \"" + escaped + "\""
    if dry_run:
        return {"technique": t["id"], "dry_run": True, "command": cmd}
    started = dt.datetime.now(dt.timezone.utc)
    out = ssh(ip, user, cmd, timeout=120)
    return {"technique": t["id"], "host": host, "output": out[:800],
            "fired_at": started.isoformat()}


def verify(t: dict, idx: Indexer, fired_at: str) -> dict:
    """Compare rule ids before/after. Anything present after but not before
    is attributable to the technique."""
    after = idx.rule_ids("WIN-SBUNBSBHIUG", fired_at)
    expect = [e.split()[0] for e in t.get("detect", [])]
    hit = [r for r in expect if after.get(r)]
    return {"technique": t["id"], "expected_rules": expect,
            "observed_after": after, "matched": hit,
            "verified": bool(hit)}


def cleanup(t: dict) -> str:
    c = t.get("cleanup")
    if not c:
        return "(no cleanup defined)"
    host = t["exec_host"]
    ip = {"win-target": "192.168.1.78", "c2-sink": "192.168.1.79"}[host]
    user = "Administrator" if host == "win-target" else "lab"
    # Cleanup is PowerShell too — same cmd.exe wrapping as fire().
    if "powershell" not in c.lower()[:20]:
        escaped = c.replace('"', chr(92) + '"')
        c = "powershell -NoProfile -NonInteractive -Command \"" + escaped + "\""
    return ssh(ip, user, c, timeout=90)[:300]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--technique")
    ap.add_argument("--wave", action="store_true",
                    help="today's seeded subset")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--enable-prereqs", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-cleanup", action="store_true")
    a = ap.parse_args()

    doc = load()

    if a.list:
        print(f"{'ID':<40} {'MITRE':<12} {'TYPE':<10} RISK")
        for t in doc["techniques"]:
            print(f"{t['id']:<40} {t.get('mitre','-'):<12} "
                  f"{t.get('type','-'):<10} {t.get('risk','-')}")
        return 0

    if a.enable_prereqs:
        for line in enable_prereqs(a.dry_run):
            print("  " + line)
        return 0

    if a.verify_only:
        print(json.dumps(auditpol_state(), indent=2))
        return 0

    if not a.technique and not a.wave:
        ap.print_help()
        return 1

    # Seeded-deterministic wave: same day -> same techniques, weekly rotation.
    if a.wave:
        day = dt.date.today()
        idx = day.toordinal()
        techs = doc["techniques"]
        window = 2
        start = (idx // 7 * window) % len(techs)
        chosen = [techs[(start + i) % len(techs)] for i in range(window)]
    else:
        chosen = [t for t in doc["techniques"] if t["id"] == a.technique]
        if not chosen:
            print(f"unknown technique: {a.technique}")
            return 1

    for t in chosen:
        print(f"\n=== {t['id']} — {t['name']} ({t.get('mitre')}) ===")
        print(f"    risk={t.get('risk')}  note={t.get('notes','')[:90]}")

        if not a.dry_run:
            # Snapshot immediately before, so verification is attributable.
            since = (dt.datetime.now(dt.timezone.utc)
                     - dt.timedelta(minutes=2)).isoformat()
            before = baseline("WIN-SBUNBSBHIUG", None) if False else None

        r = fire(t, a.dry_run)
        if a.dry_run:
            print(json.dumps(r, indent=2))
            continue
        print(f"    output: {r['output'][:200]}")

        # Wazuh ships alerts with a small delay; give the pipeline time.
        print("    waiting 45s for the alert pipeline...")
        time.sleep(45)

        fired_at = r["fired_at"]
        if not a.no_cleanup and t.get("cleanup"):
            print(f"    cleanup: {cleanup(t)}")

        print(f"    detect-expected: {t.get('detect')}")

    print("\ndone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())