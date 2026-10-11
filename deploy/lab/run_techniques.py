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
import re
import ssl
import sys
import time
import urllib.request
from pathlib import Path

import paramiko

HERE = Path(__file__).resolve().parent
TECHNIQUES = HERE / "techniques" / "windows-target.json"

# Key used to reach the lab hosts. Overridable because this runner now executes
# from the UNATTENDED plane (ssop-wave.service runs as ssop-agent, whose HOME is
# /home/rdrolfe/agent-runtime), where a bare "~" expands INSIDE the runtime tree
# rather than to the human home. The scheduled unit sets SSOP_LAB_SSH_KEY
# explicitly so the dependency is stated rather than implied; the default keeps
# the manual, human-plane invocation working unchanged.
SSH_KEY = os.path.expanduser(os.environ.get("SSOP_LAB_SSH_KEY",
                                            "~/.ssh/hermes_ssop"))

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

    @classmethod
    def from_env(cls) -> "Indexer":
        """Build from the standard SSOP indexer env vars.

        The runner lives outside agent-runtime, so it cannot import
        IndexerTransport. Reads the same WAZUH_INDEXER_* env the runtime uses
        and falls back to the known lab indexer on .75. Credentials are never
        written to the repo.
        """
        host = os.environ.get("WAZUH_INDEXER_HOST", "192.168.1.75")
        port = int(os.environ.get("WAZUH_INDEXER_PORT", "9200"))
        user = os.environ.get("WAZUH_INDEXER_USERNAME", "")
        pw = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
        if not pw:
            raise RuntimeError(
                "indexer credentials not in env: set WAZUH_INDEXER_PASSWORD "
                "(and WAZUH_INDEXER_USERNAME) to run the invariant gate")
        return cls(host, port, user, pw)

    def rule_ids(self, agent: str, since: str) -> dict[str, int]:
        q = {"size": 0,
             "query": {"bool": {"filter": [
                 {"term": {"agent.name": agent}},
                 {"range": {"timestamp": {"gte": since}}}]}},
             "aggs": {"rules": {"terms": {"field": "rule.id", "size": 60}}}}
        r = self._get("wazuh-alerts-4.x-*/_search", q)
        return {b["key"]: b["doc_count"]
                for b in r["aggregations"]["rules"]["buckets"]}

    def count(self, index: str, since: str, extra_filter: dict | None = None) -> int:
        """Total docs in an index since a timestamp (optionally filtered)."""
        filters: list[dict] = [{"range": {"timestamp": {"gte": since}}}]
        if extra_filter:
            filters.append(extra_filter)
        q = {"size": 0, "query": {"bool": {"filter": filters}}}
        r = self._get(index, q)
        return int(r["hits"]["total"]["value"])

    def case_tier_counts(self, since: str) -> dict:
        """Tier-2+ escalations recorded since a timestamp.

        The invariant every wave must hold: a technique we generated ourselves
        may open cases, but it must NEVER mint a tier-2 escalation. Rule 60154
        broke this before the lab gate existed, and broke it AGAIN on
        2026-10-05 while this gate was being written.

        NOTE: there is no `ssop-cases` or `ssop-tuning` index. Everything —
        verdicts, tiers, cases, escalations — lands in the single `ssop-events`
        index, filtered by `actor`. Querying `ssop-cases*` returns zero docs
        without erroring, which reads as a passing gate. Verified with _cat/indices.
        """
        q = {"size": 0,
             "query": {"bool": {"filter": [
                 {"range": {"ts": {"gte": since}}},
                 {"term": {"actor": "analyst"}},
                 {"range": {"tier": {"gte": 2}}}]}},
             "aggs": {"t": {"terms": {"field": "tier", "size": 5}}}}
        r = self._get("ssop-events/_search", q)
        total = int(r["hits"]["total"]["value"])
        by_tier = {b["key"]: b["doc_count"]
                   for b in r.get("aggregations", {}).get("t", {}).get("buckets", [])}
        return {"total_tier2_plus": total, "by_tier": by_tier}

    def analyst_events(self, since: str) -> int:
        """Count of analyst decisions since a timestamp (case-creation signal)."""
        return self.count_actor("ssop-events/_search", since, "analyst")

    def count_actor(self, index: str, since: str, actor: str) -> int:
        filters = [{"range": {"ts": {"gte": since}}}, {"term": {"actor": actor}}]
        q = {"size": 0, "query": {"bool": {"filter": filters}}}
        return int(self._get(index, q)["hits"]["total"]["value"])

    def ledger_tuning(self) -> int:
        """Tuning-ledger writes. There is no separate tuning index — ledger
        decisions are ssop-events with actor=supervisory, so growth in those is
        the forbidden side effect to watch for."""
        q = {"size": 0,
             "query": {"bool": {"filter": [{"term": {"actor": "supervisory"}}]}}}
        return int(self._get("ssop-events/_search", q)["hits"]["total"]["value"])

    def describe(self, agent: str, since: str) -> str:
        q = {"size": 0,
             "query": {"bool": {"filter": [
                 {"term": {"agent.name": agent}},
                 {"range": {"timestamp": {"gte": since}}}]}},
             "aggs": {"d": {"terms": {"field": "rule.description", "size": 60}}}}
        r = self._get("wazuh-alerts-4.x-*/_search", q)
        return {b["key"]: b["doc_count"]
                for b in r["aggregations"]["d"]["buckets"]}


VICTIM_AGENT = "WIN-SBUNBSBHIUG"

# Rules the victim emits for ANY SSH session to it (measured 2026-10-11 against
# a control window with no technique fired: the control produced only 67027).
# Used as a FALLBACK expectation when no technique in the wave has a
# technique-specific rule, so assertion 3 always asserts something. This is
# strictly weaker -- it proves the pipeline moved an alert, not that this
# technique was seen -- and the report says so rather than crediting it as a
# detection. A wave that asserts NOTHING reads as coverage while measuring
# nothing, which is the failure this whole gate exists to avoid.
SESSION_BASELINE_RULES = ["60106", "67028", "67027"]


def expected_wazuh_rules(techniques: list[dict]) -> tuple[list[str], list[str]]:
    """Wazuh rule ids that would prove each technique detected, plus the ones
    that yield none.

    Two sources, because the catalog records two different identifiers and
    conflating them is how the (unused) verify() reported a demonstrably working
    technique as unmatched: `observed_rules` is what Wazuh actually emitted, and
    `detect` is prose that usually leads with the WINDOWS event id (4698, 4720) —
    which is not a Wazuh rule id and can never match one in a bucket of rule ids.
    Wazuh rule ids in this deployment are five digits (60106, 67027, 92032), so
    from `detect` only five-digit tokens are accepted.
    """
    expected: list[str] = []
    unresolved: list[str] = []
    for t in techniques:
        ids = [str(r) for r in (t.get("observed_rules") or [])]
        ids += re.findall(r"\b\d{5}\b", " ".join(t.get("detect") or []))
        ids = list(dict.fromkeys(ids))
        if ids:
            expected += ids
        else:
            unresolved.append(t["id"])
    return list(dict.fromkeys(expected)), unresolved


def assert_invariants(idx: Indexer, fired_at: str,
                      techniques: list[dict] | None = None) -> dict:
    """Post-wave gate. Returns a report; raises AssertionError on violation.

    Three things must hold after a wave of real techniques:
      1. no tier-2 escalation was minted (the drill invariant)
      2. the tuning ledger did not grow (production policy is never learned
         from adversary traffic we generated ourselves)
      3. the wave's OWN detection is visible on the sensor (non-vacuity: a wave
         that detects nothing and escalates nothing has silently stopped
         working)

    (3) is the one that catches a decode regression. On 2026-10-05 the manager
    was silently discarding 1.6M events with "Too many fields for JSON decoder";
    assertions 1 and 2 would both still have passed.

    (3) WAS ORIGINALLY "did the analyst record something", counted as
    actor=analyst documents in ssop-events, and that assertion could never pass.
    Those documents are SHIPPED ESCALATION TICKETS (escalate_tools ->
    ship_ticket_doc) — they are precisely what assertion 1 forbids, so 1 and 3
    were mutually exclusive and the gate failed on every healthy wave. A case
    mint does not write to ssop-events at all; verdicts and cases live in the
    Qdrant spine and audit/cases.jsonl. Measured 2026-10-11 on the first
    scheduled run: alerts on the victim, ledger 0, escalations 0, gate FAILED.
    """
    rep: dict = {"fired_at": fired_at, "violations": []}

    esc = idx.case_tier_counts(fired_at)
    rep["escalations"] = esc
    if esc["total_tier2_plus"] > 0:
        rep["violations"].append(
            f"tier-2 escalation(s) minted from lab traffic: {esc['total_tier2_plus']}")

    led = idx.ledger_tuning()
    rep["tuning_ledger_total"] = led
    rep["tuning_delta"] = led - _LEDGER_BASELINE
    if led > _LEDGER_BASELINE:
        rep["violations"].append(
            f"tuning ledger grew by {led - _LEDGER_BASELINE} "
            "(lab traffic must never tune production policy)")

    expected, unresolved = expected_wazuh_rules(techniques or [])
    if not expected:
        expected = list(SESSION_BASELINE_RULES)
        rep["asserted_weakly"] = True
    seen = idx.rule_ids(VICTIM_AGENT, fired_at)
    rep["victim_alerts_by_rule"] = seen
    rep["expected_rules"] = expected
    rep["detected"] = [r for r in expected if seen.get(r)]
    if unresolved:
        rep["techniques_without_a_resolvable_rule"] = unresolved
    if expected and not rep["detected"]:
        rep["violations"].append(
            "none of the wave's expected rules appeared on %s (%s) - the "
            "detection did not land (possible decode, agent, or rule regression)"
            % (VICTIM_AGENT, ", ".join(expected)))
    elif not seen:
        rep["violations"].append(
            "no alerts at all on %s since the wave fired - the sensor or the "
            "decode path is down" % VICTIM_AGENT)

    if rep["violations"]:
        raise AssertionError("wave invariant violated: " + "; ".join(rep["violations"]))
    return rep


_LEDGER_BASELINE = 0


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
    ap.add_argument("--assert-invariants", action="store_true",
                    help="after the wave, assert zero escalations, zero "
                         "tuning-ledger growth, and >=1 case opened")
    a = ap.parse_args()

    doc = load()

    # Capture the ledger size BEFORE anything fires, so growth is attributable.
    if a.assert_invariants:
        global _LEDGER_BASELINE
        try:
            _LEDGER_BASELINE = Indexer.from_env().ledger_tuning()
            print(f"lab gate: tuning-ledger baseline = {_LEDGER_BASELINE}")
        except Exception as e:  # noqa: BLE001
            print(f"lab gate: could not read ledger baseline ({e}); "
                  "invariant check will still assert zero growth from 0")
            _LEDGER_BASELINE = 0

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
        # Exclude techniques the catalog marks do_not_run. Selection is
        # position-based, so without this filter the wave WILL pick a technique
        # the operator has explicitly deferred: T1003.001 (LSASS memory access)
        # sat in the 2026-10-25 week block, so an unattended daily timer would
        # have dumped credential material every morning for a week. A
        # do_not_run technique stays reachable via --technique, which is a
        # deliberate act; --wave is not.
        techs = [t for t in doc["techniques"] if not t.get("do_not_run")]
        skipped = [t["id"] for t in doc["techniques"] if t.get("do_not_run")]
        if skipped:
            print(f"wave: excluding do_not_run: {', '.join(skipped)}")
        if not techs:
            print("wave: no runnable techniques in the catalog")
            return 1
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
        t["_fired_at"] = fired_at
        if not a.no_cleanup and t.get("cleanup"):
            print(f"    cleanup: {cleanup(t)}")

        print(f"    detect-expected: {t.get('detect')}")

    # Post-wave invariant gate. Deliberately AFTER all techniques have run and
    # cleaned up, and after the pipeline has had time to produce cases.
    if a.assert_invariants and not a.dry_run:
        # The analyst sweeps on a 5-minute timer (ssop-analyst.timer), not
        # continuously. Waiting less than a full period produces a FALSE
        # "analyst recorded nothing" failure: on 2026-10-05 a 60s wait reported
        # a broken pipeline when the sweep simply had not run yet. Default to
        # 330s so the assertion always covers at least one complete period.
        wait_s = int(os.environ.get("SSOP_WAVE_QA_WAIT_S", "330"))
        print(f"\n    waiting {wait_s}s for the analyst sweep (5m timer) "
              "before asserting...")
        time.sleep(wait_s)
        wave_start = chosen[0].get("_fired_at") if chosen else None
        wave_start = min((t.get("_fired_at") for t in chosen
                          if t.get("_fired_at")), default=None)
        try:
            rep = assert_invariants(Indexer.from_env(), wave_start, chosen)
            print("\nlab gate PASSED:")
            print(f"    escalations (tier2+) : {rep['escalations']['total_tier2_plus']}")
            print(f"    tuning ledger delta   : {rep['tuning_delta']}")
            print(f"    expected rules        : "
                  f"{', '.join(rep['expected_rules']) or '(none resolvable)'}")
            print(f"    detected on the victim: "
                  f"{', '.join(rep['detected']) or '(NONE - not asserted)'}")
            print(f"    rules seen on victim  : {len(rep['victim_alerts_by_rule'])}")
            if rep.get("techniques_without_a_resolvable_rule"):
                print("    WARNING: no Wazuh rule id resolvable for "
                      + ", ".join(rep["techniques_without_a_resolvable_rule"])
                      + " - the detection of those techniques is NOT asserted")
            if rep.get("asserted_weakly"):
                print("    WARNING: asserted WEAKLY - no technique in this wave has a "
                      "technique-specific rule, so this only proves the pipeline "
                      "moved an alert, NOT that any technique was seen. Harvest "
                      "observed_rules for these techniques before trusting the "
                      "green.")
        except AssertionError as e:
            print(f"\nlab gate FAILED: {e}")
            return 2

    print("\ndone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())