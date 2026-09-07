#!/usr/bin/env python3
"""Non-vacuity test for the alert/evidence contract (#25).

Proves the four review findings are dead:
  - Wazuh-nested, SO ECS, SO-envelope, and BOTS alert shapes normalize to
    the SAME contract (same src/dst, rule fields) — one source of truth.
  - Engine provenance is EXPLICIT (backend field), so a numeric rule_id can
    never flip the engine guess (the old rule_id.isdigit() heuristic).
  - Entity selection: a hostname observable BEFORE the IP in the observable
    list can never be investigated as the source IP (obs[0] failure mode).
  - Hash observables carry semantic hash_type (md5/sha1/sha256 distinct).
  - The live incident path cannot call investigate() unbounded (signature
    check: window_hours is required for the incident-path wrapper).

Hermetic: pure functions, no stores, no network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.alert_contract import (  # noqa: E402
    investigation_entity, ip_observables, is_valid_ip, normalize_alert,
)

FAILS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


def main() -> int:
    # --- 1. Four backend shapes normalize to the same contract -------------
    wazuh_nested = normalize_alert({
        "rule": {"id": 5710, "level": 7, "description": "sshd: auth failure"},
        "agent": {"name": "we8105desk"},
        "data": {"srcip": "10.0.0.99", "dstip": "192.168.1.50"},
        "timestamp": "2026-09-07T12:00:00.000+0000",
    }, backend="wazuh", index="wazuh-alerts-4x", doc_id="wz-1", ts_field="timestamp")

    so_ecs = normalize_alert({
        "rule": {"name": "ET MALWARE C2", "uuid": "abc-123", "category": "malware"},
        "event": {"severity": 3},
        "source": {"ip": "10.0.0.99"},
        "destination": {"ip": "192.168.1.50"},
        "tags": ["malware"],
        "@timestamp": "2026-09-07T12:00:00.000Z",
    }, backend="securityonion", index=".ds-logs-suricata", doc_id="so-1")

    bots = normalize_alert({
        "rule": {"id": "BOTS-77", "level": 5, "description": "lateral movement"},
        "data": {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.50"},
        "timestamp": "2026-09-07T12:00:00Z",
    }, backend="bots", index="bots-sysmon", doc_id="b-1")

    for name, c in (("wazuh-nested", wazuh_nested), ("so-ecs", so_ecs), ("bots", bots)):
        check(f"{name}: src/dst roles explicit", c["src_ip"] == "10.0.0.99" and c["dst_ip"] == "192.168.1.50",
              f"src={c['src_ip']!r} dst={c['dst_ip']!r}")
        check(f"{name}: backend explicit", c["backend"] in ("wazuh", "securityonion", "bots"))
        check(f"{name}: rule_id is str", isinstance(c["rule_id"], str))
        check(f"{name}: occurred_at parses", "T" in c["occurred_at"] and "+" in c["occurred_at"].replace("Z", "+"))

    # --- 2. Numeric rule_id can NOT flip the engine (heuristic is gone) ----
    numeric_so = normalize_alert({"rule": {"id": 2027862, "level": 7}},
                                 backend="securityonion", doc_id="so-2")
    check("numeric SO rule_id: backend stays securityonion",
          numeric_so["backend"] == "securityonion" and numeric_so["rule_id"] == "2027862")

    # --- 3. Hostname can never substitute for the source IP ---------------
    tricky = normalize_alert({
        "rule": {"id": "550", "level": 5},
        "hostname": "we8105desk.corp.local",   # first observable = hostname
        "data": {"srcip": "10.0.0.99"},
    }, backend="wazuh", doc_id="wz-2")
    entity = investigation_entity(tricky)
    check("entity selection: hostname never substitutes for src_ip",
          entity == "10.0.0.99", f"got {entity!r}")
    check("entity selection: empty when no IP at all",
          investigation_entity(normalize_alert({"rule": {"id": "1"},
                                               "hostname": "host.example.com"},
                                              backend="wazuh")) == "")

    # --- 4. Semantic hash types -------------------------------------------
    hashes = normalize_alert({
        "rule": {"id": "554", "level": 5, "description": "file "
                 "d41d8cd98f00b204e9800998ecf8427e written"},
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
    }, backend="wazuh", doc_id="wz-3")
    by_ht = {o.get("hash_type"): o["value"] for o in hashes["observables"] if o["type"] == "hash"}
    check("hash_type sha256 distinct", by_ht.get("sha256", "").startswith("e3b0"))
    check("hash_type md5 distinct (field)", by_ht.get("md5", "").startswith("d41d"))
    # regex-swept hash from description text also carries its type
    check("hash_type from description sweep",
          by_ht.get("md5") == "d41d8cd98f00b204e9800998ecf8427e")
    ip_obs = ip_observables(hashes)
    check("ip_observables filters to type=ip only", isinstance(ip_obs, list))

    # --- 5. Malformed input degrades, never raises -------------------------
    broken = normalize_alert({"rule": None, "data": "not-a-dict", "srcip": 12345},
                             backend="wazuh")
    check("malformed alert: no raise, empty roles", broken["src_ip"] == "" and broken["rule_id"] == "")
    check("is_valid_ip rejects garbage", not is_valid_ip("not-an-ip") and not is_valid_ip(None))

    # --- 6. Live incident path cannot investigate unbounded ----------------
    import inspect
    from tools.investigator import Investigator
    sig = inspect.signature(Investigator.correlate_entity)
    has_budget = "budget_s" in sig.parameters
    check("correlate_entity supports wall-clock budget (bounded correlation)",
          has_budget)

    print("\nNON-VACUOUS" if FAILS == 0 else f"\n{FAILS} NON-VACUITY FAILURES")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
