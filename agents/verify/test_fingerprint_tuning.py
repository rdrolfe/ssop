#!/usr/bin/env python3
"""Non-vacuity test for fingerprint-based tuning (thread #2).

The ledger records the DECISION-RELEVANT signature of the alert a human
tuned (rule_id/groups/level/category/threat-desc). Identical signatures
suppress; only a MATERIAL delta lifts the tuning for re-adjudication.

This test proves the decision helper is non-vacuous:
  - identical fingerprint              -> suppress
  - benign drift (different package
    name, lower level)                 -> suppress (still the tuned class)
  - MATERIAL delta: new attack group   -> override
  - MATERIAL delta: threat-desc token  -> override
  - MATERIAL delta: category -> attack -> override
  - MATERIAL delta: level rose         -> override
  - legacy entry WITHOUT a fingerprint -> falls back to the strong-TP gate
    (config-driven: integrity at lvl 7 suppresses, threat-desc overrides)

Uses TuningLedger directly but monkeypatches the client upsert/retrieve to
an in-memory dict — no Qdrant, hermetic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.tuning_tools import TuningLedger, tuned_rule_suppresses  # noqa: E402


class _FakePoint:
    def __init__(self, payload):
        self.payload = payload


class _FakeClient:
    def __init__(self, store):
        self._store = store

    def retrieve(self, collection_name, ids, with_payload=True):
        return [_FakePoint(self._store[i]) for i in ids if i in self._store]

    def upsert(self, collection_name, points):
        for p in points:
            self._store[str(p.id)] = p.payload
        return None


class _FakeMemory:
    """In-memory stand-in for QdrantMemory (retrieve/upsert/ensure_collection)."""

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.collections: set[str] = set()
        self.client = _FakeClient(self.store)

    def ensure_collection(self, name: str):
        self.collections.add(name)

    def scroll(self, *a, **k):
        return []


def _mk(rule_id, level, desc, groups):
    return {"rule": {"id": rule_id, "level": level, "description": desc, "groups": groups}}


def main() -> int:
    fails = 0
    fake = _FakeMemory()
    led = TuningLedger.__new__(TuningLedger)
    led._memory = fake  # type: ignore[assignment]

    # Baseline tuning for rule 2902 (dpkg install), the flood case.
    seed = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"])
    led.write("2902", "auto_fp", "human: routine package mgmt", source="human",
              fingerprint=None)  # legacy, no fingerprint
    tuning = led.lookup("2902")
    assert tuning is not None
    legacy_suppress, _ = tuned_rule_suppresses(tuning, seed, category="integrity")
    print(f"legacy (no fp) dpkg lvl7 integrity: suppress={legacy_suppress} (want True)")
    if not legacy_suppress:
        fails += 1

    # Re-tune WITH a fingerprint (the thread-#2 path).
    from tools.ontology import fingerprint_from_verdict
    seed_v = {"rule_id": "2902", "groups": ["syscheck"], "level": 7,
              "category": "integrity", "description": "New dpkg (Debian Package) installed."}
    led.write("2902", "auto_fp", "human: routine package mgmt", source="human",
              fingerprint=fingerprint_from_verdict(seed_v))
    tuning = led.lookup("2902")
    assert tuning is not None and tuning.get("fingerprint"), "fingerprint not stored"

    # 1. identical alert -> suppress
    same = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"])
    s, reason = tuned_rule_suppresses(tuning, same, category="integrity")
    print(f"identical dpkg: suppress={s} (want True) — {reason[:60]}")
    if not s:
        fails += 1

    # 2. benign drift: different package name, same groups/level -> suppress
    drift = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"])
    drift["rule"]["description"] = "New dpkg (Debian Package) install: libfoo 1.2.3"
    s, _ = tuned_rule_suppresses(tuning, drift, category="integrity")
    print(f"benign drift (pkg name): suppress={s} (want True)")
    if not s:
        fails += 1

    # 3. MATERIAL: new attack group
    newgrp = _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck", "suricata"])
    s, _ = tuned_rule_suppresses(tuning, newgrp, category="threat")
    print(f"new attack group (suricata): suppress={s} (want False)")
    if s:
        fails += 1

    # 4. MATERIAL: threat-desc token appeared
    threat = _mk("2902", 7, "ET MALWARE Sality (dpkg)", ["syscheck"])
    s, _ = tuned_rule_suppresses(tuning, threat, category="threat")
    print(f"threat-desc token: suppress={s} (want False)")
    if s:
        fails += 1

    # 5. MATERIAL: category became attack (authentication group added)
    auth = _mk("2902", 7, "sshd brute-force failure", ["syscheck", "authentication_failed"])
    s, _ = tuned_rule_suppresses(tuning, auth, category="authentication")
    print(f"category->authentication: suppress={s} (want False)")
    if s:
        fails += 1

    # 6. MATERIAL: level rose
    high = _mk("2902", 12, "New dpkg (Debian Package) installed.", ["syscheck"])
    s, _ = tuned_rule_suppresses(tuning, high, category="integrity")
    print(f"level rose 7->12: suppress={s} (want False)")
    if s:
        fails += 1

    # 7. legacy strong-TP gate still works for entries without a fingerprint:
    #    a tuned integrity rule at lvl 7 with a threat-desc token -> override
    led.write("550", "auto_fp", "human: integrity drift", source="human", fingerprint=None)
    t550 = led.lookup("550")
    assert t550 is not None, "550 tuning lookup failed"
    mal = _mk("550", 7, "ET C2 beacon (checksum)", ["syscheck", "fim"])
    s, _ = tuned_rule_suppresses(t550, mal, category="integrity")
    print(f"legacy gate threat-desc: suppress={s} (want False)")
    if s:
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
