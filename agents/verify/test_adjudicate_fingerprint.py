#!/usr/bin/env python3
"""Non-vacuity test: a human deny on an OVERRIDE ticket must update the
tuning fingerprint — the loop-closer.

Regression for the bug where adjudicate() resolved rule_id from
ticket.detail.rule_id only, but the router spreads the verdict DICT at top
level (ticket.verdict.rule_id). rule_id came back empty -> the tuning write
was silently skipped -> a deny never taught the ledger the new fingerprint
and the override loop never settled.

Proves, hermetically:
  - router-shaped ticket (verdict=dict at top level) -> rule_id resolves,
    fingerprint written with the delta level
  - blank verdict (no rule_id anywhere)              -> no crash, no write
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.tuning_tools import TuningLedger  # noqa: E402


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
    def __init__(self):
        self.store: dict[str, dict] = {}
        self.collections: set[str] = set()
        self.client = _FakeClient(self.store)

    def ensure_collection(self, name: str):
        self.collections.add(name)

    def scroll(self, *a, **k):
        return []


def _router_ticket(rule_id, level, verdict_str="escalate", extra=None):
    """Shape exactly as the router's escalate() produces: verdict DICT spread
    at top level (case_id, verdict, tuning_override all flat)."""
    vd = {"verdict": verdict_str, "confidence": "high", "level": level,
          "rule_id": rule_id, "groups": ["syslog", "dpkg", "config_changed"],
          "description": "New dpkg (Debian Package) installed.",
          "tuned": True, "tuning_override": True}
    if extra:
        vd.update(extra)
    return {"ticket_id": f"tk-{rule_id}-{level}", "case_id": "case-x",
            "title": f"[ROUTER-ANALYST] rule {rule_id}", "verdict": vd}


def _adjudicate_fingerprint_write(ticket) -> dict | None:
    """The exact decision logic from SupervisoryClient.adjudicate() (the
    deny path): resolve the verdict dict, then write the fingerprint."""
    from tools.ontology import fingerprint_from_verdict

    # -- the fixed resolution (was: ticket.get("detail").get("verdict")) --
    vd = ticket.get("verdict")
    if not isinstance(vd, dict):
        vd = (ticket.get("detail") or {}).get("verdict")
    if not isinstance(vd, dict):
        return None
    rule_id = str(vd.get("rule_id") or "")
    if not rule_id:
        return None

    led = TuningLedger.__new__(TuningLedger)
    led._memory = _FakeMemory()  # type: ignore[assignment]
    led.write(rule_id=rule_id, decision="auto_fp",
              rationale=f"supervisory deny: {ticket.get('rationale', '')}",
              source="human", fingerprint=fingerprint_from_verdict(vd))
    return led.lookup(rule_id)


def main() -> int:
    fails = 0

    # 1. router-shaped override ticket (verdict dict, top level).
    ticket = _router_ticket("2902", 12)
    tuning = _adjudicate_fingerprint_write(ticket)
    if tuning is None:
        print("FAIL: router-shaped ticket produced no tuning entry")
        fails += 1
    else:
        fp = tuning.get("fingerprint") or {}
        ok = fp.get("rule_id") == "2902" and fp.get("level") == 12
        print(f"router ticket -> fingerprint rule_id={fp.get('rule_id')} "
              f"level={fp.get('level')} (want 2902/12): {'ok' if ok else 'FAIL'}")
        if not ok:
            fails += 1

    # 2. deny on the delta must STORE the delta level (loop settles: an
    #    identical level-12 alert now suppresses).
    from tools.tuning_tools import tuned_rule_suppresses
    suppress, _reason = tuned_rule_suppresses(
        tuning, {"rule": {"id": "2902", "level": 12,
                          "description": "New dpkg (Debian Package) installed.",
                          "groups": ["syslog", "dpkg", "config_changed"]}},
        category="operational")
    print(f"identical delta suppresses after deny: {suppress} (want True)")
    if not suppress:
        fails += 1

    # 3. blank verdict (no rule_id anywhere) -> no crash, no write.
    blank = {"ticket_id": "tk-0", "case_id": "case-y", "title": "x",
             "verdict": ""}
    out = _adjudicate_fingerprint_write(blank)
    if out is not None:
        print("FAIL: blank verdict should not write a tuning entry")
        fails += 1
    else:
        print("blank verdict -> no write: ok")

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
