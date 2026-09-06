#!/usr/bin/env python3
"""Non-vacuity test: the persisted investigation carries the FULL detail.

The writeup-quality fix persists entity + sources + sources_engaged +
evidence_count + severity + severity_label + kill_chain on the investigation
event — a case whose investigation omits these renders hollow in the
report/advisory (\"Entity `None` engaged\"). This proves _persist_investigation
(shared by the analyst + router mint paths) writes the whole shape.

Monkeypatches the Investigator class so no live store is touched.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# A fake investigator result (the shape investigate() returns).
_FAKE_RESULT = {
    "entities": ["192.168.250.100"],
    "evidence": [{"source": "http", "label": "x"}, {"source": "dns"}],
    "kill_chain": ["EXFILTRATION: HTTP upload/exfil traffic [T1041, T1048.003]",
                   "C2: DNS queries/tunneling [T1071.004, T1572]"],
    "hypothesis": "Entity 192.168.250.100 engaged across 2 source(s): dns, http.",
    "correlated_sources": ["dns", "http"],
    "severity": 5.1,
    "severity_label": "high",
}


def _run() -> dict:
    """Run _persist_investigation against a fake Investigator; return the
    investigation detail dict (empty if not written)."""
    import types
    from analyst import _persist_investigation

    # Fake the tools.investigator.Investigator module.
    fake_inv_cls = type("Investigator", (), {"investigate": lambda self, **kw: _FAKE_RESULT})
    fake_mod = types.ModuleType("investigator")
    fake_mod.Investigator = fake_inv_cls  # type: ignore[attr-defined]
    sys.modules["tools.investigator"] = fake_mod

    captured = {}

    class FakeCases:
        def append_event(self, case_id, role, etype, detail):
            captured["detail"] = detail

    _persist_investigation(FakeCases(), "case-test", {"data": {"srcip": "192.168.250.100"}}, [])
    return captured.get("detail", {})


def main() -> int:
    fails = 0
    detail = _run()

    # Every field the report/advisory/supervisor read must be present.
    required = {
        "entity": "192.168.250.100",
        "entities": ["192.168.250.100"],
        "sources": ["dns", "http"],
        "sources_engaged": 2,
        "evidence_count": 2,
        "severity": 5.1,
        "severity_label": "high",
        "hypothesis": _FAKE_RESULT["hypothesis"],
        "kill_chain": _FAKE_RESULT["kill_chain"],
        "evidence": _FAKE_RESULT["evidence"],
    }
    missing = []
    for k, v in required.items():
        if detail.get(k) != v:
            missing.append(f"{k}={detail.get(k)!r} (want {v!r})")
    print(f"detail keys: {sorted(detail.keys())}")
    if missing:
        fails += 1
        for m in missing:
            print(f"  MISSING/mismatch: {m}")

    # Hollow guard: entity must not be None when the investigation found one.
    if detail.get("entity") in (None, ""):
        fails += 1
        print("  entity is None/empty — hollow render")

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
