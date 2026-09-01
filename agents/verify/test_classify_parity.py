#!/usr/bin/env python3
"""Non-vacuity parity test: analyst verdict and router classify MUST agree.

The Sep 2026 dpkg flood root cause was the two classifiers (analyst_tools
vs router) deriving category independently and drifting — a tuned-FP rule
could be treated differently depending on which path touched it. The fix:
both derive from tools.ontology.categorize_alert (single source of truth).

This test locks the invariant:
  - same alert -> same ontology category from BOTH the analyst classify and
    the shared categorizer (catches a re-introduced local heuristic)
  - a tuned-FP alert -> analyst verdict "note" AND router classify
    (operational, None) — both suppress, consistently
  - a tuned-FP alert carrying a threat-desc token -> BOTH lift the tuning
    (analyst escalate w/ tuning_override, router dispatches) — the
    clear-exception path is symmetric
  - a high-severity attack-category alert on a tuned rule -> both override
    (severity leg, config-driven allowlist)

Uses a fake TuningLedger.lookup — no Qdrant, hermetic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.analyst_tools import AnalystClient  # noqa: E402
from tools.ontology import categorize_alert  # noqa: E402
import tools.tuning_tools as tt  # noqa: E402

# Tuned-FP rules: 2902 (dpkg), 550 (integrity checksum), 86601 (generic suricata)
_TUNED: dict[str, dict] = {
    "2902": {"decision": "auto_fp", "rationale": "human: routine package mgmt", "source": "human"},
    "550": {"decision": "auto_fp", "rationale": "human: integrity drift, host clean", "source": "human"},
    "86601": {"decision": "auto_fp", "rationale": "human: generic suricata noise", "source": "human"},
}


def _fake_lookup(rule_id: str):
    return _TUNED.get(str(rule_id))


def _mk(rule_id: str, level: int, desc: str, groups: list[str]) -> dict:
    return {"rule": {"id": rule_id, "level": level, "description": desc, "groups": groups}}


def main() -> int:
    # Inject the fake ledger (both analyst and router call TuningLedger()).
    tt.TuningLedger.lookup = staticmethod(_fake_lookup)  # type: ignore[assignment]
    fails = 0
    a = AnalystClient()

    cases = [
        # (name, alert, expect_note_both, expect_override_both)
        ("dpkg 2902 lvl7 (tuned)", _mk("2902", 7, "New dpkg (Debian Package) installed.", ["syscheck"]),
         True, False),
        ("integrity 550 lvl7 (tuned)", _mk("550", 7, "Integrity checksum changed.", ["syscheck", "fim"]),
         True, False),
        ("generic suricata 86601 lvl7 (tuned)", _mk("86601", 7, "Suricata alert.", ["ids", "suricata"]),
         True, False),
        # threat-desc token on a tuned rule -> clear exception, BOTH lift
        ("et malware on tuned 86601", _mk("86601", 7, "ET MALWARE Sality C2 beacon", ["ids", "suricata"]),
         False, True),
        # high-severity attack-category (authentication) on a tuned rule ->
        # severity leg lifts (authentication in allowlist, threshold 7)
        ("auth fail high on tuned 2902", _mk("2902", 7, "sshd brute-force failure", ["authentication_failed"]),
         False, True),
    ]
    for name, alert, expect_note, expect_override in cases:
        v = a.verdict(alert)
        vd = v["verdict"]
        # router classify: tuning gate -> operational/None means suppressed;
        # anything else means it dispatches (override).
        from router import classify  # noqa: E402
        cat, role = classify(alert)
        routed = not (cat == "operational" and role is None)

        # 1. shared category: analyst's classify must equal the shared source
        c_cat = a.classify(alert)["category"]
        shared = categorize_alert(alert)
        cat_agree = c_cat == shared
        if not cat_agree:
            print(f"[{name}] CATEGORY MISMATCH: analyst={c_cat} shared={shared}")
            fails += 1

        # 2. note-both expectation
        if expect_note:
            ok = vd == "note" and not routed
            print(f"[{name}] verdict={vd} routed={routed} (want note+not routed) -> {'OK' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        # 3. override-both expectation
        elif expect_override:
            ok = vd == "escalate" and routed
            print(f"[{name}] verdict={vd} routed={routed} (want escalate+routed) -> {'OK' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        else:
            print(f"[{name}] no expectation set")

    print("NON-VACUOUS" if fails == 0 else f"{fails} PARITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
