"""Lab gate: real-technique traffic must never escalate or tune production.

Written 2026-10-05 after rule 60154 minted a tier-2 escalation from lab traffic
twice: once before the gate existed, and once more while it was being written
(the second time because tools/analyst_tools.py was missing from
deploy_runtime.sh's TRACKED list, so the gate never reached the runtime).

These assert the decision itself, not that a deploy happened.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agents"))

from tools.ontology import is_lab_traffic, lab_tuning_forbidden, is_drill_replay

FAILED = []


def check(name, cond, detail=""):
    if cond:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name} {detail}")
        FAILED.append(name)


def main():
    print("lab gate: detection surface")
    check("label identifies lab traffic",
          is_lab_traffic({"agent": {"name": "anywhere"},
                          "data": {"ssop_lab": "real-technique"}}))
    check("host identifies lab traffic",
          is_lab_traffic({"agent": {"name": "WIN-SBUNBSBHIUG"}, "data": {}}))
    check("real host is not lab",
          not is_lab_traffic({"agent": {"name": "we8105desk.waynecorpinc.local"},
                              "data": {}}))
    check("foreign label is not lab",
          not is_lab_traffic({"agent": {"name": "we8105desk.waynecorpinc.local"},
                              "data": {"ssop_lab": "something-else"}}))
    check("malformed alert does not raise",
          is_lab_traffic({"agent": "not-a-dict", "data": "not-a-dict"}) is False)

    print("lab gate: escalation + tuning")
    lab = {"agent": {"name": "WIN-SBUNBSBHIUG"}, "data": {},
           "rule": {"id": "60154", "level": 12,
                    "description": "Administrators Group Changed"}}
    check("lab traffic is tuning-forbidden", lab_tuning_forbidden(lab))
    check("real traffic is not tuning-forbidden",
          not lab_tuning_forbidden({"agent": {"name": "we8105desk.waynecorpinc.local"},
                                    "data": {}}))

    print("lab gate: lab alerts are NOT drill replays")
    drill, _ = is_drill_replay(lab)
    check("lab alert is not a drill replay", drill is False)
    d2, _ = is_drill_replay({"id": "atomic-1", "agent": {"name": "x"}, "data": {}})
    check("atomic replay still gated as drill", d2 is True)

    print("lab gate: deploy coverage")
    deploy = (ROOT / "deploy" / "deploy_runtime.sh").read_text()
    for f in ("tools/analyst_tools.py", "tools/tuning_tools.py", "tools/ontology.py"):
        check(f"deploy_runtime.sh tracks {f}", f in deploy)

    print("lab gate: invariant gate is wired")
    runner = (ROOT / "deploy" / "lab" / "run_techniques.py").read_text()
    for needle, label in [
        ("--assert-invariants", "gate has a CLI flag"),
        ("def assert_invariants", "gate function defined"),
        ("total_tier2_plus", "gate asserts zero escalations"),
        ("tuning_delta", "gate asserts zero ledger growth"),
        ("analyst_events", "gate asserts the analyst recorded something"),
    ]:
        check(label, needle in runner)
    # The wildcard-index trap: ssop-cases* / ssop-tuning* do not exist and
    # return 0 docs without erroring, which reads as a passing gate.
    check("gate does not query the non-existent ssop-cases index",
          "ssop-cases*/_search" not in runner)
    check("gate does not query the non-existent ssop-tuning index",
          "ssop-tuning*/_search" not in runner)

    if FAILED:
        print(f"\nLAB GATE SUITE: FAIL ({len(FAILED)})")
        return 1
    print("\nLAB GATE SUITE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
