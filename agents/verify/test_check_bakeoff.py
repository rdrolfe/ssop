#!/usr/bin/env python3
"""Non-vacuity test for the bake-off parity gate.

Proves verify/check_bakeoff is NON-VACUOUS without touching the live SO
store: it monkeypatches the capture/score subprocess runner to a no-op,
pre-seeds /tmp JSON files with controlled scenarios, and asserts the gate:
  - baseline 12/12                -> 0 problems (parity holds)
  - SO axis-1 drops to 1 (the real
    category-backfill regression) -> caught
  - console axis-3 drops to 1      -> caught
  - empty SO store (seed not
    published)                     -> caught (fail-closed)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verify.check_bakeoff as cb  # noqa: E402

CAP = "/tmp/bakeoff_capture.json"
SCORES = "/tmp/bakeoff_scores.json"


def _axes(overrides: dict) -> list[dict]:
    """Six healthy axes, with the given (axis->(console,so)) overrides."""
    names = {1: "Ontology fidelity", 2: "Agent-fact transparency",
             3: "Negative-outcome clarity", 4: "Case compilation",
             5: "Retention/queryability", 6: "Report readiness"}
    out = []
    for a in range(1, 7):
        cs, so = overrides.get(a, (2, 2))
        out.append({"axis": a, "axis_name": names[a], "console": cs, "so": so,
                    "console_note": f"axis {a} note", "so_note": f"axis {a} note"})
    return out


def _write(cap: dict, axes: list[dict]) -> None:
    Path(CAP).write_text(json.dumps(cap))
    Path(SCORES).write_text(json.dumps({"case_id": "case-26b166ce32", "axes": axes}))


def _healthy_cap() -> dict:
    return {
        "so_native_case_store": [{"operation": "create"}, {"operation": "comment"}],
        "wazuh_console_api": {"ok": True, "case": {"case_id": "case-26b166ce32"}},
    }


def main() -> int:
    # no-op the subprocess runners (the test owns the /tmp state)
    cb._run = lambda *a, **k: (0, "")  # type: ignore[assignment]
    fails = 0

    # baseline: 12/12 -> no problems
    _write(_healthy_cap(), _axes({}))
    probs = cb.check_bakeoff()
    print(f"baseline: {len(probs)} problems")
    if probs:
        fails += 1
        for p in probs:
            print("  ", p)

    # 1. SO axis-1 regression (the category gap we fixed) -> caught
    _write(_healthy_cap(), _axes({1: (2, 1)}))
    probs = cb.check_bakeoff()
    caught = any("axis 1" in p for p in probs)
    print(f"SO axis-1 drop: {len(probs)} problems, axis-1 caught={caught}")
    if not caught:
        fails += 1

    # 2. console axis-3 regression -> caught
    _write(_healthy_cap(), _axes({3: (1, 2)}))
    probs = cb.check_bakeoff()
    caught = any("axis 3" in p for p in probs)
    print(f"console axis-3 drop: {len(probs)} problems, axis-3 caught={caught}")
    if not caught:
        fails += 1

    # 3. fail-closed: empty SO store (seed not published) -> caught
    _write({"so_native_case_store": [], "wazuh_console_api": {"ok": True}}, _axes({}))
    probs = cb.check_bakeoff()
    caught = any("0 SO ops" in p for p in probs)
    print(f"empty SO store: {len(probs)} problems, fail-closed caught={caught}")
    if not caught:
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
