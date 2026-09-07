#!/usr/bin/env python3
"""Non-vacuity test for the bake-off parity gate (engine-in-IRIS form).

Proves verify/check_bakeoff is NON-VACUOUS without touching live IRIS: it
monkeypatches the capture/score subprocess runner to a no-op, pre-seeds
/tmp/iris_*.json with controlled scenarios, and asserts the gate:
  - baseline 12/12                -> 0 problems (parity holds)
  - an axis drops to 1 (the negative-outcome clarity regression) -> caught
  - report axis (6) drops to 1     -> caught
  - seed not published to IRIS (no iris_case_id) -> caught (fail-closed)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verify.check_bakeoff as cb  # noqa: E402

CAP = "/tmp/iris_bakeoff_capture.json"
SCORES = "/tmp/iris_bakeoff_scores.json"


def _axes(overrides: dict) -> list[dict]:
    """Six healthy IRIS axes, with the given (axis->iris) overrides."""
    names = {1: "Ontology fidelity", 2: "Agent-fact transparency",
             3: "Negative-outcome clarity", 4: "Case compilation",
             5: "Retention/queryability", 6: "Report readiness"}
    out = []
    for a in range(1, 7):
        iris = overrides.get(a, 2)
        out.append({"axis": a, "axis_name": names[a], "iris": iris,
                    "note": f"axis {a} note"})
    return out


def _write(cap: dict, axes: list[dict], case_id: str = "case-26b166ce32") -> None:
    Path(CAP).write_text(json.dumps({**cap, "case_id": case_id}))
    Path(SCORES).write_text(json.dumps({"case_id": case_id, "axes": axes}))


def _healthy_cap() -> dict:
    return {"iris_case_id": 33, "timeline": [], "notes": [], "iocs": [],
            "report_spine_markdown": "x" * 300}


def main() -> int:
    # Stubs emulating the REAL lab scripts: capture reads nothing and writes
    # the cap file; score reads the CAP file and writes a scores file with
    # cap's case_id + the axes we last staged in _staged_axes. A static
    # no-op stub breaks with two gated cases sharing /tmp files (the second
    # case's scores would carry the first case's id).
    staged = {"axes": {}}

    def _stub_run(script: str, timeout: int = 120) -> tuple[int, str]:
        if "capture_iris_bakeoff" in script:
            case_id = script.split()[-1]
            cap = _staged_cap(case_id)
            Path(CAP).write_text(json.dumps(cap))
            return 0, ""
        if "score_iris_bakeoff" in script:
            cap = json.loads(Path(CAP).read_text())
            Path(SCORES).write_text(json.dumps(
                {"case_id": cap.get("case_id"), "axes": _axes(staged["axes"])}))
            return 0, ""
        return 0, ""

    def _staged_cap(case_id: str) -> dict:
        return {**(_scenario_cap or _healthy_cap()), "case_id": case_id}

    cb._run = _stub_run  # type: ignore[assignment]
    fails = 0
    _scenario_cap = None

    def write_scenario(axes: dict, cap_override: dict | None = None) -> None:
        """Stage axes + capture overrides for BOTH gated cases."""
        nonlocal _scenario_cap
        staged["axes"] = axes
        _scenario_cap = cap_override

    # baseline: 12/12 across BOTH gated cases -> no problems
    write_scenario({})
    probs = cb.check_bakeoff()
    print(f"baseline: {len(probs)} problems")
    if probs:
        fails += 1
        for p in probs:
            print("  ", p)

    # 1. negative-outcome clarity (axis 3) regression -> caught
    write_scenario({3: 1})
    probs = cb.check_bakeoff()
    caught = any("axis 3" in p for p in probs)
    print(f"axis-3 drop: {len(probs)} problems, axis-3 caught={caught}")
    if not caught:
        fails += 1

    # 2. report readiness (axis 6) regression -> caught
    write_scenario({6: 1})
    probs = cb.check_bakeoff()
    caught = any("axis 6" in p for p in probs)
    print(f"axis-6 drop: {len(probs)} problems, axis-6 caught={caught}")
    if not caught:
        fails += 1

    # 3. fail-closed: seed not published to IRIS (no iris_case_id) -> caught
    write_scenario({}, cap_override={"iris_case_id": None, "timeline": [],
                                     "notes": [], "iocs": [],
                                     "report_spine_markdown": ""})
    probs = cb.check_bakeoff()
    caught = any("no IRIS case" in p or "iris_case_id" in p for p in probs)
    print(f"not-published: {len(probs)} problems, fail-closed caught={caught}")
    if not caught:
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
