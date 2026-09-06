"""Bake-off parity gate — the decision chain renders in IRIS (engine parity).

ADR-006 redefines the bake-off: IRIS is the single human front-end, so
parity = both detection engines (Wazuh + SO) render the SAME decision chain
in IRIS, not UI parity across three surfaces. The spine is the source of
truth; IRIS is fed from it via publish_case_iris.py. A fully-decided case
must therefore render its whole chain (investigation -> verdict ->
adjudication -> assignment/close) on the IRIS Timeline tab, plus the SSOP
note + IOCs + the spine report.

Two cases are gated (both outcome directions): the negative-outcome seed
(case-26b166ce32, deny/FP) and the positive-outcome case
(case-204a8dc4f9, approve). Each must score 12/12 on the six axes scored
against what IRIS renders (capture_iris_bakeoff.py + score_iris_bakeoff.py).

Fail-closed: if the seed isn't published to IRIS (no IRIS case maps to the
spine id), or the capture fails, or any axis scores < 2, the gate goes RED.

Usage: python3 -m verify.check_bakeoff
Exit 0 = parity holds; 1 = broken or unverifiable.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# The two gated cases: (case_id, label)
CASES = [
    ("case-26b166ce32", "seed (negative outcome)"),
    ("case-204a8dc4f9", "positive outcome"),
]


def _run(script: str, timeout: int = 120) -> tuple[int, str]:
    """Run a lab script from the runtime root with the current interpreter."""
    import shlex
    r = subprocess.run(
        [sys.executable, *shlex.split(script)],
        capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr)[-2000:]


def _score_case(case_id: str) -> list[str]:
    """Capture + score one case against the IRIS surface; return problems."""
    problems: list[str] = []

    rc, out = _run(f"deploy/lab/capture_iris_bakeoff.py {case_id}")
    if rc != 0:
        return [f"capture_iris_bakeoff {case_id} failed (rc={rc}): {out[-500:]}"]
    cap_path = Path("/tmp/iris_bakeoff_capture.json")
    if not cap_path.exists():
        return [f"capture produced no /tmp/iris_bakeoff_capture.json for {case_id}"]
    cap = json.loads(cap_path.read_text())
    if not cap.get("iris_case_id"):
        return [f"{case_id} has no IRIS case (publish_case_iris first): "
                "capture found no iris_case_id"]

    rc, out = _run("deploy/lab/score_iris_bakeoff.py", timeout=60)
    if rc != 0:
        return [f"score_iris_bakeoff failed (rc={rc}): {out[-500:]}"]
    scores_path = Path("/tmp/iris_bakeoff_scores.json")
    if not scores_path.exists():
        return [f"score produced no /tmp/iris_bakeoff_scores.json for {case_id}"]
    scores = json.loads(scores_path.read_text())

    # Schema + identity validation (fail-closed): the scores file must be for
    # THIS case and must carry exactly one row per axis 1..6, each a valid
    # 0-2 integer. An empty/short/duplicate/stale score set fails the gate
    # rather than silently passing rows that happen to exist.
    if scores.get("case_id") != case_id:
        problems.append(
            f"{case_id}: scores file case_id mismatch "
            f"(expected {case_id}, got {scores.get('case_id')!r}) — stale capture?")
    rows = scores.get("axes")
    if not isinstance(rows, list) or not rows:
        return problems + [f"{case_id}: scores file has no axes (incomplete scoring)"]
    seen: set[int] = set()
    for r in rows:
        try:
            axis = int(r.get("axis"))
            val = int(r.get("iris"))
        except (TypeError, ValueError):
            problems.append(f"{case_id}: malformed score row {r!r}")
            continue
        if axis not in range(1, 7):
            problems.append(f"{case_id}: axis {axis} out of range 1-6")
        elif axis in seen:
            problems.append(f"{case_id}: duplicate score for axis {axis}")
        else:
            seen.add(axis)
        if val not in (0, 1, 2):
            problems.append(f"{case_id}: axis {axis} score {val} not in 0-2")
        elif val != 2:
            problems.append(
                f"{case_id}: axis {axis} ({r.get('axis_name','')}): "
                f"iris={val} — {str(r.get('note',''))[:100]}")
    missing = sorted(set(range(1, 7)) - seen)
    if missing:
        problems.append(f"{case_id}: missing score for axis(es) {missing} "
                        f"({len(seen)}/6 present) — incomplete scoring")
    return problems


def check_bakeoff() -> list[str]:
    """Return human-readable problems; empty list = parity holds."""
    problems: list[str] = []
    for case_id, label in CASES:
        for p in _score_case(case_id):
            problems.append(f"[{label}] {p}")
    return problems


def main() -> int:
    probs = check_bakeoff()
    if not probs:
        print("bake-off parity (engine-in-IRIS): 12/12 both seeds")
        return 0
    print(f"bake-off parity: {len(probs)} problem(s)")
    for p in probs:
        print(f"  [parity] {p}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
