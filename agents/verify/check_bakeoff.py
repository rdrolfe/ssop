"""Bake-off parity gate — the two-backend case surface must stay at parity.

The bake-off (docs/lab/case-bakeoff.md) scores both SIEM surfaces — SO's
native so-case store and the Wazuh-side console — on six axes (0-2 each)
for the same fully-decided case. Two cases are gated: the negative-outcome
seed (case-26b166ce32, deny/FP) and the positive-outcome case
(case-204a8dc4f9, DNS-tunnel approve) — both must score 2 on every axis on
BOTH surfaces. Catches regressions like the axis-1 category gap (SO create
op lost the ontology category) or the report compiler silently degrading,
for either outcome direction.

Fail-closed: if a case isn't published to SO, or SO/console is
unreachable, or any axis scores < 2 on either side, the gate goes RED — an
unverifiable bake-off is itself a parity failure.

Usage: python3 -m verify.check_bakeoff
Exit 0 = parity holds; 1 = parity broken or unverifiable.
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
    """Capture + score one case; return parity problems (empty = 12/12)."""
    problems: list[str] = []

    # 1. Capture both surfaces fresh.
    rc, out = _run(f"deploy/lab/capture_bakeoff.py {case_id}")
    if rc != 0:
        return [f"capture_bakeoff {case_id} failed (rc={rc}): {out[-500:]}"]
    cap_path = Path("/tmp/bakeoff_capture.json")
    if not cap_path.exists():
        return [f"capture produced no /tmp/bakeoff_capture.json for {case_id}"]
    cap = json.loads(cap_path.read_text())
    if not cap.get("so_native_case_store"):
        return [f"capture found 0 SO ops for {case_id} — not published to SO? "
                "(run clean_so_case.py + publish_case_so.py)"]
    console = cap.get("wazuh_console_api") or {}
    if not (console.get("case") or console.get("cases")):
        return [f"console view missing for {case_id}: {json.dumps(console)[:300]}"]

    # 2. Score from the fresh capture.
    rc, out = _run("deploy/lab/score_bakeoff.py", timeout=60)
    if rc != 0:
        return [f"score_bakeoff failed (rc={rc}): {out[-500:]}"]
    scores_path = Path("/tmp/bakeoff_scores.json")
    if not scores_path.exists():
        return [f"score produced no /tmp/bakeoff_scores.json for {case_id}"]
    scores = json.loads(scores_path.read_text())

    # 3. Assert every axis scores 2 on BOTH surfaces.
    axes = {str(r["axis"]): r for r in scores.get("axes", [])}
    for a in ("1", "2", "3", "4", "5", "6"):
        if a not in axes:
            problems.append(f"{case_id}: axis {a} missing from scores")
            continue
        r = axes[a]
        cs, so = r.get("console"), r.get("so")
        if cs != 2 or so != 2:
            problems.append(
                f"{case_id}: axis {a} ({r.get('axis_name','')}): console={cs} so={so} "
                f"— console note: {r.get('console_note','')[:80]}; "
                f"SO note: {r.get('so_note','')[:80]}")
    return problems


def check_bakeoff() -> list[str]:
    """Return human-readable problems; empty list = parity holds."""
    problems: list[str] = []
    for case_id, label in CASES:
        probs = _score_case(case_id)
        for p in probs:
            problems.append(f"[{label}] {p}")
    return problems


def main() -> int:
    probs = check_bakeoff()
    if not probs:
        print("bake-off parity: 12/12 both surfaces (seed + positive outcome)")
        return 0
    print(f"bake-off parity: {len(probs)} problem(s)")
    for p in probs:
        print(f"  [parity] {p}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

