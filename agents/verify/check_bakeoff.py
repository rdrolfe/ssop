"""Bake-off parity gate — the two-backend case surface must stay at parity.

The bake-off (docs/lab/case-bakeoff.md) scores both SIEM surfaces — SO's
native so-case store and the Wazuh-side console — on six axes (0-2 each)
for the same fully-decided seed case. This gate re-runs the capture + score
and asserts BOTH surfaces still score 2 on every axis. It catches regressions
like the axis-1 category gap (SO create op lost the ontology category) or the
report compiler silently degrading.

Fail-closed: if the seed case isn't published to SO, or SO/console is
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


def _run(script: str, timeout: int = 120) -> tuple[int, str]:
    """Run a lab script from the runtime root with the current interpreter."""
    r = subprocess.run(
        [sys.executable, script],
        capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr)[-2000:]


def check_bakeoff() -> list[str]:
    """Return human-readable problems; empty list = parity holds."""
    problems: list[str] = []

    # 1. Capture both surfaces fresh.
    rc, out = _run("deploy/lab/capture_bakeoff.py")
    if rc != 0:
        return [f"capture_bakeoff failed (rc={rc}): {out[-500:]}"]
    cap_path = Path("/tmp/bakeoff_capture.json")
    if not cap_path.exists():
        return ["capture produced no /tmp/bakeoff_capture.json"]
    cap = json.loads(cap_path.read_text())
    if not cap.get("so_native_case_store"):
        return ["capture found 0 SO ops — seed case not published to SO? "
                "(run clean_so_case.py + publish_case_so.py)"]
    console = cap.get("wazuh_console_api") or {}
    if not (console.get("case") or console.get("cases")):
        return [f"console view missing: {json.dumps(console)[:300]}"]

    # 2. Score from the fresh capture.
    rc, out = _run("deploy/lab/score_bakeoff.py", timeout=60)
    if rc != 0:
        return [f"score_bakeoff failed (rc={rc}): {out[-500:]}"]
    scores_path = Path("/tmp/bakeoff_scores.json")
    if not scores_path.exists():
        return ["score produced no /tmp/bakeoff_scores.json"]
    scores = json.loads(scores_path.read_text())

    # 3. Assert every axis scores 2 on BOTH surfaces.
    axes = {str(r["axis"]): r for r in scores.get("axes", [])}
    for a in ("1", "2", "3", "4", "5", "6"):
        if a not in axes:
            problems.append(f"axis {a} missing from scores")
            continue
        r = axes[a]
        cs, so = r.get("console"), r.get("so")
        if cs != 2 or so != 2:
            problems.append(
                f"axis {a} ({r.get('axis_name','')}): console={cs} so={so} "
                f"— console note: {r.get('console_note','')[:80]}; "
                f"SO note: {r.get('so_note','')[:80]}")
    return problems


def main() -> int:
    probs = check_bakeoff()
    if not probs:
        print("bake-off parity: 12/12 both surfaces (seed case)")
        return 0
    print(f"bake-off parity: {len(probs)} problem(s)")
    for p in probs:
        print(f"  [parity] {p}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
