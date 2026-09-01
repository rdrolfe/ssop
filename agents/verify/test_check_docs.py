#!/usr/bin/env python3
"""Non-vacuity test for the docs-citation check.

Builds a synthetic repo with the cited files + docs present, then proves
the check is non-vacuous:
  - baseline (all citations valid) -> 0 problems
  - a citation pointing past EOF    -> caught (range)
  - a symbol moved out of its range -> caught (symbol)
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verify.check_docs import check_docs  # noqa: E402

REPO = Path("/tmp/dcrepo")
ROLES = Path(__file__).resolve().parent.parent.parent / "docs" / "roles"

FILES = [
    "agents/analyst.py", "agents/hunt.py", "agents/router.py", "agents/responder.py",
    "agents/intel.py", "agents/config.py",
    "agents/tools/analyst_tools.py", "agents/tools/hunt_tools.py",
    "agents/tools/supervisory_tools.py", "agents/tools/investigator.py",
    "agents/tools/self_heal.py", "agents/tools/intel_tools.py",
    "agents/tools/case_tools.py", "agents/tools/observables.py",
    "agents/tools/ontology.py", "agents/tools/tuning_tools.py",
]


def build() -> None:
    shutil.rmtree(REPO, ignore_errors=True)
    for f in FILES:
        src = Path(f)
        if src.exists():
            dst = REPO / f
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(src.read_text())
    d = REPO / "docs" / "roles"
    d.mkdir(parents=True, exist_ok=True)
    for md in ROLES.glob("*.md"):
        (d / md.name).write_text(md.read_text())


def main() -> int:
    build()
    fails = 0

    base = check_docs(REPO)
    print(f"baseline: {len(base)} problems")
    if base:
        fails += 1
        for p in base:
            print("  ", p)

    # 1. Past-EOF range
    build()
    for md in (REPO / "docs" / "roles").glob("*.md"):
        t = md.read_text()
        md.write_text(t.replace("`analyst_tools.py:55-85`", "`analyst_tools.py:999-85`"))
    probs = check_docs(REPO)
    caught = [p for p in probs if p["kind"] == "range"]
    print(f"past-EOF: {len(probs)} problems, {len(caught)} range-caught")
    if not caught:
        fails += 1

    # 2. Symbol moved out of range (real co-located case: `dispatch_security`
    #    is named on the same line as `router.py:300-369`)
    build()
    for md in (REPO / "docs" / "roles").glob("*.md"):
        t = md.read_text()
        md.write_text(t.replace("`router.py:300-369`", "`router.py:10-20`"))
    probs = check_docs(REPO)
    caught = [p for p in probs if p["kind"] == "symbol"]
    print(f"symbol-moved: {len(probs)} problems, {len(caught)} symbol-caught")
    if not caught:
        fails += 1

    shutil.rmtree(REPO, ignore_errors=True)
    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
