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
_HERE = Path(__file__).resolve()
# Resolve the tree the cited files actually live in.
#
# In the repo they sit under `agents/` (three levels up from verify/); on a
# DEPLOYED runtime the verify/ tree IS inside the agents tree (two levels up)
# and there is no `agents/` segment. Hardcoding one depth makes this test
# silently VACUOUS on the other host: it builds an empty synthetic repo, the
# negative controls catch nothing, and it still prints a verdict. That is
# exactly what it did on .29 until this was found (2026-09-12).
_AGENT_ROOT = _HERE.parent.parent
if not (_AGENT_ROOT / "hunt.py").exists():
    _AGENT_ROOT = _HERE.parent.parent.parent / "agents"
_DOCS_ROOT = _AGENT_ROOT / "docs"
if not _DOCS_ROOT.exists():
    _DOCS_ROOT = _AGENT_ROOT.parent / "docs"
ROLES = _DOCS_ROOT / "roles"

FILES = [
    "agents/analyst.py", "agents/hunt.py", "agents/router.py", "agents/responder.py",
    "agents/intel.py", "agents/config.py",
    "agents/tools/analyst_tools.py", "agents/tools/hunt_tools.py",
    "agents/tools/supervisory_tools.py", "agents/tools/investigator.py",
    "agents/tools/self_heal.py", "agents/tools/intel_tools.py",
    "agents/tools/case_tools.py", "agents/tools/observables.py",
    "agents/tools/ontology.py", "agents/tools/tuning_tools.py",
    # cited by docs/roles/router.md (the INFRA disposition rule's home) — the
    # synthetic repo must mirror every file the cited docs point at
    "agents/tools/infra_disposition.py",
    # cited by docs/roles/hunt.md (the bulk-intel contract for hunt)
    "agents/tools/bulk_intel.py",
]


def _src(rel: str) -> Path:
    """Map a repo-relative citation path onto THIS host's tree."""
    if rel.startswith("agents/"):
        return _AGENT_ROOT / rel[len("agents/"):]
    return _AGENT_ROOT / rel


def build() -> None:
    shutil.rmtree(REPO, ignore_errors=True)
    for f in FILES:
        src = _src(f)
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

    # 2. Symbol moved out of range (`high_level` named on the same line as
    #    `analyst_tools.py:66-71`; window 10-20 does not contain it)
    build()
    for md in (REPO / "docs" / "roles").glob("*.md"):
        t = md.read_text()
        md.write_text(t.replace("`analyst_tools.py:66-71`", "`analyst_tools.py:10-20`"))
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
