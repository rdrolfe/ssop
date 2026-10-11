#!/usr/bin/env python3
"""Non-vacuity test for the docs-citation check.

Builds a synthetic repo with the cited files + docs present, then proves
the check is non-vacuous:
  - baseline (all citations valid) -> 0 problems
  - a citation pointing past EOF    -> caught (range)
  - a symbol moved out of its range -> caught (symbol)
"""
import re
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


# Any analyst_tools.py line-range citation. The negative controls below used to
# hardcode the exact numbers ("analyst_tools.py:55-85"), so re-anchoring a
# citation in the docs turned the probe into a SILENT NO-OP: the replace matched
# nothing, no problem was planted, nothing was caught, and the test still printed
# a verdict. Match the shape and assert the plant landed.
CITE_RE = re.compile(r"`analyst_tools\.py:\d+-\d+`")


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
    planted = 0
    for md in (REPO / "docs" / "roles").glob("*.md"):
        t = md.read_text()
        t2, k = CITE_RE.subn("`analyst_tools.py:999-85`", t, count=1)
        if k:
            planted += 1
        md.write_text(t2)
    probs = check_docs(REPO)
    caught = [p for p in probs if p["kind"] == "range"]
    print(f"past-EOF: {len(probs)} problems, {len(caught)} range-caught (planted {planted})")
    if not caught or planted == 0:
        fails += 1

    # 2. Symbol moved out of range (`high_level` named on the same line as
    #    `analyst_tools.py:66-71`; window 10-20 does not contain it)
    build()
    planted = 0
    for md in (REPO / "docs" / "roles").glob("*.md"):
        out = []
        for line in md.read_text().split("\n"):
            if "high_level" in line and CITE_RE.search(line):
                line = CITE_RE.sub("`analyst_tools.py:10-20`", line, count=1)
                planted += 1
            out.append(line)
        md.write_text("\n".join(out))
    probs = check_docs(REPO)
    caught = [p for p in probs if p["kind"] == "symbol"]
    print(f"symbol-moved: {len(probs)} problems, {len(caught)} symbol-caught (planted {planted})")
    if not caught or planted == 0:
        fails += 1

    shutil.rmtree(REPO, ignore_errors=True)
    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
