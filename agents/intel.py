#!/usr/bin/env python3
"""Intel role (P1): CISA KEV -> fleet match -> staged hunt packs.

The SOC's proactive layer. Every other role REACTS to alerts; intel reads
the exploited-vulnerability feed, matches it against the fleet inventory,
and proposes hunt packs for human review. Sovereign by construction:
public-domain government data, pulled only, keyless, no environment
egress (check_egress clean — the only remote call is the KEV GET).

State machine (docs/wayfinder/tickets/hunt-pack-schema.md):
  INGEST -> MATCH -> GENERATE -> STAGE -> (human PROMOTE)

Run manually:  python3 intel.py [--stage-dir PATH]
Scheduled:     ssop-intel.timer (daily)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tools.intel_tools import run_intel  # noqa: E402

DEFAULT_STAGE = Path(__file__).resolve().parent / "hunts" / "staging"


def main() -> None:
    import json

    stage = DEFAULT_STAGE
    if "--stage-dir" in sys.argv:
        stage = Path(sys.argv[sys.argv.index("--stage-dir") + 1])
    report = run_intel(stage, _ix())
    out = json.dumps(report, indent=1)
    print(out[:3000] if len(out) > 3000 else out)
    if report.get("error"):
        sys.exit(1)


def _ix():
    from router import get_indexer
    return get_indexer()


if __name__ == "__main__":
    main()
