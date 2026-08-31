"""Verify matrix CLI — the SSOP equivalent of `bun run verify`.

Usage:
    python3 -m verify.matrix                 # full matrix, all fixtures x roles
    python3 -m verify.matrix --role analyst  # only the analyst role
    python3 -m verify.matrix --json          # machine-readable report
    python3 -m verify.matrix --fixture rootcheck-fp

Exit code 1 on any FAIL/BLOCKED (CI-friendly). Verdict taxonomy:
PASS | FAIL | BLOCKED | SKIP (phase-3-verify pattern).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # entry point — before config import (frozen settings)

from logging_setup import get_logger
from verify.core import load_fixtures, VERDICT_FAIL, VERDICT_BLOCKED
from verify.runner import run_matrix, summarize

logger = get_logger(__name__)


def main() -> int:
    args = sys.argv[1:]
    roles = None
    fixture_filter = None
    as_json = "--json" in args
    if "--role" in args:
        i = args.index("--role")
        roles = [args[i + 1]]
    if "--fixture" in args:
        i = args.index("--fixture")
        fixture_filter = args[i + 1]

    # The verify fixtures are Wazuh-shaped (wazuh-alerts-* field layout).
    # Pin the transport to the wazuh backend so the matrix tests the spine
    # deterministically, regardless of the active transport.yaml backend.
    import yaml as _yaml
    _tp = Path("transport.yaml")
    if _tp.exists():
        _cfg = _yaml.safe_load(_tp.read_text(encoding="utf-8"))
        _cfg["backend"] = "wazuh"
        _tp.write_text(_yaml.safe_dump(_cfg, default_flow_style=False), encoding="utf-8")
        print("verify matrix: backend pinned to wazuh")
    os.environ.setdefault("SSOP_TRANSPORT_BACKEND", "wazuh")

    fixtures = load_fixtures()
    if fixture_filter:
        fixtures = [f for f in fixtures if f.get("id") == fixture_filter]
        if not fixtures:
            print(f"no fixture matches {fixture_filter}")
            return 1

    # Seed deterministic tuning state the fixtures depend on (idempotent).
    # Fixtures stay pure data; this is the matrix's setup phase.
    try:
        from tools.tuning_tools import TuningLedger
        ledger = TuningLedger()
        # tuned-rule-no-escalate: rule 987654 is pre-tuned auto_fp by policy.
        if not ledger.lookup("987654"):
            ledger.write("987654", "auto_fp",
                         "verify seed: fixture tuned-rule-no-escalate", source="human")
        # high-severity-suricata-c2: rule 86610 is tuned auto_fp in the live
        # ledger (human adjudication) — encode it so the fixture is
        # deterministic in a clean environment too (data wins, 5715 precedent).
        if not ledger.lookup("86610"):
            ledger.write("86610", "auto_fp",
                         "verify seed: fixture high-severity-suricata-c2 (human adjudicated)", source="human")
    except Exception:  # noqa: BLE001 — seed failure must not abort the matrix
        logger.warning("tuning seed skipped — tuned fixtures may fail as BLOCKED")

    # Seed the entity-pair case the repeated-entity-attaches fixture depends on.
    # Entity recidivism is stateful: verdict() attaches to an existing OPEN
    # case for the pair. Without a seeded open case the attach path has
    # nothing to attach to, and the fixture's attach/no_new_case expectations
    # pass vacuously. Idempotent: reuse an existing matching open case.
    try:
        from tools.case_tools import CaseStore
        from tools.observables import entity_pair
        _cs = CaseStore()
        for f in fixtures:
            exp = f.get("expect", {})
            if not (exp.get("attach") or exp.get("no_new_case")):
                continue
            pair = entity_pair(f.get("alert", {}))
            if not pair:
                continue
            srcip, dstip = pair
            existing = _cs.recent_entity_cases(srcip, dstip, window_s=30 * 86400)
            if not existing:
                _cs.open_case(
                    source={"srcip": srcip, "dstip": dstip, "verify_seed": True},
                    title=f"VERIFY SEED repeated-entity {srcip}:{dstip}",
                )
                logger.info("verify seed: open case for entity %s:%s", srcip, dstip)
    except Exception:  # noqa: BLE001 — seed failure must not abort the matrix
        logger.warning("entity seed skipped — attach fixtures may fail as BLOCKED")

    results = run_matrix(fixtures, roles)
    report = {
        "summary": summarize(results),
        "results": [r.to_dict() for r in results],
    }

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        s: dict = report["summary"]  # type: ignore[assignment]
        print(f"=== SSOP verify matrix: {s['passed']} passed / {s['failed']} failed / "
              f"{s['blocked']} blocked / {s['total']} total ===")
        for r in results:
            badge = {"PASS": "✅", "FAIL": "❌", "BLOCKED": "🚫", "SKIP": "⏭️"}.get(r.verdict, "?")
            print(f"  {badge} {r.role:<9} {r.fixture_id:<28} {r.verdict}")
            for c in r.checks:
                if c.status in ("fail", "warn", "probe"):
                    print(f"      {c.status:<6} {c.name}: {c.detail}")

    failed = s["failed"] > 0 or s["blocked"] > 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
