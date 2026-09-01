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
from verify.check_docs import check_docs
from verify.core import load_fixtures, VERDICT_FAIL, VERDICT_BLOCKED
from verify.runner import run_matrix, summarize

logger = get_logger(__name__)


def _check_docs_gate() -> list[dict]:
    """Docs-citation drift gate — the role docs are the ontology's spec; a
    citation that no longer resolves (file/range/symbol) is a correctness
    bug. Runs once per matrix, folded into the exit gate."""
    global _docs_skip
    try:
        from verify.check_docs import check_docs
        probs = check_docs()
        _docs_skip = bool(probs) and probs[0].get("kind") == "skip"
        if _docs_skip:
            print(f"docs citations: SKIP — {probs[0]['detail']}")
        elif probs:
            print(f"docs citations: {len(probs)} problem(s)")
            for p in probs:
                print(f"  [{p['kind']}] {p['cite']} ({p['file']}): {p['detail']}")
        else:
            print("docs citations: all resolve")
        return probs
    except Exception as e:  # noqa: BLE001 — the docs gate must not crash the matrix
        print(f"docs citations: ERROR {e}")
        _docs_skip = False
        return [{"kind": "error", "detail": str(e)}]


def _registry_gate() -> bool:
    """Registry reentrancy gate: the lazy-singleton deadlock that wedged the
    router for 19h (Aug 30). Subprocess: it resets registry singletons —
    must not clobber the matrix's own clients."""
    try:
        import subprocess as _sp
        rr = _sp.run(
            [sys.executable, "-m", "verify.test_registry_reentrancy"],
            capture_output=True, text=True, timeout=60)
        ok = rr.returncode == 0
        print("registry reentrancy: " + ("ok" if ok else "FAIL"))
        if not ok:
            print(rr.stdout[-500:])
            print(rr.stderr[-500:])
        return ok
    except Exception as e:  # noqa: BLE001 — gate must not crash the matrix
        print(f"registry reentrancy: ERROR {e}")
        return False


def _timer_gate() -> bool:
    """Timer-liveness gate: no ssop timer may silently stop firing (the
    router wedged for 19h Aug 30-31 unseen). Subprocess: needs systemctl."""
    try:
        import subprocess as _sp
        tr = _sp.run(
            [sys.executable, "-m", "verify.check_timers"],
            capture_output=True, text=True, timeout=30)
        ok = tr.returncode == 0
        print("timer liveness: " + ("all healthy" if ok else "FAIL"))
        if not ok:
            print(tr.stdout[-500:])
        return ok
    except Exception as e:  # noqa: BLE001 — gate must not crash the matrix
        print(f"timer liveness: ERROR {e}")
        return False


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
    # case for the pair, and it only looks at the last `window_s` (default 1h).
    # Without a seeded case the attach path has nothing to attach to, and the
    # fixture's attach/no_new_case expectations pass vacuously.
    # CRITICAL: the seed must be FRESH — a stale open case from a previous
    # matrix run is outside verdict()'s recidivism window and the attach never
    # fires. Close any stale seed case for the pair, then mint a fresh one.
    # (The analyst driver closes its minted case after verifying, so a fresh
    # seed per run does not accumulate — and no_new_case excludes verify_seed.)
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
            # Close any existing open case for the pair (stale or current) so
            # the seed below is the ONLY open one and is guaranteed fresh.
            stale = _cs.recent_entity_cases(srcip, dstip, window_s=30 * 86400)
            for c in stale:
                if (c.get("source") or {}).get("verify_seed"):
                    _cs.close_case(c["case_id"], reason="verify seed refresh")
            _cs.open_case(
                source={"srcip": srcip, "dstip": dstip, "verify_seed": True},
                title=f"VERIFY SEED repeated-entity {srcip}:{dstip}",
            )
            logger.info("verify seed: fresh open case for entity %s:%s", srcip, dstip)
    except Exception:  # noqa: BLE001 — seed failure must not abort the matrix
        logger.warning("entity seed skipped — attach fixtures may fail as BLOCKED")

    # The dispatching timers (router/hunt) write live cases/tickets. While
    # they run, their writes race the matrix's no_dispatch/no_case isolation
    # windows and contaminate results (seen when the router came back alive:
    # its apparmor dispatch minted a case mid-matrix -> spurious FAILs).
    # Pause them for the FIXTURE run only; the gates run after restore
    # (docs/registry/timer checks are read-only or fake-injected).
    _timers_paused = False
    try:
        import subprocess as _sp_pause
        for _u in ("ssop-router.timer", "ssop-hunt.timer"):
            _sp_pause.run(["systemctl", "stop", _u], capture_output=True, text=True, timeout=15)
        _timers_paused = True
    except Exception:  # noqa: BLE001 — pausing is best-effort
        _timers_paused = False
    try:
        results = run_matrix(fixtures, roles)
    finally:
        if _timers_paused:
            try:
                import subprocess as _sp_resume
                for _u in ("ssop-hunt.timer", "ssop-router.timer"):
                    _sp_resume.run(["systemctl", "start", _u], capture_output=True, text=True, timeout=15)
            except Exception:  # noqa: BLE001
                pass
    report = {
        "summary": summarize(results),
        "results": [r.to_dict() for r in results],
    }

    _docs_problems = _check_docs_gate()
    _reg_ok = _registry_gate()
    _tmr_ok = _timer_gate()

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

    summary = report["summary"]
    failed = (summary["failed"] > 0 or summary["blocked"] > 0
              or (_docs_problems and not _docs_skip) or not _reg_ok or not _tmr_ok)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
