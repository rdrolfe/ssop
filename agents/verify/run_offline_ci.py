"""Offline CI suite for SSOP.

Runs the hermetic (no secrets / no network / no live services) regression
tests from a clean checkout. The verify/test_*.py files are standalone
main-style scripts (each exits 0/1), so the runner executes each in a
PRIVATE temp environment and reports per-file results. Missing hard
dependencies => BLOCKED, never a silent pass. Live/integration checks
(verify matrix on the runtime hosts) are explicitly OUT of scope here.

Usage:
    python3 agents/verify/run_offline_ci.py
Exit codes: 0 = all pass, 1 = failures, 2 = BLOCKED (deps missing).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# Layout tolerance. In the REPO the hermetic tests sit under `agents/` (three
# levels up from verify/); in a DEPLOYED runtime the verify/ tree IS the agents
# tree (two levels up) and there is no `agents/` segment. Hardcoding the repo
# depth made this suite report BLOCKED on the runtime host — every path
# resolved to a tree that does not exist (found on .29, 2026-09-12).
_HERE = Path(__file__).resolve()
if not (_HERE.parent.parent.parent / "agents" / "verify").is_dir():
    REPO = _HERE.parent.parent


def _p(rel: str) -> Path:
    """Resolve a repo-relative path in EITHER layout (see above)."""
    p = REPO / rel
    if p.exists():
        return p
    if rel.startswith("agents/"):
        stripped = REPO / rel[len("agents/"):]
        if stripped.exists():
            return stripped
    return p

# Hard deps the hermetic tests import (directly or transitively).
REQUIRED = ["yaml", "dotenv", "langgraph", "langchain_core"]

# The hermetic suite: real mutation-path tests, no stores, no network.
HERMETIC = [
    "agents/verify/test_classify_parity.py",
    "agents/verify/test_alert_contract.py",
    "agents/verify/test_audit_chain.py",
    "agents/verify/test_check_bakeoff.py",
    "agents/verify/test_check_docs.py",
    "agents/verify/test_check_timers.py",
    "agents/verify/test_close_reason.py",
    "agents/verify/test_compose_rationale.py",
    "agents/verify/test_fingerprint_tuning.py",
    "agents/verify/test_infra_dedupe.py",
    "agents/verify/test_infra_disposition.py",
    "agents/verify/test_alert_provenance.py",
    "agents/verify/test_intel_pipeline.py",
    "agents/verify/test_misp_client.py",
    "agents/verify/test_bulk_intel.py",
    "agents/verify/test_registry_reentrancy.py",
    "agents/verify/test_strong_tp_gate.py",
    "agents/verify/test_technique_mapping.py",
    "agents/verify/test_investigation_persist.py",
    "agents/verify/test_adjudicate_fingerprint.py",
    "agents/verify/test_case_lifecycle.py",
    "agents/verify/test_case_decision_writeback.py",
    "agents/verify/test_decision_readers.py",
    "agents/verify/test_egress_and_vt.py",
    "agents/verify/test_ontology_export.py",
    "agents/verify/check_ontology.py",
]


def check(label: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "BLOCKED"
    line = f"[{mark}] {label}"
    if detail:
        line += f" — {detail}"
    print(line, flush=True)


def run_one(test: str, td_base: str) -> tuple[str, int, str]:
    """Run one hermetic test in its OWN private temp dir (no shared /tmp)."""
    td = tempfile.mkdtemp(prefix="ssop-ci-", dir=td_base)
    env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": td,
        "AUDIT_DIR": str(Path(td) / "audit"),
        "ROUTER_STATE": str(Path(td) / "router_state.json"),
        "SSOP_OFFLINE": "1",
        # Test profile (issue #29): no internal CA exists in a hermetic run,
        # and the fail-closed default would BLOCK the whole suite. The
        # verified-TLS path is exercised against live services, not here.
        "SSOP_TLS_VERIFY": "0",
        "SSOP_ALLOW_NO_QDRANT_KEY": "1",
        "LANG": "C.UTF-8",
        "PYTHONPATH": str(_p("agents")),
    }
    Path(env["AUDIT_DIR"]).mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [sys.executable, str(_p(test))],
            cwd=str(td), env=env, timeout=180,
            capture_output=True, text=True)
        tail = (proc.stdout + proc.stderr).strip().splitlines()
        # Keep the LAST FEW LINES, not just the last one. A flaky failure that
        # prints only its final line is undiagnosable after the fact, and the
        # temp dir is gone by then — a flake you cannot read is a flake you
        # will never fix. Bounded so a noisy test cannot flood the report.
        detail = "\n".join(tail[-12:]) if tail else ""
        return test, proc.returncode, detail
    except subprocess.TimeoutExpired:
        return test, 124, "TIMEOUT (180s)"
    except Exception as e:  # noqa: BLE001 — report, don't die mid-suite
        return test, 125, f"harness error: {e}"


def main() -> int:
    print(f"SSOP offline CI — repo: {REPO}")
    print("=" * 60)

    blocked = []

    # 1. Python version declaration (repo dev standard: 3.11).
    v = sys.version_info
    version_ok = v[:2] == (3, 11)
    check(f"python {'.'.join(map(str, v[:3]))}", version_ok,
          "repo standard is 3.11" if not version_ok else "")
    if not version_ok:
        blocked.append(f"python {v[:2]} != 3.11")

    # 2. Required deps present?
    missing = [m for m in REQUIRED if importlib.util.find_spec(m) is None]
    check("required deps", not missing, ", ".join(missing))
    if missing:
        blocked.append(f"missing required deps: {', '.join(missing)}")

    # 3. Tests exist?
    absent = [t for t in HERMETIC if not _p(t).exists()]
    check(f"hermetic tests present ({len(HERMETIC)})", not absent, ", ".join(absent))
    if absent:
        blocked.append(f"missing test files: {absent}")

    if blocked:
        print("\nBLOCKED — environment cannot run the offline suite:")
        for b in blocked:
            print(f"  - {b}")
        print("Fix the environment (make venv, pip install -r requirements.txt).")
        return 2

    # 4. Run each hermetic test in its own private temp dir (no shared /tmp).
    print(f"\nRunning {len(HERMETIC)} hermetic tests (parallel, isolated temp dirs)...\n")
    with tempfile.TemporaryDirectory(prefix="ssop-ci-base-") as base:
        with ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(lambda t: run_one(t, base), HERMETIC))

    failures = 0
    blocked_tests: list[str] = []

    def _dump(detail: str) -> None:
        for ln in (detail or "").splitlines():
            print(f"       {ln[:200]}")

    for test, code, detail in sorted(results):
        if code == 0:
            print(f"[PASS] {test}")
        elif code == 2:
            # rc 2 = the test's own preflight says THIS ENVIRONMENT cannot run
            # it (missing dep/JVM). That is BLOCKED, not FAIL: "we could not
            # check" and "the check failed" are different facts, and a suite
            # that reports BLOCKED as PASS is worse than no suite.
            blocked_tests.append(test)
            print(f"[BLOCKED] {test}")
            _dump(detail)
        else:
            failures += 1
            print(f"[FAIL rc={code}] {test}")
            _dump(detail)

    if failures:
        print(f"\nOFFLINE SUITE: FAIL ({failures}/{len(HERMETIC)})")
        return 1
    if blocked_tests:
        print(f"\nOFFLINE SUITE: BLOCKED ({len(blocked_tests)}/{len(HERMETIC)} could not run)")
        for t in blocked_tests:
            print(f"  - {t}")
        return 2
    print(f"\nOFFLINE SUITE: PASS ({len(HERMETIC)}/{len(HERMETIC)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
