"""Verification runner — fixture -> role -> observe spine -> verdict.

Mirrors phase-3-verify's runner.ts: mount (feed fixture to role), act (run
the role's decision path), verify (invariants over the spine), verdict.

Roles verify against LIVE stores (case spine, escalation queue) so BLOCKED
(indexer/qdrant unreachable) is distinguishable from FAIL (wrong behavior).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from tools.registry import get_analyst, get_cases, get_escalation, get_hunt, get_indexer
from verify.core import FixtureResult, CHECK_FAIL, CHECK_OK, VERDICT_BLOCKED, VERDICT_FAIL, VERDICT_PASS
from verify.invariants import INVARIANTS, Stores

logger = logging.getLogger(__name__)


class RoleOutcome:
    """What a role produced for a fixture (verdict + any side effects)."""

    def __init__(self, verdict: str, **extra: Any) -> None:
        self.verdict = verdict
        self.extra = extra

    def get(self, key: str, default: Any = None) -> Any:
        if key == "verdict":
            return self.verdict
        return self.extra.get(key, default)


# --- role drivers ----------------------------------------------------------
# Each driver: fn(fixture) -> RoleOutcome. Pure decision logic — no writes.

def drive_analyst(fixture: Dict[str, Any]) -> RoleOutcome:
    """Feed the fixture alert to the analyst's verdict logic."""
    analyst = get_analyst()
    alert = fixture.get("alert", {})
    v = analyst.verdict(alert)
    return RoleOutcome(v["verdict"], category=v.get("category"), level=v.get("level"),
                       tuned=v.get("tuned", False),
                       tuning_override=v.get("tuning_override", False),
                       existing_chain=v.get("existing_chain"),
                       driver_role="analyst")


def drive_router_classify(fixture: Dict[str, Any]) -> RoleOutcome:
    """Feed the fixture to the router's classification (category + role).

    The router's contract is DISPATCH: it assigns category + owning role.
    Its verdict-equivalent is 'dispatched' (role assigned) vs 'not dispatched'
    (noise/unclassified). The analyst/hunt drivers own the escalate/note call.
    """
    from router import classify
    alert = fixture.get("alert", {})
    category, role = classify(alert)
    # Tuned rules: the router returns ("operational", None) — mark tuned so
    # the invariant can verify the tuning was respected in dispatch. If the
    # rule is tuned but STILL dispatched, that's the evidence-gated override
    # (strong TP evidence lifted the tuning) — surface tuning_override.
    tuned = False
    tuning_override = False
    try:
        from tools.tuning_tools import TuningLedger
        rid = str(alert.get("rule", {}).get("id", ""))
        t = TuningLedger().lookup(rid)
        tuned = bool(t and t.get("decision") in ("auto_fp", "operational"))
        # dispatched despite tuned = override (router fell through for evidence)
        if tuned and role is not None:
            tuning_override = True
    except Exception:  # noqa: BLE001
        tuned = False
    # Fixture may declare the expected router_role; the verdict check for the
    # router driver is about DISPATCH, not escalate/note.
    expected_role = fixture.get("expect", {}).get("router_role")
    if expected_role is not None:
        dispatched = role == expected_role
    else:
        dispatched = role is not None
    return RoleOutcome("escalate" if dispatched else "note",
                       category=category, role=role, dispatched=dispatched,
                       tuned=tuned, tuning_override=tuning_override,
                       wrote_case=False, driver_role="router")


def drive_hunt(fixture: Dict[str, Any]) -> RoleOutcome:
    """Run the hunt implied by the fixture's rule id (pattern class)."""
    from tools.hunt_tools import HuntClient
    hunter = get_hunt()
    rule_id = str(fixture.get("alert", {}).get("rule", {}).get("id", ""))
    hunt_id = None
    if rule_id in ("52002", "52000"):
        hunt_id = "apparmor-denials"
    elif rule_id == "510":
        hunt_id = "rootcheck-anomalies"
    if hunt_id is None:
        # No hunt pattern applies to this rule — the hunt role correctly
        # declines; the analyst owns single-alert verdicts. This is a SKIP,
        # not a FAIL (the fixture shouldn't expect hunt escalation here).
        tuned = False
        try:
            from tools.tuning_tools import TuningLedger
            t = TuningLedger().lookup(rule_id)
            tuned = bool(t and t.get("decision") in ("auto_fp", "operational"))
        except Exception:  # noqa: BLE001
            tuned = False
        return RoleOutcome("skip", category="pattern", role="hunt", tuned=tuned,
                           reason=f"no hunt for rule {rule_id}", driver_role="hunt")
    r = hunter.run_hunt(hunt_id, days=7)
    finding = r.get("finding", "clean")
    verdict = "escalate" if finding == "suspicious" else "note"
    return RoleOutcome(verdict, category="pattern", hunt_id=hunt_id, finding=finding,
                       driver_role="hunt")


# --- the runner ------------------------------------------------------------

def verify_fixture(fixture: Dict[str, Any], role: str, stores: Stores,
                   driver: Callable[[Dict[str, Any]], RoleOutcome],
                   ticket_baseline: Optional[set] = None,
                   case_baseline: Optional[set] = None) -> FixtureResult:
    """Run one fixture through one role driver, then check invariants."""
    fid = fixture.get("id", "unknown")
    result = FixtureResult(fid, role)
    try:
        outcome = driver(fixture)
    except Exception as e:  # noqa: BLE001 — a driver crash is BLOCKED, not FAIL
        logger.exception("fixture %s driver %s crashed", fid, role)
        result.error = str(e)
        result.finalize()
        return result

    # Attach the baselines so no_dispatch / no_case can exclude pre-existing
    # entities (test isolation against cross-fixture contamination).
    if ticket_baseline is not None:
        outcome._ticket_baseline = ticket_baseline
    if case_baseline is not None:
        outcome._case_baseline = case_baseline

    # Run invariants (each returns a Check)
    for name, inv in INVARIANTS:
        try:
            check = inv(fixture, outcome, stores)
            result.add_check(name, check.status, check.detail)
        except Exception as e:  # noqa: BLE001 — invariant crash = fail loudly
            logger.exception("invariant %s crashed for %s", name, fid)
            result.add_check(name, CHECK_FAIL, f"invariant crashed: {e}")

    result.finalize()
    return result


ROLE_DRIVERS: Dict[str, Callable[[Dict[str, Any]], RoleOutcome]] = {
    "analyst": drive_analyst,
    "router": drive_router_classify,
    "hunt": drive_hunt,
}


def run_matrix(fixtures: List[Dict[str, Any]], roles: Optional[List[str]] = None) -> List[FixtureResult]:
    """Run all fixtures against all (or selected) roles."""
    stores = Stores(get_cases(), get_escalation())
    targets = roles or list(ROLE_DRIVERS.keys())
    results: List[FixtureResult] = []
    for fixture in fixtures:
        # Record the ticket + case baselines BEFORE this fixture runs, so the
        # no_dispatch / no_case invariants can exclude entities from earlier
        # fixtures (test isolation — prevents cross-fixture contamination).
        baseline = {t.get("ticket_id") or t.get("id") for t in stores.open_tickets()}
        case_baseline = {c.get("case_id") or c.get("id") for c in stores.recent_cases(since_minutes=30)}
        for role in targets:
            if role not in ROLE_DRIVERS:
                logger.warning("unknown role driver %s — skipping", role)
                continue
            res = verify_fixture(fixture, role, stores, ROLE_DRIVERS[role],
                                 ticket_baseline=baseline, case_baseline=case_baseline)
            results.append(res)
    return results


def summarize(results: List[FixtureResult]) -> Dict[str, Any]:
    """Aggregate verdicts into a report."""
    from collections import Counter
    verdicts = Counter(r.verdict for r in results)
    return {
        "total": len(results),
        "verdicts": dict(verdicts),
        "passed": verdicts.get(VERDICT_PASS, 0),
        "failed": verdicts.get(VERDICT_FAIL, 0),
        "blocked": verdicts.get(VERDICT_BLOCKED, 0),
        "all_pass": verdicts.get(VERDICT_PASS, 0) == len(results) and len(results) > 0,
    }
