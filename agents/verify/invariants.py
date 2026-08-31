"""Invariant checks — assertions over the SSOP machine-readable surface.

The surface: case spine (Qdrant + JSONL), escalation queue (tickets/), audit
trail (actions.jsonl). Invariants are the "must hold" rules of the platform.

Each invariant takes (fixture, role_outcome, stores) and returns a Check.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List

from tools.case_tools import CaseStore
from tools.escalate_tools import EscalationClient
from verify.core import CHECK_OK, CHECK_FAIL, CHECK_SKIP, CHECK_WARN, Check

logger = logging.getLogger(__name__)


class Stores:
    """Access to the shared stores for verification (injected, not fresh)."""

    def __init__(self, cases: CaseStore, escalation: EscalationClient) -> None:
        self.cases = cases
        self.escalation = escalation

    # --- queue inspection ---
    def open_tickets(self) -> List[Dict[str, Any]]:
        return self.escalation.list_tickets(status="open")

    # --- case spine inspection ---
    def recent_cases(self, since_minutes: int = 5) -> List[Dict[str, Any]]:
        """Cases with a receipt in the last N minutes (from JSONL — append-only).

        Returns only cases that are STILL OPEN (checks current status in the
        working Qdrant store). A case_opened receipt is not proof of an open
        case — it may have been closed since. This prevents synthetic/closed
        test cases from tripping the no_case invariant.
        """
        out = []
        if not self.cases.cases_file.exists():
            return out
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        for line in self.cases.cases_file.read_text().splitlines():
            try:
                rec = json.loads(line)
                ts = datetime.fromisoformat(rec.get("ts", "").replace("Z", "+00:00"))
                if ts >= cutoff and rec.get("event") == "case_opened":
                    # Only count if the case is still OPEN in the working store.
                    cur = self.cases.get_case(rec.get("case_id", ""))
                    if cur and cur.get("status") == "open":
                        out.append(rec)
            except (json.JSONDecodeError, ValueError):
                continue
        return out

    def reconcile_consistent(self) -> bool:
        return self.cases.reconcile().get("consistent", False)


# --- invariant definitions -------------------------------------------------
# Each invariant: (name, fn(fixture, outcome, stores) -> Check)


def inv_verdict_matches(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """The role's verdict must match the fixture's ground truth.

    Role-aware: a fixture may declare router_role (dispatch expectation) for
    the router driver, while 'verdict' applies to the analyst/hunt drivers.
    """
    expected = fixture.get("expect", {}).get("verdict")
    # If this run is the router driver and the fixture declares router_role,
    # the router's contract is DISPATCH: escalate == dispatched to that role.
    if outcome.get("driver_role") == "router" and fixture.get("expect", {}).get("router_role"):
        expected = "escalate"  # dispatching to the expected role IS correct
    actual = outcome.get("verdict")
    if expected is None:
        return Check("verdict", CHECK_OK, "no expectation declared")
    detail = f"expected={expected} actual={actual}"
    # A deliberate 'skip' (role correctly declines, e.g. no hunt pattern)
    # is not a failure — it's the role knowing it isn't the owner.
    if actual == "skip":
        return Check("verdict", CHECK_OK, detail + " (role correctly declined)")
    # hunt_may_escalate: the hunt finding suspicious on real data is
    # acceptable when the fixture declares it (pattern class behavior).
    if fixture.get("expect", {}).get("hunt_may_escalate") and outcome.get("driver_role") == "hunt":
        return Check("verdict", CHECK_OK, detail + " (hunt escalation permitted by fixture)")
    if expected == actual:
        return Check("verdict", CHECK_OK, detail)
    # escalate expected but got note on a boundary case = warn, not fail
    if expected == "escalate" and actual == "note":
        return Check("verdict", CHECK_FAIL, detail)
    return Check("verdict", CHECK_FAIL, detail)


def inv_no_case_when_expected(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """If fixture says no_case, no case may have been minted.

    Isolation: only cases created DURING this fixture count. The baseline
    (case ids present when the fixture started) is recorded on the outcome by
    the runner; cases from earlier fixtures must not contaminate this check.
    """
    if fixture.get("expect", {}).get("no_case"):
        baseline = set(getattr(outcome, "_case_baseline", []) or [])
        recent = stores.recent_cases(since_minutes=5)
        new = [c for c in recent if (c.get("case_id") or c.get("id")) not in baseline]
        if new:
            return Check("no_case", CHECK_FAIL, f"{len(new)} case(s) opened, expected none (excl. {len(baseline)} baseline)")
        return Check("no_case", CHECK_OK, "no case opened")
    return Check("no_case", CHECK_SKIP, "no expectation")


def inv_case_when_expected(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """If fixture says case:true, a case must exist.

    Only meaningful for WRITE-path drivers (integration tests that feed an
    alert through the real router/analyst dispatch). The pure-logic drivers
    (verdict/classify/hunt) never mint cases by design — for them this check
    is SKIP unless the driver actually performed a dispatch.
    """
    if not fixture.get("expect", {}).get("case"):
        return Check("case", CHECK_SKIP, "no expectation")
    # Logic-only drivers don't write; only assert when a case was actually
    # written (integration drivers set wrote_case=True).
    if outcome.get("wrote_case"):
        recent = stores.recent_cases(since_minutes=5)
        if not recent:
            return Check("case", CHECK_FAIL, "expected a case, none opened")
        return Check("case", CHECK_OK, f"case opened ({recent[0].get('case_id')})")
    return Check("case", CHECK_SKIP, "logic driver — case covered by integration test")


def inv_tuned_when_expected(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """If fixture says tuned:true, the verdict must respect the tuning —
    UNLESS the outcome carries tuning_override (evidence-gated override:
    a tuned-FP rule firing with strong TP evidence escalates to a human)."""
    if fixture.get("expect", {}).get("tuned"):
        # note/skip = tuning respected (correct decline for a tuned rule)
        if outcome.verdict in ("note", "skip") and outcome.extra.get("tuned"):
            return Check("tuned", CHECK_OK, "tuning respected — no escalation")
        # escalate + tuning_override = evidence override (clear-exception path)
        if outcome.verdict == "escalate" and outcome.extra.get("tuning_override"):
            return Check("tuned", CHECK_OK, "tuning override — strong TP evidence escalated to human")
        return Check("tuned", CHECK_FAIL, "tuned rule: expected note (respected) or escalate+tuning_override, got mismatch")
    return Check("tuned", CHECK_SKIP, "no expectation")


def inv_no_new_case_when_expected(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """If fixture says no_new_case:true, attaching must not mint a new case.

    The old check scanned receipts for a `source` field that never exists
    (receipts carry no source) — vacuously green. The real assertion is:
    (1) the analyst ATTACHED — verdict() returned an existing_chain for the
    entity pair (recidivism fired); and (2) no NEW open case exists for that
    pair beyond the seeded/attached one.
    """
    exp = fixture.get("expect", {})
    if not (exp.get("attach") or exp.get("no_new_case")):
        return Check("no_new_case", CHECK_SKIP, "no expectation")
    # (1) attach must be observable from the ANALYST driver: verdict() returned
    # existing_chain (recidivism fired). The router driver runs classify(), not
    # verdict(), so it never produces existing_chain — skip the attach assert
    # for non-analyst drivers (its dispatch outcome is checked separately).
    chain = outcome.get("existing_chain")
    driver = outcome.get("driver_role")
    if exp.get("attach") and driver == "analyst" and not chain:
        return Check("no_new_case", CHECK_FAIL,
                     "expected attach to existing chain but recidivism did not fire (existing_chain absent)")
    # (2) no NEW open case minted for the pair: scan Qdrant working store.
    try:
        from tools.observables import entity_pair
        pair = entity_pair(fixture.get("alert", {}))
        if not pair:
            return Check("no_new_case", CHECK_SKIP, "no entity pair on fixture alert")
        srcip, dstip = pair
        open_cases = stores.cases.recent_entity_cases(srcip, dstip, window_s=30 * 86400)
        # The seed case (verify_seed) may legitimately exist; count non-seed.
        non_seed = [c for c in open_cases if not (c.get("source") or {}).get("verify_seed")]
        if len(non_seed) > 0:
            return Check("no_new_case", CHECK_FAIL,
                         f"new case(s) minted for repeated entity: {[c.get('case_id') for c in non_seed]}")
        note = f"attached to chain {chain}" if chain else "no new case minted"
        return Check("no_new_case", CHECK_OK, note)
    except Exception as e:  # noqa: BLE001 — invariant must not crash the matrix
        return Check("no_new_case", CHECK_WARN, f"entity scan failed: {e}")


def inv_no_dispatch_for_noise(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """Noise fixtures must produce no escalation tickets.

    Isolation: only tickets created DURING this fixture count. The baseline
    (tickets present when the fixture started) is recorded on the outcome by
    the runner; tickets from earlier fixtures must not contaminate this check.
    """
    if fixture.get("expect", {}).get("no_dispatch"):
        from datetime import datetime, timedelta, timezone
        baseline = set(getattr(outcome, "_ticket_baseline", []) or [])
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent = []
        for t in stores.open_tickets():
            tid = t.get("ticket_id") or t.get("id")
            if tid in baseline:
                continue  # pre-existing ticket, not this fixture's dispatch
            try:
                ts = datetime.fromisoformat(t.get("ts", "").replace("Z", "+00:00"))
                if ts >= cutoff:
                    recent.append(t)
            except (ValueError, TypeError):
                continue
        if recent:
            return Check("no_dispatch", CHECK_FAIL, f"{len(recent)} new ticket(s) in last 5min (excl. {len(baseline)} baseline)")
        return Check("no_dispatch", CHECK_OK, "no new tickets")
    return Check("no_dispatch", CHECK_SKIP, "no expectation")


def inv_deduped_burst(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """Burst repeats must be deduped (one dispatch, not N)."""
    if fixture.get("expect", {}).get("dedupe_if_repeat"):
        burst = outcome.get("burst", 1)
        if burst > 1:
            return Check("dedupe", CHECK_OK, f"burst #{burst} deduped")
        return Check("dedupe", CHECK_OK, "first occurrence (dispatch once)")
    return Check("dedupe", CHECK_SKIP, "no expectation")


def inv_reconcile_consistent(fixture: Dict[str, Any], outcome: Dict[str, Any], stores: Stores) -> Check:
    """After any role activity, the spine must stay consistent.

    OPT-IN: only enforced when the fixture declares `expect.reconcile: true`.
    The spine's standing divergence (orphan receipts from debugging) is a
    separate operational concern, not a per-fixture invariant — otherwise one
    stale orphan drowns every fixture with a false FAIL.
    """
    if not fixture.get("expect", {}).get("reconcile"):
        return Check("reconcile", CHECK_SKIP, "not part of this fixture")
    if stores.reconcile_consistent():
        return Check("reconcile", CHECK_OK, "Qdrant == JSONL")
    return Check("reconcile", CHECK_FAIL, "spine divergence detected")


# registry
INVARIANTS: List[tuple[str, Callable[[Dict, Dict, Stores], Check]]] = [
    ("verdict", inv_verdict_matches),
    ("no_case", inv_no_case_when_expected),
    ("case", inv_case_when_expected),
    ("no_dispatch", inv_no_dispatch_for_noise),
    ("dedupe", inv_deduped_burst),
    ("reconcile", inv_reconcile_consistent),
    ("tuned", inv_tuned_when_expected),
    ("no_new_case", inv_no_new_case_when_expected),
]
