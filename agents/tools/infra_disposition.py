"""The ONE derivation of a router-minted INFRA case's disposition.

WHY THIS MODULE EXISTS: `dispatch_infra` mints a spine case per fleet-health
event and recommends a playbook — and nothing ever decided it. Those cases sat
`state=new` forever: no decision on the spine, so the advisory rendered
"under review" for an event the platform had already handled and every audit of
decided-but-open work found the SAME list, one event longer each sweep (Sep 11:
64 applied, then 7 pending — the class recurred because the rule did not live
in the cadence that mints the case). The rule existed only as a terminal script
(`deploy/lab/dispose_infra_cases.py`).

Same failure shape as the decision-reader drift (`b12264b`): a second copy of a
policy is a copy that goes stale. Now the router applies this at mint time and
the lab tool delegates here, so a DRY RUN and a LIVE DISPATCH cannot disagree
about what a given case's disposition should be.

THE AUTHORITY (no new policy invented here): by operator policy 2026-09-09 the
ROUTER approves INFRA tier0/1 and is explicitly barred from tier2. That rule is
already encoded in the ontology (`docs/ontology/ssop.ttl`), in
`case_decision`'s router branch, and in the advisory's decision reader. This
module applies exactly that rule:

  tier0/tier1 recommended playbook -> decision `approve` (the playbook is
      verify/known-safe; approve != close, so the responder still executes)
  no playbook / unknown / tier-less -> decision `operational` (routine
      fleet-health event, no response required — never an approval)
  tier2 playbook -> decision `operational` (a tier2 action is
      supervisory/human-only by construction, so the router records that no
      router response applies; it never authorizes one)
  category is not `infra` -> refused, untouched (a security/threat case is the
      supervisory path's business at any tier)
  playbook library unreadable -> DEFERRED (not eligible). Recording "no
      response required" for a playbook-backed event because the library read
      failed would be a decision made from missing data; the case stays
      undecided and the next sweep retries.

PURE: reads a case dict, returns a verdict dict. Writes nothing, imports no
store at module level, so both the router and the offline tests can call it.

NULL-SHAPE RULE (spine code): case payloads round-trip through Qdrant as JSON,
so an absent field comes back PRESENT-AND-NULL and `case.get(x, {})` returns
None. Every read here is `case.get(x) or default`.
"""
from __future__ import annotations

from typing import Any

#: Categories this disposition is allowed to touch. Anything else is refused.
INFRA_CATEGORIES = {"infra"}

#: The mint marker `dispatch_infra` puts in every case it creates. A case
#: without it was not minted by the router cadence — the terminal sweep has no
#: business deciding it (same rule the lab tool has always applied).
ROUTER_MINT_MARK = "[ROUTER]"

#: reason codes (stable strings: the lab tool counts them, tests assert them)
REASON_ELIGIBLE = "eligible"
REASON_ALREADY_DECIDED = "already_decided"
REASON_NOT_ROUTER_MINTED = "not_router_minted"
REASON_UNREACHABLE = "unreachable"           # + ":<state>" — lifecycle refuses
REASON_LIBRARY_UNAVAILABLE = "playbook_library_unavailable"
REASON_CATEGORY = "category"                 # + "=<cat>"


def case_category(case: dict[str, Any]) -> str:
    """The case's category, from `source` (mint) or the dispatch event."""

    def _from_detail(detail: Any) -> str:
        return str((detail or {}).get("category") or "").lower() \
            if isinstance(detail, dict) else ""

    cat = str((case.get("source") or {}).get("category") or "").lower()
    if cat:
        return cat
    for ev in case.get("timeline") or []:
        if not isinstance(ev, dict):
            continue
        cat = _from_detail(ev.get("detail"))
        if cat:
            return cat
    return ""


def recommended_playbook(case: dict[str, Any]) -> str:
    """The playbook the router recommended for this case, if any."""

    def _from_detail(detail: Any) -> str:
        return str((detail or {}).get("recommended_playbook") or "") \
            if isinstance(detail, dict) else ""

    pb = str((case.get("source") or {}).get("recommended_playbook") or "")
    if pb:
        return pb
    for ev in case.get("timeline") or []:
        if not isinstance(ev, dict):
            continue
        pb = _from_detail(ev.get("detail"))
        if pb:
            return pb
    return ""


def playbook_tier(playbooks: Any, name: str) -> str:
    """The `approval` tier of a named playbook ('' when unknown/tier-less)."""
    pb = playbooks.get(name) if isinstance(playbooks, dict) else None
    return str(getattr(pb, "approval", "") or "")


def infra_disposition(case: dict[str, Any], playbooks: Any,
                      recommended: str | None = None) -> dict[str, Any]:
    """Decide what a router-minted INFRA case's disposition should be.

    `playbooks` is the loaded playbook library (name -> playbook) or None when
    it could not be read — None DEFERS rather than guessing a tier.

    `recommended` is the recommendation the CALLER has just made (the router
    dispatch path knows it for the alert in hand). None means "derive it from
    the case's own record" — the terminal sweep's mode, and the only honest one
    for a backlog case whose dispatch event is the surviving evidence. The
    caller's value wins because a live dispatch may legitimately recommend a
    new playbook (level rose) for a case minted earlier with another one.

    Returns {"eligible": bool, "decision": str, "rationale": str,
             "reason": str, "playbook": str, "tier": str}. Never raises on a
    malformed case: an undecidable case comes back ineligible with a reason.
    """
    from tools.case_tools import can_decide, case_decision  # lazy: no import cycle

    out = {"eligible": False, "decision": "", "rationale": "", "reason": "",
           "playbook": "", "tier": ""}

    if case_decision(case)[0]:
        out["reason"] = REASON_ALREADY_DECIDED
        return out
    if ROUTER_MINT_MARK not in str(case.get("title") or ""):
        out["reason"] = REASON_NOT_ROUTER_MINTED
        return out
    cat = case_category(case)
    if cat not in INFRA_CATEGORIES:
        out["reason"] = f"{REASON_CATEGORY}={cat or 'unknown'}"
        return out
    state = str(case.get("state") or "new")
    if not can_decide(state):
        out["reason"] = f"{REASON_UNREACHABLE}:{state}"
        return out

    pb_name = recommended if recommended is not None else recommended_playbook(case)
    pb_name = str(pb_name or "")
    out["playbook"] = pb_name
    if playbooks is None:
        # Missing data is not a disposition. Leave it undecided.
        out["reason"] = REASON_LIBRARY_UNAVAILABLE
        return out
    tier = playbook_tier(playbooks, pb_name) if pb_name else ""
    out["tier"] = tier

    out["eligible"] = True
    out["reason"] = REASON_ELIGIBLE
    if tier in ("tier0", "tier1"):
        out["decision"] = "approve"
        out["rationale"] = (
            f"router adjudication (infra): tier{tier[-1]} playbook {pb_name} "
            f"authorized under operator policy 2026-09-09 — router approves "
            f"INFRA tier0/1 only")
        return out
    why = (f"playbook {pb_name} is tier{tier[-1]}" if tier == "tier2"
           else (f"playbook {pb_name} unknown/tier-less" if pb_name
                 else "no playbook recommended"))
    out["decision"] = "operational"
    out["rationale"] = (f"router disposition (infra): routine fleet-health "
                        f"event, no response required ({why})")
    return out
