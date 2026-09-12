#!/usr/bin/env python3
"""Non-vacuity test for INFRA disposition in the router cadence (thread #1).

The gap this guards: `dispatch_infra` minted a spine case per fleet-health
event, recommended a playbook, and NOTHING ever decided it. The rule lived only
in `deploy/lab/dispose_infra_cases.py`, so the undecided backlog grew one event
per sweep (64 applied Sep 11, 7 more pending hours later — the class recurred
because the cadence that mints the case did not apply the rule).

What is asserted (each one can FAIL, which is the point):
  1. an INFRA alert with a tier1 recommendation is decided BY THE ROUTER as it
     mints — state=decided, decision=approve, role=router on the sup block.
  2. approve is NOT a close: the case is still open for the responder.
  3. the disposition is derivable from the case's OWN record (the store view,
     which has no timeline) — the dry-run/live-dispatch parity property. If the
     sweep and the cadence disagree about a case, one of them is lying.
  4. a tier2 recommendation is NEVER an approval — it records `operational`
     (a tier2 action is supervisory-only by construction).
  5. no recommendation -> `operational`, with the honest reason.
  6. a non-INFRA category (threat) is REFUSED, case left undecided — a security
     case is never the router's to adjudicate.
  7. an unreadable playbook library DEFERS (case undecided), never guesses a
     tier into an approval or a "no response required".
  8. re-dispatch of a decided case attaches and does NOT rewrite the decision.
  9. attribution: `case_adjudication` reports role=router for a router-stamped
     block AND for a legacy block that only carries it on the timeline event —
     while a genuinely human decision is still reported supervisory.
 10. a case not minted by the router is never touched (the sweep's guard).

Hermetic: fake CaseStore + monkeypatched registry getters + a fake playbook
library. No Qdrant, no network, no live services.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import router  # noqa: E402
import tools.playbook_loader as pl  # noqa: E402
from tools.case_tools import case_adjudication  # noqa: E402
from tools.infra_disposition import infra_disposition  # noqa: E402

FAILS = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


class _PB:
    """Playbook stand-in: only the fields the router + derivation read."""

    def __init__(self, name, approval, category="infra", min_level=4):
        self.name = name
        self.approval = approval
        self.trigger_category = category
        self.trigger_min_level = min_level
        self.trigger_rule_ids = []


LIB = {
    "service-impact-check": _PB("service-impact-check", "tier1", min_level=4),
    "restart-flapping-service": _PB("restart-flapping-service", "tier1", min_level=5),
    "drain-and-reimage": _PB("drain-and-reimage", "tier2", min_level=6),
}


class _FakeCaseStore:
    """In-memory CaseStore with the lifecycle semantics the router relies on."""

    def __init__(self):
        self.cases: dict[str, dict] = {}

    # --- reads -----------------------------------------------------------
    def recent_host_cases(self, host, rule_id=None, window_s=3600, open_only=False):
        out = []
        for c in self.cases.values():
            if str(c["source"].get("agent")) != str(host):
                continue
            if rule_id is not None and str(c["source"].get("rule_id")) != str(rule_id):
                continue
            if c.get("status") == "closed":
                continue
            out.append(c)
        return out

    # --- writes ----------------------------------------------------------
    def open_case(self, source, title, observables=None, assignee=None):
        cid = f"case-{len(self.cases):04d}"
        case = {"case_id": cid, "title": title, "status": "open", "state": "new",
                "source": source, "timeline": [], "assignee": assignee}
        self.cases[cid] = case
        return case

    def append_event(self, case_id, role, etype, detail):
        self.cases[case_id]["timeline"].append(
            {"ts": "2026-09-12T00:00:00+00:00", "role": role, "type": etype,
             "detail": detail})

    def decide(self, case_id, decision, rationale, role="supervisory"):
        case = self.cases[case_id]
        if case.get("state") != "new":
            raise RuntimeError(f"illegal transition {case.get('state')} -> decided")
        case["state"] = "decided"
        case["supervisory"] = {"decision": decision, "rationale": rationale,
                               "ts": "2026-09-12T00:00:01+00:00", "role": role}
        case["timeline"].append(
            {"ts": "2026-09-12T00:00:01+00:00", "role": role, "type": "adjudication",
             "detail": {"decision": decision, "rationale": rationale}})
        return case


class _FakeIndexer:
    backend = "wazuh"
    field_timestamp = "timestamp"


class _FakeSelfHeal:
    def sense(self, agent):
        return {}

    def decide(self, agent, sense):
        return []


def _store_view(case: dict) -> dict:
    """The case AS THE STORE SEES IT: state fields only, no timeline.

    This is what the backlog sweep reads (the case point carries state fields;
    timeline events are separate points), so it is the shape the parity
    property has to hold on.
    """
    return {k: v for k, v in case.items() if k != "timeline"}


def _alert(agent="kb-vec", rid=541, level=4,
           desc="Systemd: Service exited due to a failure."):
    return {"id": "", "timestamp": "", "agent": {"name": agent},
            "rule": {"id": rid, "level": level, "description": desc}}


def _wire(store):
    router.get_cases = lambda: store
    router.get_indexer = lambda: _FakeIndexer()
    router.get_selfheal = lambda: _FakeSelfHeal()


def run():
    pl.load_playbooks = lambda: LIB          # hermetic library

    # 1/2/3 — tier1 recommendation -> router approves at mint; parity holds
    store = _FakeCaseStore()
    _wire(store)
    r = router.dispatch_infra(_alert())
    case = store.cases[r["case_id"]]
    check("tier1 minted case is decided approve by the router",
          case["state"] == "decided" and r.get("decision") == "approve",
          f"state={case['state']} result={r.get('decision')}")
    check("the router is the recorded adjudicator (sup block role)",
          (case.get("supervisory") or {}).get("role") == "router",
          str(case.get("supervisory")))
    check("approve is not a close — case still open for the responder",
          case.get("status") == "open", str(case.get("status")))
    # Parity asked the right way: strip the recorded decision and let the
    # derivation re-run on the case's OWN record (no timeline — the shape the
    # backlog sweep reads). It must reach the same verdict the cadence did.
    view = _store_view(case)
    view.pop("supervisory", None)
    view["state"] = "new"
    d = infra_disposition(view, LIB)
    check("parity: the store view derives the SAME decision",
          d["eligible"] and d["decision"] == r.get("decision"),
          f"derived={d['decision']!r} reason={d['reason']!r} recorded={r.get('decision')!r}")
    check("parity: the store view names the same playbook the cadence used",
          d["playbook"] == "service-impact-check" and d["tier"] == "tier1", str(d))

    # 4 — tier2 recommendation is never authorized by the router
    store = _FakeCaseStore()
    _wire(store)
    r = router.dispatch_infra(_alert(level=6))
    case = store.cases[r["case_id"]]
    check("tier2 recommendation -> operational, NEVER approve",
          r.get("decision") == "operational" and case["state"] == "decided",
          f"decision={r.get('decision')} state={case['state']}")
    check("tier2 rationale names the tier, not an approval",
          "tier2" in ((case.get("supervisory") or {}).get("rationale") or ""),
          str(case.get("supervisory")))

    # 5 — no recommendation -> operational with an honest reason
    store = _FakeCaseStore()
    _wire(store)
    r = router.dispatch_infra(_alert(level=1, rid=531, desc="Low disk space"))
    check("no recommendation -> operational (no response required)",
          r.get("decision") == "operational", str(r.get("decision")))
    check("no-recommendation rationale says so",
          "no playbook recommended" in
          ((store.cases[r["case_id"]].get("supervisory") or {}).get("rationale") or ""))

    # 6 — a non-INFRA category is refused, case left undecided
    store = _FakeCaseStore()
    _wire(store)
    r = router.dispatch_infra(_alert(rid=86610, level=12,
                                     desc="Suricata: Alert - ET MALWARE C2 Beacon"))
    case = store.cases[r["case_id"]]
    check("security-category case is NOT adjudicated by the router",
          case["state"] == "new" and not (case.get("supervisory") or {}),
          f"state={case['state']} sup={case.get('supervisory')}")
    check("refusal is reported with its reason",
          str(r.get("disposition_skipped", "")).startswith("category="),
          str(r.get("disposition_skipped")))

    # 7 — unreadable library DEFERS: no decision from missing data
    def _boom():
        raise RuntimeError("library unreadable")

    pl.load_playbooks = _boom
    store = _FakeCaseStore()
    _wire(store)
    r = router.dispatch_infra(_alert())
    case = store.cases[r["case_id"]]
    check("unreadable playbook library leaves the case UNDECIDED",
          case["state"] == "new" and r.get("disposition_skipped") ==
          "playbook_library_unavailable",
          f"state={case['state']} skipped={r.get('disposition_skipped')}")
    pl.load_playbooks = lambda: LIB

    # 8 — re-dispatch attaches, never rewrites the decision
    store = _FakeCaseStore()
    _wire(store)
    r1 = router.dispatch_infra(_alert())
    first = dict(store.cases[r1["case_id"]].get("supervisory") or {})
    r2 = router.dispatch_infra(_alert())
    check("re-dispatch ATTACHES to the decided open case",
          r2.get("attached") is True and r2["case_id"] == r1["case_id"])
    check("re-dispatch does not rewrite the recorded decision",
          (store.cases[r1["case_id"]].get("supervisory") or {}) == first
          and r2.get("disposition_skipped") == "already_decided",
          str(r2.get("disposition_skipped")))

    # 9 — attribution, forward and legacy
    legacy_router = {"title": "[ROUTER] INFRA alert", "state": "decided",
                     "supervisory": {"decision": "approve", "rationale": "x",
                                     "ts": "t"},
                     "timeline": [{"role": "router", "type": "adjudication",
                                   "detail": {"decision": "approve"}}]}
    human = {"title": "[HUNT] finding", "state": "decided",
             "supervisory": {"decision": "deny", "rationale": "y", "ts": "t"},
             "timeline": [{"role": "supervisory", "type": "adjudication",
                           "detail": {"decision": "deny"}}]}
    undecided = {"title": "[ROUTER] INFRA alert", "state": "new",
                 "timeline": [{"role": "router", "type": "dispatch",
                               "detail": {"verdict": "escalate"}}]}
    check("legacy router decision (role only on the event) reads as router",
          case_adjudication(legacy_router).get("role") == "router",
          str(case_adjudication(legacy_router)))
    check("a human decision is still reported supervisory",
          case_adjudication(human).get("role") == "supervisory",
          str(case_adjudication(human)))
    check("a dispatch event alone is NOT a decision (undecided stays empty)",
          case_adjudication(undecided) == {}, str(case_adjudication(undecided)))

    # 10 — the sweep's guard: a case the router did not mint is never touched
    foreign = {"title": "Some analyst case", "state": "new",
               "source": {"category": "infra"},
               "supervisory": None, "timeline": []}
    d = infra_disposition(foreign, LIB)
    check("non-router-minted case is refused by the derivation",
          not d["eligible"] and d["reason"] == "not_router_minted", str(d))

    print(f"\n{'PASS' if not FAILS else 'FAIL'} — infra disposition in the router "
          f"cadence ({10 - FAILS}/10 checks)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(run())
