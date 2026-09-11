#!/usr/bin/env python3
"""Non-vacuity test for the ticket -> case-spine decision write-back.

The bug this guards (live spine, Sep 2026): `adjudicate()` recorded the human
verdict in the ticket file + the tuning ledger but NEVER on the case, so 1,708
of 2,078 adjudicated tickets pointed at cases sitting `state=new` — the
advisory rendered "under review" for an incident a human had already denied,
and the coverage number counted decided work as open.

What is asserted (each one can FAIL, which is the point):
  1. `case_decision` reads the top-level `supervisory` block.
  2. ...and the timeline-event shape (hunt findings), and ROUTER adjudication.
  3. ...and returns ("", "") for an undecided case — the negative probe that
     makes the write-back's idempotency check meaningful.
  4. `can_decide` is honest: new -> True, closed/archived -> False.
  5. write-back on an undecided case: outcome `written`, and the decision is
     then readable from the spine by the SAME helper the advisory uses.
  6. replaying the same ticket: outcome `already_decided`, decision unchanged
     (no double-decide, no CaseStateError escape).
  7. a closed case is reported `unreachable:closed`, never forced.
  8. ticket decisions normalize (auto_fp -> fp) while the TICKET keeps its
     original string as the audit record.
  9. the ticket's `case_id` resolves from BOTH shapes (top-level and detail).

Hermetic: in-memory fake memory (no Qdrant), temp audit dir, temp ticket dir.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import CaseStore, can_decide, case_decision  # noqa: E402
from tools.supervisory_tools import SupervisoryClient  # noqa: E402

FAILS = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


class _FakeMemory:
    """Qdrant stand-in: case payloads + event-points (same as the lifecycle test)."""

    def __init__(self):
        self.store: dict[str, dict] = {}
        self.events: dict[str, dict] = {}

    def upsert_point(self, collection, point_id, payload, vector=None):
        self.events[point_id] = dict(payload)

    def events_for(self, collection, case_id):
        out = [p for p in self.events.values() if p.get("case_id") == case_id]
        out.sort(key=lambda p: p.get("ts", ""))
        return out

    def get_by_payload(self, collection, field, value):
        if field == "case_id" and value in self.store:
            return {"content": f"{value} {json.dumps(self.store[value])}", "case_id": value}
        return None

    def search_memory(self, collection, query, limit=5, scroll_limit=1000):
        out = []
        for cid, case in self.store.items():
            if query in cid:
                out.append({"id": cid, "content": f"{cid} {json.dumps(case)}",
                            "timestamp": case.get("ts", "")})
        return out[:limit]

    class _Client:
        def __init__(self, store):
            self._store = store

        def upsert(self, collection_name, points, **kw):
            for p in points:
                payload = p.payload or {}
                content = payload.get("content", "")
                cid = payload.get("case_id") or content.split(" ", 1)[0]
                self._store[cid] = json.loads(content.split(" ", 1)[1])

        def count(self, collection_name, exact=True):
            class _C:
                count = len(self._store)
            return _C()

        def scroll(self, collection_name, limit=100, with_payload=True, with_vectors=False):
            pts = [type("P", (), {"id": cid, "payload": {
                "content": f"{cid} {json.dumps(case)}", "case_id": cid}})
                for cid, case in self._store.items()]
            return pts, None

    def __getattr__(self, name):
        if name == "client":
            return self._Client(self.store)
        raise AttributeError(name)


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        cs = CaseStore.__new__(CaseStore)
        cs.audit_dir = Path(td)
        cs.cases_file = Path(td) / "cases.jsonl"
        cs._memory = _FakeMemory()

        # SupervisoryClient without the constructor (it would build real
        # analyst/ticket-dir singletons); inject the fake store instead.
        sup = SupervisoryClient.__new__(SupervisoryClient)
        sup.ticket_dir = Path(td)
        sup.audit_dir = Path(td)
        sup._cases = cs
        sup._analyst = None

        # --- 1-3. case_decision reads BOTH shapes, and is empty when undecided
        undecided = {"case_id": "case-u", "state": "new", "timeline": [
            {"role": "analyst", "type": "verdict", "detail": {"verdict": "escalate"}}]}
        check("1 undecided case yields no decision (negative probe)",
              case_decision(undecided) == ("", ""), str(case_decision(undecided)))

        top = {"supervisory": {"decision": "deny", "rationale": "policy"}, "timeline": []}
        check("2a top-level supervisory block read",
              case_decision(top) == ("deny", "policy"), str(case_decision(top)))

        ev = {"timeline": [{"role": "supervisory", "type": "adjudication",
                            "detail": {"decision": "approve", "rationale": "scored high"}}]}
        check("2b timeline adjudication event read",
              case_decision(ev) == ("approve", "scored high"), str(case_decision(ev)))

        rt = {"timeline": [{"role": "router", "type": "adjudication",
                            "detail": {"decision": "approve", "rationale": "infra tier1"}}]}
        check("2c router adjudication read (infra authority)",
              case_decision(rt) == ("approve", "infra tier1"), str(case_decision(rt)))

        # --- 4. can_decide honesty
        check("4 can_decide: new True / closed False / archived False",
              can_decide("new") and not can_decide("closed") and not can_decide("archived"))

        # --- 5. write-back on an undecided case
        c = cs.open_case(source={"rule_id": "R1"}, title="[ROUTER] INFRA alert lvl=5 on h")
        cid = c["case_id"]
        ticket = {"ticket_id": "t1", "case_id": cid, "decision": "approve",
                  "rationale": "router approved infra"}
        res = sup.sync_case_decision(ticket, dry_run=False, attach=False)
        check("5a write-back outcome written", res.get("outcome") == "written", str(res))
        after = cs.get_case(cid)
        check("5b decision readable from the spine by the shared helper",
              case_decision(after or {})[0] == "approve", str(case_decision(after or {})))

        # --- 6. replay is idempotent (no double-decide, no exception)
        res2 = sup.sync_case_decision(ticket, dry_run=False, attach=False)
        check("6 replay -> already_decided", res2.get("outcome") == "already_decided",
              str(res2))

        # --- 7. closed case is unreachable, never forced
        c2 = cs.open_case(source={"rule_id": "R2"}, title="[ROUTER] INFRA alert lvl=5 on h2")
        cid2 = c2["case_id"]
        cs.close_case(cid2, reason="closed before the write-back existed")
        res3 = sup.sync_case_decision(
            {"ticket_id": "t2", "detail": {"case_id": cid2}, "decision": "deny"},
            dry_run=False, attach=False)
        check("7a detail-shaped case_id resolved + closed reported",
              res3.get("outcome") == "unreachable:closed", str(res3))
        check("7b closed case still carries NO decision (nothing forced)",
              case_decision(cs.get_case(cid2) or {})[0] == "",
              str(case_decision(cs.get_case(cid2) or {})))

        # --- 8. normalization: auto_fp -> fp, ticket string preserved
        c3 = cs.open_case(source={"rule_id": "R3"}, title="[ANALYST] case-x drill")
        cid3 = c3["case_id"]
        t3 = {"ticket_id": "t3", "case_id": cid3, "decision": "auto_fp", "rationale": "fp"}
        sup.sync_case_decision(t3, dry_run=False, attach=False)
        check("8a auto_fp normalized to fp on the spine",
              case_decision(cs.get_case(cid3) or {})[0] == "fp",
              str(case_decision(cs.get_case(cid3) or {})))
        check("8b ticket keeps the original string", t3["decision"] == "auto_fp")

        # --- 9. ticket with no case_id is a clean no-op
        res4 = sup.sync_case_decision({"ticket_id": "t4", "decision": "deny"}, attach=False)
        check("9 no case_id -> no_case_id outcome",
              res4.get("outcome") == "no_case_id", str(res4))

        # --- 10. DRY RUN PREDICTS WHAT APPLY DOES (a dry run that promises
        # writes the apply refuses is a lying tool — it predicted 89 backlog
        # writes and landed 2 before the lifecycle gate moved ahead of the
        # dry-run branch).
        c4 = cs.open_case(source={"rule_id": "R4"}, title="[ROUTER] INFRA alert lvl=5 on h4")
        cid4 = c4["case_id"]
        cs.close_case(cid4, reason="closed before backfill")
        dry_closed = sup.sync_case_decision(
            {"ticket_id": "t5", "case_id": cid4, "decision": "deny"}, dry_run=True, attach=False)
        check("10a dry run on a closed case reports unreachable, not would_write",
              dry_closed.get("outcome") == "unreachable:closed", str(dry_closed))
        c5 = cs.open_case(source={"rule_id": "R5"}, title="[ROUTER] INFRA alert lvl=5 on h5")
        dry_open = sup.sync_case_decision(
            {"ticket_id": "t6", "case_id": c5["case_id"], "decision": "deny"},
            dry_run=True, attach=False)
        check("10b dry run on an open undecided case reports would_write",
              dry_open.get("outcome") == "would_write", str(dry_open))
        check("10c dry run wrote nothing",
              case_decision(cs.get_case(c5["case_id"]) or {})[0] == "")

    print("\nNON-VACUOUS" if FAILS == 0 else f"\n{FAILS} NON-VACUITY FAILURES")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
