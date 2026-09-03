#!/usr/bin/env python3
"""Non-vacuity test for the case lifecycle state machine (SO parity).

Proves the machine is real and enforced:
  - mint -> state "new", status "open", assignment history recorded
  - investigation event  -> investigating (opportunistic advance)
  - escalate/verdict     -> awaiting_decision
  - decide()             -> decided, status STAYS open (approve != close)
  - close_case()         -> closed via the machine
  - reopen()             -> reopened (back into the flow)
  - illegal transition (decided -> triage) RAISES CaseStateError
  - assignment history accumulates (mint + assign)

Hermetic: in-memory fake memory (no Qdrant), temp audit dir.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import CaseStore, CaseStateError  # noqa: E402


class _FakeMemory:
    """Minimal QdrantMemory stand-in: search_memory + client.count/scroll."""

    def __init__(self):
        self.store: dict[str, dict] = {}  # case_id -> case dict

    def search_memory(self, collection, query, limit=5, scroll_limit=1000):
        out = []
        for cid, case in self.store.items():
            if query in cid:
                out.append({"id": cid, "content": f"{cid} {__import__('json').dumps(case)}",
                            "timestamp": case.get("ts", "")})
        return out[:limit]

    class _Client:
        def __init__(self, store):
            self._store = store

        def upsert(self, collection_name, points, **kw):
            for p in points:
                import json as _json
                payload = p.payload or {}
                content = payload.get("content", "")
                cid = payload.get("case_id") or content.split(" ", 1)[0]
                self._store[cid] = _json.loads(content.split(" ", 1)[1])

        def count(self, collection_name, exact=True):
            class _C:
                count = len(self._store)
            return _C()

        def scroll(self, collection_name, limit=100, with_payload=True, with_vectors=False):
            pts = []
            for cid, case in self._store.items():
                pts.append(type("P", (), {"id": cid, "payload": {
                    "content": f"{cid} {__import__('json').dumps(case)}",
                    "case_id": cid}}))
            return pts, None

    def __getattr__(self, name):
        if name == "client":
            return self._Client(self.store)
        raise AttributeError(name)


def main() -> int:
    fails = 0

    with tempfile.TemporaryDirectory() as td:
        cs = CaseStore.__new__(CaseStore)
        cs.audit_dir = Path(td)
        cs.cases_file = Path(td) / "cases.jsonl"
        cs._memory = _FakeMemory()

        # 1. mint
        c = cs.open_case(source={"rule_id": "T1"}, title="lifecycle",
                         assignee="analyst")
        cid = c["case_id"]
        ok1 = c["state"] == "new" and c["status"] == "open"
        ok1b = c["assignment_history"][-1]["assignee"] == "analyst"
        print(f"1 mint: state={c['state']} status={c['status']} hist={ok1b} (want new/open/True)")
        if not (ok1 and ok1b):
            fails += 1

        # 2. investigation -> investigating
        cs.append_event(cid, "analyst", "investigation", {"h": 1})
        s2 = cs.get_case(cid)["state"]
        print(f"2 investigation: {s2} (want investigating)")
        if s2 != "investigating":
            fails += 1

        # 3. verdict -> awaiting_decision
        cs.append_event(cid, "analyst", "verdict", {"verdict": "escalate"})
        s3 = cs.get_case(cid)["state"]
        print(f"3 verdict: {s3} (want awaiting_decision)")
        if s3 != "awaiting_decision":
            fails += 1

        # 4. decide -> decided, status STAYS open
        cs.decide(cid, "approve", "test approve")
        g4 = cs.get_case(cid)
        ok4 = g4["state"] == "decided" and g4["status"] == "open"
        ok4b = (g4.get("supervisory") or {}).get("decision") == "approve"
        print(f"4 decide: state={g4['state']} status={g4['status']} sup={ok4b} (want decided/open/True)")
        if not (ok4 and ok4b):
            fails += 1

        # 5. illegal: decided -> triage must raise
        try:
            cs.transition(cid, "triage", role="analyst")
            print("5 illegal transition: ALLOWED (BUG)")
            fails += 1
        except CaseStateError:
            print("5 illegal transition: blocked OK")

        # 6. close via machine
        cs.close_case(cid, role="supervisory", reason="test close")
        g6 = cs.get_case(cid)
        ok6 = g6["state"] == "closed" and g6["status"] == "closed"
        has_close_ev = any(e.get("type") == "case_closed" for e in g6.get("timeline", []))
        print(f"6 close: state={g6['state']} status={g6['status']} close_ev={has_close_ev}")
        if not (ok6 and has_close_ev):
            fails += 1

        # 7. reopen
        cs.reopen(cid, role="supervisory", rationale="test reopen")
        g7 = cs.get_case(cid)
        print(f"7 reopen: state={g7['state']} status={g7['status']} (want reopened/open)")
        if g7["state"] != "reopened" or g7["status"] != "open":
            fails += 1

        # 8. assignment history accumulates on reassign
        cs.assign_case(cid, "responder", note="handoff")
        g8 = cs.get_case(cid)
        hist = [(h["assignee"], h["by"]) for h in g8.get("assignment_history", [])]
        ok8 = hist[-1] == ("responder", "assign") and len(hist) >= 2
        print(f"8 assignment history: {hist} (want >=2 entries, responder last)")
        if not ok8:
            fails += 1

        # 9. direct triage-deny from fresh case (new -> decided) is legal
        c2 = cs.open_case(source={"rule_id": "T2"}, title="triage-deny")
        cid2 = c2["case_id"]
        cs.decide(cid2, "deny", "triage deny")
        g9 = cs.get_case(cid2)
        print(f"9 triage-deny: state={g9['state']} status={g9['status']} (want decided/open)")
        if g9["state"] != "decided" or g9["status"] != "open":
            fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
