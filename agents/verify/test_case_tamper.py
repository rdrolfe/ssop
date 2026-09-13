#!/usr/bin/env python3
"""Non-vacuity test for case-payload tamper detection (issue #28, criterion 4).

Proves reconciliation compares CONTENT, not just id sets:
  - a healthy dual-written case verifies (signed digest == payload digest)
  - a same-ID payload rewrite is reported as drifted/tampered, even though the
    id sets still match (the old comparison's blind spot) — the assertion
    `id_sets_match and tampered` IS the proof that the new check adds signal
  - rewriting only a QUERYABLE PROJECTION (title), not the embedded document,
    is caught too (the digest covers the whole payload)
  - a forged receipt record whose digest matches the tampered payload is caught
    by HMAC authenticity — i.e. trusting the file without verifying it would
    have reported this tamper as clean
  - drifted points are REPORTED, never auto-repaired (the tampered payload is
    evidence and must survive the check)
  - a case with no signed digest (pre-#28 record) is `unverified`, NOT
    tampered — coverage gaps must not masquerade as alarms
  - healing a missing point re-attests the repaired payload, so the repair is
    not itself reported as drift on the next run

Hermetic: in-memory fake memory (no Qdrant), temp audit dir + audit key.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.audit_chain import AuditChainWriter  # noqa: E402
from tools.case_tools import (  # noqa: E402
    CaseStore, case_payload_digest, case_point_payload,
)


class _Rec:
    """A scroll record: what Qdrant hands back (id + payload)."""

    def __init__(self, point_id: str, payload: dict):
        self.id = point_id
        self.payload = payload


class _FakeMemory:
    """QdrantMemory stand-in: raw payloads in, raw payloads out.

    Unlike the lifecycle fake this one keeps the FULL payload (not just the
    embedded case dict), because the thing under test is the payload digest.
    """

    def __init__(self):
        self.points: dict[str, dict] = {}    # point id -> payload (case points)
        self.events: dict[str, dict] = {}    # event point id -> payload

    # --- event points ---
    def upsert_point(self, collection, point_id, payload, vector=None):
        self.events[point_id] = dict(payload)

    def events_for(self, collection, case_id):
        out = [p for p in self.events.values() if p.get("case_id") == case_id]
        out.sort(key=lambda p: p.get("ts", ""))
        return out

    # --- case points ---
    def get_by_payload(self, collection, field, value):
        if field == "case_id":
            for payload in self.points.values():
                if payload.get("case_id") == value:
                    return dict(payload)
        return None

    def search_memory(self, collection, query, limit=5, scroll_limit=1000):
        out = []
        for pid, payload in self.points.items():
            if query in str(payload.get("content", "")):
                out.append({"id": pid, "content": payload.get("content", ""),
                            "timestamp": payload.get("timestamp", ""),
                            "metadata": {k: v for k, v in payload.items()
                                         if k not in ("content", "timestamp")}})
        return out[:limit]

    def scroll_all(self, collection, **kw):
        for pid, payload in list(self.points.items()):
            yield _Rec(pid, payload)

    def point_id_for(self, case_id: str) -> str | None:
        for pid, payload in self.points.items():
            if payload.get("case_id") == case_id:
                return pid
        return None

    class _Client:
        def __init__(self, points):
            self._points = points

        def upsert(self, collection_name, points, **kw):
            for p in points:
                self._points[str(p.id)] = dict(p.payload or {})

        def count(self, collection_name, exact=True):
            class _C:
                count = len(self._points)
            return _C()

    def __getattr__(self, name):
        if name == "client":
            return self._Client(self.points)
        raise AttributeError(name)


def _store(td: Path) -> tuple[CaseStore, _FakeMemory]:
    cs = CaseStore.__new__(CaseStore)
    cs.audit_dir = td
    cs.cases_file = td / "cases.jsonl"
    mem = _FakeMemory()
    cs._memory = mem
    return cs, mem


def _tamper_content(mem: _FakeMemory, case_id: str, new_title: str) -> None:
    """Rewrite the embedded document in place — same point id, same case_id."""
    pid = mem.point_id_for(case_id)
    assert pid, f"no point for {case_id}"
    payload = mem.points[pid]
    case = json.loads(payload["content"].split(" ", 1)[1])
    case["title"] = new_title
    case["injected"] = "attacker-supplied content"
    payload["content"] = f"{case_id} {json.dumps(case)}"


def _tamper_projection(mem: _FakeMemory, case_id: str, title: str) -> None:
    """Rewrite only a queryable projection; leave the document untouched."""
    pid = mem.point_id_for(case_id)
    assert pid, f"no point for {case_id}"
    mem.points[pid]["title"] = title


def _forge_receipt(cs: CaseStore, case_id: str, digest: str) -> None:
    """Append a RECORD that agrees with a tampered payload but is not signed.

    Uses the REAL key_id (it is visible in the file) with a garbage hash: that
    is what an attacker with store access but no audit key can produce. Reading
    the receipt file without verifying it would accept this record, and because
    it is the newest record its digest would win — reporting the tamper clean.
    """
    key_id = ""
    if cs.cases_file.exists():
        for line in cs.cases_file.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("key_id"):
                key_id = rec["key_id"]
    rec = {
        "v": 2, "seq": 999, "prev_hash": "sha256:GENESIS",
        "event_id": "forged-event", "case_id": case_id,
        "ts": "2026-09-13T00:00:00+00:00", "role": "case-spine",
        "event": "case_opened", "status": "open", "title": "forged",
        "detail": {}, "actor_id": None, "actor_verified": False,
        "key_id": key_id, "payload_digest": digest,
        "hash": "sha256:forged",
    }
    with open(cs.cases_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def main() -> int:
    fails = 0

    def step(label: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        print(f"{'OK  ' if ok else 'FAIL'} {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            fails += 1

    # ---------------------------------------------------------------- 1. legacy
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        # A pre-#28 case: point exists, receipt is signed but carries no digest.
        legacy_case = {"case_id": "case-LEGACY", "title": "old", "status": "open",
                       "ts": "2026-01-01T00:00:00+00:00", "timeline": []}
        mem.points["legacy-point"] = case_point_payload(legacy_case)
        w = AuditChainWriter(cs.cases_file)
        w.write(case_id="case-LEGACY", role="case-spine", event="case_opened",
                status="open", title="old", detail={}, payload_digest=None)
        r = cs.reconcile()
        step("1 legacy receipt: unverified, not tampered",
             r["unverified"] == ["case-LEGACY"] and r["tampered"] is False
             and r["verified_count"] == 0,
             f"unverified={r['unverified']} tampered={r['tampered']}")

    # ------------------------------------------------------- 2. healthy verify
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        c = cs.open_case(source={"rule_id": "T28"}, title="healthy")
        cid = c["case_id"]
        r = cs.reconcile()
        step("2 healthy case verifies against its signed digest",
             r["verified_count"] == 1 and r["tampered"] is False
             and r["consistent"] is True and r["drifted"] == [],
             f"verified={r['verified_count']} consistent={r['consistent']}")

        # Same-ID payload rewrite: the id sets still match.
        _tamper_content(mem, cid, "attacker rewrote this")
        r2 = cs.reconcile()
        step("3 same-ID content rewrite detected (id sets still match)",
             r2["id_sets_match"] is True and r2["tampered"] is True
             and r2["drifted"] == [cid] and r2["consistent"] is False,
             f"id_sets_match={r2['id_sets_match']} drifted={r2['drifted']} "
             f"tampered={r2['tampered']}")
        step("4 drift detail carries both digests",
             r2["drift_detail"].get(cid, {}).get("attested", "").startswith("sha256:")
             and r2["drift_detail"][cid]["attested"]
             != r2["drift_detail"][cid]["observed"],
             str(r2["drift_detail"].get(cid)))

        # The tampered payload must SURVIVE the check (evidence, not repaired).
        pid = mem.point_id_for(cid)
        assert pid is not None
        step("5 drifted point is reported, not auto-repaired",
             "attacker rewrote this" in json.dumps(mem.points[pid]),
             "tampered payload still present in the store")

        # A projection-only rewrite is caught too.
        cs2, mem2 = _store(Path(td) / "proj")
        cs2.cases_file.parent.mkdir(parents=True, exist_ok=True)
        c2 = cs2.open_case(source={"rule_id": "T28"}, title="proj")
        cid2 = c2["case_id"]
        _tamper_projection(mem2, cid2, "attacker title")
        r3 = cs2.reconcile()
        step("6 projection-only rewrite detected",
             r3["drifted"] == [cid2] and r3["tampered"] is True,
             f"drifted={r3['drifted']}")

    # --------------------------------------------------------- 7. forged receipt
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        c = cs.open_case(source={"rule_id": "T28"}, title="forge")
        cid = c["case_id"]
        _tamper_content(mem, cid, "rewritten")
        # A forged record that AGREES with the tampered payload: if reconcile
        # merely read the file, this tamper would look verified.
        pid = mem.point_id_for(cid)
        assert pid is not None
        _forge_receipt(cs, cid, case_payload_digest(mem.points[pid]))
        r = cs.reconcile()
        step("7 forged receipt (digest matches tampered payload) caught by HMAC",
             r["untrusted_receipt"] == [cid] and r["tampered"] is True
             and cid not in r["drifted"],
             f"untrusted={r['untrusted_receipt']} drifted={r['drifted']}")

    # ------------------------------------------- 8. heal re-attests the rebuild
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        c = cs.open_case(source={"rule_id": "T28"}, title="heal")
        cid = c["case_id"]
        # Simulate the .94 loss: receipt survives, point is gone.
        mem.points.clear()
        r = cs.reconcile(heal=True)
        step("8 missing point healed from the receipt",
             r["healed"] == [cid] and r["receipt_only"] == [],
             f"healed={r['healed']} receipt_only={r['receipt_only']}")
        # The rebuild is lossy — it must be re-attested, not read as drift.
        r2 = cs.reconcile(heal=False)
        step("9 healed point verifies on the next run (repair re-attested)",
             r2["drifted"] == [] and r2["tampered"] is False
             and r2["verified_count"] == 1,
             f"drifted={r2['drifted']} verified={r2['verified_count']}")
        # ...and a tamper AFTER the heal is still caught.
        _tamper_content(mem, cid, "post-heal tamper")
        r3 = cs.reconcile(heal=False)
        step("10 tamper after a heal is still detected",
             r3["drifted"] == [cid] and r3["tampered"] is True,
             f"drifted={r3['drifted']}")

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
