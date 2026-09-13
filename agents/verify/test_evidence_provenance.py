#!/usr/bin/env python3
"""Non-vacuity test for evidence provenance, the publish gate, and
re-attestation (issue #28 criterion-4 coverage work).

Proves the distinction the whole change rests on — that a point-in-time
re-attestation is NEVER presented as "chained since creation":

  - a freshly minted case is `write` provenance; a healed/re-attested one is
    `reattest`, in its own reconcile bucket, and named in `reattested`
  - re-attesting a pre-digest case makes it publishable; a second run reports
    `already` (idempotent), and the dry run's prediction equals the apply
  - re-attestation REFUSES a drifted case (an active tamper must never be
    signed over — that would launder it into "attested") and writes nothing
  - the `attestation` field is INSIDE the HMAC: editing it on disk turns the
    case `untrusted` (so the distinction cannot be forged)
  - the publication surfaces REFUSE unattested and drifted evidence, and with
    the explicit override they render the notice instead of hiding the verdict
  - report and advisory print the SAME verdict wording (one derivation, N
    surfaces), and backend="so" says the spine attestation does not apply
  - the gate's default is configurable (SSOP_EVIDENCE_ATTESTATION_REQUIRED)

Hermetic: in-memory fake memory, temp audit dir + audit key.
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import (  # noqa: E402
    ATTEST_REATTEST, PROV_DRIFTED, PROV_REATTEST, PROV_UNTRUSTED, PROV_WRITE,
    CaseStore, UnattestedEvidenceError, case_point_payload, provenance_note,
)


class _Rec:
    def __init__(self, point_id, payload):
        self.id, self.payload = point_id, payload


class _FakeMemory:
    """Minimal stand-in: raw case payloads in, raw payloads out."""

    def __init__(self):
        self.points: dict[str, dict] = {}
        self.events: dict[str, dict] = {}

    def upsert_point(self, collection, point_id, payload, vector=None):
        self.events[point_id] = dict(payload)

    def events_for(self, collection, case_id):
        return sorted([p for p in self.events.values() if p.get("case_id") == case_id],
                      key=lambda p: p.get("ts", ""))

    def get_by_payload(self, collection, field, value):
        if field == "case_id":
            for p in self.points.values():
                if p.get("case_id") == value:
                    return dict(p)
        return None

    def search_memory(self, collection, query, limit=5, scroll_limit=1000):
        return [{"id": pid, "content": p.get("content", ""),
                 "timestamp": p.get("timestamp", ""),
                 "metadata": {k: v for k, v in p.items() if k not in ("content", "timestamp")}}
                for pid, p in self.points.items()
                if query in str(p.get("content", ""))][:limit]

    def scroll_all(self, collection, **kw):
        for pid, payload in list(self.points.items()):
            yield _Rec(pid, payload)

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


def _store(td: Path):
    cs = CaseStore.__new__(CaseStore)
    cs.audit_dir = td
    cs.cases_file = td / "cases.jsonl"
    mem = _FakeMemory()
    cs._memory = mem
    return cs, mem


def _legacy_case(cs: CaseStore, mem: _FakeMemory, case_id: str) -> None:
    """A pre-digest case: point present, signed receipt WITHOUT a digest."""
    from tools.audit_chain import AuditChainWriter
    case = {"case_id": case_id, "title": "old", "status": "open",
            "ts": "2026-01-01T00:00:00+00:00", "timeline": [],
            "supervisory": {"decision": "approve", "rationale": "historical"}}
    mem.points["point-" + case_id] = case_point_payload(case)
    AuditChainWriter(cs.cases_file).write(
        case_id=case_id, role="case-spine", event="case_opened", status="open",
        title="old", detail={}, payload_digest=None)


def main() -> int:
    fails = 0

    def step(label: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        print(f"{'OK  ' if ok else 'FAIL'} {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            fails += 1

    # ------------------------------------------------ 1. write vs reattest
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        # Written FIRST, through its own chain writer, so the CaseStore's writer
        # picks up the tail cleanly (writing it later would reuse a cached seq).
        _legacy_case(cs, mem, "case-OLD1")
        c = cs.open_case(source={"rule_id": "T28"}, title="fresh")
        cid = c["case_id"]
        step("1 fresh case is write-provenance, not reattested",
             cs.provenance_for(cid) == PROV_WRITE, cs.provenance_for(cid))
        r = cs.reconcile()
        step("2 reconcile splits it into verified_write",
             r["verified_write"] == 1 and r["verified_reattested"] == 0
             and r["reattested"] == [],
             f"write={r['verified_write']} reattest={r['verified_reattested']}")

        # -------------------------------------------- 3. reattest + idempotency
        before = cs.provenance_for("case-OLD1")
        dry = cs.reattest_backlog(case_ids=["case-OLD1"], dry_run=True)
        apply_ = cs.reattest_backlog(case_ids=["case-OLD1"], dry_run=False)
        step("3 legacy case is unattested before the run",
             before == "unattested", before)
        step("4 dry-run prediction == apply outcome (same membership)",
             dry["would_attest"] == apply_["attested"] == ["case-OLD1"],
             f"dry={dry['would_attest']} applied={apply_['attested']}")
        step("5 after attestation provenance is REATTEST, never write",
             cs.provenance_for("case-OLD1") == PROV_REATTEST,
             cs.provenance_for("case-OLD1"))
        again = cs.reattest_backlog(case_ids=["case-OLD1"], dry_run=False)
        step("6 re-run is idempotent (reports already, writes nothing)",
             again["already"] == ["case-OLD1"] and again["attested"] == [],
             f"already={again['already']} attested={again['attested']}")
        r2 = cs.reconcile()
        step("7 reconcile counts it as re-attested and names it",
             r2["verified_reattested"] == 1 and "case-OLD1" in r2["reattested"]
             and r2["verified_write"] == 1 and r2["tampered"] is False,
             f"reattested={r2['reattested']} write={r2['verified_write']}")

    # ------------------------------------------- 8. refuses to sign over drift
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        c = cs.open_case(source={"rule_id": "T28"}, title="orig")
        cid = c["case_id"]
        pid = next(p for p, pl in mem.points.items() if pl.get("case_id") == cid)
        tampered = json.loads(mem.points[pid]["content"].split(" ", 1)[1])
        tampered["title"] = "ATTACKER"
        mem.points[pid]["content"] = f"{cid} {json.dumps(tampered)}"
        before_lines = len(cs.cases_file.read_text().splitlines())
        res = cs.reattest_payload(cid, dry_run=False)
        after_lines = len(cs.cases_file.read_text().splitlines())
        step("8 re-attestation REFUSES a drifted case",
             res["action"] == "refused_drifted", res["action"])
        step("9 ...and writes NOTHING (drift must not be signed over)",
             after_lines == before_lines,
             f"receipt lines {before_lines} -> {after_lines}")
        step("10 provenance still reads drifted",
             cs.provenance_for(cid) == PROV_DRIFTED, cs.provenance_for(cid))

        # ---------------------------------- 11. the attestation field is signed
        with tempfile.TemporaryDirectory() as td2:
            cs2, mem2 = _store(Path(td2))
            c2 = cs2.open_case(source={"rule_id": "T28"}, title="signed")
            cid2 = c2["case_id"]
            lines = cs2.cases_file.read_text().splitlines()
            rec = json.loads(lines[-1])
            rec["attestation"] = ATTEST_REATTEST   # forged downgrade on disk
            lines[-1] = json.dumps(rec)
            cs2.cases_file.write_text("\n".join(lines) + "\n")
            step("11 editing the attestation field breaks the HMAC (untrusted)",
                 cs2.provenance_for(cid2) == PROV_UNTRUSTED,
                 cs2.provenance_for(cid2))

    # ------------------------------------------------- 12. the publish gate
    with tempfile.TemporaryDirectory() as td:
        from tools import report_gen
        from tools.advisory_gen import render_advisory
        cs, mem = _store(Path(td))
        c = cs.open_case(source={"rule_id": "T28"}, title="gate")
        cid = c["case_id"]

        def _render(prov, fn):
            with patch.object(CaseStore, "get_case", return_value=c), \
                 patch.object(CaseStore, "provenance_for", return_value=prov):
                return fn()

        refused = []
        for prov in ("unattested", PROV_DRIFTED, PROV_UNTRUSTED):
            for name, fn in (("report", lambda p=prov: report_gen.render_case_report(cid)),
                             ("advisory", lambda p=prov: render_advisory(cid))):
                try:
                    _render(prov, fn)
                    refused.append(f"{name}/{prov} RENDERED")
                except UnattestedEvidenceError:
                    pass
        step("12 report + advisory refuse unattested, drifted and untrusted",
             refused == [], "; ".join(refused) or "all six refused")

        md = _render("unattested", lambda: report_gen.render_case_report(
            cid, allow_unattested=True))
        adv = _render("unattested", lambda: render_advisory(cid, allow_unattested=True))
        note = provenance_note("unattested")
        step("13 the override renders the notice, both surfaces, same wording",
             note in md and note in adv,
             "notice present in report and advisory")

        md_drift = _render(PROV_DRIFTED, lambda: report_gen.render_case_report(
            cid, allow_unattested=True))
        step("14 an overridden DRIFTED case says so loudly",
             "DRIFTED" in md_drift and provenance_note(PROV_DRIFTED) in md_drift,
             "drifted notice rendered")

    # ------------------------------------- 16. SO backend + config default
    with tempfile.TemporaryDirectory() as td:
        from tools.advisory_gen import render_advisory
        import tools.advisory_gen as ag
        case = {"case_id": "case-SO", "title": "so case", "status": "open",
                "ts": "2026-01-01T00:00:00+00:00", "timeline": []}
        with patch.object(ag, "_case_from_so", return_value=case):
            md = render_advisory("case-SO", backend="so")
        step("16 backend='so' renders and says the spine attestation does not apply",
             "n/a (Security Onion surface)" in md
             and "Not applicable" in md and "not the spine" in md,
             "SO advisory rendered with the not-applicable notice")

        # The gate's default is config-driven, not hardcoded.
        from config import settings
        from tools import case_tools
        try:
            object.__setattr__(settings, "evidence_attestation_required", False)
            allowed = True
            try:
                case_tools.require_publishable("unattested")
            except UnattestedEvidenceError:
                allowed = False
            step("17 SSOP_EVIDENCE_ATTESTATION_REQUIRED=0 relaxes the default",
                 allowed, "relaxed default allowed the render")
        finally:
            object.__setattr__(settings, "evidence_attestation_required", True)

    def _case(case_id: str) -> dict:
        return {"case_id": case_id, "title": "t", "status": "open",
                "ts": "2026-01-01T00:00:00+00:00", "timeline": []}

    # -------- 18. a point written by ANOTHER code path still attests cleanly
    # Regression for a live-caught bug: `reattest_payload` measured the store
    # payload for its report but signed the digest of the CANONICAL writer
    # payload, so any point created by a different writer (the older generic
    # `store_memory` path adds `agent` and omits observables/enrichments) read
    # as drifted the instant it was attested. The digest must be the one
    # measured from the store.
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        cid = "case-FOREIGN"
        case = _case(cid)
        # Deliberately NOT case_point_payload: a different, older shape.
        mem.points["p-foreign"] = {
            "content": f"{cid} {json.dumps(case)}",
            "timestamp": case["ts"], "type": "case", "case_id": cid,
            "status": "open", "title": "t", "agent": "infra-agent",
        }
        from tools.audit_chain import AuditChainWriter
        AuditChainWriter(cs.cases_file).write(
            case_id=cid, role="case-spine", event="case_opened", status="open",
            title="t", detail={}, payload_digest=None)
        before = cs.provenance_for(cid)
        res = cs.reattest_payload(cid, dry_run=False)
        after = cs.provenance_for(cid)
        step("18 a foreign-shape point attests cleanly (measured, not rebuilt)",
             before == "unattested" and res["action"] == "attested"
             and after == PROV_REATTEST,
             f"{before} -> action={res['action']} -> {after}")

        # ...and a genuine same-ID rewrite of that foreign point is STILL caught.
        mem.points["p-foreign"]["content"] = f"{cid} {json.dumps({**case, 'title': 'HACKED'})}"
        step("19 ...and a rewrite of it is still detected as drift",
             cs.provenance_for(cid) == PROV_DRIFTED, cs.provenance_for(cid))
        refused = cs.reattest_payload(cid, dry_run=False)
        step("20 ...and the default still refuses to sign over it",
             refused["action"] == "refused_drifted", refused["action"])

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
