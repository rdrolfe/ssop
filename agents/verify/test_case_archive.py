#!/usr/bin/env python3
"""Non-vacuity test for case archiving (retiring test artifacts, issue #28).

Proves the two things that make archiving safe, and the one thing that makes it
worth doing:

  - the artifact rule DISCRIMINATES: a verify seed / drill case / probe is an
    artifact; a real THREAT/INTEL/INFRA case is not, and is never selected —
    however undecided it is
  - the retirement is DURABLE: after the tombstone, `reconcile(heal=True)` does
    NOT re-hydrate the case. This is the documented failure it exists to
    prevent (a naive purge was silently undone live: reset to 2 seeds, next
    supervisory run re-hydrated 1,213 points)
  - a case carrying a DECISION is REFUSED (a decided case is a record with
    reasoning behind it — retiring it is a human call, not a cleanup)
  - it is re-runnable and idempotent, including completing a failed point delete
  - the payload is dumped for recovery before the point is destroyed
  - `archived` is reported as its own bucket, not as a divergence, and archived
    evidence is not publishable

Hermetic: in-memory fake memory, temp audit dir + audit key.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import (  # noqa: E402
    ARCHIVE_DUMP_NAME, PROV_ARCHIVED, PROV_UNATTESTED, CaseStore,
    case_point_payload, evidence_is_publishable, is_artifact_case,
)

# Real case ids are `case-<hex>`; the spine scan keys on that prefix, so fixtures
# must look like the real thing (a non-conforming id would be invisible to
# reconcile AND to the archiver — worth knowing, and worth testing against).
SEEK, THREAT, DRILL, INFRA = ("case-seek0001", "case-threat01",
                              "case-drill001", "case-infra001")
P_SEEK, P_THREAT, P_INFRA = "p-" + SEEK, "p-" + THREAT, "p-" + INFRA


class _Rec:
    def __init__(self, point_id, payload):
        self.id, self.payload = point_id, payload


class _FakeMemory:
    """Minimal stand-in, plus delete_memory (archiving removes points)."""

    def __init__(self):
        self.points: dict[str, dict] = {}
        self.events: dict[str, dict] = {}
        self.fail_delete = False

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

    def delete_memory(self, collection, point_id):
        if self.fail_delete:
            raise RuntimeError("simulated store refusal")
        self.points.pop(point_id, None)
        return {"deleted": True, "point_id": point_id}

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


def _mint(cs, case_id: str, title: str, source: dict) -> dict:
    from tools.audit_chain import AuditChainWriter
    case = {"case_id": case_id, "title": title, "status": "closed",
            "state": "closed", "ts": "2026-01-01T00:00:00+00:00",
            "timeline": [], "source": source}
    cs._memory.points["p-" + case_id] = case_point_payload(case)
    AuditChainWriter(cs.cases_file).write(
        case_id=case_id, role="case-spine", event="case_opened", status="closed",
        title=title, detail={}, payload_digest=None)
    return case


def main() -> int:
    fails = 0

    def step(label: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        print(f"{'OK  ' if ok else 'FAIL'} {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            fails += 1

    # ------------------------------- 1. the rule must discriminate -----------
    rule_cases = {
        "seed": {"title": "VERIFY SEED repeated-host x 5715",
                 "source": {"agent": "x", "verify_seed": True}},
        "drill": {"title": "THREAT alert lvl=10",
                  "source": {"alert_id": "atomic-t1053-task"}},
        "probe": {"title": "qdrant auth cutover check", "source": {}},
        "ttx": {"title": "TTX deploy verification", "source": {"agent": "ttx-test"}},
        "threat": {"title": "THREAT alert lvl=12 on network", "source": {"agent": "network"}},
        "intel": {"title": "[INTEL] CVE-2021-3156 (Sudo) present on kb-vec",
                  "source": {"agent": "kb-vec"}},
        "infra": {"title": "[ROUTER] INFRA alert lvl=5 on kb-vec",
                  "source": {"agent": "kb-vec"}},
    }
    flagged = {k for k, c in rule_cases.items() if is_artifact_case(c)}
    step("1 artifact rule flags artifacts and NOT real cases",
         flagged == {"seed", "drill", "probe", "ttx"}, f"flagged={sorted(flagged)}")

    # --------------------------- 2. archive: tombstone, delete, reported -----
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        _mint(cs, SEEK, "VERIFY SEED repeated-host x 5715",
              {"agent": "we8105desk", "verify_seed": True})
        _mint(cs, THREAT, "THREAT alert lvl=12 on network", {"agent": "network"})
        r0 = cs.reconcile(heal=False)
        step("2 both cases are present before anything is retired",
             r0["qdrant_count"] == 2 and r0["verified_count"] == 0,
             f"qdrant={r0['qdrant_count']} receipt={r0['receipt_count']}")

        res = cs.archive_case(SEEK, reason="test artifact", actor="test")
        step("3 archive reports 'archived' and removes the point",
             res["action"] == "archived" and P_SEEK not in mem.points,
             f"action={res['action']} point_gone={P_SEEK not in mem.points}")

        r1 = cs.reconcile(heal=True)
        step("4 reconcile reports it as ARCHIVED, not receipt_only/qdrant_only",
             r1["archived"] == [SEEK] and r1["receipt_only"] == []
             and r1["qdrant_only"] == [] and r1["consistent"] is True,
             f"archived={r1['archived']} receipt_only={r1['receipt_only']} "
             f"qdrant_only={r1['qdrant_only']}")
        step("5 HEAL DOES NOT RESURRECT IT (the documented purge trap)",
             P_SEEK not in mem.points and SEEK not in r1["healed"]
             and r1["archived_lingering"] == [],
             f"healed={r1['healed']} point_present={P_SEEK in mem.points}")
        step("6 provenance reads archived and it is not publishable",
             cs.provenance_for(SEEK) == PROV_ARCHIVED
             and not evidence_is_publishable(PROV_ARCHIVED),
             cs.provenance_for(SEEK))
        step("7 the real case is untouched by all of this",
             cs.provenance_for(THREAT) == PROV_UNATTESTED
             and P_THREAT in mem.points, cs.provenance_for(THREAT))

        dump = Path(td) / ARCHIVE_DUMP_NAME
        dumped = [json.loads(x) for x in dump.read_text().splitlines()] if dump.exists() else []
        step("8 the payload was dumped for recovery before deletion",
             len(dumped) == 1 and dumped[0]["case_id"] == SEEK
             and dumped[0]["payload"].get("content", "").startswith(SEEK + " "),
             f"{len(dumped)} dump line(s)")

        step("9 re-archiving is idempotent",
             cs.archive_case(SEEK, reason="again", actor="test")["action"] == "already",
             "second call reports already")

        # 9b. The MARKED path: a run retires a case it minted BY EXACT IDENTITY,
        # including a decided one — the caller's assertion is the authority, and
        # only an explicit case_id list can relax the undecided guard.
        decided = _mint(cs, "case-fix0001", "fixture verdict case",
                        {"agent": "x"})
        decided["supervisory"] = {"decision": "approve", "rationale": "fixture"}
        mem.points["p-case-fix0001"] = case_point_payload(decided)
        refused = cs.archive_backlog(dry_run=True, case_ids=["case-fix0001"])
        marked = cs.archive_backlog(dry_run=False, case_ids=["case-fix0001"],
                                    require_undecided=False, reason="run artifact",
                                    actor="verify-matrix")
        step("9b a marked id retires even a decided case; the default still refuses",
             refused["refused_decided"] == ["case-fix0001"]
             and marked["archived"] == ["case-fix0001"]
             and "p-case-fix0001" not in mem.points,
             f"default={refused['refused_decided']} marked={marked['archived']}")

    # ---------------------------------- 10. refuses a decided case ----------
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        case = _mint(cs, SEEK, "VERIFY SEED repeated-host x 5715",
                     {"agent": "x", "verify_seed": True})
        case["supervisory"] = {"decision": "approve", "rationale": "human said so"}
        mem.points[P_SEEK] = case_point_payload(case)
        res = cs.archive_case(SEEK, reason="try", actor="test")
        step("10 a case carrying a DECISION is refused, and its point survives",
             res["action"] == "refused_decided" and P_SEEK in mem.points,
             f"action={res['action']}")
        forced = cs.archive_case(SEEK, reason="operator override", actor="test",
                                 require_undecided=False)
        step("11 ...unless the caller explicitly requires it (operator override)",
             forced["action"] == "archived" and P_SEEK not in mem.points,
             f"action={forced['action']}")

    # ----------------------- 12. backlog: dry-run == apply, idempotent -------
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        _mint(cs, SEEK, "VERIFY SEED repeated-host x 5715",
              {"agent": "x", "verify_seed": True})
        _mint(cs, DRILL, "OPERATIONAL alert lvl=7", {"alert_id": "atomic-t1046-scan"})
        _mint(cs, THREAT, "THREAT alert lvl=12 on network", {"agent": "network"})
        _mint(cs, INFRA, "[ROUTER] INFRA alert lvl=5 on kb-vec", {"agent": "kb-vec"})

        dry = cs.archive_backlog(dry_run=True, reason="t", actor="t")
        app = cs.archive_backlog(dry_run=False, reason="t", actor="t")
        step("12 selection is artifacts only (real cases never candidates)",
             dry["candidates"] == 2
             and sorted(dry["would_archive"]) == sorted([DRILL, SEEK]),
             f"candidates={dry['candidates']} would={sorted(dry['would_archive'])}")
        step("13 dry-run prediction == apply outcome",
             sorted(app["archived"]) == sorted(dry["would_archive"]),
             f"predicted={sorted(dry['would_archive'])} actual={sorted(app['archived'])}")
        again = cs.archive_backlog(dry_run=True, reason="t", actor="t")
        step("14 re-run finds nothing (idempotent)",
             again["would_archive"] == [] and again["already"] == []
             and again["candidates"] == 0, f"candidates={again['candidates']}")
        step("15 both real cases survived",
             P_THREAT in mem.points and P_INFRA in mem.points,
             f"remaining points={sorted(mem.points)}")

    # --------------------------- 16. a failed delete self-completes ----------
    with tempfile.TemporaryDirectory() as td:
        cs, mem = _store(Path(td))
        _mint(cs, SEEK, "VERIFY SEED repeated-host x 5715",
              {"agent": "x", "verify_seed": True})
        mem.fail_delete = True
        first = cs.archive_case(SEEK, reason="t", actor="t")
        step("16 a refused point delete is reported, tombstone still written",
             first["action"] == "delete_failed" and P_SEEK in mem.points
             and cs.provenance_for(SEEK) == PROV_ARCHIVED,
             f"action={first['action']} provenance={cs.provenance_for(SEEK)}")
        mem.fail_delete = False
        second = cs.archive_case(SEEK, reason="t", actor="t")
        step("17 the next run COMPLETES it (re-runnable)",
             second["action"] == "completed" and P_SEEK not in mem.points,
             f"action={second['action']}")
        r = cs.reconcile(heal=True)
        step("18 and it stays archived, not healed back",
             r["archived"] == [SEEK] and r["healed"] == [] and P_SEEK not in mem.points,
             f"archived={r['archived']} healed={r['healed']}")

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())