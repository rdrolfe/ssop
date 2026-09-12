#!/usr/bin/env python3
"""ONE decision, N surfaces — the parity test for the shared decision reader.

The bug class this guards (live spine, Sep 2026): `case_tools.case_decision`
was introduced as THE one reader for the two-shape decision field (a
top-level `supervisory` block OR a timeline event, including router
adjudication of INFRA tier0/1 cases), and three surfaces still derived the
decision themselves. The drift is public and it is a lie on a human surface:

  - `report_gen._all_spine_cases` (the /reports enumeration gate) checked only
    the `supervisory` block → on the live spine it saw 118 decided cases where
    the spine held 281. 163 decided cases were missing from the compiled
    report while the digest's Coverage line (which shared the reader) counted
    them.
  - `report_gen._exec_summary` repeated the block-or-supervisory-timeline rule
    → a router-approved INFRA case read "Decision: under review" in the
    summary of its own report.
  - `attach_case_report` repeated it too → the routed case posted to the SOC
    as "Case Outcome — UNDER REVIEW" one minute after the router approved it.

What is asserted (each can FAIL on purpose):
  1. the shared reader resolves all four shapes (block / supervisory timeline /
     router timeline / none) — including the negative probe for "none";
  2. the advisory, the report, and the SO comment header agree with the shared
     reader on every fixture (parity, table-driven — a new independent
     derivation in any of them breaks this);
  3. the report's decision chain renders a router adjudication as a DECISION,
     not a truncated JSON blob;
  4. the /reports enumeration counts a timeline-decided case and skips an
     undecided one — the 163-case leak, pinned against a fake store.

Hermetic: no Qdrant, no network — the enumeration check patches a fake memory
into CaseStore.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import CASE_COLLECTION, CaseStore, case_decision  # noqa: E402
from tools.advisory_gen import _decision as advisory_decision  # noqa: E402
from tools import report_gen  # noqa: E402
from tools.attach_case_report import outcome_header  # noqa: E402

FAILS = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


NOW = "2026-09-11T12:00:00+00:00"


def _block_shape() -> dict:
    """Console /case-decision path: top-level supervisory block."""
    return {
        "case_id": "case-block00001",
        "title": "denied by a human",
        "ts": NOW, "updated_ts": NOW, "state": "decided", "status": "closed",
        "supervisory": {"decision": "deny", "rationale": "benign admin activity", "ts": NOW},
        "timeline": [{"ts": NOW, "role": "supervisory", "type": "adjudication",
                      "detail": {"decision": "deny", "rationale": "benign admin activity"}}],
    }


def _supervisory_timeline_shape() -> dict:
    """Ticket-adjudicated case whose decision rides the timeline only."""
    return {
        "case_id": "case-super00001",
        "title": "OPERATIONAL alert lvl=7",
        "ts": NOW, "updated_ts": NOW, "state": "closed", "status": "closed",
        "supervisory": None,
        "timeline": [
            {"ts": NOW, "role": "analyst", "type": "verdict",
             "detail": {"verdict": "escalate", "rationale": "needs a human"}},
            {"ts": NOW, "role": "supervisory", "type": "verdict",
             "detail": {"decision": "deny", "verdict": "false_positive",
                        "rationale": "synthetic drill FP"}},
        ],
    }


def _router_shape() -> dict:
    """Router-adjudicated INFRA tier1 case — router IS the authority."""
    return {
        "case_id": "case-router0001",
        "title": "[ROUTER] INFRA alert lvl=5 on network",
        "ts": NOW, "updated_ts": NOW, "state": "decided", "status": "open",
        "supervisory": None,
        "timeline": [
            {"ts": NOW, "role": "router", "type": "dispatch",
             "detail": {"verdict": "escalate", "category": "infra"}},
            {"ts": NOW, "role": "router", "type": "adjudication",
             "detail": {"decision": "approve",
                        "rationale": "tier1 read-only/restart playbooks pre-approved by "
                                     "router dispatch policy (operator 2026-09-09)",
                        "recommended_playbook": "restart-flapping-service"}},
        ],
    }


def _undecided_shape() -> dict:
    """Negative probe: no decision anywhere — the reader must NOT invent one."""
    return {
        "case_id": "case-undec00001",
        "title": "awaiting a human",
        "ts": NOW, "updated_ts": NOW, "state": "new", "status": "open",
        "supervisory": None,
        "timeline": [{"ts": NOW, "role": "analyst", "type": "verdict",
                      "detail": {"verdict": "escalate", "rationale": "needs a human"}}],
    }


CASES = [_block_shape(), _supervisory_timeline_shape(), _router_shape(), _undecided_shape()]
EXPECTED = {"case-block00001": "deny", "case-super00001": "deny",
            "case-router0001": "approve", "case-undec00001": ""}

# --- 1. the shared reader resolves every shape ------------------------------
for case, want in zip(CASES, ["deny", "deny", "approve", ""]):
    got, rationale = case_decision(case)
    check(f"1. case_decision({case['case_id']}) == {want!r}", got == want, f"got {got!r}")
check("1b. rationale survives the timeline shapes",
      case_decision(_router_shape())[1].startswith("tier1 read-only")
      and case_decision(_supervisory_timeline_shape())[1] == "synthetic drill FP")

check("1c. the block beats a stale timeline event (same case, two shapes)",
      case_decision({**_router_shape(), "supervisory": {"decision": "deny",
                                                        "rationale": "human overruled"}})[0] == "deny")

# --- 1d. the dict-shaped view is the SAME derivation ------------------------
from tools.case_tools import case_adjudication  # noqa: E402

check("1d. case_adjudication returns {} for an undecided case (the console must not show a badge)",
      case_adjudication(_undecided_shape()) == {})
check("1d. case_adjudication names the DECIDER (router for INFRA tier1)",
      case_adjudication(_router_shape()).get("role") == "router"
      and case_adjudication(_router_shape()).get("decision") == "approve")
check("1d. case_adjudication names the human decider",
      case_adjudication(_block_shape()).get("role") == "supervisory")
check("1d. case_decision IS a projection of case_adjudication (one derivation, two shapes)",
      all(case_decision(c) == (case_adjudication(c).get("decision", ""),
                               case_adjudication(c).get("rationale", ""))
          for c in CASES))


# --- 2. every surface agrees (table-driven parity) --------------------------
# Each surface has its OWN honest wording for the genuinely-undecided case
# ("under review" in a deliverable, "No supervisory decision recorded" in the
# report body, "UNDER REVIEW" on the SOC comment) — that wording is fine. What
# must never differ is the DECISION VALUE, so the absent case normalizes to
# the sentinel "none" and a real verdict must survive verbatim.
NONE_WORDS = {"", "under review", "no supervisory decision recorded", "none"}


def _norm(value: str) -> str:
    v = (value or "").strip().lower()
    return "none" if v in NONE_WORDS else v


def _from_report_summary(case: dict) -> str:
    m = re.search(r"Decision: \*\*(.+?)\*\*", report_gen._exec_summary(case))
    return _norm(m.group(1) if m else "")


def _from_outcome_header(case: dict) -> str:
    m = re.search(r"Case Outcome — \*\*(.+?)\*\*", outcome_header(case))
    return _norm(m.group(1) if m else "")


def _from_report_section(case: dict) -> str:
    """Section 5 of the compiled report — '**DENY** — <ts>'."""
    md = "\n".join(report_gen._md_core(case))
    m = re.search(r"## 5\. Decision\n\n\*\*([A-Za-z_ ]+)\*\*", md)
    return _norm(m.group(1) if m else "") if m else "none"


SURFACES = {
    "advisory": lambda c: _norm(advisory_decision(c)[0]),
    "report-summary": _from_report_summary,
    "so-comment-header": _from_outcome_header,
    "reports-decision-section": _from_report_section,
}

for case in CASES:
    want = EXPECTED[case["case_id"]] or "none"
    for name, fn in SURFACES.items():
        got = fn(case)
        check(f"2. {name} agrees on {case['case_id']} ({want!r})",
              got == want, f"got {got!r}")

# --- 3. the decision chain renders the router decision as a decision --------
chain = "\n".join(report_gen._md_core(_router_shape()))
check("3. report decision chain renders router adjudication as a decision",
      "decision **approve**" in chain and '"decision": "approve"' not in chain)

# --- 4. the /reports enumeration gate ---------------------------------------
class _FakeMemory:
    def __init__(self, cases):
        self.cases = cases

    def search_memory(self, collection, query, limit=1000, scroll_limit=None):
        assert collection == CASE_COLLECTION, collection
        return [{"id": c["case_id"], "content": f"{c['case_id']} {_dumps(c)}",
                 "timestamp": c.get("ts", "")} for c in self.cases]

    def close(self):
        pass


def _dumps(case):
    import json
    return json.dumps(case)


fake = _FakeMemory([_supervisory_timeline_shape(), _router_shape(), _undecided_shape(),
                    _block_shape()])
_orig = CaseStore._get_memory
CaseStore._get_memory = lambda self: fake
try:
    listed = report_gen._all_spine_cases(days=1)
finally:
    CaseStore._get_memory = _orig

ids = [c.get("case_id") for c in listed]
check("4. /reports enumerates timeline-decided cases (was 163 of 281 missing)",
      "case-super00001" in ids and "case-router0001" in ids, f"got {ids}")
check("4b. /reports still enumerates the block-shaped decision", "case-block00001" in ids)
check("4c. /reports does NOT count an undecided case", "case-undec00001" not in ids)

# --- 5. spine fields are JSON-null-safe (the class behind two crashes) ------
# A case payload round-trips through Qdrant as JSON, so an absent field comes
# back present-and-NULL: `case.get("source", {})` then returns None (the
# default only covers a MISSING key) and the renderer dies on None.get — on
# the /reports endpoint, over one of the 163 cases the enumeration gate used
# to hide. Ban the shape in the reporting modules.
import re as _re  # noqa: E402

BAD_DEFAULT = _re.compile(r'case\.get\("[a-z_]+",\s*(\{\}|\[\])\)')
for mod in ("report_gen.py", "advisory_gen.py", "attach_case_report.py"):
    path = Path(__file__).resolve().parent.parent / "tools" / mod
    hits = BAD_DEFAULT.findall(path.read_text())
    check(f"5. {mod} uses `or {{}}`/`or []` for spine fields (not .get(x, {{}}))",
          not hits, f"{len(hits)} unsafe default read(s)")

# ...and the behavioral proof: the live crash shape renders, rather than
# segfaulting the /reports endpoint on a single null-heavy case.
_null_heavy = {
    "case_id": "case-null000001", "title": "null-heavy spine case", "ts": NOW,
    "updated_ts": NOW, "state": "decided", "status": "open",
    "supervisory": None, "source": None, "observables": None, "timeline": None,
}
try:
    _rendered = "\n".join(report_gen._md_core(_null_heavy))
    check("5b. _md_core renders a null-heavy case (source/supervisory/observables/timeline = null)",
          "## 5. Decision" in _rendered)
except Exception as e:  # noqa: BLE001 — the crash IS the finding
    check("5b. _md_core renders a null-heavy case (source/supervisory/observables/timeline = null)",
          False, f"{type(e).__name__}: {e}")

print()
print(f"{'FAILURES: ' + str(FAILS) if FAILS else 'ALL CHECKS PASSED'}")
sys.exit(1 if FAILS else 0)
