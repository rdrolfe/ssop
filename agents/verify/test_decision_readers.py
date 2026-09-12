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
     undecided one — the 163-case leak, pinned against a fake store;
  5. spine fields are JSON-null-safe (the crash class behind two 500s);
  6. **the IRIS publish surface** renders a decision event for every decided
     case AND names the same DECIDER — the mirror is the human front-end, so a
     decision the spine holds but IRIS never shows is the same lie as the
     console badge reading "undecided";
  7. the digest's Coverage count and the /reports enumeration agree on the SAME
     store (two surfaces, one number — the original defect was 281 vs 118).

Hermetic: no Qdrant, no network — the enumeration check patches a fake memory
into CaseStore, and the IRIS surface is exercised as a pure payload mapper
(no IRIS, no credentials: `_event_payload` is called directly).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.case_tools import CASE_COLLECTION, CaseStore, case_decision  # noqa: E402
from tools.advisory_gen import _decision as advisory_decision  # noqa: E402
from tools.advisory_gen import _key_actions as advisory_key_actions  # noqa: E402
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


def _router_block_shape() -> dict:
    """decide(..., role="router") — the block AS WRITTEN since 543becd.

    This is the shape the router creates at mint time (INFRA tier0/1). Before
    543becd the block carried no `role`, and because readers hit the block
    FIRST, every router approval projected as a HUMAN "supervisory" one.
    """
    return {
        "case_id": "case-routerblock",
        "title": "[ROUTER] INFRA alert lvl=5 on kb-vec",
        "ts": NOW, "updated_ts": NOW, "state": "decided", "status": "open",
        "supervisory": {"decision": "approve",
                        "rationale": "router adjudication (infra): tier1 playbook "
                                     "service-impact-check authorized under operator "
                                     "policy 2026-09-09",
                        "ts": NOW, "role": "router"},
        "timeline": [
            {"ts": NOW, "role": "router", "type": "dispatch",
             "detail": {"verdict": "escalate", "category": "infra",
                        "recommended_playbook": "service-impact-check"}},
            {"ts": NOW, "role": "router", "type": "adjudication",
             "detail": {"decision": "approve",
                        "rationale": "router adjudication (infra): tier1 playbook "
                                     "service-impact-check authorized under operator "
                                     "policy 2026-09-09"}},
        ],
    }


def _legacy_router_block_shape() -> dict:
    """A router adjudication recorded BEFORE 543becd: role on the EVENT only.

    The read-repair (`_decider_role_from_timeline`) must attribute this to the
    router, not to a human — the attribution a human surface shows.
    """
    c = _router_block_shape()
    c["case_id"] = "case-legacyrouter"
    c["supervisory"] = {"decision": "approve",
                        "rationale": "router adjudication (infra): tier1 playbook "
                                     "service-impact-check authorized under operator "
                                     "policy 2026-09-09",
                        "ts": NOW}          # no `role` — the historical gap
    return c


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


CASES = [_block_shape(), _supervisory_timeline_shape(), _router_shape(),
         _router_block_shape(), _legacy_router_block_shape(), _undecided_shape()]
EXPECTED = {"case-block00001": "deny", "case-super00001": "deny",
            "case-router0001": "approve", "case-routerblock": "approve",
            "case-legacyrouter": "approve", "case-undec00001": ""}

# --- 1. the shared reader resolves every shape ------------------------------
for case, want in zip(CASES, ["deny", "deny", "approve", "approve", "approve", ""]):
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

# --- 1e. WHO decided is part of the answer, on every shape ------------------
# The attribution defect (543becd) lived here: a router-written block read as a
# HUMAN decision because the block carried no role. Every decided shape must
# name its decider, and the human one must not be misattributed to the router.
DECIDERS = {"case-block00001": "supervisory", "case-super00001": "supervisory",
            "case-router0001": "router", "case-routerblock": "router",
            "case-legacyrouter": "router", "case-undec00001": ""}
for case in CASES:
    want = DECIDERS[case["case_id"]]
    got = case_adjudication(case).get("role", "")
    check(f"1e. decider for {case['case_id']} == {want!r}", got == want, f"got {got!r}")


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

# --- 6. the IRIS publish surface: the mirror must show the same decision -----
# IRIS is the human front-end. `publish_case_iris._event_payload` maps spine
# timeline events onto IRIS timeline events, and it only mapped SUPERVISORY
# adjudications — so a router-adjudicated INFRA case (the class this repo just
# made the router authoritative for) reached IRIS as a case with no decision
# event at all: the spine held the approve, the human surface showed nothing.
# Same defect class as the console badge reading "undecided"; different surface.
import importlib.util  # noqa: E402

_PP = Path(__file__).resolve().parent.parent      # repo: agents/ · runtime: root


def _load_iris_publisher():
    for cand in (_PP / "deploy" / "lab" / "publish_case_iris.py",
                 _PP.parent / "deploy" / "lab" / "publish_case_iris.py"):
        if cand.exists():
            spec = importlib.util.spec_from_file_location("iris_pub_under_test", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    return None


_iris = _load_iris_publisher()
check("6. publish_case_iris is importable for the parity check (no IRIS, no keys)",
      _iris is not None, "module not found in this layout")

# What the IRIS timeline would render: (decision, decider) from the mapped
# payloads. The titles are the surface's own words — the parity property is
# that a DECISION event exists for every decided case and that it names the
# same decider the spine names.
_DECISION_TITLE = re.compile(r"^(Supervisory|Router) decision:\s*(\w+)", re.I)


def _iris_surface(case: dict) -> tuple[str, str]:
    if _iris is None:
        return "", ""
    dec, who = "", ""
    for ev in (case.get("timeline") or []):
        payload = _iris._event_payload(ev, case["case_id"])
        if not payload:
            continue
        m = _DECISION_TITLE.match(str(payload.get("event_title", "")))
        if m:
            who, dec = m.group(1).lower(), m.group(2).lower()
    return _norm(dec), who


if _iris is not None:
    for case in CASES:
        want = EXPECTED[case["case_id"]] or "none"
        got_dec, got_who = _iris_surface(case)
        check(f"6. IRIS renders the decision for {case['case_id']} ({want!r})",
              got_dec == want, f"got {got_dec!r}")
        want_who = DECIDERS[case["case_id"]]
        if want_who:
            check(f"6b. IRIS names the decider for {case['case_id']} ({want_who!r})",
                  got_who == want_who, f"got {got_who!r}")
        else:
            check("6b. IRIS invents no decider for an undecided case", not got_who,
                  f"got {got_who!r}")

# --- 1f. the recommended playbook is ONE field with THREE homes -------------
# It lives in the decision block, the mint source, or an event detail depending
# on who wrote it. The advisory's Key Actions read only the sup block — which
# never carries it — so "Execute playbook …" was dead on every case.
from tools.case_tools import case_recommended_playbook  # noqa: E402

check("1f. playbook resolves from the decision block",
      case_recommended_playbook(
          {**(_router_block_shape()),
           "supervisory": {"decision": "approve", "recommended_playbook": "from-block"}})
      == "from-block")
check("1f. playbook resolves from the mint source",
      case_recommended_playbook(
          {"source": {"recommended_playbook": "from-source"},
           "timeline": [{"type": "dispatch",
                         "detail": {"recommended_playbook": "from-event"}}]})
      == "from-source")
check("1f. playbook resolves from an event detail (the store-view shape)",
      case_recommended_playbook(
          {"source": {"category": "infra"},
           "timeline": [{"type": "dispatch",
                         "detail": {"recommended_playbook": "from-event"}}]})
      == "from-event")
check("1f. no playbook anywhere -> empty (never invented)",
      case_recommended_playbook(_undecided_shape()) == "")

# --- 8. the advisory's Key Actions actually renders the recommendation ------
# (It never did: the read was dead, so a decided case awaiting execution
# rendered no action at all.) The decider is named, so a router-authorized INFRA
# case is not described as a supervisory decision.
_router_actions = "\n".join(advisory_key_actions(_router_block_shape()))
check("8. a decided case with a recommendation renders the execute action",
      "Execute playbook `service-impact-check`" in _router_actions
      and "(per router decision)" in _router_actions, _router_actions[:160])
_human_actions = "\n".join(advisory_key_actions(
    {**_block_shape(), "timeline": [{"ts": NOW, "role": "supervisory", "type": "adjudication",
                                     "detail": {"decision": "deny",
                                                "recommended_playbook": "verify-only"}}]}))
check("8. a human decision still reads 'per supervisory decision'",
      "(per supervisory decision)" in _human_actions, _human_actions[:160])
check("8. an executed case reports the execution, not a pending recommendation",
      "Execute playbook" not in "\n".join(advisory_key_actions(
          {**_router_block_shape(),
           "timeline": [{"ts": NOW, "role": "responder", "type": "execution",
                         "detail": {"playbook": "service-impact-check", "tier": "tier1",
                                    "results": [{"ok": True, "detail": "suricata is active"}]}}]})))

# --- 6c. the console badge must DELEGATE, not re-derive ---------------------
# `adjudicate_api._view` is the human console card. Its decision badge used to
# be derived inline (a "last supervisory adjudication event" scan), which made a
# router-approved case read "undecided" on the console while the advisory showed
# the approval. The closure isn't importable (it is defined inside the handler),
# so this pins the DELEGATION statically: the module must call the shared reader
# and must not compare a spine role to "supervisory" to find a decision.
_api_src = (_PP / "tools" / "adjudicate_api.py")
if not _api_src.exists():                       # runtime layout: <root>/tools
    _api_src = _PP.parent / "tools" / "adjudicate_api.py"
_api_text = _api_src.read_text() if _api_src.exists() else ""
check("6c. the console view delegates to case_adjudication (no inline re-derivation)",
      "case_adjudication(" in _api_text, "no call to the shared reader")
check("6c. the console view does not scan for a supervisory role to decide",
      not re.search(r'role"?\)?\s*==\s*"supervisory"', _api_text),
      "inline supervisory-role decision scan is back")

# --- 6d. the IRIS collection-row reader handles BOTH response shapes -------
# `/case/ioc/list` returns `data` as an OBJECT wrapping the rows while the
# timeline/notes/cases endpoints return a bare LIST. Assuming a list made the
# publish iterate the object's KEYS and die with `'str' object has no attribute
# 'get'` — after the IRIS case had already been created, aborting the run
# before the timeline was written.
if _iris is not None and hasattr(_iris, "_rows"):
    check("6d. _rows reads a bare-list response",
          [r.get("v") for r in _iris._rows({"data": [{"v": 1}, {"v": 2}]})] == [1, 2])
    check("6d. _rows reads an object-wrapped response (the ioc/list shape)",
          [r.get("v") for r in _iris._rows({"data": {"ioc": [{"v": 3}], "state": {}}}, "ioc")]
          == [3])
    check("6d. _rows reads an unnamed object wrapper and drops non-records",
          _iris._rows({"data": {"whatever": [{"v": 4}, "junk"]}}) == [{"v": 4}])
    check("6d. _rows survives a missing/None data field",
          _iris._rows({}) == [] and _iris._rows({"data": None}) == [])

# --- 7. two surfaces, one number (digest Coverage vs /reports) --------------
# The original defect read 281 decided cases in the digest and 118 in /reports
# on the SAME store. A count is a claim: it has to come from one derivation.
_oracle = [c for c in CASES if case_decision(c)[0]]
_check_store = _FakeMemory(CASES)
_orig2 = CaseStore._get_memory
CaseStore._get_memory = lambda self: _check_store
try:
    enumerated = report_gen._all_spine_cases(days=3650)
finally:
    CaseStore._get_memory = _orig2
check("7. /reports enumerates exactly the cases the reader calls decided "
      f"({len(_oracle)})",
      len(enumerated) == len(_oracle),
      f"enumerated {len(enumerated)} of {len(_oracle)} decided")
check("7b. the undecided case is counted by NEITHER surface",
      "case-undec00001" not in [c.get("case_id") for c in enumerated])

print()
print(f"{'FAILURES: ' + str(FAILS) if FAILS else 'ALL CHECKS PASSED'}")
sys.exit(1 if FAILS else 0)
