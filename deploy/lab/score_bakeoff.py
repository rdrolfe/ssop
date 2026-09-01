#!/usr/bin/env python3
"""Score the bake-off axes (0–2) from a captured bake-off representation.

Reads /tmp/bakeoff_capture.json (written by capture_bakeoff.py) and scores
each axis for each surface against ACTUAL captured data — the same rubric the
bake-off doc defines:

  0 = absent  1 = partial  2 = faithful

Axes:
  1. Ontology fidelity     — category / verdict / decision-chain visible
  2. Agent-fact transparency — evidence count / kill-chain / severity / rec
  3. Negative-outcome clarity — WHY an alert was NOT acted on (FP rationale)
  4. Case compilation      — one incident assembled from ordered events
  5. Retention/queryability — older case retrievable by id
  6. Report readiness      — produces the final report deliverable

Usage: python3 score_bakeoff.py [capture_path]
Writes /tmp/bakeoff_scores.json and prints a human table.
"""
import json
import sys


def _console(cap: dict) -> dict:
    """The Wazuh console case view (reads the spine)."""
    v = cap.get("wazuh_console_api") or {}
    # /cases?case_id= returns {"ok":true,"case":{...}}; /cases returns {"cases":[...]}
    if isinstance(v, dict) and "case" in v:
        return v["case"] or {}
    if isinstance(v, dict) and isinstance(v.get("cases"), list) and v["cases"]:
        return v["cases"][0]
    return {}


def _so(cap: dict) -> list:
    """The SO native so-case activity-log ops for the case."""
    return cap.get("so_native_case_store") or []


def _so_comments(so_ops: list) -> str:
    return "\n".join((o.get("comment") or "") for o in so_ops)


def _so_case_fields(so_ops: list) -> dict:
    """The create-op fields; a re-published case has multiple create ops, so
    prefer the most recent one that carries a category (the parity fix)."""
    creates = [o for o in so_ops if o.get("operation") == "create"]
    if not creates:
        return {}
    for o in reversed(creates):  # newest first
        if o.get("category"):
            return o
    return creates[0]


# --- evidence checks ------------------------------------------------------

def _console_has(c, key):
    """Does the console case view carry the key anywhere (case or timeline detail)?"""
    def _walk(x, k):
        if isinstance(x, dict):
            if k in x and x[k] not in (None, "", [], {}):
                return True
            return any(_walk(v, k) for v in x.values())
        if isinstance(x, list):
            return any(_walk(i, k) for i in x)
        return False
    return _walk(c, key)


def _console_timeline(c) -> list:
    return c.get("timeline") or []


def _so_has(so_ops, needle):
    return needle in _so_comments(so_ops) or needle in json.dumps(so_ops)


# --- per-axis scoring ------------------------------------------------------

def score_console(c, cap) -> list:
    """Return [(axis, score, note), ...] for the Wazuh console surface."""
    tl = _console_timeline(c)
    notes = []

    # 1. Ontology fidelity
    verdict = _console_has(c, "verdict")
    decision = _console_has(c, "decision")
    category = _console_has(c, "category")
    chain = any((e.get("detail") or {}).get("kill_chain") for e in tl)
    s1 = 2 if (verdict and decision and (category or chain)) else (1 if (verdict or decision) else 0)
    notes.append(("1", s1, f"verdict={verdict} decision={decision} category={category} chain={chain}"))

    # 2. Agent-fact transparency
    ev_count = _console_has(c, "evidence_count")
    evidence = _console_has(c, "evidence")
    sev = _console_has(c, "severity")
    kc = any((e.get("detail") or {}).get("kill_chain") for e in tl)
    s2 = 2 if (evidence and (kc or sev)) else (1 if (evidence or ev_count) else 0)
    notes.append(("2", s2, f"evidence={evidence} ev_count={ev_count} severity={sev} kill_chain={kc}"))

    # 3. Negative-outcome clarity
    fp = "false_positive" in json.dumps(c).lower()
    rationale = any((e.get("detail") or {}).get("rationale") for e in tl) or bool((c.get("supervisory") or {}).get("rationale"))
    s3 = 2 if (fp and rationale) else (1 if (fp or rationale) else 0)
    notes.append(("3", s3, f"false_positive={fp} rationale={rationale}"))

    # 4. Case compilation
    ordered = tl and all(e.get("ts") for e in tl)
    s4 = 2 if (len(tl) >= 3 and ordered) else (1 if tl else 0)
    notes.append(("4", s4, f"timeline_events={len(tl)} ordered={bool(ordered)}"))

    # 5. Retention / queryability — a capture EXISTS means the case was
    # retrieved by id (this is /cases?case_id= working), and the view is real.
    retrieved = isinstance(c, dict) and bool(c.get("case_id") or c.get("title") or c.get("timeline"))
    s5 = 2 if retrieved else 0
    notes.append(("5", s5, f"case retrieved by id (view={retrieved})"))

    # 6. Report readiness — was the spine report actually captured?
    rep = cap.get("report_spine_markdown") or ""
    s6 = 2 if len(rep) > 200 else (1 if rep else 0)
    notes.append(("6", s6, f"report captured: {len(rep)} chars"))
    return notes


def score_so(so_ops: list, cap: dict) -> list:
    """Return [(axis, score, note), ...] for the SO native so-case surface."""
    comments = _so_comments(so_ops)
    cf = _so_case_fields(so_ops)
    notes = []

    # 1. Ontology fidelity
    has_cat = bool(cf.get("category"))
    has_verdict = "verdict=" in comments
    has_decision = "decision=" in comments
    s1 = 2 if (has_verdict and has_decision and has_cat) else (1 if (has_verdict or has_decision) else 0)
    notes.append(("1", s1, f"category={has_cat} verdict={has_verdict} decision={has_decision}"))

    # 2. Agent-fact transparency
    ev_count = "evidence sources" in comments or "evidence_count" in comments
    kc = "chain=" in comments
    sev = "severity=" in comments
    s2 = 2 if (ev_count and (kc or sev)) else (1 if (ev_count or kc) else 0)
    notes.append(("2", s2, f"evidence={ev_count} kill_chain={kc} severity={sev}"))

    # 3. Negative-outcome clarity
    fp = "false_positive" in comments
    rationale = "rationale=" in comments
    s3 = 2 if (fp and rationale) else (1 if (fp or rationale) else 0)
    notes.append(("3", s3, f"false_positive={fp} rationale={rationale}"))

    # 4. Case compilation
    ops = sorted([o for o in so_ops if o.get("ts")], key=lambda o: o.get("ts"))
    s4 = 2 if (len(ops) >= 4 and all(o.get("operation") for o in ops)) else (1 if ops else 0)
    notes.append(("4", s4, f"ops={len(ops)} ordered_by_ts"))

    # 5. Retention / queryability — docs exist in the native store keyed by
    # so_related.case_id (proven by this very capture).
    s5 = 2 if so_ops else 0
    notes.append(("5", s5, f"{len(so_ops)} so-case ops present for id"))

    # 6. Report readiness — was the SO-native report actually captured?
    rep = cap.get("report_so_markdown") or ""
    s6 = 2 if len(rep) > 200 else (1 if rep else 0)
    notes.append(("6", s6, f"report captured: {len(rep)} chars"))
    return notes


def main() -> int:
    cap_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/bakeoff_capture.json"
    with open(cap_path) as f:
        cap = json.load(f)

    console = _console(cap)
    so_ops = _so(cap)
    c_scores = score_console(console, cap)
    so_scores = score_so(so_ops, cap)

    axes = {1: "Ontology fidelity", 2: "Agent-fact transparency",
            3: "Negative-outcome clarity", 4: "Case compilation",
            5: "Retention/queryability", 6: "Report readiness"}

    print(f"case: {cap.get('case_id')}")
    print(f"{'Axis':<6}{'Wazuh console':<16}{'SO native':<16}Note")
    print("-" * 60)
    rows = []
    for a in sorted(axes):
        cs = next(n for n in c_scores if n[0] == str(a))
        ss = next(n for n in so_scores if n[0] == str(a))
        rows.append({"axis": a, "axis_name": axes[a], "console": cs[1], "so": ss[1],
                     "console_note": cs[2], "so_note": ss[2]})
        print(f"{a:<6}{'/'*cs[1]:<16}{'/'*ss[1]:<16}{axes[a]}")
    print("-" * 60)
    for r in rows:
        print(f"  axis {r['axis']} ({r['axis_name']}): console {r['console']} — {r['console_note']}")
        print(f"         so   {r['so']} — {r['so_note']}")

    with open("/tmp/bakeoff_scores.json", "w") as f:
        json.dump({"case_id": cap.get("case_id"), "axes": rows}, f, indent=2)
    print("\nwrote /tmp/bakeoff_scores.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
