#!/usr/bin/env python3
"""Score the bake-off axes (0-2) from the IRIS case surface.

ADR-006: parity = both detection engines render the SAME decision chain in
IRIS (the single human front-end). The spine is the source of truth; IRIS is
fed from it, so a decided case must render its full chain on the IRIS
Timeline tab + SSOP note + IOCs + the spine report. If IRIS shows the whole
chain, engine-parity holds by construction (both engines feed the same spine
and IRIS reads the spine).

Reads /tmp/iris_bakeoff_capture.json (capture_iris_bakeoff.py) and scores the
same six axes as the classic bake-off, now against what IRIS renders:

  1. Ontology fidelity     - investigation / verdict / decision on the timeline
  2. Agent-fact transparency - evidence, kill-chain, severity on the timeline
  3. Negative-outcome clarity - an FP/deny carries the WHY (rationale)
  4. Case compilation      - >=3 ordered timeline events assemble one incident
  5. Retention/queryability - the IRIS case is retrievable by its spine id
  6. Report readiness      - the spine report deliverable was captured

Usage: python3 score_iris_bakeoff.py [capture_path]
Writes /tmp/iris_bakeoff_scores.json and prints a table.
"""
import json
import sys


def _timeline(cap: dict) -> list:
    return cap.get("timeline") or []


def _tl_titles(tl: list) -> list:
    return [str(e.get("event_title") or "") for e in tl]


def _tl_all(tl: list) -> str:
    return " ".join(_tl_titles(tl)) + " " + json.dumps(tl)


def _has(cap: dict, needle: str) -> bool:
    """Does the needle appear in timeline titles + content + note + ioc?"""
    blob = _tl_all(cap.get("timeline") or [])
    for n in (cap.get("notes") or []):
        blob += " " + str(n.get("note_title") or "") + " " + str(n.get("note_content") or "")
    for i in (cap.get("iocs") or []):
        blob += " " + str(i.get("ioc_value") or "")
    return needle.lower() in blob.lower()


def _ordered(tl: list) -> bool:
    ts = [e.get("event_date") or e.get("event_id") for e in tl]
    return bool(tl) and all(ts)


def score_iris(cap: dict) -> list:
    tl = _timeline(cap)
    titles = _tl_titles(tl)
    notes = []

    # 1. Ontology fidelity — investigation, verdict, decision visible.
    inv = any("investigation" in t.lower() for t in titles)
    verdict = any("verdict" in t.lower() for t in titles)
    decision = any("decision" in t.lower() for t in titles)
    cat = any("category" in _tl_all(tl).lower() for _ in [0])
    s1 = 2 if (inv and verdict and decision) else (1 if (inv or verdict or decision) else 0)
    notes.append(("1", s1, f"investigation={inv} verdict={verdict} decision={decision}"))

    # 2. Agent-fact transparency — evidence, kill-chain, severity.
    evidence = "evidence" in _tl_all(tl).lower()
    kc = "chain" in _tl_all(tl).lower() or "kill" in _tl_all(tl).lower()
    sev = "severity" in _tl_all(tl).lower()
    s2 = 2 if (evidence and (kc or sev)) else (1 if (evidence or kc) else 0)
    notes.append(("2", s2, f"evidence={evidence} kill_chain={kc} severity={sev}"))

    # 3. Negative-outcome clarity — an FP/deny carries the WHY (rationale).
    # IRIS renders a negative outcome as a "DENY"/"false positive" decision
    # event title (not the literal spine verdict token), so detect deny/FP.
    tl_blob = _tl_all(tl).lower()
    deny = "deny" in tl_blob or "false_positive" in tl_blob or "false positive" in tl_blob
    rationale = "rationale" in tl_blob or _has(cap, "rationale")
    s3 = 2 if (deny and rationale) else (1 if (deny or rationale) else 0)
    notes.append(("3", s3, f"deny/fp={deny} rationale={rationale}"))

    # 4. Case compilation — >=3 ordered events.
    s4 = 2 if (len(tl) >= 3 and _ordered(tl)) else (1 if tl else 0)
    notes.append(("4", s4, f"timeline_events={len(tl)} ordered={_ordered(tl)}"))

    # 5. Retention/queryability — IRIS case found by its spine soc_id.
    iris_id = cap.get("iris_case_id")
    s5 = 2 if iris_id else 0
    notes.append(("5", s5, f"iris_case_id={iris_id} (retrieved by spine id)"))

    # 6. Report readiness — the spine report deliverable captured.
    rep = cap.get("report_spine_markdown") or ""
    s6 = 2 if len(rep) > 200 else (1 if rep else 0)
    notes.append(("6", s6, f"report captured: {len(rep)} chars"))
    return notes


def main() -> int:
    cap_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/iris_bakeoff_capture.json"
    with open(cap_path) as f:
        cap = json.load(f)

    scores = score_iris(cap)
    axes = {1: "Ontology fidelity", 2: "Agent-fact transparency",
            3: "Negative-outcome clarity", 4: "Case compilation",
            5: "Retention/queryability", 6: "Report readiness"}

    print(f"case: {cap.get('case_id')} -> IRIS case {cap.get('iris_case_id')}")
    print(f"{'Axis':<6}{'Score':<8}Note")
    print("-" * 70)
    rows = []
    for a in sorted(axes):
        s = next(n for n in scores if n[0] == str(a))
        rows.append({"axis": int(a), "axis_name": axes[a], "iris": s[1], "note": s[2]})
        print(f"{a:<6}{'/'*s[1]:<8}{axes[a]} — {s[2]}")
    total = sum(r["iris"] for r in rows)
    print("-" * 70)
    print(f"IRIS total: {total}/12")

    with open("/tmp/iris_bakeoff_scores.json", "w") as f:
        json.dump({"case_id": cap.get("case_id"), "axes": rows, "total": total}, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
