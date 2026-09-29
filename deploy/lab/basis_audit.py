#!/usr/bin/env python3
"""Basis audit — how much of each routing decision rests on a human?

WHY THIS EXISTS. The question "should we add a learned classifier to SSOP's
dispatch path?" could not be answered with data, because the router's
decision record said WHAT it decided and never WHY. A signed tuning entry,
a hand-written rule-map line, and the ontology fallback were
indistinguishable at the call site. So the size of the *unadjudicated* share
of live decisions — the only number that would justify or kill a classifier
— was unmeasurable.

`classify()` now reports a Basis. This tool replays live/recorded alerts
through the REAL classify() and counts the distribution.

WHAT IT DOES NOT DO. It does not read the decision back out of the router's
own dispatch records (those only exist per-run, in a transient report). It
re-derives the classification from the alert, which is the honest
definition here: the basis is a property of the (alert, current-config,
current-ledger) triple, not a stored fact. Where the alert is absent it
reads the rule id from the case spine and synthesises a minimal alert —
that subset is reported separately as `synthetic`, because a rule id alone
cannot exercise the group heuristics.

READ THE OUTPUT LIKE THIS.
  * `tuned_entry` is the adjudicated share. High is good.
  * `group_heuristic` + `ontology` is the UNADJUDICATED share — a substring
    test or a category fallback decided, with no human ever looking.
  * `degraded` is a BUG SIGNAL, not a classification quality signal. Any
    non-zero count means a guard is raising in production.
  * `tuned_delta` is a re-adjudication request, not a suppression.

Usage:
  python3 basis_audit.py                     # live alerts, last 24h, from the indexer
  python3 basis_audit.py --days 7
  python3 basis_audit.py --from-spine       # rule ids from the case spine instead
  python3 basis_audit.py --json             # machine-readable
  python3 basis_audit.py --limit 500
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

def _agents_dir() -> str:
    """Locate the agents/ (or runtime-root) dir that holds tools/ and router.py.

    The repo layout is <root>/agents/, but the DEPLOYED runtime mirrors
    agents/* to the runtime root (~/agent-runtime/tools, ~/agent-runtime/
    router.py). Hardcoding the repo shape made the tool fail with
    "No module named 'tools'" on the one host that has real data — so
    probe both, and let an explicit SSOP_AGENTS_DIR win.
    """
    env = os.getenv("SSOP_AGENTS_DIR")
    if env:
        return env
    here = Path(__file__).resolve()
    for cand in (here.parents[2] / "agents", here.parents[2], Path.cwd()):
        if (cand / "router.py").exists() and (cand / "tools").is_dir():
            return str(cand)
    return str(here.parents[2] / "agents")


sys.path.insert(0, _agents_dir())

# The hermetic profile. Without a Qdrant key the tuning ledger RAISES, and
# then EVERY alert reports DEGRADED — the audit would report a fake 100%
# degradation that is really just a missing credential. Set before importing
# router so the import-time settings snapshot picks it up.
os.environ.setdefault("SSOP_ALLOW_NO_QDRANT_KEY", "1")


def _live_alerts(days: int, limit: int) -> list[dict]:
    """Real alerts from the active indexer transport.

    These are the RAW `_source` documents, deliberately NOT run through
    normalize_alert(). router.run() passes the hit's `_source` straight
    into dispatch()/classify() (see the intake loop) — the alert contract
    is applied later, inside the analyst. Normalizing here produced a flat
    shape with no `rule` key, so every alert read as `ontology` with a
    blank rule id: a 100% result that was an artefact of the harness, and
    the first version of this tool did exactly that.
    """
    from tools.registry import get_indexer

    ix = get_indexer()
    ts_field = getattr(ix, "field_timestamp", "timestamp")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    query = {
        "size": limit,
        "sort": [{ts_field: {"order": "desc"}}],
        "query": {"bool": {"filter": [{"range": {ts_field: {"gte": since}}}]}},
    }
    hits = ix.search(query).get("hits", {}).get("hits", [])
    out = []
    for h in hits:
        src = dict(h.get("_source") or {})
        src["_id"] = h.get("_id") or ""
        out.append(src)
    return out


def _spine_alerts(limit: int) -> tuple[list[dict], int]:
    """Rule ids from the case spine, as MINIMAL alerts.

    Returns (alerts, n_synthetic). These are reported separately: a bare
    rule id cannot exercise the group heuristics, so a case mined this way
    measures the rule-map/tuning/ontology split and nothing more.
    """
    from tools.registry import get_cases

    cases = get_cases().all_cases()
    alerts = []
    for c in cases[:limit]:
        rid = str((c.get("alert") or {}).get("rule", {}).get("id") or "")
        if not rid:
            meta = c.get("meta") or {}
            rid = str(meta.get("rule_id") or "")
        if not rid:
            continue
        alerts.append({
            "rule": {"id": rid, "level": 5, "groups": [], "description": ""},
            "agent": {"id": "?", "name": "spine"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    return alerts, len(alerts)


def _count(alerts: list[dict]) -> tuple[Counter, Counter, list[dict]]:
    from router import Basis, classify

    basis_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    unadjudicated: list[dict] = []
    for a in alerts:
        c = classify(a)
        basis_counts[c.basis.value] += 1
        # Only UNADJUDICATED sources go in the ranked list. Listing every
        # basis here while heading the section "Top unadjudicated sources"
        # was a labelling bug: the first run's list was dominated by
        # noise_rule and tuned_entry entries, which are adjudicated.
        if c.basis not in (Basis.TUNED_ENTRY, Basis.DRILL_GATE, Basis.NOISE_RULE):
            rule_counts[f"{c.basis.value}:{a.get('rule', {}).get('id', '?')}"] += 1
            unadjudicated.append({
                "rule_id": a.get("rule", {}).get("id"),
                "groups": a.get("rule", {}).get("groups", []),
                "category": c.category,
                "role": c.role,
                "basis": c.basis.value,
                "detail": c.basis_detail,
            })
    return basis_counts, rule_counts, unadjudicated


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from-spine", action="store_true",
                     help="mine rule ids from the case spine (synthetic alerts)")
    src.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--days", type=int, default=1, help="lookback window (default 1)")
    ap.add_argument("--limit", type=int, default=500, help="max alerts (default 500)")
    ap.add_argument("--top", type=int, default=15, help="top rules to list")
    a = ap.parse_args()

    n_synthetic = 0
    try:
        if a.from_spine:
            alerts, n_synthetic = _spine_alerts(a.limit)
            origin = "case spine (synthetic minimal alerts — rule maps only)"
        else:
            alerts = _live_alerts(a.days, a.limit)
            origin = f"live indexer, last {a.days}d"
    except Exception as e:  # noqa: BLE001 — report the cause, do not fake a number
        print(f"BASIS AUDIT FAILED: {e}", file=sys.stderr)
        print("No distribution is reported: a partial audit that cannot read the "
              "tuning ledger would report every alert as DEGRADED, which is a "
              "measurement artefact, not a finding.", file=sys.stderr)
        return 1

    if not alerts:
        print(f"No alerts from {origin} — nothing to audit.", file=sys.stderr)
        return 1

    basis_counts, rule_counts, unadjudicated = _count(alerts)
    total = sum(basis_counts.values())
    # A blank rule id means the harness is feeding classify() a shape the
    # router never sees, and the whole distribution is an artefact. The
    # first run of this tool reported "100% ontology, rule id ?" and that
    # was the tool's bug, not a platform finding — so make that shape
    # impossible to report rather than merely unlikely.
    blank = sum(n for k, n in rule_counts.items() if k.endswith(":?") or k.endswith(":"))
    if blank == total and total:
        print("BASIS AUDIT REFUSING TO REPORT: every alert had a blank rule id.",
              file=sys.stderr)
        print("The alerts reaching classify() are not the shape router.run() "
              "passes. Fix the harness before reading any number here.",
              file=sys.stderr)
        return 1
    adjudicated = (basis_counts.get("tuned_entry", 0)
                   + basis_counts.get("drill_gate", 0)
                   + basis_counts.get("noise_rule", 0))
    pct_adj = 100.0 * adjudicated / total if total else 0.0
    pct_deg = 100.0 * basis_counts.get("degraded", 0) / total if total else 0.0

    out = {
        "origin": origin,
        "generated": datetime.now(timezone.utc).isoformat(),
        "alerts": total,
        "n_synthetic": n_synthetic,
        "basis_counts": dict(basis_counts),
        "adjudicated_pct": round(pct_adj, 1),
        "degraded_pct": round(pct_deg, 1),
        "unadjudicated_pct": round(100.0 - pct_adj, 1) if total else 0.0,
        "top_unadjudicated": rule_counts.most_common(a.top),
        "unadjudicated_sample": unadjudicated[:20],
    }

    if a.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(f"=== SSOP BASIS AUDIT ===  source: {origin}  alerts: {total}")
    if n_synthetic:
        print("  NOTE: synthetic spine alerts measure rule maps only — the group")
        print("        heuristics cannot be exercised from a bare rule id.")
    print()
    for basis, n in basis_counts.most_common():
        bar = "#" * max(1, round(40 * n / total))
        print(f"  {basis:<18} {n:>5}  {100.0*n/total:5.1f}%  {bar}")
    print()
    print(f"  ADJUDICATED (tuned_entry|drill_gate|noise_rule): {pct_adj:.1f}%")
    print(f"  UNADJUDICATED (heuristic|ontology|transport)   : {out['unadjudicated_pct']:.1f}%")
    if pct_deg:
        print(f"  !! DEGRADED: {pct_deg:.1f}% — a guard is RAISING in production.")
        print("     This is a bug signal, not a quality signal. Check the router")
        print("     journal for 'tuning lookup failed' / 'drill gate failed'.")
    print()
    _top = out["top_unadjudicated"]
    if _top:
        _top_name, _top_n = _top[0]
        _share = 100.0 * _top_n / total
        print(f"  Top unadjudicated source: {_top_name} — {_top_n} alerts "
              f"({_share:.0f}% of ALL traffic)")
        if _share >= 50.0:
            print(f"  !! CONCENTRATED: one source is {_share:.0f}% of every alert.")
            print("     The unadjudicated PERCENTAGE is therefore not evidence of a")
            print("     broad classification problem — it is one chatty rule. Tune or")
            print("     rate-limit THAT rule; a classifier trained on this distribution")
            print("     would mostly learn to recognise one rule id.")
    print(f"  Top unadjudicated sources ({a.top}):")
    for k, n in _top:
        print(f"    {n:>5}  {k}")
    print()
    print("  Read: a HIGH unadjudicated share is the only thing that would")
    print("  justify training a classifier on the spine. A LOW share means the")
    print("  signed tuning ledger is already carrying the load and a model")
    print("  would add a second, unauditable decider to a path that works.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
