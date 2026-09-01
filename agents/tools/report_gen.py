"""Final-report generator — compiles a fully-decided spine case into a
human-readable report for a larger audience.

The report is the deliverable that comes out of the investigation framework:
an executive-facing artifact that shows WHAT happened, WHAT the agents found,
HOW they decided, and WHAT was recommended — without requiring the reader to
know the ontology internals.

Design (from the bake-off axis 6): the report must be
  - self-contained: reads ONLY the spine case (no live queries), so it can
    be generated for any case, anytime, and compared across backends
  - audience-appropriate: plain-language sections, not raw JSON
  - compilable: every role step in the timeline is rendered in order, so the
    reader follows the same decision chain the agents walked

Sections:
  1. Incident header (case_id, title, status, opened)
  2. Trigger / source (what alerted, on what entity)
  3. Decision chain (timeline compressed into human steps)
  4. Evidence (investigation detail: sources, severity, kill-chain)
  5. Supervisory decision + rationale + recommended playbook
  6. Notes (tuning / disposition if adjudicated)

Usage:
    from tools.report_gen import render_case_report
    md = render_case_report("case-26b166ce32")
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def _ts(t: str | None) -> str:
    """Compact UTC timestamp or '—'."""
    if not t:
        return "—"
    try:
        return t[:19].replace("T", " ")
    except Exception:
        return t


def _role_label(role: str, type_: str) -> str:
    """Human label for a timeline (role, type) pair."""
    labels = {
        ("router", "dispatch"): "Routed",
        ("router", "pattern_finding"): "Pattern finding",
        ("router", "pattern_recheck"): "Pattern recheck (repeat signal)",
        ("analyst", "verdict"): "Analyst verdict",
        ("analyst", "investigation"): "Investigation",
        ("hunt", "finding"): "Hunt finding",
        ("hunt", "recheck"): "Hunt recheck (repeat signal)",
        ("hunt", "escalated"): "Hunt escalation",
        ("supervisory", "verdict"): "Supervisor verdict",
        ("supervisory", "adjudication"): "Adjudication",
        ("responder", "playbook_run"): "Responder",
    }
    return labels.get((role, type_), f"{role}/{type_}")


def _evidence_lines(inv: dict[str, Any] | None) -> list[str]:
    if not inv:
        return []
    out = []
    for e in inv.get("evidence", []):
        label = e.get("label") or e.get("source") or "?"
        cnt = e.get("count", "?")
        samples = e.get("samples") or []
        line = f"- **{label}** — {cnt} event(s)"
        if samples:
            s = str(samples[0])[:70]
            if s:
                line += f" (e.g. `{s}`)"
        out.append(line)
    return out


def render_case_report(case_id: str) -> str:
    """Render a fully-decided spine case as a markdown report.

    Returns the markdown. Raises KeyError if the case isn't in the spine.
    """
    from tools.case_tools import CaseStore
    case = CaseStore().get_case(case_id)
    if not case:
        raise KeyError(f"case {case_id} not found in spine")

    L: list[str] = []

    # --- 1. Header ---
    title = case.get("title", "Untitled incident")
    status = case.get("status", "open")
    ts = _ts(case.get("ts"))
    L.append(f"# Incident Report — {title}")
    L.append("")
    L.append(f"- **Case**: `{case_id}`")
    L.append(f"- **Status**: {status}")
    L.append(f"- **Opened**: {ts}")
    L.append("")

    # --- 2. Trigger ---
    src = case.get("source", {})
    L.append("## 2. Trigger")
    L.append("")
    trigger_parts = []
    if src.get("rule_desc"):
        trigger_parts.append(f"Alert: `{src['rule_desc']}`")
    if src.get("category"):
        trigger_parts.append(f"Category: {src['category']}")
    if src.get("hunt_id"):
        trigger_parts.append(f"Hunt: `{src['hunt_id']}`")
    if src.get("level"):
        trigger_parts.append(f"Level: {src['level']}")
    if not trigger_parts:
        trigger_parts.append("No trigger detail recorded.")
    L.extend(f"- {p}" for p in trigger_parts)
    L.append("")

    obs = case.get("observables", [])
    if obs:
        L.append("**Observables**: " + ", ".join(
            f"{o.get('type')} `{o.get('value')}`" for o in obs))
        L.append("")

    # --- 3. Decision chain ---
    L.append("## 3. Decision Chain")
    L.append("")
    timeline = case.get("timeline", [])
    if not timeline:
        L.append("_No decision steps recorded._")
        L.append("")
    for ev in timeline:
        d = ev.get("detail", {})
        label = _role_label(ev.get("role", "?"), ev.get("type", "?"))
        when = _ts(ev.get("ts"))
        line = f"**{when}** — {label}"
        # detail lines per step type
        detail_lines: list[str] = []
        if ev.get("type") == "verdict":
            verdict = d.get("verdict", "")
            if verdict:
                extra = []
                if d.get("level"):
                    extra.append(f"level={d['level']}")
                if d.get("category"):
                    extra.append(f"category={d['category']}")
                detail_lines.append(f"verdict **{verdict}**" + (f" ({', '.join(extra)})" if extra else ""))
            if d.get("rationale"):
                detail_lines.append(d["rationale"])
        elif ev.get("type") == "investigation":
            if d.get("evidence_count") is not None:
                detail_lines.append(
                    f"{d['evidence_count']} evidence source(s), "
                    f"severity **{d.get('severity_label', '?')}** "
                    f"({d.get('severity', '?')})")
            if d.get("kill_chain"):
                detail_lines.append("Kill-chain: " + " → ".join(str(k) for k in d["kill_chain"]))
            if d.get("entity"):
                detail_lines.append(f"Entity `{d['entity']}` engaged across "
                                    f"{d.get('sources_engaged', '?')} source(s): "
                                    f"{', '.join(d.get('sources', []) or [])}")
            # hypothesis is the composed sentence (often restating
            # kill-chain/entity) — only show it when no structured line
            # already covers the story.
            if d.get("hypothesis") and not (d.get("kill_chain") or d.get("entity")):
                detail_lines.append(d["hypothesis"])
        elif ev.get("type") in ("finding", "pattern_finding", "pattern_recheck", "recheck"):
            if d.get("finding"):
                detail_lines.append(f"finding **{d['finding']}** "
                                    f"(confidence {d.get('confidence', '?')})")
            if d.get("summary"):
                detail_lines.append(d["summary"])
        elif ev.get("type") in ("adjudication", "verdict") and ev.get("role") == "supervisory":
            if d.get("decision"):
                detail_lines.append(f"decision **{d['decision']}**")
            if d.get("rationale"):
                detail_lines.append(d["rationale"])
        elif ev.get("type") == "escalated":
            if d.get("finding"):
                detail_lines.append(f"finding **{d['finding']}**")
        elif ev.get("type") == "playbook_run":
            detail_lines.append(json.dumps(d, default=str)[:160])
        elif ev.get("type") == "dispatch":
            if d.get("verdict"):
                detail_lines.append(f"verdict **{d['verdict']}**")
        else:
            if d:
                detail_lines.append(json.dumps(d, default=str)[:160])
        if detail_lines:
            line += "  \n  " + "  \n  ".join(detail_lines)
        L.append(f"- {line}")
    L.append("")

    # --- 4. Evidence detail ---
    inv = None
    for ev in timeline:
        if ev.get("type") == "investigation" and ev.get("detail"):
            inv = ev["detail"]
            break
    ev_lines = _evidence_lines(inv)
    if ev_lines:
        L.append("## 4. Evidence")
        L.append("")
        L.extend(ev_lines)
        L.append("")

    # --- 5. Supervisory decision ---
    sup = case.get("supervisory", {})
    L.append("## 5. Decision")
    L.append("")
    if sup.get("decision"):
        L.append(f"**{sup['decision'].upper()}** — {_ts(sup.get('ts'))}")
        if sup.get("rationale"):
            L.append("")
            L.append(sup["rationale"])
        if sup.get("recommended_playbook"):
            L.append("")
            L.append(f"Recommended playbook: **`{sup['recommended_playbook']}`**")
    else:
        # fall back to the adjudication timeline event
        for ev in reversed(timeline):
            if ev.get("role") == "supervisory" and ev.get("type") == "adjudication":
                d = ev.get("detail", {})
                L.append(f"**{(d.get('decision') or '?').upper()}** — {_ts(ev.get('ts'))}")
                if d.get("rationale"):
                    L.append("")
                    L.append(d["rationale"])
                break
        else:
            L.append("_No supervisory decision recorded._")
    L.append("")

    # --- 6. Disposition notes ---
    notes = []
    for ev in timeline:
        if ev.get("role") == "supervisory" and ev.get("type") == "verdict":
            d = ev.get("detail", {})
            if d.get("verdict") in ("false_positive", "tuning", "operational"):
                notes.append(d.get("verdict"))
    if notes:
        L.append("## 6. Disposition")
        L.append("")
        L.append(f"Adjudicated as: **{', '.join(set(notes))}**")
        L.append("")

    L.append("---")
    L.append(f"*Generated by the SSOP investigation framework · case `{case_id}`*")
    return "\n".join(L)


def render_case_report_html(case_id: str) -> str:
    """Render a case report as a standalone HTML page (for the console)."""
    md = render_case_report(case_id)
    import html as _html
    body = _html.escape(md)
    # very small md subset: #, ##, - list, **bold**
    import re as _re
    body = _re.sub(r"^### (.*)$", r"<h3>\1</h3>", body, flags=_re.M)
    body = _re.sub(r"^## (.*)$", r"<h2>\1</h2>", body, flags=_re.M)
    body = _re.sub(r"^# (.*)$", r"<h1>\1</h1>", body, flags=_re.M)
    body = _re.sub(r"^- ", r"<li>", body, flags=_re.M)
    body = _re.sub(r"<li>(.*)\n(?=<li>|$)", r"<li>\1</li>\n", body)
    body = _re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", body)
    body = _re.sub(r"`(.*?)`", r"<code>\1</code>", body)
    body = _re.sub(r"  \n", r"<br>", body)
    body = body.replace("\n\n", "\n")
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>SSOP Incident Report</title>"
        "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "max-width:820px;margin:24px auto;padding:0 16px;color:#111;line-height:1.5}"
        "h1{font-size:1.4em}h2{font-size:1.15em;margin-top:1.6em}"
        "li{margin:0.35em 0}code{background:#f0f0f0;padding:1px 4px;border-radius:3px}"
        "hr{margin:2em 0;border:0;border-top:1px solid #ddd}"
        "</style></head><body>"
        + body
        + "</body></html>"
    )
