"""Final-report generator — compiles a fully-decided case into a
human-readable report for a larger audience, from EITHER backend.

The report is the deliverable that comes out of the investigation framework:
an executive-facing artifact that shows WHAT happened, WHAT the agents found,
HOW they decided, and WHAT was recommended — without requiring the reader to
know the ontology internals.

Design (from the bake-off axis 6):
  - backend-agnostic: the SAME markdown compiler renders a case whether the
    facts come from the spine (Wazuh side) or SO's native so-case store
    (Security Onion side), so the two backends can be compared deliverable
    vs. deliverable on the same decided incident
  - self-contained: reads only the decided case (no live queries), so it can
    be generated for any case, anytime
  - audience-appropriate: plain-language sections, not raw JSON
  - compilable: every role step in the timeline is rendered in order, so the
    reader follows the same decision chain the agents walked

Sections:
  0. Executive summary (TL;DR — status, decision, one-line why)
  1. Incident header (case_id, title, status, opened)
  2. Trigger / source (what alerted, on what entity)
  3. Decision chain (timeline compressed into human steps)
  4. Evidence (investigation detail: sources, severity, kill-chain)
  5. Decision (supervisory decision + rationale + recommended playbook)
  6. Disposition (tuning / false-positive if adjudicated)

Usage:
    from tools.report_gen import (
        render_case_report,          # spine (Wazuh side)
        render_so_case_report,       # SO native so-case store
        render_reports,              # combined multi-case (spine)
        render_reports_html,         # combined multi-case as HTML
    )
    md = render_case_report("case-26b166ce32")
    md = render_so_case_report("case-26b166ce32")   # axis-6 parity
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.request
from datetime import datetime, timezone
from typing import Any

import yaml

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)


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


def _evidence_items(inv: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not inv:
        return []
    return inv.get("evidence") or []


def _evidence_lines(inv: dict[str, Any] | None) -> list[str]:
    out = []
    for e in _evidence_items(inv):
        label = e.get("label") or e.get("source") or "?"
        if label == "?" and not e.get("count"):
            continue
        cnt = e.get("count", "?")
        samples = e.get("samples") or []
        line = f"- **{label}** — {cnt} event(s)"
        if samples:
            s = str(samples[0])[:70]
            if s:
                line += f" (e.g. `{s}`)"
        out.append(line)
    return out


def _exec_summary(case: dict[str, Any]) -> str:
    """One-paragraph TL;DR for the top of the report."""
    sup = case.get("supervisory") or {}
    decision = sup.get("decision")
    rationale = (sup.get("rationale") or "").strip()
    if not decision:
        for ev in reversed(case.get("timeline", [])):
            if ev.get("role") != "supervisory":
                continue
            d = ev.get("detail") or {}
            if ev.get("type") in ("adjudication", "verdict"):
                decision = d.get("decision") or d.get("verdict") or ""
                if not rationale:
                    rationale = (d.get("rationale") or "").strip()
                break
    src = case.get("source") or {}
    status = case.get("status", "open")

    what = (src.get("rule_desc") or "").strip()
    hunt = src.get("hunt_id")
    if hunt and not what:
        what = f"hunt `{hunt}` finding"
    if not what:
        what = "an alert"

    summary = (
        f"**{status.upper()}** case for {what.lower() if what else 'an incident'}. "
    )
    inv_count = None
    for ev in case.get("timeline", []):
        if ev.get("type") == "investigation" and (ev.get("detail") or {}).get("evidence"):
            inv_count = len(ev["detail"]["evidence"])
            break
    if inv_count:
        summary += f"The investigation engaged {inv_count} evidence source(s). "
    if decision:
        summary += f"Decision: **{decision.upper()}**"
        if rationale:
            summary += f" — {rationale}"
        summary += "."
    else:
        summary += "Decision: **under review**."
    return summary


def _md_core(case: dict[str, Any]) -> list[str]:
    """Render the body sections (2–6) from a normalized spine-shaped case."""
    L: list[str] = []
    case_id = case.get("case_id", "?")
    title = case.get("title", "Untitled incident")
    status = case.get("status", "open")
    ts = _ts(case.get("ts"))
    timeline = case.get("timeline", [])

    L.append(f"# Incident Report — {title}")
    L.append("")
    L.append(f"- **Case**: `{case_id}`")
    L.append(f"- **Status**: {status}")
    L.append(f"- **Opened**: {ts}")
    L.append("")

    # 0. Executive summary
    L.append("## Summary")
    L.append("")
    L.append(_exec_summary(case))
    L.append("")

    # 2. Trigger
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

    # 3. Decision chain
    L.append("## 3. Decision Chain")
    L.append("")
    if not timeline:
        L.append("_No decision steps recorded._")
        L.append("")
    for ev in timeline:
        d = ev.get("detail", {})
        label = _role_label(ev.get("role", "?"), ev.get("type", "?"))
        when = _ts(ev.get("ts"))
        line = f"**{when}** — {label}"
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

    # 4. Evidence
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

    # 5. Decision
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
        for ev in reversed(timeline):
            if ev.get("role") == "supervisory" and ev.get("type") in ("adjudication", "verdict"):
                d = ev.get("detail", {})
                L.append(f"**{(d.get('decision') or d.get('verdict') or '?').upper()}** — {_ts(ev.get('ts'))}")
                if d.get("rationale"):
                    L.append("")
                    L.append(d["rationale"])
                break
        else:
            L.append("_No supervisory decision recorded._")
    L.append("")

    # 6. Disposition
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
    return L


def render_case_report(case_id: str) -> str:
    """Render a fully-decided spine case as a markdown report.

    Returns the markdown. Raises KeyError if the case isn't in the spine.
    """
    from tools.case_tools import CaseStore
    case = CaseStore().get_case(case_id)
    if not case:
        raise KeyError(f"case {case_id} not found in spine")
    return "\n".join(_md_core(case))


# ---------------------------------------------------------------------------
# SO-native reader (axis-6 parity: same deliverable from Security Onion)
# ---------------------------------------------------------------------------

def _so_target():
    with open(settings.hunts_dir.parent / "transport.yaml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    b = cfg["backends"]["securityonion"]
    import re
    m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
    host = m.group(1) if m else "192.168.1.76"
    port = int(m.group(2) or 9200) if m else 9200
    user = b.get("user")
    pw = settings.so_indexer_password
    return host, port, user, pw


def _so_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _so_search(index, body):
    host, port, user, pw = _so_target()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(
        f"https://{host}:{port}/{index}/_search", data=json.dumps(body).encode(),
        method="POST",
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20, context=_so_ctx()) as r:
        return json.loads(r.read().decode())


def _so_parse_comment(msg: str) -> dict[str, Any]:
    """Parse an SO comment op message back into a timeline detail dict.

    The publisher encodes the spine event as `[role/type] k=v ...` (see
    deploy/lab/publish_case_so.py) — this reverses that for the report so
    the SO-native surface carries the same facts as the spine.
    """
    d: dict[str, Any] = {}
    m = msg.split("] ", 1)
    if len(m) == 2:
        d["raw"] = m[1]
    body = m[1] if len(m) == 2 else msg

    # verdict=/finding= /decision= key:value pairs in the comment body
    pairs = {
        "verdict": "verdict",
        "decision": "decision",
        "finding": "finding",
        "confidence": "confidence",
        "category": "cat",
    }
    for key, token in pairs.items():
        if f"{token}=" in body:
            rest = body.split(f"{token}=", 1)[1]
            val = rest.split()[0].strip(",") if rest.strip() else ""
            d[key] = val
    # level=N
    if " level=" in body or body.startswith("level="):
        seg = body.split("level=", 1)[1]
        d["level"] = seg.split()[0].strip(",")
    # evidence_count / "N evidence sources"
    for tok in body.replace(",", " ").split():
        if tok.isdigit() and "evidence" in body:
            d["evidence_count"] = int(tok)
            break
    # severity=LABEL (N)
    if "severity=" in body:
        seg = body.split("severity=", 1)[1]
        label = seg.split()[0].strip("()")
        d["severity_label"] = label
        mm = re.search(r"\((\d+)\)", seg)
        if mm:
            d["severity"] = int(mm.group(1))
    # chain=[...] -> kill_chain
    if "chain=" in body:
        seg = body.split("chain=", 1)[1]
        inner = seg.strip()
        if inner.startswith("["):
            inner = inner[1:]
        inner = inner.split("]", 1)[0] if "]" in inner else inner
        parts = [p.strip().strip("'\"") for p in inner.split(",") if p.strip().strip("'\"")]
        d["kill_chain"] = parts
    # rationale=... (the rest of the message after the key)
    if "rationale=" in body:
        seg = body.split("rationale=", 1)[1]
        d["rationale"] = seg.strip()[:300]
    # summary=...
    if "summary=" in body:
        seg = body.split("summary=", 1)[1]
        d["summary"] = seg.strip()[:300]
    return d


def render_so_case_report(case_id: str) -> str:
    """Render the SAME report format from SO's native so-case store.

    Axis-6 parity: given the same fully-decided case id, both the spine
    (Wazuh side) and SO's native case model compile to the same deliverable.
    Raises KeyError if no SO case exists for this id.
    """
    q = {"query": {"term": {"so_related.case_id": case_id}}, "size": 50,
         "sort": [{"@timestamp": "asc"}]}
    res = _so_search("so-case", q)
    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        raise KeyError(f"case {case_id} not found in SO native store")

    case: dict[str, Any] = {
        "case_id": case_id,
        "title": "Untitled incident",
        "status": "open",
        "ts": None,
        "source": {},
        "observables": [],
        "timeline": [],
    }
    for h in hits:
        s = h["_source"]
        op = s.get("so_operation")
        rel = s.get("so_related") or {}
        sc = s.get("so_case") or {}
        ts = s.get("@timestamp") or case["ts"]
        if op == "create":
            case["title"] = sc.get("title") or case["title"]
            case["status"] = sc.get("status") or case["status"]
            case["ts"] = ts or case["ts"]
            case["source"] = {"category": sc.get("category") or ""}
            desc = (sc.get("description") or "").split("\n\n")
            if len(desc) >= 2 and desc[1].strip():
                case["source"]["rule_desc"] = desc[1].strip()
            else:
                case["source"]["rule_desc"] = case["title"]
            for tag in sc.get("tags") or []:
                if ":" in tag:
                    k, v = tag.split(":", 1)
                    case["observables"].append({"type": k, "value": v})
            case["timeline"].append({
                "role": "router", "type": "dispatch", "ts": ts,
                "detail": {"category": sc.get("category") or ""},
            })
        else:
            comment = (s.get("so_comment") or {}).get("message", "")
            d = _so_parse_comment(comment)
            role = rel.get("role", "?")
            typ = rel.get("type") or (("adjudication" if "decision=" in comment else "comment"))
            case["timeline"].append({"role": role, "type": typ, "ts": ts, "detail": d})

    return "\n".join(_md_core(case))


# ---------------------------------------------------------------------------
# Combined multi-case report (the "larger audience" deliverable)
# ---------------------------------------------------------------------------

def _all_spine_cases(days: int) -> list[dict[str, Any]]:
    """Enumerate decided spine cases in the last N days.

    One pass over the Qdrant working store — the same enumeration pattern
    `recent_hunt_cases` uses (`search_memory("case-", limit=1000)`), not a
    get_case() round-trip per receipt line (which stalled /reports as the
    receipt file grew). Falls back to the JSONL receipts if Qdrant is down.
    """
    from tools.case_tools import CASE_COLLECTION, CaseStore
    cs = CaseStore()
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    seen: list[dict[str, Any]] = []

    def _ok(case: dict[str, Any]) -> bool:
        return bool((case.get("supervisory") or {}).get("decision"))

    try:
        mem = cs._get_memory()
        for r in mem.search_memory(CASE_COLLECTION, "case-", limit=1000):
            payload = CaseStore._parse_content(r.get("content", ""))
            if not payload or not _ok(payload):
                continue
            try:
                t = datetime.fromisoformat(
                    (payload.get("updated_ts") or payload.get("ts") or "").replace("Z", "+00:00")
                ).timestamp()
            except Exception:
                t = 0
            if t >= cutoff:
                seen.append(payload)
    except Exception as e:  # noqa: BLE001 — fall back to receipts on store failure
        logger.warning("qdrant scan failed for /reports, falling back to receipts: %s", e)
        if not cs.cases_file.exists():
            return []
        ids: set[str] = set()
        for line in cs.cases_file.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            cid = rec.get("case_id")
            if not cid or cid in ids:
                continue
            try:
                t = datetime.fromisoformat(rec.get("ts", "").replace("Z", "+00:00")).timestamp()
            except Exception:
                t = 0
            if t >= cutoff:
                ids.add(cid)
                case = cs.get_case(cid)
                if case and _ok(case):
                    seen.append(case)
    seen.sort(key=lambda c: c.get("ts", ""))
    return seen


def render_reports(days: int = 7) -> str:
    """Compile all decided spine cases in the last N days into one report."""
    cases = _all_spine_cases(days)
    L: list[str] = []
    L.append(f"# SSOP Decision Report — last {days} day(s)")
    L.append("")
    L.append(f"**{len(cases)} decided case(s).**")
    L.append("")
    for case in cases:
        L.extend(_md_core(case))
        L.append("")
    if not cases:
        L.append("_No decided cases in the window._")
    return "\n".join(L)


def render_reports_html(days: int = 7) -> str:
    md = render_reports(days)
    return _md_to_html(md, "SSOP Decision Report")


def render_case_report_html(case_id: str) -> str:
    md = render_case_report(case_id)
    return _md_to_html(md, f"Incident Report {case_id}")


def _md_to_html(md: str, title: str) -> str:
    """Convert the markdown report to a clean standalone HTML page.

    Line-based converter: proper <ul> grouping (not the per-<li> regex
    which produced broken nesting), <br> for the markdown hard-breaks,
    escaped text with <strong>/<code> restored.
    """
    import html as _html
    import re as _re
    BR = "\x00BR\x00"
    out: list[str] = []
    in_list = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    for raw in md.splitlines():
        # continuation lines are detected on RAW (before the 2-space ->
        # <br> replacement eats their leading indent)
        if raw.startswith("  ") and in_list:
            out.append(f"<br>{_html.escape(raw.strip())}")
            continue
        line = raw.replace("  ", BR)
        if not line.strip():
            # blank line inside a list: keep the <ul> open (markdown lists
            # can have blank lines between items) — only close on a heading
            # or a new block-level element.
            continue
        # headings — ATX only (# ...), never confused with "- " list lines
        hm = _re.match(r"^(#{1,6}) (.*)$", line)
        if hm:
            close_list()
            level = len(hm.group(1))
            out.append(f"<h{level}>{_html.escape(hm.group(2))}</h{level}>")
            continue
        if line.startswith("- "):
            content = line[2:]
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_html.escape(content)}</li>")
            continue
        close_list()
        out.append(f"<p>{_html.escape(line)}</p>")
    close_list()
    body = "\n".join(out)
    body = body.replace(BR, "<br>")
    body = _re.sub(r"<p>---</p>", "<hr>", body)
    body = _re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", body)
    body = _re.sub(r"`([^`]*)`", r"<code>\1</code>", body)
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{_html.escape(title)}</title>"
        "<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;"
        "max-width:820px;margin:24px auto;padding:0 16px;color:#111;line-height:1.5}"
        "h1{font-size:1.4em}h2{font-size:1.15em;margin-top:1.6em}"
        "ul{margin:0.35em 0;padding-left:20px}"
        "li{margin:0.35em 0}code{background:#f0f0f0;padding:1px 4px;border-radius:3px}"
        "hr{margin:2em 0;border:0;border-top:1px solid #ddd}"
        "</style></head><body>"
        + body
        + "</body></html>"
    )
