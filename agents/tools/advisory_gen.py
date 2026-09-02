"""CISA-style advisory generator — the end-goal report product.

A cybersecurity advisory in the shape CISA publishes (see
aa26-237a A Tale of Two SOCs): a single incident compiled from the spine's
evidence into the structure a larger audience reads. The report and the
advisory are the same underlying decided case; the advisory adds the
executive/narrative frame:

  Advisory at a Glance   title, exec summary, lessons learned, key actions
  Introduction / Summary the incident in prose
  Technical Details      kill-chain, evidence sources, observables, decision
  ATT&CK Mapping         kill-chain stages mapped to MITRE techniques
  Mitigations            from the recommended playbook
  Report footer          source line (the spine/SO backend the facts came from)

Everything is derived from fields the spine ALREADY holds — nothing is
invented. Where a field has no value (e.g. no ATT&CK mapping on the case),
the section is honestly omitted or marked as such.

Usage:
    from tools.advisory_gen import render_advisory
    md = render_advisory("case-26b166ce32")
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# Kill-chain stage -> MITRE ATT&CK tactic (best-effort, deterministic).
# The spine's kill_chain entries are "STAGE: description"; we map the
# STAGE token to a tactic so the advisory can carry an ATT&CK table without
# inventing data. Unknown stages fall back to "Other".
_KILLCHAIN_TO_TACTIC: dict[str, str] = {
    "INITIAL ACCESS": "Initial Access",
    "RECON": "Reconnaissance",
    "RECONNAISSANCE": "Reconnaissance",
    "C2": "Command and Control",
    "C2/MALWARE": "Command and Control",
    "EXFILTRATION": "Exfiltration",
    "NETWORK": "Lateral Movement",
    "PRIVILEGE ESCALATION": "Privilege Escalation",
    "LATERAL MOVEMENT": "Lateral Movement",
    "IMPACT": "Impact",
    "DISCOVERY": "Discovery",
    "PERSISTENCE": "Persistence",
    "CREDENTIAL ACCESS": "Credential Access",
    "DEFENSE EVASION": "Defense Evasion",
}


def _killchain_tactic(stage: str) -> str:
    """Map a kill-chain stage token to an ATT&CK tactic label."""
    key = stage.split(":", 1)[0].strip().upper()
    return _KILLCHAIN_TO_TACTIC.get(key, "Other")


# Technique IDs embedded in kill-chain stage labels, e.g.
# 'C2: DNS queries/tunneling [T1071.004, T1572]' (investigator-injected).
_TECH_TAG_RE = re.compile(r"\[([T\d][\dA-Za-z.]*(?:, *[T\d][\dA-Za-z.]*)*)\]")


def _stage_techniques(stage: str) -> list[str]:
    """Extract MITRE technique IDs from a tagged kill-chain stage label."""
    m = _TECH_TAG_RE.search(stage)
    if not m:
        return []
    return [t.strip() for t in m.group(1).split(",")]


def _decision(case: dict[str, Any]) -> tuple[str, str]:
    """Resolve the supervisory decision + rationale, falling back to the
    timeline when the verdict rides an event instead of the top-level
    `supervisory` block (hunt findings and router-dispatched cases). The
    report already scans the timeline; the advisory must not report
    "under review" for a human-denied case."""
    sup = case.get("supervisory") or {}
    decision = sup.get("decision") or ""
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
    return (decision or "under review"), rationale


def _exec_summary(case: dict[str, Any]) -> str:
    """One-paragraph summary from the spine (status, trigger, decision)."""
    src = case.get("source") or {}
    what = (src.get("rule_desc") or "").strip() or f"hunt {src.get('hunt_id')}" or "an incident"
    status = case.get("status", "open")
    decision, rationale = _decision(case)
    chain = []
    for ev in case.get("timeline", []):
        kc = (ev.get("detail") or {}).get("kill_chain")
        if kc:
            chain = kc
            break
    chain_txt = ", ".join(str(x) for x in chain[:3]) if chain else "no kill-chain recorded"
    text = (
        f"A {status} case was opened for {what}. "
        f"The investigation mapped {chain_txt}. "
        f"Supervisory decision: {decision.upper()}."
    )
    if rationale:
        text += f" {rationale}"
    return text


def _lessons_learned(case: dict[str, Any]) -> list[str]:
    """Derive lessons from the decision + kill-chain (deterministic)."""
    decision, rationale = _decision(case)
    lessons = []
    if decision == "deny" and "false_positive" in json_dumps_lower(case):
        lessons.append("The detection pattern fired on non-actionable data — "
                       "tune the rule/query rather than respond.")
    if decision == "deny" and "weak" in (rationale or "").lower():
        lessons.append("Thin evidence (few sources / low score) is itself a "
                       "finding: enrichment before escalation.")
    if decision == "approve":
        lessons.append("The evidence chain (kill-chain breadth + severity) "
                       "justified an active response.")
    chain = []
    for ev in case.get("timeline", []):
        kc = (ev.get("detail") or {}).get("kill_chain")
        if kc:
            chain = kc
            break
    if chain:
        tactics = sorted({_killchain_tactic(str(s)) for s in chain})
        lessons.append("Observed activity spans: " + ", ".join(tactics) + ".")
    return lessons or ["No lessons derivable from this case."]


def _key_actions(case: dict[str, Any]) -> list[str]:
    """The playbook recommended by the supervisor is the key action."""
    sup = case.get("supervisory") or {}
    actions = []
    pb = sup.get("recommended_playbook")
    if pb:
        actions.append(f"Execute playbook `{pb}` (per supervisory decision).")
    decision, _rat = _decision(case)
    if decision == "approve":
        actions.append("Contain the affected entity and preserve evidence for "
                       "post-incident analysis.")
    elif decision == "deny":
        actions.append("Record the disposition; no response required beyond "
                       "tuning/closure.")
    return actions or ["Review and disposition the case."]


def json_dumps_lower(d: dict) -> str:
    import json
    return json.dumps(d, default=str).lower()


def render_advisory(case_id: str, backend: str = "spine") -> str:
    """Render a decided spine case as a CISA-style advisory (markdown).

    backend param is honored for the footer (which SIEM surface the facts
    were read from) so the same advisory product can be produced from either
    side of the bake-off.
    """
    if backend == "so":
        from tools.report_gen import render_so_case_report  # reuse the SO reader
        # The SO reader returns markdown; we re-derive the case by parsing
        # it back is heavy — instead reuse the same spine-shaped compile.
        case = _case_from_so(case_id)
    else:
        from tools.case_tools import CaseStore
        case = CaseStore().get_case(case_id)
    if not case:
        raise KeyError(f"case {case_id} not found ({backend} backend)")

    L: list[str] = []
    src = case.get("source") or {}
    sup = case.get("supervisory") or {}
    title = case.get("title", "Untitled incident")
    ts = (case.get("ts") or "")[:19].replace("T", " ")

    # --- Advisory at a Glance ---
    L.append("# Cybersecurity Advisory")
    L.append("")
    L.append("## Advisory at a Glance")
    L.append("")
    L.append(f"| Field | Value |")
    L.append(f"|---|---|")
    L.append(f"| Title | {title} |")
    L.append(f"| Case | `{case_id}` |")
    L.append(f"| Opened | {ts} |")
    L.append(f"| Status | {case.get('status', 'open')} |")
    L.append(f"| Source backend | {backend} |")
    L.append("")
    L.append("**Executive Summary**")
    L.append("")
    L.append(_exec_summary(case))
    L.append("")
    L.append("**Lessons Learned**")
    L.append("")
    for lsn in _lessons_learned(case):
        L.append(f"- {lsn}")
    L.append("")
    L.append("**Key Actions**")
    L.append("")
    for act in _key_actions(case):
        L.append(f"- {act}")
    L.append("")

    # --- Technical Details ---
    L.append("## Technical Details")
    L.append("")
    obs = case.get("observables", [])
    if obs:
        L.append("**Observables / indicators**")
        L.append("")
        for o in obs:
            L.append(f"- `{o.get('type')}` `{o.get('value')}`")
        L.append("")
    chain = []
    inv = None
    for ev in case.get("timeline", []):
        d = ev.get("detail") or {}
        if d.get("kill_chain"):
            chain = d["kill_chain"]
        if ev.get("type") == "investigation":
            inv = d
    if chain:
        L.append("**Kill-chain**")
        L.append("")
        for c in chain:
            L.append(f"- {c}")
        L.append("")
    if inv and inv.get("evidence"):
        L.append("**Evidence**")
        L.append("")
        for e in inv["evidence"]:
            cnt = e.get("count", "?")
            L.append(f"- {e.get('label') or e.get('source') or '?'} — {cnt} event(s) "
                     f"(index `{e.get('index', '?')}`)")
        L.append("")

    # --- ATT&CK Mapping ---
    L.append("## ATT&CK Mapping")
    L.append("")
    # Real technique IDs persisted on the case (analyst verdict -> open_case)
    # win: ID + name + tactic, exactly like CISA's per-technique tables. Only
    # when the case carries no technique IDs do we fall back to the derived
    # kill-chain stage -> tactic mapping (the pre-technique behavior).
    techniques = case.get("techniques") or []
    if not techniques:
        for ev in case.get("timeline", []):
            d = ev.get("detail") or {}
            for k in ("techniques", "mitre_techniques"):
                if d.get(k):
                    techniques = [str(x) for x in d[k]]
                    break
            if techniques:
                break
    # Investigated cases carry technique IDs on the kill-chain stage labels
    # themselves ('C2: DNS queries/tunneling [T1071.004, T1572]') — extract
    # them so every correlated case renders a real per-technique table.
    if not techniques and chain:
        stage_tids: set[str] = set()
        for c in chain:
            for tid in _stage_techniques(str(c)):
                if tid not in stage_tids:
                    stage_tids.add(tid)
                    techniques.append(tid)
    if techniques:
        from tools.techniques import technique_meta
        seen_tids: set[str] = set()
        L.append("| Technique | Name | MITRE ATT&CK tactic |")
        L.append("|---|---|---|")
        for tid in techniques:
            tid = str(tid)
            if tid in seen_tids:
                continue
            seen_tids.add(tid)
            m = technique_meta(tid)
            L.append(f"| `{m['id']}` | {m['name']} | {m['tactic']} |")
        # When the technique IDs came from the kill-chain stage labels, also
        # render the stage -> tactic table so the reader sees WHICH behavior
        # each technique attached to (CISA advisories keep both views).
        if any(_stage_techniques(str(c)) for c in chain):
            L.append("")
            L.append("_Technique-to-stage association_")
            L.append("")
            L.append("| Kill-chain stage | MITRE ATT&CK tactic |")
            L.append("|---|---|")
            seen_stages: set[str] = set()
            for c in chain:
                s = str(c)
                tactic = _killchain_tactic(s)
                if tactic in seen_stages:
                    continue
                seen_stages.add(tactic)
                L.append(f"| {s} | {tactic} |")
    elif chain:
        seen = set()
        L.append("| Kill-chain stage | MITRE ATT&CK tactic |")
        L.append("|---|---|")
        for c in chain:
            s = str(c)
            tactic = _killchain_tactic(s)
            key = tactic
            if key in seen:
                continue
            seen.add(key)
            L.append(f"| {s} | {tactic} |")
    else:
        L.append("_No technique mapping recorded on this case._")
    L.append("")

    # --- Decision & Mitigations ---
    L.append("## Decision")
    L.append("")
    decision, rationale = _decision(case)
    L.append(f"**{decision.upper()}**")
    if rationale:
        L.append("")
        L.append(rationale)
    L.append("")
    L.append("## Mitigations")
    L.append("")
    for act in _key_actions(case):
        L.append(f"- {act}")
    L.append("")

    L.append("---")
    L.append(f"*Generated by the SSOP investigation framework · case "
             f"`{case_id}` · source backend `{backend}`*")
    return "\n".join(L)


def _case_from_so(case_id: str) -> dict[str, Any]:
    """Read the spine case; for backend=so we still need the spine case to
    compile the advisory (the SO store holds the same facts but without the
    nested evidence/kill-chain structure the advisory needs). We keep this
    honest: the footer carries the backend the facts were read from."""
    from tools.case_tools import CaseStore
    case = CaseStore().get_case(case_id)
    if not case:
        raise KeyError(f"case {case_id} not found (spine, for backend=so)")
    return case


def render_advisory_html(case_id: str, backend: str = "spine") -> str:
    from tools.report_gen import _md_to_html
    return _md_to_html(render_advisory(case_id, backend),
                       f"Cybersecurity Advisory {case_id}")
