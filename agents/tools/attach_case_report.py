#!/usr/bin/env python3
"""Attach the generated report + advisory INTO the case itself, on both
human surfaces, when the supervisor lands a verdict:

  - SO side: appends two comment ops (report, advisory markdown) to the
    case in so-case/so-casehistory with deterministic _ids — the SOC
    renders comments, so the meatsuit sees the full report as part of the
    case conversation, not as a separate link.
  - Wazuh side: the console embeds /report?case_id= inline per case card
    (no storage needed — the API renders it live).

Best-effort: never breaks adjudication. Deterministic ids => re-runs
upsert. skips when SO creds/transport unavailable (repo checkout).

Usage (on infra-ops): python3 -m tools.attach_case_report <case_id>
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import ssl
import sys
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# op role/type markers so the SO-side report renderer can distinguish the
# attached artifact comments from the decision-chain timeline events.
_REPORT_REL = {"role": "report", "type": "report"}
_ADVISORY_REL = {"role": "report", "type": "advisory"}


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _so_target() -> tuple[str, int, str, str] | None:
    """SO ES endpoint + creds from transport.yaml + settings (runtime only)."""
    try:
        import yaml
        from config import settings
        with open("transport.yaml") as f:
            cfg = yaml.safe_load(f)
        b = cfg["backends"]["securityonion"]
        import re
        m = re.match(r"https?://([^:]+)(?::(\d+))?", b["endpoint"])
        host = m.group(1) if m else "192.168.1.76"
        port = int(m.group(2) or 9200) if m else 9200
        user = b.get("user")
        pw = settings.so_indexer_password
        if not user or not pw:
            logger.warning("attach_case_report: SO creds missing, skipping")
            return None
        return host, port, user, pw
    except Exception as e:  # noqa: BLE001 — repo checkout / no transport
        logger.warning("attach_case_report: SO target unavailable: %s", e)
        return None


def _op_id(case_id: str, kind: str) -> str:
    return "ssop-" + hashlib.sha1(f"{case_id}-{kind}".encode()).hexdigest()[:20]


def _render_artifacts(case_id: str) -> tuple[str, str] | None:
    """Render the spine report + advisory markdown. None if case not decided."""
    try:
        from tools.report_gen import render_case_report
        from tools.advisory_gen import render_advisory
        report = render_case_report(case_id)
        advisory = render_advisory(case_id, backend="spine")
        return report, advisory
    except Exception as e:  # noqa: BLE001
        logger.warning("attach_case_report: render failed for %s: %s", case_id, e)
        return None


def _comment_op(create_id: str, description: str, ts: str, rel: dict[str, str]) -> dict[str, Any]:
    """Native comment doc: so_kind 'comment', so_comment {createTime,
    userId, caseId=create _id, description, hours}, so_related.caseId
    (camelCase) — verified against the SOC's own comment writes."""
    from config import settings
    return {
        "@timestamp": ts,
        "so_kind": "comment",
        "so_comment": {
            "createTime": ts,
            "userId": settings.so_user_id_for_role(None),  # automation
            "caseId": create_id,
            "description": description,
            "hours": 0,
        },
        "so_related": {"caseId": create_id, **rel},
    }


def _create_id(case_id: str) -> str:
    """The deterministic create-doc _id for a case — comments link to the
    case via so_comment.caseId = create _id (the case identity). Must match
    publish_case_so._op_ids(case_id, 1)[0] = sha1("<case_id>-0")."""
    import hashlib
    return "ssop-" + hashlib.sha1(f"{case_id}-0".encode()).hexdigest()[:20]


def publish_artifacts_to_so(case_id: str) -> bool:
    """Append report + advisory comment ops to the case in so-case and
    so-casehistory. Deterministic _ids => idempotent upsert. Returns True
    on success (both indices, no errors)."""
    target = _so_target()
    if not target:
        return False
    host, port, user, pw = target
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    arts = _render_artifacts(case_id)
    if not arts:
        return False
    report_md, advisory_md = arts

    import datetime as _dt
    ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
    create_id = _create_id(case_id)

    # ONE consolidated closing comment: case-outcome header -> report ->
    # advisory. Two separate blobs back-to-back read as fragmentation; a
    # single final package ties the thread off (the header states the
    # decision, then the full report + advisory follow).
    from tools.case_tools import CaseStore
    _case = CaseStore().get_case(case_id) or {}
    _sup = _case.get("supervisory") or {}
    _decision = (_sup.get("decision") or "").upper()
    _rationale = (_sup.get("rationale") or "").strip()
    if not _decision:
        # verdict may ride the timeline (hunt/router cases): adjudication or
        # verdict event on a supervisory role, newest first — same fallback
        # the report reader uses.
        for ev in reversed(_case.get("timeline") or []):
            if ev.get("role") != "supervisory":
                continue
            _d = ev.get("detail") or {}
            if ev.get("type") in ("adjudication", "verdict"):
                _decision = (_d.get("decision") or _d.get("verdict") or "").upper()
                if not _rationale:
                    _rationale = (_d.get("rationale") or "").strip()
                break
    _decision = _decision or "UNDER REVIEW"
    header = (
        f"## Case Outcome — **{_decision}**\n\n"
        f"{_rationale}\n\n"
        "---\n\n"
    )
    combined = header + report_md + "\n\n---\n\n" + advisory_md
    ops = [
        ("report", _comment_op(create_id, combined, ts, _REPORT_REL)),
    ]
    bulk: list[dict[str, Any]] = []
    for kind, op in ops:
        oid = _op_id(case_id, kind)
        bulk.append({"index": {"_index": "so-case", "_id": oid}})
        bulk.append(op)
        hist = {**op, "so_kind": "casehistory"}
        bulk.append({"index": {"_index": "so-casehistory", "_id": oid}})
        bulk.append(hist)
    body = "".join(json.dumps(x) + "\n" for x in bulk)
    req = urllib.request.Request(
        f"https://{host}:{port}/_bulk", data=body.encode(), method="POST",
        headers={"Authorization": auth, "Content-Type": "application/x-ndjson"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ctx()) as r:
            out = json.loads(r.read().decode())
        errs = sum(1 for item in out.get("items", [])
                   if "error" in (item.get("index") or {}))
        if errs:
            logger.warning("attach_case_report: %d bulk errors for %s", errs, case_id)
            return False
        logger.info("attached report+advisory to SO case %s", case_id)
        return True
    except Exception as e:  # noqa: BLE001 — best-effort
        logger.warning("attach_case_report: SO publish failed for %s: %s", case_id, e)
        return False


def attach_case_artifacts(case_id: str) -> bool:
    """Best-effort hook: attach the report/advisory into the case on the SO
    surface. Never raises (adjudication must not break)."""
    try:
        return publish_artifacts_to_so(case_id)
    except Exception as e:  # noqa: BLE001
        logger.warning("attach_case_artifacts failed for %s: %s", case_id, e)
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python3 -m tools.attach_case_report <case_id>")
        sys.exit(1)
    logging.basicConfig(level=logging.INFO)
    ok = attach_case_artifacts(sys.argv[1])
    print("ATTACHED" if ok else "SKIPPED/FAILED (see log)")
    sys.exit(0 if ok else 1)
