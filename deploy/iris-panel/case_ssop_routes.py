#  IRIS Source Code additions — SSOP Decision Panel (custom, lab)
#  Copyright (C) 2026 SSOP — adds an SSOP tab to the IRIS case page that
#  shows the spine's live state for the case and lets a supervisory user
#  approve/deny/false-positive the open tier-2 ticket via the spine
#  adjudication API on infra-ops (.29:8787).
#
#  This is a FIRST-PARTY blueprint (same pattern as case_tasks_routes.py),
#  registered alongside the sibling case blueprints in case_routes.py.

# IMPORTS ------------------------------------------------
from flask import Blueprint
from flask import current_app
try:
    from markupsafe import escape  # Flask >= 2.3 (flask.escape removed)
except ImportError:  # older IRIS Flask versions
    from flask import escape
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask_login import current_user
from flask_wtf import FlaskForm

import json
import ssl
import urllib.error
import urllib.request
from typing import Optional

from app.datamgmt.case.case_db import get_case
from app.models.authorization import CaseAccessLevel
from app import db
from app.models.cases import Cases
from app.util import ac_api_case_requires
from app.util import ac_case_requires
from app.util import response_error
from app.util import response_success

case_ssop_blueprint = Blueprint('case_ssop',
                                __name__,
                                template_folder='templates')

# Spine adjudication API (infra-ops). Bound to 0.0.0.0:8787 with TLS.
_SSOP_API = "https://192.168.1.29:8787"
# IRIS users allowed to DECIDE (everyone else sees the tab read-only).
# Names are the IRIS login names (users table). Service accounts excluded.
_DECIDERS = {"Ryan", "administrator"}


def _spine_call(method: str, path: str, body: Optional[dict] = None) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{_SSOP_API}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        return json.loads(r.read().decode())


def _spine_case(soc_id: str) -> Optional[dict]:
    try:
        d = _spine_call("GET", f"/cases?case_id={soc_id}")
        return d.get("case")
    except Exception:  # noqa: BLE001 — panel must degrade, not die
        return None


def _open_ticket_for(soc_id: str) -> Optional[dict]:
    try:
        d = _spine_call("GET", "/tickets")
        for t in d.get("tickets", []):
            cid = (t.get("detail") or {}).get("case_id") or t.get("case_id")
            if cid == soc_id:
                return t
    except Exception:  # noqa: BLE001
        pass
    return None


def _can_decide() -> bool:
    return current_user is not None and current_user.name in _DECIDERS


# CONTENT ------------------------------------------------
@case_ssop_blueprint.route('/case/ssop', methods=['GET'])
@ac_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def case_ssop(caseid, url_redir):
    if url_redir:
        return redirect(url_for('case_ssop.case_ssop', cid=caseid, redirect=True))

    form = FlaskForm()
    case = get_case(caseid)
    soc_id = case.soc_id if case else None
    spine = _spine_case(soc_id) if soc_id else None
    ticket = _open_ticket_for(soc_id) if soc_id else None
    return render_template(
        "case_ssop.html", case=case, form=form,
        spine=spine, ticket=ticket, soc_id=soc_id,
        can_decide=_can_decide(),
        decide_url=url_for('case_ssop.case_ssop_decide', cid=caseid))


def _case_soc_id(case) -> Optional[str]:
    """Resolve the spine case ID linked to an IRIS case.

    Prefers the soc_id column; falls back to custom_attributes.ssop.soc_id
    for cases linked only through the SSOP panel metadata.
    """
    if case is None:
        return None
    soc_id = getattr(case, "soc_id", None)
    if soc_id:
        return str(soc_id)
    ssop = ((case.custom_attributes or {}).get("ssop") or {})
    v = ssop.get("soc_id") if isinstance(ssop, dict) else None
    return str(v) if v else None


@case_ssop_blueprint.route('/case/ssop/decide', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def case_ssop_decide(caseid):
    """POST the human decision to the spine case-decision API.

    Body: {decision: approve|deny|fp, rationale: str, case_id: str}
    The spine API writes the verdict ON THE CASE (case_verdict: timeline
    event + state transition + assignment on approve) and closes the linked
    open tier-2 ticket. Attribution: current_user.name is appended to the
    rationale so the spine audit trail records WHO decided from IRIS.
    """
    if not _can_decide():
        return response_error("Only supervisory users can decide (SSOP panel)")
    try:
        payload = request.get_json(force=True)
    except Exception:  # noqa: BLE001
        return response_error("bad json body")
    decision = (payload or {}).get("decision", "")
    rationale = (payload or {}).get("rationale", "")
    case_id = (payload or {}).get("case_id", "")
    if decision not in ("approve", "deny", "fp"):
        return response_error("decision must be approve|deny|fp")
    if not case_id:
        return response_error("case_id required")
    # Bind the decision to the IRIS case this route was authorized for:
    # the spine target must be the case linked to the authorized caseid,
    # never a foreign spine case smuggled in the JSON body (issue #3).
    authorized_case = get_case(caseid)
    soc_id = _case_soc_id(authorized_case)
    if not authorized_case or not soc_id:
        return response_error("IRIS case is not linked to a spine case")
    if str(case_id) != str(soc_id):
        return response_error(
            "case_id does not match the spine case authorized for "
            "this IRIS case")
    rationale = f"{rationale} — decided by {current_user.name} via IRIS"
    try:
        d = _spine_call("POST", "/case-decision", {
            "case_id": soc_id, "decision": decision,
            "rationale": rationale})
        if d.get("ok"):
            return response_success("decision recorded on spine", data=d)
        return response_error(d.get("error", "spine case-decision failed"))
    except urllib.error.HTTPError as e:
        return response_error(f"spine HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:  # noqa: BLE001
        return response_error(f"spine unreachable: {e}")


@case_ssop_blueprint.route('/case/ssop/meta', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def case_ssop_meta(caseid):
    """Write the SSOP summary into the case's custom_attributes.

    Body: {custom_attributes: {...}} — merged under the "ssop" key so the
    case-list datatable (manage.cases.js) can render Engine/Decision/
    Playbook/Agent columns. This bypasses CaseSchema (whose create/update
    load drops custom_attributes on this IRIS version) and writes the ORM
    object directly.
    """
    try:
        payload = request.get_json(force=True)
    except Exception:  # noqa: BLE001
        return response_error("bad json body")
    attrs = (payload or {}).get("custom_attributes")
    if not isinstance(attrs, dict):
        return response_error("custom_attributes (dict) required")
    case = get_case(caseid)
    if not case:
        return response_error("case not found")
    # Sanitize/validate SSOP metadata before storing it (issue #27): it is
    # rendered as HTML in manage.cases.js, so only string fields are
    # accepted and every value is HTML-escaped at the write boundary.
    ssop = attrs.get("ssop", attrs)
    if not isinstance(ssop, dict):
        return response_error("custom_attributes.ssop (dict) required")
    sanitized = {}
    for k, v in ssop.items():
        if not isinstance(v, str):
            return response_error(
                f"custom_attributes.ssop.{k} must be a string")
        if len(v) > 512:
            return response_error(
                f"custom_attributes.ssop.{k} exceeds 512 characters")
        sanitized[str(k)] = str(escape(v))
    existing = dict(case.custom_attributes or {})
    existing["ssop"] = sanitized
    case.custom_attributes = existing
    db.session.commit()
    return response_success("SSOP meta saved", data={"case_id": caseid})
