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
    rationale = f"{rationale} — decided by {current_user.name} via IRIS"
    try:
        d = _spine_call("POST", "/case-decision", {
            "case_id": case_id, "decision": decision,
            "rationale": rationale})
        if d.get("ok"):
            return response_success("decision recorded on spine", data=d)
        return response_error(d.get("error", "spine case-decision failed"))
    except urllib.error.HTTPError as e:
        return response_error(f"spine HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:  # noqa: BLE001
        return response_error(f"spine unreachable: {e}")
