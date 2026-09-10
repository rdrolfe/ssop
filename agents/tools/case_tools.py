"""Case ID spine for SSOP incident lifecycle.

Every security incident gets a case_id minted at first detection. All roles
(analyst, hunter, infra-manager, supervisory) read/write the same incident
record threaded by that ID, so an incident can be reconstructed end-to-end.

DUAL-WRITE CONTRACT:
  - Qdrant collection "cases" = working memory (roles collaborate here)
  - JSONL audit/cases.jsonl = signed, append-only receipt (provable record)
Cross-referencing the two is the supervisory agent's audit-integrity duty.

CASE LIFECYCLE (SO parity — real case management):
  A case moves through an enforced state machine — new -> triage ->
  investigating -> awaiting_decision -> decided -> closed (-> archived) —
  every move logged as a timeline event with the acting role. `status`
  (open/closed) is DERIVED from state for compatibility with recidivism
  scans; `state` is the authoritative lifecycle position. Assignment
  history and last_touched_ts make the case a managed object, not a queue
  row.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)

CASE_COLLECTION = settings.case_collection
# Event-points design: timeline events live as independent points in their
# own collection; the case point carries state fields only.
CASE_EVENTS_COLLECTION = settings.case_collection + "_events"


def load_case_template(rule_id: Any) -> str | None:
    """Return the markdown case-template for a rule, if one is mapped.

    Adopted SO concept (case templates per rule -> ontology): the rule map in
    transport.yaml can carry `template: <name>`; the template lives in
    agents/templates/<name>.md. When a case is opened for that rule, the
    checklist is prepopulated into the case so the human (supervisory role)
    sees the investigation steps immediately. Backend-agnostic — the mapping
    is ontology data, not SIEM-specific.
    """
    try:
        tfile = settings.hunts_dir.parent / "transport.yaml"  # agents/transport.yaml
        data = yaml.safe_load(tfile.read_text()) if tfile.exists() else {}
        rules = data.get("rules", {})
        # Rule-map keys parse as ints in YAML; try both forms.
        entry = rules.get(rule_id) or rules.get(str(rule_id))
        tpl_name = (entry or {}).get("template") if isinstance(entry, dict) else None
        if not tpl_name:
            return None
        tpl = settings.hunts_dir.parent / "templates" / f"{tpl_name}.md"
        if tpl.exists():
            return tpl.read_text()
        logger.warning("case template %s not found for rule %s", tpl_name, rule_id)
        return None
    except Exception as e:  # noqa: BLE001 — template lookup must never break case creation
        logger.warning("case template lookup failed for rule %s: %s", rule_id, e)
        return None


# --- Case lifecycle state machine (SO parity: real case management) ---
#
# A SOC case moves through states; every move is enforced, logged as a
# first-class timeline event with the acting role, and stamps
# last_touched_ts. `status` (open/closed) is DERIVED from state for
# compatibility with recidivism scans and existing call sites.
CASE_STATES = (
    "new", "triage", "investigating", "awaiting_decision",
    "decided", "closed", "archived",
)

# Allowed transitions: state -> {next states}. Anything else is rejected
# (loudly) — a decided case can't silently drift back to triage, a closed
# case is terminal unless explicitly reopened.
_CASE_TRANSITIONS: dict[str, set[str]] = {
    # new -> decided is legal: a SOC triage-deny (or quick approve) a fresh
    # case without a full investigation.
    "new": {"triage", "investigating", "decided", "closed"},
    "triage": {"investigating", "awaiting_decision", "decided", "closed"},
    "investigating": {"awaiting_decision", "decided", "closed"},
    "awaiting_decision": {"decided", "closed"},
    "decided": {"closed", "reopened"},   # reopened -> back into the flow
    "closed": {"archived", "reopened"},
    "archived": set(),
    "reopened": {"triage", "investigating", "awaiting_decision", "decided", "closed"},
}

# States that read as "open" for the derived status + recidivism checks.
_OPEN_STATES = {"new", "triage", "investigating", "awaiting_decision",
                "decided", "reopened"}


class CaseStateError(RuntimeError):
    """Raised when a case transition is invalid (the machine is enforced)."""


class CaseConflictError(RuntimeError):
    """Raised when concurrent case writers keep colliding past the retry
    budget (optimistic-concurrency verification failed repeatedly)."""


def _derive_status(state: str) -> str:
    return "open" if state in _OPEN_STATES else "closed"


def _normalize_state(state: str) -> str:
    """Backfill legacy cases: map the old two-value status onto the machine."""
    if not state or state not in CASE_STATES:
        return "closed" if state == "closed" else "new"
    return state


class CaseStore:
    """Incident spine backed by Qdrant (working) + JSONL (receipt).

    Owns the case lifecycle state machine (transition/decide/reopen/close),
    assignment history, aging (list_stale), recidivism scans, and the
    dual-write to Qdrant + the append-only receipt spine.

    EVENT-POINTS DESIGN (concurrency):
    Timeline events are INDEPENDENT Qdrant points (collection
    CASE_EVENTS_COLLECTION, deterministic id = uuid5 of
    case_id:ts:role:type:detail) — appends never read-modify-write, so
    concurrent writers cannot lose events (proven failure of the previous
    whole-payload upsert design on live Qdrant, Sep 6). The case point in
    CASE_COLLECTION carries STATE FIELDS ONLY (no timeline); get_case()
    folds case point + event points into the same dict shape every consumer
    expects. Legacy points with embedded timelines still read correctly.
    """

    def __init__(self, memory=None) -> None:
        self.audit_dir: Path = settings.audit_dir
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.cases_file = self.audit_dir / "cases.jsonl"
        self._memory = memory  # injected (registry) or None -> lazy

    def _get_memory(self):
        if self._memory is None:
            from tools.qdrant_tools import QdrantMemory

            self._memory = QdrantMemory()
        return self._memory

    # --- event-point helpers (event-points design) ---

    @staticmethod
    def _event_point_id(case_id: str, entry: dict[str, Any]) -> str:
        """Deterministic id for one timeline event: a retried write of the
        SAME event overwrites the same point (idempotent), never duplicates."""
        import hashlib
        import uuid as _uuid

        detail_hash = hashlib.sha1(
            json.dumps(entry.get("detail", {}), sort_keys=True, default=str).encode()
        ).hexdigest()[:12]
        basis = f"{case_id}:{entry.get('ts')}:{entry.get('role')}:{entry.get('type')}:{detail_hash}"
        return str(_uuid.uuid5(_uuid.NAMESPACE_URL, basis))

    def _write_event_point(self, case_id: str, entry: dict[str, Any]) -> None:
        """Append one timeline event as an independent Qdrant point.

        This is the ONLY write the event itself requires — no read, no
        compare, no whole-payload upsert. Concurrent appends commute.
        """
        from tools.case_tools import CASE_EVENTS_COLLECTION  # same module (avoids runtime layout coupling)

        content = f"{case_id} {json.dumps(entry)}"
        self._get_memory().upsert_point(
            CASE_EVENTS_COLLECTION,
            self._event_point_id(case_id, entry),
            {
                "content": content,
                "case_id": case_id,
                "ts": entry.get("ts", ""),
                "role": entry.get("role", ""),
                "type": entry.get("type", ""),
            },
        )

    def _read_event_points(self, case_id: str) -> list[dict[str, Any]]:
        """Fold event points for a case into timeline entries (ts order)."""
        mem = self._get_memory()
        if not hasattr(mem, "events_for"):
            return []  # test double without event-point support
        timeline: list[dict[str, Any]] = []
        for payload in mem.events_for(CASE_EVENTS_COLLECTION, case_id):
            parsed = self._parse_content(payload.get("content", ""))
            if parsed:
                timeline.append(parsed)
        return timeline

    # --- core ops ---

    def open_case(self, source: dict[str, Any], title: str, observables: list[dict[str, str]] | None = None,
                  enrichments: list[dict[str, Any]] | None = None,
                  techniques: list[str] | None = None,
                  assignee: str | None = None) -> dict[str, Any]:
        """Mint a new incident and write it to both stores.

        `observables` (optional) is the extracted IOC list [{type, value}] —
        a first-class case field per the adopted SO concept (Concept 1 of the
        two-example doctrine). `enrichments` (optional) is the threat-intel
        verdict list from EnrichmentClient (Concept 2). `techniques` (optional)
        is the MITRE ATT&CK technique ID list from the analyst verdict
        (Concept 6) — persisted so the supervisor + advisory render real
        technique IDs, not just derived tactics. All ride in the case payload —
        backend-agnostic, not in any SIEM index. `assignee` (optional)
        is the role that owns/handles the case from the start (auto-assign;
        defaults to None = unowned until the escalation/adjudication path
        assigns it).
        """
        case = {
            "case_id": "case-" + uuid.uuid4().hex[:10],
            "ts": datetime.now(timezone.utc).isoformat(),
            "title": title,
            "status": "open",
            # Real case-management state (SO parity): the state machine a SOC
            # actually runs — new -> triage -> investigating ->
            # awaiting_decision -> decided -> closed (-> archived). `status`
            # stays derived (open/closed) so recidivism scans and existing
            # call sites keep working; `state` is the authoritative lifecycle.
            "state": "new",
            "source": source,  # original alert/trigger
            "observables": observables or [],  # [{type, value}, ...]
            "enrichments": enrichments or [],  # [{provider, status, raw, ts}, ...]
            "techniques": techniques or [],  # ["T1041", ...] — MITRE ATT&CK IDs
            "checklist": None,  # case-template markdown (adopted SO concept 5)
            "timeline": [],  # append-only events (verdicts, actions)
            "assignee": assignee,  # role currently handling it (auto-assign)
            "assignment_history": [],  # [{assignee, ts, by}] — who held it, when
            "last_touched_ts": datetime.now(timezone.utc).isoformat(),
        }
        # The human who mints a case IS the acting role: assignment + history.
        if assignee:
            case["assignment_history"].append({
                "assignee": assignee, "ts": case["ts"], "by": "mint"})
        # Prepopulate the case checklist from the rule's case-template, if any
        # (adopted SO concept: rule.case_template -> auto-populated checklist).
        try:
            rid = source.get("rule_id") or (source.get("alert_id") and None)
            if rid is not None:
                tpl = load_case_template(rid)
                if tpl:
                    case["checklist"] = tpl
        except Exception as e:  # noqa: BLE001 — template must never break case creation
            logger.warning("case template prepopulate failed: %s", e)
        self._write_both(case, event="case_opened")
        logger.info("case opened: %s (%s) [%d observables, %d enrichments]", case["case_id"], title[:60],
                    len(case["observables"]), len(case["enrichments"]))
        return case

    # Optimistic-concurrency retry budget (issue: concurrent writers). Each
    # mutation re-reads the case, mutates, and verifies its write landed
    # before returning; a racing writer bumps the revision, we re-read, and
    # retry — so the last writer never silently discards an earlier one.
    _WRITE_ATTEMPTS = 5

    def _mutate_case(self, case_id: str, mutate, *, event: str, role: str = "case-spine") -> dict[str, Any] | None:
        """Read-mutate-write with revision verification + retry.

        `mutate(case)` mutates the case dict in place (returns nothing) or
        returns a replacement dict. Between read and upsert another process
        can write the same point — Qdrant upserts are last-write-wins, so we
        verify by re-reading: our revision must be the one on the point.
        On a lost race, re-read (incorporating the other writer's state) and
        retry. Exhausting the budget raises CaseConflictError instead of
        silently overwriting (the reviewed failure mode).
        """
        last_err: Exception | None = None
        for attempt in range(self._WRITE_ATTEMPTS):
            case = self.get_case(case_id)
            if not case:
                return None
            base_rev = int(case.get("revision") or 0)
            result = mutate(case)
            if isinstance(result, dict):
                case = result
            case["revision"] = base_rev + 1
            case["updated_ts"] = datetime.now(timezone.utc).isoformat()
            self._write_both(case, event=event, role=role)
            try:
                verify = self.get_case(case_id)
                if verify and int(verify.get("revision") or 0) == case["revision"] \
                        and verify.get("updated_ts") == case["updated_ts"]:
                    return case
                last_err = RuntimeError(
                    f"case {case_id} write raced (rev {base_rev} -> {case['revision']})")
                logger.warning("case write race on %s (attempt %d/%d): %s",
                               case_id, attempt + 1, self._WRITE_ATTEMPTS, last_err)
            except Exception as e:  # noqa: BLE001 — verify failure must not skip the retry loop
                last_err = e
                logger.warning("case write verify failed on %s (attempt %d/%d): %s",
                               case_id, attempt + 1, self._WRITE_ATTEMPTS, e)
        raise CaseConflictError(
            f"case {case_id}: {self._WRITE_ATTEMPTS} concurrent write attempts "
            f"failed — refusing to clobber: {last_err}")

    def append_event(self, case_id: str, role: str, event_type: str, detail: dict[str, Any]) -> dict[str, Any] | None:
        """Append a timeline event to an existing case (by case_id).

        EVENT-POINTS DESIGN: the event is written as an independent Qdrant
        point (idempotent deterministic id) — no read-modify-write, so
        concurrent appends can never lose an event regardless of timing.

        The case point gets a best-effort STATE-ONLY update (last_touched_ts
        + opportunistic machine advance: investigation -> investigating;
        escalate/verdict -> awaiting_decision). A lost race on THIS write can
        only delay a last_touched refresh or a state advance the next event
        re-derives — it cannot lose the event itself. Adjudication is NOT
        handled here: use decide()/case_verdict (it writes the decision +
        transition).
        """
        case = self.get_case(case_id)
        if not case:
            logger.warning("append_event: case %s not found", case_id)
            return None
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "type": event_type,
            "detail": detail,
        }
        # 1. The event itself — independent point, race-free.
        self._write_event_point(case_id, entry)
        # 2. State projection on the case point (best-effort under races).
        case.setdefault("timeline", []).append(entry)  # embedded copy for legacy readers
        case["last_touched_ts"] = entry["ts"]
        cur = _normalize_state(case.get("state", "new"))
        want = None
        if event_type == "investigation" and cur in ("new", "triage"):
            want = "investigating"
        elif event_type in ("escalate", "verdict") and cur in ("triage", "investigating"):
            want = "awaiting_decision"
        if want and want in _CASE_TRANSITIONS.get(cur, set()):
            case["state"] = want
            case["status"] = _derive_status(want)
        self._write_both(case, event=event_type, role=role)
        return case

    def assign_case(self, case_id: str, role: str, note: str = "") -> dict[str, Any] | None:
        """Assign a case to the role handling it (auto-assign).

        Concurrency-safe (event-points): the `assigned` event is written as
        an independent point first (never lost); the assignee/assignment-
        history fields then update best-effort on the case point (a lost
        race only delays the assignment field; the event + receipt remain).
        """
        prev_holder = [None]  # filled inside _mut (read under the retry loop)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "type": "assigned",
            "detail": {"assignee": role, "previous": prev_holder[0], "note": note or ""},
        }

        def _mut(case: dict[str, Any]) -> None:
            prev_holder[0] = case.get("assignee")
            entry["detail"]["previous"] = prev_holder[0]
            case["assignee"] = role
            case.setdefault("timeline", []).append(entry)
            case["last_touched_ts"] = entry["ts"]
            # Assignment history — who held the case, when, by whom (the SOC
            # audit trail for handoffs between roles).
            case.setdefault("assignment_history", []).append({
                "assignee": role, "ts": entry["ts"], "by": "assign"})

        case = self._mutate_case(case_id, _mut, event="assigned", role=role)
        if not case:
            logger.warning("assign_case: case %s not found", case_id)
            return None
        # Event-points: the assigned event also lands as an independent
        # point, so a lost race on the case-point fields can never lose it.
        try:
            self._write_event_point(case_id, entry)
        except Exception as e:  # noqa: BLE001 — projection write must not fail the call
            logger.warning("assigned event point write failed for %s: %s", case_id, e)
        logger.info("case assigned: %s -> %s (%s)", case_id, role, note or "no note")
        return case

    # --- lifecycle: transitions -------------------------------------------------

    def transition(self, case_id: str, to_state: str, role: str = "case-spine",
                   rationale: str = "") -> dict[str, Any] | None:
        """Move a case through the state machine (enforced).

        Validates the transition, updates `state` + derived `status`, stamps
        `last_touched_ts`, appends a `transition` timeline event (the audit
        trail of WHO moved the case and why), and dual-writes. Raises
        CaseStateError on an illegal move — fail loud, not silent.
        Concurrency-safe (event-points): the transition event is ALSO an
        independent point (written after the state write), so a lost race
        can delay state but never lose the audit event.
        """
        ts = datetime.now(timezone.utc).isoformat()

        def _mut(case: dict[str, Any]) -> None:
            cur = _normalize_state(case.get("state", "new"))
            if to_state not in _CASE_TRANSITIONS.get(cur, set()):
                raise CaseStateError(
                    f"illegal case transition {cur} -> {to_state} (case {case_id})")
            case["state"] = to_state
            case["status"] = _derive_status(to_state)
            case["last_touched_ts"] = ts
            case.setdefault("timeline", []).append({
                "ts": ts,
                "role": role,
                "type": "transition",
                "detail": {"from": cur, "to": to_state, "rationale": rationale or ""},
            })

        try:
            case = self._mutate_case(case_id, _mut, event=f"transition:{to_state}", role=role)
        except CaseStateError:
            raise
        if not case:
            logger.warning("transition: case %s not found", case_id)
            return None
        # Event-points: independent point for the transition audit event.
        try:
            self._write_event_point(case_id, {
                "ts": ts, "role": role, "type": "transition",
                "detail": {"from": case.get("state"), "to": to_state,
                           "rationale": rationale or ""},
            })
        except Exception as e:  # noqa: BLE001 — projection write must not fail the call
            logger.warning("transition event point write failed for %s: %s", case_id, e)
        logger.info("case %s transition: -> %s (%s)", case_id, to_state, role)
        return case

    def decide(self, case_id: str, decision: str, rationale: str,
               role: str = "supervisory") -> dict[str, Any] | None:
        """Record a supervisory decision — the case leaves the decision queue.

        Sets state=decided (approve/deny/auto_fp all land here — the OUTCOME
        is carried by the decision field, the lifecycle position is uniform),
        writes the top-level `supervisory` block AND the adjudication
        timeline event (the console reads the timeline), and stamps the
        case. Callers that previously set status directly now ride the
        machine: an approved case stays OPEN until the responder/close step
        closes it (real SOC semantics — approve ≠ close). Concurrency-safe
        (event-points): the adjudication event is ALSO an independent point,
        so a lost race can delay the decision fields but never lose the
        human decision record.
        """
        ts = datetime.now(timezone.utc).isoformat()

        def _mut(case: dict[str, Any]) -> None:
            cur = _normalize_state(case.get("state", "new"))
            if "decided" not in _CASE_TRANSITIONS.get(cur, set()):
                raise CaseStateError(
                    f"illegal case transition {cur} -> decided (case {case_id})")
            case["state"] = "decided"
            case["status"] = _derive_status("decided")
            case["supervisory"] = {"decision": decision, "rationale": rationale, "ts": ts}
            case.setdefault("timeline", []).append({
                "ts": ts,
                "role": role,
                "type": "transition",
                "detail": {"from": cur, "to": "decided", "rationale": f"{decision}: {rationale[:80]}"},
            })
            case.setdefault("timeline", []).append({
                "ts": ts,
                "role": role,
                "type": "adjudication",
                "detail": {"decision": decision, "rationale": rationale},
            })
            case["last_touched_ts"] = ts

        try:
            case = self._mutate_case(case_id, _mut, event="adjudication", role=role)
        except CaseStateError:
            raise
        if not case:
            return None
        # Event-points: independent point for the human decision.
        try:
            self._write_event_point(case_id, {
                "ts": ts, "role": role, "type": "adjudication",
                "detail": {"decision": decision, "rationale": rationale},
            })
        except Exception as e:  # noqa: BLE001 — projection write must not fail the call
            logger.warning("adjudication event point write failed for %s: %s", case_id, e)
        return case

    def reopen(self, case_id: str, role: str = "case-spine",
               rationale: str = "") -> dict[str, Any] | None:
        """Reopen a closed case (transition via the machine)."""
        return self.transition(case_id, "reopened", role=role,
                               rationale=rationale or "case reopened")

    def list_stale(self, window_days: float = 7.0,
                   include_decided: bool = True) -> list[dict[str, Any]]:
        """Open cases that have NOT been touched in `window_days`.

        Aging as a managed thing (SO parity): a case with no activity for
        the window is stale — it needs a supervisory ping or auto-close.
        `include_decided` adds decided-but-unclosed cases (the class that
        accumulated 73 deep in the backlog audit). Returns the stale cases
        with age + state for the duty to act on.
        """
        from datetime import datetime as _dt
        cutoff = _dt.now(timezone.utc).timestamp() - window_days * 86400
        out = []
        mem = self._get_memory()
        for r in mem.search_memory(CASE_COLLECTION, "case-", limit=2000,
                                   scroll_limit=10000):
            p = self._parse_content(r.get("content", ""))
            if not p:
                continue
            if p.get("status") == "closed":
                continue
            state = _normalize_state(p.get("state", "new"))
            if not include_decided and state == "decided":
                continue
            touched = p.get("last_touched_ts") or p.get("updated_ts") or p.get("ts") or ""
            try:
                age_d = (_dt.now(timezone.utc).timestamp()
                         - _dt.fromisoformat(touched).timestamp()) / 86400
            except (ValueError, TypeError):
                age_d = 999.0
            if age_d >= window_days:
                out.append({**p, "_age_days": round(age_d, 1),
                            "_state": state})
        return out

    def close_case(self, case_id: str, role: str = "case-spine", reason: str = "") -> dict[str, Any] | None:
        """Close a case (status -> closed) and record the lifecycle event.

        A first-class lifecycle op (not a deletion): the append-only receipt
        preserves the full history; the working Qdrant store marks it closed
        so it stops matching 'recent open' checks and entity-recidivism.

        REQUIRES a non-blank `reason`: a closed case with no reason is a
        dead end for post-incident review (writeup audit: 44/47 closed cases
        had an empty reason). Blank reason raises ValueError — fail loud,
        not silent, so callers that forget the reason get caught.
        """
        if not (reason or "").strip():
            raise ValueError(
                "close_case requires a non-blank reason (a closed case with "
                "no reason is a dead end for post-incident review)")
        # Route through the state machine: validates the move, sets state +
        # derived status, stamps last_touched, dual-writes.
        case = self.transition(case_id, "closed", role=role,
                               rationale=reason)
        if not case:
            logger.warning("close_case: case %s not found", case_id)
            return None
        # Keep the explicit case_closed event (existing consumers/audit read
        # it) in addition to the machine's transition event.
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "type": "case_closed",
            "detail": {"reason": reason},
        }
        case.setdefault("timeline", []).append(entry)
        case["updated_ts"] = entry["ts"]
        self._write_both(case, event="case_closed", role=role)
        logger.info("case closed: %s (%s)", case_id, reason[:60])
        return case

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        """Fetch case from Qdrant (working store).

        Exact identity match (issue: capped substring scans): the point
        content is `"<case_id> <json>"`, so the FIRST TOKEN must equal the
        requested case_id. A substring match (`case_id in content`) can
        return a DIFFERENT case whose text merely mentions the id — decision
        and assignment callers trust the payload, so that is a correctness
        bug, not a heuristic. Prefers an exact payload-field lookup; falls
        back to a scanned exact-token match; falls back to receipts.

        Event-points design: the returned timeline = independent event
        points (authoritative, race-free) MERGED with any embedded timeline
        on the case point (legacy rows / the append_event embedded copy),
        deduped by (ts, role, type, detail). All consumers see the same dict
        shape as before.
        """
        try:
            mem = self._get_memory()
            # Primary: exact payload match (Qdrant filter, no scan).
            payload = mem.get_by_payload(CASE_COLLECTION, "case_id", case_id)
            case = None
            if payload:
                parsed = self._parse_content(payload.get("content", ""))
                if parsed and parsed.get("case_id") == case_id:
                    case = parsed
            if case is None:
                # Fallback: full scan with EXACT first-token identity.
                for r in mem.search_memory(CASE_COLLECTION, case_id):
                    content = r.get("content", "")
                    if content.split(" ", 1)[0] == case_id:
                        parsed = self._parse_content(content)
                        if parsed and parsed.get("case_id") == case_id:
                            case = parsed
                            break
            if case is None:
                return None
            # Fold event points over the embedded timeline.
            event_points = self._read_event_points(case_id)
            if event_points:
                embedded = case.get("timeline") or []
                seen = {
                    json.dumps(
                        (e.get("ts"), e.get("role"), e.get("type"), e.get("detail")),
                        sort_keys=True, default=str)
                    for e in embedded
                }
                merged = list(embedded)
                for e in event_points:
                    key = json.dumps(
                        (e.get("ts"), e.get("role"), e.get("type"), e.get("detail")),
                        sort_keys=True, default=str)
                    if key not in seen:
                        seen.add(key)
                        merged.append(e)
                merged.sort(key=lambda e: e.get("ts", ""))
                case["timeline"] = merged
            return case
        except Exception as e:  # noqa: BLE001 — fall back to receipt on any store failure
            logger.warning("qdrant read failed for %s, falling back to receipt: %s", case_id, e)
            return self._get_from_receipt(case_id)

    @staticmethod
    def _parse_content(content: str) -> dict[str, Any] | None:
        if " " not in content:
            return None
        try:
            return json.loads(content.split(" ", 1)[1])
        except (json.JSONDecodeError, IndexError):
            return None

    def _receipts_for(self, case_id: str) -> list[dict[str, Any]]:
        """ALL receipt records for a case, in file (chronological) order."""
        out: list[dict[str, Any]] = []
        if not self.cases_file.exists():
            return out
        for line in self.cases_file.read_text().splitlines():
            try:
                rec = json.loads(line)
                if rec.get("case_id") == case_id:
                    out.append(rec)
            except json.JSONDecodeError:
                continue
        return out

    @staticmethod
    def _rebuild_from_receipts(case_id: str, recs: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Rebuild the LATEST COMPLETE case state from receipts.

        The last receipt is the most recent truth (its status/title); the
        full timeline is folded from EVERY receipt's detail in order, so the
        recovered case carries its history — not a one-event stub (issue:
        receipt recovery returned the first record and a minimal rebuild).
        """
        if not recs:
            return None
        last = recs[-1]
        timeline = [r["detail"] for r in recs if r.get("detail")]
        case: dict[str, Any] = {
            "case_id": case_id,
            "title": last.get("title", case_id),
            "status": last.get("status", "open"),
            "ts": recs[0].get("ts"),
            "updated_ts": last.get("ts"),
            "last_touched_ts": last.get("ts"),
            "observables": [],
            "enrichments": [],
            "techniques": [],
            "state": "closed" if last.get("status") == "closed" else "new",
            "supervisory": last.get("supervisory"),
            "timeline": timeline,
        }
        if case["supervisory"] is None:
            case.pop("supervisory")
        return case

    def _get_from_receipt(self, case_id: str) -> dict[str, Any] | None:
        return self._rebuild_from_receipts(case_id, self._receipts_for(case_id))

    # --- dual-write helpers ---

    def _write_both(self, case: dict[str, Any], event: str, role: str = "case-spine") -> None:
        self._write_receipt(case, event=event, role=role)
        self._write_memory(case)

    def _write_receipt(self, case: dict[str, Any], event: str, role: str = "case-spine") -> None:
        """Append a tamper-evident receipt (issue #26).

        v2 records: hash-chained (prev_hash -> hash) + HMAC'd with the audit
        key, so editing/reordering/deleting/forgetting any record breaks the
        chain detectably. Actor attribution comes from the local SPIRE agent
        when reachable; DEGRADED (actor_verified=false) is explicit, never
        silent. Legacy v1 records (pre-chain) remain readable; the verifier
        labels them unsigned and starts chain math from the first v2 record.
        """
        receipt = {
            "case_id": case["case_id"],
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "event": event,
            "status": case.get("status"),
            "title": case.get("title", ""),
            "detail": case.get("timeline", [{}])[-1] if case.get("timeline") else {},
        }
        try:
            from tools.audit_chain import AuditChainWriter

            if not hasattr(self, "_chain_writer"):
                self._chain_writer = AuditChainWriter(self.cases_file)
            actor_id, actor_ok = None, False
            try:
                from tools.ssh_tools import _fetch_spiffe_id
                actor_id = _fetch_spiffe_id(settings.spire_socket, settings.spire_bin)
                # 'unverified' is the sentinel ssh_tools returns when SPIRE
                # is unreachable — that is DEGRADED attribution, not verified.
                actor_ok = bool(actor_id) and actor_id != "unverified"
                if not actor_ok:
                    actor_id = None
            except Exception as e:  # noqa: BLE001 — degraded mode is explicit
                logger.warning("audit actor attribution unavailable (recording degraded): %s", e)
            self._chain_writer.write(
                case_id=receipt["case_id"], role=role, event=event,
                status=receipt["status"], title=receipt["title"],
                detail=receipt["detail"], actor_id=actor_id,
                actor_verified=actor_ok)
            return
        except Exception as e:  # noqa: BLE001 — chain failure must not kill the case write
            logger.error("chained receipt write failed (falling back to v1): %s", e)
        # Fallback: v1-shaped record (verifier labels it legacy-unsigned).
        with open(self.cases_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(receipt) + "\n")

    def _write_memory(self, case: dict[str, Any]) -> None:
        """Upsert canonical case point in Qdrant (stable uuid5 point id).

        Retries transient connection refusals so a brief network blip cannot
        strand a case as receipt-only (the divergence we hit on .94).
        """
        try:
            import uuid as _uuid

            from qdrant_client.models import PointStruct
            from tools.qdrant_tools import _retry_call

            content = f"{case['case_id']} {json.dumps(case)}"
            pid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, case["case_id"]))
            _retry_call(
                self._get_memory().client.upsert,
                collection_name=CASE_COLLECTION,
                points=[PointStruct(
                    id=pid,
                    vector=[0.0] * 384,
                    payload={
                        "content": content,
                        "timestamp": case.get("ts") or case.get("updated_ts", ""),
                        "type": "case",
                        "case_id": case["case_id"],
                        "status": case.get("status", "open"),
                        "title": case.get("title", ""),
                        "observables": case.get("observables", []),  # queryable IOC list
                        "enrichments": case.get("enrichments", []),  # queryable TI verdicts
                    },
                )],
            )
        except Exception as e:
            logger.exception("qdrant write failed for %s", case.get("case_id"))
            raise RuntimeError(f"case memory write failed: {e}") from e

    # --- audit-integrity (supervisory duty) ---

    def recent_hunt_cases(self, hunt_id: str, window_s: int = 86400,
                          include_closed: bool = False) -> list[dict[str, Any]]:
        """Find open/recent cases filed by the same HUNT (by hunt_id).

        Hunt-level recidivism: a periodic hunt sweep re-tests the same
        hypothesis, so a persistent finding must ATTACH to the existing hunt
        case (append a recheck event), not mint a new case + re-escalate.

        Default returns only OPEN cases (status != closed). Pass
        include_closed=True to also get recently-CLOSED cases for the same
        hunt — powers the re-arm cooldown (a finding whose case was just
        denied must not instantly re-mint a fresh case on the next sweep).

        Scans the Qdrant working store (the receipt spine has no `source` —
        only Qdrant carries source.hunt_id).
        """
        out: list[dict[str, Any]] = []
        cutoff = datetime.now(timezone.utc).timestamp() - window_s
        try:
            mem = self._get_memory()
            for r in mem.search_memory(CASE_COLLECTION, "case-", limit=1000,
                                       scroll_limit=10000):
                payload = self._parse_content(r.get("content", ""))
                if not payload:
                    continue
                if payload.get("status") == "closed" and not include_closed:
                    continue
                src = payload.get("source", {})
                if str(src.get("hunt_id")) != str(hunt_id):
                    continue
                try:
                    ts = payload.get("ts", "")
                    if datetime.fromisoformat(ts).timestamp() < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
                out.append(payload)
        except Exception as e:  # noqa: BLE001 — recidivism must never break the sweep
            logger.warning("recent_hunt_cases scan failed: %s", e)
        return out

    def recent_entity_cases(self, srcip: str, dstip: str, window_s: int = 3600) -> list[dict[str, Any]]:
        """Find open/recent cases engaged with the same (srcip, dstip) pair.

        Powers the stateful entity-recidivism check: a repeated pair should
        ATTACH to an existing chain, not mint a new case.

        Scans the Qdrant working store (the receipt spine carries no `source`
        — only Qdrant holds source.srcip/src.dstip). Keeps cases with a
        matching entity pair, status != closed, and a recent ts.
        """
        out: list[dict[str, Any]] = []
        cutoff = datetime.now(timezone.utc).timestamp() - window_s
        try:
            mem = self._get_memory()
            for r in mem.search_memory(CASE_COLLECTION, "case-", limit=1000,
                                       scroll_limit=10000):
                payload = self._parse_content(r.get("content", ""))
                if not payload:
                    continue
                if payload.get("status") == "closed":
                    continue
                src = payload.get("source", {})
                if (str(src.get("srcip")) != str(srcip)
                        or str(src.get("dstip")) != str(dstip)):
                    continue
                try:
                    ts = payload.get("ts", "")
                    if datetime.fromisoformat(ts).timestamp() < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
                out.append(payload)
        except Exception as e:  # noqa: BLE001 — recidivism must never break triage
            logger.warning("recent_entity_cases scan failed: %s", e)
        return out

    def recent_host_cases(self, host: str, rule_id: str | None = None,
                      window_s: int | None = 3600,
                      open_only: bool = False) -> list[dict[str, Any]]:
        """Find open/recent cases on the SAME HOST (and optionally rule).

        Host-based recidivism: alerts without an entity pair (srcip/dstip —
        e.g. sysmon host events) have nothing to chain on, so every event
        minted its own case (the BOTS Cerber replay: 133 cases for one
        campaign on we8105desk). Same host + same rule within the window = one campaign chain, not N cases. Mirrors recent_entity_cases.

        Scans Qdrant (the receipt spine carries no `source`). Keeps cases
        with matching source.agent (+ source.rule_id when given), status !=
        closed, and a recent ts.

        open_only=True: NO time bound — an open case IS the unresolved
        incident, however old it is. dispatch_infra uses this: a still-open
        case for agent+rule_id must absorb every new identical dispatch
        until a human closes it (the 40704 lesson: a 1h window re-minted
        one case per sweep all day because each mint was >1h from the last).
        """
        out: list[dict[str, Any]] = []
        cutoff = (datetime.now(timezone.utc).timestamp() - window_s
                  if window_s is not None else None)
        try:
            mem = self._get_memory()
            for r in mem.search_memory(CASE_COLLECTION, "case-", limit=1000,
                                       scroll_limit=10000):
                payload = self._parse_content(r.get("content", ""))
                if not payload:
                    continue
                if payload.get("status") == "closed":
                    continue
                src = payload.get("source", {})
                if str(src.get("agent")) != str(host):
                    continue
                if rule_id and str(src.get("rule_id")) != str(rule_id):
                    continue
                if cutoff is not None:
                    try:
                        ts = payload.get("ts", "")
                        if datetime.fromisoformat(ts).timestamp() < cutoff:
                            continue
                    except (ValueError, TypeError):
                        pass
                out.append(payload)
        except Exception as e:  # noqa: BLE001 — recidivism must never break triage
            logger.warning("recent_host_cases scan failed: %s", e)
        return out

    def reconcile(self, heal: bool = True) -> dict[str, Any]:
        """Compare Qdrant vs JSONL for each case. Returns mismatches.

        The supervisory agent consumes this as its audit-integrity check.
        With heal=True (default), receipt-only cases are automatically
        re-synced into Qdrant — the JSONL receipt is the provable truth, so a
        working-memory gap is repaired in place rather than left for a human.
        Qdrant-only points are only reported (never deleted automatically: a
        phantom point is safer than a silently dropped case).
        """
        qdrant_ids: set[str] = set()
        try:
            for r in self._get_memory().search_memory(CASE_COLLECTION, "case-", limit=10000,
                                                      scroll_limit=10000):
                cid = (r.get("metadata") or {}).get("case_id") or r.get("content", "").split(" ", 1)[0]
                if cid.startswith("case-"):
                    qdrant_ids.add(cid)
        except Exception as e:  # noqa: BLE001
            logger.warning("reconcile: qdrant scan failed: %s", e)
        receipt_ids: set[str] = set()
        if self.cases_file.exists():
            for line in self.cases_file.read_text().splitlines():
                try:
                    rec = json.loads(line)
                    if rec.get("case_id"):
                        receipt_ids.add(rec["case_id"])
                except json.JSONDecodeError:
                    continue
        receipt_only = sorted(receipt_ids - qdrant_ids)
        healed: list[str] = []
        heal_failed: list[str] = []
        if heal and receipt_only:
            for cid in receipt_only:
                try:
                    # Rebuild the LATEST COMPLETE state: fold EVERY receipt
                    # for this case into a full timeline (not the first
                    # record + a minimal stub).
                    case = self._rebuild_from_receipts(cid, self._receipts_for(cid))
                    if not case:
                        heal_failed.append(cid)
                        continue
                    self._write_memory(case)
                    healed.append(cid)
                except Exception as e:  # noqa: BLE001 — report, don't die
                    logger.warning("reconcile heal failed for %s: %s", cid, e)
                    heal_failed.append(cid)
            # Refresh the Qdrant id set after healing.
            qdrant_ids.update(healed)
        return {
            "qdrant_only": sorted(qdrant_ids - receipt_ids),
            "receipt_only": sorted(receipt_ids - qdrant_ids),
            "healed": healed,
            "heal_failed": heal_failed,
            "consistent": qdrant_ids == receipt_ids,
            "qdrant_count": len(qdrant_ids),
            "receipt_count": len(receipt_ids),
        }
