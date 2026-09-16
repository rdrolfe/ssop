"""Tuning ledger — durable, human-confirmed decisions about alert classes.

The stateful analyst decision loop consults this BEFORE the heuristic: has
this rule_id been adjudicated (auto-fp / operational / escalate)? Human
decisions (supervisory adjudication) are the source of truth; analyst
verdicts only SEED entries and never finalize them.

Hygiene: config-driven, imports at top, logging, structured errors.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from qdrant_client.models import PointStruct

from config import settings
from tools.qdrant_tools import QdrantMemory

logger = logging.getLogger(__name__)

TUNING_COLLECTION = "tuning"

# Decisions that make a rule "already handled" — analyst must not re-escalate.
FINAL_DECISIONS = {"auto_fp", "operational", "escalate"}

# Threat-class description tokens: a tuned-FP rule must not silently swallow
# a strong true-positive signal. Single source of truth lives in
# tools.ontology (shared with the analyst + router classifiers) — this
# module imports it rather than redefining.
from tools.ontology import THREAT_DESC_TOKENS  # noqa: E402


def strong_tp_evidence(alert: dict, category: str | None = None) -> bool:
    """True when the current alert carries strong true-positive evidence.

    A tuned-FP rule is suppressed by default, but if THIS alert independently
    shows a threat-class description token, the suppression is lifted
    (evidence overrides tuning — the "clear exception").

    The severity leg (level >= per-category threshold) ONLY counts for
    categories in settings.strong_tp_override_categories (config-driven —
    default threat/authentication/security). Wazuh rule `level` is a STATIC
    property of the rule, not per-alert evidence — dpkg installs (2902),
    integrity checksums (550), and package-manager events (2904/533) are all
    level 7 by rule definition. Treating their static level as strong TP
    evidence defeats the human's auto_fp tuning on those rules and firehoses
    routine maintenance into the queue. The per-category threshold
    (settings.category_high_levels) makes that tunable per category without
    code. When category is None (legacy caller), do NOT lift on severity —
    we can't prove it's attack class, and lifting on an unknown category
    reintroduces the flood. Only the description-token leg above overrides.
    """
    rule = alert.get("rule") or {}
    desc = str(rule.get("description", "")).lower()
    if any(t in desc for t in THREAT_DESC_TOKENS):
        return True
    # Severity leg — config-driven allowlist (which categories may lift on
    # severity) + config-driven per-category threshold.
    if category not in settings.strong_tp_override_categories:
        return False
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    threshold = settings.category_high_levels.get(category, settings.high_level)
    return level >= threshold


def _alert_host(alert: dict) -> str:
    """Extract the agent hostname from an alert, best-effort."""
    agent = alert.get("agent") or {}
    if isinstance(agent, dict):
        return str(agent.get("name") or agent.get("id") or "")
    return str(agent or "")


_PROFILE_RE = re.compile(r'profile="([^"]+)"')


def _profile_key(profile: str) -> str:
    """Normalise an AppArmor profile for comparison.

    Real profiles arrive as FULL PATHS (`/snap/snapd/27710/usr/lib/snapd/
    snap-confine`), while an adjudication records the plain name. Comparing the
    raw strings would make every real alert look out-of-scope and override the
    tuning — a flood, not a fix. `hunt_tools._analyze_apparmor` matches on
    basename for exactly this reason; do the same on BOTH sides so an allowlist
    entry may be written either way.
    """
    import posixpath
    text = str(profile or "").strip()
    if not text:
        return ""
    return posixpath.basename(text.rstrip("/")) or text


def _alert_apparmor_profile(alert: dict) -> str:
    """The AppArmor profile an alert fired on, best-effort ("" if unreadable).

    The profile is NOT a structured field in this pipeline: the Wazuh apparmor
    decoder leaves it inside `full_log` as `profile="..."`, which is exactly how
    `hunt_tools._analyze_apparmor` reads it. Reuse that convention rather than
    inventing a field path that never appears in real alerts. `data.apparmor`
    is also checked, so an upstream that DOES populate it still works.
    """
    log = str(alert.get("full_log") or "")
    if log:
        m = _PROFILE_RE.search(log)
        if m:
            return m.group(1)
    data = alert.get("data")
    ap = data.get("apparmor") if isinstance(data, dict) else None
    if isinstance(ap, dict):
        return str(ap.get("profile") or "")
    if isinstance(ap, str):
        return ap
    return ""


# --- propose / commit authority (ADR-008) ----------------------------------
#
# A tuning entry is a durable suppression: `router.classify` returns no role for
# a tuned rule BEFORE its heuristics run, and the analyst honours the same
# ledger. ADR-008 draws the boundary — an interactive, user-directed session may
# COMMIT; an unattended scheduled process may only PROPOSE; blank attribution
# fails closed.
#
# WHAT THIS IS NOT: not a cryptographic boundary. The unattended writer
# (`ssop-supervisory.service`, hourly) runs as the same OS user as everything
# else on that host, so any key it was asked to respect it could also read.
# Making the boundary real means a dedicated service user, or a signing key held
# off-host. Until then, describe this as a code-level boundary with a fail-closed
# default — auditable in the diff, not unforgeable.
PROPOSED = "proposed"
COMMITTED = "committed"
# Decisions that SUPPRESS alerting, as ONE constant on purpose: the router used
# to accept `escalate` while the analyst did not, so the same entry meant
# different things on the two paths (measured 2026-09-15).
SUPPRESSING_DECISIONS = ("auto_fp", "operational", "escalate")


def tuning_state(tuning: dict | None) -> str:
    """The entry's state, failing CLOSED.

    Missing or unrecognized state reads as PROPOSED. After the 2026-09-15
    migration every legitimate entry carries a state, so an absent one is either
    a fresh unattended write or an un-migrated oddity — neither should suppress.
    """
    state = str((tuning or {}).get("state") or "").strip().lower()
    return state if state in (PROPOSED, COMMITTED) else PROPOSED


def suppression_allowed(tuning: dict | None) -> tuple[bool, str]:
    """May this entry suppress? (suppressing decision AND committed.)

    Returns (allowed, reason). Called by the shared decision helper AND by the
    hunt sweep: the hunt used to do its own existence check, so a gate added
    only to `tuned_rule_suppresses` would have left every hunt silenceable by an
    uncommitted entry — a hole in the boundary on day one.
    """
    if not isinstance(tuning, dict) or not tuning:
        return False, "no tuning entry"
    decision = str(tuning.get("decision") or "")
    if decision not in SUPPRESSING_DECISIONS:
        return False, f"decision {decision!r} does not suppress"
    state = tuning_state(tuning)
    if state != COMMITTED:
        return False, (
            f"rule {tuning.get('rule_id')} carries a {state} tuning entry "
            f"({decision}, proposed_by={tuning.get('tuned_by') or 'unknown'}) — "
            f"a proposal never suppresses; it needs a human commit (console "
            f"confirm, or a case adjudication)")
    return True, f"committed {decision}"


def tuned_rule_suppresses(tuning: dict, alert: dict, category: str | None = None) -> tuple[bool, str]:
    """Decide whether a tuned rule should suppress THIS alert (verdict note /
    no dispatch), or lift the tuning (override -> re-adjudication).

    HOST-SCOPED EXCEPTION (option-C support): a tuning entry may carry
    `exclude_hosts` — agent names the human explicitly wants to KEEP
    dispatching on despite the tuned-FP decision (e.g. package-change
    rules auto_fp fleet-wide EXCEPT on the secrets host, where package
    drift is high-stakes). An alert from an excluded host NEVER suppresses:
    it dispatches normally, so the analyst still reviews it there.

    Fingerprint-aware (thread #2): if the tuning entry carries the
    decision-relevant fingerprint of the alert the human originally tuned,
    we compare — identical signature suppresses; only a MATERIAL delta
    (new attack groups, category became attack-class, threat-desc token
    appeared, level rose) lifts the tuning. Legacy entries WITHOUT a stored
    fingerprint fall back to the config-gated strong_tp_evidence heuristic,
    so old tuning entries keep working.

    Returns (suppress, reason). suppress=True -> note/no-dispatch with the
    reason (for the rationale). suppress=False -> the alert should override
    the tuning (escalate with tuning_override for re-adjudication).
    """
    # Host-scoped exception: excluded hosts are never suppressed by the
    # tuning — the human wants those surfaces reviewed regardless.
    # AUTHORITY FIRST (ADR-008): an entry that was never committed cannot
    # suppress, whatever its fingerprint or scope says. Placed before every
    # other check so no later branch can accidentally honour a proposal.
    _allowed, _why_not = suppression_allowed(tuning)
    if not _allowed:
        return False, _why_not
    host = _alert_host(alert)
    excluded = tuning.get("exclude_hosts") if isinstance(tuning, dict) else None
    if excluded and host and host in {str(h) for h in excluded}:
        return False, (
            f"rule {tuning.get('rule_id')} tuned {tuning.get('decision')} "
            f"({tuning.get('source')}) BUT host {host} is excluded from the "
            f"tuning (exclude_hosts) — dispatching for review")
    stored_fp = tuning.get("fingerprint") if isinstance(tuning, dict) else None
    # PROFILE-SCOPED tuning (ADR-008 narrowing, 2026-09-15): when the entry's
    # fingerprint names the AppArmor PROFILES the adjudication actually covered,
    # a denial on a DIFFERENT profile is outside the adjudicated scope and must
    # dispatch. This exists because a rule-wide auto_fp on an apparmor rule
    # silences the whole channel — measured: a level-12 denial on a profile the
    # human never saw suppressed silently, and AppArmor denials are how a
    # container escape or privilege escalation surfaces.
    #
    # An alert whose profile cannot be read is NOT treated as out-of-scope: the
    # same decoder withholds full_log on some variants, and overriding there
    # would flood the analyst with the very noise class the human adjudicated.
    # Such an alert falls through to the ordinary machinery (fingerprint delta /
    # strong-TP gate), which is the pre-existing behaviour.
    allowed = stored_fp.get("profiles") if isinstance(stored_fp, dict) else None
    if allowed:
        profile = _alert_apparmor_profile(alert)
        allowed_keys = {_profile_key(p) for p in allowed}
        if profile and _profile_key(profile) not in allowed_keys:
            return False, (
                f"rule {tuning.get('rule_id')} tuned {tuning.get('decision')} "
                f"({tuning.get('source')}) for profiles "
                f"[{', '.join(sorted(str(p) for p in allowed))}] BUT this alert "
                f"fired on profile '{profile}' — outside the adjudicated scope, "
                f"dispatching for review")
    if isinstance(stored_fp, dict) and stored_fp.get("rule_id"):
        # Fingerprint-aware path.
        from tools.ontology import fingerprint_from_alert, fingerprint_materially_differs
        cur = fingerprint_from_alert(alert)
        if fingerprint_materially_differs(stored_fp, cur):
            return False, (
                f"rule {cur.get('rule_id')} tuned {tuning.get('decision')} "
                f"({tuning.get('source')}): {tuning.get('rationale','')} BUT alert "
                f"fingerprint differs from the tuned signature — override for "
                f"human re-adjudication")
        return True, (
            f"rule {cur.get('rule_id')} tuned {tuning.get('decision')} "
            f"({tuning.get('source')}): {tuning.get('rationale','')} — matches the "
            f"tuned alert fingerprint, no escalation")
    # Legacy path: no stored fingerprint -> config-gated strong-TP heuristic.
    if strong_tp_evidence(alert, category=category):
        return False, "strong true-positive evidence (threat-desc/high severity) on tuned rule — override"
    rid = str((alert.get("rule") or {}).get("id", ""))
    return True, (
        f"rule {rid} tuned {tuning.get('decision')} "
        f"({tuning.get('source')}): {tuning.get('rationale','')} — noted, no escalation")


class TuningError(RuntimeError):
    """Raised when the tuning ledger is unreachable or a write fails."""


class TuningLedger:
    """Qdrant-backed key-value ledger: rule_id -> {decision, rationale, source}.

    Point id is a stable uuid5 of the rule_id, so re-writing the same rule
    upserts (no duplicates). Payload carries the decision + provenance.
    """

    def __init__(self, memory: QdrantMemory | None = None) -> None:
        self._memory = memory or QdrantMemory()
        try:
            self._memory.ensure_collection(TUNING_COLLECTION)
        except Exception as e:
            logger.error("tuning collection ensure failed: %s", e)
            raise TuningError(f"tuning collection ensure failed: {e}") from e

    @staticmethod
    def _point_id(rule_id: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tuning:{rule_id}"))

    def lookup(self, rule_id: str) -> dict[str, Any] | None:
        """Return the tuning entry for a rule_id, or None if untuned."""
        try:
            pid = self._point_id(rule_id)
            res = self._memory.client.retrieve(
                collection_name=TUNING_COLLECTION, ids=[pid], with_payload=True
            )
            if not res:
                return None
            return res[0].payload
        except Exception as e:  # noqa: BLE001 — lookup must never break triage
            logger.warning("tuning lookup failed for %s: %s", rule_id, e)
            return None

    def all_rules(self) -> list[str]:
        """Return every rule_id in the ledger (for backfill/audit)."""
        try:
            records = self._memory.client.scroll(
                collection_name=TUNING_COLLECTION, limit=1000,
                with_payload=True, with_vectors=False,
            )[0]
            return sorted({str((r.payload or {}).get("rule_id", ""))
                           for r in records if (r.payload or {}).get("rule_id")})
        except Exception as e:  # noqa: BLE001 — enumeration must never crash
            logger.warning("tuning all_rules failed: %s", e)
            return []

    def write(
        self,
        rule_id: str,
        decision: str,
        rationale: str,
        source: str = "analyst_seed",
        ts: str | None = None,
        tuned_by: str = "",
        fingerprint: dict | None = None,
        exclude_hosts: list | None = None,
        state: str = PROPOSED,
    ) -> bool:
        """Upsert a tuning entry. Human writes are final; analyst seeds mark source.

        `tuned_by` names the actor (e.g. "admin" / "supervisory@hermes") so the
        managed-tuning surface shows WHO decided, not just the decision. This is
        the adopted SO 'detection tuning as a managed action' concept — the
        ledger gains history/attribution (Concept 4 of the two-example doctrine).

        `fingerprint` (thread #2) is the DECISION-RELEVANT signature of the
        alert that was tuned (rule_id/groups/level/category/threat-desc) — the
        ledger records WHAT the human actually decided on, so identical future
        alerts suppress and only a material delta overrides (see
        tuned_rule_suppresses). Legacy entries without one fall back to the
        strong-TP heuristic.
        """
        if decision not in FINAL_DECISIONS:
            raise TuningError(f"invalid decision {decision!r}; expected one of {sorted(FINAL_DECISIONS)}")
        try:
            pid = self._point_id(rule_id)
            # FAIL CLOSED on state: an unrecognized value becomes PROPOSED, so a
            # typo or a future state name cannot silently grant suppression.
            _state = state if state in (PROPOSED, COMMITTED) else PROPOSED
            payload: dict[str, Any] = {
                "rule_id": rule_id,
                "decision": decision,
                "rationale": rationale,
                "source": source,  # human | analyst_seed
                "tuned_by": tuned_by,  # actor name ("" = system/seed)
                "state": _state,  # proposed | committed (ADR-008)
                "ts": ts or datetime.now(timezone.utc).isoformat(),
                "type": "tuning",
            }
            if fingerprint:
                payload["fingerprint"] = fingerprint
            if exclude_hosts:
                # Host-scoped policy (option-C): excluded hosts never suppress.
                payload["exclude_hosts"] = [str(h) for h in exclude_hosts]
            self._memory.client.upsert(
                collection_name=TUNING_COLLECTION,
                points=[PointStruct(
                    id=pid,
                    vector=[0.0] * 384,
                    payload=payload,
                )],
            )
            logger.info("tuning write: rule %s -> %s (%s) by %s", rule_id, decision, source, tuned_by or "system")
            return True
        except Exception as e:
            logger.exception("tuning write failed for %s", rule_id)
            raise TuningError(f"tuning write failed for {rule_id}: {e}") from e

    def propose(self, rule_id: str, decision: str, rationale: str, *,
                proposed_by: str = "", **kw: Any) -> bool:
        """Record an UNATTENDED proposal — visible, attributable, inert.

        This is what the autonomous adjudicator calls
        (`ssop-supervisory.service` -> `supervisory.py supervisory:adjudicate`,
        hourly). The proposal is written to the same ledger the human surface
        reads, so confirming it is one action there, not a re-derivation.

        `proposed_by` should name the writer. Blank is accepted (old callers) but
        it is exactly the case ADR-008 makes fail CLOSED for: the unattended hunt
        entry was written with an empty `tuned_by` and was otherwise
        indistinguishable from a hand-written console entry.
        """
        return self.write(rule_id, decision, rationale, source="automation",
                          tuned_by=proposed_by, state=PROPOSED, **kw)

    def commit(self, rule_id: str, decision: str, rationale: str, *,
               committed_by: str, **kw: Any) -> bool:
        """Commit a tuning entry for an INTERACTIVE, user-directed session.

        The actor is REQUIRED: a commit with no actor is a proposal wearing a
        different name, and the whole point of this boundary is that the
        distinction is recorded rather than inferred.
        """
        if not str(committed_by or "").strip():
            raise TuningError(
                "commit() requires committed_by — an unattributed commit is a "
                "proposal wearing a different name")
        return self.write(rule_id, decision, rationale, source="human",
                          tuned_by=committed_by, state=COMMITTED, **kw)

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent tuning entries (for dashboards/supervisory review)."""
        try:
            res = self._memory.client.scroll(
                collection_name=TUNING_COLLECTION, limit=limit, with_payload=True
            )
            return [p.payload for p in res[0]]
        except Exception as e:  # noqa: BLE001
            logger.warning("tuning scroll failed: %s", e)
            return []
