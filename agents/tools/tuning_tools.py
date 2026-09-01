"""Tuning ledger — durable, human-confirmed decisions about alert classes.

The stateful analyst decision loop consults this BEFORE the heuristic: has
this rule_id been adjudicated (auto-fp / operational / escalate)? Human
decisions (supervisory adjudication) are the source of truth; analyst
verdicts only SEED entries and never finalize them.

Hygiene: config-driven, imports at top, logging, structured errors.
"""

from __future__ import annotations

import logging
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

    def write(
        self,
        rule_id: str,
        decision: str,
        rationale: str,
        source: str = "analyst_seed",
        ts: str | None = None,
        tuned_by: str = "",
    ) -> bool:
        """Upsert a tuning entry. Human writes are final; analyst seeds mark source.

        `tuned_by` names the actor (e.g. "admin" / "supervisory@hermes") so the
        managed-tuning surface shows WHO decided, not just the decision. This is
        the adopted SO 'detection tuning as a managed action' concept — the
        ledger gains history/attribution (Concept 4 of the two-example doctrine).
        """
        if decision not in FINAL_DECISIONS:
            raise TuningError(f"invalid decision {decision!r}; expected one of {sorted(FINAL_DECISIONS)}")
        try:
            pid = self._point_id(rule_id)
            self._memory.client.upsert(
                collection_name=TUNING_COLLECTION,
                points=[PointStruct(
                    id=pid,
                    vector=[0.0] * 384,
                    payload={
                        "rule_id": rule_id,
                        "decision": decision,
                        "rationale": rationale,
                        "source": source,  # human | analyst_seed
                        "tuned_by": tuned_by,  # actor name ("" = system/seed)
                        "ts": ts or datetime.now(timezone.utc).isoformat(),
                        "type": "tuning",
                    },
                )],
            )
            logger.info("tuning write: rule %s -> %s (%s) by %s", rule_id, decision, source, tuned_by or "system")
            return True
        except Exception as e:
            logger.exception("tuning write failed for %s", rule_id)
            raise TuningError(f"tuning write failed for {rule_id}: {e}") from e

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
