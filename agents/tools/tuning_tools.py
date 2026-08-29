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

from tools.qdrant_tools import QdrantMemory

logger = logging.getLogger(__name__)

TUNING_COLLECTION = "tuning"

# Decisions that make a rule "already handled" — analyst must not re-escalate.
FINAL_DECISIONS = {"auto_fp", "operational", "escalate"}


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
