"""Escalation tool module for infra-agent (sysadmin role).

When the agent encounters an action outside its authority (Tier 1/2),
it emits a structured escalation ticket: symptom, diagnosis, what was
attempted, what's blocked, and the pre-staged command a human (or
supervisory agent) could approve in seconds.

Delivery: POST to the Hermes API (which reaches the supervisory human).
Fallback: write to a local tickets/ queue so nothing is ever lost.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


class EscalationError(RuntimeError):
    """Raised when a ticket cannot be queued (durability failure)."""


class EscalationClient:
    """Structured escalation tickets routed to the supervisory layer."""

    def __init__(self) -> None:
        self.api_url = settings.hermes_api_url
        self.api_key = settings.hermes_api_key
        self.model = settings.hermes_model
        self.queue_dir: Path = settings.escalation_dir
        self.timeout = settings.escalation_timeout_s
        self.queue_dir.mkdir(parents=True, exist_ok=True)

    def _ticket(self, tier: int, title: str, detail: dict[str, Any], actor: str = "infra-agent") -> dict[str, Any]:
        """Assemble a structured escalation ticket.

        `actor` is WHO decided to escalate (role + runtime identity), not the
        alert's source agent. Callers pass role, e.g. "analyst"; the source
        agent rides in `detail` (agent=network) so attribution is honest.
        """
        return {
            "ticket_id": str(uuid.uuid4())[:8],
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "tier": tier,
            "title": title,
            **detail,
            "status": "open",
        }

    def _queue(self, ticket: dict[str, Any]) -> str:
        """Persist ticket to local queue (always, as durable fallback)."""
        path = self.queue_dir / f"{ticket['ticket_id']}.json"
        try:
            path.write_text(json.dumps(ticket, indent=2))
        except OSError as e:
            logger.exception("failed to write ticket %s", ticket["ticket_id"])
            raise EscalationError(f"cannot queue ticket: {e}") from e
        return str(path)

    def _deliver(self, ticket: dict[str, Any]) -> dict[str, Any]:
        """POST ticket to Hermes API (supervisory agent). Returns response."""
        if not self.api_key:
            logger.warning("HERMES_API_KEY not set — ticket queued only")
            return {"delivered": False, "reason": "HERMES_API_KEY not set"}
        prompt = (
            f"[ESCALATION tier={ticket['tier']}] {ticket['title']}\n"
            f"{json.dumps(ticket, indent=2)}\n"
            f"Approve, deny, or ask for more info."
        )
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            f"{self.api_url}/v1/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
                return {
                    "delivered": True,
                    "response": payload["choices"][0]["message"]["content"],
                }
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            logger.warning("escalation delivery failed for %s: %s", ticket["ticket_id"], e)
            return {"delivered": False, "reason": str(e)}
        except (KeyError, json.JSONDecodeError) as e:
            logger.warning("escalation response malformed for %s: %s", ticket["ticket_id"], e)
            return {"delivered": False, "reason": f"malformed response: {e}"}

    def list_tickets(self, status: str | None = None) -> list[dict]:
        """Read all escalation tickets from the queue, optionally filtered."""
        out = []
        if not self.queue_dir.exists():
            return out
        for f in sorted(self.queue_dir.glob("*.json")):
            try:
                with open(f, encoding="utf-8") as fh:
                    d = json.load(fh)
                if status and d.get("status") != status:
                    continue
                out.append(d)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("skipping unreadable ticket %s: %s", f, e)
        return out

    def escalate(self, tier: int, title: str, detail: dict[str, Any], actor: str = "infra-agent") -> dict[str, Any]:
        """Create + queue + deliver an escalation ticket.

        Queue is always written (durable). Delivery is attempted with a
        bounded timeout so the analyst loop never blocks on the supervisor.
        `actor` names who decided (role); the alert's source agent belongs in
        `detail["agent"]`.
        """
        ticket = self._ticket(tier, title, detail, actor=actor)
        path = self._queue(ticket)
        delivery = {"delivered": False, "reason": "queued (async delivery)"}
        if self.api_key:
            # Fire-and-forget delivery: a daemon thread posts to the supervisor.
            # The analyst loop NEVER blocks on the supervisory turn.
            try:
                t = threading.Thread(target=self._deliver, args=(ticket,), daemon=True)
                t.start()
            except (RuntimeError, OSError) as e:
                logger.warning("delivery thread failed for %s: %s", ticket["ticket_id"], e)
                delivery = {"delivered": False, "reason": f"delivery deferred: {e}"}
        # Ship to the index (human dashboard visibility) — best-effort, never
        # blocks the queue. Independent of the OTel filelog (which skips
        # one-shot files); direct bulk index is the reliable path.
        try:
            from tools.ship_ticket import ship_ticket_doc
            ship_ticket_doc(ticket)
        except Exception as e:  # noqa: BLE001 — shipping must never break escalation
            logger.warning("ticket index-ship failed for %s: %s", ticket["ticket_id"], e)
        logger.info("escalated tier=%s %s -> %s", tier, ticket["ticket_id"], path)
        return {
            "ticket_id": ticket["ticket_id"],
            "queued_at": path,
            "delivery": delivery,
        }
