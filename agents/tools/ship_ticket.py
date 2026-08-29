#!/usr/bin/env python3
"""Direct ticket shipping to the index — the reliable human-dashboard path.

The OTel filelog one-shot-file behavior is unreliable (start_at semantics
skip files created before watch). Instead, the escalation path writes each
ticket directly to ssop-events via the indexer's bulk API — deterministic,
immediate, and independent of the collector's file watching.

Usage (on infra-ops): python3 ship_ticket.py <ticket.json>
"""

from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import logging

from config import settings

logger = logging.getLogger(__name__)


def ship_ticket_doc(ticket: dict) -> bool:
    """Index a ticket DICT into ssop-events (the reliable human-dashboard path).

    Best-effort: callers (escalation) must never block on this. Adds
    ssop.source=tickets + @timestamp so the dashboard can filter.
    """
    doc = dict(ticket)
    doc.setdefault("ts", datetime.now(timezone.utc).isoformat())
    doc["ssop.source"] = "tickets"
    doc["@timestamp"] = doc.get("ts")

    # Mapping-safe rename: the ssop-events index has `severity` mapped as an
    # object (from an older doc shape), so a concrete string here is rejected
    # (mapper_parsing_exception). Namespace our severity string to
    # alert_severity on ship; the ticket file keeps its internal name.
    if isinstance(doc.get("severity"), str):
        doc["alert_severity"] = doc.pop("severity")

    url = settings.indexer_url or f"https://{settings.indexer_host}:{settings.indexer_port}"
    # Explicit host override wins over the URL host (the URL may be a
    # docker-internal name unreachable from infra-ops).
    if settings.indexer_host and settings.indexer_host != "localhost":
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        url = f"{scheme}://{settings.indexer_host}:{parsed.port or settings.indexer_port}"
    auth = "Basic " + base64.b64encode(
        f"{settings.indexer_user}:{settings.indexer_password}".encode()
    ).decode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    body = json.dumps({"index": {"_index": "ssop-events"}}) + "\n" + json.dumps(doc) + "\n"
    req = urllib.request.Request(
        url.rstrip("/") + "/_bulk",
        data=body.encode(),
        headers={"Authorization": auth, "Content-Type": "application/x-ndjson"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            result = json.loads(resp.read().decode())
        if result.get("errors"):
            logger.warning("bulk errors shipping ticket %s", doc.get("ticket_id"))
            return False
        return True
    except Exception as e:  # noqa: BLE001
        logger.warning("ticket ship failed: %s", e)
        return False


def ship(ticket_path: str) -> bool:
    """Index a ticket file into ssop-events (adds ssop.source=tickets)."""
    ticket = json.loads(Path(ticket_path).read_text())
    ticket.setdefault("ts", datetime.now(timezone.utc).isoformat())
    ticket["ssop.source"] = "tickets"
    ticket["@timestamp"] = ticket.get("ts")

    url = settings.indexer_url or f"https://{settings.indexer_host}:{settings.indexer_port}"
    # Explicit host override wins over the URL host (the URL may be a
    # docker-internal name unreachable from infra-ops).
    if settings.indexer_host and settings.indexer_host != "localhost":
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        url = f"{scheme}://{settings.indexer_host}:{parsed.port or settings.indexer_port}"
    auth = "Basic " + base64.b64encode(
        f"{settings.indexer_user}:{settings.indexer_password}".encode()
    ).decode()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    body = json.dumps({"index": {"_index": "ssop-events"}}) + "\n" + json.dumps(ticket) + "\n"
    req = urllib.request.Request(
        url.rstrip("/") + "/_bulk",
        data=body.encode(),
        headers={"Authorization": auth, "Content-Type": "application/x-ndjson"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
            result = json.loads(resp.read().decode())
        if result.get("errors"):
            print("bulk errors:", json.dumps(result.get("items", [{}])[0])[:200])
            return False
        print(f"shipped ticket {ticket.get('ticket_id')} to ssop-events")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"ship failed: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: ship_ticket.py <ticket.json>")
        sys.exit(1)
    sys.exit(0 if ship(sys.argv[1]) else 1)
