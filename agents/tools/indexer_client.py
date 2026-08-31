"""Indexer transport — the SIEM-agnostic query surface.

The agents query alerts through this interface; the concrete transport
(OpenSearch/Wazuh today, Elastic/Security Onion tomorrow) is selected by
transport.yaml. Field names come from the transport config, never hardcoded.

Per the transport-agnostic spec (docs/TRANSPORT_AGNOSTIC.md): the decision
spine is transport-agnostic; this is the query seam.
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import Any

import yaml

from config import settings

logger = logging.getLogger(__name__)

# transport.yaml lives next to the config module (agents/ dir)
_AGENTS_DIR = settings.hunts_dir.parent  # hunts/ is under agents/
TRANSPORT_FILE = _AGENTS_DIR / "transport.yaml"


class IndexerError(RuntimeError):
    """Raised when the indexer is unreachable or rejects a query."""


def _load_transport() -> dict[str, Any]:
    """Load transport.yaml (backend + field ontology + rule map)."""
    path = TRANSPORT_FILE
    if path and path.exists():
        try:
            return yaml.safe_load(path.read_text())
        except (yaml.YAMLError, OSError) as e:
            logger.warning("transport.yaml unreadable (%s) — using defaults", e)
    return {}


def _so_severity_to_level(sev: Any) -> int:
    """Map SO event.severity (1–4) to the Wazuh rule.level scale (0–15).

    Wazuh's analyst thresholds: medium_level=4, high_level=7. SO severities
    are 1 (informational/low) .. 4 (critical). Map so the spine's level
    heuristics behave sensibly on SO alerts: 1->3 (low), 2->6 (medium),
    3->9 (high), 4->12 (critical). Accepts str/int.
    """
    try:
        s = int(sev)
    except (TypeError, ValueError):
        return 1
    return {1: 3, 2: 6, 3: 9, 4: 12}.get(s, 3 if s <= 2 else 9)


class IndexerTransport:
    """Transport interface: search/count/recent_alerts over any backend."""

    def __init__(self) -> None:
        self.transport_cfg = _load_transport()
        self.backend = self.transport_cfg.get("backend", "wazuh")
        fields = self.transport_cfg.get("fields", {})
        b = self.transport_cfg.get("backends", {}).get(self.backend, {})
        # Per-backend field overrides win; global fields are the fallback.
        bfields = {**fields, **(b.get("fields") or {})}
        self.field_timestamp = bfields.get("timestamp", "@timestamp")
        self.field_level = bfields.get("level", "rule.level")
        self.field_groups = bfields.get("groups", "rule.groups")
        self.field_category = bfields.get("category", "category")
        self.alerts_index = b.get("alerts_index", settings.alerts_index)
        self.inventory_index = b.get("inventory_index", settings.inventory_index)

        # Endpoint resolution: backend endpoint > config URL > host/port.
        url = b.get("endpoint") or settings.indexer_url
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            url_host = parsed.hostname or ""
            # If the URL host is a real IP (e.g. 192.168.1.76), use it — it's
            # directly reachable. If it's a service name (e.g. wazuh.indexer,
            # a docker-internal name), the settings host override wins (the
            # reachable LAN IP from infra-ops).
            is_ip = url_host.replace(".", "").isdigit()
            if is_ip:
                self.host = url_host
            else:
                self.host = settings.indexer_host if settings.indexer_host != "localhost" else url_host
            self.port = str(parsed.port or settings.indexer_port)
            self.scheme = parsed.scheme or "https"
        else:
            self.host = settings.indexer_host
            self.port = settings.indexer_port
            self.scheme = "https"
        # Per-backend creds (transport.yaml) win; .env is the fallback.
        # The securityonion password lives in .env (SO_INDEXER_PASSWORD) —
        # never in the committed transport.yaml.
        self.user = b.get("user") or settings.indexer_user
        if b.get("password"):
            self.passwd = b["password"]
        elif self.backend == "securityonion" and settings.so_indexer_password:
            self.passwd = settings.so_indexer_password
        else:
            self.passwd = settings.indexer_password
        self._ctx = self._make_ctx()

    @staticmethod
    def _make_ctx() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _auth(self) -> str:
        return "Basic " + base64.b64encode(f"{self.user}:{self.passwd}".encode()).decode()

    def _url(self, path: str, index: str) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/{index}/{path}"

    def _normalize(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Normalize a backend result into the ontology shape.

        The spine expects Wazuh-shaped alerts (rule.id/level/groups/
        description, top-level srcip/dstip). Two SO shapes exist:
          - Elastic Security `signal.rule.*` (detection-engine schema);
          - native ECS alerts (`.ds-logs-suricata.alerts-so-*` /
            `.ds-logs-detections.alerts-so-*`): rule is a dict
            {name, uuid, category, ...}, level lives in event.severity,
            groups in tags, the entity pair in source.ip/destination.ip.
        The transport adapter's job is parity of the ontology across both.
        """
        if self.backend != "securityonion":
            return doc
        src = dict(doc)
        # Case 1: Elastic Security signal.* wrapper (existing behaviour)
        sig = src.get("signal")
        if isinstance(sig, dict):
            # Flatten signal.rule.* -> rule.* (don't clobber an existing rule)
            if "rule" not in src and isinstance(sig.get("rule"), dict):
                src["rule"] = sig["rule"]
            # Also surface signal-level fields the spine may use
            for k in ("id", "status", "risk_score"):
                if k in sig and k not in src:
                    src[k] = sig[k]
            # Drop the nested signal wrapper to avoid confusion
            src.pop("signal", None)
            return src
        # Case 2: native ECS alert shape (suricata/detections alerts-so)
        rule = src.get("rule")
        if isinstance(rule, dict) and (rule.get("uuid") or rule.get("name")):
            sev = (src.get("event") or {}).get("severity")
            level = _so_severity_to_level(sev)
            groups = list(src.get("tags") or [])
            if not groups:
                cat = rule.get("category")
                if cat:
                    groups = [str(cat)]
            mapped: dict[str, Any] = {
                "id": str(rule.get("uuid") or rule.get("gid") or ""),
                "level": level,
                "groups": groups,
                "description": rule.get("name") or rule.get("description") or "",
                "category": rule.get("category") or "",
            }
            if rule.get("id"):
                mapped["id"] = str(rule["id"])
            src["rule"] = mapped
            # Entity pair: ECS source.ip / destination.ip -> top-level srcip/dstip
            srcip = (src.get("source") or {}).get("ip")
            dstip = (src.get("destination") or {}).get("ip")
            if srcip:
                src["srcip"] = srcip
            if dstip:
                src["dstip"] = dstip
        return src

    def search(self, body: dict[str, Any], index: str | None = None) -> dict[str, Any]:
        """Run a search against the backend (default: configured alerts index)."""
        target = index or self.alerts_index
        req = urllib.request.Request(
            self._url("_search", target),
            data=json.dumps(body).encode(),
            headers={"Authorization": self._auth(), "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=self._ctx) as resp:
                result = json.loads(resp.read().decode())
            # Normalize hits into the ontology shape (backend-agnostic spine)
            for h in result.get("hits", {}).get("hits", []):
                if "_source" in h:
                    h["_source"] = self._normalize(h["_source"])
            return result
        except urllib.error.HTTPError as e:
            logger.warning("indexer HTTP %s on %s", e.code, target)
            raise IndexerError(f"indexer HTTP {e.code} on {target}") from e
        except urllib.error.URLError as e:
            logger.warning("indexer unreachable (%s)", e.reason)
            raise IndexerError(f"indexer unreachable: {e.reason}") from e

    def count(self, query: dict[str, Any], index: str | None = None) -> int:
        """Fast count for a query (used for surveys/verification)."""
        target = index or self.alerts_index
        req = urllib.request.Request(
            self._url("_count", target),
            data=json.dumps(query).encode(),
            headers={"Authorization": self._auth(), "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=self._ctx) as resp:
                return int(json.loads(resp.read().decode()).get("count", 0))
        except urllib.error.HTTPError as e:
            raise IndexerError(f"count HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise IndexerError(f"indexer unreachable: {e.reason}") from e

    def recent_alerts(self, limit: int = 10, min_level: int = 0, index: str | None = None) -> list[dict[str, Any]]:
        """Fetch recent alerts, newest first, optionally filtered by level.

        `index` overrides the configured alerts_index (e.g. target specific
        BOTS slices).
        """
        body: dict[str, Any] = {"size": limit, "sort": [{self.field_timestamp: {"order": "desc"}}]}
        if min_level:
            body["query"] = {"bool": {"filter": [{"range": {self.field_level: {"gte": min_level}}}]}}
        else:
            body["query"] = {"match_all": {}}
        result = self.search(body, index=index or self.alerts_index)
        return [h.get("_source", {}) for h in result.get("hits", {}).get("hits", [])]


# Backwards-compatible alias: everything that imported IndexerClient keeps working.
IndexerClient = IndexerTransport
