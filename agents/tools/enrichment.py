"""Observable enrichment — threat-intel verdicts on case observables.

Adopted concept (Security Onion -> ontology): SO runs ANALYZERS on case
observables (VirusTotal, GreyNoise, ThreatFox, OTX, ...) to gather context
around an IOC. We generalize that into a backend-agnostic primitive:
`enrich_observable()` takes one observable, calls a threat-intel provider,
and returns a verdict dict stored on the case payload.

PORTABILITY: enrichment knows nothing about Wazuh or SO — it consumes an
observable {type, value} and the provider config from config.py. It is
identical against either backend. This is Concept 2 of the two-example
doctrine (see wayfinder ticket so-integration-human-experience.md).

OPSEC note: providers are external by nature. The default path uses
GreyNoise's community endpoint (keyless, one lookup per IP) — free-tier and
low-noise. A `GREYNOISE_KEY` env var upgrades it. Failures degrade to a
cached "unknown" verdict — enrichment must NEVER block case creation.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)


class EnrichmentError(RuntimeError):
    """Raised when enrichment fails in a non-degradable way."""


def _cached_verdict(observable: dict[str, str], provider: str) -> dict[str, Any]:
    """Degradable failure verdict — enrichment never blocks the case."""
    return {
        "observable": observable,
        "provider": provider,
        "status": "unknown",  # lookup failed / degraded
        "ts": datetime.now(timezone.utc).isoformat(),
    }


class EnrichmentClient:
    """Threat-intel enrichment for observables (registry of providers)."""

    def __init__(self, cache: dict[str, dict[str, Any]] | None = None) -> None:
        self.timeout = settings.enrichment_timeout_s
        self.greynoise_url = settings.greynoise_url
        self.greynoise_key = settings.greynoise_key
        self.vt_key = settings.vt_api_key
        self.vt_url = settings.vt_url
        self.vt_submit = settings.vt_submit_enabled
        self._cache: dict[str, dict[str, Any]] = cache or {}  # key: type|value
        # VT quota: 4 req/min + 500 req/day (free public API — one shared
        # bucket across ALL request types, lookups and submissions alike).
        # Client-level throttle so hunt sweeps + analyst enrichment draw
        # from ONE budget regardless of calling role.
        self._vt_min_window: list[float] = []  # timestamps of recent calls
        self._vt_day: str = ""
        self._vt_day_count: int = 0

    # --- provider registry ---

    def _providers_for(self, observable: dict[str, str]) -> list[str]:
        """Which providers apply to this observable type (extensible).

        VIRUSTOTAL requires an API key (VT_API_KEY); without one it is
        skipped (the provider list stays empty for non-IP types — degrade,
        never fail). Registered in the egress registry (config.egress +
        transport.yaml external_calls): external calls are a DECLARED
        property, enforced by agents/verify/check_egress.py.
        """
        otype = observable.get("type", "")
        if otype == "ip":
            return ["greynoise"]
        if otype in ("hash", "domain", "url") and self.vt_key:
            return ["virustotal"]
        # remaining types: no keyless provider enabled yet — extend here.
        return []

    # --- GreyNoise community (keyless) ---

    def _greynoise_lookup(self, ip: str) -> dict[str, Any]:
        """GreyNoise community lookup — keyless, rate-limited, single IP.

        Returns a verdict with classification (benign/malicious/unknown) and
        raw noise info when available.
        """
        url = self.greynoise_url.rstrip("/") + "/" + ip
        headers = {}
        if self.greynoise_key:
            headers["key"] = self.greynoise_key
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            # 404 = IP not seen by GreyNoise (clean/unknown) — that's data, not error
            if e.code == 404:
                return {"provider": "greynoise", "status": "unknown",
                        "classification": "unknown", "raw": {"seen": False}}
            logger.warning("greynoise HTTP %s for %s: %s", e.code, ip, e)
            return _cached_verdict({"type": "ip", "value": ip}, "greynoise")
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.warning("greynoise lookup failed for %s: %s", ip, e)
            return _cached_verdict({"type": "ip", "value": ip}, "greynoise")
        classification = data.get("classification", "unknown")
        status = {
            "benign": "benign",
            "malicious": "malicious",
            "unknown": "unknown",
            "": "unknown",
        }.get(classification, "unknown")
        return {
            "provider": "greynoise",
            "status": status,
            "classification": classification,
            "raw": data,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    # --- VirusTotal (egress-registered, lookup-class) ---

    def _vt_throttle(self) -> str:
        """Client-level VT quota: 4 req/min + 500 req/day. Returns "" when a
        request may proceed, else a skip reason (never raises)."""
        import time as _time
        now = _time.time()
        self._vt_min_window = [t for t in self._vt_min_window if now - t < 60]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._vt_day != today:
            self._vt_day, self._vt_day_count = today, 0
        if len(self._vt_min_window) >= 4:
            return "vt rate limit (4/min) — skipping"
        if self._vt_day_count >= 500:
            return "vt daily cap (500) — skipping"
        self._vt_min_window.append(now)
        self._vt_day_count += 1
        return ""

    def _vt_base64url(self, value: str) -> str:
        """VT v3 url/domain identifier: base64url without padding."""
        import base64
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

    def _vt_lookup(self, observable: dict[str, str]) -> dict[str, Any]:
        """VT v3 lookup: hash (md5/sha1/sha256), domain, or url.

        Lookup-class egress (value-only; no artifact upload). File/URL
        SUBMISSION is a separate disclosure decision (vt_submit_enabled,
        default OFF) and is intentionally NOT in this path.
        """
        otype = observable.get("type", "")
        value = str(observable.get("value", ""))
        skip = self._vt_throttle()
        if skip:
            logger.warning("virustotal: %s", skip)
            return _cached_verdict(observable, "virustotal")
        if otype == "hash":
            path = f"files/{value}"
        elif otype == "domain":
            path = f"domains/{value}"
        elif otype == "url":
            path = f"urls/{self._vt_base64url(value)}"
        else:
            return _cached_verdict(observable, "virustotal")
        req = urllib.request.Request(
            f"{self.vt_url.rstrip('/')}/{path}",
            headers={"x-apikey": self.vt_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # 404 = artifact unknown to VT — that's data, not an error
                return {"provider": "virustotal", "status": "unknown",
                        "classification": "not_found",
                        "raw": {"found": False, "note": "unknown to VT"},
                        "ts": datetime.now(timezone.utc).isoformat()}
            if e.code == 429:
                logger.warning("virustotal 429 for %s (quota exceeded)", value)
                return _cached_verdict(observable, "virustotal")
            logger.warning("virustotal HTTP %s for %s: %s", e.code, value, e)
            return _cached_verdict(observable, "virustotal")
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.warning("virustotal lookup failed for %s: %s", value, e)
            return _cached_verdict(observable, "virustotal")
        stats = ((data.get("data") or {}).get("attributes") or {}).get(
            "last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values())
        if malicious > 0 or suspicious > 0:
            status = "malicious" if malicious > 0 else "suspicious"
        elif total > 0:
            status = "benign"
        else:
            status = "unknown"
        return {
            "provider": "virustotal",
            "status": status,
            "classification": f"{malicious} malicious / {suspicious} suspicious / {total} engines",
            "raw": {"stats": stats, "found": True},
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    # --- main entry ---

    def enrich_observable(self, observable: dict[str, str]) -> dict[str, Any]:
        """Enrich one observable via applicable providers.

        Returns a verdict dict (provider, status, raw, ts). Cached per
        observable so repeated enrichments are cheap. Never raises on
        provider failure — degrades to a cached "unknown" verdict.
        """
        key = f"{observable.get('type')}|{observable.get('value')}"
        if key in self._cache:
            return self._cache[key]
        verdict: dict[str, Any] = {}
        for provider in self._providers_for(observable):
            try:
                if provider == "greynoise" and observable.get("type") == "ip":
                    verdict = self._greynoise_lookup(str(observable.get("value")))
                    verdict["observable"] = observable
                elif provider == "virustotal":
                    verdict = self._vt_lookup(observable)
                    verdict["observable"] = observable
            except Exception as e:  # noqa: BLE001 — enrichment must degrade
                logger.warning("enrich %s via %s failed: %s", key, provider, e)
                verdict = _cached_verdict(observable, provider)
        if not verdict:
            verdict = _cached_verdict(observable, "none")
        self._cache[key] = verdict
        return verdict

    def enrich_many(self, observables: list[dict[str, str]]) -> list[dict[str, Any]]:
        """Enrich a list of observables, returning verdicts in order."""
        return [self.enrich_observable(o) for o in observables]

    def verdict_summary(self, verdicts: list[dict[str, Any]]) -> str:
        """Compact summary for ticket/console display."""
        if not verdicts:
            return "no enrichment"
        parts = []
        for v in verdicts:
            obs = v.get("observable", {})
            label = obs.get("value", "?")
            st = v.get("status", "unknown")
            prov = v.get("provider", "?")
            parts.append(f"{label}={st}({prov})")
        return ", ".join(parts)
