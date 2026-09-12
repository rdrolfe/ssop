"""MISP bulk indicator matching — local, bulk, READ-ONLY (ADR-007).

Hunt becomes the consumer of BULK intel: match its candidate observables
against the pooled feed corpus pulled LOCALLY, and only the survivors go on to
per-indicator external lookups (`tools/enrichment.py`). That converts hunt from
"pivot then look up each" into "match thousands at once, look up the survivors"
— see `docs/roles/hunt.md` and `docs/feeds-and-licensing.md`.

WHAT THIS MODULE MUST NEVER DO:

  - **No writes, ever.** No `/attributes/add`, no `/events/add`, no publish, no
    sharing-group edits. There is no submit path here and there must not be one
    by default: contributing our observables back to MISP or any feed is a
    DISCLOSURE event (sovereignty doctrine, ADR-007 call 3). `verify/test_misp_client.py`
    asserts this module's source contains no write endpoint, so a future edit
    cannot quietly add one.
  - **No `CERT_NONE`.** TLS goes through `tools.tls.verified_ssl_context()`
    (issue #29's factory). A bridge that disables verification is the bug.
  - **Never report an empty result on failure.** "MISP unreachable" and "no
    matches" are different facts; conflating them is how a fleet gets reported
    clean when the feed platform is simply down. Failures return
    `degraded=True` and the caller must treat the batch as UNKNOWN.
  - **No external egress.** MISP is on the SSOP LAN, so this is not external
    egress and needs no `external_calls` entry (`verify/check_egress.py` treats
    RFC1918 as local). MISP's own feed sync is the infrastructure egress that
    IS declared (transport.yaml) and enforced on the MISP host — it runs there,
    not here.

LICENCE AWARENESS: results carry provenance (event id, type, tags) but this
module does NOT resolve which feed an event came from, because it cannot do so
reliably from an attribute payload. Callers that intend to PUBLISH an indicator
(a committed hunt pack) must resolve provenance and check it against
`docs/feeds-and-licensing.md` first. The default path — match locally, never
publish — needs none of that.
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

# Fields worth keeping from a MISP attribute. Keep this narrow: the point is a
# boolean "known indicator" + honest provenance, not a second copy of MISP's
# data model inside the spine.
_KEEP = ("type", "category", "value", "to_ids", "event_id", "timestamp",
         "comment", "Tags", "Feed")


class MispError(RuntimeError):
    pass


class MispConfigError(MispError):
    """A configuration error (bad URL, insecure transport).

    Deliberately NOT swallowed by `match_many`'s degradation path: an insecure
    or malformed configuration must fail LOUDLY. Reporting it as `degraded`
    would make "your MISP_URL is plain HTTP" indistinguishable from "MISP is
    down", which is exactly the kind of too-quiet control this project keeps
    getting bitten by.
    """


class MispClient:
    """Bulk, read-only indicator matching against the in-lab MISP."""

    def __init__(self, url: str | None = None, api_key: str | None = None) -> None:
        self.url = (url if url is not None else settings.misp_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.misp_api_key
        self.timeout = settings.misp_timeout_s
        self.batch_size = max(1, settings.misp_batch_size)

    # --- availability -----------------------------------------------------

    def available(self) -> bool:
        """True when a URL AND key are configured.

        An unconfigured client is not an error — it means bulk matching is not
        deployed yet, and callers must treat results as "not checked", never as
        "clean".
        """
        return bool(self.url and self.api_key)

    # --- transport --------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.available():
            raise MispError("MISP is not configured (set MISP_URL and MISP_API_KEY)")
        from urllib.parse import urlparse

        from tools.tls import verified_ssl_context

        host = (urlparse(self.url).hostname or "").lower()
        # Verified TLS is the default and the only production shape. Plain HTTP
        # is permitted ONLY for a loopback test fixture, so a hermetic test
        # cannot become a production downgrade (issue #29 doctrine: fix the
        # certificate, never weaken the client).
        if not self.url.startswith("https://") and host not in ("127.0.0.1", "localhost", "::1"):
            raise MispConfigError(
                "MISP_URL must be https:// — plain HTTP is allowed only for a "
                f"loopback test fixture (got {self.url!r})")
        # Build the verifying context ONLY for https. Calling the factory for a
        # plain-HTTP loopback fixture made it fail-closed on a host with no CA
        # bundle, which broke the hermetic test for a reason that had nothing to
        # do with the code under test (the factory is right; the call was wrong).
        context = verified_ssl_context() if self.url.startswith("https://") else None

        req = urllib.request.Request(
            f"{self.url}{path}", data=json.dumps(payload).encode(), method="POST")
        req.add_header("Authorization", self.api_key)
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=self.timeout,
                                    context=context) as resp:
            body = resp.read().decode()
        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise MispError(f"non-JSON response from {path}: {body[:200]}") from e

    # --- the bulk match ---------------------------------------------------

    def match_many(self, values: list[str]) -> dict[str, Any]:
        """Match a batch of indicator VALUES in as few requests as possible.

        Returns::

            {"source": "misp", "enabled": True, "degraded": False,
             "searched": <int>, "matched": <int>, "batches": <int>,
             "matches": {value: [ {type, category, event_id, ...}, ... ]},
             "ts": <iso8601>}

        `degraded=True` (with `error`) means the batch was NOT checked —
        callers must not read that as "no matches".
        """
        uniq = sorted({v for v in values if v})
        out: dict[str, Any] = {
            "source": "misp", "enabled": self.available(), "degraded": False,
            "searched": len(uniq), "matched": 0, "batches": 0, "matches": {},
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        if not uniq:
            return out
        if not self.available():
            out["degraded"] = True
            out["error"] = "MISP not configured (MISP_URL / MISP_API_KEY unset)"
            out["searched"] = 0
            return out

        matches: dict[str, list[dict[str, Any]]] = {}
        for i in range(0, len(uniq), self.batch_size):
            chunk = uniq[i:i + self.batch_size]
            try:
                data = self._post("/attributes/restSearch",
                                  {"value": chunk, "returnFormat": "json"})
            except MispConfigError:
                raise          # an insecure config must not read as "MISP down"
            except (MispError, urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
                logger.warning("misp bulk match failed (%d values in flight): %s",
                               len(chunk), e)
                out["degraded"] = True
                out["error"] = f"{type(e).__name__}: {e}"
                out["searched"] = 0
                out["matches"] = matches
                return out
            out["batches"] += 1
            for attr in ((data.get("response") or {}).get("Attribute") or []):
                val = attr.get("value")
                if not val:
                    continue
                matches.setdefault(val, []).append(
                    {k: attr[k] for k in _KEEP if k in attr})
        out["matches"] = matches
        out["matched"] = len(matches)
        return out

    def annotate_observables(self, observables: list[dict[str, Any]]) -> dict[str, Any]:
        """Bulk-match typed observables and mark which ones are known.

        Adds `known: True|False` + `intel` to each observable (by value) and
        returns the same envelope as `match_many`, plus `known_values` — the
        survivors a caller would then send to per-indicator enrichment.

        Typed observables only (`tools/observables.py` shapes): a match is
        driven by the extractor's typing, never by ad-hoc string scraping.
        """
        values = [o.get("value", "") for o in observables if o.get("value")]
        result = self.match_many(values)
        known = set(result.get("matches", {}))
        for o in observables:
            v = o.get("value", "")
            o["known"] = v in known and not result["degraded"]
            if o["known"]:
                o["intel"] = result["matches"][v]
        result["known_values"] = sorted(known)
        return result
