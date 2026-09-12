"""Bulk intel for hunt — match the LOCAL corpus first, then look up survivors.

The cost model this module exists to enforce, in one line:

    match MANY candidate observables against the in-lab MISP corpus in a handful
    of batched requests, and spend per-indicator EXTERNAL lookups
    (`tools/enrichment.py`: GreyNoise/VT/OTX, quota-limited and metered) only on
    the values the local corpus already recognises.

Hunt used to have no intel step at all. With it, hunt becomes a bulk consumer:
"match thousands at once, look up the survivors" (docs/roles/hunt.md,
ADR-007, docs/feeds-and-licensing.md).

WHAT THIS MODULE MUST NEVER DO:

  - **No writes / no disclosure.** It only ever calls MISP's read-only
    restSearch through `tools/misp_client.py`. There is no submit path and
    there must not be one by default (sovereignty doctrine, ADR-007 call 3).
  - **Degraded is NOT clean.** If MISP is unreachable the result is UNKNOWN:
    no promotion, no "clean" summary, and — deliberately — no external
    lookups either. Spending the metered/quota'd providers to compensate for
    a missing local filter inverts the entire cost argument.
  - **If the local filter is absent, nothing is spent.** An unconfigured MISP
    means bulk intel is off, which means hunt behaves exactly as it did
    before: no silent per-indicator fan-out.
  - **Strict survivors only.** An observable that the corpus did not match is
    never passed to a provider. This is asserted in
    `verify/test_bulk_intel.py` with a recording enrichment stub — a
    regression that "helpfully" enriches everything is the failure mode.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from config import settings
from logging_setup import get_logger

logger = get_logger(__name__)

# Observable types where a corpus match is a DETECTION rather than a lead.
#
# A hash, a domain or a url in your telemetry that a community corpus already
# knows is a detection. A bare IP match is weaker: scanning infrastructure,
# CDN and sinkhole addresses are shared, and abuse.ch-style feeds carry a lot
# of them. So an IP match raises confidence and is recorded, but on its own it
# does not turn a clean hunt into an escalation. This is the boundary between
# "the hunt found something real" and "the hunt found an address that someone
# somewhere has seen" — deliberately conservative, because a hunt sweep that
# escalates on incidental IP matches would put the fleet's loudest noise
# straight back on the human's queue.
STRONG_TYPES = frozenset({"hash", "domain", "url"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def promote_finding(finding: str, intel: dict[str, Any]) -> tuple[str, str]:
    """Apply a bulk-intel result to a hunt finding. Returns (finding, why).

    The rule, in order of precedence:

      - degraded / not checked  -> unchanged, "intel-unknown"
      - no matches              -> unchanged, "no-intel-match"
      - strong match            -> "suspicious" (escalatable by category)
      - weak (ip-only) match    -> clean -> "info"; nothing else changes

    Escalation is still owned by `hunt.py`'s ESCALATE_CATEGORIES gate on the
    finding word — this function only decides how much a corpus match is
    worth, never whether a category escalates.
    """
    if intel.get("degraded"):
        return finding, "intel-unknown"
    if not intel.get("matched"):
        return finding, "no-intel-match"
    if intel.get("strong_matches"):
        return "suspicious", "strong-intel-match"
    if finding == "clean":
        return "info", "weak-intel-match"
    return finding, "weak-intel-match"


class BulkIntel:
    """Local-corpus-first intel for a set of candidate observables."""

    def __init__(self, misp: Any | None = None, enrichment: Any | None = None) -> None:
        # Injected for tests (hermetic fake MISP / recording enrichment stub).
        self._misp = misp
        self._enrichment = enrichment

    # --- lazily-built real clients (import at use, not at module import) ---

    def _misp_client(self) -> Any:
        if self._misp is None:
            from tools.misp_client import MispClient
            self._misp = MispClient()
        return self._misp

    def _enrichment_client(self) -> Any:
        if self._enrichment is None:
            from tools.enrichment import EnrichmentClient
            self._enrichment = EnrichmentClient()
        return self._enrichment

    # --- steps ------------------------------------------------------------

    def match(self, observables: list[dict[str, Any]],
              external: bool = False) -> dict[str, Any]:
        """Match typed observables against MISP; optionally enrich survivors.

        `external=True` runs provider lookups — but ONLY for the values the
        corpus matched. See the module docstring: that is the whole point.
        """
        out: dict[str, Any] = {
            "source": "bulk-intel", "enabled": False, "degraded": False,
            "error": None, "candidates": 0, "searched": 0, "matched": 0,
            "strong_matches": 0, "batches": 0, "types": {},
            "matches": {}, "known_values": [], "external_looked_up": 0,
            "external": [], "ts": _now(),
        }

        # Value -> type, so a match can be classified without trusting the
        # caller's ordering. Typed observables only (`tools/observables.py`).
        by_value: dict[str, str] = {}
        for o in observables or []:
            v = (o or {}).get("value")
            if v:
                by_value.setdefault(str(v), str(o.get("type") or "unknown"))
        out["candidates"] = len(by_value)
        if not by_value:
            out["summary"] = "no candidate observables"
            return out

        client = self._misp_client()
        enabled = bool(client.available()) if hasattr(client, "available") else True
        out["enabled"] = enabled
        if not enabled:
            # Bulk intel is not deployed. NOT an error, NOT "clean" — and
            # explicitly no external spend (see module docstring).
            out["summary"] = (f"{out['candidates']} candidates, bulk intel "
                              f"not configured (no external lookups spent)")
            return out

        result = client.match_many(list(by_value))
        for key in ("degraded", "error", "searched", "matched", "batches", "matches"):
            out[key] = result.get(key, out.get(key))
        known = [v for v in (result.get("matches") or {})]
        out["known_values"] = sorted(known)
        out["matched"] = len(known)

        type_counts: dict[str, int] = {}
        strong = 0
        for v in known:
            t = by_value.get(v, "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
            if t in STRONG_TYPES:
                strong += 1
        out["types"] = type_counts
        out["strong_matches"] = strong

        if out["degraded"]:
            out["summary"] = (f"{out['candidates']} candidates, corpus UNKNOWN "
                              f"({out.get('error')}) — no external lookups spent")
            return out

        if external and known:
            survivors = [{"type": by_value.get(v, "unknown"), "value": v}
                         for v in known]
            try:
                verdicts = self._enrichment_client().enrich_many(survivors)
            except Exception as e:  # noqa: BLE001 — enrichment must not break a sweep
                logger.warning("bulk-intel enrichment failed: %s", e)
                verdicts = []
                out["error"] = f"enrichment: {type(e).__name__}: {e}"
            out["external"] = verdicts
            out["external_looked_up"] = len(verdicts)

        out["summary"] = (
            f"{out['candidates']} candidates, {out['matched']} matched the corpus "
            f"({out['strong_matches']} strong/{out['types']}), "
            f"{out['batches']} batch(es)"
            + (f", {out['external_looked_up']} external lookup(s)" if external else "")
        )
        return out


# --- hunt-shaped entry points ---------------------------------------------
# These live HERE, not in the role, so the live sweep and the verification
# matrix run the same derivation instead of two copies that can drift (the
# failure mode this project keeps paying for: one surface deriving what is
# already known, differently).

def collect_observables(result: dict[str, Any]) -> list[dict[str, str]]:
    """Candidate observables from the events a hunt returned.

    Typed extraction via `tools/observables.py` — never ad-hoc string scraping,
    so what gets matched is exactly what the extractor recognises fleet-wide
    (ip / hash / domain / url). Hunt analyzers cap `detail` at 5 events.
    """
    from tools.observables import extract_observables

    seen: set[tuple] = set()
    out: list[dict[str, str]] = []
    for doc in (result.get("detail") or [])[:5]:
        try:
            found = extract_observables(doc if isinstance(doc, dict) else {})
        except Exception:  # noqa: BLE001 — extraction must not break a sweep
            continue
        for o in found:
            key = (o.get("type"), o.get("value"))
            if not o.get("value") or key in seen:
                continue
            seen.add(key)
            out.append(o)
    return out


def bulk_intel_for(result: dict[str, Any], external: bool = False) -> dict[str, Any]:
    """Match a hunt's candidate observables against the LOCAL MISP corpus.

    Never raises: a hunt sweep must not fail because the feed platform is
    unreachable — it must report UNKNOWN. `external=True` additionally spends
    per-indicator provider lookups, and only on corpus-matched survivors; it is
    OFF by default because that spend is metered (VT quota) and is the thing
    bulk matching exists to reduce.
    """
    try:
        return BulkIntel().match(collect_observables(result), external=external)
    except Exception as e:  # noqa: BLE001 — intel must not break the hunt
        logger.warning("bulk intel failed (continuing): %s", e)
        return {"source": "bulk-intel", "degraded": True, "matched": 0,
                "strong_matches": 0, "candidates": 0, "batches": 0,
                "matches": {}, "known_values": [], "external": [],
                "external_looked_up": 0, "summary": f"bulk intel error: {e}"}


# 40 hex zeros — a value no real corpus contains. The probe's negative control.
_PROBE_VALUE = "0" * 40


def probe_corpus(client: Any | None = None) -> dict[str, Any]:
    """One deterministic read-only round trip to the corpus. Never raises.

    WHY THIS EXISTS: the per-hunt bulk intel only fires when a hunt happens to
    return extractable observables — in practice the live hunts usually do not,
    so a "did the hunt check the corpus?" assertion SKIPS on nearly every
    matrix run and proves nothing. A gate that cannot see the thing must not
    report success (or skip silently); it must ask the question directly.

    So: is the hunt path's corpus configured at all, and does it answer? The
    value is 40 hex zeros, which must return zero matches — a non-empty result
    would mean the probe is matching noise, not that an indicator was found.

    `client` is injectable so this is testable without a live corpus.
    """
    out: dict[str, Any] = {"enabled": False, "reachable": False,
                           "degraded": True, "error": None, "summary": ""}
    try:
        if client is None:
            from tools.misp_client import MispClient
            client = MispClient()
        out["enabled"] = bool(client.available())
        if not out["enabled"]:
            out["summary"] = ("MISP not configured on this host "
                              "(MISP_URL / MISP_API_KEY unset)")
            return out
        res = client.match_many([_PROBE_VALUE])
        out["degraded"] = bool(res.get("degraded"))
        out["error"] = res.get("error")
        out["reachable"] = not out["degraded"]
        if out["reachable"]:
            out["summary"] = (f"reachable — answered in {res.get('batches')} "
                              f"request(s), {res.get('matched')} match(es) for the "
                              f"negative control (0 expected)")
        else:
            out["summary"] = f"UNREACHABLE — {out['error']}"
    except Exception as e:  # noqa: BLE001 — the probe reports, never raises
        out["error"] = f"{type(e).__name__}: {e}"
        out["summary"] = f"probe failed — {out['error']}"
    return out
