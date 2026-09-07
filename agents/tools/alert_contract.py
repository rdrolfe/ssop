"""Alert/evidence contract — one normalization at the transport boundary.

Every consumer (investigation, IRIS publish, recidivism, report) reads the
SAME validated shape instead of re-deriving identity independently:

  - src_ip/dst_ip are VALIDATED IPs with explicit roles (a hostname or hash
    can never substitute for a source IP — the obs[0] failure mode);
  - observables carry semantic hash_type (md5/sha1/sha256), not a generic
    "hash" blob;
  - backend/index/doc_id/occurred_at ride along so IRIS publish never
    guesses the engine from rule_id.isdigit();
  - the raw alert is retained untouched for audit.

Hermetic: pure functions, no stores, no network. See
docs/plans/2026-09-07-alert-contract.md for the design.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from logging_setup import get_logger

logger = get_logger(__name__)

BACKENDS = ("wazuh", "securityonion", "bots", "elastic")

# Shared candidate-field order: ONE list per role, used by the contract AND
# re-exported for entity_pair/extract_observables (no per-module tuples).
SRC_IP_FIELDS = ("srcip", "src_ip", "data.srcip", "data.src_ip", "source.ip", "clientip")
DST_IP_FIELDS = ("dstip", "dst_ip", "data.dstip", "data.dst_ip", "destination.ip")
DOMAIN_FIELDS = ("domain", "hostname", "src_domain", "dst_domain", "url_domain", "dns.question.name")
URL_FIELDS = ("url", "uri", "full_url", "url.full", "url.original")
# (field, hash_type) — typed fields carry their semantic hash type.
HASH_FIELDS = (
    ("sha256", "sha256"), ("sha1", "sha1"), ("md5", "md5"),
    ("file.hash.sha256", "sha256"), ("file.hash.sha1", "sha1"),
    ("file.hash.md5", "md5"), ("hashes", None),
)

_LENGTH_TO_HASH = {64: "sha256", 40: "sha1", 32: "md5"}

_IP_RE_STRONG = (
    # IPv4 with strict octets
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
)
_SHA256_RE = r"\b[0-9a-fA-F]{64}\b"
_SHA1_RE = r"\b[0-9a-fA-F]{40}\b"
_MD5_RE = r"\b[0-9a-fA-F]{32}\b"
_DOMAIN_RE = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, prefix=f"{key}."))
        else:
            out[key] = v
    return out


def _first_ip(flat: dict[str, Any], fields: tuple[str, ...]) -> str:
    for f in fields:
        v = flat.get(f)
        if isinstance(v, str) and v.strip() and is_valid_ip(v.strip()):
            return v.strip()
    return ""


def _hash_type_for(value: str, declared: str | None) -> str | None:
    if declared:
        return declared
    return _LENGTH_TO_HASH.get(len(value))


def _observables(flat: dict[str, Any], text: str) -> list[dict[str, Any]]:
    """Typed observables with semantic hash_type. Deduped on (type, value)."""
    import re

    obs: list[dict[str, Any]] = []

    for f, htype in HASH_FIELDS:
        v = flat.get(f)
        if isinstance(v, str) and v.strip() and v.strip().lower() not in ("-", "unknown", "null"):
            ht = _hash_type_for(v.strip(), htype)
            obs.append({"type": "hash", "value": v.strip(), **({"hash_type": ht} if ht else {})})

    for f in DOMAIN_FIELDS:
        v = flat.get(f)
        if isinstance(v, str) and v.strip() and "." in v and not v.strip().endswith((".local", ".arpa")):
            obs.append({"type": "domain", "value": v.strip()})

    for f in URL_FIELDS:
        v = flat.get(f)
        if isinstance(v, str) and v.strip().startswith(("http://", "https://")):
            obs.append({"type": "url", "value": v.strip()})

    # Description/log regex sweep (lower confidence, typed by construction).
    if text:
        for m in re.findall(_SHA256_RE, text):
            obs.append({"type": "hash", "value": m, "hash_type": "sha256"})
        for m in re.findall(_SHA1_RE, text):
            obs.append({"type": "hash", "value": m, "hash_type": "sha1"})
        for m in re.findall(_MD5_RE, text):
            obs.append({"type": "hash", "value": m, "hash_type": "md5"})
        for pat in _IP_RE_STRONG:
            for m in re.findall(pat, text):
                obs.append({"type": "ip", "value": m})
        for m in re.findall(_DOMAIN_RE, text):
            if not m.endswith((".local", ".arpa")):
                obs.append({"type": "domain", "value": m})

    # Dedupe on (type, value-lowercase), preserving hash_type of first seen.
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for o in obs:
        key = (o["type"], o["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(o)
    return out


def _occurred_at(flat: dict[str, Any], ts_field: str | None = None) -> str:
    candidates = [ts_field] if ts_field else []
    candidates += ["timestamp", "@timestamp", "event.created", "data.timestamp"]
    for f in candidates:
        v = flat.get(f)
        if isinstance(v, str) and v.strip():
            try:
                dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc).isoformat()
            except ValueError:
                continue
    # Last resort: now (flagged by callers via absence of the source field).
    return datetime.now(timezone.utc).isoformat()


def normalize_alert(alert: dict[str, Any], *, backend: str = "",
                    index: str = "", doc_id: str = "",
                    ts_field: str | None = None) -> dict[str, Any]:
    """Normalize ANY backend alert into the evidence contract.

    Never raises: a malformed doc degrades to empty fields (alert processing
    must not die on bad input). The raw alert is retained under "raw".
    """
    if not isinstance(alert, dict):
        alert = {}
    flat = _flatten(alert)

    if backend and backend not in BACKENDS:
        logger.warning("normalize_alert: unknown backend %r — carrying as-is", backend)

    rule = alert.get("rule") or {}
    if not isinstance(rule, dict):
        rule = {}

    src_ip = _first_ip(flat, SRC_IP_FIELDS)
    dst_ip = _first_ip(flat, DST_IP_FIELDS)

    text = " ".join(str(flat.get(f, "")) for f in
                    ("rule.description", "description", "full_log") if flat.get(f))

    observables = _observables(flat, text)

    return {
        "backend": backend or "unknown",
        "index": index or "",
        "doc_id": doc_id or "",
        "occurred_at": _occurred_at(flat, ts_field),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "observables": observables,
        "rule_id": str(rule.get("id", "") or ""),
        "rule_desc": str(rule.get("description", "") or rule.get("name", "") or ""),
        "level": int(rule.get("level", 0) or 0),
        "raw": alert,
    }


def investigation_entity(contract: dict[str, Any]) -> str:
    """Pick the entity to investigate: src_ip ONLY if it's a validated IP.

    A hostname/hash observable can never substitute (the obs[0] failure
    mode). Returns "" when the alert carries no IP — the caller skips
    correlation rather than investigating the wrong value.
    """
    ip = contract.get("src_ip") or ""
    return ip if is_valid_ip(ip) else ""


def ip_observables(contract: dict[str, Any]) -> list[dict[str, Any]]:
    """Only the IP-typed observables — for recidivism/correlation keys."""
    return [o for o in contract.get("observables", []) if o.get("type") == "ip"]
