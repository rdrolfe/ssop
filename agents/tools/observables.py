"""Observable extraction for the SSOP incident spine.

Adopted concept (Security Onion -> ontology): SO tracks observables (IPs,
domains, hashes, URLs) as first-class case fields, auto-type-detected and
addable from any event. We generalize that into a backend-agnostic primitive:
extract IOCs from an escalated alert and attach them to the case.

PORTABILITY: this module knows nothing about Wazuh or SO — it takes an alert
dict (already normalized by the transport) and returns observable dicts. It
works identically against either backend. This is Concept 1 of the
two-example doctrine (see wayfinder ticket
so-integration-human-experience.md).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from logging_setup import get_logger

logger = get_logger(__name__)

# --- field-name candidates per observable type (transport-normalized + raw) ---
IP_FIELDS = ("srcip", "dstip", "src_ip", "dst_ip", "source.ip", "destination.ip", "clientip")
DOMAIN_FIELDS = ("domain", "hostname", "src_domain", "dst_domain", "url_domain", "dns.question.name")
HASH_FIELDS = ("sha256", "sha1", "md5", "file.hash.sha256", "file.hash.sha1", "file.hash.md5", "hashes")
URL_FIELDS = ("url", "uri", "full_url", "url.full", "url.original")

# Loose IPv4/IPv6 matcher (safe — we validate with ipaddress afterward)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{2,}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")


def _flatten(alert: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested dict keys into dot-notation for field lookup."""
    out: dict[str, Any] = {}

    def _walk(node: Any, prefix: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                _walk(v, key)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, f"{prefix}.{i}")
        else:
            out[prefix] = node

    _walk(alert)
    return out


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def entity_pair(alert: dict[str, Any]) -> tuple[str, str] | None:
    """Extract the (srcip, dstip) entity pair from an alert, if present.

    Flatten-aware: live Wazuh alerts nest these under data.* (data.srcip /
    data.src_ip), replayed/other backends use top-level srcip/src_ip, and
    ECS-style backends use source.ip / destination.ip. Tries all candidate
    names (shared with extract_observables) so the entity key is backend-
    agnostic. Returns None when either side is missing — a pair is required
    for entity recidivism (one-sided alerts get no attach/chain).
    """
    flat = _flatten(alert)
    src = dst = ""
    for f in ("srcip", "src_ip", "data.srcip", "data.src_ip", "source.ip", "clientip"):
        v = flat.get(f)
        if isinstance(v, str) and v and _is_valid_ip(v):
            src = v
            break
    for f in ("dstip", "dst_ip", "data.dstip", "data.dst_ip", "destination.ip"):
        v = flat.get(f)
        if isinstance(v, str) and v and _is_valid_ip(v):
            dst = v
            break
    if not src or not dst:
        return None
    return src, dst


def _dedupe(observables: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set = set()
    out: list[dict[str, str]] = []
    for obs in observables:
        key = (obs["type"], obs["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(obs)
    return out


def extract_observables(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Extract IOCs from an alert dict -> [{type, value}, ...] (deduped).

    Works on transport-normalized fields AND raw Wazuh/SO field names, so it
    is backend-agnostic. Returns [] when nothing recognizable is present.
    """
    flat = _flatten(alert)
    observables: list[dict[str, str]] = []

    # 1. Direct field hits (typed, highest confidence)
    for field, otype in (
        *( (f, "ip") for f in IP_FIELDS ),
        *( (f, "domain") for f in DOMAIN_FIELDS ),
        *( (f, "hash") for f in HASH_FIELDS ),
        *( (f, "url") for f in URL_FIELDS ),
    ):
        val = flat.get(field)
        if isinstance(val, str) and val and val not in ("-", "unknown", "null"):
            if otype == "ip" and not _is_valid_ip(val):
                continue
            observables.append({"type": otype, "value": val.strip()})

    # 2. Description/rule text regex sweep (secondary, lower confidence —
    #    catches IOCs embedded in descriptions that lack typed fields)
    text_src = " ".join(
        str(flat.get(f, "")) for f in ("rule.description", "description", "full_log", "data.srcip")
        if flat.get(f)
    )
    if text_src:
        for m in _SHA256_RE.findall(text_src):
            observables.append({"type": "hash", "value": m})
        for m in _SHA1_RE.findall(text_src):
            observables.append({"type": "hash", "value": m})
        for m in _MD5_RE.findall(text_src):
            observables.append({"type": "hash", "value": m})
        for m in _IP_RE.findall(text_src):
            if _is_valid_ip(m):
                observables.append({"type": "ip", "value": m})
        for m in _DOMAIN_RE.findall(text_src):
            # avoid matching bare "example" or TLD-only fragments
            if "." in m and not m.endswith((".local", ".arpa")):
                observables.append({"type": "domain", "value": m})

    return _dedupe(observables)


def observable_summary(observables: list[dict[str, str]]) -> str:
    """Compact human-readable summary for ticket/console display."""
    if not observables:
        return "none"
    counts: dict[str, int] = {}
    for o in observables:
        counts[o["type"]] = counts.get(o["type"], 0) + 1
    parts = [f"{n}x {t}" for t, n in sorted(counts.items())]
    return ", ".join(parts) + f" ({len(observables)} total)"
