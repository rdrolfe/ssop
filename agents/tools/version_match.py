"""CPE version-range matching for intel cases (P2 of intel backlog).

The KEV->fleet join was product-NAME only (match_kev); every match minted
an open intel case regardless of whether the installed version is inside
the CVE's vulnerable range. NVD configurations carry the authoritative
version bounds (cpeMatch versionStartIncluding/EndExcluding etc.).

Disposition per (CVE, agent):
  vulnerable — fleet version parses AND falls inside a vulnerable range
  patched    — fleet version parses AND falls outside ALL vulnerable ranges
  unknown    — version does not parse against the CPE product's version
               scheme (snap stubs, distro-forked strings) — NEVER
               auto-closed; human disposition required.

Auto-close policy: a case is closed as version-checked-FP ONLY when every
(CVE, agent) leg is `patched`. Any vulnerable or unknown leg keeps it open.

Pull-only: NVD GET, no environment data leaves (sovereignty clean).
"""
from __future__ import annotations

import re
from typing import Any

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ---------------------------------------------------------------------------
# Version normalization
# ---------------------------------------------------------------------------

def normalize_version(raw: str) -> str | None:
    """Fleet package version -> upstream version string, or None if the
    string is not an upstream version at all (snap stubs, forks).

    Handles: Debian epoch (1:2.53.0 -> 2.53.0), debian revision
    (-1ubuntu7.3), dfsg suffixes (10.06.0~dfsg -> 10.06.0).
    Returns None for strings whose leading numeric component is not a
    real upstream version (e.g. '1:1snap1-...' where upstream '1snap1'
    is a snap transitional marker, not a firefox version).
    """
    if not raw:
        return None
    v = raw.strip()
    if ":" in v:  # debian epoch
        v = v.split(":", 1)[1]
    v = re.split(r"[-+]", v, maxsplit=1)[0]     # revision / ubuntu suffix
    v = v.split("~", 1)[0]                       # dfsg / pre-release tail
    v = v.strip(".")
    if not v or not re.match(r"^\d+(\.\d+)*$", v):
        return None
    return v


def version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


# ---------------------------------------------------------------------------
# NVD configurations -> version ranges
# ---------------------------------------------------------------------------

def fetch_cpe_ranges(cve_id: str, product: str,
                     timeout: int = 30) -> list[dict[str, Any]]:
    """Vulnerable version ranges for one CVE restricted to `product`.

    Returns [{start, start_inc, end, end_inc}] with version TUPLES (None
    = unbounded). Ranges for OTHER products in the same CVE are dropped
    (a CVE can span products we do not run). Exact-version cpeMatch
    entries (no bounds) become degenerate ranges [v, v].
    """
    import json
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{NVD_URL}?cveId={cve_id}",
            headers={"User-Agent": "ssop-intel/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001 — range fetch is best-effort
        return []
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return []
    prod_l = product.lower()
    ranges: list[dict[str, Any]] = []
    for conf in (vulns[0].get("cve", {}).get("configurations") or []):
        for node in conf.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                crit = str(m.get("criteria") or "")
                parts = crit.split(":")
                # cpe:2.3:<part>:<vendor>:<product>:<version>:...
                if len(parts) < 6 or parts[2] not in ("a", "o") \
                        or parts[4].lower() != prod_l:
                    continue
                if not m.get("vulnerable", False):
                    continue
                ver = m.get("version") or parts[5] or "*"
                if ver not in ("*", "-", ""):
                    # exact-version entry -> degenerate closed range
                    nv = normalize_version(ver)
                    if nv is None:
                        continue
                    t = version_tuple(nv)
                    ranges.append({"start": t, "start_inc": True,
                                   "end": t, "end_inc": True})
                    continue
                s = e = None
                s_inc = e_inc = True
                for key, tgt, incflag in (
                        ("versionStartIncluding", "start", True),
                        ("versionStartExcluding", "start", False),
                        ("versionEndIncluding", "end", True),
                        ("versionEndExcluding", "end", False)):
                    raw = m.get(key)
                    if raw:
                        nv = normalize_version(raw)
                        if nv is None:
                            continue
                        if tgt == "start":
                            s, s_inc = version_tuple(nv), incflag
                        else:
                            e, e_inc = version_tuple(nv), incflag
                if s is not None or e is not None:
                    ranges.append({"start": s, "start_inc": s_inc,
                                   "end": e, "end_inc": e_inc})
    return ranges


def in_range(vt: tuple[int, ...], r: dict[str, Any]) -> bool:
    if r["start"] is not None:
        c = _cmp(vt, r["start"])
        if c < 0 or (c == 0 and not r["start_inc"]):
            return False
    if r["end"] is not None:
        c = _cmp(vt, r["end"])
        if c > 0 or (c == 0 and not r["end_inc"]):
            return False
    return True


# ---------------------------------------------------------------------------
# Disposition
# ---------------------------------------------------------------------------

def disposition_version(raw_version: str | None,
                        ranges: list[dict[str, Any]]) -> str:
    """vulnerable | patched | unknown for one (CVE, agent) leg.

    No ranges (NVD gave none / fetch failed) -> unknown, never patched —
    absence of bounds is not proof of safety.
    """
    if not ranges:
        return "unknown"
    nv = normalize_version(raw_version or "")
    if nv is None:
        return "unknown"
    vt = version_tuple(nv)
    return "vulnerable" if any(in_range(vt, r) for r in ranges) else "patched"
