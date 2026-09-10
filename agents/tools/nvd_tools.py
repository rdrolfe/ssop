"""NVD API 2.0 enrichment for intel cases (P1 second pass).

Fills CVSS/description for matched CVEs (the join key). Keyless: ~2.7s
per request, 5 req/30s limit — a handful of CVEs per day fits easily.
Pull-only: no environment data leaves (sovereignty clean).
"""
import json
import urllib.request
from typing import Any

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd(cve_id: str, timeout: int = 30) -> dict[str, Any]:
    """CVSS score/description for one CVE. Returns {} on any failure —
    enrichment must never break the case it's filling in."""
    try:
        req = urllib.request.Request(
            f"{NVD_URL}?cveId={cve_id}",
            headers={"User-Agent": "ssop-intel/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return {}
        cve = vulns[0].get("cve", {})
        desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        # Prefer v3.1, fall back v3.0, then v2
        metrics = cve.get("metrics", {})
        score = vector = version = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                d = m.get("cvssData", {})
                if d.get("baseScore") is not None:
                    score = d["baseScore"]
                    vector = d.get("vectorString", "")
                    version = d.get("version", key)
                    break
            if score is not None:
                break
        return {"description": desc[:300], "cvss": score,
                "cvss_vector": vector, "cvss_version": version}
    except Exception:  # noqa: BLE001 — enrichment is best-effort by design
        return {}
