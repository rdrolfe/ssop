#!/usr/bin/env python3
"""Intel tools: CISA KEV -> fleet match -> staged hunt packs.

The intel role's engine (wayfinder: intel-sources + fleet-inventory-source +
hunt-pack-schema tickets, all resolved):

  INGEST   fetch the CISA KEV catalog (1 GET, keyless, public-domain —
           sovereign: we only PULL, no environment data leaves).
  MATCH    KEV vendorProject/product vs fleet inventory
           (wazuh-states-inventory-packages-*). Mandatory gate: products we
           don't run are skipped entirely — 1,700 entries collapse to the
           handful that matter.
  GENERATE one hunt-pack YAML per matched CVE, targeting the INVENTORY
           indices (honest: checks presence of the vulnerable product, not
           speculative exploitation IOCs).
  STAGE    packs land in staging/ for human (or supervisory) review and
           promotion. The machine proposes; the human disposes.

NVD enrichment (CVSS detail) is a P1 second pass — KEV alone is already
exploited-in-the-wild signal.
"""
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
INVENTORY_INDEX = "wazuh-states-inventory-packages-*"


def fetch_kev(url: str = KEV_URL, timeout: int = 60) -> dict[str, Any]:
    """Fetch and parse the KEV catalog. Returns {catalogVersion, vulnerabilities}.

    Raises on network/parse failure — callers decide degradation policy.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "ssop-intel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("KEV feed missing vulnerabilities[]")
    return data


def fleet_products(ix: Any) -> dict[str, list[str]]:
    """Distinct lowercased product -> sorted agent list, from inventory.

    Reads the packages states index DIRECTLY (the gotcha from the
    fleet-inventory ticket: inventory is NOT in wazuh-alerts-*).
    """
    body = {"size": 2000, "query": {"match_all": {}},
            "_source": ["agent.name", "package.name"]}
    d = ix.search(body, index=INVENTORY_INDEX)
    pkgs: dict[str, set[str]] = {}
    for h in d.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        agent = (s.get("agent") or {}).get("name") or "?"
        name = (s.get("package") or {}).get("name") or ""
        if name:
            pkgs.setdefault(name.strip().lower(), set()).add(agent)
    return {k: sorted(v) for k, v in sorted(pkgs.items())}


def match_kev(kev: dict[str, Any], products: dict[str, list[str]]) -> list[dict[str, Any]]:
    """KEV entries whose product is in the fleet. Environment gate applied.

    Matching is case-insensitive on the lowercased product name. Vendor is
    checked too when the bare product is ambiguous? No — product-only: the
    inventory records package names, not vendor hierarchies, and a product
    name collision across vendors is rarer than a vendor-string mismatch.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for v in kev.get("vulnerabilities", []):
        cve = str(v.get("cveID") or "")
        prod = str(v.get("product") or "").strip().lower()
        if not cve or cve in seen or not prod:
            continue
        agents = products.get(prod)
        if agents:  # THE GATE: product must exist in our fleet
            seen.add(cve)
            out.append({**v, "_matched_agents": agents})
    return out


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40]


def build_hunt_pack(match: dict[str, Any]) -> dict[str, Any]:
    """A generated hunt pack, valid per load_hunts() (name/category/
    hypothesis/analyze/query) + an intel `meta` block the loader ignores."""
    cve = match["cveID"]
    product = match.get("product") or "product"
    vendor = match.get("vendorProject") or ""
    agents = match.get("_matched_agents") or []
    name = match.get("vulnerabilityName") or f"{vendor} {product} vulnerability"
    return {
        "name": f"{cve.lower()} {product}".strip(),
        "category": "threat",
        "technique_id": "T1190",  # exploit public-facing app — presence check
        "hypothesis": (f"Exploited {cve} ({name}) may be present — checking "
                       f"fleet for the vulnerable product {product}"),
        "analyze": "generic",
        "query": {
            "size": 100,
            "query": {"bool": {"filter": [
                {"term": {"package.name": product}},
            ]}},
            "_source": ["timestamp", "agent.name", "package"],
        },
        "meta": {
            "cve_id": cve,
            "source": "cisa-kev",
            "matched_agents": agents,
            "vendor": vendor,
            "product": product,
            "date_added": match.get("dateAdded", ""),
            "generated": datetime.now(timezone.utc).isoformat(),
        },
    }


def stage_packs(matches: list[dict[str, Any]], staging_dir: Path) -> dict[str, int]:
    """Write one YAML per matched CVE into staging/, skipping CVEs already
    staged or already promoted into the live hunts dir. Returns counts."""
    import yaml
    live_dir = staging_dir.parent
    staged = written = skipped = 0
    staging_dir.mkdir(parents=True, exist_ok=True)
    live_cves: set[str] = set()
    for f in list(live_dir.glob("*.yaml")) + list(staging_dir.glob("*.yaml")):
        try:
            live_cves.add(str((yaml.safe_load(f.read_text()) or {})
                              .get("meta", {}).get("cve_id", "")))
        except Exception:  # noqa: BLE001 — unreadable file can't dedupe
            pass
    staged_names = {f.name for f in staging_dir.glob("*.yaml")}
    for m in matches:
        cve = m["cveID"]
        if cve in live_cves or f"{cve.lower()}.yaml" in staged_names:
            skipped += 1
            continue
        pack = build_hunt_pack(m)
        path = staging_dir / f"{cve.lower()}.yaml"
        path.write_text(yaml.safe_dump(pack, sort_keys=False))
        staged += 1
    return {"staged": staged, "skipped": skipped, "matched": len(matches)}


def mint_match_cases(matches: list[dict[str, Any]], cases: Any) -> dict[str, int]:
    """The inventory match IS evidence — mint spine cases for it.

    KEV says "exploited in the wild"; syscollector says "this package is
    installed on THIS agent, observed at scan time". The join is two
    grounded observations about the fleet, not a proposal: it belongs on
    the spine as a threat case with full provenance (CVE, package record,
    matched agents), assigned to supervisory for triage. The staged hunt
    pack remains a separate artifact — that's the proposed DETECTION, and
    reviewing a proposed detection stays human.

    Dedupe mirrors dispatch_infra's open-only rule: one OPEN case per
    (CVE, agent). A re-run attaches nothing new when the case is open; a
    closed case re-mints if the product is still present (re-surfacing).
    """
    minted = 0
    for m in matches:
        cve = m["cveID"]
        for agent in m.get("_matched_agents", []):
            existing = _open_intel_case(cases, cve, agent)
            if existing:
                cases.append_event(existing, "intel", "dispatch", {
                    "verdict": "match", "cve_id": cve,
                    "product": m.get("product", ""),
                    "rationale": f"KEV re-match: {cve} product still "
                                 f"present on {agent}",
                })
                continue
            product = m.get("product") or ""
            vendor = m.get("vendorProject") or ""
            name = m.get("vulnerabilityName") or f"{vendor} {product}"
            cases.open_case(
                source={
                    "alert_id": "",  # no SIEM alert — intel-generated case
                    "agent": agent,
                    "rule_desc": f"KEV: {name}",
                    "rule_id": cve,   # CVE is the natural intel rule key
                    "category": "threat",
                    "level": 8,  # exploited-in-the-wild on our host
                    "backend": "intel",
                    "index": "cisa-kev",
                    "doc_id": cve,
                    "occurred_at": m.get("dateAdded") or "",
                    "intel": {
                        "cve_id": cve, "vendor": vendor, "product": product,
                        "date_added": m.get("dateAdded", ""),
                        "due_date": m.get("dueDate", ""),
                        "source_url": KEV_URL,
                    },
                },
                title=f"[INTEL] {cve} ({product}) present on {agent}",
                observables=[
                    {"type": "cve", "value": cve},
                    {"type": "product", "value": product},
                ],
                assignee="supervisory",
            )
            minted += 1
    return {"minted": minted}


def _open_intel_case(cases: Any, cve: str, agent: str) -> str | None:
    """Open case for this (CVE, agent) pair, if any — the intel dedupe key."""
    try:
        for c in cases.recent_host_cases(agent, window_s=None, open_only=True):
            src = c.get("source") or {}
            if src.get("backend") == "intel" and src.get("doc_id") == cve:
                return c["case_id"]
    except Exception:  # noqa: BLE001 — dedupe must never break intel
        return None
    return None


def run_intel(staging_dir: Path, ix: Any,
              kev_fetcher=fetch_kev, cases: Any | None = None) -> dict[str, Any]:
    """Full state machine: INGEST -> MATCH -> GENERATE -> STAGE -> ESCALATE.

    `cases` (a CaseStore) is optional for tests; when absent the registry
    provides it. Case minting is fail-open: a spine outage must not lose
    the staging report (it's retried next run; staging dedupe holds).
    """
    report: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(), "source": "cisa-kev"}
    try:
        kev = kev_fetcher()
        report["catalog_version"] = kev.get("catalogVersion")
        report["catalog_size"] = len(kev.get("vulnerabilities", []))
        products = fleet_products(ix)
        report["fleet_products"] = len(products)
        matches = match_kev(kev, products)
        report["matched"] = [m["cveID"] for m in matches]
        report.update(stage_packs(matches, staging_dir))
        if cases is None:
            from tools.registry import get_cases as _get_cases
            cases = _get_cases()
        try:
            report["cases"] = mint_match_cases(matches, cases)
        except Exception as e:  # noqa: BLE001 — spine down must not lose staging
            report["case_error"] = str(e)
    except Exception as e:  # noqa: BLE001 — intel failure must not break cadence
        report["error"] = str(e)
    return report
