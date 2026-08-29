"""Intel role tools: threat-intel ingestion, fleet matching, hunt-pack generation.

The intel role reads advisories (CISA KEV + NVD), matches them against fleet
inventory (Wazuh syscollector states indices), and generates hunt packs as
YAML in a staging area for human/supervisory review.

Flow: INGEST -> MATCH -> GENERATE -> STAGE -> (PROMOTE after review)
Per wayfinder ticket hunt-pack-schema: packs are valid hunt YAML targeting
the inventory indices; quality gate = environment match + dedupe +
staging-review.

Hygiene: config-driven (config.py), registry singletons, logging, imports at top.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from config import settings
from logging_setup import get_logger
from tools.indexer_client import IndexerClient

logger = get_logger(__name__)


class IntelError(RuntimeError):
    """Raised when intel ingestion fails."""


class IntelClient:
    """Threat-intel ingestion + hunt-pack generation."""

    def __init__(self, indexer: IndexerClient | None = None) -> None:
        self._indexer = indexer or IndexerClient()
        self.kev_url = settings.kev_url
        self.nvd_url = settings.nvd_url
        self.staging_dir: Path = settings.hunt_staging_dir
        self.hunts_dir: Path = settings.hunts_dir
        self.inventory_index = settings.inventory_index

    # --- INGEST ---

    def fetch_kev(self) -> list[dict[str, Any]]:
        """Fetch the CISA KEV catalog (one GET, no auth)."""
        try:
            with urllib.request.urlopen(self.kev_url, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.error("KEV fetch failed: %s", e)
            raise IntelError(f"KEV fetch failed: {e}") from e
        vulns = data.get("vulnerabilities", [])
        logger.info("KEV: %d entries (version %s)", len(vulns), data.get("catalogVersion"))
        return vulns

    def fetch_nvd_since(self, days: int = 1) -> list[dict[str, Any]]:
        """Fetch NVD CVEs published in the last N days (keyless date-range)."""
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
        end = now.strftime("%Y-%m-%dT00:00:00.000")
        url = f"{self.nvd_url}?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.error("NVD fetch failed: %s", e)
            raise IntelError(f"NVD fetch failed: {e}") from e
        vulns = data.get("vulnerabilities", [])
        logger.info("NVD: %d CVEs published in last %d days", len(vulns), days)
        return vulns

    # --- MATCH (fleet inventory) ---

    def inventory_products(self) -> dict[str, list[str]]:
        """Return {agent_name: [package names]} from the inventory indices.

        Queries wazuh-states-inventory-packages-* directly (the states
        indices, NOT wazuh-alerts-* — per the fleet-inventory ticket).
        """
        body = {
            "size": 10000,
            "_source": ["agent.name", "package.name"],
            "query": {"match_all": {}},
        }
        try:
            data = self._indexer.search(body, index=self.inventory_index)
        except Exception as e:
            logger.error("inventory query failed: %s", e)
            raise IntelError(f"inventory query failed: {e}") from e
        by_agent: dict[str, list[str]] = {}
        for h in data.get("hits", {}).get("hits", []):
            src = h.get("_source", {})
            agent = src.get("agent", {}).get("name", "?")
            pkg = src.get("package", {}).get("name", "")
            if pkg:
                by_agent.setdefault(agent, []).append(pkg.lower())
        logger.info("inventory: %d agents, %d packages total",
                    len(by_agent), sum(len(v) for v in by_agent.values()))
        return by_agent

    def match_kev_to_inventory(self, kev_entries: list[dict[str, Any]],
                               inventory: dict[str, list[str]]) -> list[dict[str, Any]]:
        """Match KEV entries against fleet packages (product name match).

        Environment-match filter: a KEV entry survives only if its product
        appears in ANY agent's package list. Returns matched entries with
        matched_agents attached.
        """
        matched = []
        for entry in kev_entries:
            product = (entry.get("product") or "").lower()
            if not product:
                continue
            # WORD-BOUNDARY match: product matches a package name exactly or
            # as a whole token (e.g. "ray" matches "ray" but not "raycast";
            # "core" doesn't match every kernel package). Prevents the
            # substring flood (342 packs) while catching real products.
            hit_agents = [
                a for a, pkgs in inventory.items()
                if any(
                    p == product
                    or re.search(rf"(^|[^a-z0-9]){re.escape(product)}($|[^a-z0-9])", p)
                    for p in pkgs
                )
            ]
            if hit_agents:
                entry = dict(entry)
                entry["matched_agents"] = hit_agents
                matched.append(entry)
        logger.info("matched %d of %d KEV entries to fleet inventory",
                    len(matched), len(kev_entries))
        return matched

    # --- GENERATE ---

    def generate_pack(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Build a hunt pack (valid hunt YAML) from a matched KEV entry."""
        cve_id = entry.get("cveID", "cve-unknown")
        product = entry.get("product", "unknown")
        slug = re.sub(r"[^a-z0-9]+", "-", f"{cve_id}-{product}".lower()).strip("-")
        hypothesis = (
            f"Exploited {cve_id} ({product}) may be present — "
            f"checking fleet inventory for the vulnerable product"
        )
        pack = {
            "name": slug,
            "category": "threat",
            "hypothesis": hypothesis,
            "analyze": "generic",
            "query": {
                "size": 100,
                "query": {"bool": {"filter": [
                    {"match": {"package.name": product}}
                ]}},
                "_source": ["timestamp", "agent.name", "package"],
            },
            "meta": {
                "cve_id": cve_id,
                "source": "cisa-kev",
                "matched_agents": entry.get("matched_agents", []),
                "cvss": entry.get("cvss", ""),
                "date_added": entry.get("dateAdded", ""),
            },
        }
        return pack

    # --- STAGE ---

    def stage_pack(self, pack: dict[str, Any]) -> Path | None:
        """Write a generated pack to the staging area (dedupe by cve_id).

        Returns the path if written, None if a pack for the same CVE already
        exists (in staging or the live library) — the dedupe gate.
        """
        cve_id = pack.get("meta", {}).get("cve_id", "")
        # dedupe: existing staging pack with same cve_id?
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        for f in self.staging_dir.glob("*.yaml"):
            try:
                existing = yaml.safe_load(f.read_text())
                if existing.get("meta", {}).get("cve_id") == cve_id:
                    logger.info("dedupe: %s already staged (%s)", cve_id, f.name)
                    return None
            except (yaml.YAMLError, OSError):
                continue
        # dedupe: live library pack with same cve_id?
        for f in self.hunts_dir.glob("*.yaml"):
            try:
                existing = yaml.safe_load(f.read_text())
                if existing.get("meta", {}).get("cve_id") == cve_id:
                    logger.info("dedupe: %s already live (%s)", cve_id, f.name)
                    return None
            except (yaml.YAMLError, OSError):
                continue
        path = self.staging_dir / f"{pack['name']}.yaml"
        path.write_text(yaml.safe_dump(pack, sort_keys=False))
        logger.info("staged hunt pack %s (%s)", path.name, cve_id)
        return path

    # --- main flow ---

    def run(self, days: int = 1, dry_run: bool = False) -> dict[str, Any]:
        """INGEST -> MATCH -> GENERATE -> STAGE. Returns a report."""
        report = {"ts": datetime.now(timezone.utc).isoformat(), "fetched": 0,
                  "matched": 0, "staged": 0, "deduped": 0, "packs": []}
        try:
            kev = self.fetch_kev()
            report["fetched"] = len(kev)
            inventory = self.inventory_products()
            matched = self.match_kev_to_inventory(kev, inventory)
            report["matched"] = len(matched)
            for entry in matched:
                pack = self.generate_pack(entry)
                if dry_run:
                    report["packs"].append({"cve": entry.get("cveID"), "pack": pack["name"]})
                    report["staged"] += 1
                else:
                    path = self.stage_pack(pack)
                    if path:
                        report["staged"] += 1
                        report["packs"].append({"cve": entry.get("cveID"), "path": str(path)})
                    else:
                        report["deduped"] += 1
        except IntelError as e:
            report["error"] = str(e)
            logger.error("intel run failed: %s", e)
        report["summary"] = (f"fetched={report['fetched']} matched={report['matched']} "
                             f"staged={report['staged']} deduped={report['deduped']}")
        return report
