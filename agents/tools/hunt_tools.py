"""Hunt role tools: proactive, hypothesis-driven queries against the SIEM.

The hunter is NOT alert-reactive (that's the analyst). It tests hypotheses
against the telemetry, looking for patterns that suggest compromise,
misconfiguration, or blind spots. Read-only: it never touches infrastructure.
Output: hunt findings + detection recommendations -> case spine + escalation.

Hygiene: config-driven (config.py), shared indexer client, imports at top.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

from config import settings
from tools.indexer_client import IndexerClient, IndexerError

logger = logging.getLogger(__name__)


def load_hunts(hunts_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load hunt definitions from YAML files in the hunts directory.

    One file per hunt (filename stem = hunt_id). Adding a hunt = dropping a
    file — no code change (per review: data-driven, not hardcoded).
    """
    hunts: Dict[str, Dict[str, Any]] = {}
    if not hunts_dir.exists():
        logger.warning("hunts dir %s not found — empty hunt library", hunts_dir)
        return hunts
    for f in sorted(hunts_dir.glob("*.yaml")) + sorted(hunts_dir.glob("*.yml")):
        try:
            with open(f, encoding="utf-8") as fh:
                spec = yaml.safe_load(fh)
            if not isinstance(spec, dict) or "name" not in spec:
                logger.warning("skipping invalid hunt file %s (missing name)", f)
                continue
            if "analyze" not in spec:
                spec["analyze"] = "generic"
            hunts[f.stem] = spec
            logger.debug("loaded hunt %s from %s", f.stem, f.name)
        except (yaml.YAMLError, OSError) as e:
            logger.warning("failed to load hunt %s: %s", f, e)
    return hunts


class HuntClient:
    """Read-only pattern queries against the Wazuh indexer."""

    def __init__(self, indexer: IndexerClient | None = None) -> None:
        self._indexer = indexer or IndexerClient()

    # --- hunt library (data-driven: loaded from YAML files in hunts/) ---
    HUNTS: Dict[str, Dict[str, Any]] = load_hunts(settings.hunts_dir)

    def run_hunt(self, hunt_id: str, days: int = 7) -> Dict[str, Any]:
        """Execute a hunt from the library and analyze the results."""
        if hunt_id not in self.HUNTS:
            raise ValueError(f"Unknown hunt: {hunt_id}. Available: {list(self.HUNTS)}")
        spec = self.HUNTS[hunt_id]
        query = json.loads(json.dumps(spec["query"]))  # deep copy
        # Time-bind the hunt — use the transport's timestamp field mapping
        # (bots/securityonion map to @timestamp; wazuh keeps timestamp).
        ts_field = getattr(self._indexer, "field_timestamp", "timestamp")
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        query["query"]["bool"]["filter"].append(
            {"range": {ts_field: {"gte": since}}}
        )
        try:
            data = self._indexer.search(query)
        except IndexerError as e:
            logger.error("hunt %s failed: %s", hunt_id, e)
            raise
        hits = data.get("hits", {}).get("hits", [])
        docs = [h.get("_source", {}) for h in hits]
        analyzer = getattr(self, f"_analyze_{spec['analyze']}", self._analyze_generic)
        result = analyzer(docs, spec)
        result.update({
            "hunt_id": hunt_id,
            "name": spec["name"],
            "category": spec["category"],
            "hypothesis": spec["hypothesis"],
            "window_days": days,
            "events_scanned": data.get("hits", {}).get("total", {}).get("value", len(docs)),
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        logger.info("hunt %s: finding=%s (%d docs)", hunt_id, result.get("finding"), len(docs))
        return result

    # --- analyzers ---

    def _analyze_generic(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        agents = sorted({d.get("agent", {}).get("name", "?") for d in docs})
        return {
            "finding": "info" if docs else "clean",
            "confidence": "low" if docs else "high",
            "summary": f"{len(docs)} events across agents {agents}",
            "detail": docs[:5],
        }

    def _analyze_bots_attack(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzer for the BOTS ground-truth hunts.

        A BOTS hunt confirms an attack when it finds events matching the
        published scenario (UploadData.aspx exfil, xmfir0 C2 DNS, the Cerber
        drop process). Finding is 'suspicious' (escalatable) when real
        evidence exists — matching the ground-truth validation the parser +
        full loop already proved. Requires >=1 hit to confirm.
        """
        if not docs:
            return {"finding": "clean", "confidence": "high",
                    "summary": "no events matched the BOTS attack pattern",
                    "detail": []}
        srcs = sorted({str(d.get("c_ip") or d.get("src_ip") or d.get("Computer") or "?") for d in docs})
        return {
            "finding": "suspicious",
            "confidence": "high",
            "summary": f"{len(docs)} events confirm the BOTS attack pattern (srcs: {srcs[:3]})",
            "detail": docs[:5],
        }

    def _analyze_srcip_frequency(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        ips = Counter()
        users = Counter()
        for d in docs:
            dd = d.get("data", {})
            # Live Wazuh varies the key: sshd auths carry data.srcip, scan/
            # STREAM alerts carry data.src_ip — read both for parity.
            ip = dd.get("srcip") or dd.get("src_ip") or "?"
            user = dd.get("dstuser", "?")
            ips[ip] += 1
            users[user] += 1
        top_ips = ips.most_common(10)
        top_users = users.most_common(10)
        finding = "clean"
        notes = []
        # A single IP doing many auths, or auth from non-VM IPs, is suspicious
        for ip, cnt in top_ips:
            if cnt >= 20:
                finding = "suspicious"
                notes.append(f"source {ip} has {cnt} auth successes (possible credential abuse)")
        if len(ips) > 5:
            notes.append(f"{len(ips)} distinct source IPs authenticating (broad access surface)")
        return {
            "finding": finding,
            "confidence": "medium" if finding == "suspicious" else "high",
            "summary": f"{len(docs)} auth successes, {len(ips)} distinct source IPs, {len(users)} users",
            "top_sources": top_ips,
            "top_users": top_users,
            "notes": notes,
            "detail": docs[:5],
        }

    def _analyze_apparmor(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        agents = {}
        for d in docs:
            a = d.get("agent", {}).get("name", "?")
            agents[a] = agents.get(a, 0) + 1
        finding = "suspicious" if len(docs) >= 50 else ("info" if docs else "clean")
        return {
            "finding": finding,
            "confidence": "medium" if finding == "suspicious" else "high",
            "summary": f"{len(docs)} AppArmor denials across {agents}",
            "by_agent": agents,
            "detail": docs[:5],
        }

    def _analyze_rootcheck(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        files = Counter()
        for d in docs:
            f = d.get("data", {}).get("file") or d.get("full_log", "")[:80]
            files[f] += 1
        # Recurring same-file flags = likely FP noise; unique high-count new = real
        recurring = {f: c for f, c in files.items() if c >= 3}
        finding = "info" if recurring else ("suspicious" if docs else "clean")
        return {
            "finding": finding,
            "confidence": "medium",
            "summary": f"{len(docs)} rootcheck events; {len(recurring)} recurring paths (likely FP noise)",
            "recurring_paths": recurring,
            "detail": docs[:5],
        }

    def _analyze_sca(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        rules = Counter()
        for d in docs:
            r = d.get("rule", {}).get("id", "?")
            rules[r] += 1
        finding = "info" if docs else "clean"
        return {
            "finding": finding,
            "confidence": "medium",
            "summary": f"{len(docs)} CIS benchmark findings ({len(rules)} distinct rules)",
            "top_rules": rules.most_common(8),
            "detail": docs[:5],
        }

    def _analyze_sudo(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        users = Counter()
        for d in docs:
            u = d.get("data", {}).get("dstuser", "?")
            users[u] += 1
        finding = "info" if docs else "clean"
        return {
            "finding": finding,
            "confidence": "medium",
            "summary": f"{len(docs)} sudo events by users {users}",
            "by_user": users,
            "detail": docs[:5],
        }
