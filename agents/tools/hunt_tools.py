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
            "technique_id": spec.get("technique_id"),  # optional MITRE ID on the hunt definition
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
        """AppArmor denial analysis — PROFILE/COMM aware, not raw volume.

        Chronic-FP class (verified Aug-Sep 2026, all stock Ubuntu): rule
        52002 fires on normal stock-profile enforcement — fusermount3
        (capable dac_override/setuid, caps commented out by design),
        unprivileged_userns (CVE-2023-2640 mitigation, ubuntu-insights
        telemetry), snap-update-ns (snap mount namespace setup). A raw
        >=50 threshold flags these as evasion every run.

        REAL evasion signal: class=exec denials, unknown profiles/comms,
        load/unload/change_profile operations, or a NEW/unknown profile
        name. Volume alone is NOT signal.
        """
        import re as _re
        profiles = Counter()
        comms = Counter()
        classes = Counter()
        operations = Counter()
        unknown = []
        for d in docs:
            fl = d.get("full_log", "") or ""
            m = _re.search(r'profile="([^"]+)"', fl)
            prof = m.group(1) if m else "?"
            m = _re.search(r'comm="([^"]+)"', fl)
            comm = m.group(1) if m else "?"
            m = _re.search(r'class="([^"]+)"', fl)
            cls = m.group(1) if m else "?"
            m = _re.search(r'operation="([^"]+)"', fl)
            op = m.group(1) if m else "?"
            profiles[prof] += 1
            comms[comm] += 1
            classes[cls] += 1
            operations[op] += 1
            if cls == "exec" or prof in ("?", "unconfined") or \
               op in ("load", "unload", "change_profile", "exec"):
                unknown.append({"profile": prof, "comm": comm, "class": cls,
                                "op": op, "full_log": fl[:200]})
        # Known-benign stock profiles/comms (verified taxonomy). Profile
        # names arrive as full paths (e.g. /snap/snapd/27710/.../snap-confine)
        # — match on the basename so stock profiles never look unknown.
        import posixpath as _pp
        benign_basenames = {"fusermount3", "unprivileged_userns",
                            "snap-update-ns.firmware-updater", "snap-confine",
                            "cupsd", "firmware-notifier", "unpr"}
        def _benign(prof: str) -> bool:
            base = _pp.basename(prof.rstrip("/"))
            return base in benign_basenames
        suspicious = (classes.get("exec", 0) > 0
                      or any(not _benign(p) for p in profiles
                             if p not in ("?", ""))
                      or len(unknown) > 0
                      or (operations.get("load", 0) + operations.get("unload", 0)
                          + operations.get("change_profile", 0)) > 0)
        finding = "suspicious" if suspicious else "info"
        return {
            "finding": finding,
            "confidence": "high" if suspicious else "high",
            "summary": (f"{len(docs)} AppArmor denials; profiles={dict(profiles.most_common(4))} "
                        f"| comms={dict(comms.most_common(4))} | classes={dict(classes)} "
                        f"| suspicious_signals={len(unknown)}"),
            "by_profile": dict(profiles),
            "by_comm": dict(comms),
            "by_class": dict(classes),
            "suspicious_signals": unknown[:10],
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

    def _analyze_so_severity(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzer for SO high-severity alerts (event.severity >= 3).

        The hunt query already filtered on the raw event.severity; docs here
        are the normalized spine shape (rule.level mapped 1-4 -> 0-15, plus
        top-level srcip/dstip when the ECS normalization fired). Any doc
        present is a high-severity alert worth surfacing.
        """
        if not docs:
            return {"finding": "clean", "confidence": "high",
                    "summary": "no high-severity SO alerts in window", "detail": []}
        descs = Counter()
        pairs = Counter()
        for d in docs:
            desc = (d.get("rule") or {}).get("description") or "?"
            descs[desc] += 1
            ed = d.get("event_data") or {}
            # SO detections wrap the entity pair under event_data.*; the
            # top-level srcip/dstip only exists for the suricata shape.
            src = (d.get("srcip") or (d.get("source") or {}).get("ip")
                   or (ed.get("source") or {}).get("ip") or "?")
            dst = (d.get("dstip") or (d.get("destination") or {}).get("ip")
                   or (ed.get("destination") or {}).get("ip") or "?")
            pairs[(str(src), str(dst))] += 1
        top = descs.most_common(5)
        notes = [f"{desc} x{cnt}" for desc, cnt in top]
        top_pairs = pairs.most_common(3)
        notes.append("pairs: " + ", ".join(f"{s}->{d} x{c}" for (s, d), c in top_pairs))
        return {
            "finding": "suspicious",
            "confidence": "medium",
            "summary": f"{len(docs)} high-severity SO alerts ({len(descs)} distinct rules)",
            "notes": notes,
            "detail": docs[:5],
        }

    def _analyze_so_detection(self, docs: List[Dict[str, Any]], spec: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzer for SO detection-framework hits (Sigma envelope docs).

        These docs carry event_data.* (the wrapped original event) with
        num_matches/num_hits, plus top-level rule.description/sigma_level.
        A detection-framework match is a finding by definition.
        """
        if not docs:
            return {"finding": "clean", "confidence": "high",
                    "summary": "no SO detection-framework hits in window", "detail": []}
        descs = Counter()
        total_matches = 0
        for d in docs:
            desc = (d.get("rule") or {}).get("description") or "?"
            descs[desc] += 1
            ed = d.get("event_data") or {}
            total_matches += int(ed.get("num_matches") or 0)
        top = descs.most_common(5)
        notes = [f"{desc} x{cnt}" for desc, cnt in top]
        notes.append(f"total embedded matches: {total_matches}")
        return {
            "finding": "suspicious",
            "confidence": "medium",
            "summary": f"{len(docs)} SO detection-framework hits ({len(descs)} distinct rules)",
            "notes": notes,
            "detail": docs[:5],
        }
