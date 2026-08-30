"""Investigator — the investigative layer's correlation + hypothesis engine.

Given an escalated case (or a signal's observables), it:
1. Pulls the case's observables (srcip, dstip, domain, hash).
2. Correlates those entities ACROSS the BOTS sources (http/dns/winsec/suricata)
   — does this srcip appear in HTTP exfil, DNS tunneling, process exec?
3. Assembles a kill-chain hypothesis with an evidence trail (which source,
   what artifact, at what time).
4. Appends the hypothesis + evidence to the case timeline.

This is the "connect the kill chain" layer — recognition (the classifier)
feeds it signals; it turns them into an investigated, evidenced conclusion.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from typing import Any

from logging_setup import get_logger

logger = get_logger(__name__)


class Investigator:
    """Correlate entities across sources and build kill-chain hypotheses."""

    # Source -> (index, entity field, artifact field, threat label, threat query)
    # The correlation must match the THREAT PATTERN within each source, not
    # just any activity — otherwise every active host (and public DNS) looks
    # like "tunneling"/"exfil". threat_query filters to the attack shape.
    SOURCES = [
        ("http",   "bots-http-poc",    "c_ip",   "uri",
         "HTTP exfil/upload",  {"match_phrase": {"uri": "UploadData.aspx"}}),
        ("dns",    "bots-dns-poc",     "src_ip", "query",
         "DNS tunneling",      {"match_phrase": {"_raw": "NIMLOC"}}, 50),
        ("winsec", "bots-winsecurity", "_raw",   "_raw",
         "Process exec",       {"match_phrase": {"_raw": "New Process Name"}}),
        ("suricata","bots-suricata-poc", "src_ip", "_raw",
         "Network flow (context)", None),
    ]

    def __init__(self, indexer_host: str | None = None,
                 user: str | None = None, password: str | None = None) -> None:
        # Defaults from env/settings (never hardcoded — see config.py):
        # the indexer host/creds come from .env; transport.yaml per-backend
        # creds override when present.
        from config import settings
        if indexer_host is None:
            indexer_host = settings.indexer_host if settings.indexer_host not in ("", "localhost") else "192.168.1.75"
        if user is None:
            user = settings.indexer_user
        if password is None:
            password = settings.indexer_password
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self.host = indexer_host

        # LIVE-alert correlation: in addition to the replayed BOTS ground-truth
        # slices, correlate the entity against the LIVE alert stream so the
        # operational lab (real attacks into Wazuh/SO) shows up in evidence.
        # Resolve the alerts index from transport.yaml (backend-aware), like
        # indexer_client does — never hardcode the index name here.
        self.SOURCES = list(self.SOURCES)
        live_index = settings.alerts_index
        try:
            import yaml as _yaml
            from pathlib import Path as _Path
            tpath = _Path(__file__).resolve().parent / "transport.yaml"
            if tpath.exists():
                tcfg = _yaml.safe_load(tpath.read_text()) or {}
                backend = tcfg.get("backend", "wazuh")
                b = (tcfg.get("backends") or {}).get(backend, {})
                if b.get("alerts_index"):
                    live_index = b["alerts_index"]
        except Exception:  # noqa: BLE001 — transport resolution is best-effort
            pass
        # The live alert index is SUBDIVIDED by attack shape (each a distinct
        # source), not one broad bucket. Rationale: the evidence model scores
        # KILL-CHAIN BREADTH — an entity that scans AND beacons AND exfils is
        # stronger evidence than one with a pile of identical alerts. Every hit
        # in the alert index IS signal (an alert, not raw traffic), so each
        # source is min_count=1 with a shape-matching filter.
        # NOTE: rule.description is a keyword field in the alert index — match
        # shapes with wildcard, not match_phrase/query_string (both return 0).
        self.SOURCES.extend([
            ("live_scan", live_index, "data.src_ip", "rule.description",
             "Live network scan", {"wildcard": {"rule.description": "*STREAM*"}}, 1),
            ("live_threat", live_index, "data.src_ip", "rule.description",
             "Live threat-class alert",
             {"wildcard": {"rule.description": "*ET MALWARE*"}}, 1),
            ("live_http", live_index, "data.src_ip", "rule.description",
             "Live HTTP exfil", {"term": {"data.dest_port": 8080}}, 1),
            ("live_net", live_index, "data.src_ip", "rule.description",
             "Live network activity", None, 1),
        ])
        # Live sources correlate the entity in EITHER direction (src or dst):
        # a scan shows the entity as the STREAM alert's target (20->11) while
        # a beacon shows it as the source (11->20). The base query for these
        # sources is a should over both IP fields.
        self._live_both_directions = {"live_scan", "live_threat", "live_http", "live_net"}

    # --- query helpers ---
    def _search(self, index: str, body: dict[str, Any], port: int = 9200) -> dict[str, Any]:
        req = urllib.request.Request(
            f"https://{self.host}:{port}/{index}/_search",
            data=json.dumps(body).encode(),
            headers={"Authorization": self._auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=25, context=self._ctx) as resp:
            return json.loads(resp.read().decode())

    def correlate_entity(self, entity: str, entity_type: str = "ip",
                         limit_per_source: int = 5,
                         window_hours: float = 0.0) -> list[dict[str, Any]]:
        """Find where this entity appears across the BOTS sources.

        `window_hours` > 0 restricts each source to events in that window
        (relative to now) — temporal correlation. Returns evidence with a
        per-source score (how engaged the entity is in that source).
        """
        evidence = []
        for entry in self.SOURCES:
            # Unpack: (name, index, field, artifact, label, threat_query[, min_count])
            src_name, index, field, artifact_field, label, threat_query = entry[:6]
            min_count = entry[6] if len(entry) > 6 else 0
            try:
                # Base query: entity match in this source's entity field
                if src_name == "winsec":
                    base_q = {"match_phrase": {"_raw": entity}}
                elif src_name in self._live_both_directions:
                    # Live alerts: the entity may be the source OR the target
                    # (a scan shows the entity as the STREAM alert's target).
                    base_q = {"bool": {"should": [
                        {"term": {"data.src_ip": entity}},
                        {"term": {"data.dest_ip": entity}},
                    ]}}
                else:
                    base_q = {"term": {field: entity}}
                # Combine with the threat-pattern filter so only the ATTACK
                # shape correlates (not benign activity from the entity).
                must = [base_q]
                if threat_query:
                    must.append(threat_query)
                query: dict[str, Any] = {"bool": {"must": must}}
                if window_hours > 0:
                    query["bool"]["filter"] = [{"range": {"@timestamp": {
                        "gte": f"now-{int(window_hours*3600)}s"}}}]
                body = {"size": limit_per_source, "query": query,
                        "_source": [artifact_field, "@timestamp"]}
                r = self._search(index, body)
                hits = r.get("hits", {}).get("hits", [])
                total = int(r.get("hits", {}).get("total", {}).get("value", 0))
                count = total or len(hits)
                # Weak signals (below min_count) don't score — avoids a few
                # incidental NIMLOC queries ranking a host as a tunnel source.
                if count >= min_count and count > 0:
                    evidence.append({
                        "source": src_name,
                        "index": index,
                        "entity": entity,
                        "count": count,
                        "label": label,
                        "samples": [h.get("_source", {}).get(artifact_field, "") for h in hits[:2]],
                    })
            except Exception as e:  # noqa: BLE001 — correlation is best-effort
                logger.warning("correlate %s failed: %s", src_name, e)
        return evidence

    def investigate(self, srcip: str = "", dstip: str = "", domain: str = "",
                    entities: list[str] | None = None) -> dict[str, Any]:
        """Investigate entities across sources -> kill-chain hypothesis.

        Returns {entities, evidence, hypothesis, kill_chain} where kill_chain
        lists the correlated stages in MITRE-ish order (initial access ->
        execution -> C2 -> exfil).
        """
        ents = list(entities or [])
        if srcip and srcip not in ents:
            ents.append(srcip)
        if dstip and dstip not in ents:
            ents.append(dstip)
        if domain and domain not in ents:
            ents.append(domain)

        all_evidence = []
        for e in ents:
            all_evidence.extend(self.correlate_entity(e))

        # Build the kill-chain from which sources have evidence
        src_set = {ev["source"] for ev in all_evidence}
        stages = []
        # rough kill-chain ordering: process exec (execution) -> http (exfil) -> dns (c2)
        if "winsec" in src_set:
            stages.append("EXECUTION: process artifacts in Windows security logs")
        if "http" in src_set or "live_http" in src_set:
            stages.append("EXFILTRATION: HTTP upload/exfil traffic")
        if "dns" in src_set:
            stages.append("C2: DNS queries/tunneling")
        if "live_threat" in src_set:
            stages.append("C2/MALWARE: threat-class live alert")
        if "suricata" in src_set or "live_scan" in src_set:
            stages.append("RECON: network scan / suricata flow observed")
        if "live_net" in src_set:
            stages.append("NETWORK: live alert activity on entity")
        if not stages:
            stages.append("NO CORRELATION: entity not observed across sources (isolated signal)")

        # ENTITY SCORING: rank engagement per source + overall.
        # score = log-scaled evidence volume (base-10), so 10 events = 1,
        # 100 = 2, 1000 = 3. Kill-chain breadth adds weight (more sources =
        # more of the chain touched).
        # THREAT-PATTERN sources (http exfil, dns tunnel, process exec) drive
        # severity; the suricata flow source is generic CONTEXT and should
        # not inflate it — so it's down-weighted.
        import math
        CONTEXT_SOURCES = {"suricata"}
        threat_evidence = [ev for ev in all_evidence if ev["source"] not in CONTEXT_SOURCES]
        for ev in all_evidence:
            ev["score"] = round(math.log10(max(ev["count"], 1)), 2)
        breadth = len({ev["source"] for ev in all_evidence})
        # severity driven by THREAT evidence; context adds at most a small nudge
        base = sum(ev["score"] for ev in threat_evidence)
        ctx = sum(ev["score"] for ev in all_evidence if ev["source"] in CONTEXT_SOURCES)
        severity = round(base + min(ctx * 0.2, 1.0) + (breadth - 1), 2) if all_evidence else 0.0
        # severity bands: <2 low, 2-4 medium, >4 high
        if severity >= 4:
            sev_label = "high"
        elif severity >= 2:
            sev_label = "medium"
        else:
            sev_label = "low"

        hypothesis = (
            f"Entity {'/'.join(ents) or '(none)'} engaged across "
            f"{breadth} source(s): {', '.join(sorted(src_set)) or 'none'}. "
            f"Kill-chain: {' -> '.join(stages)}. "
            f"Engagement score {severity} ({sev_label})."
        )
        return {
            "entities": ents,
            "evidence": all_evidence,
            "kill_chain": stages,
            "hypothesis": hypothesis,
            "correlated_sources": sorted(src_set),
            "severity": severity,
            "severity_label": sev_label,
        }

    def summarize(self, result: dict[str, Any]) -> str:
        """One-block text summary of an investigation for the case timeline."""
        lines = [f"HYPOTHESIS: {result['hypothesis']}"]
        for ev in result["evidence"]:
            art = " | ".join(str(s)[:40] for s in ev.get("samples", [])[:2])
            lines.append(f"  [{ev['source']:<8}] {ev['label']}: {ev['count']} events "
                         f"(score {ev.get('score', '?')}) {art}")
        return "\n".join(lines)
