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

import yaml

from logging_setup import get_logger

logger = get_logger(__name__)

# Kill-chain stage -> MITRE technique IDs, derived from the evidence source
# set (deterministic, data-driven). Each stage is annotated with the
# technique(s) MITRE maps to that behavior so cases carry real technique
# IDs (TXXXX) — the advisory renders them as a CISA-style per-technique
# table instead of falling back to the kill-chain->tactic heuristic.
# Grounded in attack.mitre.org v19 (verified 2026-09-02):
#   T1059      Command and Scripting Interpreter (Execution)
#   T1110      Brute Force (Credential Access)
#   T1041      Exfiltration Over C2 Channel (Exfiltration)
#   T1048.003  Exfiltration Over Unencrypted Non-C2 Protocol (Exfiltration)
#   T1071.004  Application Layer Protocol: DNS (Command and Control)
#   T1572      Protocol Tunneling (Command and Control)
#   T1046      Network Service Discovery (Discovery)
#   T1021      Remote Services (Lateral Movement)
_SOURCE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "winsec": ("T1059",),
    "live_brute": ("T1110",),
    "http": ("T1041", "T1048.003"),
    "live_http": ("T1041", "T1048.003"),
    "dns": ("T1071.004", "T1572"),
    "suricata": ("T1046",),
    "live_scan": ("T1046",),
    "live_net": ("T1021",),
}


def _tag(stage: str, *tids: str) -> str:
    """Append MITRE technique IDs to a stage label, e.g.
    'C2: DNS queries/tunneling [T1071.004, T1572]'."""
    if not tids:
        return stage
    return f"{stage} [{', '.join(tids)}]"


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
        # Resolve the ACTIVE backend from transport.yaml ONCE — its endpoint
        # (host), creds, alerts_index, and raw-rule-field name. Explicit
        # constructor args (used by the two-backend harnesses) override.
        # Defaults otherwise follow the transport, NOT settings — the
        # Investigator must talk to whichever SIEM the spine is running
        # against (parity, not a special case).
        from config import settings
        self._backend_cfg: dict = {}
        try:
            tpath = settings.hunts_dir.parent / "transport.yaml"
            if tpath.exists():
                tcfg = yaml.safe_load(tpath.read_text()) or {}
                self._backend = tcfg.get("backend", "wazuh")
                self._backend_cfg = (tcfg.get("backends") or {}).get(self._backend, {}) or {}
        except Exception:  # noqa: BLE001 — transport resolution is best-effort
            self._backend = "wazuh"
        if indexer_host is None:
            ep = self._backend_cfg.get("endpoint") or ""
            if ep:
                indexer_host = ep.replace("https://", "").replace("http://", "").split(":")[0]
            if not indexer_host:
                indexer_host = settings.indexer_host if settings.indexer_host not in ("", "localhost") else "192.168.1.75"
        if user is None:
            user = self._backend_cfg.get("user") or settings.indexer_user
        if password is None:
            password = self._backend_cfg.get("password")
            if not password:
                password = settings.so_indexer_password if self._backend == "securityonion" else settings.indexer_password
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
        self._live_desc_field = "rule.description"  # wazuh stores it here
        if self._backend_cfg.get("alerts_index"):
            live_index = self._backend_cfg["alerts_index"]
        # SO raw alerts store the rule title under rule.name (the read-time
        # normalize() aliases it to rule.description); wildcard filters must
        # query the RAW field.
        if self._backend == "securityonion":
            self._live_desc_field = "rule.name"
        # The live alert index is SUBDIVIDED by attack shape (each a distinct
        # source), not one broad bucket. Rationale: the evidence model scores
        # KILL-CHAIN BREADTH — an entity that scans AND beacons AND exfils is
        # stronger evidence than one with a pile of identical alerts. Every hit
        # in the alert index IS signal (an alert, not raw traffic), so each
        # source is min_count=1 with a shape-matching filter.
        # NOTE: rule.description is a keyword field in the alert index — match
        # shapes with wildcard, not match_phrase/query_string (both return 0).
        _d = self._live_desc_field
        self.SOURCES.extend([
            ("live_scan", live_index, "data.src_ip", _d,
             "Live network scan", {"wildcard": {_d: "*STREAM*"}}, 1),
            ("live_threat", live_index, "data.src_ip", _d,
             "Live threat-class alert",
             {"wildcard": {_d: "*ET MALWARE*"}}, 1),
            ("live_brute", live_index, "data.src_ip", _d,
             "Live brute-force / login failure",
             {"wildcard": {_d: "*Login Failure*"}}, 1),
            ("live_http", live_index, "data.src_ip", _d,
             "Live HTTP exfil", {"term": {"data.dest_port": 8080}}, 1),
            ("live_net", live_index, "data.src_ip", _d,
             "Live network activity", None, 1),
        ])
        # Live sources correlate the entity in EITHER direction (src or dst):
        # a scan shows the entity as the STREAM alert's target (20->11) while
        # a beacon shows it as the source (11->20). The base query for these
        # sources is a should over both IP fields.
        self._live_both_directions = {"live_scan", "live_threat", "live_http", "live_net", "live_brute"}

        # Backend-aware entity fields for the live sources. Wazuh stores the
        # entity pair as data.src_ip/data.dest_ip; Security Onion stores ECS
        # source.ip/destination.ip (suricata) and wraps the original event
        # under event_data.* (detections envelope) — the entity can be in any
        # of these shapes. Query all stored shapes so live correlation works
        # on both backends (parity, not a special case).
        self._entity_pairs = [("data.src_ip", "data.dest_ip")]  # wazuh shape
        self._dest_port_field = "data.dest_port"
        try:
            from config import settings as _s
            # transport.yaml lives next to the config module (agents/ dir),
            # same convention as indexer_client.TRANSPORT_FILE.
            tpath = _s.hunts_dir.parent / "transport.yaml"
            if tpath.exists():
                tcfg = yaml.safe_load(tpath.read_text()) or {}
                if (tcfg.get("backend") or "") == "securityonion":
                    self._entity_pairs = [
                        ("source.ip", "destination.ip"),
                        ("event_data.source.ip", "event_data.destination.ip"),
                    ]
                    self._dest_port_field = "destination.port"
                    # live_http matches the dest-port in the backend's shape
                    for i, src in enumerate(self.SOURCES):
                        if src[0] == "live_http":
                            s, idx, field, art, label, tq, mc = src
                            self.SOURCES[i] = (s, idx, field, art, label,
                                               {"term": {self._dest_port_field: 8080}}, mc)
                            break
        except Exception:  # noqa: BLE001 — transport resolution is best-effort
            pass

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
                    # Query every entity-pair field the backend may store the
                    # pair in (Wazuh data.src_ip/data.dest_ip; SO ECS
                    # source.ip/destination.ip + event_data envelope).
                    should = []
                    for sf, df in self._entity_pairs:
                        should.append({"term": {sf: entity}})
                        should.append({"term": {df: entity}})
                    base_q = {"bool": {"should": should}}
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

        # Build the kill-chain from which sources have evidence. Each stage
        # carries the MITRE technique ID(s) for that behavior (see
        # _SOURCE_TECHNIQUES) so cases persist real technique IDs and the
        # advisory renders a per-technique table instead of the stage->
        # tactic heuristic. C2/MALWARE (live_threat) and NO CORRELATION
        # stay untagged: a class-level signal and an absence of evidence
        # have no honest single technique.
        src_set = {ev["source"] for ev in all_evidence}
        stages = []
        # rough kill-chain ordering: process exec (execution) -> http (exfil) -> dns (c2)
        if "winsec" in src_set:
            stages.append(_tag("EXECUTION: process artifacts in Windows security logs",
                               *_SOURCE_TECHNIQUES["winsec"]))
        if "live_brute" in src_set:
            stages.append(_tag("INITIAL ACCESS: brute-force / login-failure pattern",
                               *_SOURCE_TECHNIQUES["live_brute"]))
        if "http" in src_set or "live_http" in src_set:
            stages.append(_tag("EXFILTRATION: HTTP upload/exfil traffic",
                               *_SOURCE_TECHNIQUES["http"]))
        if "dns" in src_set:
            stages.append(_tag("C2: DNS queries/tunneling",
                               *_SOURCE_TECHNIQUES["dns"]))
        if "live_threat" in src_set:
            stages.append("C2/MALWARE: threat-class live alert")
        if "suricata" in src_set or "live_scan" in src_set:
            stages.append(_tag("RECON: network scan / suricata flow observed",
                               *_SOURCE_TECHNIQUES["suricata"]))
        if "live_net" in src_set:
            stages.append(_tag("NETWORK: live alert activity on entity",
                               *_SOURCE_TECHNIQUES["live_net"]))
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
