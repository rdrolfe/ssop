"""BOTSv1 document normalizer — map any BOTS doc into the ontology alert shape.

The BOTSv1 sourcetypes carry their data in source-specific fields:
  - suricata: `_raw` = Suricata EVE JSON (event_type, src_ip/dest_ip, dns.*,
    tls.*, alert.* when present)
  - stream:http: uri / c_ip / method / action / bytes
  - WinEventLog/Sysmon: EventCode / Computer / Image / SourceIp / DestinationIp
  - stream:dns: query / answer / src_ip / dest_ip
This normalizer extracts the ontology-relevant fields (srcip, dstip, rule
description, category hints, timestamp) into the shape `analyst.verdict()`
expects, so the analyst can classify ANY BOTS event regardless of source.

The transport field ontology (transport.yaml) still applies on top — this
is the per-source adapter that the transport's per-backend fields don't cover.
"""
from __future__ import annotations

import json
from typing import Any

from logging_setup import get_logger

logger = get_logger(__name__)


def _parse_raw(src: dict[str, Any]) -> dict[str, Any] | None:
    """Parse the Suricata EVE JSON from _raw (if present)."""
    raw = src.get("_raw") or src.get("raw")
    if not raw:
        return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
    if isinstance(raw, dict):
        return raw
    return None


def _normalize_http(src: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    """Normalize a BOTS HTTP-stream doc into the ontology alert shape."""
    alert["srcip"] = src.get("c_ip") or src.get("src_ip")
    alert["dstip"] = src.get("s_ip") or src.get("dest_ip")
    alert["uri"] = src.get("uri", "")
    alert["method"] = src.get("http_method") or src.get("method", "")
    alert["action"] = src.get("action", "")
    uri_l = str(src.get("uri", "")).lower()
    ua_l = str(src.get("http_user_agent", "")).lower()
    # DATA-GROUNDED THREAT SIGNATURES (BOTSv1 APT patterns — the ontology
    # learns the data as it lies):
    # 1. Repeated exfil POST to an upload endpoint (po1s0n1vy /UploadData.aspx)
    exfil_upload = ("/uploaddata" in uri_l or "/upload" in uri_l) and \
                   (src.get("http_method") or "").upper() == "POST"
    # 2. Weird/unknown user-agent (MSDW, non-standard) on a POST — attacker tooling
    odd_ua_post = (src.get("http_method") or "").upper() == "POST" and ua_l in (
        "msdw", "ms dw", "custom", "-", "") or (ua_l and len(ua_l) < 6 and src.get("http_method") == "POST")
    # 3. Query-string command-ish params (cmd/exec/eval) — webshell behavior
    webshell_q = any(p in uri_l for p in ("cmd=", "exec=", "eval=", "shell", "c99", "b374k", "r57"))
    if exfil_upload or odd_ua_post or webshell_q:
        alert["rule"] = {
            "id": "bots-threat-http-exfil", "level": 8,
            "groups": ["http", "threat", "exfiltration"],
            "description": f"HTTP exfil/webshell pattern: {src.get('http_method','')} {src.get('uri','')[:60]} (ua={src.get('http_user_agent','')[:20]})",
        }
        alert["category_hint"] = "exfiltration"
    else:
        alert["rule"] = {
            "id": "bots-http", "level": 4,
            "groups": ["http"], "description": f"HTTP {src.get('http_method','')} {src.get('uri','')[:80]}",
        }
    return alert


def normalize(src: dict[str, Any]) -> dict[str, Any]:
    """Normalize a BOTS source doc into the ontology alert shape."""
    alert: dict[str, Any] = {}

    # 0. Splunk Stream DNS (the DNS index uses Stream format, not EVE)
    #    _raw is JSON with query[] / query_type[] / src_ip — NOT dns.qname.
    #    MUST be checked before the Suricata EVE branch (both have JSON _raw).
    _raw_s = src.get("_raw") or ""
    if "query" in src or '"query":[' in str(_raw_s):
        import json as _json
        ev = {}
        try:
            if isinstance(_raw_s, str) and _raw_s.lstrip().startswith("{"):
                ev = _json.loads(_raw_s)
        except Exception:
            ev = {}
        qs = src.get("query") or ev.get("query") or []
        qt = src.get("query_type") or ev.get("query_type") or []
        alert["srcip"] = src.get("src_ip") or ev.get("src_ip")
        alert["dstip"] = src.get("dest_ip") or ev.get("dest_ip")
        qname = ""
        if isinstance(qs, list) and qs:
            qname = str(qs[0])
        elif isinstance(qs, str):
            qname = qs
        alert["qname"] = qname
        qtype = ""
        if isinstance(qt, list) and qt:
            qtype = str(qt[0])
        elif isinstance(qt, str):
            qtype = qt
        alert["qtype"] = qtype
        # DATA-GROUNDED DNS THREAT SIGNATURES (BOTSv1):
        #   - high-entropy / all-caps long hostnames (DNS tunneling/exfil)
        #   - rare query types (NIMLOC, etc.)
        entropy_sus = (len(qname) > 30 and qname.isupper() and
                       any(c in qname for c in "ABCDEF0123456789"))
        rare_type = qtype.upper() in ("NIMLOC", "TXT", "NULL", "AXFR")
        if entropy_sus or (rare_type and len(qname) > 10):
            alert["rule"] = {
                "id": "bots-threat-dns-tunnel", "level": 8,
                "groups": ["dns", "threat", "tunneling"],
                "description": f"DNS tunneling/exfil: {qname} ({qtype})",
            }
            alert["category_hint"] = "dns_tunneling"
        else:
            alert["rule"] = {
                "id": "bots-dns", "level": 3,
                "groups": ["dns"], "description": f"DNS query {qname} ({qtype})",
            }
        return alert

    # 1. Suricata EVE (from _raw) — richest source.
    #    GUARD: HTTP-stream docs carry uri/c_ip/http_method as top-level
    #    fields (NOT inside _raw) — do NOT let the EVE branch claim them
    #    (their _raw happens to be JSON too, but it's the HTTP stream shape).
    if "uri" in src or "c_ip" in src or "http_method" in src:
        return _normalize_http(src, alert)
    eve = _parse_raw(src)
    if eve:
        alert["srcip"] = eve.get("src_ip") or src.get("src_ip")
        alert["dstip"] = eve.get("dest_ip") or src.get("dest_ip")
        alert["dstport"] = eve.get("dest_port") or src.get("dest_port")
        alert["event_type"] = eve.get("event_type", "")
        alert["timestamp"] = eve.get("timestamp", "")
        # alert records carry signature/severity/category
        a = eve.get("alert") or {}
        if a:
            desc = a.get("signature", "") or a.get("metadata", {}).get("description", "")
            alert["rule"] = {
                "id": a.get("signature_id", ""),
                "level": int(a.get("severity", 3) or 3) + 2,  # EVE sev 1-3 -> 3-5
                "groups": ["suricata", a.get("category", "ids")],
                "description": desc,
            }
            alert["category_hint"] = a.get("category", "")
        else:
            # flow/dns/tls — build a rule from the event type
            et = eve.get("event_type", "flow")
            dns = eve.get("dns") or {}
            tls = eve.get("tls") or {}
            desc = f"Suricata {et}"
            if dns.get("qname"):
                desc += f" DNS query {dns['qname']}"
                alert["qname"] = dns["qname"]
            if tls.get("sni"):
                desc += f" TLS {tls['sni']}"
                alert["sni"] = tls["sni"]
            alert["rule"] = {
                "id": f"suricata-{et}", "level": 3,
                "groups": ["suricata", et], "description": desc,
            }
        return alert

    # 2. HTTP stream (also reached via the EVE-branch guard)
    if src.get("uri") is not None or src.get("c_ip") is not None:
        return _normalize_http(src, alert)

    # 3. Windows/Sysmon
    if src.get("EventCode") is not None:
        alert["srcip"] = src.get("SourceIp") or src.get("source_ip")
        alert["dstip"] = src.get("DestinationIp") or src.get("dest_ip")
        alert["dstport"] = src.get("DestinationPort")
        alert["agent"] = {"name": src.get("Computer") or src.get("ComputerName", "")}
        ec = src.get("EventCode")
        # WinEventLog docs often only carry EventCode + _raw (the process
        # fields are inside the raw key=value text). Extract them if missing.
        def _from_raw(k: str) -> str:
            v = src.get(k)
            if v:
                return str(v)
            raw = src.get("_raw") or ""
            # Format 1: "Key=value" lines (Sysmon style)
            for line in raw.splitlines():
                if line.strip().startswith(k + "="):
                    return line.split("=", 1)[1].strip()
            # Format 2: "Label:\tvalue" in the Message (WinEventLog style,
            # e.g. "New Process Name:\tC:\...php-cgi.exe")
            label = k.replace("_", " ")
            for line in raw.splitlines():
                s = line.strip()
                if s.startswith(label + ":") or s.startswith(label + ":"):
                    return s.split(":", 1)[1].strip()
            return ""

        proc_name = (_from_raw("New_Process_Name") or _from_raw("Image")).lower()
        proc_cmd = (_from_raw("Process_Command_Line") or _from_raw("CommandLine")).lower()
        hay = f"{proc_name} {proc_cmd}"
        is_process_creation = str(ec) in ("4688", "1")
        webshell = "php-cgi" in proc_name or ("w3wp.exe" in proc_name and "joomla" in hay)
        dll_sideload = "rundll32" in proc_name and not any(k in hay for k in ("system32\\", "shell32.dll", "user32.dll"))
        # script_exec must target the REAL scripting binaries, not any name
        # containing the substring (Splunk's splunk-powershell is NOT an attack).
        script_exec = (
            any(real in proc_name for real in (
                "windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "\\powershell.exe", "\\pwsh.exe",
                "windows\\system32\\mshta.exe", "windows\\system32\\cscript.exe",
                "windows\\system32\\wscript.exe", "windows\\system32\\certutil.exe"))
            and len(proc_cmd) > 40)
        temp_exec = any(k in proc_cmd for k in ("\\temp\\", "\\tmp\\", "%temp%", "\\appdata\\local\\temp"))
        if is_process_creation and (webshell or dll_sideload or script_exec or temp_exec):
            alert["rule"] = {
                "id": f"win-{ec}", "level": 8,
                "groups": ["windows", "process", "threat", "execution"],
                "description": f"Process attack pattern: {proc_name} :: {proc_cmd[:70]}",
            }
            alert["category_hint"] = "execution"
        else:
            alert["rule"] = {
                "id": f"win-{ec}", "level": 4,
                "groups": ["windows", "process"],
                "description": src.get("EventDescription") or src.get("Message") or f"Windows EventCode {ec}",
            }
        return alert

    # 5. Fallback: pass through generic fields
    alert["srcip"] = src.get("src_ip") or src.get("srcip")
    alert["dstip"] = src.get("dest_ip") or src.get("dstip")
    alert["rule"] = {"id": "bots-unknown", "level": 3, "groups": [], "description": "BOTS event"}
    return alert


def summary(alert: dict[str, Any]) -> str:
    """Compact one-line summary for agent output."""
    rule = alert.get("rule") or {}
    return (f"src={alert.get('srcip','?')} dst={alert.get('dstip','?')}:{alert.get('dstport','?')} "
            f"et={alert.get('event_type','-')} [{rule.get('description','')[:60]}]")
