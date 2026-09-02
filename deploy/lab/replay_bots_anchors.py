#!/usr/bin/env python3
"""BOTSv1 anchor replay — feed the KNOWN attack events through the real
spine dispatch and count cases. Maps the ground-truth anchors (from the
published BOTSv1 walkthroughs) into the alert shape the ontology expects,
with REAL threat signal (not synthetic):

  HTTP  poisonivy deface / 3791.exe upload / webshell  -> threat (ET MALWARE)
  HTTP  acunetix scanner activity                      -> security (scan)
  DNS   cerber C2 query (xmfir0.win)                   -> threat (C2)
  Sysmon 121214.tmp / 3791.exe / AAE3F5A2...           -> threat (malware proc)

Run: python3 deploy/lab/replay_bots_anchors.py [--publish]
--publish: also publish created cases to SO (native schema, per-role authors)
"""
import argparse
import json
import sys
import time
import uuid

sys.path.insert(0, ".")
import router
from tools.indexer_client import IndexerTransport

THREAT_TOKENS = ["poisonivy", "3791.exe", "121214.tmp", "xmfir0", "cerber",
                 "AAE3F5A29935E6ABCC2C2754D12A9AF0", "shell", "webshell", "upload"]
SCAN_TOKENS = ["acunetix", "scan", "nmap"]


def _http_alert(doc: dict) -> dict | None:
    raw = json.dumps(doc, default=str)
    low = raw.lower()
    c_ip = doc.get("c_ip") or ""
    dest_ip = doc.get("dest_ip") or ""
    uri = doc.get("uri_path") or doc.get("url") or ""
    useragent = doc.get("user_agent") or doc.get("ua") or ""
    has_threat = any(t in low for t in THREAT_TOKENS)
    has_scan = any(t in low for t in SCAN_TOKENS)
    if not (has_threat or has_scan):
        return None
    desc = "ET MALWARE webshell/backdoor upload attempt" if has_threat else "Web scanner reconnaissance"
    groups = ["suricata", "malware", "web_attack"] if has_threat else ["suricata", "ids", "scan"]
    return {
        "id": "bots-http-" + str(doc.get("_serial") or uuid.uuid4().hex[:8]),
        "timestamp": doc.get("@timestamp") or doc.get("timestamp") or "",
        "rule": {"id": "9001", "level": 12 if has_threat else 6,
                 "groups": groups, "description": desc},
        "agent": {"name": "bots-web"},
        "data": {"srcip": c_ip, "dstip": dest_ip, "uri": uri, "ua": useragent,
                 "raw_tokens": [t for t in THREAT_TOKENS if t in low][:3]},
    }


def _dns_alert(doc: dict) -> dict | None:
    raw = json.dumps(doc, default=str)
    low = raw.lower()
    if not any(t in low for t in ("xmfir0", "cerber")):
        return None
    return {
        "id": "bots-dns-" + str(doc.get("_serial") or uuid.uuid4().hex[:8]),
        "timestamp": doc.get("@timestamp") or "",
        "rule": {"id": "9002", "level": 12, "groups": ["suricata", "malware", "c2", "dns"],
                 "description": "ET MALWARE Possible DNS Tunneling (NIMLOC/C2)"},
        "agent": {"name": "bots-dns"},
        "data": {"dstip": doc.get("dest_ip"), "query": doc.get("query"),
                 "dest": doc.get("dest")},
    }


def _sysmon_alert(doc: dict) -> dict | None:
    raw = json.dumps(doc, default=str)
    low = raw.lower()
    toks = [t for t in ("121214.tmp", "3791.exe", "AAE3F5A29935E6ABCC2C2754D12A9AF0") if t in low]
    if not toks:
        return None
    return {
        "id": "bots-sys-" + str(doc.get("RecordID") or doc.get("_serial") or uuid.uuid4().hex[:8]),
        "timestamp": doc.get("@timestamp") or "",
        "rule": {"id": "9003", "level": 12,
                 "groups": ["sysmon", "malware", "process_creation"],
                 "description": "ET MALWARE Cerber ransomware process-exec"},
        "agent": {"name": doc.get("Computer") or "bots-sysmon"},
        "data": {"image": doc.get("Image"), "cmdline": doc.get("CommandLine"),
                 "hashes": doc.get("Hashes"), "anchor": toks[0]},
    }


def _scroll(t, idx, query, limit=0):
    after = None
    fetched = 0
    while True:
        body = {"size": 500, "query": query, "sort": [{"@timestamp": "asc"}]}
        if after:
            body["search_after"] = after
        r = t.search(body, index=idx)
        hits = r.get("hits", {}).get("hits", [])
        if not hits:
            break
        fetched += len(hits)
        last = hits[-1].get("sort")
        if last:
            after = last
        for h in hits:
            yield h.get("_source", {})
        if limit and fetched >= limit:
            break


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--publish", action="store_true")
    args = ap.parse_args()
    t = IndexerTransport()

    sources = [
        # PRECISE anchor fetches only — not full-index scrolls. Each query
        # matches the ground-truth attack events directly.
        ("bots-http-poc", {"bool": {"should": [
            {"match_phrase": {"_raw": "poisonivy"}}, {"match_phrase": {"_raw": "3791.exe"}},
            {"match_phrase": {"_raw": "shell"}}, {"match_phrase": {"_raw": "defac"}},
        ], "minimum_should_match": 1}}, _http_alert),
        ("bots-dns-poc", {"bool": {"should": [
            {"match_phrase": {"_raw": "xmfir0"}}, {"match_phrase": {"_raw": "cerber"}},
        ], "minimum_should_match": 1}}, _dns_alert),
        ("bots-sysmon-op-poc", {"bool": {"should": [
            {"match_phrase": {"_raw": "121214.tmp"}}, {"match_phrase": {"_raw": "3791.exe"}},
            {"match_phrase": {"_raw": "AAE3F5A29935E6ABCC2C2754D12A9AF0"}},
        ], "minimum_should_match": 1}}, _sysmon_alert),
    ]

    counts = {"mapped": 0, "no_signal": 0, "cases_created": 0, "attached": 0,
              "no_dispatch": 0, "notes": 0, "errors": 0}
    case_ids: set[str] = set()
    by_src: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    t0 = time.time()

    for idx, query, mapper in sources:
        n = 0
        for doc in _scroll(t, idx, query):
            alert = mapper(doc)
            if not alert:
                counts["no_signal"] += 1
                continue
            counts["mapped"] += 1
            n += 1
            by_src[idx] = by_src.get(idx, 0) + 1
            try:
                res = router.dispatch(alert)
            except Exception as e:  # noqa: BLE001
                counts["errors"] += 1
                continue
            disp = res.get("dispatch") or {}
            action = disp.get("action", "")
            by_cat[res.get("category", "?")] = by_cat.get(res.get("category", "?"), 0) + 1
            cid = res.get("case_id") or disp.get("case_id")
            if action.startswith("dispatched_to"):
                counts["cases_created"] += 1
                if cid:
                    case_ids.add(cid)
            elif res.get("attached") or disp.get("attached"):
                counts["attached"] += 1
                if cid:
                    case_ids.add(cid)
            elif action in ("noted_no_escalate", "note"):
                counts["notes"] += 1
            else:
                counts["no_dispatch"] += 1
        print(f"{idx}: {n} signal events")

    counts["unique_cases"] = len(case_ids)
    counts["elapsed_s"] = round(time.time() - t0, 1)
    print(json.dumps(counts, indent=1))
    print("case_ids:", sorted(case_ids)[:10], "..." if len(case_ids) > 10 else "")

    if args.publish and case_ids:
        from deploy.lab.publish_case_so import main as pub
        import sys as _sys
        from pathlib import Path
        for cid in sorted(case_ids):
            print(f"publishing {cid} to SO...")
            _sys.argv = ["publish_case_so.py", cid]
            pub()
    return 0


if __name__ == "__main__":
    sys.exit(main())
