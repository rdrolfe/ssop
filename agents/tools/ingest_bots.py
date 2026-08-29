"""Ingest a BOTSv1 JSON slice into the Wazuh indexer as a bots-* index.

Reads a gzipped BOTSv1 JSON (newline-delimited, each line {offset, preview,
result}) and bulk-indexes the `result` objects into OpenSearch. Flattens
result.* into the doc and adds @timestamp from the Splunk date_* fields so
the transport's time-based queries work.

Usage: python3 ingest_bots.py <input.json.gz> <index> [--limit N]
"""
import base64
import gzip
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()
from config import settings


def _auth():
    return "Basic " + base64.b64encode(
        f"{settings.indexer_user}:{settings.indexer_password}".encode()
    ).decode()


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _splunk_ts(result: dict) -> str:
    """Build an ISO @timestamp from Splunk's date_* fields (if present)."""
    try:
        y = result.get("date_year"); mo = result.get("date_month")
        d = result.get("date_mday"); h = result.get("date_hour")
        mi = result.get("date_minute"); s = result.get("date_second")
        if not all([y, mo, d, h, mi, s]):
            return datetime.now(timezone.utc).isoformat()
        months = {m: i for i, m in enumerate(
            ["january","february","march","april","may","june","july",
             "august","september","october","november","december"], 1)}
        mo_num = months.get(str(mo).lower(), 1)
        dt = datetime(int(y), mo_num, int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _indexer_host() -> str:
    """Resolve the reachable indexer host (settings may be 'localhost' if
    unset — fall back to the transport's resolved host or the known .75)."""
    if settings.indexer_host and settings.indexer_host != "localhost":
        return settings.indexer_host
    # Fall back: transport.yaml backend endpoint or the known Wazuh indexer
    try:
        from tools.indexer_client import IndexerTransport
        t = IndexerTransport()
        if t.backend == "wazuh":
            return t.host
    except Exception:
        pass
    return "192.168.1.75"


def _target(backend: str = ""):
    """Resolve the ingest target (host, port, user, password).

    backend='wazuh' -> .env creds + .75. backend='securityonion' -> SO ES
    (transport.yaml securityonion per-backend creds/endpoint). Default: use
    the active transport backend if it's wazuh, else wazuh.

    IMPORTANT: reads the SPECIFIED backend from transport.yaml directly —
    not the active backend — so 'securityonion' always targets SO even when
    the transport is pointed elsewhere (e.g. bots).
    """
    import yaml as _yaml
    with open("transport.yaml") as _f:
        _cfg = _yaml.safe_load(_f)
    _b = (_cfg.get("backends") or {}).get(backend)
    if backend == "securityonion" and _b:
        ep = _b.get("endpoint", "")
        import re as _re
        m = _re.match(r"https?://([^:]+)(?::(\d+))?", ep)
        if m:
            host = m.group(1)
            port = int(m.group(2) or 9200)
            # SO per-backend creds from transport.yaml backends.securityonion
            user = _b.get("user") or (_b.get("fields") or {}).get("user", "")
            pw = _b.get("password") or (_b.get("fields") or {}).get("password", "")
            if not user or not pw:
                from tools.indexer_client import IndexerTransport
                t = IndexerTransport()
                user, pw = t.user, t.passwd
            return host, port, user, pw
    host = _indexer_host()
    port = settings.indexer_port or 9200
    return host, port, settings.indexer_user, settings.indexer_password


def ingest(path: str, index: str, limit: int = 0, backend: str = ""):
    ctx = _ctx()
    auth = _auth()
    host, port, user, pw = _target(backend)
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    url = f"https://{host}:{port}/_bulk"
    print(f"ingesting -> {host}:{port}/{index} (backend={backend or 'default'})")
    # Pre-create the index (OpenSearch auto-creates, but explicit is safer)
    import urllib.request as ur
    idx_req = ur.Request(
        f"https://{host}:{port}/{index}",
        data=b"{}", method="PUT",
        headers={"Authorization": auth, "Content-Type": "application/json"})
    try:
        ur.urlopen(idx_req, timeout=15, context=ctx)
    except urllib.error.HTTPError as e:
        if e.code != 400:  # 400 = already exists
            print(f"index create: HTTP {e.code}")

    count = 0
    batch = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                result = rec.get("result") or {}
            except json.JSONDecodeError:
                continue
            if not isinstance(result, dict):
                continue
            # Flatten: add @timestamp, map Computer -> host.name for the transport
            doc = dict(result)
            doc["@timestamp"] = _splunk_ts(result)
            if doc.get("Computer"):
                doc.setdefault("host", {"name": doc["Computer"]})
            batch.append({"index": {"_index": index}})
            batch.append(doc)
            count += 1
            if len(batch) >= 1000:
                _bulk(url, auth, ctx, batch)
                batch = []
                if limit and count >= limit:
                    break
        if batch:
            _bulk(url, auth, ctx, batch)
    print(f"ingested {count} docs into {index}")


def _bulk(url, auth, ctx, batch):
    body = "".join(json.dumps(x) + "\n" for x in batch)
    req = urllib.request.Request(url, data=body.encode(),
                                 headers={"Authorization": auth,
                                          "Content-Type": "application/x-ndjson"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            r = json.loads(resp.read().decode())
            if r.get("errors"):
                # count real errors
                errs = sum(1 for item in r.get("items", [])
                           if "error" in (item.get("index") or {}))
                print(f"  bulk: {len(batch)//2} docs, {errs} errors")
    except Exception as e:
        print(f"  bulk ERR: {e}")


if __name__ == "__main__":
    path = sys.argv[1]
    index = sys.argv[2] if len(sys.argv) > 2 else "bots-sysmon-*"
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    ingest(path, index, limit)
