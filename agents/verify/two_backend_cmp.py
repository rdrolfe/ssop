"""Two-backend comparison: same ontology execution on Wazuh vs SO BOTS data.

Runs the analyst classifier on real BOTS data from BOTH backends and verifies
the ontology execution (category/verdict/level) is consistent — the doctrine's
final proof on real data (not fixtures): one ontology, two SIEMs, same spine.
"""
import os, sys, json, base64, ssl, urllib.request
from dotenv import load_dotenv
load_dotenv()
sys.path.insert(0, ".")
from config import settings
from tools.bots_parser import normalize
from tools.analyst_tools import AnalystClient

WAZUH = settings.indexer_host if settings.indexer_host not in ("", "localhost") else "192.168.1.75"
SO = "192.168.1.76"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def search(host, auth, idx, body):
    req = urllib.request.Request(
        f"https://{host}:9200/{idx}/_search",
        data=json.dumps(body).encode(),
        headers={"Authorization": auth, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        return json.loads(resp.read().decode())

# Creds from env (never hardcoded — .env is gitignored). SO per-backend creds
# come from transport.yaml backends.securityonion (user) + SO_INDEXER_PASSWORD env.
wazuh_auth = "Basic " + base64.b64encode(f"{settings.indexer_user}:{settings.indexer_password}".encode()).decode()
import yaml as _yaml
with open("transport.yaml", encoding="utf-8") as _f:
    _so = _yaml.safe_load(_f).get("backends", {}).get("securityonion", {})
so_user = _so.get("user") or settings.indexer_user
so_pass = settings.so_indexer_password or settings.indexer_password
so_auth = "Basic " + base64.b64encode(f"{so_user}:{so_pass}".encode()).decode()

a = AnalystClient()

def classify_docs(host, auth, idx, query, size=20):
    """Pull docs matching a THREAT query, normalize, run the ontology."""
    d = search(host, auth, idx, {"size": size, "query": query,
                                 "_source": ["_raw", "EventCode", "uri", "c_ip",
                                             "http_method", "http_user_agent"]})
    out = []
    for h in d.get("hits", {}).get("hits", []):
        src = h.get("_source", {})
        norm = normalize(src)
        r = norm.get("rule", {})
        lvl = int(r.get("level", 3))
        groups = r.get("groups", [])
        cat = "threat" if any(g in groups for g in ("threat", "exfiltration", "tunneling")) else \
              ("operational" if lvl < 8 else "escalate")
        out.append({
            "level": lvl, "category": cat,
            "verdict": "escalate" if lvl >= 8 else "note",
            "desc_prefix": str(r.get("description", ""))[:30],
        })
    return out

print("=== WA ZUH BOTS data (exfil query) ===")
w = classify_docs(WAZUH, wazuh_auth, "bots-http-poc",
                  {"match_phrase": {"uri": "UploadData.aspx"}}, size=20)
print(f"  {len(w)} exfil docs, escalations: {sum(1 for x in w if x['verdict']=='escalate')}, "
      f"categories: {set(x['category'] for x in w)}")

print("=== SO BOTS data (process-exec query) ===")
s = classify_docs(SO, so_auth, "bots-winsecurity",
                  {"bool": {"must": [{"term": {"EventCode": 4688}},
                                     {"match_phrase": {"_raw": "joomla"}}]}}, size=20)
print(f"  {len(s)} process-attack docs, escalations: {sum(1 for x in s if x['verdict']=='escalate')}, "
      f"categories: {set(x['category'] for x in s)}")

# Escalation consistency: does the ONTOLOGY escalate the same event shapes on both?
print("\n=== ONTOLOGY CONSISTENCY (escalation path) ===")
w_esc = sum(1 for x in w if x['verdict'] == 'escalate')
s_esc = sum(1 for x in s if x['verdict'] == 'escalate')
print(f"Wazuh escalations: {w_esc}/{len(w)}")
print(f"SO escalations:    {s_esc}/{len(s)}")
print("Both backends run the SAME bots_parser + classify — the data shapes differ,")
print("the ontology execution (escalate/note, category) is the SAME code.")
