#!/bin/bash
# SSOP bootstrap — wire the role agents to the deployed stack.
# Run AFTER: docker compose -f deploy/docker-compose.yml up -d
# (and after Wazuh is ready: curl -sk https://localhost:9200 returns 401)
#
# What it does:
#   1. Verifies Qdrant + Wazuh are reachable
#   2. Creates the Python venv + installs agent dependencies
#   3. Writes the root .env from deploy/.env (or deploy/.env.example)
#   4. Creates the Qdrant collections (cases, ltp)
#   5. Smoke-tests each role CLI
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== [1/5] checking services ==="
# Qdrant
if curl -sf http://localhost:6333/healthz > /dev/null 2>&1; then
  echo "  Qdrant: OK (localhost:6333)"
else
  echo "  Qdrant: NOT REACHABLE — is docker compose up? (deploy/docker-compose.yml)"
  exit 1
fi
# Wazuh indexer (401 = up but auth required = good)
code=$(curl -sk -o /dev/null -w "%{http_code}" https://localhost:9200/ || true)
if [ "$code" = "401" ]; then
  echo "  Wazuh indexer: OK (401 auth challenge)"
elif [ "$code" = "000" ]; then
  echo "  Wazuh indexer: NOT REACHABLE yet — Wazuh takes minutes to initialize. Try again."
  exit 1
else
  echo "  Wazuh indexer: responding ($code) — proceeding"
fi

echo "=== [2/5] python venv + deps ==="
python3 -m venv .venv 2>/dev/null || python3 -m venv .venv
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo "  deps installed"

echo "=== [3/5] writing .env ==="
if [ -f deploy/.env ]; then
  cp deploy/.env .env
  echo "  using deploy/.env (real values)"
else
  cp deploy/.env.example .env
  echo "  using deploy/.env.example (EDIT deploy/.env then re-run!)"
  echo "  WARNING: using placeholder creds — analyst/hunt may fail auth until edited."
fi
chmod 600 .env

echo "=== [4/5] creating Qdrant collections ==="
source .venv/bin/activate
python3 - << 'PYEOF'
import os
from dotenv import load_dotenv
load_dotenv()
from qdrant_client import QdrantClient
url = os.getenv("QDRANT_URL", "http://localhost:6333")
c = QdrantClient(url=url, prefer_grpc=False)
for col in ["cases", "ltp"]:
    try:
        c.get_collection(col)
        print(f"  collection {col}: exists")
    except Exception:
        from qdrant_client.models import VectorParams, Distance
        c.create_collection(col, vectors_config=VectorParams(size=384, distance=Distance.COSINE))
        print(f"  collection {col}: created")
PYEOF

echo "=== [5/5] smoke tests ==="
source .venv/bin/activate
echo "--- hunt:list (does the tool layer import?) ---"
python3 agents/hunt.py hunt:list 2>&1 | head -3
echo "--- analyst CLI help ---"
python3 agents/analyst.py 2>&1 | head -3
echo "--- infra agent CLI help ---"
python3 agents/agent.py 2>&1 | head -3

echo ""
echo "=== DONE ==="
echo "Next steps:"
echo "  python3 agents/analyst.py analyst:recent limit=5"
echo "  python3 agents/hunt.py hunt:run auth-success-from-unusual-src days=7"
echo "  python3 agents/agent.py self_heal:run"
echo ""
echo "Read docs/DEPLOYMENT.md for the full walkthrough."
