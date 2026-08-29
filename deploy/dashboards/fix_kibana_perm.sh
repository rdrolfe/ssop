#!/bin/bash
# Grant kibanaserver read access to ssop-events via OpenSearch security API
# Run on telemetry (dashboard container has admin creds in env)
set -e

echo "=== 1. create ssop_read role ==="
docker exec single-node-wazuh.dashboard-1 bash -c '
  curl -s -k -u ${INDEXER_USERNAME}:${INDEXER_PASSWORD} -X PUT \
    "https://single-node-wazuh.indexer-1:9200/_plugins/_security/api/roles/ssop_read" \
    -H "Content-Type: application/json" \
    -d "{
      \"cluster_permissions\": [],
      \"index_permissions\": [{
        \"index_patterns\": [\"ssop-events*\"],
        \"allowed_actions\": [\"read\", \"indices:data/read/*\", \"indices:admin/mappings/get\", \"indices:admin/field_caps*\"]
      }],
      \"tenant_permissions\": []
    }" 2>/dev/null
' 2>&1 | head -c 300
echo ""

echo "=== 2. map kibanaserver to ssop_read ==="
docker exec single-node-wazuh.dashboard-1 bash -c '
  curl -s -k -u ${INDEXER_USERNAME}:${INDEXER_PASSWORD} -X PUT \
    "https://single-node-wazuh.indexer-1:9200/_plugins/_security/api/rolesmapping/ssop_read" \
    -H "Content-Type: application/json" \
    -d "{\"users\": [\"kibanaserver\"]}" 2>/dev/null
' 2>&1 | head -c 300
echo ""
