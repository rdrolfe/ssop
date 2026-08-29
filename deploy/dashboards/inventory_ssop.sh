#!/bin/bash
# Inventory ssop-events: what sources and fields are actually in the index
docker exec single-node-wazuh.dashboard-1 bash -c '
  curl -s -k -u ${INDEXER_USERNAME}:${INDEXER_PASSWORD} -X POST \
    "https://single-node-wazuh.indexer-1:9200/ssop-events/_search" -H "Content-Type: application/json" \
    -d "{\"size\":0,\"aggs\":{\"by_source\":{\"terms\":{\"field\":\"resource.ssop.source\",\"size\":10}},\"by_type\":{\"terms\":{\"field\":\"attributes.type\",\"size\":15}},\"by_actor\":{\"terms\":{\"field\":\"attributes.actor\",\"size\":10}}}}" 2>/dev/null
' 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('total docs:', d.get('hits', {}).get('total', {}).get('value'))
aggs = d.get('aggregations', {})
print('=== BY SOURCE ===')
for b in aggs.get('by_source', {}).get('buckets', []):
    print(f\"  {b['key']}: {b['doc_count']}\")
print('=== BY ATTRIBUTES.TYPE ===')
for b in aggs.get('by_type', {}).get('buckets', []):
    print(f\"  {b['key']}: {b['doc_count']}\")
print('=== BY ACTOR ===')
for b in aggs.get('by_actor', {}).get('buckets', []):
    print(f\"  {b['key']}: {b['doc_count']}\")
"
