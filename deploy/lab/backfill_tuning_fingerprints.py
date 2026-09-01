#!/usr/bin/env python3
"""Backfill fingerprints onto EXISTING tuned rules (thread #2).

The tuning ledger entries written before fingerprint support (2902/2904/
550/533, …) have no stored fingerprint, so they fall back to the strong-TP
heuristic. This backfill computes the fingerprint from a representative
CURRENT alert each tuned rule emits and writes it onto the entry — so the
rules become fingerprint-aware going forward (identical -> suppress, material
delta -> override). Purely additive: decision/rationale/source preserved.

Usage: python3 deploy/lab/backfill_tuning_fingerprints.py [--dry-run]
"""
import json
import sys

sys.path.insert(0, ".")
from tools.indexer_client import IndexerTransport
from tools.ontology import fingerprint_from_alert
from tools.tuning_tools import TuningLedger


def main() -> int:
    dry = "--dry-run" in sys.argv
    t = IndexerTransport()
    led = TuningLedger()
    backfilled = 0
    skipped = 0
    for rule_id in sorted(led.all_rules()):
        entry = led.lookup(rule_id)
        if not entry or entry.get("fingerprint"):
            skipped += 1
            continue
        # Fetch a representative alert for this rule.
        body = {"size": 1,
                "query": {"bool": {"filter": [{"term": {"rule.id": rule_id}}]}},
                "sort": [{"@timestamp": {"order": "desc"}}]}
        r = t.search(body, index="wazuh-alerts-4.x-*")
        hits = r.get("hits", {}).get("hits", [])
        if not hits:
            print(f"  {rule_id}: no live alert to fingerprint — skipping (keeps legacy path)")
            skipped += 1
            continue
        fp = fingerprint_from_alert(hits[0]["_source"])
        if dry:
            print(f"  {rule_id}: would write fingerprint {json.dumps(fp)[:90]}")
            backfilled += 1
            continue
        led.write(
            rule_id=rule_id,
            decision=entry["decision"],
            rationale=entry.get("rationale", ""),
            source=entry.get("source", "human"),
            tuned_by=entry.get("tuned_by", ""),
            fingerprint=fp,
        )
        backfilled += 1
        print(f"  {rule_id}: fingerprint backfilled {json.dumps(fp)[:90]}")
    print(f"backfilled={backfilled} skipped={skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
