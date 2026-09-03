#!/usr/bin/env python3
"""Option-C scoped tuning: 2901/2903 -> auto_fp fleet-wide EXCEPT
vault-secrets (exclude_hosts), where package drift stays under analyst
review. Grounded in the real alert shapes (probe 2026-09-02):
  2901 groups [syslog, dpkg] level 3  desc 'New dpkg ... requested to install'
  2903 groups [syslog, dpkg, config_changed] level 7 desc 'Dpkg ... removed'
Category security both. Human decision (user 2026-09-02, option C).

Usage: python3 deploy/lab/apply_dpkg_scoped_tuning.py
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")

ENTRIES = [
    {
        "rule_id": "2901",
        "decision": "auto_fp",
        "rationale": "user option-C (2026-09-02): dpkg install noise is 83-for-83 "
                     "adjudicated FP fleet-wide; keep dispatching ONLY on vault-secrets "
                     "(package drift there is high-stakes).",
        "source": "human",
        "tuned_by": "user@option-c",
        "fingerprint": {
            "rule_id": "2901", "groups": ["dpkg", "syslog"], "level": 3,
            "category": "security", "threat_desc": False,
        },
        "exclude_hosts": ["vault-secrets"],
    },
    {
        "rule_id": "2903",
        "decision": "auto_fp",
        "rationale": "user option-C (2026-09-02): dpkg change noise is 83-for-83 "
                     "adjudicated FP fleet-wide; keep dispatching ONLY on vault-secrets "
                     "(package drift there is high-stakes).",
        "source": "human",
        "tuned_by": "user@option-c",
        "fingerprint": {
            "rule_id": "2903", "groups": ["config_changed", "dpkg", "syslog"],
            "level": 7, "category": "security", "threat_desc": False,
        },
        "exclude_hosts": ["vault-secrets"],
    },
]


def main() -> int:
    from tools.tuning_tools import TuningLedger
    ledger = TuningLedger()
    for e in ENTRIES:
        ledger.write(
            e["rule_id"], e["decision"], e["rationale"],
            source=e["source"], tuned_by=e["tuned_by"],
            fingerprint=e["fingerprint"],
        )
        # exclude_hosts rides the payload AFTER the base write (write() doesn't
        # take it) — upsert with the merged payload to keep the atomic point.
        from tools.tuning_tools import TUNING_COLLECTION
        from qdrant_client.models import PointStruct
        import uuid as _uuid
        pid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"tuning:{e['rule_id']}"))
        pts = ledger._memory.client.retrieve(
            collection_name=TUNING_COLLECTION, ids=[pid], with_payload=True)
        if pts:
            payload = dict(pts[0].payload)
            payload["exclude_hosts"] = e["exclude_hosts"]
            ledger._memory.client.upsert(
                collection_name=TUNING_COLLECTION,
                points=[PointStruct(id=pid, vector=[0.0] * 384, payload=payload)])
        got = ledger.lookup(e["rule_id"])
        print(f"rule {e['rule_id']}: decision={got and got.get('decision')} "
              f"exclude_hosts={got and got.get('exclude_hosts')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
