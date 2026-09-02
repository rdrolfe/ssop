#!/usr/bin/env python3
"""Feed a fresh realistic threat alert through the router so it mints a
case and queues the analyst — then return the case_id. The analyst +
supervisor runs (on-demand) build the real decision chain.

Alert: ET MALWARE DNS tunneling (NIMLOC) — the classic tunnel signal, so
the analyst escalates and the supervisor approves with a full chain.
"""
import json
import sys
import uuid

sys.path.insert(0, ".")
import router

# A realistic alert in the Wazuh shape (rule + agent + srcip/dstip).
alert = {
    "id": "fresh-" + uuid.uuid4().hex[:8],
    "@timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    "rule": {
        "id": "20203",
        "level": 12,
        "description": "ET MALWARE Possible DNS Tunneling (NIMLOC)",
        "groups": ["suricata", "malware", "dns"],
    },
    "agent": {"id": "003", "name": "vault-secrets"},
    "data": {
        "srcip": "10.6.6.66",
        "dstip": "8.8.8.8",
        "srcport": 53124,
        "dstport": 53,
    },
    "input": {"type": "log"},
}

res = router.dispatch(alert)
print(json.dumps(res, indent=1, default=str)[:800])
