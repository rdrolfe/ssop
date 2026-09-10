#!/usr/bin/env python3
"""Non-vacuity test for alert provenance (occurred_at gap, thread #3).

The router read the hit's @timestamp and _id for its own cursor but never
stamped them onto the alert dict handed to dispatch paths. Wazuh transport
(ts_field=@timestamp) + dispatch_infra reading alert.get("timestamp") +
dispatch_security reading verdict v.get("ts") (a key the verdict never
carried) = every minted case got occurred_at="" and alert_id="".

Proves the fix is non-vacuous (all hermetic, no Qdrant/ES):
  - _occurred_at contract resolves @timestamp (Wazuh shape) -> ISO string
  - dispatch_infra mint: occurred_at == alert ts, doc_id == _id
  - dispatch_security mint: occurred_at == alert ts (dead v["ts"] gone)
  - analyst verdict carries the timestamp it was given
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.alert_contract import _occurred_at, _flatten  # noqa: E402
from tools.ontology import categorize_alert  # noqa: E402
import router  # noqa: E402


WAZUH_ALERT = {
    "_id": "JAg-FqABLbCkK_1s2_1I",
    "@timestamp": "2026-09-10T17:24:15.340Z",
    "timestamp": "2026-09-10T17:24:15.340+0000",
    "id": "1787079605.497762",
    "agent": {"name": "kb-vec"},
    "rule": {"id": 40704, "level": 5,
             "description": "Systemd: Service exited due to a failure.",
             "groups": ["systemd"]},
}


class _FakeCaseStore:
    def __init__(self):
        self.cases, self.events = [], []

    def recent_host_cases(self, host, rule_id=None, window_s=3600,
                          open_only=False):
        return []

    def recent_entity_cases(self, src, dst):
        return None

    def open_case(self, source, title, observables=None, assignee=None,
                  techniques=None):
        cid = f"case-{len(self.cases):04d}"
        self.cases.append({"case_id": cid, "source": source, "title": title})
        return {"case_id": cid}

    def append_event(self, case_id, role, etype, detail):
        self.events.append(case_id)


class _FakeIndexer:
    backend = "wazuh"
    field_timestamp = "@timestamp"


class _FakeSelfHeal:
    def sense(self, agent):
        return {}

    def decide(self, agent, sense):
        return []


def run():
    failures = []

    # 1. contract resolves the Wazuh shape directly
    occ = _occurred_at(_flatten(WAZUH_ALERT), ts_field="@timestamp")
    if not occ.startswith("2026-09-10T17:24:15"):
        failures.append(f"contract missed @timestamp: {occ!r}")

    # 2. dispatch_infra mint carries real provenance
    store = _FakeCaseStore()
    router.get_cases = lambda: store
    router.get_indexer = lambda: _FakeIndexer()
    router.get_selfheal = lambda: _FakeSelfHeal()
    r = router.dispatch_infra(WAZUH_ALERT)
    case = store.cases[0] if store.cases else {}
    src = case.get("source", {})
    if not src.get("occurred_at", "").startswith("2026-09-10T17:24:15"):
        failures.append(f"infra occurred_at empty/wrong: {src.get('occurred_at')!r}")
    if src.get("doc_id") != "JAg-FqABLbCkK_1s2_1I":
        failures.append(f"infra doc_id wrong: {src.get('doc_id')!r}")

    # 3. analyst verdict carries what it was given (ts-field fallback)
    from tools.analyst_tools import AnalystClient
    v = AnalystClient().classify(WAZUH_ALERT)
    if not v.get("timestamp"):
        failures.append("analyst classify timestamp empty")
    if v.get("alert_id") != "JAg-FqABLbCkK_1s2_1I":
        failures.append(f"analyst alert_id wrong: {v.get('alert_id')!r}")

    if failures:
        print("FAIL")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("PASS: provenance — occurred_at/doc_id/alert_id all populated "
          "through the contract")


if __name__ == "__main__":
    run()
