#!/usr/bin/env python3
"""Non-vacuity test for infra-case dedupe (dispatch_infra, thread #1 fix).

dispatch_infra called recent_host_cases() but IGNORED the result — every
sweep with a still-present infra alert minted a fresh spine case (rule
40704 alone minted 37 duplicates in one day). The fix mirrors
dispatch_security's existing_chain behavior: an open case for the same
agent+rule_id within the recidivism window ATTACHES (append_event +
attached=True), never re-mints.

Proves the dedupe is non-vacuous:
  - two identical infra alerts (same agent+rule)  -> ONE case, second attached
  - no prior open case                            -> mints normally
  - prior case CLOSED                             -> mints a new case
  - different rule_id on the same host            -> mints a new case

Uses a fake CaseStore (in-memory recent_host_cases/open_case/append_event)
plus monkeypatched get_cases/get_indexer/get_selfheal — no Qdrant, hermetic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import router  # noqa: E402


class _FakeCaseStore:
    def __init__(self):
        self.cases = []
        self.events = []

    def recent_host_cases(self, host, rule_id=None, window_s=3600):
        return [c for c in self.cases
                if c["source"]["agent"] == str(host)
                and (rule_id is None or c["source"]["rule_id"] == str(rule_id))
                and c["status"] != "closed"]

    def open_case(self, source, title, observables=None, assignee=None):
        cid = f"case-{len(self.cases):04d}"
        self.cases.append({"case_id": cid, "title": title,
                           "status": "open", "source": source,
                           "timeline": []})
        return {"case_id": cid}

    def append_event(self, case_id, role, etype, detail):
        self.events.append((case_id, role, etype, detail))


class _FakeIndexer:
    backend = "wazuh"


class _FakeSelfHeal:
    def sense(self, agent):
        return {}

    def decide(self, agent, sense):
        return []


def _alert(agent="kb-vec", rid=40704, level=5):
    return {"id": "", "timestamp": "",
            "agent": {"name": agent},
            "rule": {"id": rid, "level": level,
                     "description": "Systemd: Service exited due to a failure."}}


def run():
    failures = []

    # 1. identical repeat -> attach, one case
    store = _FakeCaseStore()
    router.get_cases = lambda: store
    router.get_indexer = lambda: _FakeIndexer()
    router.get_selfheal = lambda: _FakeSelfHeal()
    r1 = router.dispatch_infra(_alert())
    r2 = router.dispatch_infra(_alert())
    if len(store.cases) != 1:
        failures.append(f"expected 1 case after repeat, got {len(store.cases)}")
    if r2.get("attached") is not True or r2.get("case_id") != r1.get("case_id"):
        failures.append(f"repeat did not attach: {r2}")
    if not store.events:
        failures.append("attach wrote no evidence event")

    # 2. first alert with empty store -> mints
    store2 = _FakeCaseStore()
    router.get_cases = lambda: store2
    if router.dispatch_infra(_alert()).get("attached"):
        failures.append("first alert should mint, not attach")

    # 3. closed prior case -> mints a new one
    store3 = _FakeCaseStore()
    router.get_cases = lambda: store3
    router.dispatch_infra(_alert())
    store3.cases[0]["status"] = "closed"
    r3 = router.dispatch_infra(_alert())
    if len(store3.cases) != 2 or r3.get("attached"):
        failures.append(f"closed case did not re-mint: {r3}")

    # 4. different rule on same host -> mints
    store4 = _FakeCaseStore()
    router.get_cases = lambda: store4
    router.dispatch_infra(_alert(rid=40704))
    r4 = router.dispatch_infra(_alert(rid=554))
    if len(store4.cases) != 2 or r4.get("attached"):
        failures.append(f"different rule merged into one case: {r4}")

    if failures:
        print("FAIL")
        for f in failures:
            print(" -", f)
        sys.exit(1)
    print("PASS: infra dedupe — repeat attaches, first/closed/other-rule mint")


if __name__ == "__main__":
    run()
