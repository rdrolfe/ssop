#!/usr/bin/env python3
"""Reset replay contamination: close the known cases the aborted anchor
run minted (identified by title + era). Leaves production cases alone.
Usage: python3 deploy/lab/reset_replay_cases.py"""
import json
import sys

sys.path.insert(0, ".")
from tools.case_tools import CASE_COLLECTION, CaseStore


def main() -> int:
    cs = CaseStore()
    mem = cs._get_memory()
    res = mem.search_memory(CASE_COLLECTION, "case-", limit=2000)
    closed = 0
    for r in res:
        content = r.get("content", "")
        if " " not in content:
            continue
        try:
            p = json.loads(content.split(" ", 1)[1])
        except Exception:  # noqa: BLE001
            continue
        cid = p.get("case_id")
        title = p.get("title") or ""
        if not cid:
            continue
        # replay-minted cases: bots-web anchor dispatch (created ~15:41Z)
        if "THREAT alert lvl=12 on bots-web" in title and p.get("status") != "closed":
            cs.close_case(cid, reason="replay baseline reset")
            closed += 1
            print(f"  closed {cid} | {title[:60]}")
    print(f"closed {closed} replay cases")
    cnt = mem.client.count(collection_name=CASE_COLLECTION, exact=True)
    print(f"spine cases now: {cnt.count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
