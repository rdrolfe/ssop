#!/usr/bin/env python3
"""Non-vacuity test for technique-level ATT&CK mapping.

Proves the advisory renders REAL technique IDs (ID + name + tactic, CISA
style) when the case carries them, and only falls back to the derived
kill-chain-stage->tactic mapping when no IDs exist — the documented
revisit item (was: kill-chain stage heuristic only).

  - case WITH techniques  -> advisory table shows `T1041` + name + tactic
  - case WITHOUT          -> derived kill-chain mapping still renders
  - unknown technique ID  -> honest fallback (name=ID, tactic=Other)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.advisory_gen import render_advisory  # noqa: E402
from tools.techniques import technique_meta  # noqa: E402


def _case(techniques=None, kill_chain=None):
    return {
        "case_id": "case-test-tech",
        "title": "Tech test",
        "status": "closed",
        "ts": "2026-09-02T12:00:00+00:00",
        "techniques": techniques,
        "source": {},
        "timeline": [
            {"role": "analyst", "type": "investigation", "ts": "2026-09-02T12:00:01+00:00",
             "detail": {"kill_chain": kill_chain or [], "evidence": []}},
            {"role": "supervisory", "type": "adjudication", "ts": "2026-09-02T12:00:02+00:00",
             "detail": {"decision": "approve", "rationale": "x"}},
        ],
    }


def main() -> int:
    fails = 0

    # 1. Case WITH technique IDs -> advisory must render the real ID table.
    import json
    import sys as _sys
    from unittest.mock import patch

    from tools.case_tools import CaseStore

    c = _case(techniques=["T1041", "T1078"])
    with patch.object(CaseStore, "get_case", return_value=c), \
         patch.object(_sys, "argv", ["advisory"]):
        md = render_advisory("case-test-tech")
    ok1 = "| `T1041` | Exfiltration Over C2 Channel | Exfiltration |" in md
    ok2 = "| `T1078` | Valid Accounts | Defense Evasion |" in md
    ok3 = "Kill-chain stage" not in md  # real IDs must WIN, not the heuristic
    print(f"technique IDs rendered: {ok1 and ok2} (real table wins: {ok3})")
    if not (ok1 and ok2 and ok3):
        fails += 1

    # 2. Case WITHOUT IDs -> derived kill-chain mapping still renders.
    c2 = _case(kill_chain=["EXFILTRATION: HTTP upload/exfil traffic"])
    with patch.object(CaseStore, "get_case", return_value=c2), \
         patch.object(_sys, "argv", ["advisory"]):
        md2 = render_advisory("case-test-tech")
    ok4 = "Kill-chain stage" in md2 and "Exfiltration" in md2
    print(f"derived fallback renders: {ok4}")
    if not ok4:
        fails += 1

    # 3. Unknown technique ID -> honest fallback, never invented tactic.
    m = technique_meta("T9999")
    ok5 = m["name"] == "T9999" and m["tactic"] == "Other"
    print(f"unknown-ID honest fallback: {ok5} ({m})")
    if not ok5:
        fails += 1

    # 4. Tagged kill-chain stages (the investigator path) -> technique IDs
    # extracted from the stage labels and rendered per-technique, with the
    # stage association table kept alongside.
    c4 = _case(kill_chain=[
        "C2: DNS queries/tunneling [T1071.004, T1572]",
        "EXFILTRATION: HTTP upload/exfil traffic [T1041, T1048.003]",
    ])
    with patch.object(CaseStore, "get_case", return_value=c4), \
         patch.object(_sys, "argv", ["advisory"]):
        md4 = render_advisory("case-test-tech")
    ok6 = ("| `T1071.004` | Application Layer Protocol: DNS | Command and Control |" in md4
           and "| `T1572` | Protocol Tunneling | Command and Control |" in md4
           and "| `T1041` | Exfiltration Over C2 Channel | Exfiltration |" in md4
           and "| `T1048.003` | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration |" in md4)
    ok7 = "_Technique-to-stage association_" in md4
    ok8 = "Kill-chain stage" in md4  # the stage view renders alongside
    print(f"tagged-stage techniques extracted: {ok6} (stage view kept: {ok7 and ok8})")
    if not (ok6 and ok7 and ok8):
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
