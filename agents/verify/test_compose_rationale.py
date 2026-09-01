#!/usr/bin/env python3
"""Non-vacuity test for compose_rationale (writeup-quality fix).

Proves the adjudication rationale can NEVER render hollow like the old
template did ("investigation: ; 3 evidence sources, score 9.35 (high)").
The exact regression class: an investigation event with NO hypothesis but
real entity/kill-chain/evidence data.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.supervisory_tools import compose_rationale  # noqa: E402


def main() -> int:
    fails = 0

    # 1. The drill-path shape: no hypothesis, but entity + kill_chain +
    #    evidence + score (the case that produced the hollow sentence).
    inv = {
        "entity": "192.168.250.100", "evidence_count": 3,
        "kill_chain": ["EXFILTRATION: HTTP upload/exfil traffic",
                       "C2: DNS queries/tunneling",
                       "RECON: network scan / suricata flow observed"],
        "severity": 9.35, "severity_label": "high",
        "evidence": [{"source": "http"}, {"source": "dns"}, {"source": "suricata"}],
    }
    r = compose_rationale(inv, "approve")
    hollow = "investigation: ;" in r or "investigation:" in r and r.strip().endswith(":")
    has_story = ("192.168.250.100" in r and "EXFILTRATION" in r
                 and "3 evidence source(s)" in r and "9.35" in r)
    print(f"no-hypothesis approve: hollow={hollow} story={has_story}")
    print(f"  -> {r}")
    if hollow or not has_story:
        fails += 1

    # 2. Fully empty investigation (no data at all) — must not crash and
    #    must not produce a half-sentence.
    r2 = compose_rationale({}, "deny")
    print(f"empty inv: -> {r2}")
    if not r2.strip() or "investigation:" in r2 and r2.strip().endswith(":"):
        fails += 1

    # 3. None investigation -> the honest fallback.
    r3 = compose_rationale(None, "deny")
    print(f"none inv: -> {r3}")
    if "no investigation" not in r3:
        fails += 1

    # 4. Hypothesis present -> it leads the rationale (no duplication).
    inv_h = {**inv, "hypothesis": "Cerber ransomware beacon on 192.168.250.100"}
    r4 = compose_rationale(inv_h, "approve")
    print(f"with hypothesis: -> {r4[:120]}")
    if not r4.startswith("approve: Cerber ransomware beacon"):
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
