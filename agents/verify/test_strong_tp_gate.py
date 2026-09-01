#!/usr/bin/env python3
"""Non-vacuity test for the category-gated strong-TP override.

The dpkg/integrity flood: rules 2902/2904/550/533 are tuned auto_fp by a
human, but strong_tp_evidence() lifted the tuning whenever rule.level >=
high_level (7) — and Wazuh rates those rules at STATIC level 7. So every
routine package install / scheduled checksum scan re-escalated, defeating
the human's tuning and firehosing 36 open tickets into the queue.

The fix: the severity leg of strong_tp_evidence() only counts for genuine
attack categories (threat/authentication/security). This test locks that in:
  - dpkg/integrity at level 7, category operational/integrity -> NO override
  - a threat-category alert at high level (e.g. Suricata) -> STILL overrides
  - a threat-desc token overrides even at low level and non-attack category
    (the original purpose: a tuned-FP rule must not blind the SOC to a real
    ET MALWARE / C2 hit).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load tuning_tools directly (module has no package __init__ deps beyond
# config; the runtime venv provides qdrant_client).
import importlib.util  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    "tuning_tools", str(Path(__file__).resolve().parent.parent / "tools" / "tuning_tools.py"))
assert _spec is not None and _spec.loader is not None, "tuning_tools.py not found"
tt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tt)


def main() -> int:
    fails = 0

    # 1. dpkg install (2902) at static level 7, operational category — the
    #    exact flood case. Must NOT override the human's auto_fp.
    dpkg = {"rule": {"id": "2902", "level": 7,
                     "description": "New dpkg (Debian Package) installed.",
                     "groups": ["syscheck"]}}
    r = tt.strong_tp_evidence(dpkg, "operational")
    print(f"dpkg lvl7 operational: override={r} (want False)")
    if r:
        fails += 1
    r = tt.strong_tp_evidence(dpkg, "integrity")
    print(f"dpkg lvl7 integrity:   override={r} (want False)")
    if r:
        fails += 1

    # 2. No category passed (legacy call) with level 7 — the OLD behavior.
    #    Callers were all migrated to pass category; a bare call without
    #    category should be conservative about the severity leg. We accept
    #    the desc-token leg only.
    r = tt.strong_tp_evidence(dpkg)  # no category
    print(f"dpkg lvl7 no-category: override={r} (desc token absent -> want False)")
    if r:
        fails += 1

    # 3. A genuine attack-class alert (Suricata/IDS) at high level DOES
    #    override — the override still works for real threats.
    suri = {"rule": {"id": "86610", "level": 7,
                     "description": "ET MALWARE Sality (suricata)",
                     "groups": ["ids", "suricata"]}}
    r = tt.strong_tp_evidence(suri, "security")
    print(f"suricata lvl7 security: override={r} (want True — attack class)")
    if not r:
        fails += 1

    # 4. A threat-desc token overrides EVEN at low level + non-attack
    #    category — the original clear-exception purpose.
    tok = {"rule": {"id": "550", "level": 4,
                    "description": "ET C2 beacon detected (syscheck)",
                    "groups": ["syscheck"]}}
    r = tt.strong_tp_evidence(tok, "operational")
    print(f"desc-token low lvl:     override={r} (want True — threat token)")
    if not r:
        fails += 1

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
