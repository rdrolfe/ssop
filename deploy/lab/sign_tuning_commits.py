#!/usr/bin/env python3
"""Sign every committed tuning entry (ADR-008 stage 2 migration).

WHY: `suppression_allowed` now requires a VERIFIED commit signature, not just
`state == "committed"`. A committed entry without a valid signature is inert —
so the 31 already-committed entries must be signed in the same window the
signature check goes live, or the whole ledger goes inert at once.

This script is IDEMPOTENT and re-runnable: it signs entries whose signature is
missing or no longer verifies (e.g. after a field was edited). It must run as
the human plane (the holder of the private key); run as an unattended user it
fails loudly, which is the point of the boundary.

Dry run by default; --apply writes; always reads back and verifies.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, ".")  # run from the runtime root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--include-proposed", action="store_true",
                    help="also sign proposals (NOT recommended: a proposal is "
                         "meant to be committed by a human, not auto-signed)")
    args = ap.parse_args()

    from tools.tuning_tools import (
        COMMITTED,
        SIG_FIELDS,
        TuningLedger,
        _commit_key_paths,
        signing_available,
        tuning_state,
        verify_entry,
    )

    key_path, pub_path = _commit_key_paths()
    print(f"key (private): {key_path}  readable here: {signing_available()}")
    print(f"key (public) : {pub_path}")
    if not signing_available():
        print("REFUSING: private key not readable from this account — this "
              "account may not commit tuning entries (ADR-008)")
        return 2

    led = TuningLedger()
    entries = led.list_all(limit=500)
    todo = []
    for e in entries:
        rid = str(e.get("rule_id") or "")
        if not rid:
            continue
        state = tuning_state(e)
        if state != COMMITTED and not args.include_proposed:
            continue
        if verify_entry(e):
            continue
        todo.append((rid, e, state))

    print(f"{'APPLY' if args.apply else 'DRY RUN'} — {len(entries)} entries, "
          f"{len(todo)} to sign\n")
    for rid, e, state in todo:
        core = {f: e.get(f) for f in SIG_FIELDS}
        print(f"  {rid:<34} state={state:<9} ts={str(e.get('ts'))[:19]} "
              f"fields={sorted(k for k, v in core.items() if v is not None)}")
    if not args.apply:
        print("\n(dry run — nothing written)")
        return 0

    for rid, e, state in todo:
        # Re-sign the entry EXACTLY as stored: same ts, same scope, same actor.
        led.write(rid, e.get("decision", "auto_fp"), e.get("rationale") or "",
                  source=e.get("source", "human"), ts=e.get("ts"),
                  tuned_by=e.get("tuned_by", ""),
                  fingerprint=e.get("fingerprint"),
                  exclude_hosts=e.get("exclude_hosts"),
                  state=state, commit_sig=_sign(led, rid, e, state))
        print(f"  signed {rid}")

    print("\n--- verify (read back) ---")
    bad = []
    for rid, _, _ in todo:
        cur = led.lookup(rid) or {}
        if not verify_entry(cur):
            bad.append(rid)
    print(f"{len(todo) - len(bad)}/{len(todo)} now verify"
          f"{'' if not bad else f' — FAILED: {bad}'}")

    # The whole ledger, not just what we touched: an entry that LOOKS committed
    # but does not verify is an outage waiting to happen.
    inert = [str(e.get("rule_id")) for e in led.list_all(limit=500)
             if tuning_state(e) == COMMITTED and not verify_entry(e)]
    print(f"committed-but-unverified anywhere in the ledger: "
          f"{len(inert)}{'' if not inert else f' -> {inert}'}")
    return 0 if not bad and not inert else 1


def _sign(led, rid: str, e: dict, state: str) -> str:
    """Signature over the authorizing core exactly as it will be stored."""
    from tools.tuning_tools import SIG_FIELDS, sign_entry
    core = {f: e.get(f) for f in SIG_FIELDS}
    return sign_entry(core)


if __name__ == "__main__":
    sys.exit(main())