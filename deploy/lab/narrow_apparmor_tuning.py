#!/usr/bin/env python3
"""Narrow the two AppArmor tunings that unattended triage wrote (ADR-008).

WHY THIS EXISTS
    On 2026-09-14T07:05Z `hermes-triage` wrote a durable `auto_fp` for rule
    52002, and at 07:16Z one for `hunt:apparmor-denials`, with no human in the
    loop. Both entries are RULE-WIDE:

      * `tuned_rule_suppresses` only takes its fingerprint (override-capable)
        path when the stored fingerprint carries `rule_id`. The triage entry
        stored `{"scope": "rule", "profiles": [...]}`, so that path never
        engaged and the only escape was the generic strong-TP heuristic.
        Measured: a level-12 AppArmor denial on a profile the adjudication
        never saw suppressed silently — the whole apparmor channel was off.
      * the hunt's suppression is a bare existence check on the ledger key, so
        a tuned hunt never surfaces anything, including the exec-class and
        unknown-profile denials its own analyzer is built to catch.

    The EVIDENCE was five stock snap profiles. The BLAST RADIUS was the channel.

WHAT IT DOES
    Rewrites both entries so scope == evidence, keeping the triage rationale:
      52002                -> standard fingerprint (rule_id/groups/level/
                              category) PLUS the adjudicated `profiles`
                              allowlist the comparator now enforces.
      hunt:apparmor-denials-> the same allowlist, so the hunt's analysis-aware
                              suppression engages and exec-class denials surface.
    Attribution is preserved honestly: the unattended writer is kept as
    `proposed_by`, and the human commit is recorded in `tuned_by`. The original
    decision `ts` is preserved (this is a re-scope, not a new decision).

DRY RUN BY DEFAULT. Prints before/after payloads and PREDICTS the effect by
running the live comparator against a fabricated after-payload.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

sys.path.insert(0, ".")  # run from the runtime root, as the other lab scripts are

# The five profiles the adjudication actually verified (ticket 7ab216f9, the
# 7-day window across infra-ops / kb-vec / vault-secrets). Plain names; the
# comparator matches on basename, so full-path alerts match these.
ALLOW = [
    "snap-confine",
    "fusermount3",
    "unprivileged_userns",
    "snap-update-ns.firmware-updater",
    "snap.firmware-updater.firmware-notifier",
]

RESCOPE_NOTE = ("rescoped 2026-09-15 (ADR-008): the unattended 2026-09-14 write "
                "was rule-wide; scope narrowed to the profiles the adjudication "
                "verified. Any other profile on this rule dispatches.")

# WHO wrote these, preserved in the judgement record.
#
# `TuningLedger.write()` persists a FIXED field set (rule_id, decision,
# rationale, source, ts, tuned_by, fingerprint, exclude_hosts) — an extra
# `proposed_by` key is silently DROPPED, which was the first version of this
# script's mistake, and it would have lost the only record of who proposed the
# entry. So attribution goes in the rationale, which does persist. The facts:
#   52002               — `tuned_by` was "hermes-triage" (unattended, 07:05Z).
#   hunt:apparmor-denials — `tuned_by` was EMPTY, written 11 minutes later by
#   the same unattended process; nothing in the entry said so. That blank is
#   the reason ADR-008 makes blank attribution fail CLOSED.
ATTRIB_MARK = "proposed_by="
ATTRIB = {
    "52002": "proposed_by=hermes-triage (unattended, 2026-09-14T07:05Z); "
             "committed_by=operator (interactive session, 2026-09-15)",
    "hunt:apparmor-denials":
        "proposed_by=hermes-triage (unattended, 2026-09-14T07:16Z; written "
        "with NO tuned_by); committed_by=operator (interactive session, 2026-09-15)",
}


def _plan(led):
    """(rule_id, after_fingerprint) pairs, built from the LIVE entry."""
    plan = []
    t52002 = led.lookup("52002")
    fp52002 = t52002.get("fingerprint") if isinstance(t52002, dict) else None
    # Only re-scope if it is still the WIDE shape. "Already narrowed" means the
    # fingerprint carries BOTH the profiles allowlist and the rule_id that makes
    # the comparator take its fingerprint path — the triage entry had the
    # profiles but no rule_id, which is precisely why nothing enforced them.
    _narrowed = (isinstance(fp52002, dict) and fp52002.get("profiles")
                 and fp52002.get("rule_id"))
    if not _narrowed:
        plan.append(("52002", {
            "rule_id": "52002", "groups": ["apparmor", "ossec"], "level": 5,
            "category": "operational", "threat_desc": False, "profiles": ALLOW,
        }))
    hunt = led.lookup("hunt:apparmor-denials")
    hfp = hunt.get("fingerprint") if isinstance(hunt, dict) else None
    if not (isinstance(hfp, dict) and hfp.get("profiles")):
        # No `rule_id` here on purpose: the hunt consults its own key, and a
        # rule_id would make the router's fingerprint path compare the hunt key
        # against an alert's rule id and override on every alert.
        plan.append(("hunt:apparmor-denials", {"profiles": ALLOW}))
    return plan


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="write the narrowed entries (default: dry run)")
    args = ap.parse_args()

    from tools.tuning_tools import TuningLedger, tuned_rule_suppresses

    led = TuningLedger()
    plan = _plan(led)
    print(f"{'APPLY' if args.apply else 'DRY RUN'} — {len(plan)} entr(ies) to rescope\n")
    if not plan:
        # Do NOT return: the attribution pass below still has work to do on an
        # already-narrowed entry (and the verify block is the evidence either way).
        print("nothing to rescope (both entries already carry a profiles allowlist)\n")

    for rule_id, fp in plan:
        before = led.lookup(rule_id) or {}
        print(f"--- {rule_id} ---")
        print("BEFORE:", json.dumps({k: before.get(k) for k in
                                     ("decision", "source", "tuned_by", "fingerprint")},
                                    indent=1))
        after = dict(before)
        after.update({"fingerprint": fp,
                      "tuned_by": "rdrolfe",
                      "source": "human",
                      "rescoped_ts": datetime.now(timezone.utc).isoformat()})
        # Attribution goes in the rationale: write() drops unknown keys.
        _extra = ATTRIB.get(rule_id, "")
        after["rationale"] = " | ".join(
            p for p in (before.get("rationale", ""), RESCOPE_NOTE, _extra) if p)
        print("AFTER :", json.dumps({k: after.get(k) for k in
                                     ("decision", "source", "tuned_by",
                                      "fingerprint")}, indent=1))

        # PREDICT the effect with the live comparator before writing anything:
        # an alert on a profile OUTSIDE the allowlist must now override.
        probe_tuning = dict(after)
        for prof, want in (("snap-confine", True), ("nginx-worker", False)):
            alert = {"rule": {"id": "52002", "level": 5,
                              "groups": ["apparmor", "ossec"],
                              "description": "Apparmor DENIED"},
                     "agent": {"name": "infra-ops"},
                     "full_log": f'apparmor="DENIED" profile="{prof}" comm="x"'}
            got, reason = tuned_rule_suppresses(probe_tuning, alert,
                                                category="operational")
            ok = "OK " if got == want else "MISMATCH"
            print(f"  predict [{ok}] profile={prof:<14} suppress={got} (want {want})")
        print()

        if args.apply:
            led.write(rule_id, after.get("decision", "auto_fp"),
                      after["rationale"], source="human", ts=before.get("ts"),
                      tuned_by=after["tuned_by"], fingerprint=fp,
                      exclude_hosts=before.get("exclude_hosts"))
            print(f"  wrote {rule_id}")

    # --- attribution pass -------------------------------------------------
    # The rescope above is done, but its FIRST apply dropped the proposer:
    # write() ignores unknown keys, so `proposed_by` never persisted and the
    # only record of the unattended writer was lost. Ensure the judgement
    # record says who PROPOSED each entry, not just who committed it.
    print("--- attribution ---")
    for rule_id in ("52002", "hunt:apparmor-denials"):
        cur = led.lookup(rule_id) or {}
        if ATTRIB_MARK in str(cur.get("rationale") or ""):
            print(f"{rule_id}: attribution present")
            continue
        new_rationale = " | ".join(p for p in (cur.get("rationale", ""),
                                               ATTRIB.get(rule_id, "")) if p)
        print(f"{rule_id}: append attribution -> ...{new_rationale[-95:]}")
        if args.apply:
            led.write(rule_id, cur.get("decision", "auto_fp"), new_rationale,
                      source=cur.get("source", "human"), ts=cur.get("ts"),
                      tuned_by=cur.get("tuned_by", ""),
                      fingerprint=cur.get("fingerprint"),
                      exclude_hosts=cur.get("exclude_hosts"))
            print(f"{rule_id}: attribution written")

    if args.apply:
        print("\n--- verify ---")
        for rule_id in ("52002", "hunt:apparmor-denials"):
            cur = led.lookup(rule_id) or {}
            fpc = cur.get("fingerprint") or {}
            print(f"{rule_id}: profiles={len(fpc.get('profiles') or [])} "
                  f"rule_id_in_fp={'rule_id' in fpc} "
                  f"tuned_by={cur.get('tuned_by')!r} "
                  f"attributed={ATTRIB_MARK in str(cur.get('rationale') or '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
