#!/usr/bin/env python3
"""Re-attest the pre-digest case backlog (issue #28 criterion-4 coverage work).

Cases written before content attestation existed carry no signed expectation, so
a later tamper of them is undetectable. This signs the CURRENT content of each as
a point-in-time attestation (ATTEST_REATTEST), so tampering from now on IS
detected — which is what makes the advisory's evidence citable.

What that asserts, exactly: "as of <ts>, the case point's content was X".
What it does NOT assert: that the content was unmodified before <ts>. Nothing
can — the receipts never carried the historical case body, so there is no source
of truth for the past. Never describe these cases as "verified since creation";
reconcile reports them separately (verified_write vs verified_reattested) for
exactly this reason.

DRY RUN BY DEFAULT, and the dry run and the apply come from the SAME function
(CaseStore.reattest_backlog), so the dry run's `would_attest` list IS the apply's
outcome — asserted below, because a dry run that predicts writes the apply
refuses is a lying tool.

Refusals are the interesting output: a DRIFTED case is never attested over
(that would launder an active tamper into "attested"), and drift is an integrity
finding that stops the apply unless explicitly overridden.

Usage (from the runtime root, e.g. ~/agent-runtime):
  deploy/lab/reattest_spine_digests.py                  # dry run, advisory scope
  deploy/lab/reattest_spine_digests.py --scope all      # dry run, every case point
  deploy/lab/reattest_spine_digests.py --apply          # APPLY, advisory scope
"""
import argparse
import sys

sys.path.insert(0, ".")
from tools.case_tools import CaseStore  # noqa: E402

ACTIONS = ("would_attest", "attested", "already", "refused_drifted",
           "refused_untrusted", "missing")


def _show(label: str, r: dict) -> None:
    print(f"— {label}: scope={r['scope']} candidates={r['candidates']}")
    for k in ACTIONS:
        ids = r.get(k) or []
        print(f"    {k:18s} {len(ids):5d}")
    for k in ("refused_drifted", "refused_untrusted", "missing"):
        for cid in (r.get(k) or [])[:20]:
            print(f"      ! {k}: {cid}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", choices=["advisory", "all"], default="advisory",
                    help="advisory = DECIDED cases (what an advisory cites); "
                         "all = every case point")
    ap.add_argument("--apply", action="store_true",
                    help="write the attestations (default is a dry run)")
    ap.add_argument("--allow-with-drift", action="store_true",
                    help="apply even though drifted/untrusted cases were found "
                         "(they are still NEVER attested over)")
    ap.add_argument("--resolve-drifted", action="store_true",
                    help="EXPLICITLY resolve drift by attesting the current "
                         "stored content of drifted cases. Only for drift you "
                         "have explained (e.g. a known writer-shape change) — "
                         "never to silence an unexplained mismatch. Each "
                         "resolution is logged.")
    a = ap.parse_args()

    cs = CaseStore()
    dry = cs.reattest_backlog(scope=a.scope, dry_run=True,
                              resolve_drifted=a.resolve_drifted)
    _show("DRY RUN", dry)

    if not a.apply:
        print("\nnothing written. Re-run with --apply to write these "
              "attestations.")
        return 0

    if not a.resolve_drifted and (dry["refused_drifted"] or dry["refused_untrusted"]):
        print(f"\nREFUSING TO APPLY: {len(dry['refused_drifted'])} drifted / "
              f"{len(dry['refused_untrusted'])} untrusted case(s) found.")
        print("An attestation over drifted content would launder a possible "
              "tamper into 'attested'. Investigate the mismatch first "
              "(reconcile reports it), then either pass --allow-with-drift to "
              "attest the CLEAN cases only, or --resolve-drifted once you have "
              "explained it.")
        return 2

    applied = cs.reattest_backlog(scope=a.scope, dry_run=False,
                                  resolve_drifted=a.resolve_drifted)
    _show("APPLIED", applied)

    predicted, actual = sorted(dry["would_attest"]), sorted(applied["attested"])
    if predicted != actual:
        print(f"\nPREDICTION MISMATCH — the dry run and the apply disagree.\n"
              f"  predicted: {predicted}\n  actual:    {actual}")
        return 3
    print(f"\nprediction == application ({len(actual)} case(s)) ✔")

    # Idempotency: a second run reporting nothing pending is the evidence that
    # the first run was complete.
    again = cs.reattest_backlog(scope=a.scope, dry_run=False)
    print(f"re-run: attested={len(again['attested'])} "
          f"already={len(again['already'])} "
          f"would_attest={len(again['would_attest'])}")
    if again["attested"]:
        print("NOT IDEMPOTENT — a re-run wrote more attestations.")
        return 4

    r = cs.reconcile()
    print("\nreconcile now:")
    print(f"    consistent={r['consistent']} tampered={r['tampered']} "
          f"drifted={len(r['drifted'])} untrusted={len(r['untrusted_receipt'])}")
    print(f"    chained-at-write={r['verified_write']} "
          f"re-attested={r['verified_reattested']} "
          f"unattested={len(r['unverified'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
