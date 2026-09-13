"""Re-sync receipt-only cases into Qdrant working memory.

The JSONL receipt is the provable truth; Qdrant is the working store. When
Qdrant lost points (e.g. the known .94 instability), the reconcile check
reports them as receipt_only. This re-writes those cases into Qdrant so the
spine is consistent again — repairing, not deleting.

Delegates to CaseStore.reconcile(heal=True) — the ONE repair path. A second
copy of the heal loop here would drift from the reconciliation guard added for
issue #28 (the rebuild is lossy, so the repair must re-attest the repaired
payload in the signed receipt; a hand-rolled copy would silently create
content drift instead).
"""
from dotenv import load_dotenv
load_dotenv()
from tools.case_tools import CaseStore


def main() -> None:
    cs = CaseStore()
    r = cs.reconcile(heal=True)
    print(f"reconcile: consistent={r.get('consistent')} "
          f"id_sets_match={r.get('id_sets_match')} "
          f"healed={r.get('healed')}")
    print(f"content: verified={r.get('verified_count')} drifted={r.get('drifted')} "
          f"tampered={r.get('tampered')} unverified={len(r.get('unverified') or [])}")
    if r.get("heal_failed"):
        print(f"HEAL FAILED: {r['heal_failed']}")
    if r.get("drifted") or r.get("untrusted_receipt"):
        print(f"INTEGRITY FAILURE — drifted={r.get('drifted')} "
              f"untrusted_receipt={r.get('untrusted_receipt')} "
              f"(reported, never auto-repaired: the tampered payload is evidence)")


if __name__ == "__main__":
    main()
