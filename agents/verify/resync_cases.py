"""Re-sync receipt-only cases into Qdrant working memory.

The JSONL receipt is the provable truth; Qdrant is the working store. When
Qdrant lost points (e.g. the known .94 instability), the reconcile check
reports them as receipt_only. This re-writes those cases into Qdrant so the
spine is consistent again — repairing, not deleting.
"""
import json
from dotenv import load_dotenv
load_dotenv()
from tools.case_tools import CaseStore

def main() -> None:
    cs = CaseStore()
    r = cs.reconcile()
    missing = r.get("receipt_only", [])
    print(f"reconcile before: consistent={r.get('consistent')} "
          f"receipt_only={missing}")
    restored = 0
    for cid in missing:
        case = cs._get_from_receipt(cid)
        if case:
            cs._write_memory(case)
            restored += 1
            print(f"  restored {cid}")
        else:
            print(f"  SKIP {cid} (no receipt reconstruction)")
    r2 = cs.reconcile()
    print(f"reconcile after: consistent={r2.get('consistent')} "
          f"qdrant_only={r2.get('qdrant_only')} receipt_only={r2.get('receipt_only')}")
    print(f"restored {restored}/{len(missing)}")

if __name__ == "__main__":
    main()
