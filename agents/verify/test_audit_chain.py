#!/usr/bin/env python3
"""Non-vacuity test for the tamper-evident audit chain (#26).

Attacks the verifier MUST catch (each is simulated against a real chain):
  1. record MUTATION     (role replaced after write)     -> hash mismatch
  2. record DELETION     (one removed from the middle)  -> seq/linkage break
  3. REORDERING          (two swapped)                  -> linkage break
  4. FORGED ATTRIBUTION  (actor_id edited)              -> hash mismatch
  5. FORGED WITH FOREIGN KEY (attacker's own key)       -> unknown key_id
  6. REKEY               (key rotated)                  -> verifier accepts both
  7. ANCHOR MISMATCH     (whole-file rewrite)           -> head != anchor
And the honest-degradation paths:
  8. legacy v1 records   -> labeled, readable, excluded from chain math
  9. SPIRE unavailable   -> actor_verified false, explicit in record

Hermetic: temp dirs, generated keys, no stores/network.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.audit_chain import (  # noqa: E402
    AuditChainWriter, load_or_create_key, record_hash, verify_chain,
)

FAILS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global FAILS
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILS += 1


def build_chain(path: Path, keys_dir: Path, n: int = 5) -> AuditChainWriter:
    w = AuditChainWriter(path, key=load_or_create_key() if False else None)
    # Force the writer's key dir into our temp keys_dir (default ctor reads
    # ~/.ssop — instead construct with an explicit key like production would).
    return w


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        keys = td / "keys"
        keys.mkdir()
        recs = td / "cases.jsonl"

        # Build a healthy 5-record chain with a known key.
        key = __import__("os").urandom(32)
        (keys / "audit-aaa.key").write_bytes(key)
        (keys / "audit-aaa.key").chmod(0o600)
        w = AuditChainWriter(recs, key=key)
        for i in range(5):
            w.write(case_id=f"case-{i:04d}", role="analyst", event="note",
                    status="open", title=f"t{i}", detail={"i": i})
        r = verify_chain(recs, keys_dir=keys)
        check("healthy chain verifies", r["ok"], str(r["problems"][:2]))
        check("chain head recorded", r["head"].startswith("sha256:"))
        anchor_head = r["head"]

        lines = recs.read_text().splitlines()

        # --- 1. MUTATION: change a role after the write -------------------
        tampered = list(lines)
        rec = json.loads(tampered[2])
        rec["role"] = "supervisory"          # forge attribution
        tampered[2] = json.dumps(rec)
        (td / "mutated.jsonl").write_text("\n".join(tampered) + "\n")
        r = verify_chain(td / "mutated.jsonl", keys_dir=keys)
        check("mutation detected (hash mismatch)",
              not r["ok"] and any("HASH MISMATCH" in p for p in r["problems"]),
              str(r["problems"][:2]))

        # --- 1b. FORGED ATTRIBUTION is the same failure (actor_id edit) ---
        tampered2 = list(lines)
        rec2 = json.loads(tampered2[1])
        rec2["actor_id"] = "spiffe://ssop.local/someone-else"
        tampered2[1] = json.dumps(rec2)
        (td / "forged-actor.jsonl").write_text("\n".join(tampered2) + "\n")
        r = verify_chain(td / "forged-actor.jsonl", keys_dir=keys)
        check("forged actor attribution detected",
              not r["ok"] and any("HASH MISMATCH" in p for p in r["problems"]))

        # --- 2. DELETION: drop a middle record ----------------------------
        deleted = [ln for i, ln in enumerate(lines) if i != 2]
        (td / "deleted.jsonl").write_text("\n".join(deleted) + "\n")
        r = verify_chain(td / "deleted.jsonl", keys_dir=keys)
        check("deletion detected (seq/linkage)",
              not r["ok"] and any("seq" in p or "prev_hash" in p for p in r["problems"]),
              str(r["problems"][:2]))

        # --- 3. REORDERING: swap two records ------------------------------
        swapped = list(lines)
        swapped[1], swapped[2] = swapped[2], swapped[1]
        (td / "swapped.jsonl").write_text("\n".join(swapped) + "\n")
        r = verify_chain(td / "swapped.jsonl", keys_dir=keys)
        check("reordering detected",
              not r["ok"] and any("prev_hash" in p or "seq" in p for p in r["problems"]),
              str(r["problems"][:2]))

        # --- 4. FORGED WITH FOREIGN KEY: attacker extends with own key ----
        attacker_key = __import__("os").urandom(32)
        attacker_key_id = __import__("hashlib").sha256(attacker_key).hexdigest()[:12]
        (keys / f"audit-{attacker_key_id}.key").write_bytes(attacker_key)
        (keys / f"audit-{attacker_key_id}.key").chmod(0o600)
        # attacker rebuilds the last record with their key
        forged = list(lines)
        last = json.loads(forged[-1])
        last["role"] = "attacker-role"
        last["hash"] = record_hash({k: v for k, v in last.items() if k != "hash"},
                                   attacker_key)
        forged[-1] = json.dumps(last)
        (td / "forged-extend.jsonl").write_text("\n".join(forged) + "\n")
        r = verify_chain(td / "forged-extend.jsonl", keys_dir=keys)
        # the attacker-record's key_id is the OLD key id but hash was made
        # with the attacker key -> mismatch under the old key
        check("forgery with foreign key detected",
              not r["ok"] and any("HASH MISMATCH" in p or "unknown" in p
                                  for p in r["problems"]),
              str(r["problems"][:2]))
        (keys / f"audit-{attacker_key_id}.key").unlink()  # cleanup

        # --- 5. KEY ROTATION: writer rekeys, verifier tracks --------------
        recs2 = td / "rekey.jsonl"
        k1 = __import__("os").urandom(32)
        (keys / "audit-aaa1.key").write_bytes(k1)
        (keys / "audit-aaa1.key").chmod(0o600)
        w1 = AuditChainWriter(recs2, key=k1)
        w1.write(case_id="case-a", role="analyst", event="note", status="open",
                 title="a", detail={})
        new_key = __import__("os").urandom(32)
        (keys / "audit-bbb.key").write_bytes(new_key)
        (keys / "audit-bbb.key").chmod(0o600)
        w2 = AuditChainWriter(recs2, key=new_key)
        w2.write(case_id="case-b", role="analyst", event="note", status="open",
                 title="b", detail={})
        r = verify_chain(recs2, keys_dir=keys)
        check("key rotation: verifier accepts chain across rekey",
              r["ok"], str(r["problems"][:2]))

        # --- 6. ANCHOR MISMATCH: whole-file rewrite -----------------------
        # attacker rewrites the file to hide an event; chain internally valid
        # (they somehow got the key) BUT the anchored head no longer matches.
        forged_file = td / "rewritten.jsonl"
        w_attacker = AuditChainWriter(forged_file, key=key)
        w_attacker.write(case_id="case-clean", role="analyst", event="note",
                         status="open", title="innocent", detail={})
        r = verify_chain(forged_file, keys_dir=keys, anchor_head=anchor_head)
        check("rewritten history caught by off-process anchor",
              not r["ok"] and any("anchor" in p.lower() for p in r["problems"]),
              str(r["problems"][:2]))

        # --- 7. LEGACY v1 records: labeled, readable, chain-exempt --------
        legacy = td / "legacy.jsonl"
        legacy.write_text(json.dumps({"case_id": "case-old", "ts": "2026-08-01",
                                      "role": "analyst", "event": "note",
                                      "status": "open", "title": "old"}) + "\n")
        k3 = __import__("os").urandom(32)
        (keys / "audit-ccc.key").write_bytes(k3)
        (keys / "audit-ccc.key").chmod(0o600)
        w_l = AuditChainWriter(legacy, key=k3)
        w_l.write(case_id="case-new", role="analyst", event="note", status="open",
                  title="new", detail={})
        r = verify_chain(legacy, keys_dir=keys)
        check("legacy v1 labeled + readable, v2 chain continues",
              r["ok"] and r["legacy_unsigned"] == 1, str(r["problems"][:2]))

        # --- 8. DEGRADED: records carry explicit actor verification state --
        recs3 = td / "degraded.jsonl"
        w3 = AuditChainWriter(recs3, key=__import__("os").urandom(32))
        rec_ok = w3.write(case_id="case-x", role="analyst", event="note",
                          status="open", title="x", detail={},
                          actor_id="spiffe://ssop.local/infra-agent",
                          actor_verified=True)
        rec_deg = w3.write(case_id="case-y", role="analyst", event="note",
                           status="open", title="y", detail={},
                           actor_id=None, actor_verified=False)
        check("verified attribution recorded explicitly",
              rec_ok["actor_verified"] is True and rec_ok["actor_id"])
        check("degraded (SPIRE down) is explicit, not silent",
              rec_deg["actor_verified"] is False and rec_deg["actor_id"] is None)

    print("\nNON-VACUOUS" if FAILS == 0 else f"\n{FAILS} NON-VACUITY FAILURES")
    return 0 if FAILS == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
