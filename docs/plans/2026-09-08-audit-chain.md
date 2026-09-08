# Tamper-evident audit chain (#26) — design

## Problem
The receipt spine (`audit/cases.jsonl`) is called "signed, append-only,
provable" but is an ordinary append write: no signature, no linkage, no
event IDs. Any process (or attacker with write access) can edit, reorder,
delete, or forge a record without detection. Reconciliation checks
case-ID *membership*, not authenticity. The README overclaims (fixed in
#23); this issue makes the claim TRUE.

## Design: hash-chained receipts + verified actor attribution

**Versioned record format (v2):**
```json
{
  "v": 2,
  "seq": 4173,                      // per-file monotonic sequence
  "prev_hash": "sha256:abc...",     // hash of the ENTIRE previous record line
  "event_id": "uuid4",              // unique per record
  "case_id": "case-...",
  "ts": "...", "role": "...", "event": "...",
  "status": "...", "title": "...",
  "detail": {...},
  "actor_id": "spiffe://ssop.local/infra-agent",   // verified via SPIRE when available
  "actor_verified": true|false,     // was the SVID fetched fresh at write time
  "hash": "sha256:...",             // SHA-256 over the record WITHOUT this field
}
```

**Chain rule:** `prev_hash` of record N == `hash` of record N-1 (genesis:
`prev_hash = "sha256:GENESIS"`). Any edit/reorder/delete breaks every
subsequent hash. Forge requires recomputing the whole chain — and the
chain head is anchored off-process (below).

**Signature (hardware-independent):** each record's `hash` is an HMAC-SHA256
keyed with the audit key (`~/.ssop/audit/audit.key`, 600 perms, generated
on first use) over `prev_hash + payload-json`. An attacker WITH file write
access but WITHOUT the key cannot extend the chain validly.

**Off-process anchoring (append-only, honestly scoped):** a daily timer
copies the chain head (seq + hash) to a second location (`.29:/home/rdrolfe/
audit-anchor/` — separate dir, owner-readonly, plus the host's journald).
A verifier compares the live chain's head against the anchor: any rewrite
of history shows as a head mismatch even if the file was rebuilt.

**Actor attribution:** `_write_receipt` optionally fetches the local
SPIFFE SVID (already wired in ssh_tools) and records `actor_id` +
`actor_verified`. When SPIRE is unavailable: `actor_verified: false`,
`actor_id: null` — DEGRADED MODE IS EXPLICIT in the record, never silent.

**Verifier (`agents/verify/audit_chain.py`, offline):**
- `verify_chain(path, expected_head=None)` → {ok, problems[], head}
  - recompute every HMAC hash; check seq monotonicity; check prev_hash
    linkage; check event_id uniqueness; report FIRST break + everything after
  - legacy v1 records (no `v` field): labeled `legacy-unsigned`, skipped
    from chain math, remain readable (acceptance criterion)
- `verify_head(path, anchor_file)` → detects rewritten history

**Key lifecycle:** `audit.key` rotates by re-keying ceremony: new key
writes a `rekey` record signed under the OLD key (proves continuity),
then subsequent records use the new key id (`key_id` field = key's
SHA-256 prefix). Verifier tracks multiple key ids; accepts only keys in
`~/.ssop/audit/` (key directory IS the trust anchor).

**Degraded behaviors (all explicit, all tested):**
- key file missing at WRITE time → receipt written WITHOUT hash, marked
  `"unsigned": true` + warning logged (audit continues, gaps are loud)
- SPIRE down → `actor_verified: false` (chain continues)
- verifier run with missing key → structural checks still run (linkage,
  seq, ids); HMAC checks reported as `unverifiable-keys`

## Acceptance criteria mapping
- mutation/ordering/forge detection → chain linkage + HMAC (tested:
  flip a role, delete a record, reorder two, forge with wrong key)
- key rotation + identity-unavailable → rekey record + actor_verified
  false paths, both unit-tested
- legacy records labeled + readable → v1 passthrough in verifier
- independence from writers → verifier is offline pure-python, reads only
  the file + key dir; no store, no SPIRE, no role code

## Non-goals
- No asymmetric signatures yet (HMAC symmetric — the key lives on the
  writer host; the ANCHOR is what makes history rewrite detectable
  despite that). Escalation path documented: move to Ed25519 signing with
  per-role keys when SPIRE-issued SVIDs can sign (X.509 SVIDs can't sign
  arbitrary payloads natively; needs a signing-identity entry).
- No network replication of receipts (single-writer host today).
