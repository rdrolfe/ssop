# Alert/Evidence Contract (#25) — design

## Problem (from the review)
Four consumers re-derive alert identity and provenance independently, and
they disagree:

1. **Entity selection** (`analyst.py:56`): investigation picks `obs[0]` as
   the source IP — observables are unordered after dedupe, so a hostname or
   hash can be investigated as if it were the attacker IP. It also misses
   nested Wazuh shapes beyond the three fallbacks it lists.
2. **Observable extraction** (`observables.py`): all hashes become type
   "hash" — MD5 vs SHA-1 vs SHA-256 is lost before IRIS mapping, and several
   nested SO envelope fields are never checked.
3. **IRIS engine guess** (`publish_case_iris.py:416`):
   `"wazuh" if rule_id.isdigit() else "securityonion"` — wrong for numeric
   SO signature IDs and every BOTS rule.
4. **Correlation window** (`investigator.py`): `investigate()` queries ALL
   history by default (no time bound), so a live incident can mix in
   historical replay evidence.

## Design: one contract at the transport boundary

**`tools/alert_contract.py`** — a single normalization function plus typed
accessors. No dataclass enforcement machinery; a plain dict with REQUIRED
keys and defensive accessors (the spine is dict-based end to end).

```
normalize_alert(alert, *, backend, index, doc_id) -> contract dict:
    {
      # identity
      "backend":      "wazuh" | "securityonion" | "bots" | "elastic",
      "index":        str,           # which index the doc came from
      "doc_id":       str,           # backend document id (provenance)
      "occurred_at":  ISO-8601 UTC,  # occurrence time, not ingest time
      # entity roles (VALIDATED IPs — never hostname/hash)
      "src_ip":       str,           # "" when absent
      "dst_ip":       str,
      # semantic IOCs
      "observables":  [{type, value, hash_type?}, ...],
                      # hash_type in {md5, sha1, sha256} when type=hash
      # scope
      "rule_id":      str (always str, never int),
      "rule_desc":    str,
      "level":        int,
      "raw":          <original alert>,   # retained for audit, never mutated
    }
```

### Resolution rules (single source of truth)
- **src/dst**: candidate-field order shared with `entity_pair`/`observables`
  (one shared constant list — no per-module candidate tuples). First VALID
  IP wins; a hostname/hash is never eligible for src_ip/dst_ip.
- **hash_type**: from the field name when typed (sha256/sha1/md5 fields),
  else from value length (64/40/32). Observable dicts gain "hash_type".
- **engine**: explicit `backend` — carried from the transport
  (`IndexerTransport.backend`) through the case `source` dict. IRIS publish
  reads `case["source"]["backend"]`; falls back to `"unknown"`, never a
  rule-ID heuristic.

### Investigation scope
- `investigate(..., window_hours=0.0)` — callers MUST pass an explicit
  window; the default becomes "no unbounded query": `window_hours=None`
  (explicitly all-history) stays available for the nightly hunt, but the
  live incident path passes a bounded window (`settings.correlation_window_h`,
  default 24h).

### Migration (callers together, as the issue requires)
1. Router intake (post-#10 it already has backend fields): build the
   contract at dispatch time; `case["source"]` gains backend/index/doc_id/
   occurred_at.
2. `analyst._persist_investigation`: entity selection = contract.src_ip →
   IP-typed observables → alert fields. NEVER obs[0] unless it's type=ip.
3. `publish_case_iris`: engine from source.backend; hash_type → IRIS
   ioc_type mapping (md5/sha1/sha256 distinct where IRIS supports it).
4. `observables.extract_observables`: gains hash_type; field lists unify
   with the contract's constants.
5. `investigator.investigate`: window_hours explicit in live paths.

### Non-goals
- No schema-validation library (no pydantic dep); contract failures log +
  degrade (missing field = "") rather than raise — alert processing must
  never die on a malformed doc.
- No change to receipt/receipts spine shape (provenance rides in case.source).

## Verification
- New hermetic test `test_alert_contract.py` in the offline suite:
  Wazuh-nested, SO ECS, SO envelope, and BOTS shapes normalize identically;
  numeric SO rule_id keeps engine=wazuh out of the picture (engine comes
  from backend); hostname-as-obs[0] does NOT become the investigated IP;
  MD5/SHA1/SHA256 carry distinct hash_type; unbounded investigate is not
  reachable from the live incident path.
- Full offline suite green; live TTX on .29 (one router dispatch → case
  with populated source.backend + investigation entity = src_ip).
