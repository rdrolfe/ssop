"""Tamper-evident audit chain for the receipt spine (issue #26).

Versioned (v2) receipt records:
  - hash-chained: record N's prev_hash == record N-1's hash
  - HMAC-SHA256 keyed with the audit key (~/.ssop/audit/audit.key) — an
    attacker with file-write but no key cannot extend the chain validly
  - seq + event_id make reordering/deletion detectable
  - actor_id + actor_verified carry SPIFFE attribution, DEGRADED
    explicitly when SPIRE is unavailable
  - legacy v1 (unsigned, no "v" field) records are labeled and readable,
    excluded from chain math

The verifier is OFFLINE and INDEPENDENT of every writer role: it reads
only the receipt file and the key directory.

Design: docs/plans/2026-09-08-audit-chain.md
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from logging_setup import get_logger

logger = get_logger(__name__)

AUDIT_KEY_DIR = Path(os.getenv("SSOP_AUDIT_KEY_DIR",
                               str(Path.home() / ".ssop" / "audit")))
GENESIS = "sha256:GENESIS"


def audit_key_path(key_id: str = "") -> Path:
    return AUDIT_KEY_DIR / f"audit{('-' + key_id) if key_id else ''}.key"


def load_or_create_key(key_id: str = "") -> bytes:
    """Load the audit HMAC key; generate on first use (600 perms)."""
    p = audit_key_path(key_id)
    if p.is_file():
        data = p.read_bytes()
        # Keys are raw urandom bytes — a byte can legitimately be whitespace
        # (0x20/newline), so NEVER strip: stripping mutates ~4.6% of random
        # keys on read-back and silently desynchronizes key_id vs signature
        # (writer signs with the full key, verifier's key_cache strips ->
        # "key_id unknown"). Only a trailing newline from an editor is the
        # historically-expected whitespace; strip exactly that.
        if data.endswith(b"\n") and not data.endswith(b"\n\n"):
            data = data[:-1]
        return data
    AUDIT_KEY_DIR.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    # Never store a key whose edge bytes are whitespace-adjacent AND never
    # rely on read-side stripping: newline-terminate explicitly on write so
    # the on-disk form is canonical and read-back is byte-exact minus the
    # one newline we remove above.
    if key[-1:] == b"\n":
        key = key[:-1] + b"\x00"
    p.write_bytes(key + b"\n")
    os.chmod(p, 0o600)
    logger.info("generated audit key %s", p)
    return key


def key_id_for(key: bytes) -> str:
    """Stable short id for a key (recorded in every signed record)."""
    return hashlib.sha256(key).hexdigest()[:12]


def _payload_bytes(record: dict[str, Any]) -> bytes:
    """Canonical bytes for hashing/HMAC: the record WITHOUT its hash field,
    sorted keys, compact separators — deterministic across processes."""
    payload = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def record_hash(record: dict[str, Any], key: bytes) -> str:
    mac = hmac.new(key, _payload_bytes(record), hashlib.sha256).hexdigest()
    return f"sha256:{mac}"


class AuditChainWriter:
    """Appends hash-chained, HMAC-signed receipts to a JSONL file."""

    def __init__(self, path: Path, key: bytes | None = None) -> None:
        self.path = path
        self.key = key if key is not None else load_or_create_key()
        self.key_id = key_id_for(self.key)
        self._seq: int | None = None      # lazy: read from file tail
        self._prev_hash: str | None = None

    def _load_tail_state(self) -> None:
        if not self.path.is_file():
            self._seq, self._prev_hash = 0, GENESIS
            return
        seq, prev, last_key_id = 0, GENESIS, ""
        with open(self.path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("v") != 2:
                    continue  # legacy v1: not part of the v2 chain
                seq = int(rec.get("seq", seq + 1))
                prev = rec.get("hash", prev)
                last_key_id = rec.get("key_id", last_key_id)
        self._seq, self._prev_hash = seq, prev
        if last_key_id and last_key_id != self.key_id:
            # Key changed since the last record — emit a rekey marker so the
            # verifier can track continuity across key rotations.
            self._write_rekey_marker(last_key_id)

    def _write_rekey_marker(self, old_key_id: str) -> None:
        marker = {
            "v": 2, "seq": (self._seq or 0) + 1,
            "prev_hash": self._prev_hash or GENESIS,
            "event_id": str(uuid.uuid4()),
            "case_id": "", "ts": datetime.now(timezone.utc).isoformat(),
            "role": "audit", "event": "rekey",
            "status": None, "title": "", "detail": {"from": old_key_id,
                                                     "to": self.key_id},
            "actor_id": None, "actor_verified": False,
            "key_id": old_key_id,  # signed under the OLD key's context marker
        }
        # The rekey record itself is HMAC'd under the NEW key but references
        # the old key_id in its own key_id field for verifier bookkeeping.
        marker["key_id"] = self.key_id
        marker["hash"] = record_hash(marker, self.key)
        self._append_line(json.dumps(marker))
        self._seq = marker["seq"]
        self._prev_hash = marker["hash"]

    def _append_line(self, line: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def write(self, *, case_id: str, role: str, event: str,
              status: str | None, title: str, detail: dict[str, Any],
              actor_id: str | None = None, actor_verified: bool = False) -> dict[str, Any]:
        """Append one chained, signed record. Returns the written record."""
        if self._seq is None:
            self._load_tail_state()
        unsigned = {
            "v": 2,
            "seq": (self._seq or 0) + 1,
            "prev_hash": self._prev_hash or GENESIS,
            "event_id": str(uuid.uuid4()),
            "case_id": case_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "event": event,
            "status": status,
            "title": title,
            "detail": detail,
            "actor_id": actor_id,
            "actor_verified": actor_verified,
            "key_id": self.key_id,
        }
        unsigned["hash"] = record_hash(unsigned, self.key)
        self._append_line(json.dumps(unsigned))
        self._seq = unsigned["seq"]
        self._prev_hash = unsigned["hash"]
        return unsigned


def verify_chain(path: Path, keys_dir: Path | None = None,
                 anchor_head: str | None = None) -> dict[str, Any]:
    """OFFLINE, writer-independent verification.

    Checks per record: HMAC (when the key is present), seq continuity,
    prev_hash linkage, event_id uniqueness. v1/legacy records: labeled
    'legacy-unsigned', excluded from chain math but still reported.

    anchor_head: expected 'sha256:...' of the last record (from the
    off-process anchor). A mismatch means history was rewritten AFTER the
    anchor was taken — even if the chain internally validates.
    """
    keys_dir = keys_dir or AUDIT_KEY_DIR
    problems: list[str] = []
    legacy = 0
    total = 0
    seq = 0
    prev = GENESIS
    seen_ids: set[str] = set()
    head = GENESIS

    key_cache: dict[str, bytes] = {}
    for kf in Path(keys_dir).glob("audit*.key"):
        try:
            # Same read discipline as load_or_create_key: strip exactly one
            # trailing newline, never full whitespace — keys are raw bytes.
            data = kf.read_bytes()
            if data.endswith(b"\n") and not data.endswith(b"\n\n"):
                data = data[:-1]
            key_cache[key_id_for(data)] = data
        except OSError as e:
            problems.append(f"key unreadable: {kf}: {e}")

    with open(path, "rb") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            total += 1
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                problems.append(f"line {lineno}: not JSON — corrupted record")
                continue
            if rec.get("v") != 2:
                legacy += 1
                continue

            # 1. record_id uniqueness
            eid = rec.get("event_id", "")
            if eid in seen_ids:
                problems.append(f"line {lineno}: duplicate event_id {eid} — duplicated record")
            seen_ids.add(eid)

            # 2. sequence continuity
            want = seq + 1
            if rec.get("seq") != want:
                problems.append(
                    f"line {lineno}: seq {rec.get('seq')} != expected {want} "
                    f"— records deleted or reordered")
            seq = int(rec.get("seq", seq))

            # 3. chain linkage
            if rec.get("prev_hash") != prev:
                problems.append(
                    f"line {lineno}: prev_hash mismatch — record edited or "
                    f"reordered (expected chain through {prev[:20]}...)")
            prev = rec.get("hash", prev)
            head = rec.get("hash", head)

            # 4. HMAC authenticity (only when we hold the key)
            kid = rec.get("key_id", "")
            key = key_cache.get(kid)
            if key is None:
                if problems and problems[-1].startswith("key unreadable"):
                    pass
                problems.append(f"line {lineno}: key_id {kid!r} unknown — "
                                f"cannot verify authenticity (forged or foreign key)")
                continue
            expect = record_hash({k: v for k, v in rec.items() if k != "hash"}, key)
            if not hmac.compare_digest(rec.get("hash", ""), expect):
                problems.append(
                    f"line {lineno}: HASH MISMATCH — record mutated after write "
                    f"(or forged attribution)")

    if anchor_head and head != anchor_head:
        problems.append(
            f"chain head {head[:20]}... != anchored head {anchor_head[:20]}... "
            f"— history rewritten after anchor")

    return {
        "ok": not problems,
        "problems": problems,
        "records": total,
        "legacy_unsigned": legacy,
        "head": head,
    }
