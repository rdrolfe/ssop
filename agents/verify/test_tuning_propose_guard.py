#!/usr/bin/env python3
"""Non-vacuity test: an unattended PROPOSAL may not disarm a human COMMIT.

ADR-008 §6 said "the unattended plane may only propose", and that was enforced
as "it writes state=proposed". Which still let it REPLACE a committed entry with
a proposal — un-committing a human decision by stealth, with no record that
anything had been committed at all.

Found live, not theorised: the hourly `ssop-supervisory` duty rewrote rule 52002
(committed 2026-09-14 by hermes-triage, ticket 7ab216f9) into a proposal at
2026-09-17T04:22:42Z. The rule quietly stopped suppressing. Nothing surfaced it
— no error, no alert, no digest line — until a verify fixture that pinned the OLD
behaviour went red two days later, and even then the failure looked like a
fixture problem (`router tuned-apparmor-no-dispatch: expected=note actual=escalate`).

The fix under test: a proposal aimed at a committed rule does not touch the
authorizing core. It is stored ALONGSIDE the decision in `pending_proposal` —
a field the gate never reads and the signature never covers — so the commit
keeps governing, its signature stays valid, and the automation's newer judgement
stays visible and one confirm away from adoption.

Proves, hermetically:
  1. a committed entry suppresses                                    (baseline)
  2. propose() at a committed rule -> STILL suppresses, sig intact    (the bug)
  3. ...and the proposal is recorded as pending, in the RIGHT shape  (visible)
  4. a newer proposal updates in place, does not stack
  5. a human commit adopts it: cleared, retained as superseded_proposal
  6. control: propose() at an UNcommitted rule is still a bare, inert proposal
     (this is what makes check 2 evidence — the guard is doing the work)
  7. a TAMPERED committed entry is preserved, stays inert, and still records the
     proposal: the automation can neither disarm a commit nor erase evidence
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Real keypair before the tools import (config reads key paths at import time).
# A committed entry suppresses only if its Ed25519 signature verifies.
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

_KEYDIR = Path(tempfile.mkdtemp(prefix="ssop-propose-guard-keys-"))
_PRIV = _KEYDIR / "tuning-commit.key"
_PUB = _KEYDIR / "tuning-commit.key.pub"
_privkey = Ed25519PrivateKey.generate()
_PRIV.write_bytes(_privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                         NoEncryption()))
_PUB.write_bytes(_privkey.public_key().public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
os.environ["SSOP_TUNING_COMMIT_KEY"] = str(_PRIV)
os.environ["SSOP_TUNING_COMMIT_PUB"] = str(_PUB)

from tools.tuning_tools import (  # noqa: E402
    COMMITTED,
    PENDING_PROPOSAL,
    PROPOSED,
    SUPERSEDED_PROPOSAL,
    TuningLedger,
    pending_proposals,
    suppression_allowed,
    verify_entry,
)


class _FakePoint:
    def __init__(self, payload):
        self.payload = payload


class _FakeClient:
    def __init__(self, store):
        self._store = store

    def retrieve(self, collection_name, ids, with_payload=True):
        return [_FakePoint(self._store[i]) for i in ids if i in self._store]

    def upsert(self, collection_name, points):
        for p in points:
            self._store[str(p.id)] = p.payload
        return None


class _FakeMemory:
    def __init__(self):
        self.store: dict[str, dict] = {}
        self.collections: set[str] = set()
        self.client = _FakeClient(self.store)

    def ensure_collection(self, name: str):
        self.collections.add(name)

    def scroll(self, *a, **k):
        return []


def _ledger() -> TuningLedger:
    led = TuningLedger.__new__(TuningLedger)
    led._memory = _FakeMemory()  # type: ignore[assignment]
    return led


def main() -> int:
    fails = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        print(f"  [{'ok' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
        if not ok:
            fails += 1

    # --- 1. baseline: a human commit suppresses ---------------------------------
    led = _ledger()
    led.commit("52002", "auto_fp",
               "triage adjudication 2026-09-14 (rule-wide AppArmor noise)",
               committed_by="hermes-triage",
               fingerprint={"rule_id": "52002", "groups": ["apparmor", "ossec"],
                            "level": 5, "category": "operational",
                            "threat_desc": False})
    before = led.lookup("52002") or {}
    allowed, why = suppression_allowed(before)
    check("baseline: committed entry suppresses", allowed and "signed" in why, why)

    # --- 2. THE REGRESSION: proposal at a committed rule must not disarm it -----
    led.propose("52002", "auto_fp", "supervisory deny: no actionable signal",
                proposed_by="ssop-supervisory",
                fingerprint={"rule_id": "52002", "groups": ["apparmor", "local",
                                                            "syslog"],
                             "level": 3, "category": "operational",
                             "threat_desc": False,
                             "entity_scope": "host:vault-secrets"})
    after = led.lookup("52002") or {}
    allowed2, why2 = suppression_allowed(after)
    check("propose() at a committed rule: STILL suppresses", allowed2, why2)
    check("...its state is still committed", after.get("state") == COMMITTED,
          f"state={after.get('state')}")
    check("...its signature still verifies (core untouched)", verify_entry(after))
    check("...the committed DECISION still governs, not the proposal",
          after.get("decision") == before.get("decision")
          and after.get("tuned_by") == "hermes-triage"
          and after.get("ts") == before.get("ts"),
          f"decision={after.get('decision')} by={after.get('tuned_by')}")

    # --- 3. the proposal is recorded, in the RIGHT shape -----------------------
    pp = after.get(PENDING_PROPOSAL)
    check("proposal recorded as pending_proposal", isinstance(pp, dict),
          str(pp)[:70])
    check("...carries the automation's decision + author",
          isinstance(pp, dict) and pp.get("decision") == "auto_fp"
          and pp.get("proposed_by") == "ssop-supervisory")
    derived = pending_proposals([after])
    check("shared derivation reports it as pending",
          len(derived) == 1 and derived[0]["shape"] == PENDING_PROPOSAL
          and derived[0]["rule_id"] == "52002",
          str(derived))

    # --- 4. a newer proposal replaces the older one, does not stack ------------
    led.propose("52002", "auto_fp", "supervisory deny: second pass, narrower scope",
                proposed_by="ssop-supervisory", fingerprint={"level": 3})
    pp2 = (led.lookup("52002") or {}).get(PENDING_PROPOSAL) or {}
    check("newer proposal updates in place",
          "second pass" in str(pp2.get("rationale")),
          str(pp2.get("rationale"))[:60])

    # --- 5. a human commit ADOPTS it and retains what it superseded ------------
    led.commit("52002", "auto_fp", "human: adopting the narrower host scope",
               committed_by="console", fingerprint={"level": 3})
    adopted = led.lookup("52002") or {}
    allowed3, why3 = suppression_allowed(adopted)
    check("after the human commit: suppresses under the NEW decision",
          allowed3 and adopted.get("tuned_by") == "console", why3)
    check("...pending_proposal cleared", PENDING_PROPOSAL not in adopted)
    check("...what it superseded is retained for the record",
          isinstance(adopted.get(SUPERSEDED_PROPOSAL), dict)
          and "second pass" in str(adopted[SUPERSEDED_PROPOSAL].get("rationale")))
    check("...and it is no longer reported as pending",
          pending_proposals([adopted]) == [])

    # --- 6. CONTROL: the guard is what makes check 2 evidence ------------------
    led2 = _ledger()
    led2.propose("592", "auto_fp", "analyst tier-2 deny: logrotate pattern",
                 proposed_by="analyst-tier2-case-616a5fd4dd")
    bare = led2.lookup("592") or {}
    allowed4, why4 = suppression_allowed(bare)
    check("control: proposal at an UNcommitted rule stays inert",
          bare.get("state") == PROPOSED and not allowed4, why4)
    bare_derived = pending_proposals([bare])
    check("...reported as a bare proposal (shape=proposed)",
          len(bare_derived) == 1 and bare_derived[0]["shape"] == PROPOSED,
          str(bare_derived))

    # --- 7. tamper path: neither disarm nor erase ------------------------------
    ledger3, fake3 = _ledger(), _FakeMemory()
    ledger3._memory = fake3  # type: ignore[assignment]
    ledger3.commit("991046", "auto_fp", "drill-FP settlement, pair-scoped",
                   committed_by="console", fingerprint={"level": 3})
    tampered = ledger3.lookup("991046") or {}
    tampered["decision"] = "escalate"          # attacker edits AFTER signing
    fake3.store[ledger3._point_id("991046")] = tampered
    ledger3.propose("991046", "auto_fp", "supervisory: still noisy",
                    proposed_by="ssop-supervisory")
    t = ledger3.lookup("991046") or {}
    allowed5, why5 = suppression_allowed(t)
    check("tampered committed entry stays INERT (not silently repaired)",
          not allowed5 and "signature" in why5, why5)
    check("...and the tamper itself is preserved, not overwritten",
          t.get("decision") == "escalate")
    check("...with the proposal recorded alongside it",
          isinstance(t.get(PENDING_PROPOSAL), dict)
          and t[PENDING_PROPOSAL].get("decision") == "auto_fp")

    # --- 8. committing OVER a bare proposal retains what it superseded ---------
    led4 = _ledger()
    led4.propose("86610", "auto_fp", "analyst: repeated logrotate on agent 004",
                 proposed_by="analyst-tier2-case-616a5fd4dd")
    led4.commit("86610", "auto_fp", "human: agreed, scoped to the host",
                committed_by="console", fingerprint={"level": 3})
    over = led4.lookup("86610") or {}
    check("committing over a BARE proposal retains it too",
          isinstance(over.get(SUPERSEDED_PROPOSAL), dict)
          and "logrotate on agent 004" in str(
              over[SUPERSEDED_PROPOSAL].get("rationale")),
          str(over.get(SUPERSEDED_PROPOSAL))[:60])
    check("...and the new commit governs", suppression_allowed(over)[0])

    print("NON-VACUOUS" if fails == 0 else f"{fails} NON-VACUITY FAILURES")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
