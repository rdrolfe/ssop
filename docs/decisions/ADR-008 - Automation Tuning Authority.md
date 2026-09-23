## ADR-008: Automation Tuning Authority

**Status:** accepted — **the boundary is DECIDED and VISIBLE, but not yet BLOCKING** (see Consequences for what is declared vs enforced)

**Date:** 2026-09-15

**Context**

The unattended triage flow (`hermes-triage`) adjudicated ticket `7ab216f9` overnight and wrote **durable tuning entries**: rule `52002` → `auto_fp` (snapd desktop noise, verified across lab hosts over a 7-day window) at `07:05Z`, and `hunt:apparmor-denials` → `auto_fp` at `07:16Z`.

A tuning entry is not a note. It changes live detection: `router.classify` consults the ledger **before** its heuristics and returns `(operational, None)` for a tuned rule, so every future alert of that shape stops reaching a role — and `analyst.verdict` honours the same ledger, so it stops reaching a human too. The platform's existing doctrine already separates *recording* a decision from *executing* it (`approve != close`), requires attributable actors, and refuses to launder absence of evidence into approval. An unattended process writing durable suppressions sits outside all of that.

**What made this a governance problem rather than just a data change:** the tuning was discovered only because a verify-matrix fixture happened to depend on rule `52002` reaching the dispatch path. That is luck, not a control. The matrix went red before anyone was told; had the fixture not existed, the suppression would have been silent and permanent, and the first anyone would know is an incident that never raised a case.

**Decision**

1. **Unattended automation may PROPOSE tuning; only a human commits it.** A proposed entry is visible and attributable (it names the actor, the rationale and the ticket), and it **does not suppress**.
2. **The commit step is a human act on a human surface** — a supervisory adjudication, or a one-click confirm in the adjudication console — recorded with `source=human` and the confirming actor. Automation's `tuned_by` is preserved as the proposer, never overwritten by the confirmer.
3. **Every tuning entry carries its provenance and its state.** `auto_fp` written by a process with no human in the loop is a different object from `auto_fp` a human signed off, even though both currently look identical in the ledger.
4. **A tuning change must be VISIBLE where a human already looks.** The daily digest reports tuning entries written in the last 24h with their source and actor. A suppression that changes detection behaviour without appearing on any human surface is the failure this ADR exists to prevent.
5. **Applies to hunts as well as rules** (`hunt:apparmor-denials` was tuned the same way).
6. **The committing actor is "an interactive, user-directed session" — not "a human".** Measurement changed this rule: the ledger's `source` field is a **constant** (32/32 entries read `source: human`), including the two a scheduled process wrote unattended, so it discriminates nothing. The real signal is `tuned_by`, and the writers in use are: blank (genuine console writes), `hermes-supervisory-<date>` (an agent working in a session a human directed), `hermes-triage` (unattended, scheduled), `analyst-tier2-case-<id>` (a role agent, case-attributed). So: an agent writing under human direction may commit; an unattended scheduled process may not. **Blank attribution fails CLOSED to proposed** — the hunt entry was written unattended with an empty `tuned_by` and was otherwise indistinguishable from a hand-written console entry, so treating blank as human would launder it.
7. **Scope must equal evidence.** A tuning may suppress only the class its adjudication actually examined. Measured counter-example: the triage entry for rule 52002 recorded five stock snap profiles as its evidence but was stored rule-wide, and `tuned_rule_suppresses` only takes its override-capable fingerprint path when the stored fingerprint carries `rule_id` — which that one did not. Result: a level-12 AppArmor denial on a profile nobody had seen suppressed silently, and AppArmor denials are how a container escape surfaces. A tuning whose blast radius exceeds its evidence is a suppression waiting to be wrong.

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Leave it: unattended triage writes durable tuning | Fewer tickets for the operator; the rationale was sound | A process can silently remove detection coverage; the only detector was a fixture; no human surface reports it | Rejected: silence is the risk, not the accuracy of any single call |
| Ban automated tuning entirely | Simplest boundary | Throws away genuinely useful triage work (the rationale here was well-evidenced: 7-day window, cross-host, `suspicious_signals=0`) | Rejected: the work is valuable, the *authority* is the problem |
| Propose-only for durable tuning, with a human confirm | Keeps the triage work, keeps a human in the loop, attributes both actors | Costs the operator one confirmation per proposal | **Adopted** |
| Require a human before the *ticket* closes, but let tuning write directly | Fewer confirms | The suppression is the durable act; closing the ticket is the paperwork | Rejected: it protects the wrong object |

**Consequences**

What becomes easier: detection coverage can no longer be removed by a process; every suppression has a proposer AND a confirmer; the digest makes tuning churn visible in the daily read.

What becomes harder: unattended triage produces proposals that need a human click, so the backlog now includes them; a "self-healing" tuning loop is explicitly out of scope.

**Declared vs enforced — stated plainly, because a boundary that exists only in prose stops anyone from checking:**

- **ENFORCED (2026-09-15, `f88485c` + `9704cef`):**
  1. The daily digest reports tuning changes from the last 24h with source + actor, and the **pending-proposal queue** with its oldest age — so a proposal cannot rot in silence.
  2. *Profile-scoped suppression*: when an entry's fingerprint names the profiles its adjudication covered, a denial on any other profile dispatches (`tuned_rule_suppresses`, applied before the fingerprint path; basename-normalised, because real profiles arrive as full paths). An alert whose profile cannot be read is NOT treated as out-of-scope — a documented limitation, asserted in `test_fingerprint_tuning.py` so it cannot drift silently.
  3. *Analysis-aware hunt suppression*: when a hunt's entry carries a profiles allowlist, the tuning holds only while the hunt's own analysis agrees nothing is actionable; `finding == "suspicious"` (exec-class denials, unknown profiles/comms, load/unload/change_profile) surfaces instead of being silenced. Entries with no allowlist keep the previous blunt behaviour.
  4. **The propose/commit state machine.** `write()` defaults to PROPOSED; `suppression_allowed()` is the single gate and requires `state == "committed"`; a missing or unrecognized state fails CLOSED; `commit()` refuses an unattributed commit ("a proposal wearing a different name"). The gate had to be put in ONE place first: the hunt sweep ran its own existence check off a local tuple, so a gate added only to the shared helper would have left hunts silenceable forever, and the router accepted `escalate` while the analyst did not, so one entry meant two things. Writers: the hourly adjudicator (`ssop-supervisory.service` → `supervisory.py`) proposes through `adjudicate(authority="automation")` (the default), the console commits through `authority="interactive"`.
- **NOT YET A CRYPTOGRAPHIC BOUNDARY — the honest limit.** The unattended writer runs as `User=rdrolfe`, the same OS user as everything else on that host, so any key it was asked to respect it could also read. What exists is a code-level boundary with a fail-closed default: it stops the automation through the path the automation actually uses, and it is auditable in the diff — but a future writer that simply called `commit()` would succeed. Making it real means a dedicated service user with the commit key owned by the human user (cheapest), or an Ed25519 signature with the private key held off-host. **Not started.**

### Stage 2 — the boundary proper (2026-09-15, `e65fb64` + `5e70ac9`)

**Signature-verified commits are LIVE.** `state="committed"` is a claim; the Ed25519 signature over the authorizing core is the proof, and the gate requires both. Verified on the live ledger: a hand-set committed state with no signature verifies as nothing and is treated as inert; an entry edited after signing is inert; a real commit suppresses. All 31 committed entries are signed and read-back verified, with zero committed-but-unverified entries anywhere.

**Asymmetric, and that is a design decision worth keeping:** the router and analyst run on the unattended side and must be able to VERIFY, so the verifier holds only the public key. An HMAC would have handed the verifier the same secret the signer uses — the automation could have minted its own commits. The private key is at `~/.ssop-keys/tuning-commit.key` (0600, outside the group-shared runtime tree); the public key is world-readable.

**What it does NOT yet cover, stated plainly:** the unattended processes still run as `rdrolfe`, the account that owns the private key. So the signature closes the *tampering and forgery* cases — a rewrite of a committed entry, a hand-set state field, a signature from an untrusted key — but the *separation* case was only staged: the moment those processes run as a different account, the private key is genuinely unreadable by them. The migration is written, idempotent, dry-run-first, with a rollback (`deploy/lab/migrate_agent_plane.sh`), and its probe (`agent_plane_probe.py`) proves the property from the automation side. It needs one privileged step — `groupadd`/`useradd`/`usermod` are not on the NOPASSWD whitelist.

**→ APPLIED 2026-09-23.** All nine unattended units run as `ssop-agent`; `ssop-adjudicate-api` (the committing click) and `ssop-qdrant-tunnel` stay on `rdrolfe`. The probe, run *as* `ssop-agent` through a one-shot unit, reports **`BOUNDARY HOLDS`**: private key unreadable (`EACCES`), `signing_available()` False, `commit()` refuses — while **31/31 committed entries still verify from the automation plane**. The signer and the automation are finally different UIDs.

#### APPLIED (2026-09-23) — and the three preconditions the script did not know about

The migration's own steps were correct; what it assumed was wrong. Each of these presented as a *different* symptom, and each cost a diagnostic round:

1. **`chgrp` failed silently, leaving a half-migrated tree.** Run from a session that did not yet have the `ssop` group (the `usermod` had not reached that session), changing a file's group *to* `ssop` is `EPERM` for every file — while `chmod` succeeds, because it needs no group membership. The script wraps it in `2>/dev/null || say WARN`, so 2,708 files got group *bits* with no group *change*, and the unit died at `203/EXEC`: `ssop-agent` fell through to `other` = `--x`, and a shell script that cannot be **read** cannot be executed. *A chgrp failure must be fatal, never decorative.*
2. **Home-directory traversal is a precondition nobody stated.** `/home/rdrolfe` is `0750 rdrolfe:rdrolfe`, so even with perfect group bits the service account could not *traverse* into the tree. Fixed with the narrowest available instrument: a traverse-only ACL — `setfacl -m u:ssop-agent:x /home/rdrolfe` (mask `r-x`, `other::---`) — rather than `chmod o+x` or `chgrp` on the whole home.
3. **`$HOME` diverges, so every `~`-resolved path silently relocates.** `ssop-agent`'s passwd home is the runtime tree, so `Path.home()` resolves *inside* it. First symptom: `FileNotFoundError: TLS verification is ON but the CA bundle is missing: /home/rdrolfe/agent-runtime/.ssop/ca/ca-bundle.crt`. Fixed by pinning absolute paths in the tree's `.env` (`SSOP_RUNTIME_DIR`, `SSOP_CA_BUNDLE` → the in-tree copy, `SSOP_AUDIT_KEY_DIR`, `SSOP_SSH_KEY`/`SSH_KEY_PATH`) and by publishing the **public** key into the tree.

**Two further findings, both structural:**

- **`ssop-intel` is installed differently from the other eleven** — `/etc/systemd/system/ssop-intel.service` is a root-owned *real file*, not a symlink into the runtime tree, and no `~/agent-runtime/ssop-intel.service` exists at all. The migration script edits runtime-dir copies, so it reported `MISSING` for this unit and the unit kept running as `rdrolfe` while everything else moved. It needed an out-of-band `sed` on the `/etc` file.
- **The verifier side is as load-bearing as the signer side.** With the private key unreachable and no public key published, the plane *verifies nothing* — every committed entry reads as inert and suppression goes silently dead (fail-open, the same shape as the stage-3 bug from the other direction). The probe caught it: `0/31 verified` → after publishing the public key, `31/31`. **A boundary that disables the thing it protects is an outage, not a control.**

**Standing rule from all of this: a service-account split is a filesystem-visibility problem before it is an identity problem.** Check traversal of every path component, group bits on every file the plane reads, and every `~`-resolved path — or the split fails in ways that look like application bugs.

**Plane split the migration implements:** nine unattended units → `ssop-agent`; `ssop-adjudicate-api` (a human click must be able to commit) and `ssop-qdrant-tunnel` (uses rdrolfe's key material) stay on `rdrolfe`.

### Stage 3 — a proposal may not disarm a commit (2026-09-22)

**Found live, two days late, and only by accident.** §6 ("the unattended plane may only propose") was enforced as "it writes `state=proposed`" — which still allowed the unattended writer to **REPLACE a committed entry with a proposal**. On `2026-09-17T04:22:42Z` the hourly `ssop-supervisory` duty rewrote rule **52002** (committed 09-14 by `hermes-triage`, ticket `7ab216f9`) into a proposal, and the rule silently stopped suppressing. No error, no alert, no digest line. The only signal was a verify fixture that pinned the old behaviour and went red on 09-18 — and it read as a *fixture* problem:

```
router tuned-apparmor-no-dispatch   FAIL:   expected=note actual=escalate
```

**Why it was invisible by construction.** A proposed entry looks exactly like a decision on every surface that renders `decision` / `tuned_by` / `ts` — the console did not show state *at all* — and the automation's overwrite is logged as an ordinary tuning write. So: the automation could not *grant itself* authority, but it could **revoke a human's**, and the human-facing surface could not tell the difference.

**The fix — a proposal aimed at a committed rule does not touch the authorizing core.** It is stored in `pending_proposal`: a field the gate never reads and the signature never covers. The human's commit keeps governing, its signature stays valid, the automation's newer judgement stays visible and one confirm from adoption. Nothing is silently disarmed; nothing is lost.
- **Rejected (a) refuse.** The Sep-17 proposal carried a *narrower, better-informed* fingerprint (`entity_scope: host:vault-secrets`, level 3) than the entry it replaced. Refusing throws that observation away and guarantees re-deriving it in three months.
- **Rejected (c) explicit supersede.** Once an unattended writer can pass a flag to overwrite a human decision, the flag *is* the boundary — and flags get passed by whoever wrote the last caller.

**Retention covers both shapes.** A commit landing over a pending proposal — or over a bare proposal — retains it as `superseded_proposal`, so the record answers "what did the automation want when this was committed?"

**The surfaces had to move with it, or the fix would have INVERTED the failure.** Proposals are derived in ONE place (`pending_proposals()`): a surface that only knows `state=proposed` would stop reporting proposals riding a committed entry — the same invisibility, mirrored. The digest uses that derivation, and the console's `/tuning` now returns each entry with **the gate's own verdict** (`suppression: {allowed, reason}`), so "in force (signed)" versus "<state> — NOT suppressing" is *stated by the gate* rather than inferred from a state name by a human who has to trust it.

**The gate itself was lying by accident, and that is how this was found.** The matrix seeded rule 52002 behind `if not ledger.lookup("52002")` — a guard ANY entry satisfies, including a proposal. So the moment the automation proposed, the fixture's premise silently evaporated and the gate went red **for a reason unrelated to the code under test** (09-18 and 09-21, same fixture, same message). Seeds now assert the *state* the fixture needs and repair it when a live writer has moved it.

**Verified:** `verify/test_tuning_propose_guard.py` (20 checks, non-vacuous, including the tamper path — a tampered committed entry is preserved and stays inert, and the proposal is still recorded, so the automation can neither disarm a commit nor erase evidence of tampering); offline suite 30/30; live console probe showing `in_force: false` with the gate's reason beside two derived pending proposals; matrix re-scored **48/48**.

**Migration applied (2026-09-15), and it is the worked example of every rule above**

`deploy/lab/narrow_apparmor_tuning.py` rescoped both unattended entries so scope equals evidence — dry run first, predicting the effect with the live comparator before writing:

| entry | was | now |
|---|---|---|
| `52002` | rule-wide; fingerprint `{"scope": "rule", "profiles": [...]}`, no `rule_id` → override machinery never engaged | standard fingerprint (`rule_id`/`groups`/`level`/`category`) **plus** the five adjudicated profiles; any other profile dispatches |
| `hunt:apparmor-denials` | no fingerprint; suppressed via a bare existence check, so exec-class denials were silenced too | the same allowlist, so the hunt's analysis-aware suppression engages |

Attribution was preserved deliberately: `tuned_by` records the human commit, and the unattended proposer is recorded in the rationale (`proposed_by=hermes-triage ...`). That last detail is a lesson, not a formality — `TuningLedger.write()` persists a **fixed** field set and silently drops unknown keys, so the first version of the migration lost the proposer entirely. When recording provenance, verify it persisted by reading the entry back; a write that returns success is not a field that exists.

**State migration (same day, `9704cef`):** all 32 entries stamped and read-back verified — 31 committed, 1 proposed. 25 carried blank/null `tuned_by` and were grandfathered by one recorded act, marked on the entry itself. Exactly one of those 25 was in fact written unattended (the hunt entry) and is unknowable as such from the fields — which is why blank attribution fails closed *going forward* rather than retroactively rewriting history.

**A finding the migration surfaced, which deserves its own rule:** rule `592`'s entry carries `entity_scope: "agent_scoped"` — not the canonical `host:<name>`. `fingerprint_materially_differs` treats a scope mismatch as a material delta, so **that entry has never suppressed since it was written on 2026-09-13**, despite a rationale claiming it was scoped to agent 004 and would leave other hosts triaging. A scope value the comparator cannot match is a tuning that silently does not exist. When reviewing a proposal, verify the scope against a real alert with `fingerprint_materially_differs` — not against the prose in the rationale.

**And note the shape of what this boundary costs, because it is the point:** the one proposed entry (rule 592) is a *good* call — four identical weekly logrotate occurrences, correctly reasoned. The boundary proposes it anyway, because at write time a good unattended write is indistinguishable from a bad one. That is what makes it a boundary rather than a heuristic.

**Related**

- [[SSOP/decisions/ADR-004 - SOAR Layer]] — the automation authority boundary this extends to detection tuning
- [[SSOP/decisions/ADR-005 - Cedar Policy Layer]] — policy that is declared but unenforced gets caught here
- `agents/tools/tuning_tools.py` (`TuningLedger`, `tuned_rule_suppresses` — the single decision helper)
- `agents/router.py` (`classify`), `agents/tools/analyst_tools.py` (`verdict`) — the two consumers that must agree
- Ticket `7ab216f9`, `hermes-triage` run 2026-09-14T07:05Z
