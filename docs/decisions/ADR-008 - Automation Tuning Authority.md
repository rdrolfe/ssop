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
