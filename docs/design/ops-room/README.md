# Ops Room — chat surface design

Internal collaboration room for the SSOP agent plane. Direction agreed 2026-09-29.
Mattermost was chosen over Matrix: simpler webhook/bot API, no federation tax, no
second IdP to operate.

**Status: DESIGN. Not built.** These are HTML mockups of the intended surface, not
screenshots of a running system.

## Governing principle

> "The chat is not a control surface — it is a surface where control is
> orchestrated and reported."

Enforceable form: **the chat may originate REQUESTS, never AUTHORITY.**

The test for any feature in this room:

> *If the agent would do this anyway had nobody typed it, it's orchestration.
> If it only does it because it was told, it's control.*

Anything that would only happen because it was typed is control, and control stays
in the signed adjudication console. ADR-008 is unchanged by this work.

## Authority tiers

Read from `docs/roles/` and the agent registry at render time. **Never re-declared
in chat configuration** — a second authority table is how they drift, and this
platform has already paid for that twice (see the `CERT_NONE` and `User=rdrolfe`
drift entries in the platform-ops skill).

| Tier | Roles | Authority |
|---|---|---|
| **executor** | router, responder, hunt, intel, drill, ops | Fixed procedure, reversible |
| **decider** | supervisory, analyst | Real authority: approve/deny, verdict, escalate. Gates executors. |
| **human-only** | — | confirm-to-close, tuning commits, anything dual-control per ADR-008 |

Separation of duties applies between agents: no agent adjudicates a case it
escalated, none commits a proposal it raised, decider ≠ executor.

The working chain: **analyst → supervisory approve/deny → responder
`block-src-ip` → human confirm-to-close** (dual-control).

## Content rules

Agents must never render raw attacker-controlled alert text inline. Chat is a
stored-XSS surface aimed at the human. Structured summaries and links only.

## Mockups

| File | Lines | What it shows |
|---|---|---|
| [`v1.html`](v1.html) | 314 | Original surface: event, proposal, question, health, answer, refused message classes; inert proposal cards; refused unsafe instruction |
| [`v2.html`](v2.html) | 289 | **Supersedes v1.** Adds teal decision messages, executor/decider badges, decision envelopes, and the three authority tiers |

v1 is kept for the design record. It predates the authority-tier correction, and
its claim that "agents may never decide" was **wrong about the existing
architecture** — supervisory already approves and denies escalations, and that
gates execution. v2 is the corrected model.

Open question, unresolved: does this room replace `bot-chat` for the daily digest
or sit beside it?
