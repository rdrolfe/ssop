# SSOP Architecture — the ontology

This document is the map of what SSOP *is*. The code implements it; this describes
the model. If you're extending SSOP, start here.

## 1. The core abstraction: roles, not agents

A **role** is a first-class object with four properties:

```
Role
├── domain knowledge   -> which Qdrant collection(s) it reads/writes (its memory)
├── tool surface       -> which tools it can call (its hands)
├── authority boundary -> what it's ALLOWED to do (its cage)
└── memory trail       -> what it did, provably (its audit)
```

An **agent** is an instantiation of a role — a LangGraph state machine with a
dedicated context window. Multiple agents can share the same role definition;
one agent can't span roles (that would violate separation of duties).

This is the ontology's key move: **roles are the stable objects, agents are
deployments of them.** A company can bind different actors to the same role
(supervisory bot vs supervisory human) without changing the model.

## 2. The role map

```
                    ┌────────────────────┐
                    │   SUPERVISORY      │  (human + bot)
                    │  audit-integrity   │
                    │  escalation judge  │
                    └─────────┬──────────┘
                              │ adjudicates
              ┌───────────────┼───────────────┐
              │               │               │
     ┌────────┴──────┐ ┌──────┴───────┐ ┌─────┴────────┐
     │  ANALYST      │ │   HUNT       │ │ INFRA-MANAGER│
     │  reactive     │ │  proactive   │ │   acts       │
     │  read-only    │ │  read-only   │ │  whitelist   │
     │  verdicts     │ │  findings    │ │  heals       │
     └───────┬───────┘ └──────┬───────┘ └──────┬───────┘
             │                │                │
             └────────────────┴────────────────┘
                      shared case spine
                   (Qdrant + JSONL dual-write)
```

- **Analyst** — consumes alerts, classifies (auth/threat/integrity/compliance/
  operational), produces verdicts (note/escalate). Read-only against the SIEM.
  No infrastructure tools. By construction it cannot break anything.

- **Hunt** — starts from a hypothesis, not an alert ("what if credentials are
  being used from unusual sources?"), queries patterns, files findings, escalates
  suspicious ones in attack-relevant categories. Read-only. Also seeds detection
  recommendations.

- **Infra-manager** — senses host health (disk, services, kernel, reachability),
  heals within its sudoers whitelist, verifies the fix, remembers the outcome.
  Everything outside the whitelist becomes a staged escalation with the exact
  command pre-staged for human approval.

- **Supervisory** — the only role allowed to *verify the others*. Runs
  audit-integrity reconciliation (Qdrant vs JSONL), adjudicates escalations
  (approve/deny with rationale), owns the case spine's accountability.
  In the reference deployment this is a human + Hermes; the model allows
  replacing either with a bot.

## 3. The incident spine (case_id)

Every incident gets a `case-<hex>` ID minted at first detection. Every role's
activity on that incident is appended to the same timeline:

```
alert ──► case_id minted ──► analyst verdict ──► hunt finding
                                    │
                                    ▼
                        escalation ticket (tier 1/2)
                                    │
                                    ▼
                        supervisory adjudication ──► human approval
                                    │
                                    ▼
                        infra-manager remediation
                                    │
                                    ▼
                        case closed, memory written
```

The spine is what makes the whole thing **reconstructable**: query by case_id and
you replay the entire incident across every role. No case_id, no incident — just logs.

## 4. Dual-write and the integrity contract

Every case write goes to two stores:

| Store | Role | Characteristics |
|-------|------|-----------------|
| Qdrant `cases` collection | working memory | searchable, prunable, where roles collaborate |
| JSONL `audit/cases.jsonl` | permanent receipt | append-only, immutable-ish, the provable record |

`reconcile()` compares the two by case_id and reports divergence:

```
{
  "qdrant_only":   [],          # in working store, missing from receipt
  "receipt_only":  [ ... ],     # in receipt, missing from working store  <- investigate
  "consistent":    false,
  "qdrant_count":  41,
  "receipt_count": 45
}
```

**Why dual-write?** It catches inconsistency (failed writes, partial state,
tampering that breaks the cross-ref). It does NOT catch coherent fabrication
(a compromised role writing matching lies to both) — that's why the authority
cage exists (a compromised analyst literally cannot run infra commands) and why
identity is cryptographic. Three layers, each covering what the others miss.

## 5. Authority: the manifest and the cage

Two layers of enforcement:

1. **The manifest (agent's conscience).** A declarative list of what a role may
   do. The agent refuses actions outside its declared authority — checked in code
   before any tool call.

2. **The OS cage (agent's cage).** The sudoers whitelist on each host. Even if
   the model hallucinates, gets prompt-injected, or the manifest check is bypassed,
   the OS physically refuses commands outside the whitelist.

Manifest generates sudoers (one-way derivation) so the cage is never hand-edited
and the two can't drift.

## 6. Approval tiers

| Tier | Requirement | Examples |
|------|-------------|----------|
| 0 | none (auto-heal) | apt upgrade, service restart within whitelist |
| 1 | one approval (agent OR human) | non-destructive but impactful |
| 2 | dual control (agent AND human) | destroy, network change, secret rotation |

Tier assignments are a declarative matrix (action class -> tier), config not code.

## 7. Identity: SPIFFE/SPIRE

Every role's agent holds an SVID from a SPIRE server. The SVID is a short-lived
X.509 certificate that auto-rotates. Audit records carry the SPIFFE ID, so
attribution is cryptographic. SPIRE is optional in the compose deployment
(documented, not required to start) — the reference deployment uses it fully.

## 8. What this is NOT (yet)

- Not a rules engine — classification is rule-based today, deliberately, so
  verdicts are deterministic and auditable. Model-assisted triage is a
  documented upgrade path.
- Not a threat-intel platform — no external feeds, by design (sovereignty).
- Not a marketplace — roles are defined in code; a plugin system is a future
  concern, and the interfaces-first design makes it possible without a rewrite.

## 9. Extending

To add a role: define its tool surface (a client class), its authority manifest,
its state machine (a LangGraph file), its CLI, and bind it to the case spine.
The skeleton — identity, audit, escalation, case spine — is shared and already
enforced. That's the promise: **the ontology is the API; roles are the plugins.**
