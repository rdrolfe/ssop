# SSOP — Sovereign Security Operations Platform

A self-healing, self-testing SOC platform where AI agents fill the operational roles
of a security operations center — with **separation of duties, cryptographic identity,
provable audit, and a human approval gate baked into the architecture**.

SSOP is designed to run entirely on infrastructure you control. No cloud dependency,
no vendor lock-in. The ontology (roles, authority, memory, audit) is the product;
the agents are the first implementations of it.

---

## Why this exists

Most "AI for security" is a chat interface bolted onto a SIEM. SSOP starts from a
different question: **what if the SOC's operational roles themselves were agents?**

A SOC has distinct jobs with distinct authority:
- an **analyst** investigates alerts and produces verdicts (read-only)
- a **hunter** tests hypotheses against telemetry (proactive, read-only)
- an **infra manager** fixes what's broken (can act, but only within a cage)
- a **supervisory human** owns high-risk decisions (final say, always)

If those roles are real objects — with identities, tool sets, authority boundaries,
and audit trails — then a platform can *be* a SOC instead of *assist* a SOC.

## The three ideas that make it work

1. **Separation of duties as architecture.** Each role is a separate state machine
   with its own context window and its own tool surface. The analyst literally cannot
   touch infrastructure — it has no SSH tool. The infra manager can act, but only
   commands in its sudoers whitelist. Roles are scoped by construction, not by prompt.

2. **Cryptographic identity for every actor.** Every role holds a SPIFFE/SPIRE SVID
   (a short-lived, auto-rotating X.509 identity). Audit records are cryptographically
   bound to the actor that produced them. "Which agent did this?" has a cryptographic
   answer, not an IP guess.

3. **Dual-write audit with cross-reference.** Every incident gets a `case_id` minted
   at first detection. All roles read/write the same incident spine. Every write goes
   to TWO stores — a Qdrant working memory and an append-only JSONL receipt — so the
   stores can be cross-referenced for integrity. A reconciliation check detects
   divergence. The role that acts is never the role that verifies.

## The roles (built and running)

| Role | File | Tool surface | Does |
|------|------|-------------|------|
| infra-manager | `agents/agent.py` | Proxmox, Qdrant, SSH, self-heal, escalate | Senses host health, heals within whitelist, escalates outside it |
| analyst | `agents/analyst.py` | indexer (read-only), case spine, escalate | Recognizes signals, **investigates** (correlates across sources, scores the kill-chain), verdicts, escalates |
| hunt | `agents/hunt.py` | indexer (read-only), case spine, escalate | Runs hypothesis-driven pattern hunts, files/escalates findings |
| supervisory | (human / bot) | case spine, escalate, tuning | **Evidence-aware adjudication** — approves/denies based on the scored investigation; writes durable tuning |
| responder | `agents/responder.py` | case spine, playbooks, escalate | Executes approved playbooks, **obeys the supervisor's verdict** (refuses denied cases) |

The closed loop: **analyst recognizes + investigates → supervisor adjudicates WITH
the evidence → responder obeys the verdict → the human sees the whole chain in
the Closed Loop console** (`adjudication-console.html`, served by `adjudicate_api.py`).

## Current state (verified)

- **Two-backend doctrine proven on real data**: the same ontology executes
  identically on Wazuh AND Security Onion (see `verify/two_backend_cmp.py`).
- **Security-scanned clean**: bandit 0 HIGH, ruff 40 (deliberate blind-except
  paths only), verify matrix 30/30.
- **Developed against real APT data**: BOTSv1 (Boss of the SOC) ingested and
  used to validate the recognition + investigation layers against known-good
  answers (`docs/wayfinder/tickets/botsv1-ground-truth.md`).
- Start here: `docs/DEPLOYMENT.md` (13 steps, clone → running roles → pane of glass).

## Approval tiers

Every action is classified:

- **Tier 0 — Auto-heal:** within whitelist, executes immediately (apt upgrade, service restart). Audited.
- **Tier 1 — Single approval:** supervisory agent OR human signs off.
- **Tier 2 — Dual control:** BOTH must approve (destroy, network change, secret rotation).

Tier assignments are config, not code — any environment can re-map them.

## Repository layout

```
ssop/
├── agents/                 # Role state machines (LangGraph)
│   ├── agent.py            # infra-manager
│   ├── analyst.py          # analyst
│   ├── hunt.py             # hunt
│   └── tools/              # shared tool layer (Proxmox, Wazuh, Qdrant, SSH, case, escalate)
├── deploy/                 # Level 2: runnable stack
│   ├── docker-compose.yml  # Qdrant + (Wazuh single-node)
│   └── bootstrap.sh        # one-shot setup
├── docs/                   # Level 1: the learning resource
│   ├── ARCHITECTURE.md     # the ontology, in depth
│   ├── decisions/          # ADRs (why Qdrant, why local models, why LangGraph)
│   └── exercises/          # campaign templates
└── .env.example            # configuration template
```

## Two ways to use this repo

**Learn (Level 1):** read `docs/ARCHITECTURE.md` and the ADRs. The design decisions
are documented — why Qdrant over Pinecone (sovereignty), why local models for L1-L2
(control), why LangGraph (state machines are the right abstraction for roles).

**Deploy (Level 2):** see `docs/DEPLOYMENT.md`. Stands up Qdrant + Wazuh in Docker,
then wires the three role CLIs against them. Designed so a small team can run it in
an afternoon and extend it to their environment.

## Status

Working reference implementation (v0.1). Built and tested against a 5-VM Proxmox
homelab with a live Wazuh stack. The roles, case spine, dual-write audit, and
escalation path are all exercised end-to-end. SPIRE identity layer is integrated
in the reference deployment; the compose version ships with it documented but
optional so you can start without the CA ceremony.

## License

MIT — share, extend, deploy, sell it. Attribution appreciated, not required.
