# ADR-004: SOAR Layer (orchestrated response + blocking actions)

## ADR-004: SOAR Layer — approval-gated, auditable response playbooks

**Status:** accepted

**Date:** 2026-08-20

**Context**

The platform detects (analyst/router), hunts (hunt), heals within a whitelist
(infra-manager), and adjudicates (supervisory) — but it cannot CONTAIN a
threat. Detection without response is a report, not a SOC. Dropzone.ai
markets "contain threats in under 10 minutes" via black-box SaaS automation;
we want the same capability with our constraints: sovereignty (nothing leaves
the network), provability (every action on the spine), and the existing
three-tier approval model (Tier-0 whitelist / Tier-1 single / Tier-2 dual).

The user's direction: add a SOAR layer where AI enrichment RECOMMENDS SOAR
rules (playbooks) and the platform can take blocking actions under approval —
fulfilling the containment role.

**Decision**

Add a **responder role + playbook engine** layered on the existing authority
model:

1. **Playbooks are YAML data** (consistent with hunts/checks):
   ```yaml
   name: block-src-ip
   description: Block a source IP at the network firewall
   trigger: {category: threat, verdict: escalate}
   approval: tier2            # dual-control required (network change)
   steps:
     - action: firewall_block
       target: "{{alert.srcip}}"
       verify: "firewall rule present"
   ```
   Playbook library: `agents/playbooks/*.yaml`. Adding a playbook = adding
   a file — no code (per the data-driven rule).

2. **The responder role** (`agents/responder.py`, LangGraph state machine
   like the other roles): loads playbooks, matches triggers, executes steps
   through the infra-manager's tools, records every step on the case spine.

3. **AI enrichment recommends; the responder executes under approval:**
   - analyst/hunt/intel verdicts attach `recommended_playbook` to the case
     (enrichment only — never execution).
   - The router (or a scheduled sweep) hands the recommendation to the
     responder, which checks the playbook's `approval` tier:
     - Tier-1: responder executes directly (single approval = agent may,
       recorded on spine).
     - Tier-2: responder produces the playbook run as an ESCALATION ticket
       with the exact commands; supervisory/human approves; execution then
       proceeds and the outcome lands on the spine.

4. **Actions** execute through the existing whitelist where possible
   (e.g. `iptables`/`nftables` via the network VM's sudoers, service
   isolation via `systemctl` on a host) or a new sudoers entry per action
   type — the authority manifest remains the cage.

5. **Every playbook run** writes: case event (spine), audit JSONL entry
   (with SPIRE identity), and a pane-of-glass event — the containment
   action is provable end-to-end.

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Commercial SOAR (Tines, Splunk SOAR, Swimlane) | Mature, integrations, UI | SaaS/vendor lock, data leaves network, cost, black-box playbooks | Violates sovereignty + provability principles |
| Custom responder + YAML playbooks (chosen) | Sovereign, auditable, matches our data-driven pattern, additive | We build it; integration breadth ours alone | The whole point of SSOP |
| Extend infra-manager only (no new role) | Smallest change | Blurs separation of duties (heal vs contain); no playbook abstraction; AI-enrichment seam lost | Roles must stay distinct |
| LLM-executed containment | Flexible | Unprovable, hallucination risk on blocking actions | Rules-first: containment must be deterministic + approval-gated |

**Consequences**

- Easier: containment within minutes (Tier-1) or with dual-control (Tier-2);
  playbooks grow by dropping YAML; every block/quarantine is provable;
  Dropzone's "contain in 10 minutes" claim becomes OUR measured capability.
- Harder: sudoers manifest must extend per action type (network firewall,
  service isolation) — each new action is a deliberate, reviewed expansion
  of the cage; the responder's trigger-matching needs care to avoid
  self-inflicted blocks (verify matrix must cover this).
- New constraints: playbook actions are privileged — the verify framework
  gains playbook fixtures (dry-run playbooks against the spine, assert no
  real action without approval).

**Related**

- [[SSOP/architecture/Agent Tiers]]
- [[SSOP/decisions/ADR-002 - Local Models]] (model enrichment recommends playbooks)
- [[SSOP/decisions/ADR-001 - Qdrant]] (spine records playbook runs)
- [[SSOP/../PRODUCT_MAP]] (P1 roadmap item; Dropzone plagiarism ledger)
