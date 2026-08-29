# SSOP Product Map

North star: **a sovereign, provable, machine-scale SOC that any team can run —
from a laptop to a fleet.** Rules do the deterministic work; models refine
verdicts; every action is auditable; every claim is measurable.

This map tracks current state, the roadmap, and where ideas came from
(including the competitive analysis of Dropzone.ai — see "Plagiarism ledger").

---

## Current state (ships today)

| Capability | Where |
|---|---|
| SOC role agents (infra-manager, analyst, hunt, supervisory) | `agents/*.py` |
| Case spine: Qdrant + JSONL dual-write, reconcile audit | `tools/case_tools.py` |
| Event-driven router (3-min dispatch, burst dedupe, noise filter) | `agents/router.py` |
| Scheduled operation (analyst 2h, self-heal + supervisory daily) | `deploy/systemd/` |
| Network plane (Suricata IDS → Wazuh), custom drill kit | `deploy/suricata/` |
| Pane of glass (OTel → ssop-events index → dashboards) | `deploy/otel-config.yaml` |
| Verification matrix (21 fixtures × 3 role drivers, all green) | `agents/verify/` |
| Data-driven definitions (hunts YAML, checks YAML) | `agents/hunts/`, `agents/checks.yaml` |
| Central config, registry singletons, logging, exception discipline | `agents/config.py` |
| Authority manifest → sudoers whitelist (3-tier approval model) | deploy + docs |

---

## Roadmap

### P1 — Threat Intel Analyst + hunt packs (from Dropzone: AI Threat Intel Analyst)

**Problem:** advisories/CVEs arrive daily; turning them into detection is manual.
**Approach:** a new `intel` role that reads advisories (NVD/CISA feeds, RSS),
matches against OUR environment (OS/software inventory from the fleet), and
auto-generates hunt YAML files (`agents/hunts/*.yaml`). The router/hunt roles
pick them up with zero code change — our YAML hunt library is the hunt-pack
format, already built.
**Status:** next build. Natural fit: intel = data-in → hunt packs = data-out.

### P1 — SOAR layer (orchestrated response + blocking actions) — see ADR-004

**Problem:** detection without response is a report, not a SOC. Dropzone claims
"contain threats in under 10 minutes" — we should do it with approval-gated,
auditable playbooks, not black-box automation.
**Approach:** a `responder` role + playbook engine layered on the existing
authority model:
- Playbooks = YAML (consistent with hunts/checks): trigger condition, steps,
  approval tier required.
- Actions execute through the infra-manager's whitelist (e.g. firewall block
  via network VM, service isolation via systemctl) or escalate to Tier-2
  dual-control when the action is outside the whitelist.
- Every playbook run writes to the case spine + audit trail — provable.
- **AI enrichment angle:** analyst/hunt/intel verdicts RECOMMEND playbooks
  ("this C2 beacon matches playbook: block-src-ip") without executing them;
  the responder runs them under the approval model.
**Status:** design in ADR-004; build after intel role.

### P2 — Cedar-style policy layer (ADR-005) — from peer review

**Problem:** the authority manifest is RBAC-ish (role→command whitelist) with
no expressive conditions and no automated provability — sudoers is opaque.
**Approach (layered, not a switch):** the manifest becomes Cedar-style
policies (`permit`/`forbid` with ABAC conditions) ABOVE the sudoers
enforcement floor. Roles ask the policy engine "is this action permitted?"
before executing; sudoers stays the kernel-enforced cage. Integration via the
`cedar` CLI binary (Rust-first; the PyPI stub is NOT the path). Immediate
incremental win: a `policy_checker` that statically proves the manifest +
sudoers consistent (the validator idea, buildable without Cedar wholesale).
**Status:** ADR-005 accepted; build after P1.

### P2 — Org-context memory (from Dropzone: "context memory unique to your organization")

**Problem:** "what's normal for THIS network" is implicit knowledge.
**Approach:** an org-baseline store in Qdrant (which hosts talk to which,
normal auth sources, expected services) that analyst/hunt decisions consult
before escalating. Turns "unusual" from vibes into "differs from baseline."
Leverages the existing Qdrant `ltp` collection.

### P2 — Per-org outcome rules (from Dropzone: "outcome rules")

**Problem:** escalation policy is currently config constants; orgs want policy.
**Approach:** formalize a per-org policy file (YAML: which alert classes
escalate, which playbooks auto-approve at Tier-1, which require Tier-2) that
wraps the existing config.py thresholds + authority manifest. The friend's
"config file for thresholds" review point, promoted to first-class policy.

### P3 — ARENA benchmark (the measured answer to "5x faster MTTR")

**Problem:** Dropzone markets claims; we measure.
**Approach:** lm-eval-harness task suite benchmarking ROLE performance
(verdict accuracy, false-escalation rate, determinism, latency, hallucination)
across models, community-auditable. The verify fixture library is the seed
corpus; every real adjudication grows it. The numbers we publish will be
reproducible — that's the honest version of the enterprise pitch.

---

## Plagiarism ledger (what we took from Dropzone.ai, and why)

Dropzone validated our architecture (agent roles, case threading, evidence
trails, custom strategy, 24/7) and beat us to market as an LLM-first SaaS.
Ideas adopted, adapted to our sovereign/rules-first model:

| Their idea | Our adaptation | Status |
|---|---|---|
| AI Threat Intel Analyst → hunt packs | `intel` role → hunt YAML generation | P1, next |
| Containment automation ("10-min MTTR") | SOAR responder + playbooks, approval-gated | P1, ADR-004 |
| Org context memory | org-baseline in Qdrant feeding verdicts | P2 |
| Outcome rules | per-org policy YAML | P2 |
| Marketing metrics (5x MTTR, 85%) | ARENA measured, auditable metrics | P3 |
| 90+ integrations | sovereign core + Wazuh/Suricata/Qdrant/Proxmox; adapters additive | ongoing |

**Peer review (Shotgun):** Cedar policy language evaluated (ADR-005) — not a
switch; layered adoption as the P2 policy layer over the manifest, sudoers
stays the enforcement floor. The validator idea (prove the authority model
consistent) is the incremental win.

**What we keep that they can't copy:** air-gap/sovereignty (they're SaaS),
provability (SPIRE identity + dual-write spine + receipts), cost (MIT),
rules-first determinism (no hallucinated 3AM verdicts — verify-enforced).

---

## Principles that govern the map

1. Every layer additive — verify matrix must stay green.
2. Data over code: hunts, checks, playbooks, policy = YAML.
3. Approvals: Tier-0 auto (whitelist) / Tier-1 single / Tier-2 dual-control.
4. Sovereignty: nothing leaves the network; models optional, local-first.
5. Provability: every action on the spine, every claim benchmarked.
