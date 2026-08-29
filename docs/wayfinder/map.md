# Wayfinder Map — P1: Intel Role + SOAR Responder

## Destination

P1 of the SSOP roadmap — Threat Intel Analyst (intel role → hunt packs) and
the SOAR responder — decided and specified enough to hand off as build
tickets. Reaching the end = every open question below resolved, each with a
spec (or an ADR) a builder can implement without re-deciding.

## Notes

- Domain: agentic SOC platform; sovereign, rules-first, provable.
- Consult skills: `ssop-code-standards` (every change additive, verify-gated,
  data-driven YAML), `wayfinder` (this method).
- Standing preferences: hunt packs = YAML files in `agents/hunts/` (already
  data-driven); playbooks = YAML in `agents/playbooks/`; approval model is
  Tier-0 whitelist / Tier-1 single / Tier-2 dual-control; nothing leaves the
  network (sovereignty); verify matrix must stay green.
- Map is DECISIONS ONLY (no execution) — hand off specs, don't build.

## Decisions so far

- [Intel sources for the intel role](tickets/intel-sources.md): CISA KEV
  (1,671 exploited vulns, keyless JSON) + NVD API 2.0 (keyless date-range
  sweep) — both sovereign public-domain; KEV vendor/product matches
  inventory; NVD fills CVSS/detail; no vendor RSS at P1.
- [Fleet inventory source for intel matching](tickets/fleet-inventory-source.md):
  Wazuh syscollector → `wazuh-states-inventory-*` indices (8 types, 4
  agents, rich host.os/package data). KEY GOTCHA: inventory is NOT in
  `wazuh-alerts-*` — intel role queries states indices directly.
- [Playbook schema + action registry](tickets/playbook-schema-actions.md):
  P1 ships whitelisted actions (service_stop/restart, host_quarantine,
  disk_clean + verify_*); firewall_block_ip + config_revert designed but
  require whitelist extension. config_revert is FIM-grounded (Wazuh
  syscheck, 63 alerts live). Schema = reusable step library, params in
  YAML, env from config.py. Full schema: playbook-schema.md.
- [Trigger matching + self-infliction guard](tickets/trigger-matching-guard.md):
  category+level = candidate, recommendation = gate (tier1+ needs
  recommended_playbook from a role). Protected set config-only (playbooks
  can't override), layered resolution (literal→CIDR→hostname), fail-closed
  whole-playbook block, blocked → spine + Tier-2 escalate (never silent).
- [Responder approval flow mechanics](tickets/approval-flow-mechanics.md):
  tier0/1 execute immediately; tier2 = ticket with run_id + full payload,
  approval mutates ticket (approved|denied), 15-min expiry, responder polls
  for approved+run_id match. Strict sequential steps, stop-on-first-failure,
  playbook_run recorded on spine + ticket.
- [Hunt-pack generation schema + quality gate](tickets/hunt-pack-schema.md):
  generated packs = valid hunt YAML targeting inventory indices (honest
  "do we have this product" hunts), meta block (cve_id/source/cvss). Gate:
  environment match (mandatory) + dedupe (mandatory) + staging-review
  (human/supervisory promotes). Intel flow: INGEST → MATCH → GENERATE →
  STAGE → PROMOTE.
- [SOAR verify fixtures prototype](tickets/soar-verify-fixtures.md):
  20-fixture spec in `agents/verify/fixtures_soar.yaml` (separate file) —
  trigger matching (5), guard (5), approval flow (6), execution (2),
  adversarial probes (2). Validated; drives a responder driver when built.

## Destination reached

All P1 tickets closed. The way is clear — hand off to build tickets:

- **Intel role (build-ready):** sources (KEV + NVD, keyless sovereign),
  inventory (syscollector states indices), pack schema + quality gate
  (env-match → dedupe → staging-review). Flow: INGEST → MATCH → GENERATE →
  STAGE → PROMOTE.
- **SOAR responder (build-ready):** playbook schema + action registry,
  trigger matching + self-infliction guard, approval flow (tier0/1/2 with
  15-min expiry), verification contract (20 fixtures).

## Not yet specified

- [Stateful analyst decision logic — tuning ledger + evidence chain](tickets/stateful-decision-logic.md):
  novelty → entity-recidivism → tuning → novel-gate flow; Qdrant `tuning`
  collection (human-written source of truth, analyst seeds); 5 W's + How
  evidence chain on escalation. SPEC'd, not yet built.
- Intel role cadence: scheduled (like analyst) vs event-driven (feed arrival
  → hunt pack) — a build-time decision, not blocking the spec.
- How playbook runs surface in the pane of glass (new event type vs
  existing) — a build-time decision.
- Sudoers whitelist extension mechanics for firewall_block_ip +
  config_revert (designed, not yet built — deferred to the build).

## Out of scope

_(nothing ruled out — P1 destination reached; P2+ items (org-context memory,
per-org policy, Cedar policy layer, ARENA) are separate efforts, per the
product map.)_
