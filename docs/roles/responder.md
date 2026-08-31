# Responder — execute under approval

`agents/responder.py` · executes playbooks (`agents/playbooks/*.yaml`) under
the approval model. Separation of duties: roles RECOMMEND playbooks
(enrichment); the responder EXECUTES under approval. Never targets protected
entities (fail-closed). Recommend, not NAC.

## Inputs
- An alert (normalized) + optional `recommended_playbook`
- The case spine (supervisor's decision + recommendation)
- Playbook library + config (`settings.protected_entities`, tiers)

## Decision flow (`responder.py:279-355`)

### 0. Approval gate from the case (`responder.py:293-331`)
The responder reads the supervisor's decision from the case
(`supervisory.recommended_playbook` + the timeline adjudication event). If
the supervisor DENIED the case → refuses to execute, no matter what was
recommended. Also pulls the analyst verdict category so live alerts carry
their classification for playbook matching.

### 1. Candidate selection + recommendation gate (`responder.py:136-152`)
A playbook fires if:
- its trigger matches the alert (`playbook.matches`: rule-id override, then
  category (single or list) + `level >= min_level`), AND
- a tier1+/recommended playbook fires ONLY if `recommended` names it — a
  role must have attached `recommended_playbook` to the case.

### 2. Self-infliction guard (`responder.py:63-107`, `201-208`)
Every step's `host`/`src_ip`/`target`/`ip` params (and `alert.srcip`) are
resolved against the protected set — literal → hostname alias → CIDR. ANY
protected target blocks the WHOLE playbook (fail-closed).

### 3. Tier check (`responder.py:242-276`)
- **tier0 / tier1** → execute immediately (`node_tier1_execute`), recorded
- **tier2** → create an escalation ticket with `run_id` + resolved params +
  expiry (`node_tier2_ticket`); execute only after human approval matches
  `run_id` and is not expired

### 4. Execution (`responder.py:159-173`)
Steps run strictly sequentially; STOP on first failure (recorded on spine +
ticket).

## Outputs
`{playbook, tier, blocked, blocked_reason, run_id, results, error,
supervisor_decision}`. Tier2 produces an approval ticket.

## Gates (in order)
1. Supervisor deny → refuse (authority)
2. Recommendation gate (tier1+ needs a role's recommendation)
3. Protected-entity guard (fail-closed)
4. Tier + approval expiry (15 min, `config.py:153`)

## Verify coverage
`agents/verify/fixtures_soar.yaml` — trigger matching, guard (protected
entities), approval flow (tier0/1/2, expiry), execution stop-on-failure,
adversarial probes. Proven live: drill chain recommend → approve →
block-src-ip; NAC experiment rolled back per doctrine (recommend/ticket,
not enforcement).
