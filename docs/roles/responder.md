# Responder — execute under approval

`agents/responder.py` · executes playbooks (`agents/playbooks/*.yaml`) under
the approval model. Separation of duties: roles RECOMMEND playbooks
(enrichment); the responder EXECUTES under approval. Never targets protected
entities (fail-closed). Recommend, not NAC.

## Inputs
- An alert (normalized) + optional `recommended_playbook`
- The case spine (supervisor's decision + recommendation)
- Playbook library + config (`settings.protected_entities`, tiers)

## Decision flow

### 0. Approval gate from the case
The responder reads the supervisor's decision from the case
(`supervisory.recommended_playbook` + the timeline adjudication event). If
the supervisor DENIED the case → refuses to execute, no matter what was
recommended. Also pulls the analyst verdict category so live alerts carry
their classification for playbook matching.

### 1. Candidate selection + recommendation gate
A playbook fires if:
- its trigger matches the alert (`playbook.matches`: rule-id override, then
  category (single or list) + `level >= min_level`), AND
- a tier1+/recommended playbook fires ONLY if `recommended` names it — a
  role must have attached `recommended_playbook` to the case.

### 2. Self-infliction guard (`guard_check`)
Every step's `host`/`src_ip`/`target`/`ip` params (and `alert.srcip`) are
resolved against the protected set — literal → hostname alias → CIDR. ANY
protected target blocks the WHOLE playbook (fail-closed).

### 3. Tier check (tier routing in `build_graph`)
- **tier0 / tier1** → execute immediately (`node_tier1_execute`), recorded
- **tier2** → create an escalation ticket with `run_id` + resolved params +
  expiry (`node_tier2_ticket`); execute only after human approval matches
  `run_id` and is not expired

### 4. Execution (`execute_playbook`)
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

---

## Worked examples — proven live 2026-09-09 (fleet-sysadmin role)

Operator framing (2026-09-09): the responder is a **sysadmin role with
responder capabilities** — (a) the agent managing OUR fleet, (b) a library
of example chains for operators. The tier0/tier1 playbooks are SRE moves
(service checks, restarts, disk clean); the tier2 containment playbooks
stay dormant until a real containment target exists.

Sanctioned target: `192.168.1.13` (network host) — REMOVED from
`settings.protected_entities` for this role; every other fleet host
remains fail-closed protected. Demo service: `ssop-demo-svc` on .13
(harmless sleep, systemd unit written via the whitelisted sudo path).

### Example 1 — tier1 read-only: service-impact-check

```
alert (synthetic, rule 40704 systemd/infra, level 4, agent=.13)
  → responder.run(recommended="service-impact-check")
    → select: matches trigger (category infra, level>=4)
    → guard: target .13 not protected (sanctioned), param resolves
    → tier1: execute [verify_service_state] → "suricata is active"
```
Result: `blocked=false, tier=tier1, results[0].ok=true`.

### Example 2 — tier1 execute: restart-flapping-service

```
alert (rule 541 systemd/operational, level 5, agent=.13, service=ssop-demo-svc)
  → responder.run(recommended="restart-flapping-service")
    → select → guard → tier1 execute:
       service_restart   ok (whitelisted systemctl restart)
       verify_service_state ok ("active (expected active)")
```

### Example 3 — FULL LOOP: router → case → responder → spine receipt

1. Synthetic alert doc `resp-flap-proof` (rule 541) injected into the live
   Wazuh index (`deploy/lab/prove_responder_full.py`).
2. Router sweep classifies via RULE_MAP `541 → (infra, infra)`;
   **`dispatch_infra` mints a spine case** (`assignee=responder`) with the
   recommended playbook attached — infra events are auditable like security
   cases.
3. Router records the ADJUDICATION on the spine as it mints — `decide(...,
   role="router")`, so the case is `state=decided` with the decision, the
   rationale and the deciding role on it, not merely a dispatch event. For
   infra events the ROUTER is the approving authority (operator policy: no
   supervisory pass on fleet-sysadmin events): tier0/tier1 recommendation →
   `approve`; no/tier-less/unknown playbook → `operational` (no response
   required); a tier2 playbook is NEVER router-authorized — only the
   supervisory run_id path may. `approve ≠ close`: the responder below still
   executes and closes. (Rule: `agents/tools/infra_disposition.py`.)
4. `responder.run(case_id=...)` reads the router approval from the spine
   (approval-gate extension 2b), executes restart + verify, appends the
   `responder_execution` event.
5. Verified: spine timeline carries `responder/execution` with all steps ok.

### Rules for extending

- New infra trigger → add the rule id to RULE_MAP (`infra`, `infra`) +
  update this doc (the docs gate enforces citation drift).
- New playbook → `agents/playbooks/*.yaml`; tier0/1 auto-fire on
  trigger+recommendation; tier2 requires supervisory run_id approval.
- Re-protecting .13 → re-add `192.168.1.13` to `protected_entities` in
  `agents/config.py` — the guard then blocks everything again (fail-closed).
