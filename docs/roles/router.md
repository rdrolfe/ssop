# Router — which role owns an alert

`agents/router.py` · polls the indexer every 3 min (systemd timer) for NEW
alerts, classifies each, and dispatches to the owning role. Every dispatch
lands on the case spine.

## Inputs
- New alerts since the last run (cursor state file, `router_state.json`)
- `transport.yaml` rule map (active backend) + `settings.noise_rules`
- Tuning ledger (which rules a human already settled)

## Decision flow

### 1. Cursor dedupe
An alert id already in `seen_ids` is skipped (never dispatched twice).
Intake pages with a STABLE cursor: sort is `[<timestamp field> asc, _id asc]`
(the timestamp field comes from the active transport, never hardcoded) and
pagination resumes via `search_after` — a full page sharing one timestamp
can never strand later alerts. The cursor advances only past alerts whose
dispatch SUCCEEDED; a failed dispatch is retried on the next run, never
checkpointed.

Burst tracking keys on `rule.id|agent.name`; a repeat within the burst
window returns `count > 1`. Two guards prevent indefinite suppression: a
hard cap (`ROUTER_BURST_MAX_MIN`, default 60 min) expires the burst, and a
NEW entity (srcip/dstip the burst has never seen) breaks suppression — a
material change dispatches, equivalent echoes dedupe. Correlation work in
the router mint path is wall-clock budgeted (`ROUTER_CORRELATION_BUDGET_S`,
default 60 s) so escalation + cursor persist always fit inside the systemd
runtime budget.

### 2. Classify → (category, role)
In priority order:
1. **Noise rules** → `(operational, None)` — no dispatch (`settings.noise_rules = {5501, 5502, 5715}`).
2. **Tuned rules** (ledger `auto_fp`/`operational`) → suppressed UNLESS a
   MATERIAL delta (new attack groups / category became attack / threat-desc
   token / level rose) — `tuned_rule_suppresses`. A
   fingerprint-matching alert stays suppressed; a materially different one
   dispatches so the analyst applies the tuning override and the human
   re-adjudicates.
3. **Transport rule map** first, then the Wazuh
   `RULE_MAP` — backend-specific rules win.
4. **Group-string heuristics**:
   - `authentication_failed` / `invalid_login` → security/analyst
   - `rootcheck` → security/analyst
   - `apparmor` → pattern/hunt
   - `suricata` / `ids` → security/analyst
   - `low_diskspace` → infra/infra
   - `syscheck` / `fim` → security/analyst
5. **Wazuh RULE_MAP infra entries**: `531/501/502` (disk), `5402/5403`
   (sudo), `541/542/543` (systemd service health) → infra/infra.
   `dispatch_infra` senses + heals via the self-heal path AND mints a
   spine case (assignee=responder, recommended playbook attached) so
   fleet-sysadmin actions are auditable end-to-end.
6. **Ontology fallback**: an unmatched rule/group is
   categorized via `tools.ontology.categorize_alert` (the single source of
   truth) — `threat`/`authentication`/`integrity` → security/analyst,
   `compliance`/`operational` → no dispatch. The router must never silently
   drop a threat-category alert the analyst would call threat (same input,
   same outcome).
6. **Default** → `(operational, None)`.

### 3. Dispatch
- `role is None` → `no_dispatch_needed` (log only).
- `burst_count > 1` → `burst_deduped` — counted, not re-dispatched.
- else route by role:

**Security → analyst** (`dispatch_security`):
- `verdict == escalate` OR `existing_chain` → attach to the existing
  entity chain (no re-mint) or mint a case, then escalate tier-2.
- If the analyst recommended a playbook → hand to the responder.

**Pattern → hunt** (`dispatch_pattern`):
- rate-limited by `pattern_due` BEFORE running the hunt (`settings.pattern_rate_minutes = 60`) — a repeatedly-firing pattern rule
  (e.g. apparmor DENIED) can't mint a fresh case + ticket every dispatch.
- runs the matching hunt; if `suspicious` → hunt-level recidivism: attach a
  `pattern_recheck` to an existing OPEN case for that hunt
  (same guard `hunt.py` uses), else mint a case +
  escalate tier-2 when the category is in the attack set.

**Infra → infra-manager** (`dispatch_infra`):
- `sense → decide → heal` fixable issues; escalate tier-1 anything outside
  the whitelist.

## Outputs
`{action: dispatched_to_<role>, case_id?, verdict?, escalated?, ...}` per
alert; a run report with processed/dispatched counts. Cursor persisted.

## Gates
- Tuning + fingerprint-override
- Burst dedupe window (`settings.burst_window_min = 10`)
- Hunt rate limit (60 min)

## Verify coverage
`agents/verify/` — `inv_deduped_burst` exercises real `dispatch(alert,
burst_count=2)`; `inv_no_dispatch`/`inv_tuned` assert the tuning gates;
`inv_no_new_case` asserts `existing_chain` attach, not re-mint.
