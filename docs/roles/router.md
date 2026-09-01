# Router — which role owns an alert

`agents/router.py` · polls the indexer every 3 min (systemd timer) for NEW
alerts, classifies each, and dispatches to the owning role. Every dispatch
lands on the case spine.

## Inputs
- New alerts since the last run (cursor state file, `router_state.json`)
- `transport.yaml` rule map (active backend) + `settings.noise_rules`
- Tuning ledger (which rules a human already settled)

## Decision flow

### 1. Cursor dedupe (`router.py:147-153`)
An alert id already in `seen_ids` is skipped (never dispatched twice).
Burst tracking keys on `rule.id|agent.name` (`router.py:502`); a repeat
within the burst window returns `count > 1`.

### 2. Classify → (category, role) (`router.py:184-225`)
In priority order:
1. **Noise rules** → `(operational, None)` — no dispatch (`router.py:189-190`,
   `settings.noise_rules = {5501, 5502, 5715}`).
2. **Tuned rules** (ledger `auto_fp`/`operational`) → suppressed UNLESS the
   alert carries `strong_tp_evidence` (`router.py:196-204`) — a tuned-FP rule
   must not blind the SOC to a real TP; it dispatches so the analyst can
   apply the tuning override.
3. **Transport rule map** first (`router.py:207-209`), then the Wazuh
   `RULE_MAP` (`router.py:51-80`, `210-211`) — backend-specific rules win.
4. **Group-string heuristics** (`router.py:213-224`):
   - `authentication_failed` / `invalid_login` → security/analyst
   - `rootcheck` → security/analyst
   - `apparmor` → pattern/hunt
   - `suricata` / `ids` → security/analyst
   - `low_diskspace` → infra/infra
   - `syscheck` / `fim` → security/analyst
5. **Default** → `(operational, None)` (`router.py:232`).

### 3. Dispatch (`router.py:400-423`)
- `role is None` → `no_dispatch_needed` (log only).
- `burst_count > 1` → `burst_deduped` — counted, not re-dispatched.
- else route by role:

**Security → analyst** (`dispatch_security`, `router.py:286-353`):
- `verdict == escalate` OR `existing_chain` → attach to the existing
  entity chain (`router.py:298-307`, no re-mint) or mint a case
  (`router.py:308-321`), then escalate tier-2.
- If the analyst recommended a playbook → hand to the responder
  (`router.py:327-346`).

**Pattern → hunt** (`dispatch_pattern`, `router.py:356-410`):
- rate-limited by `pattern_due` BEFORE running the hunt (`router.py:380-384`,
  `settings.pattern_rate_minutes = 60`) — a repeatedly-firing pattern rule
  (e.g. apparmor DENIED) can't mint a fresh case + ticket every dispatch.
- runs the matching hunt; if `suspicious` → hunt-level recidivism: attach a
  `pattern_recheck` to an existing OPEN case for that hunt
  (`router.py:393-404`, same guard `hunt.py` uses), else mint a case +
  escalate tier-2 when the category is in the attack set (`router.py:385`).

**Infra → infra-manager** (`dispatch_infra`, `router.py:249-283`):
- `sense → decide → heal` fixable issues; escalate tier-1 anything outside
  the whitelist.

## Outputs
`{action: dispatched_to_<role>, case_id?, verdict?, escalated?, ...}` per
alert; a run report with processed/dispatched counts. Cursor persisted.

## Gates
- Tuning + strong-TP override (`router.py:196-204`)
- Burst dedupe window (`settings.burst_window_min = 10`)
- Hunt rate limit (60 min)

## Verify coverage
`agents/verify/` — `inv_deduped_burst` exercises real `dispatch(alert,
burst_count=2)`; `inv_no_dispatch`/`inv_tuned` assert the tuning gates;
`inv_no_new_case` asserts `existing_chain` attach, not re-mint.
