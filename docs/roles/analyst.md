# Analyst — verdict: note | escalate

`agents/tools/analyst_tools.py` · reactive triage: consumes alerts,
classifies them, and produces a deterministic verdict. Read-only against the
SIEM — by construction it cannot change infrastructure.

## Inputs
- An alert (already normalized by the transport)
- `settings.fp_rule_ids`, `settings.noise_rules`
- Tuning ledger (human decisions)

## Decision flow

### 1. Classify → category + severity (`analyst_tools.py:55-100`)
Category heuristics on `rule.groups` + description tokens:
- `authentication` / `authentication_failures` group → **authentication**
  (`:71-72`)
- threat-class description token (`et malware`, `et c2`, `malicious`, …)
  or `attack`/`malware`/`threat`/`exfiltration`/`c2` group → **threat**
  (`:73-77`)
- `rootcheck`/`syscheck`/`pci_dss` → **integrity** (`:78-80`)
- `policy`/`vulnerability` → **compliance** (`:81-82`)
- else → **operational** (`:83`)

Severity: `level >= settings.high_level (7)` → high (`:84`).

### 2. Verdict (`analyst_tools.py:103-234`)
In priority order:
1. **Known-FP rule** (`rule_id in settings.fp_rule_ids`, default `{510}`)
   → `note` (`:117-124`).
2. **Noise rule** (`rule_id in settings.noise_rules`) → `note` (`:125-133`).
3. **Tuned rule** (ledger `auto_fp`/`operational`) → `note`, BUT
   `strong_tp_evidence(alert)` (threat-desc token or level ≥ high) lifts the
   tuning → `escalate` with `tuning_override=True` so the tuning itself is
   re-adjudicated (`:137-169`).
4. **Escalate decision** (`:170-210`):
   ```
   escalate = severity == high
              or (severity == medium AND category in settings.medium_escalate_categories)
   ```
   `medium_escalate_categories = ("authentication", "threat")`
   (`config.py:111`).
5. **Entity recidivism** — if the same `(srcip, dstip)` pair has a recent
   open case (`case_tools.recent_entity_cases`), the verdict surfaces
   `existing_chain` so the router ATTACHES instead of re-minting (`:195`).

### 3. Write path (`analyst.py::process_alert`)
On escalate: mint/attach case, append verdict + investigation events,
escalate. The single-node + sweep paths share this write path.

## Outputs
`{verdict: note|escalate, level, category, agent, rationale, ...}` —
optionally `existing_chain`, `tuning_override`, `recommended_playbook`.

## Config thresholds (`config.py:107-116`)
| Key | Default | Meaning |
|---|---|---|
| `ANALYST_HIGH_LEVEL` | 7 | level ≥ 7 → severity high |
| `ANALYST_MEDIUM_LEVEL` | 4 | level ≥ 4 → severity medium |
| `medium_escalate_categories` | auth, threat | categories that escalate at medium (`config.py:111`) |
| `ANALYST_FP_RULE_IDS` | 510 | never auto-escalate (rootcheck) |
| `noise_rules` | 5501,5502,5715 | baseline events → note |

## Gates
- FP / noise rule classes
- Tuning ledger (human decisions) + strong-TP override
- Entity recidivism (attach, not re-mint)
- Anti-noise: single SSH auth failure (5710) → `note` is CORRECT, not a miss
  (validated by the daily purple-team drill)

## Verify coverage
`agents/verify/` — verdict/classify fixtures (auth/threat/integrity/
compliance/operational), tuned/FP/noise gates, recidivism seed fixture
(`no_new_case` invariant fails without the seed — proven non-vacuous).
