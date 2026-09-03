# Analyst — verdict: note | escalate

`agents/tools/analyst_tools.py` · reactive triage: consumes alerts,
classifies them, and produces a deterministic verdict. Read-only against the
SIEM — by construction it cannot change infrastructure.

## Inputs
- An alert (already normalized by the transport)
- `settings.fp_rule_ids`, `settings.noise_rules`
- Tuning ledger (human decisions)

## Decision flow

### 1. Classify → category + severity (`analyst_tools.py:55-85`)
Category is the SINGLE shared source of truth — `tools/ontology.py`
`categorize_alert()` — used identically by the analyst verdict and the router
dispatch (no local re-derivation; that drift is what let a tuned-FP rule be
treated differently by each path — the Sep 2026 dpkg flood). Heuristics on
`rule.groups` + description tokens (`ontology.py:36-62`):
- `authentication` / `authentication_failed` / `authentication_failures`
  group → **authentication**
- threat-class description token (`et malware`, `et c2`, `malicious`, …)
  or `attack`/`malware`/`threat`/`exfiltration`/`c2` group → **threat**
- `rootcheck`/`syscheck`/`pci_dss` → **integrity**
- `policy`/`vulnerability` → **compliance**
- else → **operational**

Severity: `level >= settings.high_level (7)` → high (`analyst_tools.py:66-71`).

### 2. Verdict (`analyst_tools.py:87-215`)
In priority order:
1. **Known-FP rule** (`rule_id in settings.fp_rule_ids`, default `{510}`)
   → `note` (`:102-110`).
2. **Noise rule** (`rule_id in settings.noise_rules`) → `note` (`:111-117`).
3. **Tuned rule** (ledger `auto_fp`/`operational`) → `note`, BUT
   `tuned_rule_suppresses(tuning, alert, category)` (`tuning_tools.py`) lifts
   the tuning on a MATERIAL fingerprint delta (threat-desc token appeared,
   category became attack-class, new attack groups, or level rose) →
   `escalate` with `tuning_override=True` so the tuning itself is
   re-adjudicated. Legacy entries without a stored fingerprint fall back to
   the config-gated `strong_tp_evidence` heuristic (`:118-149`).
4. **Escalate decision** (`:151-165`):
   ```
   escalate = severity == high
              or (severity == medium AND category in settings.medium_escalate_categories)
              or (category == threat AND threat-desc token)   # ET malware at low lvl
   ```
   `medium_escalate_categories = ("authentication", "threat")`
   (`config.py:111`).
5. **Entity recidivism** — if the same `(srcip, dstip)` pair has a recent
   open case (`case_tools.recent_entity_cases`), the verdict surfaces
   `existing_chain` so the router ATTACHES instead of re-minting (`:166-181`).
   **Host recidivism fallback** — alerts with NO entity pair (sysmon host
   events, no srcip/dstip) chain on `(agent, rule_id)` via
   `case_tools.recent_host_cases` (same window): one campaign = one case
   per host, not N cases per event (the BOTS Cerber replay finding — 133
   cases for one campaign). Cases must carry `source.rule_id` at mint.
6. **SOAR enrichment** — matching playbook attached for the responder
   (`:182-193`); MITRE ATT&CK techniques surfaced (`:198-203`).

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
| `medium_escalate_categories` | auth, threat | categories that escalate at medium (`config.py:164`) |
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
