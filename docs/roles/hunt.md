# Hunt — proactive finding: clean | info | suspicious

`agents/hunt.py` (state machine) + `agents/tools/hunt_tools.py` (library +
analyzers) · the PROACTIVE half of detection: starts from a hypothesis, not
an alert, and tests it against SIEM telemetry. Read-only. Also seeds
detection recommendations.

## Inputs
- Hunt library: `agents/hunts/*.yaml` — data-driven (adding a hunt = a
  YAML file, no code). Each spec: `{name, category, hypothesis, analyze,
  query, _source}`.
- The active backend's alert index (time-bind on the transport's timestamp
  field, `hunt_tools.py:69-75`).
- Tuning ledger (keyed `hunt:<id>` for hunt findings).

## Decision flow

### 1. Run a hunt (`hunt_tools.py:63-95`)
Executes the YAML query (time-bounded to `days`), then dispatches to the
analyzer named by `spec["analyze"]` (`hunt_tools.py:83`, fallback
`_analyze_generic`). Analyzers:
- `generic`, `bots_attack` (BOTSv1 ground-truth)
- `srcip_frequency` (auth-from-unusual-src)
- `apparmor`, `rootcheck`, `sca`, `sudo`
- `so_severity`, `so_detection` (Security Onion native shapes)

Each returns `{finding: clean|info|suspicious, confidence, summary, notes,
detail, ...}`.

### 2. Escalate decision (`hunt.py:70-71, 181`)
```
esc = finding == "suspicious" AND category in ESCALATE_CATEGORIES
ESCALATE_CATEGORIES = {lateral-movement, defense-evasion, privilege-escalation}   (hunt.py:38)
```

### 3. Tuning respect (`hunt.py:74-96`)
A human `auto_fp`/`operational` on `hunt:<id>` suppresses the hunt: attach a
recheck to an open case if one exists, NEVER mint a new case/ticket.

### 4. Hunt-level recidivism (`hunt.py:97-119`)
A persistent finding ATTACHES a recheck to the existing open case for that
hunt (`case_tools.recent_hunt_cases`) — no re-mint. Escalates once per case
(re-arms on close).

### 5. Re-arm cooldown (`hunt.py:120-128`)
A finding whose case was recently CLOSED (e.g. denied) is not instantly
re-minted — a chronic FP must not re-ticket every sweep until a human tunes
it.

### 6. New finding → mint + escalate (`hunt.py:129-147`)
Mint a case, append finding + verdict events, escalate tier-2 when `esc`.
The verdict event carries level/category so the supervisory recommendation
matches the finding (a hunt escalation reaches the human with a playbook,
not bare).

## Outputs
Per-hunt: `{finding, confidence, summary, notes, events_scanned,
window_days}`. Sweep aggregates lines; escalated findings mint cases +
tickets.

## Gates
- `ESCALATE_CATEGORIES` (attack categories only)
- Tuning suppress (`hunt:<id>`)
- Recidivism attach (no re-mint)
- Re-arm cooldown (recently-closed case)

## Verify coverage
`agents/verify/` — hunt sweep fixtures assert clean/info/suspicious
classification, escalation on attack categories, tuning suppress, recheck
attach. SO-native hunts proven live (Grid Node SSH brute-force → escalate →
approve → block-src-ip).
