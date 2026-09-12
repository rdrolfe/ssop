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
- The in-lab MISP corpus, for BULK intel (below).

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
detail, ...}`. `detail` carries the events the hunt returned (capped at 5),
which is what the bulk-intel step consumes.

### 2. Bulk intel — LOCAL CORPUS FIRST (`hunt.py:82-115, 153-155`)
`collect_observables` (`tools/bulk_intel.py:194`) extracts TYPED observables
(ip/hash/domain/url, via `tools/observables.py`) from the hunt's returned
events; `bulk_intel_for` (`tools/bulk_intel.py:219`) matches them against the
in-lab MISP corpus through `tools/misp_client.py` — thousands of pooled
community-feed indicators, matched in batched requests, locally (sovereignty:
the data plane comes to us). See ADR-007.

External per-indicator provider lookups (GreyNoise/VT/OTX) are spent ONLY on
the corpus-matched survivors, and ONLY when `intel_external=1` is passed —
they are metered (VT quota) and are the cost bulk matching exists to reduce.
An unconfigured or unreachable corpus spends NOTHING: no silent per-indicator
fan-out.

Both entry points live in `tools/bulk_intel.py` rather than in the role, so the
LIVE sweep and the `verify` matrix run the same derivation — the "one surface
deriving what another already knows, differently" failure this project keeps
paying for.

### 3. Promotion — a match is EVIDENCE (`tools/bulk_intel.py:52-77`)
```
strong match (hash/domain/url)  -> finding becomes "suspicious"
weak match   (bare ip)          -> clean -> "info"; nothing else changes
corpus UNKNOWN / unreachable    -> finding UNCHANGED (never promotes on stale intel)
```
A bare-IP match is deliberately weak: scanning infrastructure and CDN
addresses are shared, so an IP match alone is a lead, not a detection. The
promotion is recorded on the case (`_intel_evidence`, `hunt.py:82`) together
with the matched values and provenance — "not checked" and "checked, nothing
found" stay distinguishable on the spine.

### 4. Escalate decision (`hunt.py:156-157, 305`)
```
esc = finding == "suspicious" AND category in ESCALATE_CATEGORIES
ESCALATE_CATEGORIES = {lateral-movement, defense-evasion, privilege-escalation}   (hunt.py:49)
```
Escalation is still owned by this gate on the FINDING WORD — bulk intel
decides how much a corpus match is worth, never which category escalates.

### 5. Tuning respect (`hunt.py:160-172`)
A human `auto_fp`/`operational` on `hunt:<id>` suppresses the hunt: attach a
recheck to an open case if one exists, NEVER mint a new case/ticket.

### 6. Hunt-level recidivism (`hunt.py:179-194`)
A persistent finding ATTACHES a recheck to the existing open case for that
hunt (`case_tools.recent_hunt_cases`) — no re-mint. Escalates once per case
(re-arms on close).

### 7. Re-arm cooldown (`hunt.py:212-220`)
A finding whose case was recently CLOSED (e.g. denied) is not instantly
re-minted — a chronic FP must not re-ticket every sweep until a human tunes
it.

### 8. New finding → mint + escalate (`hunt.py:237-257`)
Mint a case, append finding + verdict events, escalate tier-2 when `esc`.
The verdict event carries level/category so the supervisory recommendation
matches the finding (a hunt escalation reaches the human with a playbook,
not bare).

## Outputs
Per-hunt: `{finding, confidence, summary, notes, events_scanned,
window_days}`. Sweep lines carry an `intel: N/M known` marker from
`_intel_suffix` (`hunt.py:106`).
Escalated findings mint cases + tickets; a strong corpus match mints a case
even for a hunt that would otherwise have been clean.

## Gates
- `ESCALATE_CATEGORIES` (attack categories only)
- Tuning suppress (`hunt:<id>`)
- Recidivism attach (no re-mint)
- Re-arm cooldown (recently-closed case)
- Bulk intel: survivors-only external spend; degraded corpus never promotes

## Verify coverage
`agents/verify/` — hunt sweep fixtures assert clean/info/suspicious
classification, escalation on attack categories, tuning suppress, recheck
attach. SO-native hunts proven live (Grid Node SSH brute-force → escalate →
approve → block-src-ip). `verify/test_bulk_intel.py` pins the bulk-intel
contract hermetically (survivors-only, no-filter-no-spend, degraded≠clean,
promotion rule), and the matrix runs two checks on the hunt→MISP path: the
`hunt_intel` invariant (`verify/invariants.py`) fails a hunt driver run whose
corpus match did not happen or whose corpus was unreachable, and the
`misp corpus` gate (`verify/matrix.py`) probes the corpus directly once per
matrix. The gate exists because the invariant alone is **vacuous in practice** —
live hunts usually return no extractable observables, so the invariant skips,
and a skip is not evidence that the corpus was ever consulted.

---

## Threat-intel workflow — BUILT (2026-09-12)

The hunt role is the consumer of BULK threat intel. It was roadmap until the
in-lab MISP feed platform landed (`docs/feeds-and-licensing.md`,
`docs/decisions/ADR-007 - MISP Feed Platform.md`): pooled community feeds are
pulled LOCALLY (sovereignty doctrine — the data plane comes to us) and matched
against hunt query results in bulk BEFORE resorting to per-indicator external
lookups. That converts hunt from "pivot then look up each" into "match
thousands of known indicators at once, look up only the survivors."

What was built:
- `tools/misp_client.py` — the bulk read-only matching client (`POST
  /attributes/restSearch` with a value list; verified shape).
- `tools/bulk_intel.py` — the cost contract: match locally, spend externally
  only on survivors, degrade to UNKNOWN rather than to "clean".
- `agents/hunt.py` — the sweep and single-hunt paths run bulk intel after
  analysis and before the case/escalation decision.

NOT built, deliberately: any path that contributes our observables back to
MISP or a feed. That is a DISCLOSURE event (ADR-007 call 3) and there is no
`submit` entry — `verify/test_misp_client.py` and `verify/test_bulk_intel.py`
enforce statically that no write endpoint can appear in either module.
