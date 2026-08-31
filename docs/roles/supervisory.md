# Supervisory — approve | deny + playbook recommendation

`agents/tools/supervisory_tools.py` · the only role allowed to VERIFY the
others. Runs audit-integrity reconciliation (Qdrant vs JSONL), adjudicates
escalations (approve/deny with rationale), and owns the case spine's
accountability. In the reference deployment this is a human + Hermes.

## Inputs
- An escalation ticket or a case with an investigation timeline
- The case's verdict + investigation events (level, category, evidence,
  kill-chain)
- Observable enrichments (threat-intel verdicts)
- Tuning ledger (human decisions are the source of truth)

## Decision flow

### 1. Adjudicate a ticket (`supervisory_tools.py:58-100`)
Sets status/decision/rationale, then writes the decision to the TUNING
ledger as durable policy:
```
fp/deny        → auto_fp
approve        → escalate
operational    → operational
```
For hunt findings (no rule_id), the ledger key is the synthetic
`hunt:<id>` — so a human deny actually reaches the sweep and stops
re-ticketing. `mark_adjudicated` closes a ticket WITHOUT the tuning write
(duplicates of an already-adjudicated representative).

### 2. Evidence-aware adjudication (`supervisory_tools.py:152-229`)
Reads the scored investigation from the case timeline:
```
decision = approve  if severity_label == high
                 or (severity_label == medium AND len(kill_chain) >= 2)
         = deny     otherwise (weak evidence / no investigation)
```
On approve, recommends a matching playbook: rebuild a pseudo-alert from the
case's REAL analyst verdict (level + category) and match it against playbook
triggers — so the recommendation matches the live alert, not a synthetic
high level (`supervisory_tools.py:197-226`).

### 3. Context-aware supervision (`supervisory_tools.py:231-287`)
When a case carries enrichments/techniques:
- **Malicious enrichment** (GreyNoise) on any observable → approve
- **Benign on ALL** → deny (likely noise)
- `rootcheck`/`integrity` title → deny (FP class)
- `disk` title → approve (cleanup)
- MITRE techniques present → approve
- else → deny (`no actionable signal`)

## Outputs
`{decision, rationale, evidence, severity, recommended_playbook}` — written
to the case's `supervisory` field + timeline; ticket status updated; tuning
ledger written (when applicable).

## The recommendation is the SOAR handoff
The responder reads `supervisory.recommended_playbook` (or the timeline
adjudication event) and gates on it — a denied case must not execute
(`responder.py:323-331`).

## Verify coverage
`agents/verify/` — approve-on-high, approve-on-medium+2chain, deny-on-weak,
deny-on-no-investigation, playbook-recommendation-on-approve. Proven live:
SO brute-force → medium/2-chain → approve + block-src-ip; Cerber
ground-truth → high/3 sources → approve + block-src-ip (identical on both
backends).
