# SSOP Role Decision Logic

How each role **decides** — the exact rules, inputs, and gates, pulled from
the code (file:line references), not the aspirational docs.

The decision spine is deterministic and auditable: rules do the work,
models only refine verdicts. Every role's decision flow is here.

## Quick map

| Role | Entry | Decides | Escalation |
|---|---|---|---|
| [Router](router.md) | `agents/router.py` | which role owns an alert, dedupe/noise | routes to analyst/hunt/infra |
| [Analyst](analyst.md) | `agents/tools/analyst_tools.py` | verdict: note \| escalate | tier-2 via router |
| [Hunt](hunt.md) | `agents/hunt.py` + `hunt_tools.py` | finding: clean \| info \| suspicious | tier-2 if attack category |
| [Investigator](investigator.md) | `agents/tools/investigator.py` | severity + kill-chain | evidence for supervisor |
| [Supervisory](supervisory.md) | `agents/tools/supervisory_tools.py` | approve \| deny + playbook | writes tuning ledger |
| [Responder](responder.md) | `agents/responder.py` | execute under tier-0/1/2 | ticket + approval |
| [Intel](intel.md) | `agents/intel.py` + `intel_tools.py` | match KEV → hunt packs | stages, never promotes |
| [Infra-manager](infra-manager.md) | `agents/tools/self_heal.py` | fixable vs escalate | tier-1 when outside whitelist |

## The decision chain (how they compose)

```
SIEM alert
  → Router: classify → (category, role), noise/dedupe/tuning gates
  → Analyst: verdict note|escalate (FP/noise/tuned gates → escalate on sev+cat)
  → Investigator: correlate entity → severity (log-count + breadth) + kill-chain
  → Supervisory: approve if high or (medium + ≥2 chain stages) → recommend playbook
  → Responder: playbook trigger → recommendation gate → guard → tier-0/1/2
  → case spine + ticket (dual-write Qdrant + JSONL, audit-reconciled)
```

Every decision a role makes is either a config threshold (see
[`agents/config.py`](../../agents/config.py)) or a data-driven YAML
(hunts, playbooks, checks, rule map in `transport.yaml`). Nothing is a
hardcoded constant inside a tool.

## Shared truth sources

- **Tuning ledger** (`tools/tuning_tools.py`) — human adjudication is final
  policy; analyst verdicts only seed entries. Keyed by `rule_id` or
  `hunt:<id>` for hunt findings.
- **Case spine** (`tools/case_tools.py`) — Qdrant + JSONL dual-write;
  `reconcile()` heals receipt-only cases, reports qdrant-only.
- **transport.yaml** — active backend, field map, and rule map (the
  ontology seam: re-mapping for a SIEM is a data edit, not code).
- **Verify matrix** — `agents/verify/` fixtures + invariants assert these
  decisions stay correct (30/30 green).

## Visual

The [role decision graph](../role-decision-graph.html) maps roles → tools →
stores as a single visual artifact.

## The docs are enforced, not just written

These docs are the ontology's spec — the source of truth we audit against.
Every `file:line` citation is verified by a **matrix gate**
(`verify/check_docs.py`, runs inside `verify.matrix`): it resolves each
citation's file (agents/, agents/tools/, agents/verify/), checks the range
is inside the file, and — where the doc names a symbol next to the citation
— asserts that symbol still appears in the cited lines.

A citation that no longer resolves (file moved, range past EOF, symbol
renamed/moved) turns the matrix **RED** (exit 1) — a divergence is a
correctness bug, not a docs housekeeping issue. Proven non-vacuous by
`verify/test_check_docs.py` (past-EOF and symbol-moved corruptions are both
caught; baseline clean). The daily digest surfaces it as **Docs: …** each
morning.

**Process implication:** change the code first, then the docs that cite it
(or both in one change) — a stale citation is a failing gate, same as a
failing invariant.
