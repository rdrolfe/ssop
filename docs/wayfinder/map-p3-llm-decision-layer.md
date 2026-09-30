# Wayfinder Map — P3: LLM Decision Layer

## Destination

SSOP has a model-advised decision layer that runs **in addition to** the
deterministic one: at least one decision in the case lifecycle is proposed by
a model, adjudicated against code, and the deterministic path remains the
fail-closed default when the model is absent, slow, or wrong — with a gate
proving the default still holds.

Reaching the end = one named decision carries a model-authored recommendation
on the case record; `supervise_case` (or the named decision) consumes it as
*advice* while its existing deterministic verdict stays authoritative; a
negative control proves the deterministic path is unchanged when the model
call is forced to fail; the matrix is green and the drill invariant (benign
activity → `['note','note']` → zero tier-2 escalations) is re-proved in the
same session.

**This destination is explicitly NOT "adopt an agent framework."** The
2026-09-30 framework briefing (below) found the framework question largely
moot: LangGraph is active (1.2.12, 43.6M downloads/mo), the vendors who
criticize graphs ship graph runtimes, and `langchain` is built on LangGraph.
The gap in this stack is not the orchestration substrate — it is that **no
decision is currently made by a model at all**. That is what this map finds
its way to.

## Notes

- Domain: model-advised adjudication inside a sovereign, rules-first SOC.
- Consult skills: `ssop-code-standards` (additive, verify-gated, data-driven),
  `wayfinder` (this method), `ssop-platform-ops` (deploy mechanics),
  `ssop-runtime-ops` (debug the deployed runtime), `research` /
  `grounded-citations` (cite before code).
- **Standing constraint — sovereignty:** the model call is EGRESS. It must be
  declared in `agents/transport.yaml` and pass `check_egress` like every other
  outbound path. An undeclared model call is a sovereignty violation, not a
  style question. Decide the class (`lookup` vs `submit`) and the disclosure
  consequence of what gets sent, BEFORE any prompt is written.
- **Standing constraint — authority:** `ADR-008` keeps authority in the signed
  tuning entry. A model proposes; it never writes policy. A `deny` from
  `supervise_case` writes the tuning ledger — that write path must stay
  unreachable from model output.
- **Standing constraint — auditability:** the drill invariant and the 48-assertion
  matrix are the property that makes this platform trustworthy. Any change
  here gates on both, and must be provably non-vacuous (see the
  `probe_promote()` lesson in the passdown: a negative control cannot see a
  positive defect).
- **Operator framing (2026-09-30):** "I need to give it data. We also need to
  build an LLM layer." Two halves — a data/eval foundation, and the model
  decision surface. Both are in scope; the data half is the `blocks:` edge on
  the first decision ticket.

## Decisions so far

- [Agentic framework status, 2026-09-30](https://github.com/rdrolfe/ssop) —
  research closed, no migration. Full sourced briefing (52 verified claims)
  at `~/research/langgraph-2026-briefing.md`. Findings that shape this map:
  (1) LangGraph is **not** deprecated — 1.2.12, 42.5k stars, 43.6M PyPI
  downloads/month, last commit same day; (2) framework adoption rose 9%→18%
  of orgs YoY (Datadog 2026); (3) Microsoft's post-AutoGen Agent Framework
  shipped a *graph* workflow API, and LangChain's 2026 docs list Temporal and
  Inngest in the same row as LangGraph — a graph runtime is one option in a
  category, not the category; (4) the defensible criticisms are abstraction
  *rot* (Anthropic Managed Agents 2026-04-08: a Sonnet-4.5 workaround became
  "dead weight" on Opus 4.5) and single-process durability (Temporal:
  "checkpoints preserve your data, not your execution"); (5) the 2026
  consensus is *more* structure where it is cheap to reason about (evals,
  observability, guardrails, durable logs) and *less* DSL ceremony between you
  and the model. **Consequence for SSOP: the deterministic transitions are
  correct as-is and should not be given to a model; the missing layer is the
  harness/eval layer above them, not a different graph library.**
- [State machines are argparse-with-extra-steps, and that is the good outcome]
  (operator, 2026-09-30) — the five LangGraph graphs on `.29`
  (`agent.py` 20 nodes, `hunt.py` 5, `supervisory.py` 3, `responder.py` 4)
  are dispatch tables: one conditional router, then every node → `END`. No
  loop, no model-chosen step, no HITL interrupt. Determinism in the decision
  path is what makes the matrix and the drill invariant expressible at all.
  **Do not treat this as boilerplate to be collapsed into a tool registry** —
  twenty explicit greppable nodes is the right call for an auditable platform.

## Not yet specified (fog)

- **Which decision gets model authority.** `supervise_case`'s approve/deny is
  the obvious candidate because it is the one place a judgement call already
  exists — but it is also the one whose `deny` branch writes the tuning
  ledger. Alternatives: case writeup narrative, investigation hypothesis
  generation, hunt prioritization, analyst tier recommendation. Unspecified
  until the data foundation exists to score any of them.
- **What "advisory" means concretely.** Does the model's recommendation get
  recorded on the case and read by a human? Does it shift a threshold? Does it
  rank a queue? Each has a different blast radius and a different
  non-vacuous-test design.
- **The eval set.** Whether the existing BOTSv1 ground-truth work
  (`tickets/botsv1-ground-truth.md`, `data-flywheel-eval-set.md`) can score
  model decisions, or whether a purpose-built labelled set is needed. LangChain
  2026: offline evals run by only 52.4% of teams, and quality is the #1
  production blocker at 32%.
- **Local vs declared-remote model.** Sovereignty doctrine may force a local
  model on-lab, which changes cost, latency, and capability ceiling. Depends
  on the egress decision.
- **Token cost.** Unquantified. Cost numbers before any recommendation, per
  standing preference — an always-on LLM in a 3-minute router loop is a
  different order of magnitude from a per-case call.
- **Prompt-injection surface.** Case timelines carry attacker-influenced text
  (alert descriptions, observables, HTTP payloads). A model reading the case
  timeline is a model reading attacker-controlled input. Unspecified and
  load-bearing.

## Out of scope

- **Migrating off LangGraph, or adopting any agent framework.** Research
  closed 2026-09-30; no evidence compels it and the migration buys nothing on
  the AI axis (zero decisions are currently model-driven). Revisit only if a
  decision ticket's design demands a capability the current runtime lacks.
- **Replacing the deterministic decision paths with model output.** Ruled out
  by the auditability constraint above; the model advises, code adjudicates.
- **Consolidating `agent.py`'s 20 nodes into a tool registry.** Ruled out by
  the operator 2026-09-30; explicit nodes are the auditable form.
