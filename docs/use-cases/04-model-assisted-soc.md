# Use case 4 — An LLM-assisted SOC that keeps authority with the human

**Status: specified and scoped, NOT built.** As of 2026-09-30 the runtime
contains exactly one LLM call, and its response is read by nobody. This document
describes a design that was argued through and agreed; it is not a description
of existing capability.

We're putting it in the docs anyway, and flagging it loudly, for two reasons.
First, because a reader evaluating an AI-adjacent security platform deserves the
honest version — including what isn't there. Second, because the *reasoning* is
the useful part, and it's what makes the eventual implementation reviewable.

---

## The situation

You have automated parts of a security workflow and the obvious next question is
"where does the model go?" It's a worse question than it looks, because the
default answer is wrong in a specific and expensive way.

The default answer: **let the model do triage.** Let it read the alert, decide
whether it's interesting, and route accordingly. Every vendor demos this. On a
real feed it fails in a way that's hard to notice, because it fails toward
*quiet* — the model learns that most alerts are boring, gets good at saying so,
and eventually fails to say so about the one that mattered.

SSOP's position is that the interesting question is not "where does the model
decide" but **"what work is there that a human shouldn't have to do, and that
doesn't require authority?"**

## The reframe that decides it

Work through the obvious design and you hit this: the platform's tuning ledger
learns from **human adjudications**. A committed entry is a person deciding a
rule is noise.

Follow that and the loop is:

> alert → investigated → human approves → rule tuned → suppressed if false
> positive → over time a baseline develops and only noise surfaces

**That loop is already built and running.** It's `TuningLedger` + the
pre-heuristic ledger consult in the analyst + the ledger write in supervisory
adjudication. It ships. It settles false positives. It works today with no model
involved at all.

So the first and most important design conclusion is a negative one:

> **A model is not needed to close this loop. Building one into the decision path
> would add a step to a loop that already turns.**

This is worth stating plainly because it's the opposite of the reflexive
assumption. If you want a model in a security platform, you have to justify it
against the machinery you already have — not against a picture of where you
suppose models go.

## The hole that remains

The ledger learns only from humans, and that has a specific cost:

- An alert class **nobody has adjudicated** has no baseline, so it escalates
  every single time, indefinitely, until a person looks at it.
- Cost scales linearly with operator attention: more volume → more escalations →
  less time → slower baseline growth → more escalations.
- The worst case is the **cognate-new** alert. Its rule looks familiar, but the
  fingerprint has materially changed, so the suppression correctly re-opens it
  for human review. It is new to the ledger. It is *not* new to you — you may
  well have judged the underlying thing a week ago.

**That is the actual opportunity.** A model reading a structured evidence
roll-up can say "this is the shape you tuned last Tuesday, here is what changed,
here is whether the change matters." A ledger lookup cannot, because the ledger
only knows exact fingerprints.

## The design

One sentence, which is the whole decision:

> **The model may propose a tuning-ledger decision for an alert class the ledger
> has never been taught; code must still decide the verdict, and the human must
> still write the policy.**

| Step | Owner |
|---|---|
| Gather evidence, score it, build the roll-up | state machines (already live) |
| Propose a decision + rationale | **model** |
| Decide the verdict | code (deterministic, arithmetic on severity + kill chain) |
| Write the tuning ledger | **human only** |

Four consequences worth being explicit about:

**Vocabulary is the ledger's, not the ticket's.** The authoritative set is
`{auto_fp, operational, escalate}` — the same words a committed entry uses. The
alternative (`approve` / `deny`) is a different vocabulary, and translating
between two word sets loses the audit trail. The recommendation is literally a
*proposal for a policy entry*, so it should read like one.

**The blast radius is a wrong suggestion.** Nothing executes. Nothing is written.
The human reads it, disagrees, and moves on. That is the property that makes this
safe enough to be a first move — and it's why "the model decides" is not a
reasonable first step even though it's the more interesting one.

**Novel classes only.** A tuned or suppressed class never reaches the model, so
the payload is a bounded set of fields from a single alert, not a case history.
This is a scope decision that also happens to make the sovereignty question much
smaller.

**Cost follows from the gate, not the other way round.** The router sweeps every
three minutes, so an always-on design would be roughly 480 calls a day. Gating on
novel classes only makes a target of ~10/day natural rather than something you
have to throttle.

## How you'd know it worked

Trust here is not a feeling that accumulates. It's a **comparison set**: every
recommendation is one data point on whether the model matched your judgement, and
fifty of them is an agreement rate you can quote and act on.

The measurement population is clean by construction. The supervisor already
refuses to re-adjudicate a case in `decided` or `closed` state — it closes the
ticket with the prior verdict — so model-versus-human is only ever compared on
fresh cases.

Three things to measure:

1. **Agreement rate** on proposals, against what the human actually committed.
2. **The model's false-`escalate` rate** specifically. This is the asymmetric
   cost: recommending `escalate` when a human would have said `auto_fp` costs a
   wasted adjudication, and that's the only direction where the model can make
   the system *slower*.
3. **The cold-start rate itself.** If alert classes are still taking as long to
   get adjudicated as they did before, the model isn't filling the hole and
   should be removed rather than kept for appearances.

## How you'd know it failed

- **A recommendation is read as a verdict.** The single most likely failure,
  because it's social rather than technical. Someone skims the dashboard, sees
  "recommendation: auto_fp", and treats it as settled. Which is why the design
  requires model output to be *structurally* marked as model output, and requires
  the recommendation to sit adjacent to the human decision on the same record so
  the disagreement is visible without cross-referencing two systems.
- **Prose starts feeding another automated decision.** If model output ever gets
  indexed, prioritized by, or pulled into a digest that a human acts on, that's a
  new design decision that needs its own review. **A confidently wrong
  recommendation is worse than no recommendation, because it gets trusted.**
- **Prompt injection via the evidence packet.** The packet contains
  attacker-influenced text. The agreed mitigation is partial and honest about
  being partial: structured observables (IPs, ports, domains, hashes, rule ids)
  are passed through raw because they're typed and can't carry instructions;
  free text (HTTP paths, User-Agent, DNS query names, rule descriptions) is
  quoted and labelled as attacker-controlled. That raises the cost of a naive
  injection. It is not a guarantee, and it shouldn't be described as one.

## Why no agent framework

Worth answering directly, since it's the obvious question: why not LangGraph, or
an agent SDK, or the current fashionable thing?

Because the orchestration is already a set of explicit state machines, and none
of the work here is *agentic* in the sense that term usually implies. Nobody is
deciding what to do next. The role agents (`infra-manager`, `analyst`, `hunt`,
`supervisory`, `responder`) are dispatch tables: one router, then a node calls a
tool and returns. There is no loop, no model-chosen step, no interruption.

The research supports keeping them that way. The current consensus in agent
framework design is that *harness* abstractions rot — a workaround built for one
model generation becomes dead weight on the next one — and that the durable
substrate should be plain, legible code. A security platform whose decision path
is a function of its inputs, rather than a sampling temperature, is also the only
kind whose behaviour you can assert in a test. That's what makes the drill
invariant expressible at all.

The missing layer in this project was never the graph. It was an eval harness
and a place to put an opinion.

## Honest status

| Piece | State |
|---|---|
| Scope decided | ✅ |
| Vocabulary, sanitization, cost target | ✅ |
| Ledger consult path | ✅ exists, proven |
| Model call | ❌ not built |
| Eval harness | ❌ not built — spec drafted |
| Egress declaration for the model endpoint | ❌ not built |

The two open tickets are `llm-eval-harness` (how you'd score it, and what its
positive control is) and `llm-egress-and-sovereignty` (whether sending our
observables to an inference endpoint is a disclosure event under our own
doctrine). The second one is a policy question, not an engineering one, and it
hasn't been answered.

---

**Related:** [ADR-008 — Automation Tuning Authority](../decisions/ADR-008%20-%20Automation%20Tuning%20Authority.md) ·
[use case 1 — the flywheel this sits on top of](01-cutting-alert-volume.md) ·
[the framing note on measured trust](README.md#the-framing-how-this-platform-earns-your-trust)