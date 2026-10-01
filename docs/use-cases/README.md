# Use cases

Worked scenarios. Each one is a real problem, what SSOP already does about it,
what's left, and **how you'd know it worked**.

These are not tutorials. For setup see [`DEPLOYMENT.md`](../DEPLOYMENT.md) and
[`docs/roles/`](../roles/README.md); for components see
[`ARCHITECTURE.md`](../ARCHITECTURE.md) and [`PRODUCT_MAP.md`](../PRODUCT_MAP.md).

---

## The framing: how this platform earns your trust

**SSOP never asks you to trust it. It shows you its reasoning and lets you
compare.**

That sounds like marketing, so here is the mechanism that backs it — and every
claim below is one you can check against a running system.

Every consequential decision in SSOP is **deterministic and inspectable**, and
every place a human judgement enters is **recorded with who made it**. Not
"recorded" — attributed. A tuning entry carries `tuned_by`; a receipt carries a
signature; a recommendation lands adjacent to the decision it was compared
against. So a reader can always answer three questions:

| Question | Where the answer lives |
|---|---|
| What decided this? | The `Basis` enum on every classification — 11 named provenance values, never a silent default |
| Who decided it? | `tuned_by` / `actor` on the write, not inferred from timing |
| Did we agree? | The comparison set, below |

### Trust is measured, not accumulated

This is the idea worth carrying into every use case here, and it came out of
work on the model layer (see
[use case 4](04-model-assisted-soc.md)).

It's tempting to describe confidence in a system as something that grows over
time — "as it learns, you can trust it more." That's not measurable and it's not
how this works. What actually happens is much more modest and much more useful:

> **The loop doesn't build trust. It builds a comparison set.**

Every time the system makes a decision you didn't expect, you find out whether
it matched your judgement. That is one data point. Fifty of them is an agreement
rate — a number you can quote, disagree with, and act on.

The live example is already in the ledger. A committed tuning entry for the dpkg
family carries this rationale:

> *"dpkg install noise is 83-for-83 adjudicated FP fleet-wide; keep dispatching
> ONLY on vault-secrets (package drift there is high-stakes)."*

**83-for-83.** Not "we believe this is noise." Eighty-three specific
adjudications, and a named exception carved out for the one host where the same
signal *would* matter. That is what earned confidence looks like when it's done
honestly — and note that it didn't generalize the finding to every host, which
is exactly the move a system optimizing for reduced alert volume would have
made.

### What you can falsify

A use-case doc that only claims capability is marketing. Each one below names
how you'd know it *failed*. Where something is designed but unbuilt, it says so.

**Known not-working, as of 2026-09-30:**

- **No real attack execution.** Atomic Red Team is not installed, and the
  `ubuntu-target` / `windows-target` hosts are not deployed. The 30-minute
  synthetic-signal timer *fabricates alert documents in the index* — it exercises
  the pipeline and produces zero adversary telemetry. Use case 2 is about closing
  this.
- **No MISP write path, by design.** Contributing observables back to MISP or any
  feed is a disclosure event under ADR-007 call 3. Read-only, deliberately.
- **No model decision layer.** Specified and scoped, unbuilt. As of this writing
  the runtime contains exactly one LLM call, and its response is read by nobody.
  Use case 4 describes the design, not a shipped capability.

---

## The scenarios

| # | Scenario | Status | The hard part |
|---|---|---|---|
| 1 | [Cutting alert volume without losing the signal](01-cutting-alert-volume.md) | **Live, proven** | Knowing when you've over-suppressed |
| 2 | [Proving a detection exists before you claim it](02-proving-a-detection-exists.md) | Partial — corpus replay, no live adversary | A negative control that can see a positive defect |
| 3 | [Running Security Onion without leaking egress](03-security-onion-egress-boundary.md) | **Live, proven** | A service scoping itself is not a boundary |
| 4 | [An LLM-assisted SOC that keeps authority with the human](04-model-assisted-soc.md) | **Specified, unbuilt** | Knowing what the model is for — and isn't |

Each is written so you can disagree with it. If a scenario's framing is wrong
for your situation, the reasoning is there to argue with.

---

## Reading order

If you're evaluating the project: **1**, then **4**. Use case 1 is the mechanism
that makes the platform worth running; use case 4 is the one people will ask
about and the one most likely to be misunderstood.

If you're extending it: **2** then **3**. Those are the two places where the
project's discipline is most distinctive and least intuitive.