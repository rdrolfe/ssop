# Use case 1 — Cutting alert volume without losing the signal

**Status:** Live and running. Every number below is from the production ledger
on the lab fleet, verified 2026-09-30.

---

## The situation

You point a SIEM at a small fleet and it works fine. Then you point it at
something real and a single event becomes forty.

The concrete instance from this lab, taken from a closed case's rationale:

> Rule 2902 (*New dpkg package installed*, level 7) fired on `kb-vec`
> (agent 002) for `libc-bin 2.43-2ubuntu2.4`. The alert was the tail of **one
> unattended-upgrade transaction** that emitted 37 dpkg-family documents on that
> host inside 55 seconds — 23 copies of rule 2904 (*half-configured*) and 14 of
> 2902.

And that was one host. Across the fleet the same morning: **180 dpkg-family
events**, spread over `infra-ops` (85), `kb-vec` (37), `vault-secrets` (37), and
`c2-sink` (21).

**This is the real shape of alert noise, and it is not what people expect.** It
isn't 180 unrelated events. It's roughly 5 real events (one upgrade transaction
per host) expressed 180 times, because a package manager's internal state
transitions are each individually reportable and none of them mean anything
alone.

## What SSOP already does about it

Three mechanisms, all shipped, in the order they run.

### 1. The ledger is consulted *before* the heuristics

Every classification first asks: has a human already decided about this rule?
The consult sits at `tools/analyst_tools.py:134-160`, ahead of any heuristic
evaluation. A rule with a suppressing committed entry is recorded as
`Basis.TUNED_ENTRY` and stops there.

**Provenance is explicit, never inferred.** `router.classify()` returns a
`Classification` carrying a `Basis` — one of eleven named values (`noise_rule`,
`drill_gate`, `tuned_entry`, `tuned_delta`, `transport_rule`, `rule_map`,
`group_heuristic`, `ontology`, `unclassified`, `degraded`). There is no default,
because a default would silently attribute a decision to a source nobody
consulted.

That matters more than it sounds. Without it you cannot answer "why did this get
suppressed?" — and a suppression you can't explain is one you'll eventually get
wrong.

### 2. Fingerprints, with a deliberate escape hatch

An entry isn't just `rule_id → suppress`. It carries a fingerprint (level,
groups, category). Identical fingerprints suppress quietly; a **material delta
re-opens** the alert for human review and is recorded as `Basis.TUNED_DELTA`.

This is the part most noise-reduction designs get wrong. They suppress at the
rule level, so a tuned rule can never surprise you again — including the day it
starts firing for a genuinely different reason. `tuned_rule_suppresses()` makes
the suppression specific enough that a real change still gets through.

### 3. A proposal never suppresses

`suppression_allowed()` requires two things: a suppressing decision *and*
`state == COMMITTED`. An uncommitted proposal does not suppress, and its
`proposed_by` is recorded.

This is the load-bearing guard. A tuning system where a machine's own verdict can
write policy is a system that erases the evidence of its own mistakes. Here,
**only a human commits.** ADR-008 keeps authority in the signed entry.

## The current numbers

The production ledger, at time of writing:

| | Count |
|---|---|
| Total entries | **33** |
| Committed | 32 |
| Proposed (non-suppressing) | 1 |
| `auto_fp` | 28 |
| `escalate` | 3 |
| `operational` | 1 |

Of the 33, five are synthetic `991*` rules from the signal injector and one is
hunt-sourced (`hunt:apparmor-denials`). The rest are real Wazuh rules — the
dpkg family `2901`/`2902`/`2903`/`2904`, `533`, `550`.

So the honest headline is **28 real false positives adjudicated and suppressed**,
which sounds modest next to 180 events per morning. That's the right reaction,
though: the ledger doesn't need an entry per event. It needs one entry per
*class*, and the dpkg family is four entries covering all 180.

## How you'd know it worked

This is the section most projects omit, so it's the one to check the claims
above against.

**The primary measure is not alert volume. It's the cost of a suppression you
later regret.** Volume is trivially easy to drive to zero and means nothing on
its own — silence looks exactly like success. Three things are worth measuring:

1. **Ledger growth rate.** Steady state means the operator's adjudications are
   covering new classes and not churning on old ones. A ledger that keeps
   rewriting the same entries means the fingerprints are wrong.
2. **Re-open rate** (`Basis.TUNED_DELTA` count). Each one is a suppression that
   *correctly* decided it was no longer the same thing. Too many means your
   fingerprints are too tight; zero over a long period means they may be too
   loose and you're just not generating enough variety to notice.
3. **Time-to-first-adjudication for a genuinely novel class.** This is the real
   cost of the design, and it's the metric that argues for the model layer in
   [use case 4](04-model-assisted-soc.md).

**The invariant you can run today** is the drill: benign activity must produce
`['note','note']` and **zero** tier-2 escalations. It's checked every wave, and
it's what would catch a regression where the suppression stops working. A system
that claims to reduce noise should be able to prove that noise is still *able* to
speak when it should.

## How you'd know it failed

- **A suppressed rule fires for real and you don't notice.** The fingerprint
  delta is the defence, but it can be tuned wrong.
- **The ledger becomes an unfalsifiable dumping ground.** Every entry is
  `auto_fp`, nothing is ever `escalate`, and the ratio of `auto_fp` to `escalate`
  climbs suspiciously. Current state is 28:3, and that ratio drifting toward 1:0
  is the alarm.
- **Fleet-wide findings get over-generalized.** Watch the rationales. The current
  dpkg entries explicitly carve out `vault-secrets` because package drift there is
  high-stakes — a finding that never carves out an exception is a finding that was
  never actually checked.

## Extending it

The mechanism is data, not code. Adjudications are records in Qdrant; hunts and
playbooks are YAML (`agents/hunts/`, `agents/playbooks/`). Adding a new suppression
class means writing an entry with a rationale, not changing the router.

If you add one programmatically, keep `source: human` honest. The ledger's
provenance fields exist so that "we decided this" and "a script decided this" are
distinguishable a year from now.

---

**Related:** [ADR-008 — Automation Tuning Authority](../decisions/ADR-008%20-%20Automation%20Tuning%20Authority.md) ·
[use case 4 — the model layer, which attacks the cold-start hole this leaves](04-model-assisted-soc.md) ·
[`docs/roles/supervisory.md`](../roles/supervisory.md) (who commits)