# Use case 2 — Proving a detection exists before you claim it

**Status:** Partially proven. The methodology is live and exercised; the corpus
is incomplete, and the numbers below are honest about that.

---

## The situation

Detection engineering has a measurement problem that looks like it doesn't have
one. You write a rule. You run it against known-good traffic and it fires.
So you know it works.

That check passes just as happily against a rule that fires on *everything*,
and just as happily against one that fires for the right reason on the wrong
evidence. Both look identical from the outside: "the rule fired on a case I know
is real."

The failure mode isn't a rule that never fires. It's a rule that fires for the
wrong reason, gets credited with a true positive, and then sits in your SIEM
looking load-bearing. In a small deployment that's tolerable. After a year of
adding alerts on its say-so, your precision record is fiction and you have no
way to know which parts.

**The specific trap this project hit twice:** a check that passes because it
confirms nothing. Both instances are worth naming, because they're the shape
most CI checks take.

- **The corpus probe.** A function probed the detection corpus with 40 hex zeros
  and proved the corpus answered and wasn't matching noise. That is a real
  check, and a completely broken promote path passed it. A negative control
  cannot see a positive defect — if you only ever test that things *don't* fire,
  you have tested nothing about whether they fire correctly.
- **The suppressed-rule proof.** A detection proof script failed twice for the
  wrong reason. The rule it had picked was tuned `auto_fp` in the ledger from an
  earlier drill, so the router suppressed it *by design*. The pipeline was fine.
  The proof was measuring suppression instead of detection. **Before choosing a
  rule for any end-to-end proof, check the tuning ledger.** A correctly
  suppressed dispatch is not a bug.

## What SSOP does about it

### 1. Ground truth has to be real, and it has to be labelled

A detection claim is only worth what its ground truth is worth. The project
ingested BOTSv1 as a labelled corpus specifically because it ships both halves:

- **Raw telemetry** — the noise floor. What normal-but-suspicious-looking traffic
  actually looks like.
- **Ground-truth anchors** — labelled real attacks.

Those two together are what let a detection be *scored* rather than merely
observed. The current finding from replaying the raw telemetry: it produces
almost no cases. That result is itself the measurement — it's the noise floor,
and it's what any new detection has to clear.

### 2. Hunts carry a technique id, and the plumbing is verified

A hunt is a data-driven YAML definition carrying a `technique_id` alongside its
query. This is what lets a finding that has no network entity to correlate — a
file dropped, a process run — still render as a real ATT&CK technique instead of
a vague tactic label.

The chain that has to hold: alert → case → technique id → advisory table. It's
verified at four legs (real-ID table wins over heuristic, derived fallback
renders, unknown id is honest, tagged-stage extraction is preserved) and
end-to-end (dispatch an alert carrying `rule.mitre` → case persists the technique
→ advisory renders a real-ID table).

**A new technique id that isn't registered still renders — as the id string with
tactic `Other`.** Honest, and useless. That's the intended failure mode: a gap
shows up as visibly degraded output rather than silently.

### 3. A hunt with no ground truth is refused

The most useful discipline in the project is a rule about what *can't* be built.
When a ticket calls for a detection, the acceptance criterion is that ground
truth must be named first — a published trace, an emulated procedure, a planted
artifact — or the ticket closes as not-buildable.

The reason is the corpus-probe failure above. A hypothesis with nothing to
compare against can never be proven or disproven, so it looks exactly like a
working detection forever. **No ground truth, no hunt.** The gate comes first,
before the YAML.

### 4. Techniques are attached honestly, including when there are none

Cases carry their technique ids through a four-layer lookup: alert fields first
(Wazuh `rule.mitre`, ECS `mitre.attack`), then correlation-stage tags, then the
hunt definition, then a derived tactic heuristic as the floor.

A backfill over 347 open cases tagged 5 and **honestly skipped 342** — the ones
with no IP or domain to correlate. Those were hunt findings and agent-only host
cases. Inventing a technique for them would have looked like better coverage and
been worse than nothing.

## The current numbers, honestly

From the live case spine:

| | Count |
|---|---|
| Total cases | **1,271** |
| Closed | 973 |
| Decided | 208 |
| New (untouched) | 84 |
| Awaiting decision | 1 |
| **Carrying at least one technique id** | **210** |
| **Carrying none** | **1,061** |

Top techniques present: `T1046` (75), `T1053.005` (72), `T1078` (40),
`T1565.001` (7), `T1071.001` (5), `T1068` (4), `T1003.001` (3).

**So roughly 83% of cases carry no technique id, and that's the honest state of
the work.** Two very different populations are in that number: cases from before
the technique feature existed (a backfill is possible where an entity exists,
and 342 were skipped for having none), and cases from live sources that have no
technique to attach — including a chunk of the synthetic-signal injector, which
mints cases for rule ids that aren't real ATT&CK techniques.

The point worth taking away is not the number. It's that **the number is
measurable at all.** A platform that couldn't produce that ratio couldn't tell
you whether its detection metadata is any good, and wouldn't know to look.

### The known gap

**There is no real adversary in this loop yet.** Atomic Red Team is not
installed, and the intended victim hosts were never deployed. The 30-minute
synthetic-signal timer *fabricates alert documents directly in the index* — it
exercises the pipeline end to end and produces zero adversary telemetry. That's
useful for what it is, and it is emphatically not detection evidence.

Concretely: there is currently no way to take an atomic technique id, execute it
for real on an observed host, and assert that a hunt fires on the resulting
telemetry. That loop is specified and unbuilt. Until it exists, every detection
claim in this project rests on corpus replay, not on a live adversary.

## How you'd know it worked

- **A detection's ground truth is nameable.** Not "it looks right" — an id, a
  trace, a procedure. If you can't name it, you have a hypothesis.
- **A deliberately broken rule fails its own test.** This is the positive
  control, and it's the check that distinguishes a real harness from a
  ceremonial one. Break something on purpose, confirm the gate goes red, put it
  back. A harness that has never failed has never been tested.
- **Noise floor and detection rate are both published.** The BOTSv1 replay
  produced the first number. The second needs the adversary loop above.
- **Coverage is honest about its ceiling.** The 5-of-347 backfill is the model
  here: report what you tagged, report what you skipped and why, never quietly
  round up.

## How you'd know it failed

- **A rule is credited with a detection it got by accident.** This is the whole
  failure mode. It gets worse with volume, because more untested rules mean more
  coincidences.
- **A proof fails for a reason other than the one it was written for.** It looks
  exactly like a broken pipeline, and the expensive response is to debug working
  code. Check the tuning ledger before touching anything else.
- **Coverage is reported as a count with no denominator.** "1,271 cases with
  technique coverage" sounds strong until you divide. Always publish both.
- **A negative control is mistaken for a test.** A check that only proves nothing
  fires is not weaker evidence — it's no evidence.

## Extending it

Everything here is data. Hunts are YAML in `agents/hunts/`; the recipe for a new
one is [`docs/exercises/Campaign Template.md`](../exercises/Campaign Template.md),
which is a detection-validation harness with the gap-report section already
built out. Playbooks are likewise declarative.

When adding a technique id, register it in the technique metadata table in the
same change. An unregistered id renders as a bare string, which is a visibly
degraded result rather than a silent one — but visibly degraded output in an
advisory is still a worse report.

---

**Related:** [`docs/lab/case-bakeoff.md`](../lab/case-bakeoff.md) ·
[use case 4 — the adversary loop this is still missing](04-model-assisted-soc.md) ·
[`agents/hunts/`](../../agents/hunts/)