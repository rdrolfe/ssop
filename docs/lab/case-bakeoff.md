# Two-Backend Case Bake-Off — Human-Facing Parity Evaluation

*Our spine is the source of truth. The experiment: how well does each SIEM's
case surface communicate the ontology — and the agents' compliance to it (the
facts they found)? Not production parity; a lab evaluation that puts Wazuh and
Security Onion against each other on their ability to *communicate* a decided
incident.*

Status: **seed case published to both surfaces, first findings captured.**
Date: 2026-09-01.

---

## The seed case

`case-26b166ce32` — a complete **negative-outcome** story, chosen deliberately
(an FP is the harder case to communicate: the surface must show WHY an alert
was NOT acted on):

| Step | Spine record |
|---|---|
| Alert | DNS tunneling/exfil: NIMLOC (bots-dns-poc / bots-suricata-poc) |
| Analyst | `investigate`: 2 evidence sources (dns, suricata), chain: C2 + NETWORK |
| Analyst | `verdict`: escalate, level=8, category=threat |
| Supervisor | `verdict`: deny / false_positive (synthetic POC feed, not live fleet) |
| Supervisor | `adjudication`: deny — "investigation weak: score 0 (low)" |

## What each side holds now

### Security Onion — native `so-case` store (ES API)

5 documents written via the SO ES API, one per case operation (activity-log
model — the SOC UI renders these):

| op | so_related | payload |
|---|---|---|
| create | case-26b166ce32 | title, status, description (incl. rule_desc) |
| comment | analyst/investigation | evidence sources, severity, kill_chain |
| comment | analyst/verdict | verdict=escalate level=8 cat=threat |
| comment | supervisory/verdict | verdict=false_positive |
| comment | supervisory/adjudication | decision=deny rationale |

Every ontology fact is present, mapped onto SO's case model. **Queryable by
case id** — an old case is retrievable.

### Wazuh — console `/cases` (reads the spine)

The seed case is in the spine receipt (8 lines) but is **NOT visible** in the
console's `/cases` response: the endpoint returns the **last 50 receipt lines**
(rolling window), and a fully-decided case from a few days ago has aged out.

---

## Findings (both real, from live capture)

1. **SO retains and communicates the full decided story** — every role step is
   a queryable operation with the ontology facts. Its gap: you must know the
   case id and the field to query; the mapping is not obvious from the schema,
   and the SOC UI rendering is unverified (no web-console creds).

2. **The Wazuh console surfaces only recent cases** — the `last 50 receipt
   lines` window meant an older fully-decided case disappeared from the human
   view entirely, even though it's complete in the spine. **RESOLVED 2026-09-01:**
   the console `/cases?case_id=<id>` endpoint now returns ANY case by id from
   the spine (Qdrant holds all cases; the 50-line receipt window was the
   artificial limit), including its full timeline. The proxy on `.75` forwards
   the query param. Verified live: `case-26b166ce32` (Aug 29) is retrievable
   through `https://192.168.1.75:5602/cases?case_id=case-26b166ce32` with all
   4 timeline events.

**Bonus finding (the fix exposed a live break):** while testing the case fix,
the router was discovered flooding the queue with 642 duplicate tickets —
the 19h deadlock wedge left the cursor's `last_ts` stuck at Aug 22, so the
router resumed chewing a ~56k-alert backlog 50 per run while the 5000-cap
`seen_ids` evicted old alert IDs → the same old alerts re-dispatched forever.
Fixed: `repair_router_cursor.py` fast-forwards the cursor past the backlog
(verified: only NEW alerts dispatch going forward), `purge_router_flood.py`
closed the 642 duplicates (no tuning writes). The timer-liveness gate
(`check_timers.py`) would have caught this class on the next matrix run —
the liveness+drift enforcement is paying for itself.

---

## Scoring axes (the rubric)

Each axis: how well does the surface communicate the ontology + agent facts
for the SAME decided incident?

| # | Axis | What we measure | SO native | Wazuh console |
|---|---|---|---|---|
| 1 | **Ontology fidelity** | Can an operator see category / verdict / decision-chain in the surface? | ops carry verdict/decision | adjudication field (when in window) |
| 2 | **Agent-fact transparency** | Are the agent's actual findings visible — evidence count, kill-chain, severity score, recommendation? | comment ops carry evidence+chain+score | investigation object (when in window) |
| 3 | **Negative-outcome clarity** | Does the surface show WHY an alert was NOT acted on (FP rationale)? | rationale in comment | rationale in adjudication |
| 4 | **Case compilation** | How does each side assemble one incident from events? (SO: per-op activity log; Wazuh: spine timeline) | per-op log | spine timeline |
| 5 | **Retention / queryability** | Can an older case be retrieved, or does it age out of view? | **YES — by case id** | **NO — last-50 window** |
| 6 | **Report readiness** | Can the surface produce the final report deliverable for a larger audience? | TBD (comments + history, export path unknown) | TBD (HTML view, no export) |

Axes 1–4 are scored on a rubric (0–2: absent / partial / faithful) from the
captured representations. Axis 5 is already decided by the capture (SO yes,
console no). Axis 6 is the forward work: designing the report format.

---

## Re-runs

- `publish_case_so.py <case_id>` — map a spine case into SO's `so-case`/`so-casehistory`
- `capture_bakeoff.py <case_id>` — dump both surfaces to `/tmp/bakeoff_capture.json`

## Next steps (when you want them)

1. Fix the console recency window (axis 5) so an old fully-decided case stays
   reachable — the first parity fix the experiment exposed.
2. Score axes 1–4 formally from the two captured representations.
3. Design the **final report format** (axis 6): the executive deliverable that
   compiles the investigation framework's outcome for a larger audience.
4. If you can log into the SO SOC console once, capture how it *renders* the
   so-case ops (the true human experience) vs. the console's rendering.
