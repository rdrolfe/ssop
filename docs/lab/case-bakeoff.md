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

## Scoring axes (the rubric) — SCORED 2026-09-01 (parity reached)

Each axis: how well does the surface communicate the ontology + agent facts
for the SAME decided incident? Scores 0–2 (absent / partial / faithful),
computed by `deploy/lab/score_bakeoff.py` from the live capture
(`capture_bakeoff.py` → `/tmp/bakeoff_capture.json`).

| # | Axis | What we measure | SO native | Wazuh console |
|---|---|---|---|---|
| 1 | **Ontology fidelity** | Can an operator see category / verdict / decision-chain in the surface? | **2** — verdict+decision in comments; **category present on create op** (after the backfill fix) | **2** — verdict, decision, category, kill-chain all present |
| 2 | **Agent-fact transparency** | Are the agent's actual findings visible — evidence count, kill-chain, severity score, recommendation? | **2** — evidence sources, chain, severity in comments | **2** — evidence + kill-chain in investigation |
| 3 | **Negative-outcome clarity** | Does the surface show WHY an alert was NOT acted on (FP rationale)? | **2** — false_positive + rationale in comments | **2** — false_positive + rationale in adjudication |
| 4 | **Case compilation** | How does each side assemble one incident from events? | **2** — 5 ops, ordered by @timestamp | **2** — 4 timeline events, ordered |
| 5 | **Retention / queryability** | Can an older case be retrieved, or does it age out of view? | **2** — so-case ops retrievable by id | **2** — `/cases?case_id=` retrieves any case by id (Qdrant) |
| 6 | **Report readiness** | Can the surface produce the final report deliverable? | **2** — `/report?case_id=&backend=so` renders the compiled report (1663 chars captured) | **2** — `/report?case_id=` renders md+html from spine (1888 chars captured) |

**Totals: SO native 12/12 · Wazuh console 12/12 — PARITY.** The one scored
gap (axis 1: the SO `so-case` create op carried `category: ""`) is closed:
`publish_case_so.py` now backfills category from the first timeline verdict
that carries one (mirroring the console reader — the spine source often
leaves `source.category` unset on a router dispatch while the analyst verdict
carries the ontology category). Re-published + re-captured + re-scored:
SO axis 1 went 1 → 2. Both surfaces now communicate the same ontology facts
for the same decided incident.

**Idempotency (added 2026-09-01):** the first publisher had no deterministic
`_id`, so re-publishing appended a second `create` op — the SO SOC Cases page
showed **2 cases** for the one spine case. `publish_case_so.py` now assigns
deterministic `ssop-<sha1(case_id-i)>` `_id`s per operation (upsert on
re-run), and `clean_so_case.py` removes all existing docs (case-keyed + the
stray `@timestamp:0` detection-envelope probe doc) before a fresh publish.
Store is now a single clean set (1 create + 4 comments per index), and the
SOC renders exactly 1 case. `capture_bakeoff.py`/`score_bakeoff.py` unchanged
— they read the cleaned shape and still score 12/12 both sides.

**Human-experience verification (2026-09-01, user-confirmed in the SO SOC):**
the operator logged into the actual Security Onion SOC console and confirmed
the published case renders as **one coherent case** in the Cases page —
single row, open status, Comments/History tabs driven by the 5 native
so-case ops we wrote (create + 4 comments). This closes the final axis-1/2
slice: the SO human experience is now directly verified, not inferred from
the ES store — and it matches what our console shows for the same case
(category, verdict chain, FP rationale all present).

Axes 1–4 are scored on the 0–2 rubric from the captured representations.
Axis 5 is decided by the capture (SO yes, console no) — and fixed:
`/cases?case_id=` now retrieves any spine case by id (adjudicate_api +
console_proxy, both route on path-only and forward the query string).
Axis 6 is built — and it is a **parity** deliverable: the SAME report
compiler (`agents/tools/report_gen.py`) renders a decided case from either
the spine (`backend=spine`, the Wazuh side) or SO's native so-case store
(`backend=so`), so the two backends can be compared deliverable vs.
deliverable on the same incident. Plus `/reports?days=N` compiles all decided
cases in a window into one report for the larger audience (console "Reports"
button).

---

## Re-runs

- `publish_case_so.py <case_id>` — map a spine case into SO's `so-case`/`so-casehistory`
  (deterministic `_id`s — safe to re-run, upserts instead of duplicating)
- `clean_so_case.py <case_id>` — remove ALL docs for the case (case-keyed + stray) before a fresh publish
- `capture_bakeoff.py <case_id>` — dump both surfaces + both backends' reports to `/tmp/bakeoff_capture.json`
- `score_bakeoff.py [capture_path]` — score all six axes (0–2) from the capture; writes `/tmp/bakeoff_scores.json`

## Next steps (when you want them)

1. ✅ Fix the console recency window (axis 5) — `/cases?case_id=` retrieves any
   spine case by id; seed case now reachable through API and proxy.
2. ✅ Score axes 1–4 formally from the captured representations (now 1–6, and
   the scorer is repeatable: `score_bakeoff.py` after any change).
3. ✅ Design the **final report format** (axis 6) — one compiler, both
   backends: `/report?case_id=` (spine) and `/report?case_id=&backend=so`
   (SO native store) produce the same markdown/HTML deliverable; the console
   adds a "Reports" button for `/reports?days=N` (all decided cases in a
   window).
4. ✅ Capture how the SO SOC console *renders* the so-case ops (the true
   human experience) — done 2026-09-01: operator confirmed the case renders
   as one coherent case in the SO Cases page, and it matches our console's
   rendering of the same decided incident. The bake-off's six axes are all
   now scored + the human experience directly verified on both sides.
