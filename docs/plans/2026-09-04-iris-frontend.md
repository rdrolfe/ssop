# IRIS Front-End Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Make DFIR-IRIS the single human case front-end: decision panel in
IRIS that posts to the spine, bidirectional state sync, both detection
engines rendering identically in IRIS, bake-off gate redefined to engine
parity.

**Architecture:** Spine (Qdrant + JSONL) remains authoritative for agent
state. IRIS (Postgres, 2.4.29) is the human surface. A custom IRIS module
("SSOP Decision Panel") provides the approve/deny/ask UI on each case; it
calls the spine `POST /adjudicate` API on infra-ops :8787. The existing
`publish_case_iris.py` path extends to sync IRIS-side changes (verdicts,
notes, status) back into the spine timeline. Wazuh + SO are engines only.

**Tech Stack:** Python (IRIS module system, Flask blueprints), Qdrant,
OpenSearch indexer, systemd timers (existing), IRIS 2.4 module framework.

---

## Phase 0 — Bidirectional state sync (foundation)

Spine → IRIS already works (publish). Add IRIS → spine so decisions made
in IRIS are authoritative on the spine.

### Task 0.1: Capture IRIS case state deltas

**Objective:** Poll/compare IRIS case state (state_name, status, notes,
timeline events) against the spine case and emit delta events.

**Files:**
- Create: `deploy/lab/sync_iris_to_spine.py`
- Modify: `deploy/lab/publish_case_iris.py` (extract shared API client into
  `deploy/lab/iris_client.py`)

**Step 1:** Extract the `_req`/`_ctx`/key-loading logic from
`publish_case_iris.py` into `deploy/lab/iris_client.py` (IrisClient with
`get_case(cid)`, `list_notes(cid)`, `list_timeline(cid)`).

**Step 2:** Write `sync_iris_to_spine.py`: for each IRIS case whose
`case_soc_id` exists in the spine, fetch IRIS timeline events + notes
newer than the spine's `last_iris_sync_ts`, and append them to the spine
timeline as `type: "iris_event"` / `type: "iris_note"` with the IRIS
user_name as role. Persist `last_iris_sync_ts` on the case.

**Step 3:** Run it. Verify: a spine case with IRIS notes now carries them
in its timeline.

### Task 0.2: Wire into the supervisory timer

**Objective:** The daily/hourly supervisory run syncs IRIS→spine before
adjudicating.

**Files:**
- Modify: `ssop-supervisory.sh` (add sync step before `supervisory.py`)

**Step 1:** Prepend `python3 deploy/lab/sync_iris_to_spine.py` to
`ssop-supervisory.sh`.

**Step 2:** Verify by triggering the timer once and confirming a spine
case picked up an IRIS-side note.

---

## Phase 1 — SSOP Decision Panel (the custom IRIS module)

### Task 1.1: IRIS module skeleton

**Objective:** A registered IRIS 2.4 module that adds an "SSOP" tab to the
case view.

**Files:**
- Create: `~/.hermes/ssop-iris-module/manifest.json` (module manifest:
  name `ssop_decision_panel`, version, hooks)
- Create: `~/.hermes/ssop-iris-module/ssop_decision_panel/__init__.py`
- Create: `~/.hermes/ssop-iris-module/ssop_decision_panel/blueprint.py`
- Modify (on IRIS host): `~/.hermes/iris-web/source/app/iris_engine/module_handler` registration (or the module install dir IRIS reads)

**Step 1:** Follow the IRIS 2.4 module pattern in
`source/app/iris_engine/module_handler/module_handler.py` — a module with
`register_hooks` + a case-scoped `manual_hook_ui_name` tab.

**Step 2:** Manifest + skeleton registers a static "SSOP" tab on the case
page showing the case's spine state (from `case_soc_id`).

**Step 3:** Install the module per IRIS docs, restart the app container,
verify the tab renders on a case (e.g. IRIS case 13).

### Task 1.2: Decision buttons → spine adjudicate API

**Objective:** Approve/Deny/Ask buttons on the tab post to the spine.

**Files:**
- Create: `~/.hermes/ssop-iris-module/ssop_decision_panel/api.py`
- Create: `~/.hermes/ssop-iris-module/ssop_decision_panel/templates/ssop_panel.html`

**Step 1:** The tab shows the current spine state + a decision form
(Approve / Deny / Ask + rationale textarea).

**Step 2:** On submit, POST to
`https://192.168.1.29:8787/adjudicate` with
`{ticket_id_or_case_id, decision, rationale, decided_by: <iris user>}`.
Credentials from the runtime `.env` (IRIS_KEY_SUPERVISOR, same as the
publisher — never literal in the module).

**Step 3:** Handle the response: on success, refresh the tab (the verdict
lands on the spine, and the next publish/sync pushes it back to the IRIS
timeline). On failure, surface the error inline.

**Step 4:** Verify: click Approve on a test case in IRIS → spine case
transitions to `decided` with `decision: approve` → IRIS timeline gains
"Supervisory decision: APPROVE (via IRIS, by <user>)".

### Task 1.3: Role gating + audit attribution

**Objective:** Only supervisory-role IRIS users can decide; every decision
records who.

**Files:**
- Modify: `~/.hermes/ssop-iris-module/ssop_decision_panel/api.py`

**Step 1:** Check the IRIS user's role against the SSOP supervisory group
(membership via IRIS `user_group` / existing role model). Non-supervisory
users see the tab read-only.

**Step 2:** `decided_by` = the IRIS user's name — flows into the spine
rationale and the IRIS timeline attribution.

**Step 3:** Verify with a non-supervisory IRIS user: buttons disabled,
read-only view.

### Task 1.4: Wire the module into the lab as a systemd-tracked unit

**Objective:** The module survives IRIS container restarts and is
re-deployable.

**Files:**
- Create: `deploy/lab/ssop-iris-module.service` (+ timer if a sync is needed)
- Modify: `docs/DEPLOYMENT.md` (install steps)

**Step 1:** Document the install path (copy module dir onto the IRIS host,
enable via IRIS module registration, restart app).

**Step 2:** Verify after a `docker compose restart` the tab persists.

---

## Phase 2 — Front-end completeness (surface everything)

### Task 2.1: Case list columns

**Objective:** The IRIS case list shows SSOP-relevant columns (source
engine, decision, playbook, agent).

**Files:**
- Modify: IRIS case list template or module-provided list view

**Step 1:** Add columns: detection engine (Wazuh/SO), current spine
decision, recommended playbook, affected agent.

**Step 2:** Verify on the case list.

### Task 2.2: Notes as the working log (bidirectional)

**Objective:** Human notes in IRIS appear in the spine timeline (Phase 0
covers it); analyst/supervisory spine commentary appears in IRIS notes.

**Files:**
- Modify: `deploy/lab/publish_case_iris.py` (also write chain summary as a
  real IRIS note, not just timeline events)

**Step 1:** Extend the publisher to create an IRIS note (the notes API
route exists: `/case/notes/add`) carrying the decision-chain summary.

**Step 2:** Verify the Notes tab on a fresh publish shows the chain.

### Task 2.3: IOCs + assets surfaced

**Objective:** Spine observables/techniques land as IRIS IOCs + assets.

**Files:**
- Modify: `deploy/lab/publish_case_iris.py` (IOC/asset add calls)

**Step 1:** Map spine `observables` → IRIS IOCs
(`/case/ioc/add?cid=`), techniques → asset tags where sensible.

**Step 2:** Verify on a published case.

---

## Phase 3 — Bake-off gate redefinition

### Task 3.1: Parity = engine parity in IRIS

**Objective:** The bake-off scores both engines rendering identically in
IRIS, not 3-surface UI parity.

**Files:**
- Modify: `agents/verify/check_bakeoff.py`
- Modify: `docs/lab/case-bakeoff.md`

**Step 1:** Redefine the parity check: for each seed case, assert the IRIS
timeline contains the same decision chain regardless of which engine
produced the alert (Wazuh vs SO).

**Step 2:** Update the matrix gate; verify 12/12 still green after the
pivot (now scored from IRIS).

### Task 3.2: SO stays engine #2

**Objective:** Security Onion remains a detection engine; its native case
store publish becomes optional/legacy.

**Files:**
- Modify: `deploy/lab/e2e_full_chain.py` (SO publish step becomes flag-gated)

**Step 1:** Keep SO detection flowing; gate the SO native-store publish
behind `--publish-so`.

**Step 2:** Verify the chain still publishes to IRIS without the SO store.

---

## Verification (whole plan)

- `python3 -m verify.matrix` → 33/33, bake-off 12/12 (engine-parity form)
- Full exercise: atomic injector → router → analyst → supervisory →
  publish → IRIS case with decision panel used to decide a live case
- IRIS case timeline shows: analyst verdict, investigation, supervisory
  decision (via panel, attributed), responder assignment, notes, IOCs

## Deployment log (Sep 5, 2026) — Phase 1 ACTIVATED

The panel is now LIVE and the decision flow is verified end-to-end. Key
facts learned while activating (see dfir-iris-integration skill for the
full pitfalls):

- **This deployment runs the STOCK image** (`ghcr.io/dfir-iris/iriswebapp_app:v2.4.29`,
  no `build:` key, no bind mount of `~/iris-web/source`). Host-source edits
  alone can never activate a blueprint; restarts + `docker compose build`
  ("No services to build") reload the stock image. Fix: DERIVED IMAGE —
  `deploy/iris-panel/Dockerfile` layers the panel onto the stock base
  (anchored, idempotent patch of case_routes.py + case-nav.html), built as
  `iriswebapp_app:ssop-panel` from `~/iris-panel-build` on .75, selected via
  `APP_IMAGE_NAME=iriswebapp_app` / `APP_IMAGE_TAG=ssop-panel` in
  `~/iris-web/.env`. Rebuild + `docker compose up -d app worker` after any
  panel change.
- **Panel bugs fixed during activation**: `case.case_soc_id` → `case.soc_id`
  (the model attribute; old code 500'd), `dict | None` annotations →
  `Optional[...]` (image runs Python 3.9 — blueprint import crashed at
  boot), template block `custom_scripts` → `javascripts` (IRIS's layout
  block; the whole panel JS silently never rendered), CSRF (JSON body must
  carry `csrf_token` — render `{{ form.csrf_token }}` hidden input, the
  global `csrf_token()` is UNDEFINED in this app), and `ticket.ticket_id |
  tojson` on a None ticket → 500 (use `{{ (x if x else '') | tojson }}`).
- **Endpoint choice matters**: the panel posts `/case-decision`
  `{case_id, decision, rationale}` — the workbench path that writes the
  CASE verdict (timeline + transition) AND closes the linked open ticket.
  `/adjudicate` `{ticket_id, ...}` only closes the ticket; the case never
  transitions (the panel originally used it — decisions "succeeded" with
  zero spine effect). Attribution: rationale gets "— decided by <user> via
  IRIS" (verified: `decided by administrator via IRIS` in the spine).
- **Live e2e (IRIS case 27)**: fresh synthetic alert → analyst escalate →
  publish (supervisor role) → panel render (state/ticket/buttons/csrf) →
  POST approve → spine `decided/approve` with attribution → IRIS timeline
  gains "Supervisory decision: APPROVE" attributed to SSOP Supervisor.
  Verified in Postgres (`cases_events` joined to users).
- **The lab self-cleans synthetic drills**: the hunt sweep's
  `adjudicate_with_investigation` (hunt.py:268) auto-DENIES synthetic
  lab-injection cases ~45s–2min after escalation ("Lab drill injection, not
  a live detection… Deny; drill achieved its goal"), even via router
  pattern-dispatch when the hunt timer is paused. For a clean panel e2e
  window, pause hunt + analyst (+ router for full isolation) and use a
  FRESH rule id + entity pair per run (host/entity recidivism otherwise
  attaches the alert to an existing case with no new ticket).

### Phase 1 remaining
- Task 1.4 (systemd-tracked unit / DEPLOYMENT.md) — partially done: the
  derived image + .env pins make the panel durable across container
  recreation; formal docs/DEPLOYMENT.md section still pending.
- Phase 2 (list columns, notes as working log, IOCs/assets) and Phase 3
  (bake-off gate redefinition) not started.
- Known follow-ups: `/case-decision` approve does NOT auto-assign the
  responder (assignee stays analyst — assignment lives in
  `adjudicate_with_investigation`); consider wiring it for panel parity.

## Risks / open questions

- **IRIS module API drift:** 2.4.29's module_handler is the reference;
  hooks/manual UI registration may differ slightly — Task 1.1 is a spike
  against the live install first.
- **Dual-control:** which categories need tier-2 (two-person) approval?
  Resolve with the SOAR approval model (tier0/tier1/tier2).
- **Notes authority:** are IRIS notes read-only mirrors of spine
  commentary, or can humans write notes that flow back? (Phase 2.2 assumes
  bidirectional; confirm.)
- **Case creation timing:** router mints IRIS case at dispatch (live during
  investigation) vs publish-after-decide (current). Later is simpler;
  earlier is better for the operator watching live.
