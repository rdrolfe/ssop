# Event-Points Case Store — design

## Problem
Case mutations (`append_event`, `assign_case`, `transition`, `decide`) do
read-modify-upsert of the WHOLE case payload in Qdrant. Qdrant upserts are
last-write-wins with no compare-and-swap; read-after-write is only
*eventually* consistent, so optimistic revision verification passes on stale
reads. Proven on live Qdrant (Sep 6 TTX): two concurrent `append_event` calls
both returned success, one timeline event was lost.

## Design
**Timeline events become their own Qdrant points. The case point becomes a
projection of state fields only.**

- Collection: `case_events` (new; alongside `cases`).
- Event point id: `uuid5(NAMESPACE_URL, f"{case_id}:{ts}:{role}:{type}:{hash(detail)}")`
  — deterministic, so a retried write is an idempotent overwrite of the SAME
  point, never a duplicate.
- Event payload: `content` ("case_id <json>"), `case_id` (filterable),
  `ts`, `role`, `type`, `detail`.
- Case point (`cases` collection, stable uuid5 id as today): ALL state fields
  EXCEPT `timeline` — title, status, state, source, observables,
  enrichments, techniques, checklist, assignee, assignment_history,
  supervisory, ts/updated_ts/last_touched_ts, revision.
- `get_case(case_id)` = case point + event points (scroll filter on
  case_id, ordered by ts) → assembled dict with `timeline`. Identical return
  shape for all consumers — zero call-site changes.
- `append_event`: TWO independent writes, no read needed for the event:
  1. upsert event point (idempotent by deterministic id);
  2. update case point state fields (last_touched_ts, opportunistic state
     advance, revision++). This second write is still read-modify-write, but
     it now only mutates idempotent/monotonic fields — a lost update can only
     lose a `last_touched_ts` refresh or a state advance that the NEXT event
     re-derives, never a timeline event. The event itself can no longer be
     lost by concurrency.
- Receipt spine: unchanged (append-only JSONL, one line per event — already
  event-shaped).
- `reconcile`: case-point id set vs receipt id set as today; event counts
  added (events in Qdrant vs events in receipts).

## Why not locking
A file lock or single-writer process serializes every role through one path,
couples roles to shared local state (multiple hosts in the design), and
turns a Qdrant blip into a stuck lock. Event points make the concurrency
problem disappear structurally: append-only writes commute.

## Migration / compat
- Old case points carry embedded timelines. `get_case` prefers event points
  when present for a case; falls back to the embedded timeline on legacy
  points. No backfill required to deploy; a one-shot backfill script
  (`scripts/backfill_case_events.py`) splits legacy cases when run.
- `recent_*_cases` / `list_stale` scan case points only (state fields) —
  unchanged behavior, faster (no timeline JSON in content).
- The in-memory FakeMemory in tests must implement `get_by_payload` +
  `scroll_all` (already does) plus `ensure_collection` for the new collection.

## Verification
- Offline: fake-memory unit tests (concurrent appends x10 threads, event
  count == 10; idempotent retry same id).
- LIVE TTX on .29 (the test that caught the last failure): two threads
  barrier-synced appends on real Qdrant, assert both events present after
  settle; plus 10-thread burst.
