# ADR-006: IRIS as the Human Case Front-End

**Status:** accepted

**Date:** 2026-09-04

**Context**

The SSOP spine produces per-role decision chains (analyst investigation →
supervisory adjudication → responder) that must be visible and actionable to
a human SOC operator. Today those chains render on THREE surfaces:
Security Onion (native case store), Wazuh (console/tickets), and DFIR-IRIS
(case + timeline). Wazuh's console has no real case management (no case
lifecycle, no notes, no assignment, no SLA); the SO surface is an iframe
patch. The operator keeps ending up in IRIS anyway — it is the only surface
with genuine case management (lifecycle states, tasks, notes, IOCs, assets,
RBAC, timeline).

**Decision**

**IRIS becomes the single human case front-end.** Wazuh and Security Onion
become pure detection engines; their dashboards are engineering-only. The
spine (Qdrant + JSONL receipt) stays the authoritative store for agent
state; IRIS (Postgres) is the human surface, kept in sync bidirectionally
on decision events.

**Engine roles after the pivot**

| Surface | Role | Humans use it for |
|---|---|---|
| Wazuh indexer | Detection engine #1 | nothing directly |
| Security Onion | Detection engine #2 | nothing directly |
| Spine (Qdrant + JSONL) | Source of truth for agent state + audit | nothing directly |
| **IRIS** | **Human case front-end** | triage, decide, note, assign, close |

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Keep 3 surfaces | No new work | 3 places to look, Wazuh has no case mgmt, SO is iframe-patched | The problem we are solving |
| Build case mgmt into Wazuh | Single-detection-engine story | Custom OpenSearch dashboard work, no lifecycle model, reinvents IRIS | Wazuh UX parity effort was heading here; abandoned by this ADR |
| TheHive as front-end | Mature case mgmt | Second service to run, no IRIS assets already built (publisher, keys, demo flow) | IRIS is already deployed + integrated |

**Consequences**

- IRIS needs one piece of custom work: a **decision panel** (approve/deny/ask)
  as an IRIS module, posting back to the spine `/adjudicate` endpoint. IRIS
  2.4's module system (`iris_engine/module_handler`, hooks +
  `manual_hook_ui_name` case tabs) supports exactly this.
- Two case stores exist (spine + IRIS Postgres). Spine stays authoritative
  for agent state; IRIS is the human surface. Publish path extends to be
  bidirectional: verdicts/notes entered in IRIS flow back to the spine
  timeline.
- Bake-off parity (12/12) gets **redefined**: parity = both detection
  engines (Wazuh + SO) render identically in IRIS, not UI parity across
  three surfaces.
- Detection coverage improves (two engines), cost is one bounded custom
  module.
- The Wazuh UX-parity push (decision button on-case in Wazuh) is
  superseded; the decision button lives in IRIS instead.

**Open questions (resolve in build)**

- Dual-control: which categories require tier-2 (two-person) approval vs
  single supervisory verdict? (SOAR approval model exists: tier0/tier1/tier2.)
- Role gating of the panel in IRIS (supervisory users only? analysts can
  add notes but not decide?).
- Notes: human notes in IRIS flow back to the spine timeline (bidirectional
  comments) or are IRIS-local?
- Case creation: router mints an IRIS case at dispatch (early) or keeps
  publish-after-decide (current)?
