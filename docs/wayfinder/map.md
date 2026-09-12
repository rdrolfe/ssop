# Wayfinder Map — P2: MISP Feed Platform (bulk intel for hunt)

## Destination

Self-hosted MISP running in-lab on its own dedicated VM and integrated as the
hunt role's **bulk** indicator-match source — match thousands of pooled
community indicators locally, look up only the survivors — with MISP's own
egress declared in `agents/transport.yaml` and enforced at the network
boundary, and the ingest feed set fixed with its licensing on record.

Reaching the end = MISP deployed and reachable from the runtime, a `tools/`
feed client + a hunt batch-match workflow merged with hermetic fixtures, the
matrix green, and the docs mirror updated (`docs/roles/hunt.md`, the Hunt OWL
comment in `agents/tools/ontology_export.py`, `docs/project-map.html`).

## Notes

- Domain: sovereign threat-intel ingestion. Rules-first, provable, nothing
  leaves the network unless declared and decided.
- Consult skills: `ssop-code-standards` (every change additive, verify-gated,
  data-driven YAML), `wayfinder` (this method), `ssop-platform-ops` (deploy
  mechanics: one file per scp + md5, runtime path ≠ repo path, restart the
  daemon that holds the module).
- Standing preferences: capabilities in `tools/`, authority in roles; the
  spine is never adapted — feeds hang off `transport.yaml`; code + docs change
  together; dry-run before any bulk write and make dry-run parity a test; the
  bake-off gate must be re-scored in the same session as any change to the
  `engine-parity-in-IRIS` surface.
- **Operator decisions on record (2026-09-12)** — made with live capacity data,
  not checklist answers: dedicated VM; egress declared AND enforced; read-only
  match for hunt only; no submit path, ever, by default.

## Decisions so far

- [MISP deploy target](tickets/misp-deploy-target.md): a DEDICATED new Proxmox
  VM on .169 — 4 vCPU / 8G RAM / 100G disk, VMID 707, static 192.168.1.80 —
  sized against the 22G actually free on .169 (running VMs already allocate
  ~176G of 125G, so 8G is the honest number, not 16G). NOT co-hosted on .75
  with the Wazuh manager + IRIS case record, although .75 is idle: MISP syncs
  from tens of third-party feeds and would otherwise share a trust/failure
  domain with the SIEM and the case record, and .75 has only 46G free.
- [MISP egress boundary](tickets/misp-egress-boundary.md): MISP's own feed-sync
  workers run on the MISP host, **outside `check_egress`'s reach** — the gate
  guards SSOP runtime code, not another host's crons. So the boundary is two
  layers: a declared infrastructure-egress entry in `agents/transport.yaml`
  (class `lookup`) AND an allow-list enforced at .13 pinning the sync
  destinations. Declared beats enforced-only; we do not let MISP's own config
  be the only thing scoping itself.
- [Bulk-match scope](tickets/misp-match-scope.md): read-only bulk match feeding
  HUNT only. No analyst case auto-enrichment in this build. No `submit` class
  entry — contributing our observables back to MISP or any feed is disclosure,
  OFF by default (sovereignty doctrine). Role-layer authority unchanged.

## Not yet specified

- **Feed selection + redistributability** of indicators derived from each feed
  (may a hunt pack built from feed X be committed to the public repo?). Gates
  both the sync config and the public-repo question; research in flight.
- The `tools/misp_client.py` contract once the feed set is known: query shape,
  batch size, and how matches map into hunt's existing finding schema.
- **Local caching:** does hunt query the MISP API every sweep, or do we
  materialize a local indicator store? Bears on sweep latency, MISP load, and
  whether hunt keeps working when MISP is down.
- Sync cadence vs hunt cadence — pre-filter inside the existing hunt sweep, or
  its own scheduled job. (Same shape as the intel cadence question.)
- MISP version pinning + upgrade policy for a lab box, and whether the MISP UI
  is reachable from the operator console at all or SSH-only.
- Whether anything in this build touches a gated surface (it should not — the
  design says tools/ + a hunt workflow only).
- The Hunt OWL comment in `ontology_export.py` is a build-time edit, flagged
  here so the docs↔code mirror test does not surprise the builder.

## Out of scope

- Any MISP↔MISP peering or sharing with external organisations (disclosure).
- Using MISP as a case/ticket system, or mirroring the spine into it — IRIS is
  the human front-end (ADR-006).
- Replacing the per-indicator enrichment client (GreyNoise / VT / OTX). MISP is
  the bulk pre-filter that runs BEFORE it, not a substitute.