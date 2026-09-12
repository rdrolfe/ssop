# ADR-007: MISP Feed Platform

**Status:** accepted

**Date:** 2026-09-12

**Context**

The platform's threat-intel workflow is per-indicator: hunt pivots on an
observable and calls the shared enrichment client (GreyNoise / VT / OTX) for
each one. That is lookup-class egress, one indicator at a time, and it scales
linearly with how much the fleet produces. The documented next step
(`docs/roles/hunt.md`, and the roadmap comment in `agents/transport.yaml`) is
bulk matching: match thousands of pooled community indicators **locally** and
look up only the survivors.

Three constraints shape the decision.

1. **Sovereignty.** The data plane comes to us rather than us going to it. Any
   new feed source is an egress-registry entry plus a gate pass; disclosure of
   our own observables to third parties is off by default.
2. **The gate does not reach another host's crons.** `verify/check_egress.py`
   constrains SSOP runtime code. A self-hosted feed platform runs its own sync
   workers, so its egress is real but invisible to the existing gate — a
   boundary that exists only in YAML would be documentation, not control.
3. **Trust domain.** The candidate co-host for MISP was `.75`, which already
   runs the Wazuh manager + indexer and the IRIS case record.

**Decision**

Adopt **self-hosted MISP** as the platform's bulk-intel source, under four
calls made by the operator on 2026-09-12:

1. **Placement:** a DEDICATED Proxmox VM on `.169` — 4 vCPU / 8G RAM / 100G,
   VMID 707, static `192.168.1.80`. Not co-hosted with the SIEM or the case
   record. Sized at 8G against the 22G *actually* available on that host (the
   running VMs already allocate ~176G of 125G), not against its nameplate.
2. **Egress:** two layers, both required — a declared infrastructure-egress
   entry in `agents/transport.yaml` (class `lookup`), **and** an allow-list
   enforced at `.13` pinning the sync destinations. Declared *and* enforced.
3. **Scope:** read-only bulk match feeding **hunt only**. No analyst case
   auto-enrichment in this build. **No `submit` class entry** — contributing our
   observables back is disclosure and stays off by default. Role-layer authority
   unchanged: capability in `tools/`, authority in the roles.
4. **Redistribution:** no indicator derived from a feed whose terms forbid
   redistribution may be committed to the public repo; such feeds stay in-lab
   only. Feeds are pinned deliberately (a modest set), not bulk-imported from
   the default list.

**Feed set and licences (2026-09-12, from primary sources — quoted in
`docs/feeds-and-licensing.md`):**

- Enabled: **CIRCL OSINT** (TLP:CLEAR — the only explicit redistribution grant)
  and **botvrij.eu** (use permitted, resale prohibited).
- Enabled **in-lab only**: **abuse.ch** family (URLhaus / Feodo / ThreatFox /
  MalwareBazaar / SSLBL) — ToS forbids derivative works without express consent.
- **Not ingested:** OTX. The EULA forbids copying/duplicating the corpus, but
  permits end use — so OTX remains a *live per-indicator lookup* while MISP
  provides bulk matching. Lookup and ingestion are different acts, and only one
  of them is licensed.
- **Not enabled at all:** every other MISP default feed, until its licence is
  read and recorded. Unknown is not permission.
- **Structural rule:** feed-derived packs are materialised at runtime into a
  non-committed path, so unlicensed indicators cannot reach the public tree.
- **A `distribution` level is not a redistribution right** — it governs
  instance-to-instance sharing (3 = all communities), not publication.

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Co-host MISP on `.75` (telemetry) | No new VM; `.75` is idle (load 0.24, 18G RAM free) | MISP syncs from tens of third-party feeds → most externally-influenced service we own, sharing a trust/failure domain with the Wazuh manager and the IRIS case record; only 46G disk free; eviction later means touching telemetry | Trust-domain cost is permanent, the resource saving is temporary |
| `.90` / `.94` / `.13` | Existing hosts | 2–4 cores, 7–15G RAM; `.13` is the deliberately-open sanctioned fleet-sysadmin / containment target | No headroom; `.13` is a target by design |
| Public/cloud MISP or a hosted feed API | Zero footprint | Violates sovereignty: indicators we pivot on become third-party-visible queries and we depend on someone else's uptime | Sovereignty is the platform's premise |
| Registry entry only (no network enforcement) | Less work; honest documentation | The gate cannot see MISP's own workers, so nothing actually scopes egress; a feed-sync bug or a feed backend swap is unbounded | "Declared" would be pretending to be enforcement |
| Stage feeds locally from the lab, no third-party sync | Strongest sovereignty; no egress at all | Discards the value of pooled community feeds and duplicates the platform's own purpose | Operator wanted the value; the allow-list bounds the risk instead |
| Skip MISP; keep per-indicator lookups only | No new surface | Linear cost per indicator; no bulk pre-filter; the documented hunt design stays unfulfilled | This is the thing the decision exists to change |

**Consequences**

Easier: hunt stops paying an external lookup per indicator; matching runs at LAN
latency against a local corpus; the platform gains a real feed plane that later
roles can reason over (without granting them new authority).

Harder / new constraints: an additional host to patch, back up and monitor; a
second place secrets live (MISP API key + `.13` allow-list) that must stay out of
the repo; a new class of processing — third-party content landing in-lab — which
is the reason for the trust-domain separation; feed licensing becomes a build
input, not an afterthought, because the repo is public.

**Related**

- [ADR-006 - IRIS Front-End.md](ADR-006%20-%20IRIS%20Front-End.md)
- [ADR-004 - SOAR Layer.md](ADR-004%20-%20SOAR%20Layer.md)
- [../wayfinder/map.md](../wayfinder/map.md) (P2: MISP Feed Platform)