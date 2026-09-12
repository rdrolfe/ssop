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
look up only the survivors. *That step has since been built — see the
Amendment at the end of this record.*

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
   entry in `agents/transport.yaml` (class `lookup`), **and** a default-deny
   allow-list pinning the sync destinations. Declared *and* enforced.
   *(The original text named `.13` as the enforcement host. That was wrong —
   see the Amendment at the end of this record.)*
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
- Enabled **in-lab only**: **abuse.ch** family — as built, URLhaus / ThreatFox /
  MalwareBazaar (misp-format) and SSLBL (csv certificate list). The original
  list also named **Feodo Tracker**, which turned out to be **defunct** (host
  no longer resolves; its last csv froze 2026-03-04), and SSLBL's *IP* blacklist
  (frozen 2025-01-03, superseded by the live certificate list) — see
  `docs/feeds-and-licensing.md`. ToS forbids derivative works without express
  consent.
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
second place secrets live (MISP API key + the allow-list **on the MISP host**)
that must stay out of the repo; a new class of processing — third-party content
landing in-lab — which is the reason for the trust-domain separation; feed
licensing becomes a build input, not an afterthought, because the repo is public.

**Amendment — 2026-09-12 (session 7): where the allow-list is actually enforced**

Call 2 named `.13` as the enforcement host. **That was wrong**, and wrong in a
way worth recording rather than quietly editing: `.13` is a same-segment peer of
the MISP VM, and both route via `192.168.1.1`, so traffic leaving `.80` never
transits `.13`. A rule placed there would have filtered nothing while looking
exactly like enforcement — the failure this record's own alternatives table
rejects as "pretending".

The allow-list is enforced **on the MISP host itself** (`.80`), default-deny,
and on **two hooks rather than one**: MISP runs as containers, and container
egress is ROUTED (veth → bridge → ens18), so it traverses `forward`, not
`output`. Measured rather than assumed — `container → 1.1.1.1:443` showed
**output 0 packets / forward 14 packets** — with the forward chain at priority
-10 so docker's own FORWARD ACCEPTs cannot decide the question first. It was
pre-flighted with `policy accept` + counters where the real ruleset says `drop`
(0 packets over live traffic) before being enforced, and is reboot-verified: the
boot unit reconstitutes the verified table, not a re-derivation. `.1` is the only
other chokepoint and is out of scope.

**Amendment — the hunt side, built**

Call 3's scope is intact: read-only bulk match for hunt only, still no `submit`
entry. `tools/bulk_intel.py` is the reader — `collect_observables` +
`bulk_intel_for` match a hunt's typed observables against the local corpus, and
external provider lookups are spent **only on the survivors**, only when
explicitly opted in (`intel_external=1`). `agents/hunt.py` calls it on both
paths and the verify matrix calls the same functions, so they cannot drift.

Two rules from this build are enforced, not merely documented: **degraded is not
clean** (an unreachable corpus reports UNKNOWN and promotes nothing — no
escalating on stale intel) and **no local filter, no spend** (an unconfigured
corpus spends nothing; there is no silent fallback to per-indicator fan-out).
The no-submit invariant is asserted statically by `verify/test_misp_client.py`
and `verify/test_bulk_intel.py`.

**Amendment — the registry entry's shape**

The declaration now lives under a distinct `infrastructure_egress:` key in
`agents/transport.yaml`, not under `external_calls:`. The distinction is
load-bearing: `external_calls` is egress the SSOP **runtime** makes — it is the
key `verify/check_egress.py` reads — while MISP's feed sync is egress we own that
runs on another host and is invisible to that gate. The hunt → MISP call itself
is host-to-LAN (RFC1918), which the gate already treats as local, so it needs no
registry entry at all.

**Related**

- [ADR-006 - IRIS Front-End.md](ADR-006%20-%20IRIS%20Front-End.md)
- [ADR-004 - SOAR Layer.md](ADR-004%20-%20SOAR%20Layer.md)
- [../wayfinder/map.md](../wayfinder/map.md) (P2: MISP Feed Platform)