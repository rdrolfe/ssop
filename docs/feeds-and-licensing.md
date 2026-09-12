# Feeds and licensing — what may leave the lab

The MISP ingest set and the redistribution verdict for each feed. This doc is
the record the build has to obey: **matching is not publishing.** Local bulk
matching of an indicator is analysis; committing that indicator to this repo is
publication, and the two are governed by completely different things.

Established 2026-09-12 from primary sources (feed ToS / licence text, quoted
below with URLs). Where a licence was not established the verdict is **unknown**,
and unknown means **not enabled**.

## The rules

1. **Nothing is disclosed outbound.** No `submit` class egress, no contributing
   observables back to MISP or to any feed. Read-only ingestion.
2. **No feed-derived indicator file is committed to this repo unless the feed
   grants redistribution.** Default behaviour: packs are generated at runtime
   into a non-committed path (e.g. `~/.ssop/state/`), never `git add`ed. Only
   feeds in the *redistributable* column may be materialised into a committed
   file, with attribution.
3. **A MISP `distribution` level is not a redistribution right.** Distribution
   (0 organisation / 1 community / 2 connected communities / 3 all communities /
   4 sharing group) governs sharing between *MISP instances*. It says nothing
   about publishing indicators in a public repository — that is the feed's
   licence, not the event's flag.
4. **TLP markings can be stricter than the feed default.** A permissive feed can
   still carry an event marked TLP:AMBER. Event-level markings win; a derived
   pack must not out-publish its source event.
5. **Adding a feed is a decision, not a config edit.** Every feed is also an
   egress destination (the allow-list at .13), a disk-growth multiplier on the
   correlations table, and a licensing question. One at a time, licence recorded
   here first.

## The pinned set

| Feed | Format | Licence / terms (quoted) | Redistribution | Verdict |
|---|---|---|---|---|
| **CIRCL OSINT feed** | misp | *"TLP:CLEAR — Recipients can spread this to the world, there is no limit on disclosure… Subject to standard copyright rules, TLP:CLEAR information may be shared without restriction."* | **Permitted**, with attribution | Enabled. The only feed here with an explicit grant; may be materialised into committed packs with provenance kept intact. |
| **Botvrij.eu** | misp | FAQ: *"You can use this data the way you prefer but all use of the data is at your own risk. You cannot resell the data, neither as an individual package or as part of a larger package."* | Use permitted; **resale prohibited** | Enabled. Keep it out of anything packaged or priced; no resale, attribution to botvrij.eu. |
| **abuse.ch family** — URLhaus, Feodo Tracker, ThreatFox, MalwareBazaar, SSLBL | csv / misp | ToS (eff. 2025-11-04) §7.3: *"You may not: copy, adapt, alter, translate, modify or make derivative works based on the Platforms and/or any other of our or Spamhaus' intellectual property, without the express consent of abuse.ch and/or Spamhaus"*; §3 free of charge for *not-for-profit* purposes under the Fair Use Principles; §4 commercial or for-profit use *"may require a paid subscription"* (Spamhaus Technology acts as *"the primary licensee of the abuse.ch datasets"*) | **Prohibited** — no derivative works without express consent | **IN-LAB ONLY.** Ingested as MISP feeds with `distribution: 0` (organisation only — the licence boundary enforced by the platform, not by memory) and `fixed_event` so a pull updates one event instead of minting new ones each time. An abuse.ch account is held (2026-09-12) for ToS standing / API use. **VERIFIED 2026-09-12 / CORRECTED 2026-09-12:** the endpoints are still anonymously reachable, and the account is therefore NOT a blocker for ingestion — but the first pass overstated the set. **Feodo Tracker is defunct** and **SSLBL's IP blacklist is retired**; the live set is four endpoints, see *The endpoints* below. Only `api.abuse.ch` did not answer, and it is not used by this design. |
| **AlienVault / LevelBlue OTX** | API (already a lookup source) | EULA: may not *"attempt to copy, modify, duplicate, create derivative works from, frame, mirror, republish, download, display, transmit, or distribute all or any portion of OTX"*; *"OTX is free to end users for non-commercial use"* | **Prohibited** | **IN-LAB ONLY — and it stays a LIVE LOOKUP, not an ingested feed.** This is the useful distinction: querying OTX per indicator is permitted use; ingesting it into a local corpus is the "duplicate" the EULA forbids. The existing enrichment client's behaviour already matches the licence. |
| **Spamhaus blocklists** (SBL/XBL/PBL/DBL/ZEN) | DNS query | DNSBL Fair Use Policy §1.1.1: free of charge *"for non-commercial use by small and medium sized organisations"*; §1.1.3 *"The network originating the DNS Query must be identifiable"*; §2 commercial use requires the Datafeed Service. Terms address **querying** only. | No grant (silent) | Not a MISP feed; if used at all, query-only, non-commercial. Silence is not permission — do not republish. |
| **Other MISP default feeds** (DigitalSide, Infoblox, OpenPhish, PhishTank, IPsum, blocklist.de, dataplane.org, CyberCure, malsilo, …) | mixed | **Not established — not researched** | **Unknown** | **NOT ENABLED.** Each must have its licence read and recorded in this table before it is turned on. |

## The endpoints, verified 2026-09-12

Probed **from the MISP host itself**, reading the first bytes of each response —
a status code alone is not evidence (a 200 can be an error page, an HTML index,
or a file frozen a year ago).

| Feed | Endpoint | State at probe |
|---|---|---|
| URLhaus | `https://urlhaus.abuse.ch/downloads/misp/` | LIVE misp feed: `manifest.json` + ~1.9k `<uuid>.json` |
| ThreatFox | `https://threatfox.abuse.ch/downloads/misp/` | LIVE misp feed |
| MalwareBazaar | `https://bazaar.abuse.ch/downloads/misp/` | LIVE misp feed |
| SSLBL (certificate blacklist) | `https://sslbl.abuse.ch/blacklist/sslblacklist.csv` | LIVE csv; sha1 in column 2 |
| Feodo Tracker | `feodo.abuse.ch` · `feodotracker.abuse.ch/downloads/misp/` | **DEFUNCT** — hostname no longer resolves, misp path 404, surviving `ipblocklist.csv` frozen 2026-03-04 |
| SSLBL (IP blacklist) | `https://sslbl.abuse.ch/blacklist/sslipblacklist.csv` | **RETIRED** — frozen 2025-01-03 |

So the pinned abuse.ch set is **four endpoints, not five**. An HTML directory
listing at a `/downloads/misp/` URL is the *normal* shape of a misp-format feed
(CIRCL's is one too) — the check is that it carries `manifest.json` plus
`<uuid>.json` event files, not that the response is JSON itself. The egress
allow-list's declared destination set must match this table, not a recollection.

Ingested with `distribution: 0` and, per format, `delta_merge` (misp) or
`fixed_event` (csv). Verified after the add: the SSLBL csv landed as a single
event holding 10,696 `sha1` attributes, and the read-only hunt client matched
fresh abuse.ch indicators in one batched `restSearch`.

### One caveat on CIRCL

CIRCL's TLP:CLEAR grant is CIRCL's own marking over a feed that aggregates
third-party reports (it is a curation of public writeups and feeds). The
practical mitigation is provenance discipline: keep the event metadata
(source org, event UUID, TLP marking) attached to any derived pack, and never
strip provenance when deriving — the derived artifact must not claim more
permission than the original event carried.

## Build notes that follow from this

- **Pin the version:** MISP **v2.5.46** (`CORE_TAG`), which is also the release
  carrying the `UrlEgressValidator` / host-pinning hardening. Verify whether its
  private-destination blocking interferes with LAN feed sources.
- **Sync as delta-merge, never "new event each pull."** The correlations table is
  what fills disks — real reports of ~80 GB of correlations on a 98 GB volume,
  traced to new-event-each-pull ingestion. A 100 GB VM is comfortable with a
  curated set and delta-merge, and is at risk without it.
- **Egress destinations = exactly the enabled feeds' hostnames.** MISP provides
  no hostname allow-list; it does provide `Proxy.host` / `Proxy.port`
  (`PROXY_ENABLE` and friends in the Docker env), so sync can be forced through a
  single inspected path. The enforceable pin lives at .13 (see
  `docs/wayfinder/tickets/misp-egress-boundary.md`). State it honestly: **MISP
  does not enforce the pin, the network does.**
- **Sizing:** 4 vCPU / 8 GB is inside upstream's documented band for an internal
  end-point instance, but the per-process PHP memory limit (2 GB default) times
  the worker/child counts is the real ceiling — keep worker counts modest.

## Sources

- CIRCL feed classification: `codeberg.org/adulau/misp-circl-feed` README (TLP:CLEAR).
- abuse.ch: `abuse.ch/terms-of-use/` (ToS, eff. 2025-11-04) and the per-platform API pages (`urlhaus.abuse.ch/api/`, `threatfox.abuse.ch/api/`).
- botvrij.eu: `www.botvrij.eu/` FAQ ("What are the terms of use?").
- OTX: `levelblue.com/legal/otx-eula-terms`.
- Spamhaus: `spamhaus.org/blocklists/dnsbl-fair-use-policy/`.
- MISP default feed list: `misp-project.org/feeds/`.
- MISP sizing / performance / architecture: `misp-project.org/sizing-your-misp-instance/`, `misp-project.org/misp-performance-tuning/`, `misp-project.org/2026/02/11/misp-architecture-choices.html/`.
- Disk blow-up (correlations table, new-event-each-pull): `github.com/MISP/MISP/issues/2800`.