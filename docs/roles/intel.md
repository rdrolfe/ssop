# Intel — advisories → hunt packs (staged, not promoted)

`agents/intel.py` (state machine) + `agents/tools/intel_tools.py` ·
proactive intelligence: reads advisories (CISA KEV + NVD), matches them
against fleet inventory (Wazuh syscollector states indices), and generates
hunt packs into a staging area for human/supervisory review.

Flow: **INGEST → MATCH → GENERATE → STAGE → ESCALATE → (PROMOTE after
review)**. The inventory match IS evidence (syscollector observes the
package on the agent; KEV says it's exploited in the wild — the join is
two grounded fleet facts), so each match mints a spine case per
(CVE, agent), open-only deduped, assigned to supervisory. The staged
hunt pack is the proposed DETECTION and stays a file for review — two
different artifacts, two different authorities.

## Decision flow

### 1. INGEST (`intel_tools.py:34-45`)
- `fetch_kev()` — CISA KEV catalog (one GET, no auth)
- `fetch_nvd_since(days)` — P1 second pass (not yet implemented): NVD CVEs
  published in the last N days (keyless date-range)

### 2. MATCH — environment filter (`intel_tools.py:66-86`)
For each KEV entry, match its `product` against the fleet's installed
packages (`fleet_products()`, from
`wazuh-states-inventory-packages-*` — NOT `wazuh-alerts-*`).
CASE-INSENSITIVE EXACT match on the lowercased product name (the inventory
records package names; vendor hierarchies don't exist there, and a
vendor-string mismatch suppresses more true matches than a product-name
collision adds false ones). An entry survives only if its product appears
on ANY agent's package list; matched agents attach. NVD enrichment
(`fetch_nvd_since`) is a P1 second pass — KEV alone is already
exploited-in-the-wild signal.

### 3. GENERATE (`intel_tools.py:92-124`)
Builds a valid hunt pack (YAML, `analyze: generic`) targeting the inventory
indices, with a `meta` block: `{cve_id, source, matched_agents, cvss,
date_added}` — honest provenance.

### 4. STAGE — dedupe gate (`intel_tools.py:126-151`)
Writes to `agents/hunts/staging/` UNLESS a pack with the same `cve_id`
already exists (in staging OR the live library) → deduped, not staged.

### 5. PROMOTE — NOT intel's job
Staging-review is human/supervisory's. A staged pack is promoted to the live
`agents/hunts/` library only after review — the hunt sweep then picks it up
with zero code change (YAML library = the hunt-pack format).

## Outputs
`{fetched_kev, fetched_nvd, matched, staged, deduped, packs[], summary}`.

## Gates
- Environment match (product word-boundary vs fleet inventory)
- Dedupe (cve_id in staging or live)
- Staging review (human/supervisory promotes — separation of duties)

## Verify coverage
Intel flow exercised by the hunt-pack schema fixtures + the intel
INGEST→MATCH→GENERATE→STAGE state machine; hunt packs validated as
`hunt.py` loads them.

---

## External data plane (egress registry)

The ontology is sovereign in **AI inference** — no cloud provider owns our
decisions. It is NOT airgapped: external **data-plane** calls exist and are
DECLARED in `agents/transport.yaml` (`external_calls:`) and ENFORCED by
`agents/verify/check_egress.py` (undeclared external endpoint in any
`agents/**.py` = matrix FAIL). Adding an external capability means making
the disclosure decision explicitly, at build time.

| Provider | Endpoint | Class | Data sent | Used by |
|---|---|---|---|---|
| GreyNoise | api.greynoise.io | lookup | IP value | `tools/enrichment.py` |
| VirusTotal | www.virustotal.com | lookup | hash/domain/url value | `tools/enrichment.py` |
| AlienVault OTX | otx.alienvault.com | lookup | IPv4/hash/domain/url value | `tools/enrichment.py` |

Provider roles: **VT = verdict authority** (AV-engine malicious/clean),
**OTX = context authority** (pulses, malware families — high capacity:
10k req/hr with free key), **GreyNoise = scanner reputation** (IP only,
keyless). OTX honest mapping: malware-family attachment → malicious;
pulse membership alone → suspicious (context, not verdict).

**Submission class (file/URL upload — a DISCLOSURE event) is DISABLED by
default** (`VT_SUBMIT_ENABLED=0`). Hash/URL lookups leak only the indicator
value itself. Enabling submission is an explicit operator act.

VT quota (free public API): **4 req/min + 500 req/day, one shared bucket
for ALL request types** — lookups and submissions alike. The client
(`EnrichmentClient`) throttles at both windows and caches verdicts; the
budget is spine-wide, not per-role.

**Roles and external calls:** the capability lives in
`tools/enrichment.py` (tool layer, role-agnostic). The analyst enriches
escalated cases automatically; hunt can pivot hashes found mid-hunt; the
responder can pre-check a target. Authority stays with the roles — the
capability doesn't.
