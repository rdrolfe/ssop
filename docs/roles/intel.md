# Intel — advisories → hunt packs (staged, not promoted)

`agents/intel.py` (state machine) + `agents/tools/intel_tools.py` ·
proactive intelligence: reads advisories (CISA KEV + NVD), matches them
against fleet inventory (Wazuh syscollector states indices), and generates
hunt packs into a staging area for human/supervisory review.

Flow: **INGEST → MATCH → GENERATE → STAGE → (PROMOTE after review)**.
Separation of duties: intel generates, it does NOT promote (review is
human/supervisory's).

## Decision flow

### 1. INGEST (`intel_tools.py:51-78`)
- `fetch_kev()` — CISA KEV catalog (one GET, no auth)
- `fetch_nvd_since(days)` — NVD CVEs published in the last N days (keyless
  date-range)

### 2. MATCH — environment filter (`intel_tools.py:109-140`)
For each KEV entry, match its `product` against the fleet's installed
packages (`inventory_products()`, from
`wazuh-states-inventory-packages-*` — NOT `wazuh-alerts-*`). WORD-BOUNDARY
match: product matches a package exactly or as a whole token — "ray" matches
"ray" but not "raycast" (prevents the substring flood of 342 packs). An
entry survives only if it appears on ANY agent's package list; matched
agents attach.

### 3. GENERATE (`intel_tools.py:144-173`)
Builds a valid hunt pack (YAML, `analyze: generic`) targeting the inventory
indices, with a `meta` block: `{cve_id, source, matched_agents, cvss,
date_added}` — honest provenance.

### 4. STAGE — dedupe gate (`intel_tools.py:177-206`)
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
