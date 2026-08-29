# SSOP Transport-Agnostic Ontology — Design Spec

**Goal:** the SSOP decision spine (alerts → categories → roles → verdicts →
cases → playbooks) is transport-agnostic: it runs identically whether the
SIEM underneath is Wazuh, Security Onion/Elastic, Splunk, or anything else.
The human-facing layer (dashboards, tickets) is likewise decoupled — humans
get a natural GUI; agents keep the machine contract.

**Why:** the user's challenge — "make our ontology extensible to any SOC."
If we ever lift-and-shift to Security Onion, the agents should follow via
config, not rewrite. The human experience (SOC-style dashboards, workable
tickets) is a first-class requirement, not an afterthought.

---

## 1. The three seams (what must decouple)

| Seam | Today (Wazuh) | Tomorrow (any SOC) | Abstraction |
|---|---|---|---|
| **Query surface** | IndexerClient → OpenSearch REST | Elastic/SO, Splunk, etc. | `IndexerClient` = transport interface: `search(body, index)`, `count`, `recent_alerts` |
| **Field ontology** | `rule.level`, `rule.groups`, `timestamp` (Wazuh field names) | SO signals use `.siem-signals`, Splunk uses `_index`+fields | Field names in **config**, not code |
| **Rule mapping** | `RULE_MAP` hardcoded in router.py | SO rule/signature IDs differ | Rule map = **data file** (`agents/rules.yaml`), loaded at runtime |

## 2. Design

### 2.1 `IndexerClient` as transport interface
Already ~90% there (thin HTTP wrapper). Changes:
- Field names become config: `indexer.field_timestamp`, `indexer.field_level`,
  `indexer.field_groups`, `indexer.field_category`.
- `recent_alerts()` builds queries from those config names.
- A `Transport` ABC with `search/count/recent_alerts`; the urllib impl is
  `OpenSearchTransport`. A future `ElasticTransport`/`SplunkTransport`
  implements the same ABC against the new backend. Registry picks by config.

### 2.2 Field ontology in config
```yaml
# agents/config.py (or a transport.yaml data file)
indexer:
  index: ssop-events            # Wazuh today; so-* / .siem-signals tomorrow
  field_timestamp: "@timestamp" # Wazuh/OSD; Elastic: same; Splunk: _time
  field_level: "rule.level"
  field_groups: "rule.groups"
  field_category: "category"    # our enriched field (set by OTel pipeline)
```

### 2.3 Rule map as data (`agents/rules.yaml`)
```yaml
# The ontology: alert signature -> (category, role). Transport-agnostic —
# the *meaning* (security/analyst) is ours; the *signature ids* are the
# SIEM's. Re-mapping for a new SOC = editing this file, not code.
rules:
  510:    {category: security, role: analyst}      # rootcheck
  52002:  {category: pattern,  role: hunt}        # apparmor
  5710:   {category: security, role: analyst}     # sshd auth failure
  86601:  {category: security, role: analyst}     # suricata generic
default: {category: operational, role: null}
```
- Router loads `rules.yaml` at startup; `RULE_MAP` constant is deleted.
- Adding/re-mapping a rule = YAML edit (data-driven, per our principles).

### 2.4 The spine is already transport-agnostic
Qdrant + JSONL dual-write (cases, audit, receipts) has zero SIEM coupling —
it's the SSOP-owned contract. The verify matrix asserts on it. This is the
anchor: no matter the transport, the spine stays.

---

## 3. Human layer: agents as identities in the ticket stack

The human works tickets the SOC way; the agents create/work them the API way.

### 3.1 Tier-2 approvals as real tickets in the human GUI
Today: responder writes `tickets/<id>.json` (machine-readable, no GUI).
Target: the SAME ticket appears in the human dashboard as a workable item:
- **Wazuh option (now):** render tickets into `ssop-events` (or a
  `ssop-tickets` index) with status fields → a "Tier-2 Approvals" dashboard
  panel: open/approved/denied/expired, click-through, comment.
  The human approves/denies via a **status-update API the agent watches**
  (a small `ticket_status` endpoint or an index write the responder polls).
- **Security Onion option (future):** Elastic Cases API — responder creates
  a real Case; human works it in the SO console; agent watches status via
  the Cases API. Same ontology, different transport.

### 3.2 Agent identity in the ticket stack
Every ticket/case carries: `actor` (role: analyst/responder/intel),
`agent_id` (SPIRE identity), `case_id`, `run_id`, `ts`, `status`. The human
sees *who* (which agent) created the ticket, *why* (rationale/verdict),
and *what it needs* (approval). The GUI is human-first; the data is
machine-readable underneath.

---

## 4. Why this wins

- **Lift-and-shift is a config change, not a rewrite** — if we ever move to
  SO/Elastic, the agents' queries re-target via config; the rule map re-maps
  via YAML; the spine doesn't move.
- **The human GUI is decoupled too** — Wazuh dashboards today, SO console
  tomorrow; the ticket ontology is the contract, not the transport.
- **Matches our principles** — data-driven (rules.yaml, field config),
  additive (spine untouched), verify-gated (matrix asserts on the spine).

---

## 5. Build order

1. `agents/rules.yaml` + router loads it (delete RULE_MAP constant).
2. Field names → config (indexer fields).
3. `Transport` ABC + registry pick (OpenSearchTransport today).
4. Tickets → `ssop-tickets` index (or ssop-events with status fields) +
   "Tier-2 Approvals" dashboard panel + status-update API the responder
   polls (the agent-identity ticket loop).
5. Verify matrix stays green throughout.
