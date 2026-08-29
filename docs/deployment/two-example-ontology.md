# Two-Example Deployment Guide — The SSOP Ontology on SO and Wazuh

Status: draft (builds verified 2026-08-26; live SO backend flip pending)
Scope: the SAME ontology (categories/roles/verdicts/cases + six adopted
human-workflow concepts) running on TWO open-source SIEMs — Security Onion
3.2 and Wazuh 4.x — so anyone can deploy it on either backend.

> The doctrine this guide realizes: the ontology is the load-bearing
> skeleton; a SIEM is just a transport (transport.yaml). We adopt a SIEM's
> mature human-workflow concepts INTO the ontology as backend-agnostic
> primitives; every primitive is expressed against BOTH backends; and the
> result is demonstrated twice, not once. If a concept only works on one
> SIEM, it belongs in that SIEM's adapter, not the ontology.

---

## 1. What you get

One incident spine (Qdrant + append-only JSONL receipt), one decision spine
(router -> analyst/hunt/infra -> supervisory), and six portable primitives
adopted from Security Onion's analyst experience, all running identically
whether the alert data comes from Wazuh or Security Onion:

| # | Primitive (ontology) | SO feature it generalizes | Wazuh contribution |
|---|---|---|---|
| 1 | `case.observables` + auto-extraction | Observables / IOC tracking | raw alert fields |
| 2 | `enrich_observable()` (TI verdicts) | Analyzers (VT/GreyNoise/...) | alert IPs/domains |
| 3 | playbook `questions:` (live evidence) | Guided Analysis | queryable index |
| 4 | tuning ledger + `/tuning` surface | Detection tuning UI | rule ids |
| 5 | `case.checklist` (rule templates) | rule.case_template | rule map |
| 6 | `extract_techniques()` | ATT&CK Navigator | rule.mitre fields |

The six primitives require ZERO backend-specific build: they operate on the
transport-normalized alert dict and the case payload. The only Wazuh-aware
bit is where Wazuh CONTRIBUTES (its `rule.mitre` feeds #6) — adapter data,
not ontology code.

## 2. Architecture (both backends)

```
SIEM (Wazuh .75 OR SO .76)                 SSOP agents (.29)
  alerts index  ----->  IndexerTransport (transport.yaml)  ->  router.classify()
  (wazuh-alerts-* /                       category + role + technique_id
   .internal.alerts-security.*)                    |
                                            analyst.verdict()  ->  escalate?
                                            (tuning ledger consult, recidivism)
                                                     |
                                             CaseStore (Qdrant + JSONL)
                                             observables / enrichments / checklist
                                                     |
                                             escalate_tools -> tier2 ticket
                                                     |
                                             supervisory console (/tuning, /tickets)
```

The transport is the seam: `agents/transport.yaml` selects `backend: wazuh`
or `securityonion` and carries the field ontology + rule map. The decision
spine and the six primitives never change.

## 3. Deploy on Wazuh (the portability test-bed)

Prereqs: a running Wazuh indexer (alerts index), Qdrant, the agent runtime.

```bash
# 1. Clone the repo, install deps
git clone <repo> ssop && cd ssop
python3 -m venv agent-env && source agent-env/bin/activate
pip install -r requirements.txt

# 2. Configure the transport for Wazuh
# agents/transport.yaml: backend: wazuh (default); alerts_index points at
# your wazuh-alerts-4.x-*; rule map maps signature ids -> ontology
# (category, role, optional template:, technique_id:)

# 3. Configure credentials via .env (never in git)
# INDEXER_URL / INDEXER_USER / INDEXER_PASSWORD, QDRANT_URL, HERMES_API_URL

# 4. Verify
python3 -m verify.matrix        # 30 fixtures, all GREEN
python3 analyst.py analyst:recent limit=5   # live run against Wazuh
```

The six primitives are already wired: escalations auto-extract observables,
enrich via GreyNoise, attach a rule checklist, and surface techniques. No
Wazuh-specific code anywhere in the spine.

## 4. Deploy on Security Onion (the second example)

Prereqs: SO 3.2 standalone/eval on a VM with TWO NICs (ens18 MGMT + ens19
MONITOR) — see the SO integration ticket for the install gotchas (bond MTU
1500 on virtio, whiptail needs console).

```bash
# 1. Same repo/venv as above (the agents are backend-agnostic).

# 2. Point the transport at SO's Elasticsearch
# agents/transport.yaml:
#   backend: securityonion
#   backends.securityonion.endpoint: https://192.168.1.76:9200   # TLS
#   backends.securityonion.alerts_index: .internal.alerts-security.alerts-default-*
#   securityonion_rules:  # SO signature ids -> SAME ontology categories
#     2024724: {category: threat, role: analyst}
#     ...

# 3. Configure SO Elasticsearch credentials in .env (a SOC user works:
#    email/password that has an ES role — same account you log into SOC with).

# 4. Verify
python3 -m verify.matrix        # same 30 fixtures, all GREEN (same code)
python3 analyst.py analyst:recent limit=5   # live run against SO signals
```

The rule map changes (SO signature ids); the code does not. The ontology
categories/roles/verdicts and all six primitives are identical.

## 5. The case seam (mirroring)

Our escalated cases stay in Qdrant (agent source of truth). The supervisory
role ALSO mirrors them into SO's case system so the human's investigation
lives in the SOC console — SO's cases get the same title/observables/
checklist. Qdrant remains the spine; SO is the meat-suit-facing surface.

## 6. Why this is shareable

- Both SIEMs are open-source; the ontology + agents are open-source.
- One repo, one ontology, two `transport.yaml` profiles.
- The portability proof is structural: the SAME 30-fixture matrix passes on
  both backends because the spine never touches SIEM-specific code.
- Adding a THIRD backend = editing transport.yaml's rule map (data, not code).

## 7. Current status

- [x] Concepts 1-6 built, deployed, verified (matrix 30/30 GREEN), committed
- [x] Wazuh backend live (the portability test-bed)
- [ ] SO backend flip + live comparison (transport flip is prepped; SO .76 is
      up with ES access confirmed; the flip + two-backend matrix run is the
      remaining live step)
- [ ] Publish-ready pass (this doc + the wayfinder ticket as the design record)
