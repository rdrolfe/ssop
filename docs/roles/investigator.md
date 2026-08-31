# Investigator — severity + kill-chain

`agents/tools/investigator.py` · the "connect the kill chain" layer: given
an escalated entity, correlates it across sources, scores engagement, and
builds an evidenced kill-chain hypothesis. Backend-aware — host/creds/fields
all follow the active transport backend.

## Inputs
- Entity (srcip / dstip / domain) from an escalated alert or hunt finding
- Active backend (transport.yaml) — endpoint, creds, alerts index, raw rule
  title field (`rule.name` on SO vs `rule.description` on Wazuh)
- BOTS replay slices + the live alert index (subdivided by attack shape)

## Decision flow

### 1. Correlate the entity across sources (`investigator.py:167-228`)
Sources (`investigator.py:34-43, 94-116`):
- `http` (UploadData.aspx exfil), `dns` (NIMLOC tunneling),
  `winsec` (process exec), `suricata` (flow context) — BOTS replay slices
- `live_scan` (`*STREAM*`), `live_threat` (`*ET MALWARE*`),
  `live_brute` (`*Login Failure*`), `live_http` (dest port 8080),
  `live_net` (any) — live alert stream

Each source: base entity query (backend-aware entity pair fields) + an
attack-shape `threat_query` filter so benign activity doesn't correlate as
"tunneling". A source counts as evidence only if `count >= min_count`.

### 2. Score severity (`investigator.py:277-295`)
```
score = Σ log10(count) over THREAT sources   (context sources down-weighted)
      + min(context_score * 0.2, 1.0)
      + (breadth - 1)                         # distinct correlated sources
```
Severity bands:
- `< 2` → low
- `2 – 4` → medium
- `> 4` → high

Kill-chain stages are derived from WHICH sources have evidence
(`investigator.py:249-270`): execution (winsec) → initial access
(live_brute) → exfil (http/live_http) → C2 (dns/live_threat) → recon
(suricata/live_scan) → network (live_net). No correlation → `isolated
signal`.

## Outputs
`{entities, evidence[{source, index, count, label, score}], kill_chain,
hypothesis, correlated_sources, severity, severity_label}`.

## Backend parity
SO docs store the entity pair as `source.ip`/`destination.ip` + an
`event_data.*` envelope and the rule title as `rule.name`; Wazuh uses
`data.src_ip`/`data.dest_ip` + `rule.description`. The investigator queries
all stored shapes so correlation works identically on both backends (proven
live: SO brute-force → medium 3.64, 2 sources → supervisor approve).

## Verify coverage
Two-backend full-loop + Cerber ground-truth harnesses assert the
investigator produces identical evidence on wazuh and SO (3 sources/high,
approve on both).
