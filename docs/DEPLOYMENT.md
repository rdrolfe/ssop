# SSOP Deployment Guide (Level 2)

This walks a fresh environment through standing up SSOP end-to-end. It's written
so a small team can go from clone to running roles in an afternoon. Total footprint:
one Docker host with ~16GB RAM and a couple of GB of disk.

## Prerequisites

- Linux (Ubuntu 22.04+/24.04+ recommended) or any Docker host
- Docker + Docker Compose plugin
- Python 3.10+
- ~20GB free disk (Wazuh images are heavy)
- A machine you're willing to SSH into (the infra-manager's reachable hosts)
  — for the first run, localhost alone is enough to test the loop

## Step 1 — clone + bring up the stack

```bash
git clone <your-repo-url> ssop && cd ssop
cp deploy/.env.example deploy/.env     # edit the values (see below)
docker compose -f deploy/docker-compose.yml up -d
```

This starts Qdrant (case spine + memory) and the Wazuh single-node stack
(indexer, manager, dashboard).

**Wait for Wazuh.** The indexer does a one-time security init that takes several
minutes:

```bash
# poll until this returns 401 (401 = up, auth required = ready)
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:9200/
```

## Step 2 — configure deploy/.env

```bash
# SIEM — these MUST match what the Wazuh containers expect
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=your_strong_password

# Manager API (used by wazuh:agents etc.)
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=your_api_password

# Escalation delivery — point at any OpenAI-compatible API, or leave blank
# to queue escalations to files (no delivery) until you wire a supervisory agent.
HERMES_API_URL=http://your-supervisor:8642/v1/chat/completions
HERMES_API_KEY=your_key

# Hosts the infra-manager can reach (name=ip pairs)
SSH_HOSTS=web=10.0.0.5,db=10.0.0.6
SSH_USER=your_user
SSH_KEY_PATH=~/.ssh/id_ed25519
```

> Note: Wazuh's official single-node compose also needs `INDEXER_PASSWORD` and
> `WAZUH_API_PASSWORD` set consistently across all containers — the SSOP compose
> reads them from the same deploy/.env so they stay in sync.

## Step 3 — bootstrap

```bash
bash deploy/bootstrap.sh
```

This creates a venv, installs deps, writes the root `.env`, creates the Qdrant
collections, and smoke-tests the three role CLIs.

## Step 4 — register a Wazuh agent (your first telemetry)

Install the agent on any host you want monitored (including the SSOP host itself):

```bash
# on the target host (Ubuntu/Debian)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor | sudo tee /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install -y wazuh-agent
# point at your manager
sudo sed -i "s|<address>MANAGER_IP</address>|<address>localhost</address>|" /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/agent-auth -m localhost -p 1515 -A $(hostname)
sudo systemctl enable --now wazuh-agent
```

## Step 5 — run the roles

```bash
source .venv/bin/activate

# ANALYST: react to alerts
python3 agents/analyst.py analyst:recent limit=5 min_level=3

# HUNT: test a hypothesis against telemetry
python3 agents/hunt.py hunt:run auth-success-from-unusual-src days=7
python3 agents/hunt.py hunt:list

# INFRA-MANAGER: sense + heal (needs SSH access to the hosts you defined)
python3 agents/agent.py self_heal:run
python3 agents/agent.py ssh:health <host>

# INCIDENT SPINE: inspect a case + reconcile the two stores
python3 agents/analyst.py analyst:case case-xxxxx
python3 agents/analyst.py analyst:reconcile
```

## What you should see

- `analyst:recent` ingests alerts, classifies them (auth/threat/integrity/...),
  and escalates high-severity ones — minting a `case-<hex>` on the spine.
- `hunt:run` executes a hypothesis query, files the finding on the spine, and
  escalates suspicious results in attack-relevant categories.
- `analyst:reconcile` compares Qdrant vs JSONL and reports divergence — the
  supervisory agent's integrity duty.
- Escalations land in `tickets/` (queued). With `HERMES_API_URL` set, they POST
  to your supervisory agent for adjudication.

## Extending

- **Add a hunt:** append to `HUNTS` in `agents/tools/hunt_tools.py` — hypothesis,
  OpenSearch query, analyzer. The skeleton does the rest.
- **Add a role:** new `agents/<role>.py` LangGraph file + tool client, bound to
  the case spine. Identity/audit/escalation are shared.
- **Wire SPIRE (optional identity layer):** see `docs/ARCHITECTURE.md` §7. The
  reference deployment uses it; the compose path starts without it so you can
  defer the CA ceremony.

## Troubleshooting

- `analyst:recent` 401/404: your `deploy/.env` creds don't match the Wazuh
  containers. All containers share the same env — keep them consistent.
- Wazuh dashboard 503 for minutes: normal during first boot, give it time.
- Qdrant "collection not found": run `bash deploy/bootstrap.sh` again — it
  creates `cases` and `ltp` idempotently.
- Hunt returns 0 events: the window is `days=N` — default 7; if the agent
  registered recently there may be little telemetry yet.

## Step 6 — the pane of glass (optional but recommended)

Ship agent activity into the SIEM so it's visible in the Wazuh dashboard:

```bash
# 1. Start the OTel collector (shipping audit JSONL + tickets -> indexer)
cp deploy/otel-config.yaml /tmp/otel-config.yaml   # edit endpoint if your indexer is elsewhere
docker run -d --name ssop-otel --restart unless-stopped \
  -v $(pwd)/audit:/data/audit:ro \
  -v $(pwd)/tickets:/data/tickets:ro \
  -v /tmp/otel-config.yaml:/etc/otel-config.yaml:ro \
  -e WAZUH_INDEXER_USERNAME=admin \
  -e WAZUH_INDEXER_PASSWORD=your_indexer_password \
  otel/opentelemetry-collector-contrib:latest --config /etc/otel-config.yaml

# 2. Register the index pattern (run on the dashboard host)
#    Dashboard -> Discover -> create index pattern "ssop-events" (time field @timestamp)
```

Then every agent action (actor, command, host, spiffe id) and escalation ticket is
searchable in the same OpenSearch as your Wazuh security events. One pane of glass.

## Step 7 — make the SOC run itself (optional but recommended)

The platform operates unattended with three systemd timers (on the host
running the role CLIs). Copy `deploy/systemd/*` to `~/.config/systemd/user/`
(or `/etc/systemd/system/`), then:

```bash
systemctl link ssop-analyst.service ssop-analyst.timer \
               ssop-supervisory.service ssop-supervisory.timer \
               ssop-selfheal.service ssop-selfheal.timer
systemctl enable --now ssop-analyst.timer ssop-supervisory.timer ssop-selfheal.timer
```

The cycle:
- every 5m — analyst sweep (ingest alerts, classify, escalate high-severity)
- 04:45    — supervisory duty (adjudicate queue, reconcile case spine)
- 03:07    — self-heal (host health, disk incl. docker prune, agent connectivity)

Every run logs to journald; outcomes flow to the case spine and the pane of
glass automatically. The platform keeps working whether anyone is watching.

**The sweep cadence is an adjustable nozzle, not a one-time flip.** Two knobs,
tuned here for a homelab (thousands of events/hour):

- `OnCalendar` in `deploy/systemd/ssop-analyst.timer` — how often the sweep
  fires. A run costs ~6s CPU / ~100MB peak regardless of cadence (pure-rule
  classification; no LLM in the sweep itself — escalation only fires when a
  verdict escalates, which is rare). So halving the interval ~doubles CPU
  spend linearly: 5m ≈ 29 min CPU/day, 1m ≈ 2.4h CPU/day, and the 1m mark is
  where the per-run Python startup stops being free.
- `limit=` in `deploy/systemd/ssop-analyst.sh` — how many alerts a run
  classifies. This is the coverage knob: at 2h/limit=20 the sweep only ever
  saw the 20 newest alerts (the blind spot we fixed — a busy 45-min window
  pulled 200). Raise `limit` alongside any cadence increase or you're just
  polling a smaller slice faster.

**At scale (millions of events/minute) the nozzle model flips to a poller.**
A fixed-cadence sweep pays ~6s of process startup every tick; past a few
hundred-thousand events/min the right shape is a resident poller (start once,
loop cheaply) or event-driven dispatch — the router in Step 8 already does
interval polling with a cursor (`router_state.json`) and is the natural
upgrade path. Rule: keep the sweep a short-lived oneshot while `limit` covers
a full interval's traffic; move to the poller the moment the backlog outruns
the window.

## Step 8 — event-driven dispatch (the router)

The platform responds to alerts in minutes, not on schedule. The router polls
the indexer every 3 minutes, classifies each new alert, and dispatches to the
owning role:

- infra-class    -> infra-manager: sense + heal, or escalate
- security-class -> analyst: triage + verdict + case
- pattern-class  -> hunt: investigate + file finding
- compliance     -> logged
- cross-cutting  -> supervisory: adjudicate + reconcile

```bash
# Router tracks processed alerts in router_state.json (dedupe, cursor)
python3 agents/router.py            # live run
python3 agents/router.py --dry-run  # preview without dispatching

# Timer (every 3 min):
systemctl link ssop-router.service ssop-router.timer
systemctl enable --now ssop-router.timer
```

Classification is rule-driven (RULE_MAP in agents/router.py) — deterministic,
auditable, and the extension point for model-assisted triage later.

## Step 9 — the network plane (Suricata IDS, optional but recommended)

Wazuh agents see what happens ON the hosts — nothing sees what crosses the
wire (DNS callouts, C2 beacons, scans are invisible). Add Suricata on a
sniffing host to close that gap:

```bash
# On the sniffing host (the "network" VM):
apt-get install -y suricata
sudo suricata-update                    # fetches ~68k rules incl. emerging-threats
sed -i 's/- interface: eth0/- interface: <your-lan-nic>/' /etc/suricata/suricata.yaml

# CRITICAL: create the log dir BEFORE starting (package may not create it,
# and Suricata silently writes nothing without it):
mkdir -p /var/log/suricata

# If the service crash-loops, override with Type=simple + autofp (see
# deploy/systemd/suricata-override.conf in the repo).
```

Wire into Wazuh: add a localfile to the agent's ossec.conf on the sniffing
host and restart the agent:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Suricata alerts become Wazuh rules (e.g. 86601) with `data.suricata` fields.
Tune the `SURICATA Ethertype unknown` (2200121) noise rule — it fires every
~2s from mDNS on home networks. A ready-made detection + drill kit lives in
`deploy/suricata/` (custom DNS-beacon rule `ssop-drill.rules` and beacon
generators to validate the full chain).

## Step 10 — operations overview dashboard (the pane of glass)

The index pattern + Discover view gives you raw events; a dashboard gives you
the high-level operational picture (tickets, actions, heal activity, actors).

```bash
# 1. Grant the dashboard user read access to ssop-events (required or every
#    panel errors with security_exception field_caps):
deploy/dashboards/fix_kibana_perm.sh

# 2. Create visualizations + dashboard with the index pattern embedded.
#    See deploy/dashboards/ — the two critical requirements:
#    - searchSourceJSON MUST contain "index":"ssop-events" (references array
#      alone is not enough -> "Trying to initialize aggs without index pattern")
#    - bar visualizations use visState.type "histogram", NOT "bar"
#      (-> "invalid visualization 'bar'")
```

The dashboard panels: total metrics, events over time by source, tickets by
source, actions by actor, heal & maintenance actions, top commands. Every
role's activity flows in automatically via the OTel pipeline.

## Step 11 — develop against real APT data (BOTSv1, optional but powerful)

To develop agent tradecraft against a rich, fully-enabled APT dataset (not just
lab noise), ingest Splunk's BOTSv1 (Boss of the SOC) — it ships as **native JSON
per sourcetype** (CC0 public domain), so no Splunk install is needed:

```bash
# 1. Download a slice (the per-sourcetype JSON files, S3-hosted):
curl -sO https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/botsv1.stream-http.json.gz
curl -sO https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz
# (full list + sizes in the README of github.com/splunk/botsv1)

# 2. Ingest into the indexer (flattens Splunk's result.* -> ontology shape):
python3 -c "
import sys; from dotenv import load_dotenv; load_dotenv(); sys.path.insert(0,'.')
from tools.ingest_bots import ingest
ingest('botsv1.stream-http.json.gz', 'bots-http-poc')"

# 3. Point the transport at the BOTS backend (see transport.yaml):
#    backend: bots   # alerts_index: bots-*-poc
```

The BOTS data (Sysmon network conns, HTTP exfil, DNS tunneling, process-exec)
is exactly what the recognition + investigation layers are validated against —
see `agents/tools/bots_parser.py` (the transport extension that teaches the
ontology each source's shape "as it lies") and `docs/wayfinder/tickets/botsv1-ground-truth.md`
(the known APT answers for validating agent findings).

## Step 12 — the two-backend doctrine (Wazuh + Security Onion)

The ontology is transport-agnostic: the same spine runs on Wazuh OR Security
Onion by flipping `backend:` in `transport.yaml`. Each backend declares its
index pattern, endpoint, and per-backend field overrides:

```yaml
backend: wazuh          # flip to: securityonion | bots
backends:
  wazuh:
    alerts_index: "wazuh-alerts-4.x-*"
    endpoint: "https://192.168.1.75:9200"
  securityonion:
    alerts_index: ".ds-logs-zeek-so-*,so-detection"
    endpoint: "https://192.168.1.76:9200"
```

The **two-backend comparison** (`python3 -m verify.two_backend_cmp`) proves the
same ontology executes identically on both SIEMs on real BOTS data — the
transport flips, the spine doesn't. When adding a backend: declare it in
`transport.yaml`, add a parser branch in `bots_parser.py` if the data shape is
new, and re-run the verify matrix (fixtures are Wazuh-shaped; the matrix pins
the backend to wazuh deterministically).

## Step 13 — the closed-loop roles (supervisor + responder)

The full loop is analyst -> supervisor -> responder, with the human as the
authority:

- **Analyst** recognizes signals, investigates (correlates the entity across
  sources, scores the kill-chain: `investigator.py`), appends the hypothesis
  + evidence to the case timeline, escalates.
- **Supervisor** adjudicates **with the evidence** (`supervisory_tools.py`
  `adjudicate_with_investigation`): high severity OR 2+ kill-chain stages =>
  approve, else deny. Decisions write the tuning ledger (analyst respects them).
- **Responder** resolves the supervisor's recommendation from the case and
  OBEYS the verdict — a denied case is refused (`responder.py` approval gate).

The adjudication API + console (`agents/tools/adjudicate_api.py`, served at
`http://<host>:8787`) gives the human the **Closed Loop** view: severity badge,
kill-chain, hypothesis, adjudication rationale, and any responder block —
every case's full chain in one screen.

```bash
# Start the adjudication console (TLS certs expected at /tmp/api_*.pem):
python3 agents/tools/adjudicate_api_entry.py --host 0.0.0.0 --port 8787 --tls
```


