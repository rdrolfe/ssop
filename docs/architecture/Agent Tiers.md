# Agent Tiers

The SSOP agent architecture uses three tiers of escalating capability and authority. This mirrors how a real SOC escalates — from observation to investigation to action.

## L1 — Sensor & Collector Agents

**Role:** Observe. Report. Never decide.

**What they do:**
- [[Wazuh Agent]] — Pulls new alerts from Wazuh API, enriches with MITRE ATT&CK tags, pushes to [[Qdrant]]
- [[Network Agent]] — Watches Suricata/Zeek flows for anomalies, pushes flow summaries
- [[Proxmox Agent]] — Monitors VM state changes: clones, snapshots, resource spikes
- [[Log Agent]] — Tails structured logs (auth, web, syslog) and pushes parsed events

**Model requirement:** None. These are structured ETL pipelines, not LLM-driven. Python scripts on cron or daemon mode, outputting to Qdrant.

**Authority:** Read-only. Cannot modify infrastructure.

**Runtime:** Daemons or cron-triggered on infra-ops.

---

## L2 — Triage & Investigation Agents

**Role:** Investigate. Contextualize. Escalate or close.

**What they do:**
1. Wake on new high-severity alert in Qdrant
2. Pull alert + temporal context window (what else happened on that host?)
3. Query related events across data sources
4. Check [[Proxmox Agent]] — is this VM a known target? Recently cloned? Snapshot available?
5. Produce verdict: `false_positive | low_priority | escalate_to_L3`
6. If low-priority but real, open ticket. If critical, page orchestrator.

**Model requirement:** 7B-14B parameter local model. Gemma 4, Mistral Small, Qwen 2.5 — enough for classification with strong RAG context. Runs on Ollama (.10).

**Why local models here:**
- 50+ tokens/second, zero API cost
- No data leaves the enclave
- RAG context from Qdrant does the heavy lifting — the model just classifies

**Authority:** Can open tickets, tag alerts, request VM snapshots. Cannot start/stop infrastructure.

---

## L3 — Orchestrator & Red Team

**Role:** Plan campaigns. Execute. Score. Report gaps.

**What they do:**

### Campaign lifecycle
1. **Plan** — Take a MITRE technique (e.g., T1003 credential dumping)
2. **Provision** — Clone fresh target VM from template via [[Proxmox Agent]]
3. **Instrument** — Deploy Wazuh agent on target, wait for heartbeat
4. **Attack** — Execute Atomic Red Team test or custom payload
5. **Observe** — Did Wazuh fire the expected alert? Within time window?
6. **Score** — Record detection status, timing, rule match quality
7. **Teardown** — Destroy target VM, clean up
8. **Report** — Update [[SSOP/exercises/]] with results

### Self-testing loop
This is the headline capability: the orchestrator *attacks the platform to validate the platform*. Every campaign produces:
- A detection score (pass/fail/partial)
- Timing data (seconds from attack to alert)
- A gap report if detection missed it

**Model requirement:** Frontier-tier for campaign planning and gap analysis (Claude, GPT-4, DeepSeek-V3). 7B models can handle execution steps.

**Authority:** Full. Can clone/destroy VMs, deploy agents, execute attack payloads. **All actions require human approval gate** (implemented in `proxmox_agent.py`). [[SuperTokens]] provides full audit trail.

---

## Data Flow

```
Target VMs ──→ Wazuh ──→ Qdrant ←── L1 Collectors
                                │
                                ▼
                          L2 Triage Agent (LangGraph)
                           │          │
                    close/park    escalate
                                      │
                                      ▼
                          L3 Orchestrator (LangGraph)
                           │
                    ┌──────┼──────┐
                    ▼      ▼      ▼
                 Proxmox  Wazuh  Atomic Red Team
                 (clone)  (verify)  (attack)
```

## Decision Points

- [[SSOP/decisions/Why Qdrant over Pinecone]]
- [[SSOP/decisions/Why local models for L1-L2]]
- [[SSOP/decisions/Why LangGraph over CrewAI]]

## Related

- [[SSOP/README]]
- [[Proxmox Agent]]
- [[Wazuh Agent]]
- [[SuperTokens]]
