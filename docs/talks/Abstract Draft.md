# Abstract Draft — Self-Testing Security Agents

> Working draft for conference CFP submissions. Revise before submitting.

---

## Title Ideas

- *Agents That Attack Themselves: Building a Sovereign Purple-Team Platform*
- *No Cloud, No Vendor Lock-In: Self-Testing Security Agents on Bare Metal*
- *When Your SIEM Fights Back: AI Agents for Autonomous Detection Validation*

---

## Elevator Pitch (100 words)

Most security AI is either a chatbot bolted onto a SIEM or a vendor demo running in someone else's cloud. We built something different: a sovereign, self-testing purple-team platform where AI agents don't just detect threats — they generate them, verify detection, and report the gaps. Running entirely on local hardware with open models, the system clones vulnerable VMs, executes Atomic Red Team tests, validates Wazuh detection rules, and scores every exercise. No data leaves the enclave. No API bills. No vendor lock-in. This is what security automation looks like when you own the whole stack.

---

## Outline

### 1. The Problem with "AI Security" Today (2 min)
- Chatbot wrappers on SIEM dashboards — not agents
- Cloud dependency: data exfiltration, recurring costs, vendor lock-in
- No feedback loop: "did our detection actually work?"

### 2. The Architecture (5 min)
- Three-tier agent model: L1 Collectors → L2 Triage → L3 Orchestrator
- **Diagram:** Agent tier data flow
- Vector memory (Qdrant) as the agent fabric
- LangGraph state machines for decision loops
- Human-in-the-loop approval gates
- All local: Ollama + Gemma 4 / Mistral Small for L1-L2, frontier models for L3

### 3. The Self-Testing Loop (5 min)
- **Live demo or recording:**
  - Orchestrator clones a Windows VM
  - Deploys Wazuh agent
  - Executes Mimikatz (Atomic Red Team T1003.001)
  - Watches for Wazuh alert
  - Scores the exercise, reports gaps
- Show a real campaign log with detection timing data

### 4. What We Learned (3 min)
- Local 7B models are surprisingly capable with good RAG context
- The hard part isn't the AI — it's the instrumentation (Wazuh rules, agent deployment, VM lifecycle)
- Real numbers: exercises per day, compute cost vs. cloud equivalent, detection gaps found

### 5. Where This Goes (2 min)
- SuperTokens for agent identity and full audit trails
- Multi-agent red/blue exercises (agents attacking agents)
- Community: open-sourcing the agent framework

---

## Target Conferences

| Conference | CFP Window | Focus | Fit |
|------------|------------|-------|-----|
| DEF CON (AI Village) | ~May | Applied AI security | Strong — live demo format |
| BSides (any city) | Rolling | Practitioner talks | Strong — hands-on, no vendor pitch |
| Black Hat Arsenal | ~April | Tool demos | Good — if we open-source the framework |
| SANS CTI Summit | ~Oct | Threat intelligence | Moderate — more analyst-focused |
| fwd:cloudsec | ~Mar | Cloud security | Weak — this is explicitly NOT cloud |

---

## Key Stats to Collect

- [ ] Number of campaigns run
- [ ] Detection gaps identified
- [ ] Average time from attack to alert
- [ ] False positive rate per campaign
- [ ] Power draw / compute cost vs. equivalent cloud spend
- [ ] Models tested and their performance at each tier

---

## Related

- [[SSOP/README]]
- [[SSOP/architecture/Agent Tiers]]
- [[SSOP/exercises/]]
