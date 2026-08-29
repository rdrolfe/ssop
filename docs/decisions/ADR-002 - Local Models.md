# ADR-002: Local Models for L1-L2 Agents

**Status:** accepted

**Date:** 2026-05-31

**Context**

The L1 (collector) and L2 (triage) agents need to process security events continuously. L1 agents produce structured data from APIs. L2 agents classify alerts with contextual enrichment from Qdrant.

We evaluated cloud API models (OpenAI, Anthropic, DeepSeek) against locally-hosted open models via Ollama.

**Decision**

**Local models on Ollama** (192.168.1.10) for L1-L2. Frontier cloud models reserved for L3 orchestrator planning.

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Cloud APIs (GPT-4, Claude) | Best reasoning quality | Per-alert cost, data leaves enclave, network dependency | Violates sovereignty + cost model |
| All-local for everything | Full sovereignty, zero cost | Frontier models still struggle on consumer GPUs | L3 planning benefits from frontier reasoning |
| Hybrid with local fallback | Resilient | Complexity, two code paths | Premature optimization for now |

**Consequences**

- **Easier:** Zero cost per alert. No rate limits. No data exfiltration risk. 50+ tok/s on local hardware for 7B models.
- **Harder:** Model quality ceiling. Must engineer strong RAG context so the model doesn't need to "know" security from pretraining — it retrieves from Qdrant.
- **Constraint:** Ollama must stay online. Gemma 4, Mistral Small, Qwen 2.5 identified as the initial model candidates.

**Related**

- [[SSOP/architecture/Agent Tiers]]
- [[Ollama]]
- [[SSOP/decisions/ADR-001 - Qdrant]]
