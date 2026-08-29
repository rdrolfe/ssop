# ADR-001: Qdrant over Pinecone for Vector Memory

**Status:** accepted

**Date:** 2026-05-31

**Context**

The agent architecture needs a vector database for:
- Storing Wazuh alerts with embeddings for similarity search (L2 triage)
- Long-term agent memory (campaign history, detection patterns)
- Semantic search across all security events

We evaluated managed cloud options (Pinecone, Weaviate Cloud) against self-hosted options (Qdrant, Milvus, Chroma).

**Decision**

**Qdrant**, self-hosted on kb-vec (192.168.1.94:6333).

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Pinecone | Zero ops, fast | Cloud-only, data leaves enclave, recurring cost | Violates sovereignty requirement |
| Weaviate Cloud | GraphQL-native, hybrid search | Cloud-only, pricing at scale unclear | Same sovereignty issue |
| Milvus | Mature, distributed | Heavy ops, overkill for single-node | Qdrant simpler for this scale |
| Chroma | Dead simple, Python-native | No production story, no clustering | Good for dev, not for persistent agent memory |

**Consequences**

- **Easier:** Full sovereignty — no data leaves the enclave. Zero API cost. SDK is clean (qdrant-client 1.18.0 already in the venv).
- **Harder:** We own the ops. Backups, monitoring, uptime are our responsibility. kb-vec must stay online.
- **Constraint:** Single-node deployment for now. Qdrant supports clustering if we outgrow it.

**Related**

- [[SSOP/architecture/Agent Tiers]]
- [[kb-vec]]
