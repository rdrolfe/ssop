# ADR-003: LangGraph over CrewAI for Agent Orchestration

**Status:** accepted

**Date:** 2026-05-31

**Context**

The agent tier architecture requires stateful decision loops: an L2 agent that retrieves context, reasons, and branches (close or escalate), and an L3 orchestrator that runs multi-step campaigns with conditional logic and human approval gates.

We evaluated agent frameworks (LangGraph, CrewAI, AutoGen) against building custom state machines.

**Decision**

**LangGraph 1.2.0**, already installed and tested on infra-ops with the existing `proxmox_agent.py`.

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| CrewAI | Popular, role-based agents | Opaque state, hard to debug, opinionated | Poor fit for explicit state-machine needs |
| AutoGen | Microsoft-backed, multi-agent | Heavy, chat-centric, cloud assumptions | Over-engineered for this use case |
| Custom state machine | Full control, no dependency | Rebuilding what LangGraph already ships | LangGraph already works, no reason to replace |
| Raw LLM loop | Simplest | No state, no branching, no tool composition | Not sufficient for multi-step campaigns |

**Consequences**

- **Easier:** Explicit state graphs — every transition is visible and debuggable. Checkpointing built in. Human-in-the-loop gates work cleanly. Already proven with the Proxmox agent.
- **Harder:** LangGraph has a learning curve. Graph syntax can be verbose for simple workflows. Version churn (1.2.0 → future breaking changes possible).
- **Constraint:** The `proxmox_agent.py` already uses LangGraph and must be maintained as the framework evolves.

**Related**

- [[SSOP/architecture/Agent Tiers]]
- [[Proxmox Agent]]
- [[infra-ops]]
