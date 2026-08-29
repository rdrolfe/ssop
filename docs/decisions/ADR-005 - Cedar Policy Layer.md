# ADR-005: Cedar-style Policy Layer (layered adoption, not switch)

## ADR-005: Cedar-style Policy Layer over the authority manifest

**Status:** accepted (P2 roadmap — designed now, built after P1)

**Date:** 2026-08-20

**Context**

Peer review suggested evaluating Cedar (cedarpolicy.com, AWS-backed policy
language + authorization engine) against our authority model. Research
completed (v4.12.0 CLI, Rust-first, validator + symbolic analysis with cvc5).

Our current model: manifest → sudoers whitelist. Role→command whitelist
enforced at the OS layer (sudoers) + agent role separation + three-tier
approvals. Strength: kernel-enforced cage. Weakness: no expressive policy
logic (RBAC-ish only, no ABAC conditions), no automated provability (sudoers
is opaque text).

Cedar: expressive RBAC+ABAC language, schema + validator (type-check
policies), symbolic analysis (prove properties, find contradictions — needs
cvc5 SMT solver, experimental flavor), performant engine, Rust-first with CLI
binaries per release. Python SDK is a 0.0.1 stub — NOT the integration path.

**Decision**

**Layered adoption — Cedar (or its ideas) as the POLICY layer ABOVE the
manifest; sudoers stays the ENFORCEMENT floor.** Not a switch.

1. **Policy layer (P2):** the authority manifest becomes Cedar-style policies
   (`permit`/`forbid` over principal/action/resource with ABAC conditions).
   The responder/analyst/intel roles ask the policy engine "is this action
   permitted?" BEFORE execution. sudoers remains the non-negotiable
   kernel-enforced cage beneath — Cedar authorizes, sudoers executes-or-not.
2. **Integration path = the `cedar` CLI binary** (pre-built per release,
   v4.12.0+), invoked by a `tools/policy_client.py` wrapper — NOT the PyPI
   stub. The CLI `authorize` evaluates requests; `validate` type-checks
   policies against a schema.
3. **The validator idea is the immediate win** — a policy-checker that
   proves our manifest/sudoers is consistent (no role has commands outside
   its tier, no orphan permissions) can be built WITHOUT adopting Cedar
   wholesale: a `tools/policy_checker.py` that statically analyzes the
   manifest + sudoers and reports contradictions. This is the "provable"
   principle applied to the authority model, and it ships incrementally.
4. **P1 does NOT adopt Cedar.** P1 ships the responder on the existing
   manifest→sudoers model (already specced in ADR-004 + wayfinder). The
   policy layer lands as a P2 enhancement ON TOP — additive, verify-gated,
   per our principles.

**Alternatives Considered**

| Option | Pros | Cons | Why Rejected |
|--------|------|------|--------------|
| Full switch to Cedar now | Expressive, analyzable, mature | New language + engine in P1; Python SDK is a stub; sudoers still needed under it; big P1 scope increase | P1 is specced; sovereignty/fit win |
| Layered adoption (chosen) | Best of both: Cedar expresses policy, sudoers enforces; validator idea ships incrementally; additive | Two layers to maintain; P2 not P1 | The right architecture |
| Keep manifest→sudoers only, no Cedar | Zero new deps | No ABAC, no provability — the review's point stands | Misses the upgrade |

**Consequences**

- Easier: expressive policy (ABAC conditions on playbook steps), automated
  validation (policy_checker proves consistency), the "provable" principle
  gets real tooling.
- Harder: a new language + CLI dependency in the stack (P2); the policy
  checker needs careful design to not false-positive on legitimate sudoers.
- New constraints: P1 must NOT break the manifest→sudoers contract (verify
  matrix stays green); policy layer is additive only.

**Related**

- [[SSOP/decisions/ADR-004 - SOAR Layer]] (responder executes under this model)
- [[SSOP/architecture/Agent Tiers]] (authority manifest)
- [[SSOP/../PRODUCT_MAP]] (P2 roadmap; peer-review ledger)
- [[SSOP/../docs/wayfinder/map]] (P1 is wayfinder-tracked)
