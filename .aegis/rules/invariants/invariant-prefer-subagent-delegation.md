---
id: invariant-prefer-subagent-delegation
domain: architecture
type: invariant
enforcement: gate
hypothesis: "Orchestrators that implement multi-file tasks directly in the primary thread suffer context saturation, token bloat, and degraded verification compared to orchestrators delegating disjoint implementation lanes to concurrent subagents"
prediction: "Enforcing the Delegation-First Mandate for plans spanning >= 2 disjoint files prevents primary context bloat, reduces token waste, and accelerates execution"
falsification: "Direct single-threaded execution achieves lower total latency, lower token cost, and higher verification pass rates than subagent fan-out across 20 multi-file tasks -> prune"
target_paths:
  - "docs/teams.md"
triggers:
  - feature_implementation
  - refactor
  - delegation
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-10-14
impact_weight: 1.2
tags:
  - delegation
  - subagent
  - architecture
  - efficiency
  - concurrency
---

# Invariant: Prefer Subagent Delegation Protocol

Enforces a strict delegation-first architecture. The orchestrator functions as
the Lead Architect, System Integrator, and Release Gatekeeper, delegating all
independent implementation, research, and audit tasks to concurrent subagents.

## 1. The Delegation-First Principle

- **Orchestrator as Conductor**: The primary conversation context is the most
  expensive and critical resource. It must be reserved for high-level system
  design, cross-module integration, architectural decisions, compilation
  verification, and test execution.
- **Mandatory Delegation Gate**: Whenever an implementation plan contains $\ge 2$
  disjoint files or independent modules, the orchestrator **must delegate** them
  to subagents concurrently under the Disjoint Lane Protocol rather than
  implementing them serially in the main thread.
- **Zero In-Thread Boilerplate**: Routine class scaffolding, widget layouts,
  helper scripts, and isolated ability tasks must always be delegated to
  subagents.

## 2. Disjoint Lane Execution

When dispatching implementation tasks:
1. **Disjoint Ownership**: Assign each subagent a non-overlapping set of files.
   Explicitly instruct the subagent: *"You own `<file_list>`. Do NOT edit or
   touch files outside this list."*
2. **Model Selection**:
   - `inherit` tier: Independent coding lanes (class implementation, logic).
   - `flash` tier: Scripts, configuration generation, documentation, research,
     and review probes.
3. **Single-Call Fan-Out**: Dispatch all independent lanes simultaneously in a
   single `invoke_subagent` tool call to maximize parallelism.
4. **Integration Gate**: Once subagents report completion, the orchestrator
   verifies file contents against claims (per `trap-unverified-delegation`),
   runs the test suite, and conducts synthesis.
