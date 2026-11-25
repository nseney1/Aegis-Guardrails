---
id: trap-unconfirmed-host-binding
type: trap
enforcement: advisory
domain: correctness
hypothesis: "A requested host can differ from the host or session that actually starts."
prediction: "A pinned assignment with a fallback or stale session will fail the observed binding check."
falsification: "Retire if ten unavailable pinned-host or stale-session cases are all surfaced before work is credited to the requested host."
target_paths:
  - aegis_core/team_host_plan.py
  - tools/hierarchy_handoff.py
triggers:
  - host_routing
  - handoff
minimum_mode: patrol
expiry_sessions: 50
expiry_days: 180
created: 2026-11-23
---

## Do

For a governed host plan, compare the observed session, generation and host
with the required binding at launch or resume, and return a routing refusal
for an unapproved substitution.

A pinned assignment with a fallback or stale session will fail the observed
binding check.

Keep the requested and observed host identities available to the coordinator
at the same decision point.

## Evidence

team_host_plan.require_binding and the handoff successor checks are the
relevant boundaries. Apply the check where an explicit plan governs the
assignment.

- 2026-11-21 — Reused a stalled session after an authentication lapse. Three timeouts preceded a fresh binding (coordinator decision log).
- 2026-11-23 — Retried a pinned assignment without ensuring capacity for that family. It fell back again after an owner-approved stop (coordinator decision log).

Catalog comparison: extends contract-workspace-session-binding.
