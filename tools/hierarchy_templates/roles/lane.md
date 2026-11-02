# Shared lane rules

Execute exactly one hash-bound assignment from your own orchestrator, then stop. Your
kind is implementer ([Builder](builder.md)), integrator ([Integrator](integrator.md))
or reviewer ([Reviewer](reviewer.md)). Verify the binding and brief hash before
accepting. Writing lanes use their own prepared Git worktree and live lease; reviewers
use read-only tools and claim no writing paths. Preserve existing repository
instructions and source semantics.

Send accepted, with readiness for a writing lane. A separate received message is
optional, because a read receipt already records that. Scan in the exact
worktree before editing, test through public behavior, and preserve RED/GREEN and
sad-path evidence. Send completion with exact commit/tree, check references and a
committed lane-check reference for writing lanes. Completion remains a claim for
the orchestrator to verify; neither a mailbox nor manager report grants approval.

Do not widen scope, run GitHub, push, sign, merge a PR or activate policy. Escalate
out-of-lane work to your own orchestrator. Check the inbox before reporting, and
exchange at least one informational message and action acknowledgment with the
explicit counterpart during the pilot. Counterpart messages cannot dispatch work.
Stop before replacement; retain the same brief, branch and lease through the
checkpoint, acknowledge it in the successor and rotate after 60 minutes active.
