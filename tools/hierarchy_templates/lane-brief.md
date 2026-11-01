# Lane brief: REPLACE_WITH_ENDPOINT_AND_REVISION

Endpoint: a/lane/f2
Kind: implementer
Hierarchy brief: REPLACE_WITH_PATH_AND_SHA256
Goal: REPLACE_WITH_REQUESTED_OUTCOME
Acceptance: REPLACE_WITH_OBSERVABLE_ACCEPTANCE_CHECK

## Source and ownership

- Repository/worktree: REPLACE_WITH_EXACT_WORKTREE_ROOT
- Branch and full base commit: REPLACE_WITH_BRANCH_AND_COMMIT
- Lease id/ref, object id and expiry: REPLACE_WITH_OBSERVED_CLAIM
- Owned paths and allowed shared paths: REPLACE_WITH_EXPLICIT_PATHS
- Cross-lane interfaces and anti-goals: REPLACE_WITH_REVIEWED_BOUNDARIES

Only this lane's worktree may be edited. Do not widen a lease yourself. Send an
escalation to the local orchestrator when another path needs a change. Integration
fixes, generated contracts and release documentation belong to a scoped integration
lane. Reviewers receive a source-pinned diff and have no writing lease.

## Readiness and verification

Record the exact interpreter/tool versions and current Git/common-directory
identity. Confirm the branch, base and live lease; have the orchestrator re-read
all claims after serial claiming. Keep claims, scan coverage and shared events
separate. Prove the scan reaches this worktree. Hook documentation or installation
alone is not a live enforcement result. Record advisory/best-effort tier and its
probe evidence. Never treat a mailbox acknowledgment as permission.

Scan before every edit, including test and documentation fixes. Use the lane-local
CLI when MCP is bound elsewhere. Write the behavior regression first, preserve its
correct RED, then implement and run affected checks. Record exact commands, source
commit/tree, failures, skipped/not-run checks and raw evidence references. Run the
required full suite before a commit. Run the committed lane check against the exact
base; a verdict on an unchanged HEAD does not check uncommitted edits.

## Reporting and session hygiene

Check the inbox before reporting. Send separate received and accepted messages;
include readiness with acceptance for a writing lane. Send source/check evidence
with completion, plus out-of-lane findings and proposed changelog text. Do not push,
use GitHub, sign, merge a PR or activate policy. Rotate after 45 minutes of active
work through a stopped-session checkpoint; do not silently reuse a stale binding.
