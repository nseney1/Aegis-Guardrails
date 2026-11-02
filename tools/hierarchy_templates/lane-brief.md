# Lane brief: REPLACE_WITH_ENDPOINT_AND_REVISION

Endpoint: a/lane/f2
Endpoint kind (bind by kind, T87): implementer
Binding (T61; the launch prompt's endpoint and generation win): REPLACE_WITH_ENDPOINT_AND_GENERATION
Hierarchy brief: REPLACE_WITH_PATH_AND_SHA256
Goal: REPLACE_WITH_REQUESTED_OUTCOME
Acceptance: REPLACE_WITH_OBSERVABLE_ACCEPTANCE_CHECK

## Source and ownership

- Repository and ROOT-registered worktree (layout f, T38 and T48): REPLACE_WITH_ABSOLUTE_WORKTREE_PATH
- Head branch (it must follow the target repo's route policy, T66; e.g. Stormheir takes only `feature/*` into develop) and full base commit: REPLACE_WITH_BRANCH_AND_COMMIT
- Build-cache directory and free-space preflight (T42; removed at teardown unless kept as evidence): REPLACE_WITH_CACHE_DIR_OR_NONE
- Owned governance paths (T75, T106; every `aegis_core.governance` category: `.aegis/**`, `allowed_signers`, `CODEOWNERS`, `.github/workflows/**`, test-infra such as `Makefile`, `pyproject.toml` and `conftest.py`, and `tests-deleted`, a deleted test file), the expected `aegis check --lane` outcome, the expected hosted `aegis check --ci` governance result and the owner decision that covers it: REPLACE_WITH_PATHS_OUTCOME_AND_DECISION_OR_NONE
- Push exception (T24; none means no push): REPLACE_WITH_OWNER_DECISION_ID_RECORD_PATH_AND_REF_PATTERN_OR_NONE
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
with completion, plus out-of-lane findings and proposed changelog text. Do not push
unless the push-exception field names an owner decision, and do not use GitHub, sign,
merge a PR or activate policy. Rotate after 60 minutes of active work through a
stopped-session checkpoint; do not silently reuse a stale binding.
