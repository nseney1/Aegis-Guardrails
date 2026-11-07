# Lane brief: REPLACE_WITH_ENDPOINT_AND_REVISION

Endpoint: a/lane/f2
Endpoint kind (bind by kind, T87): implementer
Binding (T61; the launch prompt's endpoint and generation win): REPLACE_WITH_ENDPOINT_AND_GENERATION
Hierarchy brief: REPLACE_WITH_PATH_AND_SHA256
Goal: REPLACE_WITH_REQUESTED_OUTCOME
Acceptance: REPLACE_WITH_OBSERVABLE_ACCEPTANCE_CHECK
Deadline (T111 (3), T117): REPLACE_WITH_MINUTES, counted from the dispatch; the wait for the dispatch does not count

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
lane. Reviewers receive a source-pinned diff and have no writing lease. This brief
lives in `initiatives/<id>/briefs/` (T116): a bind or dispatch refuses a brief outside
the mailbox's parent folder (`tools/hierarchy_mailbox.py:315-317` at `b41c75b9`).

## Readiness and verification

Scan results (from the orchestrator's `scan` job, one per path you will edit, each with
its receipt's evidence path and sha256): REPLACE_WITH_SCAN_RESULTS

You run in Claude print mode, with no command tool. Confirm the branch, base and live
lease from this brief and your tools' output; have the orchestrator re-read all claims
after serial claiming. Keep claims, scan coverage and shared events separate. Record the
advisory/best-effort tier. Never treat a mailbox acknowledgment as permission.

Before your first edit, hold a scan result above for every path you will edit; if any
path lacks one, edit nothing and report a blocker. Write the behavior regression first.
Its RED and GREEN runs, the commit and the other checks are jobs your orchestrator files
from root's recipes: name each in your result, with why, as `not_run`, and name the exact
paths you changed, which stay uncommitted in the worktree. A check that no recipe
provides is recorded `not_run` under the recorded weaker boundary (owner decision 4).

## Reporting and session hygiene

Check the inbox before reporting. Accept by publishing a mailbox `ack` in reply to the
dispatch, with readiness for a writing lane; only that `ack` is the acceptance (T134,
T126 (2)). A separate received message is optional. Publish the
`ack` and the `result` with the fields and in the order of the protocol checklist in
your role contract (your start turn). Send source/check evidence with completion,
plus out-of-lane findings and proposed changelog text. Do not push
unless the push-exception field names an owner decision, and do not use GitHub, sign,
merge a PR or activate policy. Rotate after 60 minutes of active work through a
stopped-session checkpoint; do not silently reuse a stale binding. Report only through
the mailbox (T136). A result that lists open items for your manager still ends your turn;
an "accept" message or a fix-round dispatch starts your next one (T125 (2)).
