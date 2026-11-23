# Architecture

Aegis keeps rules in the repository, delivers matching guidance before an edit,
checks changes, and records evidence about the result. The CLI and MCP server use
the same core services. The agent's report, a local test result, and confirmation
from the landing commit's CI are separate inputs with different authority.

Start with [how Aegis works](how-it-works.md) for the workflow and rule format.
The [reference](reference.md) lists every public command and MCP schema.

## Components

| Component | Responsibility | Boundary |
|---|---|---|
| `aegis_core` | Workspace resolution, rules, matching, checks, evidence and fitness | Imports no CLI, MCP or SDK code; internal layers depend only on their own layer or lower layers |
| `aegis_cli` | Commands, installation, host hooks and human-readable output | Calls core services; does not import MCP or SDK adapters |
| `aegis_mcp` | Tool schemas, session binding and tool handlers | Calls core services; does not import CLI or SDK adapters |
| `aegis_sdk` | External Python facade through `Governance` and `parse_rule_file` | Calls core services; production adapters do not depend on it |
| Host integrations | Bootstrap instructions, MCP registration and optional hooks | Run with the user's permissions; host behavior determines what reaches Aegis |
| Git and CI | Commit identity, reviewed policy and landing evidence | Local hooks are bypassable; required CI and branch protection provide the review boundary |

The Python runtime uses only the standard library. Some operations invoke external
programs: Git for repository operations, the user's `gh` for GitHub evidence,
configured test commands, the opt-in Go parser and user drivers, and an explicitly requested
Layer 2 model command. Zero runtime dependencies does not mean every operation is
self-contained or offline.

```mermaid
flowchart TD
    Agent[Agent] --> MCP[MCP adapter]
    Person[Person or automation] --> CLI[CLI adapter]
    MCP --> Workspace[Workspace binding]
    CLI --> Workspace
    Workspace --> Rules[Rule loading and matching]
    Rules --> Scan[Budgeted guidance]
    Scan --> Agent
    CLI --> Checks[Deterministic checks]
    CLI -. optional .-> Review[Advisory Layer 2 review]
    Checks --> Result[Check result]
    CLI -- record with tests --> Witness[Recorded test witness]
    MCP -- outcome report --> Credit[Credit state machine]
    Witness --> Credit
    CI[Landing commit CI] --> Credit
    Credit --> Ledger[(Outcome ledger)]
    Ledger --> Fitness[Derived fitness and suggestions]
    Fitness --> Human[Human review and committed rule change]
    Human --> Rules
```

## A scan and a check answer different questions

A scan answers which guidance applies to the named files. The shared rule loader
fails if any rule file cannot be loaded. Matching uses repository-relative paths;
mandatory rules take priority, with a slot cap and explicit omission reporting.
The response also has a token budget. In Git, binding rules come from the selected
base rather than branch-local edits; the response identifies that base and whether
it is review-witnessed. A local-HEAD fallback is not reviewed-base evidence.

A check asks whether a change meets the enabled deterministic checks. Layer 1
covers rule validity, applicable AST constraints, introduced security findings and
other code checks. The Git pre-commit hook checks staged content. CI checks the
candidate commit and governance changes. The optional Layer 2 verdict is advisory:
it does not change the exit status determined by Layer 1 or award rule credit.
A failed model invocation or test discovery still makes the command fail.

Workspace resolution happens before guidance is served. An operator pin has
priority, followed by host context, registered workspaces and a bounded directory
walk. Conflicting context holds the request rather than choosing silently. When no
workspace is governed, MCP can serve the read-only personal rule layer without
writing repository state. See [workspace binding](hosts-and-hooks.md#workspace-binding).

## Evidence and state

| State | Writer and purpose | Authority |
|---|---|---|
| `.aegis/rules/`, repository configuration and team policy | Reviewed repository changes | Policy; repository settings cannot choose arbitrary executable commands |
| `~/.aegis/config.json` | Operator | Command-like settings, including test and custom driver commands |
| `.aegis/state/activity.jsonl` | Scans and edit bookkeeping | Recent scan coverage; not proof that guidance was followed |
| `<git common dir>/aegis/state/<ws-id>/ledger.jsonl` | Checks, reports and evidence processing | Append-only rule evidence, shared by worktrees of the same workspace |
| `<git common dir>/aegis/events.jsonl` | Hooks, teams and other commands | Operational events; never used for fitness or scan compliance |
| `refs/aegis/lanes/<lane>` | Team commands | Cooperative path claims, not locks or identity |

Outside Git, the ledger and events log live under `.aegis/state/`. The full storage
map and retention details are in [how Aegis works](how-it-works.md) and
[PRIVACY](../PRIVACY.md).

For an outcome report to use a local test witness, a passing
`aegis check --record --tests` row must cover the exact Git tree. A report without
that witness is an unwitnessed claim and earns no rule credit. A `--record` check
without tests is not a test witness. Rules eligible for report credit come from
the session's scans and matching diff, not an agent-supplied list of rule IDs.
Confirmation from the landing commit's CI is a further step; local success alone
does not establish it. Reviewed adjudications are a separate evidence path.

### Tree-bound Teams qualification

`team_qualify` is a custodian library, with no CLI activation. A trusted executor
adapter supplies a passing result bound to the exact tree, source/base commit, leg and
run identifier. The executor never writes refs. The custodian stores the result
as a bounded JSON message in a commit at `refs/aegis/qual/<tree>/<leg>`, using only
`team_git.cas_fast_forward`. The first record parents its source/base commit;
each newer record parents the previous record. Records are never deleted or
force-moved. A GitOpsJournal intent precedes publication and an observed result
follows it. A repeated request observes its first attempt without repeating CAS;
an interrupted result write is recovered through journal reconciliation.
The tested tree may be an uncommitted private snapshot: its base commit need not
have that tree, so qualification can precede the tested-bytes lane commit.

`qualified(store, tree, legs)` requires every explicit leg on the exact tree.
Missing, malformed, foreign-tree, wrong-leg, oversized and non-commit records
return false. Object sizes are checked before capture and JSON parsing. Ref reads
use strict custody bound to the GitStore's trusted worktree and validated
scratch. Object reads and publication use the GitStore's fenced operations, so a
Git executable planted inside the editable checkout cannot run in the custodian.
Required legs come from the trusted caller: the Publisher contract requires the applicable
local legs and hosted legs for release PRs, but declares no fixed leg identifiers.
Its `qualified(request)` hook is not connected in this tree.

`approval_equivalent` permits structural carry-over only for a direct empty commit
with the same tree, the standard approval subject and exactly one printable
`Aegis-Approve` digest line. Extra metadata, continued values and changed trees
refuse carry-over. This is separate from the policy gate's signature and digest
verification; structural equivalence alone grants no approval authority.

`team_qualify` occupies layer zero in `CORE_LAYERS` in
`tests/contract/test_import_boundary.py`. Its runtime dependencies are existing
layer-zero Git, journal, approval-shape, primitive and redaction services.

### Git delivery

`aegis_core.team_git` has no CLI. `snapshot_tree` writes a private index and returns a tree id. `plan_merge`, `plan_pick` and `plan_revert` do not publish. `commit_tested` records a commit inside the store. Only `cas_fast_forward` publishes objects and updates a ref. `team_qualify.record_pass` and `team_custody.commit` journal that effect first through `aegis_core.team_gitops`, which runs neither git nor `gh`. `Publisher` in `aegis_core.team_publish` accepts an effect only with an unused permit, an owner-supplied `gh` adapter and a qualification reader. Activation of that service is not wired.

`aegis_core.merge_queue.MergeQueue` checks every required qualification leg against the exact landing tree. `MergeQueue.revalidate` rechecks the candidate and uses its own queue checkpoint before calling `team_git.cas_fast_forward` to create the candidate pin. It issues a receipt for a separate publisher and does not write a team_gitops journal. `revalidate` refuses `issued_unresolved` while an issued record or cleanup is set, and `check_issued` refuses it when that issued checkpoint conflicts or results remain, so another publication does not start. A refusal's `next_action` names the custodian and a fixed recovery text, and it echoes no transport text. Automatic landing remains separate work.

#### Teams platform capabilities

Windows lacks the strict Git runner and the POSIX capabilities required by the
snapshot and confined-storage probes. On macOS the POSIX probes use the same
capability checks, and GitStore still requires descriptor procfs and native Git.

| Operation | Required capability | Refusal if unavailable | Code owner |
|---|---|---|---|
| Open a `GitStore` with the strict lane runner | POSIX with `O_NOFOLLOW`, `O_DIRECTORY`, descriptor-relative `open`, `stat` and `readlink`, and descriptor procfs at `/proc/self/fd`. Pinning the executable also requires the confined-storage probe below, including descriptor-relative `link`, `mkdir`, `rename` and `unlink`. Git must be a native ELF executable outside the bound roots. | `unsupported_effect_platform` when the runner's platform probe fails. `effect_command_refused` when confined storage is unavailable at executable pinning or the executable is a script wrapper or other non-ELF program. | [`gitsafe_run`](../aegis_core/gitsafe_run.py) and [`storage_confined.confined_file`](../aegis_core/storage_confined.py) |
| Snapshot the worktree with `snapshot_tree` | An active `GitStore` and Git 2.40 or newer for `check-attr --source`. The snapshot probe checks POSIX, `O_NOFOLLOW`, `O_DIRECTORY`, and descriptor-relative `open`, `stat` and `readlink`. | `unsupported_platform` if the snapshot descriptor probe fails. `conversion_unavailable` on older Git. | [`team_git`](../aegis_core/team_git.py) and [`team_git_snapshot.attribute_version`](../aegis_core/team_git_snapshot.py) |
| Plan a merge, pick or revert | `plan_merge`, `plan_pick` and `plan_revert` use supplied Git objects in an active `GitStore` with the strict runner above and require Git 2.38 or newer with the applicable `merge-tree` options, including `--merge-base` for pick and revert. The snapshot probe is skipped. | `merge_unavailable` when the required Git support is unavailable. | [`team_git`](../aegis_core/team_git.py) |
| Create a tested commit with `commit_tested` | The supplied tree and parent commits must resolve in the active `GitStore` with the strict runner above for `commit-tree`. The snapshot probe is skipped. | `invalid_object` for a missing or wrong-type object | [`team_git.commit_tested`](../aegis_core/team_git.py) |
| Access the team work queue | Confined-storage support requires `os.name == "posix"`, `O_NOFOLLOW` and `O_DIRECTORY`, and descriptor-relative `open`, `mkdir`, `link`, `rename`, `unlink` and `stat`. The probe omits `readlink`. | `unsupported_platform` | [`team_queue.descriptor_supported`](../aegis_core/team_queue.py) calls `storage.confined_descriptor_supported`, exported from [`storage_confined.descriptor_supported`](../aegis_core/storage_confined.py). |
| Access the proposal store | The confined-storage probe above. | `unsupported` | [`proposals.store`](../aegis_core/proposals/store.py) |
| Access the Git operations journal | `fcntl` and the confined-storage probe above. Admission and write transactions take an exclusive journal lock. The filesystem must support exclusive `flock` on a read-only descriptor for new `record_intent` calls and `record_result` with an inherited read-only receipt passed as `effect_fd`. `record_result` without a receipt reuses the caller's existing lock when available, or acquires an exclusive lock on a read-write descriptor. `reconcile` and independent retirement of old effect locks also acquire exclusive locks on read-write descriptors. Effect acquisition can probe a shared lock when busy, and `in_flight` uses a shared lock on a read-only descriptor. | `unsupported_platform` if the journal probe fails, confined storage refuses platform support, or a per-request `flock` returns `ENOLCK` or `EBADF`. `journal_busy` if the journal-wide lock times out. | [`team_gitops`](../aegis_core/team_gitops.py) |
| Export or pass a journal receipt to a Git effect holder | Linux subreaper support. The probe requires `sys.platform == "linux"`, `os.name == "posix"` and a successful `prctl(37)`. Effect startup separately requires the holder to enable subreaping with `prctl(36)` and applies the strict runner's executable checks to Git and the Python interpreter. | `effect_busy` if `IntentReceipt.inheritable_fds()` cannot export the receipt, including a failed platform probe. `unsupported_effect_platform` if the pass-through probe fails or the holder cannot enable subreaping. `effect_command_refused` if Git or Python violates the strict executable checks, which require each to resolve outside the bound roots. | [`gitops_fds`](../aegis_core/gitops_fds.py) and [`gitops_holder`](../aegis_core/gitops_holder.py) |
| Record a passing qualification | An active `GitStore` with the strict runner, the snapshot descriptor and journal probes, and Linux subreaper support. Intent creation and reconciliation need the journal locks above. The ref update requires the receipt holder's `prctl(36)` and executable checks. | `unsupported_platform` if the qualification probe fails. A transport refusal of `unsupported_effect_platform` or `effect_command_refused` after the intent is recorded surfaces as `git_failed` when reconciliation observes the unchanged ref. Journal failures during intent creation, receipt export or reconciliation map to `journal_failed`. A reconciliation refusal can follow a ref update. Restore journal access and observe the existing request before any new attempt. | [`team_qualify.record_pass`](../aegis_core/team_qualify.py) |
| Publish a tested lane commit through custody | An active `GitStore` with the strict runner, the snapshot and qualification platform probes, and the journal locks for intent creation and reconciliation. The ref update requires the receipt holder's `prctl(36)` and executable checks. Fresh publication calls `check_preconditions`, which checks the snapshot probe and then snapshots the worktree after checking the live lease, branch and HEAD. It requires Git 2.40 or newer. | `unsupported_platform` if the entry probe fails in `commit` or `check_preconditions`. `tree_mismatch` if the fresh snapshot refuses older Git. A transport refusal of `unsupported_effect_platform` or `effect_command_refused` after the intent is recorded surfaces as `git_failed` when reconciliation observes the unchanged ref. Journal platform and access failures during intent creation, receipt export or reconciliation map to `journal_failed`. A request ID already bound to different inputs is refused as `request_conflict`. A reconciliation refusal can follow a ref update. Restore journal access and observe the existing request before any new attempt. | [`team_custody.commit`](../aegis_core/team_custody.py) and [`team_custody_checks`](../aegis_core/team_custody_checks.py) |
| Admit, prepare, revalidate or recover merge-queue work | The snapshot and qualification platform probes, including Linux subreaper support, and the strict runner for GitStore operations. Candidate preparation uses the merge-plan capabilities above when the candidate needs a merge. The gate covers `enqueue`, `prepare`, `revalidate`, `check_issued`, `observe_landed`, `reconcile_not_landed`, `restore_target`, `reconcile_result`, and the internal operations for withdrawing issued or cleanup records. | `unsupported_platform` before inspecting queue state in each gated operation. Merge planning refusals such as `merge_unavailable` are surfaced by the queue as `git_failed`. | [`merge_queue`](../aegis_core/merge_queue.py) |
| Gate a publisher permit and use it through the library | The journal probe above. The library uses the journal locks above for intent creation, result recording and reconciliation. Publisher activation is still unwired. | `unsupported_platform` when the journal probe fails. The library preserves journal refusal codes when reading history, creating intents, recording results or reconciling. | [`team_publish.Publisher`](../aegis_core/team_publish.py) |

The `CORE_LAYERS` table in `tests/contract/test_import_boundary.py` puts `team_git`, `team_gitops`, `team_qualify`, `team_jobs_recipes` and the message codec in layer 0. It puts `team_mailbox`, `team_session_wake` and `model_select` in layer 1, and `team_queue`, `team_publish`, `proposals`, `rule_lint` and `merge_queue` in layer 2. It also puts `team_native_wire`, `team_workspace_store` and `team_workspace_display` in layer 0, and `team_mailbox_doctor`, `team_board`, `team_session_census`, `team_session_custody`, `team_session_stop` and `model_served` in layer 1.

### Where to read next

- [Agent teams](teams.md#on-this-branch) indexes lanes, the queue and the other surfaces.
- [Model selection](model-selection.md) is the admission and history contract. `aegis team model` and `aegis_team_model` call it and launch no host.
- [Team profiles](teams-profile.md) and the [supervisor profile](teams-supervisor.md) cover layered settings and pauses.
- [Runtime hierarchy guide](agent-hierarchies.md) and [team-run prerequisites](hierarchy-team.md#prerequisites) describe `tools/hierarchy_team.py`. That tool is outside the wheel.
- [Mailbox index](hierarchy-mailbox-index.md) covers the source-checkout index. The product mailbox is `aegis_core.team_mailbox`. Its `initialize` validates a manifest before `initialize_store`. `Mailbox` does not import `tools` or launch a process. `aegis team mail` provides send, read and doctor commands, and `aegis team board` provides board configuration, reads and inspection. See [mail and board](teams.md#mail-and-board) for platform requirements and refusal codes. A record read or digest in `aegis_core.team_mailbox_records` returns the received message ids a read receipt uses, and the library writes no receipt. A pinned refusal keeps `E_AUTH`, `E_REF` or `E_LIMIT`.
- Normal mailbox reads and indexing skip recognized staging entries in the directories they scan. The classifier accepts `.pending-` followed by 32 lowercase hex digits. It also recognizes `.pending-stub` in message folders, `.pending-grants` in the sibling `mailbox-records` directory and `.pending-root-id` at the mailbox root. When an inspection completes, the mailbox doctor reports `MD_PENDING` for each tracked path under the mailbox root with a name that starts with `.pending-`.
- `aegis_core.team_session_wake` handles bound wakes and `aegis_core.team_jobs_recipes` validates recipes and packets. The source-checkout hierarchy runner still uses the legacy wake and job paths.
- `aegis_core.team_native_wire.ProtocolClient` is the product-core Codex stdio client. It launches no process. The caller owns and reaps the process and transfers both pipe streams to the client, which closes them on `close()` or a terminal protocol error; cancel through `client.close()` and never close or reuse the streams directly. A completed frame authenticates neither a host principal nor a role. Non-POSIX hosts refuse `UNSUPPORTED_HOST` before any stream use.
- `aegis_core.team_native_session.HostSession` is a process-local live host session. `AppserverIO` is that binding's `ProtocolClient`. Neither launches a process.
- `aegis_core.team_source.SourceViews` serves pinned object pages from an owner-selected absolute root. Refusals are fixed envelopes. Grep output over 4194304 bytes is refused instead of a partial prefix.
- `aegis_core.team_lifecycle.reduce_event` checks policy, state, the envelope and the time string once at the public boundary, then reduces a copy of the state.
- `aegis_core.team_workspace_store` is the product-core workspace ledger, with display in `aegis_core.team_workspace_display`. It refuses `unsupported_platform` unless `team_mailbox_store.descriptor_supported` is true. Schema, sequence and time are checked before a transition is applied. A refusal does not apply it. The source-checkout controller remains `tools/hierarchy_workspace.py`.
- `aegis_core.team_session_stop` signals a process only after `team_session_census` and `team_session_custody` prove it belongs to the recorded session. Unproven argv boundaries do not signal. The source-checkout command remains `tools/hierarchy_launcher.py`.
- `aegis_core.model_served.observe_served` appends the host, model, level and family that served an existing decision, with a fallback reason when any of those four fields differ from the choice. It adds no CLI. The contract is [model selection](model-selection.md).
- The job runner calls `check_settlement_processes` on settlement and recovery before it treats a stopped job as finished, and refuses while the recorded process group still has members. The small-change dispatcher calls `check_stopped` before it accepts a completed retained job.
- [Delivery over MCP](how-it-works.md#delivery-over-mcp) names `aegis msg` and the message tools. The codec module defers Windows support. The command refuses unless directory descriptors support `open`, `mkdir`, `stat`, `link` and `unlink`, `stat` supports `follow_symlinks`, and `O_DIRECTORY`, `O_NOFOLLOW` and `geteuid` exist.
- [Proposals and rule lint](how-it-works.md#proposals-and-rule-lint): `aegis rule lint` reports and exits 0. Proposal merge can record source `mine` and does not install a rule.
- [Absorption](teams-absorption.md) describes the template boundary. `tools/hierarchy_templates/` is outside the wheel. `aegis_core/team_templates/` packages `job-recipes.json` and `role-registry.json`, and `team_roles.registry` reads the role registry.

Fitness is derived from the ledger; `aegis sync` computes suggestions. Applying a
suggestion is an explicit action that changes files for review. Host hooks and
team events do not silently promote rules.

## Failure and extension boundaries

Rule-load failures stop scans and checks rather than serving a partial rule set.
An enabled AST check cannot treat an unparseable governed file as a pass. A host
hook has a different contract: errors and deadlines fail open so the host can
continue. Missing evidence cannot be promoted into confirmed evidence. These
boundaries are described in [SECURITY](../SECURITY.md),
[hosts and hooks](hosts-and-hooks.md), and [trust tiers](trust-tiers.md).

Python, TypeScript/JavaScript and Rust parse in process; native JS/TS and Rust
need no language runtime or repository dependencies. Opted-in Go uses a packaged
standard-library parser built into the user cache, then one bounded NDJSON batch
process per check. A check-local AST session reuses parsed facts across rules,
security head/base comparisons and structural checks. Custom user-scope drivers
retain the per-file protocol; repository settings cannot select a command.

Missing driver coverage produces advisory `unverified no_driver` evidence, blocking
under ordinary `--strict`. Oversized native sources produce advisory `too_large`;
a configured driver or active parser failure fails closed. Parsing is syntactic,
without type resolution or Rust macro expansion. [Language checks](languages.md)
describes extraction coverage, matching and evasion bounds.

Test execution consumes pure user-command plans, prepares installed runtimes outside
the repository, and retains namespaced outcomes with completeness and mapping errors.
Recorded checks and commit replay share the same snapshot recipe. A global command
has precedence; automatic language runs require complete evidence from every selected
language. Coverage keeps per-language availability and remains report-only. User
commands execute repository code: offline defaults are not a network sandbox.

The SDK offers a Python integration surface, while host adapters supply workspace
and tool-call context. Shared operations keep the same core semantics and authority;
CLI-only setup, checks and release actions do not require duplicate MCP tools.
Neither adapter gives model output authority over deterministic checks.
