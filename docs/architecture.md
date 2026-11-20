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

`aegis_core.merge_queue.MergeQueue` checks every required qualification leg against the exact landing tree. `MergeQueue.revalidate` rechecks the candidate and uses its own queue checkpoint before calling `team_git.cas_fast_forward` to create the candidate pin. It issues a receipt for a separate publisher and does not write a team_gitops journal. Automatic landing remains separate work.

`snapshot_tree` calls `descriptor_support` and refuses `unsupported_platform` unless `os.name` is `posix`, `O_NOFOLLOW` and `O_DIRECTORY` exist, and directory descriptors support `open`, `stat` and `readlink`. `plan_merge`, `plan_pick`, `plan_revert` and `commit_tested` do not use that check. The work queue refuses `unsupported_platform` unless `storage.confined_descriptor_supported` is true: `os.name` is `posix`, `O_NOFOLLOW` and `O_DIRECTORY` exist, and directory descriptors support `open`, `mkdir`, `link`, `rename`, `unlink` and `stat`. That function does not use `readlink`. The proposal store refuses `unsupported` on that same function. Both probes are false when `os.name` is not `posix`, so Windows fails them. Neither function tests for macOS.

Qualification writes call `team_qualify.descriptor_supported` and otherwise refuse `unsupported_platform`. That probe requires `team_git.descriptor_support`, `team_gitops.descriptor_supported` (`fcntl` is available and `storage.confined_descriptor_supported` is true), and Linux subreaper support from `gitops_fds.descriptor_supported` (`sys.platform` is `linux`, `os.name` is `posix`, and `prctl(37)` returns 0). The merge queue checks both the snapshot and qualification probes when preparing or revalidating a candidate. `MergeQueue.prepare` refuses `unsupported_platform` if either fails.

The `CORE_LAYERS` table in `tests/contract/test_import_boundary.py` puts `team_git`, `team_gitops`, `team_qualify`, `team_jobs_recipes` and the message codec in layer 0. It puts `team_mailbox`, `team_session_wake` and `model_select` in layer 1, and `team_queue`, `team_publish`, `proposals`, `rule_lint` and `merge_queue` in layer 2.

### Where to read next

- [Agent teams](teams.md#on-this-branch) indexes lanes, the queue and the other surfaces.
- [Model selection](model-selection.md) is the admission and history contract. `aegis team model` and `aegis_team_model` call it and launch no host.
- [Team profiles](teams-profile.md) and the [supervisor profile](teams-supervisor.md) cover layered settings and pauses.
- [Runtime hierarchy guide](agent-hierarchies.md) and [team-run prerequisites](hierarchy-team.md#prerequisites) describe `tools/hierarchy_team.py`. That tool is outside the wheel.
- [Mailbox index](hierarchy-mailbox-index.md) covers the source-checkout index. The product mailbox is `aegis_core.team_mailbox`. Its `initialize` validates a manifest before `initialize_store`. `Mailbox` does not import `tools` or launch a process. `aegis team mail` provides send, read and doctor commands, and `aegis team board` provides board configuration, reads and inspection. See [mail and board](teams.md#mail-and-board) for platform requirements and refusal codes.
- Normal mailbox reads and indexing skip recognized staging entries in the directories they scan. The classifier accepts `.pending-` followed by 32 lowercase hex digits. It also recognizes `.pending-stub` in message folders, `.pending-grants` in the sibling `mailbox-records` directory and `.pending-root-id` at the mailbox root. When an inspection completes, the mailbox doctor reports `MD_PENDING` for each tracked path under the mailbox root with a name that starts with `.pending-`.
- `aegis_core.team_session_wake` handles bound wakes and `aegis_core.team_jobs_recipes` validates recipes and packets. The source-checkout hierarchy runner still uses the legacy wake and job paths.
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
