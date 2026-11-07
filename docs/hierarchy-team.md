# Team runs with `hierarchy_team.py`

`tools/hierarchy_team.py` is the owner's one command for a team run. It replaces the real run's shell guide (steps
1-18), its `m1.py` helper and `role_turn.py` with one config file and nine subcommands. It drives the existing tools
(launcher, provision, lifecycle, workspace, jobs, loop, router, review, `aegis team`) and retains their admission
checks: when a tool refuses, you see that tool's message.

The same flow runs on fixtures in
[`tests/integration/test_hierarchy_team.py`](../tests/integration/test_hierarchy_team.py) and in the M1 rehearsal
[`tests/integration/test_hierarchy_m1_loop.py`](../tests/integration/test_hierarchy_m1_loop.py), with fake Codex
sessions. The tests show that the tools carry the run together, not that real sessions behave this way.

```mermaid
sequenceDiagram
    autonumber
    actor Owner
    participant T as hierarchy_team.py
    participant ROOT as ROOT session
    participant L as launcher
    participant Loop as hierarchy_loop.py
    Owner->>T: init (recipes, store, journal, worktree, slot, lease, preflight)
    Owner->>T: login (codex login in the run's CODEX_HOME)
    Owner->>ROOT: start ROOT (codex exec), note its session id
    Owner->>T: root --session <id>
    Owner->>T: up
    T->>L: start router, orchestrator, decider, reviewers, implementers
    T->>T: check each rollout: sub-agent tools, model, effort
    T->>Loop: start detached, check /proc/<pid>/environ
    Owner->>T: request <id> --file <draft>
    Owner->>T: approve <id> --reason TEXT
    T->>ROOT: one turn: team_pending, then root_decide
    T->>T: check the journal for that decision
    Owner->>T: status --text
    Owner->>T: down [--purge-codex-home]
```

## Prerequisites

- Linux, Python 3.9 or later, and `git`, `bwrap` and `codex` on PATH. A kept recipe that runs `cargo` needs it on
  the recipes' `path`, and one that runs `cargo nextest` needs `cargo-nextest` there too.
- At least `min_free_gb` free (default 8 GB) where the run folder lives. A Rust job uses about 0.8 GB while it runs.
- A fresh clone of the project with HEAD at the base commit and nothing uncommitted. Never point `project` at your
  live checkout; list that one under `live_checkouts` so `init` refuses it.
- A clean Aegis checkout for `source` (default: the checkout this tool is in). Every adapter runs its committed code.
- A ChatGPT login for Codex. `login` runs `codex login` in the run's own CODEX_HOME, never in `~/.codex`.

## Environment variables

None are required: the tool sets `CODEX_HOME` to the run's `codex_home` for every process it starts.
- `CODEX_HOME`: if your shell exports it, it must be the run's `codex_home`; otherwise every subcommand refuses.
- `OPENAI_API_KEY`, `CODEX_API_KEY`: unset them. `login`, `up`, `approve` and `turn` refuse while either is set,
  because codex could bill the turns to the key instead of the login.

## The config

Copy [`tools/hierarchy_templates/team-run.json`](../tools/hierarchy_templates/team-run.json) and fill every
placeholder. Every subcommand refuses a config that still holds `REPLACE` or a `<...>` marker, and any key the
schema does not name.

| Key | Meaning |
|---|---|
| `schema` | `aegis.team-run/v1` |
| `run` | Absolute path of the run folder. It may hold the config itself, nothing else `init` makes. `<base>` below is `<run>/initiatives/<initiative id>`, not the `base` commit. |
| `codex_home` | Optional. Default `<run>/codex-home`. A new dedicated folder; cannot overlap the project, source, managed run data or `~/.codex`, or contain the run or home folder. |
| `source` | Optional. The Aegis checkout the adapters run from. Default: this tool's checkout. |
| `project` | The project clone. |
| `live_checkouts` | Optional. Paths `project` must not be or be inside. |
| `base`, `base_tree` | The base commit (40 hex). `init` derives its tree and checks it against `base_tree` when given. |
| `branch` | The implementer lanes' branch. A lane may set its own `branch`; two lanes may not share one. |
| `initiative` | `{id, project, repository, priority, target_branch}`, as provision takes it. |
| `roles` | Extra roles: `router`, `decider`, or both. |
| `lanes` | `[{id, kind}]`, kind `implementer` or `reviewer`. An implementer also takes `paths` (its lease globs), and optional `worktree` (default `<run>/worktrees/<id>`), `branch` and `tmpdir` (relative to the worktree, made by `init`, best under an ignored folder such as `target/`). |
| `recipes` | `{keep, python, commit_identity: {name, email}, template?}`. `init` fills the template's home folder, sets `python` and the identity, and keeps only the named recipes. |
| `limits` | The workspace limits: `{writer_limit, heavy_limit, heavy_tests_limit?}`. |
| `preflight` | `{recipes, expect, paths?}`. Each listed recipe runs on the base. `expect.<recipe>` takes `state` (default `completed`), `failed` and `min_passed`. `paths.<recipe>` is for a recipe that takes `$paths`. |
| `min_free_gb` | Optional. Default 8. |
| `loop` | Optional. `{interval}` in seconds, 5 to 600. Default 30. |
| `lease_ttl_seconds` | Optional. 60 to 86400. Default 21600 (6 h). |
| `team` | `{model, reasoning, reasoning_by_kind}`, written as-is to `<base>/team.json` by `up`. Kinds: `orchestrator`, `decider`, `implementer`, `reviewer`, `integrator`. |

The template's `team` follows the owner's cost choice 6: the same model (`gpt-6.1-sol`) for every role, `medium`
for the Orchestrator and the Decider, `high` for the Implementer and the Reviewer. The Router always runs at
`medium` with the `ultrafast` tier from the role registry; `team.json` cannot change that, and `up` says so.

## Quick start

```sh
T="python3 -I -B $HOME/aegis/tools/hierarchy_team.py --config $RUN/team-run.json"
$T init
$T login                                   # finish the sign-in in the browser
# ROOT is your own session: start it read-only, with no shell and no tools, as approve later resumes it.
OFF=(); for f in apps plugins remote_plugin multi_agent multi_agent_v2 memories computer_use browser_use \
  browser_use_external browser_use_full_cdp_access goals shell_tool unified_exec; do OFF+=(--disable "$f"); done
CODEX_HOME=$RUN/codex-home codex "${OFF[@]}" exec --ignore-user-config --sandbox read-only \
  -c 'approval_policy="never"' -c 'mcp_servers={}' --json -C "$PROJECT" \
  "You are ROOT for this run. You only approve or deny canonical requests with root_decide when the owner asks. Reply READY."
$T root --session <thread_id from the thread.started line above>
$T up
$T request feature-1 --file $RUN/feature-1.json # a team_request draft, or the request's fields
$T approve feature-1 --reason "agreed in chat"
$T status --text
$T down                                    # add --purge-codex-home once you no longer need the login
```

Each subcommand prints one JSON object on its last line (`status --text` prints text). Exit codes: 0 done, 2 refused
(this command changed nothing), 3 failed (a step ran and did not succeed). `--config` and `--file` take absolute paths
without `..`.

## What each subcommand does and refuses

Every subcommand checks path safety. Commands that start work also check disk space and tools, refusing with exit 2:
- `CODEX_HOME <path> is inside ~/.codex (<path>); a team run uses its own folder`
- `CODEX_HOME in this shell is <a>, not this run's codex_home <b>; unset it or export the run's`
- `only <n> GB free at <folder>; this run needs min_free_gb <n>`
- `required tool not found on PATH: <git|bwrap|codex>`
- `required tool not found on the recipes' path: <cargo|cargo-nextest> (kept recipe <name> runs <cargo|cargo nextest>)`

`login`, `root`, `up`, `request`, `approve` and `turn` then refuse until `init` has completed: `init has not completed;
run init first`. `status` and `down` work at any point.
They remain available below the disk-space threshold and without the tools required to start a run.
The run records its custody configuration at initialization. Changing its project, lanes or other custody fields
requires restoring that configuration before another mutation. Once teardown starts, only inspection and repeated
teardown are allowed; another run needs a new folder.

Provisioning records the runtime source commit and tree. Profile generation, role start/resume and provisioned
MCP startup check that identity and the actual runtime and template bytes. Hidden index flags, staged changes and
untracked or ignored importable code refuse the check. Each new base retains its own verifier; generated MCP
connections enter through it before loading source modules or local bytecode caches.

A source-drift refusal reports the expected and observed identity. From a separate clean control checkout,
inspect the run and stop its owned actors, then use the existing [handoff flow](hierarchy-dogfood.md) to provision
a new base from the reviewed checkout.
Keep the active base and its recorded pin intact. A base created before the verifier existed also needs that
handoff; regenerating profiles does not silently adopt a different tool version. Status, stopping and safe cleanup
remain available from that trusted control checkout after source drift. These checks establish reproducibility,
not native host authentication; they cannot make an altered entry script itself safe to execute.

The role registry sets the maximum file tools for each role. A `file_tools` override can narrow that set;
it cannot grant additional tools. Reviewer, Router and Decider connections also refuse direct board access.
Provisioning and the MCP adapter enforce these limits independently.

### `init [--continue]`

Every setup step that spends no model turn, in order: `codex-home` (made with mode 0700 and an
`.aegis-team-run` mark), `recipes` (built and checked with `check-recipes`), `workspace`, `provision`, `front-door`
(a stand-in binding that never runs), `policy` (with an owner-authority file), `lifecycle` (init and a checkpoint),
`slots` (request and grant per implementer), `worktrees`, `leases` (`aegis team claim`), `checkouts`, and
`preflight` (the configured recipes on the base, in a separate store, against `expect`).

A fresh init refuses a run folder that already holds what init makes, a `codex_home` that already holds files, the
live checkout, a project that is not the root of a git checkout, a project whose HEAD is not `base` or that has
uncommitted files, a `base_tree` that does not match, and a lane branch that already exists.
A failed step exits 3 and records itself; `init` then refuses until you fix the cause and run `init --continue`,
which resumes at the first step, and within a step at the first command, that did not finish. A completed init
refuses to run again: a new run needs a new run folder.

### `login`

Runs `codex login` with the run's CODEX_HOME in your terminal, then checks the folder with the native probe's
real-login rules: only `auth.json`, `auth.lock`, `log/`, `tmp/`, `sessions/` and the run's mark; `auth.json`
private, single-link and yours. Anything else refuses, for example `CODEX_HOME holds entries a codex login does
not create: config.toml`.

### `root --session <id>`

Binds your ROOT session as `<team>/root` with its decision connection (journal and actor `root-1`, plus the loop
folder and the evidence folder for its read tools). It lists the tools the connection offers (`root_decide`,
`team_status`, `team_pending`, `team_request`) and records the session and connection in `team-state.json`.
Another session for a bound ROOT refuses: `endpoint is bound to another session; hand it off first`.

### `up [--accept-agent-tools] [--no-loop]`

Writes `<base>/team.json` (`<run>/initiatives/<initiative id>/team.json`) from the config's `team`, then starts the
roles with the launcher: Router, Orchestrator, Decider, reviewer lanes, implementer lanes. Provision builds each
role's model and effort from that file, so `up` refuses a role that would start without both. It also refuses to
change a `team.json` that roles already started under. A role that is already bound is not started again, only
checked. After each start:
- the launcher record must be `bound`, or `up` stops with `<endpoint> did not start: <the launcher's error> (launcher
  exit <n>, state <state>)`;
- the role's rollout must not offer Codex sub-agent tools, or the role is stopped and `up` refuses, unless you
  pass `--accept-agent-tools`, which is recorded in `evidence/up-agent-tools-accepted.json`;
- a missing tool catalog or an unfamiliar tool name remains unavailable and stops the role, including with
  `--accept-agent-tools`; qualifying a new tool catalog requires review;
- the rollout's served model and effort must be what `team.json` (or, for the Router's effort, the role registry)
  asks for, or the role is stopped and `up` refuses, for example `<team>/router was served model X, but team.json
  asks for Y`. The served tier is reported, not checked.

Then the loop starts detached (its own session, output to `<run>/loop.log`, pid in `<run>/loop.pid`), and `up`
checks `/proc/<pid>/environ`: CODEX_HOME must be the run's, and PATH must hold the recipes' cargo folder when a kept
recipe runs cargo. `up` refuses while a loop for this run is running. `--no-loop` starts the roles only, for a
rehearsal that runs its own passes with `hierarchy_loop.py once`.

### `request <id> --file <draft>`

Publishes a canonical request as the journal's coordinator. The file is either the draft ROOT's `team_request` tool
returns (its raw text, sha256 and publish event are checked, and must still be what the journal would draft) or the
request's fields, which are made canonical the same way. Its `id` must be `<id>`. It writes `<run>/requests/<id>.json`
and `<run>/events/publish-<id>.json`, and records the event with `hierarchy_lifecycle.py record --evidence-only`.
Prints the id and sha256; you never paste a hash.

### `approve <id> [--deny] --reason TEXT`

Refuses unless ROOT is bound (`root --session`) and the request is pending a ROOT decision (`team_pending` lists
it); `--deny` also accepts an approved request for revocation, using its hash from `team_status`.
Otherwise it reports `request <id> is not pending a ROOT decision (journal state: <state>)`. Then runs one ROOT turn,
`codex exec ... resume <root session>`, with Codex's extra features and its shell disabled, a read-only sandbox,
`approval_policy="never"` and ROOT's connection. Its prompt names only the request id, the decision and the reason
(`reason="owner: <reason>"`), and tells ROOT to call `team_pending`, then `root_decide` with that row's arguments.
The turn's output is appended to `evidence/root-turns.jsonl`. Afterwards the journal must hold that decision on the
request's exact sha256. Any unexpected decision during the turn fails the command and retains all journal effects
for inspection. Read-tool text is untrusted data, never permission to decide another request.
Otherwise `approve` exits 3 with ROOT's last message. The reason is 1 to 512 characters, with
no double quotes or line breaks.

### `turn <endpoint> <prompt>`

One trusted owner turn in a role's own session, with its current wake-profile argv. This is how the owner answers a
`silent_role` hold: a turn that tells the role what it owes. It refuses for ROOT (`ROOT's turns go through
approve`), for an endpoint that is not bound or has no wake profile for its current generation, while a wake runs for
the role, and while it has unread mail (the loop's wake reads that mail, so an owner turn would race it). It does not
stop the loop. The output is appended to `evidence/role-turns-<endpoint>.jsonl`, with each `/` in the endpoint written
as `%2F`.
The command claims the wake marker under the mailbox lock and rechecks the binding before launching. It retains
the marker after an uncertain interruption so another turn cannot silently overlap it.

### `status [--text]`

ROOT's team view (`aegis.team-status/v1`: holds by who must act, pending decisions, requests, delegated
decisions), the loop's lock-based liveness, the loop pid, and each role's launcher record. `--text` lists the holds
under root, owner and router, and each pending ROOT decision with the `approve` command for it. The `silent_role`
and `stalled_dispatch` holds show under root; [the hierarchy guide](agent-hierarchies.md#run-the-loop) says what
raises and clears them.

### `down [--purge-codex-home] [--loop-wait SECONDS]`

1. Sends SIGTERM to this run's loop (it checks the pid's command line first) and waits up to `--loop-wait`
   seconds (default 15, at least 1). If it is still running, `down` exits 3 and changes nothing more; run it again
   later.
2. Stops every Codex role the launcher started. It never stops ROOT, the owner's session.
3. Collects the evidence once: lifecycle checkpoint, launcher and router status, launches, delivery, loop state,
   requests, events, the mailbox, store events, jobs, Codex sessions, policy, recipes, the loop log and pid, and
   `team-commands.jsonl`; the turn ledger (`evidence/turn-ledger.json`: each role's turns, tokens and publishes, with
   retries, plus the owner's commands); then `SHA256SUMS`.
4. Holds resources when an initialization operation has an unresolved outcome or a job has not finished. Otherwise
   cleans finished jobs, checks each lease's claim and owner against the recorded claim, releases it with the oid it reads now, releases each writer slot with that release
   as evidence, removes only this run's worktrees (`git worktree remove`, never prune or repair; the branches stay),
   and removes review copies that carry a review manifest.
5. Writes `SHA256SUMS` again, so it also covers the release records.
6. With `--purge-codex-home`, deletes `codex_home` only when its ownership record matches this run and every session file in it
   has an identical copy in `evidence/codex-sessions` that `SHA256SUMS` lists; otherwise it refuses with `codex_home
   was kept: <why>` and keeps it.

A second `down` reports the loop, the evidence, the leases, the slots, the worktrees and the purge as already done.
It sends each role a launcher `stop` again, and runs the job and review-copy cleanup again.

Journal reads use the existing writer lock to avoid observing a half-published event. A forcibly killed reader
can leave that lock behind. Treat this as a hold requiring inspection of the recorded process and journal; never
delete a lock automatically based on age. Changing the journal lock protocol is outside item 9.

Initialization records an intent before each external setup operation. If a reply is lost, `init --continue` holds
at that operation until its durable records have been inspected; it does not repeat the command. Teardown also
keeps resources while such an outcome is unresolved.

## Where evidence lands

Everything is under `<run>/evidence`; `evidence/index.json` holds the sha256 of each file a subcommand saved (not
the folders `down` copies), and `SHA256SUMS` (written by `down`) covers every file.

| File | Written by |
|---|---|
| `recipes-check.json`, `workspace-init.json`, `provision-init.json`, `front-door.json`, `owner-authority.txt`, `policy.json`, `lifecycle-init.json`, `checkpoint-before.json` | `init` |
| `slot-request-<lane>.json`, `slot-grant-<lane>.json`, `worktree-<lane>.json`, `lease-claim-<lane>.json`, `checkouts.json` | `init` |
| `preflight-run-open.json`, `preflight-results.json`, `preflight-clean.json` | `init` |
| `login.json` | `login` |
| `root-binding.json` | `root` |
| `team.json`, `up-roles.json`, `launcher-status-start.json`, `loop-environ.txt`, `up-agent-tools-accepted.json` | `up` |
| `request-<id>.json` | `request` |
| `root-turns.jsonl` | `approve` |
| `role-turns-<endpoint, / as %2F>.jsonl` | `turn` |
| `checkpoint-after.json`, `launcher-status-end.json`, `router-end.json`, `turn-ledger.json`, the copied folders, `lease-release-<lane>.json` (or `lease-absent-<lane>.json`), `slot-release-<lane>.json`, `SHA256SUMS` | `down` |

The run's own records stay beside it: `<run>/team-state.json` (which steps are done, ROOT's session and
connection), `<run>/team-commands.jsonl` (each command and its exit code), `<run>/inputs/` (every request file a
tool read), `<run>/requests/` and `<run>/events/`.

## Not in the team command

The failure inductions stay in the tests and the runbook. Pushing the branch, opening the PR, CI and the merge stay
with the owner.
