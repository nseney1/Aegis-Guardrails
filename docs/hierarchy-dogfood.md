# Dogfooding the agent hierarchy

This is how root runs a trial of the [agent hierarchy](agent-hierarchies.md) with real
sessions. Every tool here has tests, but those tests use a fake host, so **no real Claude or
Codex session has run this flow yet**. The first-run checks below are what would show that it
works. Configuration and acknowledgments alone never count as proof.

## Run it beside the live prototype

A trial uses new folders and leaves the running prototype alone. Don't move running work into
it.

- **Start with one initiative that has nothing in flight.** Aegis 4.7 fits, because its
  dispatches are held.
- **Leave Stormheir and Aegis 4.5 where they are for now.** Move each one only at a natural
  stopping point, after the trial has run clean.
- **Expect new mailbox roots.** The live manifests have no `<hierarchy>/root` endpoint, so job
  requests cannot be routed in them. Old roots stay readable.
- **Count all work against the limits.** The job runner counts outside heavy processes using
  root's census rule. Writers in the live prototype are not in this ledger, so root still has
  to keep the workspace total at three.

| | Beside the live prototype | Replacing it in place |
| --- | --- | --- |
| Latency | Root runs two loops for a while | One loop, once it works |
| Complexity | Two sets of folders to keep apart | Rebinding running sessions, with no way back mid-work |
| Cost | One extra initiative's sessions | None extra, but a failure stops all three initiatives |

## Prerequisites

- Linux, because the job runner and its census read `/proc`.
- Git 2.31 or newer, Python 3.9 or newer, and `bwrap` for sandboxed recipes.
- `claude` and `codex` on `PATH`, signed in by the owner.
- No environment variables are required. Set `CLAUDE_CONFIG_DIR` or `CODEX_HOME` only if a host
  keeps its transcripts somewhere unusual, so the meter can find them.

## Set up once

Run every tool from a clean clone at the exact commit under trial, so all roles run the same
code. Adapters run from it, so don't edit it during the trial.

```sh
export TRIAL=/absolute/path/to/trial-folder
export TOOLS=$TRIAL/tools-clone
git clone --no-hardlinks /absolute/path/to/aegis-repository "$TOOLS"
git -C "$TOOLS" checkout --detach <commit-under-trial>
tool() { python3 -I -B "$TOOLS/tools/hierarchy_$1.py" "${@:2}"; }

printf '{"writer_limit": 3, "heavy_limit": 3}\n' > "$TRIAL/limits.json"
tool workspace --store "$TRIAL/store" init --request "$TRIAL/limits.json"
tool board --board "$TRIAL/board" init

cp "$TOOLS/tools/hierarchy_templates/job-recipes.json" "$TRIAL/recipes.json"
# Set python, path, hide and identity in recipes.json. Nothing runs until the placeholders are gone.
tool jobs --store "$TRIAL/store" --recipes "$TRIAL/recipes.json" check-recipes
```

`hide` lists folders a job must not see, such as your home folder, which holds credentials.
If the interpreter, a virtual environment or a Rust toolchain lives inside one, add that folder
to `ro_binds`, and set `RUSTUP_HOME` and `RUSTUP_TOOLCHAIN` in `env` for Rust tests.
The template has no push recipe on purpose. Pushing stays with root, and merges and
signatures stay with the owner.

## Add an initiative

`$TRIAL/init.json`:

```json
{
  "store": "/absolute/path/to/trial-folder/store",
  "base": "/absolute/path/to/trial-folder/initiatives/aegis-47",
  "source": "/absolute/path/to/trial-folder/tools-clone",
  "board": "/absolute/path/to/trial-folder/board",
  "python": "/usr/bin/python3",
  "lanes": {"build-1": "implementer", "review-1": "reviewer"},
  "initiative": {"id": "aegis-47", "project": "aegis", "repository": "aegis", "priority": 5,
                 "target_branch": "feature/manager-workspace-prototype",
                 "checkouts": ["/absolute/path/to/a/lane/worktree"], "lanes": ["build-1"],
                 "source": "owner"}
}
```

```sh
tool provision init --request "$TRIAL/init.json"
```

Then add each role with its own request, for example
`{"base": ".../initiatives/aegis-47", "endpoint": "aegis-47/orchestrator", "host": "claude-code", "cwd": "...", "model": "...", "effort": "..."}`:

```sh
tool provision add-role --request "$TRIAL/orchestrator.json" > "$TRIAL/orchestrator.out.json"
```

The answer holds the session ID, the connection file, the wake profile and, for Claude,
`start_argv`.

| Role | Host to start with | Why |
| --- | --- | --- |
| Front door, Orchestrator | Claude or Codex | Mailbox and file reading only |
| Builder, Integrator | Codex | Its OS sandbox lets it run tests in its worktree. A generated Claude writer can edit but has no shell, so every test becomes a job |
| Reviewer | Claude, with `cwd` set to a review copy | It has native file tools. A Codex reviewer needs `"reader_shell": true`, and no real host has run that profile yet |
| Root | Any | Bound with `"session"` and no adapter. Root uses these tools directly |

- **Start a Claude role:** run `start_argv` from the role's `cwd`, with the role's template on
  stdin (`tools/hierarchy_templates/roles/<role>.md`).
- **Start a Codex role:** Codex assigns its own session ID, so a session has to exist before it
  can be bound. Run `tool provision codex-start --request <file>`, run the `start_argv` it
  returns, read the session ID from the first JSON event, then call `add-role` with that
  `"session"`.
- **Set up the board:** `tool board --board "$TRIAL/board" add-channel --request <file>` with
  `{"channel", "orchestrator", "source"}`, then `grant` with
  `{"channel", "endpoint", "access", "source"}`, where `access` is `read` or `post`. Grants
  apply to endpoints, so they survive a rotation.

## First-run checks

Run these once on real sessions before trusting anything else, and keep the evidence. Stop at
the first one that fails.

1. Each session's reported tool catalog matches what its profile asked for, and nothing else.
2. A published message reaches a stopped session: after `sweep`, `delivery` shows it as `read`.
3. A job request produces a receipt whose evidence hashes match the files.
4. A sandboxed job cannot write to its checkout, reach the network or read a `hide` folder.
5. A reviewer reads a review copy, and `verify` still passes afterward.
6. A stopped role is replaced on the other host, keeps its assignment and acknowledges the
   checkpoint.
7. A fourth writer across two initiatives is refused.
8. A forged approval on the board leaves bindings, dispatches and leases byte-identical.

## The root loop

Nothing runs on a timer. Root runs this at task boundaries:

```sh
tool jobs --store "$TRIAL/store" --recipes "$TRIAL/recipes.json" run-open
tool sweep --store "$TRIAL/store" --rounds 5
tool workspace --store "$TRIAL/store" report --format text
```

Exit code 0 means nothing needs root, 3 means something does, and 2 means the tool refused and
changed nothing. A failed job is still exit 0, because the receipt reports it.

| You see | It means | Do this |
| --- | --- | --- |
| `waiting` with `capacity_full` | All heavy slots are taken, counting outside work | Run again later |
| `running` | Another runner has it | Nothing |
| `abandoned` | The runner stopped, and the slot stays held | Stop `process_group` if `process_alive`, then run `tool jobs --store ... resolve --job <initiative>/<message-id> --reason "..."` |
| `settle_pending` | A busy mailbox or store delayed the receipt or the release | Run `run-open` again |
| `granted_elsewhere` | A slot went to work that is not a job | Start that work |
| `rotate_needed` | The session passed 60 active minutes, so it was not woken | Rotate it |
| `root_time` with `rotate_now` | Root passed its own 90 minutes | Rotate root |
| `woken_unread` or `timed_out` | A turn ran and the mail stayed unread | Read the turn's log. It gets no second turn for that mail in this sweep |
| `no_profile` | The current binding has no wake profile | Run `add-role` for that session |
| `meter_error` | Active time could not be measured, so it was not woken | Find out why |
| `root_queue` | Open jobs and unread mail for root | `run-open`, and `hierarchy_mailbox.py inbox --endpoint <hierarchy>/root --delivery-dir <dir> --mark-read` |

A runner works through jobs one at a time, so start a second `run-open` to use more than one
heavy slot. A sweep also runs turns one at a time, so use `--initiative` to sweep initiatives
separately when a long turn would hold the others up.

## How the roles use it

**Orchestrator, to request a job.** It has no file writer, so the packet is a message:

```json
{"schema": "aegis.hierarchy-job-packet/v1", "recipe": "targeted-tests",
 "checkout": "/absolute/worktree", "commit": "<40 hex>", "tree": "<40 hex>",
 "paths": ["tests/integration/test_x.py::test_y"]}
```

Publish that JSON as the body of an `info` message to `<hierarchy>/root`. Then publish a
`job_request` whose `brief` is the `path` and `sha256` the first publish returned. Add
`dirty_state_sha256` to run on uncommitted changes. Without it, the checkout must be clean.
Nothing in a message body is ever run, and only root's recipe file decides commands.

**Commit jobs.** `commit-exact` also needs `expected_tree` and `message`, and `paths` lists the
exact files. Compute the tree with a throwaway index:

```sh
GIT_INDEX_FILE=/tmp/lane-index git read-tree HEAD
GIT_INDEX_FILE=/tmp/lane-index git add -- <exact paths>
GIT_INDEX_FILE=/tmp/lane-index git write-tree
```

The commit is unsigned and runs no repository hooks, and a wrong tree changes nothing. The
lease check uses Aegis's own overlap rule, where a top-level file such as `CHANGELOG.md` overlaps
every other lease because a name with no folder also matches basenames. Commit those files when
no other lane holds a lease, or expect a refusal.

**Reviewer.** Root prepares the copy and points the reviewer at it:

```sh
tool review prepare --repository <repo> --base <commit> --candidate <commit> --out <new folder> --expect-candidate-tree <tree>
tool review verify --out <folder> --expect-manifest <manifest_sha256>
tool review remove --out <folder>
```

The verdict should cite the manifest hash. Run `verify` before relying on the verdict.

**Board.** Post information several roles may want, and keep control in the mailbox. A post
wakes nobody. Open blockers appear on every page, and only the author or the channel's
orchestrator can close one. Text that looks like a key is refused, but pattern matching cannot
catch every secret, so `tool board --board ... tombstone --request <file>` lets the owner remove
a post's text and keep its record.

## Rotation

Root rotates after 90 active minutes and every other session after 60. Active time is summed from
the host's transcript, so an idle session uses none of it.

```sh
tool meter --host codex-cli --session <id> --role root    # exit 3 means rotate now
```

1. Stop the outgoing session and check that it stopped.
2. Run `tool handoff --spec <file>`, starting from `hierarchy_templates/handoff-spec.json`. One
   spec covers every endpoint of that session, and rerunning it is safe.
3. Run `add-role` with the new session, which writes the new connection and wake profile.
4. Start the successor. It inspects the checkpoint and acknowledges it before continuing.

## Measure the trial

Compare with the same counting method against this baseline from 489 mailbox messages:

| Measure | Baseline |
| --- | --- |
| Messages per dispatch | 61.1 |
| Orchestrator to reviewer | 168 messages, 1.06 MB |
| Front door and orchestrator | 178 messages |
| `received` acks | 22 of 30 acks |

Keep a change only if these numbers improve with no more missed updates or lost evidence.

## Stop the trial

Stop the sessions and keep the trial folder as evidence. Nothing outside it was changed, so the
live prototype needs no undoing.

## Known limits

- All of this runs under one OS user, so it prevents accidents and records claims. It is not a
  security boundary, and a same-user process can edit these files.
- Git inspection of a checkout runs outside the sandbox, so a process that edits that checkout's
  `.git/config` could run code there.
- A process that starts its own session escapes the stop at the end of a job step.
- The census counts a heavy process that started after its last check against the next job, not
  this one, so root's limit can briefly be exceeded when outside work starts at the same moment.
- A store, a board and a mailbox each stop accepting records at 10,000. Start a new one before
  that.
- Assistants stay off until the owner lifts the no-subagent rule for that trial.
