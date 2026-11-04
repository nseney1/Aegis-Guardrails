# Dogfooding the agent hierarchy

**2026-11-03 owner-facing ROOT amendment:** the operational ROOT procedures below
are historical. Current ROOT only reviews evidence, talks with the owner and
approves/denies canonical requests. It cannot run these commands or delegate them
through a helper. A distinct qualified operator and independently accepted native
capability/decision/dispatch interfaces are required before cutover. See the
[maintenance design](hierarchy-maintenance-design.md) and
[shutdown/cutover runbook](hierarchy-maintenance-runbook.md). The evidence-only
lifecycle journal does not enable a native executor. Legacy routes and command
names are compatibility evidence, not execution authority.

This is how root moves live sessions onto the [agent hierarchy](agent-hierarchies.md) tools, and how it
runs them afterward. Every tool here has tests, but those tests use a fake host, so **no real Claude or
Codex session has run this flow yet**. The checks below are what would show that it works.
Configuration and acknowledgments alone never count as proof.

## Move the live sessions

The owner approved this move. It keeps every session. A live front door or orchestrator is a thread
hosted by Codex's app server, which runs the mailbox adapter from a connection file in its own shell, so
it moves by getting a new connection file. It keeps its thread, its context and its tools. A CLI lane
gets a new wake profile with the sandbox options it already runs with.

| | Changes | Stays the same |
| --- | --- | --- |
| Native thread | Connection file, mailbox root, tool commit | Thread, context, tools, how root messages it |
| CLI lane | Wake profile, mailbox root | Session, worktree, branch, lease, sandbox options |
| Open dispatch | Continues as a new dispatch of the same brief | Worktree, branch, lease |
| Old mailbox root | Nothing. It stays readable as history | All of it |
| Cross-hierarchy messages | The counterpart route is gone, so use a board channel, and root for resources | |

| | Moving sessions in place (this) | Fresh narrow-profile sessions |
| --- | --- | --- |
| Latency | One command per hierarchy, at a task boundary | A startup and handoff for every role |
| Complexity | Host mechanics do not change, so there is little new to prove | Every profile needs real-host proof first |
| Cost | No new sessions | One new session per role |
| What you give up | Native threads keep their broad tools for now | |

**Order:** `prototype47` first, because nothing is in flight there, then `stormheir`, then `aegis`, which
has an accepted writer. Stop at the first check that fails, and leave the rest where they are.

For each hierarchy, when root tracks no running turn for its sessions:

1. Fill in the request. `root.session` must be the active root's real ID, and a placeholder is refused.
   Root will not resume Claude session `446f22db`, so `prototype47/orchestrator` moves to a fresh native
   thread named under `replaced`, with its real ID.
2. Run it. It is safe to repeat, and it only reads the old root:
   ```sh
   tool provision move --request <request file>
   ```
3. Send each thread in `tell` that exact text with `send_message_to_thread`.
4. Run `tool provision carry-check --request <file with {"base": ...}>` now and at each loop. Exit 3 means
   mail reached the old root afterward, or a binding changed there, so deal with those before going on.
5. For each lane in `needs_profile`, run `add-role` with its worktree when it is next assigned.
6. If the orchestrator continues an open dispatch from its carried brief, the lane accepts again with fresh
   readiness. Its writer slot is already in the ledger, so release it with evidence when that work ends.
7. When root rotates, bind its successor on each moved initiative with `tool handoff --spec <file>`.

Then check, on real sessions:

1. A moved orchestrator reads its carried brief through the new connection, and `delivery` shows it as `read`.
2. `sweep` wakes a moved CLI lane from its profile, and `delivery` shows its mail as `read`.
3. A job request produces a receipt whose evidence hashes match the files.
4. A sandboxed job cannot write to its checkout, reach the network or read a `hide` folder.
5. A reviewer reads a review copy, and `verify` still passes afterward.
6. A fourth writer across initiatives is refused, and a forged approval on the board changes no control state.

**To go back:** tell the moved sessions their old connection files again. The old root was never changed,
so only mail published in the new root in the meantime needs carrying back by hand.

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

The board is its own server with its own connection, so a damaged board cannot stop a session's mailbox.
`hide` lists folders a job must not see, such as your home folder, which holds credentials.
If the interpreter, a virtual environment or a Rust toolchain lives inside one, add that folder
to `ro_binds`, and set `RUSTUP_HOME` and `RUSTUP_TOOLCHAIN` in `env` for Rust tests.
The template offers `targeted-tests`, `full-suite`, `lint`, `aegis-check` and `commit-exact`, and
has no push recipe on purpose. Pushing stays with root, and merges and signatures stay with the
owner.

### Capacity limits

The code caps a store's limits at 5 writers, 3 `heavy` and 1 `heavy-tests`. `init` takes
`writer_limit`, `heavy_limit` and an optional `heavy_tests_limit`; a store initialized without
it gets a Heavy-Tests limit of 1.

- `heavy` is the 3 test slots: pytest suites, targeted tests and other test jobs.
- `heavy-tests` (Heavy-Tests) is the single slot where cargo builds and tests run.

So at most 4 test jobs run at once, and at most 1 of them is cargo. A recipe takes
`heavy-tests` with `"heavy_tests": true`; see [Heavy-Tests jobs](#heavy-tests-jobs).

To change an initialized store's limits, append a `set-limits` event that names its source:

```sh
printf '{"source": "owner-writers-5 requests/root-c6-owner-decisions-20261102.json", "writer_limit": 5}\n' \
  > "$TRIAL/set-limits.json"
tool workspace --store "$TRIAL/store" set-limits --request "$TRIAL/set-limits.json"
```

Each value must be within its cap and at least the number already granted for that kind, and a
refused change writes nothing. Raising a cap itself is an owner decision and a reviewed code change.

### Heavy-Tests jobs

A command recipe with `"heavy_tests": true`, which needs `"heavy": true`, waits for `heavy-tests`;
every other heavy recipe waits for `heavy`. Each kind is granted on its own, so a full Heavy-Tests
slot never holds a pytest job, and `min_free_gigabytes` holds both. The census counts outside work
per kind: pytest-family roots against `heavy`, cargo build/test and `rustc` roots against
`heavy-tests`. A waiting row names its `kind`.

- **Cargo rule.** A step whose program is `rustc`, or `cargo` whose first later word not starting
  with `-` or `+` is one of `build b test t check c run r bench clippy doc d rustc install nextest
  miri`, runs only in a `heavy_tests` recipe. `check-recipes` and `run-open` refuse any other
  recipe and name the recipe and step. `cargo fmt`, `metadata`, `tree` and `--version` stay light.
  Limits: a script that runs cargo inside it is not seen, and an option with a separate value
  before the subcommand (`cargo --manifest-path x test`) hides it, so write `--manifest-path=x`.
- **Cleanup.** After the result is written, every job removes `cargo-target/`, and a Heavy-Tests job
  removes all of its work folders, failed or not. Other failed jobs keep `scratch`, `tmp`, `home`,
  `ruff-cache` and `hypothesis` until `clean`. Logs and `result.json` always stay. The run row lists
  `removed`, `work_kept` names what stayed, and `cleanup_error` says why space was not freed.
  `cargo-target/`, `ruff-cache/` and `hypothesis/` carry a standard `CACHEDIR.TAG`.
- **`keep`.** Up to 16 paths relative to `scratch/`, with no `..`, at most 64 MiB together. Before
  any cleanup, success or failure, each regular file is copied to `<job>/evidence/` and listed
  with its `sha256` under `kept` in `result.json`. A missing, linked or oversized file is reported
  there and in the receipt, never truncated.
- **`$cargo_target`.** A step word that becomes the job's `cargo-target` folder, the same path
  `CARGO_TARGET_DIR` gets, for a runner that needs `--target-dir`.
- **PID namespace.** A `bwrap` recipe runs with `--unshare-pid`, so a process that calls `setsid`
  still ends with its job. `sandbox: none` recipes are unchanged.
- **Batch clean.** `tool jobs --store ... clean --initiative <id> --finished` removes the work
  folders of every finished job of that initiative, reports `freed_bytes`, and lists jobs without
  a result under `not_finished` without touching them.

**Re-pin step for root.** The new `load_recipes` refuses the live `recipes.json`, because its
`storm-settings-*` recipes run `cargo test`. In the same step as the re-pin, add
`"heavy_tests": true` to `storm-settings-focused`, `storm-settings-sadpaths` and
`storm-settings-regression`, then run `check-recipes`. `storm-fmt-check` (`cargo fmt`,
`heavy: false`) needs no change.

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
| Front door, Orchestrator | Claude, or Codex with `"reader_shell": true` for an orchestrator | Mailbox and file reading only. Codex has no file tools without its shell |
| Builder, Integrator | Codex | Its OS sandbox lets it run tests in its worktree. A generated Claude writer can edit but has no shell, so every test becomes a job |
| Reviewer | Claude, with `cwd` set to a review copy | It has native file tools. A Codex reviewer needs `"reader_shell": true`, and no real host has run that profile yet |
| Root | Any, including a native thread (`"host": "codex"`) | Bound with `"session"` and no adapter. Root uses these tools directly |

- **Start a Claude role:** run `start_argv` from the role's `cwd`, with the role's template on
  stdin (`tools/hierarchy_templates/roles/<role>.md`).
- **Show a Claude role in the owner's session list:** add `"background": true` to its `add-role`
  request. A `--print` turn never appears there. A background role runs with `claude --bg`, named
  `<endpoint>-g<generation>`, so `claude agents` and the owner's app list it and `claude attach`
  opens it. Pass its template as the last argument of `start_argv`, after the closing `--`, not on
  stdin.
  - **Permissions:** `--permission-mode dontAsk` replaces the prompt flags that only apply with `--print`.
  - **Each wake:** it starts a turn, follows it in `claude agents --json` until the session is no
    longer busy, saves `claude logs` beside the wake log, then stops the session.
  - **Safety:** an idle session is stopped before the next wake, a busy one is not woken, and a stop
    that cannot be confirmed keeps the wake lock.
  - **Switching:** run `add-role` again with the same `"session"` to switch a bound role in place.
  - **Unproven:** only a stand-in host has run this, so run the first-run checks on one role first.
- **Show a Codex role in the Codex app:** only native app-server threads (`"host": "codex"`) appear
  there. `codex exec` lanes do not. A native thread keeps the app server's tools unless its thread
  is created with the lane's limits.
- **Start a Codex role:** Codex assigns its own session ID, so a session has to exist before it
  can be bound. Run `tool provision codex-start --request <file>`, run the `start_argv` it
  returns, read the session ID from the first JSON event, then call `add-role` with that
  `"session"`.
- **Set up the board:** `tool board --board "$TRIAL/board" add-channel --request <file>` with
  `{"channel", "orchestrator", "source"}`, then `grant` with
  `{"channel", "endpoint", "access", "source"}`, where `access` is `read` or `post`. Grants
  apply to endpoints, so they survive a rotation.

## First-run checks for a new profile

Run these once on real sessions before trusting a generated narrow profile, and keep the evidence. Stop
at the first one that fails.

1. The session's reported tool catalog matches what its profile asked for, and nothing else.
2. A published message reaches a stopped session: after `sweep`, `delivery` shows it as `read`.
3. A stopped role is replaced on the other host, keeps its assignment and acknowledges the checkpoint.
4. For a background Claude role:
   - `claude agents --json` lists the session as busy while it works.
   - The wake result shows `"stop_confirmed": true`.
   - `delivery` shows the mail as `read`, which proves the prompt after `--` reached the session.

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
| `waiting` with `capacity_full` | All slots of the row's `kind` are taken, counting outside work | Run again later |
| `waiting` with `low_disk` | Free space is under `min_free_gigabytes`, so no heavy job starts | Free some space. `tool jobs --store ... clean --job <initiative>/<message-id>` removes a finished job's work folders |
| `running` | Another runner has it | Nothing |
| `abandoned` | The runner stopped, and the slot stays held | Stop `process_group` if `process_alive`, then run `tool jobs --store ... resolve --job <initiative>/<message-id> --reason "..."` |
| `settle_pending` | A busy mailbox or store delayed the receipt or the release | Run `run-open` again |
| `granted_elsewhere` | A slot went to work that is not a job | Start that work |
| `rotate_needed` | The session passed 60 active minutes, so it was not woken | Rotate it |
| `root_time` with `rotate_now` | Root passed its own 90 minutes | Rotate root |
| `woken_unread` or `timed_out` | A turn ran and the mail stayed unread | Read the turn's log. It gets no second turn for that mail in this sweep |
| `message_thread` | A native thread has unread mail, and its app server hosts it | Send it a message with `send_message_to_thread` |
| `no_profile` | The current binding has no wake profile | Run `add-role` for that session |
| `meter_error` | Active time could not be measured, so it was not woken | Find out why |
| `time_unknown` | No transcript was found for a CLI session, so its active time is unknown and it was not woken | Start it once with its start command, or check `CLAUDE_CONFIG_DIR` and `CODEX_HOME` |
| `root_queue` | Open jobs and unread mail for root | `run-open`, then `tool mailbox --root <mailbox> inbox --endpoint <hierarchy>/root --delivery-dir <dir> --mark-read` |

A full test run can leave about 2 GB in its job folder. A completed job removes that itself and
keeps its logs and result. A failed job removes `cargo-target/`, and a failed Heavy-Tests job
removes everything; another failed job keeps the rest (`work_kept`) as possible evidence until you
run `clean --job`, or `clean --initiative <id> --finished` for all of them.

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
`job_request` whose `brief` is the `path` and `sha256` the first publish returned. To run on
uncommitted changes, add `dirty_content_sha256` from `tool jobs source-digest --checkout <path>`, which a
lane with a shell can run and report. It covers the bytes of every changed and untracked file. Without
it, the checkout must be clean. Files Git ignores are not covered.
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

## ROOT launch checks (`hierarchy_root.py`)

ROOT launches and rotates Claude sessions with `tools/hierarchy_root.py`. Every subcommand prints
one JSON object; `--help` lists the exit codes and what each subcommand leaves behind on exit 2.

Never type a hash into a prompt. A ROOT once completed a hash from its 8-character prefix, and
nothing caught it (T92). Render prompts from a template instead, and check them before launch:

```sh
python3 -B -I tools/hierarchy_root.py render-prompt --template /abs/lane-prompt.template \
  --path brief=/abs/brief.md --path role=/abs/roles/lane.md --out /abs/requests/lane-prompt.txt
python3 -B -I tools/hierarchy_root.py check-hashes /abs/requests/lane-prompt.txt
```

- **Templates** write `{path:key}` and `{sha256:key}`. Each `--path key=...` fills `{path:key}`
  with the path as given and `{sha256:key}` with the sha256 of that file's bytes. Put each
  `{sha256:key}` on the same line as its `{path:key}`, or on the line below. A shell expansion
  such as `${CLAUDE_CODE_SESSION_ID:0:8}` is not a placeholder and is left as written.
- **render-prompt** refuses a relative or `..` path (naming the argument), an unknown placeholder
  kind such as `{md5:key}`, an unused or unfilled key, any existing `--out` (exit 3, even one
  with identical bytes), and output that would fail `check-hashes` (exit 6).
- **check-hashes** checks every token of exactly 64 lowercase hex characters bounded by anything
  but an ASCII letter or digit, so `_` and `*` are delimiters. Each token must re-hash from a
  file named by an absolute path on its line or the line above, repeat a token matched that way
  elsewhere in the same file (`via: "repeat"`), or match a `--source` file. It exits 6 and lists
  each unmatched token with its line, the candidate paths and their real sha256. It also exits 6
  on a malformed hash-like token: a hex run of 56-72 characters that is not exactly 64 lowercase
  ones. 40-hex git ids and short prefixes are not checked.
- **Candidates:** relative and `..` paths never count (T100), nor do paths with spaces or
  `key:/path` forms. A folder never counts, so a hash beside a folder stays unmatched. Symlinks
  are followed. FILE and `--template` must be regular files of at most 262144 bytes with no
  symlink in their path.
- **Review copies:** cite a review copy's manifest hash beside the path of its `manifest.json`,
  the file that hash covers, never beside the review folder.
- **launch** runs the same check on the spec's prompt before it calls `claude`, and exits 6
  without starting anything. A spec may list `hash_sources` (absolute paths) for hashes of files
  the prompt does not name beside them. The launch record lists every checked token, path and line.
- **Rotations:** after `verify-retired`, the incoming ROOT reruns `rebind --plan --custody` and
  expects `outgoing_stop.verified: true`. Only the record `verify-retired` writes counts, and
  `transfer --ack` takes only the ACK `startup-ack` wrote.

The ROOT helper checks disk space with the platform's portable disk-usage API and accepts
absolute paths in the host's native syntax. Its writes flush the file before atomic publication;
on POSIX they also flush the containing directory and report directory-flush failures. Windows
does not provide that directory flush through these standard-library APIs, so successful writes
there do not establish directory durability across power loss. Process verification uses POSIX
semantics: `verify-retired` and a `startup-ack` that probes a host PID refuse on Windows before
signalling a process or writing an acknowledgment/custody update. Planning remains read-only.

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
- Under `sandbox: none`, a process that starts its own session escapes the stop at the end of a
  job step. A `bwrap` recipe's PID namespace ends it with the job.
- The cargo rule reads only a step's own program and subcommand, so a script that runs cargo
  inside it can compile outside the Heavy-Tests slot.
- The census looks once before each grant, so outside heavy work that starts right after it can
  briefly put the total over the limit.
- A store, a board and a mailbox each stop accepting records at 10,000. Start a new one before
  that.
- Assistants stay off until the owner lifts the no-subagent rule for that trial.
- A moved native thread keeps its broad tools, so nothing in this move narrows what it can do.
- The ledger only counts writers in moved initiatives. Until all three have moved, root still has to keep
  the workspace total at three across the old and new roots.
