# M1 loop runbook

This runbook takes one small feature through the M1 loop with real sessions, on a disposable
GitHub repository, and induces the five failure cases. It is the owner's run, and it is what the
M1 exit gate "the loop above passes once with real sessions" asks for (`v5.0-m1-definition-20261105.md:84`).

The same loop runs on fixtures in
[`tests/integration/test_hierarchy_m1_loop.py`](../tests/integration/test_hierarchy_m1_loop.py),
with fake hosts. That test shows the tools carry the loop together. It does not show that real
sessions behave this way, and it supports no enforcement claim. CI and the merge are not in it.

Every command below was checked against the tool's own `--help`. The tools themselves are described in
[the hierarchy guide](agent-hierarchies.md); this page only puts them in order.

```mermaid
sequenceDiagram
    autonumber
    actor Owner
    participant Op as Operator shell
    participant J as Lifecycle journal
    participant ROOT as ROOT session
    participant Loop as hierarchy_loop.py
    participant O as Orchestrator
    participant I as Implementer
    participant Jobs as run-open
    participant R as Reviewer
    participant D as Decider
    Op->>Op: writer grant, git worktree add, team claim, launcher start (Implementer)
    Owner->>ROOT: agree a small feature
    Op->>J: record publish (feature-1)
    ROOT->>J: root_decide approve
    Loop->>J: router status, then route
    Loop->>O: route info, durable sweep wake
    O->>I: lane brief + dispatch
    Loop->>I: wake (codex resume)
    I->>O: ack accepted with readiness, red commit c1
    O->>Jobs: job_request targeted-tests on c1
    Jobs-->>O: job_receipt failed (tests.failed > 0)
    I->>I: green commit c2
    O->>Jobs: job_request targeted-tests on c2
    Jobs-->>O: job_receipt completed (junit counts)
    O->>R: review dispatch with the receipts' evidence
    R->>O: review naming c2
    I->>O: result naming c2
    Op->>J: record publish (merge-c2, source.commit = c2)
    O->>D: decide merge-c2
    D->>J: decider_record approve (or escalate)
    Loop-->>ROOT: escalation hold in status --text
    Owner->>Owner: CI on the branch, then merge
```

## Prerequisites

- **Item 7's native probe has run first** on this host and Codex version, and passed
  (`v5.0-m1-definition-20261105.md:81-83`). See the native probe in
  [the restart guide](hierarchy-restart.md). Its report is evidence for this run, and a role whose
  profile it did not qualify is not started here.
- **A disposable GitHub repository** the owner creates, with a tiny Python project, a `tests/`
  folder and a CI workflow that runs the tests on push and pull request. A public repository gets
  free Actions minutes; a private one spends the owner's. Nothing here touches Aegis or Stormheir.
- `OPENAI_API_KEY` set in the operator shell, and a **disposable `CODEX_HOME`**: an empty folder that
  is logged in with that key and deleted afterward. Never use `~/.codex`, and never touch the shared
  Codex app server. The launcher, the wake and the loop pass their environment to Codex unchanged, so
  the `CODEX_HOME` in the environment that starts them is what keeps every session in it.
- **A disposable ROOT session**: a new session the owner opens for this run only. Never bind the live
  dogfood ROOT, or any other session in use, to `m1/root`.
- Linux, Git 2.31+, Python 3.11+ (the Codex connection settings are TOML), `codex` on `PATH`,
  and a clean clone of Aegis at the exact commit under trial, which no one edits during the run.
  Run Aegis from that clone (`PYTHONPATH="$TOOLS" python3 -m aegis_cli`), never an installed `aegis`.
- `TMPDIR=/tmp`, and at least **5 GB free** on the store's disk: the recipe template sets
  `min_free_gigabytes: 5`, and every job writes an export and keeps its evidence.
- **pytest installed in the job's Python** (the recipe file's `python`), because `targeted-tests` runs
  `$python -m pytest`.
- The template's recipe environment sets `PYTHONPATH` to `$checkout`, the job's export root. That
  suits a flat layout; for a `src/` layout add `pythonpath = ["src"]` under `[tool.pytest.ini_options]`
  in the project's `pyproject.toml`, because the recipe file takes `$checkout` only as a whole value.

```sh
export RUN=/absolute/path/m1-run                 # everything this run writes
export TOOLS=$RUN/tools-clone                    # clean Aegis clone at the commit under trial
export PROJECT=$RUN/project                      # clone of the disposable GitHub repository
export CODEX_HOME=$RUN/codex-home                # disposable; logged in with OPENAI_API_KEY
export TMPDIR=/tmp
tool() { python3 -I -B "$TOOLS/tools/hierarchy_$1.py" "${@:2}"; }
[ "$(realpath -m "$CODEX_HOME")" != "$(realpath -m "$HOME/.codex")" ] || echo "STOP: CODEX_HOME is ~/.codex"
mkdir -p "$RUN/evidence"
```

Log the disposable home in once, with the key on stdin, so the key never lands in shell history or
in a file: `printenv OPENAI_API_KEY | codex login --with-api-key`.

## Provision, in this order

The team is `m1`. Each request file is strict JSON with absolute paths.

1. **Store and initiative.** `limits.json` is `{"writer_limit": 3, "heavy_limit": 3}`. `init.json`
   follows the dogfood guide's [Add an initiative](hierarchy-dogfood.md#add-an-initiative), with
   `"roles": ["router", "decider"]`, `"lanes": {"f2": "implementer", "review": "reviewer"}` and
   `$PROJECT` in `checkouts`.

   ```sh
   tool workspace --store "$RUN/store" init --request "$RUN/limits.json"
   tool provision init --request "$RUN/init.json"
   ```

2. **Journal, with a policy that names the router and decider actors.** `policy.json` is
   `aegis.lifecycle-policy/v1`, with actors for `root`, `router`, `coordinator`, `operator`,
   `reviewer` and `decider` (for example `root-1`, `router-1`, `coordinator-1`, `operator-1`,
   `reviewer-1`, `decider-1`), each `current`. ROOT's profile must be read-only with tools within
   `read`, `decide` and `attest`; the router's must be `medium` effort and `ultrafast` tier.

   ```sh
   tool lifecycle --root "$RUN/lifecycle" init --policy "$RUN/policy.json" --evidence-only
   ```

3. **Bind ROOT** to the disposable ROOT session, with `add-role` and
   `{"base": "$RUN/initiatives/m1", "endpoint": "m1/root", "host": "<ROOT's host>", "session": "<ROOT session id>",
   "lifecycle": "$RUN/lifecycle", "actor": "root-1"}`. The answer names the `aegis_decision`
   connection, and for `codex-cli` an `mcp_config` setting (a native thread, host `codex`, gets a flat
   connection file). The owner adds that to the ROOT session: its
   only tool is `root_decide`. The launcher never starts or stops ROOT.

   ```sh
   tool provision add-role --request "$RUN/root.json"
   ```

4. **Bind the operator's front door.** The operator's own mail (the :70 recovery below) is signed as
   `m1/front-door`, and a publish needs a bound sender. `front-door.json` is
   `{"base": "$RUN/initiatives/m1", "endpoint": "m1/front-door", "host": "claude-code", "session": "<a fresh UUID,
   for example from uuidgen>", "cwd": "$RUN"}`. No session runs behind it: that UUID has no transcript,
   so mail to it is held as `time_unknown` and never wakes anything.

   ```sh
   tool provision add-role --request "$RUN/front-door.json" > "$RUN/front-door.out.json"
   ```

5. **Pin the recipes and publish their hash.** Start from `$TOOLS/tools/hierarchy_templates/job-recipes.json`,
   set `python`, `path`, `hide` (include your home folder) and `identity`, and keep `targeted-tests` as it
   is (`require_clean`, `expects_tests`, `bwrap`). Add a `slow-tests` recipe for the :71 induction: a
   copy of `targeted-tests` whose `steps` start with `["$python", "-c", "import time; time.sleep(300)"]`,
   so its `started` receipt comes five minutes before its final one. Add it now, so the published hash
   covers it. Post the printed `sha256` where the Reviewer will see it, for example in the review brief.

   ```sh
   tool jobs --store "$RUN/store" --recipes "$RUN/recipes.json" check-recipes
   ```

6. **Start the sessions with the launcher**, in this order: Router, Orchestrator, Decider, Reviewer.
   The Implementer starts last, after its worktree exists (the operator's lease step below). Each
   start request names the `endpoint` and its options:

   | Endpoint | Start request keys |
   | --- | --- |
   | `m1/router` | `cwd` (the project), `lifecycle`; no actor |
   | `m1/orchestrator` | `cwd`, `reader_shell: true` |
   | `m1/decider` | `cwd`, `reader_shell: true`, `lifecycle`, `actor: "decider-1"` |
   | `m1/lane/review` | `cwd` (a review copy from `hierarchy_review.py prepare`, or the project), `reader_shell: true` |
   | `m1/lane/f2` | `cwd` (the lane worktree) |

   ```sh
   tool launcher --base "$RUN/initiatives/m1" start --request "$RUN/start-router.json"
   tool launcher --base "$RUN/initiatives/m1" status
   ```

   Each start writes a record under `$RUN/initiatives/m1/launches/<endpoint>/`. A start exits 0 when
   bound, 2 when refused and 3 when the start failed.

## Start the loop

Start it once, as a plain process outside any model session, so it outlives every session. Put
`CODEX_HOME` on the command itself, so a new shell without the export cannot send its wakes to
`~/.codex`, and run Python directly rather than through `tool`, so `$!` is the loop's own pid:

```sh
CODEX_HOME="$RUN/codex-home" nohup python3 -I -B "$TOOLS/tools/hierarchy_loop.py" --lifecycle "$RUN/lifecycle" \
  --store "$RUN/store" --recipes "$RUN/recipes.json" --state-dir "$RUN/loop" run --interval 30 \
  > "$RUN/loop.log" 2>&1 &
echo $! > "$RUN/loop.pid"
tr '\0' '\n' < "/proc/$(cat "$RUN/loop.pid")/environ" | grep '^CODEX_HOME='
tool loop --lifecycle "$RUN/lifecycle" --store "$RUN/store" --recipes "$RUN/recipes.json" \
  --state-dir "$RUN/loop" status --text
```

The `environ` line must print `CODEX_HOME=$RUN/codex-home` (expanded). If it prints nothing or
`~/.codex`, stop the loop before anything is woken. Check the pid yourself later: a background-task
"completed" notice in an agent shell is not proof it stopped.

`status --text` groups the holds by who must act (`root`, `owner`, `router`). Read it after every
step below. Do not also run the sweep or `run-open` by hand for the same store while the loop runs.

## Operator commands

These are the operator's steps, from the owner's shell. They are deviations the owner accepted on
2026-11-05: no session tool publishes a canonical request yet, and no tool provisions a lane worktree.

- **Grant the writer slot, add the worktree, claim the lease, start the Implementer.** Do this before
  ROOT approves `feature-1`: the pass that routes it also wakes the Orchestrator, and the mailbox
  refuses a dispatch to an unbound lane. `slot.json` is
  `{"initiative": "m1", "kind": "writer", "holder": "m1/lane/f2"}`.

  ```sh
  tool workspace --store "$RUN/store" request --request "$RUN/slot.json"
  tool workspace --store "$RUN/store" grant-next --kind writer
  git -C "$PROJECT" worktree add -b feature/m1-f2 "$RUN/worktrees/f2" main
  PYTHONPATH="$TOOLS" python3 -m aegis_cli team claim m1-f2 --workspace "$PROJECT" --paths 'src/**' 'tests/**' \
    --ttl 21600 --owner m1/lane/f2 --role implementer --branch feature/m1-f2 --json > "$RUN/evidence/lease-claim.json"
  ```

  The globs are quoted so the shell passes them unexpanded, and `--workspace` keeps an
  `AEGIS_WORKSPACE` set in the owner's shell from sending the lease elsewhere. `--ttl 21600` (6 hours)
  covers the 2 to 4 hour run: the default is one hour, and an expired lease makes the Implementer's
  acceptance fail with "readiness lease has expired". Put the printed `oid` and `expires_at` in the lane
  brief. If `aegis team list --workspace "$PROJECT"` shows less than an hour left, renew it before the
  Implementer accepts, and give the lane the new oid:

  ```sh
  PYTHONPATH="$TOOLS" python3 -m aegis_cli team renew m1-f2 --workspace "$PROJECT" --expect <current oid> --ttl 21600 --json
  ```

  Every renew prints a new oid, and `release --expect` later needs the current one. Then add the
  worktree to the initiative's `checkouts` with `tool workspace --store "$RUN/store" update --request
  "$RUN/checkouts.json"`, and start `m1/lane/f2` with the launcher.

- **Publish a canonical request.** Write the request (`aegis.lifecycle-request/v1`; `team: "m1"`,
  `paths` absolute in the lane worktree, `source` the base commit and tree with the empty dirty digest),
  then an event file `{"id": "publish-feature-1", "actor": "coordinator-1", "generation": 1,
  "custody": {"cid": "root-1", "generation": 1}, "event": {"type": "publish", "request": {"raw": "<exact
  request bytes>", "sha256": "<their sha256>"}}}`. The `raw` text is the request's JSON plus a newline,
  and its sha256 is over exactly those bytes.

  ```sh
  tool lifecycle --root "$RUN/lifecycle" record --event "$RUN/publish-feature-1.json" --evidence-only
  tool lifecycle --root "$RUN/lifecycle" status
  ```

## The happy path

1. The operator's lease step above, then the Implementer's start. Evidence: the claim output, the
   workspace `request` and `grant` events, and `tool launcher --base "$RUN/initiatives/m1" status`.
2. The owner and ROOT agree the feature in ROOT's conversation. The operator publishes `feature-1`;
   ROOT approves it with `root_decide`. Evidence: a journal `decision` by `root-1`.
3. The next pass routes it: a `route-<sha>` info message to `m1/orchestrator` and a journal `route`.
   The same pass wakes the Orchestrator, which publishes the lane brief (paths, tests, acceptance,
   lease oid) and a dispatch naming it.
4. The next pass wakes the Implementer. It accepts with readiness naming the worktree, branch and
   lease, writes the failing test, commits it (c1) and tells the Orchestrator. The Orchestrator files
   `targeted-tests` on c1; its receipt is `failed` with `tests.failed` above 0. The Implementer makes
   it pass (c2); `targeted-tests` on c2 is `completed`. The operator pushes the branch to the
   disposable repository and opens the pull request; no recipe pushes, and a lane pushes only when its
   brief names an owner decision.
5. The Orchestrator dispatches the Reviewer with the c2 receipt's evidence references. The Reviewer
   checks them as [Reviewing with job evidence](agent-hierarchies.md#root-and-job-requests) says, and
   its `review` names c2. ROOT approves a `delegate-merge` request (team `m1`, the lane's paths,
   `max_starts: 1`, an `expires_at`), published by the operator. The operator then publishes
   `merge-c2` with `source.commit` set to c2. The Orchestrator asks the Decider, which records
   `delegated_decision` approve with `decider_record`, citing the review message's path and sha256.
6. CI runs on the branch's pull request. The owner merges. Neither has an Aegis record: write down
   the CI run URL and the merge commit.

## Induce each failure case

One safe way per case. Each is done once, on this disposable repository. The :70 and :73 cases fit
inside the happy path; do :71 after step 4, and the two :72 cases only after step 6 (revoked first,
then stale), because the stale case rebinds the real Implementer.

For :71, find the mailbox root once:

```sh
MAILBOX=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["mailbox_root"])' "$RUN/initiatives/m1/provision.json")
```

| Case (definition) | Induce | Expect | Recover |
| --- | --- | --- | --- |
| Implementer session ends mid-task (:70) | While the Implementer's turn runs (`status --text` shows the sweep step running), `tool launcher --base "$RUN/initiatives/m1" stop --endpoint m1/lane/f2` | No second turn on its own. If the lane had not read its mail yet, a `woken_unread` then `ignored_mail` hold for root; if it had, no hold at all, because nothing re-wakes read mail, so watch for the missing reply yourself (see Known gaps) | New mail for the lane: the operator, as the bound `m1/front-door` (session and generation from `front-door.out.json`), asks the Orchestrator to follow up with the lane (`tool mailbox --root "$MAILBOX" publish --request <file>`). The next pass resumes the same Codex thread (`resume <thread>` in its wake log) |
| A reply is lost (:71) | Ask the Orchestrator to file `slow-tests` on c2. After its `started` receipt, while its five-minute sleep runs and no session turn runs, create the lock exclusively: `( set -o noclobber; : > "$MAILBOX/.write.lock" ) \|\| echo "STOP: a writer holds the lock"`. On STOP, do nothing more: that lock is a live writer's, and removing it would break it. Keep yours until `status --text` shows the hold (`run-open` waits up to 30 s for the lock); session writes are refused as busy meanwhile | A `job_settle_pending` hold for root; the receipt is not published | Remove only the lock you created: `rm "$MAILBOX/.write.lock"`. The next pass publishes the receipt exactly once, and the pass after wakes the Orchestrator for it. A lost route is repaired the same way (`delivered_unrecorded`, recorded with no second message); it is shown on fixtures only |
| A revoked or stale session is refused (:72) | After step 6. Revoked: the operator publishes a throwaway `feature-2` whose `next_decision` says it is a refusal test and needs no work; ROOT approves it, and once `status` shows it routed, ROOT denies it with `root_decide`. Stale: stop the Implementer, hand `m1/lane/f2` to a new session with `tool mailbox --root "$MAILBOX" draft-handoff --request <file> > "$RUN/bind-f2.json"` (`outgoing_stopped: true`) and `tool mailbox --root "$MAILBOX" bind --request "$RUN/bind-f2.json"`, then run the old connection's adapter with an `initialize` frame and one `mailbox_publish` frame (the script below) | Revoked: a `revoked_after_route` hold for the router; no further routing. Stale: exit 2 and "stale or mismatched sender binding", and the mailbox is unchanged | None needed; the successor carries on |
| An out-of-delegation request reaches ROOT (:73) | The operator publishes `merge-outside` with a path outside the delegation, and the Orchestrator asks the Decider | The journal refuses the Decider's approve ("target path is outside the delegation's paths"); its `escalate` shows in router `status` `escalations` and as an `escalation` hold for root | ROOT approves or denies with `root_decide`; the hold clears, and an approved request is routed |
| ROOT and Router attempts to execute work are refused (:74) | Ask the ROOT session to run a job or publish mail; run the Router's connection adapter with a `job_request` and a `dispatch` frame; `tool launcher --base "$RUN/initiatives/m1" start --request "$RUN/start-root.json"` | ROOT's only tool is `root_decide`; the Router's publishes are refused; the launcher answers "ROOT is the owner's session; bind it with add-role" and records only `refused`; no host starts | None. Whether ROOT's and the Router's own sandboxes refuse a shell call to the job tool is item 7's probe |

The stale check runs the old Implementer connection the way its host would, from the first launch
record (the original start):

```sh
OLD=$(ls "$RUN/initiatives/m1/launches/m1%2Flane%2Ff2/"*.json | head -1)
python3 - "$OLD" <<'EOF' | tee "$RUN/evidence/stale-session.txt"
import json, subprocess, sys
record = json.load(open(sys.argv[1]))
server = json.load(open(record["connection"]))["mcpServers"]["aegis_mailbox"]
frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
          {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "mailbox_publish", "arguments": {
              "message_id": "stale-check", "to": "m1/orchestrator", "type": "info", "body": "Stale session check."}}}]
proc = subprocess.run([server["command"], *server["args"]], input="".join(json.dumps(f) + "\n" for f in frames),
                      capture_output=True, text=True, timeout=30)
print("exit", proc.returncode)
print(proc.stdout, proc.stderr)
EOF
```

## Evidence checklist

Keep every file below under `$RUN/evidence/`, then record the sha256 of each:

```sh
find "$RUN/evidence" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$RUN/evidence/SHA256SUMS"
```

- [ ] The item 7 probe report (`report --text` and the JSON) for this host and Codex version.
- [ ] `policy.json`, every request and event file the operator wrote, and `tool lifecycle ... checkpoint`
      output before and after the run.
- [ ] The lease claim output (oid, expiry), every renew's output, and the workspace `request` and
      `grant` events from `$RUN/store/events/`.
- [ ] c1 and c2: `git -C "$RUN/worktrees/f2" rev-parse <commit> "<commit>^{tree}"` for each.
- [ ] `status.json` from `$RUN/loop` after each step, and `status --text` at each hold.
- [ ] The loop's pid and its `CODEX_HOME` line from `/proc/<pid>/environ`.
- [ ] Router `status` before and after routing and after the escalation.
- [ ] `tool launcher --base "$RUN/initiatives/m1" status` output, the launch records under
      `$RUN/initiatives/m1/launches/` and the wake receipts under its `delivery/`.
- [ ] Each job's `result.json`, step logs and `evidence/run/junit.xml`, with `recipes_sha256` equal
      to the published `check-recipes` hash, `before` and `after` naming c1 or c2, and `tests` counts.
- [ ] The dispatch, readiness acceptance, result and review messages, and the lane brief.
- [ ] The `delegated_decision` events and the escalation's ROOT decision.
- [ ] Each Codex role's rollout records for its settings (`turn_context`), from the disposable home.
- [ ] One row per failure case: what was induced, the hold seen, and how it recovered, with the
      stale-session refusal output (`stale-session.txt`).
- [ ] The pull request URL, with its head equal to c2.
- [ ] The CI run URL on the exact c2 commit and the owner's merge commit.

## Cleanup

1. SIGTERM the loop (`kill "$(cat "$RUN/loop.pid")"`) and confirm its pid is gone. It never removes a
   lock: check for leftover `.write.lock` files and wake markers by hand.
2. `tool launcher --base "$RUN/initiatives/m1" stop --endpoint <endpoint>` for each started role.
3. `tool jobs --store "$RUN/store" --recipes "$RUN/recipes.json" clean --initiative m1 --finished`;
   `resolve` any job left `unknown`.
4. Release the writer slot with `tool workspace --store "$RUN/store" release --request <file>`, and the
   lease with `PYTHONPATH="$TOOLS" python3 -m aegis_cli team release m1-f2 --workspace "$PROJECT" --expect <current oid>`
   (the oid from the last claim or renew, or `aegis team list --workspace "$PROJECT"`).
5. `git -C "$PROJECT" worktree remove "$RUN/worktrees/f2"`. Remove only the worktrees this run
   created; never run `git worktree prune` or `git worktree repair`.
6. Delete `$CODEX_HOME` (the disposable login), any `/tmp` exports, and, once the evidence is kept,
   the disposable repository. Close the disposable ROOT session.

## Owner-only steps

- ROOT's approvals and denials (`root_decide`), including the delegation.
- Opening the disposable ROOT session.
- Creating the disposable repository, its CI workflow and any Actions spend.
- The OpenAI API spend for the roughly 20 model turns (and item 7's probe).
- Pushing the branch and opening the pull request.
- The merge, and `aegis approve --base <pr-base>` on the Aegis PR head whenever that PR changes a
  governance path (the `aegis-human-gate` ruleset has no bypass).
- Clearing a `start_failing` hold, by deleting `$RUN/loop/status.json` once the cause is fixed.

## Known gaps

- **:70, a session that dies after accepting.** It raises no hold, because nothing re-wakes read
  mail, and it is resumed only by a follow-up mail (the operator's front-door message above), not by
  the supervisor on its own. This is a deviation the owner must record; the fixture test covers only a
  session that dies before reading.
- **:71, a lost session reply** (a lane's `result`, `review` or `ack`) has no detector and is not
  covered. The owner chose delivery loss: a lost route and a lost job receipt.
- **:72 is covered as a stale binding plus a ROOT deny**, not as a revoked-binding event: no tool
  retires or revokes a session binding yet.
- **Readiness lease oid is checked for shape only.** `Mailbox.readiness` in the pinned
  `tools/hierarchy_mailbox.py` checks the worktree root, the branch, the base revision and the lease
  expiry, but never reads `lease_ref` in git, so a made-up oid of the right shape is accepted. Compare
  the acceptance's `lease_oid` with the claim output by hand.

## Cost and duration

About 20 model turns, by count: 5 starts, about 9 happy-path wakes (Orchestrator 5, Implementer 2,
Reviewer 1, Decider 1) and about 6 more for the failure cases. Item 7's probe is about 28. The loop
itself spends nothing between turns; it only polls. Expect 2 to 4 hours with 30 s passes, the
Implementer's own test runs and CI. Each `targeted-tests` job writes an export and keeps its
evidence, so run `clean` as you go if the disk is tight.

## Exit-gate mapping

| Exit gate (`v5.0-m1-definition-20261105.md`) | What this run gives |
| --- | --- |
| :78-79 Affected and full suites on the exact commit; hosted CI runs the tests | The c2 `targeted-tests` result; the CI run URL on c2 in the disposable repository |
| :80 One independent review per PR, findings resolved | The Reviewer's `review` on c2; Aegis's own PR review is separate |
| :81-83 One native probe per host | Item 7's probe report, run first; fake-host results claim nothing |
| :84 The loop passes once with real sessions | This runbook's evidence: every happy-path step and the five failure-case rows |
