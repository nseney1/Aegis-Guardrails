# M1 loop runbook

This runbook takes one small feature through the M1 loop with real sessions, on a disposable
GitHub repository, and induces the five failure cases. It is the owner's run, and it is what the
M1 exit gate "the loop above passes once with real sessions" asks for (`v5.0-m1-definition-20261105.md:84`).

The same loop runs on fixtures in
[`tests/integration/test_hierarchy_m1_loop.py`](../tests/integration/test_hierarchy_m1_loop.py),
with fake hosts. That test shows the tools carry the loop together. It does not show that real
sessions behave this way, and it supports no enforcement claim. CI and the merge are not in it.

Setup, start, status and cleanup run through `tools/hierarchy_team.py`, described in
[the team guide](hierarchy-team.md). Every command below was checked against the tool's own `--help`. The tools
themselves are described in [the hierarchy guide](agent-hierarchies.md); this page only puts them in order.

```mermaid
sequenceDiagram
    autonumber
    actor Owner
    participant T as hierarchy_team.py
    participant J as Lifecycle journal
    participant ROOT as ROOT session
    participant Loop as hierarchy_loop.py
    participant O as Orchestrator
    participant I as Implementer
    participant Jobs as run-open
    participant R as Reviewer
    participant D as Decider
    Owner->>T: init, login, root, up
    Owner->>T: request feature-1
    T->>J: publish, as the coordinator
    Owner->>T: approve feature-1
    T->>ROOT: one turn: team_pending, then root_decide
    ROOT->>J: decision approve
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
    Owner->>T: request merge-c2 (source.commit = c2)
    O->>D: decide merge-c2
    D->>J: decider_record approve (or escalate)
    D->>O: info with the outcome
    Loop-->>Owner: holds in status --text
    Owner->>Owner: CI on the branch, then merge
    Owner->>T: down
```

## Prerequisites

- **Item 7's native probe has run first** on this host and Codex version, and passed
  (`v5.0-m1-definition-20261105.md:81-83`). See the native probe in
  [the restart guide](hierarchy-restart.md). Its report is evidence for this run, and a role whose
  profile it did not qualify is not started here.
- **A disposable GitHub repository** the owner creates, with a tiny Python project, a `tests/`
  folder and a CI workflow that runs the tests on push and pull request. A public repository gets
  free Actions minutes; a private one spends the owner's. Nothing here touches Aegis or Stormheir.
- **The team guide's [prerequisites](hierarchy-team.md#prerequisites)**: Linux, `git`, `bwrap` and `codex` on
  `PATH`, free disk, a fresh clone of the disposable repository at the base commit, and a clean clone of Aegis at
  the exact commit under trial, which no one edits during the run. Run Aegis from that clone, never an installed
  `aegis`.
- **A ChatGPT login for the run's own `CODEX_HOME`**, made by `login`. Unset `OPENAI_API_KEY` and `CODEX_API_KEY`:
  `login`, `up`, `approve` and `turn` refuse while either is set. Never run `codex login` without `CODEX_HOME`: it
  replaces `~/.codex/auth.json`. Never use `~/.codex`, and never touch the shared Codex app server.
- **A disposable ROOT session**: a new session the owner opens for this run only. Never bind the live
  dogfood ROOT, or any other session in use, to `m1/root`.
- **pytest installed in the job's Python** (the config's `recipes.python`), because `targeted-tests` runs
  `$python -m pytest`.
- The template's recipe environment sets `PYTHONPATH` to `$checkout`, the job's export root. That
  suits a flat layout; for a `src/` layout add `pythonpath = ["src"]` under `[tool.pytest.ini_options]`
  in the project's `pyproject.toml`, because the recipe file takes `$checkout` only as a whole value.

The native probe from the prerequisites uses its own `codex-home`. For SSO there, log that folder in with
`CODEX_HOME=<probe_root>/codex-home codex login` and pass `run --auth existing` (see
[the restart guide](hierarchy-restart.md)). The probe refuses while `OPENAI_API_KEY` or `CODEX_API_KEY` is set, and
needs `CODEX_HOME` spelled exactly as the plan prints it.

## Set up and start

```sh
export RUN=/absolute/path/m1-run                 # the config's run folder
export TOOLS=/absolute/path/aegis-clone          # clean Aegis clone at the commit under trial
export PROJECT=/absolute/path/project            # fresh clone of the disposable repository
export CODEX_HOME=$RUN/codex-home                # must be the config's codex_home, or every subcommand refuses
export TMPDIR=/tmp
T="python3 -I -B $TOOLS/tools/hierarchy_team.py --config $RUN/team-run.json"
tool() { python3 -I -B "$TOOLS/tools/hierarchy_$1.py" "${@:2}"; }
```

1. **The config.** Copy `$TOOLS/tools/hierarchy_templates/team-run.json` to `$RUN/team-run.json` and fill it in as
   [the team guide](hierarchy-team.md#the-config) says. For this run:
   - `initiative.id` is `m1`, `roles` is `["router", "decider"]`, `project` is `$PROJECT`, `base` is its HEAD and
     `branch` is `feature/m1-f2`.
   - `lanes` is an implementer `f2` with `paths` `["src/**", "tests/**"]` and a reviewer `review`.
   - `recipes.keep` is `["targeted-tests", "slow-tests"]`, with `recipes.template` set to the absolute path of a copy of
     `$TOOLS/tools/hierarchy_templates/job-recipes.json` that adds `slow-tests` for the :71 induction: a copy of
     `targeted-tests` whose `steps` start with `["$python", "-c", "import time; time.sleep(300)"]`, so its `started`
     receipt comes five minutes before its final one. Add it now, so the published recipe hash covers it.
   - `preflight` runs `targeted-tests` on the base, with `paths.targeted-tests` naming the test folder and `expect`
     what the base gives.
   - `lease_ttl_seconds` stays 21600 (6 hours), which covers the 2 to 4 hour run.
2. **`$T init`.** It runs every setup step that spends no model turn: the recipes and their hash, the store and
   initiative, provision, the front door's stand-in binding, the journal and its policy (actors `root-1`,
   `router-1`, `coordinator-1`, `operator-1`, `reviewer-1`, `decider-1`), the writer slot, the worktree, the lease
   and the preflight. Each output lands in `$RUN/evidence`. Post the `recipes_sha256` from
   `evidence/recipes-check.json` where the Reviewer will see it, for example in the review brief. Put the lease's
   `oid` and `expires_at` from `evidence/lease-claim-f2.json` in the lane brief.
3. **`$T login`**, and finish the sign-in in the browser. It checks the folder afterward.
4. **ROOT.** Start the disposable ROOT session as [the team guide's quick start](hierarchy-team.md#quick-start)
   shows (read-only, no shell, no tools, in `$RUN/codex-home`), then bind it with
   `$T root --session <thread_id>`. Its connection offers `root_decide`, `team_status`, `team_pending` and
   `team_request`. The launcher never starts or stops ROOT.
5. **`$T up`.** It writes `<base>/team.json`, starts the Router, Orchestrator, Decider, Reviewer and Implementer in
   that order, and checks each rollout for sub-agent tools and the served model and effort. Each role's start turn
   carries its role contract. Then it starts the loop with `CODEX_HOME` inline and checks `/proc/<pid>/environ`
   (`evidence/loop-environ.txt`).
6. **`$T status --text`** groups the holds by who must act (`root`, `owner`, `router`) and lists each pending ROOT
   decision with its `approve` command. Read it after every step below, and keep a copy at each hold
   (`$T status --text > "$RUN/evidence/status-<step>.txt"`). Do not also run the sweep or `run-open` by hand for
   the same store while the loop runs.

If `aegis team list --workspace "$PROJECT"` shows less than an hour left on the lease, renew it before the
Implementer accepts, and give the lane the new oid:

```sh
PYTHONPATH="$TOOLS" python3 -m aegis_cli team renew m1-f2 --workspace "$PROJECT" --expect <current oid> --ttl 21600 --json
```

`down` later releases the lease with the oid it reads then, so a renew needs no other step.

## Requests and decisions

A request file holds the request's fields (`aegis.lifecycle-request/v1`; `team: "m1"`, `paths` absolute in the lane
worktree, `source` the base commit and tree with the empty dirty digest), or a draft ROOT's `team_request`
returned. Keep these files outside the folders `init` makes, for example in `$RUN/drafts/`.

```sh
$T request feature-1 --file "$RUN/drafts/feature-1.json"   # prints the id and sha256
$T approve feature-1 --reason "agreed with the owner"       # one ROOT turn; add --deny to deny
```

`request` publishes as the coordinator, never as ROOT. `approve` refuses unless `team_pending` lists the request.
ROOT's turn reads the hash from `team_pending`, so no hash is pasted, and `approve` checks the journal afterward.

## The happy path

1. Setup and start, as above. Evidence: the `init` files, `up-roles.json`, `loop-environ.txt` and
   `$T status --text`.
2. The owner and ROOT agree the feature. The owner publishes `feature-1` and approves it with `approve`.
   Evidence: a journal `decision` by `root-1`, and ROOT's turn in `evidence/root-turns.jsonl`.
3. The next pass routes it: a `route-<sha>` info message to `m1/orchestrator` and a journal `route`.
   The same pass wakes the Orchestrator, which publishes the lane brief (paths, tests, acceptance,
   lease oid) and a dispatch naming it.
4. The next pass wakes the Implementer. It accepts with readiness naming the worktree, branch and
   lease, writes the failing test, commits it (c1) and tells the Orchestrator. The Orchestrator files
   `targeted-tests` on c1; its receipt is `failed` with `tests.failed` above 0. The Implementer makes
   it pass (c2); `targeted-tests` on c2 is `completed`. The owner pushes the branch to the
   disposable repository and opens the pull request; no recipe pushes, and a lane pushes only when its
   brief names an owner decision.
5. The Orchestrator dispatches the Reviewer with the c2 receipt's evidence references. The Reviewer
   checks them as [Reviewing with job evidence](agent-hierarchies.md#root-and-job-requests) says, and
   its `review` names c2. The owner publishes a `delegate-merge` request (team `m1`, the lane's paths,
   `max_starts: 1`, an `expires_at`, no continuation members) and approves it. The owner then publishes
   `merge-c2` with `source.commit` set to c2. While the delegation covers it, `status --text` lists it as
   `within_delegation`: it is the Decider's to decide first, so do not approve it. The Orchestrator asks the
   Decider, which records `delegated_decision` approve with `decider_record`, citing the review message's path and
   sha256, and replies to the Orchestrator.
6. CI runs on the branch's pull request. The owner merges. Neither has an Aegis record: write down
   the CI run URL and the merge commit.

## Induce each failure case

One safe way per case. Each is done once, on this disposable repository. The :70 and :73 cases fit
inside the happy path; do :71 after step 4, and the two :72 cases only after step 6 (revoked first,
then stale), because the stale case rebinds the real Implementer.

For :70, :71 and :72, find the mailbox root once:

```sh
MAILBOX=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["mailbox_root"])' "$RUN/initiatives/m1/provision.json")
```

| Case (definition) | Induce | Expect | Recover |
| --- | --- | --- | --- |
| Implementer session ends mid-task (:70) | While the Implementer's turn runs (`status --text` shows the sweep step running), `tool launcher --base "$RUN/initiatives/m1" stop --endpoint m1/lane/f2` | No second turn on its own. If the lane had not read its mail yet, a `woken_unread` then `ignored_mail` hold for root. If it read its dispatch and published nothing, a `silent_role` hold for root; if it had accepted, a `stalled_dispatch` hold for root | Unread mail: new mail for the lane. The owner, as the bound `m1/front-door` (session and generation in `$RUN/evidence/front-door.json`), asks the Orchestrator to follow up with the lane (`tool mailbox --root "$MAILBOX" publish --request <file>`). The next pass resumes the same Codex thread (`resume <thread>` in its wake log). Read mail: `$T turn m1/lane/f2 "<what it owes>"`, one owner turn in the same thread; its publish clears `silent_role`, and its `result` clears `stalled_dispatch` |
| A reply is lost (:71) | Ask the Orchestrator to file `slow-tests` on c2. After its `started` receipt, while its five-minute sleep runs and no session turn runs, create the lock exclusively: `( set -o noclobber; : > "$MAILBOX/.write.lock" ) \|\| echo "STOP: a writer holds the lock"`. On STOP, do nothing more: that lock is a live writer's, and removing it would break it. Keep yours until `status --text` shows the hold (`run-open` waits up to 30 s for the lock); session writes are refused as busy meanwhile | A `job_settle_pending` hold for root; the receipt is not published | Remove only the lock you created: `rm "$MAILBOX/.write.lock"`. The next pass publishes the receipt exactly once, and the pass after wakes the Orchestrator for it. A lost route is repaired the same way (`delivered_unrecorded`, recorded with no second message); it is shown on fixtures only |
| A revoked or stale session is refused (:72) | After step 6. Revoked: the owner publishes a throwaway `feature-2` whose `next_decision` says it is a refusal test and needs no work, and approves it. Once `status` shows it routed, `approve` refuses it, because a routed request is no longer pending. So the owner resumes ROOT for one turn by hand, with the argv `approve` uses (the quick start's flags, `-c` with the `mcp_config` from `evidence/root-binding.json`, then `resume <ROOT session>`), and asks it to deny `feature-2` with `root_decide`, giving the sha256 from `evidence/request-feature-2.json`. Stale: stop the Implementer, hand `m1/lane/f2` to a new session with `tool mailbox --root "$MAILBOX" draft-handoff --request <file> > "$RUN/bind-f2.json"` (`outgoing_stopped: true`) and `tool mailbox --root "$MAILBOX" bind --request "$RUN/bind-f2.json"`, then run the old connection's adapter with an `initialize` frame and one `mailbox_publish` frame (the script below) | Revoked: a `revoked_after_route` hold for the router; no further routing. Stale: exit 2 and "stale or mismatched sender binding", and the mailbox is unchanged | None needed; the successor carries on |
| An out-of-delegation request reaches ROOT (:73) | The owner publishes `merge-outside` with a path outside the delegation, and the Orchestrator asks the Decider | The journal refuses the Decider's approve ("target path is outside the delegation's paths"); its `escalate` shows in router `status` `escalations`, as an `escalation` hold for root, and in `team_pending` as `escalated` | `$T approve merge-outside --reason <text>`, or with `--deny`; the hold clears, and an approved request is routed |
| ROOT and Router attempts to execute work are refused (:74) | Ask the ROOT session to run a job or publish mail; run the Router's connection adapter with a `job_request` and a `dispatch` frame; `tool launcher --base "$RUN/initiatives/m1" start --request "$RUN/drafts/start-root.json"` (`{"endpoint": "m1/root"}`) | ROOT's tools are `root_decide` and three read-only tools; none publishes or runs a job. The Router's publishes are refused; the launcher answers "ROOT is the owner's session; bind it with add-role" and records only `refused`; no host starts | None. Whether ROOT's and the Router's own sandboxes refuse a shell call to the job tool is item 7's probe |

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

`down` collects the run's records into `$RUN/evidence` and writes `SHA256SUMS`; see
[the team guide](hierarchy-team.md#where-evidence-lands). It covers the policy, the journal checkpoints before and
after, the lease claim and releases, the workspace and store events, the launcher and router status, the launch
records and wake receipts, the loop's state, pid and log, every request and event file, the mailbox, each job's
results, ROOT's and the owner's turns, the Codex sessions and the turn ledger. Add the rest under `$RUN/evidence/`;
a second `down` rewrites `SHA256SUMS`, so files added after the first are covered.

- [ ] The item 7 probe report (`report --text` and the JSON) for this host and Codex version.
- [ ] Every lease renew's output.
- [ ] c1 and c2: `git -C "$RUN/worktrees/f2" rev-parse <commit> "<commit>^{tree}"` for each.
- [ ] `status --text` at each step and each hold.
- [ ] Router `status` before and after routing and after the escalation.
- [ ] Each job's `result.json` checked: `recipes_sha256` equal to the published hash, `before` and `after` naming c1
      or c2, and `tests` counts.
- [ ] One row per failure case: what was induced, the hold seen, and how it recovered, with the
      stale-session refusal output (`stale-session.txt`).
- [ ] The pull request URL, with its head equal to c2.
- [ ] The CI run URL on the exact c2 commit and the owner's merge commit.

## Cleanup

1. `$T down`. It stops the loop (and exits 3 if the loop is still running after `--loop-wait`; run it again), stops
   every role it started, collects the evidence, cleans finished jobs, releases the lease with the oid it reads now
   and the writer slot, removes the run's worktree with `git worktree remove` (never prune or repair), and removes
   review copies that carry a review manifest.
2. Check for leftover `.write.lock` files and wake markers by hand: the loop never removes a lock. `resolve` any job
   left `unknown` with `hierarchy_jobs.py`, then run `down` again.
3. Once the evidence is kept, `$T down --purge-codex-home`. It deletes the disposable login only when every session
   file has a matching copy in `evidence/codex-sessions`.
4. Delete any `/tmp` exports and, once the evidence is kept, the disposable repository. Close the disposable ROOT
   session.

## Owner-only steps

- ROOT's approvals and denials, each one ROOT turn through `approve`, including the delegation.
- Opening the disposable ROOT session, and `login`.
- Answering a `silent_role` or `stalled_dispatch` hold, with `turn` or follow-up mail.
- Creating the disposable repository, its CI workflow and any Actions spend.
- The model spend for the roughly 25 model turns (and item 7's probe).
- Pushing the branch and opening the pull request.
- The merge, and `aegis approve --base <pr-base>` on the Aegis PR head whenever that PR changes a
  governance path (the `aegis-human-gate` ruleset has no bypass).
- Clearing a `start_failing` hold, by deleting `$RUN/loop/status.json` once the cause is fixed.

## Known gaps

- **:70, a session that dies after reading.** It now raises `silent_role` (read and published nothing) or
  `stalled_dispatch` (accepted and sent no result), but nothing resumes it on its own: the owner's `turn` or a
  follow-up mail does. The holds have known false negatives, listed in
  [the hierarchy guide](agent-hierarchies.md#run-several-initiatives).
- **:71, a lost session reply** (a lane's `result`, `review` or `ack`) is not induced here. A turn that read its work
  and published nothing raises `silent_role`. The owner chose delivery loss for the induction: a lost route and a
  lost job receipt.
- **:72 is covered as a stale binding plus a ROOT deny**, not as a revoked-binding event: no tool
  retires or revokes a session binding yet.
- **Readiness lease oid is checked for shape only.** `Mailbox.readiness` in the pinned
  `tools/hierarchy_mailbox.py` checks the worktree root, the branch, the base revision and the lease
  expiry, but never reads `lease_ref` in git, so a made-up oid of the right shape is accepted. Compare
  the acceptance's `lease_oid` with the claim output by hand.

## Cost and duration

About 25 model turns, by count: 5 starts, about 9 happy-path wakes (Orchestrator 5, Implementer 2,
Reviewer 1, Decider 1), about 6 more for the failure cases, and 5 ROOT turns (`approve` for feature-1, the
delegation, feature-2 and merge-outside, and the :72 deny). Item 7's probe is about 28. The loop itself spends nothing between turns;
it only polls. Expect 2 to 4 hours with 30 s passes, the Implementer's own test runs and CI. Each `targeted-tests`
job writes an export and keeps its evidence, so watch the disk.

## Exit-gate mapping

| Exit gate (`v5.0-m1-definition-20261105.md`) | What this run gives |
| --- | --- |
| :78-79 Affected and full suites on the exact commit; hosted CI runs the tests | The c2 `targeted-tests` result; the CI run URL on c2 in the disposable repository |
| :80 One independent review per PR, findings resolved | The Reviewer's `review` on c2; Aegis's own PR review is separate |
| :81-83 One native probe per host | Item 7's probe report, run first; fake-host results claim nothing |
| :84 The loop passes once with real sessions | This runbook's evidence: every happy-path step and the five failure-case rows |
