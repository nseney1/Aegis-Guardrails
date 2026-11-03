# Shared lane rules

Owner-facing ROOT amendment: ROOT is read-only evidence/owner conversation and
approve/deny only; historical operational ROOT references below confer no
execution authority. Distinct qualified operators own physical operations.
Before a FINAL/HOLD, preserve exact failed/incomplete evidence and have your
coordinator retain accepted delivery, an immutable next request with accountable
owner and next decision, or an owned blocker with a resolution condition.
An incomplete attempt never becomes eligible merely because its turn ended.
Carry unresolved intents and obligations through the checkpoint. The 3600
cumulative-active-second role cap includes open turns and waits and supersedes
dispatch-only timing; prepare the handoff before it, without resuming capped
actors. Native own-attestation and capability enforcement are separate gates.

Execute exactly one hash-bound assignment from your own orchestrator, then stop. Your
kind is implementer ([Builder](builder.md)), integrator ([Integrator](integrator.md))
or reviewer ([Reviewer](reviewer.md)). Verify the binding and brief hash before
accepting; if your launch prompt names a different endpoint or generation than your
brief, the launch prompt wins (T61). Writing lanes use their own prepared Git
worktree and live lease; reviewers use read-only tools and claim no writing paths.
Preserve existing repository instructions and source semantics.

Accept by publishing a mailbox `ack` in reply to the dispatch, with readiness for a
writing lane; a SendMessage is a notice, not the acceptance (T134, T126 (2)). A
separate received message is optional, because a read receipt already records that. Scan in the exact
worktree before editing, test through public behavior, and preserve RED/GREEN and
sad-path evidence. Send completion with exact commit/tree, check references and a
committed lane-check reference for writing lanes. Completion remains a claim for
the orchestrator to verify; neither a mailbox nor manager report grants approval.

Do not widen scope, run GitHub, push, sign, merge a PR or activate policy. Escalate
out-of-lane work to your own orchestrator. Check the inbox before reporting. No
manifest lists counterparts (`counterparts: []`), and a counterpart is a route inside
one mailbox only (`tools/hierarchy_mailbox.py:213-222` and `:305-306` at `b41c75b9`), so
no lane kind, reviewers included, holds a counterpart exchange (T144), and
cross-initiative traffic goes through your orchestrator, which uses ROOT relay (owner
decision `c12-cross-orchestrator-traffic-a`; T53, T119 (5)). Counterpart messages cannot dispatch work.
Stop before replacement; retain the same brief, branch and lease through the
checkpoint, acknowledge it in the successor and rotate after 60 minutes active.

## Working rules

- **Layout (f), T38 and T48.** Writing lanes: you are launched in the trusted workspace. Work only in the ROOT-registered worktree under `<repo>/.claude/worktrees/`, from the launch cwd (Cwd below).
- **No `EnterWorktree`, T38, T48 and T139.** No lane calls `EnterWorktree`, whatever its kind: its dialog cannot be answered remotely.
- **Refusals, T13.** If Edit or Write is refused, or a permission dialog appears, report the exact text and stop. Never work around a refused tool, guard or classifier decision, and never fall back to shell writes.
- **Shell output, T54 and T135.** Redirecting command output into your own `$CLAUDE_JOB_DIR/tmp` (or a `mktemp -d /var/tmp/…` folder) is allowed; writing repository, brief or report files with the shell is not.
- **Scan, T50, T76 and T109.** Scan each path you will edit on its own, and follow the union of the rule ids: a combined scan can drop rules without printing an "omitted" line. If the MCP scan says not governed for your worktree, use the repository's CLI scan from the worktree with `AEGIS_MAX_JIT_TOKENS=8000`. If a per-path scan still lists omitted rules, follow those ids too. Record which scans you used.
- **Session id, T77.** Your own session id is `$CLAUDE_CODE_SESSION_ID`; the host does not set `CLAUDE_SESSION_ID`.
- **Pacing, T5.** Take small test-first steps and prefer a command to long deliberation. Record an item blocked for more than 10 minutes as unfinished and move on. Give `</dev/null` to every command that could read stdin.
- **Temp and home folders, T135.** Pytest and tool runs put `TMPDIR` and `HOME` in a `mktemp -d /var/tmp/…` folder, not under `/tmp`: a Codex sandbox can leave an empty `/tmp/.git`, which fails 12 `test_hierarchy_root.py` tests. Output into your own `$CLAUDE_JOB_DIR/tmp` stays allowed.
- **Evidence, T22, T25 and T109.** Each test run records the commit, tree and dirty-content digest (`hierarchy_jobs.py source-digest --checkout`). Results also go to a JSON sidecar: head, tree, commits, files, tests (each with its digest), unfinished. Mailbox text fields hold at most 4096 characters; put longer scan or hook evidence in a file and cite its absolute path, its sha256 and the rule ids.
- **Push exception, T24.** The no-push rule has one exception: push only when the brief cites the owner decision (id and record path), and only to the ref pattern it names.
- **Build caches, T42.** Remove build caches (e.g. cargo `target/`) at teardown unless the brief keeps them as evidence; the brief names the cache directory and a free-space preflight.
- **Shell quoting, T11, T17, T36 and T47.** Quote separators, globs and words that start with `=` (`'====='`, `--include='*.py'`): in zsh a bare `=word` is a command lookup. Write `${VAR}:path`, never `$VAR:path`, because zsh applies `:t`/`:a` modifiers. Do not pass flags through an unquoted `$VAR`; zsh does not split words.
- **Worktree admin, T14 and T65.** Never run `git worktree repair` or `git worktree prune`: both act on every registered worktree (repair would rewrite 107 pointers; prune would drop 13 live moved worktrees). Remove only your own worktree, by path; otherwise use explicit `GIT_DIR`/`GIT_WORK_TREE`.
- **Diff before commit, T83.** Before each commit, read `git diff <base> -- <file>` for every file you changed. Never end an Edit anchor in whitespace (an anchor `"SLUG = "` lost its space and ruff did not notice).
- **Hashes and times, T92.** Never type a hash or a time: copy each from command output in the same turn, and mark a shortened hash as a prefix (`933fd497…`).
- **Absolute paths, T100.** Packets, prompts and specs write every path in a command line as absolute; placeholders say so (`<absolute spec path>`).
- **Cwd, T97, T104, T111, T135 and T139.** Your session cwd stays at the launch cwd for the whole session: never a bare `cd`, not even at the start of a compound command; never `cd` into the dogfood folder (`aegis-hierarchy-dogfood`), even as a writer; and run `pwd` before your first Write; if it is not the launch cwd, run one lone `cd <launch cwd>` and report it. Writers use `git -C <worktree>` for git and a `( cd <worktree> && … )` subshell for anything that needs a working directory; read-only roles follow `reviewer.md`, which allows no subshell `cd` either. Never rely on a `cd` made by an earlier or a parallel call.
- **Files outside the repository, T101 and T104.** Scan the repository paths you edit. For files outside every repository (requests, reports, scratch) the MCP scan answers `not_governed` and the CLI scan prints "No changed files detected": record that and continue.
- **Lint and size, T128 and T124.** Run `ruff check --no-cache <paths>` with ruff's default rules on every `.py` file you change, as the lint recipe does; it is stricter than `make lint` (T128). If you grow a large `aegis_core` module, also run `tests/contract/test_module_size.py`: the budget is shrink-only (T124).
- **Deadline, T111 (3), T117 and T126 (1).** Your deadline counts from the dispatch, and the wait for the dispatch does not count. If the prompt, the brief and the dispatch give different deadlines, ask your orchestrator before you start.
- **Mixed hosts, T136.** If your launch prompt says your manager's host is `codex`, report only through the mailbox (`ack`, `result`, `info`), and keep SendMessage for ROOT, for urgent items only. A published dispatch or verdict does not wake you, so while you wait for one, poll your inbox under a bounded background sleep (about 120 s, capped by your deadline). The open-items wait below polls the same way.
- **Open items before the self-stop, T125 (2).** If your result lists open items for your manager, end your turn under a background timer (`sleep 600` run in the background, capped by your deadline) instead of stopping. On an "accept" message, or when the timer fires, self-stop; on a fix-round dispatch, do the work, then self-stop. A result with no open items stops at once. T99 c stays the last action.
- **Last action, T99 c.** After your final SendMessage, run `claude stop "${CLAUDE_CODE_SESSION_ID:0:8}" </dev/null` once; if it is refused, send one line saying so, and never stop another session.
