# Shared lane rules

Execute exactly one hash-bound assignment from your own orchestrator, then stop. Your
kind is implementer ([Builder](builder.md)), integrator ([Integrator](integrator.md))
or reviewer ([Reviewer](reviewer.md)). Verify the binding and brief hash before
accepting; if your launch prompt names a different endpoint or generation than your
brief, the launch prompt wins (T61). Writing lanes use their own prepared Git
worktree and live lease; reviewers use read-only tools and claim no writing paths.
Preserve existing repository instructions and source semantics.

Send accepted, with readiness for a writing lane. A separate received message is
optional, because a read receipt already records that. Scan in the exact
worktree before editing, test through public behavior, and preserve RED/GREEN and
sad-path evidence. Send completion with exact commit/tree, check references and a
committed lane-check reference for writing lanes. Completion remains a claim for
the orchestrator to verify; neither a mailbox nor manager report grants approval.

Do not widen scope, run GitHub, push, sign, merge a PR or activate policy. Escalate
out-of-lane work to your own orchestrator. Check the inbox before reporting, and
exchange at least one informational message and action acknowledgment with the
explicit counterpart during the pilot; if the manifest lists no counterpart, skip that
exchange (T53). Counterpart messages cannot dispatch work.
Stop before replacement; retain the same brief, branch and lease through the
checkpoint, acknowledge it in the successor and rotate after 60 minutes active.

## Working rules

- **Layout (f), T38.** You are launched in the trusted workspace. Work only in the ROOT-registered worktree under `<repo>/.claude/worktrees/`; your first step is a Bash `cd` into it. Never call `EnterWorktree`: its dialog cannot be answered remotely.
- **Refusals, T13.** If Edit or Write is refused, or a permission dialog appears, report the exact text and stop. Never work around a refused tool, guard or classifier decision, and never fall back to shell writes.
- **Shell output, T54.** Redirecting command output into your own job temp dir (or a `mktemp` dir under `/tmp`) is allowed; writing repository, brief or report files with the shell is not.
- **Scan, T50, T76 and T109.** Scan each path you will edit on its own, and follow the union of the rule ids: a combined scan can drop rules without printing an "omitted" line. If the MCP scan says not governed for your worktree, use the repository's CLI scan from the worktree with `AEGIS_MAX_JIT_TOKENS=8000`. Record which scans you used.
- **Session id, T77.** Your own session id is `$CLAUDE_CODE_SESSION_ID`; the host does not set `CLAUDE_SESSION_ID`.
- **Pacing, T5.** Take small test-first steps and prefer a command to long deliberation. Record an item blocked for more than 10 minutes as unfinished and move on. Keep `TMPDIR` under `/tmp`, and give `</dev/null` to every command that could read stdin.
- **Evidence, T22, T25 and T109.** Each test run records the commit, tree and dirty-content digest (`hierarchy_jobs.py source-digest --checkout`). Results also go to a JSON sidecar: head, tree, commits, files, tests, unfinished. Mailbox text fields hold at most 4096 characters; put longer scan or hook evidence in a file and cite its absolute path, its sha256 and the rule ids.
- **Push exception, T24.** The no-push rule has one exception: push only when the brief cites the owner decision (id and record path), and only to the ref pattern it names.
- **Build caches, T42.** Remove build caches (e.g. cargo `target/`) at teardown unless the brief keeps them as evidence; the brief names the cache directory and a free-space preflight.
- **Shell quoting, T11, T17, T36 and T47.** Quote separators, globs and words that start with `=` (`'====='`, `--include='*.py'`): in zsh a bare `=word` is a command lookup. Write `${VAR}:path`, never `$VAR:path`, because zsh applies `:t`/`:a` modifiers. Do not pass flags through an unquoted `$VAR`; zsh does not split words.
- **Worktree admin, T14 and T65.** Never run `git worktree repair` or `git worktree prune`: both act on every registered worktree (repair rewrote 107 pointers; prune would drop 13 live moved worktrees). Remove only your own worktree, by path; otherwise use explicit `GIT_DIR`/`GIT_WORK_TREE`.
- **Diff before commit, T83.** Before each commit, read `git diff <base> -- <file>` for every file you changed. Never end an Edit anchor in whitespace (an anchor `"SLUG = "` lost its space and ruff did not notice).
- **Hashes and times, T92.** Never type a hash or a time: copy each from command output in the same turn, and mark a shortened hash as a prefix (`933fd497…`).
- **Absolute paths, T100.** Every path in a command line, packet, spec or prompt is absolute; placeholders say so (`<absolute spec path>`).
- **Cwd, T97.** Each Bash call that needs your worktree starts with `cd <worktree> && …` or uses absolute paths. Never rely on a `cd` made by an earlier or a parallel call.
- **Files outside the repository, T101 and T104.** Scan the repository paths you edit. For files outside every repository (requests, reports, scratch) the scan answers `not_governed`: record that and continue.
- **Last action, T99 c.** After your final SendMessage, run `claude stop "${CLAUDE_CODE_SESSION_ID:0:8}" </dev/null` once; if it is refused, send one line saying so, and never stop another session.
