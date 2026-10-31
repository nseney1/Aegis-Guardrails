# Privacy

Aegis runs on your machine. It has no service, no account and no telemetry, and its own code opens no network connection. Four things can still send data elsewhere, all started by you:

- **Your agent host.** Claude Code, Codex CLI, Antigravity or another MCP client sends what Aegis returns (rules, guidance) to its model provider, under that host's own privacy terms.
- **Layer 2.** `aegis check --full` pipes two prompts, one after the other, to the command you name with `--llm-cmd` or `AEGIS_LLM_CMD`. The first holds your task plan, the function signatures (with their docstrings) and the test names. The second holds the full text of each changed non-test Python file (not the diff; `__init__.py` is skipped), the test output, the Layer 1 results and the risks the first reply predicted. If that command calls a hosted model, that provider receives them. Without `--full`, `aegis check` sends no code anywhere.
- **Your GitHub CLI.** `aegis doctor`, `aegis doctor --release`, `aegis sync` and `aegis rule promote`, `demote` and `archive` start your own `gh`, with your own login, to read repository, ruleset, CI-run or attestation data. `aegis check --ci` does too, on a pull-request run and only when a flagged change has no signed approval: it reads the repository, the base branch's rules and the pull request's reviews (in CI with the job's `GH_TOKEN`). `aegis doctor --github --apply` creates one ruleset and `aegis sync --pr` opens a pull request. Scanning, `aegis_list_rules`, `aegis status`, `aegis rule list`, `aegis check` without `--ci` and the agent hooks start no `gh`.
- **Your git remote.** `aegis sync --pr` is the one command that pushes. It sends one `aegis/lifecycle-*` branch, a single commit of the changes under `.aegis/rules` and `.aegis/adjudications`, to the current branch's remote with your own git credentials. The pull request it opens states each rule's evidence state and up to three unlabelled examples per rule.

## What Aegis stores

In your git directory, `<git common dir>/aegis/`, which every worktree of the repository shares and which `git status` never shows (directories `0700`, files `0600`):

- `state/<ws-id>/ledger.jsonl`: outcome rows with the rule id, outcome, source, host, session id, time, the checked file paths and verdict, and the absolute path of the work tree that wrote the row. Outside a git repository the ledger is `.aegis/state/ledger.jsonl`.
- Check receipts additionally retain per-file tool, verdict, language and missing-driver reason. These evidence rows omit source snippets and diagnostic text.
- `events.jsonl`: one row per event (lease claims and denials, `aegis check --lane` and `--partition`, the hooks' scan-gate and guard decisions, skills sync, host setup, baseline, pack, benchmark and package runs) with the time, event kind, absolute work tree path, host, result and a small detail object. The detail holds counts, lane names and globs, rule ids and lease owner labels; for `lane_check` also the label, the base branch name and the commit ids of the range; for `package` the output path; for `partition_check` the file paths and symbol names of up to 200 predicted call and import edges. It never holds file contents or command text. Outside git it is `.aegis/state/events.jsonl`.

In the repository, under `.aegis/state/` (git-ignored by `aegis init`):

- `activity.jsonl`: MCP scan and edit events and `aegis scan` runs from the command line (file paths, host, session id, client name and version), read by `aegis status --compliance`.
- `gate_events.jsonl`: decisions of `aegis hook safety-gate`, with the command text cut to 200 characters and known secret patterns redacted.
- `arbiter_predictions.jsonl`: Layer 2 predictions from `aegis check --full`: id, verdict id, time, tree, backend (the program's base name), scope (path and symbol), category, observable (kind and selector), window in days, probability, severity, disposition and outcome. It holds no risk, mechanism or other model text.
- `lifecycle.jsonl`: the rule id and time of each rule moved to the archive.
- `derived.json`: the fitness view `aegis sync` writes. `migrate-backup-*/`: the files `aegis migrate --apply` replaced.

Elsewhere in the repository, written only by commands you run: `.aegis/adjudications/` (the labels you add), `.aegis/baseline.json` (the ratchet baseline) and `.aegis/proposals/` (draft rules from `aegis rule insight`: a kind, a count, the insight ids and up to three directory globs, never prompt text). In git refs, `refs/aegis/lanes/<lane>` holds each lane's lease: the lane name, role, branch, path globs, times and an owner label that is `<user>@<hostname>` unless you pass one. Aegis does not push these refs; the only push it makes is the `aegis sync --pr` branch above.

In your home directory:

- `~/.aegis/workspaces.json`: the absolute paths of the repositories you ran `aegis init` in, and their hosts.
- `~/.aegis/link.key`: 32 random bytes (mode `0600` on POSIX), created by `aegis init`, by `aegis rule insight enable` and, when it is missing, by the first insight capture that carries a session id, to pseudonymize host session IDs into keyed `hs` hashes.
- `~/.aegis/insights/<workspace-id>.jsonl`: opt-in user-scope insight rows (mode `0600` on POSIX) holding redacted correction excerpts (`<= 300` characters, with PEM blocks, tokens, `key=value` and prose credentials, emails, home paths and IPv4 addresses scrubbed; a prompt is scanned through its first 4,096 characters, and past that only a whole-word head is kept) and text-free session heartbeats.
- `~/.aegis/backups/`: a copy of each file before Aegis changes it, in one timestamped folder per run: the host config files that `aegis init --host`, `aegis uninstall` and `aegis doctor --fix` change, the host hook files that `aegis hook install --host`, `aegis rule insight enable` and `uninstall --host` change, and the git pre-commit hook that `aegis hook install` (or `aegis init`) rewrites (`~/.aegis` and `~/.aegis/backups` are created with mode `0700`; they can contain other servers' settings).
- The `aegis` entry in each host's own config, written through that host's CLI or config file.

On Windows, `link.key` and insight files inherit access control from their parent directories; Aegis does not set a Windows access control list for them.

To remove it: `aegis uninstall` takes out the host registrations, the instruction-file blocks, the git hook block and the registry entry; deleting `.aegis/` and `~/.aegis/` removes the rest, and the ledger and events log live in the repository's git directory under `aegis/`.
