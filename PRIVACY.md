# Privacy

Aegis runs on your machine. It has no service, no account and no telemetry, and its own code opens no network connection. Three things can still send data elsewhere, all under your control:

- **Your agent host.** Claude Code, Codex CLI, Antigravity or another MCP client sends what Aegis returns (rules, guidance) to its model provider, under that host's own privacy terms.
- **Layer 2.** `aegis check --full` pipes a prompt that includes the changed code, your task plan and test output to the command you name with `--llm-cmd` or `AEGIS_LLM_CMD`. If that command calls a hosted model, that provider receives the prompt. Without `--full`, `aegis check` sends nothing anywhere.
- **Your GitHub CLI.** Only `aegis doctor`, `aegis doctor --release`, `aegis sync`, `aegis rule promote`, `demote` and `archive` start your own `gh`, with your own login, to read repository, ruleset, CI-run or attestation data; `aegis doctor --github --apply` creates one ruleset and `aegis sync --pr` opens a pull request. Scanning, `aegis_list_rules`, `aegis status`, `aegis rule list`, `aegis check` and the agent hooks start no `gh`.

## What Aegis stores

In the repository, under `.aegis/state/` (git-ignored by `aegis init`):

- `ledger.jsonl`: outcome rows: rule id, outcome, source, host, session id, time, and the checked file paths and verdict.
- `activity.jsonl`: MCP scan and edit events (file paths, host, session id, client name and version), read by `aegis status --compliance`.
- `gate_events.jsonl`: decisions of `aegis hook safety-gate`, with the command text cut to 200 characters and known secret patterns redacted.
- `arbiter_predictions.jsonl`: Layer 2 predictions from `aegis check --full`: id, verdict id, time, tree, backend (the program's base name), scope (path and symbol), category, observable (kind and selector), window in days, probability, severity, disposition and outcome. It holds no risk, mechanism or other model text.
- `derived.json`: the fitness view `aegis sync` writes. `migrate-backup-*/`: the files `aegis migrate --apply` replaced.

In your home directory:

- `~/.aegis/workspaces.json`: the absolute paths of the repositories you ran `aegis init` in, and their hosts.
- `~/.aegis/link.key`: 32 random bytes (mode `0600` on POSIX) created by `aegis init` to pseudonymize host session IDs into keyed `hs` hashes.
- `~/.aegis/insights/<workspace-id>.jsonl`: opt-in user-scope insight rows (mode `0600` on POSIX) holding redacted correction excerpts (`<= 300` characters, with PEM blocks, tokens, `key=value` and prose credentials, emails, home paths and IPv4 addresses scrubbed; a prompt is scanned through its first 4,096 characters, and past that only a whole-word head is kept) and text-free session heartbeats.
- `~/.aegis/backups/`: copies of the host config files `aegis doctor --fix` changed (owner-only permissions; they can contain other servers' settings).
- The `aegis` entry in each host's own config, written through that host's CLI or config file.

On Windows, `link.key` and insight files inherit access control from their parent directories; Aegis does not set a Windows access control list for them.

To remove it: `aegis uninstall` takes out the host registrations, the instruction-file blocks, the git hook block and the registry entry; deleting `.aegis/` and `~/.aegis/` removes the rest.
