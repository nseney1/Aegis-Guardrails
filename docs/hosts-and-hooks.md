# Hosts and hooks

MCP registration delivers Aegis tools to an agent. Bootstrap instructions ask the
agent to use them. Optional host hooks can intercept some edits and commands; the
Git hook and CI check the resulting change. These mechanisms have different limits.

## Register a host

Preview setup, then apply it from the repository:

```sh
aegis init --host codex-cli --dry-run
aegis init --host codex-cli
aegis doctor --json
```

`init` creates the bootstrap, repository configuration, workspace registration and
Git hook. `--host` also registers MCP; it does not install the host's pre-tool hook.
A host names a shared configuration plane: Codex CLI, its IDE extension and desktop
surface share `codex-cli`; Claude's CLI, IDE extensions and desktop Code tab share
`claude-code`; the Antigravity app, IDE and `agy` share `antigravity`. Surface aliases
such as `codex-app` are accepted. `--host auto` discovers configuration directories,
supported desktop bundles and executables on `PATH`.

| Host | MCP registration | Instructions and limits |
|---|---|---|
| `claude-code` | Native `claude mcp add --scope user` | `AGENTS.md` when no `CLAUDE.md` exists; otherwise an `@AGENTS.md` block in `CLAUDE.md`; 40 KiB budget |
| `codex-cli` | Native `codex mcp add` | `AGENTS.md`; 32 KiB, silently truncated |
| `antigravity` | `~/.gemini/config/mcp_config.json` | `AGENTS.md`; 24,000 bytes per file |
| `kiro` (experimental) | `~/.kiro/settings/mcp.json` | `AGENTS.md`; not checked on a real installation |
| `cursor` (experimental) | `~/.cursor/mcp.json` | `AGENTS.md`; not checked on a real installation |
| `copilot` (experimental) | `~/.copilot/mcp-config.json`, relocated by `COPILOT_HOME` | Instruction support not checked on a real installation |
| `windsurf` (experimental) | `~/.codeium/windsurf/mcp_config.json` | Not checked on a real installation; vendor documentation names a different config path |

Gemini CLI is retired: `aegis init --host gemini-cli` and
`aegis uninstall --host gemini-cli` exit 2 and name `--host antigravity`.
`claude-desktop` is an identity-only row, not a registration target; its Code tab
uses `claude-code`. Experimental registrations are labeled as such by init and doctor.

Aegis registers an absolute server command: an installed `aegis-mcp` launcher, or
the installing interpreter in isolated mode. It never registers
`python -m aegis_mcp`, which could import a repository's substitute package.
Doctor identifies unsafe registrations without executing them: a command that is
not absolute, a Python that runs `-m` or `-c` without `-I` or a script by a relative
path, or either behind `env`. Repository files do not register the server: a
committed `.mcp.json` would let a pull request choose a command to run. The MCP
server itself runs unsandboxed with the user's permissions.

## Workspace binding

Each MCP call must resolve a governed workspace containing `.aegis/`. Resolution
uses, in order, a strict `AEGIS_WORKSPACE` operator pin, host context, the workspace
registry and a walk from the server's working directory bounded by the Git root.
Codex supplies per-turn workspace metadata; Claude supplies `CLAUDE_PROJECT_DIR`
or MCP roots. Antigravity sends no roots and relies on the registry.

`aegis init --pin` writes the pin into the registration. An invalid pin is an error;
a pin conflicting with host context holds the call. File arguments may select only
among registered workspaces, not invent a new workspace. `$HOME` and `/` are never
workspaces. Without a governed workspace, MCP serves only read-only personal rules.
The CLI honors the pin too and exits 1 with `pin_conflicts_with_cwd` when a command
inside another repository conflicts with it. Unset the pin in that repository.

## Install host hooks

```sh
aegis hook install --host codex-cli --dry-run
aegis hook install --host codex-cli
```

Codex requires trust in its `/hooks` screen before running a new or changed hook;
until then it silently skips it. Doctor reports `needs approval in /hooks (cannot
be checked)`. `codex exec` has no documented trust path besides its per-run
`--dangerously-bypass-hook-trust` option.

| Host | User scope, the default | Project scope | Execution |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json` | `.claude/settings.json` | Exec form without a shell; documented host support |
| Codex CLI | `~/.codex/hooks.json`, or `$CODEX_HOME/hooks.json`, plus `~/.codex/rules/aegis.rules` | `.codex/hooks.json`, in trusted projects | POSIX: `$SHELL -lc`; Windows: `%COMSPEC% /C`, subject to the path limit below; trust required |
| Antigravity | `~/.gemini/config/hooks.json` | `.agents/hooks.json` | Shell wrapper maps handler exit 75 to blocking exit 1; all other exits to 0 |

Codex hooks on Windows are reported unavailable when the handler path contains
characters outside `[A-Za-z0-9._/+-]+`, including drive-letter colons, backslashes
or spaces. Aegis does not quote these shell paths, so a typical Windows install
path does not qualify. Antigravity hooks are unavailable on Windows.

`--scope project` writes a file that
teammates' hosts may execute after pulling and trusting it. Aegis refuses duplicate
user/project registrations, unparsable files, symlinks and hard links. It preserves
other entries, backs up existing files under `~/.aegis/backups/`, writes atomically
and re-reads the result. Every registration has a 10 s timeout.

`aegis hook install` without `--host` manages the Git pre-commit hook;
`aegis hook status` reports that Git hook. Use doctor for host integrations.
`aegis hook uninstall --host codex-cli --dry-run` previews removal of Aegis's host
entries, including an installed insight-capture entry. Other entries are retained.

## Runtime behavior

The handler receives stdin JSON describing the tool, command or edited paths and
workspace. It resolves the nearest governed workspace within the Git root. An
ungoverned repository is left alone; paths outside the workspace are not checked.
The installed matchers are:

| Host | Matcher |
|---|---|
| Claude Code | `Bash|PowerShell|Monitor|Write|Edit|NotebookEdit` |
| Codex CLI | `Bash|apply_patch` |
| Antigravity | `run_command|write_to_file|replace_file_content|multi_replace_file_content` |

Only `*` was probed live for Antigravity's matcher; if its regex is ignored, the
hook never fires. Codex edit paths come from patch headers, including an
`apply_patch` heredoc intercepted from Bash. Claude and Antigravity edit tools
provide file paths in their payloads.

The handler has a 5 s deadline where `SIGALRM` is available on the main thread;
otherwise, including Windows, the host's registration timeout is the bound.
An error, timeout, unreadable payload, unknown host/event or ungoverned workspace
exits 0. It writes no stdout. Blocking uses
exit 2 with a reason on stderr for Claude and Codex, or exit 75 for Antigravity's
wrapper. It never returns an interactive approval decision.

**Scan-before-edit.** One recent scan row must name every edited path, from any host
or session in the workspace. The setting is `jit.scan_window_s` (default 3600, from
60 to 86400) seconds. MCP scans and `aegis scan FILE...` both record coverage; new
files can be scanned before creation. Scanning a directory does not cover its files.
An uncovered edit blocks on Claude and trusted Codex hooks; Antigravity records it
only. Edits under `.aegis/rules/` are recorded only on every host, so a broken rule
can still be repaired when scans fail.

**Destructive commands.** The guard lexes shell commands and selected wrappers;
it does not execute or fully interpret the shell. It blocks these rule IDs:

- `git-push-force` (`--force`, `-f`, `--force-with-lease`), `git-push-refspec` (`+refspec`),
  `git-reset-hard` and `git-clean-force`.
- `rm-recursive-dangerous` (recursive removal of `/`, `~`, `$HOME`, `*`, `.` or `..`),
  `mkfs` and `dd-device` (writing a device).

It records, without blocking, `git-merge`, `gh-pr-merge`, `git-add-bulk`,
`git-push-protected`, `sudo`, `chmod-777` and `sql-destructive`. Merges are not
blocked by this guard. Codex also receives forbidden prefix rules in `aegis.rules`;
Aegis leaves `default.rules` alone. The manual `aegis hook safety-gate` has a
different contract: it asks about risky commands beyond this fixed block set.

The lexer cannot see shell functions, aliases defined outside the command, shell
stdin, or arbitrary wrappers. Unsupported cases include `chrt`, `taskset`, `flock`,
`nsenter`, `watch`, `script -c`, abbreviated wrapper options and more than 16 nested
Git alias scripts. An unparseable command fails open, including a later line with
an unclosed quote.

## Doctor and enforcement limits

Doctor's hook tier and evidence strings are:

- Claude Code: blocking (documented; fails open on error) [DOC]
- Codex CLI: blocking once trusted in /hooks (documented; fails open) [DOC]
- Antigravity: blocks destructive commands (live); scan gate records only [LIVE]

`DOC` means documented host behavior, not a successful live probe; `LIVE` means a
real host probe; `UNVERIFIED` means neither. Registration presence does not prove
enforcement is running. Doctor cannot verify Codex trust and reports the
best-effort tier as `unknown` rather than inferring it from a file.

Doctor prints these known gaps:

- Edits made through shell commands never reach the edit gate on any host.
- Codex write_stdin into an interactive shell has no PreToolUse payload, and the Codex Bash payload carries no working directory.
- Antigravity manage_task with send_input types into a background terminal past run_command.
- Aegis never emits an 'ask' decision (it fails open on Codex and soft-denies in agy headless runs).
- The hooks fail open on any Aegis error: they are guardrails, not a security boundary.

| Enforcement tier | What it establishes |
|---|---|
| Advisory | Bootstrap, MCP instructions and matching rules reach the agent |
| Best-effort | A host hook may intercept supported operations, subject to the limits above |
| Local floor | An installed, current and reachable Git pre-commit hook runs `aegis check --hook`; `--no-verify` bypasses it |
| Authoritative | CI checks the exact commit; branch protection and a human control the merge |

These are separate from the repository's [evidence trust tiers](trust-tiers.md).
Plain `aegis doctor` reads configuration and may make read-only GitHub requests
through the user's `gh` to resolve trust. Its only host CLI probe is
`codex mcp get aegis --json`. It reports `missing_binary`, `unregistered`,
`auth_unknown`, `policy_gap` or `ok`; `--json` returns the same findings.
`aegis doctor --fix` repairs supported reported leftovers after confirmation and
backs files up first. `aegis uninstall` removes Aegis's hooks, bootstrap and
registrations while retaining a host another registered workspace uses; it never
deletes `.aegis/`.

## Project skills

```sh
aegis skills sync --host codex-cli --dry-run
aegis skills sync --host codex-cli
```

Sync copies the packaged [skills](../skills/) into `.claude/skills/<id>/SKILL.md`
for Claude, or `.agents/skills/<id>/SKILL.md` for Codex and Antigravity. Claude and
Antigravity paths are documented; Codex's is unverified. None has been checked on a
real installation. Whether a host uses a projected skill is up to that host.

Each copy keeps `name` and `description` frontmatter, renders its host slots and
carries `<!-- aegis:skill id=<id> v=1 sha=<12 hex> -->`. Sync replaces an unchanged
marked copy; an edited copy needs `--force`. A file without the marker is yours and
is never replaced, even with `--force`. CRLF or a byte order mark alone is not an
edit. Paths must remain inside the workspace, with real directories and a regular
single-link file; force never overrides those checks.

If home resolution fails, init and uninstall exit 1 before writing. Skills sync
with `--host auto` exits 2 and asks for explicit hosts; an explicit host can still
project skills into the workspace. See the [reference](reference.md) for all flags
and [PRIVACY](../PRIVACY.md) for stored activity and backup files.
