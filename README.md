# Aegis Guardrails: Rules, AST Checks & MCP Server for AI Coding Agents

[![PyPI](https://img.shields.io/pypi/v/aegis-guardrails)](https://pypi.org/project/aegis-guardrails/)
[![Python](https://img.shields.io/pypi/pyversions/aegis-guardrails)](https://pypi.org/project/aegis-guardrails/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/nseney1/Aegis-Guardrails/blob/main/LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/nseney1/Aegis-Guardrails/blob/main/pyproject.toml)
[![CI](https://github.com/nseney1/Aegis-Guardrails/actions/workflows/validate.yml/badge.svg)](https://github.com/nseney1/Aegis-Guardrails/actions/workflows/validate.yml)

Aegis keeps Claude Code, Codex CLI and Antigravity on your project's rules via a zero-dependency Model Context Protocol (`MCP`) server (`aegis-mcp`), `AGENTS.md` / `CLAUDE.md` bootstrap, git `pre-commit` hooks, and CI governance (`aegis check`). It serves each agent just-in-time rules for the files it is about to edit, then enforces AST and repository invariants before commit and in pull requests.

## What is Aegis?

Aegis is a Python package with zero runtime dependencies that provides a CLI (`aegis`) and an MCP server (`aegis-mcp`) for AI coding agent governance. Your rules are short markdown files in `.aegis/rules/`, committed with your code. Before an agent edits a file, the `aegis_scan` MCP tool hands it only the rules whose `target_paths` match that file. `aegis check` then runs deterministic checks — including AST code patterns your rules ban — in a git `pre-commit` hook and in CI, while a local ledger records how each rule fared.

## Why guardrails for AI coding agents?

An instructions file (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`) is a gentleman's agreement: nothing checks that the agent followed it. Agents break it in three ways:

- **They skip rules.** Under task pressure an agent follows the letter of a rule and misses its point.
- **They forget.** Long sessions compact their context, and every new session starts from zero.
- **They fail open.** A check that crashed, a tool that is missing or a rule that never loaded looks exactly like "no problem found".

In one coding session analyzed step by step, 749 of 1,339 agent steps (55.9%) were rework. The largest items were guessed UI controls (180 steps), the wrong Python environment (110) and a test that polled forever (103), and each became a rule Aegis ships. That is one session by one developer with no second rater; the sources and caveats are in [Why Aegis is built this way](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/why-aegis.md).

## Quick start

Aegis runs a **3-step loop** in any git repository with Python 3.9 or newer:

1. **Step 1 — Install & initialize**: Install `aegis-guardrails` (`pipx install aegis-guardrails` or `pip install aegis-guardrails`) and run `aegis init` in your repo to write the `AGENTS.md` bootstrap, register `aegis-mcp` with your hosts, and install the `pre-commit` hook.
2. **Step 2 — Scan before edit**: Your coding agent calls `aegis_scan` over MCP before editing files to receive just-in-time rules matched to those paths.
3. **Step 3 — Block bad commits in Git & CI**: `aegis check` runs automatically in the `pre-commit` hook and in CI to block forbidden AST patterns and rule regressions.

```bash
pipx install aegis-guardrails            # or: pip install aegis-guardrails
cd my-app
aegis init --host claude-code,codex-cli   # or --host auto: every supported host found on this machine
```

<details>
<summary>Troubleshooting install & PATH (PEP 668, ~/.local/bin, virtualenv)</summary>

If pip stops with `externally-managed-environment` (PEP 668, as many Linux distributions and Homebrew Python do), run `pipx install aegis-guardrails` or install into a virtual environment. If your shell then says `aegis: command not found`, run `pipx ensurepath` after a pipx install, activate the virtual environment, or run the script by its full path (on Linux `~/.local/bin/aegis` after `pip install --user`); `aegis init` and `aegis doctor` print the PATH fix for your shell. Do not fall back to `python3 -m aegis_cli` inside a repository: `-m` imports from the current directory first.

</details>

`aegis init` prints its plan and asks before it writes anything. After you confirm, it reports (absolute paths shortened to `~`):

```text
  ✅ .aegis/config.json: created (hosts: codex-cli, claude-code)
  ✅ .aegis/.gitignore: created
  Starter rules (preset=standard) in .aegis/rules/personas/:
    ✅ providence
    ✅ destructive-ops
    ✅ testing
    ✅ cost-optimization
    ✅ git-workflow
    They apply to no file until you set their target_paths (aegis status lists them).
  Active rule in .aegis/rules/invariants/:
    ✅ no-eval: bans builtin eval() and exec() in **/*.py (method calls like df.eval() and model.eval() are allowed); aegis check and the pre-commit hook enforce it
    Next: add a rule for your own code with aegis rule create (aegis rule create --help)
  ✅ AGENTS.md: created
  ✅ ~/.aegis/workspaces.json: added
  ✅ codex-cli: registered (codex mcp add aegis --env AEGIS_CLIENT=codex-cli -- ~/.local/bin/aegis-mcp)
  ✅ claude-code: registered (claude mcp add --scope user aegis -e AEGIS_CLIENT=claude-code -- ~/.local/bin/aegis-mcp)
    🪝 Pre-commit hook installed (~/code/my-app/.git/hooks/pre-commit)
```

`init` seeds one rule that is active from day one: `.aegis/rules/invariants/no-eval.md` (leave it out with `--rules none-active`). Because `builtin: true` is set on its call predicates, it catches Python's builtin `eval()` and `exec()` while allowing method calls like pandas `df.eval()`, PyTorch `model.eval()`, and SQLModel `session.exec()`. Here is what it looks like, as a template for your own (`aegis rule create` writes one for you):

```markdown
---
id: no-eval
type: invariant
domain: security
enforcement: gate
hypothesis: Agents reach for eval() to parse input
target_paths:
  - "**/*.py"
forbid_ast:
  calls:
    - name: eval
      builtin: true
    - name: exec
      builtin: true
---
Never call `eval` or `exec` on data. Parse it with `json.loads` or `ast.literal_eval`.
```

`aegis check` enforces the **reviewed** rules: a rule is enforced locally once it is in the base (committed, when there is no `origin/HEAD`; on the branch `origin/HEAD` points to, when there is one). Commit `.aegis/` and `AGENTS.md` before you try it; the local ledger in `.aegis/state/` is git-ignored:

```bash
git add .aegis AGENTS.md && git commit -m "Add Aegis"
```

An agent that calls `aegis_scan` before editing `app.py` gets this rule (`aegis scan app.py` shows the same thing in a shell). If the change calls `eval` anyway, the check fails, and so does `git commit`, because the pre-commit hook runs the same check on the staged content. With no file arguments, `aegis check` looks only at tracked files: your changes and staged files (on a clean tree, what the branch adds to its base). It skips untracked files, so `git add` a new file first, or name it: `aegis check app.py`.

```text
$ git add app.py
$ aegis check
checkpoint: all checks passed
🔴 forbid_ast:no-eval: app.py — Forbidden call 'eval' matched rule forbid_ast.calls
Layer 1: 1/3 FAILED — forbid_ast:no-eval
```

Run `aegis doctor` to verify your host registrations and enforcement tiers, and add `aegis check` to CI since `git commit --no-verify` skips the local hook:

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0          # aegis check diffs the pull request against its base branch
- uses: actions/setup-python@v7
  with:
    python-version: "3.12"
- run: pip install aegis-guardrails && aegis check
```

## Works with your agents

| Host | How `aegis init --host` wires it | Instructions the agent reads |
|---|---|---|
| **Claude Code** (`claude-code`) | `claude mcp add --scope user aegis` | `AGENTS.md`, but only when there is no `CLAUDE.md`. If the repo has one, `init` adds an `@AGENTS.md` block to it; it never creates one. |
| **Codex CLI** (`codex-cli`) | `codex mcp add aegis` | `AGENTS.md` (Codex truncates it past 32 KiB) |
| **Antigravity** (`antigravity`: app, IDE and `agy`) | an `aegis` entry in `~/.gemini/config/mcp_config.json` | `AGENTS.md` (24,000 bytes per file). Antigravity tells the server no workspace, so run `aegis init` once per repo on each machine. |
| **Kiro** (`kiro`, experimental: IDE and CLI) | an `aegis` entry in `~/.kiro/settings/mcp.json` | `AGENTS.md` |
| **Gemini CLI** | Retired: Google refuses the client for individual Code Assist accounts, and Antigravity is the Gemini-family host. `aegis init --host gemini-cli` exits with status 2 and points you to `--host antigravity`. | — |

On every host, rules are advisory through the bootstrap and `aegis_scan`, the git pre-commit hook is the local floor, and CI is the authority. `aegis hook install --host <host>` adds a pre-tool hook that stops destructive commands and edits to files nobody scanned first (`--scope project` writes project hook settings your teammates' hosts will run).

## How it works

1. **Bootstrap**: `aegis init` writes a compact bootstrap block into `AGENTS.md` (no rule text) and registers the `aegis` MCP server with your hosts.
2. **Just-in-time scan**: Before editing, the agent calls `aegis_scan` with the files it will change and receives only matching rules, prioritizing gates and invariants within a token budget.
3. **Witnessed verification**: The agent edits, runs tests, and reports with `aegis_report_outcome`. `aegis check --record --tests` snapshots the exact git tree and runs your tests there, so only witnessed passes earn rule credit.
4. **Pre-commit & CI enforcement**: `aegis check` runs Layer 1 (deterministic checks and every `forbid_ast` ban) in the pre-commit hook and in CI; `aegis check --full --plan "..." --llm-cmd 'claude -p'` adds an optional cross-vendor model review.
5. **Evidence-driven promotion**: Outcomes append to a local ledger; `aegis sync` computes rule fitness and suggests promotions for human review.

<details>
<summary>Bootstrap size, JIT slot allocation, and Layer-1/2 architecture details</summary>

- `aegis init` writes a 572-byte bootstrap block into `AGENTS.md`, and the MCP server repeats the same guidance in its `initialize` instructions so editing files cannot strip it.
- `aegis_scan` returns at most 3 rules by default (gates and invariants first, capped at 2 slots so advisory rules are not starved) within a 2,000-token default budget (`jit.max_tokens` or `AEGIS_MAX_JIT_TOKENS`).
- An `aegis_report_outcome` call without a passing `aegis check --record --tests` row for that git tree is recorded as `claimed` and earns no rule credit; `aegis check --record` without `--tests` checks Layer 1 only and earns none.

</details>

The full architecture, with diagrams, is in [How Aegis works](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md). Every command, flag and MCP tool schema is in the generated [reference](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/reference.md).

## What's included

- **A CLI** with 15 commands (`init`, `uninstall`, `doctor`, `migrate`, `check`, `approve`, `scan`, `status`, `rule`, `sync`, `hook`, `team`, `skills`, `benchmark`, `package`) and **an MCP server** with 5 tools (`aegis_scan`, `aegis_report_outcome`, `aegis_create_rule`, `aegis_list_rules`, `aegis_capture_insight`).
- **Host surfaces.** `codex-cli` covers the Codex CLI, IDE extension and ChatGPT desktop app; `claude-code` covers the CLI, IDE extensions and desktop Code tab; `antigravity` covers the app, IDE and `agy`; `kiro` (experimental) covers the Kiro IDE and CLI. `--host auto` discovers hosts via config directories and app bundles as well as CLIs on `PATH`.
- **12 starter [rules](https://github.com/nseney1/Aegis-Guardrails/tree/main/rules)**: grounding claims in code, dry runs before destructive commands, behavioral tests, TDD, git hygiene and more (`aegis init --rules minimal|standard|full` seeds 2, 5 or all 12; set `target_paths` to activate them).
- **15 [skills](https://github.com/nseney1/Aegis-Guardrails/tree/main/skills)**: `SKILL.md` playbooks synced by `aegis skills sync` (or `aegis init --skills`) into `.claude/skills/` and `.agents/skills/`.
- **Multi-language AST checks**: Python (in-process), plus packaged drivers for Rust, TypeScript/JavaScript (`node`) and Go (`go`).
- **A Python SDK facade**, `aegis_sdk.Governance`, for tools that query rules and fitness.

## Agent teams

When parallel agents work in separate worktrees (lanes), declare each lane's path scope with `aegis team claim docs --paths 'docs/**' README.md`. A lease is cooperative conflict input — not a lock, not an identity, and not proof an agent is still running — and overlapping live claims are refused.

Verify containment with `aegis check --lane docs`: every path changed since the merge base must stay inside the lane's scope, and no Python test may disappear or gain a skip. With a lease or `--paths` the check is self-attested; with `--base-policy` it reads `.aegis/team.json` from the base branch and is witnessed. In CI it is advisory in v4.1. See [How Aegis works](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md) for lease refs and `aegis team metrics`.

## Rules that earn their place

- **Evidence-backed promotion (`trap` → `invariant` → `gate`)**: Rules start as traps and earn promotion only through CI-witnessed checks and git history replay — never from unwitnessed agent self-reports. Aegis never rewrites a rule file on its own; a human applies promotions with `aegis sync --apply`, `aegis sync --pr`, or `aegis rule promote`.
- **CI weakening & regression gates (`aegis check --ci`)**: Flags any pull request that weakens a gate or invariant relative to the base branch, enforces fail-to-pass regression tests on bug-fix commits, and emits PR-native `--format github|sarif` output.
- **Closed loop from human corrections (`aegis rule insight`)**: Captures recurring developer corrections via `aegis_capture_insight` and `aegis rule insight` (`add`, `review`, `enable`) and clusters them into draft rule proposals in `.aegis/proposals/`.

<details>
<summary>Statistical fitness, session-count decay (w = 2^(-delta / H)), and calibration internals</summary>

`aegis sync` computes four sample-size states (`untestable`, `insufficient (n=K)` with no precision number shown until `n >= 25`, `inconclusive`, and `decided`) over CI-confirmed checks, git detector replay (`caught` vs `leaked`), and human-adjudicated labels, weighted by exponential session-count decay (`w = 2^(-delta / H)`) over heartbeat-alive eligible sessions. Inline `# aegis: allow` comments record `contested` overrides (never false positives) and flag rules with high override rates for review. `aegis sync --pr` opens a human-reviewed PR with up to 3 sampled examples per rule and never auto-merges. For Layer-2 reviews, the arbiter logs falsifiable predictions scored by `aegis check --calibration`. Full details are in [How Aegis works](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md) and [Why Aegis is built this way](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/why-aegis.md).

</details>

## What Aegis does not do

Aegis does not claim enforcement it lacks. `aegis doctor` reports these tiers, in these words:

| Tier | Mechanism | What gets past it |
|---|---|---|
| Advisory | AGENTS.md bootstrap, MCP instructions, JIT rules | any agent: it is guidance |
| Best-effort | per-host pre-tool hooks | everything on a host without `aegis hook install --host`, a Codex hook you have not trusted in `/hooks`, edits made through shell commands, and any call when Aegis itself errors: the hooks fail open. Installed, `aegis doctor` reports Claude Code: blocking (documented; fails open on error) [DOC] (exit 2, documented by Anthropic); Codex CLI: blocking once trusted in /hooks (documented; fails open) [DOC] (exit 2, documented by OpenAI); Antigravity: blocks destructive commands (live); scan gate records only [LIVE] (exit 1, verified live). Antigravity hooks are unavailable on Windows |
| Local floor | git pre-commit runs aegis check --hook (--no-verify bypasses it) | anyone using `git commit --no-verify` |
| Authoritative | CI runs aegis check on the exact SHA; a human merges | a pull request that also weakens the rules or the CI workflow it is checked with, unless `aegis check --ci` runs as a required check and a person reviews those changes (tier A); a signed `aegis approve` (tier B) holds only while the pull request leaves `.github/workflows/**` and aegis alone. `aegis doctor` prints the trust tier (A, B or C) GitHub actually enforces |

**CI is the floor.** Agent hooks are guardrails, not a security boundary. Plain `aegis check` enforces the **reviewed** rules, not the rules in the pull request itself: a rule is enforced locally once it is in the base (committed, when there is no `origin/HEAD`), so a pull request that deletes a rule and breaks it now fails plain `check` too. Where `origin/HEAD` does not resolve, as in a checkout that does not set it, the base is the checked-out commit itself. Run `aegis check --ci` as a required pull-request check: it compares gates and invariants against the base branch and passes a governance weakening only with a signed `aegis approve` commit (at tier B that holds only while the pull request leaves `.github/workflows/**` and aegis alone), while `aegis_scan` serves mandatory rules from the reviewed base commit.

<details>
<summary>Trust Tiers (A/B/C) & Solo SSH Signing Ceremony (allowed_signers)</summary>

- **Tier A (Separation of duties)**: GitHub branch protection / rulesets require pull-request reviews from a human `CODEOWNERS` reviewer and required status checks (`aegis check --ci`) before merge.
- **Tier B (Solo developer with cryptographic signing)**: When one developer owns both the repo and the agent, `aegis approve` signs the governance tree hash (`Aegis-Approve: <hash>`) using your SSH key (`git config gpg.format ssh`), verified by `aegis check --ci` against `allowed_signers` at the repository root on the base branch. Only SSH signatures count, and Tier B holds only while pull requests leave `.github/workflows/**` and aegis alone, because the required check runs the pull request's own workflow.
- **Tier C (Self-attested)**: Local hooks and unsigned CI checks; `aegis doctor` reports the active tier read-only (`aegis doctor --github` inspects branch protection).
- **Hook & sandbox boundaries**: Pre-tool hooks block unscanned edits on Claude Code and trusted Codex CLI (`Antigravity` records only; shell edits pass everywhere; `aegis status --compliance` measures scan-before-edit rates). Aegis does not sandbox processes. Its own code opens no network connection; `aegis check --full --llm-cmd` and the commands that start your `gh` (listed in [PRIVACY.md](PRIVACY.md)) are the only ways it reaches one.

</details>

## FAQ

**How do I add guardrails to Claude Code?** Run `aegis init --host claude-code` in the repo. It registers the server at user scope and writes the `AGENTS.md` bootstrap (or adds `@AGENTS.md` to an existing `CLAUDE.md`). Run `aegis hook install --host claude-code` to add the pre-tool hook.

**How do I add guardrails to Codex CLI?** Run `aegis init --host codex-cli`. For the pre-tool hook, run `aegis hook install --host codex-cli` and trust the hook in Codex's `/hooks` screen.

**What is AGENTS.md?** A markdown instructions file in the repository root that coding agents (Codex CLI, Antigravity, Claude Code) read at session start. Aegis writes only a small bootstrap block into it; rules stay in `.aegis/rules/` and are served just-in-time via `aegis_scan`.

**Does Aegis send my code anywhere?** No. Aegis opens no network connection of its own, and the ledger stays in `.aegis/state/` on your machine. Two things can reach the network, both started by you: `aegis check --full --llm-cmd ...` pipes the diff to the command you name, and the commands listed in [PRIVACY.md](PRIVACY.md) run your own `gh`.

**I used Aegis 3.x. How do I upgrade?** Run `aegis migrate`, then `aegis migrate --apply`, `aegis init --host <your hosts>`, and `aegis doctor --fix`. See the [changelog](https://github.com/nseney1/Aegis-Guardrails/blob/main/CHANGELOG.md#upgrading-from-3x) for details.

## Documentation, contributing, security, license

- [How Aegis works](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md): the loop, rules, MCP delivery, checks, the ledger, hosts and enforcement.
- [Why Aegis is built this way](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/why-aegis.md): the evidence, what went wrong in v3, and the v4.3 trust and evidence model.
- [Reference](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/reference.md): every command, flag and MCP tool, generated from the code.
- Plan of record (ADR 0005, ADR 0006) and the [changelog](https://github.com/nseney1/Aegis-Guardrails/blob/main/CHANGELOG.md).
- [Contributing](https://github.com/nseney1/Aegis-Guardrails/blob/main/CONTRIBUTING.md) and [privacy](https://github.com/nseney1/Aegis-Guardrails/blob/main/PRIVACY.md).
- Security issues: report them privately as described in [SECURITY.md](SECURITY.md).

Apache 2.0. Copyright 2026 Nicholas Seney. See [LICENSE](https://github.com/nseney1/Aegis-Guardrails/blob/main/LICENSE) and [NOTICE](https://github.com/nseney1/Aegis-Guardrails/blob/main/NOTICE).
