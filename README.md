# Aegis Guardrails: project rules for Claude Code, Codex CLI and Antigravity

[![PyPI](https://img.shields.io/pypi/v/aegis-guardrails)](https://pypi.org/project/aegis-guardrails/)
[![Python](https://img.shields.io/pypi/pyversions/aegis-guardrails)](https://pypi.org/project/aegis-guardrails/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/nseney1/Aegis-Guardrails/blob/main/LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/nseney1/Aegis-Guardrails/blob/main/pyproject.toml)
[![CI](https://github.com/nseney1/Aegis-Guardrails/actions/workflows/validate.yml/badge.svg)](https://github.com/nseney1/Aegis-Guardrails/actions/workflows/validate.yml)

Aegis gives Claude Code, Codex CLI and Antigravity the project rules for the files they are about to edit, then checks the result with `aegis check` in a git pre-commit hook and in CI. It is a Model Context Protocol (MCP) server (`aegis-mcp`) plus a CLI (`aegis`), with zero runtime dependencies.

Rules are short markdown files in `.aegis/rules/`, committed with your code. Aegis serves the rules that match each file before the agent edits it, checks forbidden patterns at commit and in CI, and records evidence for human review. An instructions file alone depends on the agent remembering it; Aegis adds checks for the parts you can express as code patterns.

In one coding session, 749 of 1,339 agent steps were rework. That single-developer observation motivated Aegis; it is not a measured productivity gain. See [Why Aegis is built this way](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/why-aegis.md) for the evidence and its limits.

## Quick start

Aegis runs a **3-step loop** in any git repository with Python 3.9 or newer:

1. **Step 1 — Install & initialize**: Install `aegis-guardrails` (`pipx install aegis-guardrails` or `pip install aegis-guardrails`) and run `aegis init` in your repo to write the `AGENTS.md` bootstrap, register `aegis-mcp` with your hosts, and install the `pre-commit` hook.
2. **Step 2 — Scan before edit**: Your coding agent calls `aegis_scan` over MCP before editing files to receive just-in-time rules matched to those paths.
3. **Step 3 — Block bad commits in Git & CI**: `aegis check` runs automatically in the `pre-commit` hook and in CI to block forbidden AST patterns and, with `aegis check --ci`, rule weakenings.

```bash
pipx install aegis-guardrails            # or: pip install aegis-guardrails
cd my-app
aegis init --host claude-code,codex-cli   # or --host auto: every supported host found on this machine
```

<details>
<summary>Troubleshooting install & PATH (PEP 668, ~/.local/bin, virtualenv)</summary>

If pip stops with `externally-managed-environment` (PEP 668, as many Linux distributions and Homebrew Python do), run `pipx install aegis-guardrails` or install into a virtual environment. If your shell then says `aegis: command not found`, run `pipx ensurepath` after a pipx install, activate the virtual environment, or run the script by its full path (on Linux `~/.local/bin/aegis` after `pip install --user`); `aegis init` and `aegis doctor` print the PATH fix for your shell. Do not fall back to `python3 -m aegis_cli` inside a repository: `-m` imports from the current directory first.

</details>

`aegis init` prints its plan and asks before writing. It preserves your text outside its marked `AGENTS.md` block. The standard preset adds five advisory starter personas; set their `target_paths` to activate them.

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

`aegis check` enforces the **reviewed** rules: a rule is enforced locally once it is in the base (committed, when there is no `origin/HEAD`; on the branch `origin/HEAD` points to, when there is one). Commit `.aegis/` and `AGENTS.md` before you try it (`.aegis/state/` is git-ignored, and the outcome ledger lives in your git directory, outside the working tree):

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

`checkpoint: all checks passed` comes from a repository-wide hygiene scan (a test file for each source file, hard-coded paths, rule conventions) that warns unless you pass `--strict`; a gate or invariant rule that does not use `enforcement: gate` and a rule file that cannot be loaded always fail. The `FAILED` line is Layer 1's verdict, which includes the checkpoint, and it sets the exit code.

Run `aegis doctor` to check registrations. `git commit --no-verify` skips the local hook, so also run the checks in CI. `aegis init --ci` writes `.github/workflows/aegis.yml`, pinned to the Aegis version that generated it: its check job runs `aegis check` and `aegis check --ci` with `contents: read`, `pull-requests: read` and `GH_TOKEN`. Make that job required. See [CI governance](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md#ci-governance) for base-branch review and test-credit setup.

## Works with your agents

| Host | Setup | Status |
|---|---|---|
| **Claude Code** | `aegis init --host claude-code` | User-scope MCP; `AGENTS.md`, or an `@AGENTS.md` block in an existing `CLAUDE.md` |
| **Codex CLI** | `aegis init --host codex-cli` | User-scope MCP and `AGENTS.md` |
| **Antigravity** (app, IDE and `agy`) | `aegis init --host antigravity` | Config-file MCP; run init once per repo on each machine because the host sends no workspace |
| **Kiro, Cursor, GitHub Copilot, Windsurf** | `aegis init --host kiro,cursor,copilot,windsurf` | Experimental registrations; not checked on real installs; no Aegis pre-tool hooks |
| **Gemini CLI** | Retired; `aegis init --host gemini-cli` exits 2 | Use Antigravity (`--host antigravity`) instead |

`--host auto` discovers supported hosts from CLIs, config directories and app bundles. CLI, IDE and desktop surfaces share registrations where the host supports them. See [Hosts and hooks](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/hosts-and-hooks.md) for file paths, instruction limits, platform gaps and safe repair.

## How it works

1. **Bootstrap.** `aegis init` writes a small `AGENTS.md` block and registers the MCP server.
2. **Scan.** The agent calls `aegis_scan` with the paths it will edit. Mandatory rules come from the reviewed base; the response lists omitted mandatory rules too.
3. **Edit and verify.** Run the project's checks. An optional `aegis check --record --tests` records an isolated test run for the exact git tree. If the scan returned rule IDs, the agent can report them with `aegis_report_outcome`; if none matched, skip that report. Never invent IDs.
4. **Commit and review.** The hook checks staged content; CI checks the commit and governance changes. Optional Layer 2 model review is advisory.
5. **Review the evidence.** `aegis sync` derives fitness and suggests lifecycle changes. A person reviews and applies them; Aegis never promotes rules automatically.

Passing a check, recording a test run and earning CI-confirmed rule credit are separate results. The current test runner recognizes pytest/JUnit evidence, with limited text-summary fallback; configuring a mixed Rust/Python or unittest command does not add reliable combined receipts. See [Evidence and outcomes](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md#evidence-and-outcomes).

Read [How Aegis works](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md) for the concepts and examples, or [Architecture](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/architecture.md) for components and data flow.

## What's included

- **A CLI** with 15 commands (`init`, `uninstall`, `doctor`, `migrate`, `check`, `approve`, `scan`, `status`, `rule`, `sync`, `hook`, `team`, `skills`, `benchmark`, `package`) and **an MCP server** with 5 tools (`aegis_scan`, `aegis_report_outcome`, `aegis_create_rule`, `aegis_list_rules`, `aegis_capture_insight`).
- **12 starter [rules](https://github.com/nseney1/Aegis-Guardrails/tree/main/rules)**: grounding claims in code, dry runs before destructive commands, behavioral tests, TDD, git hygiene and more (`aegis init --rules minimal|standard|full` seeds 2, 5 or all 12; set `target_paths` to activate them).
- **15 [skills](https://github.com/nseney1/Aegis-Guardrails/tree/main/skills)**: `SKILL.md` playbooks synced by `aegis skills sync` (or `aegis init --skills`) into `.claude/skills/` and `.agents/skills/`.
- **Built-in security checks**: a seven-rule Python security pack and a known-format secret scan run in every `aegis check` on what your change adds (`# aegis: allow[rule]` and `# gitleaks:allow` suppress a finding).
- **Multi-language AST checks**: Python (in-process), plus packaged drivers for Rust, TypeScript/JavaScript (`node`) and Go (`go`).
- **A Python SDK facade**, `aegis_sdk.Governance`, for tools that query rules and fitness.

## Agent teams

When parallel agents work in separate worktrees (lanes), declare each lane's path scope with `aegis team claim docs --paths 'docs/**' README.md`. A lease is cooperative conflict input — not a lock, not an identity, and not proof an agent is still running — and overlapping live claims are refused.

Verify containment with `aegis check --lane docs`: every path changed since the merge base must stay inside the lane's scope, and no Python test may disappear or gain a skip. With a lease or `--paths` the check is self-attested; with `--base-policy` it reads `.aegis/team.json` from the base branch and is witnessed. In CI it is advisory (not a required check). See [Agent teams](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/teams.md) for lease refs and `aegis team metrics`.

## Limits and trust

Aegis checks explicit patterns; a rule written only as prose remains guidance. Python AST matching is syntactic, not a proof about runtime behavior. Packaged drivers need their runtimes and activation; unparsed TypeScript/JavaScript and Go files are skipped when no driver is enabled.

`aegis doctor` reports four enforcement tiers:

| Tier | Mechanism | Limit |
|---|---|---|
| Advisory | AGENTS.md bootstrap, MCP instructions, JIT rules | The agent can ignore guidance |
| Best-effort | per-host pre-tool hooks | Fail open on Aegis errors; shell edits bypass edit checks; host support varies |
| Local floor | git pre-commit runs aegis check --hook (--no-verify bypasses it) | The committer can skip the hook |
| Authoritative | CI runs aegis check on the exact SHA; a human merges | Depends on protected checks and review of governance and workflow changes |

Plain `aegis check` enforces reviewed rules where `origin/HEAD` resolves: a pull request that deletes a rule and breaks it fails plain `check` there. Without that ref, as in CI's checkout, plain `check` enforces the pull request's own rules and `aegis check --ci` is what catches a deleted or weakened rule. Make both checks required.

The trust tiers describe protection of the rules themselves: **C** is self-attested, **B** uses an SSH approval key the agent cannot use, and **A** adds an independent code-owner review. With no key in the base's `allowed_signers`, governance-file changes pass with a note; rule weakening still fails unless a qualifying Tier A review approves it. Tier B holds only while the pull request leaves Aegis and `.github/workflows/**` alone. `aegis doctor --github` shows the setup without changing it. See [Trust tiers](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/trust-tiers.md).

Aegis does not sandbox processes or authenticate its mutable local ledger. CI-confirmed checks and detector replay inform fitness, but promotion requires reviewed human labels and sufficient breadth. [Evidence and outcomes](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md#evidence-and-outcomes) explains the thresholds and remaining limits.

## FAQ

**How do I add guardrails to Claude Code?** Run `aegis init --host claude-code` in the repo. It registers the server at user scope and writes the `AGENTS.md` bootstrap (or adds `@AGENTS.md` to an existing `CLAUDE.md`). Run `aegis hook install --host claude-code` to add the pre-tool hook.

**How do I add guardrails to Codex CLI?** Run `aegis init --host codex-cli`. For the pre-tool hook, run `aegis hook install --host codex-cli` and trust the hook in Codex's `/hooks` screen.

**Claude Code ignoring CLAUDE.md?** A `CLAUDE.md` is advice in the model's context, and nothing checks that Claude Code followed it. Claude Code reads `AGENTS.md` only when the repository has no `CLAUDE.md`, so `aegis init` adds an `@AGENTS.md` block to an existing one (`aegis doctor` flags a `CLAUDE.md` that shadows `AGENTS.md`). Aegis then puts the matching rules in front of the agent when it edits, the pre-tool hook (`aegis hook install --host claude-code`) blocks unscanned edits and destructive commands (it fails open on any Aegis error and does not see edits made through shell commands), and `aegis check` blocks banned patterns at commit and in CI.

**How do I enforce AGENTS.md rules?** An `AGENTS.md` is read by the agent, not enforced. Keep it short and put every rule a `forbid_ast` pattern can express into `.aegis/rules/`, like the `no-eval` example above: `aegis check` then fails the commit and the CI run, and a required `aegis check --ci` fails a pull request that weakens the rule. A rule without `forbid_ast` stays guidance that `aegis_scan` serves to the agent.

**What is AGENTS.md?** A markdown instructions file in the repository root that coding agents (Codex CLI, Antigravity, Claude Code) read at session start. Aegis writes only a small bootstrap block into it; rules stay in `.aegis/rules/` and are served just-in-time via `aegis_scan`.

**Does Aegis send my code anywhere?** Not by itself. Aegis opens no network connection of its own, and the ledger stays on your machine, in your git directory. Three things can reach the network, all started by you: `aegis check --full --llm-cmd ...` pipes your plan, the source of the changed non-test Python files (not the diff; `__init__.py` is skipped), the test output and the Layer 1 results to the command you name; the commands listed in [PRIVACY.md](https://github.com/nseney1/Aegis-Guardrails/blob/main/PRIVACY.md) run your own `gh`; and `aegis sync --pr` pushes one branch to your remote. Your agent host sends what Aegis returns to its own model provider.

**I used Aegis 3.x. How do I upgrade?** Run `aegis migrate`, then `aegis migrate --apply`, `aegis init --host <your hosts>`, and `aegis doctor --fix`. See the [changelog](https://github.com/nseney1/Aegis-Guardrails/blob/main/CHANGELOG.md#upgrading-from-3x) for details.

## Documentation, contributing, security, license

- [How Aegis works](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/how-it-works.md): the loop, rules, MCP delivery, checks, the ledger, hosts and enforcement.
- [Architecture](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/architecture.md), [hosts and hooks](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/hosts-and-hooks.md), and [agent teams](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/teams.md): focused setup and design guides.
- [Why Aegis is built this way](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/why-aegis.md): the evidence, what went wrong in v3, and the trust and evidence model.
- [Trust tiers](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/trust-tiers.md): what each tier protects and how to set up your repository for it.
- [Reference](https://github.com/nseney1/Aegis-Guardrails/blob/main/docs/reference.md): every command, flag and MCP tool, generated from the code.
- The [changelog](https://github.com/nseney1/Aegis-Guardrails/blob/main/CHANGELOG.md).
- [Contributing](https://github.com/nseney1/Aegis-Guardrails/blob/main/CONTRIBUTING.md) and [privacy](https://github.com/nseney1/Aegis-Guardrails/blob/main/PRIVACY.md).
- Security issues: report them privately as described in [SECURITY.md](https://github.com/nseney1/Aegis-Guardrails/blob/main/SECURITY.md).

Apache 2.0. Copyright 2026 Nicholas Seney. See [LICENSE](https://github.com/nseney1/Aegis-Guardrails/blob/main/LICENSE) and [NOTICE](https://github.com/nseney1/Aegis-Guardrails/blob/main/NOTICE).

<!-- mcp-name: io.github.nseney1/aegis-guardrails -->
