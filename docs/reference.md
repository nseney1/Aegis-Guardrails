# Aegis reference

Every `aegis` command and option, and every tool the `aegis-mcp` server offers, with
its input schema. This page is generated from the contract snapshots
(`tests/contract/cli_tree.json` and `tests/contract/mcp_tools.json`) by
`tests/contract/gen_reference.py`, and a test fails when it drifts from them. Do not
edit it by hand: change the code, then regenerate the snapshots and this page:

```
PYTHONPATH=. python3 tests/contract/test_cli_contract.py --write
PYTHONPATH=. python3 tests/contract/test_mcp_contract.py --write
PYTHONPATH=. python3 tests/contract/gen_reference.py --write
```

## Command line: `aegis`

Aegis Governance — make AI coding agents trustworthy

### Global options

Every command also accepts `-h/--help`, `--json`, `--plain` and `--workspace`.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `-h`, `--help` |  |  | show this help message and exit |
| `--json` |  |  | Emit machine-readable JSON output |
| `--plain` |  |  | Strip ANSI styling and emoji |
| `--workspace` | `WORKSPACE` |  | Target workspace root |
| `--version` |  |  | show program's version number and exit |

### Commands

| Command | Category | Description |
| --- | --- | --- |
| `aegis doctor` | Setup & Environment | System health and governance audit |
| `aegis init` | Setup & Environment | Set up governance for this project and register it with your agent hosts |
| `aegis migrate` | Setup & Environment | Convert a v3 or .soma workspace to the v4 layout (dry run unless --apply) |
| `aegis package` | Setup & Environment | Write an experimental Claude Code plugin directory (MCP server, hook, skills); nothing is published |
| `aegis skills` | Setup & Environment | Copy the packaged skills into your hosts' project skills folders (sync) |
| `aegis uninstall` | Setup & Environment | Remove Aegis from this workspace's hosts, AGENTS.md/CLAUDE.md and git hook (keeps .aegis/) |
| `aegis approve` | Daily Workflow & Verification | Sign a human approval of this branch's governance changes |
| `aegis check` | Daily Workflow & Verification | Verify changes: Layer 1 checks, plus a Layer 2 model review with --full |
| `aegis scan` | Daily Workflow & Verification | Show which rules apply to the given files (run before editing them) |
| `aegis status` | Daily Workflow & Verification | Show active rules and stats |
| `aegis team` | Daily Workflow & Verification | Lease lane paths for parallel agents (claim, renew, transfer, release, gc, list, metrics) |
| `aegis rule` | Rule Evolution & Intelligence | Manage rule lifecycle (list, create, promote, demote, archive) and share rules as unsigned packs |
| `aegis sync` | Rule Evolution & Intelligence | Rebuild rule fitness from the ledger and suggest promotions (--apply to apply them) |
| `aegis benchmark` | Plumbing | Measure scan and hook latency, payload size and Layer 1 throughput (not an efficacy measure) |
| `aegis hook` | Plumbing | Install, inspect or remove the git pre-commit hook and the agent hosts' PreToolUse hooks |

### `aegis doctor`

System health and governance audit

Read-only health checks, the host matrix (binary, registration, identity, workspace, bootstrap, budget per host) and the enforcement tiers in force here. --fix changes only what doctor reported (stale v3 and misplaced MCP entries, v3 hook entries, legacy rule blocks, unedited v3 rule copies, missing packaged AST drivers), after confirmation, backing each file up to ~/.aegis/backups/<UTC stamp>/ first.

Category: Setup & Environment.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--fix` |  |  | Repair what doctor reported, after confirmation; every file is backed up first |
| `--yes` |  |  | With --fix: apply without asking (required with --json or without a terminal) |
| `--drivers` |  |  | Run only AST driver and language detection health check |
| `--github` |  |  | Print what trust tiers A and B need: the ruleset JSON, CODEOWNERS lines and signing setup |
| `--apply` |  |  | With --github --tier: create the ruleset through gh, only after a y/N at a terminal |
| `--release` | `SHA` |  | Verify that the CI verdict job attested this commit (gh attestation verify, gh >= 2.93.0; otherwise UNVERIFIED and a non-zero exit) |
| `--tier` | one of `A`, `B` |  | With --github --apply: which ruleset to create (A: reviews; B: solo, signed approvals) |

### `aegis init`

Set up governance for this project and register it with your agent hosts

Set up .aegis/ (config, starter rules, .gitignore), the Aegis block in AGENTS.md (and an @AGENTS.md block in an existing CLAUDE.md), the git pre-commit hook, and this workspace's entry in ~/.aegis/workspaces.json {"v": 1, "workspaces": [{root, added_at, added_by, hosts}]}, which only aegis init and aegis uninstall write. Hosts named with --host get the 'aegis' MCP server (codex-cli: codex mcp add; claude-code: claude mcp add --scope user; antigravity: ~/.gemini/config/mcp_config.json; kiro: ~/.kiro/settings/mcp.json). A new workspace also gets one active rule, the no-eval invariant; --ci writes the CI workflow .github/workflows/aegis.yml, which init otherwise only prints.

Category: Setup & Environment.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--host` | `HOST[,HOST]|auto` |  | Register the Aegis MCP server with these hosts, or 'auto' for the ones found on this machine (by CLI on PATH, config directory or desktop app). Without it, found hosts are only listed. A host is the config plane its surfaces share, so a surface name selects its host: codex-cli (Codex CLI, Codex IDE extension, ChatGPT desktop app (Codex mode); also codex, codex-ide, codex-app, chatgpt-desktop); claude-code (Claude Code CLI, Claude Code IDE extensions, Claude desktop app (Code tab); also claude-desktop-code); antigravity (Antigravity app, Antigravity IDE, agy CLI; also antigravity-app, antigravity-ide); kiro, experimental (Kiro IDE, Kiro CLI; also kiro-ide, kiro-cli); cursor, experimental (Cursor IDE, Cursor CLI (cursor-agent); also cursor-ide, cursor-cli); copilot, experimental (GitHub Copilot in VS Code (agent mode), GitHub Copilot CLI; also github-copilot, copilot-cli, vscode-copilot); windsurf, experimental (Windsurf IDE; also windsurf-ide) |
| `--rules` | one of `minimal`, `standard`, `full`, `none-active` | `"standard"` | Starter rules: guidance seeded into .aegis/rules/personas/ (minimal 2, standard 5, full every shipped one), which applies to no file until you set its target_paths; a new workspace also gets one active rule, the no-eval invariant in .aegis/rules/invariants/ (bans eval and exec in **/*.py). none-active seeds the standard guidance without it (default: standard) |
| `--dry-run` |  |  | Check and show every step without writing anything or running a host CLI |
| `--yes`, `-y` |  |  | Skip the confirmation prompt |
| `--force` |  |  | Replace Aegis blocks in AGENTS.md/CLAUDE.md even if they were edited by hand |
| `--pin` |  |  | Pin the host registrations to this workspace (AEGIS_WORKSPACE) |
| `--no-hooks` |  |  | Skip installing the git pre-commit hook |
| `--skills` |  |  | Also copy the packaged skills into the hosts' project skills folders (.claude/skills, .agents/skills), as aegis skills sync does |
| `--ci` |  |  | Also write .github/workflows/aegis.yml, a GitHub Actions workflow that runs aegis check on every pull request (CI is the floor: git commit --no-verify skips the pre-commit hook). Without it, init prints that workflow when no workflow runs aegis check |

### `aegis migrate`

Convert a v3 or .soma workspace to the v4 layout (dry run unless --apply)

Plan, then with --apply perform, the move to the v4 layout: the v3 ledger becomes .aegis/state/ledger.jsonl (v2 rows), aegis.conf/slots.yaml/config.yaml become .aegis/config.json, .soma cells move to .aegis/rules/<type>/, derived counters leave rule frontmatter and v3 runtime state is removed. Every changed file is backed up to .aegis/state/migrate-backup-<time>/ first; running it again changes nothing.

Category: Setup & Environment.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--apply` |  |  | Perform the migration (default: dry run) |
| `--dry-run` |  |  | Only report what would change (the default) |

### `aegis package`

Write an experimental Claude Code plugin directory (MCP server, hook, skills); nothing is published

Write a Claude Code plugin directory: .claude-plugin/plugin.json, the Aegis MCP server (.mcp.json), the pre-tool hook (hooks/hooks.json) and the packaged skills (skills/). Experimental: nothing is published, and the directory names absolute paths on this machine, so it works only here. Only --host claude-code is supported; the Gemini CLI is retired. In an Aegis workspace a real run appends one package event.

Category: Setup & Environment.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--host` | `claude-code` |  | The host to package for; only claude-code |
| `--out` | `DIR` |  | Where to write the plugin (default ./aegis-claude-plugin in the workspace); an existing directory must be empty or an earlier Aegis plugin |
| `--dry-run` |  |  | Report what would be written; write nothing |

### `aegis skills`

Copy the packaged skills into your hosts' project skills folders (sync)

Category: Setup & Environment. Subcommands: `sync`.

### `aegis skills sync`

Copy the packaged skills to .claude/skills (Claude Code) and .agents/skills (Codex CLI, Antigravity), replacing only Aegis's own unedited copies

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--host` | `HOST[,HOST]|auto` |  | Hosts to copy skills for (default: the hosts in .aegis/config.json); 'auto' takes the ones detected on this machine |
| `--force` |  |  | Also replace Aegis copies edited by hand (never a file without the Aegis marker, a link or anything outside the workspace) |
| `--dry-run` |  |  | Report what would change; write nothing |

### `aegis uninstall`

Remove Aegis from this workspace's hosts, AGENTS.md/CLAUDE.md and git hook (keeps .aegis/)

Remove the git pre-commit hook block, the Aegis blocks in AGENTS.md and CLAUDE.md, this workspace's entry in ~/.aegis/workspaces.json and the Aegis MCP registration (including the v3 name) of the hosts it was registered with. A host that another registered workspace still lists keeps its registration unless named with --host. Never deletes .aegis/.

Category: Setup & Environment.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--host` | `HOST[,HOST]` |  | Unregister these hosts even if another workspace uses them (default: the hosts this workspace was registered with) |
| `--dry-run` |  |  | Show what would be removed without changing anything |
| `--force` |  |  | Also remove Aegis blocks that were edited by hand |

### `aegis approve`

Sign a human approval of this branch's governance changes

Makes one signed, empty commit 'Aegis-Approve: <governance tree hash>' naming the governance files as committed at HEAD. Refuses when nothing governance-related changed since the base branch, when anything is staged or uncommitted, and without a terminal. The signing key, format and program come from your user-level git config (gpg.format ssh); no key is created.

Category: Daily Workflow & Verification.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--base` | `REF` |  | The base branch to measure governance changes against (default: origin/main, main, origin/develop, develop) |
| `--exempt-test` | `COMMIT` |  | Sign a test exemption (Aegis-Exempt-Test) for a specific fix commit |
| `--reason` | `TEXT` |  | Explanation for --exempt-test (signed into the commit) |

### `aegis check`

Verify changes: Layer 1 checks, plus a Layer 2 model review with --full

Category: Daily Workflow & Verification.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `files` | `[FILES ...]` |  | Files to check (default: changed against HEAD, staged, or against the branch base) |
| `--hook` |  |  | Git pre-commit mode: Layer 1 only, never a model call |
| `--strict` |  |  | Fail on checkpoint warnings too (missing tests, hardcoded paths, stub tests...) |
| `--full` |  |  | Add Layer 2: adversarial review of the change by the --llm-cmd model |
| `--plan` | `TEXT` |  | Task plan for Layer 2 (implies --full) |
| `--plan-file` | `PATH` |  | File holding the task plan (implies --full) |
| `--llm-cmd` | `CMD` |  | Layer 2 model command, e.g. 'claude -p': gets the prompt on stdin, prints the reply. It runs in an empty temporary directory, never the repository, so give scripts absolute paths (default: $AEGIS_LLM_CMD; never read from repository files) |
| `--dry-run` |  |  | Show what would be checked without running anything |
| `--record` |  |  | Bind the work tree to a git tree, run Layer 1 on an exported snapshot of it and write one ledger check row (witness: aegis). A label, not proof: only CI on the landing commit confirms it. A tree git cannot see completely (assume-unchanged or skip-worktree files) or that holds symbolic links is unbindable and writes no row; exit 0 only when the run passed |
| `--tests` |  |  | With --record: also run the test command from the user-scope config (tests.command in ~/.aegis/config.json, default python -m pytest, never the repository's) in the snapshot with a fixed environment; exit 5 or zero passed tests is never evidence |
| `--format` | one of `text`, `json`, `github`, `sarif` | `"text"` | Output format (github, with --ci only: workflow-command annotations) |
| `--lane` | `LANE` |  | Post-lane gate: check the lane's commits since merge-base(--base, HEAD) for containment (every changed path, deletions and both sides of a move included, inside the lane's globs) and Python test integrity (removed tests, added skips or xfails, pytest collection changes; assert weakening is not detected). Any finding fails. Self-attested from the live lease or --paths; witnessed with --base-policy. As a CI job it is advisory in v4.1, and a witness is only as strong as the protection on .github/** and on the base branch |
| `--partition` |  |  | Report the cross-lane call, def and import edges between lanes planned with --split (at least two), and the [FROZEN_SIGNATURES] of the functions that cross a lane boundary. Python, and Rust when its driver is enabled. A report: it changes nothing and exits 0 even when it finds edges |
| `--card` |  |  | Print the day-0 card: languages, AST drivers, rules by type, the Layer 1 pass rate on the files and the 5 files with the most findings (above 2000 files it samples, and says so). Changes nothing and never reads baseline.json; --json for the machine-readable form |
| `--write-baseline` |  |  | Record every current Layer 1 finding in .aegis/baseline.json, so that aegis check then fails only on new ones. Findings are fingerprinted by rule, path, matched line and its occurrence, not by line number. A failure that is not about a line (a rule that cannot load, a file that cannot be parsed) is listed and is never recorded |
| `--prune-baseline` |  |  | Drop the entries of .aegis/baseline.json whose findings are fixed (or whose file is gone). It never adds a finding, and it refuses to run while a check cannot run |
| `--ci` |  |  | The CI weakening check: compare the rules that bind (gates, invariants, enforcement: gate) at merge-base(--base, --head) with those at --head, and flag every way one binds less (a deletion or archive, a rank decrease, a target_paths pattern no longer kept or a file moved out of reach, a forbid_ast pattern or call entry no longer covered, a new or unknown key, any applies_to change, or a mandatory rule widened or added past the scan's slot cap), or a change to the governance set (when the base lists a signing key). A flagged change passes only with a signed Aegis-Approve commit (aegis approve) by a key in the base branch's allowed_signers. Also runs T5 fix-commit regression checks (advisory at default warning tier; blocking at gate tier via --strict or user config regression.tier="gate"). Exit 0 pass, 1 fail |
| `--head` | `REF` |  | With --ci: the commit under review (default: the pull request head in $GITHUB_EVENT_PATH, else HEAD) |
| `--split` | `NAME=GLOB[,GLOB...]` |  | With --partition: one planned lane and the globs of its files; give at least two. They match as rule target_paths do: a glob without '/' matches at any depth |
| `--base` | `REF` |  | With --ci: the pull request's base (default: its base.sha in $GITHUB_EVENT_PATH, else as below). With --lane: the base branch (default: origin/$GITHUB_BASE_REF, $GITHUB_BASE_REF, origin/main, main, origin/develop or develop). A shallow clone fails: fetch with fetch-depth 0. Without --lane: read .aegis/baseline.json from REF (label baseline: base@<sha>; absent there means empty: baseline: absent at base) and check what changed since REF; the working tree's baseline is then not consulted, and a REF that does not resolve is an error. Without --base the working tree's baseline is used and labelled self-attested: a candidate can edit its own. There is no CI detection |
| `--paths` | `GLOB [GLOB ...]` |  | With --lane: the lane's globs instead of its live lease (self-attested). They match as rule target_paths do: a glob without '/' matches at any depth, so CHANGELOG.md also admits docs/CHANGELOG.md. They never allow .aegis/** or .github/workflows/** |
| `--base-policy` |  |  | With --lane: take lanes.<lane> and shared from .aegis/team.json at the base tip, never the candidate; refuses --paths. Only then is the result 'witnessed: base policy', and only then may .aegis/** and .github/workflows/** change |
| `--coverage` |  |  | With --ci: run pytest with diff coverage over changed lines |
| `--perf` |  |  | With --ci: run performance regression check |

### `aegis scan`

Show which rules apply to the given files (run before editing them)

Category: Daily Workflow & Verification.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `files` | `FILE [FILE ...]` |  | File(s) you are about to edit (required) |

### `aegis status`

Show active rules and stats

Category: Daily Workflow & Verification.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--compliance` |  |  | Show the per-host scan-before-edit rate from the MCP activity log (.aegis/state/activity.jsonl), per session and per host. Edits are the files a session named in aegis_report_outcome 'files' plus the files of commits inside exactly one session's window (first to last event, plus 15 minutes). Limits: an edit time is an upper bound (report or commit time), so the rate can overstate compliance; uncommitted edits that were never reported are not seen; commits in overlapping sessions count as ambiguous, not as misses; a session with no observed edit is unknown, never 0. A host rate is an aggregate over sessions, not a per-attempt verdict. Reads only. |

### `aegis team`

Lease lane paths for parallel agents (claim, renew, transfer, release, gc, list, metrics)

Leases under refs/aegis/lanes/<lane> declare which paths a lane works on. A lease is cooperative conflict input, not a lock, not an identity and not proof that an agent is alive: claims of different lanes can race, and owner and role are display labels. The backstops are the post-lane gate (aegis check --lane) and aegis team metrics.

Category: Daily Workflow & Verification. Subcommands: `claim`, `gc`, `list`, `metrics`, `release`, `renew`, `transfer`.

### `aegis team claim`

Lease a lane's paths; prints the lease oid

Refuse when a live lease of another lane may overlap the paths; otherwise create the lane's lease, or take over its expired lease. Prints the new lease oid.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `lane` | `LANE` |  | Lane name: [a-z0-9][a-z0-9._-]{0,62} (required) |
| `--paths` | `GLOB [GLOB ...]` |  | Globs the lane will change (the conflict scope) |
| `--role` | `ROLE` |  | Display label (default: implementer) |
| `--owner` | `OWNER` |  | Display label (default: <user>@<hostname>) |
| `--ttl` | `SECONDS` | `3600` | Seconds until the lease expires, at most 86400 |
| `--branch` | `BRANCH` |  | The lane's branch, recorded for display |

### `aegis team gc`

Delete expired leases

Delete every expired lease by compare-and-swap; unreadable leases are kept.

### `aegis team list`

Show leases (conflict input, not liveness proof)

A lease is conflict input, not liveness proof: it records which paths a lane declared and until when, not that its agent is still working. The backstops are the post-lane gate (aegis check --lane) and aegis team metrics.

### `aegis team metrics`

Lease events and merge outcomes

Claims and denials from the events log, and for each first-parent merge since --base: whether both sides changed a common path and whether git merge-tree reports a conflict (unavailable before git 2.38). GitHub's synthetic refs/pull/*/merge commits are excluded.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--base` | `REF` |  | Count merges since this commit (default: the branch base, as for aegis check --lane: origin/main, main, origin/develop or develop; with none, the whole first-parent history) |

### `aegis team release`

Delete a lease

Delete a lease by compare-and-swap. Anyone may release; the events log records the caller.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `lane` | `LANE` |  | Lane name: [a-z0-9][a-z0-9._-]{0,62} (required) |
| `--expect` | `OID` |  | The lease oid the lane must hold now (printed by claim, renew, transfer and list) |

### `aegis team renew`

Extend a lease; prints the new lease oid

Renew by compare-and-swap; an expired lease is re-claimed, overlap check included.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `lane` | `LANE` |  | Lane name: [a-z0-9][a-z0-9._-]{0,62} (required) |
| `--expect` | `OID` |  | The lease oid the lane must hold now (printed by claim, renew, transfer and list) |
| `--ttl` | `SECONDS` |  | New lifetime in seconds, at most 86400 (default: keep it) |

### `aegis team transfer`

Give a live lease to another owner

Change a live lease's owner (and role) by compare-and-swap.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `lane` | `LANE` |  | Lane name: [a-z0-9][a-z0-9._-]{0,62} (required) |
| `--expect` | `OID` |  | The lease oid the lane must hold now (printed by claim, renew, transfer and list) |
| `--owner` | `OWNER` |  | The new owner label |
| `--role` | `ROLE` |  | The new role label (default: keep it) |

### `aegis rule`

Manage rule lifecycle (list, create, promote, demote, archive) and share rules as unsigned packs

Category: Rule Evolution & Intelligence. Subcommands: `adjudicate`, `archive`, `create`, `demote`, `export`, `import`, `insight`, `list`, `promote`.

### `aegis rule adjudicate`

Record an adjudication label (tp or fp) in .aegis/adjudications/; it counts after it is merged to the base branch

Append a tp or fp label for a rule to .aegis/adjudications/<rule-id>.jsonl. The label counts toward the rule's fitness only after a reviewed pull request merges it to the base branch.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `rule_id` | `RULE_ID` |  | Rule identifier to adjudicate (required) |
| `verdict` | one of `tp`, `fp` |  | Adjudication verdict (tp or fp) (required) |
| `--ref` | `REF` |  | Optional commit SHA, PR number, or issue reference |
| `--summary` | `SUMMARY` |  | Optional one-line summary of the adjudicated example |
| `--file` | `FILE` |  | Optional file path where the rule applied |
| `--line` | `LINE` |  | Optional line number in --file |
| `--session` | `SESSION` |  | Optional session identifier |
| `--repo` | `REPO` |  | Optional repository identifier |

### `aegis rule archive`

Archive rules whose ledger evidence says they misfire

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--dry-run` |  |  | Report the rules that would be archived; move nothing |

### `aegis rule create`

Create a new governance rule

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `-t`, `--type` | `TYPE` | `"trap"` | Rule type (invariant, trap, gate, boundary, persona, contract) |
| `--hypothesis` | `HYPOTHESIS` | `""` | Testable rule hypothesis |
| `-p`, `--prediction` | `PREDICTION` | `""` | Expected outcome when hypothesis holds |
| `-f`, `--falsification` | `FALSIFICATION` | `""` | Criteria that falsify the rule |
| `-d`, `--domain` | `DOMAIN` | `"correctness"` | Governance domain |
| `-e`, `--enforcement` | `ENFORCEMENT` |  | Enforcement tier (gate, advisory) |
| `-n`, `--name`, `--id` | `ID` |  | Explicit rule ID stem |
| `--target-paths` | `TARGET_PATHS` | `""` | Comma-separated target path globs |
| `--tags` | `TAGS` | `""` | Comma-separated tags |
| `--body-file` | `PATH` |  | Rule body (markdown after the frontmatter) from PATH, or '-' for stdin; max 64 KiB |

### `aegis rule demote`

Demote a rule down lifecycle tiers (no RULE_ID: list candidates)

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `rule_id` | `[RULE_ID]` |  | Rule identifier to demote |
| `--dry-run` |  |  | Preview demotion without moving files |

### `aegis rule export`

Write the workspace's rules to an unsigned pack file

Write the workspace's rules to OUT as a pack: their text and digests, no ledger rows. The pack is unsigned: its sha256 shows it was not altered after export, not who made it. A rule that cannot be loaded, or that still has derived or retired keys (run aegis migrate --apply), stops the export; an expired rule is skipped and reported. An existing regular file at OUT is replaced; a link is refused.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `out` | `OUT` |  | The pack file to write (required) |
| `--type` | one of `invariant`, `trap`, `gate`, `boundary`, `persona`, `contract` |  | Export only rules of this type (repeatable): invariant, trap, gate, boundary, persona, contract |
| `--min-fitness` | `X` |  | Export only rules whose fitness in this repository's ledger is at least X |

### `aegis rule import`

Add the rules of an unsigned pack file to the workspace

Add the rules of PACK to the workspace's .aegis/rules. The pack is unsigned: its digests show it was not altered after export, not who made it, so every entry is checked (its path must be exactly <type dir>/<id>.md, and the rule loader must accept it) and the pack is imported whole or not at all. An id the workspace already has refuses the pack unless --rename gives the incoming rule a free id. With --workspace DIR, DIR itself must hold .aegis (there is no walk-up from it). Review the imported rules before you rely on them.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `pack` | `PACK` |  | The pack file to read (required) |
| `--rename` |  |  | Give a rule whose id is taken a free id (<id>-imported, -imported-2, ...) instead of refusing |
| `--dry-run` |  |  | Check the pack and report what would be added; write nothing |

### `aegis rule insight`

Capture, review, and enable human correction insights (add, review, enable)

Subcommands: `add`, `enable`, `review`.

### `aegis rule insight add`

Record an explicit human correction insight

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `text` | `TEXT` |  | Correction insight text (redacted and capped at 300 chars) (required) |
| `--paths` | `[PATHS ...]` |  | Target file paths (default: git dirty set) |
| `--kind` | `KIND` |  | Optional insight category or kind |
| `--commit` | `COMMIT` |  | Optional signed commit SHA carrying Aegis-Approve-Insight |
| `--base-ref` | `BASE_REF` |  | Optional base branch reference for --commit |

### `aegis rule insight enable`

Opt-in enable UserPromptSubmit insight capture for a host

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--host` | one of `claude-code`, `codex-cli` |  | Host to configure (claude-code or codex-cli) |
| `--excerpts` |  |  | Also store redacted <=300 char excerpts on correction cues (default: counters/heartbeats only) |

### `aegis rule insight review`

Cluster and review insights or record a decision

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--decision` | one of `propose`, `reject`, `snooze`, `merge-into-rule`, `noise` |  | Record a review decision for a cluster |
| `--cluster` | `CLUSTER_ID` |  | Cluster ID for --decision |
| `--proposal-id` | `PROPOSAL_ID` |  | Proposal ID when --decision propose |
| `--category` | `CATEGORY` | `"correctness"` | Proposal category when --decision propose |
| `--summary` | `SUMMARY` |  | Closed-template summary bullet when --decision propose |
| `--rule` | `RULE_ID` |  | Target rule ID for merge-into-rule or recurrence check |
| `--reason` | `REASON` |  | Optional reason for the decision |

### `aegis rule list`

List active rules and fitness metrics

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--type` | one of `invariant`, `trap`, `gate`, `boundary`, `persona`, `contract` |  | Filter by rule type |
| `--min-fitness` | `MIN_FITNESS` |  | Filter by minimum fitness score |

### `aegis rule promote`

Promote a rule up lifecycle tiers (no RULE_ID: list candidates)

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `rule_id` | `[RULE_ID]` |  | Rule identifier to promote |
| `--tier-check` |  |  | Evaluate enforcement tier transitions |
| `--dry-run` |  |  | Preview promotion without moving files |

### `aegis sync`

Rebuild rule fitness from the ledger and suggest promotions (--apply to apply them)

Category: Rule Evolution & Intelligence.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--apply` |  |  | Apply the suggested promote/demote/archive transitions (moves rule files) |
| `--pr` |  |  | Apply decided transitions and open a pull request with the evidence report (never auto-merges) |

### `aegis benchmark`

Measure scan and hook latency, payload size and Layer 1 throughput (not an efficacy measure)

Time the aegis_scan answer (latency p50/p95, payload bytes, approximate tokens), the `aegis hook run pre-tool` hook as a host starts it (a fresh Python process), and Layer 1 throughput (files per second), on a built-in fixture corpus in a temporary directory: nothing in your repository is read or written. It appends one benchmark event to this workspace's events log. This is not an efficacy measure: it says nothing about whether Aegis makes an agent's code better. Compare only runs of the same corpus (its sha256 is in the output) on the same machine.

Category: Plumbing.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--runs` | `N` | `20` | Timed runs of each measurement, 1 to 1000 (default 20); one untimed warm-up of the hook and Layer 1 comes first |

### `aegis hook`

Install, inspect or remove the git pre-commit hook and the agent hosts' PreToolUse hooks

Category: Plumbing. Subcommands: `install`, `run`, `safety-gate`, `status`, `uninstall`.

### `aegis hook install`

Install the git pre-commit hook, or with --host an agent host's PreToolUse hook

Without --host: install the git pre-commit hook (it runs aegis check --hook). With --host claude-code\|codex-cli\|antigravity: register `aegis hook run pre-tool --host <h>` as that host's PreToolUse hook, at user scope (default) or, with --scope project, in the repository's host file, which teammates' hosts will execute. The merge keeps everything else in the file, refuses unparseable, symlinked or hard-linked files, and backs the old file up to ~/.aegis/backups/<stamp>/<scope>/. Codex also gets ~/.codex/rules/aegis.rules and runs the hook only after you trust it in /hooks; Antigravity hooks are unavailable on Windows. aegis doctor shows each host's entries and tier; it cannot confirm that a host runs them. Run it from any directory but your home directory, which Aegis never takes as a workspace, even for --scope user (which changes only your user files). Known gaps: - Edits made through shell commands never reach the edit gate on any host. - Codex write_stdin into an interactive shell has no PreToolUse payload, and the Codex Bash payload carries no working directory. - Antigravity manage_task with send_input types into a background terminal past run_command. - Aegis never emits an 'ask' decision (it fails open on Codex and soft-denies in agy headless runs). - The hooks fail open on any Aegis error: they are guardrails, not a security boundary.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--force` |  |  | Git hook only: overwrite symlinks pointing outside repository |
| `--dry-run` |  |  | Preview without creating or modifying hook |
| `--host` | `HOST` |  | Register the PreToolUse hook with this host instead of the git hook: claude-code, codex-cli, antigravity |
| `--scope` | one of `user`, `project` |  | With --host: user (default) or project |

### `aegis hook run`

Run the agent-host hook on the payload on stdin (what host hook registrations call)

Reads the host's PreToolUse JSON on stdin and never prints on stdout. Exit 0 allows, and also follows any error, a timeout, an unknown host or event and an ungoverned workspace: the hooks fail open. Exit 2 blocks on claude-code and codex-cli (reason on stderr); exit 75 blocks on antigravity, whose registration maps it to 1.

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `event` | `[EVENT]` |  | The hook event: pre-tool |
| `--host` | `HOST` |  | The host whose payload is on stdin: claude-code, codex-cli or antigravity |

### `aegis hook safety-gate`

Check a shell command against the safety gate (prints a JSON decision)

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--cmd` | `CMD` |  | Command line to check (default: JSON payload on stdin) |

### `aegis hook status`

Inspect the pre-commit hook and the interpreter it runs

### `aegis hook uninstall`

Remove the aegis block from the pre-commit hook, or with --host an agent host's PreToolUse hook and its insight capture hook

Without --host: remove the aegis block from the git pre-commit hook. With --host: remove Aegis's PreToolUse entries and its insight capture (UserPromptSubmit) entries from that host's files at --scope (default: both scopes) and nothing else, backing each file up first; for Codex also ~/.codex/rules/aegis.rules once no Aegis Codex hook is left. Run it from any directory but your home directory, which Aegis never takes as a workspace, even for --scope user (which changes only your user files).

| Argument | Value | Default | Description |
| --- | --- | --- | --- |
| `--force` |  |  | Git hook only: force removal |
| `--dry-run` |  |  | Preview without modifying disk |
| `--host` | `HOST` |  | Remove Aegis's PreToolUse and insight capture hook entries from this host instead of the git hook: claude-code, codex-cli, antigravity |
| `--scope` | one of `user`, `project` |  | With --host: only this scope (default: both) |

### Removed commands

Each of these exits with status 2 and prints where to go instead.

| Command | Instead |
| --- | --- |
| `aegis agent` | use aegis scan to see which rules apply; record outcomes with the MCP tool aegis_report_outcome |
| `aegis agent record` | use aegis_report_outcome (MCP) |
| `aegis agent scan` | use aegis scan |
| `aegis audit` | use aegis doctor |
| `aegis checkpoint` | use aegis check |
| `aegis completion` | no replacement |
| `aegis detect` | use aegis doctor |
| `aegis drivers` | use aegis doctor |
| `aegis handoff` | no replacement |
| `aegis hook governance-monitor` | no replacement; remove it from your agent host's hook config |
| `aegis hook immune-init` | no replacement; remove it from your agent host's hook config |
| `aegis hook post-session` | no replacement; remove it from your agent host's hook config |
| `aegis hook pre-commit` | use aegis check --hook |
| `aegis hook pre-invocation` | no replacement; remove it from your agent host's hook config |
| `aegis hook session-close` | no replacement; remove it from your agent host's hook config |
| `aegis hook stop` | no replacement; remove it from your agent host's hook config |
| `aegis install` | use aegis init --host |
| `aegis languages` | use aegis doctor |
| `aegis report` | aegis status shows rule trigger counts; outcomes are recorded with the MCP tool aegis_report_outcome |
| `aegis rule clean` | no replacement; remove leaked global rule copies by hand |
| `aegis rules` | use aegis status |
| `aegis skill` | no replacement |
| `aegis sys` | use aegis doctor |
| `aegis system` | use aegis doctor |
| `aegis system doctor` | use aegis doctor |
| `aegis system drivers` | use aegis doctor |
| `aegis system hook` | use aegis hook |
| `aegis verify` | use aegis check |

## MCP server: `aegis-mcp`

The server speaks MCP over stdio. Its tools, as `tools/list` returns them. A write tool declares only `readOnlyHint: false`, so the MCP defaults apply to its other hints:

| Tool | Title |
| --- | --- |
| `aegis_scan` | Scan JIT Rules |
| `aegis_report_outcome` | Report Outcome |
| `aegis_create_rule` | Create Rule |
| `aegis_list_rules` | List Rules |
| `aegis_capture_insight` | Capture Insight |

### `aegis_scan`

**Scan JIT Rules** (read-only, idempotent)

Call before editing files: returns the governance rules matching `files` (or the git diff when `files` is omitted), ranked by ledger fitness and clamped to the JIT token budget. Use this tool before any file edit to satisfy the pre-edit scan gate and record session rule exposure; use `aegis_list_rules` to inspect the full inventory without file matching, and `aegis_report_outcome` after verifying your changes. Mandatory rules (gates, invariants) take at most two slots; any excess is listed in `omitted_mandatory`. Gates and invariants are served from the reviewed base commit (`rules_base`), so branch-local edits to them never bind and are listed in `unreviewed_rules`, while `stale_rules` lists rules edited since the last `aegis sync`. Fails closed (`status: 'FAIL'`) if any rule file cannot be loaded.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `files` | array of string | no | Workspace-relative file paths you are about to edit. When omitted or empty, defaults to modified files in the current git working tree and index. |
| `view` | string: one of `"full"`, `"summary"`, `"ids"` | no | Optional response projection: 'full' (default, complete payload), 'summary' (retains identity/type/status/fitness fields, caps lists at 10 items, and adds <list>_count), or 'ids' (projects each list to rule ID strings). Error responses are never projected. |

Input schema:

```json
{
  "type": "object",
  "properties": {
    "files": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Workspace-relative file paths you are about to edit. When omitted or empty, defaults to modified files in the current git working tree and index."
    },
    "view": {
      "type": "string",
      "enum": [
        "full",
        "summary",
        "ids"
      ],
      "description": "Optional response projection: 'full' (default, complete payload), 'summary' (retains identity/type/status/fitness fields, caps lists at 10 items, and adds <list>_count), or 'ids' (projects each list to rule ID strings). Error responses are never projected."
    }
  },
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "properties": {
    "relevant_rules": {
      "type": "array",
      "description": "Active rules matching the target files, ranked by fitness within the JIT token budget (rule objects in 'full'/'summary' view, or rule ID strings in 'ids' view)."
    },
    "relevant_rules_count": {
      "type": "integer",
      "description": "Total count of relevant_rules before 'summary' view truncation (present when view='summary')."
    },
    "guidance": {
      "type": "string",
      "description": "Rendered markdown guidance block ready for prompt injection (omitted when view='summary' or 'ids')."
    },
    "invariant_warnings": {
      "type": "array",
      "description": "Mandatory gate and invariant rules triggered by the target files."
    },
    "invariant_warnings_count": {
      "type": "integer",
      "description": "Total count of invariant_warnings before 'summary' view truncation (present when view='summary')."
    },
    "rules_staged": {
      "type": [
        "integer",
        "array"
      ],
      "description": "Count of rules staged in relevant_rules after budget clamping (omitted when view='ids')."
    },
    "rules_staged_count": {
      "type": "integer",
      "description": "Total count of rules_staged before 'summary' view truncation (present when view='summary')."
    },
    "omitted_mandatory": {
      "type": "array",
      "description": "Mandatory gate or invariant rules that matched but exceeded the two-slot mandatory cap."
    },
    "omitted_mandatory_count": {
      "type": "integer",
      "description": "Total count of omitted_mandatory before 'summary' view truncation (present when view='summary')."
    },
    "stale_rules": {
      "type": "array",
      "description": "Rules edited on disk since the last 'aegis sync' derived-file regeneration."
    },
    "stale_rules_count": {
      "type": "integer",
      "description": "Total count of stale_rules before 'summary' view truncation (present when view='summary')."
    },
    "unreviewed_rules": {
      "type": "array",
      "description": "Gate or invariant rules added or modified since rules_base whose local changes do not bind."
    },
    "unreviewed_rules_count": {
      "type": "integer",
      "description": "Total count of unreviewed_rules before 'summary' view truncation (present when view='summary')."
    },
    "unreviewed_total": {
      "type": "integer",
      "description": "Total count of unreviewed gate or invariant rules across the workspace."
    },
    "rules_base": {
      "type": [
        "object",
        "string",
        "null"
      ],
      "description": "Reviewed git base anchor from which binding gate and invariant rules were loaded."
    },
    "stats": {
      "type": "object",
      "description": "Scan telemetry summary including matched counts and token budget usage (omitted in 'summary'/'ids' views)."
    },
    "warnings": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Optional non-fatal scan warning messages."
    },
    "warnings_count": {
      "type": "integer",
      "description": "Total count of warnings before 'summary' view truncation (present when view='summary')."
    },
    "user_layer": {
      "type": "object",
      "description": "Read-only user-layer metadata ({path, rules}) when scanning outside a governed Aegis workspace."
    },
    "status": {
      "type": "string",
      "description": "Optional status indicator ('not_governed' when scanning the user layer outside an Aegis workspace, or 'FAIL' on error)."
    },
    "message": {
      "type": "string",
      "description": "Informational message when status='not_governed'."
    },
    "reason": {
      "type": [
        "string",
        "null"
      ],
      "description": "Unbound workspace reason code when status='not_governed'."
    },
    "error": {
      "type": "string",
      "description": "Error detail when status='FAIL'."
    },
    "rule_errors": {
      "type": "array",
      "description": "Rule files that failed to parse when status='FAIL'."
    }
  },
  "required": [
    "relevant_rules"
  ],
  "additionalProperties": false
}
```

### `aegis_report_outcome`

**Report Outcome**

Record post-verification rule feedback in the local outcome ledger after running tests or `aegis check`. Use this tool at the end of an edit-and-verify cycle; use `aegis_scan` before editing files and `aegis_capture_insight` to record user corrections. When a passing `aegis check --record` exists for the current git tree, the server credits rules exposed by `aegis_scan` in this session that match the diff (`rules_used` is validated against the rule inventory, not used as the credit source). Those credits count toward fitness once CI passes on the landing commit. Without a matching check record, it writes at most one unwitnessed claim per session and tree that earns no fitness credit. Capped at 200 report rows per session and rate-limited to 5 calls per 60 seconds.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `outcome` | string: one of `"success"`, `"partial"`, `"failure"`, `"tp"`, `"fp"`, `"pass"`, `"fail"` | yes | Verification result for the rules in this change: 'success'/'tp'/'pass' record a true positive ('tp'), 'failure'/'fp'/'fail' record a false positive ('fp'), and 'partial' records a neutral trigger ('trigger'). |
| `idempotency_key` | string | yes | Caller-supplied unique key (1-256 chars, scoped per host and session). Retrying with the same key and outcome is a no-op; reusing a key with a different outcome fails with status 'FAIL'. |
| `rules_used` | array of string | yes | Non-empty list of existing rule IDs from aegis_scan. Validated against the workspace rule inventory; actual fitness credit is computed server-side from session scan exposure and git diff paths. |
| `tests_passed` | boolean | no | Optional boolean recording whether the project's test suite passed during verification. |
| `rework_count` | integer | no | Optional non-negative integer count of edit-and-retest cycles before verification succeeded (default: 0). |
| `notes` | string | no | Optional free-text context describing how the rules helped or failed (max 4096 chars). |
| `files` | array of string | no | Optional workspace-relative file paths edited in this change. Records one 'edit' activity event per idempotency_key for scan-before-edit compliance (aegis status --compliance); does not affect rule credit. |
| `view` | string: one of `"full"`, `"summary"`, `"ids"` | no | Optional response projection: 'full' (default, complete payload), 'summary' (retains identity/type/status/fitness fields, caps lists at 10 items, and adds <list>_count), or 'ids' (projects each list to rule ID strings). Error responses are never projected. |

Input schema:

```json
{
  "type": "object",
  "properties": {
    "outcome": {
      "type": "string",
      "enum": [
        "success",
        "partial",
        "failure",
        "tp",
        "fp",
        "pass",
        "fail"
      ],
      "description": "Verification result for the rules in this change: 'success'/'tp'/'pass' record a true positive ('tp'), 'failure'/'fp'/'fail' record a false positive ('fp'), and 'partial' records a neutral trigger ('trigger')."
    },
    "idempotency_key": {
      "type": "string",
      "maxLength": 256,
      "description": "Caller-supplied unique key (1-256 chars, scoped per host and session). Retrying with the same key and outcome is a no-op; reusing a key with a different outcome fails with status 'FAIL'."
    },
    "rules_used": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "minItems": 1,
      "description": "Non-empty list of existing rule IDs from aegis_scan. Validated against the workspace rule inventory; actual fitness credit is computed server-side from session scan exposure and git diff paths."
    },
    "tests_passed": {
      "type": "boolean",
      "description": "Optional boolean recording whether the project's test suite passed during verification."
    },
    "rework_count": {
      "type": "integer",
      "default": 0,
      "description": "Optional non-negative integer count of edit-and-retest cycles before verification succeeded (default: 0)."
    },
    "notes": {
      "type": "string",
      "maxLength": 4096,
      "description": "Optional free-text context describing how the rules helped or failed (max 4096 chars)."
    },
    "files": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Optional workspace-relative file paths edited in this change. Records one 'edit' activity event per idempotency_key for scan-before-edit compliance (aegis status --compliance); does not affect rule credit."
    },
    "view": {
      "type": "string",
      "enum": [
        "full",
        "summary",
        "ids"
      ],
      "description": "Optional response projection: 'full' (default, complete payload), 'summary' (retains identity/type/status/fitness fields, caps lists at 10 items, and adds <list>_count), or 'ids' (projects each list to rule ID strings). Error responses are never projected."
    }
  },
  "required": [
    "outcome",
    "rules_used",
    "idempotency_key"
  ],
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "properties": {
    "status": {
      "type": "string",
      "enum": [
        "recorded",
        "claimed",
        "rate_limited",
        "FAIL"
      ],
      "description": "Report disposition: 'recorded' (witnessed by a matching check record), 'claimed' (unwitnessed self-report), 'rate_limited' (session cap reached), or 'FAIL'."
    },
    "witness": {
      "type": "string",
      "enum": [
        "aegis",
        "self"
      ],
      "description": "Attestation tier: 'aegis' when backed by an 'aegis check --record' run for the current tree, or 'self' for unwitnessed claims."
    },
    "credited": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Rule IDs credited in the outcome ledger (empty for unwitnessed 'claimed' or 'rate_limited' reports)."
    },
    "credited_count": {
      "type": "integer",
      "description": "Total count of credited rules before 'summary' view truncation (present when view='summary')."
    },
    "check": {
      "type": "string",
      "description": "Check record ID that witnessed the report (present when status='recorded')."
    },
    "tree": {
      "type": [
        "string",
        "null"
      ],
      "description": "Git tree hash computed for the workspace at report time."
    },
    "recorded": {
      "type": "boolean",
      "description": "False when status='rate_limited' or when an unwitnessed claim for the same session and tree was already recorded."
    },
    "limit": {
      "type": "integer",
      "description": "Per-session report cap (200) returned when status='rate_limited'."
    },
    "source": {
      "type": "string",
      "description": "Command or tool name that produced the response ('aegis_report_outcome')."
    },
    "aegis_version": {
      "type": "string",
      "description": "Running Aegis package version string."
    },
    "checked_at": {
      "type": "string",
      "description": "UTC ISO-8601 timestamp when the report was processed."
    },
    "scope": {
      "type": "object",
      "description": "Workspace scope metadata envelope ({tree})."
    },
    "error": {
      "type": "string",
      "description": "Error message when status='FAIL'."
    }
  },
  "required": [
    "credited"
  ],
  "additionalProperties": false
}
```

### `aegis_create_rule`

**Create Rule** (read-only, idempotent)

Build a structured prompt for drafting a new governance rule from a natural-language `description`. Use this tool when asked to author or codify a repository rule; use `aegis_list_rules` to inspect existing rules first, or `aegis_capture_insight` to log a raw user correction without creating a rule file. Samples up to three active workspace rules (500 chars each) as style examples, incorporates optional `rule_type` and `domain` hints, and writes nothing to disk: save the drafted markdown to `.aegis/rules/<type_dir>/<id>.md` yourself as directed by `instruction`.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `description` | string | yes | Non-empty natural-language description of the engineering defect, anti-pattern, or invariant to codify into a rule. |
| `rule_type` | string: one of `"invariant"`, `"trap"`, `"gate"`, `"boundary"`, `"persona"`, `"contract"` | no | Optional target rule category ('invariant' or 'gate' for blocking checks; 'trap', 'boundary', 'persona', or 'contract' for advisory guidance). Determines the target subdirectory under .aegis/rules/. |
| `domain` | string | no | Optional domain hint injected into the drafting prompt (e.g., 'security', 'correctness', 'efficiency', 'style', 'governance'). |

Input schema:

```json
{
  "type": "object",
  "properties": {
    "description": {
      "type": "string",
      "description": "Non-empty natural-language description of the engineering defect, anti-pattern, or invariant to codify into a rule."
    },
    "rule_type": {
      "type": "string",
      "enum": [
        "invariant",
        "trap",
        "gate",
        "boundary",
        "persona",
        "contract"
      ],
      "description": "Optional target rule category ('invariant' or 'gate' for blocking checks; 'trap', 'boundary', 'persona', or 'contract' for advisory guidance). Determines the target subdirectory under .aegis/rules/."
    },
    "domain": {
      "type": "string",
      "description": "Optional domain hint injected into the drafting prompt (e.g., 'security', 'correctness', 'efficiency', 'style', 'governance')."
    }
  },
  "required": [
    "description"
  ],
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "properties": {
    "prompt": {
      "type": "string",
      "description": "Structured rule-generation prompt containing schema requirements and up to three workspace rule examples."
    },
    "instruction": {
      "type": "string",
      "description": "Step-by-step instruction telling the caller where under .aegis/rules/<type_dir>/<id>.md to save the drafted markdown."
    },
    "status": {
      "type": "string",
      "description": "Present with value 'FAIL' only when input validation fails."
    },
    "error": {
      "type": "string",
      "description": "Error message when status='FAIL'."
    }
  },
  "required": [
    "prompt",
    "instruction"
  ],
  "additionalProperties": false
}
```

### `aegis_list_rules`

**List Rules** (read-only, idempotent)

List the workspace governance rule inventory in directory order without recording a scan or exposure event. Use this tool to browse or audit rules, check ledger fitness, or find stale/broken rule files; use `aegis_scan` instead before editing files so pre-edit scan compliance and session rule exposure are recorded. Returns every rule with its metadata and ledger fitness (or `_error` if unloadable, and `_expired: true` if retired), rules modified since the last `aegis sync` (`stale_rules`), and non-rule markdown under `.aegis/rules/` (`ignored`). Pass `rule_type` to filter `rules` and `stale_rules` to one category, or `view` (`'summary'` or `'ids'`) to compact the payload.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `rule_type` | string: one of `"invariant"`, `"trap"`, `"gate"`, `"boundary"`, `"persona"`, `"contract"` | no | Optional filter restricting both 'rules' and 'stale_rules' to a single rule category ('invariant', 'trap', 'gate', 'boundary', 'persona', or 'contract'). Omit to list all categories. |
| `view` | string: one of `"full"`, `"summary"`, `"ids"` | no | Optional response projection: 'full' (default, complete payload), 'summary' (retains identity/type/status/fitness fields, caps lists at 10 items, and adds <list>_count), or 'ids' (projects each list to rule ID strings). Error responses are never projected. |

Input schema:

```json
{
  "type": "object",
  "properties": {
    "rule_type": {
      "type": "string",
      "enum": [
        "invariant",
        "trap",
        "gate",
        "boundary",
        "persona",
        "contract"
      ],
      "description": "Optional filter restricting both 'rules' and 'stale_rules' to a single rule category ('invariant', 'trap', 'gate', 'boundary', 'persona', or 'contract'). Omit to list all categories."
    },
    "view": {
      "type": "string",
      "enum": [
        "full",
        "summary",
        "ids"
      ],
      "description": "Optional response projection: 'full' (default, complete payload), 'summary' (retains identity/type/status/fitness fields, caps lists at 10 items, and adds <list>_count), or 'ids' (projects each list to rule ID strings). Error responses are never projected."
    }
  },
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "properties": {
    "rules": {
      "type": "array",
      "description": "Workspace rule records with metadata and ledger fitness (or rule ID strings when view='ids')."
    },
    "rules_count": {
      "type": "integer",
      "description": "Total count of rules before 'summary' view truncation (present when view='summary')."
    },
    "stale_rules": {
      "type": "array",
      "description": "Rules edited since the last 'aegis sync' derived-file regeneration."
    },
    "stale_rules_count": {
      "type": "integer",
      "description": "Total count of stale_rules before 'summary' view truncation (present when view='summary')."
    },
    "ignored": {
      "type": "array",
      "description": "Non-rule markdown files under .aegis/rules/ with path and reason."
    },
    "ignored_count": {
      "type": "integer",
      "description": "Total count of ignored files before 'summary' view truncation (present when view='summary')."
    },
    "status": {
      "type": "string",
      "description": "Present with value 'FAIL' only when the rules directory cannot be safely loaded."
    },
    "error": {
      "type": "string",
      "description": "Error message when status='FAIL'."
    }
  },
  "required": [
    "rules",
    "stale_rules",
    "ignored"
  ],
  "additionalProperties": false
}
```

### `aegis_capture_insight`

**Capture Insight**

Append a user correction quote to the user-scoped insights log (`~/.aegis/insights/`) for rule curation. Use this tool when the user corrects your approach or states a recurring preference; use `aegis_create_rule` to draft a `.aegis/rules/` file immediately, or `aegis_report_outcome` to report whether existing rules helped. Each call redacts secrets, truncates `quote` to 300 characters, associates `paths` (or dirty git worktree paths when omitted), and appends a new `ins-<hex>` record. Agent-submitted records start at `level: 'suggestion'`, which is invisible to `aegis_scan` and excluded from `aegis insights review` rule proposals until corroborated (`level: 'W2'`) by a matching user prompt captured by a host hook in the same session.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `quote` | string | yes | Non-empty verbatim quote of the user's correction or preference (1-1024 chars; secrets are automatically redacted and stored text is capped at 300 chars). |
| `paths` | array of string | no | Optional workspace-relative file paths this correction applies to (sets psrc='explicit'). When omitted or empty, defaults to currently modified git worktree paths (psrc='dirty'). |

Input schema:

```json
{
  "type": "object",
  "properties": {
    "quote": {
      "type": "string",
      "maxLength": 1024,
      "description": "Non-empty verbatim quote of the user's correction or preference (1-1024 chars; secrets are automatically redacted and stored text is capped at 300 chars)."
    },
    "paths": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Optional workspace-relative file paths this correction applies to (sets psrc='explicit'). When omitted or empty, defaults to currently modified git worktree paths (psrc='dirty')."
    }
  },
  "required": [
    "quote"
  ],
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "properties": {
    "status": {
      "type": "string",
      "enum": [
        "OK",
        "FAIL"
      ],
      "description": "'OK' when the insight row was appended, or 'FAIL' on validation/storage error."
    },
    "id": {
      "type": "string",
      "description": "Content-addressed insight identifier ('ins-<12-hex>')."
    },
    "level": {
      "type": "string",
      "enum": [
        "suggestion",
        "W2"
      ],
      "description": "Corroboration tier: 'suggestion' initially, or 'W2' when matched to a hook-captured user prompt in the same session."
    },
    "text": {
      "type": "string",
      "description": "Secret-redacted and length-capped (max 300 chars) correction quote stored in the ledger."
    },
    "paths": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "Workspace-relative file paths associated with this insight."
    },
    "psrc": {
      "type": "string",
      "enum": [
        "explicit",
        "dirty"
      ],
      "description": "Path provenance: 'explicit' when caller supplied paths, or 'dirty' when inferred from git status."
    },
    "error": {
      "type": "string",
      "description": "Error message when status='FAIL'."
    }
  },
  "required": [
    "status",
    "id",
    "level",
    "text",
    "paths",
    "psrc"
  ],
  "additionalProperties": false
}
```
