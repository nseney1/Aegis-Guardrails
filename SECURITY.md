# Security Policy

## Supported Versions

Security fixes go into the latest 4.x release. Earlier major lines are not patched; v4 changed the layout, the config and the MCP surface, and [`aegis migrate`](CHANGELOG.md#upgrading-from-3x) converts a v3 workspace.

| Version | Supported |
|:--------|:---------:|
| 4.x | ✅ |
| < 4.0 | ❌ |

## Reporting a Vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Report it privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (<https://github.com/nseney1/Aegis-Guardrails/security/advisories/new>). The report stays visible only to you and the maintainers.

> [!NOTE]
> This channel works only after the maintainer enables *Private vulnerability reporting* under **Settings → Code security** for the repository. If the button is missing, open a public issue that asks for a private contact channel, without any vulnerability details.

Include, where you can: the version (`aegis --version`), OS and shell, the component (`aegis_core`, `aegis_mcp`, `aegis_cli`, `aegis_sdk`), steps or a proof of concept, and the impact you observed.

Aegis Guardrails is maintained by one person, so these are goals, not guarantees: acknowledge within 7 days, confirm or reject with reasons within 30 days, and coordinate the fix and a GitHub Security Advisory with you before disclosure, crediting you unless you prefer otherwise. Fixes are recorded in the [CHANGELOG](CHANGELOG.md) and the advisory. There is no bug bounty.

## Scope

In scope: a defect that breaks one of these guarantees.

- **Path confinement** ([`aegis_core/workspace/confinement.py`](aegis_core/workspace/confinement.py), [`aegis_core/storage.py`](aegis_core/storage.py)): a tool or command reading or writing outside the governed workspace, through `..`, symlinks, NUL bytes, Windows device names or alternate data streams, or writing state through a link.
- **Repository-controlled execution** ([`aegis_core/gitsafe.py`](aegis_core/gitsafe.py), [`aegis_core/config.py`](aegis_core/config.py), [`aegis_cli/install_hosts.py`](aegis_cli/install_hosts.py)): a file the repository controls (`.aegis/config.json`, rule files, `.git/config`, `.gitattributes`, or a package such as `aegis_mcp/` in its tree) making Aegis run a program or code it did not choose, or injecting instructions into scan output. See [Repository trust](#repository-trust) for what Aegis does run.
- **Workspace binding** ([`aegis_core/workspace/binding.py`](aegis_core/workspace/binding.py)): the MCP server governing `$HOME`, a directory above the git top level, or a repository chosen by a tool argument.
- **No automatic rule rewrites** ([`tests/integration/test_no_rule_writes.py`](tests/integration/test_no_rule_writes.py)): `aegis check`, `aegis scan`, the MCP tools or the git hook modifying files under `.aegis/rules/`. Only explicit commands (`aegis rule …`, `aegis sync --apply`, `aegis migrate --apply`) write rule files.
- **Ledger integrity** ([`aegis_core/telemetry_engine/ledger.py`](aegis_core/telemetry_engine/ledger.py)): lost, duplicated or rewritten rows in `.aegis/state/ledger.jsonl` under concurrent writers, or a torn line corrupting later reads.
- **MCP input and output** ([`aegis_mcp/server.py`](aegis_mcp/server.py), [`aegis_mcp/projection.py`](aegis_mcp/projection.py)): an argument that bypasses its tool schema, a client overriding the server-owned host or session, or a `view` projection leaking fields it should drop.
- **Host hook registration** ([`aegis_cli/hooks/registrar.py`](aegis_cli/hooks/registrar.py)): `aegis hook install --host` or `uninstall --host` changing anything in a host file other than Aegis's own entry, writing through a link, leaving a file the host cannot parse, or registering a command a repository chose.
- **Supply chain** ([`.github/workflows/publish.yml`](.github/workflows/publish.yml)): a published wheel or sdist that differs from the one CI built and tested, or secrets in the repository, the wheel or the sdist.

Out of scope: an agent or person with shell access as your user (Aegis advises and checks; it does not sandbox anyone), self-reported outcomes (any connected MCP client can write them; without a check row for the tree they are recorded as claimed and never count as evidence for a rule), defects in agent hosts, MCP clients, Python or the OS, denial of service of the local stdio server by its own client, and versions marked ❌ above.

## Repository trust

Aegis treats a repository you clone as untrusted input. What it runs, and from where:

| What runs | When | Where it comes from |
|---|---|---|
| `git` | most commands, and `aegis_scan` | your PATH, always through `gitsafe`: the repository's own config cannot make git run anything (fsmonitor, hooks, filter drivers, credential helpers, signature-verification programs, trailer commands, remote protocols and submodule status are switched off; your user and system git config still apply, except that signature programs are switched off there too). One command pushes: `aegis sync --pr` pushes one `aegis/lifecycle-*` branch to the current branch's remote (default `origin`) with your own credentials, over https, ssh or a local path only, unsigned, with this repository's hooks off and `GIT_TERMINAL_PROMPT=0`. It refuses any other URL scheme, a local push URL inside this repository's work tree or git directory, a protected branch that differs from its remote-tracking branch, and repository config that sets a program or rewrite the push would use (`core.sshCommand`, `core.askPass`, `credential.*`, `url.*`, `protocol.*`, or the remote's `receivepack`, `uploadpack` or `vcs`). A local-path remote outside the repository runs its own hooks, as any receiving repository does. It never merges |
| `codex`, `claude` | `aegis init --host`, `aegis uninstall`, and `aegis doctor` (`codex mcp get` only) | by name from the absolute entries of PATH; relative and empty entries, which point into the current directory, are skipped, and doctor also skips entries inside the workspace |
| AST drivers (`node`, `go`) | `aegis check` on TypeScript or Go files, or on files your user config names a driver for | Aegis's packaged driver templates, which a repository may only switch on, or commands from your user `~/.aegis/config.json`; the interpreter must be outside the workspace, and a Python driver runs under the Python running Aegis. The packaged Rust driver starts no program: it runs inside Aegis's own process |
| `aegis-mcp`, the MCP server | every session of a host you registered with `aegis init --host`, started by the host in the project directory | the absolute command `init` registered: the `aegis-mcp` script from an absolute PATH entry or from next to the Python running `aegis`, else that Python in isolated mode (`-I -c`) importing `aegis_mcp` from the directory Aegis is installed in. Never `python -m aegis_mcp`, which imports from the project directory first. `aegis doctor` reports as unsafe a registration that is not an absolute path, a Python that runs `-m` or `-c` without `-I` or a script by a relative path, or either behind `env`; it starts no MCP server and no `python3` |
| `aegis`, the hook handler | every matching tool call of a host where you ran `aegis hook install --host` (`aegis hook run pre-tool`); `install` itself runs it once on an empty payload, in an empty temporary directory, to refuse an `aegis` that has no `hook run` | the absolute path `install` registered: the first `aegis` in an absolute PATH entry outside the repository, else the script installed with the Python running Aegis. It must match `[A-Za-z0-9._/+-]+`, so the shell forms need no quoting. It reads the payload, the activity log and `.aegis/config.json`, starts nothing but `git`, and never runs repository code. `aegis benchmark` starts the same handler under the Python running Aegis (`-I -c`), on a built-in fixture payload in a temporary workspace, never on your repository |
| `pytest` | `aegis check --full` only | your active virtualenv, then `.venv/` inside the repository, then PATH. It runs the tests that match the changed files, which executes repository code (tests, `conftest.py`) just as running the suite yourself would |
| your model command | `aegis check --full` only | `--llm-cmd` or `AEGIS_LLM_CMD`, never repository files. It runs in an empty temporary directory and receives the prompt, which includes the diff, on stdin |
| your test command | `aegis check --record --tests`, and `aegis check --ci` unless `--no-exec` is given (it reruns the head commit's `Aegis-Check` trailer snapshot and the fix-commit regression tests) | `tests.command` in your user `~/.aegis/config.json` (default `python -m pytest`, run under the Python running Aegis, or the absolute Python named as the first word of `tests.command`; a bare `pytest` is run as `python -m pytest` under that Python), never the repository's config. It runs in a snapshot export of the tree with a fixed environment, no stdin and a timeout that kills its process group. On Windows the group is killed while the run is alive; descendants a test run leaves behind after a normal exit are not swept. Like any test run, it executes the repository's tests and `conftest.py`. A root module that shadows the runner (`pytest.py`, `_pytest/`, `pluggy/`, `py.py`, `iniconfig.py`) is test infrastructure and withholds credit until approved; the check is path-only, so a root `argparse.py` or `json.py` can still replace what `python -m pytest` imports, and `witness: aegis` stays a label |
| `ssh-keygen` | `aegis approve` (signing) and every approval check (`aegis check --ci`, `aegis approve`, approvals that gate credit) | by name from an absolute PATH entry outside the repository, like `gh`; git is pointed at that program for SSH signatures and runs no other |
| `gh` | `aegis doctor` (the trust tier: read-only `gh api` GETs), `aegis doctor --github --apply` (one POST that creates the ruleset, after a typed y/N at a terminal) and `aegis doctor --release` (`gh --version`, one read-only `gh api` GET of the repository for its default branch, the tier GETs, `gh attestation verify`, and at tier A two read-only GETs of the merged pull request and its reviews); `aegis sync` and the `aegis rule promote`, `demote` and `archive` decisions (read-only GETs of the repository's default branch and its CI runs, to confirm credit), and `aegis sync --pr` (`gh pr create`); `aegis check --ci` on a pull-request run, only when a weakening or governance change has no signed approval (read-only `gh api` GETs of the repository, the default branch's rules and the pull request's reviews, with the job's `GH_TOKEN` and `pull-requests: read`) | by name from an absolute PATH entry outside the repository, with your own gh login (in CI, the job's token). No other command starts `gh`: scanning, `aegis_list_rules`, `aegis status`, `aegis rule list`, `aegis check` without `--ci`, and the agent hooks stay offline |

Plain `aegis check` and the git pre-commit hook (`aegis check --hook`) parse files and never run the repository's code or a model. Run `aegis check --full` only on code you would run yourself.

## Agent hooks and team leases

The 4.1 hooks and leases change files outside the repository and git refs. What each one is, and what it is not:

| What | Where | What it means for you |
|---|---|---|
| Hook entries, user scope (the default) | `~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/config/hooks.json`, written by `aegis hook install --host` | your host runs `aegis hook run pre-tool` before matching tool calls in every repository; in one without `.aegis/` it does nothing. Each file is backed up to `~/.aegis/backups/` first, and a file that does not parse, is a symlink or has more than one link is refused |
| Hook entries, `--scope project` | `<repo>/.claude/settings.json`, `<repo>/.codex/hooks.json`, `<repo>/.agents/hooks.json` | committed files that your teammates' hosts will execute after they pull. Review them like code, as you would any hook a pull request adds |
| Codex rules | `~/.codex/rules/aegis.rules` | `forbidden` prefix rules for the destructive-command block set; `default.rules` is never touched |
| Codex hook trust | Codex's `/hooks` screen | Codex runs a new or changed hook only after you trust it there, and skips it silently until then. Doctor cannot see this and says so |
| The Antigravity wrapper | the `aegis` group's command | a shell line that maps the handler's exit 75 to Antigravity's blocking exit 1 and every other code to 0, so a crash never blocks. Antigravity hooks are not installed on Windows, where its hook shell is unverified |
| Team leases | `refs/aegis/lanes/<lane>` | cooperative conflict input for parallel lanes: `owner` and `role` are labels, not an identity, and nothing checks them. Anyone who can run git in the repository can claim, take over an expired lease or release one |

The hooks are guardrails, not a security boundary. They fail open on any Aegis error, a timeout or a payload they cannot read; edits made through shell commands never reach the edit check; and an agent running as your user can edit the host files. `aegis check --lane` is self-attested unless `--base-policy` reads the lane's paths from the base branch, and even then a witness is only as strong as the protection on `.github/**` and on the base branch. CI on the exact commit stays the floor.

## Trust tiers

The adversary Aegis plans for is the coding agent itself: it runs as your user, can edit the repository, `$HOME`, host configs and Aegis's own state, and holds your git and gh credentials unless you separate them. Nothing local is a witness against it, so what Aegis sees locally (the ledger, `aegis check --record` rows, commit trailers) is a **label**. What holds depends on what GitHub enforces, which `aegis doctor` detects and prints on every report:

- **Tier A, separation of duties:** the default branch requires a pull request, an approving review by a non-author that is dismissed when new commits are pushed, the Aegis job as a required check (no path filter and no condition that could skip it; an unpinned check source is reported as a caveat, and `aegis doctor --github` pins GitHub Actions), CODEOWNERS on the governance files with owners named as users or `@org/team`, and the agent's identity cannot approve.
- **Tier B, solo and signed:** the Aegis job as a required check with its source pinned to an app (`aegis doctor --github` pins GitHub Actions) and no path filter or condition that could skip it, plus `aegis approve` commits signed by a key listed in the base branch's `allowed_signers` that the agent cannot use (a hardware key, or a passphrase or touch-confirmed agent). A key stored as a plain, readable file degrades B to C. Only SSH signatures count: a PGP or X.509 signature is never an approval. Tier B is weaker than it looks; see the caveat under the table.
- **Tier C, self-attested:** neither. Detection and audit only, and every report says "self-attested".

`aegis doctor --github` prints the ruleset, CODEOWNERS lines and signing setup tiers A and B need.

| Claim | Tier A | Tier B | Tier C |
|---|---|---|---|
| A rule weakening was approved by a human | ✔ | partial: holds only if the pull request leaves `.github/workflows/**` and aegis alone (it runs its own check; itemized, auditable) | ✘ (itemized, auditable) |
| An outcome credited to a rule was confirmed by CI on the landing commit | ✔ | ✔ (CI only, workflow editable by the agent) | ✔ (CI only, workflow editable by the agent) |
| A release passed CI on its exact SHA, with a signed attestation | ✔ | ✘ (agent can edit the workflow) | ✘ (agent can edit the workflow) |
| Local labels (`witness: aegis`) | label | label | label |

At tier B the required checks run the pull request's own workflow and the aegis it installs, and a required status context accepts a result from any source unless the ruleset pins an integration, so a pull request that edits `.github/workflows/**` or aegis can change the check that verifies the signature. `aegis doctor --release` therefore reports tier B as `agent_editable`, never `VERIFIED`; restoring the tier B ticks needs a check sourced from the base branch.

The first row holds only where CI runs `aegis check --ci` as a required check; `aegis init --ci`'s workflow does not add it yet. The second row holds for the workflow named in `ci.workflow` in your user `~/.aegis/config.json` (default `validate.yml`); the repository's config and ledger rows never choose it. It is read by `aegis sync` and `aegis sync --pr` (which pushes one `aegis/lifecycle-*` branch holding the moves and up to three unlabelled examples, opens a pull request from it, and never merges), which read the runs and the default branch from GitHub. The third row holds only for a repository whose `validate.yml` has Aegis's verdict job; it is what `aegis doctor --release <sha>` verifies, it reports tier B as `agent_editable`, and it prints `UNVERIFIED` and exits non-zero when it cannot.

Residuals: `refs/remotes/origin/*` is writable by the agent, so the approval ancestry test and `detect_tier` are only as strong as that ref. The repository `aegis doctor --release` asks GitHub about comes from the local `remote.origin.url`, and the one credit confirmation asks about is resolved by `gh` itself (`GH_REPO`, the clone's git remotes or `gh repo set-default`); both are local settings, so a fork substitution is visible only because the report prints the repository. A revert is found from its commit message, which the agent can write, but a forged revert message can only void credit, never grant it.

## What Aegis does not claim

Test skip markers and pytest collection hooks are reported by `aegis check --lane` only; `aegis check --ci` and `aegis check --record` neither gate nor withhold credit for them.

Aegis reads at most the first 64 KiB of a local key file to classify its protection (plain, passphrase or hardware) and never copies, prints or stores it; the local key is not compared with `allowed_signers`. A plain `aegis check` row and a ledger `adjudication` row are labels that count for nothing. Other ledger rows (hand-written `source: "ci"` rows, session rows with `from`, `caught` detection rows) still count toward local fitness until labels become the only promotion path, and a developer machine's base refs can be moved by the agent: local fitness is a label, and only a reviewed pull request that `check --ci` gates moves a rule. This release does not close the bypass in which a pull request edits its own workflow (Tier B, above).

Aegis itself signs nothing and holds no keys: approvals are git signatures that git verifies against the base branch's `allowed_signers`, and the release attestation is GitHub's, which `gh` verifies. The v3 HMAC manifest and receipts were removed because a same-user agent could forge them ([why-aegis](docs/why-aegis.md) §5). v4.3 replaces them with the tiers above: gates and invariants are served from the reviewed base commit, a weakening needs an approval the agent cannot produce, and local checks are labels that only CI on the landing commit confirms. The Layer 2 arbiter is log-only in v4.3 (`aegis check --calibration` scores its predictions only after `>= 25` effective outcomes and suppresses skill claims below `100`); this policy does not claim LLM arbitration as a security boundary. At tier C, Aegis detects a deliberate same-user attacker's changes; it does not prevent them.

Release artifacts are built once in CI, recorded with SHA-256 digests, given a GitHub build provenance attestation, and published to PyPI with Trusted Publishing, so no long-lived upload token exists.
