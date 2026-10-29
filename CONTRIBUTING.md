# Contributing to Aegis Guardrails

Aegis is a Python package with no runtime dependencies. It supports Python 3.9 and later on Linux, macOS and Windows, so use the standard library only and no syntax newer than 3.9.

## Set up

Install Python 3.9 or later and git. Approval signatures also need `ssh-keygen`; release checks need `gh`. Use a virtual environment so the development tools do not change your system Python.

```bash
git clone --branch develop https://github.com/nseney1/Aegis-Guardrails.git
cd Aegis-Guardrails
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows, use Git Bash for these shell examples, create the environment with `python -m venv .venv`, and activate it with `source .venv/Scripts/activate` before the install command. The Python commands below work without `make`.

From this development checkout, `./aegis` or `python -m aegis_cli` runs the CLI. When changing worktrees, check the import location with `python -c "import aegis_core; print(aegis_core.__file__)"`: an editable install for another checkout can otherwise test the wrong code. Install into an environment for the checkout you are testing.

Tests must never read or write your real `~/.aegis`, `~/.claude`, `~/.codex` or `~/.gemini`. Use `tmp_path`, a temporary `HOME` and `USERPROFILE`, and mock host CLIs at the subprocess boundary. This focused-test recipe preserves the active interpreter and isolates the child process's home:

```bash
python - <<'PY'
import os
from pathlib import Path
import site
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="aegis-test-") as test_home:
    test_env = dict(os.environ, HOME=test_home, USERPROFILE=test_home,
                    XDG_CONFIG_HOME=str(Path(test_home) / ".config"),
                    PYTHONUSERBASE=os.environ.get("PYTHONUSERBASE", site.getuserbase()))
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/unit/test_docs_claims.py", "-q"],
        env=test_env,
    )
sys.exit(result.returncode)
PY
```

Replace the test file with `tests/` for the full suite. On Linux and macOS, `make test` provides home isolation and uses `pytest-xdist` when installed. A test may not depend on order or write outside its temporary directory. Run only one full suite at a time.

Before opening a pull request, run the full suite, the deterministic checks and lint:

```bash
python -m aegis_cli check
python -m ruff check --isolated --select E9,F63,F7,F82 aegis_cli aegis_core aegis_mcp aegis_sdk tests .github/scripts
python -m build  # when packaging changes; wheel and sdist go into dist/
```

`make install`, `make lint` and `make build` are shortcuts for the corresponding Python commands.

## Branches and reviews

- Branch from `develop` as `feature/<name>`, `fix/<name>`, `docs/<name>` or `chore/<name>`, and open the pull request against `develop`.
- The author of a change does not approve it. Every pull request gets an independent review: a maintainer, or an AI reviewer working in a separate context with a different lens than the author's.
- `main` takes release merges only (see [Releases](#releases)).

Maintainers may split larger work into `wave/<name>` and `lane/<name>` branches: one git worktree per lane (`git worktree add -b lane/<name> ../lanes/<name> <base>`), each owning a disjoint set of files. A lane that needs a file outside its set stops and says so instead of editing it. [Team leases and lane checks](docs/teams.md) provide cooperative coordination.

## Tests first

1. Write the tests for the new behavior, and run them: they must fail for the right reason (a missing name or a failed assertion, not a syntax error or a wrong call).
2. Write the smallest change that makes them pass.
3. Run the full suite (`make test`). Fix a regression in the code, not in the test, unless the test was wrong, and then say why in the commit.

Test what a user can observe: the CLI's output and exit code, an MCP response, the files written. Cover the failure paths, assert exact errors, and mock only the OS and network boundaries. When you delete a feature, delete its dedicated tests in the same commit and keep the tests of behavior that survives.

## Commits and the public surface

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`). A change to a command, an option or an MCP tool needs a `BREAKING CHANGE:` footer when it removes or changes something. Regenerate the contracts instead of editing their snapshots:

```bash
PYTHONPATH=. python3 tests/contract/test_cli_contract.py --write
PYTHONPATH=. python3 tests/contract/test_mcp_contract.py --write
PYTHONPATH=. python3 tests/contract/gen_reference.py --write
PYTHONPATH=. python3 tests/contract/test_legacy_ratchet.py --write
```

The reference generator writes [docs/reference.md](docs/reference.md); never edit that file by hand. The legacy ratchet records lower counts of retired v3 words and refuses increases. Removing or renaming a public name pinned in `tests/contract/public_names_4_3_3.json` needs a `removed` entry there and a `Breaking:` line in the CHANGELOG. Keep `.github/scripts/wheel_smoke.py` in step with public-surface changes: it calls the CLI, the MCP tools and the SDK against the built wheel in CI.

Docs: relative links must resolve (`tests/unit/test_docs_links.py`), the README must not repeat a retracted claim (`tests/unit/core/test_readme_claims.py`), and `rules/`, `skills/`, `docs/` and the README may not contain a path under `/home/` (a CI step greps for it).

## Governance changes

Commit the proposed changes before previewing this gate: it reads git objects, not uncommitted edits.

```bash
aegis check --ci --no-exec --base origin/develop --head HEAD
```

A rule weakening always needs approval. Other governance-file changes are gated when the base branch lists a key in `allowed_signers`. The governed paths include workflows, signing and ownership files, Aegis configuration and adjudications, test infrastructure such as `conftest.py` and pytest configuration, and deleted test files. Deleting a feature's dedicated tests therefore needs the same review. [The path inventory](aegis_core/governance.py) defines the full set; `check --ci` compares regular-file changes to `pyproject.toml`, `setup.cfg` and `tox.ini` by their pytest sections, while the approval digest covers their whole contents.

A qualifying review can approve changes under [tier A](docs/trust-tiers.md#tier-a-separation-of-duties). Otherwise the maintainer reviews the final diff and runs `aegis approve --base <reviewed-base>` using a key listed on that base which the agent cannot use. Approve after the review and fixes: later governance edits invalidate the signature. Contributors and agents must not create their own approval to clear a failed gate.

For fork pull requests, the base-sourced `.github/workflows/aegis-governance.yml` reads the head as git objects without checking out or executing its code, using a read-only token. It becomes an enforced check only after it is on the default branch and required. Until then, retain the [tier B caveat](SECURITY.md#trust-tiers): the pull request can edit the workflow and Aegis that check it. Do not provide credentials to pull-request code to work around a failed check.

## Releases

A release requires all of these before its tag is published:

1. An independent review of the release pull request.
2. CI green on that commit: `python3 .github/scripts/ci_green.py <sha>` exits 0, with the full 40-character commit SHA (it needs the `gh` CLI).
3. `aegis check` passes Layer 1.

The version-bump pull request targets `develop`, updates `aegis_core/_version.py` and both version fields in `server.json`, and turns the [CHANGELOG](CHANGELOG.md) Unreleased section into notes for users. Set its date when the release is cut. A maintainer merges the reviewed release from `develop` into `main`, verifies CI on that merge, tags `v<version>` (it must equal `_version.py`; `.github/scripts/release_guard.py` refuses a publish otherwise) and publishes the GitHub Release. That runs `.github/workflows/publish.yml`, which ships the wheel CI already built and tested.

If a test job makes the publish run red, use **Re-run failed jobs** at most once on that same run. Never use Re-run all jobs or start a branch workflow dispatch to recover a release. If the retry fails, fix forward with a new patch version. After tagging, run `aegis doctor --release <sha>` and retain its verdict and trust-tier caveats. A release is complete only when `https://pypi.org/pypi/aegis-guardrails/<version>/json` returns HTTP 200; `aegis init --ci` pins the version that writes its workflow.

## Writing a rule

Rules are Markdown files with YAML frontmatter, one per file, in `.aegis/rules/<type-directory>/<id>.md`. The six types map to plural directories: `invariant` to `invariants/`, `trap` to `traps/`, `gate` to `gates/`, `boundary` to `boundaries/`, `persona` to `personas/` and `contract` to `contracts/`. Create one with the CLI:

```bash
aegis rule create --type trap --id trap-unbounded-retries --domain correctness \
  --hypothesis "Retry loops without a cap hang the session when a dependency stays down" \
  --prediction "Fires on edits to code that retries network calls" \
  --falsification "0 findings in 20 sessions: prune" \
  --target-paths "src/**/*.py" --body-file body.md
aegis scan src/app.py   # shows the rule for a file it targets
```

A rule earns its place the same way a test does: it comes from a failure someone saw, it states what it predicts and when it should be pruned, and its `target_paths` name the files it is about (a rule with none applies to no file). Rules in this repository's `.aegis/rules/` govern Aegis itself. Rules in `rules/` ship to users, so they must be host-neutral, and `tests/unit/core/test_rule_lint.py` checks both sets.

## License

By submitting a pull request you agree that your contribution is licensed under the [Apache License 2.0](LICENSE). Data handling is described in [PRIVACY.md](PRIVACY.md), and vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues.
