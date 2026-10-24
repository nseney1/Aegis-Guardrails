# Contributing to Aegis Guardrails

Aegis is a Python package with no runtime dependencies. It supports Python 3.9 and later on Linux, macOS and Windows, so use the standard library only and no syntax newer than 3.9.

## Set up

```bash
git clone https://github.com/nseney1/Aegis-Guardrails.git
cd Aegis-Guardrails
make install   # editable install with the dev tools (pytest, ruff, build, ...)
make test      # the full suite, with HOME pointed at a throwaway directory
make lint      # ruff: syntax errors and undefined names
make build     # wheel and sdist into dist/
```

From a checkout without installing, `./aegis` or `python3 -m aegis_cli` runs the CLI. Tests must never read or write your real `~/.aegis`, `~/.claude`, `~/.codex` or `~/.gemini`: use the `tmp_path` fixture and a fake `HOME`, and mock host CLIs at the subprocess boundary. `make test` (and CI on Linux and macOS) runs the suite in parallel with `pytest-xdist`, so a test may not depend on order or write outside its temporary directory.

## Branches and reviews

- Branch from `develop` as `feature/<name>` or `fix/<name>`, and open the pull request against `develop`.
- The author of a change does not approve it. Every pull request gets an independent review: a maintainer, or an AI reviewer working in a separate context with a different lens than the author's.
- `main` takes release merges only (see [Releases](#releases)).

Larger work is split into lanes: one git worktree and branch per lane (`git worktree add -b lane/<name> ../lanes/<name> <base>`), each owning a disjoint set of files. A lane that needs a file outside its set stops and says so instead of editing it.

## Tests first

1. Write the tests for the new behavior, and run them: they must fail for the right reason (a missing name or a failed assertion, not a syntax error or a wrong call).
2. Write the smallest change that makes them pass.
3. Run the full suite (`make test`). Fix a regression in the code, not in the test, unless the test was wrong, and then say why in the commit.

Test what a user can observe: the CLI's output and exit code, an MCP response, the files written. Cover the failure paths, assert exact errors, and mock only the OS and network boundaries. When you delete a feature, delete its dedicated tests in the same commit and keep the tests of behavior that survives.

## Commits and the public surface

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`). A change to a command, an option or an MCP tool needs a `BREAKING CHANGE:` footer when it removes or changes something, plus three regenerated files in the same commit:

```bash
PYTHONPATH=. python3 tests/contract/test_cli_contract.py --write
PYTHONPATH=. python3 tests/contract/test_mcp_contract.py --write
PYTHONPATH=. python3 tests/contract/gen_reference.py --write
```

The last command writes [docs/reference.md](docs/reference.md); never edit that file by hand. When a change lowers the count of a legacy v3 word, `PYTHONPATH=. python3 tests/contract/test_legacy_ratchet.py --write` records the lower number (the test fails on a lower count too). Removing or renaming a public name pinned in `tests/contract/public_names_4_3_3.json` needs a `removed` entry there and a `Breaking:` line in the CHANGELOG. Also update `.github/scripts/wheel_smoke.py`, which calls the CLI, the MCP tools and the SDK against the built wheel and runs only in CI.

Docs: relative links must resolve (`tests/unit/test_docs_links.py`), the README must not repeat a retracted claim (`tests/unit/core/test_readme_claims.py`), and `rules/`, `skills/`, `docs/` and the README may not contain a path under `/home/` (a CI step greps for it).

## Releases

A release goes to `main` only after all of these hold for the exact commit being tagged:

1. An independent review of the release pull request.
2. CI green on that commit: `python3 .github/scripts/ci_green.py <sha>` exits 0 (it needs the `gh` CLI).
3. `aegis check` passes Layer 1. A Layer 2 review with a model from a different vendor than the one that wrote the change (`aegis check --full --plan-file <plan> --llm-cmd "<command>"`) is advisory: since 4.3.4 its verdict is logged and never changes the exit status, so it informs the release review but does not gate it.

A maintainer merges the release pull request into `main`, tags `v<version>` (it must equal `aegis_core/_version.py`; `.github/scripts/release_guard.py` refuses a publish otherwise) and publishes the GitHub Release. That runs `.github/workflows/publish.yml`, which ships the wheel CI already built and tested. The [CHANGELOG](CHANGELOG.md) entry describes what changed for users, and its date is set when the release is cut.

## Writing a rule

Rules are Markdown files with YAML frontmatter, one per file, in `.aegis/rules/<type>/<id>.md`. The six types are `invariant`, `trap`, `gate`, `boundary`, `persona` and `contract`. Create one with the CLI:

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
