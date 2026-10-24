# Changelog

All notable changes to Aegis Guardrails are documented here. The project uses [Semantic Versioning](https://semver.org/). Releases before 1.0.0 are summarized at the end.

## [Unreleased]

The 4.4.0 remediation waves land here; the section becomes `[4.4.0]` at release.

### Security

- **`aegis_capture_insight` is bounded.** It allows 5 calls per 60 seconds and 50 captures per session, and refuses more than 20 `paths` or a path longer than 512 characters; the dirty-path default keeps the first 20 and records `paths_dropped`. Hook rows do not count toward the cap.
- **`aegis check --ci --no-exec` runs no repository code.** It reads git objects only: it skips the regression and `Aegis-Check` trailer reruns, never reads or writes the ledger, says what it skipped (JSON `skipped`), and refuses `--coverage`, `--perf` and `--strict`.
- **A reviewed weakening can pass at tier A.** On a pull-request run, `aegis check --ci` accepts a flagged weakening or governance change when a person other than the author approved the head commit in their latest review, the rules of the pull request's base branch require an approval, code-owner review, stale-review dismissal and approval of the most recent push by someone other than its pusher, and the base `CODEOWNERS` owns every flagged path. A missing or unusual base branch name means no review approval and no `gh` call; `aegis doctor --github` builds its ruleset for the default branch only, so pull requests into other branches still need a signed approval. It makes read-only `gh api` GETs, refuses reviews by bots and apps, and fails closed on any doubt. The `aegis-check` job in `validate.yml` and in the scaffolded `aegis.yml` grants `pull-requests: read` and sets `GH_TOKEN` on the `check --ci` step; the JSON approval object gains `method` (`signature` or `review`).

- **A base-sourced governance check.** The new `aegis-governance` workflow runs only on `pull_request_target`. It checks out the base commit without credentials, fetches the pull request head as git objects only, and runs the base branch's own `aegis check --ci --no-exec`: no pull-request code is checked out, installed or run, and no secret is used. Its token reads contents and pull requests, and `GH_TOKEN` reaches the check step only, so tier A approving reviews count there too. As with the `aegis-check` step, the check step has no condition (the register planned a pull-request-only `if`); the trigger alone limits it to pull requests. GitHub runs `pull_request_target` workflows from the default branch, so it takes effect once 4.4.0 is on `main`; add `aegis-governance` as a required check after that.
- **Tree identity runs no program the repository chose.** `aegis check --record` and `aegis_report_outcome` switch off every filter driver that the repository's or a checked-out submodule's own config defines, read submodules without the work tree's `GIT_*` variables and with replace refs ignored, and turn off remote protocols, credential helpers and `core.sshCommand`.
- **T5 reads commit metadata without `git log`.** Two git calls (`rev-list` and `diff-tree`) replace it, so a configured `gpg.program` never runs.
- **`aegis check --ci --coverage` reads no repository coverage configuration.** It runs the user-scope `tests.command` (pytest-based only) with an empty rcfile in a private state directory and never reads the repository's `.coveragerc` or `coverage.json`. It still runs the repository's tests, as `--coverage` always has.
- **A short agent capture no longer blocks insight proposals.** The verbatim lint protects only human, `cli` and hook text, with a 25-character floor both ways and an exact match for short prompts; a one-character `aegis_capture_insight` quote blocked every proposal.

- **`aegis check` runs the security pack and the secret scan.** The 7-rule Python security pack and the known-format secret scan had no caller; they now run in every `aegis check` (also `--hook` and `--record`) on what a change introduces, judged against the diff base; the hook and `--record` scan every changed file for secrets (YAML, JSON, `.env` and so on), as plain `check` does, never copying them to the snapshot, and a staged file over 5 MiB gets a "not checked" note. An exact rename (`git mv`) is judged against the file's old text, and a `core.autocrlf=true` checkout against the same base as an LF one. Test paths are exempt but reported, `# aegis: allow[rule]` and `# gitleaks:allow` (also after `//` or `/*`) are honoured, an allow for a user rule never silences a different banned call on the same line, and a baseline never grandfathers these rows. A planted secret on a changed line fails Layer 1. On this repository Layer 1 over 147 files went from about 2 s to about 11 s (measured on a loaded machine).
- **The step summary renders pull-request text as inert data.** Finding text from the pull request, and the coverage UNVERIFIED reason, are placed in code spans, so they cannot inject Markdown, links or images into the job summary.
- **A proposal never quotes stored human text.** A `--summary` or `--kind` that repeats a stored human insight is refused even when the typed copy holds the raw email or home path that storage redacted.
- **`aegis doctor --fix` keeps a host config's permissions** (for example `0600` on `~/.claude.json`) when the file is swapped for a symlink during the fix, and atomic writes set the temporary file's mode through its open descriptor.
- **`aegis doctor --fix` and Aegis's host-config rewrites never write through a swapped-in symlink.** A file replaced by a symlink after the check is replaced, not followed, and `~/.aegis` and `~/.aegis/backups` are created with mode `0700`.

### Changed behaviour

- **`aegis sync --pr` puts the transitions in the pull request.** It cuts an `aegis/lifecycle-*` branch from the protected branch, commits exactly the moves and the examples to label, pushes the branch to the current branch's remote with your own credentials, opens the PR with `gh pr create --head`, and leaves your branch, index and tree as they were. It never merges. The push is unsigned and goes over https, ssh or a local path only. It refuses when HEAD is detached, not on the protected branch, or not equal to the protected branch's remote-tracking branch (fetch, or push your commits, first); when `.aegis/rules` or `.aegis/adjudications` has uncommitted changes; when no usable remote exists, a push URL has another scheme or is a local path inside the repository; when the repository's own config sets a program the push would run; or when git has no identity. When only `gh` fails, the pushed branch is kept and named; a push that never answers names the branch the remote may already hold. An archive proposed this way writes no local `lifecycle.jsonl` row, since the move exists only on the branch.
- The `aegis sync` table shows State, n, Weight and Score (blank below the 25-verdict minimum) instead of Fitness, Triggers, TP and FP. The `--pr` body states each rule's state, n and weight and the BASE commit its labels were read at, prints P(precision < 0.7) and the interval only for decided or inconclusive rules, and lists up to three replay detections per rule that are still unlabelled, instead of already-labelled rows.
- `derived.json` entries carry `n` and `p_below_demote`; `samples` is always empty.
- Detector replay walks the branch you name, else the user-scope `rules.base_ref` branch, else the protected branch, and never HEAD; with none it prints `replay skipped: no base branch`. Replayed catches carry the time of their evidence commit, so an old catch no longer clears newer exposure sessions.
- `aegis sync` and `aegis doctor` print `BASE as of last fetch N days ago` or `never fetched`, and `aegis sync --json` gains `base_fetch_age_days`. Aegis never fetches.
- A dangling `origin/HEAD` is read as absent, so the protected branch falls through to `main` or `master`.
- Layer 2 reports a review that did not happen as `unverified` with named reasons (`no_predictions`, `no_reviewed_files`, `skipped:N`, `unknown_category:N`, `spec_agent_unparseable`, `code_agent_unparseable`) in text and in JSON `unverified_reasons`, instead of SHIP. Exit codes are unchanged: Layer 2 is log-only.
- `aegis check --full` prints a one-line vendor advisory (JSON `vendor_warning`) when the user-scope `arbiter_vendor` is declared.
- CI: every job has a timeout, the `validate` matrix no longer fails fast, Windows runs the wheel smoke, pytest dumps the stacks of a test hung for 300 seconds, and `aegis-check` runs the installed wheel (`python3 -I`) with the same test dependencies as the other test jobs. `check --ci` runs only in `aegis-check`, and tier detection accepts `python3 -I -m aegis_cli.cli check --ci` as the whole of a step.
- **No rule is promoted without adjudicated labels** merged at the reviewed base: 25 with no false positive, or 42 with one, from at least 3 sessions and 2 repositories or 14 days. Local and CI-confirmed verdicts alone never promote. Known limitation: labels are kept per rule id and a move keeps them, so one label set can move a rule a step per explicit `aegis sync --apply` (trap to invariant, then to gate; or, when false positives dominate, down to archive). Each move is a rule-file change you review; `check --ci` flags the moves of binding rules.
- `aegis sync`, `aegis rule promote`, `aegis status`, `aegis rule archive` and `derived.json` show the one transition `Fitness.compute` decides. Demotion needs P(precision < 0.7) >= 0.9, so Wilson-only and small-sample demotions stop; a rule whose CI evidence cannot be read reads `insufficient` or `inconclusive` with `evidence_available: false` instead of the `evidence_unavailable` state.
- `aegis rule promote --tier-check` no longer changes an enforcement tier from ledger counts.
- `# aegis: allow[rule]` sites are no longer baselined, counted or reported as new, and the baseline keeps the rule's `where` clauses.
- `aegis check` prints `note:` rows (and JSON rows) for `forbid_ast` sites it could not decide and for test files a rule does not check, with "(N unverified, see notes)"; exit codes and `passed` are unchanged.
- The Python security pack ships 7 rules (the XML rule is removed). It reports unparseable files as unverified, scans dot-directories, and flags `Session().get(verify=False)` and `hashlib.new('MD5')`.
- A `check --ci` run whose base and head are the same commit prints "nothing was compared" instead of PASSED; the pull-request run is the gate.
- `aegis init` points at `aegis doctor --github` for the `CODEOWNERS` lines and the ruleset; it writes no `CODEOWNERS`.
- `aegis approve --exempt-test` refuses while governance files have uncommitted changes, as `aegis approve` already did.

- **T5 is a warning-tier report in 4.4.0.** It judges fix commits once against the pull-request head in at most 2 pytest runs, whatever the number of fix commits (at most 2 x the timeout). A test module that fails to collect on base now counts as fail-to-pass, a fix that a later commit in the pull request breaks fails, and a timed-out run says `timeout`.
- **Coverage is a report.** `aegis check --ci --coverage` never changes the exit code. A run that cannot be measured prints `coverage: UNVERIFIED (<reason>)`, never 0% or 100%. It diffs merge-base(base, head) to head, and reports UNVERIFIED unless the work tree is a clean checkout of `--head`: "the checkout is not <head>; check out the pull request head" (GitHub's default pull-request checkout is a merge commit) or "the work tree has uncommitted changes to tracked files". Untracked files are ignored.
- `aegis check --ci` prints a progress line on stderr before and after each T5 pytest run and each `Aegis-Check` trailer rerun. stdout is unchanged, and `--no-exec` prints none.
- The default base branch (`check --record`, `check --lane`, `approve`, the `check --ci` fallback, insights, `team metrics`, `verify`) is `origin/$GITHUB_BASE_REF`, then the branch `origin/HEAD` names, then `main`, `develop` or `master`, each as `origin/<name>` before `<name>`. A repository whose only branch is `master` now has a base.
- User and system clean filters (git-lfs, for example) now run during tree identity, as in any git command you type, so such trees can equal their commit's tree and earn T1 credit. A driver name that the repository's or a submodule's own config defines is still switched off, in every scope.
- `aegis rule insight review --decision` gains `confirm --insight ID [--kind K]`: a confirmed suggestion counts at level `cli`. Snooze, propose and merge-into-rule now hide a cluster; snooze and reject resurface it after 2 new insights. A `propose` whose proposal cannot be written (an invalid `--proposal-id`, or a `--summary` quoting a human prompt) exits 1 and records no decision.
- `aegis status` and `aegis sync` (text, and JSON `insights`) print each insight-born rule's recurrence, labelled `sessions = all heartbeat-alive sessions in this workspace (not scope-filtered)`, and `N unconfirmed agent suggestions (not counted)`.
- Insight rows gain add-only `source` and `corroborated_by` fields, and exposure rows carry each rule's digest prefix as `rev`.

- **`aegis check --ci` prints one verdict.** It never prints PASSED with exit 1: `FAILED: <first cause>` matches the JSON status, the new JSON `blocking` list (causes in priority order) and the exit code, and perf, coverage and `Aegis-Check` trailer results show in the text, GitHub and step-summary outputs. The text adds `scanners: none configured`, or the scanner results with a security-suppression count and its merge-base delta.
- The step summary is appended to, not rewritten.
- Security-pack and secret findings keep their SARIF fingerprint when lines move: their message no longer names the line, and `--format json` Layer 1 rows gain `lines`.
- SARIF logs hold only schema keys and anchored findings: a finding without a line (weakenings, governance, regressions) is never given one and goes to the annotations and the step summary; approved weakenings are notes, not errors; a failed run prints a valid empty log.
- `aegis check --ci --perf` no longer crashes on an UNVERIFIED reason, uses pytest-benchmark by default when it is installed, and reports UNVERIFIED when `--head` is not the checkout. An UNVERIFIED perf or scanner result never blocks.
- Aegis-Check trailers that 4.3.x recorded on commits adding calls the security pack flags no longer match a 4.4.0 rerun: re-record the trailer on in-flight pull requests.
- The pre-tool hook starts one git process per edit instead of two and reads the activity log once on an unscanned edit; its decisions, exit codes, messages and events rows are unchanged.

### Added

- `aegis-guardrails` is a second name for the `aegis-mcp` command: it starts the same MCP server, so `uvx aegis-guardrails` and the MCP Registry entry (`server.json`) can run it.
- `docs/trust-tiers.md` explains what each trust tier (A, B and C) protects and how to set a repository up for it.
- `aegis check FILES --format github|sarif` reports Layer 1 findings (reverses a 4.0 removal).
- The user-scope `scanners` key (`["ruff", "gitleaks"]`) runs those presets in `aegis check --ci`, from PATH outside the repository; only findings new against the merge base fail.
- `aegis check --calibration` is a registered flag. Layer 2 predictions are stamped and kept in `.aegis/state/arbiter_predictions.jsonl` with no model text (a symbol, selector or kind is kept only when Aegis can verify it); every disposition and outcome is computed from git when the file is read and stored values are ignored, and scores are per backend and observable kind.
- `aegis init --ci` writes an `aegis-sarif` job with a gated code-scanning upload. It is a separate job, so `security-events: write` never reaches the job that hands `GH_TOKEN` to the test reruns.
- Insight proposals are always an advisory `trap` with `kind`, `count` and `insight_ids`. Their `target_paths` are the insights' common directories weighted by how rare they are, as at most three `<dir>/**` globs (a top-level file is kept as its bare name, which matches that name in any directory), never `**`; insights without paths make `propose` exit 1 and point at `aegis rule insight add --paths`.
- `aegis rule insight add` prints the exact `Aegis-Approve-Insight:` trailer and a sign-then-re-run recipe (JSON `approval_trailer`, not stored), so an insight can reach level H. Following the recipe counts the correction once in review, proposals and recurrence: the earlier `cli` row is superseded by the signed one.

### Fixed

- A warm scan in a git repository starts 3 git processes (was 9, and 13 for an MCP scan); the first scan starts 4, and a scan outside git starts 1 (was 7).
- A scan reads the ledger once (was 3 times); an MCP scan reads it at most twice on a session's first scan and once afterwards (was 4); `aegis status` reads it once (was 5).
- A branch that keeps editing a rule no longer re-lists, re-reads and re-parses the BASE rules on every scan.
- git is looked up on PATH once per process instead of on every call.
- Detector replay reports how many commits it walked, how many files it skipped (`replay UNVERIFIED`) and that CI runs are not evaluated, and reports a git failure as `replay UNVERIFIED: ...` while still writing `derived.json`; `--json` gains `replay`.
- A Layer 2 reply entry that is not a JSON object is dropped and counted instead of failing the run.
- MCP tool text names `aegis rule insight review` (not the missing `aegis insights review`), calls insight ids random, says `failure`, `fp` and `fail` read as a neutral trigger, and marks `tests_passed`, `rework_count` and `notes` as ignored and never stored.
- A changed argument expression in a `forbid_ast` call (for example `build_safe()` to `request.args['cmd'] + x`) is now reported as new; a pure move or re-indent is not.
- The baseline judges a `forbid_ast` check by the rule version the gate enforces (the reviewed base), so narrowing the rule in the working tree or the index no longer hides a new violation, and a check whose sites do not account for every reported line cannot be baselined.
- The first `aegis sync` after upgrading replays the whole history once (the stored replay tip records its format), and again whenever the replay format changes.
- `aegis sync` replays detector history with batched reads, about 2 git processes per commit (was 19), and resumes from `replay.tip` in `derived.json` when only single-parent commits follow it.
- `aegis approve` signs with a passphrase-protected SSH key that is not in an agent: `ssh-keygen` asks for the passphrase at the terminal. In 4.3.4 it fell back to an `ssh-askpass` program and failed when none was installed.

- T5 judges a fix to a module named like a document (`src/security.py`, `app/history.py`, `src/doc/parser.py`); it skipped them as docs.
- A fix whose only tests are Go, TypeScript, JavaScript or Rust is reported as `[UNVERIFIED:regression/tests_not_pytest]` (a GitHub warning), not as a fix without a test.
- Diff coverage attributes every added line of a hunk, including lines that look like `+++` or `---` headers, and reads C-quoted paths (non-ASCII, tab, quote, backslash).
- The recurrence rate is alive sessions with a recurrence over heartbeat-alive sessions, so it is at most 1; sessions without a heartbeat are not counted, and the baseline excludes the triggering burst.
- A proposal's kind defaults to the single kind the cluster's human insights share, and text review lists each insight with its top-3 neighbours.
- Tree identity reports a tree as unbindable, instead of raising, when git times out or is missing.

- `aegis migrate --apply` says `state modes: tightened N of M loose entries` instead of offering to tighten them, and outside git neither `aegis doctor` nor `aegis migrate` counts or changes the modes of the workspace's `.aegis/state`.
- `aegis hook uninstall` removes Aegis's prepare-commit-msg hook even when the pre-commit hook is missing, user-owned or refused, and leaves a pre-commit hook that is not UTF-8 unchanged (reported) instead of failing with a codec error.
- `aegis rule adjudicate` exits 1 and writes nothing for an id that is not a cleanly loading rule (a typo, a case variant, an `.md` name, an archived or broken rule).

### Breaking (command line, JSON and MCP)

- Breaking: `aegis check --ci --strict` exits 2 as a usage error ("--ci does not combine with --strict"); `--strict` keeps one meaning, failing on checkpoint warnings without `--ci`. `--no-exec` refuses only `--coverage` and `--perf` as running repository code. The user-scope `regression.tier` key and a `require_regression` attribute are ignored.
- Breaking: the JSON `coverage` block loses `passed`, `coverage`, `threshold` and `uncovered_by_file`. It has `status` (`reported` or `unverified`), `reason`, `covered_lines`, `executable_lines`, `ratio` (null when nothing was measured), `uncovered_ranges` and `unmeasured`.
- Breaking: the fail-to-pass reason `collection_error_on_base` is gone; the reason `timeout` and the status `unverifiable` with reason `tests_not_pytest` are added.
- Breaking: MCP `aegis_capture_insight` captures stay at level `suggestion` and never become `W2`. A same-host hook prompt containing the quote (12 characters or more) within 30 minutes only annotates the capture with `corroborated_by`, and the correction counts once.
- Breaking: "exposed and ignored" needs a persisted exposure by the same host within 30 minutes at the rule's current rev (exposure rows written before 4.4.0 carry no rev and match any). Agent outcome reports, scan rows and in-memory exposures no longer count, and insights added with `aegis rule insight add` (host `cli`) never join an agent's exposure.
- Breaking: `aegis rule insight review --decision` needs `--cluster` (or `--insight` for `confirm`), and `reject` needs `--reason` (exit 2). An unknown cluster or suggestion id lists the valid ids and writes nothing (exit 1). JSON review output emits neighbours once; the per-cluster `neighbours` key is removed.
- Breaking: tree identity makes a tree unbindable when the repository's or a checked-out submodule's own config defines a filter driver whose name `git -c` cannot carry (containing `=` or bytes that are not UTF-8), or when checked-out submodules nest more than 16 deep.

- Breaking: `aegis check --coverage` and `--perf` outside `--ci` exit 2, and `--json` with `--format github|sarif` is a usage error (exit 2).
- Breaking: `perf.command` is read only from `perf.command` under `perf` in `~/.aegis/config.json`; a dotted top-level key is ignored, and the perf JSON loses `advisory`.
- Breaking: SARIF alert fingerprints are now stable under line moves and unique per run, so GitHub reopens existing Aegis alerts once.
- Breaking: JSON `llm_predictions` rows carry `scope` `{path, symbol}` and `observable` `{kind, selector}` and drop `resolved_at` and `resolving_commit`; an observable that is not such an object is void.
- Breaking: `aegis rule insight review --category` is removed. A proposal's kind is the one its insights share, or the `--kind` given with `--decision propose`; with neither, `propose` exits 1 and asks for `--kind`.
- Breaking: `rule insight add --commit` checks the `Aegis-Approve-Insight` hash against the text as typed, so approvals signed over redacted text no longer verify for texts that redaction changed.

### Breaking (internal `aegis_core` and `aegis_cli` API; `aegis_sdk` is unchanged)

- Breaking: `aegis_core.fitness.Fitness.samples` and the `samples=` parameter of `aegis_core.fitness.compute` are removed.
- Breaking: `aegis_core.verification.arbiter` loses `structural_ship_gaps`, `prune_predictions`, `PruneResult`, `check_vendor_independence` and `Z95` (and the `Path` and `is_test_path` names it imported); `arbitrate` loses `infra_status`, `changed_files`, `all_files`, `rule_miss_counts`, `arbiter_vendor` and `generator_vendor` and takes `gaps=`.
- Breaking: `aegis_core.verification` loses `Prediction.claim_type`, `target`, `horizon_commits` and `Prediction.from_dict`, and `ArbitrationResult.decision`, `confidence`, `rationale`, `structural_gaps` and `vendor_warning`; `aegis_core.verification.pipeline` loses `VerificationPipelineResult.layer1_verdict`, `infra_status` and `llm_predictions`, and `Arbiter.arbitrate` no longer takes `**kwargs`. `AdversarialVerifier.verify` and `extract_target_data` return four values, and `adversarial_verify.parse_predictions` and `parse_claims` return `(items, dropped)`.
- Breaking: `aegis check --full --json` prediction rows no longer carry `claim_type`, `target` or `horizon_commits`.
- Breaking: `aegis_cli.status.collect_status`, `aegis_core.ast.policy.evaluate_forbid_ast_with_overrides`, `aegis_core.verification.security_pack.build_python_security_pack` and `is_test_path`, and the `aegis_core.lifecycle.constants` names `MIN_PROMOTION_VERDICTS`, `PROMOTION_THRESHOLD`, `TIER_UP`, `TIER_DOWN_MISFIRE` and `MISFIRE_THRESHOLD` are removed. `evaluate_forbid_ast_structured` returns a findings list, and `evaluate_security_pack` takes `(root, changed_files, base_sources)`.
- Breaking: `aegis_cli.approve.datetime` and `aegis_cli.approve.timezone` are no longer importable (`aegis_cli.approve` no longer imports them).

- Breaking: `aegis_core.regression.VALID_TIERS` and the `tier=` argument of `aegis_core.regression.check_ci_regressions` are removed.
- Breaking: `aegis_core.verification.coverage_check.evaluate_diff_coverage` and `aegis_core.verification.coverage_check.verify_coverage_threshold` are removed, and `run_diff_coverage(root, base, head)` takes no other parameter.

- Breaking: `aegis_core.verification.scanners.build_preset_argv` and `aegis_core.verification.scanners.run_preset_scanner` are removed (use `run_preset`), and `ingest_sarif` loses `base_fingerprints=`.
- Breaking: `aegis_cli.formatters.report.format_github_annotations` and `aegis_cli.formatters.report.SarifReport` are removed; `format_sarif_report` returns a plain `str`.
- Breaking: `aegis_core.verification.arbiter.brier_skill_score`, `score_predictions`, `calibration_summary` and `CalibrationSummary` are removed (use `calibration`); `Prediction` loses `resolved_at` and `resolving_commit`; `perf_check.run_perf_check` loses `command=`.
- Breaking: `aegis_core.insights.write_proposal` no longer takes `rule_type`, `enforcement`, `category` or `target_paths`; it takes the counted `insight_ids`, plus optional `summary_bullets` and `kind`.

### Corrections

- The 4.3.0 entry for the accountable Layer-2 arbiter advertised deterministic structural SHIP gaps, a vendor-family warning and 60-day prediction compaction. None of that code had a caller; 4.4.0 removes it, and the advisory above replaces the warning.

## [4.3.4] - 2026-10-20

4.3.4 is a security and repair release. It fixes the user harms of 4.3.0-4.3.3 and the trust claims the 4.3 review found forgeable. **4.3.3 never reached PyPI**: its publish run failed on a Windows wall-clock test (`test_100_rules_scan_in_under_a_second`, 1.5 s against a 1.0 s limit) and never uploaded, so PyPI goes from 4.3.2 to 4.3.4.

### Security

- **`aegis rule insight enable` no longer destroys host settings.** It refuses a settings file it cannot read back whole (unparseable, JSONC, BOM, non-UTF-8, wrong shape) or that is a symlink, hard link or FIFO, and leaves it byte-identical. Otherwise it merges, keeps everything else, backs the file up to `~/.aegis/backups/` first and re-reads the result. The insight hook entry is now written by the hook registrar, under the same rules as the PreToolUse hook. The entry runs the interpreter that wrote it, not whatever `python3` is first on `PATH`. A 4.3.0-4.3.3 entry ran `python3 -I`, which fails where Aegis is not installed in the system Python; it stays as it is until you re-run `aegis rule insight enable`, which replaces it.
- **Secrets are redacted.** The `key=value` pattern never matched in 4.3 (an f-string turned `{4,}` into a format field), so values such as `password=...` and `API_TOKEN=...` were stored as written. Stored insights, `aegis_capture_insight` and hook logs now share one bounded pattern table that also covers prose (`the password is ...`), `Authorization` headers and every format the Tier A detector blocks (all AWS key id prefixes, and `://user:pass@host` with or without a scheme). A private key cut by the length bound is dropped whole. Redaction time is linear in its input, and a prompt longer than 4,096 characters is scanned through its first 4,096 (past that only a whole-word head is kept). **Exposure:** insight rows written by 4.3.0-4.3.3 may hold raw `key=value` secrets; there is no scrub command, so delete `~/.aegis/insights/<workspace-id>.jsonl` if that matters to you.
- **Reads make no GitHub call.** `aegis_scan`, `aegis_list_rules`, `aegis status`, `aegis rule list`, metrics, packs, the hooks and the SDK no longer start `gh` (a scan made 14 `gh` calls with 7 CI rows in the ledger). Only `aegis doctor`, `doctor --release`, `aegis sync` and the promote, demote and archive decisions read GitHub; a dead `gh` costs one attempt per projection. PRIVACY.md lists them.
- **Publishing runs only on a published release.** `publish.yml` has no manual trigger, and a `guard` job checks that the ref is the tag, that the tag is `v` + the package version and that the tag's commit is the commit being built. Before uploading, the job reads PyPI: it uploads only the files PyPI lacks, succeeds when PyPI already holds identical files, and fails without uploading on a digest mismatch or when PyPI cannot be read. A failed release is re-run with "Re-run failed jobs".
- **CI-confirmed credit can no longer be steered from the ledger or local refs.** Confirmation reads the required workflow the caller names and the default branch GitHub reports; a `ci` row naming another workflow, or a locally repointed `origin/HEAD`, no longer confirms credit. Which repository is asked is still local: credit calls `gh api repos/{owner}/{repo}`, so `gh` resolves the repository from `GH_REPO` or its own choice among the clone's git remotes (and `gh repo set-default`), all of which the agent can change.
- **The agent no longer chooses the sign or scope of its own credit.** A `failure` or `fp` report on a CI-confirmed check is a neutral trigger, never a false positive; only a `success` report on a passed check earns a true positive. `aegis_report_outcome` credits only rules this server process's own scans showed; exposure rows written into the ledger no longer widen the credited set.
- **PGP and X.509 approvals are refused.** Approvals, test exemptions and insight approvals verify only as SSH signatures against the base branch's `allowed_signers`; a PGP or X.509 signature returns `bad_signature`. Every git command Aegis runs through `gitsafe` sets `log.showSignature=false` and points `gpg.program`, `gpg.openpgp.program` and `gpg.x509.program` at the null device, so no signature program named in repository or user git config starts (the tree-identity reads in `treeid` never verify signatures). Existing SSH approvals still verify: the approval hash is unchanged.
- **The prepare-commit-msg hook no longer runs repository trailer commands.** It adds its `Aegis-Check` trailer without reading the repository's git config, so a repository `trailer.<alias>.cmd` or `.command` no longer runs during `git commit` (a trailer command in your user or system config still runs, as for any git command).
- **Windows path containment.** The fallback tree export (`aegis check --record`, the regression check) skips entries with a drive or stream component (`D:x`, `x:stream`) and checks that every joined path stays below the snapshot; rule ids containing `:` are rejected on Windows. Nothing changes on POSIX.
- **Tier B is reported honestly.** At tier B the required checks run the pull request's own workflow, so SECURITY.md's truth table no longer ticks Tier B for human-approved weakenings (partial), CI-confirmed credit (as Tier C) or release attestation (✘), and `aegis doctor --release` reports tier B as `agent_editable` and exits non-zero instead of printing `VERIFIED`. Credit's attestation fallback no longer confirms credit at tier B.
- **`aegis check --ci` gates the governance set, not only rule weakenings.** In 4.3 an added `allowed_signers` key plus a new workflow passed `check --ci`. When the base branch lists at least one key in `allowed_signers`, a pull request that changes `allowed_signers`, `CODEOWNERS`, a workflow, `.aegis/config.json`, `team.json` or `baseline.json`, test infrastructure, or deletes a test now fails without a signed `Aegis-Approve` from a key already on the base. With no key on the base it prints a tier C note and passes.
- **Narrowing a rule's reach is a weakening.** A `forbid_ast.calls` entry whose `where` tightens, that gains `builtin`, or is renamed; a `target_paths` list that drops any pattern the reviewed rule had (even when no existing file loses coverage) or newly skips tests; and a widening of a mandatory rule onto a path that already has two mandatory rules now need an approval and are served as the reviewed version until merged. This replaces 4.3's "lost coverage of existing files".
- **Nested workspaces are governed.** `check --ci` and serving in a workspace below the git top level checked zero rules and missed renames, and telemetry credited no rule; path frames are now translated, and `.aegis` rules, config, team and baseline files at any depth are governance.
- **A committed runner module no longer forges a passing check.** A root `pytest.py`, `_pytest`, `pluggy`, `py` or `iniconfig` module (as a source, `.pyw` or compiled file, or a package with any `__init__` or `__main__`) is test infrastructure and withholds credit until approved.
- **Destructive-command guard evasions are closed.** Commands after a blank line or a separator plus newline are checked; abbreviated long options of the blocked git and `rm` commands (`--force-w`, `--har`, `--recurs`), the `ionice`, `stdbuf`, `setsid`, `busybox`, `su -c` and `env -S` wrappers, option bundles such as `sudo -Eu root`, and non-canonical `dd of=//dev/sda` paths no longer hide a blocked command, in both the pre-tool guard and `aegis hook safety-gate`. In the pre-tool guard (the gate already asked for these), same-line git aliases (`git -c alias.*`, inline `GIT_CONFIG_*`, including a `!` alias that calls another and an alias defined by `-c` inside another alias's words) and quote-bearing shell comments no longer hide one either. `git clean` spellings that git treats as real deletions (`-e -n`, `-- -n`, `--no-dry-run`, `-e x -e -n -f`) are no longer taken for dry runs, while real dry runs that give `-e`/`--exclude` a separate value (`git clean -fdx -e .env -n`) are not blocked.
- **Fewer agent-writable evidence paths count.** A plain `aegis check` writes triggers, not tp/fp rows, and native session tp/fp rows already in a ledger read as triggers. Adjudication labels count only as `.aegis/adjudications/<rule-id>.jsonl` at the reviewed base branch (a governance path); ledger `adjudication` rows, which any process can write, never count. Leaked violations are dispositions, not false positives, and frontmatter is no longer an evidence channel. Residuals until labels become the only promotion path (planned for 4.4.0): hand-written ledger rows marked `source: "ci"`, session rows carrying `from`, and forged `caught` detection rows still count, and on a developer machine the "reviewed base" is whatever the local `origin/HEAD` or `rules.base_ref` points to, which the agent can move. Local fitness is a label; the decision that counts is the reviewed pull request that moves a rule file, which `check --ci` gates (SECURITY.md).
- **Tier detection can no longer be satisfied by settings an agent controls.** Tier B requires each required check's source pinned to an app (`aegis doctor --github` pins GitHub Actions), and Tier A reports an unpinned source as a caveat; Tier A requires `dismiss_stale_reviews_on_push`; the required check must be the Aegis job (read from the base branch's workflows) with no path filter and no condition that could skip it or let it pass without running `check --ci`; a bare `@org` CODEOWNERS owner does not count for an organization-owned repository. `ssh-keygen` is found only outside the repository.
- **`forbid_ast` rules can no longer be emptied by their own predicates.** The `where` grammar is four forms validated at load; a rule using a removed operator, an empty `where`, `unknown` or `call` fails closed at load instead of passing every file.
- **Scanner fences.** Scanner presets and a bare `perf.command` program are found only outside the workspace; a repository `.gitleaks.toml` makes the gitleaks preset `unverified` instead of configuring it; SARIF is read only inside the workspace; a malformed SARIF file or a scan that did not demonstrably complete is `unverified`; the secret scanner no longer skips lines over 4,096 characters, finds Tier A tokens after a data-URL prefix and after `_`, `-`, `/` or `+`, and masks the secret-shaped values on a finding's line (a URL password that starts with a placeholder word such as `test` stays visible).
- **Credit and release evidence no longer rest on state the agent writes.** A Layer-1-only `aegis check --record` row earns no `witness: aegis` credit or `exit=0` trailer; credit's approval lookup accepts a ledger row's base only when it is a full commit id on the protected branch's history at or after its last change to `allowed_signers` (so a removed key cannot be brought back); credit no longer falls back to `gh attestation verify` with ledger- and local-derived pins; `aegis doctor --release` pins the source ref to the default branch GitHub reports (failing closed with `default_branch_unknown` or `source_ref_mismatch`) and, at Tier A, reports `not_approved` unless the merged pull request was approved on its head by someone other than its author.
- **Local `aegis check` enforces the reviewed rules.** Plain `aegis check` and the pre-commit hook enforce the base version of `forbid_ast` rules: in a clone where `origin/HEAD` resolves a branch can no longer weaken or delete a gate locally, a gate new on the branch blocks only once it reaches the base, and a malformed new gate still fails closed. In CI, where `origin/HEAD` is not set, the base is the checked-out commit, so plain `aegis check` enforces the pull request's own rules there and `aegis check --ci` catches a deleted or weakened rule.

### Changed behaviour

- In a fresh process, scan-time fitness ignores CI-confirmed credit; `aegis sync`, `rule promote`, `demote` and `archive` still verify it (the read-path change above).
- When `gh` fails while `aegis sync`, `aegis rule archive`, `aegis rule promote --tier-check` or the promote evaluation is checking CI results (including inside sync's own CI confirmation), checking stops and the rules' evidence is reported as unavailable, so no decision is made on partly checked credit: sync applies nothing, archive refuses with the reason, and tier changes are reported but not written. The error names the commit and how many commits were left unchecked; it is in `--json` and `derived.json`, and the text output of `aegis sync`, `aegis rule archive` and `aegis rule demote` prints it once as an "Evidence unavailable" line. With no working `gh`, this happens whenever the ledger holds CI rows to verify.
- `aegis hook uninstall --host` also removes the insight capture entry; a file that held only that entry is rewritten, with a backup.
- On Windows, `aegis rule insight enable --host codex-cli` refuses and writes nothing (Codex runs hooks through `%COMSPEC%`). Codex users must trust the re-written hook in Codex's `/hooks` screen.
- A relative `CLAUDE_CONFIG_DIR` or `CODEX_HOME` is ignored when locating the insight hook's file.
- Hook logs redact more formats. An `Aegis-Approve-Insight` trailer signed over 4.3 text that held a `key=value` secret stops verifying, because the stored text is now redacted.
- `publish.yml` loses its `workflow_dispatch` trigger, and release runs no longer produce or need a verdict attestation (`validate.yml` still runs the verdict on pushes to `main` and on dispatch).
- `aegis check --full` exits on Layer 1 only. A Layer 2 `BLOCK` or `REVISE` is printed and reported as advisory (`layer2.advisory: true` in JSON); a Spec Agent reply that cannot be read prints `Layer 2: UNVERIFIED` instead of `BLOCK`. Rule telemetry from `--full` records the Layer 1 result. A model command that cannot run, or a failed test discovery, still exits 1 but no longer writes `fp` rows.
- `aegis rule insight add` no longer accepts `--host` or `--session` (usage error, exit 2); CLI insights carry no session identity.
- The MCP write tools `aegis_report_outcome` and `aegis_capture_insight` declare only `readOnlyHint: false` and a title, reverting the extra hints added in 4.3.2, so hosts that honour hints prompt before running them again.
- `aegis sync` and the promote, demote and archive decisions make one extra read-only `gh api repos/{owner}/{repo}` call per process to read the default branch; if GitHub cannot name it, the credit stays landed and the evidence is reported unavailable.
- `~/.aegis/config.json` has one reader for `tests.command`, `rules.base_ref`, `perf.command` and `regression.*`: a config whose `v` is not 1 is ignored by all four, `perf.command` is honoured in a BOM-prefixed file and capped at 64 KiB, an unsplittable `perf.command` is ignored instead of crashing the perf check, and those four keys no longer trigger the unknown-key warning.
- `VerificationPipeline.run` and `DeterministicVerifier.verify` called without `changed_files` outside a git work tree (or when git fails) raise `ValueError` instead of returning a clean pass.
- PGP and X.509 approvals are refused (see Security); re-sign governance changes with an SSH key.
- `aegis doctor --release` at tier B reports `agent_editable` and exits non-zero (see Security).
- The fallback tree export refuses `''`, `.` and `..` path parts, so `a//b`, `a/./b` and `a/x/../b` are skipped instead of normalised; git trees never contain them.
- `aegis check --ci` enforces the governance set when the base lists a signer (see Security). `pyproject.toml`, `setup.cfg` and `tox.ini` count only when their pytest section changes and the file is a regular file on both sides (a symlink or other type change is gated whole; any root `tool` value or backslash-escaped TOML key counts as pytest configuration), so a pytest plugin entry point, a dependency or a `tox.ini [testenv]` command change is not gated. The checked workspace's own rule edits stay under the weakening check; another workspace's `.aegis/rules/` (or a case variant) is governance. If the base already holds a symlinked `pyproject.toml`, `tox.ini` or `conftest.py`, an edit to the file it points to is not gated. The JSON report gains a `governance` object; the schema name is unchanged. A Tier A team that keeps an `allowed_signers` file needs a signed approval for governance changes.
- Approvals bind the tests a branch deleted: an approval signed under 4.3 for a branch that also deleted tests no longer verifies, and a branch that only deletes tests can now be approved. An approval signed under 4.3 also stops verifying in a repository that tracks a nested `.aegis` file or a root runner module, because those paths now enter the approval hash; elsewhere the hash is unchanged.
- A `CODEOWNERS` file written before 4.3.4 loses Tier A until it gains the lines `aegis doctor --github` prints (runner modules, adjudication labels and nested `.aegis` files are now governance). Those lines now include `/.aegis/adjudications/` and `**/.aegis/rules/`, `**/.aegis/adjudications/`, `**/.aegis/config.json`, `**/.aegis/team.json` and `**/.aegis/baseline.json`; a Tier A repository that applied the lines of an earlier 4.3.4 build should re-apply them, or it drops a tier when it merges its first label or tracks a nested workspace. A repository with real top-level packages named `py`, `pluggy` or `_pytest` is gated.
- `rules.base_ref` anchors at the merge base with HEAD, as `origin/HEAD` already did; the tip is used, and labelled, only when there is no common history.
- A short-option bundle stops at the first letter that takes a value, in the guard and the gate, so `git checkout -bfeat`, `git checkout -Bfix` and `git push -ofeature origin feat` are no longer flagged as forced.
- The guard no longer reads text inside a shell comment as arguments (`rm -rf build # remove /` is no longer blocked); `dd of=/dev//null` is allowed and `dd of=/dev/` no longer matches; `aegis hook safety-gate` also asks for `dd of=<device>` without `if=`, `git push -fu`, `git checkout -fq`, `git add -Av` and inline `GIT_CONFIG_*` variables. The guard and the gate stay separate policies, pinned by a parity table.
- Breaking: `forbid_ast` drops the operators `not_equals`, `not_in`, `equals`, `present`, `is_literal`, `not_literal`, `contains`, `not_contains` and `matches`, the per-call `unknown` key and the `call` alias (listed as supported in 4.3.0 to 4.3.3); `where` takes a scalar, `in`, `not` or `absent`. Rewrites: `not_equals: X` becomes `not: X`; `not_in: [...]` becomes `not: {in: [...]}`; `equals: X` becomes `X`; `present: true` becomes `absent: false` (and `present: false` becomes `absent: true`). `is_literal`, `not_literal`, `contains`, `not_contains` and `matches` have no equivalent: drop the predicate or narrow the call entry by `name`. A rule that uses a removed form fails at load and, in a clone where `origin/HEAD` resolves, blocks every local commit, because local checks enforce the reviewed (base) copy. To recover: rewrite the rule, commit with `git commit --no-verify`, and open the pull request. CI's plain `aegis check` enforces the pull request's own rules; `aegis check --ci` may flag the rewrite as a weakening, which needs an `aegis approve` from a key in the base's `allowed_signers` (or a maintainer's merge). Once it is merged, local checks work again.
- Breaking: `aegis rule adjudicate` writes `.aegis/adjudications/<rule-id>.jsonl`, and a label counts only after it is merged to the base branch. Ledger `adjudication` rows from 4.3.x stop counting, so until labels are merged almost no rule is promoted.
- Breaking: promotion, demotion, tier changes and archive-by-misfire need 25 verdicts (`MIN_N`), and no precision number is shown below 25. Calendar days no longer decay a rule; decay counts sessions. `prior`, `pack_prior`, `trigger_rate_per_day` and `expected_triggers_per_day` are inert, and `expiry.*` is accepted and ignored.
- Breaking: a plain `aegis check` no longer moves tp or fp; `aegis check --full` telemetry records triggers.
- Tier detection reports lower tiers for rulesets made before this release: an unpinned check source reports C instead of B, Tier A needs `dismiss_stale_reviews_on_push`, the required check must be the Aegis job without a path filter, and a bare `@org` CODEOWNERS owner stops counting for an organization. A missing local signing key no longer downgrades Tier B (it becomes a caveat). `aegis doctor --github` requires only the Aegis job and pins its source. The Aegis job counts only when nothing can skip it and its `aegis check --ci` step can fail it: no job condition other than `always()`, `needs:` only with `if: always()`, no `continue-on-error`, no custom shell, and a step whose whole `run` is the command itself (a `run: |` block with setup lines before the command no longer counts; give the command its own step). The `doctor` reason says what to set. Residuals: another job reporting the same check name, and earlier steps or `env:` that replace the `aegis` program, are not visible in the workflow text.
- `Aegis-Exempt-Test` trailers must name the full commit id (short prefixes stop verifying); the signed reason no longer has to repeat the no-test reason word for word; a rejected exemption names its verdict in the `check --ci` report, and only when its `Aegis-Exempt-Test` line names that fix (an unrelated `Aegis-Accept:` line no longer shows up as a rejected exemption).
- `--perf` benchmarks the merge-base through an export instead of `git worktree add`, and a base that does not resolve is `unverified`.
- A bare mention of a PEM header no longer gates; key material is required. Placeholder suppression matches whole words.
- `aegis check --ci` reruns only the head commit's `Aegis-Check` trailer, with the same recipe and 1,800 s timeout as `aegis check --record --tests`; a timeout or git failure is `unbound`, never a failed job.
- Credit is voided when `aegis check --lane`'s integrity gate fails (`lane_integrity`) and when its landing commit is reverted (`reverted`); a later CI success still supersedes a CI-failure void.
- New user-scope key `ci.workflow` names the workflow whose runs confirm credit (default `validate.yml`, so a repository that used `aegis init --ci` with `aegis.yml` can now confirm credit); `aegis doctor` and `doctor --github` print it and warn when it is missing at HEAD, and `aegis init --ci` says how to set it.
- `aegis doctor --release` makes one more read-only `gh api` GET (the repository's default branch) and, at Tier A, two GETs of the merged pull request and its reviews; git failures become a `git_failed` JSON report, and every doctor report shows the trust tier or why it is unknown.
- A bare `pytest` or an absolute interpreter in `tests.command` runs hermetically under the documented flags (the interpreter's own site dirs, not the user site); `aegis check --record --tests` prints a hint when that interpreter has no pytest. On Windows the test-run group is killed with `%SystemRoot%\System32\taskkill.exe`; descendants left after a normal exit are not swept.
- The insight hook writes a text-free heartbeat with a cue flag on every prompt that carries a session id, plus one inventory row per rule-set change; a prompt without a session id writes nothing. It no longer runs a submodule's clean filter for dirty paths, and deleted or merely touched files are not dirty. `aegis rule insight add --paths a,b` no longer splits on commas.
- `check_test_coverage` applies Aegis's own test-name map only to `aegis_*` and `soma_*` packages, so other repositories now see the "Missing test file" warnings it used to hide.
- A check row without a passing tests run, including a 4.3.x Layer-1-only `aegis check --record` row, no longer earns confirmed credit (reason `no_tests`); record again with `--tests`.
- `aegis check --record` and the trailer rerun enforce the snapshot's own gate rules, even when the temp directory sits inside another git repository; plain `check` enforces the working-tree rules when the reviewed base does not contain the workspace.

### Fixed

- The wall-clock assertions that failed Windows legs (a 1.0 s scan budget, a 300 ms hook median, a 40 ms insight-hook budget) are replaced by spawn and ledger-open counters and one baseline-subtracted overhead test. The report-flood test makes `cap + 50` calls instead of 10,000 (about 70 s shorter per leg).
- `.github/scripts/ci_green.py` drops unused pagination and `--repo` options, and `aegis_core.credit` now skips a CI run with a non-integer id the way `ci_green.py` does instead of raising.
- `aegis_scan` called with `files: []` records its git-diff scan, so the scan-before-edit hook and `aegis status --compliance` see it; `aegis_report_outcome` computes the work tree once per report.
- Hook insights recorded from a subdirectory (or with `CLAUDE_PROJECT_DIR` set) land in the governed workspace's insights file, so `aegis rule insight review` sees them. Files already written under subdirectory ids are not migrated.
- A Layer 2 review that did not complete is recorded in the ledger as `UNVERIFIED`, not `SHIP`, matching the text and JSON output.
- Layer 2 risk text from the model, and the `Layer 2 failed` and test-discovery error lines, print as one sanitized line of at most 300 characters.
- `gitsafe.list_files` is documented as returning workspace-relative paths, which it always did.
- Destructive SQL in a heredoc read by a SQL client (`psql`, `mysql`, `sqlite3` and others) or run by a shell is recorded again, as in 4.2.0.
- When an approved change is blocked by a failing regression or trailer check, the `check --ci` headline names that check instead of "without approval".
- `builtin: true` shadowing follows Python scoping, and a call site with no argument information makes `where` unknown instead of a match or a pass.
- `gitsafe.merge_base` resolves a full commit id once instead of twice, and `checkrun`'s snapshot rerun validates its revision first.
- A scan's `unreviewed_rules` list fits the token budget (`unreviewed_total` gives the true count; long ids are clipped to 80 characters); a scan that matches no rule reads no ledger; reading the reviewed base takes two git calls and parsed base rules are cached; a CRLF checkout of LF rule files takes the fast path.
- Insight paths that resolve outside the workspace are refused on the CLI, the MCP tool and the core API alike; captures parse only the log rows they need.
- `find_approval` reads commit messages in one batch instead of about four git calls per commit.
- `aegis doctor --release` skips review entries that are not objects and prints its JSON report instead of a bare error.

### Breaking (internal `aegis_core` and `aegis_cli` API; `aegis_sdk` is unchanged)

- Breaking: `aegis_core.insights.enable_host_hook` is removed; the registrar writes host files (`aegis_cli.hooks.registrar.install_insight_hook`, `edit_hook_file`), and core keeps the pure `merge_insight_hook` and `remove_insight_hook`.
- Breaking: `aegis_core.insights.redact_secrets` and `aegis_core.insights.shannon_entropy` are removed; redaction lives in `aegis_core.verification.scanners`.
- Breaking: `aegis_core.verification.scanners.redact_secrets`, `aegis_core.verification.scanners.redact_hook_text`, `aegis_core.verification.scanners.redact_payload` and `aegis_core.verification.scanners.HOOK_REDACTION_PATTERNS` are removed in favour of the one pattern table.
- Breaking: `aegis_cli.hooks.redaction.HOOK_REDACTION_PATTERNS` and `aegis_cli.hooks.redaction.redact_payload` are removed.
- Breaking: `aegis_cli.verify.verdict_to_exit_code` is removed; Layer 2 no longer maps to an exit code.
- Breaking: `aegis_core.insights.add_insight` loses its `host` and `session` keyword arguments.
- Breaking: the incidental re-exports `aegis_core.regression.UserLayout`, `aegis_core.rule_integrity.UserLayout`, `aegis_core.rule_integrity.Path`, `aegis_core.checkrun.UserLayout`, `aegis_core.checkrun.AegisError` and `aegis_core.verification.perf_check.UserLayout` are removed; import `UserLayout` from `aegis_core.workspace.layout`, `AegisError` from `aegis_core.errors` and `Path` from `pathlib`.
- Breaking: `aegis_core.human_gate.workflow_contexts` is removed in favour of `aegis_check_jobs`; `human_gate.verify_test_exemption` and `find_test_exemption` lose their `expected_reason` argument.
- Breaking: `aegis_core.fitness.decay_factor` is removed and `fitness.compute` loses `half_life_days`.
- Breaking: `aegis_core.verification.scanners.ingest_sarif` takes a parsed document and drops `base_sarif` and `diff_text`; `build_preset_argv` and `run_preset_scanner` drop `config_path`.
- Breaking: `aegis_core.release_verify.verify_release` loses `environ`, `workflow` and `expected_run`; `aegis_core.credit.project_credits` loses `attestation_runner`; `aegis_core.credit.check_ci_divergence` takes a parsed trailer only.

### Corrections

- The 4.3.0 entry's `< 40ms` insight-hook latency was never measured: the capture hook takes about 66 ms per prompt at 58 rules (a bare interpreter starts in about 9 ms).
- The 4.3.0 entry's "4 KB line chunking" for the secret scanner never existed: the scanner skipped lines over 4,096 characters until 4.3.4.

## [4.3.3] - 2026-10-17

### Changed

- **MCP `outputSchema` and `structuredContent` support (`aegis_mcp.registry`, `aegis_mcp.server`, `docs/reference.md`).** All 5 MCP tools now declare formal JSON Schema `outputSchema` definitions, and `_tool_result` emits `structuredContent` on non-error dict responses alongside `content` text blocks.
- **100% MCP `inputSchema` property coverage and TDQS description remediation (`aegis_mcp.registry`, `tests/contract/mcp_tools.json`).** Added missing parameter descriptions on `aegis_report_outcome` (`tests_passed`, `rework_count`, `notes`), documented parameter semantics/defaults (`view`, `outcome`, `idempotency_key`, `paths`, `files`), and updated all 5 tool descriptions with explicit sibling routing, rate/session limits, and side-effect disclosures.

## [4.3.2] - 2026-10-17

### Changed

- **Seeded `no-eval` starter rule uses `builtin: true` (`rules/no-eval.md`, `aegis_cli.init`, `aegis_core.scaffolding`).** The active starter invariant seeded by `aegis init` now uses v4.3's structured `forbid_ast.calls` predicate (`[{"name": "eval", "builtin": true}, {"name": "exec", "builtin": true}]`), blocking builtin `eval()` and `exec()` (including `builtins.eval` / `__builtins__.exec`) while eliminating false positives on method calls such as pandas `df.eval()`, PyTorch `model.eval()`, and SQLModel `session.exec()`.
- **Monolith modularization across `aegis_cli` and `aegis_core` (`aegis_cli.doctor`, `aegis_cli.init`, `aegis_core.lane_gate`).** Extracted pure test-AST and `pytest` INI/TOML parsing into `aegis_core.lane_ast` (`L0`), rule packaging and CI workflow scaffolding into `aegis_core.scaffolding` (`L1`) and `aegis_cli.init_views`, and decomposed `aegis_cli.doctor` into `doctor_findings`, `doctor_repair`, and `doctor_render` while preserving all public and compatibility re-exports.
- **README progressive disclosure and search discoverability (`README.md`, `docs/how-it-works.md`, `pyproject.toml`).** Restructured the README quick start around the 3-step loop (Install, Scan before edit, Block bad commits in Git/CI) and moved statistical decay, Wilson interval, and SSH signing ceremony internals into collapsible sections and `docs/how-it-works.md`.

### Fixed

- **Explicit MCP tool annotation hints across all 5 tools (`aegis_mcp.registry`, `tests/contract/mcp_tools.json`).** `aegis_report_outcome` and `aegis_capture_insight` now explicitly declare all four boolean MCP hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) matching their handler behavior (`idempotentHint: True` for `idempotency_key`-deduplicated `aegis_report_outcome`; `idempotentHint: False` for append-per-call `aegis_capture_insight`), satisfying strict MCP directory validators.
- **Canonical test-suite candidate resolution (`aegis_core.verification.checkpoint_checks`).** Expanded `_resolve_canonical_test_candidates` to include `tests/contract/` and mapped domain test suites so `aegis check` no longer emits false-positive missing-test warnings.

## [4.3.1] - 2026-10-17

### Fixed

- **Pre-tool hook (`codex`) `apply_patch` command-guard bypass (`aegis_core.hook_events`, `aegis_core.command_safety`, `aegis_cli.hooks.management`).** A Codex `Bash` call is classified as a pure edit (`command=None`) only when the entire command is a single `apply_patch`/`applypatch` invocation with no chained shell commands, pipelines, trailing lines after the heredoc delimiter, or unquoted `$(...)`/backtick command substitutions. Heredoc splitting and subshell extraction are unified in `aegis_core.command_safety` (`split_heredocs`, `extract_subshell_commands`, `tokenize_command`, `decompose_command`), eliminating custom pointer loops in `hook_events` and `management`.
- **Exact `CODEOWNERS` governance coverage (`aegis_core.human_gate`).** `codeowners_coverage()` and `detect_tier()` now verify ownership across every tracked governance and workflow file on the base branch in addition to `COVERAGE_SAMPLES`, and fail closed when `!pattern` negation, unowned rule overrides, or unsupported character-class/escape patterns leave any governance path unowned.
- **Content-bound human insight approval (`aegis_core.insights`, `aegis_core.human_gate`).** `add_insight()` no longer reuses branch-wide `Aegis-Approve: <governance_tree_hash>` commits to grant `level="H"`. Human-approved insights require an explicit `--commit` carrying a valid base-trusted SSH signature over `Aegis-Approve-Insight: <sha256("aegis-insight/v1\n" + normalized_text)>`.
- **Resilient exposure ledger writes in `aegis_scan` (`aegis_mcp.handlers.core`, `aegis_core.credit`).** `credit.record_exposure()` records in-memory session exposure before disk persistence, and `_record_exposure()` catches and logs ledger write failures so read-only or locked state files never fail `aegis_scan`.
- **Mutation tester subprocess startup timeouts and hermetic process-group cleanup (`aegis_core.verification.mutation_tester`, `aegis_core.verification.test_runner`, `aegis_core.verification.coverage_check`, `aegis_core.checkrun`).** When a mutant test run times out before importing the target module (`status == "timeout"` and `not loaded`), the runner retries once and classifies persistent timeouts as `timeout` (killed) rather than a surviving mutant. All verification runners (`test_runner`, `mutation_tester`, `coverage_check`, `checkrun`) now enforce timeouts, spawn subprocesses in dedicated process groups, and terminate the entire process group via `checkrun.kill_group` on timeout.
- **`git diff-tree -z` rename/copy desynchronization in `regression` and `insights` (`aegis_core.gitsafe`, `aegis_core.regression`, `aegis_core.insights`).** Added `gitsafe.parse_name_status_z()` to handle 3-token `R*`/`C*` rename and copy records without shifting subsequent NUL-delimited path tokens, and consolidated `tree_blobs`, `read_blobs`, `blob_id`, and temporary-index `export_tree` in `aegis_core.gitsafe`.
- **Core primitives consolidation (`aegis_core.storage`, `aegis_core.stats`, `aegis_core.verification.scanners`, `aegis_core.telemetry_engine.ledger`, `aegis_core.workspace.layout`).** Unified JUnit XML inspection (`checkrun.parse_junit` / `parse_junit_cases`, including `<testsuite>`-level collection errors), centralized secret regex patterns and Shannon entropy in `aegis_core.verification.scanners`, extracted Layer-0 statistical intervals (`wilson_interval`, `wilson_ci`, `regularized_incomplete_beta`, `clopper_pearson_upper`) into `aegis_core.stats`, added `read_tail_bytes`, `read_json_dict`, and `file_lock` to `aegis_core.storage`, recognized credit event rows natively in `ledger.normalize_rows()`, and added `half_life_sessions`/`epsilon` to `RepoConfig`.

## [4.3.0] - 2026-10-17

v4.3 makes each trust claim Aegis prints checkable, at a level it names: what Aegis sees locally is a label, CI on the landing commit confirms it, and approvals the agent cannot produce gate governance changes. Three changes are breaking; they are marked.

### Added

- **Trust tier.** `aegis doctor` detects the tier read-only and prints it on every report. **A**: the default branch requires a pull request, an approving review by a non-author, the Aegis status checks and CODEOWNERS on the governance files, and the agent's identity cannot approve. **B** (solo, signed): required status checks plus `aegis approve` signatures from a key listed in the base branch's `allowed_signers`. **C**: neither, and every report says "self-attested". A signing key stored as a plain, readable file degrades B to C. The JSON's `trust_tier` is now the detected tier (it was null) and the JSON gains `human_gate` and `state_modes`.
- **`aegis doctor --github [--apply --tier A|B]`** prints the ruleset JSON, CODEOWNERS lines and signing setup each tier needs. `--apply` creates the ruleset through `gh api` only after a typed y/N at a terminal; `--yes` and `--json` never apply it.
- **`aegis approve`** (new command) makes one signed, empty commit `Aegis-Approve: <governance tree hash>` (or `Aegis-Exempt-Test: <fix-sha> <reason>` with `--exempt-test <commit> --reason <text>`) with the key, format and signing program from your user-level git config, never the repository's. It refuses when nothing governance-related changed since the base branch (unless `--exempt-test` is used), when anything is staged or uncommitted, and without a terminal, and it never creates a key. CI verifies the signature against `allowed_signers` on the base branch.
- **`aegis check --record [--tests]`** binds the work tree to the git tree it would commit, runs Layer 1 and, with `--tests`, the test command from your user config (`tests.command` in `~/.aegis/config.json`, default `python -m pytest`, never the repository's) on a snapshot export, and writes one ledger `check` row. The row is a label (`witness: aegis`), not proof. A file hidden with assume-unchanged or skip-worktree makes the tree unbindable; a tree holding a symlink gives no label; exit 5 or zero passed tests is never evidence. A change to a governance file (rules, Aegis config, CODEOWNERS, `allowed_signers`, workflows, or test infrastructure such as `conftest.py`) sets `protected_changed`, and the check earns no credit until it is approved.
- **Credit model, sample-size states, session decay, and `aegis sync --pr`** (`aegis_core.credit`, `aegis_core.fitness`, `aegis_core.sync`). Credit is computed on read from CI-confirmed checks, git detector replay over merged history for `forbid_ast` rules (`caught` vs `leaked`, deduplicated by `(rule, file, pattern, branch)`), and human-adjudicated labels (the only source of `fp`). Inline `# aegis: allow` comments suppress `forbid_ast` findings, record `contested` overrides (never `fp`), and flag high-override rules for human review. Rules report one of four sample-size states (`untestable`, `insufficient (n=K)` with no precision number shown, `inconclusive`, `decided`), asymmetric promotion/demotion thresholds (`>= 25` independent labels with `0` FP or `>= 42` with `1` FP across `>= 3` sessions and `>= 2` repos or `>= 14` days to promote to gate; agent-only self-reports never promote), prior mass capped at `<= 10` pseudo-labels with explicit `"prior supplies X% of the evidence"` disclosure, and read-time session-count decay `w = 2^(-delta / H)` over heartbeat-alive eligible sessions (`0.125` at `3H`). `aegis sync --pr` writes decided transitions and opens an evidence-backed pull request with up to 3 sampled examples per rule, never auto-merging.
- **`Aegis-Check` trailer.** A prepare-commit-msg hook, installed beside the pre-commit hook, adds `Aegis-Check: tree=<tree> exit=<n>` only when a passing check row exists for exactly the staged tree.
- **`aegis check --ci [--base REF] [--head REF] [--format text|json|github|sarif] [--coverage] [--perf]`**, the CI weakening, fail-to-pass regression, PR annotation/SARIF, and opt-in diff-coverage/perf check. Over the rules that bind (gates, invariants, `enforcement: gate`) at the merge base, it flags a deletion or archive, a rank decrease, lost coverage of existing files (renames followed), a `forbid_ast` pattern no longer covered, a `detect` that is not a superset, any new or unknown key, any `applies_to` change, and a mandatory rule added past the scan's two-slot cap. It also runs the T5 fail-to-pass regression check (starting at warning tier): non-merge commits in `merge-base(base, head)..head` with both a non-exempt Conventional `fix` subject (or `Fixes:`/`Closes:` trailer) and at least one changed source file must include a test that fails when overlaid onto `base` and passes on `head` in an isolated hermetic snapshot (`Aegis-No-Test` on the fix commit explains; a commit-scoped signed `Aegis-Exempt-Test: <fix-sha> <reason>` from `aegis approve --exempt-test` exempts it, tracking `exemption_rate`), and non-fix source changes without tests are listed in `untested_changes`. `--format sarif` emits SARIF 2.1.0 with repo-relative `artifactLocation.uri`, `region.startLine`/`startColumn`, and `partialFingerprints.primaryLocationLineHash` (routing line-less findings to `$GITHUB_STEP_SUMMARY`). `--coverage` checks diff coverage on changed executable lines (`COVERAGE_CORE=sysmon` on Python 3.12+, coverage data confined to `.aegis/state`), and `--perf` runs a paired, interleaved base-vs-head benchmark (`>= 15` rounds, A/A noise floor check, user-scope `perf.command`, no stored baseline).
- **Structured `forbid_ast` call predicates, Python security pack, secret scanner, and SARIF ingest** (`aegis_core.ast.policy`, `aegis_core.verification.security_pack`, `aegis_core.verification.scanners`). `forbid_ast.calls` entries accept structured dicts (`name`, `where` with `equals`, `not_equals`, `present`, `absent`, `is_literal`, `not_literal`, `matches`, `contains`, `not_contains`, `in`, `not_in`, `builtin: true`, and 3-valued `unknown: "report"|"skip"` for `*args`/`**kwargs`), evaluated as a multiset delta against the base commit so untouched legacy calls do not block. The first-party Python security pack ships 8 high-confidence AST rules (`sec-py-eval-exec`, `sec-py-pickle-loads`, `sec-py-yaml-unsafe-load`, `sec-py-subprocess-shell`, `sec-py-xml-etree`, `sec-py-weak-hash-md5-sha1`, `sec-py-tempfile-mktemp`, `sec-py-requests-verify-false`) at `invariant` tier with explicit test-path exemption reporting. The known-format secret scanner detects 11 Tier A token prefixes with bounded quantifiers, 4 KB line chunking, masked snippets (`prefix...last2`), and Tier B/C advisory-only modes, plus SARIF 2.1.0 ingest (`ingest_sarif`) and `ruff`/`gitleaks` external scanner presets (`UNVERIFIED` when binary is missing).
- **Accountable Layer-2 arbiter (log-only) and hook-observed `blocked_commands`** (`aegis_core.verification.arbiter`, `aegis check --calibration`, `aegis status`). `ArbitrationResult` separates `layer1_verdict`, `infra_status` (`"ok"` | `"unverified"`), and `llm_predictions` (log-only in v4.3), reports deterministic structural SHIP gaps (`missing_test`, `high_rule_miss_history`, `uncovered_changed_lines`), warns when the arbiter and generator share a model vendor family, and scores predictions (`score_predictions`, `calibration_summary` with Wilson 95% confidence intervals, Brier skill score vs climatology, `heeded` exclusion, `(scope, observable)` deduplication, sample-size gates at `n_effective >= 25` and `>= 100`, and 60-day compaction). `aegis status` reports hook-observed `blocked_commands` per host from `guard_match` events.
- **Human insights closed loop** (`aegis rule insight add|review|enable`, `aegis_capture_insight`). Corrections are stored at user scope in `~/.aegis/insights/<workspace-id>.jsonl` (`0600`) with session IDs pseudonymized as `hs` via `~/.aegis/link.key` (`0600`, 32 random bytes created by `aegis init`) and free-text secret/PII redaction (`<= 300` chars). `aegis rule insight enable --host claude-code|codex-cli [--counters-only]` installs an opt-in `UserPromptSubmit` hook that records text-free session `heartbeat` rows on every prompt and redacted excerpts on correction cues (`< 40ms`, exit 0, empty stdout). `aegis_capture_insight(quote, paths)` records agent-suggested insights (`suggestion` level, upgraded to `W2` only when `quote` is a substring of a hook-captured prompt in the same `hs`). `aegis rule insight review` clusters insights via stdlib TF-IDF cosine similarity, joins against ledger exposures (`exposed_and_ignored`, `not_exposed`, `matches_proposal`, `matches_archived`, `no_rule`), records append-only decisions (`propose` writing to `.aegis/proposals/<id>.md`, `reject` with a `>= 2` new-insight cooldown, `snooze`, `merge-into-rule`, `noise`), and measures post-activation recurrence normalized by heartbeat-alive sessions.
- **Release verification.** The validate workflow gains a final `verdict` job (never on pull requests) that attests that every other job passed for the exact commit and tree. `aegis doctor --release <sha>` verifies that attestation with `gh attestation verify`, pinned to the repository, signer workflow, ref and digests, then re-checks gh's JSON. It fails closed: with gh missing or older than 2.93.0 it prints `UNVERIFIED (gh >= 2.93.0 required)` and exits non-zero, and at tier C it reports the attestation as present but agent-editable and exits non-zero.

### Changed

- **Breaking: `aegis_report_outcome` no longer turns the agent's word into evidence.** With a passing check row for the tree the server recomputes, it credits the rules this server session served that match the change. Otherwise it records one `claimed` (unwitnessed) row per session and tree, returns `claimed` instead of `recorded`, and the row never counts as evidence for any rule. The tool takes no receipt. A server session writes at most 200 report rows; past that the tool returns `rate_limited` and writes nothing. `aegis status` and `aegis sync` show claimed reports in a count of their own.
- **Breaking: gates and invariants bind from the reviewed base.** `aegis_scan` serves rank 2+ rules (gates, invariants, `enforcement: gate`) from the base commit: `rules.base_ref` in your user config, else the merge base with `origin/HEAD`, else HEAD, labelled "local-head, not review-witnessed". Where the branch differs, the stricter version wins; a rule new or changed on the branch is never served as mandatory and appears only in `unreviewed_rules` (id and title). `aegis_scan` gains `rules_base` and `unreviewed_rules`.
- **Breaking: `expired_at` on a gate or invariant is a load error.** A rule that binds is retired by a reviewed change, never by expiry. `applies_to` is a known key; until v4.4 a rule carrying it is served unscoped.
- Commit trailers explain; `aegis approve` authorizes. `Aegis-Test-Change` no longer exempts a removed or skipped test in the lane gate, and an approval commit carrying an `Aegis-Accept` line (reserved) is refused.
- The shared state under `<git-common-dir>/aegis/` is created with 0700 directories and 0600 files whatever the umask. `aegis migrate --apply` tightens existing state and `aegis doctor` counts looser entries without naming them.
- On Linux the MCP server marks itself non-dumpable (`PR_SET_DUMPABLE` 0), so another process of your user cannot attach a debugger to it or read its memory.
- `.github/scripts/ci_green.py` (the pre-tag check) reads workflow runs through the REST API and counts only runs of the named workflow on this commit in this repository, from `push`, `workflow_dispatch` or `release` events; cancelled runs are ignored and the newest run decides.

### Known limits

- `aegis doctor --release` pins gh's `--source-ref` to the default branch, so it verifies the attestation made by the push there; an attestation made on a tag does not match. The gh JSON fields it re-checks follow sigstore's documented format and have not been run against a live gh 2.93.
- In-process session exposure sets live in the MCP server process (while governed MCP session scans also persist rule exposure rows to the shared ledger), so a restarted server's in-memory session set resets across process restarts.

## [4.2.0] - 2026-10-17

v4.2 makes a first run on an existing repository adoptable, lets rules travel, and gives parallel worktrees one shared ledger. Two changes are breaking; they are marked.

### Added

- **Day-0 card and partition report.** `aegis check --card` prints what Aegis found in this repository (rules active, findings per rule); `aegis init` prints the card. `aegis check --partition` splits the findings into what blocks and what is advisory.
- **Ratchet baseline.** `aegis check --write-baseline` records today's findings (the fingerprint is the full SHA-256 of the rule, the path, the matched line's normalized text and its occurrence index among identical lines; it does not include the line number) so only new ones fail; `--prune-baseline` drops entries that no longer match; `--base REF` reads the baseline from the base ref and never falls back to the candidate's file. Events: `baseline_written`, `baseline_check`.
- **Rule packs.** `aegis rule export OUT [--min-fitness X] [--type T]` writes the rule files (no ledger rows) with a checksum; `aegis rule import PACK [--rename] [--dry-run]` treats the pack as untrusted: every entry is re-parsed by the one loader, an id the workspace already has refuses the whole pack unless `--rename`, and the write is all or nothing. Packs are unsigned.
- **`aegis benchmark`** measures scan and hook latency, payload size and Layer-1 throughput over a shipped fixture corpus.
- **`aegis package --host claude-code`** (experimental) writes a Claude Code plugin directory: `.claude-plugin/plugin.json`, `.mcp.json`, `hooks/hooks.json` and the skills. The Claude Code plugin layout was written from the vendor documentation and has not been tried against a live install.
- **Experimental host rows** for Cursor, Copilot and Windsurf join Kiro. `aegis init --host <experimental>` warns and records an `init_host` event; `aegis doctor` marks them experimental. A row becomes verified by hand after three clean runs.

### Changed

- **Breaking: the ledger is shared across worktrees.** In a git repository every worktree of one repository appends to `<git-common-dir>/aegis/state/<workspace-id>/ledger.jsonl` under one lock. Rows in a worktree's own `.aegis/state/ledger.jsonl` are read again only after `aegis migrate --apply` merges them (read-only on the sources, a second run adds nothing). Outside git the ledger stays where it was. After upgrading, run `aegis migrate --apply` once in each repository, or its old per-worktree rows are not read and rules show no evidence until you do. The shared directory needs a writable git directory; if `.git` is read-only (some sandboxes), outcome reports fail until it is writable.
- **Breaking: `aegis check` modes are exclusive.** `--lane`, `--partition`, `--card`, `--write-baseline` and `--prune-baseline` refuse `FILES`, `--full` and `--plan*`.

## [4.1.1] - 2026-10-17

Fixes from the independent 4.1.0 release review.

### Fixed

- `aegis hook install --host` registered whichever `aegis` came first on `PATH`, even one older than 4.1 that has no `hook run`. Claude Code and Codex read that command's exit 2 (a usage error) as a block, so every tool call in every repository would have been blocked. Install now runs `aegis hook run pre-tool --host H` on an empty payload first and refuses unless it exits 0. If you downgrade below 4.1, run `aegis hook uninstall --host H` first for each host.
- `aegis hook install` and `aegis hook uninstall` accept the surface names `init` accepts (`codex-app`, `chatgpt-desktop`, `claude-desktop-code`, and so on).
- `aegis uninstall` says that user-scope host hooks stay until `aegis hook uninstall --host <host>`.
- The seeded `no-eval` rule, its init line and the README now say it matches by call name, so a method named `eval` or `exec` (pandas `df.eval()`, PyTorch `model.eval()`) fails the check; delete the file or init with `--rules none-active` if your code relies on them.

### Known limitations

- `aegis hook install` and `uninstall` run from your home directory fail with "not an Aegis workspace"; run them inside any repository (they only touch user files at user scope).
- `aegis check --lane` reports a test file moved to another path as removed tests; it has no exemption flag, so a refactor lane that moves tests needs a human merge.

## [4.1.0] - 2026-10-16

v4.1 adds per-host agent hooks, lane leases with a post-lane gate for parallel agents, and skills projection, as designed in ADR 0005 AD-7 and AD-8 (amended 2026-10-16). Nothing from 4.0 is removed. The details are in [How Aegis works](docs/how-it-works.md) section 8.

### Added

- **Per-host hooks.** `aegis hook install --host claude-code|codex-cli|antigravity [--scope user|project] [--dry-run]` registers one PreToolUse handler, `aegis hook run pre-tool --host <h>`, in `~/.claude/settings.json`, `~/.codex/hooks.json` (plus `~/.codex/rules/aegis.rules`) or `~/.gemini/config/hooks.json`, or with `--scope project` in the repository's `.claude/settings.json`, `.codex/hooks.json` or `.agents/hooks.json`. `aegis hook uninstall --host <h> [--scope ...]` removes only Aegis's entries. `aegis hook install` and `uninstall` without `--host` still manage the git pre-commit hook.
  - **Scan-before-edit**: an edit passes when a scan from any host or session named every edited path within `jit.scan_window_s` (new repo config key, default 3600 seconds, from 60 to 86400). Otherwise Claude Code exits 2 with `aegis: call aegis_scan with <paths> before editing (or run: aegis scan <paths>)`, Codex does the same once the hook is trusted, and Antigravity records it. Edits to `.aegis/rules/` are only recorded.
  - **Destructive-command guard**: force and `+refspec` pushes, `git reset --hard`, `git clean -f`, `rm -r` of `/`, `~`, `$HOME`, `*`, `.` or `..`, `mkfs*` and `dd of=/dev/…` are blocked (exit 2 on Claude Code and Codex, exit 1 through the wrapper on Antigravity). Merges, `gh pr merge`, bulk `git add`, pushes to `main` or `master`, `sudo`, `chmod 777` and destructive SQL are recorded, never blocked.
  - `aegis doctor` shows each host's hook entries per scope, whether they run an executable `aegis`, and the tier with its evidence label: Claude Code `blocking (documented; fails open on error)` [DOC], Codex `blocking once trusted in /hooks (documented; fails open)` [DOC] with `needs approval in /hooks (cannot be checked)`, Antigravity `blocks destructive commands (live); scan gate records only` [LIVE] or `unavailable` on Windows. It flags duplicate and hand-edited entries and v3 hook leftovers (`soma hook …`, removed `aegis hook` phases, the stale Antigravity `plugins/governance/hooks.json`), which `aegis doctor --fix` removes with a backup.
- **Agent teams.** `aegis team claim <lane> --paths G... [--role R] [--owner O] [--ttl S] [--branch B]`, then `renew`, `transfer`, `release` (each with `--expect <oid>`), `gc`, `list` and `metrics [--base REF]`. A lease is the git ref `refs/aegis/lanes/<lane>`, written by compare-and-swap and shared by every worktree; a claim whose paths may overlap another live lane's is refused. The optional committed `.aegis/team.json` holds `shared` globs and per-lane paths. `aegis team metrics` counts claims, denials, and merges where both sides changed a common path or `git merge-tree` reports a conflict.
- **Post-lane gate.** `aegis check --lane LANE [--base REF] [--paths GLOB...] [--base-policy]` checks every change since the merge base: containment (every changed path, deletions and both sides of a move included, inside the lane's globs; `.aegis/**` and `.github/workflows/**` only through the base branch's `team.json`) and Python test integrity (removed tests, added skips or xfails, pytest collection changes). Any finding fails; there is no exemption flag. The result is self-attested from the lease or `--paths`, and witnessed only with `--base-policy`, which reads `team.json` from the base branch's tip.
- **Skills projection.** `aegis skills sync [--host ...] [--force] [--dry-run]` and `aegis init --skills` copy the 15 packaged skills to `.claude/skills/<id>/SKILL.md` (Claude Code) and `.agents/skills/<id>/SKILL.md` (Codex CLI and Antigravity), with a provenance marker line. A later sync replaces only Aegis's unedited copies; edited copies need `--force`, and a file without the marker is never replaced.
- **Events log.** `<git common dir>/aegis/events.jsonl` (`.aegis/state/events.jsonl` outside git), shared by every worktree, records `lease_claimed`, `lease_denied`, `lane_check`, `scan_gate`, `guard_match` and `skills_sync` rows for the prune metrics. Fitness and compliance never read it.

### Changed

- `aegis_scan` writes its scan activity row again once the last one for the same session and files is older than half of `jit.scan_window_s` (4.0 wrote one per server process), and accepts a file inside the workspace that does not exist yet, so a new file can be scanned before it is created.
- `aegis scan FILE...` records a scan row with host `cli`, so the shell fallback satisfies the scan-before-edit hook too.
- `aegis doctor`'s Best-effort tier reports `unknown` with each registered host's tier when hooks are installed (doctor reads files only and cannot confirm a host runs them), `inactive` outside a governed repository and `unavailable` when no selected host can run them.

- **Host surfaces and Kiro.** Each host row lists the apps and IDEs that share its config plane, and `--host` accepts their names (`codex-ide`, `codex-app`, `chatgpt-desktop`, `claude-desktop-code`, `antigravity-app`, `antigravity-ide`, `kiro-ide`, `kiro-cli`); the config stores the plane id. New experimental `kiro` host: `aegis init --host kiro` writes `~/.kiro/settings/mcp.json`. `--host auto` also detects hosts by config directory and app bundle. `aegis doctor` warns when a host reads the `AGENTS.md` bootstrap but has no Aegis MCP registration (`bootstrap_without_tools`). Registering the Kiro workspace file (`.kiro/settings/mcp.json`) is not offered: a committed MCP file would run whatever a pull request puts there.
- **First run.** `aegis init` seeds one active rule, the `no-eval` invariant (`--rules none-active` leaves it out), prints the next step, and prints a CI workflow that `--ci` writes to `.github/workflows/aegis.yml`. The PATH hint names the script by its full path (and `~/Library/Python/3.x/bin` on macOS) instead of `python -m aegis_cli`.

### Fixed

- The 4.0.0 pre-commit hook failed every staged file an AST driver parses (Rust, TypeScript, Go) with "escapes workspace" and blocked the commit: the staged content is checked from an index snapshot outside the repository, and the driver confined that snapshot file to the repository. Staged driver files are now checked from the index snapshot, confined to the snapshot, while drivers are still resolved from the repository.

### Security

- The hooks are guardrails, not a security boundary: they fail open on any Aegis error, timeout or unreadable payload, and CI stays the floor.
- `aegis hook install --host` writes your user's host settings (`~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.codex/rules/aegis.rules`, `~/.gemini/config/hooks.json`), backing each file up to `~/.aegis/backups/` first and refusing unparseable, symlinked or hard-linked files. `--scope project` writes committed files that your teammates' hosts will execute; review such a change like code.
- Codex runs a hook only after the user trusts it in `/hooks`, so an installed Codex hook may not run; doctor says it cannot check this. The Antigravity entry is a shell wrapper that maps the handler's exit 75 to 1 and every other code to 0. The registered `aegis` path must match `[A-Za-z0-9._/+-]+`, so no quoting is needed in the shell forms.
- Team leases are labels, not an identity: `owner` and `role` are display text that nothing checks, and anyone may release a lease. The lane gate's self-attested result rests on inputs the lane can write; only `--base-policy` reads them from the base branch.

### Known limitations

- Edits made through shell commands never reach the edit gate on any host.
- Codex write_stdin into an interactive shell has no PreToolUse payload, and the Codex Bash payload carries no working directory.
- Antigravity manage_task with send_input types into a background terminal past run_command.
- Aegis never emits an 'ask' decision (it fails open on Codex and soft-denies in agy headless runs).
- The hooks fail open on any Aegis error: they are guardrails, not a security boundary.
- Claude Code and Codex blocking are documented by their vendors but not probed live; Antigravity's scan gate only records until a visible deny is probed, and Antigravity hooks are unavailable on Windows.
- `aegis check --lane` is advisory as a CI job in v4.1; under `pull_request` the workflow comes from the candidate, so a witness is only as strong as the protection on `.github/**` and the base branch. Assert weakening is not detected, and test integrity covers Python test files only.
- The skills directories are documented for Claude Code and Antigravity and unverified for Codex; none has been checked on a real install. Events written on a CI runner are lost with it unless uploaded.

## [4.0.0] - 2026-10-16

v4.0 rebuilds v3.3 around what was actually used and what can be checked. It has fewer commands and MCP tools, one config file, an append-only ledger as the only source of rule fitness, and a host plane that registers Aegis with Codex CLI, Claude Code and Antigravity. The reasons, with the evidence and the mistakes behind them, are in [docs/why-aegis.md](docs/why-aegis.md); the decisions are in ADR 0005. Every removed command and flag exits with status 2. Removed commands, and the removed `init` and `uninstall` flags, print one line naming the replacement (or saying there is none); the other removed flags get the argument parser's usage error, and the Breaking changes list below names their replacements.

### Upgrading from 3.x

1. `pip install --upgrade aegis-guardrails`
2. In each repository, run `aegis migrate` to see the plan, then `aegis migrate --apply`. It converts to the v4 layout: the v3 ledger (`.aegis/evidence/signals.jsonl` and `.aegis/telemetry/signals.jsonl`, with the `archive/*.jsonl.gz` files `aegis system compact` wrote) and the v2 ledger in `.soma/evidence/`; `aegis.conf` or `soma.conf`, `.aegis/slots.yaml` and `.aegis/config.yaml`; and the rules in `.soma/cells/`, `.soma/rules/` and v3 rule folders such as `walls/`. It reports `steering.conf` and `~/.aegis/slots.yaml` as not converted, backs up every file it changes to `.aegis/state/migrate-backup-<time>/`, and running it again changes nothing. Until you apply it, `aegis status`, `aegis scan` and `aegis sync` refuse to run in that repository and name the v3 files v4 does not read, `aegis check` warns and still runs, `aegis init` refuses while `.soma/` holds rules, and `aegis doctor` lists the files.
3. Run `aegis init --host codex-cli,claude-code,antigravity` (or `--host auto`; add `--dry-run` to preview). It registers the MCP server with each host and writes the `AGENTS.md` bootstrap. It also refreshes the pre-commit hook: the v4 block goes right after the shebang of an existing shell hook, which is first copied to `~/.aegis/backups/`; a hook written in another language stops `init` before it writes anything, and `aegis hook install --force` replaces it (keeping the copy).
4. Run `aegis doctor`, then `aegis doctor --fix` to remove v3 leftovers: `soma` MCP entries, misplaced MCP entries and legacy rule blocks in instruction files. Each file is backed up first.
5. If you set `AEGIS_WORKSPACE` in your shell, unset it: it must now name a directory with `.aegis/`, and a command run inside another workspace, or a git repository that does not hold the pinned one, holds (`pin_conflicts_with_cwd`) instead of acting on it.

### Breaking changes

**Commands**

- Removed commands and their replacements: `install` → `aegis init --host`; `system`, `sys`, `detect`, `languages`, `drivers`, `audit` → `aegis doctor`; `verify`, `checkpoint` → `aegis check` (v3's `aegis checkpoint` is `aegis check --strict`); `agent` → `aegis scan`, with outcomes recorded through the MCP tool `aegis_report_outcome`; `report`, `rules` → `aegis status`; `completion`, `skill`, `handoff` → no replacement.
- `aegis migrate` is now a converter (dry run by default, `--apply` to perform it). In v3 it only reported migration status.
- `aegis rule clean` and `aegis doctor --fix-path` are removed (they rewrote global files and shell rc files). `aegis doctor --fix` removes legacy rule blocks and unedited v3 rule copies; remove edited copies by hand.
- `aegis hook pre-commit` is replaced by `aegis check --hook`. The agent-side hook phases `pre-invocation`, `governance-monitor`, `immune-init`, `session-close`, `stop` and `post-session` are removed; remove them from your host's hook config. `python -m aegis_cli.hooks` no longer exists. Git hooks installed by v3 are reported as outdated, and `aegis hook install` rewrites them.

**Hosts**

- Gemini CLI is retired: Google refuses the client for individual Code Assist accounts, and Antigravity is the Gemini-family host. `aegis init --host gemini-cli` and `aegis uninstall --host gemini-cli` exit with status 2 and print `gemini-cli is not supported: Google retired Gemini CLI for individual Code Assist accounts; use --host antigravity.` The MCP server still recognizes a connecting Gemini CLI client by name; no Gemini CLI registration, hooks or extension are planned.

**Flags**

- Global flags are `--json`, `--plain` and `--workspace`. `--plumbing`, `--internal`, `-q`, `-v`, `--no-emoji` and the global `--format` are removed.
- `aegis init`: `--platform`, `--mcp` and `--local` are replaced by `--host`. `aegis uninstall`: `--platform`/`-p`, `--local` and `--purge` are removed.
- `aegis check`: Release Gate 4.5 (`--release`, `--release-gate`, `--require-arbitration`) is removed; releases are gated by CI on the exact commit. `--provider` and `--in-band` are replaced by `--llm-cmd`. `--no-layer2`, `--all`, `--files` (files are now positional), `--pre-commit`, `--checkpoint-only`, `--layer1-only`, `--deep` and `--format sarif` are removed. `check` now also runs the workspace checkpoint and prints its warnings; `--strict` turns them into failures.
- `aegis rule create`: `--from-description` (it never worked), `--weight`, `--expiry-sessions`, `--expiry-days`, `--minimum-mode`, `--effector` and `--memory` are removed. `rule promote`/`demote` lose `--rule`, `--reason` and `--force`; `rule archive` loses `--apply` and its rule argument. `status --all` is removed.
- `aegis doctor --yes` is only valid with `--fix`, and `--fix` asks before changing anything (`--yes` is required with `--json` or without a terminal).

**MCP server**

- The server has 4 tools: `aegis_scan`, `aegis_report_outcome`, `aegis_create_rule` and `aegis_list_rules`. Removed: `aegis_request_receipt`, `aegis_verify_changes`, `aegis_poll_verification`, `aegis_checkpoint`, `aegis_grade`, `aegis_coverage`, `aegis_rule_fitness`, `aegis_audit_security`, `aegis_audit_performance`, `aegis_capture_insight`, `aegis_propose_change`, `aegis_handoff` and `aegis_generate_manifest`. Calling one returns the JSON-RPC error -32602 "Unknown tool".
- Receipts and the session token are removed, with the `receipt` and `_sessionToken` arguments. `AEGIS_EXECUTION_ENABLED` and `AEGIS_REQUIRE_SESSION_TOKEN` are gone.
- Arguments are checked against each tool's schema before dispatch, so unknown arguments are rejected. `aegis_report_outcome` requires `idempotency_key` and `rules_used`; the aliases `cells_used`, `rule_id`, `rules` and `cell_id` are rejected. The `fields` projection is removed; `view` stays.
- `aegis_scan` has one name per field (`relevant_rules`, `guidance`, `invariant_warnings`, `rules_staged`, `stats`) and adds `stats.omitted`, `omitted_mandatory`, `stale_rules` and `warnings`. It drops `relevant_cells`, `context`, `wall_warnings`, `cells_staged`, `target_constraints`, `genome_guidance`, the per-rule copies of the guidance text and the `planned_symbols` argument. Matching is by path only. `AEGIS_MAX_JIT_TOKENS` now bounds the whole response: gates and invariants fill first, and the rules that do not fit are counted. A scan fails while a rule file cannot be loaded.
- `aegis_list_rules` returns `{rules, stale_rules, ignored}` instead of a list.

**Configuration and environment**

- One repository config, `.aegis/config.json` (hosts, JIT budget, rule expiry, opted-in packaged AST drivers), and one user config, `~/.aegis/config.json` (custom AST driver commands and slot overrides). `aegis.conf`, `.aegis/config.yaml`, `.aegis/slots.yaml`, `~/.aegis/slots.yaml` and `steering.conf` are no longer read. `aegis migrate` converts the first three (and `soma.conf`) into `.aegis/config.json`, and reports `~/.aegis/slots.yaml` and `steering.conf` as not converted. A repository can no longer name a command: not an AST driver, not a slot such as `TEST_RUNNER`, not the Layer 2 model command.
- The environment variables are `AEGIS_WORKSPACE`, `AEGIS_CLIENT`, `AEGIS_MAX_JIT_TOKENS` and `AEGIS_LLM_CMD`. Removed: `AEGIS_ROOT`, `AEGIS_CONTEXT_BUDGET`, `AEGIS_LOGS_DIR`, `AEGIS_INFERENCE_PROVIDER`, the `RULE_EXPIRY_*` and `CELL_TELOMERE_*` variables, and the Layer 2 API keys (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) with the keyring lookup.

**Workspace layout and data**

- The layout is `.aegis/{config.json, .gitignore, rules/<type>/, state/}`. `state/` holds machine-local, git-ignored files: `ledger.jsonl`, `activity.jsonl`, `derived.json`, `gate_events.jsonl` and the one workspace lock.
- The outcome ledger moves from `.aegis/evidence/signals.jsonl` to `.aegis/state/ledger.jsonl`, with versioned (v2) rows. v1 rows are still read, and `aegis migrate` converts them.
- Rules live in `.aegis/rules/<type>/` for the six types `invariant`, `trap`, `gate`, `boundary`, `persona` and `contract`. Rules in v3 folders (`walls/`, `membranes/` and the like) are not served: `scan` and `check` fail closed and name them until `aegis migrate` moves them.
- Fitness comes only from the ledger. Fitness fields in rule frontmatter are ignored, and nothing at runtime writes rule files.
- The HMAC manifest (`.aegis/rules/manifest.json`), its keys, the receipt keys and the Release Gate arbitration evidence are gone. `aegis sync` writes an unsigned sha256 index used only to show which rules were edited since the last sync.
- `aegis init` no longer copies rules into `~/.gemini`, `~/.claude`, `~/.cursor`, `~/.kiro` or `.github/copilot`, no longer inlines rules into `CLAUDE.md` and no longer writes `.mcp.json`. It seeds starter rules into `.aegis/rules/personas/`.
- Five rules that only govern this repository (`gitflow-review-gate`, `ci-green-before-release`, `core-change-protocol`, `no-pre-existing-excuse`, `optional-import-guard`) moved from the shipped `rules/` to this repository's `.aegis/rules/`, and `desktop-automation` is no longer shipped.
- The `VERSION` file is gone; the version is in `aegis_core/_version.py`.
- The wheel installs only the `aegis_cli`, `aegis_core`, `aegis_mcp` and `aegis_sdk` packages. The shipped rules and skills, which 3.x installed as top-level `rules` and `skills` packages, are package data in `aegis_core/_data/`; the repository keeps them in `rules/` and `skills/`.

**Layer 2 (`aegis check --full`)**

- One backend: the command given with `--llm-cmd` or `AEGIS_LLM_CMD`, for example `claude -p` or `codex exec`. It runs as an argument list (no shell) in an empty temporary directory, gets the prompt on stdin and returns its reply on stdout. It is never read from repository files. The Gemini, Anthropic and OpenAI SDK wrappers, the keyring, the in-band charge sheet and MCP sampling are removed.
- `--full`, `--plan` or `--plan-file` without a backend exits 2 instead of skipping Layer 2.

**Output and Python API**

- `aegis check --json` renames the checks `cell_fitness`, `cell_conventions` and `paper_walls` to `rule_fitness`, `rule_conventions` and `paper_gates`, and adds `rule_load`. `aegis doctor --json` prints one `aegis.doctor/v1` document. `aegis hook status --json` reports `managed_by_aegis` and `interpreter`.
- `aegis_sdk` exports only `Governance` (`grade`, `coverage_report`, `scan`, `entropy`, `list_rules`, `fitness_landscape`), `parse_rule_file` and `__version__`. Its other modules are removed, and so are many internal `aegis_core` modules, among them `integrity`, `scoring`, `receipts`, `locking`, `evidence` and `workspace.git.GitWorkspace`.

### Added

- **Host plane.** `aegis init --host codex-cli,claude-code,antigravity` (or `auto`) registers the `aegis` MCP server through each host's own mechanism (`codex mcp add`, `claude mcp add --scope user`, Antigravity's `~/.gemini/config/mcp_config.json`). It also writes a short bootstrap block into `AGENTS.md` (plus an `@AGENTS.md` block in an existing `CLAUDE.md`), installs the git pre-commit hook and records the workspace in `~/.aegis/workspaces.json`. It supports `--dry-run`, `--pin` and `--force`. `aegis uninstall` reverses this and never deletes `.aegis/`.
- **Workspace binding.** The MCP server binds each call to a workspace: an operator pin, then the roots the host reports, then the registry, then a walk up from its working directory that stops at the git top level. It never governs `$HOME`, and it never takes a workspace from a tool argument. When nothing resolves, `aegis_scan` serves the read-only user rule layer in `~/.aegis/rules/` and writes nothing.
- **Host identity.** The server identifies its host from the registration (`AEGIS_CLIENT`) or the client name, defaulting to `generic`. Host and session are recorded by the server, never taken from tool arguments. The bootstrap text is also returned as the MCP `initialize` instructions.
- **`aegis doctor`** reports one state per host (`ok`, `missing_binary`, `unregistered`, `auth_unknown`, `policy_gap`) with its enforcement level, plus the enforcement tiers in force here. It compares the MCP command each host registered with the one `aegis init --host` registers from this install, and counts the local floor only when the Aegis pre-commit hook is installed, current and reached by git. `--fix` changes only what doctor reported, after confirmation, and backs each file up to `~/.aegis/backups/<UTC stamp>/` first. Doctor makes no network calls.
- **`aegis scan FILE...`** shows the rules that apply to files you are about to edit (it was `aegis agent scan`).
- **`aegis sync`** rebuilds rule fitness from the ledger and suggests promotions, demotions and archives. `--apply` applies them; nothing else changes a rule's tier.
- **`aegis status --compliance`** reports the scan-before-edit rate per host and per session from `.aegis/state/activity.jsonl`, with the method's limits printed next to the numbers.
- **`aegis rule create --body-file`** reads a rule body from a file or stdin. `aegis rule list` flags rules edited since the last sync.
- **gitsafe.** Every git command Aegis runs switches off what a repository's own config can make git execute: `core.fsmonitor`, hooks, the repository's filter drivers, credential helpers, remote protocols and submodule status.
- **Generated reference.** [docs/reference.md](docs/reference.md) lists every command, option and MCP tool. It is generated from contract snapshots of the CLI and the MCP surface, and a test fails when either changes without the snapshot.
- **Pre-tag check.** `.github/scripts/ci_green.py <sha>` exits 0 only when CI passed on that exact commit.

### Security

- The MCP server command `aegis init --host` registers never depends on the directory a host starts it in, which is the project and so under a cloned repository's control. It is the absolute `aegis-mcp` script (from an absolute `PATH` entry, or the one installed next to the Python running `aegis`), else that Python in isolated mode (`-I`) importing `aegis_mcp` from the directory Aegis is installed in. It is never `python -m aegis_mcp`, which would run a repository's own `aegis_mcp` package. `aegis doctor` reports as an unsafe registration, with `aegis init --host` as the fix, a registered command that is relative or bare, a Python that runs `-m` or `-c` without `-I` or a script by a relative path, or either behind `env`; it starts no MCP server and no `python3` to check it.
- The pre-commit hook (`aegis check --hook`) checks the staged content that `git commit` records, not the working tree: a violation that is staged and then edited away in the working tree, or staged in part, no longer passes it.
- The pre-commit hook block goes right after the hook's shebang, so a hook whose own lines end in `exec` or `exit` no longer skips the check. A hook written in another language is refused instead of edited, and an existing hook is copied to `~/.aegis/backups/` before it changes. `aegis doctor` no longer calls the local floor active for a block git never reaches (a hook file that is not executable, or a line that ends the hook before the block).
- An `AEGIS_WORKSPACE` pin must name a directory with `.aegis/`, and a CLI command run inside another workspace, or a git repository that does not hold the pinned one, holds (`pin_conflicts_with_cwd`) instead of acting on the pinned workspace. Before, with the variable set in the shell, every command acted on the pinned workspace, and the pre-commit hook of another repository checked the pinned one's files instead of its own.
- Aegis never runs a program found through a relative or empty `PATH` entry, the current directory, or a copy inside the workspace where a repository could plant it. git, the AST drivers (`node`, `go`, `rustc`), `pytest`, the `--llm-cmd` command and doctor's probes all resolve through one lookup that accepts absolute `PATH` entries only (on Windows it never searches the current directory, and npm `.cmd` shims for `--llm-cmd` run through `cmd.exe` with escaped arguments).
- The wheel no longer installs top-level `rules` and `skills` packages. Installing one overwrote another distribution's `rules` package, and under `python -m aegis_cli` a repository's own `rules/` package ran and its files were seeded as Aegis starter rules.

### Fixed

These are the v3.3 defects found by the v4 review (evidence review) and the build waves.

- `forbid_ast` was bypassed by import aliases (`import subprocess as sp`), rebinding, a CR-only encoding cookie and dynamic imports, and silently skipped files it could not read (a byte-order mark, latin-1). It now resolves aliases and fails closed.
- A repository's `.aegis/slots.yaml` could run commands and inject text into scan output. Repository config can no longer name commands.
- Manifest auto-sync re-signed tampered rules, and the release gate accepted a hand-written SHIP verdict. Both mechanisms are removed.
- About 80 of 120 concurrent fitness updates were lost, and rules whose frontmatter Aegis had rewritten were then dropped as "tampered". Fitness is now appended to the ledger under one lock, and rule files are never rewritten at runtime.
- `aegis rule create --workspace` on a repository without `.aegis/` wrote to `~/.aegis/rules`.
- The YAML serializer wrote text its own parser rejected (`\r`, U+2028, keys with newlines).
- An unparseable host MCP config was overwritten; it is now refused with a clear error.
- The MCP server died on a non-object JSON line, created `~/.aegis` at startup and ran reflection on shutdown, recording one change once per open server. None of these happen now, and `aegis_report_outcome` retries no longer double-count.
- Layer 1 fails closed when a check tool raises, and a skip or xfail no longer counts as an assertion.
- `aegis check --full` mutation testing ran only one test file chosen by its name, so a mutant that other tests catch was reported as surviving, and the mutant reached only that file's imports. It now runs every test file that imports the module and names the function (at most 15, and the result says when the cap cut any), serves the mutant to the whole test process, scales its timeout with the number of files, and reports a baseline that did not finish as "could not assess (timeout)".
- Windows and macOS: workspace path containment on Windows, line endings compared through git's own conversion, host CLIs run under their on-disk spelling, and `--llm-cmd` split without POSIX escapes on Windows.

### Known limitations

- `aegis check` records each run's pass or fail against every rule whose paths match the checked files, and self-reports from MCP clients count toward fitness too. So a gate that blocks a bad commit is scored as a miss. Fitness only ranks guidance and drives `sync` suggestions; no rule changes tier without an explicit command. A per-rule credit model is planned for v4.3 ([why-aegis](docs/why-aegis.md) §6).
- The starter rules `aegis init` seeds have no `target_paths`, so they apply to no file until you add patterns; `aegis status` lists them.
- Per-host agent hooks for Claude Code, Codex CLI and Antigravity are planned for v4.1. In v4.0 the enforcement points are the git pre-commit hook (`--no-verify` skips it) and CI.
- Rule frontmatter has no schema version yet; the ledger, the config files, the derived view and the workspace registry do.

## [3.3.0] — 2026-10-14 — "Cryptographic Provenance, Declarative AST Rules, Telemetry Compaction, SARIF 2.1.0 & Multi-Platform Claude Desktop Support"

### Security & Cryptographic Provenance (Phase 3.3.1)
- **Git Working-Tree Digest Binding (`aegis_core/receipts.py`)**:
  - Updated `compute_file_digest()` so operations without explicit file arguments (`target_paths=[]`) inside a Git workspace bind the receipt state digest to `git rev-parse HEAD` + `git status --porcelain`, invalidating receipts if working-tree state changes between issuance and redemption.
- **Inbound `HandoffTicket` Verification (`aegis_core/skills/handoff.py`, `aegis_cli/skills.py`)**:
  - Added `HandoffRouter.consume_handoff()` and `aegis handoff consume <ticket_id> [--no-verify-tree] [--json]`, verifying the `ArtifactEnvelope` HMAC signature and optional `HEAD^{tree}` hash before returning the payload and marking the ticket `"consumed"`.
- **Automatic `.aegis/manifest.json` Verification in `RuleCache` (`aegis_mcp/rule_cache.py`)**:
  - Updated `RuleCache` to verify rule SHA-256 digests against `.aegis/manifest.json` on cache load/refresh, automatically excluding tampered rules and logging a diagnostic warning.
- **Claude Desktop & Cross-Model Platform Parity (`aegis_cli/platforms/claude.py`, `aegis_mcp/server.py`)**:
  - Updated `ClaudeAdapter.install()` / `uninstall()` to provision all 15 `skills/*/SKILL.md` into `.claude/skills/`, register `aegis` MCP in `~/.config/Claude/claude_desktop_config.json`, inject a cross-model tool/tier equivalence table into `CLAUDE.md`, and auto-scaffold `~/.aegis/rules` when `aegis-mcp` starts from `$HOME`.

### Declarative Rule-Level AST Checks & Pre-Edit Symbol Scan (Phase 3.3.2)
- **Declarative `forbid_ast` in Rule Frontmatter (`aegis_core/ast/match.py`, `aegis_core/verification/runner.py`)**:
  - Added `evaluate_forbid_ast()` supporting `imports`, `calls`, and `decorators` in `invariant` and `gate` rule YAML frontmatter, evaluated deterministically by Layer 1 (`DeterministicVerifier`) across `NormalizedAST`.
- **Pre-Edit Symbol Intent (`planned_symbols`) in `aegis_scan` (`aegis_mcp/registry.py`, `aegis_mcp/jit_engine.py`, `aegis_mcp/handlers/audit.py`)**:
  - Added optional `planned_symbols: list[str]` to `aegis_scan` so agents can declare imports, calls, or decorators they plan to use before writing code, matching `ast_triggers` and `forbid_ast` rules proactively.

### Segmented Telemetry Compaction & SARIF 2.1.0 Output (Phase 3.3.3)
- **Segmented Telemetry Compaction (`aegis_core/telemetry.py`, `aegis_cli/system.py`)**:
  - Added `compact_signals()` and `aegis system compact [--days 30] [--dry-run] [--json]`, rolling up expired signals into `.aegis/telemetry/checkpoint_rollup.json`, archiving raw records to `.aegis/telemetry/archive/signals-<YYYY-MM>.jsonl.gz`, and preserving Thompson Sampling priors across compactions.
- **SARIF 2.1.0 Output (`aegis_cli/check.py`, `aegis_cli/verify.py`)**:
  - Added `--format sarif` (`format_sarif_report()`) to `aegis check` and `aegis verify` for GitHub Code Scanning and IDE diagnostics integration.

## [3.2.0] — 2026-10-14 — "Fortress Perimeter Hardening, Horizontal Skill Graph Wiring, O(1) Telemetry Caching & Full Documentation Overhaul"

### Security & Perimeter Hardening (Fortress Adaptive Review)
- **Workspace Confinement in Core I/O (`aegis_core/operations.py`)**:
  - Hardened `Operations.resolve_path()` to enforce `confine_path_internal()` across all `Operations` file/JSONL reads and writes while allowing workspace root tokens (`""` / `"."`).
- **Ephemeral Receipt Authentication Before Burn (`aegis_core/receipts.py`)**:
  - Fixed `ReceiptManager.verify()` in ephemeral mode so `self._store.get()` is used during Step 1 (TTL + HMAC verification) and `self._store.pop()` only executes in Step 2 (`BURN BEFORE COMPARE`), preventing unauthenticated probes from evicting valid in-memory nonces.
- **MCP Privileged Tool Schemas, Projection & AST Workspace Threading (`aegis_mcp/`)**:
  - Threaded `workspace` from `jit_engine.express()` through `match_cells_to_files()` and `match_cells_for_diff()` so syntactic AST triggers resolve relative to the workspace root rather than process `CWD`.
  - Added optional `receipt` property to `TOOL_DEFINITIONS` schemas for all 6 privileged write/execute tools (`aegis_propose_change`, `aegis_checkpoint`, `aegis_report_outcome`, `aegis_capture_insight`, `aegis_generate_manifest`, `aegis_handoff`).
  - Exposed `rule_prompt` in `_handle_create_cell()` and `SUMMARY_FIELDS` (`aegis_mcp/projection.py`) so `aegis_create_rule` returns the generated prompt without colliding with the `"prompt"` denylist filter.

### CLI Dispatch, Platform Adapters & Closed-Loop Rules
- **CLI Dispatch & `migrate` Unblocking (`aegis_cli/cli.py`, `aegis_cli/registry.py`, `aegis_cli/rule.py`, `aegis_cli/check.py`, `aegis_cli/init.py`)**:
  - Unblocked `aegis migrate` on legacy `.soma` workspaces by walking upward to locate `.soma` or `.aegis` before `Workspace.resolve()` runs `check_legacy_soma_sentinel()`.
  - Unified `install` and `uninstall` into `COMMANDS` and registered `DetectCommand` (`aegis detect`), `SkillCommand` (`aegis skill`), and `HandoffCommand` (`aegis handoff`) in `CommandRegistry`.
  - Added `aegis rule create` subcommand (`aegis_cli/rule.py`), `--no-hooks` flag on `aegis init`, and fixed `aegis check --in-band` so it proceeds to Layer 2 ChargeSheet generation.
  - Updated `GeminiAdapter` hook commands (`aegis hook ...`), `PlatformAdapter.render_mcp_entry()` (`command="aegis-mcp"`), and `install/hooks/pre-commit` (Format 4 `#!/bin/sh` runner).

### `AegisYAML`, JSONL Efficiency & Horizontal Skills as Slots
- **Stat-Fingerprinted `_SIGNALS_CACHE` & `AegisYAML` Validation (`aegis_core/telemetry.py`, `aegis_core/yaml.py`, `aegis_core/lifecycle/creation.py`, `aegis_core/insights.py`)**:
  - Added an in-memory `(st_ino, st_mtime_ns, st_size)` cache (`_SIGNALS_CACHE`) to `_read_existing_events()` and `append_signals()`, eliminating $O(N)$ historical JSONL re-parsing on repeated signal appends.
  - Added round-trip `AegisYAML.parse_text()` validation to `create_cell()` and added `scaffold_invariant` / `invariant_id` support to `capture_insight()`.
- **Horizontal Skill Graph & Slot Interpolation (`aegis_core/skills/`, `aegis_cli/skills.py`, `skills/*/SKILL.md`)**:
  - Enriched all 15 shipped `skills/*/SKILL.md` manifests with `id`, `kind: skill`, `tier`, `consumes`, `produces`, and `handoff_targets`.
  - Updated `SkillGraph.discover()`, `SkillGraph.default_search_paths()`, and `SkillNode.from_doc()` to discover all 15 skills by directory slug out of the box and interpolate `${SLOT.*}` bindings from `.aegis/slots.yaml` in `SkillNode.load_instructions()`.

### Full-Repository Documentation Overhaul
- Overhauled 22 documentation files across root (`CONTRIBUTING.md`, `QUICKSTART.md`, `PRIVACY.md`, `SECURITY.md`), guides (`docs/guides/rule_lifecycle.md`, `mcp_gateway.md`, `polyglot_ast.md`, `skill_graph.md`, `verification_pipeline.md`, `docs/index.md`), architecture (`mechanism_design.md`, `phylogeny.md`, `scripts.md`, `ADR-012..016`), and project governance (`COMPATIBILITY.md`, `CONTRIBUTING.md`, `RELEASE_WORKFLOW.md`, `ROADMAP.md`, `METRICS.md`), and removed obsolete `docs/organelles.md`.

## [3.1.0] — 2026-10-14 — "Architecture Hardening, Cryptographic Receipt Burn-Before-Compare & Canonical Aegis Taxonomy"

### Packaging & Standalone Wheel Parity
- **`rules` & `skills` Package Bundling (`pyproject.toml`, `aegis_cli/platforms/base.py`, `.github/scripts/wheel_smoke.py`)**:
  - Added `rules` and `skills` (`rules/__init__.py`, `skills/__init__.py`) to `[tool.setuptools.packages.find]` and `[tool.setuptools.package-data]` (`rules = ["*.md", ".oracles/*.md"]`, `skills = ["*/SKILL.md"]`) so standalone `pip install aegis-guardrails` wheels bundle all 18 core rules and 15 agent skills.
  - Updated `PlatformAdapter.get_source_skills()` (`aegis_cli/platforms/base.py`) to fall back to `importlib.resources.files("skills")` when running outside a git checkout, matching `get_source_rules()`.
  - Extended `.github/scripts/wheel_smoke.py` to assert non-empty `get_source_rules()` and `get_source_skills()` under `python -I` outside the repository.

### Cryptographic Security Hardening
- **Burn-Before-Compare Single-Use Receipts & Sidecar Locking (`aegis_core/receipts.py`, `aegis_mcp/server.py`)**:
  - Hardened `ReceiptManager.verify(..., consume=True)` under exclusive sidecar file lock `.aegis/locks/receipts.lock` to verify HMAC-SHA256 signature and expiration first, immediately append the consumed nonce to `.aegis/receipts.jsonl` (`fsync`), and only then compare `file_digest` and `rule_digest`, preventing pre-burn replay attacks on digest mismatch or path validation failures.
  - Fixed ledger compaction (`_compact_consumed_locked`) to prune only expired nonces (`exp < now`), eliminating the 1,000-nonce FIFO eviction replay vulnerability.
  - Wrapped `server.py:_verify_receipt_for_call` `_compute_state_digest` in `try/except ValueError` so invalid path arguments occur after receipt burn and return structured JSON-RPC errors without leaking unburned tokens.

### Verification Engine & MCP Tool Surface Cleanup
- **Deduplicated `scan_test_issues()` & Narrowed Exception Handling (`aegis_core/ast_checks.py`, `aegis_core/verification/`, `aegis_core/rule_inventory.py`, `aegis_core/telemetry.py`)**:
  - Extracted shared `scan_test_issues()` in `aegis_core/ast_checks.py` and wired both `aegis_cli/check.py` and `aegis_core/verification/pipeline.py` to eliminate duplicated test AST scanning logic.
  - Narrowed broad `except Exception:` blocks in `aegis_core/verification/runner.py`, `aegis_core/rule_inventory.py`, and `aegis_core/telemetry.py` to specific exception tuples (`(OSError, ValueError, KeyError, TypeError)` / `(OSError, subprocess.SubprocessError, ValueError, KeyError)`).
- **17 Canonical `aegis_*` MCP Tools (`aegis_mcp/registry.py`, `aegis_mcp/tools.py`, `aegis_mcp/server.py`)**:
  - Removed legacy duplicate MCP tool definitions `aegis_list_cells`, `aegis_fitness`, and `aegis_create_cell`, standardizing on the 17 canonical `aegis_*` tools (`aegis_list_rules`, `aegis_rule_fitness`, `aegis_create_rule`, etc.).
- **Clean-Tree Manifest Generation (`aegis_cli/check.py`, `aegis_core/rule_inventory.py`)**:
  - Made `aegis check` read-only by default (no longer mutating `.aegis/rules/manifest.json` during read-only checks) and added `RuleInventory.check_manifest_sync()`.

### Canonical Aegis Taxonomy Cutover
- **Review Modes, Prongs, Genesis Stages & `.aegis/rules/` Metadata (`aegis_core/`, `aegis_cli/`, `rules/`, `skills/`, `.aegis/rules/`)**:
  - Cut over review modes from weather metaphors (`breeze`, `gale`, `trident`, `maelstrom`, `tempest`, `supercell`) to defensive posture tiers (`patrol`, `sweep`, `vanguard`, `bulwark`, `fortress`, `citadel`).
  - Cut over review prongs from botanical metaphors (`spores`, `roots`, `thorns`, `bedrock`, `canopy`, `mulch`) to security operations roles (`sentry`, `trace`, `probe`, `bastion`, `gauntlet`, `debrief`).
  - Cut over Genesis onboarding stages from biological metaphors (`membrane`, `fossil`, `anatomy`, `physio`) to structural reconnaissance stages (`perimeter`, `chronology`, `blueprint`, `policy`).
  - Updated all 18 core rules (`rules/`), 15 agent skills (`skills/*/SKILL.md`), and 42 `.aegis/rules/` rule files to canonical Aegis v3.1.0 terminology and persisted Citadel v3.0.0 debrief learnings in `governance/debrief_queue.jsonl`.

## [3.0.0] — 2026-10-14 — "Pure Aegis Clean-Slate Architecture & Zero-Dependency CLI UX"

### Breaking Changes (Pure Aegis Clean-Slate Cutover)
- **Legacy `soma_*` Shims & `Soma*` / `Cell*` Aliases Removed**:
  - Deleted `aegis_core/compat.py`, `aegis_core/somayaml.py`, `aegis_sdk/cells.py`, `aegis_core/cell_inventory.py`, and `aegis_mcp/cell_cache.py`. Importing `soma_core`, `soma_cli`, `soma_sdk`, or `soma_mcp` now raises `ModuleNotFoundError`.
  - Removed all `Soma*` and `Cell*` class/error aliases (`SomaError`, `SomaValidationError`, `SomaYAMLError`, `SomaDocument`, `SomaYAML`, `SomaCommand`, `SomaParser`, `Cell`, `CellFitness`, `CellNotFoundError`, `CellParseError`, `CellPathTraversalError`).
- **Pure `.aegis/rules/` Workspace & Upgrade Sentinel**:
  - Removed `.soma/` and `.soma/cells/` fallback resolution across `aegis_core/workspace/`, `aegis_core/locking.py`, `aegis_core/rule_inventory.py`, `aegis_mcp/rule_cache.py`, and `aegis_sdk/rules.py`.
  - Unmigrated `.soma/` workspaces now trigger an immediate Upgrade Sentinel diagnostic instructing users to run `aegis migrate` on v2.1.x before upgrading to v3.0.0.
  - Renamed all repository rules in `.aegis/rules/invariants/` and `.aegis/rules/boundaries/` from `wall-*.md` / `membrane-*.md` to `invariant-*.md` / `boundary-*.md` and removed legacy biological rule types (`vacuole`, `chloroplast`, `plasmodesmata`).
- **Pure `aegis_*` MCP Tool Namespace**:
  - Cut over all 20 MCP tools in `aegis_mcp/registry.py`, `aegis_mcp/tools.py`, and `aegis_mcp/server.py` to the `aegis_*` namespace (`aegis_scan`, `aegis_report_outcome`, `aegis_create_rule`, `aegis_list_rules`, `aegis_verify_changes`, `aegis_checkpoint`, `aegis_handoff`, etc.) and removed `_CANONICAL_TOOL_MAP`.

### Zero-Dependency Terminal UI & CLI Unification
- **Terminal Theme & Adaptive Table Engine (`aegis_cli/ui/`)**:
  - Added `OutputContext` (`aegis_cli/ui/theme.py`) honoring `NO_COLOR`, `FORCE_COLOR`, `TERM=dumb`, `isatty()`, `--plain`, `--no-emoji`, and `--json` with zero ANSI leakage in non-TTY/JSON modes.
  - Added ANSI-aware `Table`, `Grid`, `Column`, `render_table`, `render_box`, and `render_error_panel` (`aegis_cli/ui/table.py`) while preserving `dependencies = []` in `pyproject.toml`.
- **Unified Command Registry & Core Deduplication**:
  - Registered `doctor`, `report`, `install`, and `uninstall` directly in `CommandRegistry` (`aegis_cli/registry.py`) and unified `aegis init` onto `aegis_cli/platforms/` adapters.
  - Consolidated frontmatter parsing onto `aegis_core/yaml.py`, atomic writes onto `aegis_core/storage.py`, relocated `aegis_core/verification/jobs.py`, and renamed `aegis_core/proposals.py`.

## [2.1.0] — 2026-10-14 — "Pure Aegis Unification, Migration Bridge & aegis-guardrails Cutover"

### Package & Repository Cutover
- **PyPI Package (`aegis-guardrails`) & Repository (`Aegis-Guardrails`)**:
  - Updated `pyproject.toml` distribution package name to `aegis-guardrails` (`pip install aegis-guardrails`) and repository links to `https://github.com/nseney1/Aegis-Guardrails`.
  - Updated `.github/workflows/publish.yml` OIDC Trusted Publisher target to `https://pypi.org/p/aegis-guardrails`.
  - Updated `aegis_core/workspace/discovery.py`, `aegis_cli/cli.py`, and `aegis_mcp/server.py` to resolve `aegis-guardrails` metadata.

### Workspace Migration Bridge (`aegis migrate`) & Modern Rule Taxonomy
- **Interactive & Automated `.soma` $\rightarrow$ `.aegis` Migration (`aegis_cli/migrate.py`)**:
  - Added `aegis migrate` (`--dry-run`, `--json`) to atomically migrate legacy `.soma/cells/` workspaces to `.aegis/rules/` (`invariants/`, `traps/`, `boundaries/`, `personas/`, `contracts/`).
  - Rewrites legacy biological `type:` frontmatter (`vacuole` $\rightarrow$ `trap`, `wall` $\rightarrow$ `invariant`, `membrane` $\rightarrow$ `boundary`, `chloroplast` $\rightarrow$ `persona`, `plasmodesmata` $\rightarrow$ `contract`) during migration (`BUG-099`).
- **Native Aegis Primitives (`AegisYAML`, `Rule`, `AegisError`, `AegisCommand`)**:
  - Promoted `aegis_core/yaml.py` (`AegisYAML`, `AegisDocument`, `parse_rule_frontmatter`), `aegis_sdk/rules.py` (`Rule`, `RuleFitness`), `aegis_core/errors.py` (`AegisError`, `AegisValidationError`, `RuleCorruptError`), and `aegis_cli/base.py` (`AegisCommand`) to primary implementations while retaining v2.x compatibility aliases.

### Runtime Engine & Governance Rule Wiring (`BUG-096`–`BUG-100`)
- **Governance Rule Frontmatter & Platform Adapter Parity (`BUG-096`, `BUG-097`)**:
  - Added required `trigger:` and `description:` frontmatter to `rules/META.md`, `rules/gitflow-review-gate.md`, `rules/core-change-protocol.md`, `rules/ci-green-before-release.md`, and `rules/no-pre-existing-excuse.md`.
  - Removed the `META.md` exclusion filter in `aegis_cli/platforms/base.py:discover_rules()`.
- **`.aegis/rules/` Engine Discovery (`BUG-098`, `BUG-100`)**:
  - Updated `aegis_mcp/jit_engine.py`, `aegis_core/sentinels.py`, `aegis_core/metrics.py`, `aegis_core/lifecycle/`, `aegis_cli/hooks/runtime.py`, `aegis_cli/init.py`, and `aegis_core/enforcement.py` to discover `.aegis/rules/` and emit modern Aegis response keys (`relevant_rules`, `invariant_warnings`, `triggered_rules`, `matched_rules`, `rules_triggered`, `total_rules`, `invariant_strength`).

## [2.0.0] — 2026-10-14 — "Soma-to-Aegis Unification & Architecture Rebrand"

### Architectural Rebrand
- Renamed core packages to `aegis_core`, `aegis_cli`, `aegis_mcp`, and `aegis_sdk` with `aegis_core/compat.py` import hooks preserving `soma_*` backwards compatibility across the v2.x line.
- Consolidated `genome/` into `rules/` and `.soma/cells/` into `.aegis/rules/`.

## [1.5.1] — 2026-10-14 — "Subagent Delegation Governance & CI Supply Chain Hardening"

### CI Supply Chain & Dependabot Pipeline Hardening
- **Artifact Action Security Bumps**:
  - Bumped `actions/upload-artifact` from v7.0.1 (`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`) to v7.0.2 (`cf430e030ddbb5b0abf93d22962f4752f3646cd9`).
  - Bumped `actions/download-artifact` from v8.0.1 (`3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`) to v8.0.2 (`9000827ccba6bdab643e8b6fd33ac0654aef8333`).
- **Dependabot Workflow Routing**:
  - Configured `target-branch: "develop"` in `.github/dependabot.yml` across `github-actions` and `pip` package ecosystems.
  - Ensured automated dependency PRs build and validate against `develop` without triggering PR-to-main Release Gate 4.5 arbitration checks.
  - Extended `tests/integration/test_ci_workflows.py` to assert `target-branch: "develop"` is preserved.

### Governance & Architecture
- **Prefer Subagent Delegation Governance Cell (`wall-prefer-subagent-delegation`)**:
  - Established `.soma/cells/walls/wall-prefer-subagent-delegation.md` enforcing the Delegation-First Mandate for implementation tasks spanning $\ge 2$ disjoint files or independent modules.
  - Preserves primary orchestrator context for system architecture, cross-module integration, test verification, and staff synthesis.
  - Codifies Disjoint Lane Execution (explicit non-overlapping file scopes, model tiering, single-call fan-out, and verification against cheap-talk self-reports).
- **Genome Alignment**:
  - Updated Section 1 of `genome/subagent-delegation.md` to incorporate the Delegation-First Mandate and Single-Call Fan-Out protocol.

## [1.5.0] — 2026-10-09 — "Lifecycle Parity & Diagnostic Transparency"

### Developer Experience, Full Lifecycle Parity & Mutation Diagnostics
- **Production Status Rule Counting Parity (BUG-090)**:
  - Decoupled `_project_root` workspace resolution from `test_mode` in `soma status`. Production CLI executions now accurately count active platform rules rather than erroneously reporting `Core rules: 0 active`.
- **Symmetric Claude Platform Uninstallation (BUG-091)**:
  - Extended `soma uninstall --platform claude` to clean up the 5 starter rule `.md` files in `~/.claude/` (or `<project>/.claude/`), sanitize both target and workspace `.mcp.json` configs, and excise the git pre-commit hook block installed during `soma init`.
  - Added opt-in `--purge` flag to `soma uninstall` for explicitly removing `.soma/` governance state, while preserving `.soma/` by default.
- **Claude Rules Parity & Local Scoping in `soma init` (BUG-092)**:
  - Unified `ClaudeAdapter.render_config()` to render full rule content across both `init` and `install` workflows, eliminating truncated rule stub files.
  - Added `--local` flag support to `soma init`, allowing developers to target project-local rule directories (`<project>/.claude` and `<project>/CLAUDE.md`) in addition to default global configuration.
- **Dry-Run Output Standardization (BUG-093)**:
  - Standardized uninstallation logging across all platform adapters (`claude`, `copilot`, `mcp`) to use standard `[dry-run] Would uninstall <path>` notation instead of past-tense `"Uninstalled"` statements during `--dry-run`.
- **Telemetry Runner Safety & Missing Make Graceful Degradation (BUG-094)**:
  - Guarded Makefile discovery in outcome telemetry with `shutil.which("make")` validation, preventing failed subprocess invocations on systems lacking `make` (such as bare Windows environments).
  - Treated process exit code 127 as unverified/command-not-found rather than recording a false test failure, preventing unfair -1.0 fitness penalties across all governed cells.
  - Added `SOMA_REFLECT_ON_CLOSE` environment variable check to allow graceful opt-out of MCP server shutdown test runs.
- **Mutation Tester Diagnostic Transparency (BUG-095)**:
  - Introduced structured `TestRunResult` to capture subprocess exit codes, timeouts, and stderr details during mutation testing prerequisite baseline checks.
  - Replaced generic `"Baseline tests fail against the unmutated code"` errors with actionable diagnostic reasons (e.g. timeout duration under load, unresolved test runner binaries, or exact test assertion/traceback excerpts).

## [1.4.0] — 2026-10-09 — "Cross-Platform Execution & Safe Claude Lifecycle"

### Cross-Platform Execution, Windows Toolchain Hardening & Claude Lifecycle Parity
- **Safe Claude Configuration Lifecycle & Data Loss Prevention (BUG-088, [#142](https://github.com/nseney1/Soma-Governance/issues/142))**:
  - Delimited injected Soma instructions in `CLAUDE.md` with `<!-- SOMA:START -->` and `<!-- SOMA:END -->` markers.
  - Hardened `soma uninstall --platform claude` to parse and excise only the Soma-governed block, completely preserving user-authored custom instructions and notes. `CLAUDE.md` is deleted only if no non-Soma content remains.
  - Automatically cleans up `soma` from `mcpServers` in `.mcp.json` / `.claude.json` upon uninstallation.
- **Unified Claude Rules Directory & Path Parity (BUG-089, [#143](https://github.com/nseney1/Soma-Governance/issues/143))**:
  - Fixed `soma init --platform claude` to install rules and `CLAUDE.md` to user home (`~/.claude/`), resolving parity conflicts with `soma doctor`, `soma status`, and `soma uninstall`.
  - Replaced improper use of `args._project_root` as home override with explicit `_home` / `_home_override` test seams.
- **Rust AST Driver on Windows Python.org Installs (BUG-086, [#144](https://github.com/nseney1/Soma-Governance/issues/144))**:
  - The AST driver runner and `soma doctor` now resolve a bare `python3`/`python` driver command that is not on `PATH` to the interpreter running Soma (`sys.executable`), bypassing missing `python3.exe` on python.org Windows installations and 0-byte Windows Store execution aliases.
- **Test Harness Hardening & Symlink Fallbacks (BUG-087, [#145](https://github.com/nseney1/Soma-Governance/issues/145))**:
  - Added `anyio` to `[dev]` extras and CI pinned dependencies so `test_async_atomic_write_text` reliably executes on all environments.
  - Switched direct `symlink_to()` calls to `conftest.symlink_or_skip` so test suites pass on Windows environments without Developer Mode or administrative privileges.
- **Claude Platform Adapter Refactoring (`soma_cli/platforms/claude.py`)**:
  - Replaced deeply nested `if/elif/else` ladders in `ClaudeAdapter` with modular, single-purpose helper functions: `_inject_soma_section`, `_strip_soma_section`, `_uninstall_claude_md`, and `_clean_mcp_config`.
  - Flattened `install()` and `uninstall()` methods into linear, declarative routines with isolated exception handling.
- **AST Driver Architectural Cleanup & Deterministic Token Resolution (`soma_core/ast/runner.py`, `soma_core/ast/detect.py`)**:
  - Introduced deterministic `{python}` token support in `slots.yaml`, expanding directly to `sys.executable` across all platforms at runtime.
  - Added an in-process fast path for the bundled Rust AST driver (`rust_ast.py`), parsing Rust sources directly via `parse_rust_source` with zero subprocess overhead.
  - Purged platform-specific heuristic string sniffing (such as `windowsapps` alias detection and OS branching) from `soma_core/ast/runner.py`, restoring core engine purity. *(Note: The interim `windowsapps` string heuristic was refactored and eliminated prior to release and is not in production; v1.4.0 relies exclusively on deterministic `{python}` token expansion and in-process execution.)*

## [1.3.0] — 2026-10-08 — "Unified CLI Command Architecture & Discovery"

### Unified CLI Command Architecture, Modular Subcommands & Categorized Discovery
- **`SomaCommand` Protocol & Categorized Discovery (`soma_cli/commands/`)**:
  - Modularized monolithic CLI handlers into distinct `SomaCommand` subclasses with explicit metadata: `name`, `category` (`CommandCategory`), `description`, and `aliases`.
  - Structured all 24 commands across four decoupled domain modules:
    - `bootstrap.py`: `init`, `genesis`, `clone`, `config`
    - `inspection.py`: `status`, `list` (`ls`), `explain` (`show`), `history`, `metrics`, `doctor`, `detect` (`languages`, `drivers`)
    - `governance.py`: `propose`, `audit`, `receipt`, `freeze`, `thaw`, `adapt` (`evolve`), `export`, `import`
    - `verification.py`: `verify` (`check`), `quarantine`, `sweep`, `restore`, `checkpoint`
- **`CommandRegistry` Engine (`soma_cli/commands/__init__.py`)**:
  - Centralized registration, aliasing, and lazy instantiation for CLI commands.
  - Built-in category filtering (`get_by_category()`), alias resolution (`resolve()`), and schema discovery.
- **Orchestrator Refactor (`soma_cli/cli.py`)**:
  - Slimmed CLI entrypoint from 620 to 300 lines by delegating argument definition and execution to registry commands.
  - Enhanced `--help` formatting with clean category grouping, visual hierarchy, and alias hints.
  - Guaranteed 100% backward compatibility with existing command arguments, subparser flags, and stdout/JSON contracts.

## [1.2.1] — 2026-10-08 — "Git-Aware Polyglot Call Graph & Doctor Display Hotfix"

### Git-Aware Call Graph Boundary Discovery & Doctor Auto-Repair Fix (BUG-085)
- **Git-Aware File Discovery & Dynamic Extension Discovery (`soma_core/verification/call_graph.py`)**:
  - Replaced brittle directory blacklists with `GitWorkspace`-backed file discovery (`git ls-files --cached --others --exclude-standard`), automatically and universally respecting `.gitignore` across all project types without hardcoding compiler output names (`target/`, `.cargo/`, `bin/`, `obj/`, etc.).
  - Eliminated static hardcoded source extension sets in favor of dynamic extension resolution (`_resolve_searchable_extensions`), discovering source extensions from configured workspace slots (`.soma/slots.yaml`), active AST runner drivers, and target file metadata.
  - Implemented `_is_safe_source_file()` defense-in-depth guard rejecting files exceeding 1MB or containing binary null bytes.
- **Standalone `soma detect` Command & `soma doctor --drivers` (`soma_cli/detect.py`, `soma_cli/doctor.py`)**:
  - Added dedicated `soma detect` command (aliases: `soma languages`, `soma drivers`) allowing developers to inspect detected languages, toolchains, and AST driver bindings, and auto-provision `.soma/slots.yaml` with `--fix` independently of `soma init` or `soma genesis`.
  - Added `--drivers` flag to `soma doctor` for fast, targeted AST driver health checks without running full platform/rules/MCP audits.
- **Doctor Auto-Provision Display & Dry-Run Fixes (`soma_cli/doctor.py`, `soma_core/ast/detect.py`)**:
  - Fixed display fallthrough bug in `soma doctor --fix`: reloads `SlotRegistry` immediately after auto-provisioning so the configured polyglot driver is accurately reported rather than falling through to the native Python message.
  - Fixed `provision_ast_driver_slots` to strictly honor `dry_run=True`, preventing unauthorized directory creation or driver template copies during simulated runs.

## [1.2.0] — 2026-10-08 — "Zero-Touch Genesis Polyglot Provisioning & Rust AST Driver"

### Zero-Touch Polyglot Detection, Rust AST Driver & Release Verification Alignment
- **Zero-Touch Polyglot Provisioning (`soma_core/ast/detect.py`)**:
  - `detect_project_languages()`: Automatically detects source languages (Rust, Go, TypeScript/JavaScript, Python) by inspecting root manifests (`Cargo.toml`, `package.json`, `go.mod`, etc.) and scanning project source trees.
  - `provision_ast_driver_slots()`: Proactively configures `.soma/slots.yaml` with recommended driver commands and stages reference driver files into `.soma/drivers/` with full dry-run support.
- **CLI Workflows Integration (`soma_cli/`)**:
  - `soma init`: Automatically detects project languages and provisions polyglot AST driver slots during repository initialization.
  - `soma genesis`: Seamlessly auto-provisions AST drivers during initial repository scan and reports status in console and JSON output.
  - `soma doctor --fix`: Identifies unconfigured AST drivers for non-Python sources in the workspace and repairs them with `--fix`.
- **Reference Rust AST Driver & Template Bundling**:
  - Pure Python stdlib regex/block parser (`rust_ast.py`) producing `NormalizedAST` JSON with functions, structs, impls, modules, macros, and mutation points without external pip dependencies.
  - Bundled driver templates in `soma_core/ast/drivers/templates/` and installer recipe in `install/drivers/rust_ast.py`. Added package data distribution in `pyproject.toml`.
- **CI/CD & Release Verification Alignment (BUG-084)**:
  - Fixed `soma verify --layer1-only` in release tag publishing workflows by propagating resolved `diff_base` to `soma_core.verification.runner.run_layer1()` and adding `HEAD~1` fallback in `_get_modified_lines()`.
- **Architecture Decision Record (ADR)**:
  - `docs/architecture/decisions/ADR-016-zero-touch-polyglot-genesis.md`: Documents design trade-offs, language detection heuristics, and template installation paths.

## [1.1.0] — 2026-10-08 — "Language-Agnostic AST Verification via Normalized AST Drivers"

### Polyglot Verification, Normalized AST Drivers & Zero-Dependency Schema
- **Normalized AST Driver (NAD) Protocol (`soma_core/ast/`)**:
  - `soma_core/ast/schema.py`: Language-agnostic intermediate representation defining `NormalizedAST`, `DefinitionNode`, `CallSiteNode`, `ImportNode`, and `MutationPoint` with JSON and mapping roundtrip serialization.
  - `soma_core/ast/drivers/python.py`: In-process native Python standard library parser (`ast.parse`) providing a sub-millisecond fast path with zero process overhead.
  - `soma_core/ast/runner.py`: External process execution engine (`ASTDriverRunner`, `ASTDriverRegistry`) resolving drivers via `.soma/slots.yaml` or code registry with strict 3.0-second timeout enforcement and workspace confinement.
- **Layer 1 Polyglot Call Graph & Mutation Adaptation (`soma_core/verification/`)**:
  - `soma_core/verification/call_graph.py`: Implements `check_normalized` to verify function call reachability, detect orphan deadwood, and ignore comments and string literals across polyglot files.
  - `soma_core/verification/mutation_tester.py`: Adds `apply_mutation_point` and `collect_mutations_from_ast` supporting byte-offset and coordinate operator swaps on non-Python sources.
  - `soma_core/verification/runner.py`: Automatically routes changed polyglot files through configured AST drivers.
- **Host Driver Recipes (`install/drivers/`)**:
  - `install/drivers/ts_ast.js`: Zero-dependency Node.js recipe for TypeScript and JavaScript using the official `typescript` compiler API when present and falling back to a deterministic built-in lexer in bare environments.
  - `install/drivers/go_ast.go`: Zero-dependency Go recipe leveraging standard library `go/parser`, `go/token`, and `go/ast`.
- **Doctor Diagnostics & Architecture Documentation**:
  - `soma_cli/doctor.py`: Added `_check_ast_drivers` diagnostic verifying that configured AST driver binaries are resolvable on PATH.
  - `docs/guides/polyglot_ast.md`: Comprehensive developer guide for authoring and configuring custom AST drivers.
  - `docs/architecture/decisions/ADR-015-normalized-ast-driver-protocol.md`: Architectural Decision Record codifying the NAD protocol and trade-offs.

## [1.0.0] — 2026-10-08 — "General Availability & Production Governance Framework"

### Production GA, Documentation Portal & Formal Backwards Compatibility
- **Lean Documentation Portal (< 200 Lines)**:
  - Restructures root `README.md` into an immediate, above-the-fold portal with 30-second quickstart, closed-loop architecture diagram, and deep-dive documentation guide cards.
- **Production Architecture & Operations Guides (`docs/guides/`)**:
  - `docs/guides/mcp_gateway.md`: Dual-Plane Gateway architecture, tool tiers, receipt security, and opt-in projection.
  - `docs/guides/verification_pipeline.md`: Two-Layer Verification engine, deterministic Layer 1 AST checks, Layer 2 Adversarial Rebuttal, and Gate 4.5.
  - `docs/guides/cell_lifecycle.md`: Five cell types, evolutionary lifecycle, Wilson-bounded fitness scoring, and zero-touch decay.
  - `docs/guides/skill_graph.md`: Horizontal skill graph, typed envelopes (<150 tokens), and file-buffered handoffs.
- **SemVer 2.0 Backwards Compatibility Guarantee (`docs/project/COMPATIBILITY.md`)**:
  - Codifies formal public API contracts across CLI, Python SDK (`soma_sdk`), MCP Server (`soma_mcp`), and Core Governance schemas starting at `v1.0.0`.
- **Checkpoint Candidate Resolution**:
  - Updates verification test candidate resolution in `soma_core/verification/checkpoint_checks.py` to recognize relocated domain hierarchy suites.

## Before 1.0.0

Releases 0.1.0 to 0.123.0 (2026-09-26 to 2026-10-08) were published under the Soma name. Their notes are not repeated here: `git show v3.3.0:docs/project/CHANGELOG.md` prints the full changelog as it stood at 3.3.0, and `git tag --list 'v0.*'` lists the tagged releases (v0.15.0 and later).
