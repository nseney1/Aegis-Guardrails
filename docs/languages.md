# Language checks and test evidence

Aegis parses source to enforce explicit patterns. Parsing, finding a paired test,
running tests, proving fail-to-pass and measuring coverage are separate results.
The [README](../README.md#whats-included) summarizes availability; this page explains
the syntax and execution boundaries.

## Parsing and rule matching

Python uses the standard-library AST. TypeScript/JavaScript and Rust use Aegis's
first-party in-process extractors, enabled by default. They need no Node, Cargo,
rustc, installed project dependencies or bundled third-party parser.

| Language | Source extraction |
|---|---|
| Python (`.py`) | Imports and aliases, calls and arguments, functions, classes and decorators |
| TS/JS (`.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, `.cjs`) | ES imports/re-exports, type-only imports, literal `require`/dynamic imports, aliases and destructuring, calls, optional chains, constructors, tagged templates, decorators, functions and classes |
| Go (`.go`) | Standard-library `go/parser` imports, aliases, functions, methods, selector calls, arguments and composite literals, including `&T{...}` |
| Rust (`.rs`) | Grouped/aliased `use`, `extern crate`, path and method calls, turbofish, macro invocation sites, struct literals, attributes, definitions and test-module metadata |

Go parsing is opt-in through `ast.packaged_drivers` in the repository configuration;
`aegis init` offers it for detected Go projects. It needs an installed Go ≥1.21.
On a cache miss Aegis builds its own standard-library-only parser outside the
repository, with a separate 120-second build timeout. One bounded batch process
serves a check's Go files, including security head/base comparisons. The cache key
includes packaged source, Go version, OS and architecture. `aegis doctor --drivers`
reports the compiler and cache state without building; confirmed `doctor --fix`
can prepare the cache.

Custom external drivers are selected only by user `~/.aegis/config.json`. They keep
the per-file protocol: the command receives a path and returns normalized AST JSON.
The packaged Go driver uses a bounded NDJSON batch protocol. Repository settings
can select packaged drivers, but cannot name an executable.

Rules use the same `forbid_ast` keys across languages: `imports`, `calls` and
`decorators`. Module separators `/` and `::` become `.`, and Node's `node:` prefix
is removed for matching: `node:child_process.exec`, `child_process.exec` and the
resolved alias refer to the same target. Relative imports keep their relative
identity. A leading-dot call pattern such as `.danger_accept_invalid_certs`
matches a method without requiring a known receiver type.

Literal arguments use semantic values: booleans stay distinct from numbers and
strings; supported numeric bases, separators and Rust suffixes normalize. Positional
arguments are `#0`, `#1`, and so on. A static JS object argument exposes its fields
to `where`, so `{shell: true}` can match `where: {shell: true}` just like Python's
`shell=True`. Go/Rust construction fields are available at construction sites.
Spreads, computed keys, nonliteral expressions and unsupported values remain
unknown; they do not prove a safe value. `builtin: true` is Python-specific.

Suppress a specific finding with a comment on the finding's line:

```python
value = eval(expression)  # aegis: allow[sec-py-eval-exec] reviewed compatibility boundary
```

```javascript
eval(expression); // aegis: allow[sec-js-eval] reviewed compatibility boundary
```

Go and Rust use the same `// aegis: allow[rule-id] reason` form. Non-Python
suppressions come from parser-recognized comments, so matching text in strings,
templates or regex literals does not suppress a finding. Secret scanning also
accepts `gitleaks:allow` in `#`, `//` and `/*` comments; Python `nosec`/`noqa`
conventions do not become cross-language AST suppressions.

## Syntax and security limits

These extractors are syntactic checks, not type checking, execution or taint
analysis. JS regex/division, template and JSX boundaries are tracked; unsupported
lexical ambiguity and unterminated tokens fail closed. TS type assertions and
generics are distinguished from JSX by extension/context. A valid parse does not
prove that every compiler-valid construct has a semantic model.

Literal computed members such as `obj['exec']()` are recognized. Arbitrary computed
targets, assignment-based aliasing, `getattr`, `eval.call`, `eval.apply`,
`Reflect.apply`, runtime import resolution and non-Python lexical shadowing are
outside the guarantee. Unknown import/call targets and argument values produce
advisory UNKNOWN evidence where the rule cannot decide. Unsupported BigInt values
also remain unknown. Rust macros are recorded without expansion; macro-generated
code and receiver types are not resolved. Go imported-package names are inferred
from the import path or alias; unusual package names can require local spellings.

Built-in security packs contain seven Python rules, five shared JS/TS rules, four
Go rules and two Rust rules. They check introduced findings against the diff base,
with test-path exemptions and suppressions reported. They cover dynamic execution,
unsafe shell use, selected weak hashes and disabled TLS/SSH verification where
the language pack has a matching rule; Rust's pack covers shell and TLS patterns,
not weak hashes. These are bounded pattern sets, not comprehensive security audits.
User `forbid_ast` checks and the secret scan remain separate.

| Evidence | Meaning and effect |
|---|---|
| `unverified no_driver:<ext>` | Matching AST coverage is unavailable. Advisory normally; ordinary `--strict` makes it blocking. A configured driver failure is a failure, not a silent skip. |
| `unverified too_large` | Native source exceeds 2 MiB. Advisory with an exclusion hint; it was not verified. |
| UNKNOWN | A target, argument or required driver capability cannot be resolved; advisory, not proof of a safe call. |
| Parse/lexical error | An active parser could not safely extract the governed file; verification fails closed. |

## Test pairing

Python keeps its filename-based lookup. TS/JS recognizes `.test`/`.spec` names and
tests in `__tests__` or `test`/`tests`, across all eight extensions. Go accepts the
matching `name_test.go` or another `*_test.go` in the same package directory;
package fallback is informational. Rust accepts inline `#[cfg(test)] mod` bodies
or matching integration tests. A pairing says where tests live, not whether they
ran or passed, and never supplies receipt credit.

## Regression tests and recorded runs

`aegis check --ci` reports regression tests (fail-to-pass) at warning tier. A changed
test must fail against the base and pass at the head under the same stable identity,
with a successful head run. Go identities include package and full subtest path;
Rust identities include package, target kind/name and module path; TS/JS identities
include repository-relative file, suite and case. A base build failure, no tests,
only skips, truncated output or ambiguous identities cannot prove a transition.

Without a global `tests.command`, Python uses pytest; Go uses `go test -json
-count=1` with selected packages/tests; Rust uses `cargo test --offline --locked`
for selected integration targets. Rust inline unit tests are recognized for
pairing, but cannot be overlaid independently of production code and report
`tests_inline_with_source`. Custom Rust harnesses and ambiguous shared helpers
cannot supply native identities. There is one command per language per repository,
not per package. Native regression execution uses at most one head and one base
test command per affected language. Default command timeouts are 300 seconds for
TS/JS and Go, 900 for Rust, configurable with `tests.languages.<key>.timeout_s`.
Metadata and cold Go parser preparation have separate bounded operations; the
test-command timeout is not a promise about total cold elapsed time.

`aegis check --record --tests` and commit-trailer replay share a whole-tree recipe.
Automatic runs retain separate language rows and require complete passing evidence
from every selected language. Go receipts run all tests in selected packages.
Rust selection remains integration-target-only. A passing Python suite cannot
certify an unavailable native suite.

An explicit user `tests.command` takes precedence over automatic language runs and
executes once per snapshot. Pytest commands produce JUnit; `python -m unittest`
uses Aegis's JUnit wrapper for receipts. A custom global wrapper must write complete
JUnit to `{junit}` to supply a receipt: a success summary alone is insufficient.
Fail-to-pass currently supports only pytest-based global commands; other wrappers
report `tests_runner_unsupported`, even if their receipt succeeded.

### TS/JS runner configuration

TS/JS requires a user-scoped command that writes complete JUnit, including file
attributes for every selected test file. It is labelled `witness: repo-runner`:
the repository runner supplies the result. Node and dependencies must already be
installed. Aegis links the existing `node_modules` into each snapshot; a missing
directory or an unavailable link on Windows gives explicit unavailable evidence.

For an already installed Vitest, merge this into **user** `~/.aegis/config.json`,
replacing `/absolute/project` with your repository's absolute path:

```json
{
  "tests": {
    "languages": {
      "ts": {
        "command": ["node", "/absolute/project/node_modules/vitest/vitest.mjs", "run", "--reporter=junit", "--outputFile={junit}", "{files}"],
        "timeout_s": 300
      }
    }
  }
}
```

Vitest documents [JUnit and output-file selection](https://vitest.dev/guide/reporters.html).
For Jest, `aegis init` suggests a fixed command only when `jest-junit` is declared;
otherwise it prints that prerequisite. It sets file attributes and suite-error
reporting and passes the output path as an argument. Init never copies package
scripts into user configuration or writes the suggested runner command for you.

Commands accept a string split into argv or a JSON argv array; no shell is used.
Whole-word `{files}`, `{packages}` and `{filters}` expand into separate arguments,
preserving spaces in filenames. `{junit}` and `{out}` are output paths. Unknown
placeholders or embedding a multi-value placeholder inside another word fail.
Absolute repository arguments are rebased to the snapshot. The executable must
resolve outside the workspace; an explicitly chosen script argument can be inside
it. Python continues to use global `tests.command`, not `tests.languages.python`.

| Regression reason | What to inspect |
|---|---|
| `tests_runner_not_configured` | Missing/invalid per-language runner configuration |
| `tests_runner_unsupported` | Global wrapper has no supported fail-to-pass contract |
| `tests_inline_with_source` | Rust tests cannot be separated from production source |
| `deps_unavailable` / `no_driver` | Installed dependencies/toolchain or enabled Go parser |
| `test_ids_unmapped` / `conflicting_test_results` | File/target ownership or conflicting records |
| `incomplete_test_output` / `no_tests_collected` | Missing/truncated report or absent test identities |
| `timeout` / `failed_on_head` / `passed_on_base` | No qualifying fail-to-pass transition |

## Diff coverage

`aegis check --ci --coverage` reports changed executable lines against the merge
base and never changes the exit code. Python uses coverage.py with pytest-based
`tests.command`; Go defaults to `go test -coverprofile={out} ./...`. TS/JS and Rust
need user `coverage.languages.ts.command` / `coverage.languages.rust.command`
that write LCOV to `{out}`. There is no global `coverage.command` setting.

This configuration illustrates a **user-provided** TS coverage script and an
already installed cargo-llvm-cov. The TS script is not supplied by Aegis: create
and review it to run your chosen coverage tool and write LCOV to its first argument.
Rust needs cargo-llvm-cov and the matching LLVM tools installed beforehand; Aegis
does not prepare them. [cargo-llvm-cov documents the report and offline flags](https://github.com/taiki-e/cargo-llvm-cov).

```json
{
  "coverage": {
    "languages": {
      "ts": {"command": ["node", "/absolute/project/scripts/coverage-lcov.mjs", "{out}"]},
      "rust": {"command": ["cargo", "llvm-cov", "--offline", "--locked", "--lcov", "--output-path", "{out}"]}
    }
  }
}
```

Coverage runs in the clean checkout of the requested head. Report paths must stay
inside it; malformed, missing, unsafe or unmappable reports remain unverified.
Unmeasured files do not become zero-percent or fully covered files. Mixed reports
retain per-language results and can report `partial_coverage`; missing configuration
is `coverage_not_configured`, bad format `coverage_report_invalid`, unavailable
dependencies `deps_unavailable`.

## Execution trust and offline defaults

All command settings above come from user configuration outside the workspace.
They run user/repository code with temporary HOME, bounded execution and no stdin.
Go uses `GOTOOLCHAIN=local`, `GOPROXY=off`, `GOFLAGS=-mod=readonly`, `GOWORK=off`
and `GOENV=off`. Rust selects the installed default toolchain outside the repository,
sets `RUSTUP_TOOLCHAIN`, `RUSTUP_AUTO_INSTALL=0`, `CARGO_NET_OFFLINE=true` and a
user-cache target directory. Existing dependency caches are reused; repository
toolchain pins cannot make Aegis fetch a toolchain.

Aegis never installs packages or fetches test dependencies. These settings are
**not a network sandbox**: tests, build scripts and user coverage commands can
execute other programs or make network requests. See [SECURITY](../SECURITY.md#repository-trust)
for process cleanup limits and the authority of local evidence.
