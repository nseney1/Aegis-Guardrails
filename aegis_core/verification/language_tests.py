"""One selected language command per snapshot; global wrapper precedence stays with callers.

Metadata probes are bounded and run once when preparing a reusable plan, outside
the repository. Commands execute user/repository code, not a network sandbox.
Execution inherits testexec's process cleanup contract, including its Windows bound.
"""
from __future__ import annotations

import os
import posixpath
import re
import time
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

from aegis_core import testexec
from aegis_core.language_runtime import (
    LanguageRuntime,
    RuntimeUnavailable,
    language_runtime_environment,
    prepare_language_runtime,
)
from aegis_core.language_runtime import (
    read_runtime_report as _read,
)
from aegis_core.primitives import is_within, key_within
from aegis_core.testplans import expand_command, language_settings, rebase_snapshot_arguments
from aegis_core.verification.test_outcomes import (
    RunOutcome,
    RustTarget,
    parse_go_test2json,
    parse_junit,
    parse_rust_libtest,
)

_DEFAULTS = {"go": ("go", "test", "-json", "-count=1", "-run", "{filters}", "{packages}"),
             "rust": ("cargo", "test", "--offline", "--locked", "--no-fail-fast", "--color", "never")}


_Unavailable = RuntimeUnavailable

@dataclass(frozen=True)
class GoTest:
    file: str
    package: str
    name: str


@dataclass(frozen=True)
class LanguageTestPlan:
    language: str
    workspace: str = ""
    command: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    timeout_s: float = 300.0
    go_tests: tuple[GoTest, ...] = ()
    rust_targets: tuple[tuple[str, tuple[RustTarget, ...]], ...] = ()
    parent_caches: tuple[tuple[str, str], ...] = ()
    rust_toolchain: str | None = None
    cargo_target: str | None = None
    reason: str | None = None
    detail: str = ""

    @property
    def available(self) -> bool:
        return self.reason is None


def _path(raw: str) -> str:
    raw = raw.replace("\\", "/")
    path = posixpath.normpath(raw)
    if (not raw or "\0" in raw or raw.startswith("/") or re.match(r"^[A-Za-z]:", raw)
            or path in (".", "..") or path.startswith("../")):
        raise _Unavailable("test_ids_unmapped", "test file must be repository relative")
    return path


def _outside(path: Path, workspace: Path) -> bool:
    return not (is_within(path, workspace, unresolvable=True) or key_within(
        os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(workspace))))


def _fresh(scratch: Path) -> None:
    scratch.mkdir(parents=True, exist_ok=True)
    if any(scratch.iterdir()):
        raise _Unavailable("deps_unavailable", "scratch must be empty; preserve prior execution evidence")


def _selection(language: str, files: tuple[str, ...], go_tests: Sequence[GoTest],
                rust_targets: Mapping[str, Sequence[RustTarget]] | None):
    selected_go = tuple(sorted({GoTest(_path(test.file), test.package, test.name)
                                  for test in go_tests if _path(test.file) in files},
                               key=lambda test: (test.file, test.package, test.name)))
    if language == "go":
        if any(not file.endswith("_test.go") for file in files) or any(
                not any(_path(test.file) == file for test in selected_go) for file in files):
            raise _Unavailable("test_ids_unmapped", "missing Go package-scoped definitions")
        identities: dict[tuple[str, str], set[str]] = {}
        for test in selected_go:
            if (not test.package or test.package.startswith("-") or any(c.isspace() for c in test.package)
                    or any(c in test.package for c in "\0*?[]") or not test.name.isidentifier()):
                raise _Unavailable("test_ids_unmapped", "invalid Go definition")
            identities.setdefault((test.package, test.name), set()).add(_path(test.file))
        if any(len(paths) != 1 for paths in identities.values()):
            raise _Unavailable("test_ids_unmapped", "ambiguous Go definition")
    targets = tuple(sorted((source, tuple(values)) for source, values in (rust_targets or {}).items()))
    if language == "rust":
        if any(not file.endswith(".rs") or ("tests" not in file.split("/")[:-1]
                                            and file not in (rust_targets or {})) for file in files):
            raise _Unavailable("tests_inline_with_source", "Rust inline tests require source changes")
        if not targets or any(len(values) != 1 for _, values in targets):
            raise _Unavailable("test_ids_unmapped", "missing or ambiguous Rust target metadata")
        for source, values in targets:
            target = values[0]
            if (not source or target.target_kind != "test" or not all(
                    value and not value.startswith("-") and not any(c.isspace() for c in value)
                    and not any(c in value for c in "\0*?[]") for value in (target.package, target.target_name))):
                raise _Unavailable("test_ids_unmapped", "unsupported Rust target metadata")
    return selected_go, targets


def prepare_language_tests(workspace: Path, language: str, files: Sequence[str], *, scratch: Path,
                           go_tests: Sequence[GoTest] = (),
                           rust_targets: Mapping[str, Sequence[RustTarget]] | None = None,
                           parent: Mapping[str, str] | None = None,
                           runtime: LanguageRuntime | None = None) -> LanguageTestPlan:
    """Resolve a reusable plan in the parent, using caller-supplied native identity metadata.

    Rust source-header keys must already identify selected targets unambiguously.
    This function does not infer target/module identity or read tests.command.
    """
    if language not in ("go", "rust", "ts"):
        raise ValueError(f"unsupported language: {language}")
    workspace, scratch = Path(workspace).resolve(), Path(scratch).resolve()
    plan = LanguageTestPlan(language, workspace=str(workspace))
    parent = dict(os.environ if parent is None else parent)
    try:
        if not _outside(scratch, workspace):
            raise _Unavailable("deps_unavailable", "scratch must be outside the workspace")
        selected = tuple(sorted({_path(file) for file in files}))
        plan = replace(plan, files=selected)
        if not selected:
            raise _Unavailable("no_tests_collected", "no changed test files")
        definitions, targets = _selection(language, selected, go_tests, rust_targets)
        plan = replace(plan, go_tests=definitions, rust_targets=targets)
        try:
            settings = language_settings(workspace, language)
        except ValueError as exc:
            raise _Unavailable("tests_runner_not_configured", str(exc)) from exc
        plan = replace(plan, timeout_s=settings.timeout_s)
        command = settings.command or _DEFAULTS.get(language)
        if command is None:
            raise _Unavailable("tests_runner_not_configured", "TS/JS requires a user-scoped runner")
        runtime = runtime or prepare_language_runtime(workspace, language, command, scratch=scratch, parent=parent)
        if runtime.language != language:
            raise _Unavailable("test_ids_unmapped", "prepared runtime language mismatch")
        command = (runtime.command[0], *command[1:])
        if language == "go":
            packages = tuple(sorted({test.package for test in definitions}))
            pattern = "^(" + "|".join(re.escape(name) for name in sorted({test.name for test in definitions})) + ")$"
            command = tuple(expand_command(command, {"packages": packages, "filters": (pattern,), "files": selected,
                                                      "junit": "{junit}", "out": "{out}"}))
        elif language == "rust":
            if settings.command is None:
                command = (*command, *(word for package in sorted({v[0].package for _, v in targets}) for word in ("--package", package)),
                           *(word for name in sorted({v[0].target_name for _, v in targets}) for word in ("--test", name)))
        return replace(plan, command=tuple(command), parent_caches=runtime.parent_caches,
                       rust_toolchain=runtime.rust_toolchain, cargo_target=runtime.cargo_target)
    except _Unavailable as exc:
        return replace(plan, reason=exc.reason, detail=exc.detail)
    except (OSError, ValueError) as exc:
        return replace(plan, reason="tests_runner_not_configured", detail=str(exc))


@contextmanager
def _dependencies(snapshot: Path, workspace: Path, enabled: bool):
    if not enabled:
        yield
        return
    source, link = workspace / "node_modules", snapshot / "node_modules"
    if not source.is_dir():
        raise _Unavailable("deps_unavailable", "node_modules unavailable")
    if os.path.lexists(link):
        raise _Unavailable("deps_unavailable", "snapshot node_modules already exists")
    try:
        link.symlink_to(source.resolve(), target_is_directory=True)
    except OSError as exc:
        raise _Unavailable("deps_unavailable", f"node_modules link unavailable: {exc}") from exc
    owned = link.lstat()
    try:
        yield
    finally:
        if os.path.lexists(link):
            current = link.lstat()
            if not link.is_symlink() or (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
                raise _Unavailable("deps_unavailable", "snapshot node_modules link changed during execution")
            link.unlink()


def _unavailable(plan: LanguageTestPlan, reason: str, detail: str = "", outcome: RunOutcome | None = None) -> RunOutcome:
    result = outcome or RunOutcome(plan.language, "repo-runner" if plan.language == "ts" else "aegis", 127)
    field = "mapping_errors" if reason == "test_ids_unmapped" else "incomplete_errors" if reason in (
        "report_missing", "report_unsafe", "report_unreadable", "output_too_large", "invalid_unicode", "no_tests_collected") else "build_errors"
    message = reason if field == "incomplete_errors" or not detail else reason + ":" + detail
    return replace(result, **{field: getattr(result, field) | {message}})


def run_language_snapshot(plan: LanguageTestPlan, snapshot: Path, workspace: Path, scratch: Path,
                          *, deadline: float | None = None) -> RunOutcome:
    """Execute at most one test command, retaining full output and every parser error.

    The caller owns head/base coordination and supplies an optional aggregate
    monotonic deadline. No snapshot retry or per-test subprocess is started.
    TS dependency links require OS support; Windows privilege failure is explicit.
    """
    if not plan.available:
        return _unavailable(plan, plan.reason, plan.detail)
    snapshot, workspace, scratch = Path(snapshot).resolve(), Path(workspace).resolve(), Path(scratch).resolve()
    if (str(workspace) != plan.workspace or not _outside(snapshot, workspace) or not _outside(scratch, workspace)
            or not _outside(workspace, snapshot) or not _outside(scratch, snapshot) or not _outside(snapshot, scratch)):
        return _unavailable(plan, "test_ids_unmapped", "snapshot, scratch or plan workspace mismatch")
    if any(not is_within(snapshot / file, snapshot, unresolvable=False) or not (snapshot / file).is_file()
           for file in plan.files):
        return _unavailable(plan, "test_ids_unmapped", "selected test file missing or outside snapshot")
    timeout = min(plan.timeout_s, deadline - time.monotonic()) if deadline is not None else plan.timeout_s
    if timeout <= 0:
        return RunOutcome(plan.language, "repo-runner" if plan.language == "ts" else "aegis", 124, timed_out=True,
                          incomplete_errors=frozenset({"deadline_exceeded"}))
    outcome = None
    try:
        _fresh(scratch)
        env = language_runtime_environment(LanguageRuntime(plan.language, plan.command, plan.parent_caches,
            plan.rust_toolchain, plan.cargo_target), scratch)
        report, output = scratch / "results.xml", scratch / "output.log"
        packages = tuple(sorted({test.package for test in plan.go_tests}))
        command = expand_command(plan.command, {"files": plan.files, "packages": packages, "filters": (),
                                                "junit": str(report), "out": str(report)})
        command = rebase_snapshot_arguments(command, workspace, snapshot)
        with _dependencies(snapshot, workspace, plan.language == "ts"):
            timeout = min(plan.timeout_s, deadline - time.monotonic()) if deadline is not None else plan.timeout_s
            if timeout <= 0:
                return RunOutcome(plan.language, "repo-runner" if plan.language == "ts" else "aegis", 124, timed_out=True,
                                  incomplete_errors=frozenset({"deadline_exceeded"}))
            status = testexec.run_tests(command, snapshot, env, timeout, scratch / "unused-pytest.xml", output)
            outcome = RunOutcome(plan.language, "repo-runner" if plan.language == "ts" else "aegis",
                                 status.exit, status.timed_out)
            text = _read(output)
            markers = {"go": ("module lookup disabled", "missing go.sum entry for module providing package"),
                       "rust": ("no matching package named", "failed to download"),
                       "ts": ("Cannot find module", "ERR_MODULE_NOT_FOUND", "Failed to resolve import", "Cannot find package")}
            dependencies_missing = any(marker in text for marker in markers[plan.language])
            if dependencies_missing:
                outcome = replace(outcome, build_errors=frozenset({"deps_unavailable"}))
            options = {"exit_code": status.exit, "timed_out": status.timed_out}
            if plan.language == "go":
                parsed = parse_go_test2json(text, expected_packages=packages, **options)
            elif plan.language == "rust":
                parsed = parse_rust_libtest(text, targets=dict(plan.rust_targets), **options)
            else:
                report_text = _read(report)
                dependencies_missing |= any(marker in report_text for marker in markers[plan.language])
                parsed = parse_junit(report_text, repo_files=plan.files, expected_files=plan.files, language="ts", **options)
            outcome = replace(parsed, build_errors=parsed.build_errors | ({"deps_unavailable"} if dependencies_missing else set()))
            if not any((outcome.passed_ids, outcome.failed_ids, outcome.skipped_ids,
                        outcome.build_errors, outcome.collection_errors, outcome.incomplete_errors,
                        outcome.conflict_errors, outcome.mapping_errors)):
                outcome = replace(outcome, incomplete_errors=frozenset({"no_tests_collected"}))
        return outcome
    except _Unavailable as exc:
        return _unavailable(plan, exc.reason, exc.detail, outcome)
    except OSError as exc:
        return _unavailable(plan, "execution_failed", str(exc), outcome)
    except ValueError as exc:
        return _unavailable(plan, "tests_runner_not_configured", str(exc), outcome)
