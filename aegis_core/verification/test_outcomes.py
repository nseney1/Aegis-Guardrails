"""Pure structured test results; no execution, path access or configuration.

Readers require complete output (8 MiB UTF-8, at most 100,000 records/elements/lines).
Malformed, truncated or ambiguous results retain an explicit error and cannot be evidence.
Identities are tuples, never delimiter-joined strings or temporary executable names.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import posixpath
import re
from typing import Collection, Mapping, Sequence
import xml.etree.ElementTree as ET

TestId = tuple[str, ...]
_MAX_BYTES = 8 * 1024 * 1024
_MAX_RECORDS = 100_000
_ERROR_FIELDS = ("build_errors", "collection_errors", "incomplete_errors", "conflict_errors", "mapping_errors")


@dataclass(frozen=True)
class RunOutcome:
    """One execution's identities and infrastructure state; errors never become failed IDs."""
    language: str
    witness: str
    exit_code: int
    timed_out: bool = False
    passed_ids: frozenset[TestId] = frozenset()
    failed_ids: frozenset[TestId] = frozenset()
    skipped_ids: frozenset[TestId] = frozenset()
    build_errors: frozenset[str] = frozenset()
    collection_errors: frozenset[str] = frozenset()
    incomplete_errors: frozenset[str] = frozenset()
    conflict_errors: frozenset[str] = frozenset()
    mapping_errors: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        # Frozen attributes alone would still alias a mutable set supplied by a caller.
        for name in ("passed_ids", "failed_ids", "skipped_ids"):
            object.__setattr__(self, name, frozenset(tuple(identity) for identity in getattr(self, name)))
        for name in _ERROR_FIELDS:
            object.__setattr__(self, name, frozenset(getattr(self, name)))

    @property
    def incomplete(self) -> bool:
        return bool(self.incomplete_errors)

    @property
    def evidence(self) -> bool:
        return (self.exit_code == 0 and not self.timed_out and bool(self.passed_ids)
                and not any((self.failed_ids, self.build_errors, self.collection_errors,
                             self.incomplete_errors, self.conflict_errors, self.mapping_errors)))


@dataclass(frozen=True)
class RustTarget:
    """Stable caller-supplied Cargo target metadata, independent of its executable hash."""
    package: str
    target_kind: str
    target_name: str


class _Run:
    def __init__(self, language: str, witness: str, exit_code: int, timed_out: bool):
        self.status = language, witness, exit_code, timed_out
        self.results: dict[TestId, str] = {}
        self.errors: dict[str, set[str]] = {name: set() for name in _ERROR_FIELDS}

    def error(self, category: str, message: str) -> None:
        self.errors[category].add(message)

    def result(self, identity: TestId, status: str, label: str) -> None:
        if identity in self.results:
            self.error("conflict_errors", "duplicate_test_result:" + label)
        else:
            self.results[identity] = status

    def bounded(self, text: str) -> bool:
        if len(text) > _MAX_BYTES:
            self.error("incomplete_errors", "output_too_large")
            return False
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            self.error("incomplete_errors", "invalid_unicode")
            return False
        if size > _MAX_BYTES:
            self.error("incomplete_errors", "output_too_large")
            return False
        return True

    def finish(self) -> RunOutcome:
        return RunOutcome(*self.status,
                          *(frozenset(i for i, s in self.results.items() if s == status)
                            for status in ("pass", "fail", "skip")),
                          **{name: frozenset(values) for name, values in self.errors.items()})


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")


@dataclass
class _GoPackage:
    started: bool = False
    ended: bool = False
    running: set[str] = field(default_factory=set)
    terminal: set[str] = field(default_factory=set)
    failed: bool = False


def parse_go_test2json(text: str, *, exit_code: int, timed_out: bool = False,
                       expected_packages: Collection[str] = ()) -> RunOutcome:
    """Read complete ``go test -json``; optional selected packages require terminal records."""
    run = _Run("go", "aegis", exit_code, timed_out)
    if not run.bounded(text):
        return run.finish()
    packages: dict[str, _GoPackage] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if number > _MAX_RECORDS:
            run.error("incomplete_errors", "too_many_records")
            break
        try:
            event = json.loads(line, object_pairs_hook=_json_object, parse_constant=_invalid_constant)
        except (ValueError, RecursionError):
            run.error("incomplete_errors", f"invalid_json:{number}")
            continue
        if not isinstance(event, dict):
            run.error("incomplete_errors", f"invalid_event:{number}")
            continue
        action, pkg, test = event.get("Action"), event.get("Package"), event.get("Test")
        if (action not in ("start", "run", "pause", "cont", "output", "pass", "fail", "skip")
                or not isinstance(pkg, str) or not pkg.strip()
                or (test is not None and (not isinstance(test, str) or not test.strip()))
                or (action in ("run", "pause", "cont") and test is None)
                or (action == "start" and test is not None)
                or (action == "output" and not isinstance(event.get("Output"), str))):
            run.error("incomplete_errors", f"invalid_event:{number}")
            continue
        state = packages.setdefault(pkg, _GoPackage())
        if state.ended:
            run.error("incomplete_errors", "event_after_package_result:" + pkg)
        if action == "start":
            if state.started:
                run.error("conflict_errors", "duplicate_package_start:" + pkg)
            state.started = True
        elif test is not None:
            if action == "run":
                if test in state.running or test in state.terminal:
                    run.error("conflict_errors", f"duplicate_test_start:{pkg}::{test}")
                state.running.add(test)
            elif action in ("pass", "fail", "skip"):
                if test not in state.running:
                    run.error("incomplete_errors", f"missing_test_start:{pkg}::{test}")
                state.terminal.add(test)
                run.result((pkg, test), action, f"{pkg}::{test}")
            elif action in ("pause", "cont") and (test not in state.running or test in state.terminal):
                run.error("incomplete_errors", f"invalid_test_lifecycle:{pkg}::{test}")
        elif action in ("pass", "fail", "skip"):
            if state.ended:
                run.error("conflict_errors", "duplicate_package_result:" + pkg)
            state.ended = True
            state.failed = action == "fail"
            if action == "skip" and state.running:
                run.error("incomplete_errors", "skipped_package_with_tests:" + pkg)
    for pkg, state in packages.items():
        if not state.started:
            run.error("incomplete_errors", "missing_package_start:" + pkg)
        if not state.ended:
            run.error("incomplete_errors", "missing_package_result:" + pkg)
        for test in state.running - state.terminal:
            run.error("incomplete_errors", f"missing_test_result:{pkg}::{test}")
        if state.failed and not any(run.results.get((pkg, test)) == "fail" for test in state.terminal):
            run.error("build_errors", "package_failed:" + pkg)
    for pkg in set(expected_packages) - packages.keys():
        run.error("incomplete_errors", "missing_package_result:" + pkg)
    return run.finish()


def _repo_path(raw: str) -> str | None:
    raw = raw.replace("\\", "/")
    if not raw or raw.startswith("/") or "\0" in raw or re.match(r"^[A-Za-z]:", raw):
        return None
    path = posixpath.normpath(raw)
    return None if path in (".", "..") or path.startswith("../") else path


def _xml(text: str, run: _Run) -> ET.Element | None:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        run.error("incomplete_errors", "xml_declaration_forbidden")
        return None
    parser = ET.XMLPullParser(events=("start", "end"))
    root, depth, count = None, 0, 0
    try:
        for offset in range(0, len(text), 4096):
            parser.feed(text[offset:offset + 4096])
            for event, element in parser.read_events():
                if event == "start":
                    root = element if root is None else root
                    depth, count = depth + 1, count + 1
                    if count > _MAX_RECORDS or depth > 128:
                        run.error("incomplete_errors", "xml_structure_limit")
                        return None
                else:
                    depth -= 1
        parser.close()
    except ET.ParseError:
        run.error("incomplete_errors", "invalid_xml")
        return None
    return root


def _junit_file(case: ET.Element, suites: list[ET.Element], files: set[str], run: _Run) -> str | None:
    sources = [case.get("file", "")]
    for suite in reversed(suites):
        sources.append(suite.get("file", ""))
        if _repo_path(suite.get("name", "")) in files:
            sources.append(suite.get("name", ""))
    paths = {_repo_path(raw) for raw in sources if raw}
    if len(paths) > 1:
        run.error("mapping_errors", "test_ids_unmapped:conflicting_file")
        return None
    if not paths or None in paths or not paths <= files:
        run.error("mapping_errors", "test_ids_unmapped:file")
        return None
    return next(iter(paths))


def _junit_identity(case: ET.Element, suites: list[ET.Element], files: set[str], run: _Run,
                    case_id_attribute: str | None) -> TestId | None:
    file = _junit_file(case, suites, files, run)
    if file is None:
        return None
    name = case.get("name", "")
    if not name.strip():
        run.error("mapping_errors", "test_ids_unmapped:name")
        return None
    suite_name = case.get("classname") or (suites[-1].get("name", "") if suites else "")
    if suite_name and _repo_path(suite_name) is None:
        run.error("mapping_errors", "test_ids_unmapped:suite")
        return None
    if _repo_path(suite_name) == file:
        suite_name = ""
    identity = (file, suite_name, name)
    if case_id_attribute is not None:
        discriminator = case.get(case_id_attribute, "")
        if not discriminator.strip():
            run.error("mapping_errors", "test_ids_unmapped:parameter_case")
            return None
        identity += (discriminator,)
    return identity


def parse_junit(text: str, *, repo_files: Collection[str], exit_code: int, timed_out: bool = False,
                language: str = "typescript", case_id_attribute: str | None = None,
                expected_files: Collection[str] = ()) -> RunOutcome:
    """Read TS/JS JUnit using a caller's repository file inventory (no path access).

    ``case_id_attribute`` is opt-in: the caller must know that reporter attribute is
    stable across base/head. Default duplicate titles are unmapped, never numbered.
    Optional selected files need case identities or an explicit complete zero-test suite.
    """
    run = _Run(language, "repo-runner", exit_code, timed_out)
    if not run.bounded(text):
        return run.finish()
    root = _xml(text, run)
    if root is None:
        return run.finish()
    if root.tag not in ("testsuite", "testsuites"):
        run.error("incomplete_errors", "invalid_junit_root")
        return run.finish()
    files = {path for raw in repo_files if (path := _repo_path(raw)) is not None}
    represented: set[str] = set()
    # Postorder aggregate counts validate optional totals without counting nested cases twice.
    counts: dict[ET.Element, tuple[int, int, int, int]] = {}
    stack = [(root, [], False, "")]
    while stack:
        element, suites, visited, parent = stack.pop()
        if not visited:
            if ((element.tag == "testcase" and parent != "testsuite")
                    or (element.tag == "testsuite" and parent not in ("", "testsuite", "testsuites"))
                    or (element.tag == "testsuites" and parent)):
                run.error("incomplete_errors", "invalid_junit_structure")
                continue
            nested = suites + [element] if element.tag == "testsuite" else suites
            stack.append((element, suites, True, parent))
            stack.extend((child, nested, False, element.tag) for child in reversed(element))
            continue
        if element.tag == "testcase":
            terminal = [child.tag for child in element if child.tag in ("failure", "error", "skipped")]
            if len(terminal) > 1:
                run.error("conflict_errors", "conflicting_junit_result:" + element.get("name", ""))
            status = "fail" if "failure" in terminal else "skip" if "skipped" in terminal else "pass"
            counts[element] = (1, int("failure" in terminal), int("error" in terminal), int("skipped" in terminal))
            explicit_status = element.get("status", "")
            if explicit_status not in ("", "run"):
                run.error("incomplete_errors", "unsupported_junit_status:" + explicit_status)
                continue
            identity = _junit_identity(element, suites, files, run, case_id_attribute)
            if identity is not None:
                represented.add(identity[0])
            if "error" in terminal:
                run.error("collection_errors", "testcase_error:" + element.get("name", ""))
            elif identity is not None:
                if identity in run.results:
                    run.error("mapping_errors", "test_ids_unmapped:duplicate_case")
                run.result(identity, status, repr(identity))
        elif element.tag in ("testsuite", "testsuites"):
            totals = tuple(sum(counts.get(child, (0, 0, 0, 0))[i] for child in element) for i in range(4))
            counts[element] = totals
            for i, attribute in enumerate(("tests", "failures", "errors", "skipped")):
                value = element.get(attribute)
                if value is not None and (not value.isascii() or not value.isdecimal()
                                          or len(value) > 7 or int(value) != totals[i]):
                    run.error("incomplete_errors", "invalid_junit_counts:" + attribute)
            if any(child.tag in ("error", "failure") for child in element):
                run.error("collection_errors", "suite_error:" + element.get("name", ""))
            if expected_files and element.tag == "testsuite" and element.get("tests") == "0" and totals == (0, 0, 0, 0):
                file = _junit_file(element, suites + [element], files, run)
                if file is not None:
                    represented.add(file)
    for file in set(expected_files) - represented:
        run.error("incomplete_errors", "missing_selected_file_result:" + file)
    return run.finish()


_RUST_HEADER = re.compile(r"^\s*Running (?:unittests )?(.+) \([^\r\n]*\)\s*$")
_RUST_COUNT = re.compile(r"^running ([0-9]{1,7}) tests?$")
_RUST_TEST = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored(?:, .*)?)$")
_RUST_SUMMARY = re.compile(r"^test result: (ok|FAILED)\. ([0-9]{1,7}) passed; ([0-9]{1,7}) failed; "
                           r"([0-9]{1,7}) ignored; ([0-9]{1,7}) measured; ([0-9]{1,7}) filtered out; finished in .+$")


@dataclass
class _RustBlock:
    source: str
    target: RustTarget | None
    expected: int | None = None
    counts: list[int] = field(default_factory=lambda: [0, 0, 0])
    summarized: bool = False
    diagnostics: bool = False


def _rust_finalize(block: _RustBlock | None, run: _Run) -> None:
    if block is not None and not block.summarized:
        run.error("incomplete_errors", "missing_target_summary:" + block.source)


def parse_rust_libtest(text: str, *, targets: Mapping[str, Sequence[RustTarget]], exit_code: int,
                       timed_out: bool = False) -> RunOutcome:
    """Read Cargo's captured stable libtest text using unambiguous source-header metadata.

    ``targets`` maps the source part of ``Running <source> (<executable>)`` to
    selected target metadata, not a repository inventory. Every unique unambiguous
    target needs a terminal summary; source aliases share its stable identity.
    Zero/multiple candidates are unmapped. Custom harnesses,
    benchmarks and nocapture-style output have no supported passing contract here.
    """
    run = _Run("rust", "aegis", exit_code, timed_out)
    if not run.bounded(text):
        return run.finish()
    block = None
    completed: set[RustTarget] = set()
    for number, line in enumerate(text.splitlines(), 1):
        if number > _MAX_RECORDS:
            run.error("incomplete_errors", "too_many_records")
            break
        # Captured failure stdout can contain arbitrary result/header/error-looking text.
        # Only the real libtest summary ends its diagnostic section.
        if block is not None and block.diagnostics and not block.summarized and not _RUST_SUMMARY.fullmatch(line):
            continue
        header = _RUST_HEADER.fullmatch(line)
        if header:
            _rust_finalize(block, run)
            source = header[1]
            candidates = targets.get(source, ())
            target = candidates[0] if len(candidates) == 1 else None
            if target is not None and not all(isinstance(v, str) and v.strip()
                                              for v in (target.package, target.target_kind, target.target_name)):
                target = None
            if target is None:
                run.error("mapping_errors", "test_ids_unmapped:" + source)
            block = _RustBlock(source, target)
            continue
        count, summary, result = _RUST_COUNT.fullmatch(line), _RUST_SUMMARY.fullmatch(line), _RUST_TEST.fullmatch(line)
        if count:
            if block is None:
                run.error("incomplete_errors", "missing_target_header")
            elif block.expected is not None or block.summarized:
                run.error("conflict_errors", "duplicate_target_start:" + block.source)
            else:
                block.expected = int(count[1])
        elif summary:
            if block is None:
                run.error("incomplete_errors", "missing_target_header")
                continue
            if block.summarized:
                run.error("conflict_errors", "duplicate_target_summary:" + block.source)
            block.summarized = True
            passed, failed, ignored, measured, _filtered = map(int, summary.groups()[1:])
            if (block.expected is None or block.counts != [passed, failed, ignored]
                    or passed + failed + ignored + measured != block.expected or measured
                    or (summary[1] == "ok") != (failed == 0)):
                run.error("incomplete_errors", "invalid_target_counts:" + block.source)
            elif block.target is not None:
                completed.add(block.target)
        elif line == "failures:":
            if block is not None:
                block.diagnostics = True
        elif result and block is not None and not block.diagnostics:
            if block.expected is None or block.summarized:
                run.error("incomplete_errors", "test_outside_target_run:" + block.source)
                continue
            status = "pass" if result[2] == "ok" else "fail" if result[2] == "FAILED" else "skip"
            block.counts[("pass", "fail", "skip").index(status)] += 1
            if block.target is not None:
                target = block.target
                run.result((target.package, target.target_kind, target.target_name, result[1]), status,
                           repr((target.package, target.target_kind, target.target_name, result[1])))
        elif line.startswith("test ") and not line.startswith("test result:"):
            if block is None:
                run.error("incomplete_errors", "missing_target_header")
            elif not block.diagnostics:
                run.error("incomplete_errors", "unsupported_test_result:" + block.source)
        elif line.startswith("test result:"):
            run.error("incomplete_errors", "unsupported_target_summary")
        elif line.startswith(("error:", "error[")) and not line.startswith("error: test failed"):
            run.error("build_errors", "cargo_error:" + line)
    _rust_finalize(block, run)
    expected = {values[0] for values in targets.values() if len(values) == 1}
    for target in expected - completed:
        run.error("incomplete_errors", "missing_selected_target_result:" + repr(
            (target.package, target.target_kind, target.target_name)))
    return run.finish()
