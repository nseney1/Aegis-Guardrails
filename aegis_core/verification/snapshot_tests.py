"""One whole-tree test recipe shared by recorded checks and commit replay.

A global user command takes precedence and runs once. Automatic language runs
retain independent evidence: one passing suite cannot certify another language.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from aegis_core import testexec
from aegis_core.lane_ast import pytest_settings
from aegis_core.testplans import rebase_snapshot_arguments

_ERRORS = ('build_errors', 'collection_errors', 'incomplete_errors', 'conflict_errors', 'mapping_errors')
_NATIVE = frozenset(('.go', '.rs', '.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'))
_PYTEST_CONFIG = frozenset(('pytest.ini', '.pytest.ini', 'pytest.toml', '.pytest.toml',
                           'pyproject.toml', 'tox.ini', 'setup.cfg'))


@dataclass(frozen=True)
class SnapshotTests(testexec.TestsRun):
    """Compatible aggregate counts with the complete per-language results attached."""
    languages: tuple[dict[str, Any], ...] = ()

    @property
    def evidence(self) -> bool:
        return super().evidence and bool(self.languages) and all(row['evidence'] for row in self.languages)

    def as_dict(self) -> dict[str, Any]:
        return {**super().as_dict(), 'languages': list(self.languages)}


def _python(workspace, snapshot, scratch, command, timeout):
    scratch.mkdir()
    junit, home, tmp = scratch / 'junit.xml', scratch / 'home', scratch / 'tmp'
    home.mkdir(mode=0o700)
    tmp.mkdir(mode=0o700)
    argv, logical = testexec.plan_command(command, junit)
    argv = rebase_snapshot_arguments(argv, workspace, snapshot)
    run = (testexec.run_tests(argv, snapshot, testexec.hermetic_env(home, tmp), timeout, junit,
                              scratch / 'output.txt') if timeout > 0 else
           testexec.TestsRun(exit=124, timed_out=True, complete=False))
    return run, logical


def _inventory(snapshot):
    groups, python = {}, False
    for path in sorted(snapshot.rglob('*')):
        if path.is_symlink():
            raise ValueError('snapshot test inventory refuses symbolic links')
        if not path.is_file():
            continue
        file = path.relative_to(snapshot).as_posix()
        python |= path.suffix == '.py' or (path.name in _PYTEST_CONFIG and
                                          pytest_settings(path.name, path.read_bytes()) is not None)
        if path.suffix in _NATIVE:
            from aegis_core.verification.regression_identity import test_language

            language = test_language(file)
            if language is not None:
                groups.setdefault(language, []).append(file)
    return groups, python


def _native_row(selection, outcome):
    errors = {field: sorted(getattr(outcome, field)) for field in _ERRORS}
    passed, failed, skipped = (getattr(outcome, field) for field in ('passed_ids', 'failed_ids', 'skipped_ids'))
    reasons = [reason for field in _ERRORS for reason in errors[field]]
    reason = (selection.plan.reason or ('timeout' if outcome.timed_out else '') or
              (reasons[0] if reasons else 'failed_tests' if failed else 'ok' if outcome.evidence else 'no_tests_passed'))
    return {'language': outcome.language, 'witness': outcome.witness, 'exit': outcome.exit_code,
            'exit_code': outcome.exit_code, 'timed_out': outcome.timed_out,
            'collected': len(passed | failed | skipped), 'passed': len(passed), 'failed': len(failed),
            'skipped': len(skipped), 'deselected': 0, 'complete': not reasons and not outcome.timed_out,
            'evidence': outcome.evidence, 'reason': reason, 'detail': selection.plan.detail,
            'files': list(selection.plan.files), **errors,
            **{field: [list(identity) for identity in sorted(getattr(outcome, field))]
               for field in ('passed_ids', 'failed_ids', 'skipped_ids')}}


def _recipe(workspace, selection):
    from aegis_core.testplans import language_settings

    plan = selection.plan
    try:
        settings = language_settings(workspace, plan.language)
        command = list(settings.command) if settings.command is not None else 'default'
        timeout = settings.timeout_s
    except ValueError as error:
        command, timeout = {'invalid_settings': str(error)}, None
    return {'language': plan.language, 'command': command, 'timeout_s': timeout, 'files': list(plan.files),
            'mode': 'all-selected-packages' if plan.language == 'go' and command == 'default' else 'selected-files',
            'go_tests': [(item.file, item.package, item.name) for item in plan.go_tests],
            'rust_targets': sorted({(target.package, target.target_kind, target.target_name)
                                    for _, targets in plan.rust_targets for target in targets}),
            'owners': selection.owners}


def _aggregate(rows, duration, pytest_missing):
    identities = [{key: row[key] for key in ('language', 'nodeid_digest', 'passed_ids', 'failed_ids', 'skipped_ids')
                   if key in row} for row in rows]
    digest = hashlib.sha256(json.dumps(identities, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    exit_code = next((row['exit'] for row in rows if row['exit']), 0)
    if not all(row['evidence'] for row in rows) and not exit_code:
        exit_code = 1
    counts = {key: sum(row[key] for row in rows) for key in ('collected', 'passed', 'failed', 'skipped', 'deselected')}
    return SnapshotTests(exit=exit_code, timed_out=any(row['timed_out'] for row in rows), **counts,
                         nodeid_digest=digest, duration_s=duration, pytest_missing=pytest_missing,
                         complete=all(row['complete'] for row in rows), languages=tuple(rows))


def run_snapshot_tests(workspace: Path, snapshot: Path, scratch: Path, *, timeout: float | None = None):
    """Run a global wrapper or all supported test languages under one aggregate deadline.

    Returned logical commands identify the same recipe across scratch roots and
    resolved runtime paths; record and trailer replay both use this entry point.
    """
    started = time.monotonic()
    limit = testexec.DEFAULT_TIMEOUT_S if timeout is None else timeout
    deadline = started + limit
    command = testexec.user_test_command(workspace)
    if command is not None:
        return _python(workspace, snapshot, scratch / 'wrapper', command, limit)
    groups, python = _inventory(snapshot)
    if not groups:
        return _python(workspace, snapshot, scratch / 'python', None, limit)
    rows, recipes, pytest_missing = [], [], False
    if python:
        run, logical = _python(workspace, snapshot, scratch / 'python', None, deadline - time.monotonic())
        # Only actual complete discovery can establish that Python has no suite.
        # An empty run supplies no passing evidence; missing pytest or a bad report still fails.
        empty = (run.exit == 5 and run.complete and not run.timed_out and
                 not any((run.collected, run.passed, run.failed, run.skipped, run.deselected)))
        if not empty:
            rows.append({'language': 'python', 'witness': 'aegis', **run.as_dict(), 'evidence': run.evidence,
                         'reason': 'ok' if run.evidence else 'incomplete_report' if not run.complete else 'failed_tests'})
        recipes.append({'language': 'python', 'command': logical})
        pytest_missing = run.pytest_missing
    from aegis_core.verification.language_tests import run_language_snapshot
    from aegis_core.verification.regression_identity import prepare_native_selection

    for language, files in sorted(groups.items()):
        selection = prepare_native_selection(workspace, snapshot, language, files,
                                             scratch=scratch / (language + '-selection'), deadline=deadline)
        if language == 'go' and selection.plan.available and _recipe(workspace, selection)['command'] == 'default':
            command = list(selection.plan.command)
            index = command.index('-run')
            del command[index:index + 2]
            selection = replace(selection, plan=replace(selection.plan, command=tuple(command)))
        outcome = run_language_snapshot(selection.plan, snapshot, workspace, scratch / (language + '-run'),
                                        deadline=deadline)
        rows.append(_native_row(selection, outcome))
        recipes.append(_recipe(workspace, selection))
    logical = ['aegis-snapshot-tests-v1', json.dumps(recipes, sort_keys=True, separators=(',', ':'))]
    return _aggregate(rows, time.monotonic() - started, pytest_missing), logical
