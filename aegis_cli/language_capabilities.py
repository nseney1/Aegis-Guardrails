"""Read-only language capabilities and suggestions shared by init and doctor."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from aegis_core.ast.detect import LANGUAGE_DEFINITIONS, detect_project_languages
from aegis_core.config import read_user_config

__all__ = ['capability_data', 'capability_lines', 'render_capabilities',
           'runner_suggestion', 'render_runner_suggestion', 'needs_go_setup']

_PACKAGE_LIMIT = 1 << 20
_JEST_BOOTSTRAP = (
    "process.env.JEST_JUNIT_OUTPUT_FILE=process.argv[1];"
    "process.env.JEST_JUNIT_ADD_FILE_ATTRIBUTE='true';"
    "process.env.JEST_JUNIT_REPORT_TEST_SUITE_ERRORS='true';"
    "process.argv.splice(1,1);require(process.argv[1]);"
)


def _configured(value):
    return (isinstance(value, str) and bool(value.strip()) and '\0' not in value or
            isinstance(value, list) and bool(value) and
            all(isinstance(word, str) and word and '\0' not in word for word in value))


def _command_label(user, section, language, default):
    settings = user.get(section, {})
    if not isinstance(settings, dict):
        return 'invalid configuration'
    if section == 'tests' and 'command' in settings:
        return 'user command (all languages)' if _configured(settings['command']) else 'invalid configuration'
    if language == 'python':
        return default
    languages = settings.get('languages', {})
    key = 'ts' if language in ('javascript', 'typescript') else language
    if not isinstance(languages, dict) or not isinstance(languages.get(key, {}), dict):
        return 'invalid configuration'
    config = languages.get(key, {})
    if 'command' not in config:
        return default
    return 'user command' if _configured(config['command']) else 'invalid configuration'


def _parser_label(root, language):
    from aegis_core.ast.runner import ASTDriverRegistry

    if language == 'python':
        return 'in-process'
    labels = set()
    registry = ASTDriverRegistry()
    for ext in LANGUAGE_DEFINITIONS[language]['extensions']:
        try:
            plan = registry.plan_driver(ext, workspace_root=root)
        except Exception:  # Doctor retains the planner's detailed failure and failing status.
            labels.add('unavailable')
            continue
        labels.add('not configured' if plan is None else
                   'unavailable' if plan.unavailable else
                   'in-process' if plan.in_process_js or plan.in_process_rust else
                   'packaged Go (go >=1.21)' if plan.packaged_go else 'user driver')
    return next(iter(labels)) if len(labels) == 1 else 'mixed drivers (see extension details)'


def capability_data(root: Path, languages=None):
    """Bounded labels from known languages and user settings; never execute commands."""
    from aegis_core.verification.security_pack import SECURITY_RULES_BY_LANGUAGE

    languages = detect_project_languages(root) if languages is None else languages
    user = read_user_config(root) or {}
    capabilities = []
    for language in sorted(LANGUAGE_DEFINITIONS):
        if language not in languages:
            continue
        tests = {'python': 'pytest', 'go': 'go test (default)', 'rust': 'cargo test (default)'}.get(language, 'not configured')
        coverage = {'python': 'coverage.py', 'go': 'coverprofile (default)'}.get(language, 'not configured')
        if language == 'python':
            from aegis_core.testexec import pytest_args, user_test_command

            command = user_test_command(root)
            if command and pytest_args(command) is None:
                coverage = 'unavailable (tests.command is not pytest-based)'
        capabilities.append({
            'language': language, 'parser': _parser_label(root, language),
            'security_rules': len(SECURITY_RULES_BY_LANGUAGE[language]),
            'tests': _command_label(user, 'tests', language, tests),
            'coverage': _command_label(user, 'coverage', language, coverage),
        })
    return capabilities


def render_capabilities(capabilities):
    """Render the same capability records retained by init JSON."""
    return [f"  {item['language']}: parser {item['parser']}; pack {item['security_rules']}; "
            f"tests {item['tests']}; coverage {item['coverage']}" for item in capabilities]


def capability_lines(root: Path, languages=None):
    """Describe installed packs and user-scope settings without executing commands."""
    return render_capabilities(capability_data(root, languages))


def _package(root):
    path = root / 'package.json'
    if not path.exists():
        return None, None
    try:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            return None, 'package.json is not a regular, unlinked file'
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None, 'package.json is not a regular file'
            raw = handle.read(_PACKAGE_LIMIT + 1)
        if len(raw) > _PACKAGE_LIMIT:
            return None, 'package.json exceeds 1 MiB'
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None, 'package.json must be an object'
        return data, None
    except (OSError, ValueError, UnicodeError):
        return None, 'package.json cannot be read as JSON'


def _runner_result(status='none', runner=None, configuration=None, messages=()):
    return {'status': status, 'runner': runner, 'configuration': configuration, 'messages': list(messages)}


def _runner_configuration(root, runner):
    from aegis_cli import sanitize_display
    from aegis_core.redaction import redact_command_secrets

    # Refuse a changed/oversized display path rather than suggesting a different executable.
    if len(str(root)) > 4096:
        return None
    if runner == 'vitest':
        command = ['node', str(root / 'node_modules/vitest/vitest.mjs'), 'run', '--reporter=junit',
                   '--outputFile={junit}', '{files}']
    else:
        command = ['node', '-e', _JEST_BOOTSTRAP, '{junit}', str(root / 'node_modules/jest/bin/jest.js'),
                   '--runInBand', '--reporters=default', '--reporters=' + str(root / 'node_modules/jest-junit'),
                   '--runTestsByPath', '{files}']
    displayed = [redact_command_secrets(sanitize_display(word, max_len=None))[:4096] for word in command]
    if displayed != command:
        return None
    return {'tests': {'languages': {'ts': {'command': displayed}}}}


def render_runner_suggestion(data):
    """Render inert guidance without executing or persisting its configuration."""
    lines = list(data['messages'])
    if data['configuration'] is not None:
        lines.insert(1, '  ' + json.dumps(data['configuration'], ensure_ascii=True))
    return lines


def runner_suggestion(root: Path, *, structured=False):
    """Fixed argv templates selected by declared package names, never package scripts or bins."""
    def result(*args, **kwargs):
        data = _runner_result(*args, **kwargs)
        return data if structured else render_runner_suggestion(data)

    package, problem = _package(root)
    if problem:
        return result('unavailable', messages=['  Runner suggestion unavailable: ' + problem])
    if package is None:
        return result()
    dependencies = set()
    for field in ('dependencies', 'devDependencies'):
        table = package.get(field, {})
        if isinstance(table, dict):
            dependencies.update(name for name in ('vitest', 'jest', 'jest-junit')
                                if isinstance(table.get(name), str) and table[name])
    if 'vitest' in dependencies:
        runner = 'vitest'
    elif 'jest' in dependencies:
        if 'jest-junit' not in dependencies:
            return result('needs_reporter', runner='jest', messages=[
                '  Jest needs jest-junit for JUnit evidence; configure a user-authorized runner after adding that reporter.'])
        runner = 'jest'
    else:
        return result()
    snippet = _runner_configuration(root, runner)
    if snippet is None:
        return result('unavailable', messages=[
            '  Runner suggestion unavailable: workspace path cannot be safely displayed'])
    return result('suggested', runner, snippet, [
        '  Suggested user configuration (review before adding to ~/.aegis/config.json; nothing is written):',
        '  The runner and its dependencies must already be installed; this runs repository code only when tests are requested.'])


def needs_go_setup(root: Path):
    """Include Go when already opted in, or when init is about to provision detected Go."""
    from aegis_core.config import RepoConfig

    return 'go' in RepoConfig.load(root).packaged_drivers or 'go' in detect_project_languages(root)
