"""Native diff coverage through public Git and process boundaries."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_core.verification.coverage_check import run_diff_coverage
from tests import helpers_humangate as hg
from tests.conftest import symlink_or_skip

_GIT_DIR = str(Path(shutil.which("git")).parent)


@pytest.fixture
def project(tmp_path, monkeypatch):
    home, root, tools = [tmp_path / name for name in ("home", "project", "tools")]
    home.mkdir(); tools.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + _GIT_DIR)
    monkeypatch.setenv("GOCACHE", str(tools / "go-cache"))
    monkeypatch.setenv("GOMODCACHE", str(tools / "go-modules"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    repo = hg.Repo(root, hg.Home(home))
    repo.write("go.mod", "module example.test/project\n\ngo 1.21\n")
    for name in ("pkg/main.go", "src/app.ts", "src/lib.rs"):
        repo.write(name, "old\n")
    repo.commit("base"); repo.branch("work")
    scenario = tools / "scenario.json"
    scenario.write_text('{}')
    script = tools / "runtime.py"
    script.write_text(
        "import json, os, pathlib, sys, time\n"
        f"state=json.loads(pathlib.Path({str(scenario)!r}).read_text()); args=sys.argv[2:]\n"
        "if sys.argv[1]=='rustup': print('stable-fixture (default)'); raise SystemExit(0)\n"
        "out=next((a.split('=',1)[1] for a in args if a.startswith(('-coverprofile=', '--out='))), None)\n"
        "if state.get('report') is not None: pathlib.Path(out).write_text(state['report'], encoding='utf-8')\n"
        "print(state.get('message',''))\n"
        "raise SystemExit(state.get('exit',0))\n", encoding="utf-8")
    runtimes = {}
    for name in ("go", "node", "cargo", "rustup"):
        binary = tools / (name + '.exe' if os.name == 'nt' else name)
        binary.write_bytes(b'process boundary fixture'); binary.chmod(0o700)
        runtimes[str(binary)] = name
    calls, real = [], subprocess.Popen

    def spawn(argv, **options):
        words = [str(word) for word in argv]
        if words[0] in runtimes:
            calls.append((words, options))
            state = json.loads(scenario.read_text())
            if state.get('link'):
                output = next(word.split('=', 1)[1] for word in words if word.startswith(('-coverprofile=', '--out=')))
                symlink_or_skip(Path(state['link']), Path(output))
            words = [sys.executable, str(script), runtimes[words[0]], *words[1:]]
            proc = real(words, **options)
            if state.get('timeout'):
                wait, first = proc.wait, [True]

                def expired(timeout=None):
                    if first[0]:
                        first[0] = False
                        raise subprocess.TimeoutExpired(words, timeout)
                    return wait(timeout=timeout)

                proc.wait = expired
            return proc
        return real(words, **options)

    monkeypatch.setattr(subprocess, 'Popen', spawn)
    return repo, home, scenario, calls


def changed(project, *files):
    repo = project[0]
    for name in files:
        repo.write(name, 'old\nadded\nmissed\n')
    repo.commit('feat: changed source')


def configure(project, language):
    config = project[1] / '.aegis'
    config.mkdir(exist_ok=True)
    (config / 'config.json').write_text(json.dumps({'v': 1, 'coverage': {'languages': {
        language: {'command': ['node' if language == 'ts' else 'cargo', 'coverage', '--out={out}']}}}}))


def test_go_default_reports_changed_lines_and_module_qualified_identity(project):
    changed(project, 'pkg/main.go')
    project[2].write_text(json.dumps({'report': 'mode: count\nexample.test/project/pkg/main.go:1.1,2.2 2 1\nexample.test/project/pkg/main.go:3.1,3.2 1 0\n'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['covered_lines'], result['executable_lines'], result['ratio']) == ('reported', 1, 2, 0.5)
    assert result['uncovered_ranges'] == {'pkg/main.go': [[3, 3]]}
    command, options = project[3][0]
    assert command[1] == 'test' and command[-1] == './...'
    assert {key: options['env'][key] for key in ('GOTOOLCHAIN', 'GOFLAGS', 'GOPROXY', 'GOWORK', 'GOENV')} == {
        'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly', 'GOPROXY': 'off', 'GOWORK': 'off', 'GOENV': 'off'}


@pytest.mark.parametrize('language,file', [('ts', 'src/app.ts'), ('rust', 'src/lib.rs')])
def test_unconfigured_native_coverage_is_explicit_and_runs_nothing(project, language, file):
    changed(project, file)
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'coverage_not_configured', None)
    assert result['languages'][language]['reason'] == 'coverage_not_configured'
    assert project[3] == []


@pytest.mark.parametrize('language,file', [('ts', 'src/app.ts'), ('rust', 'src/lib.rs')])
def test_user_native_lcov_command_reports_counts_with_runtime_policy(project, language, file):
    changed(project, file); configure(project, language)
    project[2].write_text(json.dumps({'report': 'SF:' + file + '\nDA:2,1\nDA:3,0\nend_of_record\n'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['covered_lines'], result['executable_lines'], result['ratio']) == (1, 2, 0.5)
    assert result['languages'][language]['status'] == 'reported'
    if language == 'rust':
        assert len(project[3]) == 2
        env = project[3][-1][1]['env']
        assert env['RUSTUP_TOOLCHAIN'] == 'stable-fixture' and env['RUSTUP_AUTO_INSTALL'] == '0'
        assert env['CARGO_NET_OFFLINE'] == 'true'
    else:
        assert len(project[3]) == 1


def test_mixed_native_partial_coverage_discloses_unconfigured_files(project):
    changed(project, 'pkg/main.go', 'src/app.ts')
    project[2].write_text(json.dumps({'report': 'mode: count\nexample.test/project/pkg/main.go:2.1,3.2 2 1\n'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert result['status'] == 'reported' and result['ratio'] == 1.0
    assert result['reason'] == 'partial_coverage'
    assert result['unmeasured'] == ['src/app.ts']
    assert result['languages']['ts']['reason'] == 'coverage_not_configured'


@pytest.mark.parametrize('report,reason', [
    (None, 'report_missing'), ('truncated', 'coverage_report_invalid'),
    ('SF:../outside.ts\nDA:2,1\nend_of_record\n', 'coverage_paths_unmapped'),
])
def test_missing_malformed_or_outside_reports_are_unverified(project, report, reason):
    changed(project, 'src/app.ts'); configure(project, 'ts')
    project[2].write_text(json.dumps({'report': report}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', reason, None)


def test_native_dependency_failure_is_not_coverage_zero(project):
    changed(project, 'pkg/main.go')
    project[2].write_text(json.dumps({'exit': 1, 'message': 'module lookup disabled by GOPROXY=off'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'deps_unavailable', None)



def test_absolute_in_workspace_lcov_paths_map_to_repository_files(project):
    changed(project, 'src/app.ts'); configure(project, 'ts')
    source = project[0].root / 'src/app.ts'
    project[2].write_text(json.dumps({'report': 'SF:' + str(source) + '\nDA:2,1\nDA:3,0\nend_of_record\n'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert result['uncovered_ranges'] == {'src/app.ts': [[3, 3]]}
    assert result['ratio'] == 0.5


def test_module_prefixed_go_path_that_has_two_local_interpretations_is_unverified(project):
    project[0].write('example.test/project/pkg/main.go', 'ambiguous\n')
    changed(project, 'pkg/main.go')
    project[2].write_text(json.dumps({'report': 'mode: count\nexample.test/project/pkg/main.go:2.1,3.2 2 1\n'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'coverage_paths_unmapped', None)


def test_repository_coverage_command_is_never_executed(project):
    project[0].write('.aegis/config.json', json.dumps({'v': 1, 'coverage': {'languages': {
        'ts': {'command': ['node', 'attack', '--out={out}']}}}}))
    changed(project, 'src/app.ts')
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert result['reason'] == 'coverage_not_configured' and project[3] == []


def test_linked_report_is_unverified_without_reading_the_target(project, tmp_path):
    changed(project, 'src/app.ts'); configure(project, 'ts')
    outside = tmp_path / 'outside.lcov'
    outside.write_text('SF:src/app.ts\nDA:2,1\nend_of_record\n')
    project[2].write_text(json.dumps({'link': str(outside)}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'report_unsafe', None)
    assert outside.read_text().startswith('SF:src/app.ts')


def test_report_mapping_never_follows_a_source_symlink(project, tmp_path):
    outside = tmp_path / 'outside.ts'
    outside.write_text('outside\n')
    symlink_or_skip(outside, project[0].root / 'src/linked.ts')
    changed(project, 'src/app.ts'); configure(project, 'ts')
    project[2].write_text(json.dumps({'report': 'SF:src/linked.ts\nDA:2,1\nend_of_record\n'}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'coverage_paths_unmapped', None)


def test_native_timeout_is_unverified_and_does_not_publish_a_ratio(project):
    changed(project, 'pkg/main.go')
    project[2].write_text(json.dumps({'timeout': True}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'timeout', None)


def test_native_report_above_bound_is_unverified(project):
    changed(project, 'src/app.ts'); configure(project, 'ts')
    project[2].write_text(json.dumps({'report': 'x' * (8 * 1024 * 1024 + 1)}))
    result = run_diff_coverage(project[0].root, 'main', 'HEAD')
    assert (result['status'], result['reason'], result['ratio']) == ('unverified', 'output_too_large', None)
