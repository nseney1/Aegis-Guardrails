"""Whole-tree multilingual receipts through record and commit replay."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_core import checkrun, testexec
from tests import helpers_verified as hv


RUNNER = '''import pathlib,sys,xml.etree.ElementTree as ET
report,*files=sys.argv[1:]
root=ET.Element('testsuites'); failed=False
for file in files:
 text=pathlib.Path(file).read_text()
 if 'OMIT' in text: continue
 suite=ET.SubElement(root,'testsuite',name='native',file=file,tests='1')
 case=ET.SubElement(suite,'testcase',name='works')
 if 'FAIL_NATIVE' in text: ET.SubElement(case,'failure'); failed=True
 if 'SKIP_NATIVE' in text: ET.SubElement(case,'skipped')
pathlib.Path(report).write_text(ET.tostring(root,encoding='unicode'))
raise SystemExit(int(failed))
'''


@pytest.fixture
def project(tmp_path, monkeypatch):
    repo = hv.make_project(tmp_path, runner=None)
    for key, value in repo.home.env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('AEGIS_WORKSPACE', raising=False)
    repo.write('runner.py', RUNNER)
    repo.write('.gitignore', '.aegis/state/\nnode_modules/\n')
    repo.commit('feat: runner')
    (repo.root / 'node_modules').mkdir()
    spawn = subprocess.Popen

    def installed_pytest(argv, *args, **kwargs):
        if '-m' in argv and 'pytest' in argv:
            kwargs['env'] = dict(kwargs['env'], PYTHONPATH=str(Path(pytest.__file__).parents[1]),
                                 PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        return spawn(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, 'Popen', installed_pytest)
    return repo


def configure(repo, **tests):
    hv.write_user_config(repo.home.path, tests=tests)


def native_runner(repo):
    configure(repo, languages={'ts': {'command': [sys.executable, 'runner.py', '{junit}', '{files}']}})


def receipt(repo):
    outcome = checkrun.record(repo.root, tests=True, base='main')
    assert outcome.status == 'recorded', outcome.reason
    return outcome.row


def languages(row):
    return {run['language']: run for run in row['tests']['languages']}


def python_boundary(monkeypatch):
    original = testexec.run_tests
    calls = []

    def execute(argv, *args, **kwargs):
        if '-m' in argv and 'pytest' in argv:
            calls.append(tuple(argv))
            return testexec.TestsRun(exit=0, collected=1, passed=1, nodeid_digest='python-fixture')
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(testexec, 'run_tests', execute)
    return calls


def test_native_receipt_runs_unchanged_tests_and_preserves_failure(project):
    native_runner(project)
    project.write('tests/old.test.ts', 'FAIL_NATIVE\n')
    project.commit('test: existing native failure')
    project.write('tests/new.test.ts', 'PASS_NATIVE\n')
    row = receipt(project)
    native = languages(row)['ts']
    assert row['passed'] is False and row['exit'] == 1
    assert native['failed_ids'] == [['tests/old.test.ts', 'native', 'works']]
    assert native['passed_ids'] == [['tests/new.test.ts', 'native', 'works']]
    assert native['witness'] == 'repo-runner' and native['reason'] == 'failed_tests'


@pytest.mark.parametrize('suffix', ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs', 'cjs'])
def test_native_record_and_replay_share_whole_tree_recipe_and_stable_digest(project, suffix):
    native_runner(project)
    project.write('tests/first.test.' + suffix, 'PASS_NATIVE\n')
    first = receipt(project)
    second = receipt(project)
    commit = project.commit('test: passing native suite')
    replay = checkrun.rerun_commit_snapshot(project.root, commit, 'main')
    assert first['passed'] and second['passed'] and replay == {'tree': first['tree'], 'exit': 0}
    assert first['cmd_digest'] == second['cmd_digest']
    assert first['tests']['complete'] is True and languages(first)['ts']['passed'] == 1


def test_python_success_cannot_mask_native_failure(project, monkeypatch):
    calls = python_boundary(monkeypatch)
    native_runner(project)
    project.write('tests/test_app.py', 'def test_python(): assert True\n')
    project.write('tests/app.test.ts', 'FAIL_NATIVE\n')
    row = receipt(project)
    runs = languages(row)
    assert len(calls) == 1 and runs['python']['evidence'] is True
    assert runs['ts']['evidence'] is False and row['passed'] is False
    commit = project.commit('test: mixed failure')
    assert checkrun.rerun_commit_snapshot(project.root, commit, 'main')['exit'] == 1
    assert len(calls) == 2


@pytest.mark.parametrize('body,reason', [('SKIP_NATIVE', 'no_tests_passed'), ('OMIT', 'missing_selected_file_result:tests/app.test.ts')])
def test_empty_or_incomplete_native_report_is_never_a_passing_receipt(project, body, reason):
    native_runner(project)
    project.write('tests/app.test.ts', body + '\n')
    row = receipt(project)
    native = languages(row)['ts']
    assert row['passed'] is False and native['evidence'] is False
    assert reason in native['reason']
    if body == 'OMIT':
        assert native['incomplete_errors']
    else:
        assert native['skipped_ids'] == [['tests/app.test.ts', 'native', 'works']]


def test_missing_native_runner_is_visible_despite_python_success(project, monkeypatch):
    python_boundary(monkeypatch)
    project.write('tests/test_app.py', 'def test_python(): assert True\n')
    project.write('tests/app.test.ts', 'PASS_NATIVE\n')
    row = receipt(project)
    native = languages(row)['ts']
    assert row['passed'] is False and row['tests']['complete'] is False
    assert native['reason'] == 'tests_runner_not_configured' and native['build_errors']


def test_global_wrapper_runs_once_and_retains_its_logical_digest(project, tmp_path):
    counter = tmp_path / 'calls.txt'
    project.write('wrapper.py', "import pathlib,sys\np=pathlib.Path(sys.argv[2])\n"
                  "p.write_text(p.read_text()+'x' if p.exists() else 'x')\n"
                  "pathlib.Path(sys.argv[1]).write_text('<testsuite tests=\"1\"><testcase name=\"all\"/></testsuite>')\n")
    command = [sys.executable, 'wrapper.py', '{junit}', str(counter)]
    configure(project, command=command, languages={'ts': {'command': ['never-run-adapter']}})
    project.write('tests/app.test.ts', 'FAIL_NATIVE\n')
    row = receipt(project)
    commit = project.commit('test: wrapper recipe')
    replay = checkrun.rerun_commit_snapshot(project.root, commit, 'main')
    assert row['passed'] and replay['exit'] == 0 and counter.read_text() == 'xx'
    assert row['cmd_digest'] == testexec.command_digest(command)
    assert 'languages' not in row['tests']


def test_global_wrapper_last_success_line_cannot_create_complete_receipt(project):
    project.write('wrapper.py', "print('1 failed in 0.01s')\nprint('3 passed in 0.01s')\n")
    configure(project, command=[sys.executable, 'wrapper.py'])
    project.write('tests/app.test.ts', 'PASS_NATIVE\n')
    row = receipt(project)
    assert row['passed'] is False and row['tests']['complete'] is False


def test_absolute_wrapper_script_and_option_read_snapshot_bytes(project, monkeypatch):
    project.write('absolute_runner.py', "import pathlib,sys\n"
                  "report=pathlib.Path(sys.argv[1]); source=pathlib.Path(sys.argv[2].partition('=')[2])\n"
                  "bad=source.read_text()!='snapshot'\n"
                  "report.write_text('<testsuite tests=\"1\"><testcase name=\"bound\">'+"
                  "('<failure/>' if bad else '')+'</testcase></testsuite>')\nraise SystemExit(int(bad))\n")
    project.write('input.txt', 'snapshot')
    command = [sys.executable, str(project.root / 'absolute_runner.py'), '{junit}',
               '--input=' + str(project.root / 'input.txt')]
    configure(project, command=command)
    commit = project.commit('test: absolute wrapper paths')
    original, launches = testexec.run_tests, []

    def launch(argv, *args, **kwargs):
        launches.append(tuple(argv))
        project.write('input.txt', 'dirty live bytes')
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(testexec, 'run_tests', launch)
    row = receipt(project)
    assert row['passed'] is True and row['cmd_digest'] == testexec.command_digest(command)
    assert checkrun.rerun_commit_snapshot(project.root, commit, 'main')['exit'] == 0
    assert len(launches) == 2 and all(str(project.root) not in word for call in launches for word in call)


def test_go_full_tree_receipt_uses_real_default_runner(project):
    if not shutil.which('go'):
        pytest.skip('Go unavailable')
    project.write('.aegis/config.json', '{"v":1,"ast":{"packaged_drivers":["go"]}}')
    project.write('go.mod', 'module example.test/receipt\n\ngo 1.21\n')
    project.write('app_test.go', 'package receipt\nimport "testing"\nfunc TestWorks(t *testing.T) {}\n')
    row = receipt(project)
    native = languages(row)['go']
    assert row['passed'] and native['passed_ids'] == [['example.test/receipt', 'TestWorks']]
    assert native['witness'] == 'aegis' and native['complete'] is True


@pytest.mark.parametrize('extra', [
    'func Example() { println("wrong")\n // Output: expected\n}\n',
    'func FuzzWorks(f *testing.F) { f.Add("seed"); f.Fuzz(func(t *testing.T, s string) { t.Fatal("fails") }) }\n',
])
def test_go_receipt_does_not_filter_failing_examples_or_fuzz_seeds(project, extra):
    if not shutil.which('go'):
        pytest.skip('Go unavailable')
    project.write('.aegis/config.json', '{"v":1,"ast":{"packaged_drivers":["go"]}}')
    project.write('go.mod', 'module example.test/receipt\n\ngo 1.21\n')
    project.write('app_test.go', 'package receipt\nimport "testing"\nfunc TestWorks(t *testing.T) {}\n' + extra)
    row = receipt(project)
    native = languages(row)['go']
    assert row['passed'] is False and native['passed_ids'] == [['example.test/receipt', 'TestWorks']]
    assert native['failed_ids'] and native['reason'] == 'failed_tests'


def test_rust_inline_tests_remain_explicitly_unverifiable(project, tmp_path, monkeypatch):
    tools = tmp_path / 'tools'
    tools.mkdir()
    for name in ('cargo', 'rustup'):
        tool = tools / (name + ('.exe' if os.name == 'nt' else ''))
        tool.write_bytes(b'external metadata tool boundary fixture')
        tool.chmod(0o755)
    monkeypatch.setenv('PATH', str(tools) + os.pathsep + os.environ.get('PATH', ''))
    original = testexec.run_tests

    def metadata(argv, cwd, env, timeout, junit, output, *, stderr_output=None):
        if 'toolchain' in argv:
            Path(output).write_text('stable-fixture (default)\n')
        elif 'metadata' in argv:
            Path(output).write_text(json.dumps({'workspace_members': ['fixture'], 'packages': [{
                'id': 'fixture', 'name': 'receipt', 'manifest_path': str(cwd / 'Cargo.toml'),
                'targets': [{'kind': ['lib'], 'name': 'receipt', 'src_path': str(cwd / 'src/lib.rs')}]}]}))
        else:
            return original(argv, cwd, env, timeout, junit, output, stderr_output=stderr_output)
        if stderr_output is not None:
            Path(stderr_output).write_text('')
        return testexec.TestsRun(exit=0)

    monkeypatch.setattr(testexec, 'run_tests', metadata)
    project.write('Cargo.toml', '[package]\nname="receipt"\nversion="0.1.0"\nedition="2021"\n')
    project.write('Cargo.lock', 'version = 3\n[[package]]\nname = "receipt"\nversion = "0.1.0"\n')
    project.write('src/lib.rs', '#[test]\nfn inline_test() {}\n')
    row = receipt(project)
    native = languages(row)['rust']
    assert row['passed'] is False and native['reason'] == 'tests_inline_with_source'


@pytest.mark.parametrize('config,text', [
    ('pytest.ini', '[pytest]\npython_files = check_*.py\n'),
    ('pyproject.toml', '[tool.pytest.ini_options]\npython_files = ["check_*.py"]\n'),
])
def test_configured_python_discovery_cannot_be_omitted_from_native_receipt(project, config, text):
    native_runner(project)
    project.write(config, text)
    project.write('checks/check_failure.py', 'def test_failure(): assert False, "must run Python"\n')
    project.write('tests/app.test.ts', 'PASS_NATIVE\n')
    row = receipt(project)
    assert row['passed'] is False and row['exit'] == 1
    assert languages(row)['python']['failed'] == 1
    assert languages(row)['ts']['evidence'] is True


def test_python_helper_only_needs_complete_empty_discovery_not_passing_evidence(project, monkeypatch):
    native_runner(project)
    project.write('pytest.ini', '[pytest]\n')
    project.write('tests/app.test.ts', 'PASS_NATIVE\n')
    original, runs = testexec.run_tests, []

    def execute(argv, *args, **kwargs):
        run = original(argv, *args, **kwargs)
        if '-m' in argv and 'pytest' in argv:
            runs.append(run)
        return run

    monkeypatch.setattr(testexec, 'run_tests', execute)
    row = receipt(project)
    assert len(runs) == 1 and runs[0].exit == 5 and runs[0].complete and not runs[0].evidence
    assert row['passed'] is True and set(languages(row)) == {'ts'}


def test_native_only_receipt_needs_no_pytest_without_python_configuration(project, tmp_path, monkeypatch):
    for file in ('src/app.py', 'runner.py'):
        (project.root / file).unlink()
    runner = tmp_path / 'native_runner.py'
    runner.write_text(RUNNER)
    configure(project, languages={'ts': {'command': [sys.executable, str(runner), '{junit}', '{files}']}})
    project.write('pyproject.toml', '[project]\nname = "native-only"\n')
    project.write('tests/app.test.ts', 'PASS_NATIVE\n')
    original = testexec.run_tests

    def no_pytest(argv, *args, **kwargs):
        assert not ('-m' in argv and 'pytest' in argv), 'pure native receipt requires no pytest'
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(testexec, 'run_tests', no_pytest)
    row = receipt(project)
    assert row['passed'] is True and set(languages(row)) == {'ts'}


def test_incomplete_empty_python_report_cannot_certify_native_receipt(project):
    native_runner(project)
    project.write('conftest.py', 'from pathlib import Path\nimport xml.etree.ElementTree as ET\n'
                  'def pytest_unconfigure(config):\n'
                  '    path = Path(config.option.xmlpath)\n'
                  '    tree = ET.parse(path)\n'
                  '    tree.getroot().set("tests", "999")\n'
                  '    tree.write(path)\n')
    project.write('tests/app.test.ts', 'PASS_NATIVE\n')
    row = receipt(project)
    python = languages(row)['python']
    assert row['passed'] is False and python['exit'] == 5 and python['collected'] == 0
    assert python['complete'] is False and python['evidence'] is False
    assert languages(row)['ts']['evidence'] is True
