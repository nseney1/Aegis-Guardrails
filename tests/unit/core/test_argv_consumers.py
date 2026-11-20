"""Operator command strings share a grammar while consumers retain their policies."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import textwrap
from types import SimpleNamespace

import pytest

from aegis_core import inference_provider, testexec, testplans
from aegis_core.ast import runner
from aegis_core.verification import perf_check
from tests import helpers_humangate as hg
from tests import helpers_verified as hv


CONSUMERS = ("model", "tests", "language", "coverage", "perf", "driver")


CI_ENVIRONMENT_NAMES = (
    "GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_BASE_REF",
    "GITHUB_STEP_SUMMARY", "GITHUB_REF_NAME",
    "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
    "GH_HOST", "GH_REPO", "GITHUB_SHA", "GITHUB_REF_TYPE", "GITHUB_OUTPUT",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX",
    "GIT_SHALLOW_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE",
    "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_123456", "GIT_CONFIG_VALUE_123456",
)


def test_ambient_ci_environment_is_isolated(tmp_path):
    """Plant launcher inputs before collection, independently of the host's environment."""
    _run_ci_environment_probe(tmp_path, workers=0)


def test_explicit_ci_environment_is_restored_after_failure(tmp_path, monkeypatch):
    _run_ci_environment_probe(tmp_path, workers=0)
    name = "GITHUB_REF"
    for _ in range(2):
        with pytest.raises(RuntimeError, match="^test-owned failure$"):
            with monkeypatch.context() as scoped:
                scoped.setenv(name, "test-owned value")
                assert os.environ[name] == "test-owned value"
                raise RuntimeError("test-owned failure")
        present = name in os.environ
        assert not present, name


@pytest.fixture(params=("posix", "nt"), ids=("POSIX", "Windows"))
def platform(request, monkeypatch):
    # Replace module references, never os.name: pathlib/pytest must keep the host OS.
    modules = [inference_provider, testexec, testplans, perf_check, runner]
    shared = sys.modules.get("aegis_core.argv")
    if shared is not None:
        modules.append(shared)
    for module in modules:
        monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "name": request.param}))
    return request.param


@pytest.fixture
def commands(tmp_path, monkeypatch):
    home, root = tmp_path / "home", tmp_path / "project"
    config = home / ".aegis" / "config.json"
    config.parent.mkdir(parents=True)
    root.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    program = tmp_path / "Program Files" / "runner.exe"
    program.parent.mkdir()
    program.write_text("not executed", encoding="utf-8")

    # Git export is an external-process boundary, unrelated to command decoding.
    # No source-checkout history or git executable is needed for these tests.
    monkeypatch.setattr(perf_check, "gitsafe", SimpleNamespace(
        merge_base=lambda *args: "0" * 40,
        export_tree=lambda *args: None,
        GitError=perf_check.gitsafe.GitError,
    ))
    calls = []

    def bench(argv, cwd, timeout):
        calls.append(list(argv))
        return {"returncode": 0, "duration_s": 0.01}

    def read(consumer, command):
        config.write_text(json.dumps({
            "v": 1,
            "tests": {"command": command, "languages": {"go": {"command": command}}},
            "coverage": {"languages": {"go": {"command": command}}},
            "perf": {"command": command},
        }), encoding="utf-8")
        if consumer == "model":
            return inference_provider.resolve_backend(command, environ={})
        if consumer == "tests":
            return testexec.user_test_command(root)
        if consumer in ("language", "coverage"):
            return testplans.language_settings(root, "go", coverage=consumer == "coverage")
        if consumer == "perf":
            return perf_check.run_perf_check(root, runner=bench, user_config_path=config)
        return runner.ASTDriverRegistry({".rf17": command}).plan_driver(".rf17")

    return read, program, root, calls


def decoded(consumer, result):
    if consumer == "model":
        return result.argv
    if consumer in ("language", "coverage"):
        return list(result.command)
    if consumer == "perf":
        assert result["status"] == "pass"
        return result["command"]
    if consumer == "driver":
        assert result.unavailable is None
        return list(result.argv)
    return result


def quoted_program(program, platform):
    return f'"{program}"' if platform == "nt" else shlex.quote(str(program))


@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("suffix, expected", [
    ('--label="a b"', ["--label=a b"]),
    ('pre"fix mid"post', ["prefix midpost"]),
    ("'two words' next", ["two words", "next"]),
    (r'--title="say \"hi\""', ['--title=say "hi"']),
])
def test_command_strings_preserve_argument_boundaries(commands, platform, consumer, suffix, expected):
    read, program, _root, _calls = commands
    command = quoted_program(program, platform) + " " + suffix
    assert decoded(consumer, read(consumer, command)) == [str(program), *expected]


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_backslashes_follow_the_platform_grammar(commands, platform, consumer):
    read, program, _root, _calls = commands
    if platform == "nt":
        suffix, expected = r'"C:\dir with space\\" C:\tools\ x', ["C:\\dir with space\\", "C:\\tools\\", "x"]
    else:
        suffix, expected = r'path\ with\ spaces back\\slash', ["path with spaces", "back\\slash"]
    command = quoted_program(program, platform) + " " + suffix
    assert decoded(consumer, read(consumer, command)) == [str(program), *expected]


@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("suffix", ['"unterminated', '--label="a b', "'unterminated"])
def test_malformed_quotes_keep_each_consumers_refusal(commands, platform, consumer, suffix):
    read, program, _root, calls = commands
    command = quoted_program(program, platform) + " " + suffix
    if consumer == "model":
        with pytest.raises(inference_provider.LLMCommandError) as caught:
            read(consumer, command)
        assert str(caught.value) == f"cannot parse --llm-cmd / AEGIS_LLM_CMD {command!r}: No closing quotation"
    elif consumer in ("language", "coverage"):
        with pytest.raises(ValueError) as caught:
            read(consumer, command)
        section = "coverage" if consumer == "coverage" else "tests"
        assert str(caught.value) == f"invalid {section}.languages.go.command"
    elif consumer == "perf":
        result = read(consumer, command)
        assert (result["status"], result["reason"], result["passed"]) == (
            "unverified", "perf.command cannot be parsed", True)
        assert calls == []
    elif consumer == "driver":
        plan = read(consumer, command)
        assert plan.argv == ()
        assert plan.unavailable == "the driver command cannot be parsed: No closing quotation"
    else:
        with pytest.raises(ValueError, match=r"^invalid tests\.command$"):
            read(consumer, command)


def test_unset_global_command_remains_unset(commands, platform):
    _read, _program, root, _calls = commands
    hv.write_user_config(root.parent / "home")
    assert testexec.user_test_command(root) is None


def test_malformed_global_command_is_unavailable_in_capabilities(commands, platform):
    from aegis_cli.language_capabilities import capability_data, capability_lines

    _read, _program, root, _calls = commands
    hv.write_user_config(root.parent / "home", tests={"command": 'pytest "private-unclosed'})
    row, = capability_data(root, languages={"python"})
    assert row["coverage"] == "unavailable (invalid tests.command)"
    text = "\n".join(capability_lines(root, languages={"python"}))
    assert "invalid tests.command" in text and "private-unclosed" not in text


@pytest.fixture
def malformed_project(tmp_path, monkeypatch):
    if not hg.git_ok():
        pytest.skip("needs git")
    repo = hv.make_project(tmp_path, real_tests=True)
    for key, value in repo.home.env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.write("tests/test_new.py", "def test_new():\n    assert True\n")
    repo.commit("fix: change app with a regression test")
    hv.write_user_config(repo.home.path, tests={"command": 'pytest "private-unclosed'})
    calls = []

    def execute(argv, *args, **kwargs):
        calls.append(list(argv))
        return testexec.TestsRun(exit=0, collected=1, passed=1)

    monkeypatch.setattr(testexec, "run_tests", execute)
    return repo, calls


def test_malformed_global_command_refuses_record_and_replay(malformed_project, platform, monkeypatch, capsys):
    from aegis_cli.cli import main
    from aegis_core import checkrun

    repo, calls = malformed_project
    monkeypatch.chdir(repo.root)
    assert main(["check", "--record", "--tests", "--base", "main"]) == 1
    output = capsys.readouterr()
    assert "invalid tests.command" in output.out + output.err
    assert "private-unclosed" not in output.out + output.err
    row, = hv.rows_of(repo.root, "check")
    assert row["passed"] is False and row["tests"]["complete"] is False
    assert row["tests"]["languages"][0]["reason"] == "invalid tests.command"
    assert checkrun.rerun_commit_snapshot(repo.root, "HEAD", "main") == {"tree": row["tree"], "exit": 2}
    assert calls == []


def test_malformed_global_command_refuses_regression(malformed_project, platform, monkeypatch, capsys):
    from aegis_cli.cli import main
    from aegis_core import regression

    repo, calls = malformed_project
    with pytest.raises(regression.RegressionError, match=r"^invalid tests\.command$"):
        regression.check_ci_regressions(repo.root, "main")
    monkeypatch.chdir(repo.root)
    assert main(["check", "--ci", "--base", "main"]) == 1
    output = capsys.readouterr()
    assert "invalid tests.command" in output.err
    assert "private-unclosed" not in output.out + output.err
    assert calls == []


@pytest.mark.parametrize("consumer", CONSUMERS)
@pytest.mark.parametrize("empty", ['""', "''"])
def test_empty_string_arguments_keep_each_consumers_validation(commands, platform, consumer, empty):
    read, program, _root, _calls = commands
    command = quoted_program(program, platform) + f" {empty} x"
    if consumer in ("language", "coverage"):
        with pytest.raises(ValueError) as caught:
            read(consumer, command)
        section = "coverage" if consumer == "coverage" else "tests"
        assert str(caught.value) == f"invalid {section}.languages.go.command"
    else:
        assert decoded(consumer, read(consumer, command)) == [str(program), "", "x"]


@pytest.mark.parametrize("consumer", ("tests", "language", "coverage", "perf"))
def test_argv_lists_are_not_decoded(commands, platform, consumer):
    read, program, _root, _calls = commands
    words = [str(program), '--label="a b"', "C:\\tools\\", "  spaced  "]
    expected = [word.strip() for word in words] if consumer == "perf" else words
    assert decoded(consumer, read(consumer, words)) == expected


@pytest.mark.parametrize("platform", ["nt"], indirect=True)
def test_driver_retains_unquoted_absolute_program_path_fallback(commands, platform):
    read, program, _root, _calls = commands
    assert decoded("driver", read("driver", f"{program} --json")) == [str(program), "--json"]


@pytest.mark.parametrize("platform", ["nt"], indirect=True)
def test_driver_never_rejoins_a_repository_relative_program_path(commands, platform, monkeypatch):
    read, _program, root, _calls = commands
    (root / "my tool").write_text("not executed", encoding="utf-8")
    monkeypatch.chdir(root)
    monkeypatch.setenv("PATH", "")
    plan = read("driver", "my tool --json")
    assert plan.argv == ()
    assert plan.unavailable == "the driver registered for '.rf17' needs 'my', which was not found on PATH"


@pytest.mark.parametrize("platform", ["nt"], indirect=True)
@pytest.mark.parametrize("quoting", ["single", "double", "unquoted"])
def test_public_driver_decoder_retains_runner_path_fallback(commands, platform, quoting):
    _read, program, _root, _calls = commands
    first = {"single": shlex.quote(str(program)), "double": f'"{program}"', "unquoted": str(program)}[quoting]
    assert runner.split_driver_command(first + " --json") == [str(program), "--json"]


def _probe_git(root, environment, *arguments):
    return subprocess.run(
        ["git", "-c", "user.name=Probe", "-c", "user.email=probe@example.com",
         "-c", "commit.gpgsign=false", *arguments], cwd=root, env=environment,
        capture_output=True, text=True, check=True, timeout=30,
    )


def _ci_probe_module(names, observations, fail):
    # This is a real child test module: its first observation runs at collection.
    return ("NAMES = " + repr(tuple(names)) + "\nOBSERVATIONS = " + repr(str(observations))
            + "\nFAIL = " + repr(fail) + "\n" + textwrap.dedent('''
        import json
        import os
        from pathlib import Path
        import subprocess
        import pytest

        def snapshot(phase):
            values = {name: os.environ.get(name) for name in NAMES}
            worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
            module = Path(__file__).stem
            payload = {"values": values, "worker": worker, "module": module, "phase": phase,
                       "ceiling": os.environ.get("GIT_CEILING_DIRECTORIES"),
                       "pythonpath": os.environ.get("PYTHONPATH")}
            path = Path(OBSERVATIONS) / (module + "-" + phase + "-" + worker + ".json")
            path.write_text(json.dumps(payload), encoding="utf-8")

        snapshot("collection")

        @pytest.fixture(scope="session", autouse=True)
        def session_environment():
            snapshot("session")

        @pytest.fixture(scope="module")
        def own_repository(tmp_path_factory):
            snapshot("module")
            root = tmp_path_factory.mktemp("own-repository")
            (root / "owned.txt").write_text("child-owned content", encoding="utf-8")
            for arguments in (("init", "-q"), ("add", "-A"),
                              ("commit", "--allow-empty", "-qm", "child commit")):
                subprocess.run(
                    ["git", "-c", "user.name=Probe", "-c", "user.email=probe@example.com",
                     "-c", "commit.gpgsign=false", *arguments], cwd=root,
                    capture_output=True, text=True, check=True, timeout=30)
            os.environ["GITHUB_REF"] = "fixture-owned"
            yield root
            os.environ.pop("GITHUB_REF", None)

        def test_01_body(own_repository, monkeypatch):
            snapshot("body")
            os.environ["GITHUB_EVENT_NAME"] = "test-owned leak"
            monkeypatch.setenv("GITHUB_EVENT_NAME", "temporary test-owned value")

        def test_02_after_leak(own_repository):
            snapshot("after-leak")

        def test_03_session_failure(own_repository):
            snapshot("failure")
            if FAIL:
                raise RuntimeError("probe-owned session failure")
    '''))


def _run_ci_environment_probe(tmp_path, workers, clear_pythonpath=False):
    if not hg.git_ok():
        pytest.skip("needs git")
    from pathlib import Path

    repository = Path(__file__).resolve().parents[3]
    home, external = tmp_path / "home", tmp_path / "external"
    home.mkdir()
    external.mkdir()
    environment = {name: value for name, value in os.environ.items()
                   if not name.upper().startswith("GIT_")}
    environment.update(HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_NOSYSTEM="1")
    _probe_git(external, environment, "init", "-q")
    (external / "sentinel.txt").write_text("original", encoding="utf-8")
    _probe_git(external, environment, "add", "-A")
    _probe_git(external, environment, "commit", "-qm", "external fixture")
    index = tmp_path / "external-index"
    original_index = (external / ".git" / "index").read_bytes()
    index.write_bytes(original_index)
    (external / "sentinel.txt").write_text("must not be staged", encoding="utf-8")
    global_config = tmp_path / "global.gitconfig"
    global_config.write_text("[user]\n\temail = ambient@example.com\n", encoding="utf-8")
    system_config = tmp_path / "system.gitconfig"
    system_config.write_text("[user]\n\tname = Ambient System\n", encoding="utf-8")
    ceiling = tmp_path / "launcher-ceiling"
    ceiling.mkdir()
    environment["GIT_CEILING_DIRECTORIES"] = str(ceiling)
    event = tmp_path / "event.json"
    event.write_text("{}", encoding="utf-8")
    hostile = {name: "hostile-ambient-value" for name in CI_ENVIRONMENT_NAMES}
    hostile.update({
        "GIT_INDEX_FILE": str(index), "GIT_DIR": str(external / ".git"),
        "git_dir": str(external / ".git"), "GIT_NAMESPACE": "ambient",
        "GIT_WORK_TREE": str(external), "GIT_CONFIG_COUNT": "123457",
        "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*",
        "GIT_CONFIG_KEY_123456": "user.name", "GIT_CONFIG_VALUE_123456": "Ambient Probe",
        "GIT_CONFIG_GLOBAL": str(global_config), "GITHUB_EVENT_PATH": str(event),
        "GIT_CONFIG_SYSTEM": str(system_config), "GIT_CONFIG_PARAMETERS": "'core.abbrev'='12'",
        "GITHUB_REF": "refs/heads/ambient", "GITHUB_EVENT_NAME": "push",
    })
    environment.update(hostile)
    environment.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTEST_ADDOPTS="", PYTEST_PLUGINS="")
    if clear_pythonpath:
        environment.pop("PYTHONPATH", None)
    inherited_pythonpath = environment.get("PYTHONPATH")
    # Fresh worker interpreters must be able to import tests.conftest.
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (str(repository), inherited_pythonpath)))
    for name in ("PYTEST_XDIST_WORKER", "PYTEST_XDIST_WORKER_COUNT", "PYTEST_XDIST_TESTRUNUID"):
        environment.pop(name, None)
    observations = tmp_path / "observations"
    observations.mkdir()
    trees = []
    for attempt in range(2):
        tree = tmp_path / ("suite-" + str(attempt))
        tree.mkdir()
        trees.append(str(tree))
        for module in ("a", "b"):
            (tree / ("test_probe_" + str(attempt) + "_" + module + ".py")).write_text(
                _ci_probe_module(hostile, observations, fail=attempt == 0), encoding="utf-8")
    error_tree = tmp_path / "collection-error"
    error_tree.mkdir()
    (error_tree / "test_collection_error.py").write_text(
        'raise RuntimeError("probe-owned collection failure")\n', encoding="utf-8")
    trees.append(str(error_tree))
    report = tmp_path / "restored.json"
    launcher = textwrap.dedent('''
        import json
        import os
        from pathlib import Path
        import sys
        sys.path.insert(0, sys.argv[1])
        import pytest
        roots, names, report, workers = json.loads(sys.argv[2]), json.loads(sys.argv[3]), sys.argv[4], sys.argv[5]
        results = []
        for root in roots:
            code = pytest.main([
                "-p", "tests.conftest", "-p", "xdist.plugin", "--import-mode=importlib",
                "--rootdir", root, "--confcutdir", root, "--basetemp", root + "/temporary",
                "-n", workers, "--dist=loadfile", "-q", root])
            results.append({"code": int(code), "values": {name: os.environ.get(name) for name in names},
                            "ceiling": os.environ.get("GIT_CEILING_DIRECTORIES")})
            Path(report).write_text(json.dumps(results), encoding="utf-8")
    ''')
    child = subprocess.run(
        [sys.executable, "-c", launcher, str(repository), json.dumps(trees),
         json.dumps(list(hostile)), str(report), str(workers)], cwd=tmp_path,
        env=environment, capture_output=True, text=True, timeout=180,
    )
    records = {path.stem: json.loads(path.read_text(encoding="utf-8"))
               for path in observations.glob("*.json")}
    assert records, "child produced no observation records"
    expected_pythonpath = str(repository)
    if inherited_pythonpath:
        expected_pythonpath += os.pathsep + inherited_pythonpath
    # Assert before inspecting a child failure: RED must identify inherited state.
    for name, record in sorted(records.items(), key=lambda item: (item[1]["phase"] != "module", item[0])):
        if record["phase"] == "collection":
            assert record["ceiling"] == str(ceiling), "launcher ceiling changed before fixtures"
            pythonpath_matches = record["pythonpath"] == expected_pythonpath
            assert pythonpath_matches, f"{name} did not receive the probe's Python import path"
        else:
            assert str(ceiling) in record["ceiling"].split(os.pathsep), "launcher ceiling was removed"
        for key, value in record["values"].items():
            expected = "fixture-owned" if key == "GITHUB_REF" and record["phase"] in (
                "body", "after-leak", "failure") else None
            assert value == expected, (name, key, "unexpected CI environment")
    assert index.read_bytes() == original_index, "external index changed"
    assert child.returncode == 0, child.stdout + child.stderr
    restored = json.loads(report.read_text(encoding="utf-8"))
    collection_failure = 2 if workers == 0 else 1  # xdist reports failed worker collection as TESTS_FAILED.
    assert [item["code"] for item in restored] == [1, 0, collection_failure]
    assert all(item["values"] == hostile for item in restored), "launcher environment was not restored"
    assert all(item["ceiling"] == str(ceiling) for item in restored), "launcher ceiling was not restored"
    assert "probe-owned session failure" in child.stdout
    assert "probe-owned collection failure" in child.stdout
    expected_groups = {
        ("test_probe_" + str(attempt) + "_" + module, phase)
        for attempt in range(2) for module in ("a", "b")
        for phase in ("collection", "session", "module", "body", "after-leak", "failure")
    }
    assert {(record["module"], record["phase"]) for record in records.values()} == expected_groups
    expected_workers = {"main"} if workers == 0 else {"gw0", "gw1"}
    assert {record["worker"] for record in records.values()} == expected_workers
    for module, phase in expected_groups:
        group = [record for record in records.values() if (record["module"], record["phase"]) == (module, phase)]
        if phase == "collection":
            assert {record["worker"] for record in group} == expected_workers
        else:
            assert len(group) == 1


@pytest.mark.parametrize(
    ("workers", "clear_pythonpath"),
    [(0, False), (2, False), (2, True)],
    ids=["serial", "xdist", "xdist-no-pythonpath"],
)
def test_ci_environment_is_removed_before_collection_and_restored(tmp_path, workers, clear_pythonpath):
    _run_ci_environment_probe(tmp_path, workers, clear_pythonpath)
