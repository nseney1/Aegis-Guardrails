"""Operator command strings share a grammar while consumers retain their policies."""
from __future__ import annotations

import json
import os
import shlex
import sys
from types import SimpleNamespace

import pytest

from aegis_core import inference_provider, testexec, testplans
from aegis_core.ast import runner
from aegis_core.verification import perf_check


CONSUMERS = ("model", "tests", "language", "coverage", "perf", "driver")


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
        assert read(consumer, command) is None


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
