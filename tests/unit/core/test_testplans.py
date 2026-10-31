"""User-scoped language commands, argv expansion and offline execution environments."""
from __future__ import annotations

import json
import os

import pytest

from aegis_core.testplans import (
    expand_command, language_environment, language_settings, resolve_executable,
)


@pytest.fixture
def project(tmp_path, monkeypatch):
    home, root = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    root.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return root, home


def config(home, raw):
    directory = home / ".aegis"
    directory.mkdir(exist_ok=True)
    (directory / "config.json").write_text(json.dumps({"v": 1, **raw}), encoding="utf-8")


@pytest.mark.parametrize("language,timeout", [("ts", 300), ("go", 300), ("rust", 900)])
def test_unconfigured_language_retains_default_timeout(project, language, timeout):
    root, _home = project
    settings = language_settings(root, language)
    assert settings.command is None and settings.timeout_s == timeout


def test_commands_come_only_from_user_scope(project):
    root, home = project
    config(root, {"tests": {"languages": {"go": {"command": ["repo-attack"]}}}})
    assert language_settings(root, "go").command is None
    config(home, {"tests": {"languages": {"go": {
        "command": ["go", "test", "{packages}"], "timeout_s": 19}}}})
    settings = language_settings(root, "go")
    assert settings.command == ("go", "test", "{packages}") and settings.timeout_s == 19


def test_existing_global_command_is_not_reinterpreted_as_language_command(project):
    root, home = project
    config(home, {"tests": {"command": ["all-suites"], "languages": {
        "ts": {"command": "node runner.mjs {files}"}}}})
    assert language_settings(root, "ts").command == ("node", "runner.mjs", "{files}")


def test_coverage_command_is_independent_of_test_command(project):
    root, home = project
    config(home, {"tests": {"languages": {"go": {"command": ["tests"]}}},
                  "coverage": {"languages": {"go": {"command": ["coverage", "{out}"]}}}})
    assert language_settings(root, "go", coverage=True).command == ("coverage", "{out}")


@pytest.mark.parametrize("command", ["", [], ["go", ""], ["go", 3], ["go", "bad\0arg"], 42])
def test_malformed_command_is_explicit(project, command):
    root, home = project
    config(home, {"tests": {"languages": {"go": {"command": command}}}})
    with pytest.raises(ValueError, match=r"^invalid tests\.languages\.go\.command$"):
        language_settings(root, "go")


@pytest.mark.parametrize("timeout", [True, 0, -1, "20", 10 ** 1000])
def test_malformed_deadline_is_explicit(project, timeout):
    root, home = project
    config(home, {"tests": {"languages": {"rust": {"timeout_s": timeout}}}})
    with pytest.raises(ValueError, match=r"^invalid tests\.languages\.rust\.timeout_s$"):
        language_settings(root, "rust")


@pytest.mark.parametrize("timeout", [float("inf"), float("nan")])
def test_nonstandard_json_is_ignored_by_existing_lenient_config_reader(project, timeout):
    root, home = project
    config(home, {"tests": {"languages": {"rust": {"timeout_s": timeout}}}})
    assert language_settings(root, "rust").timeout_s == 900


def test_unknown_language_and_malformed_language_table_are_explicit(project):
    root, home = project
    with pytest.raises(ValueError, match="^unsupported language: java$"):
        language_settings(root, "java")
    config(home, {"tests": {"languages": {"go": "not a table"}}})
    with pytest.raises(ValueError, match=r"^invalid tests\.languages\.go$"):
        language_settings(root, "go")


def test_placeholder_lists_preserve_argv_boundaries_and_empty_selections():
    assert expand_command(("go", "test", "{filters}", "{packages}", "--out={out}"),
                          {"filters": (), "packages": ("./path with spaces", "./other"),
                           "out": "report with spaces.out"}) == [
        "go", "test", "./path with spaces", "./other", "--out=report with spaces.out"]


@pytest.mark.parametrize("words,values,message", [
    (("{files}",), {}, "missing placeholder: files"),
    (("--files={files}",), {"files": ("a", "b")}, "embedded placeholder requires one value: files"),
    (("{unknown}",), {}, "unknown placeholder: unknown"),
    (("{out}",), {"out": "bad\0path"}, "invalid placeholder value: out"),
])
def test_unsafe_or_ambiguous_expansion_is_explicit(words, values, message):
    with pytest.raises(ValueError, match="^" + message + "$"):
        expand_command(words, values)


def test_code_argument_without_named_placeholder_is_literal():
    code = "print({'number': 3})"
    assert expand_command(("python", "-c", code), {}) == ["python", "-c", code]


def test_go_environment_uses_fixed_controls_and_only_declared_parent_caches():
    base = {"PATH": "/usr/bin:/bin", "HOME": "/scratch/home"}
    parent = {"HOME": "/real/home", "PATH": ".", "GOTOOLCHAIN": "auto", "GOENV": "unsafe",
              "GOFLAGS": "-mod=mod", "GOCACHE": "/cache/build", "GOMODCACHE": "/cache/modules",
              "GOCACHEPROG": "repo-program", "PYTHONPATH": "repo"}
    env = language_environment("go", base, parent=parent, executable="/tools/go")
    assert env == {**base, "PATH": "/tools" + os.pathsep + base["PATH"],
                   "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOENV": "off",
                   "GOFLAGS": "-mod=readonly", "GOCACHE": "/cache/build", "GOMODCACHE": "/cache/modules"}
    assert base == {"PATH": "/usr/bin:/bin", "HOME": "/scratch/home"}


def test_rust_environment_pins_installed_toolchain_and_preserves_user_caches():
    env = language_environment("rust", {"PATH": "/usr/bin"},
        parent={"RUSTUP_TOOLCHAIN": "absent", "RUSTUP_HOME": "/user/rustup", "CARGO_HOME": "/user/cargo",
                "CARGO_NET_OFFLINE": "false", "CARGO_TARGET_DIR": "/repo/target", "RUSTC_WRAPPER": "attack"},
        executable="/tools/cargo", rust_toolchain="stable-x86_64-unknown-linux-gnu", cargo_target="/cache/target")
    assert env == {"PATH": "/tools" + os.pathsep + "/usr/bin", "RUSTUP_HOME": "/user/rustup",
                   "CARGO_HOME": "/user/cargo", "RUSTUP_TOOLCHAIN": "stable-x86_64-unknown-linux-gnu",
                   "RUSTUP_AUTO_INSTALL": "0", "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": "/cache/target"}


@pytest.mark.parametrize("pin,target", [(None, "/cache/target"), ("stable", None), ("bad\nname", "/cache/target")])
def test_rust_environment_requires_resolved_pin_and_target(pin, target):
    with pytest.raises(ValueError, match="^Rust requires a resolved installed toolchain and absolute cache target$"):
        language_environment("rust", {}, parent={}, rust_toolchain=pin, cargo_target=target)


def test_javascript_environment_never_inherits_install_hooks_or_parent_home():
    base = {"HOME": "/scratch", "PATH": "/usr/bin"}
    assert language_environment("ts", base, parent={"npm_config_prefix": "/repo", "HOME": "/user"}) == base


def test_executable_lookup_refuses_repository_and_relative_candidates(project, tmp_path, monkeypatch):
    root, _home = project
    tools = tmp_path / "tools"
    tools.mkdir()
    name = "node.exe" if os.name == "nt" else "node"
    for directory in (root, tools):
        path = directory / name
        path.write_bytes(b"fixture executable, never run")
        path.chmod(0o700)
    monkeypatch.setenv("PATH", os.pathsep.join((str(root), ".", str(tools))))
    assert resolve_executable("node", root) == str(tools / name)
    assert resolve_executable(str(root / name), root) is None
    assert resolve_executable("relative/node", root) is None
    assert resolve_executable(str(tools / name), root) == str(tools / name)


def test_missing_executable_is_unavailable(project, monkeypatch):
    root, _home = project
    monkeypatch.setenv("PATH", "")
    assert resolve_executable("go", root) is None


def test_repository_symlink_to_trusted_program_is_not_an_executable_plan(project, tmp_path):
    from tests.conftest import symlink_or_skip

    root, _home = project
    program = tmp_path / "trusted-node"
    program.write_bytes(b"fixture executable, never run")
    program.chmod(0o700)
    alias = root / "node"
    symlink_or_skip(program, alias)
    assert resolve_executable(str(alias), root) is None


def test_snapshot_arguments_rebase_repo_program_files_and_options_only(project, tmp_path):
    from aegis_core.testplans import rebase_snapshot_arguments

    root, _home = project
    snapshot, tools = tmp_path / "snapshot", tmp_path / "tools"
    sibling = tmp_path / (root.name + "-other") / "keep.py"
    words = [str(root / "runner"), str(root / "file=with spaces.py"), "--report=" + str(root / "out.json"),
             str(tools / "python"), str(sibling), "relative.py", "literal=$(not-a-shell)"]
    assert rebase_snapshot_arguments(words, root, snapshot) == [
        str(snapshot / "runner"), str(snapshot / "file=with spaces.py"), "--report=" + str(snapshot / "out.json"),
        str(tools / "python"), str(sibling), "relative.py", "literal=$(not-a-shell)"]
    assert words[0] == str(root / "runner")  # logical command/digest input is unchanged
