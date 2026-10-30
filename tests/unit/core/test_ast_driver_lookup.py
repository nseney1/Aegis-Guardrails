"""Which program an AST driver runs: aegis_core.pathlookup, absolute PATH entries only.

`aegis check` runs in CI on pull-request code. An empty or relative PATH entry names the
current directory (the repository), and on Windows the standard library's lookup searches
the current directory first whatever PATH says: a PR that plants node.exe or go.exe in
the repository root must never pick the interpreter a driver runs, nor hide the real one.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Optional, Tuple

import pytest

from aegis_core.ast.detect import detect_project_languages
from aegis_core.ast.runner import (
    ASTDriverError,
    ASTDriverRegistry,
    ASTDriverRunner,
    NoDriverConfiguredError,
    _split_command,
    resolve_driver_executable,
)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".aegis").mkdir(parents=True)
    return root


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_executable(path: Path, body: str) -> Path:
    """A Python program PATH lookup finds as ``path.name`` (a .cmd launcher on Windows,
    which runs only PATHEXT types)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        script = path.with_name(path.name + "-script.py")
        script.write_text(body, encoding="utf-8")
        launcher = path.with_name(path.name + ".cmd")
        launcher.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return launcher
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _planted(directory: Path, name: str, pwned: Path) -> Path:
    return _write_executable(directory / name, f"open({str(pwned)!r}, 'w').close()\n")


def _real(directory: Path, name: str, language: str = "typescript") -> Path:
    """The interpreter the user installed: prints a one-definition NormalizedAST."""
    body = (
        "import json, sys\n"
        f"print(json.dumps({{'version': '1.0', 'language': {language!r}, 'file_path': sys.argv[-1],"
        " 'definitions': [{'name': 'fromRealProgram', 'kind': 'function', 'line': 1, 'is_exported': True}],"
        " 'call_sites': [], 'imports': [], 'mutation_points': []}))\n"
    )
    return _write_executable(directory / name, body)


def _parse(path: Path, ws: Path, runner: Optional[ASTDriverRunner] = None) -> Tuple[Optional[Any], Optional[Exception]]:
    try:
        return (runner or ASTDriverRunner()).parse_file(path, workspace_root=ws), None
    except ASTDriverError as exc:
        return None, exc


def _plant_everywhere(ws: Path, name: str, pwned: Path) -> None:
    """The repository root (the cwd), its bin/ and node_modules/.bin/."""
    for directory in (ws, ws / "bin", ws / "node_modules" / ".bin"):
        _planted(directory, name, pwned)


# Where the planted copy is reachable from: each comes before the real program on PATH.
PLANTED_ENTRIES = {
    "empty_entry": "",
    "dot_entry": ".",
    "relative_entry": "bin",
    "entry_inside_workspace": "{ws}/node_modules/.bin",
}


def _path(ws: Path, layout: str, real_dir: Path) -> str:
    return os.pathsep.join([PLANTED_ENTRIES[layout].format(ws=ws), str(real_dir)])


# ── Packaged drivers (a repository opt-in) ───────────────────────────────────
# TS/JS parse in process, so a legacy opt-in never reaches any node on PATH. Go's
# compiler lookup has its own planted/linked-compiler tests in test_go_build_cache.py.

@pytest.mark.parametrize("layout", sorted(PLANTED_ENTRIES))
def test_a_legacy_packaged_ts_opt_in_never_runs_a_node_on_path(ws, tmp_path, monkeypatch, layout):
    pwned = tmp_path / "PWNED"
    _plant_everywhere(ws, "node", pwned)
    _planted(tmp_path / "real-bin", "node", pwned)
    monkeypatch.chdir(ws)
    monkeypatch.setenv("PATH", _path(ws, layout, tmp_path / "real-bin"))
    _write_json(ws / ".aegis" / "config.json", {"v": 1, "ast": {"packaged_drivers": ["ts"]}})
    app = ws / "app.ts"
    app.write_text("export function run(): void {}\n", encoding="utf-8")

    result, error = _parse(app, ws)

    assert not pwned.exists(), "a node on PATH was run for a TypeScript file"
    assert error is None, error
    assert [d.name for d in result.definitions] == ["run"]


def test_an_interpreter_outside_the_workspace_that_links_into_it_is_not_run(ws, tmp_path, monkeypatch):
    # The PATH entry is outside the workspace; the program in it is the repository's.
    from conftest import symlink_or_skip

    pwned = tmp_path / "PWNED"
    planted = _planted(ws / "tools", "node", pwned)
    (tmp_path / "real-bin").mkdir()
    symlink_or_skip(planted, tmp_path / "real-bin" / planted.name)
    monkeypatch.setenv("PATH", str(tmp_path / "real-bin"))
    _write_json(ws / ".aegis" / "config.json", {"v": 1, "ast": {"packaged_drivers": ["ts"]}})
    app = ws / "app.ts"
    app.write_text("export function run(): void {}\n", encoding="utf-8")

    result, error = _parse(app, ws)

    assert not pwned.exists(), "a link into the repository was run"
    assert error is None, error
    assert result.language == "typescript" and [d.name for d in result.definitions] == ["run"]


# ── User-scope driver commands (~/.aegis/config.json) ────────────────────────

def test_a_user_scope_driver_on_path_that_links_into_the_workspace_is_not_run(ws, tmp_path, isolated_home, monkeypatch):
    from conftest import symlink_or_skip

    pwned = tmp_path / "PWNED"
    planted = _planted(ws / "tools", "mddriver", pwned)
    (tmp_path / "real-bin").mkdir()
    link = tmp_path / "real-bin" / planted.name
    symlink_or_skip(planted, link)
    monkeypatch.setenv("PATH", str(tmp_path / "real-bin"))
    _write_json(isolated_home / ".aegis" / "config.json", {"v": 1, "drivers": {"md": "mddriver"}})
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    _, error = _parse(readme, ws)

    assert not pwned.exists(), "a link into the repository was run"
    assert isinstance(error, NoDriverConfiguredError)
    assert f"needs 'mddriver', which resolves to {link} inside the workspace" in str(error)


@pytest.mark.parametrize("layout", sorted(PLANTED_ENTRIES))
def test_a_user_scope_driver_named_bare_runs_the_real_program_never_a_planted_one(
    ws, tmp_path, isolated_home, monkeypatch, layout
):
    pwned = tmp_path / "PWNED"
    _plant_everywhere(ws, "mddriver", pwned)
    _real(tmp_path / "real-bin", "mddriver", language="markdown")
    monkeypatch.chdir(ws)
    monkeypatch.setenv("PATH", _path(ws, layout, tmp_path / "real-bin"))
    _write_json(isolated_home / ".aegis" / "config.json", {"v": 1, "drivers": {"md": "mddriver"}})
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    result, error = _parse(readme, ws)

    assert not pwned.exists(), "a driver planted in the repository was run"
    assert error is None, error
    assert [d.name for d in result.definitions] == ["fromRealProgram"]


def test_a_user_scope_driver_found_only_inside_the_workspace_says_where(ws, tmp_path, isolated_home, monkeypatch):
    pwned = tmp_path / "PWNED"
    planted = _planted(ws / "node_modules" / ".bin", "mddriver", pwned)
    (tmp_path / "empty").mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join([str(planted.parent), str(tmp_path / "empty")]))
    _write_json(isolated_home / ".aegis" / "config.json", {"v": 1, "drivers": {"md": "mddriver"}})
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    _, error = _parse(readme, ws)

    assert not pwned.exists()
    assert isinstance(error, NoDriverConfiguredError)
    assert f"needs 'mddriver', which resolves to {planted} inside the workspace" in str(error)


def test_a_relative_driver_path_in_user_config_resolves_against_the_workspace_root(
    ws, tmp_path, isolated_home, monkeypatch
):
    # The driver runs in a fresh empty directory: a relative path left as written would
    # resolve there (or, through CreateProcess on Windows, against aegis's own cwd).
    real = _real(tmp_path / "tools", "mddriver", language="markdown")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    command = "../tools/" + real.name
    _write_json(isolated_home / ".aegis" / "config.json", {"v": 1, "drivers": {"md": command}})
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    plan = ASTDriverRegistry().plan_driver(".md", workspace_root=ws)
    assert plan.unavailable is None
    assert plan.argv[0] == os.path.normpath(os.path.join(str(ws), command))

    result, error = _parse(readme, ws)
    assert error is None, error
    assert [d.name for d in result.definitions] == ["fromRealProgram"]


def test_an_absolute_driver_path_in_user_config_still_runs(ws, tmp_path, isolated_home):
    real = _real(tmp_path / "tools", "mddriver", language="markdown")
    _write_json(isolated_home / ".aegis" / "config.json", {"v": 1, "drivers": {"md": str(real)}})
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    result, error = _parse(readme, ws)

    assert error is None, error
    assert [d.name for d in result.definitions] == ["fromRealProgram"]


# ── Drivers registered in code ───────────────────────────────────────────────

@pytest.mark.parametrize("layout", sorted(PLANTED_ENTRIES))
def test_a_driver_registered_in_code_runs_the_program_an_absolute_entry_names(ws, tmp_path, monkeypatch, layout):
    # The driver runs with the workspace as its cwd; a bare name left to the child's
    # own search resolves an empty or relative PATH entry there.
    pwned = tmp_path / "PWNED"
    _plant_everywhere(ws, "mddriver", pwned)
    _real(tmp_path / "real-bin", "mddriver", language="markdown")
    monkeypatch.chdir(ws)
    monkeypatch.setenv("PATH", _path(ws, layout, tmp_path / "real-bin"))
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    result, error = _parse(readme, ws, ASTDriverRunner(ASTDriverRegistry({".md": "mddriver"})))

    assert not pwned.exists(), "a driver planted in the repository was run"
    assert error is None, error
    assert [d.name for d in result.definitions] == ["fromRealProgram"]


def test_a_driver_registered_in_code_that_is_on_no_absolute_entry_is_unavailable(ws, tmp_path, monkeypatch):
    pwned = tmp_path / "PWNED"
    _plant_everywhere(ws, "mddriver", pwned)
    monkeypatch.chdir(ws)
    monkeypatch.setenv("PATH", os.pathsep.join(["", "bin"]))
    readme = ws / "README.md"
    readme.write_text("# hi\n", encoding="utf-8")

    _, error = _parse(readme, ws, ASTDriverRunner(ASTDriverRegistry({".md": "mddriver --json"})))

    assert not pwned.exists()
    assert isinstance(error, NoDriverConfiguredError)
    assert "the driver registered for '.md' needs 'mddriver', which is reached only through the relative PATH entry ''" in str(error)

    monkeypatch.chdir(tmp_path)
    _, error = _parse(readme, ws, ASTDriverRunner(ASTDriverRegistry({".md": "mddriver --json"})))
    assert "the driver registered for '.md' needs 'mddriver', which was not found on PATH" in str(error)
    assert not pwned.exists()


# ── What doctor reports and language detection ──────────────────────────────

@pytest.mark.parametrize("entry", ["", ".", "bin"])
def test_a_driver_executable_behind_a_relative_entry_does_not_resolve(tmp_path, monkeypatch, entry):
    pwned = tmp_path / "PWNED"
    _planted(tmp_path / "repo", "node", pwned)
    _planted(tmp_path / "repo" / "bin", "node", pwned)
    monkeypatch.chdir(tmp_path / "repo")
    monkeypatch.setenv("PATH", entry)
    assert resolve_driver_executable("node") is None

    real = _real(tmp_path / "real-bin", "node")
    monkeypatch.setenv("PATH", os.pathsep.join([entry, str(real.parent)]))
    assert resolve_driver_executable("node") == str(real)


def test_a_driver_executable_inside_the_workspace_does_not_resolve(ws, tmp_path, monkeypatch):
    inside = _planted(ws / "node_modules" / ".bin", "node", tmp_path / "PWNED")
    monkeypatch.setenv("PATH", str(inside.parent))
    assert resolve_driver_executable("node") == str(inside)
    assert resolve_driver_executable("node", workspace=ws) is None
    assert resolve_driver_executable(str(inside), workspace=ws) is None
    assert resolve_driver_executable(os.path.join("node_modules", ".bin", inside.name), workspace=ws) is None
    assert resolve_driver_executable("python3", workspace=ws) == sys.executable


def test_a_driver_path_resolves_against_the_workspace_root_never_the_cwd(ws, tmp_path, monkeypatch):
    real = _real(tmp_path / "tools", "mddriver")
    elsewhere = tmp_path / "elsewhere"
    _real(elsewhere / "tools", "mddriver")
    monkeypatch.chdir(elsewhere)
    relative = os.path.join("..", "tools", real.name)
    assert resolve_driver_executable(relative, workspace=ws) == os.path.normpath(os.path.join(str(ws), relative))
    assert resolve_driver_executable(os.path.join("tools", real.name)) is None  # no workspace: no base
    assert resolve_driver_executable(str(real)) == str(real)
    assert resolve_driver_executable(str(tmp_path / "missing")) is None


@pytest.mark.skipif(os.name == "nt", reason="Windows runs any file; POSIX needs the execute bit")
def test_a_driver_path_names_a_program_only_when_it_is_an_executable_file(tmp_path):
    tools = tmp_path / "tools"
    runnable = _write_executable(tools / "mddriver", "print('{}')\n")
    plain = tools / "notes.txt"
    plain.write_text("not a program\n", encoding="utf-8")

    assert resolve_driver_executable(str(runnable)) == str(runnable)
    assert resolve_driver_executable(str(plain)) is None
    assert resolve_driver_executable(str(tools)) is None  # a directory: searchable, not runnable


def test_a_registered_driver_is_found_for_any_spelling_of_its_extension(tmp_path):
    registry = ASTDriverRegistry({".md": "mddriver --json"})

    assert registry.resolve_driver(".MD") == "mddriver --json"
    assert registry.resolve_driver("md") == "mddriver --json"
    assert registry.plan_driver(".Md").label == "mddriver --json"
    assert registry.resolve_driver(".rst") is None  # nothing registered, no workspace to ask


@pytest.mark.parametrize("layout", sorted(PLANTED_ENTRIES))
def test_a_toolchain_planted_in_the_repository_is_not_detected(ws, tmp_path, monkeypatch, layout):
    (ws / "tsconfig.json").write_text("{}", encoding="utf-8")
    _plant_everywhere(ws, "node", tmp_path / "PWNED")
    (tmp_path / "empty").mkdir()
    monkeypatch.chdir(ws)
    monkeypatch.setenv("PATH", _path(ws, layout, tmp_path / "empty"))
    assert detect_project_languages(ws)["typescript"]["toolchains"] == []

    _real(tmp_path / "real-bin", "node")
    monkeypatch.setenv("PATH", _path(ws, layout, tmp_path / "real-bin"))
    assert detect_project_languages(ws)["typescript"]["toolchains"] == ["node"]


# ── Windows command splitting ────────────────────────────────────────────────

@pytest.mark.parametrize("command, words", [
    ("my tool --json", ["my", "tool", "--json"]),
    ("sub/my tool --json", ["sub/my", "tool", "--json"]),
])
def test_windows_splitting_never_joins_words_by_a_file_in_the_current_directory(tmp_path, monkeypatch, command,
                                                                                  words):
    # Rejoining unquoted words is for absolute paths with spaces (C:\Program Files\...):
    # a relative candidate names a file in aegis's cwd, which the repository controls.
    (tmp_path / "sub").mkdir()
    for planted in (tmp_path / "my tool", tmp_path / "sub" / "my tool"):
        planted.write_text("planted", encoding="utf-8")
        planted.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    with monkeypatch.context() as m:
        m.setattr("aegis_core.ast.runner.os.name", "nt")
        assert _split_command(command) == words


def test_windows_splitting_joins_an_unquoted_absolute_path_with_spaces(tmp_path, monkeypatch):
    program = _real(tmp_path / "Program Files" / "drv", "driver")
    command = f"{program} --json"
    with monkeypatch.context() as m:
        m.setattr("aegis_core.ast.runner.os.name", "nt")
        assert _split_command(command) == [str(program), "--json"]


def test_parse_file_confines_to_confine_root_while_drivers_come_from_the_workspace(tmp_path):
    """The pre-commit hook parses staged blobs from a snapshot outside the repository."""
    from aegis_core.ast.runner import ASTDriverRunner
    from aegis_core.errors import PathTraversalError

    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    (ws / ".aegis" / "config.json").write_text('{"v": 1, "ast": {"packaged_drivers": ["rs"]}}', encoding="utf-8")
    snapshot = tmp_path / "snapshot"
    (snapshot / "src").mkdir(parents=True)
    staged = snapshot / "src" / "main.rs"
    staged.write_text("fn main() {\n    helper();\n}\n", encoding="utf-8")

    norm = ASTDriverRunner().parse_file(staged, workspace_root=ws, confine_root=snapshot)
    assert any(d.name == "main" for d in norm.definitions)

    outside = tmp_path / "elsewhere.rs"
    outside.write_text("fn x() {}\n", encoding="utf-8")
    with pytest.raises(PathTraversalError):
        ASTDriverRunner().parse_file(outside, workspace_root=ws, confine_root=snapshot)
