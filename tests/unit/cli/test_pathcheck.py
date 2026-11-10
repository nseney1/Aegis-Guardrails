"""BUG-041: tell the user how to put the aegis CLI on PATH for their shell.

After `pip install --user`, the console script lands in the user scripts
directory (~/.local/bin on Linux). zsh does not read ~/.profile, so on a stock
oh-my-zsh setup `aegis` is "command not found" and nothing said why.
aegis_cli.pathcheck detects that and prints a shell-specific remedy.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aegis_cli.pathcheck import (
    build_hint,
    detect_shell,
    on_path,
    rc_file,
    remedy,
    scripts_dir,
)

REPO = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


# ── detect_shell ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("shell_var,os_name,expected", [
    ("/usr/bin/zsh", "posix", "zsh"),
    ("/bin/bash", "posix", "bash"),
    ("/usr/local/bin/fish", "posix", "fish"),
    ("-zsh", "posix", "zsh"),                       # login-shell argv0 form
    ("/usr/bin/bash", "nt", "bash"),                # Git Bash on Windows
    ("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "nt", "pwsh"),
    ("", "nt", "pwsh"),                             # cmd/PowerShell set no SHELL
    ("/bin/tcsh", "posix", "unknown"),
])
def test_detect_shell(shell_var, os_name, expected):
    env = {"SHELL": shell_var} if shell_var else {}
    assert detect_shell(env, os_name=os_name) == expected


def test_detect_shell_unset_on_posix_is_unknown():
    assert detect_shell({}, os_name="posix") == "unknown"


# ── rc_file ──────────────────────────────────────────────────────────────────

def test_rc_file_zsh_default():
    assert rc_file("zsh", env={}, platform="linux") == "~/.zshrc"


def test_rc_file_zsh_honours_zdotdir():
    assert rc_file("zsh", env={"ZDOTDIR": "/cfg/zsh"}, platform="linux") == "/cfg/zsh/.zshrc"


def test_rc_file_bash_linux_vs_macos():
    assert rc_file("bash", env={}, platform="linux") == "~/.bashrc"
    assert rc_file("bash", env={}, platform="darwin") == "~/.bash_profile"


def test_rc_file_fish():
    assert rc_file("fish", env={}, platform="linux") == "~/.config/fish/config.fish"


def test_rc_file_unknown_has_no_single_rc():
    assert rc_file("unknown", env={}, platform="linux") is None


def test_rc_file_pwsh_windows_vs_posix():
    # Windows: persistent user Path variable, not a profile line.
    assert rc_file("pwsh", env={}, platform="win32") is None
    assert rc_file("pwsh", env={}, platform="linux") == "$PROFILE"


# ── on_path ──────────────────────────────────────────────────────────────────

def test_on_path_exact_and_trailing_slash():
    assert on_path("/home/u/.local/bin", "/usr/bin:/home/u/.local/bin/", sep=":")


def test_on_path_rejects_substring_match():
    # The old Makefile check was a grep substring match; a longer entry that
    # merely contains the directory must not count.
    assert not on_path("/home/u/.local/bin", "/home/u/.local/bin-old:/usr/bin", sep=":")


def test_on_path_casefold_for_windows():
    assert on_path("C:\\Users\\U\\Scripts", "c:\\users\\u\\scripts;C:\\Windows",
                   sep=";", casefold=True)
    assert not on_path("C:\\Users\\U\\Scripts", "c:\\users\\u\\scripts",
                       sep=";", casefold=False)


def test_on_path_empty_path_env():
    assert not on_path("/home/u/.local/bin", "", sep=":")


# ── remedy ───────────────────────────────────────────────────────────────────

def test_remedy_posix_uses_home_variable_under_home():
    line = remedy("zsh", "/home/u/.local/bin", home="/home/u")
    assert line == 'export PATH="$HOME/.local/bin:$PATH"'


def test_remedy_posix_absolute_outside_home():
    line = remedy("bash", "/opt/py/bin", home="/home/u")
    assert line == 'export PATH="/opt/py/bin:$PATH"'


def test_remedy_fish():
    assert remedy("fish", "/home/u/.local/bin", home="/home/u") == 'fish_add_path "$HOME/.local/bin"'


def test_remedy_pwsh_sets_user_path():
    line = remedy("pwsh", "C:\\Users\\U\\Scripts", home="C:\\Users\\U", os_name="nt")
    assert "SetEnvironmentVariable" in line
    assert "C:\\Users\\U\\Scripts" in line
    assert '"User"' in line


def test_remedy_pwsh_on_posix_uses_profile_line():
    # EnvironmentVariableTarget.User throws PlatformNotSupportedException off Windows.
    line = remedy("pwsh", "/home/u/.local/bin", home="/home/u", os_name="posix")
    assert line == '$env:PATH = "$HOME/.local/bin:" + $env:PATH'
    assert "SetEnvironmentVariable" not in line


def test_remedy_git_bash_translates_windows_path_under_home():
    line = remedy("bash", "C:\\Users\\U\\AppData\\Roaming\\Python\\Python312\\Scripts",
                  home="C:\\Users\\U", os_name="nt")
    assert line == 'export PATH="$HOME/AppData/Roaming/Python/Python312/Scripts:$PATH"'


def test_remedy_git_bash_translates_drive_outside_home():
    # A raw "C:\\..." entry would be split on ':' by bash and corrupt PATH.
    line = remedy("bash", "D:\\Py\\Scripts", home="C:\\Users\\U", os_name="nt")
    assert line == 'export PATH="/d/Py/Scripts:$PATH"'


def test_remedy_git_bash_home_match_is_case_insensitive():
    line = remedy("bash", "c:\\users\\u\\Scripts", home="C:\\Users\\U", os_name="nt")
    assert line == 'export PATH="$HOME/Scripts:$PATH"'


# ── scripts_dir ──────────────────────────────────────────────────────────────

def test_scripts_dir_picks_first_candidate_containing_aegis(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    real = tmp_path / "bin"
    real.mkdir()
    (real / "aegis").write_text("#!/bin/sh\n")
    assert scripts_dir([str(empty), str(real)]) == str(real)


def test_scripts_dir_finds_windows_exe(tmp_path):
    (tmp_path / "aegis.exe").write_bytes(b"MZ")
    assert scripts_dir([str(tmp_path)]) == str(tmp_path)


def test_scripts_dir_none_when_not_installed(tmp_path):
    assert scripts_dir([str(tmp_path), str(tmp_path / "missing")]) is None


# ── build_hint ───────────────────────────────────────────────────────────────

def _bin_with_aegis(tmp_path):
    home = tmp_path / "home"
    bindir = home / ".local" / "bin"
    bindir.mkdir(parents=True)
    (bindir / "aegis").write_text("#!/bin/sh\n")
    return home, bindir


def test_build_hint_none_when_resolvable(tmp_path):
    home, bindir = _bin_with_aegis(tmp_path)
    env = {"SHELL": "/usr/bin/zsh", "PATH": str(bindir), "HOME": str(home)}
    assert build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: str(bindir / "aegis"),
                      home=str(home), platform="linux", os_name="posix") is None


def test_build_hint_zsh_names_zshrc_and_fallback(tmp_path):
    home, bindir = _bin_with_aegis(tmp_path)
    env = {"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin:/bin", "HOME": str(home)}
    text = build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: None,
                      home=str(home), platform="linux", os_name="posix")
    assert text is not None
    assert str(bindir) in text
    assert "zsh" in text
    assert "~/.zshrc" in text
    assert 'export PATH="$HOME/.local/bin:$PATH"' in text
    # The stopgap names the script by its full path; `-m aegis_cli` would import from the cwd.
    assert f"{bindir / 'aegis'} <command>" in text
    assert "-m aegis_cli" not in text


def test_build_hint_on_path_but_shell_not_refreshed(tmp_path):
    # Directory already on PATH but `which` misses it (e.g. stale hash):
    # don't tell the user to edit their rc file again.
    home, bindir = _bin_with_aegis(tmp_path)
    env = {"SHELL": "/usr/bin/zsh", "PATH": str(bindir), "HOME": str(home)}
    text = build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: None,
                      home=str(home), platform="linux", os_name="posix")
    assert text is not None
    assert "export PATH" not in text
    assert "new terminal" in text


def test_build_hint_not_installed(tmp_path):
    env = {"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin", "HOME": str(tmp_path)}
    text = build_hint(env=env, candidates=[str(tmp_path)], which=lambda *_a, **_k: None,
                      home=str(tmp_path), platform="linux", os_name="posix")
    assert text is not None
    assert "pip install" in text


def test_build_hint_defaults_to_the_aegis_package(tmp_path):
    """The default names aegis-guardrails, never the v3 aegis-governance package."""
    env = {"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin", "HOME": str(tmp_path)}
    text = build_hint(env=env, candidates=[str(tmp_path)], which=lambda *_a, **_k: None,
                      home=str(tmp_path), platform="linux", os_name="posix")
    assert text == ("ℹ️  The 'aegis' command is not installed for this Python.\n"
                    "    Install it with: python3 -m pip install aegis-guardrails\n"
                    "    (or pipx install aegis-guardrails)")


def test_build_hint_unknown_shell_gives_generic_advice(tmp_path):
    home, bindir = _bin_with_aegis(tmp_path)
    env = {"SHELL": "/bin/tcsh", "PATH": "/usr/bin", "HOME": str(home)}
    text = build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: None,
                      home=str(home), platform="linux", os_name="posix")
    assert text is not None
    assert "startup file" in text


def test_build_hint_venv_says_activate_not_rc_file(tmp_path):
    # Putting an unactivated venv's bin/ in ~/.zshrc would be wrong advice.
    venv = tmp_path / "venv"
    bindir = venv / "bin"
    bindir.mkdir(parents=True)
    (bindir / "aegis").write_text("#!/bin/sh\n")
    env = {"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin", "HOME": str(tmp_path)}
    text = build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: None,
                      home=str(tmp_path), platform="linux", os_name="posix",
                      venv_prefix=str(venv))
    assert text is not None
    assert "virtual environment" in text
    vprefix = str(venv).replace("\\", "/")
    assert f"source {vprefix}/bin/activate" in text
    assert "~/.zshrc" not in text


def test_build_hint_which_searches_env_path(tmp_path):
    seen = {}

    def fake_which(cmd, mode=os.F_OK | os.X_OK, path=None):
        seen["path"] = path
        return None

    env = {"SHELL": "/usr/bin/zsh", "PATH": "/only/this", "HOME": str(tmp_path)}
    build_hint(env=env, candidates=[str(tmp_path)], which=fake_which,
               home=str(tmp_path), platform="linux", os_name="posix")
    assert seen["path"] == "/only/this"


def _stub_aegis(directory):
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / ("aegis.exe" if os.name == "nt" else "aegis")
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o755)
    return program


@pytest.mark.parametrize("entry", ["", ".", "bin"])
def test_build_hint_by_default_never_counts_an_aegis_behind_a_relative_entry(tmp_path, monkeypatch, entry):
    # The default lookup is doctor's (aegis_core.pathlookup): an aegis reached only
    # through an empty or relative entry is one the current directory (a cloned
    # repository) supplies, so the hint agrees with doctor's "not found".
    repo = tmp_path / "repo"
    _stub_aegis(repo)
    _stub_aegis(repo / "bin")
    monkeypatch.chdir(repo)
    env = {"SHELL": "/usr/bin/zsh", "PATH": entry, "HOME": str(tmp_path)}
    text = build_hint(env=env, candidates=[str(tmp_path / "nowhere")], home=str(tmp_path),
                      platform="linux", os_name="posix")
    assert text is not None and "is not installed for this Python" in text


def test_build_hint_by_default_finds_aegis_on_an_absolute_entry(tmp_path):
    program = _stub_aegis(tmp_path / "bin")
    env = {"SHELL": "/usr/bin/zsh", "PATH": str(program.parent), "HOME": str(tmp_path)}
    assert build_hint(env=env, candidates=[str(tmp_path / "nowhere")], home=str(tmp_path),
                      platform="linux", os_name="posix") is None


def test_build_hint_venv_path_with_spaces_is_quoted(tmp_path):
    venv = tmp_path / "my venv"
    bindir = venv / "bin"
    bindir.mkdir(parents=True)
    (bindir / "aegis").write_text("#!/bin/sh\n")
    env = {"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin", "HOME": str(tmp_path)}
    text = build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: None,
                      home=str(tmp_path), platform="linux", os_name="posix",
                      venv_prefix=str(venv))
    vprefix = str(venv).replace("\\", "/")
    assert f"source '{vprefix}/bin/activate'" in text


def test_build_hint_pwsh_venv_activate_is_quoted_call(tmp_path):
    venv = tmp_path / "my venv"
    scripts = venv / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "aegis.exe").write_bytes(b"MZ")
    text = build_hint(env={"PATH": "C:\\Windows"}, candidates=[str(scripts)],
                      which=lambda *_a, **_k: None, home="C:\\Users\\U",
                      platform="win32", os_name="nt", shell="pwsh",
                      venv_prefix=str(venv))
    assert f"& '{venv}\\Scripts\\Activate.ps1'" in text


def _venv_hint(tmp_path, name, bin_name, **kw):
    venv = tmp_path / name
    bindir = venv / bin_name
    bindir.mkdir(parents=True)
    (bindir / "aegis").write_text("#!/bin/sh\n")
    text = build_hint(env={"PATH": "/usr/bin"}, candidates=[str(bindir)],
                      which=lambda *_a, **_k: None, home="/nonexistent",
                      venv_prefix=str(venv), **kw)
    return venv, text


def test_build_hint_pwsh_venv_single_quote_is_doubled(tmp_path):
    venv, text = _venv_hint(tmp_path, "O'Neil env", "Scripts",
                            platform="win32", os_name="nt", shell="pwsh")
    escaped = f"{venv}\\Scripts\\Activate.ps1".replace("'", "''")
    assert f"& '{escaped}'" in text


def test_build_hint_pwsh_on_posix_venv_uses_activate_ps1(tmp_path):
    # pwsh has no `source`; the venv ships bin/Activate.ps1 on POSIX.
    venv, text = _venv_hint(tmp_path, "my venv", "bin",
                            platform="linux", os_name="posix", shell="pwsh")
    assert f"& '{venv}/bin/Activate.ps1'" in text
    assert "source" not in text


def test_build_hint_fish_venv_with_space_is_quoted(tmp_path):
    venv, text = _venv_hint(tmp_path, "my venv", "bin",
                            platform="linux", os_name="posix", shell="fish")
    vprefix = str(venv).replace("\\", "/")
    assert f"source '{vprefix}/bin/activate.fish'" in text


def test_build_hint_git_bash_venv_with_space_is_quoted(tmp_path):
    venv, text = _venv_hint(tmp_path, "my venv", "Scripts",
                            platform="win32", os_name="nt", shell="bash")
    from aegis_cli.pathcheck import _msys_path
    assert f"source '{_msys_path(str(venv))}/Scripts/activate'" in text


def test_build_hint_empty_path_reports_install_dir(tmp_path):
    home, bindir = _bin_with_aegis(tmp_path)
    env = {"SHELL": "/usr/bin/zsh", "PATH": "", "HOME": str(home)}
    text = build_hint(env=env, candidates=[str(bindir)], which=lambda *_a, **_k: None,
                      home=str(home), platform="linux", os_name="posix", venv_prefix=None)
    assert text is not None
    assert "already on PATH" not in text
    assert 'export PATH="$HOME/.local/bin:$PATH"' in text


def test_build_hint_windows_uses_python_not_python3(tmp_path):
    home = tmp_path
    (tmp_path / "aegis.exe").write_bytes(b"MZ")
    env = {"PATH": "C:\\Windows"}
    text = build_hint(env=env, candidates=[str(tmp_path)], which=lambda *_a, **_k: None,
                      home=str(home), platform="win32", os_name="nt")
    assert text is not None
    assert f"{tmp_path / 'aegis.exe'} <command>" in text
    assert "-m aegis_cli" not in text

def test_scripts_dir_ignores_an_unrelated_script(tmp_path):
    # v4 installs only `aegis`; an unrelated script is not where aegis is.
    (tmp_path / "foreign-tool").write_text("#!/bin/sh\n")
    (tmp_path / "foreign-tool.exe").write_bytes(b"MZ")
    assert scripts_dir([str(tmp_path)]) is None


def test_build_hint_is_not_silenced_by_an_unrelated_tool_on_path(tmp_path):
    env = {"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin", "HOME": str(tmp_path)}
    text = build_hint(env=env, candidates=[str(tmp_path)],
                      which=lambda cmd, **_k: "/usr/bin/foreign-tool" if cmd == "foreign-tool" else None,
                      home=str(tmp_path), platform="linux", os_name="posix")
    assert text is not None and "The 'aegis' command is not installed" in text


# ── module entry points ──────────────────────────────────────────────────────

def test_python_m_aegis_cli_runs():
    proc = subprocess.run([sys.executable, "-m", "aegis_cli", "--help"],
                          cwd=str(REPO), capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    assert proc.returncode == 0, proc.stderr
    assert "usage: aegis" in proc.stdout or "usage: aegis" in proc.stdout


def test_pathcheck_on_path_handles_windows_colons():
    """on_path with sep=';' should not corrupt Windows drive paths containing colons."""
    from aegis_cli.pathcheck import on_path
    path_env = r"C:\Python312\Scripts;C:\Windows\System32"
    assert on_path(r"C:\Python312\Scripts", path_env, sep=";", casefold=True)


# ── macOS: pip --user puts aegis in ~/Library/Python/X.Y/bin (emulated darwin) ──

_PY = f"{sys.version_info[0]}.{sys.version_info[1]}"
_ON_MAC = pytest.mark.skipif(os.name == "nt", reason="emulates a macOS (POSIX) shell and home directory")


@pytest.fixture
def mac(tmp_path, monkeypatch):
    """A macOS user whose `pip3 install --user aegis-guardrails` put the script in
    ~/Library/Python/X.Y/bin (field report: Kiro's shell could not find `aegis`).

    sysconfig answers for the Python running the tests, so it stands in for a framework
    build's own scripts directory, which holds no aegis here."""
    import aegis_cli.pathcheck as pathcheck

    home = tmp_path / "Users" / "dev"
    user_bin = home / "Library" / "Python" / _PY / "bin"
    user_bin.mkdir(parents=True)
    (user_bin / "aegis").write_text("#!/bin/sh\n")
    framework_bin = tmp_path / "Library" / "Frameworks" / "Python.framework" / "Versions" / _PY / "bin"
    framework_bin.mkdir(parents=True)
    monkeypatch.setattr(pathcheck.sysconfig, "get_path", lambda *_a, **_k: str(framework_bin))
    monkeypatch.setattr(pathcheck.sys, "platform", "darwin")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("ZDOTDIR", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return home, user_bin


def _mac_hint(home, shell):
    return build_hint(env={"SHELL": shell, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                      which=lambda *_a, **_k: None, home=str(home), os_name="posix", venv_prefix=None)


@_ON_MAC
def test_on_macos_the_candidates_include_the_pip_user_scripts_dir(mac):
    from aegis_cli.pathcheck import default_candidates

    home, user_bin = mac
    assert str(user_bin) in default_candidates()


def test_off_macos_the_library_dir_is_never_a_candidate(tmp_path, monkeypatch):
    from aegis_cli.pathcheck import default_candidates

    monkeypatch.setattr("aegis_cli.pathcheck.sys.platform", "linux")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert str(tmp_path / "Library" / "Python" / _PY / "bin") not in default_candidates()


@_ON_MAC
@pytest.mark.parametrize("shell, rc, line", [
    ("/bin/zsh", "~/.zshrc", f'export PATH="$HOME/Library/Python/{_PY}/bin:$PATH"'),
    ("/bin/bash", "~/.bash_profile", f'export PATH="$HOME/Library/Python/{_PY}/bin:$PATH"'),
    ("/opt/homebrew/bin/fish", "~/.config/fish/config.fish", f'fish_add_path "$HOME/Library/Python/{_PY}/bin"'),
])
def test_the_macos_hint_names_the_user_scripts_dir_and_the_exact_rc_line(mac, shell, rc, line):
    home, user_bin = mac
    text = _mac_hint(home, shell)
    lines = text.splitlines()
    assert lines[0] == f"ℹ️  'aegis' was installed to {user_bin}, which is not on your {shell.rsplit('/', 1)[1]} PATH."
    assert lines[1] == (f"    On macOS, pip install --user puts commands in ~/Library/Python/{_PY}/bin, "
                        "which is not on PATH by default.")
    assert lines[2] == f"    Add this line to {rc}, then open a new terminal:"
    assert lines[3] == f"      {line}"
    assert lines[4] == "    An IDE or desktop app started before this change keeps its old PATH: restart it."
    assert lines[5] == f"    Until then you can run it by its full path: {user_bin / 'aegis'} <command>"


@_ON_MAC
def test_the_macos_line_appears_only_for_the_library_dir(mac, tmp_path):
    home, _user_bin = mac
    other = home / ".local" / "bin"
    other.mkdir(parents=True)
    (other / "aegis").write_text("#!/bin/sh\n")
    text = build_hint(env={"SHELL": "/bin/zsh", "PATH": "/usr/bin"}, candidates=[str(other)],
                      which=lambda *_a, **_k: None, home=str(home), os_name="posix", venv_prefix=None)
    assert "Library/Python" not in text
    assert 'export PATH="$HOME/.local/bin:$PATH"' in text


def test_off_macos_the_hint_has_no_macos_line(tmp_path):
    home = tmp_path / "home"
    lib = home / "Library" / "Python" / _PY / "bin"
    lib.mkdir(parents=True)
    (lib / "aegis").write_text("#!/bin/sh\n")
    text = build_hint(env={"SHELL": "/usr/bin/zsh", "PATH": "/usr/bin"}, candidates=[str(lib)],
                      which=lambda *_a, **_k: None, home=str(home), platform="linux", os_name="posix",
                      venv_prefix=None)
    assert "On macOS" not in text and "IDE" not in text
