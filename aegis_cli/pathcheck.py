"""Shell-aware PATH guidance for the aegis console script (BUG-041).

`pip install --user` puts `aegis` in the user scripts directory, which is often
not on PATH. zsh in particular never reads ~/.profile, where Debian/Ubuntu add
~/.local/bin. This module finds where the script actually is and prints the
one line the user needs, in their shell's syntax and for the right rc file.

It only reports and never edits dotfiles; `aegis doctor` and the end of
`aegis init` print its hint.
"""
from __future__ import annotations

import os
import shlex
import sys
import sysconfig
from typing import Callable, Iterable, Mapping

from aegis_core import pathlookup

KNOWN_SHELLS = ("zsh", "bash", "fish", "pwsh")


def detect_shell(env: Mapping[str, str] | None = None, os_name: str | None = None) -> str:
    """Return zsh, bash, fish, pwsh or unknown from $SHELL."""
    env = os.environ if env is None else env
    os_name = os.name if os_name is None else os_name
    raw = env.get("SHELL", "")
    # Split on both separators: $SHELL can be a Windows path even off Windows.
    name = raw.replace("\\", "/").rsplit("/", 1)[-1].lstrip("-").lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name in ("pwsh", "powershell"):
        return "pwsh"
    if name in KNOWN_SHELLS:
        return name
    if not name and os_name == "nt":
        # cmd.exe and PowerShell set no SHELL; Git Bash sets /usr/bin/bash.
        return "pwsh"
    return "unknown"


def rc_file(shell: str, env: Mapping[str, str] | None = None,
            platform: str | None = None) -> str | None:
    """Startup file the PATH line belongs in, or None when there isn't one."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    if shell == "zsh":
        zdotdir = env.get("ZDOTDIR")
        return f"{zdotdir.rstrip('/')}/.zshrc" if zdotdir else "~/.zshrc"
    if shell == "bash":
        # macOS Terminal opens login shells, which read ~/.bash_profile.
        return "~/.bash_profile" if platform == "darwin" else "~/.bashrc"
    if shell == "fish":
        # fish reads $XDG_CONFIG_HOME/fish; the spec ignores relative values.
        xdg = env.get("XDG_CONFIG_HOME", "")
        if xdg and os.path.isabs(xdg):
            return f"{xdg.rstrip('/')}/fish/config.fish"
        return "~/.config/fish/config.fish"
    if shell == "pwsh" and not platform.startswith("win"):
        # Off Windows there is no persistent user Path variable; use the profile.
        return "$PROFILE"
    return None


def _norm(path: str, casefold: bool) -> str:
    path = os.path.normpath(os.path.expanduser(path)) if path else ""
    path = path.rstrip("/\\") or path
    return path.casefold() if casefold else path


def on_path(directory: str, path_env: str, sep: str = os.pathsep,
            casefold: bool = os.name == "nt") -> bool:
    """True if directory is an exact entry of path_env (not a substring)."""
    target = _norm(directory, casefold)
    raw = path_env.split(sep)
    raw_entries = []
    i = 0
    while i < len(raw):
        if sep == ":" and len(raw[i]) == 1 and raw[i].isalpha() and i + 1 < len(raw) and (raw[i+1].startswith("/") or raw[i+1].startswith("\\")):
            raw_entries.append(f"{raw[i]}:{raw[i+1]}")
            i += 2
        else:
            raw_entries.append(raw[i])
            i += 1
    entries = []
    for e in raw_entries:
        if sep == ";" and ":" in e:
            sub = e.split(":")
            j = 0
            while j < len(sub):
                if len(sub[j]) == 1 and sub[j].isalpha() and j + 1 < len(sub) and (sub[j+1].startswith("/") or sub[j+1].startswith("\\")):
                    entries.append(f"{sub[j]}:{sub[j+1]}")
                    j += 2
                else:
                    if sub[j]:
                        entries.append(sub[j])
                    j += 1
        elif sep == ":" and ";" in e:
            entries.extend(e.split(";"))
        else:
            entries.append(e)
    return any(_norm(entry, casefold) == target
               for entry in entries if entry)


def _home_relative(directory: str, home: str, casefold: bool = False) -> str | None:
    """'/rest' if directory is under home (either separator), else None."""
    d = directory.replace("\\", "/").rstrip("/")
    h = home.replace("\\", "/").rstrip("/")
    dc, hc = (d.casefold(), h.casefold()) if casefold else (d, h)
    if h and (dc == hc or dc.startswith(hc + "/")):
        return d[len(h):]
    return None


def _msys_path(directory: str) -> str:
    """C:\\x\\y -> /c/x/y. A raw drive path would be split on ':' by bash."""
    d = directory.replace("\\", "/")
    if len(d) >= 2 and d[1] == ":" and d[0].isalpha():
        return f"/{d[0].lower()}{d[2:]}"
    return d


def remedy(shell: str, directory: str, home: str, os_name: str | None = None) -> str:
    """The single line that puts directory on PATH for shell."""
    os_name = os.name if os_name is None else os_name
    if shell == "pwsh" and os_name == "nt":
        return ('[Environment]::SetEnvironmentVariable("Path", '
                f'"{directory};" + [Environment]::GetEnvironmentVariable("Path", "User"), "User")')
    rel = _home_relative(directory, home, casefold=os_name == "nt")
    if rel is not None:
        shown = f"$HOME{rel}"
    else:
        shown = _msys_path(directory) if os_name == "nt" else directory
    if shell == "pwsh":
        return f'$env:PATH = "{shown}:" + $env:PATH'
    if shell == "fish":
        return f'fish_add_path "{shown}"'
    return f'export PATH="{shown}:$PATH"'


def macos_user_scripts(home: str | None = None) -> str:
    """~/Library/Python/X.Y/bin: where ``pip install --user`` puts commands on macOS.

    That is the user scheme of the framework builds (python.org, Homebrew and the Xcode
    command line tools Python), and macOS puts no such directory on PATH.
    """
    home = os.path.expanduser("~") if home is None else home
    return os.path.join(home, "Library", "Python", f"{sys.version_info[0]}.{sys.version_info[1]}", "bin")


def default_candidates() -> list[str]:
    """Script directories pip may have used for this interpreter."""
    out: list[str] = []
    schemes = [None, f"{os.name}_user"]
    if sys.platform == "darwin":
        schemes.append("osx_framework_user")
    for scheme in schemes:
        try:
            path = sysconfig.get_path("scripts", scheme) if scheme else sysconfig.get_path("scripts")
        except KeyError:
            continue
        if path and path not in out:
            out.append(path)
    if sys.platform == "darwin":
        # Named outright, not only through sysconfig: an interpreter that is not a framework
        # build (pyenv, uv) maps its user scheme to ~/.local, yet a `pip3 install --user` by
        # the system or Homebrew python3 put aegis in ~/Library/Python/X.Y/bin.
        user = macos_user_scripts()
        if user not in out:
            out.append(user)
    return out


def scripts_dir(candidates: Iterable[str] | None = None, cmd_name: str = "aegis") -> str | None:
    """First candidate directory that contains the ``cmd_name`` console script.

    Only that exact console-script name counts; unrelated executables are ignored.
    """
    for directory in (default_candidates() if candidates is None else candidates):
        for name in (cmd_name, cmd_name + ".exe"):
            if os.path.isfile(os.path.join(directory, name)):
                return directory
    return None


def _script_path(directory: str, cmd_name: str, os_name: str) -> str:
    """The console script scripts_dir found, quoted when its path has a space."""
    names = (cmd_name + ".exe", cmd_name) if os_name == "nt" else (cmd_name, cmd_name + ".exe")
    path = next((os.path.join(directory, n) for n in names if os.path.isfile(os.path.join(directory, n))),
                os.path.join(directory, names[0]))
    return f'"{path}"' if " " in path else path


def _active_venv_prefix() -> str | None:
    """sys.prefix when running inside a virtual environment, else None."""
    base = getattr(sys, "base_prefix", sys.prefix)
    return sys.prefix if sys.prefix != base else None


_UNSET = object()


def build_hint(env: Mapping[str, str] | None = None,
               candidates: Iterable[str] | None = None,
               which: Callable[..., str | None] | None = None,
               home: str | None = None,
               platform: str | None = None,
               os_name: str | None = None,
               shell: str | None = None,
               venv_prefix: object = _UNSET,
               cmd_name: str = "aegis") -> str | None:
    """Human-readable remedy, or None when ``cmd_name`` (the aegis command) already resolves.

    It resolves through the lookup doctor uses (aegis_core.pathlookup: absolute PATH
    entries only), so the hint never calls resolvable what doctor reports missing.
    """
    env = os.environ if env is None else env
    which = pathlookup.which if which is None else which
    home = os.path.expanduser("~") if home is None else home
    platform = sys.platform if platform is None else platform
    os_name = os.name if os_name is None else os_name
    if venv_prefix is _UNSET:
        venv_prefix = _active_venv_prefix()
    path_val = env.get("PATH", "")
    if which(cmd_name, path=path_val):
        return None

    pkg_name = "aegis-guardrails"
    py = "python" if os_name == "nt" else "python3"
    directory = scripts_dir(candidates if candidates is not None else default_candidates(), cmd_name=cmd_name)
    if directory is None:
        return (f"ℹ️  The '{cmd_name}' command is not installed for this Python.\n"
                f"    Install it with: {py} -m pip install {pkg_name}\n"
                f"    (or pipx install {pkg_name})")
    # The stopgap names the installed script by its full path. `python -m aegis_cli` would
    # put the current directory first on sys.path and import a repository's own aegis_* code.
    fallback = f"    Until then you can run it by its full path: {_script_path(directory, cmd_name, os_name)} <command>"

    shell = shell or detect_shell(env, os_name=os_name)
    sep = ";" if os_name == "nt" else ":"
    if on_path(directory, env.get("PATH", ""), sep=sep, casefold=os_name == "nt"):
        return (f"ℹ️  '{cmd_name}' is in {directory}, which is already on PATH.\n"
                "    Open a new terminal (or run `hash -r` / `rehash`) so the shell picks it up.\n"
                + fallback)

    if venv_prefix and _home_relative(directory, str(venv_prefix),
                                      casefold=os_name == "nt") is not None:
        # Don't tell the user to put a venv's bin/ in a global rc file.
        if shell == "pwsh":
            # pwsh has no `source`; every venv ships Activate.ps1.
            ps1 = (f"{venv_prefix}\\Scripts\\Activate.ps1" if os_name == "nt"
                   else f"{venv_prefix}/bin/Activate.ps1").replace("'", "''")
            activate = f"& '{ps1}'"
        elif os_name == "nt":
            activate = "source " + shlex.quote(f"{_msys_path(str(venv_prefix))}/Scripts/activate")
        else:
            vprefix = str(venv_prefix).replace("\\", "/")
            script = f"{vprefix}/bin/activate" + (".fish" if shell == "fish" else "")
            activate = "source " + shlex.quote(script)
        return (f"ℹ️  '{cmd_name}' is installed in the virtual environment {venv_prefix},\n"
                "    which is not active in this shell. Activate it first:\n"
                f"      {activate}\n"
                + fallback)

    line = remedy(shell, directory, home, os_name=os_name)
    rc = rc_file(shell, env=env, platform=platform)
    shell_label = shell if shell != "unknown" else "shell"
    lines = [f"ℹ️  '{cmd_name}' was installed to {directory}, which is not on your {shell_label} PATH."]
    on_mac = platform == "darwin" and _norm(directory, False) == _norm(macos_user_scripts(home), False)
    if on_mac:
        shown = "~" + (_home_relative(directory, home) or "")
        lines.append(f"    On macOS, pip install --user puts commands in {shown}, which is not on PATH by default.")
    if shell == "pwsh" and os_name == "nt":
        lines.append("    Run this once in PowerShell, then open a new terminal:")
    elif rc:
        lines.append(f"    Add this line to {rc}, then open a new terminal:")
    else:
        lines.append("    Add the equivalent of this line to your shell's startup file, "
                     "then open a new terminal:")
    lines.append(f"      {line}")
    if on_mac:
        # The field case: an IDE agent's shell had no aegis. An app keeps the environment it
        # started with, so the rc line reaches it only after a restart.
        lines.append("    An IDE or desktop app started before this change keeps its old PATH: restart it.")
    lines.append(fallback)
    return "\n".join(lines)
