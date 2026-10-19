"""`aegis rule insight enable` writes the UserPromptSubmit insight hook under the host-plane
contract, and `aegis hook uninstall --host` removes it (R-structure-1).

- a file Aegis cannot read back whole (JSONC, BOM, bad UTF-8, NaN, wrong shape), a
  symlink, a hard link or a FIFO is refused: exit 1, bytes identical, no backup, no
  ~/.aegis/link.key, no temp file;
- a valid file keeps every foreign key and entry, is backed up once (0600), and a second
  run is a no-op;
- the written command names this interpreter and import root, so a decoy ``python3`` on
  PATH and a planted ``aegis_cli/`` in the working directory never run;
- the probe before the write only imports the hook module: it records nothing.

Every test uses a fake HOME and never runs a host CLI.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import threading

import pytest

from conftest import symlink_or_skip

from aegis_cli.hooks import registrar
from aegis_core.insights import host_capture_status, read_insight_rows

SETTINGS = {"claude-code": (".claude", "settings.json"), "codex-cli": (".codex", "hooks.json")}
HOSTS = tuple(SETTINGS)
FOREIGN = b'{"permissions": {"allow": ["Bash(ls)"]}, "env": {"A": "1"}'
LEGACY = "python3 -I -m aegis_cli.hooks.insights --host claude-code --excerpts"
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="runs POSIX shell shims")


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    (ws / ".aegis" / "rules").mkdir(parents=True)
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    # Codex insight capture is refused on Windows; tests that want that path patch it back.
    monkeypatch.setattr(registrar, "_windows", lambda: False)
    subprocess.run(["git", "init", "-q", str(ws)], check=True)
    monkeypatch.chdir(ws)
    return argparse.Namespace(home=home, ws=ws, tmp=tmp_path)


def settings(env, host: str) -> Path:
    return env.home.joinpath(*SETTINGS[host])


def enable(capsys, host: str, *extra: str, as_json: bool = True):
    from aegis_cli.cli import main

    rc = main(["rule", "insight", "enable", "--host", host, *(["--json"] if as_json else []), *extra])
    cap = capsys.readouterr()
    return rc, (json.loads(cap.out) if as_json and cap.out.strip() else cap.out), cap.err


def hook_uninstall(capsys, host: str):
    from aegis_cli.cli import main

    rc = main(["hook", "uninstall", "--host", host, "--json"])
    cap = capsys.readouterr()
    return rc, json.loads(cap.out) if cap.out.strip() else None, cap.err


def backups(env):
    root = env.home / ".aegis" / "backups"
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


def insight_groups(env, host):
    data = json.loads(settings(env, host).read_text(encoding="utf-8"))
    return data["hooks"]["UserPromptSubmit"]


def assert_untouched(env, host, path: Path, before: bytes):
    assert path.read_bytes() == before
    assert not (env.home / ".aegis" / "link.key").exists()
    assert backups(env) == []
    assert not (env.home / ".aegis" / "insights").exists()
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name]


def write(path: Path, raw: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return path


# ── (a) files Aegis cannot read back whole are refused ──────────────────────

UNREADABLE = {
    "trailing-comma": (FOREIGN + b",}\n", "not valid JSON"),
    "comment": (b"// mine\n" + FOREIGN + b"}\n", "not valid JSON"),
    "bom": (b"\xef\xbb\xbf" + FOREIGN + b"}\n", "BOM"),
    "bad-utf8": (b'{"permissions": {}, "env": {"A": "\xff"}}\n', "UTF-8"),
    "nan": (b'{"permissions": {}, "env": {}, "x": NaN}\n', "NaN"),
    "list": (b'[{"permissions": {}}]\n', "JSON object"),
    "hooks-list": (b'{"permissions": {}, "hooks": ["x"]}\n', "hooks"),
    "ups-object": (b'{"permissions": {}, "hooks": {"UserPromptSubmit": {}}}\n', "UserPromptSubmit"),
}


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("case", list(UNREADABLE))
def test_unreadable_file_is_refused(env, capsys, host, case):
    raw, cause = UNREADABLE[case]
    path = write(settings(env, host), raw)
    rc, doc, _ = enable(capsys, host)
    assert rc == 1 and doc["status"] == "error"
    assert cause in doc["error"] and "left unchanged" in doc["error"]
    assert_untouched(env, host, path, raw)


# ── (b) links ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", HOSTS)
def test_symlinked_file_is_refused_and_its_target_kept(env, capsys, host):
    target = write(env.tmp / "dotfiles" / "settings.json", FOREIGN + b"}\n")
    path = settings(env, host)
    path.parent.mkdir(parents=True)
    symlink_or_skip(target, path)
    rc, doc, _ = enable(capsys, host)
    assert rc == 1 and "symlink" in doc["error"]
    # Windows readlink returns the \\?\ form of an absolute target, so compare identity.
    assert path.is_symlink() and os.path.samefile(path, target)
    assert target.read_bytes() == FOREIGN + b"}\n"
    assert not (env.home / ".aegis" / "link.key").exists() and backups(env) == []


@pytest.mark.parametrize("host", HOSTS)
def test_hard_linked_file_is_refused(env, capsys, host):
    path = write(settings(env, host), FOREIGN + b"}\n")
    try:
        os.link(path, env.tmp / "other-name.json")
    except (OSError, NotImplementedError):
        pytest.skip("hard links are unavailable")
    rc, doc, _ = enable(capsys, host)
    assert rc == 1 and "hard link" in doc["error"]
    assert path.read_bytes() == FOREIGN + b"}\n"
    assert not (env.home / ".aegis" / "link.key").exists() and backups(env) == []


def test_status_follows_a_link_as_the_host_does(env):
    path = settings(env, "claude-code")
    path.parent.mkdir(parents=True)
    symlink_or_skip(env.tmp / "missing.json", path)
    assert host_capture_status("claude-code", home=env.home)["status"] == "disabled"
    path.unlink()
    held = {"hooks": {"UserPromptSubmit": [{"matcher": "", "hooks": [{"type": "command", "command": LEGACY}]}]}}
    target = write(env.tmp / "dotfiles" / "settings.json", json.dumps(held).encode("utf-8"))
    symlink_or_skip(target, path)
    assert host_capture_status("claude-code", home=env.home)["status"] == "enabled_excerpts"


# ── (c) special files ───────────────────────────────────────────────────────

def _in_thread(fn):
    box = {}
    worker = threading.Thread(target=lambda: box.setdefault("value", fn()), daemon=True)
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "hung on a FIFO"
    return box["value"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_fifo_is_refused_promptly_and_reads_disabled(env, capsys):
    path = settings(env, "claude-code")
    path.parent.mkdir(parents=True)
    os.mkfifo(path)
    rc, doc, _ = _in_thread(lambda: enable(capsys, "claude-code"))
    assert rc == 1 and "not a regular file" in doc["error"]
    status = _in_thread(lambda: host_capture_status("claude-code", home=env.home))
    assert status["status"] == "disabled"
    assert not (env.home / ".aegis" / "link.key").exists()


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="chmod 000 does not stop root or Windows")
def test_unreadable_permissions_leave_the_bytes(env, capsys):
    path = write(settings(env, "claude-code"), FOREIGN + b"}\n")
    path.chmod(0)
    try:
        rc, doc, _ = enable(capsys, "claude-code")
    finally:
        path.chmod(0o600)
    assert rc == 1 and "left unchanged" in doc["error"]
    assert path.read_bytes() == FOREIGN + b"}\n"
    assert not (env.home / ".aegis" / "link.key").exists()


# ── (d) a valid file keeps everything foreign and is backed up once ──────────

def _foreign_settings() -> dict:
    return {"permissions": {"allow": ["Bash(ls)"]}, "env": {"A": "1"},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/mine"}]}],
                      "UserPromptSubmit": [{"matcher": "", "hooks": [{"type": "command", "command": "echo mine"}]}]}}


@pytest.mark.parametrize("host", HOSTS)
def test_valid_file_keeps_foreign_entries_and_one_backup(env, capsys, host):
    original = json.dumps(_foreign_settings(), indent=4).encode("utf-8")
    path = write(settings(env, host), original)
    rc, doc, _ = enable(capsys, host)
    assert rc == 0, doc
    data = json.loads(path.read_text(encoding="utf-8"))
    foreign = _foreign_settings()
    assert {k: data[k] for k in ("permissions", "env")} == {k: foreign[k] for k in ("permissions", "env")}
    assert data["hooks"]["PreToolUse"] == foreign["hooks"]["PreToolUse"]
    groups = data["hooks"]["UserPromptSubmit"]
    assert len(groups) == 2 and groups[0] == foreign["hooks"]["UserPromptSubmit"][0]
    assert groups[1]["matcher"] == "" and len(groups[1]["hooks"]) == 1
    (copy,) = backups(env)
    assert copy.read_bytes() == original and copy.parent.name == "user"
    assert copy.parent.parent.parent == env.home / ".aegis" / "backups"
    assert doc["backup_dir"] == str(copy.parent.parent)
    if os.name != "nt":
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
    assert (env.home / ".aegis" / "link.key").is_file()
    assert not (env.home / ".aegis" / "insights").exists()
    written = path.read_bytes()
    rc, doc, _ = enable(capsys, host)
    assert rc == 0 and doc["backup_dir"] is None
    assert path.read_bytes() == written and len(backups(env)) == 1
    rc, doc, _ = enable(capsys, host, "--excerpts")
    assert rc == 0 and doc["status"] == "enabled_excerpts"
    assert len(backups(env)) == 2 and len(insight_groups(env, host)) == 2


def test_missing_file_is_created_without_a_backup(env, capsys):
    rc, doc, _ = enable(capsys, "claude-code")
    assert rc == 0 and doc["backup_dir"] is None and doc["status"] == "enabled_counters_only"
    assert len(insight_groups(env, "claude-code")) == 1
    assert backups(env) == [] and not (env.home / ".aegis" / "insights").exists()


def test_relative_config_dir_is_ignored(env, capsys, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "rel/cfg")
    rc, doc, _ = enable(capsys, "claude-code")
    assert rc == 0 and doc["config_path"] == str(settings(env, "claude-code"))
    assert not (env.ws / "rel").exists()


# ── (e) the written command runs this interpreter and import root ────────────

def _payload(env) -> str:
    return json.dumps({"prompt": "Please run the unit tests.", "session_id": "launcher-1", "cwd": str(env.ws)})


def _plant_and_decoy(env) -> dict:
    marker = env.tmp / "planted"
    body = f"open({str(marker)!r}, 'w').close()\n"
    pkg = env.ws / "aegis_cli"
    (pkg / "hooks").mkdir(parents=True)
    for rel in ("__init__.py", "hooks/__init__.py", "hooks/insights.py"):
        (pkg / rel).write_text(body + "def main(argv):\n    return 0\n", encoding="utf-8")
    decoys = env.tmp / "decoy"
    decoys.mkdir()
    for name in ("python3", "python"):
        stub = decoys / name
        stub.write_text(f"#!/bin/sh\ntouch '{env.tmp / 'decoy-ran'}'\nexit 97\n", encoding="utf-8")
        stub.chmod(0o755)
    return {"HOME": str(env.home), "PATH": f"{decoys}{os.pathsep}{os.defpath}"}


def _run_written(env, host: str, child_env: dict) -> subprocess.CompletedProcess:
    (group,) = [g for g in insight_groups(env, host) if "aegis_cli.hooks.insights" in json.dumps(g)]
    (handler,) = group["hooks"]
    if host == "claude-code":
        argv = [handler["command"], *handler["args"]]
    else:
        assert "args" not in handler
        argv = ["/bin/sh", "-c", handler["command"]]
    return subprocess.run(argv, input=_payload(env), capture_output=True, text=True, cwd=str(env.ws),
                          env=child_env, timeout=60, check=False)


def _assert_one_heartbeat(env, proc):
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "" and proc.stderr == ""
    rows = read_insight_rows(env.ws, home=env.home)
    assert [r["event"] for r in rows] == ["heartbeat"]
    assert not (env.tmp / "planted").exists() and not (env.tmp / "decoy-ran").exists()


@POSIX_ONLY
@pytest.mark.parametrize("host", HOSTS)
def test_written_command_ignores_decoy_python_and_planted_package(env, capsys, host):
    rc, doc, _ = enable(capsys, host)
    assert rc == 0, doc
    _assert_one_heartbeat(env, _run_written(env, host, _plant_and_decoy(env)))


def _shim(env, monkeypatch) -> str:
    real = os.path.realpath(sys.executable)
    shim = env.tmp / "my py" / "python it"
    shim.parent.mkdir()
    shim.write_text(f"#!/bin/sh\nexec {shlex.quote(real)} \"$@\"\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(shim))
    return str(shim)


@POSIX_ONLY
@pytest.mark.parametrize("host", HOSTS)
def test_interpreter_path_with_spaces_still_runs(env, capsys, monkeypatch, host):
    _shim(env, monkeypatch)
    rc, doc, _ = enable(capsys, host)
    assert rc == 0, doc
    _assert_one_heartbeat(env, _run_written(env, host, _plant_and_decoy(env)))


# ── (f) and (i): hook uninstall removes the entry ───────────────────────────

AEGIS_PRETOOL = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/x/aegis",
                                               "args": ["hook", "run", "pre-tool", "--host", "claude-code"]}]}
MINE = {"matcher": "", "hooks": [{"type": "command", "command": "echo mine"}]}
STOP = [{"hooks": [{"type": "command", "command": "/usr/bin/notify"}]}]


def test_hook_uninstall_removes_insight_and_pretool_entries(env, capsys):
    path = write(settings(env, "claude-code"), json.dumps(
        {"model": "x", "hooks": {"PreToolUse": [AEGIS_PRETOOL], "Stop": STOP, "UserPromptSubmit": [MINE]}}).encode())
    assert enable(capsys, "claude-code")[0] == 0
    rc, doc, err = hook_uninstall(capsys, "claude-code")
    assert rc == 0, err
    by_scope = {r["scope"]: (r["status"], r["insight_capture"]) for r in doc["results"]}
    assert by_scope == {"user": ("removed", "removed"), "project": ("absent", "absent")}
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "model": "x", "hooks": {"Stop": STOP, "UserPromptSubmit": [MINE]}}
    assert host_capture_status("claude-code", home=env.home)["status"] == "disabled"


def test_hook_uninstall_of_a_file_with_only_a_foreign_prompt_hook_changes_nothing(env, capsys):
    raw = json.dumps({"hooks": {"UserPromptSubmit": [MINE]}}).encode()
    path = write(settings(env, "claude-code"), raw)
    rc, doc, err = hook_uninstall(capsys, "claude-code")
    assert rc == 0, err
    assert {r["insight_capture"] for r in doc["results"]} == {"absent"}
    assert path.read_bytes() == raw and backups(env) == []


def test_hook_uninstall_of_an_insight_only_file_writes_it_with_a_backup(env, capsys):
    assert enable(capsys, "codex-cli")[0] == 0
    rc, doc, err = hook_uninstall(capsys, "codex-cli")
    assert rc == 0, err
    assert doc["results"][0]["status"] == "absent" and doc["results"][0]["insight_capture"] == "removed"
    assert json.loads(settings(env, "codex-cli").read_text(encoding="utf-8")) == {}
    assert len(backups(env)) == 1


def test_legacy_entry_is_recognised_upgraded_and_removed(env, capsys):
    legacy = {"matcher": "", "hooks": [{"type": "command", "command": LEGACY}]}
    path = write(settings(env, "claude-code"), json.dumps({"hooks": {"UserPromptSubmit": [legacy, MINE]}}).encode())
    assert host_capture_status("claude-code", home=env.home)["status"] == "enabled_excerpts"
    assert enable(capsys, "claude-code")[0] == 0
    groups = insight_groups(env, "claude-code")
    assert groups[0] == MINE and len(groups) == 2 and "python3 -I -m" not in path.read_text(encoding="utf-8")
    assert host_capture_status("claude-code", home=env.home)["status"] == "enabled_counters_only"
    upgraded = path.read_bytes()
    assert enable(capsys, "claude-code")[0] == 0
    assert path.read_bytes() == upgraded
    # An exec-form entry next to a legacy one: both are Aegis's and both go.
    data = json.loads(upgraded)
    data["hooks"]["UserPromptSubmit"].insert(0, legacy)
    path.write_bytes(json.dumps(data).encode())
    rc, doc, err = hook_uninstall(capsys, "claude-code")
    assert rc == 0, err
    assert json.loads(path.read_text(encoding="utf-8")) == {"hooks": {"UserPromptSubmit": [MINE]}}


# ── (g) the per-host command forms ──────────────────────────────────────────

def test_codex_on_windows_is_refused_before_any_write(env, capsys, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    rc, doc, _ = enable(capsys, "codex-cli")
    assert rc == 1 and "%COMSPEC%" in doc["error"]
    assert not settings(env, "codex-cli").exists() and not (env.home / ".aegis").exists()


@POSIX_ONLY
def test_claude_gets_the_exec_form_even_on_windows(env, capsys, monkeypatch):
    shim = _shim(env, monkeypatch)
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    assert enable(capsys, "claude-code")[0] == 0
    (group,) = insight_groups(env, "claude-code")
    (handler,) = group["hooks"]
    root = str(Path(registrar.__file__).resolve().parents[2])
    assert handler == {"type": "command", "command": shim,
                       "args": ["-I", "-c", registrar.INSIGHT_RUNNER, root, "--host", "claude-code", "--no-excerpts"]}


@POSIX_ONLY
def test_codex_on_posix_gets_the_shell_string_and_the_trust_step(env, capsys):
    rc, out, err = enable(capsys, "codex-cli", "--excerpts", as_json=False)
    assert rc == 0, err
    (group,) = insight_groups(env, "codex-cli")
    root = str(Path(registrar.__file__).resolve().parents[2])
    assert group["hooks"] == [{"type": "command", "command": shlex.join(
        [sys.executable, "-I", "-c", registrar.INSIGHT_RUNNER, root, "--host", "codex-cli", "--excerpts"])}]
    assert registrar.CODEX_TRUST_STEP in out


# ── (j) the interpreter must be absolute ────────────────────────────────────

@pytest.mark.parametrize("python", ["", "python3"], ids=["empty", "relative"])
def test_non_absolute_interpreter_is_refused_and_nothing_written(env, monkeypatch, python):
    from aegis_cli.hooks.insights import enable_insight_hook

    monkeypatch.setattr(sys, "executable", python)
    with pytest.raises(OSError, match="interpreter|absolute"):
        enable_insight_hook("claude-code", home=env.home)
    assert not settings(env, "claude-code").exists() and not (env.home / ".aegis").exists()


# ── guard: the per-prompt hook module stays light ──────────────────────────

def test_hook_module_does_not_import_the_registrar():
    root = str(Path(registrar.__file__).resolve().parents[2])
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import aegis_cli.hooks.insights; "
            "print('aegis_cli.hooks.registrar' in sys.modules)")
    proc = subprocess.run([sys.executable, "-I", "-c", code, root], capture_output=True, text=True, timeout=60,
                          check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "False"
