"""`aegis hook install --host <h>` / `aegis hook uninstall --host <h>` (v4.1 spec §2 Registration).

The registration writes one PreToolUse group per host into a file the user owns, so:
- the exact group per host is pinned here (Claude exec form, Codex and Antigravity shell
  forms, every timeout 10 s);
- the merge keeps everything else, is atomic, refuses unparseable, symlinked and
  multiply-linked files, backs the old bytes up to ~/.aegis/backups/<stamp>/, and
  re-parses what it wrote;
- Aegis entries are found by their command (absolute aegis + ``hook run``), never by
  position, and a re-install with the same aegis is byte-stable (Codex trust);
- a host never gets a second Aegis entry at the other scope;
- Codex also gets ~/.codex/rules/aegis.rules from the shared BLOCK_SET.

Every test uses a fake HOME and a fake ``aegis`` file; no host CLI is ever run.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict

import pytest

from aegis_cli.hooks import registrar
from aegis_cli.install_hosts import InstallError
from aegis_core import command_safety


#: The aegis path the registration tests write when the stub's own path is outside the
#: shell-form charset, as every native Windows path is ('\\' and ':'), which makes Codex
#: hooks unavailable there (test_codex_on_windows_*). A forward-slash UNC path is absolute
#: on every platform and Python and inside the charset; the registrar never opens it.
PLAIN_AEGIS = "//aegis.test/tools/bin/aegis"


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    (repo / ".aegis" / "rules").mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # Windows finds a program on PATH only under a PATHEXT name.
    stub = bindir / ("aegis.exe" if os.name == "nt" else "aegis")
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o755)
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    aegis = str(stub) if registrar.AEGIS_PATH_CHARSET.fullmatch(str(stub)) else PLAIN_AEGIS
    return argparse.Namespace(home=home, repo=repo, aegis=aegis, stub=str(stub), environ={}, tmp=tmp_path)


def install(env, host, scope="user", **kw):
    return registrar.install(host, scope, home=env.home, root=env.repo, aegis=env.aegis,
                             environ=env.environ, **kw)


def uninstall(env, host, scope=None, **kw):
    return registrar.uninstall(host, scope, home=env.home, root=env.repo, environ=env.environ, **kw)


def load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def backups(env):
    root = env.home / ".aegis" / "backups"
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


# ── the exact registration forms ────────────────────────────────────────────

def test_claude_user_scope_writes_the_exec_form_group_and_no_permission_rules(env):
    result = install(env, "claude-code")
    path = env.home / ".claude" / "settings.json"
    assert result.status == "added" and result.path == path
    assert load(path) == {"hooks": {"PreToolUse": [{
        "matcher": "Bash|PowerShell|Monitor|Write|Edit|NotebookEdit",
        "hooks": [{"type": "command", "command": env.aegis,
                   "args": ["hook", "run", "pre-tool", "--host", "claude-code"], "timeout": 10}]}]}}


def test_claude_project_scope_writes_the_repository_settings_file(env):
    result = install(env, "claude-code", "project")
    assert result.path == env.repo / ".claude" / "settings.json"
    assert load(result.path)["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == env.aegis
    assert not (env.home / ".claude").exists()


def test_claude_config_dir_moves_the_user_settings_file(env):
    custom = env.tmp / "claude-cfg"
    env.environ = {"CLAUDE_CONFIG_DIR": str(custom)}
    assert install(env, "claude-code").path == custom / "settings.json"


def test_codex_user_scope_writes_the_shell_form_group_and_the_rules_file(env):
    result = install(env, "codex-cli")
    path = env.home / ".codex" / "hooks.json"
    assert result.path == path
    assert load(path) == {"hooks": {"PreToolUse": [{
        "matcher": "Bash|apply_patch",
        "hooks": [{"type": "command", "command": f"{env.aegis} hook run pre-tool --host codex-cli",
                   "timeout": 10}]}]}}
    rules = env.home / ".codex" / "rules" / "aegis.rules"
    assert result.rules_path == rules and result.rules_status == "added"
    assert rules.read_text(encoding="utf-8") == registrar.codex_rules_text()
    assert not (env.home / ".codex" / "rules" / "default.rules").exists()


def test_codex_home_moves_the_user_files(env):
    custom = env.tmp / "codex-home"
    env.environ = {"CODEX_HOME": str(custom)}
    result = install(env, "codex-cli")
    assert result.path == custom / "hooks.json"
    assert result.rules_path == custom / "rules" / "aegis.rules"


def test_codex_project_scope_writes_the_repository_hooks_file(env):
    assert install(env, "codex-cli", "project").path == env.repo / ".codex" / "hooks.json"


def test_antigravity_user_scope_writes_the_aegis_group_with_the_exit_mapping_wrapper(env):
    if os.name == "nt":
        pytest.skip("agy hooks are unavailable on Windows")
    result = install(env, "antigravity")
    path = env.home / ".gemini" / "config" / "hooks.json"
    assert result.path == path
    assert load(path) == {"aegis": {"PreToolUse": [{
        "matcher": "run_command|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [{"type": "command",
                   "command": f"{env.aegis} hook run pre-tool --host antigravity >/dev/null; "
                              "[ $? -eq 75 ] && exit 1; exit 0",
                   "timeout": 10}]}]}}


def test_antigravity_project_scope_writes_dot_agents_hooks_json(env):
    if os.name == "nt":
        pytest.skip("agy hooks are unavailable on Windows")
    assert install(env, "antigravity", "project").path == env.repo / ".agents" / "hooks.json"


def test_antigravity_on_windows_is_unavailable_and_installs_nothing(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    result = install(env, "antigravity")
    assert result.status == "unavailable"
    assert "Windows" in result.detail
    assert not (env.home / ".gemini").exists()


@pytest.mark.parametrize("host", ["codex-cli", "antigravity"])
def test_a_shell_form_refuses_an_aegis_path_outside_the_safe_charset(env, host, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: False)
    spaced = env.tmp / "my bin" / "aegis"
    spaced.parent.mkdir()
    spaced.write_text("#!/bin/sh\n", encoding="utf-8")
    env.aegis = str(spaced)
    with pytest.raises(InstallError, match=r"\[A-Za-z0-9\._/\+-\]\+"):
        install(env, host)
    assert not (env.home / ".codex").exists() and not (env.home / ".gemini").exists()


def test_the_claude_exec_form_needs_no_shell_so_any_absolute_path_is_accepted(env):
    spaced = env.tmp / "my bin" / "aegis"
    spaced.parent.mkdir()
    spaced.write_text("#!/bin/sh\n", encoding="utf-8")
    env.aegis = str(spaced)
    result = install(env, "claude-code")
    assert load(result.path)["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == str(spaced)


def test_a_relative_aegis_path_is_refused(env):
    env.aegis = "bin/aegis"
    with pytest.raises(InstallError, match="absolute"):
        install(env, "claude-code")


def test_hook_group_refuses_a_host_without_hooks():
    with pytest.raises(registrar.UsageError, match="has no Aegis hooks"):
        registrar.hook_group("claude-desktop", "/x/aegis")


@pytest.mark.parametrize("host", ["claude-desktop", "gemini-cli", "nope"])
def test_hosts_without_hooks_are_refused(env, host):
    with pytest.raises(registrar.UsageError) as exc:
        install(env, host)
    if host == "gemini-cli":
        assert str(exc.value) == ("gemini-cli is not supported: Google retired Gemini CLI for individual "
                                  "Code Assist accounts; use --host antigravity.")
    else:
        assert "claude-code, codex-cli, antigravity" in str(exc.value)


def test_matches_install_holds_only_for_the_exact_group_of_an_aegis_handler():
    want = registrar.hook_group("claude-code", "/x/aegis")
    assert registrar.matches_install("claude-code", want, want["hooks"][0])
    lookalike = {key: value for key, value in want["hooks"][0].items() if key != "command"}
    assert not registrar.matches_install("claude-code", dict(want, hooks=[lookalike]), lookalike)
    assert not registrar.matches_install("claude-code", ["not", "a", "group"], want["hooks"][0])


# ── the merge keeps the user's file ─────────────────────────────────────────

def test_the_merge_keeps_every_other_key_and_hook_and_appends_after_them(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    theirs = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/mine"}]}
    path.write_text(json.dumps({"model": "x", "permissions": {"allow": ["Bash(ls)"]},
                                "hooks": {"PreToolUse": [theirs], "Stop": [theirs]}}), encoding="utf-8")
    install(env, "claude-code")
    data = load(path)
    assert data["model"] == "x" and data["permissions"] == {"allow": ["Bash(ls)"]}
    assert data["hooks"]["Stop"] == [theirs]
    assert data["hooks"]["PreToolUse"][0] == theirs
    assert data["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == env.aegis


def test_the_old_bytes_are_backed_up_owner_only_before_the_file_changes(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    original = b'{"model": "x"}\n'
    path.write_bytes(original)
    result = install(env, "claude-code")
    (copy,) = backups(env)
    assert copy.read_bytes() == original and copy.name == "settings.json"
    assert copy == result.backup_dir / "user" / "settings.json"
    assert result.backup_dir.parent == env.home / ".aegis" / "backups"
    if os.name != "nt":
        assert copy.stat().st_mode & 0o777 == 0o600
        assert {d.stat().st_mode & 0o777 for d in (copy.parent, copy.parent.parent)} == {0o700}


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_a_dry_run_refuses_when_the_backup_directory_cannot_be_created(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"model": "x"}')
    (env.home / ".aegis").mkdir()
    (env.home / ".aegis").chmod(0o555)
    try:
        with pytest.raises(InstallError, match="cannot be created"):
            install(env, "claude-code", dry_run=True)
    finally:
        (env.home / ".aegis").chmod(0o755)
    assert path.read_bytes() == b'{"model": "x"}'


def test_a_new_file_needs_no_backup(env):
    install(env, "claude-code")
    assert backups(env) == []


def test_reinstall_with_the_same_aegis_is_byte_stable_and_writes_nothing(env):
    first = install(env, "codex-cli")
    before = first.path.read_bytes(), first.rules_path.read_bytes(), first.path.stat().st_mtime_ns
    again = install(env, "codex-cli")
    assert again.status == "unchanged" and again.rules_status == "unchanged"
    assert (first.path.read_bytes(), first.rules_path.read_bytes(), first.path.stat().st_mtime_ns) == before
    assert backups(env) == []


def test_a_moved_aegis_updates_the_entry_in_place_never_by_position(env):
    path = env.home / ".codex" / "hooks.json"
    path.parent.mkdir(parents=True)
    old = {"matcher": "Bash|apply_patch", "hooks": [{"type": "command",
           "command": "/old/venv/bin/aegis hook run pre-tool --host codex-cli", "timeout": 10}]}
    mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/lint"}]}
    path.write_text(json.dumps({"hooks": {"PreToolUse": [mine, old, mine]}}), encoding="utf-8")
    result = install(env, "codex-cli")
    groups = load(path)["hooks"]["PreToolUse"]
    assert result.status == "updated"
    assert groups[0] == mine and groups[2] == mine
    assert groups[1]["hooks"][0]["command"] == f"{env.aegis} hook run pre-tool --host codex-cli"


def test_an_aegis_handler_sharing_a_group_is_split_out_and_the_other_handler_kept(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    other = {"type": "command", "command": "/usr/bin/other"}
    ours = {"type": "command", "command": "/x/aegis", "args": ["hook", "run", "pre-tool", "--host", "claude-code"]}
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [other, ours]}]}}),
                    encoding="utf-8")
    install(env, "claude-code")
    groups = load(path)["hooks"]["PreToolUse"]
    assert groups[0] == {"matcher": "Bash", "hooks": [other]}
    assert [g["hooks"][0]["command"] for g in groups[1:]] == [env.aegis]


@pytest.mark.parametrize("content, why", [
    (b"{ // jsonc\n}", "not valid JSON"),
    (b'{"hooks": {}, "hooks": {}}', "duplicate key"),
    (b"[]", "JSON object"),
    (b'{"hooks": []}', "hooks"),
    (b'{"hooks": {"PreToolUse": {}}}', "PreToolUse"),
    (b'{"hooks": {"PreToolUse": ["x"]}}', "PreToolUse"),
    (b'{"hooks": {"PreToolUse": [{"hooks": "x"}]}}', "PreToolUse\\[\\]\\.hooks' must be a list"),
])
def test_an_unparseable_or_unexpected_file_is_refused_and_left_byte_identical(env, content, why):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    with pytest.raises(InstallError, match=why):
        install(env, "claude-code")
    assert path.read_bytes() == content and backups(env) == []


def test_install_appends_after_every_group_of_the_user_and_keeps_groups_without_handlers(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    first = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/one"}]}
    bare = {"matcher": "Edit"}
    path.write_text(json.dumps({"hooks": {"PreToolUse": [first, bare]}}), encoding="utf-8")
    assert install(env, "claude-code").status == "added"
    assert load(path)["hooks"]["PreToolUse"] == [first, bare, registrar.hook_group("claude-code", env.aegis)]


def test_agy_top_level_values_that_are_not_groups_are_kept(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: False)
    path = env.home / ".gemini" / "config" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"description": "mine", "version": 2}), encoding="utf-8")
    install(env, "antigravity")
    data = load(path)
    assert data["description"] == "mine" and data["version"] == 2
    assert data["aegis"] == {"PreToolUse": [registrar.hook_group("antigravity", env.aegis)]}


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_a_read_only_settings_file_is_refused_before_any_backup(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"model": "x"}')
    path.chmod(0o444)
    with pytest.raises(InstallError, match="read-only"):
        install(env, "claude-code")
    assert path.read_bytes() == b'{"model": "x"}' and backups(env) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_a_rules_file_that_cannot_be_rewritten_stops_install_before_the_hook_is_written(env):
    rules = env.home / ".codex" / "rules" / "aegis.rules"
    rules.parent.mkdir(parents=True)
    rules.write_text(registrar.CODEX_RULES_HEADER + "# an older block set\n", encoding="utf-8")
    rules.chmod(0o444)
    with pytest.raises(InstallError, match="read-only"):
        install(env, "codex-cli")
    assert not (env.home / ".codex" / "hooks.json").exists() and backups(env) == []


def test_codex_on_windows_with_an_aegis_path_cmd_would_split_is_unavailable(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    env.aegis = r"C:\Users\me\Scripts\aegis.exe"
    result = install(env, "codex-cli")
    assert result.status == "unavailable"
    assert "%COMSPEC% /C" in result.detail and env.aegis in result.detail
    assert not (env.home / ".codex").exists()


def test_codex_on_windows_with_a_plain_aegis_path_is_installed(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    env.aegis = PLAIN_AEGIS
    result = install(env, "codex-cli")
    assert result.status == "added"
    assert load(result.path)["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == \
        f"{PLAIN_AEGIS} hook run pre-tool --host codex-cli"


def test_reinstall_from_the_home_directory_is_unchanged_not_a_clash(env):
    env.repo = env.home
    assert install(env, "claude-code").status == "added"
    assert install(env, "claude-code").status == "unchanged"


def test_an_agy_aegis_group_that_is_not_an_object_is_refused(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: False)
    path = env.home / ".gemini" / "config" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"aegis": []}')
    with pytest.raises(InstallError, match="aegis"):
        install(env, "antigravity")
    assert path.read_bytes() == b'{"aegis": []}'


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlinked_settings_file_is_refused(env):
    real = env.tmp / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = env.home / ".claude" / "settings.json"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    with pytest.raises(InstallError, match="symlink"):
        install(env, "claude-code")
    assert real.read_text(encoding="utf-8") == "{}" and link.is_symlink()


def test_a_multiply_linked_settings_file_is_refused(env):
    real = env.tmp / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = env.home / ".claude" / "settings.json"
    link.parent.mkdir(parents=True)
    os.link(real, link)
    with pytest.raises(InstallError, match="hard link"):
        install(env, "claude-code")
    assert real.read_text(encoding="utf-8") == "{}"


def test_install_reparses_what_it_wrote_and_restores_the_old_bytes_when_it_is_broken(env, monkeypatch):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"model": "x"}\n')
    monkeypatch.setattr(registrar, "_serialize", lambda data: b'{"hooks": ')
    with pytest.raises(InstallError, match="re-read"):
        install(env, "claude-code")
    assert path.read_bytes() == b'{"model": "x"}\n'


def test_a_broken_write_of_a_new_file_leaves_no_file(env, monkeypatch):
    monkeypatch.setattr(registrar, "_serialize", lambda data: b"{")
    with pytest.raises(InstallError, match="re-read"):
        install(env, "claude-code")
    assert not (env.home / ".claude" / "settings.json").exists()


def test_dry_run_checks_everything_and_writes_nothing(env):
    result = install(env, "codex-cli", dry_run=True)
    assert result.status == "added" and result.dry_run
    assert not (env.home / ".codex").exists() and backups(env) == []


# ── one Aegis entry per host ────────────────────────────────────────────────

def test_a_second_entry_at_the_other_scope_is_refused(env):
    install(env, "claude-code", "project")
    with pytest.raises(InstallError, match="project scope"):
        install(env, "claude-code", "user")
    assert not (env.home / ".claude" / "settings.json").exists()


def test_a_user_entry_blocks_a_project_install_too(env):
    install(env, "codex-cli", "user")
    with pytest.raises(InstallError, match="user scope"):
        install(env, "codex-cli", "project")
    assert not (env.repo / ".codex").exists()


def test_a_misshapen_file_at_the_other_scope_does_not_block_an_install(env):
    project = env.repo / ".claude" / "settings.json"
    project.parent.mkdir(parents=True)
    project.write_bytes(b'{"hooks": []}')
    assert install(env, "claude-code", "user").status == "added"
    assert project.read_bytes() == b'{"hooks": []}'


def test_project_scope_at_the_home_directory_is_refused(env):
    env.repo = env.home
    with pytest.raises(InstallError, match="home directory"):
        install(env, "claude-code", "project")


# ── uninstall ───────────────────────────────────────────────────────────────

def test_uninstall_removes_only_aegis_entries_and_keeps_the_rest(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    theirs = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/bin/mine"}]}
    path.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [theirs]}}), encoding="utf-8")
    install(env, "claude-code")
    (result,) = uninstall(env, "claude-code", "user")
    assert result.status == "removed"
    assert load(path) == {"model": "x", "hooks": {"PreToolUse": [theirs]}}


def test_uninstall_also_removes_the_insight_capture_entry(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    mine = {"matcher": "", "hooks": [{"type": "command", "command": "echo mine"}]}
    ours = {"matcher": "", "hooks": [{"type": "command", "command": "/py",
                                      "args": ["-I", "-c", registrar.INSIGHT_RUNNER, "/root", "--host", "claude-code"]}]}
    path.write_text(json.dumps({"hooks": {"UserPromptSubmit": [mine, ours]}}), encoding="utf-8")
    install(env, "claude-code")
    (result,) = uninstall(env, "claude-code", "user")
    assert (result.status, result.insight_capture) == ("removed", "removed")
    assert result.as_dict()["insight_capture"] == "removed"
    assert load(path) == {"hooks": {"UserPromptSubmit": [mine]}}
    assert len(backups(env)) == 2


def test_install_result_carries_no_insight_capture(env):
    assert install(env, "claude-code").as_dict()["insight_capture"] is None


def test_edit_hook_file_writes_nothing_when_the_edit_changes_nothing(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"model": "x"}')
    assert registrar.edit_hook_file(path, lambda data: None, home=env.home) is None
    assert path.read_bytes() == b'{"model": "x"}' and backups(env) == []


def test_edit_hook_file_turns_an_edit_refusal_into_install_error(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"model": "x"}')

    def refuse(data):
        raise ValueError("'hooks' must be a JSON object")

    with pytest.raises(InstallError, match="'hooks' must be a JSON object; left unchanged"):
        registrar.edit_hook_file(path, refuse, home=env.home)
    assert path.read_bytes() == b'{"model": "x"}' and backups(env) == []


def test_edit_hook_file_backs_up_then_replaces(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"model": "x"}')
    used = registrar.edit_hook_file(path, lambda data: data.update(effort="high"), home=env.home)
    assert load(path) == {"model": "x", "effort": "high"}
    (copy,) = backups(env)
    assert copy.read_bytes() == b'{"model": "x"}' and copy.parent == used / "user"


def test_uninstall_drops_the_containers_it_emptied(env):
    install(env, "claude-code")
    uninstall(env, "claude-code")
    assert load(env.home / ".claude" / "settings.json") == {}


def test_uninstall_finds_an_entry_by_command_whatever_its_aegis_path(env):
    path = env.home / ".codex" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "/elsewhere/aegis hook run pre-tool --host codex-cli"}]}]}}),
        encoding="utf-8")
    (result,) = uninstall(env, "codex-cli", "user")
    assert result.status == "removed" and load(path) == {}


@pytest.mark.parametrize("entry", [
    {"type": "command", "command": "/elsewhere/aegis hook run"},
    {"type": "command", "command": "'/opt/my tools/aegis' hook run pre-tool --host codex-cli"},
    {"type": "command", "command": "/x/aegis hook run pre-tool --host claude-code", "args": []},
    {"type": "command", "command": "/x/aegis", "args": ["hook", "run", "pre-tool"]},
    {"type": "command", "command": r"C:\Users\me\Scripts\aegis.exe hook run pre-tool --host codex-cli"},
    {"type": "command", "command": r'"C:\Program Files\aegis\aegis.exe" hook run pre-tool --host codex-cli'},
])
def test_uninstall_finds_every_form_of_an_aegis_entry(env, entry):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [entry]}]}}),
                    encoding="utf-8")
    (result,) = uninstall(env, "claude-code", "user")
    assert result.status == "removed" and load(path) == {}


def test_uninstall_keeps_the_users_other_events(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    stop = [{"hooks": [{"type": "command", "command": "/usr/bin/notify"}]}]
    path.write_text(json.dumps({"hooks": {"Stop": stop}}), encoding="utf-8")
    install(env, "claude-code")
    uninstall(env, "claude-code")
    assert load(path) == {"hooks": {"Stop": stop}}


def test_uninstall_refuses_a_misshapen_file(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"hooks": []}')
    with pytest.raises(InstallError, match="'hooks' must be a JSON object"):
        uninstall(env, "claude-code", "user")
    assert path.read_bytes() == b'{"hooks": []}'


def test_uninstall_from_the_home_directory_has_one_scope(env):
    env.repo = env.home
    install(env, "claude-code")
    assert [(r.scope, r.status) for r in uninstall(env, "claude-code")] == [("user", "removed")]


def test_uninstall_keeps_a_rules_file_aegis_did_not_write(env):
    rules = env.home / ".codex" / "rules" / "aegis.rules"
    rules.parent.mkdir(parents=True)
    rules.write_text('prefix_rule(pattern=["ls"], decision="allow")\n', encoding="utf-8")
    (result,) = uninstall(env, "codex-cli", "user")
    assert result.rules_status == "not_aegis" and rules.exists() and backups(env) == []


def test_uninstall_on_agy_empties_another_group_it_found_aegis_in_but_keeps_it(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: False)
    path = env.home / ".gemini" / "config" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"mine": {"PreToolUse": [registrar.hook_group("antigravity", env.aegis)],
                                         "PostToolUse": []}}), encoding="utf-8")
    uninstall(env, "antigravity", "user")
    assert load(path) == {"mine": {"PostToolUse": []}}


def test_uninstall_leaves_lookalike_commands_alone(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    keep = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "/x/aegis-lint hook run"},
        {"type": "command", "command": "aegis hook run pre-tool --host claude-code"},
        {"type": "command", "command": "/x/aegis", "args": ["check"]},
        {"type": "command", "command": "/x/aegis hook 'run"},
        {"type": "command", "command": "", "args": ["hook", "run", "pre-tool"]},
        {"type": "command", "args": ["hook", "run", "pre-tool"]},
        {"type": "command", "command": r"C:\x\aegis-lint.exe hook run"}]}]}}
    path.write_text(json.dumps(keep), encoding="utf-8")
    (result,) = uninstall(env, "claude-code", "user")
    assert result.status == "absent" and load(path) == keep


def test_uninstall_without_scope_covers_both_scopes(env):
    install(env, "codex-cli", "project")
    results = uninstall(env, "codex-cli")
    assert {(r.scope, r.status) for r in results} == {("user", "absent"), ("project", "removed")}
    assert load(env.repo / ".codex" / "hooks.json") == {}


def test_uninstall_removes_the_codex_rules_file_it_wrote_and_backs_it_up(env):
    install(env, "codex-cli")
    rules = env.home / ".codex" / "rules" / "aegis.rules"
    (result,) = uninstall(env, "codex-cli", "user")
    assert result.rules_status == "removed" and not rules.exists()
    assert any(p.name == "aegis.rules" for p in backups(env))


def test_a_rules_file_aegis_did_not_write_is_refused_not_overwritten(env):
    rules = env.home / ".codex" / "rules" / "aegis.rules"
    rules.parent.mkdir(parents=True)
    rules.write_text('prefix_rule(pattern=["ls"], decision="allow")\n', encoding="utf-8")
    with pytest.raises(InstallError, match="not written by Aegis"):
        install(env, "codex-cli")
    assert rules.read_text(encoding="utf-8").startswith("prefix_rule")
    assert not (env.home / ".codex" / "hooks.json").exists()


def test_uninstall_of_a_missing_file_is_absent_and_creates_nothing(env):
    (result,) = uninstall(env, "claude-code", "user")
    assert result.status == "absent" and not (env.home / ".claude").exists()


def test_uninstall_refuses_an_unparseable_file(env):
    path = env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{,}")
    with pytest.raises(InstallError):
        uninstall(env, "claude-code", "user")
    assert path.read_bytes() == b"{,}"


def test_uninstall_of_both_scopes_keeps_a_backup_of_each_same_named_file(env):
    """Both scopes' files are called hooks.json: neither backup may overwrite the other."""
    entry = {"matcher": "Bash|apply_patch", "hooks": [{"type": "command",
             "command": f"{env.aegis} hook run pre-tool --host codex-cli", "timeout": 10}]}
    user = env.home / ".codex" / "hooks.json"
    project = env.repo / ".codex" / "hooks.json"
    originals = {}
    for path, marker in ((user, "user"), (project, "project")):
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"marker": marker, "hooks": {"PreToolUse": [entry]}}), encoding="utf-8")
        originals[marker] = path.read_bytes()
    results = uninstall(env, "codex-cli")
    assert [(r.scope, r.status) for r in results] == [("user", "removed"), ("project", "removed")]
    copies = sorted(p.read_bytes() for p in backups(env) if p.name == "hooks.json")
    assert copies == sorted(originals.values())
    for r in results:
        assert (r.backup_dir / r.scope / "hooks.json").read_bytes() == originals[r.scope]


def test_uninstall_on_agy_drops_the_empty_aegis_group_only(env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: False)
    path = env.home / ".gemini" / "config" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"mine": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "true"}]}]}}), encoding="utf-8")
    install(env, "antigravity")
    uninstall(env, "antigravity")
    assert list(load(path)) == ["mine"]


# ── uninstall: the Codex rules file follows the last Codex hook ─────────────

def rules_file(env) -> Path:
    return env.home / ".codex" / "rules" / "aegis.rules"


def test_uninstall_of_the_project_scope_keeps_the_rules_file_the_user_hook_uses(env):
    install(env, "codex-cli", "user")
    before = rules_file(env).read_bytes()
    (result,) = uninstall(env, "codex-cli", "project")
    assert (result.scope, result.status) == ("project", "absent")
    assert result.rules_status == "kept"
    assert result.detail == f"the Aegis hook at user scope ({env.home / '.codex' / 'hooks.json'}) still uses it"
    assert rules_file(env).read_bytes() == before and backups(env) == []
    assert registrar.aegis_handlers("codex-cli", load(env.home / ".codex" / "hooks.json"))


def test_uninstall_of_the_user_scope_keeps_the_rules_file_a_project_hook_uses(env):
    install(env, "codex-cli", "project")
    (result,) = uninstall(env, "codex-cli", "user")
    assert (result.status, result.rules_status) == ("absent", "kept")
    assert "project scope" in result.detail and rules_file(env).exists()


def test_uninstall_of_the_last_codex_hook_removes_the_rules_file_whatever_the_scope(env):
    install(env, "codex-cli", "project")
    (result,) = uninstall(env, "codex-cli", "project")
    assert (result.status, result.rules_status) == ("removed", "removed")
    assert not rules_file(env).exists()
    assert sorted(p.name for p in backups(env)) == ["aegis.rules", "hooks.json"]


def test_uninstall_removes_an_orphaned_rules_file_and_backs_it_up(env):
    result = install(env, "codex-cli")
    result.path.write_text("{}", encoding="utf-8")  # the hook entry removed by hand
    (after,) = uninstall(env, "codex-cli", "user")
    assert (after.status, after.rules_status) == ("absent", "removed")
    assert not result.rules_path.exists()
    assert [p.name for p in backups(env)] == ["aegis.rules"]
    assert (after.backup_dir / "user" / "aegis.rules").is_file()


def test_uninstall_keeps_the_rules_file_when_the_other_scopes_file_cannot_be_read(env):
    install(env, "codex-cli", "project")
    user = env.home / ".codex" / "hooks.json"
    user.write_bytes(b"{bad")
    (result,) = uninstall(env, "codex-cli", "project")
    assert (result.status, result.rules_status) == ("removed", "kept")
    assert result.detail.startswith("cannot tell whether a user-scope hook uses it: ")
    assert "not valid JSON" in result.detail
    assert rules_file(env).exists() and user.read_bytes() == b"{bad"


# ── uninstall checks every file before it writes one ────────────────────────

def _claude_entry_at_both_scopes(env) -> Dict[str, Path]:
    """An Aegis Claude entry at each scope (install refuses the second, so it is written)."""
    user = install(env, "claude-code", "user").path
    project = env.repo / ".claude" / "settings.json"
    project.parent.mkdir(parents=True)
    project.write_text(json.dumps({"hooks": {"PreToolUse": [registrar.hook_group("claude-code", env.aegis)]}}),
                       encoding="utf-8")
    return {"user": user, "project": project}


def test_uninstall_of_both_scopes_writes_nothing_when_a_later_file_is_unparseable(env):
    user = install(env, "claude-code", "user").path
    before = user.read_bytes()
    project = env.repo / ".claude" / "settings.json"
    project.parent.mkdir(parents=True)
    project.write_bytes(b"{bad")
    with pytest.raises(InstallError, match="not valid JSON"):
        uninstall(env, "claude-code")
    assert user.read_bytes() == before and project.read_bytes() == b"{bad" and backups(env) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_uninstall_of_both_scopes_writes_nothing_when_a_later_file_is_read_only(env):
    paths = _claude_entry_at_both_scopes(env)
    before = {scope: path.read_bytes() for scope, path in paths.items()}
    paths["project"].chmod(0o444)
    with pytest.raises(InstallError, match="read-only"):
        uninstall(env, "claude-code")
    assert {scope: path.read_bytes() for scope, path in paths.items()} == before and backups(env) == []


def test_uninstall_refuses_a_linked_rules_file_before_it_changes_the_hooks_file(env):
    result = install(env, "codex-cli")
    before = result.path.read_bytes()
    elsewhere = env.tmp / "elsewhere.rules"
    os.link(result.rules_path, elsewhere)
    with pytest.raises(InstallError, match="hard link"):
        uninstall(env, "codex-cli", "user")
    assert result.path.read_bytes() == before and result.rules_path.exists() and backups(env) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
def test_uninstall_refuses_a_read_only_rules_file_before_it_changes_the_hooks_file(env):
    result = install(env, "codex-cli")
    before = result.path.read_bytes()
    result.rules_path.chmod(0o444)
    with pytest.raises(InstallError, match="read-only"):
        uninstall(env, "codex-cli", "user")
    assert result.path.read_bytes() == before and result.rules_path.exists() and backups(env) == []


def test_a_rules_file_that_cannot_be_removed_names_the_hook_already_removed(env, monkeypatch):
    result = install(env, "codex-cli")
    real = os.unlink

    def busy(path, *args, **kwargs):
        if Path(path) == result.rules_path:
            raise PermissionError(13, "Permission denied")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", busy)
    with pytest.raises(InstallError) as exc:
        uninstall(env, "codex-cli", "user")
    assert str(exc.value).startswith(f"{result.rules_path}: cannot be removed (Permission denied); left in place. "
                                     f"The Aegis hook was already removed from {result.path} (backup in ")
    assert result.rules_path.exists() and not registrar.aegis_handlers("codex-cli", load(result.path))


def test_a_write_that_fails_after_the_checks_names_the_removals_already_made(env, monkeypatch):
    from aegis_cli import install_hosts

    paths = _claude_entry_at_both_scopes(env)
    real = install_hosts.atomic_write_bytes

    def disk_full(path, data, *args, **kwargs):
        if Path(path) == paths["project"]:
            raise OSError(28, "No space left on device")
        return real(path, data, *args, **kwargs)

    monkeypatch.setattr(install_hosts, "atomic_write_bytes", disk_full)
    with pytest.raises(InstallError) as exc:
        uninstall(env, "claude-code")
    message = str(exc.value)
    assert "No space left on device" in message
    assert f"already removed from {paths['user']} (backup in " in message
    assert registrar.aegis_handlers("claude-code", load(paths["project"]))
    assert not registrar.aegis_handlers("claude-code", load(paths["user"]))


# ── the agy wrapper, run by a real shell ────────────────────────────────────

_SHELLS = [name for name in ("sh", "bash", "dash") if shutil.which(name)]


@pytest.mark.skipif(os.name == "nt", reason="agy hooks are unavailable on Windows")
@pytest.mark.parametrize("shell", _SHELLS)
@pytest.mark.parametrize("code, blocks", [(0, False), (1, False), (2, False), (75, True), (126, False),
                                          (127, False), (None, False)])
def test_the_exact_agy_registration_maps_only_75_to_a_block_and_prints_nothing(tmp_path, shell, code, blocks):
    """agy blocks a tool call on any non-zero exit (LIVE): the registered string must turn
    the handler's 75 into 1 and everything else (a crash, a usage error, 126, 127, a
    missing binary) into 0, and agy parses stdout, so it must stay empty."""
    aegis = tmp_path / "bin" / "aegis"
    aegis.parent.mkdir()
    if code is not None:
        aegis.write_text(f"#!/bin/sh\ncat >/dev/null\necho '{{\"decision\":\"deny\"}}'\nexit {code}\n",
                         encoding="utf-8")
        aegis.chmod(0o755)
    command = registrar.hook_group("antigravity", str(aegis))["hooks"][0]["command"]
    done = subprocess.run([shutil.which(shell), "-c", command], input=b'{"toolCall": {}}',
                          capture_output=True, timeout=30, cwd=str(tmp_path))
    assert done.returncode == (1 if blocks else 0)
    assert done.stdout == b""


# ── the Codex rules come from the shared block set ──────────────────────────

def test_codex_rules_are_generated_from_every_block_set_prefix_as_forbidden():
    text = registrar.codex_rules_text()
    assert text.startswith(registrar.CODEX_RULES_HEADER)
    count = sum(len(rule.codex_prefixes) for rule in command_safety.BLOCK_SET)
    assert text.count("prefix_rule(") == count > 0
    assert text.count('decision = "forbidden"') == count
    for rule in command_safety.BLOCK_SET:
        for prefix in rule.codex_prefixes:
            pattern = json.dumps([list(p) if isinstance(p, tuple) else p for p in prefix])
            assert f"pattern = {pattern}," in text
            assert f'justification = {json.dumps("aegis: " + rule.reason)},' in text
    assert all(rule.id not in text for rule in command_safety.RECORD_SET)


# ── aegis lookup ────────────────────────────────────────────────────────────

def test_aegis_command_prefers_an_absolute_path_entry_outside_the_repo(env, tmp_path):
    inside = env.repo / "bin"
    inside.mkdir()
    planted = inside / Path(env.stub).name
    planted.write_text("#!/bin/sh\n", encoding="utf-8")
    planted.chmod(0o755)
    path_env = os.pathsep.join(["relative", str(inside), str(Path(env.stub).parent)])
    assert registrar.aegis_command(path_env, scripts_dirs=[], outside=env.repo) == env.stub


def test_aegis_command_is_none_when_nothing_is_found(env):
    assert registrar.aegis_command("", scripts_dirs=[], outside=env.repo) is None


def test_aegis_command_falls_back_to_this_interpreters_scripts_directory(env):
    scripts = str(Path(env.stub).parent)
    assert registrar.aegis_command("", scripts_dirs=[scripts], outside=env.repo) == env.stub


@pytest.mark.skipif(os.name == "nt", reason="Windows has no execute bit")
def test_aegis_command_skips_a_scripts_entry_that_is_not_executable(env):
    Path(env.stub).chmod(0o644)
    assert registrar.aegis_command("", scripts_dirs=[str(Path(env.stub).parent)], outside=env.repo) is None


# ── the CLI ─────────────────────────────────────────────────────────────────

def cli(env, *argv, monkeypatch=None):
    from aegis_cli.cli import main

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(argv))
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture
def cli_env(env, monkeypatch):
    monkeypatch.setenv("PATH", str(Path(env.stub).parent))
    monkeypatch.setattr(registrar, "_scripts_dirs", lambda: [])
    monkeypatch.chdir(env.repo)
    if os.name == "nt":  # the stub is a text file there, which Windows cannot run; the probe has its own POSIX tests
        monkeypatch.setattr(registrar, "probe_hook_run", lambda *args, **kwargs: None)
    return env


@pytest.fixture
def shell_form_cli_env(cli_env, monkeypatch):
    """The CLI given env.aegis as the aegis it finds. The stub it would find on PATH has a
    native path, which on Windows makes Codex hooks unavailable: not these tests' subject."""
    monkeypatch.setattr(registrar, "aegis_command", lambda *args, **kwargs: cli_env.aegis)
    monkeypatch.setattr(registrar, "probe_hook_run", lambda *args, **kwargs: None)  # env.aegis is no file
    return cli_env


def test_cli_install_json_carries_the_envelope_and_the_result(cli_env):
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code", "--json")
    doc = json.loads(out)
    assert rc == 0 and out.startswith('{\n  "source": ')
    assert doc["source"] == "aegis hook install" and doc["aegis_version"]
    assert doc["checked_at"].endswith("Z")
    assert doc["scope"] == {"host": "claude-code", "scope": "user", "workspace": str(cli_env.repo.resolve())}
    (result,) = doc["results"]
    assert result["status"] == "added" and result["tier"] == "blocking (documented; fails open on error)"
    assert result["evidence"] == "DOC"


def test_cli_codex_install_prints_the_trust_step(shell_form_cli_env):
    rc, out, err = cli(shell_form_cli_env, "hook", "install", "--host", "codex-cli")
    assert rc == 0
    assert "/hooks" in out and "trust" in out
    assert "--dangerously-bypass-hook-trust" in out


def test_cli_project_scope_prints_the_teammates_warning(cli_env):
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code", "--scope", "project")
    assert rc == 0
    assert "teammates" in err and str(Path(".claude") / "settings.json") in err


def test_cli_scope_without_host_is_a_usage_error(cli_env):
    rc, out, err = cli(cli_env, "hook", "install", "--scope", "project")
    assert rc == 2 and "--scope needs --host" in err


def test_cli_retired_host_exits_2_with_the_retirement_message(cli_env):
    rc, out, err = cli(cli_env, "hook", "install", "--host", "gemini-cli")
    assert rc == 2
    assert "gemini-cli is not supported: Google retired Gemini CLI" in err


def test_cli_refusal_exits_1_and_names_the_file(cli_env):
    path = cli_env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{nope")
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code")
    assert rc == 1 and "settings.json" in err and "not valid JSON" in err


def test_cli_agy_on_windows_reports_unavailable_and_exits_1(cli_env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    rc, out, err = cli(cli_env, "hook", "install", "--host", "antigravity", "--json")
    assert rc == 1
    (result,) = json.loads(out)["results"]
    assert result["status"] == "unavailable" and result["tier"] == "unavailable"
    assert not (cli_env.home / ".gemini").exists()


def test_cli_text_names_the_tier_on_install_only(cli_env):
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code")
    assert rc == 0 and "tier: blocking (documented; fails open on error) [DOC]" in out
    rc, out, err = cli(cli_env, "hook", "uninstall", "--host", "claude-code")
    assert rc == 0 and "removed from" in out and "tier:" not in out


def test_cli_text_says_why_a_host_is_unavailable(cli_env, monkeypatch):
    monkeypatch.setattr(registrar, "_windows", lambda: True)
    rc, out, err = cli(cli_env, "hook", "install", "--host", "antigravity")
    assert rc == 1 and "antigravity: hooks unavailable: Antigravity hooks are unavailable on Windows" in out


def test_cli_dry_run_writes_nothing(shell_form_cli_env):
    rc, out, err = cli(shell_form_cli_env, "hook", "install", "--host", "codex-cli", "--dry-run")
    assert rc == 0 and "(dry run)" in out
    assert not (shell_form_cli_env.home / ".codex").exists()


def test_cli_without_any_aegis_found_refuses(cli_env, monkeypatch):
    monkeypatch.setenv("PATH", "")
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code")
    assert rc == 1 and "absolute" in err
    assert not (cli_env.home / ".claude").exists()


def test_cli_uninstall_json(cli_env):
    cli(cli_env, "hook", "install", "--host", "claude-code")
    rc, out, err = cli(cli_env, "hook", "uninstall", "--host", "claude-code", "--json")
    doc = json.loads(out)
    assert rc == 0 and doc["source"] == "aegis hook uninstall"
    assert {r["scope"]: r["status"] for r in doc["results"]} == {"user": "removed", "project": "absent"}


def test_cli_uninstall_says_why_the_codex_rules_file_stays(shell_form_cli_env):
    cli(shell_form_cli_env, "hook", "install", "--host", "codex-cli")
    rc, out, err = cli(shell_form_cli_env, "hook", "uninstall", "--host", "codex-cli", "--scope", "project")
    assert rc == 0
    assert (f"Codex rules {shell_form_cli_env.home / '.codex' / 'rules' / 'aegis.rules'}: kept "
            f"(the Aegis hook at user scope ({shell_form_cli_env.home / '.codex' / 'hooks.json'}) still uses it)") in out


def test_run_hook_takes_a_callers_namespace_without_the_new_options(cli_env, capsys):
    """run_hook is public (aegis_cli.hooks): a Namespace built without --force, --scope,
    --json or --dry-run still installs the host hook, at user scope."""
    from aegis_cli.hooks import run_hook

    rc = run_hook(argparse.Namespace(hook_action="install", host="claude-code"))
    assert rc == 0 and "added to" in capsys.readouterr().out
    assert (cli_env.home / ".claude" / "settings.json").is_file()


def test_cli_without_host_still_manages_the_git_hook(cli_env, monkeypatch):
    calls = []
    from aegis_cli.hooks import runtime

    monkeypatch.setattr(runtime, "run_hook_install", lambda args: calls.append(args) or 0)
    rc, out, err = cli(cli_env, "hook", "install")
    assert rc == 0 and len(calls) == 1


def test_install_help_documents_the_known_gaps(cli_env):
    from aegis_cli.cli import _build_parser

    parser = _build_parser(prog="aegis")
    help_text = parser._subparsers._group_actions[0].choices["hook"]._subparsers._group_actions[0] \
        .choices["install"].format_help()
    flat = " ".join(help_text.split())
    assert "Edits made through shell commands never reach the edit gate" in flat
    assert "write_stdin" in flat and "manage_task" in flat
    for gap in registrar.KNOWN_GAPS:
        assert " ".join(gap.split()) in flat
    assert "--host claude-code|codex-cli|antigravity" in flat


@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_host_hook_help_says_it_does_not_run_from_the_home_directory(cli_env, action):
    from aegis_cli.cli import _build_parser

    parser = _build_parser(prog="aegis")
    help_text = parser._subparsers._group_actions[0].choices["hook"]._subparsers._group_actions[0] \
        .choices[action].format_help()
    flat = " ".join(help_text.split())
    assert ("Run it from any directory but your home directory, which Aegis never takes as a workspace, "
            "even for --scope user") in flat


@pytest.mark.parametrize("action", ["install", "uninstall"])
def test_cli_force_with_host_is_a_usage_error_and_touches_nothing(cli_env, action):
    path = cli_env.home / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"{nope")
    rc, out, err = cli(cli_env, "hook", action, "--host", "claude-code", "--force")
    assert rc == 2 and "--force applies only to the git hook" in err
    assert path.read_bytes() == b"{nope"


# ── an aegis without `hook run` is never registered (release review F1) ──────────

@pytest.mark.skipif(os.name == "nt", reason="the stub is a shell script")
def test_install_refuses_an_aegis_that_has_no_hook_run(cli_env):
    """A 4.0.x aegis answers `hook run` with an argparse usage error (exit 2), which Claude Code
    and Codex read as a block; registering it would block every tool call in every repo."""
    Path(cli_env.stub).write_text("#!/bin/sh\necho \"aegis: error: argument command: invalid choice: 'run'\" >&2\nexit 2\n",
                                  encoding="utf-8")
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code")
    assert rc == 1
    assert "does not support `hook run` (exit 2: aegis: error: argument command: invalid choice: 'run')" in err
    assert "older aegis than 4.1" in err
    assert not (cli_env.home / ".claude" / "settings.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="the stub is a shell script")
def test_install_refuses_an_aegis_that_cannot_be_run(cli_env):
    Path(cli_env.stub).write_text("not a program\n", encoding="utf-8")
    Path(cli_env.stub).chmod(0o755)
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code")
    assert rc == 1 and "cannot run" in err
    assert not (cli_env.home / ".claude" / "settings.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="the stub is a shell script")
def test_install_probes_with_an_empty_payload_from_an_empty_directory(cli_env):
    log = cli_env.tmp / "probe.log"
    Path(cli_env.stub).write_text(f"#!/bin/sh\necho \"$@|$PWD\" > {log}\nexit 0\n", encoding="utf-8")
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-code")
    assert rc == 0, err
    args, cwd = log.read_text(encoding="utf-8").strip().split("|")
    assert args == "hook run pre-tool --host claude-code"
    assert Path(cwd).name.startswith("aegis-hook-probe-") and not str(cli_env.repo) in cwd


def test_hook_install_and_uninstall_accept_a_surface_alias(cli_env):
    """init and skills sync take surface names; hook install takes them too (release review F4)."""
    rc, out, err = cli(cli_env, "hook", "install", "--host", "claude-desktop-code", "--json")
    assert rc == 0, err
    assert json.loads(out)["results"][0]["host"] == "claude-code"
    rc, out, err = cli(cli_env, "hook", "uninstall", "--host", "claude-desktop-code", "--json")
    assert rc == 0, err
    assert json.loads(out)["results"][0]["host"] == "claude-code"


def test_hook_install_still_refuses_a_host_without_hooks(cli_env):
    rc, out, err = cli(cli_env, "hook", "install", "--host", "kiro-ide")
    assert rc == 2 and "has no Aegis hooks" in err
