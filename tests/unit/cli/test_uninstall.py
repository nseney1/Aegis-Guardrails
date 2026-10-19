"""`aegis uninstall`: undo what `aegis init` did on this machine, and never touch .aegis/.

It removes the git hook block, the Aegis managed blocks, this workspace's registry
entry and the hosts' ``aegis`` (and legacy ``soma``) registrations. A host another
registered workspace still uses keeps its registration unless named with ``--host``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import symlink_or_skip

import aegis_cli.install_hosts as ih
from aegis_cli.cli import main
from aegis_cli.hooks.management import _AEGIS_HOOK_START, generate_hook_block


class Runner:
    def __init__(self):
        self.calls: list = []

    def __call__(self, argv):
        # The binary's name without its extension: Windows spells it as the file on disk does.
        self.calls.append([Path(argv[0]).stem, *argv[1:]])
        return subprocess.CompletedProcess(argv, 0, "", "")


@pytest.fixture
def env(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("codex", "claude", "aegis-mcp"):
        exe = bindir / (name + (".exe" if os.name == "nt" else ""))
        exe.write_bytes(b"#!/bin/sh\nexit 0\n")
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    runner = Runner()
    monkeypatch.setattr(ih, "_run_cli", runner)
    project = tmp_path / "project"
    project.mkdir()
    return type("Env", (), {"tmp": tmp_path, "project": project, "home": Path.home(), "runner": runner,
                            "bin": bindir})


def init(env, project: Path, hosts: str) -> None:
    assert main(["init", "--workspace", str(project), "--yes", "--no-hooks", "--rules", "minimal",
                 "--host", hosts]) == 0


def uninstall(project: Path, *flags) -> int:
    return main(["uninstall", "--workspace", str(project), *flags])


def snapshot(*roots: Path) -> dict:
    out = {}
    for root in roots:
        for dirpath, dirs, names in os.walk(root):
            for name in dirs + names:
                p = Path(dirpath, name)
                out[str(p)] = "<dir>" if p.is_dir() else p.read_bytes()
    return out


def registry(env) -> dict:
    return json.loads((env.home / ".aegis" / "workspaces.json").read_text(encoding="utf-8"))


class TestUndoesInit:
    def test_full_round_trip(self, env):
        claude = env.project / "CLAUDE.md"
        claude.write_bytes(b"# Claude\r\nmine\r\n")
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"mcpServers": {"github": {"command": "gh"}}}), encoding="utf-8")
        init(env, env.project, "codex-cli,antigravity")
        rules_before = snapshot(env.project / ".aegis" / "rules")
        config_before = (env.project / ".aegis" / "config.json").read_bytes()
        env.runner.calls.clear()

        assert uninstall(env.project) == 0

        assert not (env.project / "AGENTS.md").exists()  # it held only the Aegis block
        assert claude.read_bytes() == b"# Claude\r\nmine\r\n"
        assert registry(env) == {"v": 1, "workspaces": []}
        assert json.loads(cfg.read_text(encoding="utf-8")) == {"mcpServers": {"github": {"command": "gh"}}}
        assert env.runner.calls == [["codex", "mcp", "remove", "aegis"], ["codex", "mcp", "remove", "soma"]]
        assert snapshot(env.project / ".aegis" / "rules") == rules_before
        assert (env.project / ".aegis" / "config.json").read_bytes() == config_before

    def test_user_text_in_agents_md_is_kept(self, env):
        agents = env.project / "AGENTS.md"
        agents.write_text("# Ours\n", encoding="utf-8")
        init(env, env.project, "codex-cli")
        assert uninstall(env.project) == 0
        assert agents.read_text(encoding="utf-8") == "# Ours\n"

    def test_second_uninstall_changes_nothing(self, env):
        init(env, env.project, "antigravity")
        assert uninstall(env.project) == 0
        before = snapshot(env.project, env.home)
        assert uninstall(env.project) == 0
        assert snapshot(env.project, env.home) == before

    def test_git_hook_block_is_removed_and_user_lines_kept(self, env):
        hooks = env.project / ".git" / "hooks"
        hooks.mkdir(parents=True)
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\n# custom user hook\necho hello\n\n" + generate_hook_block("/usr/bin/python3"),
                        encoding="utf-8")
        assert uninstall(env.project) == 0
        remaining = hook.read_text(encoding="utf-8")
        assert "custom user hook" in remaining
        assert _AEGIS_HOOK_START not in remaining


class TestSharedHosts:
    def test_a_host_another_workspace_uses_is_kept(self, env, capsys):
        other = env.tmp / "other"
        other.mkdir()
        init(env, env.project, "codex-cli,antigravity")
        init(env, other, "codex-cli")
        env.runner.calls.clear()

        assert uninstall(env.project) == 0

        assert env.runner.calls == []  # codex-cli is still registered for `other`
        assert [w["root"] for w in registry(env)["workspaces"]] == [str(other.resolve())]
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        assert "aegis" not in json.loads(cfg.read_text(encoding="utf-8"))["mcpServers"]
        assert "codex-cli: kept" in capsys.readouterr().out

    def test_naming_a_host_unregisters_it_anyway_and_warns(self, env, capsys):
        other = env.tmp / "other"
        other.mkdir()
        init(env, env.project, "codex-cli")
        init(env, other, "codex-cli")
        env.runner.calls.clear()

        assert uninstall(env.project, "--host", "codex-cli") == 0

        assert env.runner.calls[0] == ["codex", "mcp", "remove", "aegis"]
        assert "still lists codex-cli" in capsys.readouterr().err

    @staticmethod
    def _add_entries(env, *roots: str, hosts=("codex-cli",)) -> None:
        path = env.home / ".aegis" / "workspaces.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["workspaces"] += [{"root": root, "added_at": "2026-10-16T00:00:00Z", "added_by": "aegis init",
                                "hosts": list(hosts)} for root in roots]
        path.write_text(json.dumps(data), encoding="utf-8")

    def _unbindable_roots(self, env) -> list:
        """Entries the MCP server's registry reader can never bind (aegis_core.workspace.binding):
        a relative root, a NUL byte, the home directory, a filesystem root, a directory that is
        gone and one that is not an Aegis workspace."""
        plain = env.tmp / "plain"
        plain.mkdir()
        return ["relative/ws", str(env.tmp / "nul\x00byte"), str(env.home), env.tmp.anchor,
                str(env.tmp / "gone"), str(plain)]

    def test_entries_the_server_can_never_bind_do_not_keep_a_host(self, env, capsys):
        init(env, env.project, "codex-cli")
        self._add_entries(env, *self._unbindable_roots(env))
        env.runner.calls.clear()

        assert uninstall(env.project) == 0

        assert env.runner.calls[:1] == [["codex", "mcp", "remove", "aegis"]]
        assert "kept (still used" not in capsys.readouterr().out

    def test_only_bindable_workspaces_are_counted_as_users(self, env, capsys):
        other = env.tmp / "other"
        other.mkdir()
        init(env, env.project, "codex-cli")
        init(env, other, "codex-cli")
        self._add_entries(env, *self._unbindable_roots(env))
        env.runner.calls.clear()

        assert uninstall(env.project) == 0

        assert env.runner.calls == []
        assert "codex-cli: kept (still used by 1 other registered workspace(s))" in capsys.readouterr().out

    def test_naming_a_host_warns_only_about_a_bindable_workspace(self, env, capsys):
        init(env, env.project, "codex-cli")
        self._add_entries(env, *self._unbindable_roots(env))
        env.runner.calls.clear()

        assert uninstall(env.project, "--host", "codex-cli") == 0

        assert env.runner.calls[:1] == [["codex", "mcp", "remove", "aegis"]]
        assert "still lists" not in capsys.readouterr().err

    def test_without_a_registry_entry_the_config_hosts_are_used(self, env):
        init(env, env.project, "codex-cli")
        (env.home / ".aegis" / "workspaces.json").write_text('{"v": 1, "workspaces": []}', encoding="utf-8")
        env.runner.calls.clear()
        assert uninstall(env.project) == 0
        assert env.runner.calls[0] == ["codex", "mcp", "remove", "aegis"]

    def test_missing_host_cli_prints_the_command(self, env, capsys):
        init(env, env.project, "claude-code")
        (env.bin / ("claude" + (".exe" if os.name == "nt" else ""))).unlink()
        env.runner.calls.clear()
        assert uninstall(env.project) == 0
        assert env.runner.calls == []
        assert "claude mcp remove --scope user aegis" in capsys.readouterr().out


class TestRecordedHostsAegisNeverRegisters:
    """A recorded host Aegis has no registration for (retired, identity only, or not in the
    host table) is skipped with a note; the rest of the uninstall still runs."""

    SKIPPED = {
        "gemini-cli": "retired: Aegis does not register there",
        "claude-desktop": "identity only: Aegis does not register there (ADR 0005 H4)",
        "zed": "not a host Aegis knows",
    }

    def _actions(self, env, capsys) -> dict:
        capsys.readouterr()
        assert main(["--json", "uninstall", "--workspace", str(env.project)]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "ok"
        return {a["target"]: (a["result"], a["detail"]) for a in payload["actions"]}

    def test_from_the_registry_entry(self, env, capsys):
        init(env, env.project, "codex-cli")
        path = env.home / ".aegis" / "workspaces.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["workspaces"][0]["hosts"] = ["codex-cli", "gemini-cli", "claude-desktop", "zed"]
        path.write_text(json.dumps(data), encoding="utf-8")
        env.runner.calls.clear()

        actions = self._actions(env, capsys)

        assert env.runner.calls == [["codex", "mcp", "remove", "aegis"], ["codex", "mcp", "remove", "soma"]]
        assert actions["codex-cli"][0] == "removed"
        assert {h: actions[h] for h in self.SKIPPED} == {h: ("skipped", d) for h, d in self.SKIPPED.items()}
        assert registry(env) == {"v": 1, "workspaces": []}

    def test_from_config_json_without_a_registry_entry(self, env, capsys):
        (env.project / ".aegis").mkdir()
        (env.project / ".aegis" / "config.json").write_text(
            json.dumps({"v": 1, "hosts": ["gemini-cli", "claude-desktop"]}), encoding="utf-8")
        gemini = env.bin / ("gemini" + (".exe" if os.name == "nt" else ""))
        gemini.write_bytes(b"#!/bin/sh\nexit 0\n")
        gemini.chmod(0o755)

        assert uninstall(env.project) == 0

        out = capsys.readouterr().out
        assert env.runner.calls == []
        assert "gemini-cli: skipped (retired: Aegis does not register there)" in out
        assert "claude-desktop: skipped (identity only: Aegis does not register there (ADR 0005 H4))" in out
        assert "Nothing was changed" not in out


class TestSafety:
    def test_dry_run_changes_nothing(self, env, capsys):
        init(env, env.project, "codex-cli,antigravity")
        env.runner.calls.clear()
        before = snapshot(env.project, env.home)
        assert uninstall(env.project, "--dry-run") == 0
        assert snapshot(env.project, env.home) == before
        assert env.runner.calls == []
        assert "codex mcp remove aegis" in capsys.readouterr().out

    def test_hand_edited_block_refuses_everything_without_force(self, env, capsys):
        init(env, env.project, "antigravity")
        agents = env.project / "AGENTS.md"
        agents.write_text(agents.read_text(encoding="utf-8").replace("Aegis", "Our Aegis"), encoding="utf-8")
        before = snapshot(env.project, env.home)
        assert uninstall(env.project) == 1
        assert snapshot(env.project, env.home) == before
        assert "--force" in capsys.readouterr().err
        assert uninstall(env.project, "--force") == 0
        assert not agents.exists()

    def test_unparseable_host_config_refuses_everything(self, env, capsys):
        init(env, env.project, "antigravity,codex-cli")
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.write_bytes(b"{ // jsonc\n}")
        env.runner.calls.clear()
        before = snapshot(env.project, env.home)
        assert uninstall(env.project) == 1
        assert snapshot(env.project, env.home) == before
        assert env.runner.calls == []
        assert "not valid JSON" in capsys.readouterr().err

    def test_symlinked_agents_md_is_refused(self, env, tmp_path, capsys):
        outside = tmp_path / "outside.md"
        outside.write_text("<!-- aegis:begin id=bootstrap v=1 sha=" + ih._digest("x\n") + " -->\nx\n"
                           "<!-- aegis:end id=bootstrap -->\n", encoding="utf-8")
        symlink_or_skip(outside, env.project / "AGENTS.md")
        assert uninstall(env.project) == 1
        assert "aegis:begin" in outside.read_text(encoding="utf-8")
        err = capsys.readouterr().err
        assert str(outside) in err and "never writes through a link" in err and "Nothing was changed." in err

    def test_force_never_deletes_aegis_dir(self, env):
        init(env, env.project, "codex-cli")
        assert uninstall(env.project, "--force") == 0
        assert (env.project / ".aegis" / "rules" / "personas" / "providence.md").is_file()
        assert (env.project / ".aegis" / "config.json").is_file()

    def test_json_result(self, env, capsys):
        init(env, env.project, "codex-cli")
        capsys.readouterr()
        assert main(["--json", "uninstall", "--workspace", str(env.project)]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["source"] == "aegis uninstall"
        assert payload["scope"]["workspace"] == str(env.project.resolve())
        assert payload["scope"]["hosts"] == ["codex-cli"]
        assert {a["target"]: a["result"] for a in payload["actions"]}["codex-cli"] == "removed"
        assert {"aegis_version", "checked_at", "status"} <= set(payload)


class TestRefusalsTheCheckPassMustSee:
    """A refusal found only while writing came after the hook had already been removed."""

    def _hooked(self, env) -> Path:
        hooks = env.project / ".git" / "hooks"
        hooks.mkdir(parents=True)
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\n" + generate_hook_block("/usr/bin/python3"), encoding="utf-8")
        return hook

    def test_read_only_agents_md_refuses_before_the_hook_is_removed(self, env, capsys):
        agents = env.project / "AGENTS.md"
        agents.write_text("# Ours\n", encoding="utf-8")
        init(env, env.project, "antigravity")
        hook = self._hooked(env)
        agents.chmod(0o444)
        try:
            before = snapshot(env.project, env.home)
            assert uninstall(env.project) == 1
            assert snapshot(env.project, env.home) == before
            assert _AEGIS_HOOK_START in hook.read_text(encoding="utf-8")
            err = capsys.readouterr().err
            assert "read-only" in err and "Nothing was changed." in err
        finally:
            agents.chmod(0o644)

    def test_a_write_error_after_the_check_names_what_was_already_changed(self, env, capsys, monkeypatch):
        import aegis_cli.uninstall as uninstall_mod

        init(env, env.project, "codex-cli")
        real = uninstall_mod.unregister_workspace

        def disk_error(home, root, *, dry_run=False):
            if dry_run:
                return real(home, root, dry_run=True)
            raise PermissionError(13, "Permission denied", str(env.home / ".aegis" / "workspaces.json"))

        monkeypatch.setattr(uninstall_mod, "unregister_workspace", disk_error)
        capsys.readouterr()
        assert uninstall(env.project) == 1
        err = capsys.readouterr().err
        assert "workspaces.json: Permission denied" in err and "Already changed: AGENTS.md" in err

    @pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                        reason="needs POSIX directory permissions as a non-root user")
    def test_a_read_only_hooks_directory_refuses_before_anything_changes(self, env, capsys):
        init(env, env.project, "antigravity")
        hook = self._hooked(env)
        hook.parent.chmod(0o555)
        try:
            before = snapshot(env.project, env.home)
            assert uninstall(env.project) == 1
            assert snapshot(env.project, env.home) == before
            err = capsys.readouterr().err
            assert "not a writable directory" in err and "Nothing was changed." in err
        finally:
            hook.parent.chmod(0o755)

    def test_aegis_hook_behind_a_link_outside_the_repository_refuses_everything(self, env, tmp_path, capsys):
        init(env, env.project, "antigravity")
        outside = tmp_path / "dotfiles" / "pre-commit"
        outside.parent.mkdir()
        outside.write_text("#!/bin/sh\n" + generate_hook_block("/usr/bin/python3"), encoding="utf-8")
        hooks = env.project / ".git" / "hooks"
        hooks.mkdir(parents=True)
        symlink_or_skip(outside, hooks / "pre-commit")
        before = snapshot(env.project, env.home)
        outside_before = outside.read_bytes()
        assert uninstall(env.project) == 1
        assert snapshot(env.project, env.home) == before
        assert outside.read_bytes() == outside_before
        err = capsys.readouterr().err
        assert "outside the repository" in err and "aegis hook uninstall --force" in err

    def test_a_foreign_hook_behind_a_link_is_left_alone(self, env, tmp_path):
        init(env, env.project, "antigravity")
        outside = tmp_path / "dotfiles" / "pre-commit"
        outside.parent.mkdir()
        outside.write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
        hooks = env.project / ".git" / "hooks"
        hooks.mkdir(parents=True)
        symlink_or_skip(outside, hooks / "pre-commit")
        assert uninstall(env.project) == 0
        assert outside.read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
        assert (hooks / "pre-commit").is_symlink()


class TestLinkedClaudeMd:
    """A CLAUDE.md that is a link (usually to AGENTS.md) must not block uninstall: there is
    nothing of Aegis to remove from it unless the file it points to holds the import block."""

    def test_a_link_to_agents_md_is_kept_and_agents_md_is_not_deleted(self, env, capsys):
        init(env, env.project, "codex-cli")
        claude = env.project / "CLAUDE.md"
        symlink_or_skip("AGENTS.md", claude)
        assert uninstall(env.project) == 0
        assert os.readlink(claude) == "AGENTS.md"
        # AGENTS.md held only the Aegis block, but deleting it would leave CLAUDE.md dangling.
        assert (env.project / "AGENTS.md").read_bytes() == b""
        assert "Nothing was changed." not in capsys.readouterr().err

    def test_user_text_in_a_linked_agents_md_is_kept(self, env):
        agents = env.project / "AGENTS.md"
        agents.write_text("# Ours\n", encoding="utf-8")
        init(env, env.project, "codex-cli")
        symlink_or_skip("AGENTS.md", env.project / "CLAUDE.md")
        assert uninstall(env.project) == 0
        assert agents.read_text(encoding="utf-8") == "# Ours\n"

    def test_a_link_to_a_file_without_the_block_is_nothing_to_remove(self, env, tmp_path):
        init(env, env.project, "codex-cli")
        outside = tmp_path / "shared.md"
        outside.write_bytes(b"# shared\n")
        symlink_or_skip(outside, env.project / "CLAUDE.md")
        assert uninstall(env.project) == 0
        assert outside.read_bytes() == b"# shared\n"
        assert (env.project / "CLAUDE.md").is_symlink()
        assert not (env.project / "AGENTS.md").exists()

    def test_a_link_to_a_file_holding_the_block_refuses_everything(self, env, tmp_path, capsys):
        claude = env.project / "CLAUDE.md"
        claude.write_text("# Claude\n", encoding="utf-8")
        init(env, env.project, "codex-cli")
        outside = tmp_path / "shared.md"
        claude.replace(outside)
        symlink_or_skip(outside, claude)
        env.runner.calls.clear()
        before, outside_before = snapshot(env.project, env.home), outside.read_bytes()
        assert uninstall(env.project) == 1
        assert snapshot(env.project, env.home) == before
        assert outside.read_bytes() == outside_before
        assert env.runner.calls == []
        err = capsys.readouterr().err
        assert str(outside) in err and "never writes through a link" in err and "Nothing was changed." in err


class TestLinkedAgentsMd:
    """An AGENTS.md that is a link (often to CLAUDE.md) must not block uninstall either:
    init never wrote through it, so unless its target holds the bootstrap block there is
    nothing of Aegis in it, and the hosts and registry entry are still removed."""

    def test_a_link_to_a_file_without_the_block_is_nothing_to_remove(self, env):
        init(env, env.project, "codex-cli")
        agents, claude = env.project / "AGENTS.md", env.project / "CLAUDE.md"
        agents.unlink()
        claude.write_bytes(b"# Claude\n")
        symlink_or_skip("CLAUDE.md", agents)
        env.runner.calls.clear()
        assert uninstall(env.project) == 0
        assert os.readlink(agents) == "CLAUDE.md" and claude.read_bytes() == b"# Claude\n"
        assert registry(env) == {"v": 1, "workspaces": []}
        assert env.runner.calls[0] == ["codex", "mcp", "remove", "aegis"]

    def test_json_names_it_absent(self, env, tmp_path, capsys):
        outside = tmp_path / "guide.md"
        outside.write_bytes(b"# Guide\n")
        symlink_or_skip(outside, env.project / "AGENTS.md")
        assert main(["--json", "uninstall", "--workspace", str(env.project)]) == 0
        actions = {a["target"]: a for a in json.loads(capsys.readouterr().out)["actions"]}
        assert actions["AGENTS.md"]["result"] == "absent"
        assert outside.read_bytes() == b"# Guide\n"


GIT = shutil.which("git")


@pytest.mark.skipif(GIT is None, reason="needs git")
class TestSharedHooksDirectory:
    """core.hooksPath outside the repository: its pre-commit hook may serve other
    repositories, so uninstall does not edit it; with no Aegis block there is nothing to do."""

    @pytest.fixture
    def shared(self, env, monkeypatch):
        monkeypatch.setenv("PATH", os.pathsep.join([str(env.bin), os.path.dirname(GIT)]))
        subprocess.run([GIT, "init", "-q", str(env.project)], check=True, capture_output=True)
        shared = env.tmp / "team-hooks"
        shared.mkdir()
        subprocess.run([GIT, "-C", str(env.project), "config", "core.hooksPath", str(shared)],
                       check=True, capture_output=True)
        init(env, env.project, "codex-cli")
        env.runner.calls.clear()
        return shared

    def test_an_aegis_block_there_refuses_everything(self, env, shared, capsys):
        hook = shared / "pre-commit"
        hook.write_text("#!/bin/sh\necho team\n\n" + generate_hook_block("/usr/bin/python3"), encoding="utf-8")
        before, hook_before = snapshot(env.project, env.home), hook.read_bytes()
        assert uninstall(env.project) == 1
        assert snapshot(env.project, env.home) == before
        assert hook.read_bytes() == hook_before
        assert env.runner.calls == []
        err = capsys.readouterr().err
        assert "outside this repository" in err and "aegis hook uninstall" in err and "Nothing was changed." in err

    def test_without_an_aegis_block_the_rest_is_uninstalled(self, env, shared):
        (shared / "pre-commit").write_bytes(b"#!/bin/sh\necho team\n")
        assert uninstall(env.project) == 0
        assert (shared / "pre-commit").read_bytes() == b"#!/bin/sh\necho team\n"
        assert not (env.project / "AGENTS.md").exists()
        assert env.runner.calls[0] == ["codex", "mcp", "remove", "aegis"]


class TestCommandLine:
    @pytest.mark.parametrize("argv, line", [
        (["uninstall", "--platform", "claude"], "aegis uninstall --platform was removed in v4: use aegis uninstall --host"),
        (["uninstall", "-p", "gemini"], "aegis uninstall --platform was removed in v4: use aegis uninstall --host"),
        (["uninstall", "--local"], "aegis uninstall --local was removed in v4: use aegis uninstall"),
        (["uninstall", "--purge"], "aegis uninstall --purge was removed in v4: aegis uninstall never deletes "
                                   ".aegis/; remove it yourself (git rm -r .aegis)"),
    ])
    def test_removed_flags_exit_2_with_one_pointer_line(self, env, argv, line, capsys):
        init(env, env.project, "codex-cli")
        capsys.readouterr()
        before = snapshot(env.project, env.home)
        with pytest.raises(SystemExit) as exc:
            main(argv + ["--workspace", str(env.project)])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert (captured.out, captured.err) == ("", line + "\n")
        assert snapshot(env.project, env.home) == before

    @pytest.mark.parametrize("value, message", [
        ("gemini-cli", "gemini-cli is not supported: Google retired Gemini CLI for individual Code Assist "
                       "accounts; use --host antigravity."),
        ("claude-desktop", "claude-desktop is identity only: Aegis does not register there (ADR 0005 H4); "
                           "the Claude desktop app's Code tab shares Claude Code's configuration: "
                           "use --host claude-code"),
    ])
    def test_naming_a_host_aegis_never_registers_exits_2_with_its_reason(self, env, value, message, capsys):
        init(env, env.project, "codex-cli")
        capsys.readouterr()
        before = snapshot(env.project, env.home)
        with pytest.raises(SystemExit) as exc:
            uninstall(env.project, "--host", value)
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines()[-1] == f"aegis uninstall: error: argument --host: {message}"
        assert snapshot(env.project, env.home) == before

    @pytest.mark.parametrize("value, message", [("auto", "names hosts"), ("zed", "unknown host")])
    def test_bad_host_is_a_usage_error(self, env, value, message, capsys):
        with pytest.raises(SystemExit) as exc:
            uninstall(env.project, "--host", value)
        assert exc.value.code == 2
        assert message in capsys.readouterr().err


def test_uninstall_says_host_hooks_stay_until_hook_uninstall(tmp_path, monkeypatch, capsys):
    """User-scope host hooks live outside the workspace; uninstall must not leave them unmentioned."""
    from aegis_cli.cli import main

    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    (repo / ".aegis" / "rules").mkdir(parents=True)
    subprocess_run = __import__("subprocess").run
    subprocess_run(["git", "init", "-q"], cwd=repo, check=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.chdir(repo)
    assert main(["uninstall", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "aegis hook uninstall --host <host>" in out
    assert "aegis rule insight enable" in out
