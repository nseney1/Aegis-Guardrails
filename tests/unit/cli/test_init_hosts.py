"""`aegis init --host ...` on a fake HOME: the exact files each host selection writes.

Lens: user-data safety on real config files. A second init changes nothing, a dry run
writes nothing, and a file Aegis cannot change safely (unparseable JSON, a symlinked
AGENTS.md, a hand-edited block) stops init before anything at all is written.
Host CLIs are replaced at the subprocess boundary (``install_hosts._run_cli``).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import symlink_or_skip

import aegis_cli.install_hosts as ih
from aegis_cli import pathcheck
from aegis_cli.cli import main
from aegis_core.bootstrap import bootstrap_text

STANDARD = {"providence", "destructive-ops", "testing", "cost-optimization", "git-workflow"}


class Runner:
    def __init__(self, returncode: int = 0):
        self.calls: list = []
        self.returncode = returncode

    def __call__(self, argv):
        # The binary's name without its extension: Windows spells it as the file on disk does.
        self.calls.append([Path(argv[0]).stem, *argv[1:]])
        return subprocess.CompletedProcess(argv, self.returncode, "", "" if self.returncode == 0 else "denied")


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A project, an empty HOME, a PATH holding only fake host binaries and aegis-mcp."""
    project = tmp_path / "project"
    project.mkdir()
    home = Path.home()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("codex", "claude", "agy", "aegis-mcp"):
        exe = bindir / (name + (".exe" if os.name == "nt" else ""))
        exe.write_bytes(b"#!/bin/sh\nexit 0\n")
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    runner = Runner()
    monkeypatch.setattr(ih, "_run_cli", runner)
    # The aegis-mcp found on PATH, as found: never the target of a link (a version
    # manager's dispatcher picks the tool from the name it is run under).
    mcp = str(bindir / ("aegis-mcp" + (".exe" if os.name == "nt" else "")))
    return type("Env", (), {"project": project, "home": home, "bin": bindir, "runner": runner, "mcp": mcp})


def init(env, *flags) -> int:
    return main(["init", "--workspace", str(env.project), "--yes", "--no-hooks", "--rules", "standard", *flags])


def files(root: Path, skip_state: bool = True) -> set:
    found = set()
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            rel = Path(dirpath, name).relative_to(root).as_posix()
            if skip_state and rel.startswith(".aegis/state/"):
                continue
            found.add(rel)
    return found


def snapshot(*roots: Path) -> dict:
    out = {}
    for root in roots:
        for dirpath, dirs, names in os.walk(root):
            for name in dirs + names:
                p = Path(dirpath, name)
                out[str(p)] = "<dir>" if p.is_dir() and not p.is_symlink() else (
                    os.readlink(p) if p.is_symlink() else p.read_bytes())
    return out


# `aegis init` also creates the session-label pseudonymization key (v4.4 spec 3.4 / §12.2).
LINK_KEY = ".aegis/link.key"

# A new workspace also gets the one active starter rule (v4.1 d5).
REPO_FILES = {".aegis/config.json", ".aegis/.gitignore", "AGENTS.md", ".aegis/rules/invariants/no-eval.md"} | {
    f".aegis/rules/personas/{n}.md" for n in STANDARD}


def _codex_add(mcp, *extra):
    return ["codex", "mcp", "add", "aegis", "--env", "AEGIS_CLIENT=codex-cli", *extra, "--", mcp]


def _claude_add(mcp, *extra):
    return ["claude", "mcp", "add", "--scope", "user", "aegis", "-e", "AEGIS_CLIENT=claude-code", *extra, "--", mcp]


class TestExactFilesPerHostSelection:
    def test_no_host_selected_registers_nothing_and_proposes_detected_hosts(self, env, capsys):
        assert init(env) == 0
        assert files(env.project) == REPO_FILES
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY}
        assert env.runner.calls == []
        assert json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8")) == {"v": 1}
        (entry,) = json.loads((env.home / ".aegis" / "workspaces.json").read_text(encoding="utf-8"))["workspaces"]
        assert entry["root"] == str(env.project.resolve()) and entry["hosts"] == []
        out = capsys.readouterr().out
        assert "aegis init --host codex-cli,claude-code,antigravity" in out

    def test_codex_only(self, env):
        assert init(env, "--host", "codex-cli") == 0
        assert files(env.project) == REPO_FILES
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY}
        assert env.runner.calls == [["codex", "mcp", "remove", "aegis"], _codex_add(env.mcp)]
        config = json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8"))
        assert config == {"v": 1, "hosts": ["codex-cli"]}

    def test_claude_code_only_at_user_scope(self, env):
        assert init(env, "--host", "claude-code") == 0
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY}
        assert env.runner.calls == [["claude", "mcp", "remove", "--scope", "user", "aegis"], _claude_add(env.mcp)]

    def test_antigravity_only_merges_its_json_file(self, env):
        assert init(env, "--host", "antigravity") == 0
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY, ".gemini/config/mcp_config.json"}
        assert env.runner.calls == []
        data = json.loads((env.home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
        assert data == {"mcpServers": {"aegis": {"command": env.mcp, "args": [],
                                                 "env": {"AEGIS_CLIENT": "antigravity"}}}}

    def test_all_three_hosts(self, env):
        assert init(env, "--host", "antigravity,claude-code,codex-cli") == 0
        assert files(env.project) == REPO_FILES
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY, ".gemini/config/mcp_config.json"}
        assert [c[0] for c in env.runner.calls] == ["codex", "codex", "claude", "claude"]
        registry = json.loads((env.home / ".aegis" / "workspaces.json").read_text(encoding="utf-8"))
        assert registry["v"] == 1
        (entry,) = registry["workspaces"]
        assert entry["hosts"] == ["codex-cli", "claude-code", "antigravity"]
        assert entry["added_by"] == "aegis init"

    def test_auto_registers_only_what_is_detected(self, env, monkeypatch):
        for name in ("codex", "agy"):
            (env.bin / (name + (".exe" if os.name == "nt" else ""))).unlink()
        assert init(env, "--host", "auto") == 0
        assert [c[0] for c in env.runner.calls] == ["claude", "claude"]
        assert not (env.home / ".gemini").exists()

    def test_kiro_by_a_surface_alias_merges_its_user_mcp_json_and_stores_the_plane_id(self, env, capsys):
        assert init(env, "--host", "kiro-ide") == 0
        assert files(env.project) == REPO_FILES
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY, ".kiro/settings/mcp.json"}
        assert env.runner.calls == []
        data = json.loads((env.home / ".kiro" / "settings" / "mcp.json").read_text(encoding="utf-8"))
        assert data == {"mcpServers": {"aegis": {"command": env.mcp, "args": [], "env": {"AEGIS_CLIENT": "kiro"}}}}
        config = json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8"))
        assert config == {"v": 1, "hosts": ["kiro"]}
        (entry,) = json.loads((env.home / ".aegis" / "workspaces.json").read_text(encoding="utf-8"))["workspaces"]
        assert entry["hosts"] == ["kiro"]
        out = capsys.readouterr().out
        assert "Hosts: kiro (Kiro IDE, Kiro CLI)" in out

    def test_an_unverified_host_is_registered_with_a_warning_that_says_so(self, env, capsys):
        assert init(env, "--host", "kiro,codex-cli") == 0
        captured = capsys.readouterr()
        warning = [line for line in captured.err.splitlines() if "kiro" in line]
        assert warning and "experimental" in warning[0] and "not yet checked on a real install" in warning[0]
        assert warning[0].lower().count("experimental") == 1
        assert not [line for line in captured.err.splitlines() if "codex-cli" in line]

    def test_auto_takes_an_ide_found_only_by_its_config_dir(self, env, capsys):
        for name in ("codex", "claude", "agy"):
            (env.bin / (name + (".exe" if os.name == "nt" else ""))).unlink()
        (env.home / ".kiro").mkdir()
        assert init(env, "--host", "auto") == 0
        assert env.runner.calls == []
        assert (env.home / ".kiro" / "settings" / "mcp.json").is_file()
        assert json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8"))["hosts"] == ["kiro"]

    def test_without_host_the_proposal_names_what_found_each_plane(self, env, capsys):
        (env.home / ".kiro").mkdir()
        assert init(env) == 0
        out = capsys.readouterr().out
        assert "aegis init --host codex-cli,claude-code,antigravity,kiro" in out
        assert "kiro (~/.kiro)" in out

    def test_pin_adds_the_workspace_env(self, env):
        assert init(env, "--host", "codex-cli,antigravity", "--pin") == 0
        root = str(env.project.resolve())
        assert env.runner.calls[-1] == _codex_add(env.mcp, "--env", f"AEGIS_WORKSPACE={root}")
        data = json.loads((env.home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
        assert data["mcpServers"]["aegis"]["env"] == {"AEGIS_CLIENT": "antigravity", "AEGIS_WORKSPACE": root}

    def test_without_aegis_mcp_on_path_the_script_next_to_the_interpreter_is_the_command(
            self, env, tmp_path, monkeypatch):
        (env.bin / ("aegis-mcp" + (".exe" if os.name == "nt" else ""))).unlink()
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        script = scripts / ("aegis-mcp" + (".exe" if os.name == "nt" else ""))
        script.write_bytes(b"#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        monkeypatch.setattr(pathcheck, "default_candidates", lambda: [str(scripts)])
        assert init(env, "--host", "codex-cli") == 0
        assert env.runner.calls[-1][-2:] == ["--", str(script)]

    def test_without_any_aegis_mcp_the_interpreter_runs_isolated_never_with_dash_m(self, env, monkeypatch):
        (env.bin / ("aegis-mcp" + (".exe" if os.name == "nt" else ""))).unlink()
        monkeypatch.setattr(pathcheck, "default_candidates", lambda: [])
        import sys
        assert init(env, "--host", "codex-cli,antigravity") == 0
        command = env.runner.calls[-1][env.runner.calls[-1].index("--") + 1:]
        assert command[:3] == [sys.executable, "-I", "-c"] and "-m" not in command
        data = json.loads((env.home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
        entry = data["mcpServers"]["aegis"]
        assert entry["command"] == sys.executable and entry["args"][:2] == ["-I", "-c"]
        assert "-m" not in entry["args"]

    def test_a_linked_aegis_mcp_is_written_as_the_path_entry(self, env, tmp_path):
        """mise or asdf put aegis-mcp on PATH as a link to one dispatcher; the config must
        start aegis-mcp, not the dispatcher (which would see its own name)."""
        dispatcher = tmp_path / "toolchain" / "mise"
        dispatcher.parent.mkdir()
        dispatcher.write_bytes(b"#!/bin/sh\nexit 0\n")
        dispatcher.chmod(0o755)
        link = Path(env.mcp)
        link.unlink()
        symlink_or_skip(dispatcher, link)
        assert init(env, "--host", "antigravity") == 0
        data = json.loads((env.home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
        assert data["mcpServers"]["aegis"]["command"] == env.mcp

    def test_existing_antigravity_servers_are_kept(self, env):
        from tests.contract.test_legacy_ratchet import REQUIRED_WORDS, _word_counts

        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"mcpServers": {"github": {"command": "gh"}}, "other": True}), encoding="utf-8")
        assert init(env, "--host", "antigravity") == 0
        data = json.loads(cfg.read_text(encoding="utf-8"))
        assert data["other"] is True and data["mcpServers"]["github"] == {"command": "gh"}
        assert not any(_word_counts(data["mcpServers"], REQUIRED_WORDS).values())


class TestBootstrapAndClaudeShim:
    def test_agents_md_gets_the_bootstrap_block_after_user_text(self, env):
        agents = env.project / "AGENTS.md"
        agents.write_text("# Our agents guide\n", encoding="utf-8")
        assert init(env) == 0
        text = agents.read_text(encoding="utf-8")
        assert text.startswith("# Our agents guide\n\n<!-- aegis:begin id=bootstrap v=1 sha=")
        assert bootstrap_text() in text
        assert text.endswith("<!-- aegis:end id=bootstrap -->\n")

    def test_claude_md_is_never_created(self, env):
        assert init(env, "--host", "claude-code") == 0
        assert not (env.project / "CLAUDE.md").exists()

    def test_existing_claude_md_gets_the_agents_import_block(self, env):
        claude = env.project / "CLAUDE.md"
        claude.write_bytes(b"# Claude notes\r\n")
        assert init(env) == 0
        assert claude.read_bytes() == (
            b"# Claude notes\r\n\r\n<!-- aegis:begin id=agents-import v=1 sha="
            + ih._digest("@AGENTS.md\n").encode() + b" -->\r\n@AGENTS.md\r\n<!-- aegis:end id=agents-import -->\r\n")

    def test_a_claude_md_linked_to_agents_md_needs_no_import(self, env, capsys):
        """`ln -s AGENTS.md CLAUDE.md` is the usual way to give Claude Code the same file:
        it already reads the bootstrap, so the link is kept and nothing is written through it."""
        agents = env.project / "AGENTS.md"
        agents.write_text("# Team guide\n", encoding="utf-8")
        symlink_or_skip("AGENTS.md", env.project / "CLAUDE.md")
        assert init(env, "--host", "claude-code") == 0
        assert os.readlink(env.project / "CLAUDE.md") == "AGENTS.md"
        text = agents.read_text(encoding="utf-8")
        assert text.startswith("# Team guide\n\n") and bootstrap_text() in text
        assert "agents-import" not in text
        captured = capsys.readouterr()
        assert "CLAUDE.md: linked" in captured.out and captured.err == ""
        before = snapshot(env.project, env.home)
        assert init(env, "--host", "claude-code") == 0
        def outside_state(snap):
            return {k: v for k, v in snap.items() if "/.aegis/state" not in k.replace(os.sep, "/")}
        assert outside_state(snapshot(env.project, env.home)) == outside_state(before)

    def test_a_claude_md_link_to_an_agents_md_init_creates(self, env):
        symlink_or_skip("AGENTS.md", env.project / "CLAUDE.md")
        assert init(env) == 0
        assert (env.project / "CLAUDE.md").is_symlink()
        assert bootstrap_text() in (env.project / "CLAUDE.md").read_text(encoding="utf-8")

    def test_a_claude_md_linked_elsewhere_is_left_alone_with_a_warning(self, env, capsys, tmp_path):
        outside = tmp_path / "shared" / "CLAUDE.md"
        outside.parent.mkdir()
        outside.write_bytes(b"x\n")
        symlink_or_skip(outside, env.project / "CLAUDE.md")
        assert init(env, "--host", "codex-cli") == 0
        assert outside.read_bytes() == b"x\n"
        assert (env.project / "CLAUDE.md").is_symlink()
        assert bootstrap_text() in (env.project / "AGENTS.md").read_text(encoding="utf-8")
        err = capsys.readouterr().err
        assert str(outside) in err and "never writes through a link" in err and "@AGENTS.md" in err

    def test_force_replaces_a_hand_edited_bootstrap(self, env):
        agents = env.project / "AGENTS.md"
        agents.write_text("<!-- aegis:begin id=bootstrap v=1 sha=000000000000 -->\nmine\n"
                          "<!-- aegis:end id=bootstrap -->\n", encoding="utf-8")
        assert init(env, "--force") == 0
        assert bootstrap_text() in agents.read_text(encoding="utf-8")


class TestIdempotency:
    def test_second_init_changes_nothing(self, env):
        claude = env.project / "CLAUDE.md"
        claude.write_text("# mine\n", encoding="utf-8")
        assert init(env, "--host", "codex-cli,claude-code,antigravity") == 0
        before = snapshot(env.project, env.home)
        first_calls = list(env.runner.calls)
        assert init(env, "--host", "codex-cli,claude-code,antigravity") == 0
        after = snapshot(env.project, env.home)
        assert {k: v for k, v in after.items() if "/.aegis/state" not in k.replace(os.sep, "/")} == \
               {k: v for k, v in before.items() if "/.aegis/state" not in k.replace(os.sep, "/")}
        # The native registrations converge (remove-then-add with the same argv).
        assert env.runner.calls == first_calls * 2

    def test_a_second_host_is_added_to_config_and_registry(self, env):
        assert init(env, "--host", "antigravity") == 0
        assert init(env, "--host", "codex-cli") == 0
        config = json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8"))
        assert config["hosts"] == ["codex-cli", "antigravity"]
        (entry,) = json.loads((env.home / ".aegis" / "workspaces.json").read_text(encoding="utf-8"))["workspaces"]
        assert entry["hosts"] == ["codex-cli", "antigravity"]


class TestRefusalsWriteNothing:
    def _refused(self, env, capsys, *flags, message):
        before = snapshot(env.project, env.home)
        assert init(env, *flags) == 1
        assert snapshot(env.project, env.home) == before
        assert env.runner.calls == []
        assert message in capsys.readouterr().err

    @pytest.mark.parametrize("raw", [b'{"mcpServers": {}, // jsonc\n}', b"\xef\xbb\xbf{}", b'{"mcpServers": {},}'])
    def test_unparseable_antigravity_config(self, env, capsys, raw):
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_bytes(raw)
        self._refused(env, capsys, "--host", "codex-cli,antigravity", message=str(cfg))

    def test_symlinked_antigravity_config(self, env, capsys, tmp_path):
        real = tmp_path / "dotfiles.json"
        real.write_bytes(b"{}")
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        symlink_or_skip(real, cfg)
        self._refused(env, capsys, "--host", "antigravity", message="symlink")
        assert real.read_bytes() == b"{}"

    def test_symlinked_agents_md(self, env, capsys, tmp_path):
        outside = tmp_path / "outside.md"
        outside.write_bytes(b"not yours\n")
        symlink_or_skip(outside, env.project / "AGENTS.md")
        self._refused(env, capsys, "--host", "codex-cli", message="symlink")
        assert outside.read_bytes() == b"not yours\n"

    def test_agents_md_linked_to_claude_md_names_the_layout_aegis_supports(self, env, capsys):
        """`ln -s CLAUDE.md AGENTS.md` is common; the refusal names the target and the way
        out (the reverse link, which init handles), not only "replace the link"."""
        (env.project / "CLAUDE.md").write_bytes(b"# Claude\n")
        symlink_or_skip("CLAUDE.md", env.project / "AGENTS.md")
        before = snapshot(env.project, env.home)
        assert init(env, "--host", "codex-cli") == 1
        assert snapshot(env.project, env.home) == before
        err = capsys.readouterr().err
        assert str((env.project / "CLAUDE.md").resolve()) in err
        assert "make CLAUDE.md the link to AGENTS.md" in err and "Nothing was written." in err

    def test_hand_edited_bootstrap_block(self, env, capsys):
        (env.project / "AGENTS.md").write_text(
            "<!-- aegis:begin id=bootstrap v=1 sha=000000000000 -->\nmine\n<!-- aegis:end id=bootstrap -->\n",
            encoding="utf-8")
        self._refused(env, capsys, "--host", "codex-cli", message="--force")

    def test_unreadable_registry(self, env, capsys):
        reg = env.home / ".aegis" / "workspaces.json"
        reg.parent.mkdir(parents=True)
        reg.write_bytes(b"[broken")
        self._refused(env, capsys, message="workspaces.json")

    def test_symlinked_config_json(self, env, capsys, tmp_path):
        (env.project / ".aegis").mkdir()
        symlink_or_skip(tmp_path / "planted.json", env.project / ".aegis" / "config.json")
        self._refused(env, capsys, message="symlink")
        assert not (tmp_path / "planted.json").exists()


class TestRefusalsTheCheckPassMustSee:
    """Refusals that only the write used to notice: init had already written .aegis/,
    AGENTS.md, the registry and a config backup when it stopped."""

    def _refused(self, env, capsys, *flags, message):
        before = snapshot(env.project, env.home)
        assert init(env, *flags) == 1
        assert snapshot(env.project, env.home) == before
        assert env.runner.calls == []
        err = capsys.readouterr().err
        assert message in err and "Nothing was written." in err

    def test_read_only_antigravity_config(self, env, capsys):
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"mcpServers": {"x": {"env": {"API_KEY": "k"}}}}), encoding="utf-8")
        cfg.chmod(0o444)
        try:
            self._refused(env, capsys, "--host", "codex-cli,antigravity", message="read-only")
        finally:
            cfg.chmod(0o644)

    def test_read_only_agents_md(self, env, capsys):
        agents = env.project / "AGENTS.md"
        agents.write_text("# Team guide\n", encoding="utf-8")
        agents.chmod(0o444)
        try:
            self._refused(env, capsys, "--host", "antigravity", message="read-only")
        finally:
            agents.chmod(0o644)

    def test_config_that_cannot_be_written_back(self, env, capsys):
        cfg = env.home / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_bytes(b'{"mcpServers": {"x": {"command": "\\ud800"}}}')
        self._refused(env, capsys, "--host", "antigravity", message="surrogate")

    def test_dry_run_reports_the_refusal(self, env, capsys):
        agents = env.project / "AGENTS.md"
        agents.write_text("# Team guide\n", encoding="utf-8")
        agents.chmod(0o444)
        try:
            before = snapshot(env.project, env.home)
            assert main(["init", "--workspace", str(env.project), "--dry-run", "--no-hooks"]) == 1
            assert snapshot(env.project, env.home) == before
            assert "read-only" in capsys.readouterr().err
        finally:
            agents.chmod(0o644)


class TestDryRunAndFailures:
    def test_dry_run_writes_nothing_and_runs_no_host_cli(self, env, capsys):
        before = snapshot(env.project, env.home)
        assert main(["init", "--workspace", str(env.project), "--dry-run", "--host",
                     "codex-cli,claude-code,antigravity"]) == 0
        assert snapshot(env.project, env.home) == before
        assert env.runner.calls == []
        out = capsys.readouterr().out
        assert "codex mcp add aegis --env AEGIS_CLIENT=codex-cli --" in out
        assert "mcp_config.json" in out

    def test_missing_host_cli_prints_the_exact_command(self, env, capsys):
        (env.bin / ("claude" + (".exe" if os.name == "nt" else ""))).unlink()
        assert init(env, "--host", "claude-code") == 0
        assert env.runner.calls == []
        out = capsys.readouterr().out
        assert ih.display_command(_claude_add(env.mcp)) in out

    def test_a_host_left_to_the_user_is_not_reported_as_governed(self, env, capsys):
        for name in ("codex", "claude"):
            (env.bin / (name + (".exe" if os.name == "nt" else ""))).unlink()
        assert init(env, "--host", "codex-cli,claude-code,antigravity") == 0
        out = capsys.readouterr().out
        assert "will be governed" not in out
        assert "Done, but 2 hosts are not registered until you run the commands above." in out

    def test_one_host_left_to_the_user_is_named_in_the_singular(self, env, capsys):
        (env.bin / ("codex" + (".exe" if os.name == "nt" else ""))).unlink()
        assert init(env, "--host", "codex-cli,antigravity") == 0
        assert "Done, but 1 host is not registered until you run the command above." in capsys.readouterr().out

    def test_every_host_registered_is_reported_as_governed(self, env, capsys):
        assert init(env, "--host", "codex-cli,antigravity") == 0
        assert "Done! Your next agent session will be governed." in capsys.readouterr().out

    def test_failed_registration_exits_1_after_the_other_steps(self, env, capsys, monkeypatch):
        monkeypatch.setattr(ih, "_run_cli", Runner(returncode=1))
        assert init(env, "--host", "codex-cli,antigravity") == 1
        assert (env.project / "AGENTS.md").is_file()
        assert (env.home / ".gemini" / "config" / "mcp_config.json").is_file()
        assert "codex-cli" in capsys.readouterr().err


# ── experimental hosts: the documented file, a warning and an init_host event (v4.2 #6) ──

EXPERIMENTAL_FILES = {
    "kiro": ".kiro/settings/mcp.json",
    "cursor": ".cursor/mcp.json",
    "copilot": ".copilot/mcp-config.json",
    "windsurf": ".codeium/windsurf/mcp_config.json",
}


def init_host_events(env):
    from aegis_core import events

    found = events.read(env.project, "init_host")
    assert found.error is None and found.malformed == 0
    return found.rows


class TestExperimentalHosts:
    @pytest.mark.parametrize("host_id", sorted(EXPERIMENTAL_FILES))
    def test_each_registers_in_its_documented_file_and_warns(self, env, capsys, host_id):
        assert init(env, "--host", host_id) == 0
        assert files(env.home) == {".aegis/workspaces.json", LINK_KEY, EXPERIMENTAL_FILES[host_id]}
        assert env.runner.calls == []
        data = json.loads(env.home.joinpath(*EXPERIMENTAL_FILES[host_id].split("/")).read_text(encoding="utf-8"))
        assert data == {"mcpServers": {"aegis": {"command": env.mcp, "args": [], "env": {"AEGIS_CLIENT": host_id}}}}
        config = json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8"))
        assert config == {"v": 1, "hosts": [host_id]}
        err = capsys.readouterr().err
        (warning,) = [line for line in err.splitlines() if "is an experimental host" in line]
        assert f"{host_id} is an experimental host." in warning
        assert "not yet checked on a real install" in warning and "3 clean runs" in warning

    def test_an_alias_selects_the_plane_and_the_config_stores_the_plane_id(self, env):
        assert init(env, "--host", "cursor-ide,github-copilot,windsurf-ide") == 0
        config = json.loads((env.project / ".aegis" / "config.json").read_text(encoding="utf-8"))
        assert config["hosts"] == ["cursor", "copilot", "windsurf"]

    def test_init_writes_one_init_host_event_for_each_experimental_host_and_none_for_the_others(self, env):
        assert init(env, "--host", "codex-cli,kiro,cursor") == 0
        rows = init_host_events(env)
        assert [(r["host"], r["result"], r["detail"]["host"], r["detail"]["verified"]) for r in rows] == [
            ("kiro", "experimental", "kiro", False), ("cursor", "experimental", "cursor", False)]
        assert all(r["worktree"] == Path(env.project).resolve().as_posix() for r in rows)
        assert init(env, "--host", "cursor") == 0  # every run is an event: the prune metric counts runs
        assert [r["host"] for r in init_host_events(env)] == ["kiro", "cursor", "cursor"]

    def test_a_verified_host_and_a_dry_run_write_no_event(self, env):
        assert init(env, "--host", "codex-cli,claude-code,antigravity") == 0
        assert init_host_events(env) == []
        assert init(env, "--host", "kiro,windsurf", "--dry-run") == 0
        assert init_host_events(env) == []
        assert not (env.home / ".kiro").exists()

    def test_auto_takes_an_ide_found_by_its_config_dir_and_records_it(self, env):
        for name in ("codex", "claude", "agy"):
            (env.bin / (name + (".exe" if os.name == "nt" else ""))).unlink()
        (env.home / ".cursor").mkdir()
        assert init(env, "--host", "auto") == 0
        assert (env.home / ".cursor" / "mcp.json").is_file()
        assert [r["host"] for r in init_host_events(env)] == ["cursor"]

    def test_an_event_that_cannot_be_recorded_never_fails_init(self, env, capsys, monkeypatch):
        from aegis_core import events

        def refuse(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(events, "append", refuse)
        assert init(env, "--host", "kiro") == 0
        err = capsys.readouterr().err
        assert "the init_host event for kiro could not be recorded (OSError: disk full)" in err
        assert (env.home / ".kiro" / "settings" / "mcp.json").is_file()
