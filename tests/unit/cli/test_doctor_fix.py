"""`aegis doctor --fix`: only what doctor reported, after confirmation, behind a backup.

Every file --fix touches is first copied to ~/.aegis/backups/<UTC stamp>/ (with a
manifest); writes are atomic; a symlink, a hard link or a file that changed since the
check is refused, never followed or overwritten; and nothing else is touched.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from aegis_cli import doctor, doctor_base
from aegis_cli.doctor import run_doctor
from aegis_core.bootstrap import BOOTSTRAP_ID, bootstrap_text


class Env:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.ws = tmp_path / "repo"
        rules = self.ws / ".aegis" / "rules" / "invariants"
        rules.mkdir(parents=True)
        (rules / "invariant-sample.md").write_text(
            "---\nid: invariant-sample\ntype: invariant\nenforcement: gate\n"
            "hypothesis: Sample rule for doctor tests.\ntarget_paths:\n  - src/*.py\n---\n"
            "# Sample\n\nKeep the sample rule body long enough to be a real rule body.\n", encoding="utf-8")
        body = bootstrap_text()
        sha = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
        (self.ws / "AGENTS.md").write_text(
            f"<!-- aegis:begin id={BOOTSTRAP_ID} v=1 sha={sha} -->\n{body}<!-- aegis:end id={BOOTSTRAP_ID} -->\n",
            encoding="utf-8")
        for name, value in (("HOME", self.home), ("USERPROFILE", self.home), ("PATH", self.bin),
                            ("APPDATA", self.home / "AppData" / "Roaming")):
            monkeypatch.setenv(name, str(value))
        for name in ("CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "CODEX_HOME", "AEGIS_WORKSPACE", "AEGIS_CLIENT"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(doctor, "_run_host_cli", self._no_cli)
        for name in ("aegis", "aegis-mcp"):  # aegis on PATH keeps the CLI check green
            stub = self.bin / (name + (".exe" if os.name == "nt" else ""))
            stub.write_text("#!/bin/sh\n", encoding="utf-8")
            stub.chmod(0o755)
        self.mcp = stub

    @staticmethod
    def _no_cli(argv, cwd, timeout):
        raise AssertionError(f"--fix tests run no host CLI: {argv}")

    def write_json(self, path: Path, data: Dict[str, Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def claude_user_registration(self, **extra):
        data = {"numStartups": 7, "mcpServers": {"aegis": {
            "command": str(self.mcp), "args": [], "env": {"AEGIS_CLIENT": "claude-code"}}}}
        data.update(extra)
        return self.write_json(self.home / ".claude.json", data)

    def run(self, **kw):
        args = argparse.Namespace(workspace=str(self.ws), fix=False, yes=False, drivers=False, json=False)
        for key, value in kw.items():
            setattr(args, key, value)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_doctor(args)
        return rc, buf.getvalue()

    def fix(self, **kw) -> Dict[str, Any]:
        rc, out = self.run(fix=True, yes=True, json=True, **kw)
        payload = json.loads(out)
        payload["_rc"] = rc
        return payload

    def backups(self):
        root = self.home / ".aegis" / "backups"
        return sorted(root.iterdir()) if root.is_dir() else []


@pytest.fixture
def env(tmp_path, monkeypatch) -> Env:
    return Env(tmp_path, monkeypatch)


def _snapshot(root: Path):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_fix_on_a_non_terminal_without_yes_changes_nothing(env, monkeypatch):
    stale = env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {"command": "soma-mcp"}}})
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    before = _snapshot(env.tmp)
    rc, out = env.run(fix=True)
    assert rc == 1
    assert "--yes" in out
    assert _snapshot(env.tmp) == before
    assert json.loads(stale.read_text())["mcpServers"] == {"soma": {"command": "soma-mcp"}}


def test_fix_asks_first_and_a_no_changes_nothing(env, monkeypatch):
    env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    monkeypatch.setattr(doctor_base, "_confirm", lambda prompt: False)
    before = _snapshot(env.tmp)
    rc, out = env.run(fix=True)
    assert rc == 1 and "No changes made" in out
    assert _snapshot(env.tmp) == before


@pytest.mark.parametrize("argv, message", [
    (["doctor", "--yes"], "--yes only applies to --fix"),
    (["doctor", "--json", "--fix"], "--json --fix needs --yes"),
])
def test_usage_errors(argv, message, env, capsys):
    from aegis_cli.cli import main
    assert main(argv + ["--workspace", str(env.ws)]) == 2
    assert message in capsys.readouterr().err


def test_fix_removes_reported_soma_entries_and_keeps_everything_else(env):
    claude = env.claude_user_registration(
        mcpServers={"aegis": {"command": str(env.mcp), "env": {"AEGIS_CLIENT": "claude-code"}},
                    "soma": {"command": "soma-mcp"}, "github": {"command": "gh-mcp"}},
        projects={"/p": {"allowedTools": ["Bash"], "mcpServers": {"soma": {}, "keep": {"command": "k"}}}})
    home_mcp = env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}, "other": 1})
    proj_mcp = env.write_json(env.ws / ".mcp.json", {"mcpServers": {"soma": {}, "db": {"command": "db"}}})
    originals = {p: p.read_bytes() for p in (claude, home_mcp, proj_mcp)}

    payload = env.fix()
    assert payload["_rc"] == 0
    assert {f["status"] for f in payload["fixes"]} == {"applied"}

    data = json.loads(claude.read_text())
    assert data["numStartups"] == 7
    assert data["mcpServers"] == {"aegis": {"command": str(env.mcp), "env": {"AEGIS_CLIENT": "claude-code"}},
                                  "github": {"command": "gh-mcp"}}
    assert data["projects"] == {"/p": {"allowedTools": ["Bash"], "mcpServers": {"keep": {"command": "k"}}}}
    assert json.loads(home_mcp.read_text()) == {"mcpServers": {}, "other": 1}
    assert json.loads(proj_mcp.read_text()) == {"mcpServers": {"db": {"command": "db"}}}

    (backup,) = env.backups()
    assert Path(payload["backup_dir"]) == backup
    manifest = json.loads((backup / "manifest.json").read_text())
    assert sorted(Path(e["path"]) for e in manifest["files"]) == sorted(originals)
    for entry in manifest["files"]:
        assert (backup / entry["backup"]).read_bytes() == originals[Path(entry["path"])]
        assert entry["sha256"] == hashlib.sha256(originals[Path(entry["path"])]).hexdigest()


def test_fix_moves_the_desktop_aegis_entry_out_and_keeps_its_other_servers(env):
    desktop = env.write_json(env.home / ".config" / "Claude" / "claude_desktop_config.json",
                             {"globalShortcut": "Ctrl+Space",
                              "mcpServers": {"aegis": {"command": "aegis-mcp"}, "files": {"command": "f"}}})
    original = desktop.read_bytes()
    payload = env.fix()
    assert json.loads(desktop.read_text()) == {"globalShortcut": "Ctrl+Space", "mcpServers": {"files": {"command": "f"}}}
    (backup,) = env.backups()
    assert original in [p.read_bytes() for p in backup.rglob("*") if p.is_file()]
    assert payload["_rc"] == 0


def test_fix_removes_a_misplaced_aegis_entry_only_when_the_user_registration_exists(env):
    misplaced = env.write_json(env.home / ".mcp.json", {"mcpServers": {"aegis": {"command": "aegis-mcp"}}})
    payload = env.fix()
    assert payload["fixes"] == []
    assert "aegis" in json.loads(misplaced.read_text())["mcpServers"]

    env.claude_user_registration()
    env.fix()
    assert json.loads(misplaced.read_text())["mcpServers"] == {}


def test_fix_removes_legacy_blocks_exactly_and_keeps_crlf_and_user_text(env):
    claude_md = env.ws / "CLAUDE.md"
    claude_md.write_bytes(b"@AGENTS.md\r\n\r\nMy notes.\r\n<!-- SOMA:START -->\r\n# Soma Governance Rules\r\n"
                          b"rule\r\n<!-- SOMA:END -->\r\nMore notes.\r\n")
    glob = env.home / ".claude" / "CLAUDE.md"
    glob.parent.mkdir()
    glob.write_bytes(b"mine\n<!-- AEGIS:START -->\nrules\n<!-- AEGIS:END -->\n")
    env.fix()
    assert claude_md.read_bytes() == b"@AGENTS.md\r\n\r\nMy notes.\r\nMore notes.\r\n"
    assert glob.read_bytes() == b"mine\n"


def test_fix_deletes_an_instruction_file_that_held_only_a_legacy_block(env):
    # An emptied CLAUDE.md would still stop Claude Code from reading AGENTS.md.
    claude_md = env.ws / "CLAUDE.md"
    original = b"<!-- SOMA:START -->\n# Soma Governance Rules\nrule\n<!-- SOMA:END -->\n"
    claude_md.write_bytes(original)
    payload = env.fix()
    assert not claude_md.exists()
    assert any(f["action"] == "delete_file" and f["status"] == "applied" for f in payload["fixes"])
    (backup,) = env.backups()
    assert original in [p.read_bytes() for p in backup.rglob("*") if p.is_file()]


def test_fix_never_touches_a_malformed_legacy_block(env):
    agents = env.home / ".codex" / "AGENTS.md"
    agents.parent.mkdir()
    agents.write_text("<!-- SOMA:START -->\nno end marker\n", encoding="utf-8")
    payload = env.fix()
    assert agents.read_text() == "<!-- SOMA:START -->\nno end marker\n"
    assert payload["fixes"] == []


def test_fix_removes_v3_rule_copies_by_digest_and_keeps_edited_ones(env, monkeypatch):
    shipped = b"---\nid: providence\n---\n# Providence\n"
    monkeypatch.setattr(doctor_base, "_V3_SHIPPED_RULE_SHA256", frozenset({hashlib.sha256(shipped).hexdigest()}))
    leak = env.home / ".gemini" / "config" / "rules" / "providence.md"
    oracle = env.home / ".kiro" / "steering" / ".oracles" / "testing.md"
    edited = env.home / ".kiro" / "steering" / "providence.md"
    for path, data in ((leak, shipped), (oracle, shipped), (edited, shipped + b"edit\n")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    env.fix()
    assert not leak.exists() and not oracle.exists()
    assert edited.read_bytes() == shipped + b"edit\n"
    (backup,) = env.backups()
    assert sum(p.read_bytes() == shipped for p in backup.rglob("*.md")) == 2


def test_fix_refuses_to_write_through_a_symlink(env, tmp_path):
    from conftest import symlink_or_skip
    target = env.write_json(tmp_path / "elsewhere.json", {"mcpServers": {"soma": {}}})
    symlink_or_skip(target, env.home / ".mcp.json")
    before = target.read_bytes()
    payload = env.fix()
    assert target.read_bytes() == before
    assert (env.home / ".mcp.json").is_symlink()
    finding = next(f for f in payload["findings"] if f["code"] == "legacy_mcp_entry")
    assert finding["fixable"] is False and "symlink" in finding["message"]


def test_fix_replaces_a_file_swapped_for_a_symlink_after_the_check_and_spares_the_link_target(env, tmp_path, monkeypatch):
    """R-cli-41: Given ~/.mcp.json checked as a regular file, When it is swapped for a symlink to
    another file just before the replacing write, Then the write replaces the link itself: the
    link's target keeps its bytes and no temporary file is left beside it."""
    from conftest import symlink_or_skip
    from aegis_core import storage

    mcp = env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}, "other": 1})
    victim = tmp_path / "victim.json"
    victim.write_bytes(b'{"keep": true}\n')
    real_write = storage.atomic_write_bytes
    swapped = []

    def swap_then_write(path, data, *args, **kwargs):
        if Path(path) == mcp and not swapped:
            os.unlink(mcp)
            symlink_or_skip(victim, mcp)
            swapped.append(path)
        return real_write(path, data, *args, **kwargs)

    monkeypatch.setattr(storage, "atomic_write_bytes", swap_then_write)
    payload = env.fix()
    assert swapped, "the swap happened before the write"
    assert {f["status"] for f in payload["fixes"]} == {"applied"}
    assert victim.read_bytes() == b'{"keep": true}\n'
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(".victim")) == []
    assert not mcp.is_symlink() and json.loads(mcp.read_text(encoding="utf-8")) == {"mcpServers": {}, "other": 1}


def test_fix_refuses_a_hard_linked_file(env, tmp_path):
    target = env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    try:
        os.link(target, tmp_path / "second-name.json")
    except OSError:
        pytest.skip("hard links unavailable")
    before = target.read_bytes()
    payload = env.fix()
    assert target.read_bytes() == before
    finding = next(f for f in payload["findings"] if f["code"] == "legacy_mcp_entry")
    assert finding["fixable"] is False and "hard link" in finding["message"]


def test_fix_skips_a_file_that_changed_after_the_check(env, monkeypatch):
    stale = env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    changed = json.dumps({"mcpServers": {"soma": {}, "new": {}}})

    def confirm_then_edit(prompt):
        stale.write_text(changed, encoding="utf-8")
        return True

    monkeypatch.setattr(doctor_base, "_confirm", confirm_then_edit)
    rc, out = env.run(fix=True)
    assert rc == 1
    assert stale.read_text() == changed
    assert "changed since the check" in out


def test_fix_touches_only_what_it_reported(env):
    env.claude_user_registration()
    env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    unrelated = {
        env.home / ".gemini" / "config" / "rules" / "my-rule.md": b"# mine\n",
        env.ws / "CLAUDE.md": b"@AGENTS.md\nnotes\n",
        env.home / ".codex" / "AGENTS.md": b"# codex global\n",
    }
    for path, data in unrelated.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    claude_before = (env.home / ".claude.json").read_bytes()
    agents_before = (env.ws / "AGENTS.md").read_bytes()
    env.fix()
    for path, data in unrelated.items():
        assert path.read_bytes() == data
    assert (env.home / ".claude.json").read_bytes() == claude_before
    assert (env.ws / "AGENTS.md").read_bytes() == agents_before


def test_a_second_fix_finds_nothing_left_to_do(env):
    env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    env.fix()
    payload = env.fix()
    assert payload["fixes"] == [] and payload["_rc"] == 0
    assert len(env.backups()) == 1


def test_fix_refuses_a_symlinked_user_plane(env, tmp_path):
    from conftest import symlink_or_skip
    env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    outside = tmp_path / "outside-aegis"
    outside.mkdir()
    symlink_or_skip(outside, env.home / ".aegis", target_is_directory=True)
    before = (env.home / ".mcp.json").read_bytes()
    payload = env.fix()
    assert payload["_rc"] == 1
    assert (env.home / ".mcp.json").read_bytes() == before
    assert list(outside.iterdir()) == []


def test_the_ast_driver_fix_also_needs_yes_and_backs_up_the_config(env, monkeypatch):
    (env.ws / "src").mkdir()
    (env.ws / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    config = env.ws / ".aegis" / "config.json"
    config.write_bytes(b'{"v": 1, "hosts": []}\n')
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    rc, _ = env.run(fix=True)
    assert rc == 1 and config.read_bytes() == b'{"v": 1, "hosts": []}\n'

    payload = env.fix()
    assert '"rs"' in config.read_text()
    (backup,) = env.backups()
    assert b'{"v": 1, "hosts": []}\n' in [p.read_bytes() for p in backup.rglob("*") if p.is_file()]
    assert any(f["action"] == "enable_packaged_ast_drivers" and f["status"] == "applied" for f in payload["fixes"])


def test_text_fix_lists_the_plan_and_where_the_backup_went(env, monkeypatch):
    env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    monkeypatch.setattr(doctor_base, "_confirm", lambda prompt: True)
    rc, out = env.run(fix=True)
    assert rc == 0
    assert "remove mcpServers.soma" in out
    assert str(env.home / ".aegis" / "backups") in out


@pytest.mark.parametrize("before, after", [
    (b'{\n\t"mcpServers": {\n\t\t"soma": {},\n\t\t"x": 1\n\t}\n}\n', b'{\n\t"mcpServers": {\n\t\t"x": 1\n\t}\n}\n'),
    (b'{\r\n    "mcpServers": {\r\n        "soma": {}\r\n    }\r\n}', b'{\r\n    "mcpServers": {}\r\n}'),
    (b'{"mcpServers": {"soma": {}, "x": "\xc3\xa9"}}', b'{"mcpServers": {"x": "\xc3\xa9"}}'),
])
def test_fix_keeps_the_files_own_json_formatting(env, before, after):
    path = env.home / ".mcp.json"
    path.write_bytes(before)
    env.fix()
    assert path.read_bytes() == after


# ── review findings 4 and 7, and a byte-order mark kept ─────────────────────

def test_the_plan_names_the_deletion_before_anything_is_confirmed(env, monkeypatch):
    claude_md = env.ws / "CLAUDE.md"
    claude_md.write_bytes(b"<!-- SOMA:START -->\n# Soma Governance Rules\nrule\n<!-- SOMA:END -->\n")
    prompts = []
    monkeypatch.setattr(doctor_base, "_confirm", lambda prompt: prompts.append(prompt) or False)
    rc, out = env.run(fix=True)
    assert prompts, "the plan is confirmed first"
    (line,) = [ln for ln in out.splitlines() if ln.strip().startswith("1. ") and str(claude_md) in ln]
    assert f"{claude_md}: delete the file (it holds only the legacy block, lines 1-4)" in line
    assert "remove the legacy block" not in line
    assert claude_md.exists()

    rc, out = env.run(json=True)
    (finding,) = [f for f in json.loads(out)["findings"] if f["code"] == "legacy_block"]
    assert "--fix deletes the file" in finding["message"]

    payload = env.fix()
    assert not claude_md.exists()
    (fix,) = payload["fixes"]
    assert (fix["action"], fix["status"]) == ("delete_file", "applied")
    assert fix["changes"] == ["delete the file (it holds only the legacy block, lines 1-4)"]


def test_a_file_with_text_besides_the_legacy_block_is_edited_never_deleted(env, monkeypatch):
    path = env.ws / "GEMINI.md"
    path.write_bytes(b"# mine\n\n<!-- SOMA:START -->\nrules\n<!-- SOMA:END -->\n")
    monkeypatch.setattr(doctor_base, "_confirm", lambda prompt: False)
    rc, out = env.run(fix=True)
    assert f"{path}: remove the legacy block (lines 3-5)" in out
    assert "delete the file" not in out


def test_a_byte_order_mark_survives_the_removal_of_a_legacy_block_on_line_one(env):
    path = env.ws / "GEMINI.md"
    path.write_bytes(b"\xef\xbb\xbf<!-- SOMA:START -->\nrules\n<!-- SOMA:END -->\nmine\n")
    payload = env.fix()
    assert [f["status"] for f in payload["fixes"]] == ["applied"]
    assert path.read_bytes() == b"\xef\xbb\xbfmine\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_backups_and_their_manifest_are_owner_only(env):
    claude = env.claude_user_registration(
        mcpServers={"aegis": {"command": str(env.mcp), "env": {"AEGIS_CLIENT": "claude-code"}},
                    "soma": {"command": "soma-mcp"}})
    claude.chmod(0o600)
    env.write_json(env.home / ".mcp.json", {"mcpServers": {"soma": {}}})
    payload = env.fix()
    assert {f["status"] for f in payload["fixes"]} == {"applied"}
    (backup,) = env.backups()
    files = sorted(backup.iterdir())
    assert len(files) == 3  # two backups and the manifest
    for path in files:
        assert path.stat().st_mode & 0o077 == 0, f"{path.name} is {oct(path.stat().st_mode & 0o777)}"
    assert backup.stat().st_mode & 0o077 == 0


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_private_config_swapped_for_a_symlink_after_the_check_stays_owner_only(env, tmp_path, monkeypatch):
    """Review L4: Given a 0600 ~/.claude.json checked as a regular file, When it is swapped for a
    symlink just before the replacing write under umask 022, Then the replacement keeps the 0600
    the check saw (not the 0644 of a new file) and the link's target is spared."""
    from conftest import symlink_or_skip
    from aegis_core import storage

    claude = env.claude_user_registration(
        mcpServers={"aegis": {"command": str(env.mcp), "env": {"AEGIS_CLIENT": "claude-code"}},
                    "soma": {"command": "soma-mcp"}})
    claude.chmod(0o600)
    victim = tmp_path / "victim.json"
    victim.write_bytes(b'{"keep": true}\n')
    victim.chmod(0o644)
    real_write = storage.atomic_write_bytes
    swapped = []

    def swap_then_write(path, data, *args, **kwargs):
        if Path(path) == claude and not swapped:
            os.unlink(claude)
            symlink_or_skip(victim, claude)
            swapped.append(path)
        return real_write(path, data, *args, **kwargs)

    monkeypatch.setattr(storage, "atomic_write_bytes", swap_then_write)
    saved = os.umask(0o022)
    try:
        payload = env.fix()
    finally:
        os.umask(saved)
    assert swapped, "the swap happened before the write"
    assert {f["status"] for f in payload["fixes"]} == {"applied"}
    assert not claude.is_symlink() and "soma" not in json.loads(claude.read_text(encoding="utf-8"))["mcpServers"]
    assert claude.stat().st_mode & 0o777 == 0o600
    assert victim.read_bytes() == b'{"keep": true}\n' and victim.stat().st_mode & 0o777 == 0o644


# ── Numbers JSON cannot hold (R-structure-21, R-cli-50) ─────────────────────────

def test_fix_leaves_a_host_config_holding_an_overflowing_number_byte_identical(env):
    """json reads 1e999 as infinity, which written back is the non-JSON literal Infinity: the file is
    reported as not valid JSON and nothing is planned for it; a control file is fixed as before."""
    overflow = env.home / ".mcp.json"
    overflow.write_bytes(b'{\n  "mcpServers": {"soma": {}},\n  "n": 1e999\n}\n')
    before = overflow.read_bytes()
    control = env.write_json(env.ws / ".mcp.json", {"mcpServers": {"soma": {}, "db": {"command": "db"}}})
    payload = env.fix()
    assert overflow.read_bytes() == before and b"Infinity" not in overflow.read_bytes()
    # By the path field, never a substring of json.dumps: it doubles every Windows backslash.
    key = os.path.normcase(os.path.realpath(overflow))
    about = [f for f in payload["findings"] + payload["fixes"]
             if isinstance(f.get("path"), str) and os.path.normcase(os.path.realpath(f["path"])) == key]
    assert [(f.get("code"), f.get("fixable")) for f in about] == [("unreadable_config", False)]
    assert "not valid JSON" in json.dumps(payload) and "1e999 is not allowed" in json.dumps(payload)
    assert json.loads(control.read_text()) == {"mcpServers": {"db": {"command": "db"}}}


def test_a_non_finite_number_is_never_serialized_into_a_host_config():
    from aegis_cli import doctor_repair

    with pytest.raises(ValueError):
        doctor_repair._dump_like(b'{\n  "n": 1\n}\n', {"n": float("inf")})
    assert doctor_repair._dump_like(b'{\n  "n": 1\n}\n', {"n": 2.5}) == b'{\n  "n": 2.5\n}\n'
