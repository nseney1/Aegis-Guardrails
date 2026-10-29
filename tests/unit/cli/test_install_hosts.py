"""The host plane writers behind `aegis init` and `aegis uninstall` (host-matrix §3.3, §3.4).

Every writer here edits a file the user owns (AGENTS.md, CLAUDE.md, a host's MCP config,
``~/.aegis/workspaces.json``), so the sad paths matter as much as the happy ones: a
symlink, a hand edit or an unparseable file is refused and the bytes on disk are kept.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import symlink_or_skip

import aegis_cli.install_hosts as ih
from aegis_core import hosts

# Captured at import, before the autouse fixture swaps it for a refusing stub.
_REAL_RUN_CLI = ih._run_cli

RETIRED_GEMINI_CLI = ("gemini-cli is not supported: Google retired Gemini CLI for individual Code Assist "
                      "accounts; use --host antigravity.")
DESKTOP_H4 = ("claude-desktop is identity only: Aegis does not register there; "
              "the Claude desktop app's Code tab shares Claude Code's configuration: use --host claude-code")

BEGIN = "<!-- aegis:begin id={id} v=1 sha={sha} -->"
END = "<!-- aegis:end id={id} -->"


def _sha(body: str) -> str:
    return hashlib.sha256(body.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:12]


def _block(block_id: str, body: str, eol: str = "\n") -> str:
    return (BEGIN.format(id=block_id, sha=_sha(body)) + eol + body.replace("\n", eol)
            + END.format(id=block_id) + eol)


# ── write_managed_block ──────────────────────────────────────────────────────


class TestWriteManagedBlock:
    def test_creates_a_missing_file_with_only_the_block(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        assert ih.write_managed_block(target, "bootstrap", "Hello\n") == "created"
        assert target.read_text(encoding="utf-8") == _block("bootstrap", "Hello\n")

    def test_appends_after_user_text_with_one_blank_line(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"# Team notes\nKeep this.\n")
        assert ih.write_managed_block(target, "bootstrap", "Hello\n") == "added"
        assert target.read_text(encoding="utf-8") == "# Team notes\nKeep this.\n\n" + _block("bootstrap", "Hello\n")

    def test_text_without_a_final_newline_gets_one(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"no newline")
        ih.write_managed_block(target, "bootstrap", "Hello")
        assert target.read_text(encoding="utf-8") == "no newline\n\n" + _block("bootstrap", "Hello\n")

    def test_second_write_is_unchanged_and_byte_identical(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"# Notes\n")
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        before = target.read_bytes()
        mtime = target.stat().st_mtime_ns
        assert ih.write_managed_block(target, "bootstrap", "Hello\n") == "unchanged"
        assert target.read_bytes() == before
        assert target.stat().st_mtime_ns == mtime

    def test_new_text_replaces_only_its_own_block_in_place(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        other = _block("other", "Not mine\n")
        target.write_text("top\n\n" + _block("bootstrap", "Old\n") + "\nmiddle\n\n" + other + "tail\n",
                          encoding="utf-8")
        assert ih.write_managed_block(target, "bootstrap", "New\n") == "updated"
        assert target.read_text(encoding="utf-8") == (
            "top\n\n" + _block("bootstrap", "New\n") + "\nmiddle\n\n" + other + "tail\n")

    def test_crlf_file_stays_crlf_and_rerun_is_unchanged(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"# Notes\r\nline\r\n")
        assert ih.write_managed_block(target, "bootstrap", "One\nTwo\n") == "added"
        data = target.read_bytes()
        assert data == ("# Notes\r\nline\r\n\r\n" + _block("bootstrap", "One\nTwo\n", "\r\n")).encode()
        assert b"\n" not in data.replace(b"\r\n", b"")
        assert ih.write_managed_block(target, "bootstrap", "One\nTwo\n") == "unchanged"
        assert target.read_bytes() == data

    def test_a_crlf_checkout_of_an_lf_block_is_not_a_hand_edit(self, tmp_path):
        # git autocrlf rewrites line endings; the sha is over LF-normalized text.
        target = tmp_path / "AGENTS.md"
        target.write_bytes(_block("bootstrap", "One\n", "\r\n").encode())
        assert ih.write_managed_block(target, "bootstrap", "One\n") == "unchanged"

    def test_utf8_bom_and_non_ascii_are_kept(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes("﻿# Équipe\n".encode("utf-8"))
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert target.read_bytes().startswith("﻿# Équipe\n\n".encode("utf-8"))

    def test_hand_edited_block_is_refused_and_kept(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        edited = _block("bootstrap", "Old\n").replace("Old", "My edit")
        target.write_text(edited, encoding="utf-8")
        with pytest.raises(ih.InstallError, match="edited by hand.*--force"):
            ih.write_managed_block(target, "bootstrap", "New\n")
        assert target.read_text(encoding="utf-8") == edited

    def test_force_replaces_a_hand_edited_block(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_text(_block("bootstrap", "Old\n").replace("Old", "My edit"), encoding="utf-8")
        assert ih.write_managed_block(target, "bootstrap", "New\n", force=True) == "updated"
        assert target.read_text(encoding="utf-8") == _block("bootstrap", "New\n")

    def test_symlink_is_refused_and_its_target_untouched(self, tmp_path):
        outside = tmp_path / "outside.md"
        outside.write_bytes(b"secret\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        link = repo / "AGENTS.md"
        symlink_or_skip(outside, link)
        with pytest.raises(ih.InstallError, match="symlink"):
            ih.write_managed_block(link, "bootstrap", "Hello\n")
        assert outside.read_bytes() == b"secret\n"
        assert link.is_symlink()

    def test_dangling_symlink_is_refused_and_nothing_is_created(self, tmp_path):
        link = tmp_path / "AGENTS.md"
        symlink_or_skip(tmp_path / "elsewhere.md", link)
        with pytest.raises(ih.InstallError, match="symlink"):
            ih.write_managed_block(link, "bootstrap", "Hello\n")
        assert not (tmp_path / "elsewhere.md").exists()

    def test_hard_linked_file_is_refused(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"shared\n")
        try:
            os.link(target, tmp_path / "copy.md")
        except (OSError, NotImplementedError):
            pytest.skip("hard links unsupported here")
        with pytest.raises(ih.InstallError, match="hard link"):
            ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert target.read_bytes() == b"shared\n"

    def test_directory_in_place_of_the_file_is_refused(self, tmp_path):
        (tmp_path / "AGENTS.md").mkdir()
        with pytest.raises(ih.InstallError, match="not a regular file"):
            ih.write_managed_block(tmp_path / "AGENTS.md", "bootstrap", "Hello\n")

    def test_non_utf8_file_is_refused_and_kept(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"caf\xe9\n")
        with pytest.raises(ih.InstallError, match="UTF-8"):
            ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert target.read_bytes() == b"caf\xe9\n"

    @pytest.mark.parametrize("text", [
        BEGIN.format(id="bootstrap", sha="0" * 12) + "\nunterminated\n",
        "stray\n" + END.format(id="bootstrap") + "\n",
        _block("bootstrap", "a\n") + "\n" + _block("bootstrap", "a\n"),
        "<!-- aegis:begin id=bootstrap v=2 sha=000000000000 -->\nx\n<!-- aegis:end id=bootstrap -->\n",
    ], ids=["unterminated", "orphan-end", "duplicate", "unknown-version"])
    def test_malformed_markers_of_its_own_id_are_refused(self, tmp_path, text):
        target = tmp_path / "AGENTS.md"
        target.write_text(text, encoding="utf-8")
        with pytest.raises(ih.InstallError):
            ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert target.read_text(encoding="utf-8") == text

    def test_create_false_never_creates_the_file(self, tmp_path):
        target = tmp_path / "CLAUDE.md"
        assert ih.write_managed_block(target, "agents-import", "@AGENTS.md\n", create=False) == "absent"
        assert not target.exists()

    def test_dry_run_reports_and_writes_nothing(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"x\n")
        assert ih.write_managed_block(target, "bootstrap", "Hello\n", dry_run=True) == "added"
        assert target.read_bytes() == b"x\n"
        assert ih.write_managed_block(tmp_path / "NEW.md", "bootstrap", "Hello\n", dry_run=True) == "created"
        assert not (tmp_path / "NEW.md").exists()

    def test_existing_permission_bits_are_kept(self, tmp_path):
        if os.name == "nt":
            pytest.skip("POSIX permission bits")
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"x\n")
        target.chmod(0o640)
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert stat.S_IMODE(target.stat().st_mode) == 0o640


class TestRemoveManagedBlock:
    def test_removes_only_its_block_and_the_separator_it_added(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"# Notes\n")
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        ih.write_managed_block(target, "other", "Keep\n")
        assert ih.remove_managed_block(target, "bootstrap") == "removed"
        assert target.read_text(encoding="utf-8") == "# Notes\n\n" + _block("other", "Keep\n")

    def test_restores_the_original_bytes_after_init(self, tmp_path):
        target = tmp_path / "CLAUDE.md"
        target.write_bytes(b"# Claude\r\nrules\r\n")
        ih.write_managed_block(target, "agents-import", "@AGENTS.md\n")
        ih.remove_managed_block(target, "agents-import")
        assert target.read_bytes() == b"# Claude\r\nrules\r\n"

    def test_file_that_held_only_the_block_is_deleted_when_asked(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert ih.remove_managed_block(target, "bootstrap", delete_if_empty=True) == "deleted"
        assert not target.exists()

    def test_file_that_held_only_the_block_is_kept_by_default(self, tmp_path):
        target = tmp_path / "CLAUDE.md"
        target.write_bytes(b"")
        ih.write_managed_block(target, "agents-import", "@AGENTS.md\n")
        assert ih.remove_managed_block(target, "agents-import") == "removed"
        assert target.exists() and target.read_bytes() == b""

    def test_absent_block_or_file_is_absent(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        assert ih.remove_managed_block(target, "bootstrap") == "absent"
        target.write_bytes(b"# mine\n")
        assert ih.remove_managed_block(target, "bootstrap") == "absent"
        assert target.read_bytes() == b"# mine\n"

    def test_hand_edited_block_is_refused_without_force(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        text = _block("bootstrap", "Old\n").replace("Old", "Mine")
        target.write_text(text, encoding="utf-8")
        with pytest.raises(ih.InstallError, match="edited by hand"):
            ih.remove_managed_block(target, "bootstrap")
        assert target.read_text(encoding="utf-8") == text
        assert ih.remove_managed_block(target, "bootstrap", force=True) == "removed"

    def test_symlink_is_refused(self, tmp_path):
        outside = tmp_path / "outside.md"
        outside.write_text(_block("bootstrap", "Hello\n"), encoding="utf-8")
        link = tmp_path / "repo" / "AGENTS.md"
        link.parent.mkdir()
        symlink_or_skip(outside, link)
        with pytest.raises(ih.InstallError, match="symlink"):
            ih.remove_managed_block(link, "bootstrap")
        assert "aegis:begin" in outside.read_text(encoding="utf-8")


# ── has_block_marker (what uninstall asks of a linked AGENTS.md / CLAUDE.md) ─


class TestHasBlockMarker:
    def test_a_file_holding_the_block_has_its_marker(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_bytes(b"# Notes\n")
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        assert ih.has_block_marker(target, "bootstrap") is True

    def test_a_lone_end_marker_counts(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_text("# Notes\n" + END.format(id="bootstrap") + "\n", encoding="utf-8")
        assert ih.has_block_marker(str(target), "bootstrap") is True

    def test_the_marker_is_read_through_a_link(self, tmp_path):
        outside = tmp_path / "outside.md"
        outside.write_text(_block("agents-import", "@AGENTS.md\n"), encoding="utf-8")
        link = tmp_path / "CLAUDE.md"
        symlink_or_skip(outside, link)
        assert ih.has_block_marker(link, "agents-import") is True

    @pytest.mark.parametrize("text", [
        "# Notes\nid=bootstrap is mentioned in prose\n",
        _block("other", "Keep\n"),
        _block("bootstrap-extra", "Keep\n"),
        "",
    ])
    def test_text_without_that_block_s_marker_has_none(self, tmp_path, text):
        target = tmp_path / "AGENTS.md"
        target.write_text(text, encoding="utf-8")
        assert ih.has_block_marker(target, "bootstrap") is False

    def test_a_missing_file_or_a_directory_has_no_marker(self, tmp_path):
        assert ih.has_block_marker(tmp_path / "AGENTS.md", "bootstrap") is False
        (tmp_path / "CLAUDE.md").mkdir()
        assert ih.has_block_marker(tmp_path / "CLAUDE.md", "bootstrap") is False

    def test_a_dangling_link_has_no_marker(self, tmp_path):
        link = tmp_path / "AGENTS.md"
        symlink_or_skip(tmp_path / "gone.md", link)
        assert ih.has_block_marker(link, "bootstrap") is False

    @pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                        reason="needs POSIX permissions that bind the user")
    def test_an_unreadable_file_has_no_marker(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        target.write_text(_block("bootstrap", "Hello\n"), encoding="utf-8")
        target.chmod(0)
        try:
            assert ih.has_block_marker(target, "bootstrap") is False
        finally:
            target.chmod(0o644)


# ── JSON MCP configs (Antigravity) ───────────────────────────────────────────

ENTRY = {"command": "/opt/bin/aegis-mcp", "args": [], "env": {"AEGIS_CLIENT": "antigravity"}}


class TestMergeMcpJson:
    def test_creates_the_file_and_its_directory(self, tmp_path):
        target = tmp_path / "config" / "mcp_config.json"
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "added"
        assert json.loads(target.read_text(encoding="utf-8")) == {"mcpServers": {"aegis": ENTRY}}

    def test_keeps_other_servers_and_keys_in_order(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        original = {"theme": "dark", "mcpServers": {"github": {"command": "gh-mcp", "env": {"T": "é"}}}, "z": 1}
        target.write_text(json.dumps(original), encoding="utf-8")
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "added"
        data = json.loads(target.read_text(encoding="utf-8"))
        assert list(data) == ["theme", "mcpServers", "z"]
        assert data["mcpServers"] == {"github": original["mcpServers"]["github"], "aegis": ENTRY}
        assert "é" in target.read_text(encoding="utf-8")

    def test_same_entry_is_unchanged_and_not_rewritten(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        ih.merge_mcp_json(target, "aegis", ENTRY)
        before, mtime = target.read_bytes(), target.stat().st_mtime_ns
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "unchanged"
        assert target.read_bytes() == before and target.stat().st_mtime_ns == mtime

    def test_a_different_aegis_entry_is_updated(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        target.write_text(json.dumps({"mcpServers": {"aegis": {"command": "old"}}}), encoding="utf-8")
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "updated"
        assert json.loads(target.read_text(encoding="utf-8"))["mcpServers"]["aegis"] == ENTRY

    @pytest.mark.parametrize("raw, reason", [
        (b'{"mcpServers": {}, // note\n}', "not valid JSON"),
        (b'{"mcpServers": {"a": {"command": "x"},},}', "not valid JSON"),
        (b'\xef\xbb\xbf{"mcpServers": {}}', "BOM"),
        (b'["not", "an", "object"]', "JSON object"),
        (b'{"mcpServers": []}', "mcpServers"),
        (b'{"mcpServers": {"a": 1, "a": 2}}', "duplicate key"),
        (b'{"x": NaN}', "not valid JSON"),
        (b'{"x": "\xff"}', "UTF-8"),
    ], ids=["comment", "trailing-comma", "bom", "array", "servers-list", "duplicate", "nan", "latin1"])
    def test_unmergeable_input_is_refused_and_kept(self, tmp_path, raw, reason):
        target = tmp_path / "mcp_config.json"
        target.write_bytes(raw)
        with pytest.raises(ih.InstallError, match=reason):
            ih.merge_mcp_json(target, "aegis", ENTRY)
        assert target.read_bytes() == raw

    def test_null_servers_and_empty_file_are_merged(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        target.write_bytes(b"  \n")
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "added"
        target.write_text('{"mcpServers": null}', encoding="utf-8")
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "added"
        assert json.loads(target.read_text(encoding="utf-8")) == {"mcpServers": {"aegis": ENTRY}}

    def test_symlinked_config_is_refused_and_its_target_kept(self, tmp_path):
        real = tmp_path / "dotfiles" / "mcp_config.json"
        real.parent.mkdir()
        real.write_bytes(b'{"mcpServers": {}}')
        link = tmp_path / "mcp_config.json"
        symlink_or_skip(real, link)
        with pytest.raises(ih.InstallError, match="symlink"):
            ih.merge_mcp_json(link, "aegis", ENTRY)
        assert real.read_bytes() == b'{"mcpServers": {}}'

    def test_read_only_config_is_refused(self, tmp_path):
        if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
            pytest.skip("needs POSIX permissions as a non-root user")
        target = tmp_path / "mcp_config.json"
        target.write_bytes(b'{"mcpServers": {}}')
        target.chmod(0o444)
        with pytest.raises(ih.InstallError, match="read-only"):
            ih.merge_mcp_json(target, "aegis", ENTRY)

    def test_dry_run_writes_nothing(self, tmp_path):
        target = tmp_path / "config" / "mcp_config.json"
        assert ih.merge_mcp_json(target, "aegis", ENTRY, dry_run=True) == "added"
        assert not target.parent.exists()


class TestRemoveMcpJson:
    def test_removes_aegis_and_legacy_soma_and_keeps_the_rest(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        target.write_text(json.dumps({"mcpServers": {"aegis": ENTRY, "soma": {"command": "s"},
                                                     "github": {"command": "g"}}}), encoding="utf-8")
        assert ih.remove_mcp_json(target, ("aegis", "soma")) == "removed"
        assert json.loads(target.read_text(encoding="utf-8")) == {"mcpServers": {"github": {"command": "g"}}}

    def test_missing_file_or_entry_is_absent_and_untouched(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        assert ih.remove_mcp_json(target, ("aegis",)) == "absent"
        assert not target.exists()
        target.write_bytes(b'{"mcpServers": {"github": {}}}')
        assert ih.remove_mcp_json(target, ("aegis",)) == "absent"
        assert target.read_bytes() == b'{"mcpServers": {"github": {}}}'

    def test_unparseable_config_is_refused(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        target.write_bytes(b"{oops")
        with pytest.raises(ih.InstallError, match="not valid JSON"):
            ih.remove_mcp_json(target, ("aegis",))
        assert target.read_bytes() == b"{oops"


# ── ~/.aegis/workspaces.json ─────────────────────────────────────────────────


class TestWorkspaceRegistry:
    def test_first_registration_writes_the_v1_schema(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        status = ih.register_workspace(home, root, ["codex-cli"], now="2026-10-15T12:00:00Z")
        assert status == "added"
        data = json.loads((home / ".aegis" / "workspaces.json").read_text(encoding="utf-8"))
        assert data == {"v": 1, "workspaces": [{
            "root": str(root.resolve()), "added_at": "2026-10-15T12:00:00Z",
            "added_by": "aegis init", "hosts": ["codex-cli"]}]}

    def test_reregistration_is_deduplicated_and_unchanged(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        ih.register_workspace(home, root, ["codex-cli"], now="2026-10-15T12:00:00Z")
        before = (home / ".aegis" / "workspaces.json").read_bytes()
        assert ih.register_workspace(home, root / ".", ["codex-cli"], now="2027-01-01T00:00:00Z") == "unchanged"
        assert (home / ".aegis" / "workspaces.json").read_bytes() == before

    def test_new_hosts_are_merged_in_table_order_and_added_at_is_kept(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        ih.register_workspace(home, root, ["antigravity"], now="2026-10-15T12:00:00Z")
        assert ih.register_workspace(home, root, ["codex-cli"], now="2027-01-01T00:00:00Z") == "updated"
        (entry,) = ih.read_registry(home)["workspaces"]
        assert entry["hosts"] == ["codex-cli", "antigravity"]
        assert entry["added_at"] == "2026-10-15T12:00:00Z"

    def test_other_workspaces_and_unknown_keys_are_kept(self, tmp_path):
        home, a, b = tmp_path / "home", tmp_path / "a", tmp_path / "b"
        a.mkdir(), b.mkdir()
        reg = home / ".aegis" / "workspaces.json"
        reg.parent.mkdir(parents=True)
        reg.write_text(json.dumps({"v": 1, "note": "mine", "workspaces": [
            {"root": str(a.resolve()), "added_at": "x", "added_by": "aegis init", "hosts": [], "extra": 1}]}),
            encoding="utf-8")
        ih.register_workspace(home, b, [], now="2026-10-15T12:00:00Z")
        data = json.loads(reg.read_text(encoding="utf-8"))
        assert data["note"] == "mine"
        assert [w["root"] for w in data["workspaces"]] == [str(a.resolve()), str(b.resolve())]
        assert data["workspaces"][0]["extra"] == 1

    def test_unregister_removes_only_that_root_and_returns_the_rest(self, tmp_path):
        home, a, b = tmp_path / "home", tmp_path / "a", tmp_path / "b"
        a.mkdir(), b.mkdir()
        ih.register_workspace(home, a, ["codex-cli"], now="t")
        ih.register_workspace(home, b, ["claude-code"], now="t")
        status, remaining = ih.unregister_workspace(home, a)
        assert status == "removed"
        assert [w["root"] for w in remaining] == [str(b.resolve())]
        assert ih.unregister_workspace(home, a)[0] == "absent"

    @pytest.mark.parametrize("stored, realpath_keeps_nul", [
        ("repo", False), (os.path.join(".", "repo"), False), ("\u0000x", False), ("/re\u0000po", False),
        ("/re\u0000po", True),
    ], ids=["relative", "dot-relative", "nul", "absolute-nul", "absolute-nul-realpath-keeps"])
    def test_a_stored_root_the_server_skips_never_matches_and_is_kept(self, tmp_path, monkeypatch, stored,
                                                                      realpath_keeps_nul):
        # The server's registry reader skips a root that is not absolute or cannot be resolved;
        # resolving a relative one here would match whatever the cwd makes of it.
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        monkeypatch.chdir(tmp_path)
        if realpath_keeps_nul:
            # Windows Python 3.12+: non-strict realpath returns a NUL path as given (gh-106242).
            real = os.path.realpath
            monkeypatch.setattr(os.path, "realpath", lambda path, *a, **k: (
                os.path.normpath(os.path.abspath(os.fspath(path))) if "\x00" in os.fspath(path)
                else real(path, *a, **k)))
        reg = home / ".aegis" / "workspaces.json"
        reg.parent.mkdir(parents=True)
        junk = {"root": stored, "added_at": "x", "added_by": "aegis init", "hosts": ["codex-cli"]}
        reg.write_text(json.dumps({"v": 1, "workspaces": [junk]}), encoding="utf-8")

        assert ih.find_workspace(ih.read_registry(home), root) is None
        assert ih.unregister_workspace(home, root) == ("absent", [junk])
        assert ih.register_workspace(home, root, ["claude-code"], now="t") == "added"
        assert ih.read_registry(home)["workspaces"] == [junk, {
            "root": str(root.resolve()), "added_at": "t", "added_by": "aegis init", "hosts": ["claude-code"]}]
        status, remaining = ih.unregister_workspace(home, root)
        assert (status, remaining) == ("removed", [junk])

    @pytest.mark.parametrize("raw, reason", [
        (b"{nope", "not valid JSON"),
        (b'{"v": 2, "workspaces": []}', "version 2"),
        (b'{"v": 1, "workspaces": {}}', "workspaces"),
        (b'{"v": 1, "workspaces": [{"root": 3}]}', "root"),
    ], ids=["garbage", "future-version", "workspaces-object", "bad-root"])
    def test_unreadable_registry_is_refused_and_kept(self, tmp_path, raw, reason):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        reg = home / ".aegis" / "workspaces.json"
        reg.parent.mkdir(parents=True)
        reg.write_bytes(raw)
        with pytest.raises(ih.InstallError, match=reason):
            ih.register_workspace(home, root, [], now="t")
        assert reg.read_bytes() == raw

    def test_symlinked_registry_or_user_dir_is_refused(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        home.mkdir()
        symlink_or_skip(elsewhere, home / ".aegis", target_is_directory=True)
        with pytest.raises(ih.InstallError, match="symlink"):
            ih.register_workspace(home, root, [], now="t")
        assert list(elsewhere.iterdir()) == []

    def test_dry_run_creates_nothing(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        assert ih.register_workspace(home, root, ["codex-cli"], dry_run=True) == "added"
        assert not (home / ".aegis").exists()


# ── Host selection, detection and registration commands ──────────────────────


EXE = ".exe" if os.name == "nt" else ""


def _fake_bin(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + EXE)
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def _paths(*paths) -> list:
    """Paths as Windows compares them (case-insensitively); unchanged on POSIX."""
    return [os.path.normcase(str(p)) for p in paths]


class TestHostSelection:
    def test_registrable_hosts_are_the_phase_1_rows_with_a_registration(self):
        assert [h.id for h in ih.registrable_hosts()] == [
            "codex-cli", "claude-code", "antigravity", "kiro", "cursor", "copilot", "windsurf"]

    def test_detection_reads_binaries_on_path_and_user_dirs(self, tmp_path):
        home, bindir = tmp_path / "home", tmp_path / "bin"
        _fake_bin(bindir, "claude")
        (home / ".gemini" / "antigravity").mkdir(parents=True)
        assert ih.detect_hosts(home, path=str(bindir)) == ["claude-code", "antigravity"]

    def test_nothing_detected_on_an_empty_machine(self, tmp_path):
        (tmp_path / "home").mkdir()
        assert ih.detect_hosts(tmp_path / "home", path=str(tmp_path / "nobin")) == []

    def test_detection_finds_ide_and_desktop_planes_by_config_path(self, tmp_path):
        """A desktop app or IDE puts no CLI on PATH; its config plane gives it away."""
        home = tmp_path / "home"
        (home / ".kiro").mkdir(parents=True)
        (home / ".claude.json").write_text("{}", encoding="utf-8")
        assert ih.detect_hosts(home, path=str(tmp_path / "nobin")) == ["claude-code", "kiro"]

    def test_detection_finds_an_app_bundle(self, tmp_path, monkeypatch):
        apps = tmp_path / "Applications"
        (apps / "Kiro.app").mkdir(parents=True)
        (apps / "Codex.app").mkdir()
        monkeypatch.setattr(hosts, "APP_DIRS", {"darwin": (str(apps),)})
        (tmp_path / "home").mkdir()
        found = ih.detect_hosts(tmp_path / "home", path=str(tmp_path / "nobin"), platform="darwin")
        assert found == ["codex-cli", "kiro"]
        assert ih.detect_hosts(tmp_path / "home", path=str(tmp_path / "nobin"), platform="linux") == []

    def test_detection_says_what_it_found(self, tmp_path, monkeypatch):
        apps = tmp_path / "Programs"
        (apps / "Kiro").mkdir(parents=True)
        monkeypatch.setattr(hosts, "APP_DIRS", {"win32": ("%LOCALAPPDATA%/Programs",)})
        home = tmp_path / "home"
        (home / ".codex").mkdir(parents=True)
        claude = _fake_bin(tmp_path / "bin", "claude")
        evidence = ih.detection_evidence(home, path=str(tmp_path / "bin"), environ={"LOCALAPPDATA": str(tmp_path)},
                                         platform="win32")
        assert evidence == {"codex-cli": "~/.codex", "claude-code": str(claude),
                            "kiro": os.path.join(str(tmp_path), "Programs", "Kiro")}

    def test_a_file_where_an_app_bundle_belongs_is_no_app(self, tmp_path, monkeypatch):
        apps = tmp_path / "Applications"
        apps.mkdir()
        (apps / "Kiro.app").write_text("", encoding="utf-8")
        monkeypatch.setattr(hosts, "APP_DIRS", {"darwin": (str(apps),)})
        (tmp_path / "home").mkdir()
        assert ih.detect_hosts(tmp_path / "home", path=str(tmp_path / "nobin"), platform="darwin") == []

    @pytest.mark.parametrize("value, expected", [
        ("auto", "auto"),
        ("codex-cli", ["codex-cli"]),
        ("antigravity, codex-cli,codex-cli", ["codex-cli", "antigravity"]),
        ("codex-app", ["codex-cli"]),
        ("kiro-ide,chatgpt-desktop,kiro-cli,codex", ["codex-cli", "kiro"]),
        ("claude-desktop-code", ["claude-code"]),
        ("antigravity-ide,antigravity-app", ["antigravity"]),
        ("kiro", ["kiro"]),
    ])
    def test_parse_hosts(self, value, expected):
        assert ih.parse_hosts(value) == expected

    @pytest.mark.parametrize("value, message", [
        ("gemini", "unknown host 'gemini'"),
        ("claude-desktop", "identity only"),
        ("", "no host"),
        ("auto,codex-cli", "auto"),
    ])
    def test_parse_hosts_refuses(self, value, message):
        with pytest.raises(ValueError, match=message):
            ih.parse_hosts(value)

    @pytest.mark.parametrize("value", ["gemini-cli", "codex-cli,gemini-cli"])
    def test_retired_gemini_cli_is_refused_with_the_way_to_antigravity(self, value):
        with pytest.raises(ValueError) as exc:
            ih.parse_hosts(value)
        assert str(exc.value) == RETIRED_GEMINI_CLI

    def test_a_retired_host_and_an_identity_only_host_are_refused_for_different_reasons(self):
        with pytest.raises(ValueError) as retired:
            ih.parse_hosts("gemini-cli")
        with pytest.raises(ValueError) as identity:
            ih.parse_hosts("claude-desktop")
        assert (str(retired.value), str(identity.value)) == (RETIRED_GEMINI_CLI, DESKTOP_H4)

    def test_a_host_this_release_cannot_register_is_refused_without_a_version_promise(self, monkeypatch):
        monkeypatch.setattr(ih, "registrable_hosts", lambda: (hosts.get("claude-code"),))
        with pytest.raises(ValueError) as exc:
            ih.parse_hosts("codex-cli")
        assert str(exc.value) == "codex-cli: Aegis does not register this host in this release; hosts now: claude-code"


class TestRegistrationCommands:
    def test_mcp_command_prefers_an_absolute_aegis_mcp_on_path(self, tmp_path):
        exe = _fake_bin(tmp_path / "bin", "aegis-mcp")
        assert _paths(*ih.mcp_command(path=str(tmp_path / "bin"))) == _paths(exe)

    def test_mcp_command_takes_the_console_script_installed_with_this_interpreter(self, tmp_path):
        """pip --user and unactivated venvs leave aegis-mcp off PATH, next to the interpreter."""
        script = _fake_bin(tmp_path / "scripts", "aegis-mcp")
        command = ih.mcp_command(path=str(tmp_path / "nobin"), scripts_dirs=[str(tmp_path / "empty"),
                                                                            str(tmp_path / "scripts")])
        assert _paths(*command) == _paths(script)

    def test_an_aegis_mcp_on_path_wins_over_the_interpreter_scripts_directory(self, tmp_path):
        on_path = _fake_bin(tmp_path / "bin", "aegis-mcp")
        _fake_bin(tmp_path / "scripts", "aegis-mcp")
        command = ih.mcp_command(path=str(tmp_path / "bin"), scripts_dirs=[str(tmp_path / "scripts")])
        assert _paths(*command) == _paths(on_path)

    def test_mcp_command_falls_back_to_this_interpreter_in_isolated_mode(self, tmp_path):
        command = ih.mcp_command(path=str(tmp_path / "nobin"), scripts_dirs=[])
        import aegis_mcp

        assert command[:3] == [sys.executable, "-I", "-c"]
        assert "-m" not in command
        root = command[4]
        assert os.path.isabs(root) and len(command) == 5
        assert Path(root, "aegis_mcp", "server.py").is_file()
        assert Path(root).resolve() == Path(aegis_mcp.__file__).resolve().parent.parent
        assert ih.launch_risk(command) is None

    @staticmethod
    def _native(argv):
        """POSIX absolute paths as Windows spells them, where a path needs a drive."""
        if os.name != "nt":
            return argv
        return [("C:" + a.replace("/", "\\")) if a.startswith("/") else a for a in argv]

    @pytest.mark.parametrize("argv, risk", [
        (["/py", "-m", "aegis_mcp"], "-m without -I"),
        (["/py", "-maegis_mcp"], "-m without -I"),
        (["/py", "-W", "ignore", "-m", "aegis_mcp"], "-m without -I"),
        (["/usr/bin/python3", "-E", "-s", "-m", "aegis_mcp"], "-m without -I"),
        (["/py", "-c", "import aegis_mcp"], "-c without -I"),
        (["/py", "-"], "stdin without -I"),
        (["python3", "-I", "-c", "x"], "not an absolute path"),
        (["aegis-mcp"], "not an absolute path"),
        (["./aegis-mcp"], "not an absolute path"),
        ([], "not an absolute path"),
        # A relative script resolves against the start directory, isolated mode or not.
        (["/usr/bin/python3", "aegis_mcp/server.py"], "aegis_mcp/server.py, a path relative to the directory"),
        (["/usr/bin/python3.12", "-I", "server.py"], "server.py, a path relative to the directory"),
        (["/opt/venv/bin/python", "--", "server.py"], "server.py, a path relative to the directory"),
        (["/usr/bin/pythonw.exe", "run.py"], "run.py, a path relative to the directory"),
        # env runs the command it is given, looked up on the host's PATH when bare.
        (["/usr/bin/env", "python3", "-m", "aegis_mcp"], "through env: the command is not an absolute path"),
        (["/usr/bin/env", "AEGIS_CLIENT=x", "/usr/bin/python3", "-m", "aegis_mcp"], "through env: it runs -m"),
        (["/usr/bin/env", "-i", "-u", "PATH", "/usr/bin/python3", "-c", "x"], "through env: it runs -c"),
        (["/usr/bin/env", "--unset=PATH", "--", "/py", "aegis_mcp/server.py"], "through env: it runs the script"),
        (["/usr/bin/env", "-S", "python3 -m aegis_mcp"], "env -S"),
        (["/usr/bin/env", "--split-string=python3 -m aegis_mcp"], "env -S"),
        (["/usr/bin/env"], "through env: the command is not an absolute path"),
    ])
    def test_launch_risk_names_a_command_that_depends_on_the_start_directory(self, argv, risk):
        assert risk in (ih.launch_risk(self._native(argv)) or "")

    @pytest.mark.parametrize("argv", [
        ["/x/aegis-mcp"],
        ["/x/aegis-mcp", "serve"],  # not an interpreter: its arguments are not scripts
        ["/py", "-I", "-c", "import sys", "/root"],
        ["/py", "-Ic", "import sys"],
        ["/py", "-X", "frozen_modules=off", "-I", "-c", "x"],
        ["/py", "-Xfrozen_modules=off", "-I", "-c", "x"],
        ["/py", "/abs/script.py"],
        # Isolated mode keeps the start directory off sys.path for -m as for -c.
        ["/py", "-Im", "aegis_mcp"],
        ["/usr/bin/python3", "-I", "-m", "aegis_mcp"],
        ["/usr/bin/python3.12", "-P", "-m", "aegis_mcp"],
        ["/usr/bin/env", "AEGIS_CLIENT=x", "/x/aegis-mcp"],
        ["/usr/bin/env", "-i", "--", "/py", "-I", "-c", "x"],
    ])
    def test_launch_risk_accepts_absolute_isolated_commands(self, argv):
        assert ih.launch_risk(self._native(argv)) is None

    def test_codex_argv_uses_the_table_template(self):
        argv = ih.register_argv(hosts.get("codex-cli"), ["/x/aegis-mcp"])
        assert argv == ["codex", "mcp", "add", "aegis", "--env", "AEGIS_CLIENT=codex-cli", "--", "/x/aegis-mcp"]

    def test_claude_argv_keeps_the_name_before_env_and_splices_the_command(self):
        argv = ih.register_argv(hosts.get("claude-code"), ["/py", "-m", "aegis_mcp"], pin="/repo")
        assert argv == ["claude", "mcp", "add", "--scope", "user", "aegis", "-e", "AEGIS_CLIENT=claude-code",
                        "-e", "AEGIS_WORKSPACE=/repo", "--", "/py", "-m", "aegis_mcp"]

    @pytest.mark.parametrize("host, name, expected", [
        ("codex-cli", "aegis", ["codex", "mcp", "remove", "aegis"]),
        ("claude-code", "soma", ["claude", "mcp", "remove", "--scope", "user", "soma"]),
    ])
    def test_unregister_argv(self, host, name, expected):
        assert ih.unregister_argv(hosts.get(host), name) == expected

    def test_antigravity_entry_is_absolute_with_explicit_env(self):
        assert ih.mcp_entry("antigravity", ["/py", "-m", "aegis_mcp"], pin="/repo") == {
            "command": "/py", "args": ["-m", "aegis_mcp"],
            "env": {"AEGIS_CLIENT": "antigravity", "AEGIS_WORKSPACE": "/repo"}}
        assert ih.mcp_entry("antigravity", ["/x/aegis-mcp"]) == {
            "command": "/x/aegis-mcp", "args": [], "env": {"AEGIS_CLIENT": "antigravity"}}


@pytest.mark.skipif(os.name == "nt", reason="a POSIX process started in the planted directory")
class TestTheRegisteredLauncherNeverImportsFromTheStartDirectory:
    """Hosts start the MCP server in the project directory, which a cloned repository
    controls. The registered command must start Aegis's own server from there, never a
    planted aegis_mcp or aegis_core (release review: v4.0.0 registered `python -m aegis_mcp`)."""

    def _planted(self, tmp_path):
        """Aegis's own packages, which the runner's import root shadows anyway, and a
        standard-library module (json, which the server imports), which only -I keeps
        the start directory from shadowing."""
        repo = tmp_path / "evil"
        marker = tmp_path / "PLANTED_RAN"
        for package in ("aegis_mcp", "aegis_core"):
            (repo / package).mkdir(parents=True)
            code = f"open({str(marker)!r}, 'a').write({package!r} + '\\n')\n"
            for module in ("__init__.py", "__main__.py", "server.py"):
                (repo / package / module).write_text(code, encoding="utf-8")
        (repo / "json.py").write_text(f"open({str(marker)!r}, 'a').write('json\\n')\n", encoding="utf-8")
        return repo, marker

    def test_the_fallback_launcher_runs_aegis_and_not_the_planted_package(self, tmp_path):
        repo, marker = self._planted(tmp_path)
        command = ih.mcp_command(path=str(tmp_path / "nobin"), scripts_dirs=[])
        request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
        env = {k: v for k, v in os.environ.items() if k != "AEGIS_WORKSPACE"}
        env["PYTHONPATH"] = str(repo)  # isolated mode ignores it too
        proc = subprocess.run(command, input=request, cwd=str(repo), capture_output=True, text=True,
                              timeout=60, env=env)
        assert not marker.exists(), marker.read_text(encoding="utf-8")
        assert proc.returncode == 0, proc.stderr
        reply = json.loads(proc.stdout.splitlines()[0])
        assert reply["result"]["serverInfo"]["name"] == "aegis-mcp"

    def test_the_v4_0_0_launcher_ran_the_planted_package(self, tmp_path):
        """The control: the same directory takes over `python -m aegis_mcp`."""
        repo, marker = self._planted(tmp_path)
        subprocess.run([sys.executable, "-m", "aegis_mcp"], input="", cwd=str(repo), capture_output=True,
                       text=True, timeout=60)
        assert marker.exists()


class _Runner:
    def __init__(self, returncode: int = 0, stderr: str = ""):
        self.calls: list[list[str]] = []
        self.returncode, self.stderr = returncode, stderr

    def __call__(self, argv):
        import subprocess
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


class TestRegisterHost:
    def test_native_host_removes_then_adds_with_the_binary_found_on_path(self, tmp_path, monkeypatch):
        exe = _fake_bin(tmp_path / "bin", "claude")
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        action = ih.register_host("claude-code", home=tmp_path, command=["/x/aegis-mcp"], path=str(tmp_path / "bin"))
        assert action.result == "registered"
        assert _paths(*{c[0] for c in runner.calls}) == _paths(exe)
        assert [c[1:] for c in runner.calls] == [
            ["mcp", "remove", "--scope", "user", "aegis"],
            ["mcp", "add", "--scope", "user", "aegis", "-e", "AEGIS_CLIENT=claude-code", "--", "/x/aegis-mcp"],
        ]

    def test_missing_cli_prints_the_exact_command_and_runs_nothing(self, tmp_path, monkeypatch):
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        action = ih.register_host("codex-cli", home=tmp_path, command=["/x/aegis-mcp"], path=str(tmp_path / "nobin"))
        assert action.result == "manual"
        assert action.command == ["codex", "mcp", "add", "aegis", "--env", "AEGIS_CLIENT=codex-cli", "--", "/x/aegis-mcp"]
        assert runner.calls == []

    def test_failed_add_is_reported_with_the_cli_error(self, tmp_path, monkeypatch):
        _fake_bin(tmp_path / "bin", "codex")
        monkeypatch.setattr(ih, "_run_cli", _Runner(returncode=1, stderr="boom: no config\n"))
        action = ih.register_host("codex-cli", home=tmp_path, command=["/x"], path=str(tmp_path / "bin"))
        assert action.result == "failed"
        assert "boom: no config" in action.detail

    def test_dry_run_runs_nothing(self, tmp_path, monkeypatch):
        _fake_bin(tmp_path / "bin", "codex")
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        action = ih.register_host("codex-cli", home=tmp_path, command=["/x"], path=str(tmp_path / "bin"), dry_run=True)
        assert action.result == "would_run"
        assert runner.calls == []

    def test_kiro_merges_its_user_mcp_json_and_keeps_other_servers(self, tmp_path):
        cfg = tmp_path / ".kiro" / "settings" / "mcp.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-fetch"]}},
                                   "other": 1}), encoding="utf-8")
        action = ih.register_host("kiro", home=tmp_path, command=["/x/aegis-mcp"])
        assert (action.result, action.detail) == ("registered", str(cfg))
        assert json.loads(cfg.read_text(encoding="utf-8")) == {
            "mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-fetch"]},
                           "aegis": {"command": "/x/aegis-mcp", "args": [], "env": {"AEGIS_CLIENT": "kiro"}}},
            "other": 1}
        assert ih.register_host("kiro", home=tmp_path, command=["/x/aegis-mcp"]).result == "unchanged"
        assert ih.unregister_host("kiro", home=tmp_path).result == "removed"
        assert json.loads(cfg.read_text(encoding="utf-8")) == {
            "mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-fetch"]}}, "other": 1}

    def test_kiro_creates_its_settings_file_when_kiro_has_none(self, tmp_path):
        assert ih.register_host("kiro", home=tmp_path, command=["/x/aegis-mcp"]).result == "registered"
        data = json.loads((tmp_path / ".kiro" / "settings" / "mcp.json").read_text(encoding="utf-8"))
        assert data == {"mcpServers": {"aegis": {"command": "/x/aegis-mcp", "args": [],
                                                 "env": {"AEGIS_CLIENT": "kiro"}}}}

    def test_kiro_refuses_a_settings_file_it_cannot_round_trip(self, tmp_path):
        cfg = tmp_path / ".kiro" / "settings" / "mcp.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text('{"mcpServers": {}, // comment\n}', encoding="utf-8")
        with pytest.raises(ih.InstallError, match="is not valid JSON"):
            ih.register_host("kiro", home=tmp_path, command=["/x/aegis-mcp"])
        assert cfg.read_text(encoding="utf-8") == '{"mcpServers": {}, // comment\n}'

    def test_antigravity_merges_its_json_file_under_home(self, tmp_path):
        action = ih.register_host("antigravity", home=tmp_path, command=["/x/aegis-mcp"])
        assert action.result == "registered"
        data = json.loads((tmp_path / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))
        assert data == {"mcpServers": {"aegis": {"command": "/x/aegis-mcp", "args": [],
                                                 "env": {"AEGIS_CLIENT": "antigravity"}}}}
        assert ih.register_host("antigravity", home=tmp_path, command=["/x/aegis-mcp"]).result == "unchanged"

    def test_unregister_native_removes_aegis_and_soma(self, tmp_path, monkeypatch):
        exe = _fake_bin(tmp_path / "bin", "codex")
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        action = ih.unregister_host("codex-cli", home=tmp_path, path=str(tmp_path / "bin"))
        assert action.result == "removed"
        assert _paths(*{c[0] for c in runner.calls}) == _paths(exe)
        assert [c[1:] for c in runner.calls] == [["mcp", "remove", "aegis"], ["mcp", "remove", "soma"]]

    def test_unregister_antigravity_edits_only_its_entries(self, tmp_path):
        cfg = tmp_path / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"mcpServers": {"aegis": {}, "soma": {}, "x": {}}}), encoding="utf-8")
        assert ih.unregister_host("antigravity", home=tmp_path).result == "removed"
        assert json.loads(cfg.read_text(encoding="utf-8")) == {"mcpServers": {"x": {}}}


class TestHostsAegisNeverRegisters:
    """A retired or identity-only row is refused before anything runs or is written."""

    @pytest.mark.parametrize("call", ["register", "unregister"])
    @pytest.mark.parametrize("host_id, message", [("gemini-cli", RETIRED_GEMINI_CLI), ("claude-desktop", DESKTOP_H4)])
    def test_register_and_unregister_refuse_with_the_row_reason(self, tmp_path, monkeypatch, call, host_id, message):
        _fake_bin(tmp_path / "bin", "gemini")
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        home = tmp_path / "home"
        home.mkdir()
        with pytest.raises(ih.InstallError) as exc:
            if call == "register":
                ih.register_host(host_id, home=home, command=["/x/aegis-mcp"], path=str(tmp_path / "bin"))
            else:
                ih.unregister_host(host_id, home=home, path=str(tmp_path / "bin"))
        assert str(exc.value) == message
        assert runner.calls == []
        assert list(home.iterdir()) == []


class TestUserConfigBackups:
    """A host config Aegis rewrites is copied to ~/.aegis/backups/<UTC stamp>/ first."""

    def _backups(self, home: Path) -> list:
        root = home / ".aegis" / "backups"
        return sorted(p for p in root.rglob("*") if p.is_file()) if root.is_dir() else []

    def test_merge_backs_up_the_original_bytes(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        original = b'{"mcpServers": {"github": {"command": "gh"}}}'
        target.write_bytes(original)
        assert ih.merge_mcp_json(target, "aegis", ENTRY, backup_dir=tmp_path / "bk") == "added"
        assert (tmp_path / "bk" / "mcp_config.json").read_bytes() == original

    def test_no_backup_for_a_new_file_an_unchanged_one_or_a_dry_run(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        ih.merge_mcp_json(target, "aegis", ENTRY, backup_dir=tmp_path / "bk")
        ih.merge_mcp_json(target, "aegis", ENTRY, backup_dir=tmp_path / "bk")
        ih.remove_mcp_json(target, ("aegis",), backup_dir=tmp_path / "bk", dry_run=True)
        assert not (tmp_path / "bk").exists()

    def test_register_and_unregister_back_up_the_antigravity_config(self, tmp_path):
        cfg = tmp_path / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_bytes(b'{"mcpServers": {}}')
        ih.register_host("antigravity", home=tmp_path, command=["/x/aegis-mcp"])
        (first,) = self._backups(tmp_path)
        assert first.name == "mcp_config.json" and first.read_bytes() == b'{"mcpServers": {}}'
        registered = cfg.read_bytes()
        ih.unregister_host("antigravity", home=tmp_path)
        assert registered in [p.read_bytes() for p in self._backups(tmp_path)]


class TestHostCliRunner:
    def test_runs_without_shell_stdin_or_the_callers_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        code = ("import os, sys; print(os.getcwd()); print(repr(sys.stdin.read())); sys.stdout.flush(); "
                "sys.stdout.buffer.write(b'caf\\xc3\\xa9 \\xff\\n')")
        proc = _REAL_RUN_CLI([sys.executable, "-c", code])
        cwd, stdin, text = proc.stdout.splitlines()
        assert proc.returncode == 0
        assert Path(cwd).resolve() != tmp_path.resolve()
        assert not Path(cwd).exists()  # a throwaway directory, removed afterwards
        assert stdin == "''"
        assert text == "café \ufffd"  # UTF-8 decoded; an invalid byte cannot crash init


# ── Review fixes: what a dry run (the check pass) must already refuse ────────


class _ReadOnly:
    """chmod a file read-only for the test, then make it writable again for cleanup."""

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        self.path.chmod(0o444)
        return self.path

    def __exit__(self, *exc):
        if self.path.exists():
            self.path.chmod(0o644)


def _registry(home: Path) -> Path:
    reg = home / ".aegis" / "workspaces.json"
    reg.parent.mkdir(parents=True, exist_ok=True)
    reg.write_text(json.dumps({"v": 1, "workspaces": []}), encoding="utf-8")
    return reg


class TestDryRunRefusesWhatTheWriteRefuses:
    """``dry_run`` is init's check pass, so it must refuse every input the write refuses;
    otherwise init writes .aegis/ and AGENTS.md and only then fails."""

    @pytest.mark.parametrize("call", [
        lambda p: ih.write_managed_block(p, "bootstrap", "Hello\n", dry_run=True),
        lambda p: ih.remove_managed_block(p, "bootstrap", dry_run=True),
        lambda p: ih.remove_managed_block(p, "bootstrap", dry_run=True, delete_if_empty=True),
    ], ids=["write-block", "remove-block", "delete-empty"])
    def test_read_only_markdown(self, tmp_path, call):
        target = tmp_path / "AGENTS.md"
        target.write_text("# mine\n\n" + _block("bootstrap", "Old\n"), encoding="utf-8")
        before = target.read_bytes()
        with _ReadOnly(target):
            with pytest.raises(ih.InstallError, match="read-only"):
                call(target)
        assert target.read_bytes() == before

    def test_read_only_file_holding_only_the_block_is_not_deleted(self, tmp_path):
        target = tmp_path / "AGENTS.md"
        ih.write_managed_block(target, "bootstrap", "Hello\n")
        with _ReadOnly(target):
            with pytest.raises(ih.InstallError, match="read-only"):
                ih.remove_managed_block(target, "bootstrap", delete_if_empty=True)
            assert target.exists()

    @pytest.mark.parametrize("call", [
        lambda p: ih.merge_mcp_json(p, "aegis", ENTRY, dry_run=True),
        lambda p: ih.remove_mcp_json(p, ("aegis", "soma"), dry_run=True),
    ], ids=["merge", "remove"])
    def test_read_only_json_config(self, tmp_path, call):
        target = tmp_path / "mcp_config.json"
        target.write_text(json.dumps({"mcpServers": {"soma": {"command": "s"}}}), encoding="utf-8")
        with _ReadOnly(target):
            with pytest.raises(ih.InstallError, match="read-only"):
                call(target)

    def test_read_only_registry(self, tmp_path):
        home, root = tmp_path / "home", tmp_path / "repo"
        root.mkdir()
        reg = _registry(home)
        with _ReadOnly(reg):
            with pytest.raises(ih.InstallError, match="read-only"):
                ih.register_workspace(home, root, ["codex-cli"], dry_run=True)
        ih.register_workspace(home, root, [], now="t")
        with _ReadOnly(reg):
            with pytest.raises(ih.InstallError, match="read-only"):
                ih.unregister_workspace(home, root, dry_run=True)

    def test_new_file_in_a_read_only_directory(self, tmp_path):
        if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
            pytest.skip("needs POSIX directory permissions as a non-root user")
        repo = tmp_path / "repo"
        repo.mkdir()
        repo.chmod(0o555)
        try:
            with pytest.raises(ih.InstallError, match="cannot be created"):
                ih.write_managed_block(repo / "AGENTS.md", "bootstrap", "Hello\n", dry_run=True)
        finally:
            repo.chmod(0o755)

    def test_unpaired_surrogate_escape_is_refused_before_any_write(self, tmp_path):
        """json.loads turns "\\ud800" into a lone surrogate that cannot be written back as UTF-8."""
        target = tmp_path / "mcp_config.json"
        raw = b'{"mcpServers": {"x": {"command": "\\ud800"}}}'
        target.write_bytes(raw)
        backups = tmp_path / "bk"
        for dry_run in (True, False):
            with pytest.raises(ih.InstallError, match="surrogate"):
                ih.merge_mcp_json(target, "aegis", ENTRY, dry_run=dry_run, backup_dir=backups)
            with pytest.raises(ih.InstallError, match="surrogate"):
                ih.remove_mcp_json(target, ("x",), dry_run=dry_run, backup_dir=backups)
        assert target.read_bytes() == raw
        assert not backups.exists()

    @pytest.mark.parametrize("number", ["1e999", "-1e999"])
    def test_a_number_that_overflows_to_infinity_is_refused_before_any_write(self, tmp_path, number):
        """json.loads reads 1e999 as inf without calling parse_constant; written back it
        would be ``Infinity``, which is not JSON, and the next init would refuse the file."""
        target = tmp_path / "mcp_config.json"
        raw = b'{"mcpServers": {"x": {"command": "x"}}, "timeout": ' + number.encode() + b"}"
        target.write_bytes(raw)
        backups = tmp_path / "bk"
        for dry_run in (True, False):
            with pytest.raises(ih.InstallError, match="cannot be written back as JSON"):
                ih.merge_mcp_json(target, "aegis", ENTRY, dry_run=dry_run, backup_dir=backups)
            with pytest.raises(ih.InstallError, match="cannot be written back as JSON"):
                ih.remove_mcp_json(target, ("x",), dry_run=dry_run, backup_dir=backups)
        assert target.read_bytes() == raw
        assert not backups.exists()

    def test_a_refused_rewrite_leaves_no_backup(self, tmp_path):
        target = tmp_path / "mcp_config.json"
        target.write_bytes(b'{"mcpServers": {}}')
        with _ReadOnly(target):
            with pytest.raises(ih.InstallError, match="read-only"):
                ih.merge_mcp_json(target, "aegis", ENTRY, backup_dir=tmp_path / "bk")
        assert not (tmp_path / "bk").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
class TestBackupPermissions:
    """A backup holds the same secrets as the config it copies (other servers' API keys)."""

    def test_backup_is_never_more_readable_than_the_original(self, tmp_path):
        cfg = tmp_path / ".gemini" / "config" / "mcp_config.json"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(json.dumps({"mcpServers": {"x": {"env": {"API_KEY": "secret"}}}}), encoding="utf-8")
        cfg.chmod(0o600)
        old = os.umask(0o002)
        try:
            ih.register_host("antigravity", home=tmp_path, command=["/x/aegis-mcp"])
        finally:
            os.umask(old)
        backups = tmp_path / ".aegis" / "backups"
        (stamp,) = list(backups.iterdir())
        (copy,) = list(stamp.iterdir())
        assert b"secret" in copy.read_bytes()
        assert stat.S_IMODE(copy.stat().st_mode) & ~0o600 == 0
        assert stat.S_IMODE(stamp.stat().st_mode) == 0o700
        assert stat.S_IMODE(backups.stat().st_mode) == 0o700
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600


def _plant(directory: Path, name: str) -> None:
    """A repository-controlled executable named like a host CLI, in every form Windows runs."""
    directory.mkdir(parents=True, exist_ok=True)
    for suffix in ("", ".exe", ".cmd", ".bat"):
        path = directory / (name + suffix)
        path.write_bytes(b"#!/bin/sh\necho planted\n")
        path.chmod(0o755)


class TestRepositoryExecutablesAreNeverRun:
    """A host CLI or aegis-mcp is looked up only in absolute PATH entries: a cloned
    repository (the current directory) can never supply the binary init runs or the MCP
    command it writes into a host's user config (host-matrix §3.7)."""

    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        for name in ("codex", "claude", "agy", "aegis-mcp"):
            _plant(repo, name)
        monkeypatch.chdir(repo)
        (tmp_path / "home").mkdir()
        empty = tmp_path / "empty-bin"
        empty.mkdir()
        return type("Repo", (), {"root": repo, "home": tmp_path / "home", "empty": str(empty)})

    def _assert_nothing_from(self, repo, path, monkeypatch):
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        assert ih.detect_hosts(repo.home, path=path) == []
        command = ih.mcp_command(path=path, scripts_dirs=[])
        assert command[:3] == [sys.executable, "-I", "-c"] and ih.launch_risk(command) is None
        assert not any(str(repo.root) in part for part in command)
        assert ih.register_host("codex-cli", home=repo.home, command=["/x"], path=path).result == "manual"
        assert ih.unregister_host("claude-code", home=repo.home, path=path).result == "manual"
        assert runner.calls == []

    def test_relative_and_empty_path_entries_are_skipped(self, repo, monkeypatch):
        path = os.pathsep.join(["", ".", "subdir", repo.empty])
        self._assert_nothing_from(repo, path, monkeypatch)

    @pytest.mark.skipif(sys.platform != "win32", reason="shutil.which searches the cwd first only on Windows")
    def test_the_current_directory_is_not_searched_on_windows(self, repo, monkeypatch):
        self._assert_nothing_from(repo, repo.empty, monkeypatch)

    def test_an_absolute_entry_after_a_planted_cwd_still_resolves(self, repo, tmp_path, monkeypatch):
        exe = _fake_bin(tmp_path / "real-bin", "codex")
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        path = os.pathsep.join([".", str(tmp_path / "real-bin")])
        assert ih.register_host("codex-cli", home=repo.home, command=["/x"], path=path).result == "registered"
        assert _paths(*{c[0] for c in runner.calls}) == _paths(exe)

    @pytest.mark.skipif(sys.platform != "win32", reason="PATHEXT applies on Windows")
    def test_windows_runs_a_cmd_shim_from_an_absolute_entry(self, tmp_path, monkeypatch):
        bindir = tmp_path / "npm"
        bindir.mkdir()
        (bindir / "codex.cmd").write_bytes(b"@echo off\r\n")
        assert ih.detect_hosts(tmp_path, path=str(bindir)) == ["codex-cli"]


class TestMultiCallShims:
    """Version managers (Volta, mise, asdf) install a host CLI as a link to one dispatcher
    that picks the tool from the name it was run under (argv[0]). The CLI must be run by
    the path found on PATH, not by the link's target, or the dispatcher sees its own name.
    The same holds for the aegis-mcp command init writes into a host's config."""

    def _shim(self, tmp_path, script: bytes = b"#!/bin/sh\nexit 0\n", name: str = "codex") -> Path:
        real = tmp_path / "toolchain" / "dispatcher"
        real.parent.mkdir()
        real.write_bytes(script)
        real.chmod(0o755)
        bindir = tmp_path / "bin"
        bindir.mkdir()
        # Windows runs only names carrying a PATHEXT extension, so the link carries one.
        symlink_or_skip(real, bindir / (name + EXE))
        return bindir

    def test_a_linked_host_cli_is_run_under_its_own_name(self, tmp_path, monkeypatch):
        bindir = self._shim(tmp_path)
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        assert ih.register_host("codex-cli", home=tmp_path, command=["/x"], path=str(bindir)).result == "registered"
        assert ih.unregister_host("codex-cli", home=tmp_path, path=str(bindir)).result == "removed"
        assert _paths(*{c[0] for c in runner.calls}) == _paths(bindir / ("codex" + EXE))

    def test_a_linked_aegis_mcp_is_the_command_under_its_own_name(self, tmp_path):
        bindir = self._shim(tmp_path, name="aegis-mcp")
        assert _paths(*ih.mcp_command(path=str(bindir))) == _paths(bindir / ("aegis-mcp" + EXE))

    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell dispatcher")
    def test_a_dispatcher_that_reads_argv0_registers(self, tmp_path, monkeypatch):
        log = tmp_path / "calls.log"
        bindir = self._shim(tmp_path, (
            "#!/bin/sh\n"
            'echo "$(basename "$0") $*" >> "%s"\n'
            'case "$(basename "$0")" in codex) exit 0 ;; *) echo "error: unknown tool" >&2; exit 127 ;; esac\n'
            % log).encode())
        monkeypatch.setattr(ih, "_run_cli", _REAL_RUN_CLI)
        action = ih.register_host("codex-cli", home=tmp_path, command=["/x/aegis-mcp"], path=str(bindir))
        assert (action.result, action.detail) == ("registered", "")
        assert log.read_text(encoding="utf-8").splitlines() == [
            "codex mcp remove aegis",
            "codex mcp add aegis --env AEGIS_CLIENT=codex-cli -- /x/aegis-mcp",
        ]

    @pytest.mark.skipif(os.name == "nt", reason="a POSIX shell dispatcher")
    def test_the_written_aegis_mcp_command_starts_aegis_mcp(self, tmp_path):
        import subprocess

        bindir = self._shim(tmp_path, b'#!/bin/sh\necho "dispatch $(basename "$0")"\n', name="aegis-mcp")
        command = ih.mcp_command(path=str(bindir))
        out = subprocess.run(command, capture_output=True, text=True, stdin=subprocess.DEVNULL, check=True).stdout
        assert out == "dispatch aegis-mcp\n"


class TestWindowsLookup:
    """Windows matches file names case-insensitively and PATHEXT spells extensions in
    capitals: ``codex`` + ``.EXE`` names the file ``codex.exe``. The command Aegis runs and
    the one it writes into a host's config carry the file's own spelling, so a config does
    not say ``aegis-mcp.EXE`` for ``aegis-mcp.exe`` and comparisons need not fold case.
    Emulated off Windows by the platform name; on Windows it is the real lookup."""

    @pytest.fixture
    def windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("PATHEXT", os.pathsep.join([".COM", ".EXE", ".BAT", ".CMD"]))

    @pytest.mark.parametrize("on_disk", ["aegis-mcp.exe", "aegis-mcp.Exe"])
    def test_the_mcp_command_is_the_on_disk_spelling(self, tmp_path, windows, on_disk):
        exe = tmp_path / "bin" / on_disk
        exe.parent.mkdir()
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        assert ih.mcp_command(path=str(exe.parent)) == [str(exe)]

    def test_a_host_cli_is_run_by_its_on_disk_spelling(self, tmp_path, windows, monkeypatch):
        exe = tmp_path / "bin" / "codex.exe"
        exe.parent.mkdir()
        exe.write_bytes(b"MZ")
        exe.chmod(0o755)
        runner = _Runner()
        monkeypatch.setattr(ih, "_run_cli", runner)
        assert ih.register_host("codex-cli", home=tmp_path, command=["/x"], path=str(exe.parent)).result == "registered"
        assert {c[0] for c in runner.calls} == {str(exe)}

    def test_a_cmd_shim_is_found_after_the_exe_extensions(self, tmp_path, windows):
        shim = tmp_path / "npm" / "codex.cmd"
        shim.parent.mkdir()
        shim.write_bytes(b"@echo off\r\n")
        shim.chmod(0o755)
        assert ih.detect_hosts(tmp_path, path=str(shim.parent)) == ["codex-cli"]


class TestInitHostEvent:
    """register_workspace is the one place `aegis init` records the hosts it set up for a
    workspace; for each selected host whose row is unverified it also appends an init_host event."""

    def test_one_event_per_unverified_host_in_the_events_log(self, tmp_path):
        from aegis_core import events

        home, root = tmp_path / "home", tmp_path / "ws"
        root.mkdir()
        assert ih.register_workspace(home, root, ["codex-cli", "windsurf", "copilot"]) == "added"
        rows = events.read(root, "init_host").rows
        assert [(r["host"], r["result"]) for r in rows] == [("copilot", "experimental"), ("windsurf", "experimental")]
        assert rows[0]["detail"] == {"host": "copilot", "verified": False,
                                     "surfaces": ["GitHub Copilot in VS Code (agent mode)", "GitHub Copilot CLI"]}

    def test_an_unchanged_registry_entry_still_records_the_run(self, tmp_path):
        from aegis_core import events

        home, root = tmp_path / "home", tmp_path / "ws"
        root.mkdir()
        ih.register_workspace(home, root, ["kiro"])
        assert ih.register_workspace(home, root, ["kiro"]) == "unchanged"
        assert len(events.read(root, "init_host").rows) == 2

    def test_a_dry_run_and_verified_hosts_record_nothing(self, tmp_path):
        from aegis_core import events

        home, root = tmp_path / "home", tmp_path / "ws"
        root.mkdir()
        ih.register_workspace(home, root, ["kiro"], dry_run=True)
        ih.register_workspace(home, root, ["codex-cli", "claude-code", "antigravity"])
        assert events.read(root, "init_host").rows == []

    def test_a_host_the_table_does_not_know_is_skipped(self, tmp_path):
        from aegis_core import events

        home, root = tmp_path / "home", tmp_path / "ws"
        root.mkdir()
        ih.register_workspace(home, root, ["zed", "kiro"])
        assert [r["host"] for r in events.read(root, "init_host").rows] == ["kiro"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_private_config_swapped_for_a_symlink_before_the_write_keeps_its_checked_mode(tmp_path, monkeypatch):
    """w8b L4: Given a 0600 config checked as a regular file, When it is swapped for a symlink just
    before the replacing write under umask 022, Then the replacement keeps the 0600 the check saw (not
    the 0644 of a new file) and the link's target is spared."""
    target = tmp_path / "mcp_config.json"
    target.write_bytes(b'{"mcpServers": {}}\n')
    target.chmod(0o600)
    victim = tmp_path / "victim.json"
    victim.write_bytes(b'{"keep": true}\n')
    victim.chmod(0o644)
    real_write = ih.atomic_write_bytes
    swapped = []

    def swap_then_write(path, data, *args, **kwargs):
        if Path(path) == target and not swapped:
            os.unlink(target)
            symlink_or_skip(victim, target)
            swapped.append(path)
        return real_write(path, data, *args, **kwargs)

    monkeypatch.setattr(ih, "atomic_write_bytes", swap_then_write)
    saved = os.umask(0o022)
    try:
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "added"
    finally:
        os.umask(saved)
    assert swapped and not target.is_symlink()
    assert json.loads(target.read_text(encoding="utf-8"))["mcpServers"] == {"aegis": ENTRY}
    assert target.stat().st_mode & 0o777 == 0o600
    assert victim.read_bytes() == b'{"keep": true}\n' and victim.stat().st_mode & 0o777 == 0o644


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_new_config_file_still_gets_the_default_mode(tmp_path):
    target = tmp_path / "new" / "mcp_config.json"
    saved = os.umask(0o022)
    try:
        assert ih.merge_mcp_json(target, "aegis", ENTRY) == "added"
    finally:
        os.umask(saved)
    assert target.stat().st_mode & 0o777 == 0o644
