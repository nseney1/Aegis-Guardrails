"""`aegis hook run pre-tool --host <h>`: the per-host PreToolUse handler (v4.1 spec §2).

Contract on every host: one JSON payload on stdin, nothing ever on stdout, and exit
- 0 to allow, and on any internal error, the 5 s deadline, an unusable payload, an
  unknown host or event, or an ungoverned workspace (fail-open is the design);
- 2 to block on Claude Code and Codex CLI, with the reason on stderr;
- 75 to block on Antigravity (its registration wrapper maps 75 to agy's blocking 1).

Scan-before-edit: an edit passes when one scan row (any host or session, the CLI's
included) names every edited path within jit.scan_window_s; otherwise Claude and Codex
block and agy only records. Destructive guard: the block set blocks, the record set is
recorded. Each outcome is an events-log row: scan_gate{result}, guard_match{tier, action}.
Payload shapes follow the host docs (cited in tests/unit/core/test_hook_events.py).
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
import errno
import gc
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from aegis_cli.hooks import pretool
from aegis_core import events, scan_compliance

REPO = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def ws(tmp_path) -> Path:
    root = tmp_path / "ws"
    (root / ".aegis" / "rules").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "a.py").write_text("a\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root.resolve()


# Claude Code: https://code.claude.com/docs/en/hooks (PreToolUse input).
def claude(ws: Path, tool: str, tool_input: dict, cwd=None) -> dict:
    return {"session_id": "s", "transcript_path": "t", "cwd": str(cwd or ws), "permission_mode": "default",
            "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input,
            "tool_use_id": "toolu_1"}


# Codex CLI: https://learn.chatgpt.com/docs/hooks; source rust-v0.162.1 (hooks/src/schema.rs).
def codex(ws: Path, tool: str, command: str) -> dict:
    return {"session_id": "s", "turn_id": "t", "transcript_path": "t", "cwd": str(ws), "model": "m",
            "hook_event_name": "PreToolUse", "permission_mode": "default", "tool_name": tool,
            "tool_input": {"command": command}, "tool_use_id": "call_1"}


# Antigravity: https://antigravity.google/docs/hooks (PreToolUse input).
def agy(ws: Path, name: str, args: dict) -> dict:
    return {"toolCall": {"name": name, "args": args}, "stepIdx": 3, "conversationId": "c-1",
            "workspacePaths": [str(ws)], "transcriptPath": "t", "artifactDirectoryPath": "a", "modelName": "m"}


def _run(capsys, host, payload, environ=None, now=NOW):
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    code = pretool.run_pre_tool(host, data, environ or {}, now=now)
    out, err = capsys.readouterr()
    return code, out, err


def _events(ws: Path, kind=None):
    return [(r["event"], r.get("host"), r["result"], r["detail"]) for r in events.read(ws, kind).rows]


def _scan_row(ws: Path, files, host="claude-code", ago=0):
    scan_compliance.record(ws, "scan", host=host, session="s-1", files=files)
    if ago:  # age the row: rewrite its timestamp
        path = scan_compliance.activity_path(ws)
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[-1]["ts"] = (NOW - timedelta(seconds=ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def _fresh_row(ws: Path, files, host="claude-code"):
    path = scan_compliance.activity_path(ws)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"v": 1, "ts": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": "scan", "host": host,
           "session": "s-1", "files": files}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


# ── scan-before-edit ─────────────────────────────────────────────────────────

def test_claude_blocks_an_edit_nobody_scanned(ws, capsys):
    code, out, err = _run(capsys, "claude-code", claude(ws, "Write", {"file_path": str(ws / "src" / "a.py"), "content": "x"}))
    assert (code, out) == (2, "")
    assert err == "aegis: call aegis_scan with src/a.py before editing (or run: aegis scan src/a.py)\n"
    assert _events(ws) == [("scan_gate", "claude-code", "block", {"paths": 1})]


def test_codex_blocks_an_unscanned_patch_naming_every_path(ws, capsys):
    patch = "*** Begin Patch\n*** Update File: src/a.py\n@@\n-a\n+b\n*** Add File: src/my new.py\n+x\n*** End Patch\n"
    code, out, err = _run(capsys, "codex-cli", codex(ws, "apply_patch", patch))
    assert (code, out) == (2, "")
    assert err == ("aegis: call aegis_scan with src/a.py 'src/my new.py' before editing "
                   "(or run: aegis scan src/a.py 'src/my new.py')\n")
    assert _events(ws) == [("scan_gate", "codex-cli", "block", {"paths": 2})]


def test_a_codex_apply_patch_heredoc_is_gated_as_an_edit(ws, capsys):
    command = "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: src/a.py\n@@\n-a\n+b\n*** End Patch\nEOF\n"
    code, _, err = _run(capsys, "codex-cli", codex(ws, "Bash", command))
    assert code == 2 and "aegis scan src/a.py" in err


def test_a_pure_quoted_apply_patch_heredoc_with_destructive_diff_line_is_only_scan_gated(ws, capsys):
    command = (
        "apply_patch <<'EOF'\n"
        "*** Begin Patch\n"
        "*** Update File: a.sh\n"
        "@@\n"
        "+git reset --hard\n"
        "*** End Patch\n"
        "EOF"
    )
    code, out, err = _run(capsys, "codex-cli", codex(ws, "Bash", command))
    assert (code, out) == (2, "")
    assert "aegis scan a.sh" in err
    assert _events(ws) == [("scan_gate", "codex-cli", "block", {"paths": 1})]
    _fresh_row(ws, ["a.sh"], host="codex-cli")
    assert _run(capsys, "codex-cli", codex(ws, "Bash", command)) == (0, "", "")
    assert _events(ws)[-1] == ("scan_gate", "codex-cli", "pass", {"paths": 1})


@pytest.mark.parametrize("command", [
    "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch\nEOF\ngit reset --hard",
    "apply_patch <<'EOF' && git reset --hard\n*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch\nEOF",
    "apply_patch '*** Begin Patch\n*** Add File: a.py\n+x = 1\n*** End Patch' && git reset --hard",
    "apply_patch <<EOF\n*** Begin Patch\n*** Add File: a.py\n+$(git reset --hard)\n*** End Patch\nEOF",
    'apply_patch <<EOF\n*** Begin Patch\n*** Add File: a.py\n+$(echo ")" && git reset --hard)\n*** End Patch\nEOF',
])
def test_codex_apply_patch_command_chaining_and_unquoted_substitutions_are_blocked_by_guard(ws, capsys, command):
    _fresh_row(ws, ["a.py"], host="codex-cli")
    code, out, err = _run(capsys, "codex-cli", codex(ws, "Bash", command))
    assert (code, out) == (2, "")
    assert err.startswith("aegis: blocked git-reset-hard")
    assert _events(ws) == [("guard_match", "codex-cli", "block", {"tier": "block", "action": "block", "rule": "git-reset-hard"})]


def test_a_compound_benign_apply_patch_command_is_still_gated_by_scan_before_edit(ws, capsys):
    command = (
        "apply_patch <<'EOF'\n"
        "*** Begin Patch\n"
        "*** Add File: a.py\n"
        "+x = 1\n"
        "*** End Patch\n"
        "EOF\n"
        "echo done"
    )
    code, out, err = _run(capsys, "codex-cli", codex(ws, "Bash", command))
    assert (code, out) == (2, "")
    assert "aegis scan a.py" in err
    assert _events(ws) == [("scan_gate", "codex-cli", "block", {"paths": 1})]
    _fresh_row(ws, ["a.py"], host="codex-cli")
    assert _run(capsys, "codex-cli", codex(ws, "Bash", command)) == (0, "", "")
    assert _events(ws)[-1] == ("scan_gate", "codex-cli", "pass", {"paths": 1})


def test_agy_only_records_an_unscanned_edit_silently(ws, capsys):
    assert _run(capsys, "antigravity", agy(ws, "write_to_file", {"TargetFile": "src/a.py"})) == (0, "", "")
    assert _events(ws) == [("scan_gate", "antigravity", "record", {"paths": 1})]


@pytest.mark.parametrize("host", ["claude-code", "codex-cli", "antigravity", scan_compliance.CLI_HOST])
def test_a_scan_row_from_any_host_lets_the_edit_pass(ws, capsys, host):
    _fresh_row(ws, ["src/a.py", "src/b.py"], host=host)
    payload = claude(ws, "Edit", {"file_path": str(ws / "src" / "a.py"), "old_string": "a", "new_string": "b"})
    assert _run(capsys, "claude-code", payload) == (0, "", "")
    assert _events(ws) == [("scan_gate", "claude-code", "pass", {"paths": 1})]


def test_a_scan_older_than_the_window_no_longer_counts(ws, capsys):
    _scan_row(ws, ["src/a.py"], ago=3601)
    payload = claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})
    assert _run(capsys, "claude-code", payload)[0] == 2
    (ws / ".aegis" / "config.json").write_text(json.dumps({"jit": {"scan_window_s": 7200}}), encoding="utf-8")
    assert _run(capsys, "claude-code", payload)[0] == 0


def test_the_real_clock_is_used_without_an_injected_one(ws, capsys):
    scan_compliance.record(ws, "scan", host="cli", session="c", files=["src/a.py"])
    payload = claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})
    assert _run(capsys, "claude-code", payload, now=None) == (0, "", "")


def test_a_notebook_edit_is_gated_on_its_notebook_path(ws, capsys):
    payload = claude(ws, "NotebookEdit", {"notebook_path": str(ws / "nb.ipynb"), "new_source": "x"})
    code, _, err = _run(capsys, "claude-code", payload)
    assert code == 2 and "aegis_scan with nb.ipynb" in err


def test_an_edit_outside_the_workspace_is_not_gated(ws, tmp_path, capsys):
    payload = claude(ws, "Write", {"file_path": str(tmp_path / "elsewhere.py")})
    assert _run(capsys, "claude-code", payload) == (0, "", "")
    assert _events(ws) == []


def test_only_the_paths_inside_the_workspace_are_gated(ws, tmp_path, capsys):
    patch = f"*** Begin Patch\n*** Add File: {tmp_path / 'out.py'}\n+x\n*** Update File: src/a.py\n*** End Patch\n"
    _fresh_row(ws, ["src/a.py"])
    assert _run(capsys, "codex-cli", codex(ws, "apply_patch", patch)) == (0, "", "")


def test_an_agy_relative_target_resolves_against_the_workspace_path(ws, capsys):
    _fresh_row(ws, ["src/a.py"])
    assert _run(capsys, "antigravity", agy(ws, "replace_file_content", {"TargetFile": "src/a.py"})) == (0, "", "")
    assert _events(ws) == [("scan_gate", "antigravity", "pass", {"paths": 1})]


def test_claude_resolves_the_workspace_from_its_project_dir_before_the_cwd(ws, tmp_path, capsys):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    payload = claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")}, cwd=elsewhere)
    assert _run(capsys, "claude-code", payload)[0] == 0  # the cwd alone governs nothing
    assert _run(capsys, "claude-code", payload, {"CLAUDE_PROJECT_DIR": str(ws)})[0] == 2


def test_the_governed_root_is_the_nearest_aegis_directory(ws, capsys):
    """A workspace in a monorepo package: paths are relative to it, rows are its own."""
    pkg = ws / "pkg"
    (pkg / ".aegis").mkdir(parents=True)
    (pkg / "sub").mkdir()
    _fresh_row(pkg, ["sub/m.py"])
    payload = claude(ws, "Write", {"file_path": str(pkg / "sub" / "m.py")}, cwd=pkg / "sub")
    assert _run(capsys, "claude-code", payload) == (0, "", "")
    assert _events(pkg) == [("scan_gate", "claude-code", "pass", {"paths": 1})]


def test_an_edit_through_a_symlink_is_gated_on_its_target(ws, capsys):
    from tests.conftest import symlink_or_skip

    symlink_or_skip(ws / "src" / "a.py", ws / "src" / "link.py")
    _fresh_row(ws, ["src/a.py"])
    assert _run(capsys, "claude-code", claude(ws, "Edit", {"file_path": str(ws / "src" / "link.py")}))[0] == 0


# A broken rule file makes every scan fail closed (no scan row), so blocking its repair
# would leave the gate unsatisfiable: edits of the rules tree are recorded, never blocked.

@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_an_unscanned_edit_of_a_rule_file_is_recorded_not_blocked(ws, capsys, host):
    rule = ws / ".aegis" / "rules" / "traps" / "trap-x.md"
    if host == "claude-code":
        payload = claude(ws, "Edit", {"file_path": str(rule), "old_string": "a", "new_string": "b"})
    else:
        payload = codex(ws, "apply_patch", "*** Begin Patch\n*** Update File: .aegis/rules/traps/trap-x.md\n@@\n-a\n+b\n*** End Patch\n")
    assert _run(capsys, host, payload) == (0, "", "")
    assert _events(ws) == [("scan_gate", host, "record", {"paths": 1})]


def test_a_scanned_rule_edit_passes(ws, capsys):
    _fresh_row(ws, [".aegis/rules/traps/trap-x.md"])
    payload = claude(ws, "Write", {"file_path": str(ws / ".aegis" / "rules" / "traps" / "trap-x.md")})
    assert _run(capsys, "claude-code", payload) == (0, "", "")
    assert _events(ws) == [("scan_gate", "claude-code", "pass", {"paths": 1})]


def test_a_patch_of_a_rule_and_a_source_file_is_gated_on_the_source_file(ws, capsys):
    patch = ("*** Begin Patch\n*** Update File: .aegis/rules/traps/trap-x.md\n@@\n-a\n+b\n"
             "*** Update File: src/a.py\n@@\n-a\n+b\n*** End Patch\n")
    code, out, err = _run(capsys, "codex-cli", codex(ws, "apply_patch", patch))
    assert (code, out) == (2, "")
    assert err == "aegis: call aegis_scan with src/a.py before editing (or run: aegis scan src/a.py)\n"
    _fresh_row(ws, ["src/a.py"])
    assert _run(capsys, "codex-cli", codex(ws, "apply_patch", patch)) == (0, "", "")
    assert [e[2] for e in _events(ws)] == ["block", "record"]


@pytest.mark.parametrize("name", [".aegis/config.json", ".aegis/rulesx/a.md", "rules/a.md", "src/rules/a.md"])
def test_other_paths_near_the_rules_tree_are_still_gated(ws, capsys, name):
    assert _run(capsys, "claude-code", claude(ws, "Write", {"file_path": str(ws / name)}))[0] == 2


def test_a_broken_rule_file_can_be_repaired_through_the_hook(ws, home):
    """The deadlock: the scan of the broken rule fails closed and records nothing, and the
    Edit that would repair it must still be allowed."""
    broken = ws / ".aegis" / "rules" / "traps" / "trap-broken.md"
    broken.parent.mkdir(parents=True, exist_ok=True)
    broken.write_text("---\nid: [unclosed\n---\nbody\n", encoding="utf-8")
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    env.pop("AEGIS_WORKSPACE", None)
    scan = subprocess.run([sys.executable, "-m", "aegis_cli", "scan", ".aegis/rules/traps/trap-broken.md"],
                          cwd=str(ws), env=env, capture_output=True, timeout=60)
    assert scan.returncode == 1 and b"cannot be served" in scan.stderr
    assert not scan_compliance.activity_path(ws).exists()
    payload = claude(ws, "Edit", {"file_path": str(broken), "old_string": "[unclosed", "new_string": "trap-broken"})
    proc = _cli(["pre-tool", "--host", "claude-code"], payload, ws, home)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


# ── destructive-command guard ────────────────────────────────────────────────

@pytest.mark.parametrize("host,payload_of,expected", [
    ("claude-code", lambda ws, c: claude(ws, "Bash", {"command": c}), 2),
    ("claude-code", lambda ws, c: claude(ws, "PowerShell", {"command": c}), 2),
    ("codex-cli", lambda ws, c: codex(ws, "Bash", c), 2),
    ("antigravity", lambda ws, c: agy(ws, "run_command", {"CommandLine": c}), 75),
])
def test_a_block_set_command_is_blocked_with_the_hosts_exit_code(ws, capsys, host, payload_of, expected):
    code, out, err = _run(capsys, host, payload_of(ws, "git push --force origin feat"))
    assert (code, out) == (expected, "")
    assert err.startswith("aegis: blocked git-push-force: force push") and err.endswith("\n")
    assert _events(ws) == [("guard_match", host, "block", {"tier": "block", "action": "block", "rule": "git-push-force"})]


@pytest.mark.parametrize("host,payload_of,expected", [
    ("claude-code", lambda ws, c: claude(ws, "Bash", {"command": c}), 2),
    ("codex-cli", lambda ws, c: codex(ws, "Bash", c), 2),
    ("antigravity", lambda ws, c: agy(ws, "run_command", {"CommandLine": c}), 75),
])
def test_a_dd_device_spelled_with_a_double_slash_is_blocked(ws, capsys, host, payload_of, expected):
    code, out, err = _run(capsys, host, payload_of(ws, "dd if=image.iso of=//dev/sda bs=4M"))
    assert (code, out) == (expected, "")
    assert err.startswith("aegis: blocked dd-device: ")
    assert _events(ws) == [("guard_match", host, "block", {"tier": "block", "action": "block", "rule": "dd-device"})]


@pytest.mark.parametrize("host,payload_of", [
    ("claude-code", lambda ws, c: claude(ws, "Bash", {"command": c})),
    ("codex-cli", lambda ws, c: codex(ws, "Bash", c)),
    ("antigravity", lambda ws, c: agy(ws, "run_command", {"CommandLine": c})),
])
def test_a_record_set_command_runs_and_is_recorded(ws, capsys, host, payload_of):
    assert _run(capsys, host, payload_of(ws, "git merge lane/x")) == (0, "", "")
    assert _events(ws) == [("guard_match", host, "record", {"tier": "record", "action": "record", "rule": "git-merge"})]


@pytest.mark.parametrize("host,payload_of", [
    ("claude-code", lambda ws, c: claude(ws, "Bash", {"command": c})),
    ("codex-cli", lambda ws, c: codex(ws, "Bash", c)),
    ("antigravity", lambda ws, c: agy(ws, "run_command", {"CommandLine": c})),
])
def test_destructive_sql_in_a_client_heredoc_runs_and_is_recorded(ws, capsys, host, payload_of):
    command = "psql -d app <<'EOF'\nDROP TABLE users;\nEOF\n"
    assert _run(capsys, host, payload_of(ws, command)) == (0, "", "")
    assert _events(ws) == [("guard_match", host, "record", {"tier": "record", "action": "record", "rule": "sql-destructive"})]


def test_a_command_line_git_alias_for_a_force_push_is_blocked(ws, capsys):
    code, out, err = _run(capsys, "claude-code", claude(ws, "Bash", {"command": "git -c alias.p='push -f' p origin feat"}))
    assert (code, out) == (2, "")
    assert err.startswith("aegis: blocked git-push-force: force push")
    assert _events(ws) == [("guard_match", "claude-code", "block", {"tier": "block", "action": "block", "rule": "git-push-force"})]


@pytest.mark.parametrize("command", ["git status", "rm -rf build/", "", "   ", "git reset --hard 'unclosed"])
def test_other_empty_or_unparseable_commands_pass_silently_and_unrecorded(ws, capsys, command):
    assert _run(capsys, "claude-code", claude(ws, "Bash", {"command": command})) == (0, "", "")
    assert _events(ws) == []


def test_a_read_only_tool_passes_without_a_trace(ws, capsys):
    assert _run(capsys, "claude-code", claude(ws, "Read", {"file_path": str(ws / "src" / "a.py")})) == (0, "", "")
    assert _run(capsys, "antigravity", agy(ws, "view_file", {"AbsolutePath": str(ws / "src" / "a.py")})) == (0, "", "")
    assert _events(ws) == []


# ── fail-open ────────────────────────────────────────────────────────────────

def test_an_ungoverned_workspace_is_a_silent_no_op(tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    subprocess.run(["git", "init", "-q", str(plain)], check=True)
    assert _run(capsys, "claude-code", claude(plain, "Bash", {"command": "git push --force"})) == (0, "", "")
    assert _run(capsys, "claude-code", claude(plain, "Write", {"file_path": str(plain / "a.py")})) == (0, "", "")
    assert _run(capsys, "antigravity", agy(plain, "run_command", {"CommandLine": "rm -rf /"})) == (0, "", "")
    assert not (plain / ".aegis").exists()
    assert not (plain / ".git" / "aegis").exists()


def test_a_payload_without_a_workspace_is_a_silent_no_op(ws, capsys):
    payload = codex(ws, "Bash", "git push --force")
    del payload["cwd"]
    assert _run(capsys, "codex-cli", payload) == (0, "", "")


@pytest.mark.parametrize("data", [b"", b"   ", b"not json", b"[1, 2]", b'"Bash"', b"\xff\xfe\x00", b'{"tool_name": 3}'])
def test_an_unusable_payload_exits_0_silently(ws, capsys, data):
    assert _run(capsys, "claude-code", data) == (0, "", "")


@pytest.mark.parametrize("host", ["gemini-cli", "", "claude"])
def test_an_unknown_host_exits_0_silently(ws, capsys, host):
    assert _run(capsys, host, claude(ws, "Bash", {"command": "git push --force"})) == (0, "", "")
    assert _events(ws) == []


def test_an_oversized_payload_is_not_read_and_exits_0(ws, capsys, monkeypatch):
    monkeypatch.setattr(pretool, "MAX_PAYLOAD_BYTES", 64)
    payload = claude(ws, "Bash", {"command": "git push --force"})
    assert _run(capsys, "claude-code", payload) == (0, "", "")


def test_a_stdin_stream_is_read_up_to_the_cap_and_no_further(ws, capsys, monkeypatch):
    """A payload of exactly MAX_PAYLOAD_BYTES is read whole and decided; one byte more is
    oversized and allowed unread, even when its first MAX_PAYLOAD_BYTES are a payload."""
    import io

    body = json.dumps(claude(ws, "Bash", {"command": "git push --force"})).encode("utf-8")
    monkeypatch.setattr(pretool, "MAX_PAYLOAD_BYTES", len(body) + 8)
    exact = body + b" " * 8
    assert pretool.run_pre_tool("claude-code", io.BytesIO(exact), {}, now=NOW) == 2
    assert pretool.run_pre_tool("claude-code", io.BytesIO(exact + b" "), {}, now=NOW) == 0
    assert pretool.run_pre_tool("claude-code", io.BytesIO(body), {}, now=NOW) == 2
    huge = io.BytesIO(exact + b" " * 1000)
    assert pretool.run_pre_tool("claude-code", huge, {}, now=NOW) == 0
    assert huge.tell() == len(exact) + 1  # the cap plus one byte, never the rest
    capsys.readouterr()


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyboardInterrupt(), SystemExit(2), MemoryError()])
def test_any_internal_error_exits_0_silently(ws, capsys, monkeypatch, error):
    def explode(*args, **kwargs):
        raise error

    monkeypatch.setattr(scan_compliance, "scan_covers", explode)
    assert _run(capsys, "claude-code", claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})) == (0, "", "")
    import aegis_core.command_safety as command_safety

    monkeypatch.setattr(command_safety, "classify_command", explode)
    assert _run(capsys, "claude-code", claude(ws, "Bash", {"command": "git push --force"})) == (0, "", "")


def test_a_failed_event_write_never_changes_the_decision(ws, capsys, monkeypatch):
    def unwritable(*args, **kwargs):
        raise OSError("read-only")

    monkeypatch.setattr(events, "append", unwritable)
    code, out, err = _run(capsys, "claude-code", claude(ws, "Bash", {"command": "git reset --hard"}))
    assert (code, out) == (2, "") and err.startswith("aegis: blocked git-reset-hard")
    assert _run(capsys, "claude-code", claude(ws, "Bash", {"command": "git merge x"})) == (0, "", "")


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="the deadline uses SIGALRM (POSIX)")
def test_the_deadline_fails_open(ws, capsys, monkeypatch):
    monkeypatch.setattr(pretool, "DEADLINE_SECONDS", 0.2)
    monkeypatch.setattr(scan_compliance, "scan_covers", lambda *a, **k: time.sleep(5))
    started = time.monotonic()
    assert _run(capsys, "claude-code", claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})) == (0, "", "")
    assert time.monotonic() - started < 2
    assert _events(ws) == []


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="the deadline uses SIGALRM (POSIX)")
def test_the_deadline_leaves_the_callers_timer_and_handler_as_they_were(ws, capsys):
    def mine(signum, frame):
        raise AssertionError("the caller's handler fired")

    previous = signal.signal(signal.SIGALRM, mine)
    try:
        signal.setitimer(signal.ITIMER_REAL, 30.0)
        _run(capsys, "claude-code", claude(ws, "Bash", {"command": "git merge x"}))
        remaining, _ = signal.getitimer(signal.ITIMER_REAL)
        assert signal.getsignal(signal.SIGALRM) is mine
        assert 25.0 < remaining <= 30.0
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    _run(capsys, "claude-code", claude(ws, "Bash", {"command": "git merge x"}))
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


# ── through the CLI ──────────────────────────────────────────────────────────

def _cli(args, payload, cwd, home, extra_env=None, timeout=60, *, popen_options=None):
    """Run `aegis hook run <args>` with ``payload`` on stdin; ``popen_options`` (the timing
    test's start options) are passed on to subprocess.run, and by default nothing is."""
    env = dict(os.environ)
    env.update({"HOME": str(home), "USERPROFILE": str(home)})
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    for key in ("AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        env.pop(key, None)
    env.update(extra_env or {})
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    return subprocess.run([sys.executable, "-m", "aegis_cli", "hook", "run", *args], input=data, cwd=str(cwd),
                          env=env, capture_output=True, timeout=timeout, **(popen_options or {}))


@pytest.fixture
def home(tmp_path) -> Path:
    path = tmp_path / "home"
    path.mkdir(exist_ok=True)
    return path


def test_the_cli_blocks_with_exit_2_and_nothing_on_stdout(ws, home):
    proc = _cli(["pre-tool", "--host", "claude-code"], claude(ws, "Bash", {"command": "git clean -fdx"}), ws, home)
    assert (proc.returncode, proc.stdout) == (2, b"")
    assert proc.stderr.decode().startswith("aegis: blocked git-clean-force")


@pytest.mark.parametrize("route", ["write", "direct-patch", "shell", "pure-patch", "compound-patch"])
@pytest.mark.parametrize("covered", [True, False], ids=["scanned", "unscanned"])
def test_the_cli_loads_command_parsing_only_for_shell_routes(ws, home, tmp_path, route, covered):
    """Observe the real import boundary in a fresh CLI process, without replacing the
    parser: direct edits need only the scan gate; shell and shell-patch routes still
    classify destructive commands and distinguish patch content from commands."""
    if covered:
        scan_compliance.record(ws, "scan", host="cli", session="s", files=["src/a.py"])
    patch = "*** Begin Patch\n*** Update File: src/a.py\n@@\n-a\n+git reset --hard\n*** End Patch\n"
    command = "apply_patch <<'EOF'\n" + patch + "EOF"
    host = "claude-code" if route in ("write", "shell") else "codex-cli"
    payload = {
        "write": claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")}),
        "direct-patch": codex(ws, "apply_patch", patch),
        "shell": claude(ws, "Bash", {"command": "git reset --hard"}),
        "pure-patch": codex(ws, "Bash", command),
        "compound-patch": codex(ws, "Bash", command + "\ngit reset --hard"),
    }[route]
    report = tmp_path / "imports.json"
    script = """
import builtins, json, runpy, sys
report, host = sys.argv[1:]
real_import = builtins.__import__
requested = []
def observe(name, globals=None, locals=None, fromlist=(), level=0):
    if name.startswith('aegis_core.command_safety') or (name == 'aegis_core' and 'command_safety' in (fromlist or ())):
        requested.append(name)
    return real_import(name, globals, locals, fromlist, level)
builtins.__import__ = observe
sys.argv = ['aegis', 'hook', 'run', 'pre-tool', '--host', host]
try:
    runpy.run_module('aegis_cli', run_name='__main__', alter_sys=True)
finally:
    with open(report, 'w', encoding='utf-8') as stream:
        json.dump(requested, stream)
"""
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    for key in ("AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        env.pop(key, None)
    proc = subprocess.run([sys.executable, "-c", script, str(report), host], input=json.dumps(payload).encode("utf-8"),
                          cwd=str(ws), env=env, capture_output=True, timeout=60)
    guarded = route in ("shell", "compound-patch")
    expected = 2 if guarded or not covered else 0
    assert (proc.returncode, proc.stdout) == (expected, b""), proc.stderr
    reason = b"aegis: blocked git-reset-hard" if guarded else b"aegis: call aegis_scan with src/a.py"
    assert proc.stderr.startswith(reason) if expected else proc.stderr == b""
    rows = events.read(ws).rows
    assert [(r["event"], r["result"]) for r in rows] == [
        ("guard_match", "block") if guarded else ("scan_gate", "pass" if covered else "block")]
    assert bool(json.loads(report.read_text(encoding="utf-8"))) is (route not in ("write", "direct-patch"))


def test_the_cli_blocks_agy_with_exit_75_from_a_cwd_outside_the_repository(ws, home, tmp_path):
    """With the global agy hooks file the hook runs outside the repository (LIVE): the
    workspace comes from workspacePaths[0]."""
    outside = tmp_path / "outside"
    outside.mkdir()
    proc = _cli(["pre-tool", "--host", "antigravity"], agy(ws, "run_command", {"CommandLine": "rm -rf ~"}), outside, home)
    assert (proc.returncode, proc.stdout) == (75, b"")
    assert proc.stderr.decode().startswith("aegis: blocked rm-recursive-dangerous")


@pytest.mark.parametrize("args", [["post-tool", "--host", "claude-code"], ["pre-tool"], [], ["pre-tool", "--host", "gemini-cli"]])
def test_the_cli_exits_0_silently_for_an_unknown_event_or_host(ws, home, args):
    proc = _cli(args, claude(ws, "Bash", {"command": "git push --force"}), ws, home)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


@pytest.fixture
def legacy_dir(tmp_path) -> Path:
    path = tmp_path / "legacy"
    (path / ".soma").mkdir(parents=True)
    return path


@pytest.mark.parametrize("where", ["home", "legacy", "plain"])
def test_the_cli_decides_from_the_payload_whatever_the_process_cwd(ws, home, legacy_dir, tmp_path, where):
    """User-scope hooks fire from any cwd: $HOME (the global agy hooks file runs outside
    every repository, LIVE), a directory with an unmigrated .soma/, or any plain one. The
    workspace comes from the payload; the CLI's own workspace attachment must not run."""
    cwd = {"home": home, "legacy": legacy_dir, "plain": tmp_path}[where]
    proc = _cli(["pre-tool", "--host", "antigravity"], agy(ws, "run_command", {"CommandLine": "rm -rf ~"}), cwd, home)
    assert (proc.returncode, proc.stdout) == (75, b"")
    assert proc.stderr.decode().startswith("aegis: blocked rm-recursive-dangerous")
    proc = _cli(["pre-tool", "--host", "claude-code"], claude(ws, "Bash", {"command": "git push --force"}), cwd, home)
    assert (proc.returncode, proc.stdout) == (2, b"")
    assert proc.stderr.decode().startswith("aegis: blocked git-push-force")


def test_the_cli_is_silent_from_the_home_directory(ws, home):
    proc = _cli(["pre-tool", "--host", "claude-code"], claude(ws, "Bash", {"command": "ls"}, cwd=home), home, home)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def test_an_aegis_workspace_pin_at_an_ungoverned_directory_is_a_silent_no_op(ws, home, tmp_path):
    """The pin takes part in the resolution as it does for aegis-mcp: an ungoverned pin
    governs nothing, so the hook allows silently instead of failing in the CLI."""
    plain = tmp_path / "plain"
    plain.mkdir()
    proc = _cli(["pre-tool", "--host", "claude-code"], claude(ws, "Bash", {"command": "git push --force"}), ws, home,
                {"AEGIS_WORKSPACE": str(plain)})
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


@pytest.mark.parametrize("args", [
    ["pre-tool", "--host"],
    ["pre-tool", "--host", "claude-code", "--bogus"],
    ["pre-tool", "extra", "--host", "claude-code"],
    ["pre-tool", "--host", "claude-code", "--host", "codex-cli"],
    ["pre-tool", "--host", "claude-code", "--json"],
    ["-x"],
])
def test_a_malformed_invocation_exits_0_silently(ws, home, args):
    """A usage error is exit 2 in argparse, which Claude Code and Codex read as a block."""
    proc = _cli(args, claude(ws, "Bash", {"command": "git push --force"}), ws, home)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, b"", b"")


def test_the_host_may_be_given_as_one_word(ws, home, tmp_path):
    proc = _cli(["--host=claude-code", "pre-tool"], claude(ws, "Bash", {"command": "git push --force"}), tmp_path, home)
    assert (proc.returncode, proc.stdout) == (2, b"")


def test_hook_run_help_is_still_the_cli_help(ws, home):
    proc = _cli(["--help"], b"", home, home)
    assert proc.returncode == 0 and b"--host" in proc.stdout and proc.stderr == b""


def test_a_global_option_before_the_command_takes_the_full_cli_path(ws, home):
    """`aegis --plain hook run ...` is not the registered form: the CLI parses it and
    attaches the cwd's workspace first, then runs the same handler."""
    env_cmd = [sys.executable, "-m", "aegis_cli", "--plain", "hook", "run", "pre-tool", "--host", "claude-code"]
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    for key in ("AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        env.pop(key, None)
    data = json.dumps(claude(ws, "Bash", {"command": "git push --force"})).encode("utf-8")
    proc = subprocess.run(env_cmd, input=data, cwd=str(ws), env=env, capture_output=True, timeout=60)
    assert (proc.returncode, proc.stdout) == (2, b"")
    assert proc.stderr.decode().startswith("aegis: blocked git-push-force")


def _busy_log(ws: Path, covering) -> None:
    """A large activity log, all of it inside the window: the scan row naming
    ``covering`` (when given) about 4 MiB from the end, then a busy hour of other scans."""
    path = scan_compliance.activity_path(ws)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc) - timedelta(seconds=1800)
    row = {"v": 1, "ts": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"), "event": "scan", "host": "claude-code",
           "session": "s-1", "files": [covering or "src/other.py"]}
    lines = [json.dumps(row, separators=(",", ":"))]
    for i in range(27000):
        other = dict(row, session=f"s-{i % 50}", files=[f"src/pkg{i % 97}/module_{i}.py", f"tests/test_{i}.py"])
        lines.append(json.dumps(other, separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def overhead(timings, baseline) -> float:
    """Median of ``timings`` minus median of ``baseline``: what Aegis adds to a Python start,
    so a uniformly slow runner does not fail and a real regression still does."""
    def median(values):
        ordered = sorted(values)
        return ordered[len(ordered) // 2]

    return median(timings) - median(baseline)


def paired_overhead(pairs) -> float:
    """Median of ``hook - python`` over (hook, python) pairs, each pair timed back to back.
    Load that comes and goes adds the same delay to both members of a pair and cancels, where
    ``overhead`` of two batches timed one after the other counts it as Aegis cost. A stall on one
    member of k < N/2 pairs moves the median at most k places among the other pairs' differences:
    hook stalls up to a neighbouring clean difference, Python stalls down to one, so Python
    stalls can understate the cost by up to the spread of the clean differences (the old
    median-of-batches method had the same weakness). A uniformly slow runner does not fail and a
    real regression still does. (A CPU slowdown that stretches all work by a factor stretches
    the difference too: that is real cost under load, not cancelled.)"""
    differences = sorted(hook - python for hook, python in pairs)
    return differences[len(differences) // 2]


_LOCK_BUSY = {errno.EACCES, errno.EAGAIN, getattr(errno, "EDEADLOCK", errno.EDEADLK)}


@contextlib.contextmanager
def hook_timing_lock(path, timeout=600.0):
    """Hold an exclusive lock on the file ``path`` against every other process (``flock`` on
    POSIX; one byte locked with ``msvcrt.locking`` on Windows), waiting at most ``timeout``
    seconds for it, and yield the seconds waited. No lock in time fails the test, never skips it."""
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        started = time.monotonic()
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                if error.errno not in _LOCK_BUSY:
                    raise
                if time.monotonic() - started > timeout:
                    pytest.fail(f"no exclusive lock on {path} within {timeout:.0f} s", pytrace=False)
                time.sleep(0.05)

        def unlock():
            if sys.platform == "win32":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)

        try:
            yield time.monotonic() - started
        except BaseException:
            with contextlib.suppress(OSError):  # report the failure inside the lock, not the unlock's
                unlock()
            raise
        unlock()  # after a clean body an unlock error is raised; closing the fd below still releases
    finally:
        os.close(fd)


def _timed_start_options(platform) -> dict:
    """Extra subprocess.run options for every timed start, the hook and the bare Python start
    alike. On Windows, HIGH_PRIORITY_CLASS (not REALTIME): both members of a pair are scheduled
    the same way, ahead of the other xdist workers' normal-priority processes, so CPU
    contention stretches them less; what is timed and the bound are unchanged. Windows does
    not pass a priority class on (a child gets NORMAL unless its parent is IDLE or
    BELOW_NORMAL), so the hook's own `git rev-parse` runs at normal priority; that is part of
    what the hook costs and is accepted. For the same reason, inside a Windows venv, where
    ``sys.executable`` is a launcher that starts the real interpreter, the interpreter of both
    members runs at normal priority: no boost, but no bias either (CI uses setup-python's
    interpreter, not a venv). On POSIX nothing: raising priority needs privileges, and other
    processes are never lowered."""
    if platform == "win32":
        return {"creationflags": getattr(subprocess, "HIGH_PRIORITY_CLASS", 0x00000080)}
    return {}


def _sample_pairs(hook_start, python_start, options, count):
    """Warm each start once (OS file cache, interpreter), then ``count`` (hook, python) pairs
    timed back to back, hook first on even i, Python first on odd i; every call gets ``options``."""
    hook_start(options)
    python_start(options)
    pairs = []
    for i in range(count):
        if i % 2 == 0:
            hook = hook_start(options)
            pairs.append((hook, python_start(options)))
        else:
            python = python_start(options)
            pairs.append((hook_start(options), python))
    return pairs


def _hook_start(data, cwd, home, expected):
    """A timed `aegis hook run pre-tool --host claude-code` start that must end with ``expected``
    (returncode, stdout, stderr)."""
    def start(options) -> float:
        started = time.perf_counter()
        proc = _cli(["pre-tool", "--host", "claude-code"], data, cwd, home, popen_options=options)
        elapsed = time.perf_counter() - started
        assert (proc.returncode, proc.stdout, proc.stderr.replace(b"\r\n", b"\n")) == expected  # Windows text stderr
        return elapsed
    return start


def _python_start(cwd):
    """A timed bare `python -c "import sys"` start."""
    def start(options) -> float:
        started = time.perf_counter()
        subprocess.run([sys.executable, "-c", "import sys"], cwd=str(cwd), capture_output=True, timeout=60,
                       check=True, **options)
        return time.perf_counter() - started
    return start


def _communicate_all(procs, timeout):
    """communicate() with each process, ``timeout`` seconds each; if any fails or times out,
    kill and reap them all before raising, so a stuck child never hangs the suite."""
    try:
        return [proc.communicate(timeout=timeout) for proc in procs]
    except BaseException:
        for proc in procs:
            proc.kill()
            proc.communicate()
        raise


def _shared_tmp(tmp_path_factory) -> Path:
    """The temp directory every xdist worker of this run shares: the run's base temp, of which
    xdist (3.6.1, workermanage.py) makes each local worker's ``popen-<id>``, with or without an
    explicit --basetemp (``<tmp>/pytest-of-<user>/pytest-<n>``, or the --basetemp itself).
    Otherwise (no xdist, a remote worker) this process's own base temp: never above it."""
    base = tmp_path_factory.getbasetemp()
    worker = os.environ.get("PYTEST_XDIST_WORKER")
    return base.parent if worker and base.name == f"popen-{worker}" else base


@pytest.mark.parametrize("baseline, ok", [([0.4] * 12, False), ([0.7] * 12, True)], ids=["regression", "slow-runner"])
def test_overhead_subtracts_the_interpreter_start(baseline, ok):
    assert (overhead([0.9] * 12, baseline) < 0.25) is ok


HOOK_PAIRS = 13  # (hook, Python start) pairs the timing test samples; odd, so the median is one pair
# A common load per pair, 0-1 s on most pairs: run 42491904451's Windows 3.12 hook samples
# (deep-scan-row, 221-1250 ms) less their 221 ms minimum, plus one quiet pair.
LOADS = [0.0, 0.0, 0.027, 0.037, 0.106, 0.176, 0.177, 0.191, 0.193, 0.207, 0.379, 0.97, 1.029]


# What Aegis adds in each pair when nothing stalls: spread out (median 0.18 s, all under 0.25 s),
# in an order where the unpaired medians of the same pairs come out different.
CLEAN = [0.21, 0.15, 0.14, 0.19, 0.16, 0.12, 0.2, 0.18, 0.1, 0.24, 0.22, 0.17, 0.23]
STALLED = [0, 4, 6, 7, 8, 10]  # (N-1)//2 pairs where one member stalls for 1 s (Defender, a page-in)


def _loaded_pairs(clean):
    """(hook, python) pairs whose members share pair i's load LOADS[i]."""
    return [(0.02 + load + extra, 0.02 + load) for load, extra in zip(LOADS, clean)]


def test_paired_overhead_ignores_load_that_hits_only_the_hook_phase():
    """Run 42491904451: the 12 hook starts ran under load, the 12 Python starts after it, quiet.
    The unpaired medians call that load Aegis cost; pairs taken back to back share it, and
    the paired result is exactly the median clean difference."""
    hooks = [0.02 + load + extra for load, extra in zip(LOADS, CLEAN)]
    assert overhead(hooks, [0.02] * len(LOADS)) >= 0.25
    assert paired_overhead(_loaded_pairs(CLEAN)) == pytest.approx(sorted(CLEAN)[HOOK_PAIRS // 2])


def test_paired_overhead_still_fails_a_real_regression_under_any_load():
    """Every clean difference over the bound, and the Python start stalled on a minority of
    pairs: the paired median drops to the lowest clean difference, still a failure, where the
    unpaired medians would hide the regression."""
    regressed = [extra + 0.15 for extra in CLEAN]  # 0.25-0.39 s, median 0.33 s
    assert min(regressed) >= 0.25
    pairs = [(hook, python + 1.0) if i in STALLED else (hook, python)
             for i, (hook, python) in enumerate(_loaded_pairs(regressed))]
    assert paired_overhead(pairs) >= 0.25


@pytest.mark.parametrize("member", ["hook", "python", "both"])
def test_paired_overhead_stays_among_the_clean_differences_with_stalls_on_a_minority_of_pairs(member):
    """A 1 s stall on one member of each of (N-1)//2 pairs moves the median by at most that many
    places among the unstalled pairs' clean differences: hook stalls up, Python stalls down,
    alternating ones not past the middle. The unpaired medians of the same pairs leave that range."""
    pairs, down = [], 0
    for i, (hook, python) in enumerate(_loaded_pairs(CLEAN)):
        if i in STALLED:
            on_hook = member == "hook" or (member == "both" and STALLED.index(i) % 2 == 0)
            hook, python = (hook + 1.0, python) if on_hook else (hook, python + 1.0)
            down += not on_hook
        pairs.append((hook, python))
    unstalled = sorted(extra for i, extra in enumerate(CLEAN) if i not in STALLED)
    result = paired_overhead(pairs)
    assert unstalled[0] - 1e-9 <= result <= unstalled[-1] + 1e-9
    assert result == pytest.approx(unstalled[HOOK_PAIRS // 2 - down])  # the neighbour it is pulled to


def test_paired_overhead_is_unchanged_on_a_uniformly_slow_runner():
    pairs = _loaded_pairs(CLEAN)
    assert paired_overhead([(h + 0.7, p + 0.7) for h, p in pairs]) == pytest.approx(paired_overhead(pairs))


_LOCK_PROBE = r"""
import importlib.util, json, os, sys, time
module_path, lock, flags, me, other = sys.argv[1:6]
spec = importlib.util.spec_from_file_location("hook_run_lock_probe", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def mark(name):
    open(os.path.join(flags, name), "w").close()


def marked(name):
    return os.path.exists(os.path.join(flags, name))


mark("asking-" + me)  # immediately before asking for the lock
with module.hook_timing_lock(lock):
    entered = time.time()
    overlap = marked("inside-" + other)
    mark("inside-" + me)
    deadline = time.monotonic() + 60
    while not marked("asking-" + other):  # hold the lock until the other asks: contention by construction
        if time.monotonic() > deadline:
            sys.exit("the other probe never asked for the lock within 60 s")
        time.sleep(0.005)
    time.sleep(0.2)
    overlap = overlap or marked("inside-" + other)
    os.remove(os.path.join(flags, "inside-" + me))
    left = time.time()
print(json.dumps([entered, left, overlap]))
"""


def test_the_hook_timing_lock_excludes_another_process(tmp_path):
    """Two processes take the real lock (imported from this file). Whoever gets it first holds
    it until the other has asked for it, so they always contend; the second enters only after
    the first has left, and neither ever sees the other inside."""
    lock, flags = tmp_path / "timing.lock", tmp_path / "flags"
    flags.mkdir()
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    procs = [subprocess.Popen([sys.executable, "-c", _LOCK_PROBE, __file__, str(lock), str(flags), me, other],
                              cwd=str(REPO), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for me, other in (("a", "b"), ("b", "a"))]
    outs = _communicate_all(procs, timeout=120)
    assert [proc.returncode for proc in procs] == [0, 0], outs
    # (entered, left, saw the other inside) per process, in the order they entered
    first, second = sorted((json.loads(out) for out, _ in outs), key=lambda probe: probe[0])
    assert not first[2] and not second[2], f"one saw the other inside the lock: {first} {second}"
    assert first[1] <= second[0], f"both held the lock at once: {first} {second}"


def _unlock_fails(monkeypatch):
    """Make this platform's unlock call raise; return the list of fds os.close is called with."""
    if sys.platform == "win32":
        import msvcrt

        real_locking = msvcrt.locking

        def locking(fd, mode, nbytes):
            if mode == msvcrt.LK_UNLCK:
                raise OSError(errno.EBADF, "unlock failed")
            return real_locking(fd, mode, nbytes)

        monkeypatch.setattr(msvcrt, "locking", locking)
    else:
        import fcntl

        real_flock = fcntl.flock

        def flock(fd, operation):
            if operation == fcntl.LOCK_UN:
                raise OSError(errno.EBADF, "unlock failed")
            return real_flock(fd, operation)

        monkeypatch.setattr(fcntl, "flock", flock)
    closed, real_close = [], os.close
    monkeypatch.setattr(os, "close", lambda fd: (closed.append(fd), real_close(fd))[1])
    return closed


def test_an_unlock_error_does_not_hide_the_failure_inside_the_lock(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        closed = _unlock_fails(patch)
        with pytest.raises(ValueError, match="the measurement failed"), hook_timing_lock(tmp_path / "timing.lock"):
            raise ValueError("the measurement failed")
        assert len(closed) == 1  # the lock's fd
    taken = False
    with hook_timing_lock(tmp_path / "timing.lock", timeout=10.0):  # closing the fd released it
        taken = True
    assert taken


def test_an_unlock_error_after_a_clean_body_is_raised_and_the_fd_closed(tmp_path, monkeypatch):
    with monkeypatch.context() as patch:
        closed = _unlock_fails(patch)
        with pytest.raises(OSError, match="unlock failed"), hook_timing_lock(tmp_path / "timing.lock"):
            pass
        assert len(closed) == 1


def test_a_child_that_outlives_the_timeout_is_killed_not_waited_for():
    """Two children that would sleep 60 s and exit 0: past the timeout both are killed and
    reaped (SIGKILL on POSIX, TerminateProcess's exit code 1 on Windows) before it raises."""
    procs = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) for _ in range(2)]
    with pytest.raises(subprocess.TimeoutExpired):
        _communicate_all(procs, timeout=0.5)
    killed = 1 if sys.platform == "win32" else -signal.SIGKILL
    assert [proc.returncode for proc in procs] == [killed, killed]


@pytest.mark.parametrize("platform, options", [("win32", {"creationflags": 0x00000080}), ("linux", {}),
                                               ("darwin", {})])
def test_timed_starts_are_raised_to_high_priority_on_windows_only(platform, options):
    assert _timed_start_options(platform) == options


def test_both_members_of_every_pair_and_both_warm_ups_get_the_same_start_options():
    calls, options = [], {"creationflags": 0x80}

    def start(name, value):
        def run(given):
            calls.append((name, given))
            return value
        return run

    pairs = _sample_pairs(start("hook", 0.3), start("python", 0.1), options, 4)
    assert [name for name, _ in calls] == ["hook", "python", "hook", "python", "python", "hook",
                                           "hook", "python", "python", "hook"]  # warm-ups, then alternating
    assert all(given is options for _, given in calls)
    assert pairs == [(0.3, 0.1)] * 4  # (hook, python) whichever ran first


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_the_timed_hook_and_python_starts_pass_the_options_to_the_process(ws, home, monkeypatch, platform):
    """Without Windows: the hook start (through _cli) and the bare Python start hand the same
    extra options to subprocess.run, and nothing extra when there are none."""
    seen = []

    def run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    options = _timed_start_options(platform)
    _sample_pairs(_hook_start(b"{}", ws, home, (0, b"", b"")), _python_start(ws), options, 2)
    assert len(seen) == 6
    assert ["aegis_cli" in argv for argv, _ in seen] == [True, False, True, False, False, True]
    for _, kwargs in seen:
        assert {key: kwargs[key] for key in kwargs if key == "creationflags"} == options


def test_the_cli_helper_passes_nothing_extra_by_default(ws, home, monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: seen.append(kwargs))
    _cli(["pre-tool", "--host", "claude-code"], b"{}", ws, home)
    _cli(["pre-tool", "--host", "claude-code"], b"{}", ws, home, popen_options={"creationflags": 0x80})
    assert sorted(seen[0]) == ["capture_output", "cwd", "env", "input", "timeout"]
    assert {key: value for key, value in seen[1].items() if key not in seen[0]} == {"creationflags": 0x80}


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_the_measurement_times_every_start_under_the_lock_with_the_same_options(ws, home, tmp_path, monkeypatch,
                                                                               platform):
    """What the timing test runs: the lock in the shared directory is held for every timed start
    (2 warm-ups + 2 per pair) and for the log line, and both members get this platform's options."""
    held, lock_log, starts = [False], [], []

    @contextlib.contextmanager
    def lock(path, timeout=600.0):
        lock_log.append(("enter", Path(path)))
        held[0] = True
        try:
            yield 0.0
        finally:
            log = tmp_path / "aegis-hook-timing.jsonl"
            lock_log.append(("exit", len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0))
            held[0] = False

    def run(argv, **kwargs):
        starts.append(("aegis_cli" in argv, held[0], kwargs.get("creationflags")))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setitem(_measure_hook_overhead.__globals__, "hook_timing_lock", lock)
    monkeypatch.setattr(subprocess, "run", run)
    pairs, waited, options = _measure_hook_overhead(ws, home, b"{}", (0, b"", b""), tmp_path, platform, "case")
    assert options == _timed_start_options(platform)
    assert lock_log == [("enter", tmp_path / "aegis-hook-timing.lock"), ("exit", 1)]  # log line written inside
    assert (len(starts), len(pairs), waited) == (2 + 2 * HOOK_PAIRS, HOOK_PAIRS, 0.0)
    assert [inside for _, inside, _ in starts] == [True] * len(starts)
    assert [flags for _, _, flags in starts] == [options.get("creationflags")] * len(starts)
    assert sum(hook for hook, _, _ in starts) == 1 + HOOK_PAIRS


def _measure_hook_overhead(ws, home, data, expected, shared, platform, label):
    """The timing test's measurement. Holding the lock in ``shared`` (the directory every xdist
    worker shares) for all of it: warm both starts, time HOOK_PAIRS back-to-back (hook, python)
    pairs with ``platform``'s start options for both members, and append the samples to
    ``shared``/aegis-hook-timing.jsonl. Returns (pairs, seconds waited for the lock, options)."""
    options = _timed_start_options(platform)
    with hook_timing_lock(Path(shared) / "aegis-hook-timing.lock") as waited:
        entered = time.time()
        pairs = _sample_pairs(_hook_start(data, ws, home, expected), _python_start(ws), options, HOOK_PAIRS)
        left = time.time()
        with open(Path(shared) / "aegis-hook-timing.jsonl", "a", encoding="utf-8") as log:  # diagnostics only
            log.write(json.dumps({"case": label, "worker": os.environ.get("PYTEST_XDIST_WORKER"), "waited": waited,
                                  "entered": entered, "left": left, "paired": paired_overhead(pairs),
                                  "unpaired": overhead([h for h, _ in pairs], [p for _, p in pairs]),
                                  "start_options": options, "pairs": pairs}) + "\n")
    return pairs, waited, options


@pytest.mark.timing
@pytest.mark.parametrize("covered", [True, False], ids=["deep-scan-row", "no-scan-row"])
def test_hook_run_overhead_is_under_250_ms(ws, home, covered, tmp_path_factory):
    """One Python start per matching tool call (v4.1 §2 Behaviour 3), timed as the hosts
    run it (`aegis hook run pre-tool --host claude-code`, payload on stdin) on the
    expensive path: an edit in a governed repository whose activity log is a full, busy
    tail (the covering scan row deep in it, or none), and an event to append. The only
    wall-clock assertion on this path; the spawn counters in test_scan_spawn_budget pin the
    regression class.

    Under `pytest -n auto` other workers load the machine while this runs, so each hook start
    is paired with a bare Python start taken right next to it (order alternating) and the
    median pair difference is what Aegis adds. On Windows both members of every pair start
    at high priority (``_timed_start_options``). The two cases take a lock in the temp
    directory all workers share, so they never time each other."""
    _busy_log(ws, "src/a.py" if covered else None)
    assert scan_compliance.activity_path(ws).stat().st_size > 3.5 * 1024 * 1024
    data = json.dumps(claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})).encode("utf-8")
    expected = (0, b"", b"") if covered else (2, b"", b"aegis: call aegis_scan with src/a.py before editing "
                                                      b"(or run: aegis scan src/a.py)\n")

    pairs, waited, options = _measure_hook_overhead(ws, home, data, expected, _shared_tmp(tmp_path_factory),
                                                    sys.platform, "deep-scan-row" if covered else "no-scan-row")
    extra = paired_overhead(pairs)
    hooks, pythons = [h for h, _ in pairs], [p for _, p in pairs]
    unpaired = overhead(hooks, pythons)

    def ms(values):
        return [round(v * 1000) for v in sorted(values)]

    assert extra < 0.25, (f"Aegis adds {extra * 1000:.0f} ms over a Python start (median of {HOOK_PAIRS} "
                          f"back-to-back pair differences {ms(h - p for h, p in pairs)}); hook {ms(hooks)} vs "
                          f"python {ms(pythons)}; unpaired medians {unpaired * 1000:.0f} ms; "
                          f"waited {waited:.1f} s for the timing lock; start options {options}")
    expected_rows = ["pass" if covered else "block"] * (1 + HOOK_PAIRS)  # the warm-up and every pair
    assert [r["result"] for r in events.read(ws, "scan_gate").rows] == expected_rows


# ── what the busy-log path costs, in counts (X-hook-windows-cost) ────────────
# Windows multiplies what the hook does besides deciding: every process it starts, file it
# opens and module it imports. These pin the counts; the test above stays the one clock.

def _counted(monkeypatch, fn):
    """Run ``fn``; return its result, the argv of every process started and every path
    opened (os.open and open), in order."""
    spawns, opens = [], []
    real_init, real_os_open, real_open = subprocess.Popen.__init__, os.open, open

    def init(self, args, *rest, **kwargs):
        spawns.append([os.fspath(a) for a in args] if isinstance(args, (list, tuple)) else [str(args)])
        return real_init(self, args, *rest, **kwargs)

    def os_opener(path, *rest, **kwargs):
        opens.append(os.fspath(path))
        return real_os_open(path, *rest, **kwargs)

    def opener(file, *rest, **kwargs):
        if not isinstance(file, int):
            opens.append(os.fspath(file))
        return real_open(file, *rest, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", init)
        patch.setattr(os, "open", os_opener)
        patch.setattr("builtins.open", opener)
        result = fn()
    return result, spawns, opens


def _busy_write(ws: Path, covered: bool) -> bytes:
    _busy_log(ws, "src/a.py" if covered else None)
    return json.dumps(claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})).encode("utf-8")


@pytest.mark.parametrize("covered", [True, False], ids=["deep-scan-row", "no-scan-row"])
def test_an_edit_on_a_busy_log_starts_one_git_and_reads_the_log_once(ws, capsys, monkeypatch, covered):
    """Given the busy log, when an edit is decided, then one process starts (git's layout
    question, asked once for the event row's worktree and shared state dir), the activity log
    is opened once, and the outcome is unchanged."""
    data = _busy_write(ws, covered)
    code, spawns, opens = _counted(monkeypatch, lambda: pretool.run_pre_tool("claude-code", data, {}))
    assert code == (0 if covered else 2)
    assert len(spawns) == 1 and "rev-parse" in spawns[0], spawns
    log = os.path.normcase(str(scan_compliance.activity_path(ws)))
    assert sum(1 for p in opens if os.path.normcase(p) == log) == 1, opens
    assert len(opens) <= 8, opens
    capsys.readouterr()
    assert [r["result"] for r in events.read(ws, "scan_gate").rows] == ["pass" if covered else "block"]


@pytest.mark.parametrize("stamp, counts", [
    ("2026-10-16T11:59:00Z", True),   # the writers' spelling
    ("2026-10-16T11:59:0Z", True),    # unpadded fields: strptime takes them, so the gate does
    ("2026-02-30T11:59:00Z", False),  # no such day
    ("2026-10-16T11:59:60Z", False),  # no leap second
    ("2026-10-16t11:59:00z", True),   # strptime matches literals ignoring case
    ("\u0662\u0660\u0662\u0666-10-16T11:59:00Z", True),  # and any Unicode decimal digit
    ("2026-10-16 11:59:00Z", False),
], ids=["canonical", "unpadded", "no-such-day", "second-60", "lower-case", "arabic-digits", "space"])
def test_a_scan_rows_time_is_read_as_strptime_reads_it(ws, capsys, stamp, counts):
    path = scan_compliance.activity_path(ws)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"v": 1, "ts": stamp, "event": "scan", "host": "claude-code", "session": "s-1", "files": ["src/a.py"]}
    path.write_bytes((json.dumps(row) + "\n").encode("utf-8"))
    assert scan_compliance.scan_covers(ws, ["src/a.py"], 3600, NOW) is counts
    code, _, _ = _run(capsys, "claude-code", claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")}))
    assert code == (0 if counts else 2)


# Measured on Linux, Python 3.12: 22 Aegis modules when this test was written, 28 after w14 split
# aegis_core.atomicio out of storage and aegis_cli.commands_table out of cli (moved code, not new
# code). The bounds leave room for another Python version and platform (Windows loads msvcrt,
# _winapi and nt-only modules), not for a new subsystem on the hook path.
_HOOK_MODULES_MAX, _HOOK_AEGIS_MODULES_MAX = 130, 28


@pytest.mark.parametrize("covered", [True, False], ids=["deep-scan-row", "no-scan-row"])
def test_the_hook_imports_only_what_the_busy_log_path_needs(ws, home, covered):
    """Given the busy log, when the hook runs as the hosts run it, then it imports no time
    parser (strptime's first call imports _strptime and builds locale tables) and no more
    modules than measured, within a wide margin."""
    data = _busy_write(ws, covered)
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), GIT_CONFIG_NOSYSTEM="1")
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    for key in ("AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        env.pop(key, None)
    report = "import json, sys; sys.stdout.write(json.dumps(sorted(sys.modules)))"
    hook = ("from aegis_cli.cli import main; rc = main(['hook', 'run', 'pre-tool', '--host', 'claude-code']); "
            "import sys; sys.stderr.write('rc=%d\\n' % rc); " + report)

    def modules(code: str, stdin: bytes):
        proc = subprocess.run([sys.executable, "-c", code], input=stdin, cwd=str(ws), env=env,
                              capture_output=True, timeout=600, check=False)
        assert proc.returncode == 0, proc.stderr
        return set(json.loads(proc.stdout.decode("utf-8"))), proc.stderr

    bare, _ = modules(report, b"")
    loaded, err = modules(hook, data)
    assert err.replace(b"\r\n", b"\n").endswith(b"rc=%d\n" % (0 if covered else 2)), err
    extra = loaded - bare
    assert "_strptime" not in loaded
    assert len(extra) <= _HOOK_MODULES_MAX, sorted(extra)
    assert len([m for m in extra if m.split(".")[0] in ("aegis_cli", "aegis_core")]) <= _HOOK_AEGIS_MODULES_MAX, \
        sorted(extra)
    assert not {"aegis_core.rules", "aegis_core.scan", "aegis_core.credit", "aegis_core.fitness"} & loaded


@pytest.mark.timing
def test_the_hooks_cost_does_not_grow_with_the_log(ws, capsys):
    """Given the busy log, then a log eight times its size (past the tail the gate reads),
    when the same unscanned edit is decided in-process, the cost grows by far less than 24x
    (t(8N)/t(N), each the best of 3 with the collector off: about 1 for a bounded read, about
    8 for a whole-log read, about 64 for a quadratic one)."""
    data = _busy_write(ws, covered=False)
    path = scan_compliance.activity_path(ws)
    small = path.read_bytes()
    pretool.run_pre_tool("claude-code", data, {})  # imports and the OS file cache

    def best_of_3() -> float:
        best = float("inf")
        for _ in range(3):
            enabled = gc.isenabled()
            gc.disable()
            try:
                started = time.perf_counter()
                code = pretool.run_pre_tool("claude-code", data, {})
                took = time.perf_counter() - started
            finally:
                if enabled:
                    gc.enable()
            assert code == 2 and took < 600
            best = min(best, took)
        return best

    one = best_of_3()
    path.write_bytes(small * 8)
    eight = best_of_3()
    capsys.readouterr()
    assert eight / max(one, 1e-9) < 24, f"eight times the log multiplied the cost by {eight / max(one, 1e-9):.1f}"
