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

from datetime import datetime, timedelta, timezone
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


@pytest.mark.parametrize("host,payload_of", [
    ("claude-code", lambda ws, c: claude(ws, "Bash", {"command": c})),
    ("codex-cli", lambda ws, c: codex(ws, "Bash", c)),
    ("antigravity", lambda ws, c: agy(ws, "run_command", {"CommandLine": c})),
])
def test_a_record_set_command_runs_and_is_recorded(ws, capsys, host, payload_of):
    assert _run(capsys, host, payload_of(ws, "git merge lane/x")) == (0, "", "")
    assert _events(ws) == [("guard_match", host, "record", {"tier": "record", "action": "record", "rule": "git-merge"})]


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

def _cli(args, payload, cwd, home, extra_env=None, timeout=60):
    env = dict(os.environ)
    env.update({"HOME": str(home), "USERPROFILE": str(home)})
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO), env.get("PYTHONPATH", "")) if p)
    for key in ("AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        env.pop(key, None)
    env.update(extra_env or {})
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
    return subprocess.run([sys.executable, "-m", "aegis_cli", "hook", "run", *args], input=data, cwd=str(cwd),
                          env=env, capture_output=True, timeout=timeout)


@pytest.fixture
def home(tmp_path) -> Path:
    path = tmp_path / "home"
    path.mkdir(exist_ok=True)
    return path


def test_the_cli_blocks_with_exit_2_and_nothing_on_stdout(ws, home):
    proc = _cli(["pre-tool", "--host", "claude-code"], claude(ws, "Bash", {"command": "git clean -fdx"}), ws, home)
    assert (proc.returncode, proc.stdout) == (2, b"")
    assert proc.stderr.decode().startswith("aegis: blocked git-clean-force")


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


@pytest.mark.parametrize("baseline, ok", [([0.4] * 12, False), ([0.7] * 12, True)], ids=["regression", "slow-runner"])
def test_overhead_subtracts_the_interpreter_start(baseline, ok):
    assert (overhead([0.9] * 12, baseline) < 0.25) is ok


@pytest.mark.timing
@pytest.mark.parametrize("covered", [True, False], ids=["deep-scan-row", "no-scan-row"])
def test_hook_run_overhead_is_under_250_ms(ws, home, covered):
    """One Python start per matching tool call (v4.1 §2 Behaviour 3), timed as the hosts
    run it (`aegis hook run pre-tool --host claude-code`, payload on stdin) on the
    expensive path: an edit in a governed repository whose activity log is a full, busy
    tail (the covering scan row deep in it, or none), and an event to append. The only
    wall-clock assertion on this path; the spawn counters in test_scan_spawn_budget pin the
    regression class."""
    _busy_log(ws, "src/a.py" if covered else None)
    assert scan_compliance.activity_path(ws).stat().st_size > 3.5 * 1024 * 1024
    data = json.dumps(claude(ws, "Write", {"file_path": str(ws / "src" / "a.py")})).encode("utf-8")
    expected = (0, b"", b"") if covered else (2, b"", b"aegis: call aegis_scan with src/a.py before editing "
                                                      b"(or run: aegis scan src/a.py)\n")

    def once() -> float:
        started = time.perf_counter()
        proc = _cli(["pre-tool", "--host", "claude-code"], data, ws, home)
        elapsed = time.perf_counter() - started
        assert (proc.returncode, proc.stdout, proc.stderr.replace(b"\r\n", b"\n")) == expected  # Windows text stderr
        return elapsed

    def noop() -> float:
        started = time.perf_counter()
        subprocess.run([sys.executable, "-c", "import sys"], cwd=str(ws), capture_output=True, timeout=60, check=True)
        return time.perf_counter() - started

    once()  # warm the OS file cache
    timings = [once() for _ in range(12)]
    baseline = [noop() for _ in range(12)]
    extra = overhead(timings, baseline)
    assert extra < 0.25, (f"Aegis adds {extra * 1000:.0f} ms over a Python start: "
                          f"{[round(t * 1000) for t in sorted(timings)]} vs {[round(t * 1000) for t in sorted(baseline)]}")
    assert [r["result"] for r in events.read(ws, "scan_gate").rows] == ["pass" if covered else "block"] * 13
