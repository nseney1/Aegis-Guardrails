"""Unit tests for `aegis rule insight`, `aegis_cli.hooks.insights`, `aegis init` link.key, and `aegis doctor` insight_capture."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest

from aegis_cli import doctor
from aegis_cli.doctor import run_doctor
from aegis_cli.hooks.insights import run_insight_hook
from aegis_cli.init import _link_key_step
from aegis_cli.rule import RuleCommand, run_rule
from aegis_core.insights import insights_path, read_insight_rows, read_link_key


def _make_workspace(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "cli@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "CLI Test"], check=True)
    (path / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    (path / ".aegis" / "config.json").write_text('{"v": 1}\n', encoding="utf-8")
    (path / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (path / "src").mkdir(exist_ok=True)
    (path / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "init"], check=True)
    return path


def _invoke_rule(ws: Path, *argv: str) -> tuple[int, str, str]:
    parser = argparse.ArgumentParser(prog="aegis rule")
    cmd = RuleCommand()
    cmd.configure_parser(parser)
    args = parser.parse_args(list(argv))
    args.workspace = str(ws)
    args._rule_workspace_arg = str(ws)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_rule(args)
    return rc, out.getvalue(), err.getvalue()


def test_init_link_key_step_creates_0600_key_idempotently(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()

    dry = _link_key_step(home, dry_run=True)
    assert dry.result == "created"
    assert not (home / ".aegis" / "link.key").exists()

    step1 = _link_key_step(home, dry_run=False)
    assert step1.result == "created"
    key_file = home / ".aegis" / "link.key"
    assert key_file.exists()
    if __import__("os").name == "posix":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    raw = read_link_key(home)
    assert raw is not None and len(raw) == 32

    step2 = _link_key_step(home, dry_run=False)
    assert step2.result == "present"
    assert read_link_key(home) == raw


def test_rule_insight_add_review_and_propose_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")

    rc, out, err = _invoke_rule(
        ws,
        "insight",
        "add",
        "Never use bare subprocess.Popen without timeout in src/main.py",
        "--paths",
        "src/main.py",
        "--kind",
        "reliability",
        "--session",
        "cli-sess-1",
        "--json",
    )
    assert rc == 0, err
    added = json.loads(out)
    assert added["level"] == "cli"
    assert added["psrc"] == "explicit"
    assert added["paths"] == ["src/main.py"]
    assert "hs" in added

    rc, out, err = _invoke_rule(ws, "insight", "review", "--json")
    assert rc == 0, err
    rev = json.loads(out)
    assert len(rev["clusters"]) == 1
    cid = rev["clusters"][0]["cluster_id"]

    rc, out, err = _invoke_rule(
        ws,
        "insight",
        "review",
        "--decision",
        "propose",
        "--cluster",
        cid,
        "--proposal-id",
        "trap-subprocess-timeout",
        "--category",
        "reliability",
        "--summary",
        "Require an explicit timeout on subprocess invocations.",
        "--json",
    )
    assert rc == 0, err
    dec = json.loads(out)
    assert dec["decision"] == "propose"
    assert (ws / ".aegis" / "proposals" / "trap-subprocess-timeout.md").is_file()


def test_rule_insight_enable_and_doctor_host_reporting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for k in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(k, raising=False)
    ws = _make_workspace(tmp_path / "ws")

    # Enable claude-code with excerpts and codex-cli counters-only
    rc1, out1, err1 = _invoke_rule(ws, "insight", "enable", "--host", "claude-code", "--excerpts", "--json")
    assert rc1 == 0, err1
    assert json.loads(out1)["status"] == "enabled_excerpts"

    claude = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
    (handler,) = claude["hooks"]["UserPromptSubmit"][-1]["hooks"]
    assert handler["command"] == sys.executable and handler["args"][:2] == ["-I", "-c"]
    assert handler["args"][-2:] == ["claude-code", "--excerpts"]

    rc2, out2, err2 = _invoke_rule(ws, "insight", "enable", "--host", "codex-cli", "--json")
    if os.name == "nt":
        # Codex runs hooks through %COMSPEC% /C, which cannot take the pinned -c program.
        assert rc2 == 1 and "%COMSPEC%" in json.loads(out2)["error"]
        assert not (home / ".codex").exists()
    else:
        assert rc2 == 0, err2
        assert json.loads(out2)["status"] == "enabled_counters_only"

    # Run doctor --json and verify per-host insight_capture state
    monkeypatch.setattr(
        doctor,
        "_run_host_cli",
        lambda argv, cwd, timeout: subprocess.CompletedProcess(argv, 1, "", "not found"),
    )
    doc_args = argparse.Namespace(workspace=str(ws), fix=False, yes=False, drivers=False, json=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_doctor(doc_args)
    payload = json.loads(buf.getvalue())
    hosts_by_id = {h["id"]: h["insight_capture"] for h in payload["hosts"]}
    assert hosts_by_id["claude-code"]["status"] == "enabled_excerpts"
    assert hosts_by_id["claude-code"]["excerpts"] is True
    assert hosts_by_id["codex-cli"]["status"] == ("disabled" if os.name == "nt" else "enabled_counters_only")
    assert hosts_by_id["codex-cli"]["excerpts"] is False
    assert hosts_by_id["antigravity"]["status"] == "explicit_only"


def test_hook_entrypoint_exits_zero_empty_stdout_and_under_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")

    payload = json.dumps({
        "prompt": "Please run the unit tests.",
        "session_id": "fast-hook-sess-1",
        "cwd": str(ws),
    })
    # Warm up link.key creation first, then time routine prompt hook execution
    run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=payload, home=home)

    out, err = io.StringIO(), io.StringIO()
    t0 = time.perf_counter()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=payload, home=home)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert rc == 0
    assert out.getvalue() == ""
    assert err.getvalue() == ""
    assert elapsed_ms < 40.0, f"hook took {elapsed_ms:.2f}ms (> 40ms budget)"
    rows = read_insight_rows(ws, home=home)
    assert len(rows) == 1
    assert rows[0]["event"] == "heartbeat"


def test_rule_insight_add_with_signed_commit_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_core import human_gate
    from tests import helpers_humangate as hg

    if not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    human_key, human_pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, human_pub)
    text_a = "Always pass explicit timeout to subprocess calls in cli"
    sha = repo.commit(
        f"chore: approve insight\n\n{human_gate.INSIGHT_APPROVE_TRAILER}: {human_gate.insight_text_hash(text_a)}\n",
        sign_key=human_key,
        allow_empty=True,
    )

    rc, out, err = _invoke_rule(
        repo.root,
        "insight",
        "add",
        text_a,
        "--paths",
        "src/app.py",
        "--commit",
        sha,
        "--base-ref",
        "main",
        "--json",
    )
    assert rc == 0, err
    assert json.loads(out)["level"] == "H"
