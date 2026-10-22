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
        "--json",
    )
    assert rc == 0, err
    added = json.loads(out)
    assert added["level"] == "cli"
    assert added["psrc"] == "explicit"
    assert added["paths"] == ["src/main.py"]
    assert "hs" not in added  # session identity comes from the host, never a CLI argument

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

    # The decision takes effect: the proposed cluster leaves the review list (its id now names
    # the proposal it matches; the decision finds it by its members).
    rc, out, err = _invoke_rule(ws, "insight", "review", "--json")
    assert rc == 0, err
    after = json.loads(out)
    assert after["clusters"] == []
    assert [c["insight_ids"] for c in after["suppressed_clusters"]] == [[added["id"]]]


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


def test_hook_entrypoint_exits_zero_with_empty_output_and_a_heartbeat_per_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
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
    run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=payload, home=home)

    from aegis_core import rules as core_rules

    parses: list = []
    real = core_rules.load_rules
    monkeypatch.setattr(core_rules, "load_rules", lambda *a, **k: parses.append(a) or real(*a, **k))
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=payload, home=home)

    assert rc == 0
    assert out.getvalue() == ""
    assert err.getvalue() == ""
    assert parses == []  # no rule files: nothing to fingerprint or parse
    rows = read_insight_rows(ws, home=home)
    assert [r["event"] for r in rows] == ["heartbeat", "heartbeat"]


def test_a_corrupt_insights_log_still_exits_zero_silently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")
    (ws / ".aegis" / "rules" / "traps" / "trap-x.md").write_text(
        "---\nid: trap-x\ntype: trap\nenforcement: advisory\n---\n# trap-x\n\nBody.\n", encoding="utf-8")
    store = insights_path(ws, home=home)
    store.parent.mkdir(parents=True)
    store.write_bytes(b'\xff\xfe{not json\n{"event": "inventory", "inv": 7\n')
    payload = json.dumps({"prompt": "Please run the unit tests.", "session_id": "corrupt-1", "cwd": str(ws)})
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=payload, home=home)
    assert (rc, out.getvalue(), err.getvalue()) == (0, "", "")
    assert [r["event"] for r in read_insight_rows(ws, home=home)] == ["inventory", "heartbeat"]


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


# ── `insight add` takes no session identity (R-evidence-42) ─────────────────

@pytest.mark.parametrize("flag", ["--session", "--host"])
def test_insight_add_refuses_a_typed_session_or_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, flag):
    from aegis_cli.cli import main

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    ws = _make_workspace(tmp_path / "ws")
    with pytest.raises(SystemExit) as exc:
        main(["rule", "insight", "add", "No, stop that", flag, "x", "--workspace", str(ws)])
    assert exc.value.code == 2
    assert flag in capsys.readouterr().err
    assert read_insight_rows(ws, home=tmp_path / "home") == []


def test_three_cli_adds_carry_no_session_and_count_as_one_episode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_core.insights import measure_recurrence

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")
    (ws / ".aegis" / "rules" / "traps" / "trap-popen-timeout.md").write_text(
        "---\nid: trap-popen-timeout\ntype: trap\nenforcement: advisory\n"
        "hypothesis: Popen without a timeout hangs.\ntarget_paths:\n  - src/*.py\n---\n"
        "# trap-popen-timeout\n\nNever call subprocess.Popen without a timeout in src modules.\n",
        encoding="utf-8",
    )
    for _ in range(3):
        rc, _out, err = _invoke_rule(
            ws, "insight", "add", "Never call subprocess.Popen without a timeout in src/main.py",
            "--paths", "src/main.py", "--json",
        )
        assert rc == 0, err
    rows = [r for r in read_insight_rows(ws, home=home) if r.get("event") == "insight"]
    assert len(rows) == 3
    assert all("hs" not in r and r["host"] == "cli" for r in rows)
    assert measure_recurrence(ws, "trap-popen-timeout", home=home)["recurrences"] == 1


# ── one confinement rule on every channel (R-evidence-43) ─────────────────────

def test_insight_add_refuses_a_path_outside_the_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")
    rc, _out, _err = _invoke_rule(ws, "insight", "add", "Never read passwd", "--paths", "../../etc/passwd", "--json")
    assert rc != 0
    assert read_insight_rows(ws, home=home) == []


def test_insight_add_keeps_a_comma_path_whole_and_stores_absolute_paths_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")
    rc, out, err = _invoke_rule(ws, "insight", "add", "Keep commas", "--paths", "src/a,b.py", "--json")
    assert rc == 0, err
    assert json.loads(out)["paths"] == ["src/a,b.py"]
    rc, out, err = _invoke_rule(ws, "insight", "add", "Absolute", "--paths", str(ws / "src" / "main.py"), "--json")
    assert rc == 0, err
    assert json.loads(out)["paths"] == ["src/main.py"]


def test_mcp_capture_insight_confines_like_the_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_mcp.tools import execute_tool

    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    ws = _make_workspace(tmp_path / "ws")
    bad = execute_tool("aegis_capture_insight", {"workspace": str(ws), "quote": "Stay inside", "paths": ["../outside.py"]})
    assert bad["status"] == "FAIL"
    assert read_insight_rows(ws, home=home) == []
    ok = execute_tool("aegis_capture_insight",
                      {"workspace": str(ws), "quote": "Stay inside", "paths": [str(ws / "src" / "main.py"), "src/a,b.py"]})
    assert ok["status"] == "OK", ok
    assert ok["paths"] == ["src/a,b.py", "src/main.py"]


# ── R-evidence-38: decisions need their target, and take effect ─────────────────

@pytest.fixture
def review_ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    ws = _make_workspace(tmp_path / "ws")
    for text in ("Never call subprocess.Popen without a timeout in src/main.py",
                 "Always pass a timeout to subprocess.Popen calls in src/main.py"):
        rc, _out, err = _invoke_rule(ws, "insight", "add", text, "--paths", "src/main.py", "--kind", "reliability")
        assert rc == 0, err
    rc, out, err = _invoke_rule(ws, "insight", "review", "--json")
    assert rc == 0, err
    cluster, = json.loads(out)["clusters"]
    return ws, home, cluster


def _decision_rows(ws: Path, home: Path) -> list:
    return [r for r in read_insight_rows(ws, home=home) if r.get("event") == "decision"]


@pytest.mark.parametrize("argv", [
    ["--decision", "snooze"],
    ["--decision", "reject", "--reason", "later"],
    ["--decision", "reject", "--cluster", "CID"],
    ["--decision", "confirm"],
], ids=["no-cluster", "reject-no-cluster", "reject-no-reason", "confirm-no-insight"])
def test_a_decision_without_its_target_or_reason_is_a_usage_error(review_ws, argv):
    ws, home, cluster = review_ws
    rc, _out, err = _invoke_rule(ws, "insight", "review", *[cluster["cluster_id"] if a == "CID" else a for a in argv])
    assert rc == 2
    assert "--cluster" in err or "--reason" in err or "--insight" in err
    assert _decision_rows(ws, home) == []


def test_an_unknown_cluster_writes_nothing_and_lists_the_valid_ids(review_ws):
    ws, home, cluster = review_ws
    rc, out, _err = _invoke_rule(ws, "insight", "review", "--decision", "propose", "--cluster", "cluster-typo", "--json")
    assert rc == 1
    assert cluster["cluster_id"] in json.loads(out)["error"]
    assert _decision_rows(ws, home) == []
    assert not (ws / ".aegis" / "proposals").exists()


def test_an_unknown_insight_to_confirm_writes_nothing_and_lists_the_valid_ids(review_ws):
    from aegis_core.insights import capture_suggestion

    ws, home, _cluster = review_ws
    cap = capture_suggestion(ws, "Prefer pathlib joins over string concatenation", paths=["src/main.py"],
                             host="claude-code", session="agent", home=home)
    rc, out, _err = _invoke_rule(ws, "insight", "review", "--decision", "confirm", "--insight", "ins-nope", "--json")
    assert rc == 1
    assert cap["id"] in json.loads(out)["error"]
    assert _decision_rows(ws, home) == []
    rc, out, err = _invoke_rule(ws, "insight", "review", "--decision", "confirm", "--insight", cap["id"],
                                "--kind", "style", "--json")
    assert rc == 0, err
    assert (json.loads(out)["insight_ids"], json.loads(out)["kind"]) == ([cap["id"]], "style")
    rc, out, err = _invoke_rule(ws, "insight", "review", "--json")
    assert [cap["id"]] in [c["insight_ids"] for c in json.loads(out)["clusters"]]


def test_a_reject_stores_its_reason_and_the_proposal_category_defaults_to_the_shared_kind(review_ws):
    ws, home, cluster = review_ws
    rc, _out, err = _invoke_rule(ws, "insight", "review", "--decision", "propose", "--cluster", cluster["cluster_id"],
                                 "--proposal-id", "trap-popen", "--summary", "Require timeouts on child processes.")
    assert rc == 0, err
    assert 'category: "reliability"' in (ws / ".aegis" / "proposals" / "trap-popen.md").read_text(encoding="utf-8")
    rc, out, err = _invoke_rule(ws, "insight", "review", "--json")
    hidden, = json.loads(out)["suppressed_clusters"]
    rc, _out, err = _invoke_rule(ws, "insight", "review", "--decision", "reject", "--cluster", hidden["cluster_id"],
                                 "--reason", "covered by trap-popen")
    assert rc == 0, err
    assert [r.get("reason") for r in _decision_rows(ws, home)] == [None, "covered by trap-popen"]


def test_text_review_lists_each_insight_once_with_its_neighbours(review_ws):
    ws, home, cluster = review_ws
    rc, out, err = _invoke_rule(ws, "insight", "review")
    assert rc == 0, err
    for ins_id in cluster["insight_ids"]:
        member_lines = [line for line in out.splitlines() if line.strip().startswith(f"{ins_id}:")]
        assert len(member_lines) == 1
        other, = [i for i in cluster["insight_ids"] if i != ins_id]
        assert f"neighbours: {other}" in member_lines[0]
