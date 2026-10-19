"""Scan and hook budgets on platform-independent counters, never on wall-clock time (R-structure-6).

Spawns are counted at ``subprocess.Popen.__init__`` and ledger opens at ``os.open`` (both
patched reversibly; an audit hook cannot be removed). The fixture's 100 rules must load:
a rule file that does not load makes the scan return early with fewer spawns (trap F2).
Counters that today's code misses are ``xfail(strict=True)`` at the observed value, and
the item that fixes each removes its marker. The only time limit here is a hang ceiling.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Callable, Dict, List

import pytest

from aegis_cli.hooks import pretool
from aegis_core.scan import scan
from aegis_core.telemetry_engine import ledger
from aegis_core.yaml_engine.serializer import dump_frontmatter

HANG_CEILING_S = 10.0
REPO = Path(__file__).resolve().parents[3]


def _write_rules(root: Path, count: int = 100) -> None:
    folder = root / ".aegis" / "rules" / "traps"
    folder.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        fm = {"id": f"perf-rule-{i}", "type": "trap", "enforcement": "advisory", "target_paths": ["src/*.py"],
              "hypothesis": f"Hypothesis {i}", "prediction": f"Prediction {i}"}
        (folder / f"perf-rule-{i}.md").write_text(dump_frontmatter(fm, body="Guidance\n"), encoding="utf-8")
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "foo.py").write_text("x = 1\n", encoding="utf-8")


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


@pytest.fixture
def plain_ws(isolated) -> Path:
    root = (isolated / "plain").resolve()
    _write_rules(root)
    return root


@pytest.fixture
def git_ws(isolated) -> Path:
    root = (isolated / "repo").resolve()
    _write_rules(root)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    # An origin BASE without a network remote: the scan resolves origin/HEAD first.
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return root


class _Counters:
    def __init__(self) -> None:
        self.spawns: List[List[str]] = []
        self.opens: List[str] = []

    def git(self) -> List[List[str]]:
        return [argv for argv in self.spawns if argv and Path(argv[0]).name.lower() in ("git", "git.exe")]


def _count(monkeypatch, fn: Callable[[], object], delay: float = 0.0) -> _Counters:
    """Run ``fn`` with spawns and os.open calls recorded (each spawn slowed by ``delay``)."""
    seen = _Counters()
    real_init, real_open = subprocess.Popen.__init__, os.open

    def init(self, args, *rest, **kwargs):
        seen.spawns.append([os.fspath(a) for a in args] if isinstance(args, (list, tuple)) else [str(args)])
        if delay:
            time.sleep(delay)
        return real_init(self, args, *rest, **kwargs)

    def opener(path, *rest, **kwargs):
        seen.opens.append(os.fspath(path))
        return real_open(path, *rest, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(subprocess.Popen, "__init__", init)
        patch.setattr(os, "open", opener)
        started = time.perf_counter()
        fn()
        assert time.perf_counter() - started < HANG_CEILING_S
    return seen


def _ledger_opens(ws: Path, seen: _Counters) -> int:
    name = ledger.ledger_path(ws).name
    return sum(1 for p in seen.opens if Path(p).name == name)


def _scan(ws: Path) -> Dict:
    result = scan(ws, ["src/foo.py"])
    assert result["rules_staged"] > 0  # the rules loaded (trap F2)
    return result


# ── (a) and (b): git spawns per scan ────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="7 git spawns outside git today; R-structure-4 brings it to 1")
def test_a_scan_outside_git_starts_one_git_process(plain_ws, monkeypatch):
    _scan(plain_ws)
    assert len(_count(monkeypatch, lambda: _scan(plain_ws)).git()) == 1


@pytest.mark.xfail(strict=True, reason="15 git spawns (one ls-tree) on a warm scan in git with an origin today (19 without; "
                   "M4 measured 17 on its fixture); R-structure-4/8")
def test_a_warm_scan_in_git_starts_at_most_four_and_no_tree_reads(git_ws, monkeypatch):
    _scan(git_ws)
    spawned = _count(monkeypatch, lambda: _scan(git_ws)).git()
    assert len(spawned) <= 4
    assert not [argv for argv in spawned if {"ls-tree", "cat-file", "rev-list"} & set(argv)]


# ── (c): ledger opens per scan ──────────────────────────────────────────────

def _seed_ledger(ws: Path) -> None:
    ledger.append(ws, [{"rule": "perf-rule-0", "outcome": "tp", "source": "ci", "key": f"k{i}"} for i in range(3)])


@pytest.mark.xfail(strict=True, reason="3 ledger opens per core scan today; R-structure-5 brings it to 1")
def test_a_core_scan_opens_the_ledger_once(git_ws, monkeypatch):
    _seed_ledger(git_ws)
    _scan(git_ws)
    assert _ledger_opens(git_ws, _count(monkeypatch, lambda: _scan(git_ws))) == 1


@pytest.mark.xfail(strict=True, reason="5 then 4 ledger opens per MCP scan in this fixture today (M5: 6 then 4); "
                   "R-structure-5 brings it to 2")
def test_an_mcp_scan_opens_the_ledger_at_most_twice(git_ws, monkeypatch):
    import aegis_mcp.server as server

    _seed_ledger(git_ws)
    monkeypatch.setattr(server, "_canonical_workspace", str(git_ws))
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                           "params": {"clientInfo": {"name": "claude-code", "version": "1"}}})

    def call(req_id: int) -> None:
        response = server.handle_request({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                                          "params": {"name": "aegis_scan", "arguments": {"files": ["src/foo.py"]}}})
        assert response["result"]["isError"] is False
        assert json.loads(response["result"]["content"][0]["text"])["rules_staged"] > 0

    counts = [_ledger_opens(git_ws, _count(monkeypatch, lambda i=i: call(i))) for i in (1, 2)]
    assert max(counts) <= 2, counts


# ── (e): the pre-tool hook ──────────────────────────────────────────────────

def _hook(ws: Path, tool: str, tool_input: Dict) -> Callable[[], None]:
    payload = {"session_id": "s", "transcript_path": "t", "cwd": str(ws), "permission_mode": "default",
               "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "tool_use_id": "t1"}
    return lambda: pretool.run_pre_tool("claude-code", json.dumps(payload).encode("utf-8"), {})


def _hook_spawns(ws: Path, monkeypatch, delay: float = 0.0) -> Dict[str, int]:
    edit = _hook(ws, "Write", {"file_path": str(ws / "src" / "foo.py")})
    bash = _hook(ws, "Bash", {"command": "ls -la"})
    return {"edit": len(_count(monkeypatch, edit, delay).git()), "bash": len(_count(monkeypatch, bash, delay).git())}


def test_the_pre_tool_hook_spawns_at_most_two_gits_on_edit_and_none_on_bash(git_ws, monkeypatch, capsys):
    counts = _hook_spawns(git_ws, monkeypatch)
    assert counts["edit"] <= 2 and counts["bash"] == 0, counts


# ── (f): the insight hook's imports ─────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="a no-cue prompt imports aegis_core.credit today; R-structure-11")
def test_a_no_cue_insight_prompt_does_not_import_credit(git_ws, isolated):
    payload = json.dumps({"prompt": "Please run the unit tests.", "session_id": "s-imports", "cwd": str(git_ws)})
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from aegis_cli.hooks.insights import run_insight_hook; "
            "run_insight_hook(['--host', 'claude-code', '--no-excerpts'], stdin=sys.argv[2]); "
            "print('aegis_core.credit' in sys.modules)")
    env = {"HOME": str(isolated / "home"), "USERPROFILE": str(isolated / "home"), "PATH": os.environ.get("PATH", ""),
           "GIT_CONFIG_NOSYSTEM": "1", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(REPO), payload], cwd=str(git_ws), env=env,
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "False"


# ── (g): a slow machine changes no verdict ──────────────────────────────────

def test_slowed_spawns_change_no_count(plain_ws, git_ws, monkeypatch, capsys):
    _scan(plain_ws)
    plain = len(_count(monkeypatch, lambda: _scan(plain_ws)).git())
    slowed = len(_count(monkeypatch, lambda: _scan(plain_ws), delay=0.05).git())
    assert slowed == plain
    assert _hook_spawns(git_ws, monkeypatch, delay=0.05) == _hook_spawns(git_ws, monkeypatch)
