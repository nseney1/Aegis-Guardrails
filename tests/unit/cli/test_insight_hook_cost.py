"""What the per-prompt insight hook costs, in counters (R-structure-11).

No wall clock: the hook runs in a fresh interpreter and the test reads which modules it
loaded and how often it parsed the rules.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_core import insights as core_insights, rules as core_rules
from aegis_core.insights import read_insight_rows, record_hook_prompt

REPO = Path(__file__).resolve().parents[3]
REVIEW_ONLY = (
    "aegis_core.credit",
    "aegis_core.human_gate",
    "aegis_core.telemetry_engine.ledger",
    "aegis_core.scan_compliance",
)
RULE = (
    "---\nid: trap-one\ntype: trap\nenforcement: advisory\nhypothesis: One.\n"
    "target_paths:\n  - src/*.py\n---\n# trap-one\n\nNever do the one thing.\n"
)
_DRIVER = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from aegis_cli.hooks.insights import main\n"
    "rc = main(sys.argv[3:])\n"
    "with open(sys.argv[2], 'w') as fh:\n"
    "    json.dump({'rc': rc, 'mods': sorted(m for m in sys.modules if m.startswith('aegis'))}, fh)\n"
)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
                   cwd=str(root), check=True, capture_output=True)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("USERPROFILE", str(h))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    return h


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = (tmp_path / "ws").resolve()
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True)
    (root / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (root / ".aegis" / "rules" / "traps" / "trap-one.md").write_text(RULE, encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _payload(ws: Path, prompt: str, session: str = "s-cost") -> dict:
    return {"prompt": prompt, "session_id": session, "cwd": str(ws)}


def _fresh_hook(ws: Path, home: Path, payload: dict, *flags: str):
    report = home.parent / "report.json"
    env = {"HOME": str(home), "USERPROFILE": str(home), "PATH": os.environ.get("PATH", ""),
           "GIT_CONFIG_NOSYSTEM": "1", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _DRIVER, str(REPO), str(report), "--host", "claude-code", *flags],
        input=json.dumps(payload).encode("utf-8"), cwd=str(ws), env=env, capture_output=True,
        timeout=120, check=False,
    )
    return proc, json.loads(report.read_text(encoding="utf-8"))


@pytest.fixture
def parses(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []
    real = core_rules.load_rules

    def counting(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(core_rules, "load_rules", counting)
    # Also the name insights may have bound at import, so the spy sees every parse either way.
    monkeypatch.setattr(core_insights, "load_rules", counting, raising=False)
    return calls


def test_a_repeat_non_cue_prompt_loads_no_review_module_and_no_rules(ws: Path, home: Path):
    record_hook_prompt("claude-code", _payload(ws, "Please run the unit tests."), home=home)
    proc, report = _fresh_hook(ws, home, _payload(ws, "Please run the unit tests."), "--excerpts")
    assert (proc.returncode, report["rc"], proc.stdout, proc.stderr) == (0, 0, b"", b"")
    loaded = set(report["mods"])
    assert loaded.isdisjoint(REVIEW_ONLY + ("aegis_core.verification.scanners", "aegis_core.rules"))


def test_a_cue_prompt_in_a_fresh_session_loads_no_review_module(ws: Path, home: Path):
    proc, report = _fresh_hook(ws, home, _payload(ws, "No, stop editing the build file again."), "--excerpts")
    assert (proc.returncode, report["rc"], proc.stdout, proc.stderr) == (0, 0, b"", b"")
    assert set(report["mods"]).isdisjoint(REVIEW_ONLY)
    assert [r["event"] for r in read_insight_rows(ws, home=home)] == ["heartbeat", "insight"]


def test_rules_are_parsed_at_most_once_per_prompt(ws: Path, home: Path, parses: list):
    record_hook_prompt("claude-code", _payload(ws, "No, stop editing the build file again."), home=home)
    assert len(parses) <= 1
    parses.clear()
    record_hook_prompt("claude-code", _payload(ws, "Please run the unit tests."), home=home)
    assert len(parses) == 0


def test_a_malformed_rule_file_still_exits_zero_silently(ws: Path, home: Path):
    (ws / ".aegis" / "rules" / "traps" / "broken.md").write_bytes(b"---\nid: [unterminated\n\xff\xfe---\n")
    proc, report = _fresh_hook(ws, home, _payload(ws, "No, stop that again."), "--excerpts")
    assert (proc.returncode, report["rc"], proc.stdout, proc.stderr) == (0, 0, b"", b"")


def test_a_crlf_rule_file_records_the_lf_normalised_revision(ws: Path, home: Path):
    raw = RULE.replace("\n", "\r\n").encode("utf-8")
    (ws / ".aegis" / "rules" / "traps" / "trap-one.md").write_bytes(raw)
    record_hook_prompt("claude-code", _payload(ws, "Please run the unit tests."), home=home)
    (row,) = [r for r in read_insight_rows(ws, home=home) if "revs" in r]
    expected = hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()[:16]
    assert row["revs"]["trap-one"] == expected == core_rules.load_rules(ws).get("trap-one").digest[:16]
