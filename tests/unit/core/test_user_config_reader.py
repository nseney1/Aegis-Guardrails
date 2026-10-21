"""One reader for ~/.aegis/config.json (R-trust-26): the same bytes give the same
honoured-or-ignored decision for tests.command, rules.base_ref, perf.command and
regression.tier, and a file inside the workspace is repository content for all four."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import threading

import pytest

from aegis_core import checkrun, config, regression, rule_integrity
from aegis_core.verification import perf_check
from aegis_core.workspace.layout import UserLayout

from conftest import symlink_or_skip

BRANCH = "anchor-branch"
SETTINGS = {
    "v": 1,
    "tests": {"command": "python run_checks.py"},
    "rules": {"base_ref": BRANCH},
    "perf": {"command": "python bench.py"},
    "regression": {"tier": "gate"},
}
HONOURED = {"tests": ["python", "run_checks.py"], "rules": "user-config", "perf": True, "regression": "gate"}
IGNORED = {"tests": None, "rules": "other", "perf": False, "regression": "warning"}


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(root, "add", "a.py")
    _git(root, "commit", "-q", "-m", "init")
    _git(root, "branch", BRANCH)
    return root


def _home(monkeypatch, home: Path) -> Path:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    (home / ".aegis").mkdir(parents=True, exist_ok=True)
    return home / ".aegis" / "config.json"


def _decisions(root: Path) -> dict:
    perf_calls = []

    def spy(argv, cwd=None, timeout=60, **_kwargs):
        perf_calls.append(list(argv))
        return {"returncode": 1, "stderr": "spy stops the run"}

    anchor = rule_integrity.resolve_base(root)
    # The fixture repository has one commit, so the default HEAD~1 base would not resolve.
    perf_check.run_perf_check(root, base_ref="HEAD", runner=spy)
    return {
        "tests": checkrun.user_test_command(root),
        "rules": "user-config" if anchor is not None and anchor.source == "user-config" else "other",
        "perf": bool(perf_calls),
        "regression": regression._user_regression_tier(str(root)),
    }


# ── Step 1: containment (the same before and after the change) ────────────────

def test_a_home_inside_the_workspace_is_repository_content_for_every_consumer(repo, monkeypatch):
    path = _home(monkeypatch, repo / "home")
    path.write_text(json.dumps(SETTINGS), encoding="utf-8")
    assert _decisions(repo) == IGNORED


def test_a_symlinked_config_into_the_workspace_is_ignored_by_every_consumer(repo, tmp_path, monkeypatch):
    target = repo / "planted.json"
    target.write_text(json.dumps(SETTINGS), encoding="utf-8")
    symlink_or_skip(target, _home(monkeypatch, tmp_path / "home"))
    assert _decisions(repo) == IGNORED


def test_a_symlinked_config_outside_the_workspace_is_honoured_by_every_consumer(repo, tmp_path, monkeypatch):
    target = tmp_path / "dotfiles" / "aegis.json"
    target.parent.mkdir()
    target.write_text(json.dumps(SETTINGS), encoding="utf-8")
    symlink_or_skip(target, _home(monkeypatch, tmp_path / "home"))
    assert _decisions(repo) == HONOURED


# ── Step 2: the same bytes, the same decision ─────────────────────────────────

def _write(path: Path, case: str) -> None:
    text = json.dumps(SETTINGS)
    if case == "plain":
        path.write_bytes(text.encode("utf-8"))
    elif case == "bom":
        path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    elif case == "v2":
        path.write_bytes(json.dumps({**SETTINGS, "v": 2}).encode("utf-8"))
    elif case == "invalid":
        path.write_bytes(text[:-1].encode("utf-8"))
    elif case == "array":
        path.write_bytes(json.dumps([SETTINGS]).encode("utf-8"))
    elif case == "100kib":
        path.write_bytes(json.dumps({**SETTINGS, "pad": "x" * (100 * 1024)}).encode("utf-8"))
    elif case == "directory":
        path.mkdir()
    elif case == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("no FIFOs on this platform")
        try:
            os.mkfifo(str(path))
        except OSError:
            pytest.skip("the OS refused a FIFO here")


def _within_ceiling(path: Path, fn):
    """fn() on a thread; a reader blocked on a FIFO is released and the test fails.
    A hang ceiling, not a time budget."""
    box = {}
    worker = threading.Thread(target=lambda: box.update(value=fn()), daemon=True)
    worker.start()
    worker.join(60)
    if worker.is_alive():
        if stat.S_ISFIFO(os.lstat(str(path)).st_mode):
            os.close(os.open(str(path), os.O_WRONLY | os.O_NONBLOCK))
        pytest.fail("a consumer blocked on the user config")
    return box["value"]


@pytest.mark.parametrize("case, expected", [
    ("plain", HONOURED), ("bom", HONOURED), ("v2", IGNORED), ("invalid", IGNORED), ("array", IGNORED),
    ("100kib", IGNORED), ("directory", IGNORED), ("fifo", IGNORED),
])
def test_every_consumer_reaches_the_same_decision(repo, tmp_path, monkeypatch, case, expected):
    path = _home(monkeypatch, tmp_path / "home")
    _write(path, case)
    assert _within_ceiling(path, lambda: _decisions(repo)) == expected
    assert (config.read_user_config(repo) is not None) == (expected == HONOURED)


def test_the_strict_loader_still_refuses_what_the_reader_ignores(repo, tmp_path, monkeypatch):
    path = _home(monkeypatch, tmp_path / "home")
    for case in ("v2", "100kib"):
        _write(path, case)
        with pytest.raises(config.ConfigError):
            config.UserConfig.load(repo, user=UserLayout(tmp_path / "home"))
        assert config.read_user_config(repo) is None


def test_an_explicit_path_is_honoured_unless_it_lies_inside_the_workspace(repo, tmp_path):
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps(SETTINGS), encoding="utf-8")
    assert config.read_user_config(repo, path=outside) == SETTINGS
    inside = repo / "cfg.json"
    inside.write_text(json.dumps(SETTINGS), encoding="utf-8")
    assert config.read_user_config(repo, path=inside) is None
    assert config.read_user_config(repo, path=tmp_path / "missing.json") is None


def test_an_unsplittable_perf_command_is_unusable_not_a_crash(repo, tmp_path, monkeypatch):
    path = _home(monkeypatch, tmp_path / "home")
    path.write_text(json.dumps({"v": 1, "perf": {"command": "python 'bench.py"}}), encoding="utf-8")
    calls = []
    res = perf_check.run_perf_check(repo, runner=lambda argv, **_kw: calls.append(argv) or {"returncode": 1})
    assert res["status"] == "unverified"
    assert calls == []
