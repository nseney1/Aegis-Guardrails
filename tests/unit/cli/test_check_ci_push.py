"""`aegis check --ci` when there is nothing to compare (R-trust-17).

A push to the default branch, a dispatch run or a stale branch resolves the base to the head (or
to a descendant of it): the range is empty, so the run says it compared nothing instead of the
PASSED a real comparison prints. Exit code and JSON shape stay as they were; a pull request run
still compares its base with its head. Real git; no network, no host CLI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aegis_cli.cli import main
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")

GATE = ".aegis/rules/gates/gate-no-eval.md"
RULE = ("---\nid: gate-no-eval\ntype: gate\nenforcement: gate\nhypothesis: Never eval\n"
        "target_paths:\n  - 'src/*.py'\nforbid_ast:\n  calls:\n    - eval\n---\n# No eval\n\nThe body explains why.\n")
NOTE = "nothing was compared"
PASSED = "PASSED, no rule weakened"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GITHUB_EVENT_NAME", "GITHUB_BASE_REF", "GITHUB_STEP_SUMMARY", "SSH_AUTH_SOCK",
                 "GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path) -> hg.Repo:
    """``main`` holds a gate rule and its origin/main tracking ref; ``main`` stays checked out."""
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    repo.write(GATE, RULE)
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return repo


def push_event(tmp_path: Path, monkeypatch, before: str, after: str) -> None:
    event = tmp_path / "push.json"
    event.write_text(json.dumps({"ref": "refs/heads/main", "before": before, "after": after}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")


def run_ci(repo: hg.Repo, capsys, *extra: str):
    os.chdir(repo.root)
    rc = main(["check", "--ci", *extra])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
def test_a_push_to_main_that_deletes_a_gate_says_it_compared_nothing(tmp_path, capsys, monkeypatch):
    """Given a push to main whose commit deletes a gate rule (origin/main is that commit), When check --ci
    runs on the push event, Then it says nothing was compared, never a bare PASSED, and exits 0."""
    repo = make_repo(tmp_path)
    before = repo.head()
    (repo.root / GATE).unlink()
    after = repo.commit("drop the gate")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    push_event(tmp_path, monkeypatch, before, after)
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0
    assert f"aegis check --ci: note: base and head are the same commit; {NOTE} ({after[:10]}..{after[:10]})" in out
    assert PASSED not in out


@needs_git
def test_the_json_document_keeps_its_shape_when_nothing_was_compared(tmp_path, capsys):
    repo = make_repo(tmp_path)
    head = repo.head()
    rc, out, _err = run_ci(repo, capsys, "--base", "main", "--format", "json")
    payload = json.loads(out)
    assert rc == 0 and payload["status"] == "pass" and NOTE not in out
    assert payload["scope"]["merge_base"] == payload["scope"]["head"] == head
    assert set(payload) == {"source", "aegis_version", "checked_at", "scope", "schema", "status", "rules_checked",
                            "weakenings", "approval", "governance", "regression"}


@needs_git
def test_a_stale_branch_behind_its_base_also_compares_nothing(tmp_path, capsys):
    """Sad: a head that is an ancestor of the base gives the note, not PASSED."""
    repo = make_repo(tmp_path)
    repo.branch("stale")
    repo.git("checkout", "-q", "main")
    repo.write("src/app.py", "x = 2\n")
    repo.commit("main moves on")
    repo.git("checkout", "-q", "stale")
    rc, out, _err = run_ci(repo, capsys, "--base", "main")
    assert rc == 0 and NOTE in out and PASSED not in out


@needs_git
def test_a_pull_request_run_still_compares_and_fails_an_unapproved_weakening(tmp_path, capsys, monkeypatch):
    """Sad: the pull_request event file names a real range; the deletion is found and fails."""
    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    (repo.root / GATE).unlink()
    head = repo.commit("drop the gate")
    event = tmp_path / "pr.json"
    event.write_text(json.dumps({"pull_request": {"number": 1, "user": {"login": "agent"},
                                                  "base": {"sha": base}, "head": {"sha": head}}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    rc, out, _err = run_ci(repo, capsys)
    assert rc == 1 and "FAILED: weakening without approval" in out and NOTE not in out
    assert f"{base[:10]}..{head[:10]}" in out


@needs_git
def test_a_real_comparison_still_says_passed(tmp_path, capsys):
    repo = make_repo(tmp_path)
    repo.branch("work")
    repo.write("src/app.py", "x = 3\n")
    repo.commit("an ordinary change")
    rc, out, _err = run_ci(repo, capsys, "--base", "main")
    assert rc == 0 and PASSED in out and NOTE not in out


# ── R-trust-13 (c)-(f): the base-sourced governance job runs on pull_request_target ─────────────

PULL = {"number": 7, "user": {"login": "agent"}, "base": {"sha": "a" * 40, "ref": "main"}, "head": {"sha": "B" * 40}}


def event_file(tmp_path: Path, monkeypatch, name: str, payload) -> None:
    event = tmp_path / "event.json"
    event.write_bytes(json.dumps(payload).encode("utf-8"))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)


@pytest.mark.parametrize("name", ["pull_request", "pull_request_target"])
def test_a_pull_request_target_run_names_its_pull_request_for_the_review_lookup(tmp_path, monkeypatch, name):
    from aegis_cli import check
    from aegis_core import human_gate

    event_file(tmp_path, monkeypatch, name, {"pull_request": PULL})
    assert check._event_pull_request() == human_gate.PullRequest(7, "agent", "b" * 40, "main")


@pytest.mark.parametrize("name", ["push", "workflow_dispatch", "pull_request_review", "PULL_REQUEST_TARGET", ""])
def test_any_other_event_names_no_pull_request(tmp_path, monkeypatch, name):
    from aegis_cli import check

    event_file(tmp_path, monkeypatch, name, {"pull_request": PULL})
    assert check._event_pull_request() is None


@pytest.mark.parametrize("pull", [
    {**PULL, "number": "7"}, {**PULL, "number": 0}, {**PULL, "user": {"login": "two words"}},
    {**PULL, "head": {"sha": "abc"}}, {**PULL, "base": {"sha": "a" * 40, "ref": "../main"}},
    {k: v for k, v in PULL.items() if k != "user"}, "not an object",
], ids=["number-str", "number-zero", "login", "sha", "ref", "no-user", "string"])
def test_a_malformed_pull_request_target_payload_names_no_pull_request(tmp_path, monkeypatch, pull):
    from aegis_cli import check

    event_file(tmp_path, monkeypatch, "pull_request_target", {"pull_request": pull})
    assert check._event_pull_request() is None


@needs_git
def test_no_exec_on_pull_request_target_hands_the_pull_request_to_the_weakening_check(tmp_path, capsys, monkeypatch):
    """--no-exec runs no repository code, but tier A's review lookup (a GitHub read) still gets the
    pull request; nothing is flagged here, so no gh call happens."""
    from aegis_core import human_gate, rule_integrity

    repo = make_repo(tmp_path)
    base = repo.head()
    repo.branch("work")
    repo.write("src/app.py", "x = 2\n")
    head = repo.commit("an ordinary change")
    event_file(tmp_path, monkeypatch, "pull_request_target", {"pull_request": {
        "number": 3, "user": {"login": "agent"}, "base": {"sha": base, "ref": "main"}, "head": {"sha": head}}})
    seen = []
    real = rule_integrity.check_ci

    def spy(*args, pull_request=None, **kwargs):
        seen.append(pull_request)
        return real(*args, pull_request=pull_request, **kwargs)

    monkeypatch.setattr(rule_integrity, "check_ci", spy)
    rc, out, _err = run_ci(repo, capsys, "--no-exec")
    assert rc == 0 and PASSED in out
    assert seen == [human_gate.PullRequest(3, "agent", head, "main")]
