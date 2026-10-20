"""CLI integration tests for T5 regression discipline in ``aegis check --ci``."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from aegis_cli.check import run_check
from aegis_cli.cli import main
from aegis_core import human_gate
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


def make_repo(tmp_path: Path, signer_pub: str | None = None) -> hg.Repo:
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "project", home)
    repo.write("README.md", "# project\n")
    repo.write("src/__init__.py", "")
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x - 1\n")
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    if signer_pub is not None:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    repo.commit("base")
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repo.branch("work")
    return repo


def run_ci(repo: hg.Repo, capsys: pytest.CaptureFixture[str], *extra: str) -> Tuple[int, str, str]:
    os.chdir(repo.root)
    try:
        rc = main(["check", "--ci", "--base", "main", *extra])
    except SystemExit as exc:
        rc = int(exc.code) if exc.code is not None else 0
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
def test_ci_text_format_reports_regression_warnings_and_untested_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo = make_repo(tmp_path)
    repo.write("src/feature.py", "def feat() -> int:\n    return 1\n")
    repo.commit("feat: add feature without tests")
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    repo.commit("fix: fix app offset\n\nAegis-No-Test: urgent hotfix")

    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0
    assert "PASSED" in out
    assert "no_test_changes" in out
    assert "urgent hotfix" in out
    assert "untested" in out.lower()


@needs_git
def test_ci_github_format_emits_error_when_strict_gate_enabled(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    repo.commit("fix: fix app without tests")

    rc, out, _err = run_ci(repo, capsys, "--strict", "--format", "github")
    assert rc == 1
    errors = [line for line in out.splitlines() if line.startswith("::error")]
    assert len(errors) == 1
    assert "no_test_changes" in errors[0]


@needs_git
def test_require_regression_namespace_attribute_enforces_gate_tier(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    repo.commit("fix: fix app without tests")

    ns = argparse.Namespace(
        ci=True,
        base="main",
        head="HEAD",
        format="json",
        json=False,
        workspace=str(repo.root),
        require_regression=True,
    )
    rc = run_check(ns)
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["status"] == "fail"
    assert payload["regression"]["tier"] == "gate"
    assert payload["regression"]["blocking"] is True


@needs_git
@needs_signing
def test_ci_json_reports_exempted_fix_and_passing_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    human, human_pub = hg.keygen(tmp_path / "keys", "human")
    repo = make_repo(tmp_path, signer_pub=human_pub)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    fix_oid = repo.commit("fix: hotfix without test\n\nAegis-No-Test: verified manually")
    repo.commit(human_gate.exemption_message(fix_oid, "verified manually"), sign_key=human, allow_empty=True)

    rc, out, _err = run_ci(repo, capsys, "--strict", "--format", "json")
    assert rc == 0
    payload = json.loads(out)
    assert payload["status"] == "pass"
    reg = payload["regression"]
    assert reg["passed"] is True
    assert reg["exempted_count"] == 1
    assert reg["exemption_rate"] == 1.0
    assert reg["prune_box_exceeded"] is True


@needs_git
@needs_signing
def test_a_rejected_exemption_shows_its_code_and_approve_agrees_with_ci(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """Given an exemption signed by a key that is not in the base allowed_signers, When aegis approve
    --exempt-test signs it and check --ci runs, Then both name untrusted_signature, and CI fails the
    fix commit with that code instead of only no_test_changes."""
    from aegis_cli import approve

    _human, human_pub = hg.keygen(tmp_path / "keys", "human")
    intruder, _pub = hg.keygen(tmp_path / "keys", "intruder")
    repo = make_repo(tmp_path, signer_pub=human_pub)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    fix_oid = repo.commit("fix: hotfix without test\n\nAegis-No-Test: verified manually")
    repo.home.sign_with(str(intruder))
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    os.chdir(repo.root)
    assert main(["approve", "--base", "main", "--exempt-test", fix_oid, "--reason", "reviewed by hand", "--json"]) == 0
    signed = json.loads(capsys.readouterr().out)
    assert (signed["verified"], signed["verification"]["code"]) == (False, "untrusted_signature")

    _rc, out, _err = run_ci(repo, capsys, "--format", "json")
    (commit,) = json.loads(out)["regression"]["commits"]
    assert (commit["status"], commit["reason"]) == ("failed", "no_test_changes")
    assert commit["exemption_code"] == "untrusted_signature"
    _rc, out, _err = run_ci(repo, capsys)
    assert "no_test_changes" in out and "untrusted_signature" in out
