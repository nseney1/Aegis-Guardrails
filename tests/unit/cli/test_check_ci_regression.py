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
def test_a_go_only_fix_is_reported_unverified_and_never_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """R-evidence-26: Given a fix whose only test is handler_test.go, When check --ci runs, Then it exits
    0, the text names UNVERIFIED:regression/tests_not_pytest and GitHub gets a warning, never an error."""
    repo = make_repo(tmp_path)
    repo.write("pkg/handler.go", "package pkg\n\nfunc Handle() int { return 2 }\n")
    repo.write("pkg/handler_test.go", "package pkg\n")
    repo.commit("fix: go handler")

    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0
    assert "[UNVERIFIED:regression/tests_not_pytest] (pkg/handler_test.go)" in out
    rc, out, _err = run_ci(repo, capsys, "--format", "github")
    annotations = [line for line in out.splitlines() if line.startswith("::")]
    assert rc == 0 and len(annotations) == 1
    assert annotations[0].startswith("::warning file=pkg/handler_test.go,title=regression check unverified::tests_not_pytest")
    rc, out, _err = run_ci(repo, capsys, "--format", "json")
    payload = json.loads(out)
    assert rc == 0 and payload["status"] == "pass"
    assert [f["code"] for f in payload["regression"]["findings"]] == ["tests_not_pytest"]
    assert payload["regression"]["commits"][0]["status"] == "unverifiable"


@needs_git
def test_ci_strict_is_a_usage_error_and_runs_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """R-evidence-29: Given aegis check --ci --strict, When it runs, Then it exits 2 naming --strict,
    prints nothing on stdout and starts no process (no git, no pytest)."""
    import subprocess
    from aegis_cli.check import CheckCommand

    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    repo.commit("fix: fix app without tests")
    spawned: list = []

    class NoSpawn:
        def __init__(self, argv, *args, **kwargs):
            spawned.append(list(argv))
            raise AssertionError(f"started {argv!r}")

    parser = argparse.ArgumentParser()
    cmd = CheckCommand()
    cmd.configure_parser(parser)
    args = parser.parse_args(["--ci", "--strict", "--base", "main"])
    args._root = repo.root
    monkeypatch.setattr(subprocess, "Popen", NoSpawn)
    rc = cmd.execute(args)
    captured = capsys.readouterr()
    assert rc == 2 and spawned == []
    assert "--ci does not combine with --strict" in captured.err
    assert captured.out == ""


@needs_git
def test_ci_github_format_emits_a_warning_for_an_untested_fix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """No setting makes T5 block in 4.4.0: the annotation is a warning and the job passes."""
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    repo.commit("fix: fix app without tests")

    rc, out, _err = run_ci(repo, capsys, "--format", "github")
    assert rc == 0
    annotations = [line for line in out.splitlines() if line.startswith("::")]
    assert len(annotations) == 1
    assert annotations[0].startswith("::warning ") and "no_test_changes" in annotations[0]


@needs_git
def test_require_regression_namespace_attribute_is_ignored(
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
    assert rc == 0
    assert payload["status"] == "pass"
    assert payload["regression"]["tier"] == "warning"
    assert payload["regression"]["blocking"] is False
    assert payload["regression"]["passed"] is False


@needs_git
def test_a_user_config_gate_tier_is_ignored_and_the_static_hint_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Given user config regression.tier = "gate" and a fix without a test, When check --ci runs,
    Then it exits 0 at warning tier and prints the static hint."""
    repo = make_repo(tmp_path)
    repo.write("src/app.py", "def app(x: int = 1) -> int:\n    return x + 1\n")
    repo.commit("fix: fix app without tests")
    user_cfg = tmp_path / "home" / ".aegis"
    user_cfg.mkdir(parents=True, exist_ok=True)
    (user_cfg / "config.json").write_text(json.dumps({"v": 1, "regression": {"tier": "gate"}}), encoding="utf-8")

    rc, out, _err = run_ci(repo, capsys)
    assert rc == 0
    assert "  regression tier: warning (advisory in 4.4.0; no setting makes it block)" in out
    assert "[WARN:regression/no_test_changes]" in out
    rc, out, _err = run_ci(repo, capsys, "--format", "json")
    reg = json.loads(out)["regression"]
    assert rc == 0 and (reg["tier"], reg["blocking"], reg["status"]) == ("warning", False, "warning")


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

    rc, out, _err = run_ci(repo, capsys, "--format", "json")
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
