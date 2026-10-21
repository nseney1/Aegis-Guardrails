"""`aegis approve` and `aegis doctor --github` through the real argument parser."""
from __future__ import annotations

import io
import json

import pytest

from aegis_cli import cli
from aegis_core import human_gate
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


def test_approve_is_a_registered_command_with_a_base_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["approve", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--base" in out and "Aegis-Approve" in out


def test_approve_appears_in_the_categorized_help(capsys):
    assert cli.main([]) == 0
    assert "approve" in capsys.readouterr().out


def test_approve_outside_a_git_work_tree_is_a_refusal_not_a_traceback(tmp_path, capsys):
    rc = cli.main(["approve", "--workspace", str(tmp_path)])
    assert rc == 1
    assert "not inside a git work tree" in capsys.readouterr().err


@needs_git
def test_approve_without_a_terminal_refuses_through_main(tmp_path, monkeypatch, capsys):
    repo = hg.make_repo(tmp_path)
    repo.write(".aegis/config.json", "{}\n")
    repo.commit("governance")
    monkeypatch.setattr("sys.stdin", io.StringIO())
    key, _pub = hg.keygen(tmp_path / "k", "human")
    repo.home.sign_with(str(key))
    monkeypatch.setenv("HOME", str(repo.home.path))
    rc = cli.main(["approve", "--workspace", str(repo.root), "--base", "main", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 1 and doc["status"] == "refused" and doc["code"] == "no_terminal"
    for field in ("source", "aegis_version", "checked_at", "scope"):
        assert doc[field]


@needs_git
@pytest.mark.parametrize("flags,needle", [
    (["--tier", "B"], "--tier only applies"),
    (["--apply"], "--apply only applies"),
    (["--github", "--fix"], "cannot be combined"),
    (["--github", "--apply", "--tier", "B", "--json"], "cannot run with --json"),
    (["--github", "--apply"], "--tier A or --tier B"),
])
def test_doctor_github_flag_combinations_are_usage_errors(tmp_path, capsys, flags, needle):
    repo = hg.make_repo(tmp_path)
    rc = cli.main(["doctor", "--workspace", str(repo.root), *flags])
    assert rc == 2
    assert needle in capsys.readouterr().err


def test_an_approval_verdict_serializes_with_the_envelope():
    verdict = human_gate.Approval(False, "unsigned", "the commit is not signed", "a" * 40)
    doc = verdict.as_dict("/work")
    assert doc["valid"] is False and doc["code"] == "unsigned" and doc["scope"]["commit"] == "a" * 40
    assert doc["checked_at"].endswith("Z") and doc["source"] and doc["aegis_version"]


# ── R-trust-34: one signing flow, one set of refusals ─────────────────────────

needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")


@pytest.fixture
def signer_repo(tmp_path, monkeypatch):
    """A signer on main, a rule edit committed on work, and a user-level SSH signing key."""
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, pub)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weaker"))
    repo.commit("weaken a rule")
    repo.home.sign_with(str(key))
    for name, value in repo.home.env.items():
        monkeypatch.setenv(name, value)
    for name in ("SSH_AUTH_SOCK", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)
    return repo


def _run(repo, monkeypatch, capsys, exempt, tty=True, answer="n"):
    from aegis_cli import approve
    prompts = []
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: tty)
    monkeypatch.setattr("builtins.input", lambda prompt="": prompts.append(prompt) or answer)
    argv = ["approve", "--workspace", str(repo.root), "--base", "main", "--json"]
    if exempt:
        argv += ["--exempt-test", repo.head(), "--reason", "checked by hand"]
    before = repo.head()
    rc = cli.main(argv)
    captured = capsys.readouterr()
    assert repo.head() == before, "a refusal makes no commit"
    return rc, json.loads(captured.out), prompts, captured.err


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_refuse_uncommitted_governance_changes(signer_repo, monkeypatch, capsys, exempt):
    signer_repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "dirty"))
    rc, doc, prompts, _err = _run(signer_repo, monkeypatch, capsys, exempt)
    assert rc == 1 and doc["status"] == "refused" and doc["code"] == "uncommitted" and prompts == []
    assert doc["reason"].startswith("governance files have uncommitted changes (rules)")


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_refuse_staged_changes_before_any_prompt(signer_repo, monkeypatch, capsys, exempt):
    signer_repo.write("src/app.py", "def app():\n    return 3\n")
    signer_repo.git("add", "src/app.py")
    rc, doc, prompts, _err = _run(signer_repo, monkeypatch, capsys, exempt)
    assert rc == 1 and doc["code"] == "staged" and prompts == []


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_refuse_without_a_terminal(signer_repo, monkeypatch, capsys, exempt):
    rc, doc, prompts, _err = _run(signer_repo, monkeypatch, capsys, exempt, tty=False)
    assert rc == 1 and doc["code"] == "no_terminal" and prompts == []


@needs_signing
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_both_flows_are_declined_by_anything_but_y(signer_repo, monkeypatch, capsys, exempt):
    rc, doc, prompts, err = _run(signer_repo, monkeypatch, capsys, exempt, answer="sure")
    assert rc == 1 and doc["status"] == "declined" and doc["code"] == "declined" and prompts == [""]
    assert "[y/N]" in err
