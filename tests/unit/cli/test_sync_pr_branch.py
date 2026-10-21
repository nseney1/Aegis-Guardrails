"""`aegis sync --pr` puts the transitions in the PR (R-evidence-13): a branch cut from the protected
branch, one commit holding exactly the moves and the examples to label, a push to the origin, then
`gh pr create --head`; the user's branch, index and tree end as they began, in every failure too.

Real git with a local bare origin and a throwaway HOME; gh is a fake; nothing reaches the network.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat

import pytest

from aegis_cli.sync import EXIT_OK, EXIT_PROBLEMS, run_sync
from tests import helpers_syncpr as hs
from tests.helpers_syncpr import git

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GIT_CONFIG_GLOBAL"):
        monkeypatch.delenv(name, raising=False)


def _writable_retry(func, path, _exc_info) -> None:
    os.chmod(path, stat.S_IWRITE)  # git writes object files read-only; Windows will not delete those
    func(path)


def _run(repo: hs.Repo, gh: hs.FakeGh, capsys) -> tuple:
    rc = run_sync(argparse.Namespace(_root=repo.root, pr=True, json=True), gh_runner=gh)
    return rc, json.loads(capsys.readouterr().out)


def test_the_pr_holds_exactly_the_transition_and_the_user_branch_is_untouched(tmp_path, capsys):
    repo = hs.make(tmp_path)
    for hook in ("pre-commit", "pre-push", "post-checkout", "reference-transaction"):
        script = repo.root / ".git" / "hooks" / hook
        script.write_text(f"#!/bin/sh\ntouch '{tmp_path / ('ran-' + hook)}'\n", encoding="utf-8")
        script.chmod(0o755)
    before, main_before = repo.state(), git(repo.origin, "rev-parse", "main")
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert rc == EXIT_OK, payload
    pr = payload["pr"]
    assert pr["status"] == "opened" and pr["branch"].startswith("aegis/lifecycle-")
    assert [c[:2] for c in gh.calls] == [["pr", "create"]] and not any("merge" in c for c in gh.calls)
    assert gh.flag("--head") == pr["branch"] and gh.flag("--base") == "main"
    assert pr["branch"] in gh.origin_at_create  # pushed before the PR was asked for
    changed = git(repo.root, "diff", "--no-renames", "--name-status", "main", pr["branch"]).splitlines()
    assert sorted(changed) == sorted([
        "A\t.aegis/rules/invariants/trap-decided.md", "D\t.aegis/rules/traps/trap-decided.md",
        "M\t.aegis/adjudications/trap-decided.jsonl"])
    added = git(repo.root, "diff", "main", pr["branch"], "--", ".aegis/adjudications")
    assert added.count('"verdict": null') == 2
    assert git(repo.origin, "rev-parse", "main") == main_before
    after = repo.state()
    assert after.pop("branches").splitlines() == sorted(before.pop("branches").splitlines() + [f"refs/heads/{pr['branch']}"])
    assert after == before  # HEAD, branch, status, every rule and label byte
    assert not list(tmp_path.glob("ran-*"))  # no hook ran
    second = run_sync(argparse.Namespace(_root=repo.root, json=True))
    entry = next(r for r in json.loads(capsys.readouterr().out)["rules"] if r["id"] == "trap-decided")
    assert second == EXIT_OK and entry["path"] == ".aegis/rules/traps/trap-decided.md"


@pytest.mark.parametrize("shape", ["no-origin", "dirty-rules", "dirty-labels", "detached", "feature-branch",
                                   "repo-ssh-command", "option-remote", "not-git"])
def test_a_failed_precondition_refuses_before_anything_moves(tmp_path, capsys, shape):
    repo = hs.make(tmp_path)
    if shape == "no-origin":  # the remote is gone; the reviewed refs (and so the labels) remain
        git(repo.root, "config", "--remove-section", "remote.origin")
    elif shape == "dirty-rules":
        repo.rule_path.write_bytes(repo.rule_path.read_bytes() + b"\nEdited.\n")
    elif shape == "dirty-labels":
        (repo.root / ".aegis" / "adjudications" / "new.jsonl").write_bytes(b"{}\n")
    elif shape == "detached":
        git(repo.root, "checkout", "-q", "--detach")
    elif shape == "feature-branch":
        git(repo.root, "checkout", "-q", "-b", "feature")
    elif shape == "repo-ssh-command":
        git(repo.root, "config", "core.sshCommand", f"touch {tmp_path / 'ran-ssh'}")
    elif shape == "option-remote":
        git(repo.root, "config", "branch.main.remote", f"--receive-pack=touch {tmp_path / 'ran-ssh'}")
    elif shape == "not-git":  # no BASE for labels: 25 tp outcome rows make the promotion
        from aegis_core.telemetry_engine import ledger

        shutil.rmtree(repo.root / ".git", onerror=_writable_retry)
        ledger.append(repo.root, [{"rule": repo.rule, "outcome": "tp", "source": "ci", "key": f"k{n}"} for n in range(25)])
    before = repo.state() if shape != "not-git" else None
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert rc == EXIT_PROBLEMS and payload["pr"]["status"] == "refused" and gh.calls == []
    assert payload["applied"] == [] and payload["refused"]
    reason = payload["refused"]
    expected = {"no-origin": "origin", "dirty-rules": "uncommitted", "dirty-labels": "uncommitted",
                "detached": "detached", "feature-branch": "main", "repo-ssh-command": "core.sshcommand",
                "option-remote": "no usable remote", "not-git": "git work tree"}[shape]
    assert expected in reason.lower(), reason
    if before is not None:
        assert repo.state() == before
    assert repo.origin_branches() == ["main"] and not (tmp_path / "ran-ssh").exists()


def test_when_every_move_is_refused_no_branch_is_made_and_gh_is_not_asked(tmp_path, capsys):
    repo = hs.make(tmp_path)
    blocker = repo.root / ".aegis" / "rules" / "invariants" / "trap-decided.md" / "keep.txt"
    blocker.parent.mkdir(parents=True)
    blocker.write_bytes(b"a directory where the promoted rule would go\n")
    git(repo.root, "add", "-A")
    git(repo.root, "commit", "-q", "-m", "block the move")
    before = repo.state()
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert payload["pr"]["status"] == "no_transitions" and gh.calls == []
    assert [a["status"] for a in payload["applied"]] == ["target_exists"] and rc == EXIT_PROBLEMS
    assert repo.state() == before and repo.origin_branches() == ["main"]


def test_a_rejected_push_deletes_the_local_branch_and_leaves_everything_as_it_was(tmp_path, capsys):
    repo = hs.make(tmp_path)
    hook = repo.origin / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'rejected by policy' >&2\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    before = repo.state()
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert rc == EXIT_PROBLEMS and payload["pr"]["status"] == "failed" and gh.calls == []
    assert "rejected by policy" in payload["pr"]["error"]
    assert repo.state() == before and repo.origin_branches() == ["main"]


def test_a_gh_failure_after_the_push_keeps_and_names_the_pushed_branch(tmp_path, capsys):
    repo = hs.make(tmp_path)
    before = repo.state()
    gh = hs.FakeGh(repo.origin, returncode=1)

    rc, payload = _run(repo, gh, capsys)

    pr = payload["pr"]
    assert rc == EXIT_PROBLEMS and pr["status"] == "failed" and pr["branch"] in repo.origin_branches()
    assert pr["branch"] in pr["error"] and "could not create the pull request" in pr["error"]
    assert {k: v for k, v in repo.state().items() if k != "branches"} == {
        k: v for k, v in before.items() if k != "branches"}
    assert git(repo.root, "symbolic-ref", "--short", "HEAD") == "main"


def test_a_branch_name_already_taken_gets_the_next_one(tmp_path, capsys, monkeypatch):
    from aegis_core import sync as core_sync

    repo = hs.make(tmp_path)
    monkeypatch.setattr(core_sync, "_lifecycle_stamp", lambda: "20261021T000000Z")
    git(repo.root, "branch", "aegis/lifecycle-20261021T000000Z")
    gh = hs.FakeGh(repo.origin)
    rc, payload = _run(repo, gh, capsys)
    assert rc == EXIT_OK and payload["pr"]["branch"] == "aegis/lifecycle-20261021T000000Z-2"


def _plant(path, marker) -> None:
    path.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
    path.chmod(0o755)


@pytest.mark.parametrize("where", ["url", "second-pushurl"])
def test_a_push_url_scheme_that_picks_a_remote_helper_is_refused_and_the_helper_never_runs(
        tmp_path, capsys, monkeypatch, where):
    repo = hs.make(tmp_path)
    helpers = tmp_path / "bin"
    helpers.mkdir()
    _plant(helpers / "git-remote-xyz", tmp_path / "ran-helper")  # git runs git-remote-<scheme> from PATH
    monkeypatch.setenv("PATH", os.pathsep.join([os.environ.get("PATH", ""), str(helpers)]))
    if where == "url":
        git(repo.root, "remote", "set-url", "origin", "xyz://host/repo")
    else:  # git pushes to every push URL: the first is fine, the second picks the helper
        git(repo.root, "remote", "set-url", "--add", "--push", "origin", str(repo.origin))
        git(repo.root, "remote", "set-url", "--add", "--push", "origin", "xyz://host/repo")
    before = repo.state()
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert rc == EXIT_PROBLEMS and payload["pr"]["status"] == "refused" and gh.calls == []
    assert "xyz://" in payload["refused"] and "host/repo" not in payload["refused"]  # a URL may hold a token
    assert repo.state() == before and repo.origin_branches() == ["main"]
    assert not (tmp_path / "ran-helper").exists()


def test_a_signing_program_from_repository_config_never_runs_on_the_push(tmp_path, capsys):
    repo = hs.make(tmp_path)
    git(repo.origin, "config", "receive.certNonceSeed", "seed")  # the origin accepts signed pushes
    _plant(tmp_path / "signer", tmp_path / "ran-signer")
    for key, value in (("push.gpgSign", "true"), ("gpg.format", "ssh"), ("gpg.ssh.program", str(tmp_path / "signer")),
                       ("user.signingKey", "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA")):
        git(repo.root, "config", key, value)
    before = repo.state()
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert rc == EXIT_OK and payload["pr"]["status"] == "opened", payload["pr"]
    assert payload["pr"]["branch"] in repo.origin_branches()
    after = repo.state()
    assert after.pop("branches") != before.pop("branches") and after == before
    assert not (tmp_path / "ran-signer").exists()


@pytest.mark.parametrize("where", ["relative-path", "file-url", "git-dir", "second-pushurl"])
def test_a_local_push_url_inside_the_repository_is_refused_and_its_hooks_never_run(tmp_path, capsys, where):
    # git drops -c for a local receiving repository, so its own hooks run; inside this work tree or
    # git dir the repository chose them.
    repo = hs.make(tmp_path)
    inner = repo.root / "inner.git"
    git(repo.root, "init", "-q", "--bare", str(inner))
    for hooks in (inner / "hooks", repo.root / ".git" / "hooks"):
        _plant(hooks / "pre-receive", tmp_path / "ran-receiver-hook")
    url = {"relative-path": "inner.git", "file-url": inner.as_uri(), "git-dir": str(repo.root / ".git"),
           "second-pushurl": "inner.git"}[where]
    if where == "second-pushurl":
        git(repo.root, "remote", "set-url", "--add", "--push", "origin", str(repo.origin))
        git(repo.root, "remote", "set-url", "--add", "--push", "origin", url)
    else:
        git(repo.root, "remote", "set-url", "origin", url)
    before = repo.state()
    gh = hs.FakeGh(repo.origin)

    rc, payload = _run(repo, gh, capsys)

    assert rc == EXIT_PROBLEMS and payload["pr"]["status"] == "refused" and gh.calls == []
    assert "inside this repository" in payload["refused"]
    assert repo.state() == before and repo.origin_branches() == ["main"]
    assert git(inner, "for-each-ref", "refs/heads") == ""
    assert not (tmp_path / "ran-receiver-hook").exists()
