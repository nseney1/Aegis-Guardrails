"""Refused insight approvals retain stable diagnostics through capture and the CLI."""
from __future__ import annotations

import argparse
import json
import subprocess

import pytest

from aegis_cli.rule import RuleCommand, run_rule
from aegis_core import approval_shape, human_gate
from aegis_core.insights import add_insight, read_insight_rows
from tests import helpers_humangate as hg


@pytest.fixture
def approved_repo(tmp_path, monkeypatch):
    if not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    key, public = hg.keygen(tmp_path / "keys", "human")
    return hg.make_repo(tmp_path, public), key, home


TEXT = "Never discard an approval refusal code"
MARKER = "private-commit-prose-do-not-display"


def _commit(repo, key, message):
    # stdin also works for messages larger than Windows' command-line limit.
    repo.git("-c", "gpg.format=ssh", "-c", f"user.signingkey={key}",
             "commit", "-q", "--allow-empty", "-S", "-F", "-", stdin=message)
    return repo.head()


def _message(kind):
    trailer = f"Aegis-Approve-Insight: {human_gate.insight_text_hash(TEXT)}\n"
    if kind == "message_too_large":
        return f"{MARKER}\n\n" + ("prose\n" * (approval_shape.MAX_MESSAGE_BYTES // 6 + 1)) + "\n" + trailer
    if kind == "message_line_too_long":
        return f"{MARKER}\n\n" + "x" * (approval_shape.MAX_LINE_LENGTH + 1) + "\n\n" + trailer
    if kind == "multiple_trailers":
        return f"{MARKER}\n\n{trailer}{trailer}"
    if kind == "invalid_message_shape":
        return f"{MARKER}\n\n{trailer} continued signed value\n"
    if kind == "hash_mismatch":
        trailer = "Aegis-Approve-Insight: " + "0" * 64 + "\n"
    if kind == "no_trailer":
        trailer = ""
    return f"{MARKER}\n\n{trailer}"


@pytest.mark.parametrize("code", ["message_too_large", "message_line_too_long", "multiple_trailers",
                                 "invalid_message_shape", "hash_mismatch", "no_trailer"])
def test_capture_persists_the_verifiers_refusal_code(approved_repo, code):
    repo, key, home = approved_repo
    oid = _commit(repo, key, _message(code))
    verdict = human_gate.verify_insight_approval(repo.root, oid, TEXT, "main")
    assert (verdict.ok, verdict.code) == (False, code)

    row = add_insight(repo.root, TEXT, paths=["src/app.py"], commit=oid, base_ref="main", home=home)

    assert (row["level"], row.get("approval_code")) == ("cli", code)
    assert read_insight_rows(repo.root, home=home)[-1] == row
    assert MARKER not in json.dumps(row)


@pytest.mark.parametrize("with_commit", [False, True])
def test_no_refusal_is_recorded_without_an_attempt_or_with_valid_approval(approved_repo, with_commit):
    repo, key, home = approved_repo
    oid = _commit(repo, key, _message("ok")) if with_commit else None
    row = add_insight(repo.root, TEXT, paths=["src/app.py"], commit=oid, base_ref="main", home=home)
    assert row["level"] == ("H" if with_commit else "cli")
    assert "approval_code" not in row


@pytest.mark.parametrize("commit", ["", "   "])
def test_empty_explicit_commit_retains_invalid_input(approved_repo, commit):
    repo, _key, home = approved_repo
    row = add_insight(repo.root, TEXT, paths=["src/app.py"], commit=commit, base_ref="main", home=home)
    assert (row["level"], row.get("approval_code")) == ("cli", "invalid_input")


@pytest.mark.parametrize("code", ["unsigned", "untrusted_signature", "unresolved"])
def test_capture_retains_signature_and_resolution_refusals(approved_repo, tmp_path, code):
    repo, _key, home = approved_repo
    if code == "unsigned":
        oid = repo.commit(_message("ok"), allow_empty=True)
    elif code == "untrusted_signature":
        intruder, _public = hg.keygen(tmp_path / "keys", "intruder")
        oid = _commit(repo, intruder, _message("ok"))
    else:
        oid = MARKER

    row = add_insight(repo.root, TEXT, paths=["src/app.py"], commit=oid, base_ref="main", home=home)

    assert (row["level"], row.get("approval_code")) == ("cli", code)
    assert MARKER not in json.dumps(row)


@pytest.mark.parametrize("failure,code", [(OSError, "unverifiable"), (RuntimeError, "unverifiable")])
def test_capture_does_not_persist_or_echo_verification_exceptions(approved_repo, monkeypatch, failure, code):
    from aegis_core import gitsafe

    repo, key, home = approved_repo
    oid = _commit(repo, key, _message("ok"))
    real_run = gitsafe.run

    def fail_message_read(args, *rest, **kwargs):
        if args[:2] == ["cat-file", "commit"]:
            raise failure(MARKER)
        return real_run(args, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", fail_message_read)
    row = add_insight(repo.root, TEXT, paths=["src/app.py"], commit=oid, base_ref="main", home=home)

    assert (row["level"], row.get("approval_code")) == ("cli", code)
    assert MARKER not in json.dumps(read_insight_rows(repo.root, home=home))


@pytest.mark.parametrize("use_json", [False, True])
def test_cli_displays_the_refusal_without_commit_prose(approved_repo, capsys, use_json):
    repo, key, _home = approved_repo
    oid = _commit(repo, key, _message("invalid_message_shape"))
    parser = argparse.ArgumentParser()
    RuleCommand().configure_parser(parser)
    argv = ["insight", "add", TEXT, "--paths", "src/app.py", "--commit", oid, "--base-ref", "main"]
    args = parser.parse_args(argv + (["--json"] if use_json else []))
    args.workspace = str(repo.root)
    args._rule_workspace_arg = str(repo.root)

    assert run_rule(args) == 0

    output = capsys.readouterr()
    if use_json:
        assert json.loads(output.out)["approval_code"] == "invalid_message_shape"
    else:
        assert "Approval refused: invalid_message_shape" in output.out
    assert MARKER not in output.out + output.err


@pytest.mark.parametrize("code,action,recipe", [
    ("invalid_input", "Provide a non-empty approval commit id and insight text.", False),
    ("unresolved", "Check the approval commit argument and base reference.", False),
    ("unverifiable", "Check Git and SSH signature verification, then retry verification.", False),
    ("no_allowed_signers", "Add the signer to the base branch's allowed_signers.", False),
    ("untrusted_signature", "Sign the approval with a key trusted by the base branch.", False),
    ("bad_signature", "Configure a trusted SSH signing key, then create a new approval.", False),
    ("unsigned", "Sign the approval commit with a trusted key.", True),
    ("no_trailer", "Create an approval with the exact Aegis-Approve-Insight trailer shown below.", True),
    ("hash_mismatch", "Create an approval for the exact insight text using the trailer shown below.", True),
    ("message_too_large", "Create a shorter approval message using the trailer shown below.", True),
    ("message_line_too_long", "Create an approval message with shorter lines using the trailer shown below.", True),
    ("multiple_trailers", "Create an approval with exactly one Aegis-Approve-Insight trailer.", True),
    ("invalid_message_shape", "Create an approval whose signed trailer value occupies one printable line.", True),
    ("accept_reserved", "Remove the reserved Aegis-Accept line from the approval message.", True),
])
def test_cli_gives_one_fixed_next_action_for_every_refusal(approved_repo, tmp_path, monkeypatch, capsys,
                                                         code, action, recipe):
    from aegis_core import gitsafe

    repo, key, _home = approved_repo
    if code == "no_allowed_signers":
        repo.write("allowed_signers", "")
        empty_base = repo.commit("base without signers")
        repo.git("update-ref", "refs/heads/main", empty_base)
    if code == "untrusted_signature":
        key, _public = hg.keygen(tmp_path / "keys", "intruder")
    message = _message(code)
    if code == "accept_reserved":
        message += "Aegis-Accept: reserved\n"
    oid = repo.commit(message, allow_empty=True) if code == "unsigned" else _commit(repo, key, message)
    if code == "invalid_input":
        oid = ""
    elif code == "unresolved":
        oid = MARKER
    if code in ("bad_signature", "unverifiable"):
        real_run = gitsafe.run

        def signature_status(args, *rest, **kwargs):
            if "--format=%G?%n%GF" in args:
                return subprocess.CompletedProcess(args, 0, b"B\n" if code == "bad_signature" else b"E\n", MARKER.encode())
            return real_run(args, *rest, **kwargs)

        monkeypatch.setattr(gitsafe, "run", signature_status)
    parser = argparse.ArgumentParser()
    RuleCommand().configure_parser(parser)
    args = parser.parse_args(["insight", "add", TEXT, "--paths", "src/app.py", "--commit", oid, "--base-ref", "main"])
    args.workspace = str(repo.root)
    args._rule_workspace_arg = str(repo.root)

    assert run_rule(args) == 0

    output = capsys.readouterr()
    assert f"Approval refused: {code}\n{action}\n" in output.out
    assert output.out.splitlines().count(action) == 1
    assert ("To record it at level H" in output.out) is recipe
    assert MARKER not in output.out + output.err
