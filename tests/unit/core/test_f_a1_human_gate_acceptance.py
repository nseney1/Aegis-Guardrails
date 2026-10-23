"""Acceptance contract for lane f-a1-human-gate (v4.3 spec §2.2-§2.4, §9; v4.4 spec §12).

Given/When/Then, written before the code and never weakened to make it pass:

1. A forged trailer, an unsigned commit, a commit signed by a key that is not in the BASE
   allowed_signers, a signature that is not an SSH signature, or a commit that carries an
   ``Aegis-Accept:`` line is never an approval, and no signature program the repository names runs.
2. Tier C says it is self-attested, on the text report and in the JSON.
3. ``doctor --github --apply`` without a terminal refuses and changes nothing on GitHub; with a
   terminal it asks first.
4. ``aegis approve`` refuses when nothing governance-related changed, makes one signed empty
   commit that names the governance tree hash it approved, and never writes a key.
5. The ``Aegis-Test-Change`` trailer authorizes nothing in the lane gate.
6. The shared state is private whatever the umask, doctor counts looser entries without naming
   them, and ``migrate --apply`` tightens them.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from aegis_core import human_gate, lane_gate, storage
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits and shell scripts")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """The user-scope git config of every test here is a throwaway one."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name, value in (("HOME", home), ("USERPROFILE", home)):
        monkeypatch.setenv(name, str(value))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)


@pytest.fixture
def keys(tmp_path):
    human, human_pub = hg.keygen(tmp_path / "keys", "human")
    other, other_pub = hg.keygen(tmp_path / "keys", "intruder")
    return {"human": human, "human_pub": human_pub, "other": other, "other_pub": other_pub}


def _changed_rule_branch(repo: hg.Repo) -> str:
    """On ``work``: a rule edit committed unsigned; returns the governance hash at HEAD."""
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weaker"))
    repo.commit("weaken a rule")
    return human_gate.governance_tree_hash(repo.root, "HEAD")


# ── 1. nothing the agent can type is an approval ─────────────────────────────

@needs_signing
def test_a_forged_trailer_on_an_unsigned_commit_is_not_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "unsigned")

@needs_signing
def test_a_commit_signed_by_a_key_outside_the_base_allowed_signers_is_not_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["other"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "untrusted_signature")

@needs_signing
def test_adding_the_attackers_key_to_allowed_signers_on_the_branch_does_not_make_it_trusted(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    repo.write("allowed_signers", hg.allowed_signers_text(keys["human_pub"], keys["other_pub"]))
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["other"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "untrusted_signature")

@needs_signing
def test_a_valid_signature_over_another_governance_state_is_not_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {'0' * 64}\n", sign_key=keys["human"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "hash_mismatch")

@needs_signing
def test_a_signed_commit_with_no_trailer_is_not_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit("looks fine to me", sign_key=keys["human"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "no_trailer")

@needs_signing
def test_a_signed_trailer_from_an_allowed_key_is_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    commit = repo.commit(f"approve governance\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code, result.commit) == (True, "ok", commit)
    assert result.signer and result.signer.startswith("SHA256:")

@needs_signing
@pytest.mark.parametrize("line", ["Aegis-Accept: rule-x", "aegis-accept: rule-x", "  Aegis-Accept : rule-x"])
def test_the_reserved_aegis_accept_line_voids_an_otherwise_valid_approval(tmp_path, keys, line):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\n{line}\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "accept_reserved")

@needs_signing
def test_the_reserved_line_in_the_body_voids_it_too(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Accept: x\n\nmore prose\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    assert human_gate.verify_approval(repo.root, "HEAD", digest, "main").code == "accept_reserved"

@needs_signing
def test_two_conflicting_approve_trailers_are_not_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {digest}\nAegis-Approve: {'1' * 64}\n", sign_key=keys["human"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "multiple_trailers")

@needs_signing
def test_the_base_must_carry_allowed_signers(tmp_path, keys):
    repo = hg.make_repo(tmp_path, signer_pub=None)
    repo.write("allowed_signers", hg.allowed_signers_text(keys["human_pub"]))
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    result = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (result.valid, result.code) == (False, "no_allowed_signers")

@needs_signing
def test_an_unresolvable_commit_is_an_error_not_an_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    result = human_gate.verify_approval(repo.root, "nonesuch", "0" * 64, "main")
    assert (result.valid, result.code) == (False, "unresolved")

@needs_signing
def test_find_approval_scans_the_branch_and_returns_the_valid_one(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"fake\n\nAegis-Approve: {digest}\n", allow_empty=True)
    good = repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    found = human_gate.find_approval(repo.root, "HEAD", "main")
    assert found is not None and found.valid and found.commit == good

@needs_signing
def test_a_later_governance_change_voids_an_earlier_approval(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=keys["human"], allow_empty=True)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weakest"))
    repo.commit("one more weakening")
    assert human_gate.find_approval(repo.root, "HEAD", "main") is None


@needs_signing
def test_verify_insight_approval_binds_to_signed_commit_and_insight_text_hash(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    text_a = "Always pass timeout to subprocess.run in aegis_core."
    text_b = "Never use eval on untrusted input in aegis_core."
    digest_a = human_gate.insight_text_hash(text_a)
    sha = repo.commit(
        f"chore: approve insight\n\n{human_gate.INSIGHT_APPROVE_TRAILER}: {digest_a}\n",
        sign_key=keys["human"],
        allow_empty=True,
    )
    ok_verdict = human_gate.verify_insight_approval(repo.root, sha, text_a, "main")
    assert ok_verdict.valid and ok_verdict.ok
    mismatch = human_gate.verify_insight_approval(repo.root, sha, text_b, "main")
    assert not mismatch.valid and not mismatch.ok and mismatch.code == "hash_mismatch"


class _ReviewsGh(hg.FakeGh):
    def __init__(self, reviews, **kw):
        super().__init__(**kw)
        self.reviews = reviews

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        if "/pulls/" in argv[-1]:
            self.calls.append((tuple(argv), stdin))
            return human_gate.GhResult(0, json.dumps(self.reviews), "")
        return super().__call__(argv, stdin, cwd)


@needs_git
def test_a_review_approves_only_where_the_ruleset_makes_it_the_merge_gate(tmp_path):
    """Given a base CODEOWNERS that owns the changed rule and a non-author's APPROVED review of the head,
    When the ruleset requires an approval, code-owner review, stale-review dismissal and the last push's
    approval by someone else (tier A), Then the review is the approval; When any of the four is missing,
    Then it is not, and the reviews are never read."""
    repo = hg.make_repo(tmp_path)
    repo.git("checkout", "-q", "main")
    repo.write(".github/CODEOWNERS", hg.CODEOWNERS_FULL)
    base = repo.commit("protect")
    head = "a" * 40
    pull = human_gate.PullRequest(3, "agent", head, "main")
    approving = [{"user": {"login": "human", "type": "User"}, "state": "APPROVED", "commit_id": head,
                  "author_association": "OWNER"}]
    paths = [".aegis/rules/traps/trap-sample.md"]
    gh = _ReviewsGh(approving, rules=[hg.pull_request_rule(last_push=True)])
    verdict = human_gate.find_review_approval(repo.root, pull, base, paths, gh=gh)
    assert verdict is not None and verdict.valid and (verdict.source, verdict.signer, verdict.commit) == ("review", "human", head)
    # The ruleset doctor --github proposes for tier A is such a merge gate.
    gh = _ReviewsGh(approving, rules=human_gate.build_ruleset("A", ["aegis-check"])["rules"])
    assert human_gate.find_review_approval(repo.root, pull, base, paths, gh=gh) is not None
    absent = hg.pull_request_rule(last_push=True)
    del absent["parameters"]["require_last_push_approval"]
    # Without require_last_push_approval whoever pushed the last commit may be the approving reviewer.
    for rule in (hg.pull_request_rule(approvals=0, last_push=True), hg.pull_request_rule(code_owners=False, last_push=True),
                 hg.pull_request_rule(dismiss_stale=False, last_push=True), hg.pull_request_rule(last_push=False), absent):
        gh = _ReviewsGh(approving, rules=[rule])
        assert human_gate.find_review_approval(repo.root, pull, base, paths, gh=gh) is None
        assert not any("/pulls/" in c[0][-1] for c in gh.calls) and gh.posts == []
    # The base branch is the pull request's, checked again here: a name in doubt reads nothing.
    for ref in ("", "../main", "main?x", "a b", None):
        gh = _ReviewsGh(approving, rules=[hg.pull_request_rule(last_push=True)])
        assert human_gate.find_review_approval(repo.root, pull._replace(base_ref=ref), base, paths, gh=gh) is None
        assert gh.calls == []


# ── 1b. an approval is an SSH signature, checked against the base allowed_signers ──
#
# git takes a signature's format from its armor, not from gpg.format, so a PGP or X.509
# signature is checked by gpg.program / gpg.x509.program (which a repository's config can
# set) and allowed_signers is never read. Given a base with allowed_signers, a weakened rule
# and an approval commit carrying a correct Aegis-Approve trailer, When its signature is not
# an SSH signature, Then it is never an approval and no program the repository names runs.

PGP = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PGP SIGNATURE-----\n"
X509 = "-----BEGIN SIGNED MESSAGE-----\nMIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkq\n-----END SIGNED MESSAGE-----\n"
SSH_STUB = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg\n-----END SSH SIGNATURE-----\n"


def _approval_commit(repo: hg.Repo) -> str:
    """On ``work``: a weakened rule, then an unsigned empty commit carrying the Aegis-Approve trailer."""
    digest = _changed_rule_branch(repo)
    repo.commit(human_gate.approval_message(digest), allow_empty=True)
    return digest


def _carry_signature(repo: hg.Repo, *signatures: tuple) -> str:
    """Rewrite HEAD (``work``) to carry ``(header, armor)`` signature headers without signing anything."""
    raw = subprocess.run(["git", "cat-file", "commit", "HEAD"], cwd=repo.root, capture_output=True,
                         check=True).stdout.decode()
    head, _, body = raw.partition("\n\n")
    block = ""
    for header, armor in signatures:
        first, *rest = armor.rstrip("\n").split("\n")
        block += f"{header} {first}\n" + "".join(f" {line}\n" for line in rest)
    forged = subprocess.run(["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=repo.root,
                            input=(head + "\n" + block.rstrip("\n") + "\n\n" + body).encode(),
                            capture_output=True, check=True).stdout.decode().strip()
    subprocess.run(["git", "update-ref", "refs/heads/work", forged], cwd=repo.root, check=True)
    return forged


def _recording_signer(tmp_path: Path):
    """A program that answers like a gpg that found a good, fully trusted signature, and records that it ran."""
    marker, program = tmp_path / "ran", tmp_path / "fake-gpg.sh"
    program.write_bytes((
        f'#!/bin/sh\necho ran >> "{marker}"\n'
        'echo "[GNUPG:] NEWSIG"\necho "[GNUPG:] GOODSIG AAAAAAAAAAAAAAAA human"\n'
        'echo "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-01-01 0 4 0 1 10 00 '
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\necho "[GNUPG:] TRUST_ULTIMATE 0 pgp"\nexit 0\n').encode())
    program.chmod(program.stat().st_mode | stat.S_IXUSR)
    return program, marker


@posix_only
@needs_signing
@pytest.mark.parametrize("config_key, armor", [
    pytest.param("gpg.program", PGP, id="pgp-program"),
    pytest.param("gpg.openpgp.program", PGP, id="pgp-openpgp"),
    pytest.param("gpg.x509.program", X509, id="x509"),
])
def test_a_repository_cannot_turn_a_non_ssh_signature_into_an_approval(tmp_path, keys, config_key, armor):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _approval_commit(repo)
    _carry_signature(repo, ("gpgsig", armor))
    program, marker = _recording_signer(tmp_path)
    repo.git("config", "--local", config_key, str(program))
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert not marker.exists(), "the program the repository chose was run"
    assert (verdict.valid, verdict.code) == (False, "bad_signature")
    assert human_gate.find_approval(repo.root, "HEAD", "main", governance_hash=digest) is None


@posix_only
@needs_signing
def test_test_exemptions_and_insight_approvals_refuse_a_non_ssh_signature_too(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    program, marker = _recording_signer(tmp_path)
    repo.git("config", "--local", "gpg.program", str(program))
    fix = repo.commit("fix: hotfix\n\nAegis-No-Test: verified manually", allow_empty=True)
    repo.commit(human_gate.exemption_message(fix, "verified manually"), allow_empty=True)
    _carry_signature(repo, ("gpgsig", PGP))
    exemption = human_gate.verify_test_exemption(repo.root, "HEAD", fix, "main")
    text = "Always pass a timeout to subprocess.run."
    repo.commit(f"approve\n\n{human_gate.INSIGHT_APPROVE_TRAILER}: {human_gate.insight_text_hash(text)}\n",
                allow_empty=True)
    _carry_signature(repo, ("gpgsig", PGP))
    insight = human_gate.verify_insight_approval(repo.root, "HEAD", text, "main")
    assert not marker.exists()
    assert (exemption.valid, exemption.code) == (insight.valid, insight.code) == (False, "bad_signature")


@posix_only
@needs_signing
def test_a_user_level_gpg_program_does_not_make_a_pgp_signature_an_approval(tmp_path, keys):
    """The user's own gpg config is not the repository's, but allowed_signers is the only list of approvers."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _approval_commit(repo)
    _carry_signature(repo, ("gpgsig", PGP))
    program, marker = _recording_signer(tmp_path)
    repo.home.config("gpg.program", str(program))
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert not marker.exists()
    assert (verdict.valid, verdict.code) == (False, "bad_signature")


@posix_only
@needs_signing
def test_a_signature_header_git_ignores_cannot_hide_a_pgp_one(tmp_path, keys):
    """A sha1 repository's git reads ``gpgsig``; an SSH-looking ``gpgsig-sha256`` header ahead of it is not the signature."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _approval_commit(repo)
    _carry_signature(repo, ("gpgsig-sha256", SSH_STUB), ("gpgsig", PGP))
    program, marker = _recording_signer(tmp_path)
    repo.git("config", "--local", "gpg.program", str(program))
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert not marker.exists()
    assert not verdict.valid


@posix_only
@needs_signing
def test_the_signature_programs_are_not_looked_up_on_a_path_the_repository_can_plant_on(tmp_path, monkeypatch, keys):
    """A bare program name (``false``, git's default ``gpg``) is looked up on PATH from the work
    tree, where a relative or empty PATH entry finds a program the repository planted."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _approval_commit(repo)
    _carry_signature(repo, ("gpgsig", PGP))
    program, marker = _recording_signer(tmp_path)
    for name in ("false", "gpg", "gpgsm"):
        planted = repo.root / name
        planted.write_bytes(program.read_bytes())
        planted.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", os.environ["PATH"]]))
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert not marker.exists()
    assert not verdict.valid
    # the git call itself, so the neutralised programs hold even without the armor check
    signers = hg.allowed_signers_text(keys["human_pub"]).encode()
    status, _fingerprint = human_gate._signature(repo.root, repo.head(), signers)
    assert status != "G" and not marker.exists()


def _planted_ssh_keygen(repo: hg.Repo, tmp_path: Path) -> Path:
    """``<repo>/bin/ssh-keygen``: records that it ran and fails. Returns the marker path."""
    marker = tmp_path / "planted-ran"
    planted = repo.root / "bin" / "ssh-keygen"
    planted.parent.mkdir()
    planted.write_bytes(f'#!/bin/sh\necho ran >> "{marker}"\nexit 1\n'.encode())
    planted.chmod(0o755)
    return marker


@posix_only
@needs_signing
def test_ssh_keygen_inside_the_repository_is_never_the_signature_program(tmp_path, monkeypatch, keys):
    """Given PATH whose first absolute entry is ``<repo>/bin`` holding an ``ssh-keygen`` and the
    system one later on PATH, When an approval is verified and one is signed, Then the planted
    program never runs and both use the system ssh-keygen."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(human_gate.approval_message(digest), sign_key=keys["human"], allow_empty=True)
    repo.home.sign_with(str(keys["human"]))
    marker = _planted_ssh_keygen(repo, tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join([str(repo.root / "bin"), os.environ["PATH"]]))
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (verdict.valid, verdict.code) == (True, "ok"), verdict
    signed = human_gate.signed_empty_commit(repo.root, human_gate.approval_message(digest))
    assert human_gate.verify_approval(repo.root, signed, digest, "main").valid
    assert not marker.exists()


@posix_only
@needs_signing
def test_with_ssh_keygen_only_inside_the_repository_approvals_are_refused(tmp_path, monkeypatch, keys):
    """Given PATH holding only ``<repo>/bin/ssh-keygen`` (and git, outside the repository), When an
    approval is verified or signed, Then it is unverifiable or refused as "not installed", and the
    planted program never runs."""
    import shutil
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(human_gate.approval_message(digest), sign_key=keys["human"], allow_empty=True)
    repo.home.sign_with(str(keys["human"]))
    marker = _planted_ssh_keygen(repo, tmp_path)
    git_only = tmp_path / "git-only"
    git_only.mkdir()
    try:
        os.symlink(shutil.which("git"), git_only / "git")
    except OSError:
        pytest.skip("cannot make a symlink here")
    monkeypatch.setenv("PATH", os.pathsep.join([str(repo.root / "bin"), str(git_only)]))
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (verdict.valid, verdict.code) == (False, "unverifiable")
    assert "ssh-keygen is not installed" in verdict.reason
    with pytest.raises(human_gate.HumanGateError, match="ssh-keygen is not installed"):
        human_gate.signed_empty_commit(repo.root, human_gate.approval_message(digest))
    assert not marker.exists()


@posix_only
@needs_git
def test_log_show_signature_in_a_repository_config_does_not_run_the_repositorys_program(tmp_path):
    """Plain ``git log --format`` checks signatures under log.showSignature; no gitsafe call may
    reach a program the repository's config names."""
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)
    repo.commit("a subject", allow_empty=True)
    oid = _carry_signature(repo, ("gpgsig", PGP))
    program, marker = _recording_signer(tmp_path)
    repo.git("config", "--local", "gpg.program", str(program))
    repo.git("config", "--local", "log.showSignature", "true")
    res = gitsafe.run(["log", "-1", "--format=%s", oid], repo.root)
    assert not marker.exists()
    assert res.returncode == 0 and res.stdout.decode().strip() == "a subject"


@needs_signing
def test_log_show_signature_in_the_users_config_does_not_reject_a_genuine_approval(tmp_path, keys):
    """Under log.showSignature git prints its check before the --format text; the verdict must not read that text."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(human_gate.approval_message(digest), sign_key=keys["human"], allow_empty=True)
    repo.home.config("log.showSignature", "true")
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (verdict.valid, verdict.code) == (True, "ok")


@needs_signing
def test_ssh_verdicts_keep_their_codes_beside_the_ssh_only_check(tmp_path, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.commit(human_gate.approval_message(digest), sign_key=keys["human"], allow_empty=True)
    good = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (good.valid, good.code) == (True, "ok") and good.signer
    repo.commit(human_gate.approval_message(digest) + "\n", sign_key=keys["other"], allow_empty=True)
    assert human_gate.verify_approval(repo.root, "HEAD", digest, "main").code == "untrusted_signature"
    repo.commit(human_gate.approval_message(digest) + "\n\n", allow_empty=True)
    assert human_gate.verify_approval(repo.root, "HEAD", digest, "main").code == "unsigned"


@needs_signing
def test_a_genuine_ssh_approval_verifies_in_a_sha256_repository(tmp_path, monkeypatch, keys):
    """A SHA-256 repository names the signature header ``gpgsig-sha256``; the SSH-only check follows it."""
    monkeypatch.setenv("GIT_DEFAULT_HASH", "sha256")
    try:
        repo = hg.make_repo(tmp_path, keys["human_pub"])
    except subprocess.CalledProcessError:
        pytest.skip("this git cannot make a SHA-256 repository")
    if repo.git("rev-parse", "--show-object-format") != "sha256":
        pytest.skip("this git cannot make a SHA-256 repository")
    digest = _changed_rule_branch(repo)
    repo.commit(human_gate.approval_message(digest), sign_key=keys["human"], allow_empty=True)
    verdict = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert (verdict.valid, verdict.code) == (True, "ok")

# ── 2. Tier C is self-attested ───────────────────────────────────────────────

@needs_git
def test_tier_c_says_self_attested_in_text_and_json(tmp_path):
    repo = hg.make_repo(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=lambda argv, stdin=None, cwd=None, timeout=None: None)
    assert report.tier == "C" and report.label == "self-attested"
    assert "self-attested" in report.text_lines()[0]
    doc = report.as_dict()
    assert doc["tier"] == "C" and doc["label"] == "self-attested"
    for key in ("source", "aegis_version", "checked_at", "scope"): assert doc[key]

@needs_git
def test_doctor_prints_the_tier_on_every_report(tmp_path, monkeypatch):
    from aegis_cli import doctor
    repo = hg.make_repo(tmp_path)
    monkeypatch.setattr(human_gate, "default_gh_runner", lambda argv, stdin=None, cwd=None, timeout=None: None)
    args = argparse.Namespace(workspace=str(repo.root), fix=False, yes=False, drivers=False, json=False, github=False, apply=False, tier=None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out): doctor.run_doctor(args)
    assert "Trust tier (human_gate): C" in out.getvalue() and "self-attested" in out.getvalue()
    args.json = True
    out = io.StringIO()
    with contextlib.redirect_stdout(out): doctor.run_doctor(args)
    payload = json.loads(out.getvalue())
    assert payload["human_gate"]["tier"] == "C" and payload["human_gate"]["label"] == "self-attested"
    assert all(h["trust_tier"] == "C" for h in payload["hosts"])


# ── 3. --apply never changes repository settings without a person at a terminal ──

def _doctor_github(repo: hg.Repo, monkeypatch, gh: hg.FakeGh, answers=None, tty=False, workflow=True, **kw):
    from aegis_cli import doctor
    if workflow:
        repo.write(".github/workflows/aegis.yml", hg.AEGIS_WORKFLOW if workflow is True else workflow)
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    monkeypatch.setattr(doctor, "_stdin_is_tty", lambda: tty)
    replies = iter(answers or [])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
    args = argparse.Namespace(workspace=str(repo.root), fix=False, yes=False, drivers=False, json=False, github=True, apply=False, tier=None)
    for key, value in kw.items(): setattr(args, key, value)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err): rc = doctor.run_doctor(args)
    return rc, out.getvalue(), err.getvalue()

@needs_git
@pytest.mark.parametrize("yes", [False, True])
def test_apply_without_a_terminal_refuses_and_posts_nothing(tmp_path, monkeypatch, yes):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh()
    rc, out, err = _doctor_github(repo, monkeypatch, gh, tty=False, apply=True, tier="B", yes=yes)
    assert rc != 0 and gh.posts == [] and "terminal" in (out + err)

@needs_git
def test_apply_with_a_terminal_asks_and_a_no_posts_nothing(tmp_path, monkeypatch):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh()
    rc, out, _err = _doctor_github(repo, monkeypatch, gh, answers=["n"], tty=True, apply=True, tier="B")
    assert rc != 0 and gh.posts == [] and "No changes made" in out

@needs_git
def test_apply_with_a_terminal_and_a_yes_creates_exactly_the_printed_ruleset(tmp_path, monkeypatch):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh()
    rc, _out, _err = _doctor_github(repo, monkeypatch, gh, answers=["y"], tty=True, apply=True, tier="B")
    assert rc == 0
    ((argv, body),) = gh.posts
    assert argv[:3] == ("api", "--method", "POST") and "rulesets" in argv[3]
    sent, printed = json.loads(body), human_gate.build_ruleset("B", ["aegis-check"])
    assert sent == printed and sent["enforcement"] == "active" and sent["bypass_actors"] == []

@needs_git
def test_apply_never_overwrites_a_ruleset_of_the_same_name(tmp_path, monkeypatch):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh(rulesets=[{"id": 3, "name": human_gate.RULESET_NAME}])
    rc, out, err = _doctor_github(repo, monkeypatch, gh, answers=["y"], tty=True, apply=True, tier="B")
    assert rc != 0 and gh.posts == [] and "already exists" in (out + err)

@needs_git
def test_apply_refuses_when_there_is_no_workflow_job_to_require(tmp_path, monkeypatch):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh()
    rc, out, err = _doctor_github(repo, monkeypatch, gh, answers=["y"], tty=True, workflow=False, apply=True, tier="B")
    assert rc != 0 and gh.posts == [] and "workflow" in out + err

@needs_git
def test_github_prints_both_rulesets_the_codeowners_lines_and_the_signing_setup(tmp_path, monkeypatch):
    repo = hg.make_repo(tmp_path)
    rc, out, _err = _doctor_github(repo, monkeypatch, hg.FakeGh())
    assert rc == 0
    for needle in ("Ruleset, tier A", "Ruleset, tier B", '"required_approving_review_count": 1', "~DEFAULT_BRANCH",
                   "/.aegis/rules/ @octo", "conftest.py @octo", "allowed_signers", "gpg.format ssh", "aegis approve", "Trust tier (human_gate): C",
                   "integration_id"):
        assert needle in out, needle

@needs_git
def test_github_codeowners_for_an_organization_repository_name_a_team_not_the_org(tmp_path, monkeypatch):
    repo = hg.make_repo(tmp_path)
    rc, out, _err = _doctor_github(repo, monkeypatch, hg.FakeGh(owner="acme", owner_type="Organization"))
    assert rc == 0
    assert "conftest.py @OWNER-OR-@org/team" in out and "team" in out
    assert not [line for line in out.splitlines() if line.rstrip().endswith(" @acme")]


@needs_git
def test_github_json_carries_the_envelope_and_applies_nothing(tmp_path, monkeypatch):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh()
    rc, out, _err = _doctor_github(repo, monkeypatch, gh, json=True)
    doc = json.loads(out)
    assert rc == 0 and doc["status"] == "printed" and gh.posts == []
    assert doc["github"]["ruleset"]["B"] == human_gate.build_ruleset("B", doc["github"]["required_checks"])
    for key in ("source", "aegis_version", "checked_at", "scope"): assert doc[key]

@needs_git
def test_apply_without_github_is_a_usage_error(tmp_path, monkeypatch):
    from aegis_cli import doctor
    repo = hg.make_repo(tmp_path)
    args = argparse.Namespace(workspace=str(repo.root), fix=False, yes=False, drivers=False, json=False, github=False, apply=True, tier="B")
    err = io.StringIO()
    with contextlib.redirect_stderr(err): assert doctor.run_doctor(args) == 2
    assert "--github" in err.getvalue()

# ── 4. aegis approve ─────────────────────────────────────────────────────────

def _approve(repo: hg.Repo, monkeypatch, tty=True, answer="y", **kw):
    from aegis_cli import approve
    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: tty)
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)
    args = argparse.Namespace(workspace=str(repo.root), json=False, base=None)
    for key, value in kw.items(): setattr(args, key, value)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err): rc = approve.run_approve(args)
    return rc, out.getvalue(), err.getvalue()

@needs_signing
def test_approve_makes_one_signed_empty_commit_naming_the_hash_it_approved(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    before = repo.head()
    key_bytes = {p: p.read_bytes() for p in (keys["human"], Path(str(keys["human"]) + ".pub"))}
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 0, out + err
    assert digest in out and repo.git("rev-parse", "HEAD~1") == before
    assert repo.git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD") == ""
    assert f"Aegis-Approve: {digest}" in repo.git("log", "-1", "--format=%B")
    verified = human_gate.verify_approval(repo.root, "HEAD", digest, "main")
    assert verified.valid, verified
    assert {p: p.read_bytes() for p in key_bytes} == key_bytes
    assert sorted(p.name for p in keys["human"].parent.iterdir()) == sorted(["human", "human.pub", "intruder", "intruder.pub"])

@needs_signing
def test_approve_refuses_when_nothing_governance_related_changed(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.commit("ordinary change")
    repo.home.sign_with(str(keys["human"]))
    before = repo.head()
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 1 and repo.head() == before and "nothing governance-related changed" in out + err

@needs_signing
def test_approve_without_a_terminal_refuses(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    before = repo.head()
    rc, out, err = _approve(repo, monkeypatch, tty=False)
    assert rc == 1 and repo.head() == before and "terminal" in out + err

@needs_signing
def test_approve_declined_at_the_prompt_commits_nothing(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    before = repo.head()
    rc, out, _err = _approve(repo, monkeypatch, answer="n")
    assert rc == 1 and repo.head() == before and "No approval" in out

@needs_signing
def test_approve_refuses_staged_changes_so_the_approval_commit_stays_empty(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    repo.write("src/app.py", "def app():\n    return 3\n")
    repo.git("add", "src/app.py")
    before = repo.head()
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 1 and repo.head() == before and "staged" in out + err

@needs_signing
def test_approve_refuses_uncommitted_governance_changes(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "dirty"))
    before = repo.head()
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 1 and repo.head() == before and "uncommitted" in out + err

@needs_signing
def test_approve_needs_ssh_signing_configured_at_user_scope(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _changed_rule_branch(repo)
    before = repo.head()
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 1 and repo.head() == before and "gpg.format" in out + err

@needs_signing
@pytest.mark.parametrize("signing", [None, "openpgp"], ids=["no-key", "openpgp"])
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_approve_without_an_ssh_signing_key_is_refused_no_key(tmp_path, monkeypatch, keys, signing, exempt):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _changed_rule_branch(repo)
    if signing:
        repo.home.sign_with("ABCDEF0123456789", fmt=signing)
    before = repo.head()
    extra = {"exempt_test": before, "reason": "by hand"} if exempt else {}
    rc, out, _err = _approve(repo, monkeypatch, json=True, **extra)
    assert rc == 1 and repo.head() == before
    assert json.loads(out)["code"] == "no_key"

@posix_only
@needs_signing
def test_a_repository_cannot_choose_the_signing_program(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    marker, program = tmp_path / "ran", tmp_path / "evil.sh"
    program.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
    program.chmod(0o755)
    _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    repo.git("config", "--local", "gpg.ssh.program", str(program))
    repo.git("config", "--local", "user.signingkey", str(keys["other"]))
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 0, out + err
    assert not marker.exists()
    digest = human_gate.governance_tree_hash(repo.root, "HEAD")
    assert human_gate.verify_approval(repo.root, "HEAD", digest, "main").valid

@needs_signing
def test_approve_json_carries_the_envelope(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    digest = _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    rc, out, err = _approve(repo, monkeypatch, json=True)
    assert "Sign an approval" in err and "Sign an approval" not in out, "the question goes to stderr, not the JSON"
    doc = json.loads(out)
    assert rc == 0 and doc["status"] == "approved" and doc["governance_tree_hash"] == digest
    assert doc["commit"] == repo.head() and doc["categories"] == ["rules"]
    for key in ("source", "aegis_version", "checked_at", "scope"): assert doc[key]

def _tests_on_main(repo: hg.Repo) -> None:
    """``main`` gains tests/test_a.py and tests/test_b.py; ``work`` is reset onto it."""
    repo.git("checkout", "-q", "main")
    repo.write("tests/test_a.py", "def test_a():\n    assert True\n")
    repo.write("tests/test_b.py", "def test_b():\n    assert True\n")
    repo.commit("tests")
    repo.git("checkout", "-q", "-B", "work")


@needs_signing
def test_a_branch_that_only_deletes_a_test_can_be_approved_and_a_further_deletion_voids_it(tmp_path, monkeypatch, keys):
    """Given a signer on main and a branch that only deletes tests/test_a.py, When aegis approve
    runs with a terminal and y, Then the approval binds the deletion: it verifies, and deleting
    tests/test_b.py afterwards voids it (hash_mismatch)."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _tests_on_main(repo)
    repo.git("rm", "-q", "tests/test_a.py")
    repo.commit("drop a test")
    repo.home.sign_with(str(keys["human"]))
    rc, out, err = _approve(repo, monkeypatch, json=True)
    doc = json.loads(out)
    assert rc == 0 and doc["categories"] == ["tests-deleted"], out + err
    digest = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    assert digest != human_gate.governance_tree_hash(repo.root, "HEAD")
    assert f"Aegis-Approve: {digest}" in repo.git("log", "-1", "--format=%B")
    approval = repo.head()
    found = human_gate.find_approval(repo.root, "HEAD", "main")
    assert found is not None and found.valid
    repo.git("rm", "-q", "tests/test_b.py")
    repo.commit("drop another")
    assert human_gate.find_approval(repo.root, "HEAD", "main") is None
    now = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    assert tuple(human_gate.verify_approval(repo.root, approval, now, "main")[:2]) == (False, "hash_mismatch")


@needs_signing
def test_an_approved_rule_change_does_not_cover_a_test_deleted_later(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _tests_on_main(repo)
    _changed_rule_branch(repo)
    repo.home.sign_with(str(keys["human"]))
    rc, out, err = _approve(repo, monkeypatch)
    assert rc == 0, out + err
    assert human_gate.find_approval(repo.root, "HEAD", "main") is not None
    repo.git("rm", "-q", "tests/test_a.py")
    repo.commit("then drop a test")
    assert human_gate.find_approval(repo.root, "HEAD", "main") is None


@needs_signing
def test_credit_honours_an_approved_deletion_until_another_test_is_deleted(tmp_path, monkeypatch, keys):
    from aegis_core import credit

    repo = hg.make_repo(tmp_path, keys["human_pub"])
    _tests_on_main(repo)
    base = repo.head()
    repo.git("rm", "-q", "tests/test_a.py")
    checked = repo.commit("drop a test")
    repo.home.sign_with(str(keys["human"]))
    assert _approve(repo, monkeypatch)[0] == 0
    rows = [{"event": "check", "id": "c1", "tree": "t", "head": checked, "base": base}]
    assert credit.approval_lookup(repo.root, rows, landed=lambda tree, head=None: checked)("c1") is True
    repo.git("rm", "-q", "tests/test_b.py")
    later = repo.commit("drop another")
    assert credit.approval_lookup(repo.root, rows, landed=lambda tree, head=None: later)("c1") is False


@needs_signing
def test_approve_exempt_test_signs_and_verifies_commit_scoped_exemption(tmp_path, monkeypatch, keys):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    repo.write("src/app.py", "def app():\n    return 2\n")
    fix_oid = repo.commit("fix: hotfix app\n\nAegis-No-Test: verified manually")
    repo.home.sign_with(str(keys["human"]))
    rc_missing, _out_m, err_m = _approve(repo, monkeypatch, exempt_test=fix_oid, reason=None)
    assert rc_missing == 2 and "--reason" in err_m
    rc, out, err = _approve(repo, monkeypatch, exempt_test=fix_oid, reason="checked by hand, no test possible")
    assert rc == 0, out + err
    assert fix_oid in out
    verdict = human_gate.verify_test_exemption(repo.root, "HEAD", fix_oid, "main")
    assert verdict.valid and "checked by hand" in verdict.reason, verdict


def test_approve_reason_help_says_it_is_signed_not_matched(capsys):
    from aegis_cli import cli
    with pytest.raises(SystemExit):
        cli.main(["approve", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "signed into the commit" in out and "must match" not in out


def _two_commits_sharing_a_prefix(repo: hg.Repo, width: int = 7) -> tuple:
    """Two commit objects whose ids share their first ``width`` hex digits (a birthday search)."""
    import hashlib
    if repo.git("rev-parse", "--show-object-format") != "sha1":
        pytest.skip("the prefix search builds SHA-1 commit ids")
    tree, parent = repo.git("rev-parse", "HEAD^{tree}"), repo.head()
    seen: dict = {}
    for nonce in range(1 << 21):
        body = (f"tree {tree}\nparent {parent}\nauthor A <a@example.com> 1700000000 +0000\n"
                f"committer A <a@example.com> 1700000000 +0000\n\nfix: attempt {nonce}\n").encode()
        oid = hashlib.sha1(b"commit %d\0" % len(body) + body).hexdigest()
        first = seen.setdefault(oid[:width], body)
        if first is not body:
            # bytes, not text: a Windows text-mode pipe would turn LF into CRLF and git would reject the object
            return tuple(subprocess.run(["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=repo.root, input=b,
                                        capture_output=True, check=True).stdout.decode().strip() for b in (first, body))
    pytest.skip("no shared prefix found")


@needs_signing
def test_a_short_prefix_exemption_names_no_commit_not_even_one_ground_to_share_it(tmp_path, keys):
    """Given two commits whose ids share their first 7 hex digits and a signed exemption naming only
    that prefix, When either is checked as the fix commit, Then neither is exempted; the full id
    exempts exactly the commit it names."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    intended, ground = _two_commits_sharing_a_prefix(repo)
    assert intended != ground and intended[:7] == ground[:7]
    short = repo.commit(f"chore: approve\n\nAegis-Exempt-Test: {intended[:7]} reviewed by hand\n",
                        sign_key=keys["human"], allow_empty=True)
    for fix in (intended, ground):
        verdict = human_gate.verify_test_exemption(repo.root, short, fix, "main")
        assert not verdict.valid and verdict.code in ("no_exemption_trailer", "commit_mismatch"), verdict
    full = repo.commit(human_gate.exemption_message(intended, "reviewed by hand"), sign_key=keys["human"], allow_empty=True)
    assert human_gate.verify_test_exemption(repo.root, full, intended, "main").valid
    assert human_gate.verify_test_exemption(repo.root, full, ground, "main").code == "commit_mismatch"


@needs_signing
@pytest.mark.parametrize("body, code", [
    ("Aegis-Exempt-Test: {other} reviewed\n", "commit_mismatch"),
    ("Aegis-Exempt-Test: {fix} reviewed\nAegis-Exempt-Test: {fix} again\n", "multiple_trailers"),
    ("Aegis-Accept: x\nAegis-Exempt-Test: {fix} reviewed\n", "accept_reserved"),
], ids=["other", "two", "accept"])
def test_a_signed_exemption_for_another_commit_twice_or_beside_a_reserved_line_is_refused(tmp_path, keys, body, code):
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    other = repo.head()
    repo.write("src/app.py", "def app():\n    return 2\n")
    fix = repo.commit("fix: hotfix app\n\nAegis-No-Test: by hand")
    approval = repo.commit("chore: approve\n\n" + body.format(fix=fix, other=other), sign_key=keys["human"],
                           allow_empty=True)
    verdict = human_gate.verify_test_exemption(repo.root, approval, fix, "main")
    assert (verdict.valid, verdict.code) == (False, code)


@needs_signing
def test_find_test_exemption_never_takes_the_fix_commit_as_its_own_approval(tmp_path, monkeypatch, keys):
    """Given a signed fix commit on the branch that carries an Aegis-Exempt-Test line, When the branch
    is scanned for its exemption, Then no verdict computed or returned is for the fix commit itself."""
    repo = hg.make_repo(tmp_path, keys["human_pub"])
    repo.write("src/app.py", "def app():\n    return 2\n")
    fix = repo.commit(f"fix: hotfix app\n\nAegis-Exempt-Test: {repo.head()} self\n", sign_key=keys["human"])
    seen = []
    real = human_gate.verify_test_exemption

    def spy(*args, **kw):
        verdict = real(*args, **kw)
        seen.append(verdict.commit)
        return verdict

    monkeypatch.setattr(human_gate, "verify_test_exemption", spy)
    assert human_gate.find_test_exemption(repo.root, "HEAD", "main", fix) is None
    assert fix not in seen


@needs_git
@pytest.mark.parametrize("body", [
    "Aegis-Accept: whatever\n",
    "Aegis-Accept: x\nAegis-Exempt-Test: {other} reviewed\n",
], ids=["accept-only", "accept-beside-another-exemption"])
def test_a_reserved_line_in_a_commit_that_does_not_name_the_fix_is_no_rejected_exemption_of_it(tmp_path, body):
    """Given a test-less fix commit and a later commit with an Aegis-Accept line and no exemption naming
    that fix, When the branch is scanned for the fix's exemption, Then there is none, not a rejected one."""
    repo = hg.make_repo(tmp_path)
    other = repo.head()
    repo.write("src/app.py", "def app():\n    return 2\n")
    fix = repo.commit("fix: hotfix app\n\nAegis-No-Test: by hand")
    repo.commit("docs: unrelated\n\n" + body.format(other=other), allow_empty=True)
    assert human_gate.find_test_exemption(repo.root, "HEAD", "main", fix) is None

@needs_git
def test_github_json_requires_only_the_scaffold_aegis_job(tmp_path, monkeypatch):
    from aegis_core import scaffolding
    repo = hg.make_repo(tmp_path)
    repo.write(".github/workflows/lint.yml", "name: Lint\non: [pull_request]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n")
    rc, out, _err = _doctor_github(repo, monkeypatch, hg.FakeGh(), workflow=scaffolding.ci_workflow(), json=True)
    doc = json.loads(out)
    assert rc == 0 and doc["github"]["required_checks"] == ["aegis-check"]


@needs_git
def test_apply_refuses_an_aegis_job_whose_name_is_templated(tmp_path, monkeypatch):
    repo, gh = hg.make_repo(tmp_path), hg.FakeGh()
    templated = ("name: Aegis\non: [pull_request]\njobs:\n  aegis:\n    name: 'Aegis (${{ github.event_name }})'\n"
                 "    steps:\n      - run: aegis check --ci\n")
    rc, out, err = _doctor_github(repo, monkeypatch, gh, answers=["y"], tty=True, workflow=templated, apply=True, tier="B")
    assert rc != 0 and gh.posts == []
    assert "literal name" in out + err

# ── 5. the Aegis-Test-Change trailer authorizes nothing ──────────────────────

@needs_git
def test_the_aegis_test_change_trailer_is_not_an_exemption_in_the_lane_gate(tmp_path):
    repo = hg.make_repo(tmp_path)
    repo.write("tests/test_app.py", "def test_a():\n    assert 1\n\n\ndef test_b():\n    assert 2\n")
    repo.git("checkout", "-q", "main")
    repo.commit("tests on base")
    repo.git("checkout", "-q", "-B", "work")
    repo.write("tests/test_app.py", "def test_a():\n    assert 1\n")
    repo.commit("drop a test\n\nAegis-Test-Change: the test was redundant\n")
    result = lane_gate.check_lane(repo.root, "docs", base="main", paths=["**"])
    assert not result.passed and [(f.kind, f.name) for f in result.findings] == [("removed", "test_b")]
    assert lane_gate.NOTE_EXEMPTION in result.text_lines()

# ── 6. file modes of the shared state ────────────────────────────────────────

def _mode(path: Path) -> int: return stat.S_IMODE(os.stat(path).st_mode)

@posix_only
@needs_git
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_the_shared_state_is_private_whatever_the_umask(tmp_path, umask):
    repo = hg.make_repo(tmp_path)
    old = os.umask(umask)
    try:
        site = storage.ledger_site(repo.root)
        storage.append_jsonl(site.path, [{"v": 2, "k": 1}])
        with storage.ledger_locked(repo.root): pass
        shared = storage.shared_state_dir(repo.root)
        storage.append_jsonl(shared / "events.jsonl", [{"v": 1}])
        with storage.shared_locked(repo.root, "events.lock"): pass
    finally:
        os.umask(old)
    entries = [shared, *shared.rglob("*")]
    assert len(entries) >= 6
    for path in entries:
        want = 0o700 if path.is_dir() else 0o600
        assert _mode(path) == want, f"{path.relative_to(shared)} is {oct(_mode(path))}"

@posix_only
@needs_git
def test_modes_report_counts_looser_entries_and_tightening_fixes_them(tmp_path):
    repo = hg.make_repo(tmp_path)
    site, shared = storage.ledger_site(repo.root), storage.shared_state_dir(repo.root)
    storage.append_jsonl(site.path, [{"v": 2}])
    os.chmod(site.path, 0o644); os.chmod(site.path.parent, 0o755)
    report = storage.shared_state_modes(repo.root)
    assert report.looser == 2 and report.checked >= 3 and report.fixed == 0
    assert "ledger" not in json.dumps(report.as_dict()), "counts only, never names"
    fixed = storage.shared_state_modes(repo.root, fix=True)
    assert fixed.looser == 2 and fixed.fixed == 2 and storage.shared_state_modes(repo.root).looser == 0
    assert _mode(site.path) == 0o600 and _mode(site.path.parent) == 0o700 and shared.is_dir()

@posix_only
@needs_git
def test_tightening_never_follows_a_symlink_out_of_the_state(tmp_path):
    repo = hg.make_repo(tmp_path)
    shared, outside = storage.shared_state_dir(repo.root), tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8"); os.chmod(outside, 0o644)
    os.symlink(outside, shared / "link")
    with pytest.raises(Exception): storage.shared_state_modes(repo.root, fix=True)
    assert _mode(outside) == 0o644

@posix_only
@needs_git
def test_doctor_reports_how_many_entries_are_looser_without_naming_them(tmp_path, monkeypatch):
    from aegis_cli import doctor
    repo = hg.make_repo(tmp_path)
    (repo.root / ".aegis").mkdir(exist_ok=True)
    site = storage.ledger_site(repo.root)
    storage.append_jsonl(site.path, [{"v": 2}])
    os.chmod(site.path, 0o644)
    monkeypatch.setattr(human_gate, "default_gh_runner", lambda argv, stdin=None, cwd=None, timeout=None: None)
    args = argparse.Namespace(workspace=str(repo.root), fix=False, yes=False, drivers=False, json=True, github=False, apply=False, tier=None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out): doctor.run_doctor(args)
    payload = json.loads(out.getvalue())
    assert payload["state_modes"]["looser"] == 1 and "ledger.jsonl" not in json.dumps(payload["state_modes"])

@posix_only
def test_doctor_counts_nothing_looser_in_a_workspace_outside_git(tmp_path, monkeypatch):
    """R-cli-39: Given a non-git workspace whose local state the umask made 0755/0644, When
    doctor runs, Then it reports no looser entry (the standard covers the git common dir only)."""
    from aegis_cli import doctor
    ws = tmp_path / "ws"
    (ws / ".aegis" / "rules" / "traps").mkdir(parents=True)
    old = os.umask(0o022)
    try:
        storage.append_jsonl(storage.state_dir(ws) / "ledger.jsonl", [{"v": 2}])
        with storage.locked(ws): pass
    finally:
        os.umask(old)
    monkeypatch.setattr(human_gate, "default_gh_runner", lambda argv, stdin=None, cwd=None, timeout=None: None)
    args = argparse.Namespace(workspace=str(ws), fix=False, yes=False, drivers=False, json=True, github=False, apply=False, tier=None)
    out = io.StringIO()
    with contextlib.redirect_stdout(out): doctor.run_doctor(args)
    assert json.loads(out.getvalue())["state_modes"]["looser"] == 0

@posix_only
@needs_git
def test_migrate_apply_tightens_the_shared_state(tmp_path):
    from aegis_cli import migrate as cli_migrate
    repo = hg.make_repo(tmp_path)
    (repo.root / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    site = storage.ledger_site(repo.root)
    storage.append_jsonl(site.path, [{"v": 2}])
    os.chmod(site.path, 0o666)
    args = argparse.Namespace(workspace=str(repo.root), apply=True, dry_run=False, json=True)
    out = io.StringIO()
    with contextlib.redirect_stdout(out): cli_migrate.run_migrate(args)
    report = json.loads(out.getvalue())
    assert report["state_modes"]["fixed"] >= 1 and _mode(site.path) == 0o600
