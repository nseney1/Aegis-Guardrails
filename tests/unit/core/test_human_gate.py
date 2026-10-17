"""human_gate: tier detection, CODEOWNERS coverage, signing-key custody, the governance tree hash.

gh is faked at its runner boundary (hg.FakeGh); git and ssh-keygen are real.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_core import human_gate, governance
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
needs_signing = pytest.mark.skipif(not hg.signing_ok(), reason="needs git >= 2.34 and ssh-keygen")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)


# ── CODEOWNERS coverage ──────────────────────────────────────────────────────

def test_the_full_codeowners_covers_every_governance_sample():
    covered, uncovered = human_gate.codeowners_coverage(hg.CODEOWNERS_FULL)
    assert uncovered == [] and covered


def test_the_codeowners_lines_doctor_prints_cover_the_whole_set_it_checks():
    text = "\n".join(human_gate.codeowners_lines("@octo"))
    for location in (".github/CODEOWNERS", "CODEOWNERS"):
        assert human_gate.codeowners_coverage(text, location)[1] == []


@pytest.mark.parametrize("text", ["", "# only a comment\n", "*.txt @octo\n", "/src/ @octo\n"])
def test_a_codeowners_that_misses_the_set_leaves_it_uncovered(text):
    _covered, uncovered = human_gate.codeowners_coverage(text)
    assert ".aegis/rules/trap/sample.md" in uncovered


def test_the_last_matching_entry_wins_and_an_entry_with_no_owner_unprotects():
    text = hg.CODEOWNERS_FULL + "/.aegis/rules/\n"
    _covered, uncovered = human_gate.codeowners_coverage(text)
    assert ".aegis/rules/trap/sample.md" in uncovered
    assert ".aegis/config.json" not in uncovered


def test_a_single_star_does_not_cross_a_directory_as_the_matcher_of_target_paths_does():
    # /.aegis/* covers direct children only on GitHub; the rules live two levels down.
    text = hg.CODEOWNERS_FULL.replace("/.aegis/rules/ @octo\n", "/.aegis/* @octo\n")
    _covered, uncovered = human_gate.codeowners_coverage(text)
    assert ".aegis/rules/trap/sample.md" in uncovered
    assert ".aegis/config.json" not in uncovered


def test_owners_must_look_like_owners():
    text = hg.CODEOWNERS_FULL.replace("@octo", "nobody-handle")
    _covered, uncovered = human_gate.codeowners_coverage(text)
    assert uncovered, "a token that is not @user, @org/team or an email owns nothing"
    ok = hg.CODEOWNERS_FULL.replace("@octo", "owner@example.com")
    assert human_gate.codeowners_coverage(ok)[1] == []


def test_a_hostile_codeowners_is_bounded():
    evil = "/" + "*a" * 200 + "b @octo\n" + ("x " * 100000) + "\n" + "/a/b/" * 5000 + " @o\n"
    covered, uncovered = human_gate.codeowners_coverage(evil)
    assert uncovered, "no pattern of it covers the set, and reading it does not hang"


def test_codeowners_coverage_includes_tracked_repo_paths_and_fails_closed_on_negation_or_invalid_override():
    partial = hg.CODEOWNERS_FULL.replace("/.github/workflows/ @octo\n", "/.github/workflows/ci.yml @org/sec\n")
    _cov, uncov = human_gate.codeowners_coverage(
        partial, ".github/CODEOWNERS", repo_paths=(".github/workflows/validate.yml",)
    )
    assert ".github/workflows/validate.yml" in uncov

    for suffix in (
        "/.github/workflows/validate.yml\n",
        "/.github/workflows/validate.yml invalid-owner-token\n",
        "!/.github/workflows/validate.yml @org/sec\n",
        "/.github/workflows/[v]alidate.yml @org/sec\n",
    ):
        _cov2, uncov2 = human_gate.codeowners_coverage(
            "* @org/sec\n" + suffix, ".github/CODEOWNERS", repo_paths=(".github/workflows/validate.yml",)
        )
        assert ".github/workflows/validate.yml" in uncov2, f"expected uncovered for {suffix!r}"


# ── signing-key custody ──────────────────────────────────────────────────────

@needs_signing
def test_a_plain_private_key_is_plain_file_custody(tmp_path):
    key, _pub = hg.keygen(tmp_path / "k", "plain")
    home = hg.Home(tmp_path / "home")
    home.sign_with(str(key))
    custody = human_gate.check_key_custody(tmp_path)
    assert custody.status == "plain_file" and custody.degrades


@needs_signing
def test_a_passphrase_protected_private_key_is_acceptable(tmp_path):
    key, _pub = hg.keygen(tmp_path / "k", "locked", passphrase="correct horse")
    home = hg.Home(tmp_path / "home")
    home.sign_with(str(key))
    custody = human_gate.check_key_custody(tmp_path)
    assert custody.status == "passphrase" and not custody.degrades


@needs_signing
def test_a_public_key_beside_a_plain_private_file_is_still_plain_file(tmp_path):
    key, _pub = hg.keygen(tmp_path / "k", "plain")
    home = hg.Home(tmp_path / "home")
    home.sign_with(str(key) + ".pub")
    assert human_gate.check_key_custody(tmp_path).status == "plain_file"


@needs_git
def test_a_security_key_public_literal_is_hardware_custody(tmp_path):
    home = hg.Home(tmp_path / "home")
    home.sign_with("key::" + hg.hardware_public_key())
    custody = human_gate.check_key_custody(tmp_path)
    assert custody.status == "hardware" and not custody.degrades


@needs_git
def test_a_public_key_with_the_private_half_held_elsewhere_is_agent_custody_unverified(tmp_path):
    _key, pub = hg.keygen(tmp_path / "k", "agentheld")
    home = hg.Home(tmp_path / "home")
    home.sign_with("key::" + pub)
    custody = human_gate.check_key_custody(tmp_path)
    assert custody.status == "agent" and not custody.degrades
    assert "unverified" in custody.detail


@needs_git
def test_no_signing_key_and_other_formats_are_reported_as_such(tmp_path):
    assert human_gate.check_key_custody(tmp_path).status == "none"
    home = hg.Home(tmp_path / "home")
    home.sign_with("ABCDEF0123456789", fmt="openpgp")
    custody = human_gate.check_key_custody(tmp_path)
    assert custody.status == "unsupported" and custody.degrades


@needs_git
def test_a_repository_cannot_declare_a_hardware_key_for_the_user(tmp_path):
    repo = hg.make_repo(tmp_path)
    key, _pub = hg.keygen(tmp_path / "k", "plain")
    repo.home.sign_with(str(key))
    repo.git("config", "--local", "user.signingkey", "key::" + hg.hardware_public_key())
    assert human_gate.check_key_custody(repo.root).status == "plain_file"


# ── tier detection ───────────────────────────────────────────────────────────

def _repo_with_governance(tmp_path, signer_pub=None, codeowners=hg.CODEOWNERS_FULL) -> hg.Repo:
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "project", home)
    repo.write("README.md", "# p\n")
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    if signer_pub:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    if codeowners:
        repo.write(".github/CODEOWNERS", codeowners)
    repo.commit("base")
    repo.branch("work")
    return repo


@needs_git
def test_tier_a_needs_reviews_code_owners_checks_codeowners_coverage_and_a_non_admin_identity(tmp_path):
    repo = _repo_with_governance(tmp_path)
    gh = hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "A", report.reasons
    assert report.evidence["rules"]["required_approving_review_count"] == 1
    assert report.evidence["identity"]["admin"] is False
    assert report.evidence["codeowners"]["uncovered"] == []


@needs_git
def test_an_admin_identity_cannot_be_tier_a(tmp_path):
    repo = _repo_with_governance(tmp_path)
    gh = hg.FakeGh(admin=True, rules=[hg.pull_request_rule(), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "C"
    assert any("admin" in reason for reason in report.reasons)


@needs_git
@pytest.mark.parametrize("rules", [
    [hg.checks_rule()],
    [hg.pull_request_rule(approvals=0), hg.checks_rule()],
    [hg.pull_request_rule(code_owners=False), hg.checks_rule()],
    [hg.pull_request_rule()],
])
def test_each_missing_ruleset_requirement_blocks_tier_a(tmp_path, rules):
    repo = _repo_with_governance(tmp_path)
    assert human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules)).tier != "A"


@needs_git
def test_uncovered_governance_files_block_tier_a(tmp_path):
    repo = _repo_with_governance(tmp_path, codeowners="/docs/ @octo\n")
    gh = hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "C"
    assert report.evidence["codeowners"]["uncovered"]
    assert report.codeowners_complete is False


@needs_git
def test_tracked_workflow_outside_sample_or_unowned_override_blocks_tier_a(tmp_path):
    partial_co = hg.CODEOWNERS_FULL.replace("/.github/workflows/ @octo\n", "/.github/workflows/ci.yml @org/sec\n")
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "project", home)
    repo.write("README.md", "# p\n")
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.write(".github/workflows/validate.yml", "name: Validate\non: [push]\n")
    repo.write(".github/CODEOWNERS", partial_co)
    repo.commit("base")
    repo.branch("work")
    gh = hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier != "A"
    assert report.codeowners_complete is False
    assert ".github/workflows/validate.yml" in report.evidence["codeowners"]["uncovered"]

    for override in ("/.github/workflows/validate.yml\n", "!/.github/workflows/validate.yml\n"):
        repo.git("checkout", "-q", "main")
        repo.write(".github/CODEOWNERS", "* @org/sec\n" + override)
        repo.commit("override codeowners")
        repo.git("checkout", "-q", "work")
        rep2 = human_gate.detect_tier(repo.root, gh=gh)
        assert rep2.tier != "A"
        assert rep2.codeowners_complete is False
        assert ".github/workflows/validate.yml" in rep2.evidence["codeowners"]["uncovered"]


@needs_signing
def test_tier_b_is_checks_plus_signers_on_base_plus_adequate_custody(tmp_path):
    _key, pub = hg.keygen(tmp_path / "k", "human")
    repo = _repo_with_governance(tmp_path, signer_pub=pub, codeowners=None)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
    assert report.tier == "B", report.reasons
    assert report.evidence["allowed_signers"]["keys"] == 1
    assert report.evidence["key_custody"]["status"] == "hardware"


@needs_signing
def test_tier_b_degrades_to_c_and_says_why_when_the_key_is_a_plain_file(tmp_path):
    key, pub = hg.keygen(tmp_path / "k", "human")
    repo = _repo_with_governance(tmp_path, signer_pub=pub, codeowners=None)
    repo.home.sign_with(str(key))
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
    assert report.tier == "C" and report.label == "self-attested"
    assert any("plain" in reason for reason in report.reasons)
    assert report.evidence["key_custody"]["status"] == "plain_file"


@needs_signing
def test_allowed_signers_must_be_on_the_base_not_only_in_the_working_tree(tmp_path):
    repo = _repo_with_governance(tmp_path, codeowners=None)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    _key, pub = hg.keygen(tmp_path / "k", "human")
    repo.write("allowed_signers", hg.allowed_signers_text(pub))
    repo.commit("add signers on the branch only")
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
    assert report.tier == "C"
    assert report.evidence["allowed_signers"]["keys"] == 0


@needs_git
def test_without_required_status_checks_there_is_no_tier_b(tmp_path):
    _key, pub = hg.keygen(tmp_path / "k", "human") if hg.signing_ok() else (None, "ssh-ed25519 AAAA x")
    repo = _repo_with_governance(tmp_path, signer_pub=pub, codeowners=None)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    assert human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[])).tier == "C"


@needs_git
def test_no_gh_is_tier_c_with_the_reason_and_no_network_call(tmp_path):
    repo = _repo_with_governance(tmp_path)
    gh = hg.FakeGh()
    gh.missing = True
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "C" and gh.calls == []
    assert any("gh" in reason for reason in report.reasons)
    assert report.evidence["gh"]["available"] is False


@needs_git
def test_a_failing_gh_is_tier_c_not_a_crash(tmp_path):
    repo = _repo_with_governance(tmp_path)

    def failing(argv, stdin=None, cwd=None):
        return human_gate.GhResult(1, "", "HTTP 404: Not Found")

    report = human_gate.detect_tier(repo.root, gh=failing)
    assert report.tier == "C"
    assert any("404" in reason for reason in report.reasons)


@needs_git
def test_unparseable_gh_output_is_tier_c(tmp_path):
    repo = _repo_with_governance(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=lambda argv, stdin=None, cwd=None: human_gate.GhResult(0, "<html>", ""))
    assert report.tier == "C"


def test_outside_a_repository_is_tier_c(tmp_path):
    report = human_gate.detect_tier(tmp_path, gh=hg.FakeGh())
    assert report.tier == "C"
    assert any("repository" in reason for reason in report.reasons)


@needs_git
def test_detection_only_issues_get_requests(tmp_path):
    repo = _repo_with_governance(tmp_path)
    gh = hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()])
    human_gate.detect_tier(repo.root, gh=gh)
    assert gh.calls and set(gh.methods) == {"GET"}
    assert gh.posts == []


@needs_git
def test_detection_writes_nothing_into_the_repository(tmp_path):
    repo = _repo_with_governance(tmp_path)
    before = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if ".git/" not in p.as_posix())
    human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
    after = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if ".git/" not in p.as_posix())
    assert before == after


@needs_git
def test_the_report_dict_carries_the_envelope_and_the_evidence(tmp_path):
    repo = _repo_with_governance(tmp_path)
    doc = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()])).as_dict()
    assert doc["source"] and doc["aegis_version"] and doc["scope"]["workspace"]
    assert doc["checked_at"].endswith("Z") and len(doc["checked_at"]) == 20
    assert set(doc["evidence"]) >= {"gh", "repo", "rules", "codeowners", "allowed_signers", "key_custody", "identity"}


# ── the governance tree hash ─────────────────────────────────────────────────

@needs_git
def test_the_hash_moves_with_governance_files_and_only_with_them(tmp_path):
    repo = hg.make_repo(tmp_path)
    base = human_gate.governance_tree_hash(repo.root, "HEAD")
    assert len(base) == 64 and set(base) <= set("0123456789abcdef")
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.commit("ordinary")
    assert human_gate.governance_tree_hash(repo.root, "HEAD") == base
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "other"))
    repo.commit("rule")
    changed = human_gate.governance_tree_hash(repo.root, "HEAD")
    assert changed != base
    repo.git("revert", "--no-edit", "HEAD")
    assert human_gate.governance_tree_hash(repo.root, "HEAD") == base


@needs_git
def test_deleting_a_governance_file_changes_the_hash(tmp_path):
    repo = hg.make_repo(tmp_path)
    repo.write("conftest.py", "x = 1\n")
    repo.commit("add conftest")
    with_it = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.git("rm", "-q", "conftest.py")
    repo.commit("remove conftest")
    assert human_gate.governance_tree_hash(repo.root, "HEAD") != with_it


@needs_git
def test_an_unresolvable_revision_is_an_error(tmp_path):
    repo = hg.make_repo(tmp_path)
    with pytest.raises(human_gate.HumanGateError):
        human_gate.governance_tree_hash(repo.root, "nonesuch")


@needs_git
def test_the_hash_is_the_same_in_every_checkout_of_the_same_tree(tmp_path):
    repo = hg.make_repo(tmp_path)
    clone = tmp_path / "clone"
    hg.run_git(tmp_path, "clone", "-q", str(repo.root), str(clone))
    assert human_gate.governance_tree_hash(clone, "origin/work") == human_gate.governance_tree_hash(repo.root, "work")


# ── the ruleset ──────────────────────────────────────────────────────────────

def test_ruleset_variants_differ_in_reviews_only():
    a, b = human_gate.build_ruleset("A", ["validate", "test-windows"]), human_gate.build_ruleset("B", ["validate"])
    by_type = lambda ruleset: {r["type"]: r.get("parameters", {}) for r in ruleset["rules"]}  # noqa: E731
    assert by_type(a)["pull_request"]["required_approving_review_count"] == 1
    assert by_type(a)["pull_request"]["require_code_owner_review"] is True
    assert by_type(b)["pull_request"]["required_approving_review_count"] == 0
    assert [c["context"] for c in by_type(a)["required_status_checks"]["required_status_checks"]] == [
        "validate", "test-windows"]
    for ruleset in (a, b):
        assert ruleset["bypass_actors"] == [] and ruleset["enforcement"] == "active"
        assert ruleset["name"] == human_gate.RULESET_NAME
        assert {"non_fast_forward", "deletion"} <= {r["type"] for r in ruleset["rules"]}
    with pytest.raises(ValueError):
        human_gate.build_ruleset("C", ["x"])


def test_workflow_job_contexts_come_from_the_workflow_files(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: CI\non: [push]\njobs:\n  lint:\n    runs-on: ubuntu-latest\n  tests:\n    name: Unit tests\n"
        "    runs-on: ubuntu-latest\n", encoding="utf-8")
    assert human_gate.workflow_contexts(tmp_path) == ["lint", "Unit tests"]
    assert human_gate.workflow_contexts(tmp_path / "none") == []
