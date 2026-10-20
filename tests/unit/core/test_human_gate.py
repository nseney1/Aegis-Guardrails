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


def test_every_coverage_sample_is_a_governance_path():
    assert [s for s in human_gate.COVERAGE_SAMPLES if governance.category_of(s) is None] == []
    assert {"pytest.py", "pytest/__init__.py", "iniconfig.py", "py/__init__.py"} <= set(human_gate.COVERAGE_SAMPLES)


def test_a_codeowners_that_owns_only_the_source_init_of_a_runner_package_leaves_it_uncovered():
    """Given CODEOWNERS lines that own ``/pytest/__init__.py`` but not the package directory, When
    coverage is checked, Then a compiled ``__init__`` and the ``__main__`` of that package are uncovered."""
    narrow = hg.CODEOWNERS_FULL.replace("/pytest/ @octo\n", "/pytest/__init__.py @octo\n")
    _covered, uncovered = human_gate.codeowners_coverage(narrow)
    assert {"pytest/__init__.pyc", "pytest/__main__.py"} <= set(uncovered)
    assert "pytest/__init__.py" not in uncovered


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
    assert custody.status == "unsupported" and not custody.degrades


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


def _tier_b_repo(tmp_path) -> hg.Repo:
    repo = _repo_with_governance(tmp_path, signer_pub=hg.hardware_public_key(), codeowners=None)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    return repo


def _check(context, **source):
    return {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": context, **source}]}}


@needs_git
@pytest.mark.parametrize("source", [{}, {"integration_id": None}, {"integration_id": 0}, {"integration_id": -1},
                                    {"integration_id": True}, {"integration_id": "15368"}],
                         ids=["absent", "null", "zero", "negative", "bool", "string"])
def test_a_required_check_any_writer_can_post_is_not_tier_b(tmp_path, source):
    """Given allowed_signers on the base, a security key, and a ruleset whose only required check has no
    integer app id as its source, When the tier is detected, Then it is C and the reason names the
    check, integration_id and the GitHub Actions app id."""
    repo = _tier_b_repo(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[_check("aegis-check", **source)]))
    assert report.tier == "C"
    assert report.evidence["rules"]["unpinned_status_checks"] == ["aegis-check"]
    reason = next(r for r in report.reasons if "integration_id" in r)
    assert "aegis-check" in reason and "15368" in reason and "write access" in reason


@needs_git
def test_one_unpinned_check_beside_a_pinned_one_is_still_not_tier_b(tmp_path):
    repo = _tier_b_repo(tmp_path)
    rules = [hg.checks_rule("aegis-check"), hg.checks_rule("coverage", integration_id=None)]
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules))
    assert report.tier == "C" and report.evidence["rules"]["unpinned_status_checks"] == ["coverage"]
    twice = [hg.checks_rule("aegis-check"), hg.checks_rule("aegis-check", integration_id=None)]
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=twice))
    assert report.tier == "C" and report.evidence["rules"]["unpinned_status_checks"] == ["aegis-check"]


@needs_git
def test_a_check_pinned_to_any_app_keeps_tier_b(tmp_path):
    repo = _tier_b_repo(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule("aegis-check", integration_id=4242)]))
    assert report.tier == "B", report.reasons
    assert report.evidence["rules"]["unpinned_status_checks"] == []


@needs_git
def test_tier_a_with_an_unpinned_check_stays_a_with_a_caveat(tmp_path):
    repo = _repo_with_governance(tmp_path)
    rules = [hg.pull_request_rule(), hg.checks_rule("aegis-check", integration_id=None)]
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules))
    assert report.tier == "A", report.reasons
    assert any("aegis-check" in c and "integration_id" in c for c in report.caveats), report.caveats


@pytest.mark.parametrize("tier", ["A", "B"])
def test_the_ruleset_pins_every_required_check_to_github_actions(tier):
    ruleset = human_gate.build_ruleset(tier, ["aegis-check", "Unit tests"])
    (checks,) = [r["parameters"]["required_status_checks"] for r in ruleset["rules"] if r["type"] == "required_status_checks"]
    assert checks == [{"context": "aegis-check", "integration_id": 15368}, {"context": "Unit tests", "integration_id": 15368}]
    assert human_gate.GITHUB_ACTIONS_APP_ID == 15368


@needs_git
def test_the_tier_b_ruleset_doctor_prints_reads_back_as_tier_b(tmp_path):
    repo = _tier_b_repo(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=human_gate.build_ruleset("B", ["aegis-check"])["rules"]))
    assert report.tier == "B", report.reasons


@needs_git
@pytest.mark.parametrize("signing", [None, "openpgp"], ids=["no-key", "openpgp"])
def test_no_ssh_signing_key_on_this_machine_is_a_tier_b_caveat_not_a_downgrade(tmp_path, signing):
    """Given allowed_signers on the base, a required check, and (a) no user.signingkey or (b) an
    OpenPGP signing format, When the tier is detected, Then it is B and a caveat says aegis approve
    cannot be run here."""
    repo = _repo_with_governance(tmp_path, signer_pub=hg.hardware_public_key(), codeowners=None)
    if signing:
        repo.home.sign_with("ABCDEF0123456789", fmt=signing)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
    assert report.tier == "B", report.reasons
    assert any("no SSH signing key is configured on this machine" in c and "aegis approve" in c
               for c in report.caveats), report.caveats
    assert report.evidence["key_custody"]["degrades"] is False


@needs_git
def test_a_configured_signing_key_carries_the_not_compared_with_allowed_signers_caveat(tmp_path):
    repo = _repo_with_governance(tmp_path, signer_pub=hg.hardware_public_key(), codeowners=None)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
    assert report.tier == "B", report.reasons
    assert "the local signing key is not compared with the keys in allowed_signers" in report.caveats


def test_approve_says_what_it_reads_of_a_key():
    from aegis_cli import approve
    doc = " ".join((approve.__doc__ or "").split())
    assert "reads at most the first 64 KiB of a key file to classify its protection" in doc
    assert "it never copies, prints or stores it" in doc
    assert "create, copy or read a key" not in doc


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


# At tier B (no required review) the required checks run the pull request's own workflow and
# aegis, so a pull request can edit the check that verifies the signature (R-trust-12).
_PR_OWN_WORKFLOW = "required checks run the pull request's own workflow and aegis"


@needs_git
def test_tier_b_says_a_pull_request_can_edit_the_check_that_verifies_the_signature(tmp_path):
    """Given required status checks, 0 required approvals and a security key in the base
    allowed_signers, When the tier is detected, Then it is B and the report, text and JSON,
    says the required checks run the pull request's own workflow and aegis."""
    repo = _repo_with_governance(tmp_path, signer_pub=hg.hardware_public_key(), codeowners=None)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    gh = hg.FakeGh(rules=[hg.pull_request_rule(approvals=0), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "B", report.reasons
    found = [c for c in report.caveats if c.startswith(_PR_OWN_WORKFLOW)]
    assert len(found) == 1, report.caveats
    caveat = found[0]
    assert ".github/workflows/**" in caveat and "signature" in caveat
    assert f"  ! {caveat}" in report.text_lines() and caveat in report.as_dict()["caveats"]


@needs_git
@pytest.mark.parametrize("tier", ["A", "C"])
def test_tiers_a_and_c_carry_no_pull_request_workflow_caveat(tmp_path, tier):
    repo = _repo_with_governance(tmp_path, codeowners=hg.CODEOWNERS_FULL if tier == "A" else None)
    rules = [hg.pull_request_rule(), hg.checks_rule()] if tier == "A" else [hg.checks_rule()]
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules))
    assert report.tier == tier, report.reasons
    assert not [c for c in report.caveats if _PR_OWN_WORKFLOW in c]


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
def test_a_rule_edit_in_a_nested_workspace_moves_the_hash(tmp_path):
    repo = hg.Repo(tmp_path / "mono", hg.Home(tmp_path / "home"))
    repo.write("README.md", "# mono\n")
    repo.write("pkg/.aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.commit("base")
    before = human_gate.governance_tree_hash(repo.root / "pkg", "HEAD")
    repo.write("pkg/.aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "other"))
    repo.commit("rule")
    assert human_gate.governance_tree_hash(repo.root / "pkg", "HEAD") != before


def _with_tests(tmp_path) -> hg.Repo:
    repo = hg.make_repo(tmp_path)
    repo.git("checkout", "-q", "main")
    repo.write("tests/test_a.py", "def test_a():\n    assert True\n")
    repo.write("tests/test_b.py", "def test_b():\n    assert True\n")
    repo.commit("tests")
    repo.git("checkout", "-q", "-B", "work")
    return repo


@needs_git
def test_with_no_deleted_test_the_hash_against_a_base_is_the_v1_digest(tmp_path):
    import hashlib

    repo = _with_tests(tmp_path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    repo.commit("ordinary")
    rule = ".aegis/rules/traps/trap-sample.md"
    oid = repo.git("rev-parse", f"HEAD:{rule}")
    expected = hashlib.sha256(b"aegis-governance-tree/v1\n" + f"100644 {oid} {rule}\n".encode()).hexdigest()
    assert human_gate.governance_tree_hash(repo.root, "HEAD", base="main") == expected
    assert human_gate.governance_tree_hash(repo.root, "HEAD") == expected


@needs_git
def test_the_hash_against_a_base_binds_exactly_the_tests_deleted_since_it(tmp_path):
    repo = _with_tests(tmp_path)
    plain = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    repo.git("rm", "-q", "README.md")
    repo.commit("drop the readme")
    assert human_gate.governance_tree_hash(repo.root, "HEAD", base="main") == plain
    repo.git("rm", "-q", "tests/test_a.py")
    repo.commit("drop a")
    drop_a = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    assert drop_a != plain and human_gate.governance_tree_hash(repo.root, "HEAD") == plain
    repo.git("checkout", "-q", "main", "--", "tests/test_a.py")
    repo.commit("restore a")
    assert human_gate.governance_tree_hash(repo.root, "HEAD", base="main") == plain
    repo.git("rm", "-q", "tests/test_b.py")
    repo.commit("drop b")
    assert human_gate.governance_tree_hash(repo.root, "HEAD", base="main") not in (plain, drop_a)


@needs_git
def test_a_version_bump_in_pyproject_moves_the_hash_because_the_whole_blob_is_digested(tmp_path):
    repo = hg.make_repo(tmp_path)
    repo.write("pyproject.toml", '[project]\nname = "x"\nversion = "1.0.0"\n')
    repo.commit("pyproject")
    before = human_gate.governance_tree_hash(repo.root, "HEAD")
    repo.write("pyproject.toml", '[project]\nname = "x"\nversion = "1.0.1"\n')
    repo.commit("bump")
    assert human_gate.governance_tree_hash(repo.root, "HEAD") != before


@needs_git
def test_an_unresolvable_base_is_an_error(tmp_path):
    repo = _with_tests(tmp_path)
    with pytest.raises(human_gate.HumanGateError):
        human_gate.governance_tree_hash(repo.root, "HEAD", base="nonesuch")


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
