"""human_gate: tier detection, signing-key custody, the governance tree hash.

gh is faked at its runner boundary (hg.FakeGh); git and ssh-keygen are real.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_cli.formatters.text import render_tier
from aegis_core import codeowners as ownership
from aegis_core import ghcli, github_ruleset, human_gate
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


@needs_git
def test_a_codeowners_in_docs_holding_the_printed_lines_reaches_tier_a(tmp_path):
    repo = _repo_with_governance(tmp_path, codeowners=None)
    repo.git("checkout", "-q", "main")
    repo.write("docs/CODEOWNERS", "\n".join(ownership.codeowners_lines("@octo")) + "\n")
    repo.commit("codeowners in docs")
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()]))
    codeowners = report.evidence["codeowners"]
    assert (codeowners["present"], codeowners["path"], codeowners["uncovered"]) == (True, "docs/CODEOWNERS", [])
    assert report.tier == "A", report.reasons



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

def _repo_with_governance(tmp_path, signer_pub=None, codeowners=hg.CODEOWNERS_FULL, workflow=hg.AEGIS_WORKFLOW) -> hg.Repo:
    home = hg.Home(tmp_path / "home")
    repo = hg.Repo(tmp_path / "project", home)
    repo.write("README.md", "# p\n")
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    if signer_pub:
        repo.write("allowed_signers", hg.allowed_signers_text(signer_pub))
    if codeowners:
        repo.write(".github/CODEOWNERS", codeowners)
    if workflow:
        repo.write(".github/workflows/aegis.yml", workflow)
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
    [hg.pull_request_rule(dismiss_stale=False), hg.checks_rule()],
])
def test_each_missing_ruleset_requirement_blocks_tier_a(tmp_path, rules):
    repo = _repo_with_governance(tmp_path)
    assert human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules)).tier != "A"


@needs_git
@pytest.mark.parametrize("last_push", [False, True], ids=["plain", "last-push"])
def test_a_ruleset_that_keeps_stale_approvals_is_not_tier_a(tmp_path, last_push):
    """Given one approving review and code-owner review that keep an approval after new commits
    (even with require_last_push_approval), When the tier is detected, Then it is not A, the
    evidence says so and a reason names dismissal and new commits."""
    repo = _repo_with_governance(tmp_path)
    rules = [hg.pull_request_rule(dismiss_stale=False, last_push=last_push), hg.checks_rule()]
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules))
    assert report.tier != "A"
    assert report.evidence["rules"]["dismiss_stale_reviews_on_push"] is False
    assert any("dismiss" in r and "new commits" in r for r in report.reasons), report.reasons


@needs_git
@pytest.mark.parametrize("value", ["true", 1, None, "yes", [True], "absent"])
def test_only_a_literal_true_dismisses_stale_reviews(tmp_path, value):
    repo = _repo_with_governance(tmp_path)
    rule = hg.pull_request_rule(dismiss_stale=value)
    if value == "absent":
        del rule["parameters"]["dismiss_stale_reviews_on_push"]
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[rule, hg.checks_rule()]))
    assert report.tier != "A" and report.evidence["rules"]["dismiss_stale_reviews_on_push"] is False


@needs_git
@pytest.mark.parametrize("first, second, tier_a", [(False, False, False), (True, False, True), (False, True, True)])
def test_any_pull_request_rule_that_dismisses_stale_reviews_counts(tmp_path, first, second, tier_a):
    repo = _repo_with_governance(tmp_path)
    rules = [hg.pull_request_rule(dismiss_stale=first), hg.pull_request_rule(dismiss_stale=second), hg.checks_rule()]
    assert (human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=rules)).tier == "A") is tier_a


@needs_git
def test_the_tier_a_ruleset_doctor_prints_reads_back_as_tier_a(tmp_path):
    repo = _repo_with_governance(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=github_ruleset.build_ruleset("A", ["aegis-check"])["rules"]))
    assert report.tier == "A", report.reasons


@needs_git
def test_a_bare_organization_owner_covers_nothing_in_an_organization_repository(tmp_path):
    """Given an organization-owned repository whose CODEOWNERS names the bare ``@acme`` on every
    governance path, When the tier is detected, Then every path is uncovered, the tier is not A and a
    reason names the organization owner; with ``@acme/security`` the paths are covered."""
    repo = _repo_with_governance(tmp_path, codeowners=hg.CODEOWNERS_FULL.replace("@octo", "@acme"))
    gh = hg.FakeGh(owner="acme", owner_type="Organization", rules=[hg.pull_request_rule(), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier != "A" and report.evidence["codeowners"]["covered"] == []
    assert report.evidence["repo"]["owner"] == {"login": "acme", "type": "Organization"}
    assert any("@acme" in r and "team" in r for r in report.reasons), report.reasons
    team = _repo_with_governance(tmp_path / "team", codeowners=hg.CODEOWNERS_FULL.replace("@octo", "@ACME/security"))
    assert human_gate.detect_tier(team.root, gh=gh).tier == "A"


@needs_git
@pytest.mark.parametrize("owner, owner_type", [("alice", "User"), ("acme", None), ("acme", "missing")])
def test_a_user_owner_or_an_owner_of_unknown_type_still_counts(tmp_path, owner, owner_type):
    repo = _repo_with_governance(tmp_path, codeowners=hg.CODEOWNERS_FULL.replace("@octo", f"@{owner}"))
    fake = hg.FakeGh(owner=owner, owner_type=owner_type, rules=[hg.pull_request_rule(), hg.checks_rule()])

    def gh(argv, stdin=None, cwd=None):
        result = fake(argv, stdin, cwd)
        if owner_type == "missing" and argv[-1] == "repos/{owner}/{repo}":
            body = json.loads(result.stdout)
            del body["owner"]
            return ghcli.GhResult(0, json.dumps(body), "")
        return result

    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "A", report.reasons


@needs_git
def test_uncovered_governance_files_block_tier_a(tmp_path):
    repo = _repo_with_governance(tmp_path, codeowners="/docs/ @octo\n")
    gh = hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()])
    report = human_gate.detect_tier(repo.root, gh=gh)
    assert report.tier == "C"
    assert report.evidence["codeowners"]["present"] and report.evidence["codeowners"]["uncovered"]


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
    assert report.evidence["codeowners"]["present"] and report.evidence["codeowners"]["uncovered"]
    assert ".github/workflows/validate.yml" in report.evidence["codeowners"]["uncovered"]

    for override in ("/.github/workflows/validate.yml\n", "!/.github/workflows/validate.yml\n"):
        repo.git("checkout", "-q", "main")
        repo.write(".github/CODEOWNERS", "* @org/sec\n" + override)
        repo.commit("override codeowners")
        repo.git("checkout", "-q", "work")
        rep2 = human_gate.detect_tier(repo.root, gh=gh)
        assert rep2.tier != "A"
        assert rep2.evidence["codeowners"]["present"] and rep2.evidence["codeowners"]["uncovered"]
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


@needs_git
def test_the_tier_b_ruleset_doctor_prints_reads_back_as_tier_b(tmp_path):
    repo = _tier_b_repo(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=github_ruleset.build_ruleset("B", ["aegis-check"])["rules"]))
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
    assert f"  ! {caveat}" in render_tier(report.as_dict()) and caveat in report.as_dict()["caveats"]


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

    def failing(argv, stdin=None, cwd=None, timeout=None):
        return ghcli.GhResult(1, "", "HTTP 404: Not Found")

    report = human_gate.detect_tier(repo.root, gh=failing)
    assert report.tier == "C"
    assert any("404" in reason for reason in report.reasons)


@needs_git
def test_unparseable_gh_output_is_tier_c(tmp_path):
    repo = _repo_with_governance(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=lambda argv, stdin=None, cwd=None, timeout=None: ghcli.GhResult(0, "<html>", ""))
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


# ── R-trust-39: detect_tier reads one requirement table ──────────────────────

class _GridGh(hg.FakeGh):
    """FakeGh that can also fail the repository or the rules read, or leave the admin bit out."""

    def __init__(self, *args, unknown_admin=False, rules_fail=False, repo_fail=False, **kw):
        super().__init__(*args, **kw)
        self.unknown_admin, self.rules_fail, self.repo_fail = unknown_admin, rules_fail, repo_fail

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        path = list(argv)[-1]
        if self.repo_fail and path == "repos/{owner}/{repo}":
            return ghcli.GhResult(1, "", "HTTP 404: Not Found")
        if self.rules_fail and "/rules/branches/" in path:
            return ghcli.GhResult(1, "", "HTTP 403: Forbidden")
        result = super().__call__(argv, stdin, cwd, timeout)
        if self.unknown_admin and result is not None and path == "repos/{owner}/{repo}":
            body = json.loads(result.stdout)
            body["permissions"] = {"push": True}
            return ghcli.GhResult(0, json.dumps(body), "")
        return result


def _missing_gh() -> hg.FakeGh:
    gh = hg.FakeGh()
    gh.missing = True
    return gh


PR, CHK = hg.pull_request_rule, hg.checks_rule
FULL = hg.CODEOWNERS_FULL
# name: (gh, repository files, signing key: None, "hardware" or a key kind ssh-keygen makes)
TIER_GRID = {
    "a-full": (lambda: _GridGh(rules=[PR(), CHK()]), {}, None),
    "admin": (lambda: _GridGh(admin=True, rules=[PR(), CHK()]), {}, None),
    "admin-unknown": (lambda: _GridGh(unknown_admin=True, rules=[PR(), CHK()]), {}, None),
    "no-owners-review": (lambda: _GridGh(rules=[PR(code_owners=False), CHK()]), {}, None),
    "approvals-0": (lambda: _GridGh(rules=[PR(approvals=0), CHK()]), {}, None),
    "no-checks": (lambda: _GridGh(rules=[PR()]), {}, None),
    "stale-kept": (lambda: _GridGh(rules=[PR(dismiss_stale=False), CHK()]), {}, None),
    "unpinned-a": (lambda: _GridGh(rules=[PR(), CHK(integration_id=None)]), {}, None),
    "unpinned-c": (lambda: _GridGh(rules=[CHK(integration_id=None)]), {"codeowners": None}, None),
    "not-aegis-check": (lambda: _GridGh(rules=[PR(), CHK("other-job")]), {}, None),
    "rules-unreadable": (lambda: _GridGh(rules_fail=True), {}, None),
    "repo-unreadable": (lambda: _GridGh(repo_fail=True), {}, None),
    "gh-missing": (_missing_gh, {}, None),
    "bare-org": (lambda: _GridGh(rules=[PR(), CHK()], owner="acme", owner_type="Organization"),
                 {"codeowners": FULL.replace("@octo", "@acme")}, None),
    "co-partial": (lambda: _GridGh(rules=[PR(), CHK()]), {"codeowners": "/docs/ @octo\n"}, None),
    "co-absent": (lambda: _GridGh(rules=[PR(), CHK()]), {"codeowners": None}, None),
    "no-workflow": (lambda: _GridGh(rules=[PR(), CHK()]), {"workflow": None}, None),
    "b-hardware": (lambda: _GridGh(rules=[CHK()]), {"codeowners": None, "signer": True}, "hardware"),
    "signers-0": (lambda: _GridGh(rules=[CHK()]), {"codeowners": None}, None),
    "b-plain-custody": (lambda: _GridGh(rules=[CHK()]), {"codeowners": None, "signer": True}, "plain"),
    "b-passphrase": (lambda: _GridGh(rules=[CHK()]), {"codeowners": None, "signer": True}, "passphrase"),
}
KEYGEN_CASES = {"b-plain-custody", "b-passphrase"}


def _tier_case(tmp_path: Path, name: str):
    """(tier, reasons, digest of the rest of as_dict()) for one grid case; checked_at, the version and
    the workspace path are left out."""
    import hashlib

    gh, files, key = TIER_GRID[name]
    home = hg.Home(tmp_path / "home")
    pub = None
    if key == "hardware":
        pub = hg.hardware_public_key()
        home.sign_with("key::" + pub)
    elif key is not None:
        private, pub = hg.keygen(tmp_path / "keys", "human", passphrase="" if key == "plain" else "pw-123456")
        home.sign_with(str(private))
    repo = _repo_with_governance(tmp_path, signer_pub=pub if files.get("signer") else None,
                                 codeowners=files.get("codeowners", FULL), workflow=files.get("workflow", hg.AEGIS_WORKFLOW))
    doc = human_gate.detect_tier(repo.root, gh=gh()).as_dict()
    del doc["checked_at"], doc["aegis_version"]
    doc["scope"]["workspace"] = "<root>"
    rest = {k: v for k, v in doc.items() if k not in ("tier", "reasons")}
    return doc["tier"], doc["reasons"], hashlib.sha256(json.dumps(rest, sort_keys=True).encode("utf-8")).hexdigest()[:16]


# Recorded at lane/w9-A c12e70cb (after R-trust-36, before the table), admin wording updated.
GOLDEN_TIERS = {
    'a-full': ('A', [
    ], 'ca1674679f2070d4'),
    'admin': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: the gh identity doctor used is an admin: re-run with the token the agent would hold',
    ], '710e23b64c1a057d'),
    'admin-unknown': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: whether the gh identity is an admin is unknown',
    ], '1fed4721f978a121'),
    'approvals-0': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: the default branch does not require an approving review',
    ], 'f74ddb2d5fa91d75'),
    'b-hardware': ('B', [
        'not tier A: the default branch does not require an approving review',
        'not tier A: the default branch does not require code-owner review',
        'not tier A: the default branch keeps an approval after new commits are pushed, so a pull request can change after its review and still merge (set dismiss_stale_reviews_on_push)',
        'not tier A: no CODEOWNERS file on the base branch',
    ], '1bbf09668d3c52cd'),
    'b-passphrase': ('B', [
        'not tier A: the default branch does not require an approving review',
        'not tier A: the default branch does not require code-owner review',
        'not tier A: the default branch keeps an approval after new commits are pushed, so a pull request can change after its review and still merge (set dismiss_stale_reviews_on_push)',
        'not tier A: no CODEOWNERS file on the base branch',
    ], '159f0c1b3c7187db'),
    'b-plain-custody': ('C', [
        'the signing key human is a plain file with no passphrase, readable by this user: an agent running as you can sign with it, so a signature proves nothing',
        'not tier A: the default branch does not require an approving review',
        'not tier A: the default branch does not require code-owner review',
        'not tier A: the default branch keeps an approval after new commits are pushed, so a pull request can change after its review and still merge (set dismiss_stale_reviews_on_push)',
        'not tier A: no CODEOWNERS file on the base branch',
    ], 'b3e430ffe88fa5b6'),
    'bare-org': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: CODEOWNERS leaves 83 governance path(s) without an owner',
        'not tier A: CODEOWNERS names @acme, the organization that owns this repository, which GitHub ignores as a code owner: name a team (@acme/<team>) or people',
    ], '6ae200fb88ec7f12'),
    'co-absent': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: no CODEOWNERS file on the base branch',
    ], '9224938590e8abd8'),
    'co-partial': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: CODEOWNERS leaves 82 governance path(s) without an owner',
    ], '6e109a481cb4f40b'),
    'gh-missing': ('C', [
        'GitHub settings could not be read: gh is not installed',
        "the default branch's ruleset was not read",
        'allowed_signers on the base branch lists no signing key',
        'not tier A: whether the gh identity is an admin is unknown',
    ], '231bdf4bdc7ee1f1'),
    'no-checks': ('C', [
        'the default branch has no required status checks',
        'allowed_signers on the base branch lists no signing key',
    ], '894cb0e48ca45fa4'),
    'no-owners-review': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: the default branch does not require code-owner review',
    ], '39a9e50b21121dde'),
    'no-workflow': ('C', [
        'the required checks do not include the Aegis job: no workflow on the base branch has a job that runs aegis check --ci under a literal name, outside a matrix',
        'allowed_signers on the base branch lists no signing key',
    ], '02d5e277c56e1b95'),
    'not-aegis-check': ('C', [
        'the required checks do not include the Aegis job: require aegis-check',
        'allowed_signers on the base branch lists no signing key',
    ], 'b4cd1dff7bfd621b'),
    'repo-unreadable': ('C', [
        'GitHub settings could not be read: gh api repos/{owner}/{repo} failed: HTTP 404: Not Found',
        "the default branch's ruleset was not read",
        'allowed_signers on the base branch lists no signing key',
        'not tier A: whether the gh identity is an admin is unknown',
    ], 'c2778e2375913655'),
    'rules-unreadable': ('C', [
        "the default branch's rules could not be read: gh api repos/{owner}/{repo}/rules/branches/main failed: HTTP 403: Forbidden",
        "the default branch's ruleset was not read",
        'allowed_signers on the base branch lists no signing key',
    ], 'b15ccacdb770aaaf'),
    'signers-0': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: the default branch does not require an approving review',
        'not tier A: the default branch does not require code-owner review',
        'not tier A: the default branch keeps an approval after new commits are pushed, so a pull request can change after its review and still merge (set dismiss_stale_reviews_on_push)',
        'not tier A: no CODEOWNERS file on the base branch',
    ], 'cb94876a7c0d25f2'),
    'stale-kept': ('C', [
        'allowed_signers on the base branch lists no signing key',
        'not tier A: the default branch keeps an approval after new commits are pushed, so a pull request can change after its review and still merge (set dismiss_stale_reviews_on_push)',
    ], '9d739a9cb376c5da'),
    'unpinned-a': ('A', [
    ], '92a6c557f1847a65'),
    'unpinned-c': ('C', [
        "the required check(s) aegis-check have no pinned source (integration_id): anyone with write access, including the agent's gh token, can post a passing status; set each check's source to GitHub Actions (app 15368) in the ruleset",
        'allowed_signers on the base branch lists no signing key',
        'not tier A: the default branch does not require an approving review',
        'not tier A: the default branch does not require code-owner review',
        'not tier A: the default branch keeps an approval after new commits are pushed, so a pull request can change after its review and still merge (set dismiss_stale_reviews_on_push)',
        'not tier A: no CODEOWNERS file on the base branch',
    ], '63ccbfdd88627974'),
}


@needs_git
@pytest.mark.parametrize("name", sorted(TIER_GRID))
def test_the_tier_grid_is_the_one_recorded_before_the_table(tmp_path, name):
    """Given a FakeGh configuration recorded before detect_tier was rebuilt from one table, When the tier
    is detected, Then the tier, the reasons in order and the rest of the report are the recorded ones
    (only the admin reason's wording changed)."""
    if name in KEYGEN_CASES and not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")
    assert _tier_case(tmp_path, name) == GOLDEN_TIERS[name]


# requirement key -> (the grid case that reports it, a part of the reason)
REQUIREMENT_CASES = {
    "ruleset": ("rules-unreadable", "the default branch's ruleset was not read"),
    "review": ("approvals-0", "does not require an approving review"),
    "code-owners": ("no-owners-review", "does not require code-owner review"),
    "stale": ("stale-kept", "set dismiss_stale_reviews_on_push"),
    "checks": ("no-checks", "the default branch has no required status checks"),
    "unpinned": ("unpinned-c", "have no pinned source (integration_id)"),
    "aegis-job": ("not-aegis-check", "the required checks do not include the Aegis job"),
    "codeowners": ("co-absent", "no CODEOWNERS file on the base branch"),
    "uncovered": ("co-partial", "governance path(s) without an owner"),
    "bare-org": ("bare-org", "which GitHub ignores as a code owner"),
    "admin": ("admin", "the gh identity doctor used is an admin: re-run with the token the agent would hold"),
    "admin-unknown": ("admin-unknown", "whether the gh identity is an admin is unknown"),
    "signers": ("signers-0", "allowed_signers on the base branch lists no signing key"),
    "custody": ("b-plain-custody", "is a plain file with no passphrase"),
}


def test_every_requirement_of_the_tier_table_has_a_case():
    assert set(REQUIREMENT_CASES) == {row[0] for row in human_gate._TIER_REQUIREMENTS}


@needs_git
@pytest.mark.parametrize("key", sorted(REQUIREMENT_CASES))
def test_each_requirement_is_reported_by_its_case(tmp_path, key):
    case, part = REQUIREMENT_CASES[key]
    if case in KEYGEN_CASES and not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")
    tier, reasons, _rest = _tier_case(tmp_path, case)
    assert tier != "A" and [r for r in reasons if part in r], reasons


@needs_git
def test_a_runner_that_returns_none_is_tier_c_with_one_ruleset_reason(tmp_path):
    repo = _repo_with_governance(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=lambda argv, stdin=None, cwd=None, timeout=None: None)
    assert report.tier == "C" and report.reasons[0] == "GitHub settings could not be read: gh is not installed"
    assert [r for r in report.reasons if "ruleset was not read" in r] == ["the default branch's ruleset was not read"]


def test_the_dead_tier_surface_is_gone():
    import inspect

    assert not hasattr(human_gate.TierReport, "codeowners_complete")
    assert list(inspect.signature(human_gate.detect_tier).parameters) == ["root", "gh"]
    custody = human_gate.KeyCustody("none", "no key", False)
    assert custody._asdict() == {"status": "none", "detail": "no key", "degrades": False, "key": None}
    assert not hasattr(custody, "as_dict")


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


# ── the Aegis job: the required check is identified, not guessed ────────────

def _workflow(on="on:\n  pull_request:\n", job="  aegis-check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: aegis check --ci\n"):
    return f"name: Aegis\n{on}jobs:\n{job}"


def test_the_aegis_jobs_of_a_workflow_are_the_jobs_that_run_aegis_check_ci():
    from aegis_core import scaffolding
    assert human_gate.aegis_check_jobs(scaffolding.ci_workflow()) == ["aegis-check"]
    text = _workflow(job=(
        "  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ruff check .\n"
        "  gate:\n    name: Aegis gate  # the check name\n    steps:\n      - name: Gate\n"
        "        run: python3 -m aegis_cli.cli check --ci\n"
        "  block:\n    steps:\n      - run: pip install aegis-guardrails\n      - run: |\n          aegis check --ci --base main\n"
        "  local:\n    steps:\n      - run: aegis check\n"))
    assert human_gate.aegis_check_jobs(text) == ["Aegis gate", "block"]


@pytest.mark.parametrize("job", [
    "  aegis:\n    name: 'Aegis (${{ matrix.os }})'\n    steps:\n      - run: aegis check --ci\n",
    "  aegis:\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n    steps:\n      - run: aegis check --ci\n",
], ids=["templated", "matrix"])
def test_an_aegis_job_without_a_fixed_check_name_is_not_a_literal_context(job):
    assert human_gate.aegis_check_jobs(_workflow(job=job)) == []


def test_this_repositorys_required_check_is_its_aggregate_aegis_job():
    root = Path(__file__).resolve().parents[3]
    text = (root / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    assert human_gate.aegis_check_jobs(text) == ["aegis-check"]


@needs_git
def test_a_required_aegis_job_without_a_path_filter_meets_the_check_criterion(tmp_path):
    repo = _repo_with_governance(tmp_path)
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule("aegis-check")]))
    assert report.tier == "A", report.reasons
    assert not [c for c in report.caveats if "not visible from here" in c]
    assert report.evidence["aegis_checks"] == {"jobs": ["aegis-check"], "path_filtered": []}


@needs_git
def test_a_required_check_that_is_not_the_aegis_job_is_neither_tier_a_nor_b(tmp_path):
    repo = _repo_with_governance(tmp_path, signer_pub=hg.hardware_public_key())
    repo.home.sign_with("key::" + hg.hardware_public_key())
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule("lint")]))
    assert report.tier == "C"
    reason = next(r for r in report.reasons if "the required checks do not include the Aegis job" in r)
    assert "aegis-check" in reason


@needs_git
@pytest.mark.parametrize("on", [
    "on:\n  pull_request:\n    paths:\n      - 'src/**'\n",
    "on:\n  pull_request:\n    branches: [main]\n    paths-ignore: ['docs/**']\n",
    "on:\n  pull_request: {paths: ['src/**']}\n",
    "on:\n  push:\n  pull_request_target:\n    paths: ['src/**']  # only source\n",
    "on: {push: {branches: [main]}, pull_request: {paths: ['src/**']}}\n",
], ids=["block", "ignore", "flow", "target", "flow-on"])
def test_an_aegis_workflow_that_filters_pull_requests_by_path_is_not_tier_a(tmp_path, on):
    repo = _repo_with_governance(tmp_path, workflow=_workflow(on=on))
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()]))
    assert report.tier != "A"
    assert any("filters pull requests by path" in r for r in report.reasons), report.reasons
    assert report.evidence["aegis_checks"]["path_filtered"] == ["aegis-check"]


@needs_git
@pytest.mark.parametrize("on", [
    "on:\n  pull_request:\n  push:\n    paths: ['src/**']\n",
    "on:\n  pull_request:\n    branches: [main, 'release/**']\n",
    "on: {push: {paths: ['src/**']}, pull_request: {branches: [main]}}\n",
    "on: [push, pull_request]\n",
], ids=["push-paths", "branches", "flow-push", "list"])
def test_a_push_path_filter_or_a_branch_filter_is_not_a_pull_request_path_filter(tmp_path, on):
    repo = _repo_with_governance(tmp_path, workflow=_workflow(on=on))
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()]))
    assert report.tier == "A", report.reasons


@needs_git
def test_an_aegis_workflow_only_in_the_working_tree_is_not_trusted(tmp_path):
    repo = _repo_with_governance(tmp_path, workflow=None)
    repo.write(".github/workflows/aegis.yml", hg.AEGIS_WORKFLOW)
    repo.commit("add the workflow on the branch only")
    report = human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule()]))
    assert report.tier != "A"
    assert any("the required checks do not include the Aegis job" in r for r in report.reasons), report.reasons


# GitHub reports a job skipped by a condition as a passing required check, so only an Aegis job that
# nothing can skip, and whose aegis step can fail it, is the required check.

def _gate_workflow(job_keys="", step="      - run: aegis check --ci\n", top=""):
    return ("name: Aegis\non:\n  pull_request:\n" + top + "jobs:\n"
            "  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ruff check .\n"
            "  aegis-check:\n" + job_keys + "    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v7\n" + step)


def _tier_with_base_workflow(tmp_path, workflow):
    repo = _repo_with_governance(tmp_path, signer_pub=hg.hardware_public_key(), workflow=workflow)
    repo.home.sign_with("key::" + hg.hardware_public_key())
    return human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.pull_request_rule(), hg.checks_rule("aegis-check")]))


_CONDITION = "has a condition (if: {}) and may be skipped"
_STEP_CONDITION = "runs aegis check --ci in a step that has a condition (if: {})"
_NOT_DIRECT = "does not run aegis check --ci as the whole of a step's run:"


@needs_git
@pytest.mark.parametrize("job_keys, step, top, why", [
    ("    if: github.event_name == 'push'\n", None, "", _CONDITION.format("github.event_name == 'push'")),
    ("    if: github.event.pull_request.draft == false\n", None, "",
     _CONDITION.format("github.event.pull_request.draft == false")),
    ("    if: ${{ !contains(github.event.pull_request.title, 'skip-aegis') }}\n", None, "", "has a condition (if: ${{ !contains("),
    ("    if: always() && github.event_name == 'pull_request'\n", None, "", "has a condition (if: always() &&"),
    ("    if: always()\n      && github.event_name == 'push'\n", None, "", "has a condition (if: always()"),
    ("    \"if\": github.event_name == 'push'\n", None, "", _CONDITION.format("github.event_name == 'push'")),
    ("    needs: [lint]\n", None, "", "needs other jobs without if: always()"),
    ("    continue-on-error: true\n", None, "", "sets continue-on-error"),
    ("    continue-on-error: ${{ github.event_name == 'pull_request' }}\n", None, "", "sets continue-on-error"),
    ("    <<: *defaults\n", None, "", "is not laid out as this check reads a workflow"),
    ("    \"name\": Aegis gate\n", None, "", "is not laid out as this check reads a workflow"),
    ("", "      - if: github.event_name == 'push'\n        run: aegis check --ci\n", "",
     _STEP_CONDITION.format("github.event_name == 'push'")),
    ("", "      - run: aegis check --ci\n        if: false\n", "", _STEP_CONDITION.format("false")),
    ("", "      - run: |\n          aegis check --ci\n        if: false\n", "", _STEP_CONDITION.format("false")),
    ("", "      - run: aegis check --ci\n        continue-on-error: true\n", "", "runs aegis check --ci in a step that sets continue-on-error"),
    ("", "      - run: aegis check --ci || true\n", "", _NOT_DIRECT),
    ("", "      - run: python3 -I -m aegis_cli.cli check --ci || true\n", "", _NOT_DIRECT),
    ("", "      - run: python3 -X dev -m aegis_cli.cli check --ci\n", "", _NOT_DIRECT),
    ("", "      - run: aegis check --ci || :\n", "", _NOT_DIRECT),
    ("", "      - run: aegis check --ci || exit 0\n", "", _NOT_DIRECT),
    ("", "      - run: aegis check --ci; true\n", "", _NOT_DIRECT),
    ("", "      - run: aegis check --ci; exit 0\n", "", _NOT_DIRECT),
    ("", "      - run: aegis check --ci | tee aegis.log\n", "", _NOT_DIRECT),
    ("", "      - run: echo aegis check --ci\n", "", _NOT_DIRECT),
    ("", "      - run: printf 'aegis check --ci'\n", "", _NOT_DIRECT),
    ("", "      - run: true  # aegis check --ci\n", "", _NOT_DIRECT),
    ("", "      - run: bash -c 'echo \"aegis check --ci\"'\n", "", _NOT_DIRECT),
    ("", "      - run: |\n          set +e\n          aegis check --ci\n          echo done\n", "", _NOT_DIRECT),
    ("", "      - run: |\n          cat <<EOF\n          aegis check --ci\n          EOF\n", "", _NOT_DIRECT),
    ("", "      - run: >\n          echo\n          aegis check --ci\n", "", _NOT_DIRECT),
    ("", "      - run: aegis check --ci\n        shell: cat {0}\n", "", "runs aegis check --ci under a custom shell (cat {0})"),
    ("", None, "defaults:\n  run:\n    shell: cat {0}\n", "runs aegis check --ci under a custom shell (cat {0})"),
    ("", None, "defaults: {run: {shell: cat {0}}}\n", "runs aegis check --ci under a custom shell ({run: {shell: cat {0}}})"),
], ids=["if-push", "if-draft", "if-title", "if-always-and", "if-folded", "if-quoted-key", "needs", "job-continue",
        "job-continue-expr", "merge-key", "name-quoted-key", "step-if", "step-if-after-run", "step-if-after-block", "step-continue",
        "or-true", "isolated-or-true", "other-flag", "or-colon", "or-exit", "semi-true", "semi-exit", "pipe", "echo", "printf", "comment", "quoted",
        "set-e-off", "heredoc", "folded", "step-shell", "default-shell", "inline-default-shell"])
def test_an_aegis_job_that_can_be_skipped_or_cannot_fail_is_not_the_required_check(tmp_path, job_keys, step, top, why):
    """Given a base-branch Aegis job, required by name, that a condition can skip or whose aegis step
    cannot fail it, When the tier is detected, Then it is tier C and the reason says why the job does not count."""
    workflow = _gate_workflow(job_keys, step or "      - run: aegis check --ci\n", top)
    assert human_gate.aegis_check_jobs(workflow) == []
    report = _tier_with_base_workflow(tmp_path, workflow)
    assert report.tier == "C"
    assert any("the Aegis job aegis-check " + why in r for r in report.reasons), report.reasons


@needs_git
@pytest.mark.parametrize("job_keys, step", [
    ("", "      - run: aegis check --ci\n"),
    ("    if: always()\n", "      - run: aegis check --ci\n"),
    ("    needs: [lint]\n    if: ${{ always() }}\n", "      - run: aegis check --ci\n"),
    ("    needs:\n      - lint\n    if: \"${{always()}}\"  # aggregate\n", "      - run: aegis check --ci\n"),
    ("    continue-on-error: false\n",
     "      - name: Gate\n        if: always()\n        continue-on-error: false\n        run: aegis check --ci  # the gate\n"),
    ("", "      - run: |\n          aegis check --ci --base main\n"),
    ("", "      - run: python3 -m aegis_cli.cli check --ci\n        shell: bash\n"),
    ("", "      - run: python3 -I -m aegis_cli.cli check --ci\n"),
    ("", "      - run: echo aegis check --ci\n      - run: aegis check --ci\n"),
], ids=["plain", "if-always", "needs-always-expr", "needs-always-tight", "continue-false", "block", "module-bash", "module-isolated",
        "decoy-then-real"])
def test_an_unconditional_aegis_job_that_can_fail_is_the_required_check(tmp_path, job_keys, step):
    workflow = _gate_workflow(job_keys, step)
    assert human_gate.aegis_check_jobs(workflow) == ["aegis-check"]
    report = _tier_with_base_workflow(tmp_path, workflow)
    assert report.tier == "A", report.reasons


@needs_git
def test_this_repositorys_validate_workflow_on_the_base_branch_meets_the_check_criterion(tmp_path):
    root = Path(__file__).resolve().parents[3]
    text = (root / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    report = _tier_with_base_workflow(tmp_path, text)
    assert report.tier == "A", report.reasons
    assert report.evidence["aegis_checks"]["jobs"] == ["aegis-check"]


@needs_git
def test_reading_the_base_workflows_costs_one_batched_git_read(tmp_path, monkeypatch):
    from collections import Counter
    from aegis_core import gitsafe
    counts = []
    real = gitsafe.run
    for name, workflow in (("without", None), ("with", hg.AEGIS_WORKFLOW)):
        repo = _repo_with_governance(tmp_path / name, workflow=workflow)
        seen = Counter()

        def spy(args, cwd, *a, **kw):
            seen[" ".join(x for x in args[:2] if x.startswith(("cat-file", "--batch", "ls-tree")))] += 1
            return real(args, cwd, *a, **kw)

        monkeypatch.setattr(gitsafe, "run", spy)
        human_gate.detect_tier(repo.root, gh=hg.FakeGh(rules=[hg.checks_rule()]))
        monkeypatch.setattr(gitsafe, "run", real)
        counts.append(seen)
    without, with_ = counts
    assert sum(with_.values()) - sum(without.values()) == 1
    assert with_["cat-file --batch"] == without["cat-file --batch"] + 1
    assert with_["ls-tree"] == without["ls-tree"]


# ── find_approval: cost independent of the range length (R-trust-40) ─────────

def _counted_find(repo, monkeypatch, **kw):
    from collections import Counter
    from aegis_core import gitsafe

    real = gitsafe.run
    seen = Counter()

    def spy(args, cwd, *a, **k):
        seen[next((x for x in args if not x.startswith("-")), "")] += 1
        return real(args, cwd, *a, **k)

    monkeypatch.setattr(gitsafe, "run", spy)
    try:
        found = human_gate.find_approval(repo.root, "HEAD", "main", **kw)
    finally:
        monkeypatch.setattr(gitsafe, "run", real)
    return found, seen


def _range(tmp_path, n: int, signer_pub=None, approve_key=None, name="r"):
    repo = hg.make_repo(tmp_path / name, signer_pub)
    digest = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    approval = None
    if approve_key is not None:
        approval = repo.commit(f"approve\n\nAegis-Approve: {digest}\n", sign_key=approve_key, allow_empty=True)
    for i in range(n - (approve_key is not None)):
        repo.commit(f"c{i}", allow_empty=True)
    return repo, approval


@needs_git
def test_a_range_without_approval_costs_the_same_git_calls_at_4_and_40_commits(tmp_path, monkeypatch):
    totals = []
    for n in (4, 40):
        repo, _ = _range(tmp_path, n, name=f"r{n}")
        found, seen = _counted_find(repo, monkeypatch)
        assert found is None
        assert seen["cat-file"] == 0, seen
        totals.append(sum(seen.values()))
    assert totals[0] == totals[1] and totals[0] <= 12, totals


@needs_signing
def test_one_signed_approval_costs_a_constant_whatever_the_range(tmp_path, monkeypatch):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    totals = []
    for n in (4, 40):
        repo, approval = _range(tmp_path, n, pub, key, name=f"r{n}")
        found, seen = _counted_find(repo, monkeypatch)
        assert found is not None and found.valid and found.commit == approval
        totals.append(sum(seen.values()))
    assert totals[0] == totals[1], totals


@needs_signing
def test_a_bad_signature_candidate_is_skipped_for_the_next_one(tmp_path):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo, approval = _range(tmp_path, 2, pub, key)
    digest = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    repo.commit(f"forged\n\nAegis-Approve: {digest}\n", allow_empty=True)  # newer, unsigned
    found = human_gate.find_approval(repo.root, "HEAD", "main")
    assert found is not None and found.commit == approval


@needs_signing
def test_the_scan_stops_at_the_cap(tmp_path, monkeypatch):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo, approval = _range(tmp_path, 4, pub, key)  # the approval is the 4th newest commit
    monkeypatch.setattr(human_gate, "MAX_SCANNED_COMMITS", 3)
    assert human_gate.find_approval(repo.root, "HEAD", "main") is None
    monkeypatch.setattr(human_gate, "MAX_SCANNED_COMMITS", 4)
    assert human_gate.find_approval(repo.root, "HEAD", "main").commit == approval


@needs_signing
def test_a_control_byte_in_a_message_does_not_hide_an_approval(tmp_path):
    key, pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, pub)
    digest = human_gate.governance_tree_hash(repo.root, "HEAD", base="main")
    approval = repo.commit(f"approve \x01 this\n\nAegis-Approve: {digest}\n", sign_key=key, allow_empty=True)
    repo.commit("later", allow_empty=True)
    found = human_gate.find_approval(repo.root, "HEAD", "main")
    assert found is not None and found.commit == approval


@needs_git
def test_a_verification_error_still_names_the_commit_the_caller_gave(tmp_path, monkeypatch):
    from aegis_core import gitsafe

    repo = hg.make_repo(tmp_path)

    def broken(*_a, **_k):
        raise gitsafe.GitError("git cat-file timed out")

    monkeypatch.setattr(human_gate, "_read_message", broken)
    verdict = human_gate.verify_approval(repo.root, "HEAD", "0" * 64, "main")
    assert (verdict.valid, verdict.code, verdict.commit) == (False, "unresolved", "HEAD")


# ── X-approve-tty: the signing program sees the person's terminal ────────────

posix_tty = pytest.mark.skipif(sys.platform == "win32", reason="a pseudo-terminal and a shell-script ssh-keygen")
LITERAL_KEY = "key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMvWg1gnqZq3v3dWJ2t3K0aVf0O8Yy3d6C6pWm3Z1b2c human"


def _tty_recording_signer(tmp_path: Path, monkeypatch) -> Path:
    """A fake ssh-keygen first on PATH that records whether its stdin is a terminal, then fails to sign."""
    seen = tmp_path / "stdin-seen"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "ssh-keygen"
    fake.write_text(f"#!/bin/sh\nif [ -t 0 ]; then echo tty > '{seen}'; else echo notty > '{seen}'; fi\nexit 1\n",
                    encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return seen


def _approve_on_a_pty(repo: hg.Repo, monkeypatch, exempt: bool, tty: bool):
    import argparse
    import contextlib
    import io
    import pty
    from aegis_cli import approve

    monkeypatch.setattr(approve, "_stdin_is_tty", lambda: tty)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    args = argparse.Namespace(workspace=str(repo.root), json=True, base=None,
                              exempt_test=repo.head() if exempt else None, reason="by hand" if exempt else None)
    master, slave = pty.openpty()
    saved = os.dup(0)
    out = io.StringIO()
    try:
        os.dup2(slave, 0)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = approve.run_approve(args)
    finally:
        os.dup2(saved, 0)
        for fd in (saved, slave, master):
            os.close(fd)
    return rc, json.loads(out.getvalue())


@needs_git
@posix_tty
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_signing_reads_the_terminal_so_a_passphrase_key_can_unlock(tmp_path, monkeypatch, exempt):
    """Given a terminal on stdin and a y, When approve signs, Then the signing program's stdin is that
    terminal (OpenSSH asks for a key passphrase there; on /dev/null it falls back to ssh-askpass)."""
    repo = hg.make_repo(tmp_path)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weaker"))
    repo.commit("weaken a rule")
    repo.home.sign_with(LITERAL_KEY)
    seen = _tty_recording_signer(tmp_path, monkeypatch)
    rc, doc = _approve_on_a_pty(repo, monkeypatch, exempt, tty=True)
    assert seen.read_text(encoding="utf-8").strip() == "tty"
    assert rc == 1 and doc["code"] == "sign_failed"


@needs_git
@posix_tty
@pytest.mark.parametrize("exempt", [False, True], ids=["approve", "exempt"])
def test_without_a_terminal_neither_flow_runs_the_signing_program(tmp_path, monkeypatch, exempt):
    repo = hg.make_repo(tmp_path)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "weaker"))
    before = repo.commit("weaken a rule")
    repo.home.sign_with(LITERAL_KEY)
    seen = _tty_recording_signer(tmp_path, monkeypatch)
    rc, doc = _approve_on_a_pty(repo, monkeypatch, exempt, tty=False)
    assert rc == 1 and doc["code"] == "no_terminal"
    assert not seen.exists() and repo.head() == before
