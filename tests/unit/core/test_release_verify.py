"""Release verification (v4.3 spec T2): the verdict job and ``aegis doctor --release <sha>``.

The verdict job attests ``sha256("aegis-ci-verdict/v1\\ncommit <sha>\\ntree <tree>\\n")`` only
when every other job succeeded, on push and dispatch only. ``doctor --release`` asks
``gh attestation verify`` (gh >= 2.93.0, every pin), re-checks the JSON gh prints, and fails
closed: a missing or old gh is UNVERIFIED, and at tier C the attestation does not make the
release claim true (the agent can edit the workflow). gh is always a fake.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from aegis_cli.cli import main
from aegis_cli.formatters.text import render_release
from aegis_core import release_verify as rv
from tests import helpers_humangate as hg

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")
posix_only = pytest.mark.skipif(os.name == "nt", reason="shell stubs")

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
REPOSITORY = "owner/project"


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    before = os.getcwd()
    yield
    os.chdir(before)


# ── the verdict job ──────────────────────────────────────────────────────────

def _jobs(text: str) -> Dict[str, str]:
    """Top-level job name -> its block (two-space job keys under ``jobs:``)."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):[ \t]*\r?$", body)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def test_the_verdict_job_needs_every_other_job():
    jobs = _jobs(WORKFLOW.read_text(encoding="utf-8"))
    assert "verdict" in jobs
    found = re.search(r"(?m)^    needs: \[([^\]]*)\]", jobs["verdict"])
    assert found, "verdict must list its needs inline"
    needs = {n.strip() for n in found.group(1).split(",") if n.strip()}
    assert needs == set(jobs) - {"verdict"}


def test_the_verdict_job_runs_only_where_its_attestation_is_consumed_and_holds_only_what_it_needs():
    """doctor --release accepts only default-branch push (or dispatch) verdicts; a release run
    calling validate.yml must not depend on producing one nobody reads."""
    block = _jobs(WORKFLOW.read_text(encoding="utf-8"))["verdict"]
    cond = re.search(r"(?m)^    if: (.*)$", block)
    assert cond, "verdict must state its events"
    events = set(re.findall(r"github\.event_name == '([^']+)'", cond.group(1)))
    assert events == {"push", "workflow_dispatch"}
    assert re.fullmatch(r"github\.event_name == '\w+'( \|\| github\.event_name == '\w+')*", cond.group(1).strip())
    found = re.search(r"(?m)^    permissions:\n((?:      .*\n)+)", block)
    assert found
    perms = dict(line.strip().split(": ", 1) for line in found.group(1).splitlines())
    assert perms == {"contents": "read", "id-token": "write", "attestations": "write"}


def test_the_verdict_job_attests_the_spec_subject_and_predicate_with_a_pinned_action():
    block = _jobs(WORKFLOW.read_text(encoding="utf-8"))["verdict"]
    assert "printf 'aegis-ci-verdict/v1\\ncommit %s\\ntree %s\\n' \"$GITHUB_SHA\" \"$tree\" > subject.txt" in block
    assert "git rev-parse 'HEAD^{tree}'" in block
    for key in ('"commit"', '"tree"', '"run"', '"jobs"'):
        assert key in block
    uses = re.findall(r"uses: (actions/attest)@([^\s#]+)", block)
    assert uses and all(re.fullmatch(r"[0-9a-f]{40}", ref) for _name, ref in uses)
    assert f"predicate-type: {rv.PREDICATE_TYPE}" in block
    assert "subject-path: subject.txt" in block and "predicate-path: predicate.json" in block
    for ref in re.findall(r"uses: [^@\s]+@([^\s#]+)", block):
        assert re.fullmatch(r"[0-9a-f]{40}", ref), ref


@pytest.mark.parametrize("path", [ROOT / "aegis_core" / "release_verify.py", WORKFLOW], ids=["module", "workflow"])
def test_the_predicate_type_uri_is_declared_permanent_where_it_is_pinned(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    at = next(i for i, line in enumerate(lines) if rv.PREDICATE_TYPE in line)
    assert any("permanent" in line for line in lines[max(0, at - 2):at + 3]), path.name


def test_the_subject_is_derivable_from_the_commit_alone():
    commit, tree = "1" * 40, "2" * 40
    assert rv.subject_bytes(commit, tree) == f"aegis-ci-verdict/v1\ncommit {commit}\ntree {tree}\n".encode()


# ── doctor --release, library level ─────────────────────────────────────────

DEFAULT_API = {"full_name": REPOSITORY, "default_branch": "main"}
PR_HEAD = "c" * 40
DEFAULT_PULLS = [{"number": 7, "merged_at": "2026-10-19T10:00:00Z", "base": {"ref": "main"},
                  "head": {"sha": PR_HEAD}, "user": {"login": "author"}}]
DEFAULT_REVIEWS = [{"state": "APPROVED", "user": {"login": "reviewer"}, "commit_id": PR_HEAD}]


class FakeGh:
    """``gh --version`` answers ``version``; ``gh api`` answers ``api`` (an object is printed as JSON,
    a tuple is ``(rc, stdout, stderr)``); ``gh attestation verify`` answers ``verify``."""

    def __init__(self, version: Optional[str] = "2.93.0", verify: Tuple[int, str, str] = (0, "[]", ""),
                 api: Any = DEFAULT_API, pulls: Any = DEFAULT_PULLS, reviews: Any = DEFAULT_REVIEWS) -> None:
        self.version = version
        self.verify = verify
        self.api = api
        self.pulls = pulls
        self.reviews = reviews
        self.calls: List[List[str]] = []
        self.subjects: List[bytes] = []

    def __call__(self, argv: Sequence[str], timeout: float) -> Optional[Tuple[int, str, str]]:
        argv = list(argv)
        self.calls.append(argv)
        if self.version is None:
            return None
        if argv == ["--version"]:
            return 0, f"gh version {self.version} (2026-10-01)\nhttps://github.com/cli/cli/releases/tag/v{self.version}\n", ""
        if argv[:1] == ["api"]:
            path = argv[-1]
            answer = (self.pulls if re.search(r"/commits/[0-9a-f]+/pulls\Z", path) else
                      self.reviews if re.search(r"/pulls/\d+/reviews\?per_page=100\Z", path) else self.api)
            return answer if isinstance(answer, tuple) else (0, json.dumps(answer), "")
        if argv[:2] == ["attestation", "verify"]:
            self.subjects.append(Path(argv[2]).read_bytes())
            return self.answer(argv)
        return 1, "", "unexpected call"

    def answer(self, argv: List[str]) -> Tuple[int, str, str]:
        return self.verify

    @property
    def verify_calls(self) -> List[List[str]]:
        return [c for c in self.calls if c[:2] == ["attestation", "verify"]]

    @property
    def api_calls(self) -> List[List[str]]:
        return [c for c in self.calls if c[:1] == ["api"]]


class PinHonoringGh(FakeGh):
    """gh as it really filters: the attestation is returned only for the ref it was signed on."""

    def __init__(self, signed_on: str, verify: Tuple[int, str, str], api: Any = DEFAULT_API) -> None:
        super().__init__("2.93.0", verify, api)
        self.signed_on = signed_on

    def answer(self, argv: List[str]) -> Tuple[int, str, str]:
        if argv[argv.index("--source-ref") + 1] != self.signed_on:
            return 1, "", "no matching attestations found"
        return self.verify


# What the base branch must hold for the tier detector to reach each tier (with tier_runner's rules).
# Both need the Aegis job on the base: R-trust-35 reads the required check from the base workflows.
TIER_FILES = {"A": {".github/CODEOWNERS": hg.CODEOWNERS_FULL, ".github/workflows/aegis.yml": hg.AEGIS_WORKFLOW},
              "B": {"allowed_signers": hg.allowed_signers_text(hg.hardware_public_key()),
                    ".github/workflows/aegis.yml": hg.AEGIS_WORKFLOW}}


def make_repo(tmp_path: Path, remote: Optional[str] = f"https://github.com/{REPOSITORY}.git",
              tier: Optional[str] = None) -> hg.Repo:
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("src/app.py", "x = 1\n")
    for path, text in TIER_FILES.get(tier or "", {}).items():
        repo.write(path, text)
    repo.commit("base")
    if tier == "B":
        repo.home.sign_with("key::" + hg.hardware_public_key())  # a security key: adequate custody
    if remote is not None:
        repo.git("remote", "add", "origin", remote)
    repo.git("update-ref", "refs/remotes/origin/main", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return repo


def facts(repo: hg.Repo) -> Tuple[str, str, str]:
    commit = repo.head()
    tree = repo.git("rev-parse", "HEAD^{tree}")
    return commit, tree, hashlib.sha256(rv.subject_bytes(commit, tree)).hexdigest()


def record(commit: str, tree: str, digest: str, **overrides: Any) -> Dict[str, Any]:
    cert = {
        "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
        "sourceRepositoryDigest": commit, "sourceRepositoryRef": "refs/heads/main",
        "buildSignerURI": f"https://github.com/{REPOSITORY}/.github/workflows/validate.yml@refs/heads/main",
        "buildSignerDigest": commit, "runnerEnvironment": "github-hosted",
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "subject.txt", "digest": {"sha256": digest}}],
        "predicateType": rv.PREDICATE_TYPE,
        "predicate": {"commit": commit, "tree": tree, "run": "1/1",
                      "jobs": {"validate": "success", "build-wheel": "success"}},
    }
    for key, value in overrides.items():
        section, _, name = key.partition("__")
        target = {"cert": cert, "statement": statement, "predicate": statement["predicate"]}[section]
        if value is None:
            target.pop(name, None)
        else:
            target[name] = value
    return {"verificationResult": {"statement": statement, "signature": {"certificate": cert}}}


def tier_runner_none(*_args: Any, **_kw: Any) -> None:
    return None  # gh unavailable for tier detection: tier C


def tier_runner(tier: str) -> hg.FakeGh:
    """The gh that tier detection reads: A adds review and code-owner rules to B's required checks."""
    rules = [hg.pull_request_rule(), hg.checks_rule()] if tier == "A" else [hg.checks_rule()]
    return hg.FakeGh(rules=rules)


@pytest.mark.parametrize("version", ["2.45.0", "2.66.0", "2.92.9", "1.99.99"])
def test_a_gh_older_than_2_93_is_unverified_and_never_asked(tmp_path, version):
    gh = FakeGh(version)
    report = rv.verify_release(make_repo(tmp_path).root, "HEAD", run=gh, tier_runner=tier_runner_none)
    assert not report.verified and report.code == "gh_too_old"
    assert render_release(report.as_dict())[0] == rv.UNVERIFIED_GH
    assert gh.verify_calls == []


@pytest.mark.parametrize("version", [None, "garbage"])
def test_no_gh_or_a_gh_without_a_version_is_unverified(tmp_path, version):
    gh = FakeGh(version) if version is None else FakeGh()
    if version == "garbage":
        gh = lambda argv, timeout: (0, "something else\n", "")  # noqa: E731
    report = rv.verify_release(make_repo(tmp_path).root, "HEAD", run=gh, tier_runner=tier_runner_none)
    assert not report.verified and report.code == "gh_missing"
    assert rv.UNVERIFIED_GH in render_release(report.as_dict())


@needs_git
def test_every_pin_is_passed_and_the_subject_file_is_the_commit_subject(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("A"))
    assert report.verified and report.tier == "A", report.message
    (argv,) = gh.verify_calls
    pairs = dict(zip(argv[3::2], argv[4::2]))
    expected = {"--repo": REPOSITORY, "--predicate-type": rv.PREDICATE_TYPE,
                "--signer-workflow": f"{REPOSITORY}/.github/workflows/validate.yml",
                "--signer-digest": commit, "--source-ref": "refs/heads/main", "--source-digest": commit}
    for flag, value in expected.items():
        assert flag in argv and argv[argv.index(flag) + 1] == value, flag
    assert "--deny-self-hosted-runners" in argv
    assert argv[argv.index("--format") + 1] == "json"
    assert gh.subjects == [rv.subject_bytes(commit, tree)]
    assert pairs  # pins are flag/value pairs after the subject path


@needs_git
def test_a_newer_gh_is_accepted(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    report = rv.verify_release(repo.root, commit, run=FakeGh("3.0.0", (0, json.dumps([record(commit, tree, digest)]), "")), tier_runner=tier_runner("A"))
    assert report.verified and report.caveats == () and report.tier == "A"


@needs_git
def test_gh_refusing_the_attestation_is_not_verified(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    report = rv.verify_release(repo.root, "HEAD", run=FakeGh("2.93.0", (1, "", "no matching attestations found\n")), tier_runner=tier_runner("A"))
    assert not report.verified and report.code == "rejected"
    assert "no matching attestations" in report.message


@needs_git
@pytest.mark.parametrize("label,overrides", [
    ("predicate-type", {"statement__predicateType": "https://slsa.dev/provenance/v1"}),
    ("subject", {"statement__subject": [{"digest": {"sha256": "0" * 64}}]}),
    ("predicate-commit", {"predicate__commit": "f" * 40}),
    ("predicate-tree", {"predicate__tree": "e" * 40}),
    ("predicate-run-bad", {"predicate__run": "not-an-id"}),
    ("predicate-run-missing", {"predicate__run": None}),
    ("a-job-failed", {"predicate__jobs": {"validate": "success", "test-windows": "failure"}}),
    ("no-jobs", {"predicate__jobs": {}}),
    ("source-digest", {"cert__sourceRepositoryDigest": "f" * 40}),
    ("signer-digest", {"cert__buildSignerDigest": "f" * 40}),
    ("self-hosted", {"cert__runnerEnvironment": "self-hosted"}),
    ("other-repo", {"cert__sourceRepositoryURI": "https://github.com/attacker/project"}),
    ("other-ref", {"cert__sourceRepositoryRef": "refs/heads/agent-branch"}),
    ("other-workflow", {"cert__buildSignerURI": f"https://github.com/{REPOSITORY}/.github/workflows/evil.yml@refs/heads/main"}),
    ("no-signer-uri", {"cert__buildSignerURI": None}),
])
def test_exit_zero_is_not_enough_the_json_is_rechecked(tmp_path, label, overrides):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest, **overrides)]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("A"))
    assert not report.verified and report.code == "bad_output", label


@needs_git
def test_a_verified_report_carries_the_run_of_the_attestation(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest, predicate__run="42/3")]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("A"))
    assert report.verified and report.details.get("run") == "42/3"


@pytest.mark.parametrize("keyword", ["workflow", "expected_run", "environ"])
def test_the_removed_pins_are_refused_not_ignored(tmp_path, keyword):
    with pytest.raises(TypeError):
        rv.verify_release(tmp_path, "HEAD", run=FakeGh(), **{keyword: "x"})


@needs_git
@pytest.mark.parametrize("stdout", ["", "not json", "[]", "{}", json.dumps([{"verificationResult": {}}])])
def test_an_empty_or_shapeless_answer_is_not_verified(tmp_path, stdout):
    repo = make_repo(tmp_path, tier="A")
    report = rv.verify_release(repo.root, "HEAD", run=FakeGh("2.93.0", (0, stdout, "")), tier_runner=tier_runner("A"))
    assert not report.verified and report.code == "bad_output"


@needs_git
def test_one_matching_attestation_among_others_is_enough(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    records = [record(commit, tree, digest, cert__sourceRepositoryRef="refs/tags/v1"), record(commit, tree, digest)]
    assert rv.verify_release(repo.root, commit, run=FakeGh("2.93.0", (0, json.dumps(records), "")), tier_runner=tier_runner("A")).verified


@needs_git
def test_at_tier_c_an_attestation_is_reported_but_the_release_claim_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner_none)
    assert report.tier == "C"
    assert not report.verified and report.code == "agent_editable"
    text = "\n".join(render_release(report.as_dict()))
    assert "attestation present, but the workflow is agent-editable" in text
    assert report.as_dict()["attested"] is True


@needs_git
def test_at_tier_b_an_attestation_is_reported_but_the_release_claim_is_agent_editable(tmp_path):
    """Given tier B (required checks, a security key in the base allowed_signers) and a good
    attestation, When the release is verified, Then it is agent_editable as at tier C, never
    VERIFIED: a pull request runs its own workflow, which is the workflow that signs."""
    repo = make_repo(tmp_path, tier="B")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("B"))
    assert report.tier == "B" and report.attested
    assert (report.verified, report.code, report.status) == (False, "agent_editable", "agent_editable")
    assert render_release(report.as_dict())[0] == "NOT VERIFIED: attestation present, but the workflow is agent-editable"
    assert report.as_dict()["verified"] is False


def _signed_on(repo: hg.Repo, branch: str) -> str:
    commit, tree, digest = facts(repo)
    ref = f"refs/heads/{branch}"
    signer = f"https://github.com/{REPOSITORY}/.github/workflows/validate.yml@{ref}"
    return json.dumps([record(commit, tree, digest, cert__sourceRepositoryRef=ref, cert__buildSignerURI=signer)])


@needs_git
@pytest.mark.parametrize("github_default, verified", [("main", False), ("release/x", True)], ids=["main", "release"])
def test_the_source_ref_is_githubs_default_branch_not_origin_head(tmp_path, github_default, verified):
    repo = make_repo(tmp_path, tier="A")
    repo.git("update-ref", "refs/remotes/origin/release/x", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/release/x")
    gh = PinHonoringGh("refs/heads/release/x", (0, _signed_on(repo, "release/x"), ""),
                       api={"full_name": REPOSITORY, "default_branch": github_default})
    gh.pulls = [dict(DEFAULT_PULLS[0], base={"ref": github_default})]
    report = rv.verify_release(repo.root, "HEAD", run=gh, tier_runner=tier_runner("A"))
    argv = gh.verify_calls[0]
    assert argv[argv.index("--source-ref") + 1] == f"refs/heads/{github_default}"
    assert report.verified is verified
    if not verified:
        assert (report.code, report.status) == ("rejected", "failed")


@needs_git
@pytest.mark.parametrize("origin_head", [True, False], ids=["origin-head", "none"])
def test_the_default_branch_is_read_once_for_the_pinned_repository(tmp_path, origin_head):
    repo = make_repo(tmp_path, tier="A")
    if not origin_head:
        repo.git("symbolic-ref", "--delete", "refs/remotes/origin/HEAD")
    gh = FakeGh("2.93.0", (1, "", "no"), api={"full_name": REPOSITORY, "default_branch": "trunk"})
    rv.verify_release(repo.root, "HEAD", run=gh, tier_runner=tier_runner("A"))
    assert gh.api_calls == [["api", "--method", "GET", f"repos/{REPOSITORY}"]]
    argv = gh.verify_calls[0]
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/trunk"
    assert argv[argv.index("--repo") + 1] == REPOSITORY


_WHY = f"cannot pin the source ref to the default branch: gh api repos/{REPOSITORY}"


@needs_git
@pytest.mark.parametrize("api, message", [
    ((1, "", "HTTP 404: Not Found\n"), f"{_WHY} failed: HTTP 404: Not Found"),
    ((1, "", ""), f"{_WHY} failed (exit 1)"),
    ((0, "not json", ""), f"{_WHY} printed no JSON"),
    ([], f"{_WHY} printed no repository object"),
    ({}, f"{_WHY} printed no usable default_branch"),
    ({"default_branch": ""}, f"{_WHY} printed no usable default_branch"),
    ({"default_branch": 7}, f"{_WHY} printed no usable default_branch"),
    ({"default_branch": " main"}, f"{_WHY} printed no usable default_branch"),
], ids=["404", "rc1", "notjson", "list", "empty", "blank", "int", "space"])
def test_an_unreadable_default_branch_fails_closed_before_any_attestation(tmp_path, api, message):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""), api=api)
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("A"))
    assert (report.verified, report.code, report.status) == (False, "default_branch_unknown", "failed")
    assert report.message == message and gh.verify_calls == []


@needs_git
@pytest.mark.parametrize("source_ref, code", [("refs/heads/release/x", "source_ref_mismatch"),
                                              ("refs/heads/main", "verified")], ids=["other", "default"])
def test_a_caller_may_assert_the_source_ref_but_not_choose_another(tmp_path, source_ref, code):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("A"), source_ref=source_ref)
    assert report.code == code
    if code == "source_ref_mismatch":
        assert gh.verify_calls == [] and report.message == (
            f"refs/heads/release/x is not the default branch GitHub reports for {REPOSITORY} (refs/heads/main)")


# ── the trust tier is on every report (R-trust-41) ──────────────────────────

@needs_git
def test_a_rejected_attestation_still_reports_the_tier(tmp_path):
    repo = make_repo(tmp_path, tier="B")
    report = rv.verify_release(repo.root, "HEAD", run=FakeGh("2.93.0", (1, "", "no matching attestations")),
                               tier_runner=tier_runner("B"))
    assert (report.code, report.tier) == ("rejected", "B")
    assert "  trust tier: B" in render_release(report.as_dict())


@needs_git
@pytest.mark.parametrize("api, code", [((1, "", "HTTP 404"), "default_branch_unknown"), (DEFAULT_API, "bad_commit")],
                         ids=["no-branch", "bad-commit"])
def test_every_failure_after_the_work_tree_check_carries_the_tier(tmp_path, api, code):
    repo = make_repo(tmp_path, tier="A")
    sha = "HEAD" if code == "default_branch_unknown" else "b" * 40
    report = rv.verify_release(repo.root, sha, run=FakeGh("2.93.0", api=api), tier_runner=tier_runner("A"))
    assert (report.code, report.tier) == (code, "A")


def test_a_report_without_gh_says_the_tier_is_unknown(tmp_path):
    report = rv.verify_release(tmp_path, "HEAD", run=FakeGh(None), tier_runner=tier_runner_none)
    assert "  trust tier: unknown (gh unavailable)" in render_release(report.as_dict())
    outside = rv.verify_release(tmp_path, "HEAD", run=FakeGh("2.93.0"), tier_runner=tier_runner_none)
    assert "  trust tier: unknown (not a git repository)" in render_release(outside.as_dict())


@needs_git
def test_doctor_drivers_says_it_did_not_read_the_tier_and_asks_gh_nothing(tmp_path, monkeypatch, capsys):
    from aegis_core import ghcli

    asked = []
    monkeypatch.setattr(ghcli, "default_gh_runner", lambda argv, stdin=None, cwd=None, **kw: asked.append(argv))
    repo = make_repo(tmp_path)
    _rc, out, _err = cli(repo.root, monkeypatch, capsys, os.environ.get("PATH", ""), "--drivers")
    assert "Trust tier: not read in this mode (run aegis doctor)" in out.splitlines() and asked == []


# ── tier A needs an independent approving review (R-trust-55) ───────────────

def _approval(tmp_path, tier: str = "A", **answers: Any):
    repo = make_repo(tmp_path, tier=tier)
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""), **answers)
    runner = tier_runner(tier) if tier in ("A", "B") else tier_runner_none
    return rv.verify_release(repo.root, commit, run=gh, tier_runner=runner), gh, commit


@needs_git
def test_an_approving_review_by_someone_else_on_the_merged_head_verifies(tmp_path):
    report, gh, commit = _approval(tmp_path)
    assert report.verified and report.code == "verified"
    assert gh.api_calls[1:] == [["api", "--method", "GET", f"repos/{REPOSITORY}/commits/{commit}/pulls"],
                                ["api", "--method", "GET", f"repos/{REPOSITORY}/pulls/7/reviews?per_page=100"]]


_REVIEW_CASES = {
    "author-only": [{"state": "APPROVED", "user": {"login": "author"}, "commit_id": PR_HEAD}],
    "changes": [{"state": "CHANGES_REQUESTED", "user": {"login": "reviewer"}, "commit_id": PR_HEAD}],
    "dismissed": [{"state": "DISMISSED", "user": {"login": "reviewer"}, "commit_id": PR_HEAD}],
    "stale": [{"state": "APPROVED", "user": {"login": "reviewer"}, "commit_id": "d" * 40}],
    "none": [],
    "rc1": (1, "", "HTTP 502"),
    "notjson": (0, "not json", ""),
    "object": {"state": "APPROVED"},
    "not-objects": [1, "APPROVED", None, ["APPROVED"]],
}


@needs_git
@pytest.mark.parametrize("case", sorted(_REVIEW_CASES))
def test_without_an_independent_approval_on_the_head_it_is_not_approved(tmp_path, case):
    report, _gh, _commit = _approval(tmp_path, reviews=_REVIEW_CASES[case])
    assert (report.verified, report.attested, report.code, report.status) == (False, True, "not_approved", "failed")
    assert report.tier == "A" and render_release(report.as_dict())[0].startswith("NOT VERIFIED:")


@needs_git
def test_a_review_entry_that_is_not_an_object_is_skipped_not_fatal(tmp_path):
    report, _gh, _commit = _approval(tmp_path, reviews=[1, DEFAULT_REVIEWS[0]])
    assert report.verified and report.code == "verified"


@needs_git
def test_the_cli_prints_the_json_report_for_a_malformed_reviews_answer(tmp_path, monkeypatch, capsys):
    from aegis_core import ghcli

    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    release = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""), reviews=[1])
    monkeypatch.setattr(ghcli, "default_gh_runner", TierAndReleaseGh("A", release))
    rc, out, err = cli(repo.root, monkeypatch, capsys, os.environ.get("PATH", ""), "--release", commit, "--json")
    payload = json.loads(out)
    assert rc == 1 and (payload["code"], payload["status"], payload["verified"]) == ("not_approved", "failed", False)
    assert "Error" not in err


_PULL_CASES = {
    "direct-push": [],
    "unmerged": [dict(DEFAULT_PULLS[0], merged_at=None)],
    "other-base": [dict(DEFAULT_PULLS[0], base={"ref": "develop"})],
    "rc1": (1, "", "HTTP 404"),
    "notjson": (0, "<html>", ""),
}


@needs_git
@pytest.mark.parametrize("case", sorted(_PULL_CASES))
def test_a_commit_no_merged_pull_request_landed_is_not_approved(tmp_path, case):
    report, gh, _commit = _approval(tmp_path, pulls=_PULL_CASES[case])
    assert (report.verified, report.code) == (False, "not_approved")
    assert not [c for c in gh.api_calls if c[-1].endswith("/reviews?per_page=100")]


@needs_git
def test_a_tier_below_a_is_agent_editable_before_any_review_is_read(tmp_path):
    report, gh, _commit = _approval(tmp_path, tier="C", reviews=[])
    assert report.code == "agent_editable" and gh.api_calls == [["api", "--method", "GET", f"repos/{REPOSITORY}"]]


def test_an_attested_but_unapproved_report_is_consistent():
    report = rv.ReleaseReport("a" * 40, False, "not_approved", "m", attested=True)
    assert report.status == "failed" and report.as_dict()["attested"] is True


# ── one consistent report, git failures included (R-trust-56) ───────────────

@pytest.mark.parametrize("verified, code, attested", [
    (True, "rejected", False), (False, "verified", True), (True, "verified", False), (False, "agent_editable", False),
    (False, "rejected", True),
], ids=["v-rejected", "verified-unset", "verified-unattested", "editable-unattested", "rejected-attested"])
def test_an_inconsistent_report_cannot_be_built(verified, code, attested):
    with pytest.raises(ValueError):
        rv.ReleaseReport("a" * 40, verified, code, "message", attested=attested)


def _git_tree_lookup(monkeypatch, answer):
    """``gitsafe.run`` with the commit's tree lookup replaced by ``answer`` (a result or an exception)."""
    import subprocess

    from aegis_core import gitsafe

    real = gitsafe.run

    def run(args, cwd, *a, **kw):
        if any(str(x).endswith("^{tree}") for x in args):
            if isinstance(answer, Exception):
                raise answer
            return subprocess.CompletedProcess(["git", *args], answer, b"", b"fatal: bad object")
        return real(args, cwd, *a, **kw)

    monkeypatch.setattr(gitsafe, "run", run)


@needs_git
def test_a_git_failure_is_a_report_not_an_exception(tmp_path, monkeypatch):
    from aegis_core import gitsafe

    repo = make_repo(tmp_path, tier="A")
    _git_tree_lookup(monkeypatch, gitsafe.GitError("git rev-parse timed out after 30s"))
    gh = FakeGh("2.93.0")
    report = rv.verify_release(repo.root, "HEAD", run=gh, tier_runner=tier_runner("A"))
    assert (report.verified, report.code, report.status) == (False, "git_failed", "failed")
    assert report.message == "git could not answer: git rev-parse timed out after 30s" and gh.verify_calls == []


@needs_git
def test_a_tree_lookup_that_git_refuses_is_a_bad_commit(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, tier="A")
    _git_tree_lookup(monkeypatch, 128)
    report = rv.verify_release(repo.root, "HEAD", run=FakeGh("2.93.0"), tier_runner=tier_runner("A"))
    assert (report.verified, report.code) == (False, "bad_commit")


@needs_git
def test_the_cli_prints_the_json_envelope_for_a_git_failure(tmp_path, monkeypatch, capsys):
    from aegis_core import ghcli, gitsafe

    repo = make_repo(tmp_path)
    head = repo.head()
    release = FakeGh("2.93.0")
    monkeypatch.setattr(ghcli, "default_gh_runner", TierAndReleaseGh("A", release))
    _git_tree_lookup(monkeypatch, gitsafe.GitError("git rev-parse timed out after 30s"))
    rc, out, err = cli(repo.root, monkeypatch, capsys, os.environ.get("PATH", ""), "--release", head, "--json")
    payload = json.loads(out)
    assert rc == 1 and (payload["code"], payload["status"], payload["verified"]) == ("git_failed", "failed", False)
    assert "Error" not in err


@needs_git
@pytest.mark.parametrize("remote,expected", [
    ("git@github.com:owner/project.git", REPOSITORY),
    ("ssh://git@github.com/owner/project", REPOSITORY),
    ("https://gitlab.com/owner/project.git", None),
    (None, None),
])
def test_the_repository_pin_comes_from_a_github_origin_only(tmp_path, remote, expected):
    repo = make_repo(tmp_path, remote=remote, tier="A")
    gh = FakeGh("2.93.0", (1, "", "no"))
    report = rv.verify_release(repo.root, "HEAD", run=gh, tier_runner=tier_runner("A"))
    if expected is None:
        assert report.code == "no_repository" and gh.verify_calls == []
    else:
        assert gh.verify_calls[0][gh.verify_calls[0].index("--repo") + 1] == expected


@needs_git
def test_an_unknown_commit_is_not_verified_and_gh_is_not_asked(tmp_path):
    gh = FakeGh("2.93.0")
    report = rv.verify_release(make_repo(tmp_path).root, "b" * 40, run=gh, tier_runner=tier_runner_none)
    assert report.code == "bad_commit" and gh.verify_calls == []


def test_outside_a_repository_nothing_is_verified(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    report = rv.verify_release(plain, "a" * 40, run=FakeGh("2.93.0"), tier_runner=tier_runner_none)
    assert report.code == "not_a_repository" and not report.verified


@needs_git
def test_verifying_writes_nothing_into_the_repository(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    before = sorted(p.relative_to(repo.root).as_posix() for p in repo.root.rglob("*") if ".git" not in p.parts)
    rv.verify_release(repo.root, commit, run=FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), "")), tier_runner=tier_runner("A"))
    after = sorted(p.relative_to(repo.root).as_posix() for p in repo.root.rglob("*") if ".git" not in p.parts)
    assert before == after


# ── the default gh runner (R-trust-29) ───────────────────────────────────────

class RecordingRunner:
    """ghcli.default_gh_runner's signature; answers ``result`` (or raises it) and records each call."""

    def __init__(self, result: Any) -> None:
        self.result, self.calls = result, []

    def __call__(self, argv, stdin=None, cwd=None, timeout=None):
        self.calls.append((list(argv), cwd, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_a_type_error_inside_the_runner_propagates_and_gh_runs_once(tmp_path, monkeypatch):
    """Given a gh runner with a bug that raises TypeError, When the release closure runs gh --version,
    Then the TypeError surfaces after one call: no second gh call with other arguments."""
    from aegis_core import ghcli

    runner = RecordingRunner(TypeError("runner bug"))
    monkeypatch.setattr(ghcli, "default_gh_runner", runner)
    with pytest.raises(TypeError, match="runner bug"):
        rv.default_gh(tmp_path)(["--version"], 20.0)
    assert runner.calls == [(["--version"], tmp_path, 20.0)]


def test_the_closure_maps_the_runner_result_and_defaults_to_the_release_timeout(tmp_path, monkeypatch):
    from aegis_core import ghcli

    runner = RecordingRunner(ghcli.GhResult(0, "gh version 2.93.0 (2026-10-01)\n", "warning"))
    monkeypatch.setattr(ghcli, "default_gh_runner", runner)
    run = rv.default_gh(tmp_path)
    assert runner.calls == []
    assert run(["--version"], 20.0) == (0, "gh version 2.93.0 (2026-10-01)\n", "warning")
    run(["auth", "status"])
    assert runner.calls[-1] == (["auth", "status"], tmp_path, rv.GH_TIMEOUT_SECONDS)


def test_a_missing_gh_is_none_through_the_closure(tmp_path, monkeypatch):
    from aegis_core import ghcli

    monkeypatch.setattr(ghcli, "default_gh_runner", RecordingRunner(None))
    assert rv.default_gh(tmp_path)(["--version"], 20.0) is None


@needs_git
def test_without_an_injected_gh_the_conftest_stub_reads_as_gh_missing(tmp_path):
    report = rv.verify_release(make_repo(tmp_path).root, "HEAD", tier_runner=tier_runner_none)
    assert (report.code, report.verified, report.status) == ("gh_missing", False, "unverified")


def test_default_gh_takes_only_the_repository_root():
    import inspect

    assert list(inspect.signature(rv.default_gh).parameters) == ["root"]


# ── doctor --release, CLI level ─────────────────────────────────────────────

def fake_gh_dir(directory: Path, version: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "gh"
    script.write_text(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'gh version {version} (2026-01-01)'; exit 0; fi\n"
                      "exit 1\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return directory


def cli(repo_root: Path, monkeypatch, capsys, path: str, *args: str) -> Tuple[int, str, str]:
    monkeypatch.setenv("PATH", path)
    os.chdir(repo_root)
    try:
        rc = main(["doctor", *args])
    except SystemExit as exc:
        rc = exc.code
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


@needs_git
def test_the_json_report_carries_the_envelope_and_fails_closed_without_gh(tmp_path, monkeypatch, capsys,
                                                                            real_gh_runner):
    repo = make_repo(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    path = f"{empty}{os.pathsep}{os.path.dirname(shutil.which('git'))}"
    rc, out, _err = cli(repo.root, monkeypatch, capsys, path, "--release", repo.head(), "--json")
    payload = json.loads(out)
    assert rc not in (0, None)
    for key in ("source", "aegis_version", "checked_at", "scope"):
        assert payload[key]
    assert payload["status"] == "unverified" and payload["verified"] is False
    assert payload["scope"]["commit"] == repo.head()


@needs_git
@posix_only
def test_the_cli_with_gh_2_45_prints_unverified(tmp_path, monkeypatch, capsys, real_gh_runner):
    repo = make_repo(tmp_path)
    gh_dir = fake_gh_dir(tmp_path / "bin", "2.45.0")
    path = f"{gh_dir}{os.pathsep}{os.path.dirname(shutil.which('git'))}"
    rc, out, _err = cli(repo.root, monkeypatch, capsys, path, "--release", repo.head())
    assert rc == 1
    assert out.splitlines()[0] == "UNVERIFIED (gh >= 2.93.0 required)"
    assert "gh 2.45.0 is installed" in out  # the fake gh on PATH ran, not the conftest stub


@needs_git
@posix_only
def test_the_cli_fails_closed_when_gh_cannot_name_the_default_branch(tmp_path, monkeypatch, capsys, real_gh_runner):
    repo = make_repo(tmp_path)
    gh_dir = fake_gh_dir(tmp_path / "bin", "2.93.0")
    path = f"{gh_dir}{os.pathsep}{os.path.dirname(shutil.which('git'))}"
    rc, out, _err = cli(repo.root, monkeypatch, capsys, path, "--release", repo.head(), "--json")
    payload = json.loads(out)
    assert rc == 1 and (payload["code"], payload["status"]) == ("default_branch_unknown", "failed")


class TierAndReleaseGh:
    """``ghcli.default_gh_runner`` for the CLI: ``gh api`` GETs go to the tier detector's
    fake, the rest to the release fake."""

    def __init__(self, tier: str, release: FakeGh) -> None:
        self.tier, self.release = tier_runner(tier), release

    def __call__(self, argv: Sequence[str], stdin: Optional[bytes] = None, cwd: Any = None, timeout: float = 0.0):
        from aegis_core import ghcli

        if list(argv)[:1] == ["api"] and not list(argv)[-1].startswith(f"repos/{REPOSITORY}"):
            return self.tier(argv, stdin, cwd)
        result = self.release(argv, timeout)
        return None if result is None else ghcli.GhResult(*result)


@needs_git
@pytest.mark.parametrize("tier, rc, first", [("A", 0, "VERIFIED:"), ("B", 1, "NOT VERIFIED:")])
def test_the_cli_says_verified_at_tier_a_only(tmp_path, monkeypatch, capsys, tier, rc, first):
    from aegis_core import ghcli

    repo = make_repo(tmp_path, tier=tier)
    commit, tree, digest = facts(repo)
    release = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""))
    monkeypatch.setattr(ghcli, "default_gh_runner", TierAndReleaseGh(tier, release))
    code, out, _err = cli(repo.root, monkeypatch, capsys, os.environ.get("PATH", ""), "--release", commit)
    assert (code, out.splitlines()[0].startswith(first)) == (rc, True), out
    assert f"trust tier: {tier}" in out and release.verify_calls


@needs_git
@pytest.mark.parametrize("extra", [["--fix"], ["--github"], ["--yes"]])
def test_release_does_not_combine_with_writing_modes(tmp_path, monkeypatch, capsys, extra):
    repo = make_repo(tmp_path)
    rc, _out, err = cli(repo.root, monkeypatch, capsys, os.environ.get("PATH", ""), "--release", "HEAD", *extra)
    assert rc == 2 and ("--release" in err or "--yes" in err)


@needs_git
def test_release_needs_a_commit(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path)
    rc, _out, err = cli(repo.root, monkeypatch, capsys, os.environ.get("PATH", ""), "--release", " ")
    assert rc == 2 and "--release" in err


# Author-recorded gh 2.103.2 output. See tests/fixtures/README.md for provenance and
# the sanitization boundary; this tests gh's JSON shape, not its cryptography.
def _recorded_attestation() -> list:
    return json.loads((ROOT / "tests/fixtures/gh_attestation_verify.json").read_text(encoding="utf-8"))


def _recorded_for(repo: hg.Repo) -> list:
    """Rebind only identities to a real temporary git repository, retaining the captured shape."""
    records = _recorded_attestation()
    result = records[0]["verificationResult"]
    statement, certificate = result["statement"], result["signature"]["certificate"]
    commit, tree, digest = facts(repo)
    statement["predicate"].update(commit=commit, tree=tree)
    statement["subject"][0]["digest"]["sha256"] = digest
    certificate.update(sourceRepositoryDigest=commit, buildSignerDigest=commit,
                       sourceRepositoryURI=f"https://github.com/{REPOSITORY}",
                       buildSignerURI=f"https://github.com/{REPOSITORY}/{rv.WORKFLOW}@refs/heads/main")
    return records


@needs_git
def test_author_recorded_gh_shape_verifies_through_public_release_api(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    records = _recorded_for(repo)
    gh = FakeGh("2.103.2", (0, json.dumps(records), ""))
    report = rv.verify_release(repo.root, repo.head(), run=gh, tier_runner=tier_runner("A"))
    assert report.verified is True and report.code == "verified" and report.tier == "A"
    assert report.details["run"] == records[0]["verificationResult"]["statement"]["predicate"]["run"]
    assert gh.subjects == [rv.subject_bytes(*facts(repo)[:2])]
    assert len(gh.verify_calls) == 1
    assert gh.verify_calls[0][gh.verify_calls[0].index("--source-ref") + 1] == "refs/heads/main"


def test_untouched_recorded_fixture_matches_its_original_subject():
    records = _recorded_attestation()
    result = records[0]["verificationResult"]
    statement, certificate = result["statement"], result["signature"]["certificate"]
    predicate = statement["predicate"]
    digest = hashlib.sha256(rv.subject_bytes(predicate["commit"], predicate["tree"])).hexdigest()
    assert statement["subject"][0]["digest"]["sha256"] == digest
    assert rv._recheck(json.dumps(records), predicate["commit"], predicate["tree"], digest,
                       "nseney1/Aegis-Guardrails", certificate["sourceRepositoryRef"]) == (
                           True, "", predicate["run"])


_RECORDED_MUTATIONS = [
    ("statement.predicateType", "other", "the predicate type is not the Aegis CI verdict"),
    ("statement.subject.0.digest.sha256", "0" * 64, "the attested subject is not this commit's verdict"),
    ("statement.predicate.commit", "0" * 40, "the predicate names another commit or tree"),
    ("statement.predicate.tree", "0" * 40, "the predicate names another commit or tree"),
    ("statement.predicate.run", "bad", "the predicate lacks a valid run id and attempt"),
    ("statement.predicate.jobs", {"validate": "failure"}, "the predicate does not say every job succeeded"),
    ("signature.certificate.sourceRepositoryDigest", "0" * 40, "the certificate is for another commit"),
    ("signature.certificate.buildSignerDigest", "0" * 40, "the certificate is for another commit"),
    ("signature.certificate.runnerEnvironment", "self-hosted", "the build did not run on a GitHub-hosted runner"),
    ("signature.certificate.sourceRepositoryURI", "https://github.com/other/repo", "the certificate is for another repository"),
    ("signature.certificate.sourceRepositoryRef", "refs/tags/v4.3.4", "the certificate is for another ref than refs/heads/main"),
    ("signature.certificate.buildSignerURI", "https://github.com/other/repo/workflow.yml", f"the signer is not {REPOSITORY}/{rv.WORKFLOW}"),
]


@needs_git
@pytest.mark.parametrize("field,value,reason", _RECORDED_MUTATIONS, ids=[m[0] for m in _RECORDED_MUTATIONS])
def test_recorded_gh_shape_rejects_each_rechecked_field(tmp_path, field, value, reason):
    repo = make_repo(tmp_path, tier="A")
    records = _recorded_for(repo)
    target = records[0]["verificationResult"]
    *parents, key = field.split(".")
    for parent in parents:
        target = target[int(parent)] if isinstance(target, list) else target[parent]
    target[key] = value
    gh = FakeGh("2.103.2", (0, json.dumps(records), ""))
    report = rv.verify_release(repo.root, repo.head(), run=gh, tier_runner=tier_runner("A"))
    assert report.verified is False and report.code == "bad_output"
    assert report.message == f"gh exited 0 but its output does not check out: {reason}"
