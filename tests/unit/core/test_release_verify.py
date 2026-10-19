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


def test_the_subject_is_derivable_from_the_commit_alone():
    commit, tree = "1" * 40, "2" * 40
    assert rv.subject_bytes(commit, tree) == f"aegis-ci-verdict/v1\ncommit {commit}\ntree {tree}\n".encode()


# ── doctor --release, library level ─────────────────────────────────────────

class FakeGh:
    """``gh --version`` answers ``version``; ``gh attestation verify`` answers ``verify``."""

    def __init__(self, version: Optional[str] = "2.93.0", verify: Tuple[int, str, str] = (0, "[]", "")) -> None:
        self.version = version
        self.verify = verify
        self.calls: List[List[str]] = []
        self.subjects: List[bytes] = []

    def __call__(self, argv: Sequence[str], timeout: float) -> Optional[Tuple[int, str, str]]:
        argv = list(argv)
        self.calls.append(argv)
        if self.version is None:
            return None
        if argv == ["--version"]:
            return 0, f"gh version {self.version} (2026-10-01)\nhttps://github.com/cli/cli/releases/tag/v{self.version}\n", ""
        if argv[:2] == ["attestation", "verify"]:
            self.subjects.append(Path(argv[2]).read_bytes())
            return self.verify
        return 1, "", "unexpected call"

    @property
    def verify_calls(self) -> List[List[str]]:
        return [c for c in self.calls if c[:2] == ["attestation", "verify"]]


# What the base branch must hold for the tier detector to reach each tier (with tier_runner's rules).
TIER_FILES = {"A": {".github/CODEOWNERS": hg.CODEOWNERS_FULL},
              "B": {"allowed_signers": hg.allowed_signers_text(hg.hardware_public_key())}}


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
    assert report.text_lines()[0] == rv.UNVERIFIED_GH
    assert gh.verify_calls == []


@pytest.mark.parametrize("version", [None, "garbage"])
def test_no_gh_or_a_gh_without_a_version_is_unverified(tmp_path, version):
    gh = FakeGh(version) if version is None else FakeGh()
    if version == "garbage":
        gh = lambda argv, timeout: (0, "something else\n", "")  # noqa: E731
    report = rv.verify_release(make_repo(tmp_path).root, "HEAD", run=gh, tier_runner=tier_runner_none)
    assert not report.verified and report.code == "gh_missing"
    assert rv.UNVERIFIED_GH in report.text_lines()


@needs_git
def test_every_pin_is_passed_and_the_subject_file_is_the_commit_subject(tmp_path):
    repo = make_repo(tmp_path, tier="B")
    commit, tree, digest = facts(repo)
    gh = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest)]), ""))
    report = rv.verify_release(repo.root, commit, run=gh, tier_runner=tier_runner("B"))
    assert report.verified and report.tier == "B", report.message
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
def test_expected_run_pin_rejects_mismatched_run_id_or_attempt(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    commit, tree, digest = facts(repo)
    gh_mismatch = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest, predicate__run="1/1")]), ""))
    bad = rv.verify_release(repo.root, commit, run=gh_mismatch, expected_run="1/2", tier_runner=tier_runner("A"))
    assert not bad.verified and bad.code == "bad_output"
    gh_match = FakeGh("2.93.0", (0, json.dumps([record(commit, tree, digest, predicate__run="42/3")]), ""))
    good = rv.verify_release(repo.root, commit, run=gh_match, expected_run="42/3", tier_runner=tier_runner("A"))
    assert good.verified and good.details.get("run") == "42/3"


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
    text = "\n".join(report.text_lines())
    assert "attestation present, but the workflow is agent-editable" in text
    assert report.as_dict()["attested"] is True


@needs_git
def test_the_source_ref_follows_origin_head(tmp_path):
    repo = make_repo(tmp_path, tier="A")
    repo.git("update-ref", "refs/remotes/origin/trunk", "HEAD")
    repo.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
    gh = FakeGh("2.93.0", (1, "", "no"))
    rv.verify_release(repo.root, "HEAD", run=gh, tier_runner=tier_runner("A"))
    argv = gh.verify_calls[0]
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/trunk"


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
def test_the_json_report_carries_the_envelope_and_fails_closed_without_gh(tmp_path, monkeypatch, capsys):
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
def test_the_cli_with_gh_2_45_prints_unverified(tmp_path, monkeypatch, capsys):
    repo = make_repo(tmp_path)
    gh_dir = fake_gh_dir(tmp_path / "bin", "2.45.0")
    path = f"{gh_dir}{os.pathsep}{os.path.dirname(shutil.which('git'))}"
    rc, out, _err = cli(repo.root, monkeypatch, capsys, path, "--release", repo.head())
    assert rc == 1
    assert out.splitlines()[0] == "UNVERIFIED (gh >= 2.93.0 required)"


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
