"""Release verification: was this exact commit green, according to a signed attestation (v4.3 spec T2).

The workflow's final ``verdict`` job (``.github/workflows/validate.yml``) runs only when every
other job succeeded and attests a subject derived from the commit alone::

    sha256("aegis-ci-verdict/v1\\ncommit <sha>\\ntree <tree>\\n")

with the predicate ``{commit, tree, run, jobs}``. ``verify_release`` rebuilds that subject from
local git and asks ``gh attestation verify`` to check it, pinning the repository, the signing
workflow and its digest, the source ref and digest, the predicate type, and hosted runners. The
source ref is the default branch GitHub reports for the repository (one read-only ``gh api`` GET),
never the clone's ``origin/HEAD``: the attestation must come from the branch whose protection the
trust tier measures. A caller may assert the expected ref; a different one is
``source_ref_mismatch``, and an unreadable default branch is ``default_branch_unknown``.
Pure-stdlib Python cannot check a Sigstore signature, so gh does, and a gh that is missing or
older than 2.93.0 (CVE-2025-25204 to 2.66; a token leak to 2.92) means the answer is
UNVERIFIED and the exit code is not zero. Exit 0 from gh is necessary, never sufficient: the
JSON it prints is re-checked field by field.

Whatever is verified, an attestation proves "this workflow, at this commit, said so". The release
claim needs trust tier A (``aegis_core.human_gate``): at tier C the workflow file is editable by
the agent, and at tier B a pull request runs its own workflow and aegis, so both report
"attestation present, but the workflow is agent-editable" and the exit code is not zero. At tier A
the release also needs the independent review that tier A promises (spec T2): a merged pull request
into the default branch holding the commit, approved on its head by someone other than its author
(two read-only ``gh api`` GETs); otherwise it is ``not_approved``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import hashlib
import json
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core import primitives
from aegis_core import ghcli, gitevidence, gitsafe, human_gate

__all__ = [
    "GH_MINIMUM",
    "PREDICATE_TYPE",
    "ReleaseReport",
    "SCHEMA",
    "SOURCE",
    "SUBJECT_DOMAIN",
    "UNVERIFIED_GH",
    "WORKFLOW",
    "default_gh",
    "release_approved",
    "subject_bytes",
    "verify_release",
]

SCHEMA = "aegis.release/v1"
SOURCE = "aegis doctor --release"
GH_MINIMUM = (2, 93, 0)
UNVERIFIED_GH = "UNVERIFIED (gh >= 2.93.0 required)"
# permanent: attestations already issued carry this URI; change it only in a release that accepts both
PREDICATE_TYPE = "https://aegis.example/predicate/ci-verdict/v1"
SUBJECT_DOMAIN = "aegis-ci-verdict/v1"
WORKFLOW = ".github/workflows/validate.yml"
TIER_C_CAVEAT = "attestation present, but the workflow is agent-editable"
GH_TIMEOUT_SECONDS = 180.0

_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
#: Codes reached after gh verified an attestation and its JSON re-checked.
_ATTESTED_CODES = frozenset({"verified", "agent_editable", "not_approved"})
_RUN_ID_ATTEMPT = re.compile(r"\A\d+/\d+\Z")
_VERSION = re.compile(r"gh version (\d+)\.(\d+)\.(\d+)")
_REMOTE = re.compile(
    r"(?:https?://(?:[^/@]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?\Z"
)

#: ``runner(argv, timeout)``: run ``gh <argv>`` and return (returncode, stdout, stderr), or None
#: when gh is not installed. Injectable so a test never reaches a real gh.
GhRun = Callable[[Sequence[str], float], Optional[Tuple[int, str, str]]]


def subject_bytes(commit: str, tree: str) -> bytes:
    """The bytes whose sha256 is the attestation subject: derivable from the commit alone."""
    return f"{SUBJECT_DOMAIN}\ncommit {commit}\ntree {tree}\n".encode("ascii")


@dataclass(frozen=True)
class ReleaseReport:
    """What was asked, what was established, and why not more."""

    sha: str
    verified: bool
    # verified | agent_editable | not_approved | gh_missing | gh_too_old | not_a_repository | bad_commit |
    # git_failed | no_repository | default_branch_unknown | source_ref_mismatch | rejected | bad_output
    code: str
    message: str
    tier: Optional[str] = None
    caveats: Tuple[str, ...] = ()
    repository: Optional[str] = None
    gh_version: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)
    attested: bool = False  # gh verified the attestation and its JSON re-checked (true at tier C too)

    def __post_init__(self) -> None:
        if self.verified != (self.code == "verified") or self.attested != (self.code in _ATTESTED_CODES):
            raise ValueError(f"inconsistent release report: verified={self.verified}, attested={self.attested}, "
                             f"code={self.code!r}")

    @property
    def unverified_gh(self) -> bool:
        return self.code in ("gh_missing", "gh_too_old")

    @property
    def status(self) -> str:
        if self.verified:
            return "verified"
        if self.unverified_gh:
            return "unverified"
        return "agent_editable" if self.code == "agent_editable" else "failed"

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        return {
            **primitives.envelope(SOURCE, {
                "machine": "local",
                "workspace": None if workspace is None else str(workspace),
                "mode": "release",
                "commit": self.sha,
                "repository": self.repository,
            }, schema=SCHEMA),
            "status": self.status,
            "verified": self.verified,
            "attested": self.attested,
            "code": self.code,
            "message": self.message,
            "gh_version": self.gh_version,
            "tier": self.tier,
            "caveats": list(self.caveats),
            "details": dict(self.details),
        }


def default_gh(root: Any) -> GhRun:
    """The ``GhRun`` for the repository at ``root``: ``ghcli.default_gh_runner``, looked up at each
    call so a patched runner is the one used."""
    def run(argv: Sequence[str], timeout: float = GH_TIMEOUT_SECONDS) -> Optional[Tuple[int, str, str]]:
        res = ghcli.default_gh_runner(argv, cwd=root, timeout=timeout)
        return None if res is None else (res.returncode, res.stdout, res.stderr)

    return run


def _gh_version(run: GhRun) -> Tuple[Optional[Tuple[int, int, int]], str]:
    """(version, why not): the running gh's version, or None with the reason."""
    result = run(["--version"], 20.0)
    if result is None:
        return None, "gh (the GitHub CLI) is not installed or not on PATH"
    found = _VERSION.search(result[1])
    if result[0] != 0 or not found:
        return None, "gh --version did not answer with a version"
    return (int(found.group(1)), int(found.group(2)), int(found.group(3))), ""


def _repository(root: Path) -> Optional[str]:
    """``owner/repo`` of the origin remote (github.com only)."""
    try:
        res = gitsafe.run(["config", "--get", "remote.origin.url"], root)
    except gitsafe.GitError:
        res = None
    if res is not None and res.returncode == 0:
        found = _REMOTE.match(res.stdout.decode("utf-8", "replace").strip())
        if found:
            return f"{found.group(1)}/{found.group(2)}"
    return None


def _default_branch(run: GhRun, repository: str) -> Tuple[Optional[str], str]:
    """(GitHub's default branch of ``repository``, why not): asked with the explicit ``owner/repo``
    that ``--repo`` pins, never gh's ``{owner}/{repo}`` placeholders (gh picks those from remotes)."""
    body, why = _gh_get(run, f"repos/{repository}")
    if why:
        return None, why
    if not isinstance(body, dict):
        return None, f"gh api repos/{repository} printed no repository object"
    branch = body.get("default_branch")
    if not isinstance(branch, str) or not branch or not branch.isprintable() or any(c.isspace() for c in branch):
        return None, f"gh api repos/{repository} printed no usable default_branch"
    return branch, ""


def _gh_get(run: GhRun, path: str) -> Tuple[Any, str]:
    """(parsed JSON of ``gh api --method GET <path>``, why not)."""
    asked = f"gh api {path.split('?', 1)[0]}"
    result = run(["api", "--method", "GET", path], 30.0)
    if result is None:
        return None, f"{asked} failed: gh is not installed"
    if result[0] != 0:
        detail = " ".join(result[2].split())[:300]
        return None, f"{asked} failed: {detail}" if detail else f"{asked} failed (exit {result[0]})"
    try:
        return json.loads(result[1]), ""
    except ValueError:
        return None, f"{asked} printed no JSON"


def _recheck(output: str, commit: str, tree: str, subject_digest: str, repository: str,
             source_ref: str) -> Tuple[bool, str, Optional[str]]:
    """Whether gh's JSON holds at least one attestation that says exactly what was asked."""
    try:
        records = json.loads(output)
    except ValueError:
        return False, "gh printed no JSON to re-check", None
    if not isinstance(records, list) or not records:
        return False, "gh reported no attestation for this commit", None
    reasons: List[str] = []
    for record in records:
        problem, run_str = _record_problem(record, commit, tree, subject_digest, repository, source_ref)
        if problem is None:
            return True, "", run_str
        reasons.append(problem)
    return False, "; ".join(dict.fromkeys(reasons)), None


def _record_problem(record: Any, commit: str, tree: str, subject_digest: str, repository: str,
                    source_ref: str) -> Tuple[Optional[str], Optional[str]]:
    result = record.get("verificationResult") if isinstance(record, dict) else None
    statement = result.get("statement") if isinstance(result, dict) else None
    signature = result.get("signature") if isinstance(result, dict) else None
    cert = signature.get("certificate") if isinstance(signature, dict) else None
    if not isinstance(statement, dict) or not isinstance(cert, dict):
        return "the verification result lacks its statement or certificate", None
    if statement.get("predicateType") != PREDICATE_TYPE:
        return "the predicate type is not the Aegis CI verdict", None
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not any(
            isinstance(s, dict) and isinstance(s.get("digest"), dict) and s["digest"].get("sha256") == subject_digest
            for s in subjects):
        return "the attested subject is not this commit's verdict", None
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or predicate.get("commit") != commit or predicate.get("tree") != tree:
        return "the predicate names another commit or tree", None
    run_val = predicate.get("run")
    if not isinstance(run_val, str) or not _RUN_ID_ATTEMPT.match(run_val):
        return "the predicate lacks a valid run id and attempt", None
    jobs = predicate.get("jobs")
    if not isinstance(jobs, dict) or not jobs or any(value != "success" for value in jobs.values()):
        return "the predicate does not say every job succeeded", None
    if cert.get("sourceRepositoryDigest") != commit or cert.get("buildSignerDigest") != commit:
        return "the certificate is for another commit", None
    if cert.get("runnerEnvironment") != "github-hosted":
        return "the build did not run on a GitHub-hosted runner", None
    uri = cert.get("sourceRepositoryURI")
    if not isinstance(uri, str) or uri.lower().rstrip("/") != f"https://github.com/{repository.lower()}":
        return "the certificate is for another repository", None
    if cert.get("sourceRepositoryRef") != source_ref:
        return f"the certificate is for another ref than {source_ref}", None
    signer = cert.get("buildSignerURI")
    if not isinstance(signer, str) or not signer.lower().startswith(f"https://github.com/{repository.lower()}/{WORKFLOW.lower()}@"):
        return f"the signer is not {repository}/{WORKFLOW}", None
    return None, run_val


def _field(obj: Mapping[str, Any], outer: str, inner: str) -> Any:
    value = obj.get(outer)
    return value.get(inner) if isinstance(value, dict) else None


def release_approved(commit: str, repository: str, branch: str, gh: GhRun) -> Tuple[bool, str]:
    """(approved, why not): a pull request into ``branch`` that merged ``commit`` holds an APPROVED
    review by someone other than its author on its head commit. Any failed or odd answer is False."""
    pulls, why = _gh_get(gh, f"repos/{repository}/commits/{commit}/pulls")
    if not isinstance(pulls, list):
        return False, why or "GitHub listed no pull requests for the commit"
    merged = [p for p in pulls if isinstance(p, dict) and p.get("merged_at") and _field(p, "base", "ref") == branch
              and isinstance(p.get("number"), int) and not isinstance(p["number"], bool)]
    if not merged:
        return False, f"no merged pull request into {branch} holds this commit"
    pull = merged[0]
    author, head = _field(pull, "user", "login"), _field(pull, "head", "sha")
    reviews, why = _gh_get(gh, f"repos/{repository}/pulls/{pull['number']}/reviews?per_page=100")
    if not isinstance(reviews, list):
        return False, why or "GitHub listed no reviews"
    for review in reviews:
        if not isinstance(review, dict):
            continue
        login = _field(review, "user", "login")
        if (review.get("state") == "APPROVED" and isinstance(login, str) and login and isinstance(author, str)
                and login != author and isinstance(head, str) and review.get("commit_id") == head):
            return True, ""
    return False, f"pull request #{pull['number']} has no approving review by someone other than its author on its head"


def _tier(root: Path, tier_runner: Optional[Callable[..., Any]]) -> Optional[str]:
    try:
        return human_gate.detect_tier(root, tier_runner).tier
    except Exception:  # noqa: BLE001 - detect_tier reports, it does not raise; this keeps a report a report
        return None


@gitsafe.scrubbed()
def verify_release(root: Any, sha: str, run: Optional[GhRun] = None, tier_runner: Optional[Callable[..., Any]] = None,
                   *, source_ref: Optional[str] = None) -> ReleaseReport:
    """Verify the CI-verdict attestation of ``sha`` (a commit id or a ref of the repository in ``root``).
    ``source_ref`` asserts the expected ref; it must equal GitHub's default branch. A caller that
    expects a particular run compares ``report.details["run"]`` itself."""
    top = Path(root)
    gh = run if run is not None else default_gh(top)
    version, why = _gh_version(gh)
    if version is None:
        return ReleaseReport(sha, False, "gh_missing", why)
    shown = ".".join(str(part) for part in version)
    if version < GH_MINIMUM:
        return ReleaseReport(sha, False, "gh_too_old", f"gh {shown} is installed; earlier versions mis-verify attestations "
                             "(CVE-2025-25204) or leak a token (to 2.92) and cannot pin the source digest", gh_version=shown)
    try:
        if gitsafe.toplevel(top) is None:
            return ReleaseReport(sha, False, "not_a_repository", f"{top} is not inside a git work tree", gh_version=shown)
    except gitsafe.GitError as exc:
        return ReleaseReport(sha, False, "git_failed", f"git could not answer: {exc}", gh_version=shown)
    tier = _tier(top, tier_runner)  # read once, so every report from here on carries it

    def failed(name: str, code: str, message: str, **extra: Any) -> ReleaseReport:
        return ReleaseReport(name, False, code, message, tier=tier, gh_version=shown, **extra)

    try:
        commit = gitsafe.resolve_commit(top, sha)
        tree = gitevidence.commit_tree(top, commit) if commit and _SHA.match(commit) else None
    except gitsafe.GitError as exc:
        return failed(sha, "git_failed", f"git could not answer: {exc}")
    if tree is None or not commit:
        return failed(sha, "bad_commit", f"{sha!r} is not a commit of this repository (fetch it first)")
    repository = _repository(top)
    if not repository:
        return failed(sha, "no_repository", "origin is not a github.com repository, so there is nothing to pin "
                      "the attestation to")
    branch, why_not = _default_branch(gh, repository)
    if branch is None:
        return failed(commit, "default_branch_unknown", f"cannot pin the source ref to the default branch: {why_not}",
                      repository=repository)
    eff_ref = f"refs/heads/{branch}"
    if source_ref is not None and source_ref != eff_ref:
        return failed(commit, "source_ref_mismatch",
                      f"{source_ref} is not the default branch GitHub reports for {repository} ({eff_ref})",
                      repository=repository)
    body = subject_bytes(commit, tree)
    digest = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix="aegis-release-") as directory:
        subject = Path(directory) / "subject.txt"
        subject.write_bytes(body)
        argv = ["attestation", "verify", str(subject), "--repo", repository, "--predicate-type", PREDICATE_TYPE,
                "--signer-workflow", f"{repository}/{WORKFLOW}", "--signer-digest", commit,
                "--source-ref", eff_ref, "--source-digest", commit, "--deny-self-hosted-runners", "--format", "json"]
        result = gh(argv, GH_TIMEOUT_SECONDS)
    pins: Dict[str, Any] = {"repository": repository, "signer_workflow": f"{repository}/{WORKFLOW}",
                            "source_ref": eff_ref, "digest": commit, "tree": tree, "subject_sha256": digest}
    if result is None:
        return failed(sha, "gh_missing", "gh disappeared during verification")
    if result[0] != 0:
        detail = " ".join(result[2].split())[:300] or "no detail"
        return failed(commit, "rejected", f"gh attestation verify failed: {detail}", repository=repository, details=pins)
    ok, reason, verified_run = _recheck(result[1], commit, tree, digest, repository, eff_ref)
    if verified_run is not None:
        pins["run"] = verified_run
    if not ok:
        return failed(commit, "bad_output", f"gh exited 0 but its output does not check out: {reason}",
                      repository=repository, details=pins)
    signed = f"signed by {pins['signer_workflow']} at {commit[:12]} on {eff_ref}"
    if tier != "A":
        # The SECURITY.md truth table: at tier C the agent can edit the workflow that signed, and at
        # tier B a pull request runs its own workflow, so the claim is not established; the
        # attestation is reported.
        return ReleaseReport(commit, False, "agent_editable", signed, tier=tier or "C", caveats=(TIER_C_CAVEAT,),
                             repository=repository, gh_version=shown, details=pins, attested=True)
    approved, why_not = release_approved(commit, repository, branch, gh)
    if not approved:
        return ReleaseReport(commit, False, "not_approved", f"attestation present ({signed}), but {why_not}", tier=tier,
                             repository=repository, gh_version=shown, details=pins, attested=True)
    return ReleaseReport(commit, True, "verified", signed, tier=tier, repository=repository, gh_version=shown,
                         details=pins, attested=True)
