"""Release verification: was this exact commit green, according to a signed attestation (v4.3 spec T2).

The workflow's final ``verdict`` job (``.github/workflows/validate.yml``) runs only when every
other job succeeded and attests a subject derived from the commit alone::

    sha256("aegis-ci-verdict/v1\\ncommit <sha>\\ntree <tree>\\n")

with the predicate ``{commit, tree, run, jobs}``. ``verify_release`` rebuilds that subject from
local git and asks ``gh attestation verify`` to check it, pinning the repository, the signing
workflow and its digest, the source ref and digest, the predicate type, and hosted runners.
Pure-stdlib Python cannot check a Sigstore signature, so gh does, and a gh that is missing or
older than 2.93.0 (CVE-2025-25204 to 2.66; a token leak to 2.92) means the answer is
UNVERIFIED and the exit code is not zero. Exit 0 from gh is necessary, never sufficient: the
JSON it prints is re-checked field by field.

Whatever is verified, an attestation proves "this workflow, at this commit, said so". The release
claim needs trust tier A or B (``aegis_core.human_gate``): at tier C the workflow file is
editable by the agent, so the report says "attestation present, but the workflow is
agent-editable" and the exit code is not zero.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core import gitsafe, human_gate
from aegis_core._version import __version__

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
    "subject_bytes",
    "verify_release",
]

SCHEMA = "aegis.release/v1"
SOURCE = "aegis doctor --release"
GH_MINIMUM = (2, 93, 0)
UNVERIFIED_GH = "UNVERIFIED (gh >= 2.93.0 required)"
PREDICATE_TYPE = "https://aegis.example/predicate/ci-verdict/v1"
SUBJECT_DOMAIN = "aegis-ci-verdict/v1"
WORKFLOW = ".github/workflows/validate.yml"
TIER_C_CAVEAT = "attestation present, but the workflow is agent-editable"
GH_TIMEOUT_SECONDS = 180.0

_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
_RUN_ID_ATTEMPT = re.compile(r"\A\d+/\d+\Z")
_VERSION = re.compile(r"gh version (\d+)\.(\d+)\.(\d+)")
_REMOTE = re.compile(
    r"(?:https?://(?:[^/@]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?\Z"
)

#: ``runner(argv, timeout)``: run ``gh <argv>`` and return (returncode, stdout, stderr), or None
#: when gh is not installed. Injectable so a test never reaches a real gh.
GhRun = Callable[[Sequence[str], float], Optional[Tuple[int, str, str]]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def subject_bytes(commit: str, tree: str) -> bytes:
    """The bytes whose sha256 is the attestation subject: derivable from the commit alone."""
    return f"{SUBJECT_DOMAIN}\ncommit {commit}\ntree {tree}\n".encode("ascii")


@dataclass(frozen=True)
class ReleaseReport:
    """What was asked, what was established, and why not more."""

    sha: str
    verified: bool
    code: str  # verified | agent_editable | gh_missing | gh_too_old | not_a_repository | bad_commit | no_repository | rejected | bad_output
    message: str
    tier: Optional[str] = None
    caveats: Tuple[str, ...] = ()
    repository: Optional[str] = None
    gh_version: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=dict)
    attested: bool = False  # gh verified the attestation and its JSON re-checked (true at tier C too)

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

    def text_lines(self) -> List[str]:
        if self.unverified_gh:
            lines = [UNVERIFIED_GH, f"  {self.message}"]
        elif self.verified:
            lines = [
                f"VERIFIED: the CI verdict for {self.sha} is attested by {self.repository}'s {WORKFLOW}",
                f"  {self.message}",
            ]
        elif self.code == "agent_editable":
            lines = [f"NOT VERIFIED: {TIER_C_CAVEAT}", f"  {self.message}"]
        else:
            lines = [f"NOT VERIFIED: {self.message}"]
        if self.tier:
            lines.append(f"  trust tier: {self.tier}")
        lines += [f"  ! {caveat}" for caveat in self.caveats]
        return lines

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "source": SOURCE,
            "aegis_version": __version__,
            "checked_at": _utc_now(),
            "scope": {
                "machine": "local",
                "workspace": None if workspace is None else str(workspace),
                "mode": "release",
                "commit": self.sha,
                "repository": self.repository,
            },
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


def _invoke_gh(
    argv: Sequence[str],
    *,
    cwd: Any = None,
    timeout: float = GH_TIMEOUT_SECONDS,
) -> Optional[Tuple[int, str, str]]:
    try:
        res = human_gate.default_gh_runner(argv, cwd=cwd, timeout=timeout)
    except TypeError:
        res = human_gate._real_default_gh_runner(argv, cwd=cwd, timeout=timeout)
    if res is None:
        return None
    return res.returncode, res.stdout, res.stderr


def default_gh(root: Any, timeout: Optional[float] = None) -> Any:
    if isinstance(root, (list, tuple)):
        eff_timeout = GH_TIMEOUT_SECONDS if timeout is None else timeout
        return _invoke_gh(root, timeout=eff_timeout)

    def run(argv: Sequence[str], call_timeout: float = GH_TIMEOUT_SECONDS) -> Optional[Tuple[int, str, str]]:
        return _invoke_gh(argv, cwd=root, timeout=call_timeout)

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


def _repository(root: Path, environ: Mapping[str, str]) -> Optional[str]:
    """``owner/repo`` of the origin remote (github.com only), else $GITHUB_REPOSITORY."""
    try:
        res = gitsafe.run(["config", "--get", "remote.origin.url"], root)
    except gitsafe.GitError:
        res = None
    if res is not None and res.returncode == 0:
        found = _REMOTE.match(res.stdout.decode("utf-8", "replace").strip())
        if found:
            return f"{found.group(1)}/{found.group(2)}"
    fallback = (environ.get("GITHUB_REPOSITORY") or "").strip()
    return fallback if re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", fallback) else None


def _default_source_ref(root: Path) -> str:
    head = gitsafe.run(["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], root)
    name = head.stdout.decode("utf-8", "replace").strip() if head.returncode == 0 else ""
    prefix = "refs/remotes/origin/"
    return f"refs/heads/{name[len(prefix):]}" if name.startswith(prefix) and len(name) > len(prefix) else "refs/heads/main"


def _recheck(output: str, commit: str, tree: str, subject_digest: str, repository: str,
             source_ref: str, *, workflow: str = WORKFLOW, expected_run: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """Whether gh's JSON holds at least one attestation that says exactly what was asked."""
    try:
        records = json.loads(output)
    except ValueError:
        return False, "gh printed no JSON to re-check", None
    if not isinstance(records, list) or not records:
        return False, "gh reported no attestation for this commit", None
    reasons: List[str] = []
    for record in records:
        problem, run_str = _record_problem(
            record, commit, tree, subject_digest, repository, source_ref,
            workflow=workflow, expected_run=expected_run,
        )
        if problem is None:
            return True, "", run_str
        reasons.append(problem)
    return False, "; ".join(dict.fromkeys(reasons)), None


def _record_problem(record: Any, commit: str, tree: str, subject_digest: str, repository: str,
                    source_ref: str, *, workflow: str = WORKFLOW, expected_run: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
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
    if expected_run is not None and run_val != expected_run:
        return f"the predicate run {run_val!r} does not match expected {expected_run!r}", None
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
    if not isinstance(signer, str) or not signer.lower().startswith(f"https://github.com/{repository.lower()}/{workflow.lower()}@"):
        return f"the signer is not {repository}/{workflow}", None
    return None, run_val


def _tier(root: Path, tier_runner: Optional[Callable[..., Any]]) -> Optional[str]:
    from aegis_core import human_gate

    try:
        return human_gate.detect_tier(root, tier_runner).tier
    except Exception:  # noqa: BLE001 - detect_tier reports, it does not raise; this keeps a report a report
        return None


def verify_release(root: Any, sha: str, run: Optional[GhRun] = None, tier_runner: Optional[Callable[..., Any]] = None,
                   environ: Optional[Mapping[str, str]] = None, *, source_ref: Optional[str] = None,
                   workflow: Optional[str] = None, expected_run: Optional[str] = None) -> ReleaseReport:
    """Verify the CI-verdict attestation of ``sha`` (a commit id or a ref of the repository in ``root``)."""
    top = Path(root)
    env = os.environ if environ is None else environ
    gh = run if run is not None else default_gh(top)
    version, why = _gh_version(gh)
    if version is None:
        return ReleaseReport(sha, False, "gh_missing", why)
    shown = ".".join(str(part) for part in version)
    if version < GH_MINIMUM:
        return ReleaseReport(sha, False, "gh_too_old", f"gh {shown} is installed; earlier versions mis-verify attestations "
                             "(CVE-2025-25204) or leak a token (to 2.92) and cannot pin the source digest", gh_version=shown)
    if gitsafe.toplevel(top) is None:
        return ReleaseReport(sha, False, "not_a_repository", f"{top} is not inside a git work tree", gh_version=shown)
    commit = gitsafe.resolve_commit(top, sha)
    if not commit or not _SHA.match(commit):
        return ReleaseReport(sha, False, "bad_commit", f"{sha!r} is not a commit of this repository (fetch it first)",
                             gh_version=shown)
    tree = gitsafe.run(["rev-parse", "--verify", f"{commit}^{{tree}}"], top).stdout.decode("ascii", "replace").strip()
    repository = _repository(top, env)
    if not repository:
        return ReleaseReport(sha, False, "no_repository", "origin is not a github.com repository, so there is nothing to pin "
                             "the attestation to", gh_version=shown)
    eff_ref = source_ref or _default_source_ref(top)
    eff_workflow = workflow or WORKFLOW
    body = subject_bytes(commit, tree)
    digest = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix="aegis-release-") as directory:
        subject = Path(directory) / "subject.txt"
        subject.write_bytes(body)
        argv = ["attestation", "verify", str(subject), "--repo", repository, "--predicate-type", PREDICATE_TYPE,
                "--signer-workflow", f"{repository}/{eff_workflow}", "--signer-digest", commit,
                "--source-ref", eff_ref, "--source-digest", commit, "--deny-self-hosted-runners", "--format", "json"]
        result = gh(argv, GH_TIMEOUT_SECONDS)
    pins: Dict[str, Any] = {"repository": repository, "signer_workflow": f"{repository}/{eff_workflow}",
                            "source_ref": eff_ref, "digest": commit, "tree": tree, "subject_sha256": digest}
    if result is None:
        return ReleaseReport(sha, False, "gh_missing", "gh disappeared during verification", gh_version=shown)
    if result[0] != 0:
        detail = " ".join(result[2].split())[:300] or "no detail"
        return ReleaseReport(commit, False, "rejected", f"gh attestation verify failed: {detail}", repository=repository,
                             gh_version=shown, details=pins)
    ok, reason, verified_run = _recheck(
        result[1], commit, tree, digest, repository, eff_ref,
        workflow=eff_workflow, expected_run=expected_run,
    )
    if verified_run is not None:
        pins["run"] = verified_run
    if not ok:
        return ReleaseReport(commit, False, "bad_output", f"gh exited 0 but its output does not check out: {reason}",
                             repository=repository, gh_version=shown, details=pins)
    signed = f"signed by {pins['signer_workflow']} at {commit[:12]} on {eff_ref}"
    tier = _tier(top, tier_runner)
    if tier not in ("A", "B"):
        # Spec T2 precondition and the SECURITY.md truth table: at tier C the agent can edit the
        # workflow that signed, so the release claim is not established; the attestation is reported.
        return ReleaseReport(commit, False, "agent_editable", signed, tier=tier or "C", caveats=(TIER_C_CAVEAT,),
                             repository=repository, gh_version=shown, details=pins, attested=True)
    return ReleaseReport(commit, True, "verified", signed, tier=tier, repository=repository, gh_version=shown,
                         details=pins, attested=True)
