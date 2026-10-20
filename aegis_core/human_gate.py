"""``human_gate``: the trust tier and the approvals an agent cannot produce (v4.3 spec §2.2)."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Any, Callable, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union
from urllib.parse import quote

from aegis_core import gitsafe, governance, pathlookup
from aegis_core._version import __version__
from aegis_core.errors import AegisError
from aegis_core.storage import atomic_write_bytes
from aegis_core.workspace.layout import AEGIS_DIRNAME, RULES_RELDIR

__all__ = [
    "ALLOWED_SIGNERS",
    "Approval",
    "COVERAGE_SAMPLES",
    "GhResult",
    "HumanGateError",
    "INSIGHT_APPROVE_TRAILER",
    "KeyCustody",
    "RULESET_NAME",
    "SCHEMA",
    "SOURCE",
    "TierReport",
    "approval_message",
    "build_ruleset",
    "check_key_custody",
    "codeowners_coverage",
    "codeowners_lines",
    "create_ruleset",
    "default_gh_runner",
    "detect_tier",
    "exemption_message",
    "find_approval",
    "find_test_exemption",
    "governance_tree_hash",
    "insight_text_hash",
    "ruleset_exists",
    "signed_empty_commit",
    "signers_setup",
    "signing_config",
    "signing_keys_at",
    "verify_approval",
    "verify_insight_approval",
    "verify_test_exemption",
    "workflow_contexts",
]

SCHEMA = "aegis.human_gate/v1"
SOURCE = "aegis human_gate"
ALLOWED_SIGNERS = "allowed_signers"
RULESET_NAME = "aegis-human-gate"
INSIGHT_APPROVE_TRAILER = "Aegis-Approve-Insight"
GH_TIMEOUT_SECONDS = 10.0
SIGN_TIMEOUT_SECONDS = 300.0
HASH_DOMAIN = b"aegis-governance-tree/v1\n"
MAX_SCANNED_COMMITS = 500
_LABELS = {
    "A": "separation of duties",
    "B": "solo, signed",
    "C": "self-attested",
}
_STATEMENTS = {
    "A": "governance changes need a review by someone other than their author",
    "B": "governance changes need a signature from a key listed in allowed_signers on the base branch",
    "C": "detection and audit only: nothing here is enforced against the agent",
}
COVERAGE_SAMPLES: Tuple[str, ...] = (
    f"{RULES_RELDIR}/trap/sample.md",
    f"{AEGIS_DIRNAME}/config.json",
    f"{AEGIS_DIRNAME}/team.json",
    f"{AEGIS_DIRNAME}/baseline.json",
    "allowed_signers",
    ".github/workflows/ci.yml",
    "conftest.py",
    "pytest.ini",
    ".pytest.ini",
    "pytest.toml",
    ".pytest.toml",
    "tox.ini",
    "setup.cfg",
    "pyproject.toml",
    "sitecustomize.py",
    "evil.pth",
    "Makefile",
    *(f"{name}.py" for name in governance.RUNNER_MODULES),
    *(f"{name}/__init__.py" for name in governance.RUNNER_MODULES),
    *(f"{name}/__init__.pyc" for name in governance.RUNNER_MODULES),
    *(f"{name}/__main__.py" for name in governance.RUNNER_MODULES),
)
_CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
_OWNER = re.compile(r"\A(?:@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?|[^@\s]+@[^@\s]+\.[^@\s]+)\Z")
_MAX_CODEOWNERS_LINES = 5000
_MAX_PATTERN = 300
_ACCEPT_LINE = re.compile(r"^[ \t]*aegis-accept[ \t]*:", re.IGNORECASE | re.MULTILINE)
_APPROVE_LINE = re.compile(r"^[ \t]*aegis-approve[ \t]*:[ \t]*(\S*)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_APPROVE_INSIGHT_LINE = re.compile(r"^[ \t]*aegis-approve-insight[ \t]*:[ \t]*(\S*)[ \t]*$", re.IGNORECASE | re.MULTILINE)
_EXEMPT_TEST_LINE = re.compile(
    r"^[ \t]*Aegis-Exempt-Test:[ \t]*([0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?)[ \t]+(\S[^\r\n]*?)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
_JOB_ID = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*(?:#.*)?$")
_JOB_NAME = re.compile(r"""^    name:[ \t]*(?:"([^"]*)"|'([^']*)'|([^#\n]*?))[ \t]*(?:#.*)?$""")


class HumanGateError(AegisError):
    """git or the signing program cannot answer, or an input cannot be trusted."""


class GhResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


GhRunner = Callable[..., Optional[GhResult]]


def default_gh_runner(
    argv: Sequence[str],
    stdin: Optional[bytes] = None,
    cwd: Any = None,
    timeout: float = GH_TIMEOUT_SECONDS,
) -> Optional[GhResult]:
    exe = pathlookup.which("gh", outside=cwd)
    if exe is None:
        return None
    env = {
        **os.environ,
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "NO_COLOR": "1",
    }
    try:
        proc = subprocess.run(
            [exe, *argv],
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            env=env,
            cwd=None if cwd is None else str(cwd),
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return GhResult(124, "", f"gh timed out after {timeout:g}s")
    except OSError as exc:
        return GhResult(126, "", f"cannot run gh: {exc}")
    return GhResult(
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


_real_default_gh_runner = default_gh_runner


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_codeowners(text: str) -> List[Tuple[str, Tuple[str, ...]]]:
    entries: List[Tuple[str, Tuple[str, ...]]] = []
    for line in text.splitlines()[:_MAX_CODEOWNERS_LINES]:
        tokens = line.strip().split()
        if not tokens or tokens[0].startswith("#"):
            continue
        owners: List[str] = []
        for token in tokens[1:]:
            if token.startswith("#"):
                break
            if _OWNER.match(token):
                owners.append(token)
        entries.append((tokens[0], tuple(owners)))
    return entries


def _segment_match(pattern: str, text: str) -> bool:
    return fnmatch.fnmatchcase(text, pattern.replace("**", "*"))


def _prefix_ends(segments: List[str], parts: List[str], start: int) -> List[int]:
    ends = {start} if not segments else set()
    reach = {(0, start)}
    seen = set()
    while reach:
        si, pi = reach.pop()
        if (si, pi) in seen:
            continue
        seen.add((si, pi))
        if si == len(segments):
            ends.add(pi)
            continue
        seg = segments[si]
        if seg == "**":
            for end in range(pi, len(parts) + 1):
                reach.add((si + 1, end))
        elif pi < len(parts) and _segment_match(seg.replace("**", "*"), parts[pi]):
            reach.add((si + 1, pi + 1))
    return sorted(ends)


def _codeowners_match(pattern: str, path: str) -> bool:
    if (
        not pattern
        or len(pattern) > _MAX_PATTERN
        or pattern[0] == "!"
        or any(c in pattern for c in "[]\\")
    ):
        return False
    directory = pattern.endswith("/")
    core = pattern.strip("/")
    if not core:
        return False
    anchored = pattern.startswith("/") or "/" in core
    segments = core.split("/")
    parts = path.split("/")
    starts = [0] if anchored else range(len(parts))
    for start in starts:
        for end in _prefix_ends(segments, parts, start):
            if (end == len(parts) and not directory) or (end > start and directory):
                return True
    return False


def codeowners_coverage(
    text: str,
    location: str = "CODEOWNERS",
    *,
    repo_paths: Sequence[str] = (),
) -> Tuple[List[str], List[str]]:
    entries = _parse_codeowners(text)
    covered: List[str] = []
    uncovered: List[str] = []
    unsupported = any(any(c in pat for c in "[]\\") for pat, _ in entries)
    targets = dict.fromkeys(
        (
            *COVERAGE_SAMPLES,
            location.lstrip("/"),
            *(p.lstrip("/") for p in repo_paths if p and p.lstrip("/")),
        )
    )
    for path in targets:
        owners: Tuple[str, ...] = ()
        if not unsupported:
            for pattern, found in entries:
                if pattern.startswith("!"):
                    if not pattern[1:] or _codeowners_match(pattern[1:], path):
                        owners = ()
                elif _codeowners_match(pattern, path):
                    owners = found
        if owners:
            covered.append(path)
        else:
            uncovered.append(path)
    return covered, uncovered


def codeowners_lines(owner: str = "@OWNER") -> List[str]:
    paths = [
        f"/{RULES_RELDIR}/",
        f"/{AEGIS_DIRNAME}/config.json",
        f"/{AEGIS_DIRNAME}/team.json",
        f"/{AEGIS_DIRNAME}/baseline.json",
        "/allowed_signers",
        "/CODEOWNERS",
        "/.github/CODEOWNERS",
        "/.github/workflows/",
        "conftest.py",
        "pytest.ini",
        ".pytest.ini",
        "pytest.toml",
        ".pytest.toml",
        "tox.ini",
        "setup.cfg",
        "pyproject.toml",
        "sitecustomize.py",
        "*.pth",
        "Makefile",
        *(f"{name}.*" for name in governance.RUNNER_MODULES),
        *(f"/{name}/" for name in governance.RUNNER_MODULES),
    ]
    return [f"{path} {owner}" for path in paths]


@dataclass(frozen=True)
class KeyCustody:
    status: str
    detail: str
    degrades: bool
    key: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail,
            "degrades": self.degrades,
            "key": self.key,
        }


def _user_config(root: Path, key: str) -> Optional[str]:
    for scope in ("--global", "--system"):
        try:
            res = gitsafe.run(["config", scope, "--get", key], root)
        except gitsafe.GitError:
            return None
        if res.returncode == 0 and os.fsdecode(res.stdout).strip():
            return os.fsdecode(res.stdout).strip()
    return None


def signing_config(root: Any) -> Dict[str, Optional[str]]:
    r = Path(root)
    return {
        "format": (_user_config(r, "gpg.format") or "openpgp").lower(),
        "key": _user_config(r, "user.signingkey"),
    }


def _literal_key(value: str) -> Optional[str]:
    if value.startswith("key::"):
        return value[len("key::"):]
    if value.startswith(("ssh-", "sk-", "ecdsa-")):
        return value
    return None


def _wire_string(blob: bytes, offset: int) -> Tuple[bytes, int]:
    (size,) = struct.unpack_from(">I", blob, offset)
    start = offset + 4
    if size > len(blob) - start:
        raise ValueError("truncated")
    return blob[start : start + size], start + size


def _private_key_protection(path: Path) -> str:
    try:
        with open(path, "rb") as handle:
            data = handle.read(65536)
    except OSError:
        return "unreadable"
    if b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        body = data.split(b"-----BEGIN OPENSSH PRIVATE KEY-----", 1)[1].split(b"-----END", 1)[0]
        try:
            blob = base64.b64decode(b"".join(body.split()))
            if not blob.startswith(b"openssh-key-v1\x00"):
                return "unknown"
            cipher, at = _wire_string(blob, len(b"openssh-key-v1\x00"))
            _kdf, at = _wire_string(blob, at)
            _opts, at = _wire_string(blob, at)
            public, _ = _wire_string(blob, at + 4)
            key_type, _ = _wire_string(public, 0)
        except (ValueError, struct.error):
            return "unknown"
        if key_type.startswith(b"sk-"):
            return "hardware"
        if cipher == b"none":
            return "plain"
        return "encrypted"
    if b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in data or b"Proc-Type: 4,ENCRYPTED" in data:
        return "encrypted"
    if b"PRIVATE KEY-----" in data:
        return "plain"
    return "unknown"


def check_key_custody(root: Any) -> KeyCustody:
    config = signing_config(Path(root))
    value = config["key"]
    if not value:
        return KeyCustody("none", "no user.signingkey in the user-level git config", True)
    if config["format"] != "ssh":
        return KeyCustody(
            "unsupported",
            f"gpg.format is {config['format']!r}: approvals are SSH signatures checked against allowed_signers (git config --global gpg.format ssh)",
            True,
        )
    literal = _literal_key(value)
    if literal is not None:
        kind = literal.split()[0] if literal.split() else ""
        if kind.startswith("sk-"):
            return KeyCustody("hardware", "a security key (touch required)", False, kind)
        return KeyCustody(
            "agent",
            "the private key is held by an ssh-agent; whether it asks before signing is unverified from here",
            False,
            kind,
        )
    path = Path(os.path.expanduser(value))
    is_public = path.name.endswith(".pub")
    public = path if is_public else Path(str(path) + ".pub")
    private = Path(str(path)[:-len(".pub")]) if is_public else path
    try:
        pub_text = public.read_text(encoding="utf-8", errors="replace") if public.is_file() else ""
    except OSError:
        pub_text = ""
    name = private.name
    if pub_text.strip().startswith("sk-"):
        return KeyCustody("hardware", "a security key (touch required)", False, name)
    if not private.is_file():
        if is_public:
            return KeyCustody(
                "agent",
                "only the public key is on disk; the private key is held by an ssh-agent and whether it asks before signing is unverified from here",
                False,
                name,
            )
        return KeyCustody("unknown", f"the signing key file {name} was not found", False, name)
    protection = _private_key_protection(private)
    if protection == "hardware":
        return KeyCustody("hardware", "a security key handle (touch required)", False, name)
    if protection == "encrypted":
        return KeyCustody("passphrase", "the private key is passphrase-protected", False, name)
    if protection == "plain":
        return KeyCustody(
            "plain_file",
            f"the signing key {name} is a plain file with no passphrase, readable by this user: an agent running as you can sign with it, so a signature proves nothing",
            True,
            name,
        )
    return KeyCustody("unknown", f"the signing key file {name} could not be classified", False, name)


@dataclass(frozen=True)
class TierReport:
    tier: str
    reasons: Tuple[str, ...] = ()
    caveats: Tuple[str, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)
    scope: Mapping[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=_utc_now)

    @property
    def label(self) -> str:
        return _LABELS[self.tier]

    @property
    def statement(self) -> str:
        return _STATEMENTS[self.tier]

    @property
    def codeowners_complete(self) -> bool:
        return bool(
            isinstance(self.evidence.get("codeowners"), Mapping)
            and self.evidence["codeowners"].get("present")
            and not self.evidence["codeowners"].get("uncovered")
        )

    def text_lines(self) -> List[str]:
        return [
            f"Trust tier (human_gate): {self.tier} ({self.label}): {self.statement}",
            *(f"  - {r}" for r in self.reasons),
            *(f"  ! {c}" for c in self.caveats),
        ]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "source": SOURCE,
            "aegis_version": __version__,
            "checked_at": self.checked_at,
            "scope": dict(self.scope),
            "tier": self.tier,
            "label": self.label,
            "statement": self.statement,
            "reasons": list(self.reasons),
            "caveats": list(self.caveats),
            "evidence": json.loads(json.dumps(self.evidence)),
        }


def _gh_json(runner: GhRunner, endpoint: str, cwd: Path) -> Tuple[Any, Optional[str]]:
    result = runner(["api", "--method", "GET", endpoint], None, cwd)
    if result is None:
        return None, "gh is not installed"
    if result.returncode != 0:
        detail = " ".join((result.stderr or result.stdout).split())[:200] or f"exit {result.returncode}"
        return None, f"gh api {endpoint} failed: {detail}"
    try:
        return json.loads(result.stdout), None
    except ValueError:
        return None, f"gh api {endpoint} did not return JSON"


def _signer_keys(text: Optional[bytes]) -> int:
    decoded = (text or b"").decode("utf-8", "replace").splitlines()
    return sum(
        1
        for ln in decoded
        if ln.strip()
        and not ln.strip().startswith("#")
        and re.search(r"\b(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@.-]* [A-Za-z0-9+/=]{20,}", ln)
    )


def signing_keys_at(root: Any, rev: str) -> int:
    """How many keys ``allowed_signers`` lists at ``rev`` (0 when the file is absent). A GitError
    propagates: an unreadable base must fail the caller, not read as "no keys"."""
    return _signer_keys(gitsafe.read_blob(_top(root), rev, ALLOWED_SIGNERS))


def _ruleset_facts(rules: Any) -> Dict[str, Any]:
    approvals = 0
    owners = False
    contexts: List[str] = []
    has_pr = False
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        params = rule.get("parameters") if isinstance(rule.get("parameters"), dict) else {}
        if rule.get("type") == "pull_request":
            has_pr = True
            count = params.get("required_approving_review_count")
            valid_count = count if isinstance(count, int) and not isinstance(count, bool) else 0
            approvals = max(approvals, valid_count)
            owners = owners or params.get("require_code_owner_review") is True
        elif rule.get("type") == "required_status_checks":
            for check in params.get("required_status_checks") or []:
                if (
                    isinstance(check, dict)
                    and isinstance(check.get("context"), str)
                    and check["context"] not in contexts
                ):
                    contexts.append(check["context"])
    return {
        "pull_request": has_pr,
        "required_approving_review_count": approvals,
        "require_code_owner_review": owners,
        "required_status_checks": contexts,
    }


def detect_tier(
    root: Any,
    gh: Optional[GhRunner] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> TierReport:
    root = Path(root)
    runner: GhRunner = gh if gh is not None else default_gh_runner
    top = gitsafe.toplevel(root)
    evidence: Dict[str, Any] = {
        "gh": {"available": None, "error": None},
        "repo": None,
        "rules": None,
        "codeowners": None,
        "allowed_signers": None,
        "key_custody": None,
        "identity": None,
    }
    scope: Dict[str, Any] = {
        "machine": "local",
        "workspace": str(top or root),
        "repository": None,
        "base": None,
    }
    if top is None:
        return TierReport("C", ("not inside a git repository: nothing to detect",), (), evidence, scope)

    reasons: List[str] = []
    caveats: List[str] = []
    repo_info, why = _gh_json(runner, "repos/{owner}/{repo}", top)
    facts: Optional[Dict[str, Any]] = None
    default_branch: Optional[str] = None
    admin: Optional[bool] = None
    if why is not None or not isinstance(repo_info, dict):
        why = why or "gh api repos/{owner}/{repo} did not return an object"
        evidence["gh"] = {"available": why != "gh is not installed", "error": why}
        reasons.append(f"GitHub settings could not be read: {why}")
    else:
        evidence["gh"] = {"available": True, "error": None}
        if isinstance(repo_info.get("default_branch"), str):
            default_branch = repo_info.get("default_branch")
        perms = repo_info.get("permissions") if isinstance(repo_info.get("permissions"), dict) else {}
        if isinstance(perms.get("admin"), bool):
            admin = perms.get("admin")
        full = repo_info.get("full_name") if isinstance(repo_info.get("full_name"), str) else None
        scope["repository"] = full
        evidence["repo"] = {"full_name": full, "default_branch": default_branch}
        evidence["identity"] = {"admin": admin}
        if default_branch:
            rules, why = _gh_json(
                runner,
                "repos/{owner}/{repo}/rules/branches/" + quote(default_branch, safe=""),
                top,
            )
            if why is None:
                facts = _ruleset_facts(rules)
                evidence["rules"] = facts
            else:
                reasons.append(f"the default branch's rules could not be read: {why}")
        else:
            reasons.append("the repository's default branch is unknown")

    branch_candidates = [f"origin/{default_branch}", default_branch] if default_branch else []
    base = (
        next((c for c in branch_candidates if gitsafe.resolve_commit(top, c)), None)
        or gitsafe.resolve_base_ref(top)
    )
    scope["base"] = base
    tracked_gov = _tracked_governance_paths(top, base) if base is not None else ()
    codeowners: Dict[str, Any] = {
        "present": False,
        "path": None,
        "covered": [],
        "uncovered": list(dict.fromkeys((*COVERAGE_SAMPLES, *tracked_gov))),
    }
    signers: Dict[str, Any] = {"present": False, "keys": 0}
    if base is not None:
        for location in _CODEOWNERS_LOCATIONS:
            blob = _blob(top, base, location)
            if blob is not None:
                covered, uncovered = codeowners_coverage(
                    blob.decode("utf-8", "replace"),
                    location,
                    repo_paths=tracked_gov,
                )
                codeowners = {
                    "present": True,
                    "path": location,
                    "covered": covered,
                    "uncovered": uncovered,
                }
                break
        blob = _blob(top, base, ALLOWED_SIGNERS)
        signers = {"present": blob is not None, "keys": _signer_keys(blob)}
    evidence["codeowners"] = codeowners
    evidence["allowed_signers"] = signers
    custody = check_key_custody(top)
    evidence["key_custody"] = custody.as_dict()

    checks = facts["required_status_checks"] if facts else []
    a_missing: List[str] = []
    if facts is None:
        a_missing.append("the default branch's ruleset was not read")
    else:
        if facts["required_approving_review_count"] < 1:
            a_missing.append("the default branch does not require an approving review")
        if not facts["require_code_owner_review"]:
            a_missing.append("the default branch does not require code-owner review")
        if not checks:
            a_missing.append("the default branch has no required status checks")
    if not codeowners["present"]:
        a_missing.append("no CODEOWNERS file on the base branch")
    elif codeowners["uncovered"]:
        a_missing.append(f"CODEOWNERS leaves {len(codeowners['uncovered'])} governance path(s) without an owner")
    if admin is True:
        a_missing.append(
            "the gh identity doctor used is a repository admin, who can edit the ruleset (an agent needs its own non-admin identity)"
        )
    elif admin is None:
        a_missing.append("whether the gh identity is an admin is unknown")

    b_missing: List[str] = []
    if facts is None:
        b_missing.append("the default branch's ruleset was not read")
    elif not checks:
        b_missing.append("the default branch has no required status checks")
    if signers["keys"] < 1:
        b_missing.append(f"{ALLOWED_SIGNERS} on the base branch lists no signing key")
    if custody.degrades:
        if custody.status == "plain_file":
            b_missing.append(custody.detail)
        else:
            b_missing.append(f"signing key: {custody.detail}")

    if not a_missing:
        tier = "A"
        why_not: List[str] = []
    elif not b_missing:
        tier = "B"
        why_not = [f"not tier A: {m}" for m in a_missing]
    else:
        tier = "C"
        why_not = reasons + b_missing + [f"not tier A: {m}" for m in a_missing if m not in b_missing]
    if tier != "C":
        if admin is True:
            caveats.append(
                "the gh identity doctor used is a repository admin: an agent holding that token can edit the ruleset, so this tier holds only while that token is withheld from the agent"
            )
        if custody.status in ("agent", "unknown"):
            caveats.append(custody.detail)
        caveats.append(
            "a ruleset can name bypass actors, which this endpoint does not show; classic branch protection is not read at all"
        )
        if facts is not None and facts["required_status_checks"]:
            caveats.append(
                "which required checks run Aegis, and that they have no path filter, is not visible from here"
            )
    if tier == "B":
        caveats.append(
            "required checks run the pull request's own workflow and aegis, so a pull request can edit the check that verifies the signature; tier B holds only while pull requests leave .github/workflows/** and aegis alone"
        )
    return TierReport(tier, tuple(why_not), tuple(caveats), evidence, scope)


def _blob(top: Path, rev: str, path: str) -> Optional[bytes]:
    try:
        return gitsafe.read_blob(top, rev, path)
    except gitsafe.GitError:
        return None


def _top(root: Any) -> Path:
    top = gitsafe.toplevel(Path(root))
    if top is None:
        raise HumanGateError(f"{root} is not inside a git work tree")
    return top


def _tracked_governance_paths(workspace: Any, rev: str) -> Tuple[str, ...]:
    top = gitsafe.toplevel(Path(workspace))
    commit = gitsafe.resolve_commit(top, rev) if top else None
    if not top or not commit:
        return ()
    try:
        entries = gitsafe.tree_blobs(top, commit, include_symlinks=True, timeout=60.0)
    except gitsafe.GitError:
        return ()
    return tuple(
        path
        for path in entries
        if governance.category_of(path) is not None
    )


def _deleted_tests(top: Path, commit: str, base: str) -> List[bytes]:
    merge = gitsafe.merge_base(top, base, commit)
    if not merge:
        raise HumanGateError(f"cannot find where {base!r} and {commit[:12]} diverge in {top}")
    try:
        entries = gitsafe.diff_entries(top, merge, commit)
    except gitsafe.GitError as exc:
        raise HumanGateError(str(exc)) from exc
    return sorted(
        os.fsencode(path)
        for status, _old, _new, path in entries
        if status == "D" and governance.category_of(path, deleted=True) == governance.DELETED_TESTS
    )


def governance_tree_hash(root: Any, rev: str = "HEAD", base: Optional[str] = None) -> str:
    """The digest an approval signs: every governance blob at ``rev`` and, given ``base``, the
    tests deleted since ``merge-base(base, rev)``. Without a deleted test (or without ``base``)
    the digest is the v1 one, so earlier approvals keep verifying."""
    top = _top(root)
    commit = gitsafe.resolve_commit(top, rev)
    if not commit:
        raise HumanGateError(f"cannot resolve {rev!r} to a commit in {top}")
    try:
        entries = gitsafe.tree_blobs(top, commit, include_symlinks=True, timeout=60.0)
    except gitsafe.GitError as exc:
        raise HumanGateError(str(exc)) from exc
    records = [
        (
            os.fsencode(path),
            f"{mode} {oid}".encode("ascii"),
        )
        for path, (mode, oid) in entries.items()
        if governance.category_of(path)
    ]
    digest = hashlib.sha256(HASH_DOMAIN)
    for raw_path, meta in sorted(records):
        digest.update(meta + b" " + raw_path + b"\n")
    deleted = _deleted_tests(top, commit, base) if base is not None else []
    if deleted:
        # NUL never occurs in a git path, so this section cannot be mistaken for a record.
        digest.update(b"\0tests-deleted\0")
        for raw_path in deleted:
            digest.update(raw_path + b"\0")
    return digest.hexdigest()


def insight_text_hash(text: str) -> str:
    normalized = " ".join(text.strip().split())
    return hashlib.sha256(f"aegis-insight/v1\n{normalized}\n".encode("utf-8")).hexdigest()


class Approval(NamedTuple):
    valid: bool
    code: str
    reason: str
    commit: str
    signer: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.valid

    def as_dict(self, workspace: Any = None) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "source": SOURCE,
            "aegis_version": __version__,
            "checked_at": _utc_now(),
            "scope": {
                "machine": "local",
                "workspace": None if workspace is None else str(workspace),
                "commit": self.commit,
            },
            "valid": self.valid,
            "code": self.code,
            "reason": self.reason,
            "signer": self.signer,
        }


def approval_message(digest: str) -> str:
    return f"chore: approve governance state\n\nAegis-Approve: {digest}\n"


def exemption_message(fix_commit: str, reason: str) -> str:
    commit = (fix_commit or "").strip()
    why = (reason or "").strip()
    if not commit or not why:
        raise ValueError("fix_commit and reason must be non-empty")
    return f"chore: approve test exemption for {commit[:12]}\n\nAegis-Exempt-Test: {commit} {why}\n"


def _ssh_keygen(top: Path) -> str:
    found = pathlookup.which("ssh-keygen", outside=top)
    if not found:
        raise HumanGateError("ssh-keygen is not installed or not on PATH; SSH signatures cannot be made or checked")
    return found


def _no(code: str, reason: str, commit: str) -> Approval:
    return Approval(False, code, reason, commit)


def _verify_commit_sig(top: Path, oid: str, base: str, ok_reason: str) -> Approval:
    signers = gitsafe.read_blob(top, base, ALLOWED_SIGNERS)
    if _signer_keys(signers) < 1:
        return _no("no_allowed_signers", f"{ALLOWED_SIGNERS} on the base branch lists no key", oid)
    armor = _signature_armor(top, oid)
    if armor is not None and not armor.startswith(_SSH_ARMOR):
        return _no("bad_signature", "the signature is not an SSH signature, so it cannot be checked against allowed_signers", oid)
    status, fingerprint = _signature(top, oid, signers or b"")
    if status == "G":
        return Approval(True, "ok", ok_reason, oid, fingerprint)
    if status == "N":
        return _no("unsigned", "the commit is not signed", oid)
    if status == "U":
        return _no("untrusted_signature", "the signing key is not in the base allowed_signers", oid)
    if status == "E":
        return _no("unverifiable", "git could not check the signature", oid)
    return _no("bad_signature", f"the signature does not verify (git reports {status!r})", oid)


def _read_message(top: Path, oid: str) -> Union[str, Approval]:
    raw = gitsafe.run(["cat-file", "commit", oid], top)
    if raw.returncode != 0:
        return _no("unresolved", f"cannot read commit {oid}", oid)
    message = raw.stdout.decode("utf-8", "replace").partition("\n\n")[2]
    if _ACCEPT_LINE.search(message):
        return _no("accept_reserved", "the message carries an Aegis-Accept line, which is reserved", oid)
    return message


def _commits_in(top: Path, head: str, base_ref: str) -> Optional[Tuple[str, str, List[str]]]:
    """(tip, merge base, the commits of base..tip newest first, at most MAX_SCANNED_COMMITS)."""
    tip = gitsafe.resolve_commit(top, head)
    base = gitsafe.merge_base(top, base_ref, head)
    if not tip or not base:
        return None
    res = gitsafe.run(["rev-list", f"--max-count={MAX_SCANNED_COMMITS}", f"{base}..{tip}"], top)
    if res.returncode != 0:
        return None
    return tip, base, res.stdout.decode("ascii", "replace").split()


def _verify_single_trailer(
    root: Any,
    commit: str,
    base_ref: Optional[str],
    rx: re.Pattern[str],
    name: str,
    expected: str,
    mismatch_msg: str,
    ok_msg: str,
) -> Approval:
    try:
        top = _top(root)
        base_target = base_ref or gitsafe.resolve_base_ref(top)
        oid = gitsafe.resolve_commit(top, commit)
        base = gitsafe.resolve_commit(top, base_target) if base_target else None
        if not oid or not base:
            return _no("unresolved", f"cannot resolve {commit!r} or the base {base_ref!r}", str(commit))
        message = _read_message(top, oid)
        if isinstance(message, Approval):
            return message
        values = rx.findall(message)
        if not values:
            return _no("no_trailer", f"no {name} trailer", oid)
        if len(values) > 1:
            return _no("multiple_trailers", f"more than one {name} trailer", oid)
        if values[0].lower() != expected.lower():
            return _no("hash_mismatch", mismatch_msg, oid)
        return _verify_commit_sig(top, oid, base, ok_msg)
    except gitsafe.GitError as exc:
        return _no("unresolved", str(exc), str(commit))
    except HumanGateError as exc:
        return _no("unverifiable", str(exc), str(commit))


def verify_approval(root: Any, commit: str, governance_hash: str, base_ref: str) -> Approval:
    return _verify_single_trailer(
        root,
        commit,
        base_ref,
        _APPROVE_LINE,
        "Aegis-Approve",
        governance_hash,
        "the approved governance hash is not this governance state",
        "good signature by a key in the base allowed_signers",
    )


def verify_insight_approval(workspace: Any, commit: str, text: str, base_ref: Optional[str] = None) -> Approval:
    if not isinstance(commit, str) or not commit.strip() or not isinstance(text, str) or not text.strip():
        return _no("invalid_input", "commit and insight text must be non-empty", str(commit or ""))
    return _verify_single_trailer(
        workspace,
        commit,
        base_ref,
        _APPROVE_INSIGHT_LINE,
        INSIGHT_APPROVE_TRAILER,
        insight_text_hash(text),
        "the approved insight hash does not match this insight text",
        "insight approval verified",
    )


def verify_test_exemption(root: Any, approval_commit: str, fix_commit: str, base_ref: str) -> Approval:
    """No reason binding: the signature names the fix's full oid, which already commits to its message."""
    try:
        top = _top(root)
        oid, fix_oid, base = (gitsafe.resolve_commit(top, rev) for rev in (approval_commit, fix_commit, base_ref))
        if not oid or not fix_oid or not base:
            why = f"cannot resolve {approval_commit!r}, {fix_commit!r}, or the base {base_ref!r}"
            return _no("unresolved", why, str(approval_commit))
        message = _read_message(top, oid)
        if isinstance(message, Approval):
            return message
        entries = _EXEMPT_TEST_LINE.findall(message)
        if not entries:
            return _no("no_exemption_trailer", "no Aegis-Exempt-Test trailer naming a full commit id", oid)
        reasons = [r.strip() for t, r in entries if t.lower() == fix_oid.lower()]
        if not reasons:
            return _no("commit_mismatch", f"Aegis-Exempt-Test does not name fix commit {fix_oid[:12]}", oid)
        if len(reasons) > 1:
            return _no("multiple_trailers", "more than one Aegis-Exempt-Test trailer for this commit", oid)
        return _verify_commit_sig(top, oid, base, f"good test exemption for {fix_oid[:12]}: {reasons[0]}")
    except gitsafe.GitError as exc:
        return _no("unresolved", str(exc), str(approval_commit))
    except HumanGateError as exc:
        return _no("unverifiable", str(exc), str(approval_commit))


_SSH_ARMOR = "-----BEGIN SSH SIGNATURE-----"


def _signature_armor(top: Path, oid: str) -> Optional[str]:
    """The first line of the signature git checks (None when unsigned): git takes its format
    from this armor, and reads ``gpgsig-sha256`` in a SHA-256 repository, ``gpgsig`` otherwise."""
    raw = gitsafe.run(["cat-file", "commit", oid], top)
    if raw.returncode != 0:
        raise HumanGateError(f"cannot read commit {oid}")
    header = b"gpgsig-sha256 " if len(oid) == 64 else b"gpgsig "
    for line in raw.stdout.partition(b"\n\n")[0].split(b"\n"):
        if line.startswith(header):
            return line[len(header):].decode("ascii", "replace")
    return None


def _signature(top: Path, oid: str, signers: bytes) -> Tuple[str, Optional[str]]:
    program = _ssh_keygen(top)
    directory = Path(tempfile.mkdtemp(prefix="aegis-signers-"))
    try:
        os.chmod(directory, 0o700)
        path = directory / "allowed_signers"
        atomic_write_bytes(path, signers, mode=0o600)
        res = gitsafe.run(
            [
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={path}",
                "-c",
                f"gpg.ssh.program={program}",
                "log",
                "-1",
                "--format=%G?%n%GF",
                oid,
            ],
            top,
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    if res.returncode != 0:
        raise HumanGateError(f"git log could not check the signature of {oid}")
    lines = res.stdout.decode("utf-8", "replace").splitlines()
    status = lines[0].strip() if lines else "N"
    fingerprint = lines[1].strip() if len(lines) > 1 and lines[1].strip() else None
    return status, fingerprint


def find_approval(root: Any, head: str, base_ref: str, governance_hash: Optional[str] = None) -> Optional[Approval]:
    top = _top(root)
    scan = _commits_in(top, head, base_ref)
    if scan is None:
        return None
    tip, base, commits = scan
    digest = governance_hash or governance_tree_hash(top, tip, base=base)
    for oid in commits:
        verdict = verify_approval(top, oid, digest, base_ref)
        if verdict.valid:
            return verdict
    return None


def find_test_exemption(root: Any, head: str, base_ref: str, fix_commit: str) -> Optional[Approval]:
    """The first valid exemption of ``fix_commit`` in base..head; else the first rejected one whose
    trailer names it (so a refusal can say why); else None."""
    top = _top(root)
    scan = _commits_in(top, head, base_ref)
    fix_oid = gitsafe.resolve_commit(top, fix_commit)
    if scan is None or not fix_oid:
        return None
    rejected: Optional[Approval] = None
    for oid in scan[2]:
        if oid == fix_oid:  # a commit cannot carry its own full oid
            continue
        verdict = verify_test_exemption(top, oid, fix_oid, base_ref)
        if verdict.valid:
            return verdict
        if rejected is None and verdict.code not in ("no_exemption_trailer", "commit_mismatch"):
            rejected = verdict
    return rejected


def signed_empty_commit(root: Any, message: str) -> str:
    top = _top(root)
    config = signing_config(top)
    if config["format"] != "ssh" or not config["key"]:
        raise HumanGateError(
            "approvals are SSH signatures: set git config --global gpg.format ssh and git config --global user.signingkey <key>"
        )
    key = config["key"] or ""
    if not _literal_key(key):
        key = os.path.expanduser(key)
    res = gitsafe.run(
        [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={key}",
            "-c",
            f"gpg.ssh.program={_ssh_keygen(top)}",
            "-c",
            "commit.gpgsign=true",
            "commit",
            "-S",
            "--allow-empty",
            "--no-verify",
            "-m",
            message,
        ],
        top,
        timeout=SIGN_TIMEOUT_SECONDS,
    )
    if res.returncode != 0:
        detail = " ".join((res.stderr or res.stdout).decode("utf-8", "replace").split())[:300]
        raise HumanGateError(f"git could not make the signed commit: {detail}")
    commit = gitsafe.head_commit(top)
    if not commit:
        raise HumanGateError("the signed commit was made but HEAD cannot be read")
    return commit


def build_ruleset(tier: str, contexts: Iterable[str]) -> Dict[str, Any]:
    if tier not in ("A", "B"):
        raise ValueError(f"tier must be 'A' or 'B', got {tier!r}")
    reviewed = tier == "A"
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1 if reviewed else 0,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": reviewed,
                    "require_last_push_approval": reviewed,
                    "required_review_thread_resolution": False,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [{"context": c} for c in contexts],
                },
            },
        ],
    }


def workflow_contexts(root: Any) -> List[str]:
    directory = Path(root) / ".github" / "workflows"
    contexts: List[str] = []
    try:
        files = sorted(p for p in directory.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file())
    except OSError:
        return contexts
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()[:5000]
        on_match = re.search(r"(?m)^on:[ \t]*(.*(?:\n(?:[ \t]+.*|[ \t]*))*)", text)
        if on_match and not re.search(r"\b(?:push|pull_request)\b", on_match.group(1)):
            continue
        in_jobs = False
        jobs: List[Dict[str, Any]] = []
        cur: Optional[Dict[str, Any]] = None
        for line in lines + ["x:"]:
            if line.startswith("jobs:"):
                in_jobs = True
                continue
            if in_jobs and line and not line[0].isspace() and not line.startswith("#"):
                in_jobs = False
            if not in_jobs:
                continue
            found = _JOB_ID.match(line)
            if found:
                cur = {
                    "ctx": found.group(1),
                    "named": False,
                    "matrix": False,
                    "no_pr": False,
                    "always": False,
                    "needs": False,
                }
                jobs.append(cur)
                continue
            if cur is None:
                continue
            named_as = _JOB_NAME.match(line)
            if named_as and not cur["named"]:
                value = next((g for g in named_as.groups() if g), "")
                if value and "${{" not in value:
                    cur["ctx"] = value
                cur["named"] = True
            elif re.match(r"^      matrix\s*:", line):
                cur["matrix"] = True
            elif re.match(r"^    if\s*:", line):
                if "!= 'pull_request'" in line or '!= "pull_request"' in line:
                    cur["no_pr"] = True
                if "always()" in line:
                    cur["always"] = True
            elif re.match(r"^    needs\s*:", line):
                after = line.split(":", 1)[1].split("#", 1)[0].strip()
                if after != "[]":
                    cur["needs"] = True
        eligible = [j for j in jobs if not j["no_pr"] and not j["matrix"]]
        agg = [j["ctx"] for j in eligible if j["always"] and j["needs"]]
        contexts.extend(agg if agg else [j["ctx"] for j in eligible])
    return contexts


def ruleset_exists(root: Any, gh: Optional[GhRunner] = None) -> bool:
    runner: GhRunner = gh if gh is not None else default_gh_runner
    listing, why = _gh_json(runner, "repos/{owner}/{repo}/rulesets", Path(root))
    if why is not None or not isinstance(listing, list):
        raise HumanGateError(why or "gh api rulesets did not return a list")
    return any(isinstance(r, dict) and r.get("name") == RULESET_NAME for r in listing)


def create_ruleset(root: Any, ruleset: Mapping[str, Any], gh: Optional[GhRunner] = None) -> Dict[str, Any]:
    runner: GhRunner = gh if gh is not None else default_gh_runner
    result = runner(
        ["api", "--method", "POST", "repos/{owner}/{repo}/rulesets", "--input", "-"],
        json.dumps(ruleset).encode("utf-8"),
        Path(root),
    )
    if result is None:
        raise HumanGateError("gh is not installed")
    if result.returncode != 0:
        raise HumanGateError(f"gh could not create the ruleset: {' '.join(result.stderr.split())[:300]}")
    try:
        created = json.loads(result.stdout)
    except ValueError:
        created = {}
    return created if isinstance(created, dict) else {}


def signers_setup() -> List[str]:
    return [
        "# 1. A signing key the agent cannot use: a hardware key (touch required) or a passphrase-protected key.",
        "ssh-keygen -t ed25519-sk -f ~/.ssh/aegis_approval      # or: ssh-keygen -t ed25519 (set a passphrase)",
        "# 2. Tell git to sign with it (user-level config; a repository's config is never used for approvals).",
        "git config --global gpg.format ssh",
        "git config --global user.signingkey ~/.ssh/aegis_approval.pub",
        f"# 3. List the public key in {ALLOWED_SIGNERS} at the top of the default branch, through a reviewed pull request:",
        '#    you@example.com namespaces="git" <contents of ~/.ssh/aegis_approval.pub>',
        "# 4. When a pull request changes governance files, review it, then run: aegis approve",
    ]
