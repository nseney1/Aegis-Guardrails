"""``human_gate``: the trust tier and the approvals an agent cannot produce (v4.3 spec §2.2)."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import hashlib
import itertools
import json
import os
from pathlib import Path
import posixpath
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

__all__ = [
    "ALLOWED_SIGNERS",
    "Approval",
    "COVERAGE_SAMPLES",
    "GITHUB_ACTIONS_APP_ID",
    "GhResult",
    "HumanGateError",
    "INSIGHT_APPROVE_TRAILER",
    "KeyCustody",
    "PullRequest",
    "RULESET_NAME",
    "SCHEMA",
    "SOURCE",
    "TierReport",
    "aegis_check_jobs",
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
    "find_review_approval",
    "is_branch_name",
    "find_test_exemption",
    "governance_tree_hash",
    "insight_text_hash",
    "resolve_repo",
    "ruleset_exists",
    "signed_empty_commit",
    "signers_setup",
    "signing_config",
    "signing_keys_at",
    "verify_approval",
    "verify_insight_approval",
    "verify_test_exemption",
]

SCHEMA = "aegis.human_gate/v1"
SOURCE = "aegis human_gate"
ALLOWED_SIGNERS = "allowed_signers"
RULESET_NAME = "aegis-human-gate"
INSIGHT_APPROVE_TRAILER = "Aegis-Approve-Insight"
# github.com's GitHub Actions app: a required check sourced from it cannot be posted by a token.
GITHUB_ACTIONS_APP_ID = 15368
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
_CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
COVERAGE_SAMPLES: Tuple[str, ...] = tuple(dict.fromkeys(governance.coverage_samples() + _CODEOWNERS_LOCATIONS))
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
_JOB_MATRIX = re.compile(r"^    strategy:.*\bmatrix\b|^      matrix[ \t]*:")
_AEGIS_CHECK_CI = re.compile(r"(?:\baegis|-m[ \t]+aegis_cli(?:\.cli)?)[ \t]+check\b[^\n]*?[ \t]--ci(?![\w-])")
# The whole of a script that fails exactly when aegis fails, in any built-in shell: no operator, quote or expansion.
# `-I` (isolated mode, which keeps the checkout off sys.path so the installed wheel runs) is the one
# interpreter flag accepted; it cannot change the exit status.
_DIRECT_CHECK = re.compile(r"(?:aegis|python3?(?:[ \t]+-I)?[ \t]+-m[ \t]+aegis_cli(?:\.cli)?)[ \t]+check(?:[ \t]+[\w./=:@%+,-]+)*")
_KEY = re.compile(r"""["']?([\w-]+)["']?[ \t]*:(?:[ \t]+(.*))?""")
_ALWAYS = re.compile(r"""(["']?)(?:\$\{\{[ \t]*always\(\)[ \t]*\}\}|always\(\))\1""")
_SHELLS = ("bash", "sh", "pwsh", "powershell", "cmd", "python")
_PATH_FILTER_WHY = ("the Aegis workflow filters pull requests by path (paths: or paths-ignore: under "
                    "on.pull_request), so it does not run on every pull request")
_UNREAD_WHY = ("is not laid out as this check reads a workflow (job keys four spaces in, steps as a list of "
               "key: value lines, no YAML merge key or repeated key)")
_PR_EVENT = re.compile(r"""["']?\bpull_request(?:_target)?["']?[ \t]*:[ \t]*""")
_PATHS_KEY = re.compile(r"""(?:^|[\s{,])["']?paths(?:-ignore)?["']?[ \t]*:""")
_MAX_WORKFLOW_LINES = 5000


class HumanGateError(AegisError):
    """git or the signing program cannot answer, or an input cannot be trusted."""


class GhResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


GhRunner = Callable[..., Optional[GhResult]]
# scheme://[userinfo@]host[:port]/path and scp-style [user@]host:path. A port is dropped only where it
# is the git transport's (ssh, git); an http(s) port names another API endpoint than gh's host.
_URL_REMOTE = re.compile(r"\A(?P<scheme>https?|ssh|git)://(?:[^/@]*@)?(?P<host>[A-Za-z0-9.-]+)(?::(?P<port>\d+))?/(?P<path>.*)\Z")
_SCP_REMOTE = re.compile(r"\A(?:[^/@:]+@)?(?P<host>[A-Za-z0-9-][A-Za-z0-9.-]+):(?P<path>[^/].*)\Z")
_REPO_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_NO_REPO = "no GitHub repository could be resolved from remote.origin.url"


def resolve_repo(root: Any) -> Optional[str]:
    """``owner/repo`` (github.com) or ``host/owner/repo`` (gh's ``[HOST/]OWNER/REPO``) of
    ``remote.origin.url`` read through gitsafe; None for a path remote, a subgroup, no origin or a git
    that cannot answer. Userinfo (a token) never reaches the result."""
    try:
        res = gitsafe.run(["config", "--get", "remote.origin.url"], Path(root))
    except gitsafe.GitError:
        return None
    url = os.fsdecode(res.stdout).strip() if res.returncode == 0 else ""
    found = _URL_REMOTE.match(url) or _SCP_REMOTE.match(url)
    if found is None or (found.re is _URL_REMOTE and found["port"] and found["scheme"].startswith("http")):
        return None
    path = found["path"][:-1] if found["path"].endswith("/") else found["path"]
    parts = (path[:-4] if path.endswith(".git") else path).split("/")
    if len(parts) != 2 or not all(_REPO_SEGMENT.fullmatch(p) and p.strip(".") for p in parts):
        return None
    host = found["host"].lower()
    return "/".join(parts) if host == "github.com" else "/".join((host, *parts))


def default_gh_runner(
    argv: Sequence[str],
    stdin: Optional[bytes] = None,
    cwd: Any = None,
    timeout: float = GH_TIMEOUT_SECONDS,
) -> Optional[GhResult]:
    """Run gh for the repository at ``cwd``. gh never runs inside it: resolving ``{owner}/{repo}``
    there would start git under the repository's own config, outside gitsafe. It runs in an empty
    directory below a git ceiling, with the repository passed as ``GH_REPO``."""
    exe = pathlookup.which("gh", outside=cwd)
    if exe is None:
        return None
    repo = resolve_repo(cwd) if cwd is not None else None
    if repo is None and any("{owner}" in arg or "{repo}" in arg for arg in argv):
        return GhResult(125, "", _NO_REPO)
    try:
        scratch = tempfile.mkdtemp(prefix="aegis-gh-")
    except OSError as exc:
        return GhResult(126, "", f"cannot run gh: {exc}")
    ceilings = dict.fromkeys((os.path.dirname(scratch), os.path.dirname(os.path.realpath(scratch))))
    env = {
        **os.environ,
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "NO_COLOR": "1",
        "GIT_CEILING_DIRECTORIES": os.pathsep.join(ceilings),
        **({"GH_REPO": repo} if repo is not None else {}),
    }
    try:
        proc = subprocess.run(
            [exe, *argv],
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            env=env,
            cwd=scratch,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return GhResult(124, "", f"gh timed out after {timeout:g}s")
    except OSError as exc:
        return GhResult(126, "", f"cannot run gh: {exc}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return GhResult(
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_codeowners(text: str, *, org_login: Optional[str] = None) -> List[Tuple[str, Tuple[str, ...]]]:
    # GitHub ignores the bare handle of the organization that owns the repository (it takes a user,
    # @org/team or an email), so that owner is dropped when the caller knows the owner is one.
    org_handle = f"@{org_login}".lower() if org_login else None
    entries: List[Tuple[str, Tuple[str, ...]]] = []
    for line in text.splitlines()[:_MAX_CODEOWNERS_LINES]:
        tokens = line.strip().split()
        if not tokens or tokens[0].startswith("#"):
            continue
        owners: List[str] = []
        for token in tokens[1:]:
            if token.startswith("#"):
                break
            if _OWNER.match(token) and token.lower() != org_handle:
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
    org_login: Optional[str] = None,
) -> Tuple[List[str], List[str]]:
    entries = _parse_codeowners(text, org_login=org_login)
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


codeowners_lines = governance.codeowners_lines


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
        return KeyCustody("none", "no user.signingkey in the user-level git config", False)
    if config["format"] != "ssh":
        return KeyCustody(
            "unsupported",
            f"gpg.format is {config['format']!r}: approvals are SSH signatures checked against allowed_signers (git config --global gpg.format ssh)",
            False,
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
    dismisses = False
    last_push = False
    contexts: List[str] = []
    unpinned: List[str] = []
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
            dismisses = dismisses or params.get("dismiss_stale_reviews_on_push") is True
            last_push = last_push or params.get("require_last_push_approval") is True
        elif rule.get("type") == "required_status_checks":
            for check in params.get("required_status_checks") or []:
                if not isinstance(check, dict) or not isinstance(check.get("context"), str):
                    continue
                context, app = check["context"], check.get("integration_id")
                if context not in contexts:
                    contexts.append(context)
                # Without a positive app id as its source, anyone with write access can post the status.
                if not (type(app) is int and app > 0) and context not in unpinned:
                    unpinned.append(context)
    return {
        "pull_request": has_pr,
        "required_approving_review_count": approvals,
        "require_code_owner_review": owners,
        "dismiss_stale_reviews_on_push": dismisses,
        "require_last_push_approval": last_push,
        "required_status_checks": contexts,
        "unpinned_status_checks": unpinned,
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
    org_login: Optional[str] = None
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
        owner = repo_info.get("owner") if isinstance(repo_info.get("owner"), dict) else {}
        login, kind = owner.get("login"), owner.get("type")
        known = isinstance(login, str) and isinstance(kind, str)
        org_login = login if known and kind == "Organization" else None
        scope["repository"] = full
        evidence["repo"] = {"full_name": full, "default_branch": default_branch,
                            "owner": {"login": login, "type": kind} if known else None}
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
    tracked = _tracked_governance_entries(top, base) if base is not None else {}
    tracked_gov = tuple(tracked)
    codeowners: Dict[str, Any] = {
        "present": False,
        "path": None,
        "covered": [],
        "uncovered": list(dict.fromkeys((*COVERAGE_SAMPLES, *tracked_gov))),
    }
    signers: Dict[str, Any] = {"present": False, "keys": 0}
    bare_org = False
    if base is not None:
        for location in _CODEOWNERS_LOCATIONS:
            blob = _blob(top, base, location)
            if blob is not None:
                text = blob.decode("utf-8", "replace")
                covered, uncovered = codeowners_coverage(text, location, repo_paths=tracked_gov, org_login=org_login)
                codeowners = {
                    "present": True,
                    "path": location,
                    "covered": covered,
                    "uncovered": uncovered,
                }
                bare_org = bool(org_login) and any(
                    o.lower() == f"@{org_login}".lower() for _p, found in _parse_codeowners(text) for o in found
                )
                break
        blob = _blob(top, base, ALLOWED_SIGNERS)
        signers = {"present": blob is not None, "keys": _signer_keys(blob)}
    evidence["codeowners"] = codeowners
    evidence["allowed_signers"] = signers
    aegis_jobs = _base_aegis_jobs(top, tracked)
    evidence["aegis_checks"] = {"jobs": sorted(aegis_jobs),
                                "path_filtered": sorted(j for j, why in aegis_jobs.items() if why == _PATH_FILTER_WHY)}
    custody = check_key_custody(top)
    evidence["key_custody"] = custody.as_dict()

    checks = facts["required_status_checks"] if facts else []
    unpinned_why, workflow_why = _required_check_gaps(facts, aegis_jobs)
    a_missing: List[str] = []
    if facts is None:
        a_missing.append("the default branch's ruleset was not read")
    else:
        if facts["required_approving_review_count"] < 1:
            a_missing.append("the default branch does not require an approving review")
        if not facts["require_code_owner_review"]:
            a_missing.append("the default branch does not require code-owner review")
        if not facts["dismiss_stale_reviews_on_push"]:
            a_missing.append(
                "the default branch keeps an approval after new commits are pushed, so a pull request can change "
                "after its review and still merge (set dismiss_stale_reviews_on_push)"
            )
        if not checks:
            a_missing.append("the default branch has no required status checks")
        elif workflow_why:
            a_missing.append(workflow_why)
    if not codeowners["present"]:
        a_missing.append("no CODEOWNERS file on the base branch")
    elif codeowners["uncovered"]:
        a_missing.append(f"CODEOWNERS leaves {len(codeowners['uncovered'])} governance path(s) without an owner")
    if bare_org:
        a_missing.append(
            f"CODEOWNERS names @{org_login}, the organization that owns this repository, which GitHub ignores as a "
            f"code owner: name a team (@{org_login}/<team>) or people"
        )
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
    elif unpinned_why:
        b_missing.append(unpinned_why)
    if workflow_why:
        b_missing.append(workflow_why)
    if signers["keys"] < 1:
        b_missing.append(f"{ALLOWED_SIGNERS} on the base branch lists no signing key")
    if custody.degrades:
        b_missing.append(custody.detail)

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
        if custody.status in ("none", "unsupported"):
            caveats.append(f"no SSH signing key is configured on this machine, so aegis approve cannot be run here ({custody.detail})")
        else:
            caveats.append("the local signing key is not compared with the keys in allowed_signers")
        caveats.append(
            "a ruleset can name bypass actors, which this endpoint does not show; classic branch protection is not read at all"
        )
        if unpinned_why:
            caveats.append(unpinned_why)
    if tier == "B":
        caveats.append(
            "required checks run the pull request's own workflow and aegis, so a pull request can edit the check that verifies the signature; tier B holds only while pull requests leave .github/workflows/** and aegis alone"
        )
    return TierReport(tier, tuple(why_not), tuple(caveats), evidence, scope)


def _required_check_gaps(
    facts: Optional[Mapping[str, Any]], aegis_jobs: Mapping[str, Optional[str]]
) -> Tuple[Optional[str], Optional[str]]:
    """Why a passing required check would not show that Aegis ran in CI: (a source anyone with write
    access can post as, a required check that is not an Aegis job that counts, with why it does not)."""
    checks = facts["required_status_checks"] if facts else []
    unpinned = facts["unpinned_status_checks"] if facts else []
    source = (
        f"the required check(s) {', '.join(unpinned)} have no pinned source (integration_id): anyone with write access, "
        "including the agent's gh token, can post a passing status; set each check's source to GitHub Actions "
        f"(app {GITHUB_ACTIONS_APP_ID}) in the ruleset"
    ) if unpinned else None
    required = [c for c in checks if c in aegis_jobs]
    counted = sorted(j for j, why in aegis_jobs.items() if why is None)
    if checks and not required:
        return source, "the required checks do not include the Aegis job: " + (
            f"require {', '.join(counted)}" if counted else aegis_jobs[min(aegis_jobs)] if aegis_jobs else
            "no workflow on the base branch has a job that runs aegis check --ci under a literal name, outside a matrix"
        )
    if required and all(aegis_jobs[c] for c in required):
        return source, aegis_jobs[required[0]]
    return source, None


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


def _governance_blobs(top: Path, commit: str) -> Dict[str, Tuple[str, str]]:
    """{path: (mode, oid)} of every governance file at ``commit``. Raises GitError."""
    entries = gitsafe.tree_blobs(top, commit, include_symlinks=True, timeout=60.0)
    return {path: entry for path, entry in entries.items() if governance.category_of(path) is not None}


def _tracked_governance_entries(workspace: Any, rev: str) -> Dict[str, Tuple[str, str]]:
    top = gitsafe.toplevel(Path(workspace))
    commit = gitsafe.resolve_commit(top, rev) if top else None
    if not top or not commit:
        return {}
    try:
        return _governance_blobs(top, commit)
    except gitsafe.GitError:
        return {}


def _base_aegis_jobs(top: Path, tracked: Mapping[str, Tuple[str, str]]) -> Dict[str, Optional[str]]:
    """{check name of an Aegis job: why it is not the required check, None when it is}, read from the
    base branch's workflow files (GitHub reads no subdirectory and no symlink there)."""
    workflows = {
        path: oid
        for path, (mode, oid) in tracked.items()
        if posixpath.dirname(path) == ".github/workflows" and path.endswith((".yml", ".yaml")) and mode != "120000"
    }
    try:
        blobs = gitsafe.read_blobs(top, workflows.values())
    except gitsafe.GitError:
        return {}
    jobs: Dict[str, Optional[str]] = {}
    for path in sorted(workflows):
        text = blobs[workflows[path]].decode("utf-8", "replace")
        filtered = _PATH_FILTER_WHY if _filters_pull_requests_by_path(text) else None
        for name, why in _aegis_job_verdicts(text).items():
            jobs[name] = jobs.get(name) or why or filtered
    return jobs


def _filters_pull_requests_by_path(text: str) -> bool:
    """``paths:`` or ``paths-ignore:`` under ``on.pull_request(_target)``, in block or flow style."""
    lines = ["" if ln.lstrip().startswith("#") else re.sub(r"[ \t]+#.*$", "", ln)
             for ln in text.splitlines()[:_MAX_WORKFLOW_LINES]]
    start = next((i for i, ln in enumerate(lines) if re.match(r"""^["']?on["']?[ \t]*:""", ln)), None)
    if start is None:
        return False
    end = next((i for i in range(start + 1, len(lines)) if lines[i][:1] not in ("", " ", "\t")), len(lines))
    section = "\n".join(lines[start:end])
    for event in _PR_EVENT.finditer(section):
        rest = section[event.end():]
        if rest.startswith("{"):
            depth = 0
            for i, char in enumerate(rest):
                depth += {"{": 1, "}": -1}.get(char, 0)
                if depth == 0:
                    rest = rest[: i + 1]
                    break
        else:
            line_start = section.rfind("\n", 0, event.start()) + 1
            indent = len(section[line_start:]) - len(section[line_start:].lstrip())
            first, *more = rest.split("\n")
            deeper = itertools.takewhile(lambda ln: not ln.strip() or len(ln) - len(ln.lstrip()) > indent, more)
            rest = "\n".join([first, *deeper])
        if _PATHS_KEY.search(rest):
            return True
    return False


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
        entries = _governance_blobs(top, commit)
    except gitsafe.GitError as exc:
        raise HumanGateError(str(exc)) from exc
    records = [(os.fsencode(path), f"{mode} {oid}".encode("ascii")) for path, (mode, oid) in entries.items()]
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
    source: str = "signature"  # or "review": tier A's approving review (find_review_approval)

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
            # not "source": that key names the producer in every envelope
            "method": self.source,
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


def _commit_message(top: Path, oid: str) -> Optional[str]:
    raw = gitsafe.run(["cat-file", "commit", oid], top)
    return raw.stdout.decode("utf-8", "replace").partition("\n\n")[2] if raw.returncode == 0 else None


def _read_message(top: Path, oid: str) -> Union[str, Approval]:
    message = _commit_message(top, oid)
    if message is None:
        return _no("unresolved", f"cannot read commit {oid}", oid)
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
    except gitsafe.GitError as exc:
        return _no("unresolved", str(exc), str(commit))
    except HumanGateError as exc:
        return _no("unverifiable", str(exc), str(commit))
    return _verify_candidate(top, oid, base, rx, name, expected, mismatch_msg, ok_msg, label=str(commit))


def _verify_candidate(top: Path, oid: str, base: str, rx: re.Pattern[str], name: str, expected: str,
                      mismatch_msg: str, ok_msg: str, label: Optional[str] = None) -> Approval:
    """Verify resolved commit ``oid`` against the allowed_signers of resolved ``base``. The message
    is re-read here (``cat-file``), so a caller's cheaper pre-filter can only skip a commit."""
    try:
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
        return _no("unresolved", str(exc), label or oid)
    except HumanGateError as exc:
        return _no("unverifiable", str(exc), label or oid)


_APPROVE_MISMATCH = "the approved governance hash is not this governance state"
_APPROVE_OK = "good signature by a key in the base allowed_signers"
_FULL_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def verify_approval(root: Any, commit: str, governance_hash: str, base_ref: str) -> Approval:
    return _verify_single_trailer(root, commit, base_ref, _APPROVE_LINE, "Aegis-Approve", governance_hash,
                                  _APPROVE_MISMATCH, _APPROVE_OK)


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
    """The newest valid ``Aegis-Approve`` commit in ``merge-base(base_ref, head)..head`` (at most
    MAX_SCANNED_COMMITS), or None. One ``git log`` reads every message, so only commits that carry an
    approve line cost a signature check: the git calls do not grow with the range."""
    top = _top(root)
    tip, base_target = gitsafe.resolve_commit(top, head), gitsafe.resolve_commit(top, base_ref)
    base = gitsafe.merge_base(top, base_target, tip) if tip and base_target else None
    if not base:
        return None
    digest = governance_hash or governance_tree_hash(top, tip, base=base)
    # -z: git refuses a NUL in a message, so no message can forge a record boundary.
    res = gitsafe.run(["log", "-z", f"--max-count={MAX_SCANNED_COMMITS}", "--format=%H%n%B", f"{base}..{tip}"], top)
    if res.returncode != 0:
        return None
    for record in res.stdout.split(b"\0"):
        oid, _, message = record.decode("utf-8", "replace").lstrip("\n").partition("\n")
        if not _FULL_OID.fullmatch(oid) or not _APPROVE_LINE.search(message):
            continue
        verdict = _verify_candidate(top, oid, base_target, _APPROVE_LINE, "Aegis-Approve", digest,
                                    _APPROVE_MISMATCH, _APPROVE_OK)
        if verdict.valid:
            return verdict
    return None


class PullRequest(NamedTuple):
    """The pull request a CI job checks, as the caller validated it from the Actions event file.
    ``base_ref``: the branch it merges into (``pull_request.base.ref``), whose rules gate the merge."""
    number: int
    author: str
    head: str
    base_ref: str


_REVIEWER_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
_REVIEW_PAGE = 100
_BRANCH_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]{0,254}")


def is_branch_name(name: Any) -> bool:
    """Whether ``name`` is a branch name safe to put in a GitHub API path: git's ref-name rules over a
    conservative character set. Anything else is refused, never escaped into a different request."""
    return (isinstance(name, str) and _BRANCH_NAME.fullmatch(name) is not None and ".." not in name
            and "//" not in name and "/." not in name and ".lock/" not in name
            and not name.endswith(("/", ".", ".lock")))


def find_review_approval(root: Any, pull: PullRequest, base: str, paths: Sequence[str],
                         gh: Optional[GhRunner] = None) -> Optional[Approval]:
    """Tier A's approval of a flagged change: some reviewer's latest review of ``pull`` is APPROVED on its
    head commit, by a person (account type User) other than its author whose ``author_association`` is
    OWNER, MEMBER or COLLABORATOR. An association is not a permission: write access is not checked here.
    What makes the review count is the merge gate: the rules GitHub applies to the pull request's own
    base branch (``pull.base_ref``, never the default branch's) require an approval, code-owner review,
    stale approvals dismissed on push and the last push approved by someone other than its pusher (so
    whoever pushed the head cannot be the approving reviewer), and the CODEOWNERS at ``base`` owns every
    one of ``paths`` (repository-relative); the reviews are read only then. Read-only gh GETs; None whenever anything
    cannot be read or does not hold (a base branch name in doubt reads nothing), so a missing gh, token
    or permission fails closed."""
    if not is_branch_name(pull.base_ref):
        return None
    runner: GhRunner = gh if gh is not None else default_gh_runner
    top = _top(root)
    repo, why = _gh_json(runner, "repos/{owner}/{repo}", top)
    if why is not None or not isinstance(repo, dict):
        return None
    rules, why = _gh_json(runner, "repos/{owner}/{repo}/rules/branches/" + quote(pull.base_ref, safe=""), top)
    facts = _ruleset_facts(rules) if why is None else None
    if not facts or facts["required_approving_review_count"] < 1 or not facts["require_code_owner_review"] \
            or not facts["dismiss_stale_reviews_on_push"] or not facts["require_last_push_approval"]:
        return None
    owner = repo.get("owner") if isinstance(repo.get("owner"), dict) else {}
    org = owner.get("login") if owner.get("type") == "Organization" and isinstance(owner.get("login"), str) else None
    text: Optional[str] = None
    for location in _CODEOWNERS_LOCATIONS:  # GitHub reads the first one present
        blob = _blob(top, base, location)
        if blob is not None:
            text = blob.decode("utf-8", "replace")
            break
    if text is None or codeowners_coverage(text, location, repo_paths=paths, org_login=org)[1]:
        return None
    reviews, why = _gh_json(runner, f"repos/{{owner}}/{{repo}}/pulls/{pull.number}/reviews?per_page={_REVIEW_PAGE}", top)
    # A full page may hide later reviews (a change request, a dismissal), so it never approves.
    if why is not None or not isinstance(reviews, list) or len(reviews) >= _REVIEW_PAGE:
        return None
    latest: Dict[str, Dict[str, Any]] = {}
    for item in reviews:
        user = item.get("user") if isinstance(item, dict) else None
        login = user.get("login") if isinstance(user, dict) else None
        if isinstance(login, str) and login:
            latest[login.lower()] = item  # the list is oldest first: keep each reviewer's last word
    for login, item in latest.items():
        # A person's review only: an app or bot account may act for the agent.
        if (item.get("state") == "APPROVED" and str(item.get("commit_id") or "").lower() == pull.head.lower()
                and login != pull.author.lower() and item.get("author_association") in _REVIEWER_ASSOCIATIONS
                and item["user"].get("type") == "User"):
            name = item["user"]["login"]
            return Approval(True, "ok", f"an approving review of the head commit by {name}, not its author",
                            pull.head.lower(), name, "review")
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
        # unresolved and accept_reserved come before the trailer is read: keep them only for a commit naming the fix
        if rejected is None and verdict.code not in ("no_exemption_trailer", "commit_mismatch") and any(
            t.lower() == fix_oid.lower() for t, _why in _EXEMPT_TEST_LINE.findall(_commit_message(top, oid) or "")
        ):
            rejected = verdict
    return rejected


def signed_empty_commit(root: Any, message: str, *, interactive: bool = False) -> str:
    """``interactive``: a person at the caller's terminal; ssh-keygen asks there for a key passphrase
    (with stdin on /dev/null it would try ssh-askpass instead)."""
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
        tty=interactive,
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
                    "required_status_checks": [{"context": c, "integration_id": GITHUB_ACTIONS_APP_ID} for c in contexts],
                },
            },
        ],
    }


def aegis_check_jobs(text: str) -> List[str]:
    """The check names (literal ``name:``, else the job id) of the jobs in one workflow file that count as
    the required Aegis check. A templated name or a matrix gives no fixed check name, so that job is left out."""
    return [name for name, why in _aegis_job_verdicts(text).items() if why is None]


def _value(text: Optional[str]) -> str:
    return re.sub(r"(?:^|[ \t]+)#.*$", "", text or "").strip()


def _step_line(step: Dict[str, Any], indent: int, body: str) -> None:
    step["col"] = indent if step["col"] is None else step["col"]
    if indent == step["col"]:
        found = _KEY.fullmatch(body)
        if not found or found.group(1) in step["vals"]:
            step["bad"] = True
            return
        step["key"], value = found.group(1), found.group(2) or ""
        step["vals"][step["key"]] = value
        if step["key"] == "run":
            step["literal"] = bool(re.fullmatch(r"\|[-+]?", _value(value)))
            step["script"] = [] if step["literal"] else [_value(value)] if value[:1] not in ("", "|", ">") else None
            step["runs"] = bool(_AEGIS_CHECK_CI.search(value))
    elif indent < step["col"]:
        step["bad"] = True
    elif step["key"] == "run":
        step["runs"] = step["runs"] or bool(_AEGIS_CHECK_CI.search(body))
        step["script"] = step["script"] + [_value(body)] if step["literal"] else None
    elif step["key"] in ("if", "continue-on-error", "shell"):
        step["vals"][step["key"]] += " ..."


def _skip_why(vals: Mapping[str, str]) -> Optional[str]:
    cond, coe = (_value(vals[k]) if k in vals else None for k in ("if", "continue-on-error"))
    if cond is not None and not _ALWAYS.fullmatch(cond):
        return f"has a condition (if: {cond}) and may be skipped, which GitHub reports as a passing check"
    return "sets continue-on-error, so it passes even when aegis check fails" if coe not in (None, "false") else None


def _step_why(step: Mapping[str, Any], default_shell: Optional[str]) -> Optional[str]:
    """Why a step that mentions ``aegis check --ci`` may not fail its job; None when it does."""
    shell = _value(step["vals"]["shell"]) if "shell" in step["vals"] else default_shell
    script, skips = step["script"] or [], _skip_why(step["vals"])
    if step["bad"]:
        return _UNREAD_WHY
    if skips:
        return "runs aegis check --ci in a step that " + skips
    if shell not in (None, *_SHELLS):
        return f"runs aegis check --ci under a custom shell ({shell}), so whether its failure fails the job is not visible"
    if len(script) != 1 or not _DIRECT_CHECK.fullmatch(script[0]) or "--ci" not in script[0].split():
        return ("does not run aegis check --ci as the whole of a step's run: with plain arguments (it is echoed, quoted, "
                "commented out, combined with other commands or followed by || true), so its failure may not fail the job")
    return None


def _aegis_job_verdicts(text: str) -> Dict[str, Optional[str]]:
    """{check name: None when the job counts as the required Aegis check, else why not}, for the jobs of one
    workflow file that run ``aegis check --ci`` under a literal name, outside a matrix. GitHub reports a job
    skipped by a condition as a passing required check, so a job counts only when nothing can skip it and an
    Aegis step can fail it; a layout this line reader cannot follow does not count."""
    jobs: Dict[str, Dict[str, Any]] = {}
    job: Optional[Dict[str, Any]] = None
    step: Optional[Dict[str, Any]] = None
    section, key, seq, wf_shell = "", "", -1, None
    lines = text.splitlines()
    for line in [*lines[:_MAX_WORKFLOW_LINES], "end:"]:
        body = line.strip()
        if not body or body.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if step is not None and indent > seq:
            _step_line(step, indent, body)
            continue
        step, item = None, re.match(r"-(?:[ \t]+|$)", body)
        if indent == 0:
            section, _colon, inline = body.partition(":")
            section, job = section.strip("\"' "), None
            if section == "defaults":  # an inline mapping is not read, so a shell it may name counts as custom
                wf_shell = _value(inline) or wf_shell
        elif section == "defaults":
            found = _KEY.fullmatch(body)
            wf_shell = _value(found.group(2)) if found and found.group(1) == "shell" else wf_shell
        elif section != "jobs":
            continue
        elif indent <= 2:
            found = _JOB_ID.match(line)
            fresh = {"name": found.group(1) if found else "", "vals": {}, "steps": [], "shell": None,
                     "bad": False, "matrix": False}
            job, key = (jobs.setdefault(found.group(1), fresh) if found else None), ""
            if job is not None and job is not fresh:
                job["bad"] = True
        elif job is None:
            continue
        elif key == "steps" and item and indent >= 4 and seq in (-1, indent):
            seq, rest = indent, body[item.end():]
            step = {"vals": {}, "key": "", "col": indent + item.end() if rest else None, "script": None,
                    "literal": False, "runs": False, "bad": False}
            job["steps"].append(step)
            if rest:
                _step_line(step, indent + item.end(), rest)
        elif indent == 4:
            found, named, seq = _KEY.fullmatch(body), _JOB_NAME.match(line), -1
            key = found.group(1) if found else ""
            # a name key _JOB_NAME cannot read would leave the check named after the job id here, not on GitHub
            job["bad"] = job["bad"] or not found or key in job["vals"] or (key == "name" and not named)
            job["vals"][key] = found.group(2) or "" if found else ""
            if key == "defaults":
                job["shell"] = _value(job["vals"][key]) or job["shell"]
            if named:
                job["name"] = next((g for g in named.groups() if g), "") or job["name"]
            job["matrix"] = job["matrix"] or bool(_JOB_MATRIX.match(line))
        elif indent < 4 or key == "steps":
            job["bad"] = True
        elif key in ("if", "continue-on-error"):
            job["vals"][key] += " ..."
        else:
            found = _KEY.fullmatch(body)
            if key == "defaults" and found and found.group(1) == "shell":
                job["shell"] = _value(found.group(2))
            job["matrix"] = job["matrix"] or bool(_JOB_MATRIX.match(line))
    verdicts: Dict[str, Optional[str]] = {}
    for job in jobs.values():
        name, vals = job["name"], job["vals"]
        whys = [_step_why(s, job["shell"] or wf_shell) for s in job["steps"] if s["runs"]]
        if not whys or job["matrix"] or "${{" in name:
            continue
        if job["bad"] or len(lines) > _MAX_WORKFLOW_LINES:
            why: Optional[str] = _UNREAD_WHY
        elif "needs" in vals and "if" not in vals:
            why = "needs other jobs without if: always(), so a failed or skipped job it needs skips it"
        else:
            why = _skip_why(vals) or (None if None in whys else whys[0])
        verdicts[name] = verdicts.get(name) or (f"the Aegis job {name} {why}" if why else None)
    return verdicts


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
