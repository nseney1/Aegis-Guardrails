"""Read-only tested-bytes preconditions for the commit custodian (Git ADR 4.5).

Only the trusted custodian calls this boundary. It owns the active GitStore,
required qualification legs, team identity and expected lane tip. The four read
callbacks belong to its adapter, never to a model payload: read_branch() returns
the current short branch (None for detached HEAD); read_head() the current full
commit id; read_paths(expected_head, tested_tree) every changed path, including
deletions and both sides of renames, from the private snapshot; read_policy()
returns a parsed TeamPolicy from the trusted target, never the candidate's policy.
All callbacks must be read-only, bounded and raise OSError, AegisError or ValueError
on failure. Their filesystem access must use the trusted descriptor boundary.

Success returns the exact tested tree, not an authorization token or a lock. The
caller must serialize custody and use the expected HEAD in its eventual CAS;
concurrent later changes cannot alter that immutable tree. No intent, commit or
ref update occurs here. Snapshot effects stay in the store's private scratch;
the real index, worktree and refs are unchanged on success and every refusal.
This module does not change any existing commit or host flow.
"""
from __future__ import annotations

from collections.abc import Mapping
from itertools import islice
import re
import time

from aegis_core import match, team, team_git, team_paths, team_qualify
from aegis_core.config import MAX_CONFIG_BYTES
from aegis_core.errors import AegisError
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text

__all__ = ["CustodyRefused", "REFUSALS", "check_preconditions"]

REFUSALS = {
    "unsupported_platform": "custody checks require descriptor-relative snapshot support",
    "lease_not_live": "lane lease is not live and owned by this team",
    "branch_mismatch": "worktree branch differs from the lane lease",
    "head_mismatch": "worktree HEAD differs from the expected lane tip",
    "tree_mismatch": "worktree snapshot differs from the tested tree",
    "not_qualified": "tested tree has no PASS for every required leg",
    "invalid_paths": "changed paths are unavailable, malformed or oversized",
    "invalid_policy": "trusted team policy is unavailable or invalid",
    "path_outside_lease": "changed path lies outside the lane lease",
    "path_outside_team": "changed path lies outside the trusted team policy",
    "invalid_message": "commit message is empty, oversized, invalid text or carries a forbidden trailer",
}
_ACTIONS = {
    "unsupported_platform": ("custodian", "use a descriptor-capable custody host"),
    "head_mismatch": ("implementer", "refresh the expected lane tip and requalify"),
    "tree_mismatch": ("executor", "test the current tree and record its PASS"),
    "not_qualified": ("executor", "record PASS for every required leg of this tree"),
    "invalid_paths": ("custodian", "repair the bounded changed-path reader"),
    "invalid_policy": ("custodian", "load valid team policy from the trusted target"),
    "path_outside_lease": ("implementer", "restore the path or obtain a covering lease"),
    "path_outside_team": ("orchestrator", "restore the path or obtain covering team policy"),
    "invalid_message": ("implementer", "provide a bounded message without approval or exemption trailers"),
}
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
# Keep the public commit_tested message contract, including all forbidden trailers.
# The private team_git validator is deliberately not imported.
_FORBIDDEN = re.compile(r"^\s*Aegis-(?:Approve(?:-Insight)?|Exempt-Test)\s*:", re.I | re.M)
_READ_ERRORS = (AegisError, OSError, ValueError, TypeError, RecursionError)


class CustodyRefused(ValueError):
    """Fixed refusal text and next_action; path is sanitized display text only."""

    def __init__(self, code, *, lane=None, path=None):
        super().__init__(REFUSALS[code])
        self.code = code
        if code in ("lease_not_live", "branch_mismatch"):
            # Only a bounded grammar-validated lane can enter a command field.
            command = "lane resume " + lane if _lane(lane) and _display(lane) == lane else "lane resume"
            actor = "implementer"
        else:
            actor, command = _ACTIONS[code]
        self.next_action = {"actor": actor, "command": command}
        self.path = _display(path) if path is not None else None


def _display(path):
    canonical = sanitize_display(path, max_len=None)
    redacted = redact_insight_text(canonical, max_len=max(len(canonical), 1))
    return sanitize_display(redacted, max_len=240)


def _lane(value):
    return type(value) is str and 1 <= len(value) <= 63 and team.valid_lane(value)


def _oid(value):
    return type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value) is not None


def _read(code, callback, *args, lane=None):
    if not callable(callback):
        raise CustodyRefused(code, lane=lane)
    try:
        return callback(*args)
    except _READ_ERRORS:
        raise CustodyRefused(code, lane=lane) from None


def _lease(store, lane):
    oid = team_git.ref_oid(store, team.lane_ref(lane))
    if oid is None:
        return None
    return team.parse_lease(store.object(oid, "blob", max_bytes=team.MAX_LEASE_BYTES), lane, oid)


def _paths(value):
    # Bound a single capture; a subclass's length need not bound its iterator.
    if not isinstance(value, (list, tuple)):
        raise CustodyRefused("invalid_paths")
    try:
        if len(value) > team_git.MAX_PATHS:
            raise CustodyRefused("invalid_paths")
        paths = tuple(islice(value, team_git.MAX_PATHS + 1))
    except Exception:
        # Only untrusted collection protocols run here. Their exception text
        # must not escape, and a partial capture must never become permission.
        raise CustodyRefused("invalid_paths") from None
    if len(paths) > team_git.MAX_PATHS:
        raise CustodyRefused("invalid_paths")
    size = 0
    for path in paths:
        if (type(path) is not str or not 1 <= len(path) <= team_git.MAX_PATH_BYTES
                or "\0" in path or "\\" in path or path.startswith("/")):
            raise CustodyRefused("invalid_paths")
        try:
            length = len(path.encode("utf-8"))
        except UnicodeError:
            raise CustodyRefused("invalid_paths") from None
        size += length + 1
        if (length > team_git.MAX_PATH_BYTES or size > team_git.MAX_RESPONSE_BYTES
                or any(part in ("", ".", "..", ".git") for part in path.split("/"))):
            raise CustodyRefused("invalid_paths")
    return paths


def _policy_paths(policy, lane):
    """Bound rule globs without converting them to lease-glob semantics."""
    if (not isinstance(policy, team.TeamPolicy) or type(policy.shared) is not tuple
            or (policy.lanes is not None and not isinstance(policy.lanes, Mapping))):
        raise CustodyRefused("invalid_policy")
    try:
        selected = () if policy.lanes is None else policy.lanes.get(lane, ())
        if type(selected) is not tuple or len(policy.shared) + len(selected) > MAX_CONFIG_BYTES:
            raise CustodyRefused("invalid_policy")
        size = 0
        for group in (policy.shared, selected):
            for glob in group:
                if type(glob) is not str or not 1 <= len(glob) <= MAX_CONFIG_BYTES:
                    raise CustodyRefused("invalid_policy")
                size += len(glob)
                if size > MAX_CONFIG_BYTES or team_paths.glob_problem(glob):
                    raise CustodyRefused("invalid_policy")
        return policy.shared + selected
    except _READ_ERRORS:
        raise CustodyRefused("invalid_policy") from None


def _message(value):
    # Character cap before UTF-8 allocation; byte cap before trailer parsing.
    if type(value) is not str or not 1 <= len(value) <= team_git.MAX_MESSAGE_BYTES:
        raise CustodyRefused("invalid_message")
    try:
        data = value.encode("utf-8")
    except UnicodeError:
        raise CustodyRefused("invalid_message") from None
    if len(data) > team_git.MAX_MESSAGE_BYTES or b"\0" in data or _FORBIDDEN.search(value):
        raise CustodyRefused("invalid_message")


def check_preconditions(store, *, lane, owner, expected_head, tested_tree, required_legs,
                        message, read_branch, read_head, read_paths, read_policy, now=None):
    """Return tested_tree or raise CustodyRefused for the first failed condition.

    Platform support is the entry gate. Then: live owned lease, branch, HEAD,
    recomputed tree, qualification, lease AND target-policy containment, message.
    Invalid inputs and documented read failures map to that phase's fixed code.
    No callback for a later phase runs after an earlier refusal. A missing policy
    or missing lane admits only explicitly shared paths; it never widens a lease.
    """
    if not team_git.descriptor_support():
        raise CustodyRefused("unsupported_platform")
    if (not isinstance(store, team_git.GitStore) or not _lane(lane)
            or type(owner) is not str or not 1 <= len(owner) <= team.LABEL_MAX
            or (now is not None and type(now) is not int)):
        raise CustodyRefused("lease_not_live", lane=lane)
    lease = _read("lease_not_live", _lease, store, lane, lane=lane)
    if (lease is None or lease.owner != owner
            or lease.expired(now if now is not None else _read("lease_not_live", time.time, lane=lane))):
        raise CustodyRefused("lease_not_live", lane=lane)
    branch = _read("branch_mismatch", read_branch, lane=lane)
    if type(branch) is not str or not branch or len(branch) > team.LABEL_MAX or lease.branch != branch:
        raise CustodyRefused("branch_mismatch", lane=lane)
    if not _oid(expected_head) or _read("head_mismatch", read_head) != expected_head:
        raise CustodyRefused("head_mismatch")
    if not _oid(tested_tree) or len(tested_tree) != len(expected_head):
        raise CustodyRefused("tree_mismatch")
    if _read("tree_mismatch", team_git.snapshot_tree, store) != tested_tree:
        raise CustodyRefused("tree_mismatch")
    if _read("not_qualified", team_qualify.qualified, store, tested_tree, required_legs) is not True:
        raise CustodyRefused("not_qualified")
    paths = _paths(_read("invalid_paths", read_paths, expected_head, tested_tree))
    policy = _policy_paths(_read("invalid_policy", read_policy), lane)
    for path in paths:
        if team_paths.first_match(lease.path_set, path) is None:
            raise CustodyRefused("path_outside_lease", path=path)
        if not any(match.matches(glob, path) for glob in policy):
            raise CustodyRefused("path_outside_team", path=path)
    _message(message)
    return tested_tree
