"""Strict manager-only policy intake from exact control-repository Git blobs.

Payload validation grants neither activation authority nor repository governance
credit. Rule prose requires owner review; bounded selectors are management data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from aegis_core import gitsafe
from aegis_core.primitives import strict_loads

__all__ = ["ACTIONS", "ManagerError", "canonical", "digest", "parse_membership", "parse_policy", "read_candidate"]

ACTIONS = frozenset(("delegation", "ownership", "hierarchy", "resource_budget", "checkpoint",
                     "handoff", "evidence_review", "escalation", "policy_change"))
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_RULES = 128
MAX_WORKTREES = 16
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_PAYLOADS = ("manager-policy/policy.json", "manager-policy/membership.json")


class ManagerError(ValueError):
    """A fixed, explicit refusal without reflecting untrusted payload content."""


def _json_value(value, depth=0):
    if depth > 64:
        raise ManagerError("invalid_json")
    if type(value) in (str, int, float, bool) or value is None:
        return
    if type(value) is list:
        for item in value:
            _json_value(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json_value(item, depth + 1)
        return
    raise ManagerError("invalid_json")


def canonical(value) -> bytes:
    """Deterministic ASCII JSON bytes; non-JSON objects and nonfinite numbers fail."""
    try:
        _json_value(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, RecursionError) as exc:
        raise ManagerError("invalid_json") from exc


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _object(value, keys, reason):
    if type(value) is not dict or set(value) != set(keys):
        raise ManagerError(reason)
    return value


def _token(value, reason):
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise ManagerError(reason)
    return value


def _rule(value):
    reason = "invalid_policy"
    _object(value, ("id", "actions", "match", "text"), reason)
    _token(value["id"], reason)
    actions = value["actions"]
    if type(actions) is not list or not 1 <= len(actions) <= len(ACTIONS) \
            or any(type(action) is not str or action not in ACTIONS for action in actions) \
            or len(set(actions)) != len(actions):
        raise ManagerError(reason)
    match = value["match"]
    if type(match) is not dict or set(match) - {"role", "phase", "risk"}:
        raise ManagerError(reason)
    for selector in match.values():
        _token(selector, reason)
    text = value["text"]
    if type(text) is not str or not text.strip() or len(text) > 4096 or "\x00" in text:
        raise ManagerError(reason)
    return {"id": value["id"], "actions": list(actions), "match": dict(match), "text": text,
            "revision": digest(value)}


def parse_policy(value) -> dict:
    """Validate only management selectors and compute immutable per-rule revisions."""
    reason = "invalid_policy"
    _object(value, ("schema", "workspace_id", "rules"), reason)
    if value["schema"] != "aegis.manager-policy/v1":
        raise ManagerError(reason)
    _token(value["workspace_id"], reason)
    rules = value["rules"]
    if type(rules) is not list or not 1 <= len(rules) <= MAX_RULES:
        raise ManagerError(reason)
    parsed = [_rule(rule) for rule in rules]
    if len({rule["id"] for rule in parsed}) != len(parsed):
        raise ManagerError(reason)
    return {"schema": value["schema"], "workspace_id": value["workspace_id"], "rules": parsed}


def _lexical_directory(value) -> Path:
    if not isinstance(value, (str, Path)):
        raise ManagerError("unsafe_path")
    raw = str(value) if isinstance(value, Path) else value
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw or "\x00" in raw:
        raise ManagerError("unsafe_path")
    path = Path(raw)
    if str(path) != raw:
        raise ManagerError("unsafe_path")
    return path


def _safe_directory(value) -> Path:
    path = _lexical_directory(value)
    try:
        if any(ancestor.is_symlink() for ancestor in (path, *path.parents)) \
                or not path.is_dir() or path.resolve() != path:
            raise ManagerError("unsafe_path")
        return path
    except (OSError, ValueError, RuntimeError) as exc:
        raise ManagerError("unsafe_path") from exc


def _worktrees(value, common, verify_identity):
    reason = "invalid_membership"
    if type(value) is not list or not 1 <= len(value) <= MAX_WORKTREES:
        raise ManagerError(reason)
    result, identities, roots = [], set(), set()
    for entry in value:
        _object(entry, ("id", "path"), reason)
        identity = _token(entry["id"], reason)
        if type(entry["path"]) is not str:
            raise ManagerError(reason)
        path = _safe_directory(entry["path"]) if verify_identity else _lexical_directory(entry["path"])
        if identity in identities or os.path.normcase(str(path)) in roots:
            raise ManagerError(reason)
        if verify_identity:
            actual_common = gitsafe.common_dir(path)
            if gitsafe.toplevel(path) != path or actual_common is None \
                    or _safe_directory(actual_common) != common:
                raise ManagerError("membership_identity_mismatch")
        identities.add(identity)
        roots.add(os.path.normcase(str(path)))
        result.append({"id": identity, "path": str(path)})
    return result


@gitsafe.scrubbed()
def parse_membership(value, *, verify_identity=True) -> dict:
    """Validate Aegis membership; replay may inspect unavailable paths as data only.

    Disabling runtime identity checks grants no approval or admission authority.
    The default verifies every exact worktree against its real Git common dir.
    """
    reason = "invalid_membership"
    if type(verify_identity) is not bool:
        raise ManagerError(reason)
    _object(value, ("schema", "workspace_id", "repositories"), reason)
    if value["schema"] != "aegis.manager-membership/v1":
        raise ManagerError(reason)
    _token(value["workspace_id"], reason)
    repositories = value["repositories"]
    if type(repositories) is not list or len(repositories) != 1:
        raise ManagerError(reason)
    repository = _object(repositories[0], ("id", "common_dir", "worktrees"), reason)
    if repository["id"] != "aegis":
        raise ManagerError(reason)
    if type(repository["common_dir"]) is not str:
        raise ManagerError(reason)
    common = (_safe_directory(repository["common_dir"]) if verify_identity
              else _lexical_directory(repository["common_dir"]))
    try:
        worktrees = _worktrees(repository["worktrees"], common, verify_identity)
    except gitsafe.GitError as exc:
        raise ManagerError("git_unavailable") from exc
    return {"schema": value["schema"], "workspace_id": value["workspace_id"], "repositories": [
        {"id": "aegis", "common_dir": str(common), "worktrees": worktrees}]}


def _payloads(root, revision):
    entries = gitsafe.tree_blobs(root, revision, paths=_PAYLOADS, include_symlinks=True, timeout=10)
    if set(entries) != set(_PAYLOADS):
        raise ManagerError("missing_payload")
    if any(mode != "100644" for mode, _ in entries.values()):
        raise ManagerError("unsafe_payload")
    oids = [entries[path][1] for path in _PAYLOADS]
    if any(size > MAX_PAYLOAD_BYTES for size in gitsafe.blob_sizes(root, oids, timeout=10).values()):
        raise ManagerError("payload_limit")
    blobs = gitsafe.read_blobs(root, oids, timeout=10)
    return [blobs[oid] for oid in oids]


def _decode(raw):
    try:
        return strict_loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ManagerError("invalid_payload") from exc


@gitsafe.scrubbed()
def read_candidate(control_root, revision, *, verify_membership=True) -> dict:
    """Read fixed payloads from one full commit, without reading checkout policy bytes."""
    if type(verify_membership) is not bool:
        raise ManagerError("invalid_membership")
    root = _safe_directory(control_root)
    if type(revision) is not str or not _COMMIT.fullmatch(revision):
        raise ManagerError("invalid_revision")
    try:
        if gitsafe.toplevel(root) != root:
            raise ManagerError("invalid_control_repository")
        if gitsafe.resolve_commit(root, revision) != revision:
            raise ManagerError("invalid_revision")
        control_common = gitsafe.common_dir(root)
        if control_common is None:
            raise ManagerError("invalid_control_repository")
        control_common = _safe_directory(control_common)
        raw_policy, raw_membership = _payloads(root, revision)
    except gitsafe.GitError as exc:
        raise ManagerError("git_unavailable") from exc
    policy = parse_policy(_decode(raw_policy))
    membership = parse_membership(_decode(raw_membership), verify_identity=verify_membership)
    if policy["workspace_id"] != membership["workspace_id"]:
        raise ManagerError("workspace_mismatch")
    if control_common == Path(membership["repositories"][0]["common_dir"]):
        raise ManagerError("control_member_overlap")
    return {"workspace_id": policy["workspace_id"], "control_root": str(root), "control_commit": revision,
            "policy_digest": hashlib.sha256(raw_policy).hexdigest(),
            "membership_digest": hashlib.sha256(raw_membership).hexdigest(), "policy": policy, "membership": membership}
