"""Startup-pinned manager configuration and explicit owner SSH-commit approval.

Only public signer material is read. No key, agent, signing or shell execution is
used. Writable same-user configuration is not a native host security boundary.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from aegis_core import approval_shape as _approval_shape, gitsafe, pathlookup
from aegis_core.atomicio import create_private_file
from aegis_core.config import manager_registration_env
from aegis_core.manager_policy import ManagerError, canonical, digest
from aegis_core.manager_store import ManagerStore, in_git_worktree, resolve_placement_path
from aegis_core.primitives import strict_loads

__all__ = ["initialize", "load_config", "public_file", "verify_owner"]
_KEYS = {"schema", "workspace_id", "control_root", "store_root", "trusted_signers", "trusted_signers_digest"}
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_OWNER_LINE = re.compile(r"^Aegis-Manager-Approve: ([0-9a-f]{64})$", re.MULTILINE)


def _path(value, *, unsafe_code="unsafe_config", repository_code=None):
    if not isinstance(value, (str, os.PathLike)):
        raise ManagerError(unsafe_code)
    raw = os.fspath(value)
    if not isinstance(raw, str) or not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise ManagerError(unsafe_code)
    path = Path(raw)
    if repository_code is not None and in_git_worktree(path, unsafe_code=unsafe_code):
        raise ManagerError(repository_code)
    physical = resolve_placement_path(path, unsafe_code=unsafe_code)
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        pass
    except (OSError, ValueError) as exc:
        raise ManagerError(unsafe_code) from exc
    else:
        if stat.S_ISLNK(info.st_mode):
            raise ManagerError(unsafe_code)
    return physical


def public_file(value, *, private=False):
    """Bounded regular-file read, refusing links and nonprivate config bytes."""
    path = _path(value)
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
                raise ManagerError("unsafe_config")
            if private and os.name == "posix" and info.st_mode & 0o077:
                raise ManagerError("unsafe_config")
            return stream.read(65537)
    except OSError as exc:
        raise ManagerError("config_unavailable") from exc


@gitsafe.scrubbed()
def load_config(path, expected_digest=None):
    path = _path(path, repository_code="config_in_repository")
    raw = public_file(path, private=True)
    fingerprint = hashlib.sha256(raw).hexdigest()
    if expected_digest is not None and fingerprint != expected_digest:
        raise ManagerError("config_mismatch")
    try:
        config = strict_loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ManagerError("invalid_config") from exc
    if type(config) is not dict or set(config) != _KEYS or config["schema"] != "aegis.manager-config/v1":
        raise ManagerError("invalid_config")
    if type(config["workspace_id"]) is not str or not _TOKEN.fullmatch(config["workspace_id"]):
        raise ManagerError("invalid_config")
    config["control_root"] = str(_path(config["control_root"]))
    config["store_root"] = str(_path(config["store_root"], unsafe_code="unsafe_store",
                                     repository_code="store_in_worktree"))
    config["trusted_signers"] = str(_path(config["trusted_signers"], repository_code="trust_root_in_repository"))
    signers = public_file(config["trusted_signers"])
    if hashlib.sha256(signers).hexdigest() != config["trusted_signers_digest"]:
        raise ManagerError("trust_root_changed")
    return config, fingerprint


@gitsafe.scrubbed()
def initialize(config_path, *, workspace_id, control_root, store_root, trusted_signers):
    """Prepare one draft manager registration; this neither approves nor activates it."""
    path = _path(config_path, repository_code="config_in_repository")
    control = _path(control_root)
    store = _path(store_root, unsafe_code="unsafe_store", repository_code="store_in_worktree")
    signers = _path(trusted_signers, repository_code="trust_root_in_repository")
    if type(workspace_id) is not str or not _TOKEN.fullmatch(workspace_id):
        raise ManagerError("invalid_workspace_id")
    if gitsafe.toplevel(control) != control or gitsafe.common_dir(control) is None:
        raise ManagerError("invalid_control_repository")
    raw_signers = public_file(signers)
    if not raw_signers.strip():
        raise ManagerError("invalid_trust_root")
    config = {"schema": "aegis.manager-config/v1", "workspace_id": workspace_id,
              "control_root": str(control), "store_root": str(store), "trusted_signers": str(signers),
              "trusted_signers_digest": hashlib.sha256(raw_signers).hexdigest()}
    raw = canonical(config)
    fingerprint = hashlib.sha256(raw).hexdigest()
    audit = ManagerStore(store, forbidden_roots=(control,))
    def create(rows):
        if path.exists() and public_file(path, private=True) != raw:
            raise ManagerError("already_initialized")
        if rows:
            if len(rows) == 1 and rows[0].get("kind") == "init" and rows[0].get("config_digest") == fingerprint:
                if not path.exists():
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    _path(path)
                    if not create_private_file(path, raw):
                        raise ManagerError("already_initialized")
                return None, None
            raise ManagerError("already_initialized")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _path(path)
        if not path.exists() and not create_private_file(path, raw):
            raise ManagerError("already_initialized")
        return ({"kind": "init", "workspace_id": workspace_id, "config_digest": fingerprint}, None)
    audit.transaction(create)
    return {"status": "prepared", "policy_approval": "draft", "fitness_credit": 0,
            "config_digest": fingerprint, "registration": {"aegis-manager": {
                "command": sys.executable, "args": ["-I", "-m", "aegis_mcp"],
                "env": manager_registration_env(path, fingerprint)}}}


@gitsafe.scrubbed()
def verify_owner(config, statement, approval):
    """Verify an owner commit trailer binding the entire domain-separated statement."""
    if type(approval) is not dict or set(approval) != {"statement", "commit"} \
            or approval["statement"] != statement:
        raise ManagerError("approval_mismatch")
    oid = approval["commit"]
    if type(oid) is not str or not _OID.fullmatch(oid):
        raise ManagerError("invalid_owner_signature")
    control = Path(config["control_root"])
    program = pathlookup.which("ssh-keygen", outside=control)
    if program is None:
        raise ManagerError("signature_verifier_unavailable")
    raw_signers = public_file(config["trusted_signers"])
    if hashlib.sha256(raw_signers).hexdigest() != config["trusted_signers_digest"]:
        raise ManagerError("trust_root_changed")
    with tempfile.TemporaryDirectory(prefix="aegis-manager-signers-") as directory:
        signers = Path(directory) / "allowed_signers"
        if not create_private_file(signers, raw_signers):
            raise ManagerError("invalid_owner_signature")
        result = gitsafe.run(["-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile=" + str(signers),
                              "-c", "gpg.ssh.program=" + program, "log", "-1", "--format=%G?%n%GS%n%B", oid],
                             control, timeout=5)
    lines = result.stdout.decode("utf-8", "replace").split("\n", 2)
    message = lines[2] if len(lines) == 3 else ""
    trailers = [] if _approval_shape.bounds_refusal(message) else _OWNER_LINE.findall(message)
    if result.returncode or len(lines) < 3 or lines[:2] != ["G", "owner"] or trailers != [digest(statement)] \
            or _approval_shape.refusal(message, _OWNER_LINE, "Aegis-Manager-Approve"):
        raise ManagerError("invalid_owner_signature")
    return {"state": "owner_signature_verified", "approval_commit": oid,
            "statement_digest": digest(statement), "signers_digest": config["trusted_signers_digest"]}
