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

from aegis_core import gitsafe, pathlookup
from aegis_core.atomicio import create_private_file
from aegis_core.config import manager_registration_env
from aegis_core.manager_policy import ManagerError, canonical, digest
from aegis_core.manager_store import ManagerStore
from aegis_core.primitives import strict_loads

__all__ = ["initialize", "load_config", "public_file", "verify_owner"]
_KEYS = {"schema", "workspace_id", "control_root", "store_root", "trusted_signers", "trusted_signers_digest"}
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _path(value):
    if not isinstance(value, (str, os.PathLike)):
        raise ManagerError("unsafe_config")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        raise ManagerError("unsafe_config")
    path = Path(raw)
    if any(p.is_symlink() for p in (path, *path.parents)) or path.resolve() != path:
        raise ManagerError("unsafe_config")
    return path


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
    for name in ("control_root", "store_root", "trusted_signers"):
        _path(config[name])
    if gitsafe.toplevel(Path(path).parent) is not None:
        raise ManagerError("config_in_repository")
    signers = public_file(config["trusted_signers"])
    if hashlib.sha256(signers).hexdigest() != config["trusted_signers_digest"]:
        raise ManagerError("trust_root_changed")
    if gitsafe.toplevel(Path(config["trusted_signers"]).parent) is not None:
        raise ManagerError("trust_root_in_repository")
    return config, fingerprint


@gitsafe.scrubbed()
def initialize(config_path, *, workspace_id, control_root, store_root, trusted_signers):
    """Prepare one draft manager registration; this neither approves nor activates it."""
    path, control, store, signers = map(_path, (config_path, control_root, store_root, trusted_signers))
    if type(workspace_id) is not str or not _TOKEN.fullmatch(workspace_id):
        raise ManagerError("invalid_workspace_id")
    if gitsafe.toplevel(control) != control or gitsafe.common_dir(control) is None:
        raise ManagerError("invalid_control_repository")
    existing_parent = next(parent for parent in path.parents if parent.is_dir())
    if gitsafe.toplevel(existing_parent) is not None or gitsafe.toplevel(signers.parent) is not None:
        raise ManagerError("config_in_repository")
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
    lines = result.stdout.decode("utf-8", "replace").splitlines()
    expected = "Aegis-Manager-Approve: " + digest(statement)
    trailers = [line for line in lines[2:] if line.startswith("Aegis-Manager-Approve:")]
    if result.returncode or len(lines) < 3 or lines[:2] != ["G", "owner"] or trailers != [expected]:
        raise ManagerError("invalid_owner_signature")
    return {"state": "owner_signature_verified", "approval_commit": oid,
            "statement_digest": digest(statement), "signers_digest": config["trusted_signers_digest"]}
