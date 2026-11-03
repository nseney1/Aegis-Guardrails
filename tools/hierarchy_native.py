#!/usr/bin/env python3
"""Observe Codex native records without turning local files into execution authority.

The current supported record format exposes identity/profile provenance, but not
an authenticated caller, effective tool allowlist or decision-only service.
`check` verifies a standalone maintenance profile; `admit` deliberately refuses
workflow admission until those independent native boundaries are implemented.
No command writes configuration, binds a session or launches an actor.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import encoded, require, safe_path, strict_json  # noqa: E402


MAX_ROLLOUT_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
ROLES = ("root", "router", "operator", "implementer", "reviewer", "orchestrator")
NATIVE_GAP = "authenticated native identity and tool capabilities are unavailable"


def inspect_codex(rollout, cid, requested_tier="default"):
    """Read the latest actual turn context; quoted prompt settings are ignored.

    An explicit input path is diagnostic data, not a trusted attestation. Even
    matching runtime environment values cannot authenticate a caller: an ordinary
    process can set them. All qualification fields therefore remain false.
    """
    path = safe_path(rollout)
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise ValueError("rollout file is unavailable") from exc
    require(stat.S_ISREG(path.stat().st_mode), "rollout must be a regular file")
    require(size <= MAX_ROLLOUT_BYTES, "rollout exceeds observation byte limit")
    metadata, context = None, None
    witnesses = {}
    total = 0
    with path.open("rb") as stream:
        number = 0
        while True:
            raw = stream.readline(MAX_RECORD_BYTES + 1)
            if not raw:
                break
            number += 1
            total += len(raw)
            require(total <= MAX_ROLLOUT_BYTES, "rollout exceeds observation byte limit")
            require(len(raw) <= MAX_RECORD_BYTES, "rollout record exceeds observation byte limit")
            require(raw.endswith(b"\n"), "rollout has an incomplete final record")
            try:
                record = strict_json(raw.decode("utf-8"))
            except (ValueError, UnicodeError) as exc:
                raise ValueError("malformed rollout JSON at line %d" % number) from exc
            require(isinstance(record, dict), "rollout record must be an object")
            kind = record.get("type")
            if kind not in {"session_meta", "turn_context"}:
                continue
            payload = record.get("payload")
            require(isinstance(payload, dict), "native record payload must be an object")
            witness = {"path": str(path), "line": number, "sha256": hashlib.sha256(raw).hexdigest(),
                       "timestamp": record.get("timestamp")}
            if kind == "session_meta":
                require(payload.get("id") == cid, "rollout identity does not match requested CID")
                metadata, witnesses["session_record"] = payload, witness
            else:
                context, witnesses["turn_record"] = payload, witness
    require(metadata is not None, "no native session identity in rollout")
    require(context is not None, "no native turn context in rollout")
    profile = {key: context.get(key) for key in ("model", "effort", "cwd", "approval_policy",
                                                "approvals_reviewer", "sandbox_policy", "permission_profile")}
    return {"schema": "aegis.native-observation/v1", "cid": cid, "host": "codex-cli" if metadata.get("source") == "exec" else "codex",
            "recorded_source": metadata.get("source"), "profile": profile,
            "requested_tier": requested_tier, "served_tier": context.get("service_tier"),
            "environment_cid_matches": os.environ.get("CODEX_THREAD_ID") == cid,
            "identity_authenticated": False, "tool_allowlist_verified": False,
            "native_execution_qualified": False, "qualification_blocker": NATIVE_GAP, **witnesses}


def restricted_profile(profile):
    """Return known filesystem entries, or None for an unsupported shape."""
    permission = profile.get("permission_profile")
    if not isinstance(permission, dict) or permission.get("type") != "managed" or permission.get("network") != "restricted":
        return None
    filesystem = permission.get("file_system")
    if not isinstance(filesystem, dict) or filesystem.get("type") != "restricted":
        return None
    entries = filesystem.get("entries")
    if not isinstance(entries, list) or not entries:
        return None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("access") not in {"read", "write"}:
            return None
        path = entry.get("path")
        if not isinstance(path, dict) or path.get("type") not in {"path", "special"}:
            return None
        if path["type"] == "path":
            value = path.get("path")
            if not isinstance(value, str) or not Path(value).is_absolute() or str(Path(value)) != value:
                return None
            if ".." in Path(value).parts or (entry["access"] == "write" and Path(value).parent == Path(value)):
                return None
        if path["type"] == "special":
            value = path.get("value")
            if not isinstance(value, dict) or value.get("kind") not in {"root", "tmpdir"}:
                return None
            if value["kind"] == "root" and entry["access"] != "read":
                return None
    return entries


def check_profile(observation, model, effort, cwd, *, write_roots=(), allow_tmpdir=False,
                  approval_policy="on-request", approvals_reviewer="auto_review"):
    profile = observation["profile"]
    reasons = []
    for actual, expected, reason in ((profile["model"], model, "model mismatch"),
                                     (profile["effort"], effort, "reasoning effort mismatch"),
                                     (profile["cwd"], cwd, "working directory mismatch")):
        if actual != expected:
            reasons.append(reason)
    if not profile.get("approval_policy"):
        reasons.append("approval policy unavailable")
    elif profile["approval_policy"] != approval_policy:
        reasons.append("approval policy mismatch")
    if not profile.get("approvals_reviewer"):
        reasons.append("approval reviewer unavailable")
    elif profile["approvals_reviewer"] != approvals_reviewer:
        reasons.append("approval reviewer mismatch")
    entries = restricted_profile(profile)
    if entries is None:
        reasons.append("effective restricted permission profile unavailable")
    else:
        roots = [Path(value) for value in (write_roots or (cwd,))]
        require(all(value.is_absolute() and ".." not in value.parts and value.parent != value for value in roots),
                "expected write roots must be absolute bounded paths")
        for entry in entries:
            if entry["access"] != "write":
                continue
            target = entry["path"]
            if target["type"] == "special":
                if not allow_tmpdir:
                    reasons.append("temporary-directory write access was not requested")
            elif not any(Path(target["path"]) == root or root in Path(target["path"]).parents for root in roots):
                reasons.append("write root is outside requested scope: " + target["path"])
    return {"state": "PROFILE_HOLD" if reasons else "PROFILE_MATCH", "reasons": reasons,
            "native_execution_qualified": False, "observation": observation}


def assess_role(observation, role):
    require(role in ROLES, "unsupported operational role")
    profile = observation["profile"]
    entries = restricted_profile(profile)
    reasons = []
    if role == "root" and (entries is None or any(entry["access"] == "write" for entry in entries)):
        reasons.append("ROOT requires an effective read-only filesystem")
    if role == "router" and (profile.get("effort") != "medium" or observation["requested_tier"] != "ultrafast"):
        reasons.append("router requires medium effort and ultrafast configured tier")
    reasons.append(NATIVE_GAP)
    return {"state": "NATIVE_HOLD", "role": role, "reasons": reasons,
            "native_execution_qualified": False, "observation": observation}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollout", required=True, help="Absolute path to the native session record")
    parser.add_argument("--cid", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "check", "admit"):
        command = commands.add_parser(name)
        command.add_argument("--requested-tier", default="default")
        if name == "check":
            command.add_argument("--model", required=True)
            command.add_argument("--effort", required=True)
            command.add_argument("--cwd", required=True)
            command.add_argument("--write-root", action="append", default=[],
                                 help="Expected write root; repeat for each root, defaults to the expected cwd")
            command.add_argument("--allow-tmpdir", action="store_true")
            command.add_argument("--approval-policy", default="on-request")
            command.add_argument("--approvals-reviewer", default="auto_review")
        if name == "admit":
            command.add_argument("--role", required=True, choices=ROLES)
    args = parser.parse_args(argv)
    try:
        observation = inspect_codex(args.rollout, args.cid, args.requested_tier)
        if args.command == "check":
            result = check_profile(observation, args.model, args.effort, args.cwd, write_roots=args.write_root,
                                   allow_tmpdir=args.allow_tmpdir, approval_policy=args.approval_policy,
                                   approvals_reviewer=args.approvals_reviewer)
            code = 2 if result["reasons"] else 0
        elif args.command == "admit":
            result, code = assess_role(observation, args.role), 2
        else:
            result, code = observation, 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
        result, code = {"state": "NATIVE_HOLD", "native_execution_qualified": False, "error": str(exc)}, 2
    print(encoded(result).decode())
    return code


if __name__ == "__main__":
    sys.exit(main())
