#!/usr/bin/env python3
"""Optional Teams container adapter (C1): validation, same-path mounts and pure engine argv.

Nothing here executes an engine, creates a directory or writes a run. The small CLI reads the isolation subset
of team-run.json; C3 will connect it to the complete team config validator. Both plan and verify are read-only.
Exit codes: 0 valid/equal, 2 refused/mismatched, 3 internal error. Python 3.9, standard library only.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hierarchy_mailbox import read_json, require, safe_path, strict_json, text  # noqa: E402,F401


from hierarchy_container_verify import (  # noqa: E402,F401 (public adapter facade)
    DEFAULT_PATH,
    DIGEST_IMAGE,
    ENGINE_ENV_KEYS,
    ENV_ALLOWLIST,
    ENV_NAME,
    EXPECTED_ERROR_ORDER,
    EXPECTED_FIELDS,
    IMAGE_INFO_FIELDS,
    IMAGE_PROTECTED_TREES,
    IMAGE_SCRATCH_TREES,
    IMAGE_SYSTEM_DIRS,
    ISOLATION_FIELDS,
    LINUX_ID_LIMIT,
    MEMORY,
    NAMESPACE_REQUESTS,
    NETWORK_MODE,
    SECRET_PATHS,
    SYMLINK_FOLLOW_LIMIT,
    _absolute,
    _canonical_path,
    _check_mount_overlap,
    _cpus_limit,
    _engine,
    _env_fingerprints,
    _home,
    _image,
    _image_record,
    _memory_bytes,
    _memory_limit,
    _mount_rows,
    _owner_exclusions,
    _owner_roots,
    _pids_limit,
    _system_mount,
    _user,
    _validated_expected,
    container_env,
    container_name,
    verify,
)


def read_isolation(raw, *, run, home):
    """Normalize the optional v2 isolation object; None means the unchanged host mode."""
    if raw is None:
        return None
    require(isinstance(raw, dict), "isolation must be a JSON object")
    unknown = raw.keys() - ISOLATION_FIELDS
    require(not unknown, "isolation has unknown fields: " + ", ".join(sorted(unknown)))
    mode = raw.get("mode")
    require(mode in ("host", "container"), "isolation.mode must be host or container")
    if mode == "host":
        require(raw.keys() == {"mode"}, "isolation host mode accepts only mode")
        return None
    require(sys.platform.startswith("linux"), "container isolation requires Linux")
    _absolute(run, "run")
    _absolute(home, "home")
    engine = _engine(raw.get("engine"))
    image = _image(raw.get("image"))
    cpus = _cpus_limit(raw.get("cpus"))
    memory = _memory_limit(raw.get("memory"))
    pids = _pids_limit(raw.get("pids"))
    unqualified = raw.get("allow_unqualified", False)
    require(type(unqualified) is bool, "isolation.allow_unqualified must be a bool")
    require(engine != "docker" or unqualified, "docker is unqualified; set isolation.allow_unqualified to true")
    return {"mode": mode, "engine": engine, "image": image, "cpus": cpus, "memory": memory, "pids": pids,
            "allow_unqualified": unqualified}


def _private_group(uid, gid):
    """Require the user-private naming convention as well as locally enumerated NSS membership."""
    import grp
    import pwd

    try:
        owner = pwd.getpwuid(uid)
        if gid != getattr(owner, "pw_gid", None):
            return False
        group = grp.getgrgid(gid)
        if group.gr_name != owner.pw_name or any(member != owner.pw_name for member in group.gr_mem):
            return False
        return not any(entry.pw_name != owner.pw_name and entry.pw_gid == gid for entry in pwd.getpwall())
    except (KeyError, OSError):
        return False


def _acl_entries(raw, path, mode):
    """Linux UAPI v2: little-endian header then <tag, permissions, ID> entries; acl(5) mode correspondence."""
    def check(condition, reason):
        require(condition, "mount access ACL malformed: %s: %s; require Linux POSIX access ACL v2 metadata" %
                (path, reason))

    check(type(raw) is bytes, "expected bytes")
    check(len(raw) >= 28 and (len(raw) - 4) % 8 == 0, "invalid length")
    check(struct.unpack_from("<I", raw)[0] == 2, "unsupported version")
    entries = list(struct.iter_unpack("<HHI", raw[4:]))
    singles, named, previous = {}, {2: set(), 8: set()}, 0
    for tag, perm, identity in entries:
        check(tag in (1, 2, 4, 8, 16, 32), "invalid tag")
        check(perm <= 7, "invalid permissions")
        check(tag >= previous, "entries out of order")
        previous = tag
        if tag in named:
            check(identity < LINUX_ID_LIMIT, "invalid entry ID")
            check(identity not in named[tag], "duplicate named ID")
            named[tag].add(identity)
        else:
            check(identity == LINUX_ID_LIMIT, "invalid entry ID")
            check(tag not in singles, "duplicate singleton")
            singles[tag] = perm
    check({1, 4, 32} <= singles.keys(), "missing required entries")
    check(not any(named.values()) or 16 in singles, "missing mask")
    represented = (singles[1] << 6) | (singles.get(16, singles[4]) << 3) | singles[32]
    require(mode & 0o777 == represented,
            "mount access ACL mode mismatch: %s; revalidate unchanged ACL and lstat metadata" % path)
    return entries


def _access_acl(path, mode):
    """ENODATA alone establishes absence; failed, unsupported or malformed metadata never means no ACL."""
    getter = getattr(os, "getxattr", None)
    limitation = None
    if not sys.platform.startswith("linux") or getter is None:
        limitation = "Linux access ACL API is unavailable"
    else:
        try:
            raw = getter(path, "system.posix_acl_access", follow_symlinks=False)
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                return None
            # Linux aliases ENOTSUP/EOPNOTSUPP; keep the refusal spelling stable across Python versions.
            code = "EOPNOTSUPP" if exc.errno == errno.EOPNOTSUPP else errno.errorcode.get(exc.errno, str(exc.errno))
            limitation = "access ACL query failed (%s)" % code
    require(limitation is None, "mount access ACL cannot be qualified: %s: %s; require readable Linux POSIX "
            "access ACL metadata" % (path, limitation))
    return _acl_entries(raw, path, mode)


def _source_foreign_write(path, info, private_groups):
    entries = _access_acl(path, info.st_mode)
    if entries is None:
        entries = [(4, (info.st_mode >> 3) & 7, LINUX_ID_LIMIT), (32, info.st_mode & 7, LINUX_ID_LIMIT)]
    mask = next((perm for tag, perm, _ in entries if tag == 16), 7)
    for tag, perm, identity in entries:
        if tag == 32 and perm & 2:
            return True  # OTHER is not masked. The owning UID was already checked by _trusted_source.
        if tag == 2 and perm & mask & 2 and identity not in (0, os.geteuid()):
            return True
        if tag in (4, 8) and perm & mask & 2:
            key = (os.geteuid(), info.st_gid if tag == 4 else identity)
            if key not in private_groups:
                private_groups[key] = _private_group(*key)
            if not private_groups[key]:
                return True
    return False


def _trusted_source(path, private_groups):
    """Other users must not be able to rename a component before the engine resolves this same path."""
    chain = list(reversed((path, *path.parents)))
    trusted = (0, os.geteuid())
    for index, component in enumerate(chain):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            break
        require(not stat.S_ISLNK(info.st_mode), "mount source contains a symlink: " + str(component))
        require(info.st_uid in trusted,
                "mount component owned by another user: %s (uid %d)" % (component, info.st_uid))
        # A leaf's write bits do not allow its directory entry to be replaced; its parent controls that.
        if index + 1 == len(chain):
            continue
        # Read even non-writable modes: malformed ACL data or mode disagreement must not be hidden by a mask.
        if _source_foreign_write(component, info, private_groups):
            child = None
            if index + 1 < len(chain):
                try:
                    child = os.lstat(chain[index + 1])
                except FileNotFoundError:
                    pass
            if child is not None and info.st_mode & stat.S_ISVTX:
                require(child.st_uid in trusted, "mount component owned by another user: %s (uid %d)" %
                        (chain[index + 1], child.st_uid))
            sticky_safe = bool(info.st_mode & stat.S_ISVTX) and child is not None and child.st_uid in trusted
            require(sticky_safe,
                    "mount component writable by other users: %s (uid %d)" % (component, info.st_uid))


def mount_plan(*, run, project, source, python_prefix, live_checkouts=(), home):
    """Sorted, deduplicated same-path bind mounts. Inspect metadata only; never enumerate an owner home.

    Paths below owner homes are allowed unless they overlap a listed secret; mounts containing a home refuse.
    All source ancestors must be free of symlinks and protected against replacement by other users.
    A mount cannot straddle a read-write/read-only boundary, including through directory identity aliases.
    """
    try:
        return _planned_mounts(run=run, project=project, source=source, python_prefix=python_prefix,
                               live_checkouts=live_checkouts, home=home)
    except RecursionError:
        # Cover owner/secret resolution, source metadata and ACL queries together. Existing OSError refusals
        # keep their path/errno diagnostics; recursive traversal is a bounded validation failure too.
        raise ValueError("mount metadata exceeds recursion limit") from None


def _planned_mounts(*, run, project, source, python_prefix, live_checkouts, home):
    require(isinstance(live_checkouts, (list, tuple)), "live_checkouts must be a list")
    requested = [(run, "run", True), (project, "project", True), (source, "source", False),
                 (python_prefix, "python_prefix", False)]
    requested += [(path, "live_checkouts", False) for path in live_checkouts]
    protected = _owner_roots(home)
    private_groups = {}
    checked = []
    for value, label, rw in requested:
        path = _absolute(value, label)
        _system_mount(path, [owner for owner, _, kind in protected if kind == "home"])
        for ancestor in (path, *path.parents):
            try:
                info = os.lstat(ancestor)
            except FileNotFoundError:
                continue
            require(not stat.S_ISLNK(info.st_mode), "mount source contains a symlink: " + str(ancestor))
        # --mount uses comma-separated fields; these characters would change its meaning or make bad argv.
        require(not any(char in str(path) for char in (",", ":", "\n", "\r")),
                "mount source contains an unsupported character: " + str(path))
        path, identities = _owner_exclusions(_canonical_path(path), protected)
        _trusted_source(path, private_groups)
        checked.append((path, rw, identities))
    _check_mount_overlap(checked)
    rows = {(str(path), rw) for path, rw, _ in checked}
    return [{"source": path, "destination": path, "rw": rw} for path, rw in sorted(rows)]


def _env_argv(run, env):
    return [part for key, value in sorted(container_env(run, env).items()) for part in ("--env", key + "=" + value)]


def _container_isolation(isolation, run):
    value = read_isolation(isolation, run=run, home=_home())
    require(value is not None, "container isolation is required")
    return value


def expected_plan(isolation, *, run, mounts, image_inspect, uid=None, gid=None, env=None):
    """Validated comparison record. C4 recomputes mount_plan from config immediately before run.

    Supply image_inspect_argv's result by digest to witness pinned environment values and platform identity.
    Pass the same optional env to create_argv and here. Only value fingerprints are retained; nothing executes.
    """
    isolation = _container_isolation(isolation, run)
    record = {"run": str(_absolute(run, "run")), "engine": isolation["engine"], "image": isolation["image"],
            "user": _user(uid, gid), "read_only": True, "mounts": _mount_rows(mounts),
            "cpus": isolation["cpus"], "memory": _memory_bytes(isolation["memory"]), "pids": isolation["pids"],
            "image_info": _image_record(image_inspect, isolation["image"]),
            "environment": _env_fingerprints(container_env(run, env))}
    checked, errors = _validated_expected(record)
    require(not errors, "invalid expected record: " + ", ".join(errors))
    return checked


def create_argv(isolation, *, run, mounts, env=None, uid=None, gid=None, command=None):
    """Long-lived run -d. C4 recomputes mount_plan from config immediately before run.

    Revalidates isolation and row structure; this pure builder does not attest filesystem safety.
    """
    isolation = _container_isolation(isolation, run)
    mounts = _mount_rows(mounts)
    engine = _engine(isolation["engine"])
    run = _absolute(run, "run")
    user = _user(uid, gid)  # Both engines validate identity before returning argv; keep-id emits no --user.
    argv = [engine, "run", "-d", "--name", container_name(run), "--label", "aegis.team.run=" + str(run),
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev", "--tmpfs", "/dev/shm:rw,nosuid,nodev",
            "--init", "--cpus", str(isolation["cpus"]),
            "--memory", isolation["memory"], "--pids-limit", str(isolation["pids"]),
            "--ipc=private", "--network=" + NETWORK_MODE]
    if engine == "podman":
        argv += ["--pid=private", "--userns=keep-id", "--security-opt=unmask=/proc/*", "--env-host=false", "--http-proxy=false",
                 "--read-only-tmpfs=false"]
    else:
        argv += ["--user", user, "--security-opt", "systempaths=unconfined"]
    argv += _env_argv(run, env)
    for row in sorted(mounts, key=lambda item: item["source"]):
        argv += ["--mount", "type=bind,src={source},dst={destination}".format(**row)
                 + ("" if row["rw"] else ",readonly")]
    return argv + [isolation["image"]] + _command(["/bin/sleep", "infinity"] if command is None else command)


def _command(command):
    require(isinstance(command, (list, tuple)) and bool(command), "command must be a nonempty argv")
    for word in command:
        require(isinstance(word, str) and "\x00" not in word, "invalid command argument")
    text(command[0], "command executable")
    require(not command[0].startswith("-"), "command must not start with -")
    return list(command)


def exec_argv(engine, run, command, *, workdir, env=None):
    return [_engine(engine), "exec", "--workdir", str(_absolute(workdir, "workdir"))] + _env_argv(run, env) + [
        container_name(run)] + _command(command)


def inspect_argv(engine, run):
    return [_engine(engine), "container", "inspect", container_name(run)]


def stop_argv(engine, run, *, timeout=10):
    require(type(timeout) is int and timeout > 0, "stop timeout must be a positive integer")
    return [_engine(engine), "stop", "--time", str(timeout), container_name(run)]


def rm_argv(engine, run):
    return [_engine(engine), "rm", container_name(run)]


def image_inspect_argv(engine, image):
    text(image, "image")
    require(not image.startswith("-"), "image must not start with -")
    return [_engine(engine), "image", "inspect", image]


def build_image_argv(engine, *, context, containerfile, tag):
    """Build argv only. The image definition and executable build-image command arrive in C2."""
    text(tag, "image tag")
    require(not tag.startswith("-"), "image tag must not start with -")
    return [_engine(engine), "build", "--file", str(_absolute(containerfile, "containerfile")), "--tag", tag,
            str(_absolute(context, "context"))]


def _plan(config):
    require(isinstance(config, dict), "team-run.json must be a JSON object")
    if "isolation" in config:
        require(isinstance(config["isolation"], dict), "isolation must be a JSON object")
        require(config.get("schema") == "aegis.team-run/v2", "isolation requires schema aegis.team-run/v2")
    raw = config.get("isolation")
    # Host parsing never uses a home. Keep the placeholder on that branch instead of looking up the owner
    # before read_isolation can return None; container validation retains the real lookup and its refusals.
    home = _home() if raw is not None and raw.get("mode") == "container" else "/"
    isolation = read_isolation(raw, run=config.get("run"), home=home)
    if isolation is None:
        return {"mode": "host", "isolation": None, "mounts": [], "create_argv": None}
    recipes = config.get("recipes")
    require(isinstance(recipes, dict), "recipes must be a JSON object")
    python = _absolute(recipes.get("python"), "recipes.python")
    require(python.parent.name == "bin", "recipes.python must be in a Python or venv bin directory")
    prefix = _absolute(config.get("python_prefix", str(python.parent.parent)), "python_prefix")
    _system_mount(prefix, (_home(),))
    if "python_prefix" not in config:
        try:
            marker = os.stat(prefix / "pyvenv.cfg")
        except FileNotFoundError:
            marker = None
        require(marker is not None and stat.S_ISREG(marker.st_mode),
                "python_prefix requires pyvenv.cfg or an explicit config key")
    plan = mount_plan(run=config.get("run"), project=config.get("project"),
                      source=config.get("source", str(HERE.parent)), python_prefix=prefix,
                      live_checkouts=config.get("live_checkouts", []), home=_home())
    return {"mode": "container", "isolation": isolation, "mounts": plan,
            "run": str(_absolute(config["run"], "run")),
            "create_argv": create_argv(isolation, run=config["run"], mounts=plan)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "verify"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", required=True)
        if name == "verify":
            sub.add_argument("--inspect", required=True)
    args = parser.parse_args(argv)
    try:
        plan = _plan(read_json(safe_path(_absolute(args.config, "--config"))))
        if args.command == "plan":
            answer, code = plan, 0
        else:
            require(plan["mode"] == "container", "verify requires container isolation")
            inspected = read_json(safe_path(_absolute(args.inspect, "--inspect")))
            isolation = plan["isolation"]
            try:
                image = subprocess.run(image_inspect_argv(isolation["engine"], isolation["image"]),
                                       env=dict(os.environ), capture_output=True, text=True, timeout=30,
                                       stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                raise ValueError("image inspect timed out after 30 seconds") from None
            require(image.returncode == 0, "image inspect failed for the configured digest")
            expected = expected_plan(isolation, run=plan["run"], mounts=plan["mounts"],
                                     image_inspect=image.stdout)
            mismatches = verify(inspected, expected)
            answer, code = {"mismatches": mismatches}, 2 if mismatches else 0
    except (ValueError, OSError, RecursionError) as exc:
        answer, code = {"error": str(exc)}, 2
    except Exception as exc:  # CLI boundary: unexpected defects remain exit 3, never a successful plan.
        answer, code = {"error": "internal error: " + str(exc)}, 3
    print(json.dumps(answer, sort_keys=True))
    return code



if __name__ == "__main__":
    sys.exit(main())
