#!/usr/bin/env python3
"""Optional Teams container adapter (C1): validation, same-path mounts and pure engine argv.

Nothing here executes an engine, creates a directory or writes a run. The small CLI reads the isolation subset
of team-run.json; C3 will connect it to the complete team config validator. Both plan and verify are read-only.
Exit codes: 0 valid/equal, 2 refused/mismatched, 3 internal error. Python 3.9, standard library only.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
from fractions import Fraction

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hierarchy_mailbox import read_json, require, safe_path, strict_json, text  # noqa: E402


ISOLATION_FIELDS = {"mode", "engine", "image", "cpus", "memory", "pids", "allow_unqualified"}
DIGEST_IMAGE = re.compile(r"[^\s@\x00-\x1f\x7f-][^\s@\x00-\x1f\x7f]*@sha256:[0-9a-fA-F]{64}")
MEMORY = re.compile(r"[1-9][0-9]*[kmg]")
ENV_ALLOWLIST = frozenset(("PATH", "LANG", "LC_ALL", "TERM", "TZ", "PYTHONDONTWRITEBYTECODE",
                           "HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR"))
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
SECRET_PATHS = (".claude", ".codex", ".ssh", ".gnupg", ".config", ".aws", ".kube", ".docker",
                ".netrc", ".git-credentials")
IMAGE_SYSTEM_DIRS = tuple(Path(path) for path in
                          ("/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc", "/var", "/opt", "/run",
                           "/proc", "/sys", "/dev", "/tmp"))
# Bounded engine exceptions: podman-run(1), ENVIRONMENT; names are shown by the official Config.Env example:
# https://docs.podman.io/en/v4.9.3/markdown/podman-container-inspect.1.html#example
# https://docs.podman.io/en/latest/markdown/podman-run.1.html#environment
# PWD and container were also observed in the owner's real-podman-4.9.3/inside.txt (2026-11-07).
ENGINE_ENV_KEYS = frozenset(("container", "HOSTNAME", "HOME", "TERM", "PWD"))
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
NETWORK_MODE = "bridge"
# user_namespaces(7): (uid_t)-1 is deliberately unmapped. Endpoints below are exclusive.
LINUX_ID_LIMIT = 4294967295
EXPECTED_FIELDS = frozenset(("run", "engine", "image", "user", "read_only", "mounts", "cpus", "memory", "pids",
                             "image_info", "environment"))
IMAGE_INFO_FIELDS = frozenset(("id", "digest", "repo_digests", "env_fingerprints"))
EXPECTED_ERROR_ORDER = ("expected", "engine", "label", "name", "image", "mounts", "read_only", "user",
                        "userns_mode", "cpus", "memory", "pids", "environment")
NAMESPACE_REQUESTS = (("--pid", "PidMode", "pid_mode", "private"),
                      ("--ipc", "IpcMode", "ipc_mode", "private"),
                      ("--userns", "UsernsMode", "userns_mode", "keep-id"),
                      ("--network", "NetworkMode", "network_mode", NETWORK_MODE))


def _image(image):
    require(isinstance(image, str) and DIGEST_IMAGE.fullmatch(image) is not None,
            "isolation.image must carry @sha256:<64 hex>")
    return image


def _absolute(value, label):
    # Reuse the team's path contract without an import-time cycle when C3 imports this adapter.
    from hierarchy_team import absolute

    return absolute(os.fspath(value) if isinstance(value, os.PathLike) else value, label)


def _cpus_limit(cpus):
    available = os.cpu_count()
    require(type(cpus) in (int, float) and available is not None and 0.01 <= cpus <= available
            and math.isfinite(cpus), "isolation.cpus must be >= 0.01 and <= os.cpu_count()")
    return cpus


def _memory_limit(memory):
    require(isinstance(memory, str) and MEMORY.fullmatch(memory) is not None,
            "isolation.memory must be <positive int>[kmg]")
    return memory


def _pids_limit(pids):
    require(type(pids) is int and pids >= 64, "isolation.pids must be an integer >= 64")
    return pids


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


def _engine(engine):
    require(engine in ("podman", "docker"), "isolation.engine must be podman or docker")
    return engine


def _inside(child, parent):
    return child == parent or parent in child.parents


def _ancestors(path):
    """Existing ancestors and their identities; missing tails are legal at dry-run/init time."""
    found = {}
    for ancestor in (path, *path.parents):
        try:
            info = os.stat(ancestor)
        except FileNotFoundError:
            continue
        found[ancestor] = (info.st_dev, info.st_ino)
    return found


def _inside_alias(child, parent, child_ids, parent_ids):
    if _inside(child, parent):
        return True
    # An identity match alone would reject everything (all paths share /). Compare the remaining suffixes
    # at each matching ancestor. This also catches bind aliases above missing tails on *both* sides.
    for child_parent, child_id in child_ids.items():
        for parent_parent, parent_id in parent_ids.items():
            if child_id == parent_id:
                if _inside(child.relative_to(child_parent), parent.relative_to(parent_parent)):
                    return True
    return False


def _overlap(left, right, left_ids, right_ids):
    return (_inside_alias(left, right, left_ids, right_ids)
            or _inside_alias(right, left, right_ids, left_ids))


def _owner_roots(home):
    import pwd  # Linux/POSIX only; host-mode parsing still works without pwd.

    try:
        passwd = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        raise ValueError("cannot find the owner's password-database home") from None
    owners = (_absolute(home, "home"), _absolute(Path.home(), "HOME"), _absolute(passwd, "password home"))
    homes = {Path(os.path.realpath(owner)) for owner in owners}
    # Only stat named paths: missing secrets are absent, and no owner folder is created or enumerated.
    secrets = {Path(os.path.realpath(owner / name)) for owner in owners for name in SECRET_PATHS
               if os.path.lexists(owner / name)}
    return ([(path, _ancestors(path), True) for path in sorted(homes)]
            + [(path, _ancestors(path), False) for path in sorted(secrets)])


def _system_mount(path, homes=()):
    require(not str(path).startswith("//"), "mount path has double leading slash: " + str(path))
    require(path != Path("/dev/shm"), "mount conflicts with mandatory scratch tmpfs: " + str(path))
    require(path != Path("/usr/local") and not any(_inside(system, path) for system in IMAGE_SYSTEM_DIRS)
            and all(path != home / ".local" for home in homes),
            "mount replaces image system directory: " + str(path))


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


def _mount_rows(mounts):
    """Structural validation only; C4 recomputes mount_plan from config immediately before run."""
    require(isinstance(mounts, list), "mounts must be a list")
    checked = []
    for row in mounts:
        require(isinstance(row, dict) and row.keys() == {"source", "destination", "rw"},
                "mount row must contain only source, destination and rw")
        source = _absolute(row["source"], "mount source")
        destination = _absolute(row["destination"], "mount destination")
        require(os.fspath(row["source"]) == os.fspath(row["destination"]),
                "mount source and destination must be equal")
        require(not any(char in str(source) for char in (",", ":", "\r", "\n")),
                "mount source contains an unsupported character: " + str(source))
        require(type(row["rw"]) is bool, "mount row rw must be a bool")
        _system_mount(source, (Path.home(),))
        checked.append({"source": str(source), "destination": str(destination), "rw": row["rw"]})
    require(len({row["destination"] for row in checked}) == len(checked), "duplicate mount destination")
    return sorted(checked, key=lambda row: row["source"])


def mount_plan(*, run, project, source, python_prefix, live_checkouts=(), home):
    """Sorted, deduplicated same-path bind mounts. Inspect metadata only; never enumerate an owner home.

    Paths below owner homes are allowed unless they overlap a listed secret; mounts containing a home refuse.
    All source ancestors must be free of symlinks and protected against replacement by other users.
    A mount cannot straddle a read-write/read-only boundary, including through directory identity aliases.
    """
    require(isinstance(live_checkouts, (list, tuple)), "live_checkouts must be a list")
    requested = [(run, "run", True), (project, "project", True), (source, "source", False),
                 (python_prefix, "python_prefix", False)]
    requested += [(path, "live_checkouts", False) for path in live_checkouts]
    protected = _owner_roots(home)
    private_groups = {}
    checked = []
    for value, label, rw in requested:
        path = _absolute(value, label)
        _system_mount(path, [owner for owner, _, is_home in protected if is_home])
        for ancestor in (path, *path.parents):
            require(not ancestor.is_symlink(), "mount source contains a symlink: " + str(ancestor))
        # --mount uses comma-separated fields; these characters would change its meaning or make bad argv.
        require(not any(char in str(path) for char in (",", ":", "\n", "\r")),
                "mount source contains an unsupported character: " + str(path))
        path = Path(os.path.realpath(path))
        identities = _ancestors(path)
        for owner, owner_ids, is_home in protected:
            unsafe = (_inside_alias(owner, path, owner_ids, identities) if is_home else
                      _overlap(path, owner, identities, owner_ids))
            require(not unsafe, "mount overlaps protected home: " + str(path))
        _trusted_source(path, private_groups)
        checked.append((path, rw, identities))
    for index, (path, rw, identities) in enumerate(checked):
        for other, other_rw, other_ids in checked[index + 1:]:
            require(rw == other_rw or not _overlap(path, other, identities, other_ids),
                    "read-write and read-only mounts overlap: %s and %s" % (path, other))
    rows = {(str(path), rw) for path, rw, _ in checked}
    return [{"source": path, "destination": path, "rw": rw} for path, rw in sorted(rows)]


def container_name(run):
    run = str(_absolute(run, "run"))
    return "aegis-team-" + hashlib.sha256(run.encode("utf-8")).hexdigest()[:12]


def container_env(run, env=None):
    """Explicit values only: never forward ambient credentials, agent sockets or engine override variables."""
    run = _absolute(run, "run")
    fixed = {"HOME": str(run / "home"), "CODEX_HOME": str(run / "codex-home"),
             "CLAUDE_CONFIG_DIR": str(run / "claude-home")}
    require(env is None or isinstance(env, dict), "environment must be an object")
    env = {} if env is None else env
    unknown = env.keys() - ENV_ALLOWLIST
    require(not unknown, "environment variables not allowlisted: " + ", ".join(sorted(unknown)))
    result = {"PATH": DEFAULT_PATH, "PYTHONDONTWRITEBYTECODE": "1", **fixed}
    for key, value in env.items():
        require(isinstance(value, str) and "\x00" not in value, "invalid environment value: " + key)
        require(key not in fixed or value == fixed[key], "container %s is fixed inside the run" % key)
        result[key] = value
    return result


def _env_argv(run, env):
    return [part for key, value in sorted(container_env(run, env).items()) for part in ("--env", key + "=" + value)]


def _user(uid, gid):
    uid, gid = os.getuid() if uid is None else uid, os.getgid() if gid is None else gid
    require(type(uid) is int and uid >= 0 and type(gid) is int and gid >= 0, "user must be a numeric uid:gid")
    require(uid < LINUX_ID_LIMIT and gid < LINUX_ID_LIMIT, "user uid and gid must be < %d" % LINUX_ID_LIMIT)
    return "%d:%d" % (uid, gid)


def _valid_user_record(value):
    if type(value) is not str or re.fullmatch(r"[0-9]+:[0-9]+", value) is None:
        return False
    try:
        _user(*map(int, value.split(":")))
    except ValueError:
        return False
    return True


def _container_isolation(isolation, run):
    value = read_isolation(isolation, run=run, home=Path.home())
    require(value is not None, "container isolation is required")
    return value


def _memory_bytes(memory):
    _memory_limit(memory)
    return int(memory[:-1]) * {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[memory[-1]]


def _inspection(value):
    if isinstance(value, str):
        try:
            value = strict_json(value)
        except (ValueError, RecursionError):
            return None
    if isinstance(value, list):
        value = value[0] if len(value) == 1 else None
    return value if isinstance(value, dict) else None


def _repo_digests(value):
    require(isinstance(value, list), "invalid repository digests")
    return {_image(item).rsplit("@", 1)[-1].lower() for item in value}


def _config_id(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", value) is not None,
            "invalid image config ID")
    return value.removeprefix("sha256:").lower()


def _digest(value):
    require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-fA-F]{64}", value) is not None,
            "invalid image digest")
    return value.lower()


def _env_values(value):
    if not isinstance(value, list):
        return None
    values = {}
    for item in value:
        if not isinstance(item, str) or "\x00" in item or "=" not in item:
            return None
        key, content = item.split("=", 1)
        if ENV_NAME.fullmatch(key) is None or key in values:
            return None
        values[key] = content
    return values


def _env_fingerprints(values):
    # Names are not value exemptions. Never retain image credential values in normalized comparison records.
    return {key: hashlib.sha256(json.dumps([key, content], ensure_ascii=True,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()
            for key, content in sorted(values.items())}


def _image_record(value, image):
    info = _inspection(value)
    require(info is not None, "image inspect must describe exactly one image")
    try:
        identities = {_config_id(info[key]) for key in ("Id", "ID") if key in info}
        digests = {_digest(info[key]) for key in ("Digest", "ImageDigest") if key in info}
        require(len(identities) == 1 and len(digests) <= 1, "conflicting image identity")
        repos = _repo_digests(info.get("RepoDigests", []))
    except ValueError:
        raise ValueError("image inspect has conflicting or invalid identity") from None
    require(image.rsplit("@", 1)[-1].lower() in repos | digests,
            "image inspect does not match configured digest")
    config = info.get("Config")
    require(isinstance(config, dict), "image inspect has invalid Config")
    raw_env = config.get("Env", [])
    values = _env_values([] if raw_env is None else raw_env)
    require(values is not None, "image inspect has invalid Config.Env")
    return {"digest": next(iter(digests), None), "id": identities.pop(), "repo_digests": sorted(repos),
            "env_fingerprints": _env_fingerprints(values)}


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


def _fingerprint_record(value):
    return isinstance(value, dict) and all(
        isinstance(key, str) and ENV_NAME.fullmatch(key) is not None
        and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
        for key, digest in value.items())


def _validated_expected(expected):
    """One side-effect-free contract for the existing comparison record; never repair unknown into absence.

    Return a normalized copy or ordered field errors before observing/equating any actual container fields.
    Scalar resource rules are shared with read_isolation; mount structure is shared with both argv builders.
    """
    if not isinstance(expected, dict):
        return None, ["expected"]
    bad, checked = set(), dict(expected)
    if expected.keys() - EXPECTED_FIELDS:
        bad.add("expected")
    try:
        require(isinstance(expected.get("run"), str), "run must be a string")
        checked["run"] = str(_absolute(expected["run"], "run"))
        container_name(checked["run"])  # The derived identity must be representable too.
    except (ValueError, TypeError):
        bad.update(("label", "name", "environment"))
    try:
        checked["engine"] = _engine(expected.get("engine"))
    except ValueError:
        bad.add("engine")
    try:
        checked["image"] = _image(expected.get("image"))
    except ValueError:
        bad.add("image")
    if not _valid_user_record(expected.get("user")):
        bad.add("user")
        if expected.get("engine") == "podman":
            bad.add("userns_mode")
    if expected.get("read_only") is not True:
        bad.add("read_only")
    try:
        checked["mounts"] = _mount_rows(expected.get("mounts"))
    except (ValueError, TypeError):
        bad.add("mounts")
    try:
        _cpus_limit(expected.get("cpus"))
    except ValueError:
        bad.add("cpus")
    try:
        memory = expected.get("memory")
        require(type(memory) is int and memory > 0 and memory % 1024 == 0, "invalid memory bytes")
        require(_memory_bytes(str(memory // 1024) + "k") == memory, "invalid memory bytes")
    except ValueError:
        bad.add("memory")
    try:
        _pids_limit(expected.get("pids"))
    except ValueError:
        bad.add("pids")
    info = expected.get("image_info")
    if not isinstance(info, dict):
        bad.update(("image", "environment"))
    else:
        if info.keys() - IMAGE_INFO_FIELDS:
            bad.add("image")
        try:
            identity = _config_id(info.get("id"))
            require("digest" in info, "missing digest witness")
            digest = None if info["digest"] is None else _digest(info["digest"])
            require(isinstance(info.get("repo_digests"), list), "invalid repository digests")
            repos = {_digest(item) for item in info["repo_digests"]}
            wanted = _image(expected.get("image")).rsplit("@", 1)[-1].lower()
            require(wanted in repos | ({digest} if digest is not None else set()), "unassociated image")
            checked["image_info"] = {"id": identity, "digest": digest, "repo_digests": sorted(repos),
                                     "env_fingerprints": info.get("env_fingerprints")}
        except (ValueError, TypeError):
            bad.add("image")
        if not _fingerprint_record(info.get("env_fingerprints")):
            bad.add("environment")
    create = expected.get("environment")
    if not _fingerprint_record(create):
        bad.add("environment")
    elif "label" not in bad:
        baseline = _env_fingerprints(container_env(checked["run"]))
        if (not baseline.keys() <= create.keys() or create.keys() - ENV_ALLOWLIST
                or any(create[key] != baseline[key] for key in ("HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR"))):
            bad.add("environment")
    errors = [field for field in EXPECTED_ERROR_ORDER if field in bad]
    return (None, errors) if errors else (checked, [])


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


def _object(value):
    return value if isinstance(value, dict) else {}


def _access_mode(options):
    require(isinstance(options, str), "invalid mount options")
    modes = [word for word in options.split(",") if word in ("ro", "rw")]
    require(len(modes) <= 1, "conflicting mount access")
    return None if not modes else modes[0] == "rw"


def _access(options):
    # Serialized Binds/Tmpfs default to rw. Optional Mode/Options without an access flag assert no mode.
    return _access_mode(options) is not False


def _scratch_options(options, *, complete=True):
    require(isinstance(options, str), "invalid tmpfs options")
    flags = set(options.split(","))
    safe = {"rw", "nosuid", "nodev"} <= flags
    require((not complete or safe) and not flags & {"ro", "suid", "dev"}
            and not {"exec", "noexec"} <= flags, "unsafe scratch tmpfs options")
    return safe


def _mount_option_witness(kind, options, rw, *, complete):
    """All provided option representations assert access; only full safe tmpfs flags establish safety."""
    access = _access_mode(options)
    require(access is None or access == rw, "conflicting mount access")
    return _scratch_options(options, complete=complete) if kind == "tmpfs" else False


def _inspected_mounts(value, host, planned, requests=()):
    """Actual declarations must prove the plan first; requests only constrain established actual facts."""
    actual_declarations = {}
    actual_safety = set()
    actual_flags = {}

    def observe_actual(kind, destination, options, rw, *, complete):
        safe = _mount_option_witness(kind, options, rw, complete=complete)
        if kind == "tmpfs":
            flags = actual_flags.setdefault(destination, set())
            flags.update(options.split(","))
            _scratch_options(",".join(sorted(flags)), complete=False)
            if safe:
                actual_safety.add(destination)

    def declaration(kind, source, destination, rw):
        require(isinstance(source, str) and isinstance(destination, str) and type(rw) is bool,
                "invalid mount declaration")
        path = _absolute(destination, "mount destination")
        require(str(path) == destination, "noncanonical mount destination")
        if kind == "tmpfs":
            require(destination in ("/tmp", "/dev/shm") and source in ("", "tmpfs", "shm"), "unexpected tmpfs")
            require(rw, "declared scratch tmpfs must be writable")
            source = "tmpfs"
        else:
            require(kind == "bind", "unexpected mount type")
            _absolute(source, "mount source")
        return kind, source, rw

    def put_actual(kind, source, destination, rw, options=None):
        row = declaration(kind, source, destination, rw)
        if options is not None:
            observe_actual(kind, destination, options, rw, complete=True)
        require(destination not in actual_declarations or actual_declarations[destination] == row,
                "conflicting mounts")
        actual_declarations[destination] = row

    try:
        require(isinstance(value, list), "invalid Mounts")
        seen = set()
        for row in value:
            require(isinstance(row, dict), "invalid mount")
            kind = row.get("Type")  # Missing kind is not affirmative evidence of a bind.
            dest = row.get("Destination")
            require(isinstance(dest, str) and dest not in seen, "duplicate mount destination")
            seen.add(dest)
            options = None
            if "Options" in row:
                require(isinstance(row["Options"], list) and all(isinstance(item, str) for item in row["Options"]),
                        "invalid mount Options")
                options = ",".join(row["Options"])
            if "Mode" in row:
                observe_actual(kind, dest, row["Mode"], row.get("RW"), complete=False)
            put_actual(kind, row.get("Source"), dest, row.get("RW"), options)
        tmpfs = {} if host.get("Tmpfs") is None else host["Tmpfs"]
        require(isinstance(tmpfs, dict), "invalid Tmpfs")
        for dest, options in tmpfs.items():
            put_actual("tmpfs", "tmpfs", dest, _access(options), options)
        binds = [] if host.get("Binds") is None else host["Binds"]
        require(isinstance(binds, list), "invalid Binds")
        seen = set()
        for bind in binds:
            require(isinstance(bind, str), "invalid bind")
            parts = bind.split(":")
            require(len(parts) in (2, 3), "invalid bind")
            source, dest = parts[:2]
            require(dest not in seen, "duplicate bind destination")
            seen.add(dest)
            put_actual("bind", source, dest, _access(parts[2] if len(parts) == 3 else "rw"))

        # Stage 1: only actual representations may establish coverage, writable scratch and safety.
        actual_binds = sorted((source, dest, rw) for dest, (kind, source, rw) in actual_declarations.items()
                              if kind == "bind")
        require(actual_binds == planned, "actual bind coverage differs from plan")
        require(actual_declarations.get("/tmp") == ("tmpfs", "tmpfs", True), "missing declared /tmp tmpfs")
        require(actual_declarations.get("/dev/shm") == ("tmpfs", "tmpfs", True), "missing declared /dev/shm tmpfs")
        require(actual_safety == {"/tmp", "/dev/shm"}, "missing actual scratch tmpfs safety options")

        # Stage 2: requests never enter actual declarations or positive safety witnesses. Copy flags only
        # for contradiction checks across actual/request and request/request observations.
        constraint_flags = {dest: set(flags) for dest, flags in actual_flags.items()}
        for kind, source, dest, rw, options in requests:
            row = declaration(kind, source, dest, rw)
            require(actual_declarations.get(dest) == row, "request differs from established actual mount")
            if options is not None:
                _mount_option_witness(kind, options, rw, complete=True)
                if kind == "tmpfs":
                    flags = constraint_flags[dest]
                    flags.update(options.split(","))
                    _scratch_options(",".join(sorted(flags)), complete=False)
    except (ValueError, TypeError):
        return False
    return True


def _image_matches(actual, config, expected):
    """Every supplied identity must agree with the image explicitly inspected by the configured digest."""
    try:
        info = expected["image_info"]
        identity = info["id"]
        associated = set(info["repo_digests"])
        # Docker has no Digest field. Absence is distinct from an invalid, explicitly empty witness.
        if info["digest"] is not None:
            associated.add(info["digest"])
        require(_config_id(actual.get("Image")) == identity, "container image config differs")
        for key in ("ImageDigest", "Digest"):
            if key in actual:
                require(_digest(actual[key]) in associated, "container digest differs")
        if "RepoDigests" in actual:
            require(_repo_digests(actual["RepoDigests"]) <= associated, "container repository digests differ")
        for value in ([config["Image"]] if "Image" in config else []) + (
                [actual["ImageName"]] if "ImageName" in actual else []):
            if isinstance(value, str) and "@" in value:
                require(_image(value).rsplit("@", 1)[-1].lower() in associated, "container image reference differs")
            else:
                require(_config_id(value) == identity, "container image reference differs")
    except (KeyError, TypeError, ValueError):
        return False
    return True


def _cpus_match(host, cpus, engine):
    nano = host.get("NanoCpus", 0)
    quota, period = host.get("CpuQuota", 0), host.get("CpuPeriod", 0)
    if any(type(item) is not int for item in (nano, quota, period)):
        return False
    if nano < 0 or quota < 0 or period < 0 or not (nano > 0 or quota > 0):
        return False
    # Podman 4.9.3 converts binary float cores to a 100000-us quota, then derives NanoCpus from that quota.
    wanted_quota = int(float(cpus) * 100000) if engine == "podman" else int(Fraction(str(cpus)) * 100000)
    wanted_nano = wanted_quota * 10000 if engine == "podman" else int(Fraction(str(cpus)) * 1000000000)
    return ((nano == 0 or nano == wanted_nano)
            and (quota == 0 or (period == 100000 and quota == wanted_quota)))


def _mapping_keeps_id(rows, identity):
    if not isinstance(rows, list) or not rows:
        return False
    ranges = []
    for row in rows:
        if not isinstance(row, str) or re.fullmatch(r"[0-9]+:[0-9]+:[0-9]+", row) is None:
            return False
        try:
            inside, outside, count = map(int, row.split(":"))
        except ValueError:
            return False
        if (count <= 0 or inside >= LINUX_ID_LIMIT or outside >= LINUX_ID_LIMIT
                or inside + count > LINUX_ID_LIMIT or outside + count > LINUX_ID_LIMIT):
            return False
        ranges.append((inside, outside, count))
    for axis in (0, 1):
        ordered = sorted((row[axis], row[axis] + row[2]) for row in ranges)
        if any(previous[1] > following[0] for previous, following in zip(ordered, ordered[1:])):
            return False
    # These HostConfig mappings are relative to the rootless engine's parent user namespace, where the
    # invoking host user is ID 0. The capture contains 1000:0:1 in both maps, confirmed by inside.txt.
    return (identity, 0, 1) in ranges


def _keep_id(host, user):
    uid, gid = map(int, user.split(":"))
    mappings = _object(host.get("IDMappings"))
    mode = host.get("UsernsMode")
    # Observed Podman 4.9.3 (real-podman-fix7-native and earlier): only "private" is admitted.
    return (type(mode) is str and mode == "private" and _mapping_keeps_id(mappings.get("UidMap"), uid)
            and _mapping_keeps_id(mappings.get("GidMap"), gid))


def _recorded_options(config, image):
    """Podman's recorded run options by arity; values stay in memory, never in normalized records/errors."""
    argv = config.get("CreateCommand")
    if not isinstance(argv, list) or not all(isinstance(word, str) for word in argv):
        return None
    if len(argv) < 3 or Path(argv[0]).name != "podman" or argv[1] != "run":
        return None
    # Parse option arities; the image string could also occur as a label/env value. Do not truncate at it.
    takes_value = {"--name", "--label", "--tmpfs", "--cpus", "--memory", "--pids-limit", "--env", "--mount",
                   "--user", "--security-opt", "--userns", "--pid", "--ipc", "--network", "--env-host",
                   "--http-proxy", "--read-only-tmpfs"}
    standalone = {"-d", "--read-only", "--init"}
    recorded = {}
    index = 2
    while index < len(argv):
        word = argv[index]
        if not word.startswith("-"):
            return recorded if word == image else None
        key, separator, value = word.partition("=")
        if key in standalone and not separator:
            index += 1
            continue
        if key not in takes_value:
            return None
        if not separator:
            index += 1
            if index >= len(argv):
                return None
            value = argv[index]
        recorded.setdefault(key, []).append(value)
        index += 1
    return None


def _unmask_requested(recorded, host):
    """Check recorded security/env/tmpfs intent, not effective unmasking or hidden automatic mounts."""
    reported = host.get("SecurityOpt")
    if not isinstance(reported, list) or any(item != "unmask=/proc/*" for item in reported):
        return False
    required = {"--security-opt": ["unmask=/proc/*"], "--env-host": ["false"], "--http-proxy": ["false"],
                "--read-only-tmpfs": ["false"]}
    return recorded is not None and all(recorded.get(key) == values for key, values in required.items())


def _recorded_bind(value):
    """Only the C1 emitted bind grammar; retain all supplied fields instead of last-value overwriting."""
    fields, access = {}, []
    for word in value.split(","):
        key, separator, content = word.partition("=")
        if separator:
            require(key in ("type", "src", "dst"), "unsupported recorded bind field")
            fields.setdefault(key, []).append(content)
        else:
            require(word == "readonly", "unsupported recorded bind option")
            access.append("ro")
    require(fields.keys() == {"type", "src", "dst"}, "missing recorded bind field")
    require(all(all(value == values[0] for value in values) for values in fields.values()),
            "conflicting recorded bind fields")
    require(fields["type"][0] == "bind", "unsupported recorded mount type")
    row = _mount_rows([{"source": fields["src"][0], "destination": fields["dst"][0],
                        "rw": _access_mode(",".join(access)) is not False}])[0]
    return "bind", row["source"], row["destination"], row["rw"], None


def _recorded_requests(config, host, expected):
    """Finite request contract, not full argv equality. Absence/subsets and existing duplicate rules persist.

    Parse only existing option arities. Validate each supplied supported witness, then merge mount subsets
    through the actual mount checker. No raw values leave this comparison as normalized records or errors.
    """
    if expected["engine"] != "podman":
        return set(), []  # Docker has no normative CreateCommand witness.
    recorded = _recorded_options(config, expected["image"])
    security_ok = _unmask_requested(recorded, host)
    bad = set() if security_ok else {"security_opt"}
    if recorded is None:
        return bad, []
    # Keep the established security-failure gating: malformed/missing intent already refuses as security_opt.
    if security_ok:
        values = _env_values(recorded.get("--env", []))
        if values is None or _env_fingerprints(values) != expected["environment"]:
            bad.add("environment")
    exact = {flag: (label, request) for flag, _, label, request in NAMESPACE_REQUESTS}
    exact["--name"] = ("name", container_name(expected["run"]))
    labels = {flag: label for flag, (label, _) in exact.items()}
    labels.update({"--cpus": "cpus", "--memory": "memory", "--pids-limit": "pids", "--user": "user",
                   "--label": "label", "--mount": "mounts", "--tmpfs": "mounts"})
    mounts = []
    for flag, values in recorded.items():
        if flag in ("--env", "--security-opt", "--env-host", "--http-proxy", "--read-only-tmpfs"):
            continue  # These complete request families were checked above, with their existing rules.
        for value in values:
            try:
                if flag in exact:
                    require(value == exact[flag][1], "contradictory recorded request")
                elif flag == "--cpus":
                    require(re.fullmatch(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", value)
                            is not None, "invalid recorded CPU number")
                    cpus = _cpus_limit(float(value))
                    require(_cpus_match(host, cpus, expected["engine"]), "contradictory recorded CPU limit")
                elif flag == "--memory":
                    require(_memory_bytes(value) == expected["memory"], "contradictory recorded memory limit")
                elif flag == "--pids-limit":
                    require(re.fullmatch(r"[+-]?[0-9]+", value) is not None, "invalid recorded PID integer")
                    require(_pids_limit(int(value)) == expected["pids"], "contradictory recorded PID limit")
                elif flag == "--user":
                    require(_valid_user_record(value), "invalid recorded user")
                    require(tuple(map(int, value.split(":"))) == tuple(map(int, expected["user"].split(":"))),
                            "contradictory recorded user")
                elif flag == "--label":
                    key, separator, content = value.partition("=")
                    require(key != "aegis.team.run" or (separator and content == expected["run"]),
                            "contradictory recorded run label")
                elif flag == "--mount":
                    mounts.append(_recorded_bind(value))
                elif flag == "--tmpfs":
                    parts = value.split(":")
                    require(len(parts) == 2, "invalid recorded tmpfs")
                    dest, options = parts
                    mounts.append(("tmpfs", "tmpfs", dest, _access(options), options))
                else:
                    require(False, "unsupported recorded request")
            except (ValueError, TypeError):
                bad.add(labels.get(flag, "security_opt"))
    return bad, mounts


def _namespace_witnesses(host, expected, requested_bad):
    """Actual namespace domains conjoin with the finite validator's recorded request errors."""
    bad = []
    podman = expected["engine"] == "podman"
    for flag, key, label, request in NAMESPACE_REQUESTS:
        if flag == "--userns":
            actual_ok = _keep_id(host, expected["user"]) if podman else host.get(key) == ""
        elif flag == "--network":
            actual_ok = host.get(key) == NETWORK_MODE
        else:
            actual_ok = host.get(key) in ("", "private")
        if not actual_ok or label in requested_bad:
            bad.append(label)
    return bad


def _name_witnesses(actual, expected):
    wanted = container_name(expected["run"])
    observed = actual.get("Name")
    if not isinstance(observed, str):
        return False
    # Moby v27.5.1 daemon/names.go reserveName adds exactly one slash. Podman capture names are plain.
    if expected["engine"] == "docker" and observed.startswith("/"):
        observed = observed[1:]
    return observed == wanted


def _environment_matches(config, expected):
    values = _env_values(config.get("Env"))
    if values is None:
        return False
    create = expected["environment"]
    pinned = expected["image_info"]["env_fingerprints"]
    # Finite precedence: explicit allowlisted create > pinned defaults > optional engine-only names.
    required = {**pinned, **create}
    observed = _env_fingerprints(values)
    if (not required.keys() <= observed.keys() or any(observed[key] != required[key] for key in required)
            or observed.keys() - required.keys() - ENGINE_ENV_KEYS):
        return False
    return True


def verify(inspect_json, expected):
    """Named mismatches in stable order. Unknown metadata is ignored; malformed required fields refuse.

    The expected image_info comes from an image inspect by digest: pinned environment value fingerprints and
    platform identity. No matching witness waives contradictory values or access declarations.
    """
    expected, errors = _validated_expected(expected)
    if errors:
        return errors
    actual = _inspection(inspect_json)
    if actual is None:
        return ["inspect"]
    config = _object(actual.get("Config"))
    host = _object(actual.get("HostConfig"))
    podman = expected["engine"] == "podman"
    requested_bad, requested_mounts = _recorded_requests(config, host, expected)
    mismatches = []
    if _object(config.get("Labels")).get("aegis.team.run") != expected["run"] or "label" in requested_bad:
        mismatches.append("label")
    if not _name_witnesses(actual, expected) or "name" in requested_bad:
        mismatches.append("name")
    if not _image_matches(actual, config, expected):
        mismatches.append("image")
    planned = sorted((row["source"], row["destination"], row["rw"]) for row in expected["mounts"])
    if not _inspected_mounts(actual.get("Mounts"), host, planned, requested_mounts) or "mounts" in requested_bad:
        mismatches.append("mounts")
    if host.get("ReadonlyRootfs") is not True:
        mismatches.append("read_only")
    if config.get("User") != expected["user"] or "user" in requested_bad:
        mismatches.append("user")
    if host.get("Privileged") is not False:
        mismatches.append("privileged")
    if host.get("CapAdd") not in (None, []):
        mismatches.append("cap_add")
    mismatches.extend(_namespace_witnesses(host, expected, requested_bad))
    if host.get("Devices") not in (None, []):
        mismatches.append("devices")
    security_ok = ("security_opt" not in requested_bad if podman else
                   host.get("SecurityOpt") == ["systempaths=unconfined"])
    if not security_ok:
        mismatches.append("security_opt")
    if not _cpus_match(host, expected["cpus"], expected["engine"]) or "cpus" in requested_bad:
        mismatches.append("cpus")
    for key, name in (("Memory", "memory"), ("PidsLimit", "pids")):
        if type(host.get(key)) is not int or host[key] != expected[name] or name in requested_bad:
            mismatches.append(name)
    if not _environment_matches(config, expected) or "environment" in requested_bad:
        mismatches.append("environment")
    return mismatches

def _plan(config):
    require(isinstance(config, dict), "team-run.json must be a JSON object")
    if "isolation" in config:
        require(isinstance(config["isolation"], dict), "isolation must be a JSON object")
        require(config.get("schema") == "aegis.team-run/v2", "isolation requires schema aegis.team-run/v2")
    isolation = read_isolation(config.get("isolation"), run=config.get("run"), home=Path.home())
    if isolation is None:
        return {"mode": "host", "isolation": None, "mounts": [], "create_argv": None}
    recipes = config.get("recipes")
    require(isinstance(recipes, dict), "recipes must be a JSON object")
    python = _absolute(recipes.get("python"), "recipes.python")
    require(python.parent.name == "bin", "recipes.python must be in a Python or venv bin directory")
    prefix = _absolute(config.get("python_prefix", str(python.parent.parent)), "python_prefix")
    _system_mount(prefix, (Path.home(),))
    require("python_prefix" in config or (prefix / "pyvenv.cfg").is_file(),
            "python_prefix requires pyvenv.cfg or an explicit config key")
    plan = mount_plan(run=config.get("run"), project=config.get("project"),
                      source=config.get("source", str(HERE.parent)), python_prefix=prefix,
                      live_checkouts=config.get("live_checkouts", []), home=Path.home())
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
