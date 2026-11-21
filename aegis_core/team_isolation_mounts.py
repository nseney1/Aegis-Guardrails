"""Pure isolation validation and same-path mount planning.

The trusted adapter supplies descriptor-derived metadata for every path component,
including before/after samples captured while descriptors remain held. This module
never opens a path, looks up an owner, or executes an engine. A plan is a snapshot,
not authority to use a later pathname: the adapter must reobserve before execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import PurePosixPath as Path
import re
import stat

from aegis_core import team_host_registry
from aegis_core.primitives import json_preflight, strict_loads
from aegis_core.team_isolation_refusal import REFUSALS, IsolationRefusal

__all__ = [
    "IsolationRefusal", "REFUSALS", "MAX_DOCUMENT_BYTES", "LINUX_ID_LIMIT", "NETWORK_MODE", "DEFAULT_PATH",
    "BASE_ENV_ALLOWLIST", "ENGINE_ENV_KEYS", "ENV_NAME", "ISOLATION_FIELDS", "require", "bounded_value",
    "load_document", "container_supported", "engine", "image", "cpus_limit", "memory_bytes", "pids_limit",
    "read_isolation", "load_isolation", "absolute_path", "inside", "system_mount", "mount_rows",
    "host_policy", "home_folders", "container_env", "metadata", "foreign_write", "aliases_overlap", "secret_names",
    "credential_names",
    "ABSENCE", "inside_alias", "link_target", "resolved_path", "path_identities", "validated_owner_homes",
    "protected_roots", "validate_mounts", "mount_plan",
]

ABSENCE = None  # An explicit mapping entry, never an omitted or unreadable observation.
MAX_DOCUMENT_BYTES = 1024 * 1024
LINUX_ID_LIMIT = 4294967295
NETWORK_MODE = "bridge"
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
BASE_ENV_ALLOWLIST = frozenset(("PATH", "LANG", "LC_ALL", "TERM", "TZ", "PYTHONDONTWRITEBYTECODE", "HOME"))
ENGINE_ENV_KEYS = frozenset(("container", "HOSTNAME", "HOME", "TERM", "PWD"))
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ISOLATION_FIELDS = frozenset(("mode", "engine", "image", "cpus", "memory", "pids", "allow_unqualified"))
# These built-in roots remain required even when an injected host table omits owner folders.
_CLAUDE_OWNER_DIR = team_host_registry.entry(team_host_registry.CLAUDE)["home"]["owner_folder"]
_CODEX_OWNER_DIR = team_host_registry.entry(team_host_registry.CODEX)["home"]["owner_folder"]
SECRET_NAMES = frozenset((".ssh", ".gnupg", ".config", ".aws", ".kube", ".docker", ".netrc", ".git-credentials",
                          ".codeium", ".copilot", ".cursor", ".gemini", ".kiro",
                          _CLAUDE_OWNER_DIR, _CLAUDE_OWNER_DIR + ".json", _CODEX_OWNER_DIR))
SYSTEM_TREES = tuple(Path(p) for p in
                     ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc", "/boot",
                      "/proc", "/sys", "/run", "/dev", "/var", "/opt", "/tmp"))


def require(condition, reason):
    if not condition:
        raise IsolationRefusal(reason)


def bounded_value(value):
    """Bound already parsed injected facts before copying, sorting or comparing."""
    pending = [(value, 0)]
    nodes, size = 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        require(nodes <= 32768 and depth <= 32, "document_size")
        if type(item) is str:
            require(len(item) <= 16384, "document_size")
            for ch in item:
                code = ord(ch)
                require(not 0xD800 <= code <= 0xDFFF, "document_invalid")
                size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
            require(size <= MAX_DOCUMENT_BYTES, "document_size")
        elif type(item) in (dict, list, tuple):
            require(len(item) <= 4096, "document_size")
            require(len(pending) + len(item) * 2 <= 32768, "document_size")
            if type(item) is dict:
                require(all(type(key) is str for key in item), "document_invalid")
                pending.extend((key, depth + 1) for key in item)
                pending.extend((child, depth + 1) for child in item.values())
            else:
                pending.extend((child, depth + 1) for child in item)
        elif type(item) is int:
            require(item.bit_length() <= 128, "document_size")
        elif type(item) is float:
            require(math.isfinite(item), "document_invalid")
        else:
            require(item is None or type(item) is bool, "document_invalid")


def load_document(raw):
    try:
        text = json_preflight(raw, max_bytes=MAX_DOCUMENT_BYTES, max_depth=32,
                              max_nodes=32768, max_items=4096, max_string=16384, max_atom=128)
        value = strict_loads(text)
    except (ValueError, UnicodeError, RecursionError) as exc:
        reason = "document_size" if str(exc) in ("size", "nesting", "nodes", "container", "string", "atom") else "document_invalid"
        raise IsolationRefusal(reason) from None
    bounded_value(value)
    return value


def container_supported(platform):
    return type(platform) is str and platform.startswith("linux")


def engine(value):
    require(type(value) is str and value in ("podman", "docker"), "isolation_engine")
    return value


def image(value):
    require(type(value) is str and len(value) <= 4096 and
            re.fullmatch(r"[^\s@\x00-\x1f\x7f-][^\s@\x00-\x1f\x7f]*@sha256:[0-9a-fA-F]{64}", value), "isolation_image")
    return value


def cpus_limit(value, cpu_count=None):
    require(type(value) in (int, float) and 0.01 <= value <= 1048576 and math.isfinite(value),
            "isolation_cpus")
    if cpu_count is not None:
        require(type(cpu_count) is int and cpu_count > 0 and value <= cpu_count, "isolation_cpus")
    return value


def memory_bytes(value):
    require(type(value) is str and len(value) <= 20 and re.fullmatch(r"[1-9][0-9]*[kmg]", value), "isolation_memory")
    result = int(value[:-1]) * {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[value[-1]]
    require(result <= 2 ** 63 - 1, "isolation_memory")
    return result


def pids_limit(value):
    require(type(value) is int and 64 <= value <= 2 ** 31 - 1, "isolation_pids")
    return value


def read_isolation(raw, *, cpu_count, platform):
    bounded_value(raw)
    if raw is None:
        return None
    require(type(raw) is dict, "isolation_object")
    require(not raw.keys() - ISOLATION_FIELDS, "isolation_fields")
    require(raw.get("mode") in ("host", "container"), "isolation_mode")
    if raw["mode"] == "host":
        require(raw.keys() == {"mode"}, "isolation_fields")
        return None
    require(container_supported(platform), "unsupported_platform")
    require(type(cpu_count) is int and cpu_count > 0, "isolation_cpus")
    selected = engine(raw.get("engine"))
    unqualified = raw.get("allow_unqualified", False)
    require(type(unqualified) is bool, "isolation_unqualified")
    require(selected != "docker" or unqualified, "docker_unqualified")
    memory_bytes(raw.get("memory"))
    return dict(mode="container", engine=selected, image=image(raw.get("image")),
                cpus=cpus_limit(raw.get("cpus"), cpu_count), memory=raw["memory"],
                pids=pids_limit(raw.get("pids")), allow_unqualified=unqualified)


def load_isolation(raw, *, cpu_count, platform):
    return read_isolation(load_document(raw), cpu_count=cpu_count, platform=platform)


def absolute_path(value, label=None):
    require(type(value) is str and 0 < len(value) <= 4096 and value.count("/") <= 128, "unsafe_mount")
    require(value.startswith("/") and not value.startswith("//") and "\\" not in value
            and not any(ord(ch) < 32 or 127 <= ord(ch) <= 159 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value)
            and not any(ch in value for ch in (",", ":")), "unsafe_mount")
    require(all(part not in (".", "..") for part in value.split("/")), "unsafe_mount")
    return Path(value)


def inside(child, parent):
    return child == parent or parent in child.parents


def system_mount(path):
    scratch = any(tree in path.parents for tree in (Path("/dev/shm"), Path("/var/tmp")))
    require(path != Path("/dev/shm") and not any(inside(tree, path) for tree in SYSTEM_TREES)
            and (scratch or not any(inside(path, tree) for tree in SYSTEM_TREES if str(tree) not in ("/opt", "/tmp"))),
            "unsafe_mount")


def mount_rows(mounts):
    bounded_value(mounts)
    require(type(mounts) is list and len(mounts) <= 128, "mount_rows")
    rows = []
    for row in mounts:
        require(type(row) is dict and row.keys() == {"source", "destination", "rw"}, "mount_rows")
        source = absolute_path(row["source"])
        require(str(source) == row["source"] == row["destination"] and type(row["rw"]) is bool, "mount_rows")
        system_mount(source)
        rows.append(dict(row))
    require(len({row["source"] for row in rows}) == len(rows), "mount_rows")
    for index, row in enumerate(rows):
        for other in rows[index + 1:]:
            require(row["rw"] == other["rw"] or not (
                inside(Path(row["source"]), Path(other["source"])) or
                inside(Path(other["source"]), Path(row["source"]))), "mount_overlap")
    return sorted(rows, key=lambda row: row["source"])


@dataclass(frozen=True)
class _HostPolicy:
    homes: tuple
    protected_names: frozenset


def _credential_name(value):
    return (type(value) is str and 0 < len(value) <= 128 and value not in (".", "..", ".local")
            and re.fullmatch(r"[A-Za-z0-9._-]+", value) is not None)


def host_policy(host_table):
    """Project the injected registry into a single immutable isolation policy."""
    if type(host_table) is _HostPolicy:
        credential_names(host_table.protected_names)
        return host_table
    bounded_value(host_table)
    require(type(host_table) is dict and 0 < len(host_table) <= 64, "host_registry")
    folders = {"HOME": "home"}
    protected = set(SECRET_NAMES)
    for row in host_table.values():
        require(type(row) is dict and type(row.get("home")) is dict, "host_registry")
        home = row["home"]
        variable, folder = home.get("variable"), home.get("run_folder")
        require(type(variable) is str and len(variable) <= 128 and ENV_NAME.fullmatch(variable), "host_registry")
        require(type(folder) is str and len(folder) <= 128 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", folder)
                and folder not in folders.values() and variable not in BASE_ENV_ALLOWLIST | ENGINE_ENV_KEYS
                and variable not in folders, "host_registry")
        folders[variable] = folder
        if "owner_folder" in home:
            owner = home["owner_folder"]
            require(_credential_name(owner), "host_registry")
            protected.add(owner)
    return _HostPolicy(tuple(folders.items()), frozenset(protected))


def home_folders(host_table):
    return dict(host_policy(host_table).homes)


def container_env(run, env=None, *, host_table):
    fixed = {variable: str(absolute_path(run) / folder) for variable, folder in home_folders(host_table).items()}
    bounded_value(env)
    require(env is None or type(env) is dict, "environment")
    env = {} if env is None else env
    require(not env.keys() - (BASE_ENV_ALLOWLIST | fixed.keys()), "environment")
    result = {"PATH": DEFAULT_PATH, "PYTHONDONTWRITEBYTECODE": "1", **fixed}
    for key, value in env.items():
        require(type(value) is str and "\x00" not in value and (key not in fixed or value == fixed[key]), "environment")
        result[key] = value
    return result


def metadata(path, observed, *, directory=True, allow_absence=False):
    require(str(path) in observed, "mount_metadata")
    row = observed.get(str(path))
    if row is ABSENCE:
        require(allow_absence and path != Path("/"), "mount_metadata")
        return None
    fields = {"device", "inode", "uid", "gid", "mode", "acl"}
    if type(row) is dict and "target" in row:
        fields.add("target")
    require(type(row) is dict and row.keys() == fields | {"after"}, "mount_metadata")
    before = {key: row[key] for key in fields}
    require(type(row["after"]) is dict and row["after"] == before, "mount_changed")
    require(all(type(row[key]) is int and 0 <= row[key] < 2 ** 64 for key in fields - {"acl", "target"}), "mount_metadata")
    require(all(type(row["after"][key]) is type(row[key]) for key in fields), "mount_changed")
    require(stat.S_ISDIR(row["mode"]) if directory else
            any(test(row["mode"]) for test in (stat.S_ISDIR, stat.S_ISREG, stat.S_ISLNK)), "unsafe_mount")
    foreign_write(row, row["uid"], (row["gid"],))  # Validate ACLs even on protected, unmounted roots.
    return row


def foreign_write(row, owner_uid, private_gids):
    acl = row["acl"]
    mode = row["mode"]
    if acl is None:
        return bool(mode & 2 or mode & 0o020 and row["gid"] not in private_gids)
    require(type(acl) is list and 3 <= len(acl) <= 1024, "mount_metadata")
    singles, named, previous = {}, {2: set(), 8: set()}, 0
    for entry in acl:
        require(type(entry) is list and len(entry) == 3 and all(type(n) is int for n in entry), "mount_metadata")
        tag, perm, identity = entry
        require(tag in (1, 2, 4, 8, 16, 32) and tag >= previous and 0 <= perm <= 7, "mount_metadata")
        previous = tag
        if tag in named:
            require(0 <= identity < LINUX_ID_LIMIT and identity not in named[tag], "mount_metadata")
            named[tag].add(identity)
        else:
            require(identity == LINUX_ID_LIMIT and tag not in singles, "mount_metadata")
            singles[tag] = perm
    require({1, 4, 32} <= singles.keys() and (not any(named.values()) or 16 in singles), "mount_metadata")
    require(mode & 0o777 == (singles[1] << 6) | (singles.get(16, singles[4]) << 3) | singles[32], "mount_metadata")
    mask = singles.get(16, 7)
    return any(perm & (7 if tag == 32 else mask) & 2 and (
        tag == 32 or tag == 2 and identity not in (0, owner_uid) or
        tag in (4, 8) and (row["gid"] if tag == 4 else identity) not in private_gids)
        for tag, perm, identity in acl)


def inside_alias(child, parent, identities):
    """Directional containment, including aliases above confirmed missing tails."""
    if inside(child, parent):
        return True
    ancestors = {}
    for b in (parent, *parent.parents):
        identity = identities.get(str(b))
        if identity is not None:
            ancestors.setdefault(identity, []).append(b)
    for a in (child, *child.parents):
        identity = identities.get(str(a))
        for b in ancestors.get(identity, ()):
            if a != b and inside(child.relative_to(a), parent.relative_to(b)):
                return True
    return False


def aliases_overlap(left, right, identities):
    return inside_alias(left, right, identities) or inside_alias(right, left, identities)


def secret_names():
    """Default exclusions for standalone mount APIs that predate injected Teams policy."""
    table = {kind: team_host_registry.entry(kind) for kind in team_host_registry.TEAM_HOSTS}
    return host_policy(table).protected_names


def credential_names(protected_names=None):
    """Require the complete baseline and bounded single-component additions."""
    if protected_names is None:
        return secret_names()
    limit = len(SECRET_NAMES) + 64
    require(type(protected_names) in (set, frozenset) and len(protected_names) <= limit, "mount_metadata")
    names = frozenset(protected_names)
    require(len(names) <= limit and SECRET_NAMES <= names
            and all(_credential_name(name) for name in names), "mount_metadata")
    return names


def link_target(value):
    """Bound readlink data without imposing the supplied mount-path grammar."""
    require(type(value) is str and 0 < len(value) <= 4096 and value.count("/") <= 128, "unsafe_mount")
    require("\\" not in value and not any(
        ord(ch) < 32 or 127 <= ord(ch) <= 159 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value), "unsafe_mount")
    return value


def resolved_path(path, observed):
    """Resolve components in order, charging every logical link follow to this call."""
    root = Path("/")
    root_info = metadata(root, observed)
    require("target" not in root_info, "mount_metadata")
    known, followed = {str(root): root_info}, 0

    def walk(base, info, parts):
        nonlocal followed
        for part in parts:
            # Even an empty or dotted component must traverse a directory.
            require(info is None or stat.S_ISDIR(info["mode"]), "unsafe_mount")
            if part in ("", ".", ".."):
                if part == "..":
                    base = base.parent
                    info = known[str(base)]
                continue
            require(len(str(base).rstrip("/")) + len(part) + 1 <= 4096
                    and len(base.parts) <= 128, "unsafe_mount")
            candidate = base / part
            entry = (metadata(candidate, observed, directory=False, allow_absence=True)
                     if info is not None or str(candidate) in observed else None)
            require(info is not None or entry is None, "mount_metadata")
            if entry is not None and stat.S_ISLNK(entry["mode"]):
                require(followed < 40, "mount_metadata")
                followed += 1
                target = link_target(entry.get("target"))
                absolute = target.startswith("/")
                base, info = walk(root if absolute else base, root_info if absolute else info,
                                  target.split("/")[1:] if absolute else target.split("/"))
            else:
                require(entry is None or "target" not in entry, "mount_metadata")
                base, info = candidate, entry
                known[str(base)] = info
        return base, info

    return walk(root, root_info, str(path).split("/")[1:])[0]


def path_identities(path, observed, identities, *, owner_uid=None, private_gids=()):
    """Check existing ancestors; a confirmed absent prefix implies an absent tail."""
    absent, info = False, None
    chain = tuple(reversed((path, *path.parents)))
    for index, component in enumerate(chain):
        if absent and str(component) not in observed:
            continue
        info = metadata(component, observed, directory=False, allow_absence=True)
        if info is None:
            absent = True
            continue
        require(not absent, "mount_metadata")
        require(not stat.S_ISLNK(info["mode"]) and (component == path or stat.S_ISDIR(info["mode"])), "unsafe_mount")
        require("target" not in info, "mount_metadata")
        identities[str(component)] = (info["device"], info["inode"])
        if owner_uid is not None:
            require(info["uid"] in (0, owner_uid), "unsafe_mount")
            if foreign_write(info, owner_uid, private_gids) and index + 1 < len(chain):
                child = metadata(chain[index + 1], observed, directory=False, allow_absence=True)
                require(info["mode"] & stat.S_ISVTX and child is not None and child["uid"] in (0, owner_uid), "unsafe_mount")
    return None if absent else info


def validated_owner_homes(home, owner_homes):
    bounded_value(owner_homes)
    roles = ("explicit", "ambient", "password")
    require(type(owner_homes) is dict and owner_homes.keys() == set(roles)
            and all(type(owner_homes[key]) is str and owner_homes[key] for key in roles), "owner_homes")
    owners = tuple(absolute_path(owner_homes[key]) for key in roles)
    require(owners[0] == absolute_path(home), "owner_homes")
    return owners


def protected_roots(owners, observed, identities, *, protected_names=None):
    """Preserve legacy home/local containment and symmetric secret exclusion."""
    names = credential_names(protected_names)
    roots = []
    for supplied in owners:
        owner = resolved_path(supplied, observed)
        info = path_identities(owner, observed, identities)
        roots.append((owner, "home"))
        if info is None or not stat.S_ISDIR(info["mode"]):
            continue
        for name in sorted(names | {".local"}):
            path = owner / name
            entry = metadata(path, observed, directory=False, allow_absence=True)
            if entry is None:
                continue
            target = resolved_path(path, observed)
            path_identities(target, observed, identities)
            roots.append((target, "local" if name == ".local" else "secret"))
    return roots


def validate_mounts(mounts, *, home, observed, owner_uid, private_gids=(), owner_homes=None,
                    protected_names=None):
    bounded_value(observed)
    require(type(observed) is dict, "mount_metadata")
    require(type(owner_uid) is int and 0 <= owner_uid < LINUX_ID_LIMIT, "mount_metadata")
    require(type(private_gids) in (tuple, list) and len(private_gids) <= 128
            and all(type(g) is int and 0 <= g < LINUX_ID_LIMIT for g in private_gids), "mount_metadata")
    owners = validated_owner_homes(home, owner_homes)
    rows = mount_rows(mounts)
    checked = {}
    protected = protected_roots(owners, observed, checked, protected_names=protected_names)
    for row in rows:
        path = Path(row["source"])
        require(path.name != ".local" or all(path.parent != root for root, kind in protected if kind == "home"),
                "unsafe_mount")  # The image's HOME/.local root stays reserved even when absent.
        path_identities(path, observed, checked, owner_uid=owner_uid, private_gids=private_gids)
        for root, kind in protected:
            unsafe = aliases_overlap(path, root, checked) if kind == "secret" else inside_alias(root, path, checked)
            require(not unsafe, "unsafe_mount")
    # Bind aliases share an ancestor identity. Compare the remaining suffixes,
    # including missing lexical relationships, across both access domains.
    for index, row in enumerate(rows):
        for other in rows[index + 1:]:
            left, right = Path(row["source"]), Path(other["source"])
            if row["rw"] == other["rw"]:
                continue
            require(not aliases_overlap(left, right, checked), "mount_overlap")
    return rows


def mount_plan(*, run, project, source, python_prefix, live_checkouts=(), home, observed, owner_uid,
               private_gids=(), owner_homes=None, protected_names=None):
    bounded_value(live_checkouts)
    require(type(live_checkouts) in (list, tuple) and len(live_checkouts) <= 124, "mount_rows")
    requested = [(run, True), (project, True), (source, False), (python_prefix, False)]
    requested.extend((path, False) for path in live_checkouts)
    rows = {(str(absolute_path(path)), rw) for path, rw in requested}
    require(len({path for path, _ in rows}) == len(rows), "mount_overlap")
    return validate_mounts([dict(source=p, destination=p, rw=rw) for p, rw in sorted(rows)],
                           home=home, observed=observed, owner_uid=owner_uid, private_gids=private_gids,
                           owner_homes=owner_homes, protected_names=protected_names)
