"""CLI boundaries for read-only team isolation plans and engine verification."""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import stat
import struct
import subprocess
import sys
import time
import unicodedata

from aegis_core import team_host_registry, team_isolation as core, team_isolation_mounts as mounts
from aegis_core.diagnostic_messages import receipt_value
from aegis_core.pathlookup import which
from aegis_core.storage_confined import ConfinedFileError, confined_file, descriptor_supported as file_support
from aegis_core.team_isolation_refusal import IsolationRefusal

__all__ = ["configure_parser", "descriptor_supported", "inspect_image", "observe", "owner_homes", "run_isolation"]

# Keep held descriptors and resulting metadata within the pure core's node and byte budgets.
_MAX_OBSERVED = 512
_MAX_ACL_BYTES = 4 + 8 * 1024
_INSPECT_SECONDS = 30


def descriptor_supported():
    return (mounts.container_supported(sys.platform) and file_support() and hasattr(os, "O_PATH")
            and hasattr(os, "getxattr") and {os.stat, os.readlink} <= os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks)


def _read_document(value):
    mounts.require(file_support(), "unsupported_platform")
    try:
        path = mounts.absolute_path(value)
        with confined_file("/", path.parts[1:]) as handle:
            return handle.read_bytes(mounts.MAX_DOCUMENT_BYTES)
    except IsolationRefusal:
        raise IsolationRefusal("document_read") from None
    except ConfinedFileError as error:
        code = {"too_large": "document_size", "unsupported": "unsupported_platform"}.get(
            error.reason, "document_read")
        raise IsolationRefusal(code) from None


def _read_config(path):
    config = mounts.load_document(_read_document(path))
    mounts.require(type(config) is dict, "document_invalid")
    # These legacy home aliases do not change the container's run homes.
    config.pop("codex_home", None)
    config.pop("claude_home", None)
    return config


def _identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _acl(fd):
    try:
        # O_PATH samples without opening devices or file contents. The proc fd
        # link is kernel-generated and refers to this held inode across renames.
        raw = os.getxattr("/proc/self/fd/" + str(fd), "system.posix_acl_access")
    except OSError as error:
        if error.errno == errno.ENODATA:
            return None
        raise IsolationRefusal("mount_metadata") from None
    mounts.require(28 <= len(raw) <= _MAX_ACL_BYTES and (len(raw) - 4) % 8 == 0, "mount_metadata")
    mounts.require(struct.unpack_from("<I", raw)[0] == 2, "mount_metadata")
    return memoryview(raw)[4:]


class _Observations:
    def __init__(self, stack, *, sample_metadata=True):
        self.stack = stack
        self.sample_metadata = sample_metadata
        self.entries = {}
        self.nodes = 0
        self.used_bytes = 0
        self.add("/", None, "/")

    def add(self, path, parent, name):
        if path in self.entries:
            return self.entries[path]
        self.used_bytes += 2 * len(path.encode("utf-8"))
        mounts.require(len(self.entries) < _MAX_OBSERVED and self.used_bytes <= mounts.MAX_DOCUMENT_BYTES,
                       "document_size")
        fd = None
        try:
            fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            mounts.require(parent is not None, "mount_metadata")
        if fd is None:
            info, row = None, None
        else:
            self.stack.callback(os.close, fd)
            info = os.fstat(fd)
            row = self.sample(fd, info, charge=True) if self.sample_metadata else None
        result = (fd, parent, name, info, row)
        self.entries[path] = result
        return result

    def sample(self, fd, info, *, charge):
        acl = None if stat.S_ISLNK(info.st_mode) else _acl(fd)
        if charge:
            self.nodes += 36 + (len(acl) if acl is not None else 0)
            mounts.require(self.nodes <= 32768, "document_size")
        row = dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid, gid=info.st_gid,
                   mode=info.st_mode, acl=[list(entry) for entry in struct.iter_unpack("<HHI", acl)]
                   if acl is not None else None)
        if stat.S_ISLNK(info.st_mode):
            row["target"] = mounts.link_target(os.readlink("", dir_fd=fd))
            if charge:
                self.used_bytes += 2 * len(row["target"].encode("utf-8"))
                mounts.require(self.used_bytes <= mounts.MAX_DOCUMENT_BYTES, "document_size")
        return row

    def walk(self, value, *, follow=False, allow_leaf_link=False):
        path = mounts.absolute_path(value)
        parts = list(path.parts[1:][::-1])
        current, links = "/", 0
        while parts:
            part = parts.pop()
            fd, _, _, info, _ = self.entries.get(current, (None,) * 5)
            mounts.require(info is None or stat.S_ISDIR(info.st_mode), "unsafe_mount")
            if part in ("", ".", ".."):
                if part == "..":
                    current = str(PurePosixPath(current).parent)
                continue
            mounts.require(len(current.rstrip("/")) + len(part) + 1 <= 4096
                           and current.count("/") <= 128, "unsafe_mount")
            candidate = current.rstrip("/") + "/" + part
            if fd is None:
                current = candidate
                continue
            _, _, _, child, row = self.add(candidate, fd, part)
            if child is not None and stat.S_ISLNK(child.st_mode):
                if allow_leaf_link and not parts:
                    return candidate, False
                mounts.require(follow, "unsafe_mount")
                links += 1
                mounts.require(links <= 40, "mount_metadata")
                target = row["target"]
                if target.startswith("/"):
                    current = "/"
                parts.extend(reversed(target.split("/")))
            else:
                current = candidate
        _, _, _, info, _ = self.entries.get(current, (None,) * 5)
        return current, info is not None and stat.S_ISDIR(info.st_mode)

    def finish(self):
        observed = {}
        for path, (fd, parent, name, before, row) in self.entries.items():
            try:
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                named = None
            if fd is None:
                mounts.require(named is None, "mount_changed")
                observed[path] = None
                continue
            info = os.fstat(fd)
            mounts.require(named is not None and _identity(named) == _identity(info) == _identity(before),
                           "mount_changed")
            after = self.sample(fd, info, charge=False)
            mounts.require(row == after and _identity(os.fstat(fd)) == _identity(info), "mount_changed")
            observed[path] = dict(row, after=after)
        return observed


def observe(paths, homes, *, marker, protected_names=None):
    """Take paired samples while each component remains attached to a held descriptor."""
    mounts.require(descriptor_supported(), "unsupported_platform")
    protected_names = mounts.credential_names(protected_names)
    try:
        with ExitStack() as stack:
            reader = _Observations(stack)
            for supplied in homes:
                home, exists = reader.walk(supplied, follow=True)
                if exists:
                    for name in sorted(protected_names | {".local"}):
                        reader.walk(home.rstrip("/") + "/" + name, follow=True)
            for path in paths:
                reader.walk(path)
            if marker is not None:
                reader.walk(marker, allow_leaf_link=True)
            return reader.finish()
    except (OSError, UnicodeError):
        raise IsolationRefusal("mount_metadata") from None


def owner_homes():
    import pwd

    try:
        home = str(Path.home())
        return dict(explicit=home, ambient=home, password=pwd.getpwuid(os.geteuid()).pw_dir)
    except (KeyError, RuntimeError, OSError):
        raise IsolationRefusal("owner_homes") from None


def _private_groups(observed):
    import grp
    import pwd

    try:
        owner = pwd.getpwuid(os.geteuid())
        gid = owner.pw_gid
        if not any(row is not None and row["gid"] == gid and row["mode"] & 0o020
                   for row in observed.values()):
            return ()
        group = grp.getgrgid(gid)
        if (group.gr_name == owner.pw_name and all(member == owner.pw_name for member in group.gr_mem)
                and not any(entry.pw_name != owner.pw_name and entry.pw_gid == gid for entry in pwd.getpwall())):
            return (gid,)
    except (KeyError, OSError):
        pass  # Unavailable account evidence grants no private-group exemption.
    return ()


def _time_left(deadline):
    remaining = deadline - time.monotonic()
    mounts.require(remaining > 0, "image_inspect_timeout")
    return remaining


def _read_image_output(stream, deadline):
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        data = bytearray()
        while True:
            mounts.require(bool(selector.select(_time_left(deadline))), "image_inspect_timeout")
            chunk = os.read(stream.fileno(), min(8192, mounts.MAX_DOCUMENT_BYTES + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            mounts.require(len(data) <= mounts.MAX_DOCUMENT_BYTES, "document_size")


def _pin_engine(executable, stack):
    """Hold the approved inode across launch and qualify each directory before descending."""
    mounts.require(descriptor_supported(), "unsupported_platform")
    try:
        path = mounts.absolute_path(executable)
        uid = os.geteuid()
        reader = _Observations(stack, sample_metadata=False)
        fd, _, _, info, _ = reader.entries["/"]
        current = PurePosixPath("/")
        for component in path.parts[1:]:
            mounts.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid)
                           and not info.st_mode & 0o022, "engine_custody")
            current = current / component
            fd, _, _, info, _ = reader.add(str(current), fd, component)
            mounts.require(info is not None, "engine_custody")
        mounts.require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, uid)
                       and not info.st_mode & 0o022 and info.st_mode & 0o111, "engine_custody")
        return fd
    except (IsolationRefusal, OSError, UnicodeError):
        raise IsolationRefusal("engine_custody") from None


def inspect_image(argv, *, workspace, search_path=None):
    mounts.require(type(argv) is list and len(argv) == 4 and argv[1:3] == ["image", "inspect"],
                   "image_inspect")
    argv = core.image_inspect_argv(argv[0], mounts.image(argv[3]))
    deadline = time.monotonic() + _INSPECT_SECONDS
    try:
        executable = which(argv[0], path=search_path, outside=workspace, fence_program=True)
        mounts.require(executable is not None, "image_inspect")
        with ExitStack() as stack:
            fd = _pin_engine(executable, stack)
            process = stack.enter_context(subprocess.Popen(
                [executable, *argv[1:]], executable="/proc/self/fd/" + str(fd), pass_fds=(fd,), cwd="/",
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL))
            try:
                raw = _read_image_output(process.stdout, deadline)
                mounts.require(process.wait(timeout=_time_left(deadline)) == 0, "image_inspect")
                return raw
            finally:
                if process.poll() is None:
                    process.kill()
    except subprocess.TimeoutExpired:
        raise IsolationRefusal("image_inspect_timeout") from None
    except OSError:
        raise IsolationRefusal("image_inspect") from None


def _refusal(error):
    return dict(status=error.status, code=error.code, reason=error.message, next_action=error.next_action)


def _display_field(value):
    # Normalization can reveal or erase a credential match. Check both views
    # before preserving the original spelling, and truncate only after redaction.
    for spelling in (value, unicodedata.normalize("NFKC", value)):
        projected = receipt_value(spelling, limit=max(4096, len(spelling)), identifier=True)
        if projected != spelling:
            return "[REDACTED]"
    return value[:4096]


def _display(value):
    if type(value) is str:
        return _display_field(value)
    if type(value) is dict:
        return {_display(key): _display(item) for key, item in value.items()}
    if type(value) is list:
        return [_display(item) for item in value]
    return value


def _emit(args, value):
    original_argv = value.get("create_argv")
    value = _display(value)
    if original_argv != value.get("create_argv"):
        value["create_argv_display_only"] = True
    if args.json:
        print(json.dumps(value, sort_keys=True, ensure_ascii=True))
    elif value["status"] == "refused":
        print(value["code"] + " — " + value["reason"], file=sys.stderr)
    elif "mismatches" in value:
        print("Isolation verified" if not value["mismatches"] else
              "Isolation mismatches: " + ", ".join(value["mismatches"]))
    else:
        print("Isolation plan (" + value["mode"] + ")")
        if value["create_argv"] is not None:
            print(json.dumps(value, sort_keys=True, ensure_ascii=True))


def run_isolation(args):
    try:
        config = _read_config(args.config)
        value = core.check(config, observer=observe, owner_homes=owner_homes,
                           owner_identity=lambda: (os.geteuid(), os.getegid()), cpu_count=os.cpu_count,
                           platform=sys.platform, host_table=lambda: {kind: team_host_registry.entry(kind)
                                                                      for kind in team_host_registry.TEAM_HOSTS},
                           source=str(Path(__file__).absolute().parents[1]), private_groups=_private_groups,
                           inspect=(lambda: _read_document(args.inspect)) if args.inspect is not None else None,
                           inspector=lambda argv: inspect_image(argv, workspace=args.workspace))
    except IsolationRefusal as error:
        value = _refusal(error)
    _emit(args, value)
    return 0 if value["status"] == "ok" else 1


def configure_parser(sub, common, parent):
    class IsolationParser(type(parent)):
        def error(self, message):
            refusal = IsolationRefusal("invalid_arguments")
            self._print_message(json.dumps(_refusal(refusal), sort_keys=True) + "\n", sys.stderr)
            self.exit(refusal.exit_code)

        def parse_known_args(self, args=None, namespace=None):
            values, extras = super().parse_known_args(args, namespace)
            if extras:
                self.error("")
            return values, extras

    factory = sub._parser_class
    sub._parser_class = IsolationParser
    try:
        parser = sub.add_parser("isolation", parents=[common], allow_abbrev=False,
                                help="Plan or verify team container isolation")
    finally:
        sub._parser_class = factory
    verbs = parser.add_subparsers(dest="isolation_action", required=True)
    check = verbs.add_parser("check", parents=[common], allow_abbrev=False,
                             help="Read an isolation plan or check engine inspection data")
    check.add_argument("--config", required=True, help="Absolute path to a bounded team-run.json")
    check.add_argument("--inspect", help="Absolute path to bounded container inspection JSON")
