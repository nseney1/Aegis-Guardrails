"""Build and verify an isolated manager runtime from a reviewed Git commit."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import site as python_site
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import time
import uuid
import zipfile
import zlib

from aegis_core import gitsafe, pathlookup, team_git
from aegis_core.config import manager_registration_env
from aegis_core.guidance_projection import project_diagnostic
from aegis_core.primitives import json_preflight, strict_loads
from aegis_core.storage_confined import ConfinedFileError, confined_file, open_directory
from aegis_core.storage_confined import descriptor_supported as confined_storage_supported
from aegis_core.team_jobs_source import JobSource, JobSourceRefusal
from aegis_core.workspace.git_objects import object_id

__all__ = ["RuntimeRefusal", "build_pin", "descriptor_supported", "verify_pin", "main"]

_SCHEMA = "aegis.manager-runtime/v1"
_MANIFEST = "pin.json"
_JSON_LIMIT = 128 * 1024
_ARTIFACT_LIMIT = 64 * 1024 * 1024
_MEMBER_LIMIT = 16 * 1024 * 1024
_INSTALL_LIMIT = 128 * 1024 * 1024
_ENTRY_LIMIT = 8192
_PATH_LIMIT = 4096
_CHUNK = 64 * 1024
_TREE_LIMIT = 8 * 1024 * 1024
_PROCESS_TIMEOUT = 180
_OID = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
_DIGEST = r"[0-9a-f]{64}"
_GENERATION = r"[0-9a-f]{32}"
_WHEEL = r"aegis_guardrails-[A-Za-z0-9_.+-]+-none-any\.whl"
_SDIST = r"aegis[-_]guardrails-[A-Za-z0-9_.+-]+\.tar\.gz"
_SITE = r"lib(?:64)?/python3\.[0-9]{1,2}/site-packages"
_PACKAGES = frozenset(("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"))
_ORIGIN_FILES = (("aegis_core", "__init__.py"), ("aegis_cli", "__init__.py"),
                 ("aegis_mcp", "__init__.py"), ("aegis_mcp", "manager.py"),
                 ("aegis_mcp", "server.py"), ("aegis_sdk", "__init__.py"))
_TOOLS = ["aegis_list_rules", "aegis_report_outcome", "aegis_scan"]
_SERVER = "aegis-manager-mcp"
_ACTIONS = {
    "invalid_input": "Supply a full reviewed Git commit and distinct absolute paths as documented.",
    "unsupported_platform": "Use a host with descriptor-relative no-follow file and directory operations.",
    "unsafe_root": "Use existing physical roots and owner-private artifact and output directories.",
    "source_changed": "Restore the clean reviewed checkout and its local Git objects before retrying.",
    "build_backend_unavailable": "Provision pip, setuptools, wheel and packaging in the offline build Python.",
    "build_failed": "Check the reviewed project's setuptools build requirements and offline environment.",
    "artifact_mismatch": "Restore both exact artifacts from the verified generation or rebuild the pin.",
    "invalid_manifest": "Restore the owner-custodied pin manifest or build a new pin.",
    "wrong_interpreter": "Select the generation's installed Python or rebuild the dedicated runtime.",
    "install_failed": "Check that the offline builder can create a venv and install its pure wheel.",
    "install_mismatch": "Restore the exact installed package files or rebuild the dedicated runtime.",
    "smoke_failed": "Check that the pinned distribution supports the manager stdio tool list.",
    "runtime_io": "Check the owner-controlled roots, storage permissions and free space, then retry.",
    "publication_uncertain": "Read back the current pin and check storage durability before retrying.",
}
_BUILD = """
import sys
from setuptools import build_meta
from setuptools.config.pyprojecttoml import load_file
config = load_file("pyproject.toml").get("build-system", {})
if config.get("build-backend") != "setuptools.build_meta" or config.get("backend-path"):
    raise SystemExit(1)
requirements = config.get("requires", [])
from packaging.requirements import Requirement
from importlib.metadata import version
for spec in requirements:
    req = Requirement(spec)
    if req.url or req.extras:
        raise SystemExit(1)
    if (req.marker is None or req.marker.evaluate()) and not req.specifier.contains(
            version(req.name), prereleases=True):
        raise SystemExit(1)
destination = sys.argv[1]
build_meta.build_sdist(destination)
build_meta.build_wheel(destination)
"""
_STARTUP = """
import sys
base, prefix, zip_path, stdlib, dynload = sys.argv[1:6]
if (sys.executable != base or sys._base_executable != base
        or (sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix) != (prefix,) * 4
        or sys.path != [zip_path, stdlib, dynload]):
    raise SystemExit(1)
del sys.argv[1:6]
"""
_BUILDER_BOOT = """
import json
import runpy
sys.path.extend(json.loads(sys.argv.pop(1)))
mode, command = sys.argv[1:3]
del sys.argv[:2]
if mode == "module":
    runpy.run_module(command, run_name="__main__", alter_sys=True)
else:
    exec(compile(command, "<offline-python>", "exec"), {"__name__": "__main__"})
"""
_IMPORT_PROBE = """
from importlib import import_module
import json
import sys
sys.path.append(sys.argv.pop(1))
print(json.dumps({name: import_module(name).__file__ for name in sys.argv[1:]}))
"""
_MCP_BOOT = 'import runpy, sys; sys.path.append(sys.argv.pop(1)); runpy.run_module("aegis_mcp", run_name="__main__")'
class RuntimeRefusal(ValueError):
    """Stable refusal for callers of the public build and verify functions."""

    def __init__(self, reason):
        self.reason = reason
        self.next_action = _ACTIONS[reason]
        super().__init__(reason)

    def as_dict(self):
        return {"status": "refused", "reason": self.reason, "code": 1, "next_action": self.next_action}
def _require(condition, reason):
    if not condition:
        raise RuntimeRefusal(reason)
def _matches(value, pattern, limit=255):
    return type(value) is str and len(value) <= limit and re.fullmatch(pattern, value) is not None
def _displayable(text):
    return (0 < len(text) <= _PATH_LIMIT and text.isprintable()
            and project_diagnostic(text, escaped=False, max_len=_PATH_LIMIT) == text)
def _path(value, reason="invalid_input"):
    _require(isinstance(value, (str, Path)), reason)
    name = str(value)
    _require(_displayable(name), reason)
    path = Path(name)
    _require(path.is_absolute() and str(path) == name and ".." not in path.parts, reason)
    return path
def _private(info):
    _require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "unsafe_root")
def _directory(name, _anchor_flags=None, *, dir_fd):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
def descriptor_supported():
    """Whether the host can provide the required confined runtime operations."""
    return (sys.platform == "linux" and confined_storage_supported()
            and os.path.isdir("/proc/self/fd"))
@contextmanager
def _roots(source, artifact_root, output_root, commit):
    _require(descriptor_supported(), "unsupported_platform")
    paths = tuple(map(_path, (source, artifact_root, output_root)))
    _require(_matches(commit, _OID) and all(
        left != right and left not in right.parents and right not in left.parents
        for index, left in enumerate(paths) for right in paths[index + 1:]
    ), "invalid_input")
    try:
        with ExitStack() as stack:
            roots = []
            for index, path in enumerate(paths):
                try:
                    roots.append(stack.enter_context(open_directory(
                        _directory, path, policy=_private if index else None, retain_ancestors=True)))
                except ConfinedFileError:
                    raise RuntimeRefusal("unsafe_root") from None
            yield paths, roots
    except RuntimeRefusal:
        raise
    except (ConfinedFileError, OSError, ValueError):
        raise RuntimeRefusal("runtime_io") from None
def _read(root, parts, limit, reason):
    try:
        with confined_file(root, parts) as file:
            return file.read_bytes(limit)
    except ConfinedFileError:
        raise RuntimeRefusal(reason) from None
def _json(raw, reason):
    try:
        text = json_preflight(raw, max_bytes=_JSON_LIMIT, max_depth=12, max_nodes=4096,
                              max_items=512, max_string=_PATH_LIMIT, max_atom=128)
        return strict_loads(text)
    except ValueError:
        raise RuntimeRefusal(reason) from None
def _git_read(checkout, argv, env, *, timeout, limit, stdin):
    result = gitsafe.run(argv, checkout, timeout=timeout, stdin=stdin)
    return result.returncode, result.stdout
def _source(source, commit, scratch):
    try:
        env = team_git.object_read_env()
        with gitsafe.custody(scratch=scratch, env=env, stdout_limit=256, replace_env=True):
            probe = gitsafe.run(team_git.object_read_argv("rev-parse", "--show-prefix"), source, timeout=15)
        _require(probe.returncode == 0 and probe.stdout == b"\n", "source_changed")
        program = probe.args[0]
        tree, entries = _source_objects(source, commit, scratch, env, program)
        _source_index(source, commit, entries, scratch, env, program)
        _source_bytes(source, entries)
        _source_index(source, commit, entries, scratch, env, program)
        reader = JobSource(run=_git_read, object_read_argv=team_git.object_read_argv,
                           object_read_env=team_git.object_read_env, child_environment=lambda env, _: env,
                           program=program)
        return reader, {"commit": commit, "tree": tree}, entries
    except (gitsafe.GitError, team_git.GitRefusal, JobSourceRefusal, ConfinedFileError, OSError, UnicodeError):
        raise RuntimeRefusal("source_changed") from None
def _git_source(source, args, scratch, env, program, limit):
    with gitsafe.custody(scratch=scratch, env=env, stdout_limit=limit, replace_env=True, program=program):
        return gitsafe.run_checked(team_git.object_read_argv(*args), source, timeout=15).stdout
def _source_rows(raw):
    _require(raw.count(b"\0") <= _ENTRY_LIMIT and (not raw or raw.endswith(b"\0")), "source_changed")
    for row in raw[:-1].split(b"\0") if raw else ():
        header, tab, name = row.partition(b"\t")
        _require(tab and len(header) <= 80 and len(name) <= _PATH_LIMIT, "source_changed")
        raw_parts = name.split(b"/")
        _require(0 < len(raw_parts) <= 128 and all(0 < len(part) <= 255
                 and part.lower() not in (b".", b"..", b".git") and b"\\" not in part
                 for part in raw_parts), "source_changed")
        yield header.split(b" "), tuple(part.decode("utf-8") for part in raw_parts)
def _source_objects(source, commit, scratch, env, program):
    with gitsafe.custody(scratch=scratch, env=env, stdout_limit=_TREE_LIMIT, replace_env=True, program=program):
        payload = gitsafe.read_blobs(source, [commit], kind="commit", timeout=15).get(commit)
    _require(payload and payload.startswith(b"tree "), "source_changed")
    tree = payload[5:6 + len(commit)]
    _require(tree.endswith(b"\n") and _matches(tree[:-1].decode("ascii"), _OID), "source_changed")
    tree = tree[:-1].decode("ascii")
    raw = _git_source(source, ("ls-tree", "-r", "-t", "-z", "--full-tree", tree), scratch, env, program, _TREE_LIMIT)
    return tree, _authenticate_tree(raw, tree, len(commit))
def _authenticate_tree(raw, tree, oid_len):
    groups, directories, entries = {(): bytearray()}, {(): tree}, {}
    for header, parts in _source_rows(raw):
        _require(len(header) == 3, "source_changed")
        mode, kind, value = header
        oid = value.decode("ascii")
        _require(len(oid) == oid_len and _matches(oid, _OID) and parts[:-1] in groups
                 and parts not in directories and parts not in entries, "source_changed")
        if mode == b"040000" and kind == b"tree":
            directories[parts], groups[parts] = oid, bytearray()
            mode = b"40000"
        else:
            _require(kind == b"blob" and mode in (b"100644", b"100755", b"120000"), "source_changed")
            entries[parts] = mode, oid
        parent = groups[parts[:-1]]
        parent.extend(mode + b" " + parts[-1].encode("utf-8") + b"\0" + bytes.fromhex(oid))
    _require(all(data and object_id(data, oid_len, "tree") == directories[parts]
                 for parts, data in groups.items()), "source_changed")
    return entries
def _source_index(source, commit, entries, scratch, env, program):
    head = _git_source(source, ("rev-parse", "--verify", "HEAD"), scratch, env, program, 256)
    _require(head == commit.encode("ascii") + b"\n", "source_changed")
    # Index listing and raw file hashing do not invoke repository clean filters.
    raw = _git_source(source, ("ls-files", "--stage", "--full-name", "-z"), scratch, env, program, _TREE_LIMIT)
    staged = {}
    for header, parts in _source_rows(raw):
        _require(len(header) == 3 and header[2] == b"0" and parts not in staged, "source_changed")
        staged[parts] = header[0], header[1].decode("ascii")
    _require(staged == entries, "source_changed")
    _git_source(source, ("ls-files", "--others", "--exclude-standard", "-z"), scratch, env, program, 0)
def _source_bytes(root, entries):
    left = _INSTALL_LIMIT
    for parts, (mode, oid) in entries.items():
        with confined_file(root, parts) as file:
            fd, name = file.parent_fd, parts[-1]
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            limit = min(left, _MEMBER_LIMIT)
            _require(before.st_size <= limit, "source_changed")
            if mode == b"120000":
                _require(stat.S_ISLNK(before.st_mode), "source_changed")
                data = os.fsencode(os.readlink(name, dir_fd=fd))
            else:
                actual = b"100755" if before.st_mode & stat.S_IXUSR else b"100644"
                _require(stat.S_ISREG(before.st_mode) and actual == mode, "source_changed")
                data = file.read_bytes(limit)
            after = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _require(_file_state(before) == _file_state(after)
                     and len(data) <= limit and object_id(data, len(oid)) == oid, "source_changed")
            left -= len(data)
def _sha(raw):
    return hashlib.sha256(raw).hexdigest()
def _environment(scratch):
    return {"HOME": str(scratch), "TMPDIR": str(scratch), "PATH": os.defpath, "LC_ALL": "C",
            "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
def _collect(stream, deadline, reason):
    output = bytearray()
    with selectors.DefaultSelector() as reader:
        reader.register(stream, selectors.EVENT_READ)
        while True:
            _require(reader.select(max(0, deadline - time.monotonic())), reason)
            item = os.read(stream.fileno(), min(_CHUNK, _JSON_LIMIT - len(output) + 1))
            if not item:
                return bytes(output)
            _require(len(item) + len(output) <= _JSON_LIMIT, reason)
            output.extend(item)
def _run(launch, args, *, cwd, env, reason, stdin=None, capture=False):
    # The caller's fixed stdio requests fit within an atomic pipe write.
    _require(stdin is None or len(stdin) <= 512, reason)
    deadline = time.monotonic() + _PROCESS_TIMEOUT
    try:
        with launch.open() as fd, subprocess.Popen(
            launch.base.command(args[1], *args[2:]),
            executable=f"/proc/self/fd/{fd}", pass_fds=(fd,), cwd=cwd, env=env,
            stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        ) as process:
            try:
                if stdin is not None:
                    process.stdin.write(stdin)
                    process.stdin.close()
                raw = _collect(process.stdout, deadline, reason) if capture else b""
                _require(process.wait(timeout=max(0, deadline - time.monotonic())) == 0, reason)
                return raw
            except (RuntimeRefusal, OSError, subprocess.TimeoutExpired):
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                raise RuntimeRefusal(reason) from None
    except OSError:
        raise RuntimeRefusal(reason) from None
def _file_state(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns
def _fd_hash(fd, reason):
    before = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    left = before.st_size
    _require(0 < left <= _ARTIFACT_LIMIT, reason)
    digest = hashlib.sha256()
    while left:
        chunk = os.read(fd, min(left, _CHUNK))
        _require(chunk, reason)
        digest.update(chunk)
        left -= len(chunk)
    _require(not os.read(fd, 1) and _file_state(os.fstat(fd)) == _file_state(before), reason)
    return digest.hexdigest()
@contextmanager
def _open_python(physical, reason):
    try:
        with open_directory(_directory, physical.parent, retain_ancestors=True) as parent:
            fd = os.open(physical.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
            try:
                info = os.fstat(fd)
                _require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111, reason)
                stamp = _file_state(info), _fd_hash(fd, reason)
                locator = f"/proc/self/fd/{fd}"
                _require(os.access(locator, os.X_OK) and os.path.samestat(os.stat(locator), info),
                         "unsupported_platform")
                _named_python(parent, physical.name, stamp[0], reason)
                try:
                    yield fd, stamp
                finally:
                    _named_python(parent, physical.name, stamp[0], reason)
                    _require(_fd_hash(fd, reason) == stamp[1], reason)
            finally:
                os.close(fd)
    except (OSError, ConfinedFileError):
        raise RuntimeRefusal(reason) from None
def _named_python(parent, name, expected, reason):
    parent.check()
    _require(_file_state(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)) == expected, reason)
def _outside(path, excluded, reason, *, optional=False):
    try:
        physical = path.resolve(strict=not optional)
    except (OSError, RuntimeError):
        raise RuntimeRefusal(reason) from None
    _require(all(root != item and root not in item.parents
                 for root in excluded for item in (path, physical)), reason)
    return physical
def _outside_program(path, excluded, reason):
    _require(all(pathlookup.fenced_program(str(path), root) is not None for root in excluded), reason)
    return _outside(path, excluded, reason)
def _entry(path, reason, *, read_link=False):
    try:
        with open_directory(_directory, path.parent, retain_ancestors=True) as parent:
            try:
                info = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                info = None
            if read_link and info and stat.S_ISLNK(info.st_mode):
                info = os.readlink(path.name, dir_fd=parent.fd)
            parent.check()
            return info
    except ConfinedFileError as error:
        if error.reason == "missing":
            return None
        raise RuntimeRefusal(reason) from None
    except OSError:
        raise RuntimeRefusal(reason) from None
def _config_fields(raw, reason):
    try:
        fields = {}
        for line in raw.decode("utf-8").splitlines():
            key, separator, value = line.partition(" = ")
            _require(separator and _matches(key, r"[a-z][a-z0-9_-]+", 64) and key not in fields
                     and value.isprintable() and value == value.strip(), reason)
            fields[key] = value
        _require(fields.get("include-system-site-packages") in ("true", "false") and "home" in fields,
                 reason)
        return fields
    except UnicodeError:
        raise RuntimeRefusal(reason) from None
class _Base:
    def __init__(self, excluded, reason):
        self.excluded, self.reason = excluded, reason
        self.version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        self.lib = getattr(sys, "platlibdir", None)
        _require(sys.implementation.name == "cpython" and self.lib in ("lib", "lib64"), reason)
        try:
            free_threaded, extra_paths = sysconfig.get_config_vars("Py_GIL_DISABLED", "PYTHONPATH")
        except (ImportError, OSError, ValueError):
            raise RuntimeRefusal(reason) from None
        _require(not free_threaded and not extra_paths, reason)
        self.entry = _path(getattr(sys, "_base_executable", None), reason)
        self.file = _outside_program(self.entry, excluded, reason)
        self.prefix = self.file.parent.parent
        _require(self.file.parent.name == "bin", reason)
        self.stdlib = self.prefix / self.lib / self.version
        self.zip = self.stdlib.with_name(self.version.replace(".", "") + ".zip")
        self.dynload = self.stdlib / "lib-dynload"
        self.profile, self.executable = self._inspect()
        try:
            current = _outside(_path(os.readlink("/proc/self/exe"), reason), excluded, reason)
            running = os.stat("/proc/self/exe")
        except OSError:
            raise RuntimeRefusal("unsupported_platform") from None
        with _open_python(current, reason) as (fd, stamp):
            _require(os.path.samestat(running, os.fstat(fd)) and stamp[1] == self.executable[1], reason)

    def _inspect(self):
        prefix, reason = self.prefix, self.reason
        # The running verifier attests the executable and both prefix names.
        # Only the physical executable's own prefix can provide startup paths.
        _require(all(_outside(_path(name, reason), self.excluded, reason) == prefix
                     for name in (sys.base_prefix, sys.base_exec_prefix)), reason)
        _require(all(_outside_program(entry, self.excluded, reason) == self.file
                     for entry in (self.entry, self.file.parent / self.version)), reason)
        encodings = self.stdlib / "encodings"
        paths = {prefix: stat.S_ISDIR, self.file.parent: stat.S_ISDIR, self.stdlib.parent: stat.S_ISDIR,
                 self.stdlib: stat.S_ISDIR, self.dynload: stat.S_ISDIR, encodings: stat.S_ISDIR,
                 self.stdlib / "os.py": stat.S_ISREG, encodings / "__init__.py": stat.S_ISREG,
                 encodings / "aliases.py": stat.S_ISREG, encodings / "utf_8.py": stat.S_ISREG,
                 self.zip: stat.S_ISREG}
        facts = []
        for path, kind in paths.items():
            _outside(path, self.excluded, reason, optional=path == self.zip)
            info = _entry(path, reason)
            _require(kind(info.st_mode) if info else path == self.zip, reason)
            facts.append(_file_state(info)[:3] if info and kind == stat.S_ISDIR
                         else _file_state(info) if info else None)
        directory = self.file.parent
        landmarks = (prefix / "pyvenv.cfg", directory / "pyvenv.cfg", directory / "pybuilddir.txt",
                     directory / "Modules" / "Setup.local", directory / "Lib" / "os.py",
                     directory / self.lib, directory / (self.version + "._pth"),
                     directory / (self.file.name + "._pth"))
        _require(all(_entry(path, reason) is None for path in landmarks), reason)
        for parent in prefix.parents:
            path = parent / self.lib / self.zip.name
            physical = _outside(path, self.excluded, reason, optional=True)
            _require(physical == self.zip or _entry(physical, reason) is None, reason)
        with _open_python(self.file, reason) as (_, state):
            return tuple(facts), state

    def command(self, program, *args):
        profile = map(str, (self.file, self.prefix, self.zip, self.stdlib, self.dynload))
        return [str(self.file), "-I", "-S", "-B", "-c", _STARTUP + program, *profile, *args]

    def sites(self, root, reason, *, venv=False):
        paths = [root / lib / self.version / "site-packages"
                 for lib in dict.fromkeys((self.lib, "lib"))] if venv else []
        paths.extend(map(Path, python_site.getsitepackages([str(root)])))
        for path in dict.fromkeys(paths):
            physical = _outside(path, self.excluded, reason, optional=True)
            _require(physical.is_relative_to(root), reason)
            info = _entry(physical, reason)
            if info is not None:
                _require(stat.S_ISDIR(info.st_mode), reason)
                yield str(physical), _file_state(info)[:3]

    def check(self):
        _require(self._inspect() == (self.profile, self.executable), self.reason)
class _Launch:
    def __init__(self, base, physical, guard, reason, expected=None):
        self.base, self.file, self.guard, self.reason = base, physical, guard, reason
        self.binding = expected
        with self.open() as fd:
            self.binding = _file_state(os.fstat(fd)), base.executable[1]

    @contextmanager
    def open(self):
        self.base.check()
        self.guard()
        with _open_python(self.file, self.reason) as (fd, stamp):
            _require(stamp[1] == self.base.executable[1]
                     and (self.binding is None or stamp == self.binding), self.reason)
            try:
                yield fd
            finally:
                self.guard()
                self.base.check()

    def check(self):
        with self.open():
            pass
def _home(fields, base, reason):
    home = _outside(_path(fields["home"], reason), base.excluded, reason)
    _require(home == base.file.parent, reason)
def _builder_configs(python, physical, excluded, reason):
    configs = {}
    for _ in range(41):
        parent = _outside(python.parent, excluded, reason)
        _require(_entry(parent / "pyvenv.cfg", reason) is None, reason)
        for root in {parent.parent, _outside(python.parent.parent, excluded, reason)}:
            if _entry(root / "pyvenv.cfg", reason) is not None:
                configs[root] = _read(root, ("pyvenv.cfg",), 8192, reason)
        name = parent / python.name
        target = _entry(name, reason, read_link=True)
        if not isinstance(target, str):
            _require(name == physical and target and stat.S_ISREG(target.st_mode), reason)
            return configs
        _require(_displayable(target), reason)
        python = parent / target
        _outside(python, excluded, reason)
    raise RuntimeRefusal(reason)
def _builder_profile(python, base):
    reason, excluded = "invalid_input", base.excluded
    physical = _outside_program(python, excluded, reason)
    configs = _builder_configs(python, physical, excluded, reason)
    _require(len(configs) <= 1 and (physical == base.file or configs), reason)
    sites = []
    system_sites = True
    if configs:
        root, raw = next(iter(configs.items()))
        fields = _config_fields(raw, reason)
        _home(fields, base, reason)
        sites.extend(base.sites(root, reason, venv=True))
        system_sites = fields["include-system-site-packages"] == "true"
    if system_sites:
        sites.extend(base.sites(base.prefix, reason))
    with _open_python(physical, reason) as (_, stamp):
        _require(stamp[1] == base.executable[1], reason)
    return physical, stamp, configs, tuple(dict.fromkeys(sites))
def _builder(python, base):
    state = _builder_profile(python, base)

    def check():
        _require(_builder_profile(python, base) == state, "invalid_input")

    return _Launch(base, base.file, check, "invalid_input", base.executable), json.dumps(
        list(dict.fromkeys(path for path, _ in state[-1])))
def _builder_run(builder, args, *, cwd, env, reason):
    launch, sites = builder
    _run(launch, ["-c", _BUILDER_BOOT, sites, *args], cwd=cwd, env=env, reason=reason)
def _export(reader, source, identity, entries, target):
    try:
        reader.export_commit(source, identity["commit"], identity["tree"], target)
        files = set(entries)
        dirs = {parts[:index] for parts in files for index in range(1, len(parts))}
        links = {parts for parts, (mode, _) in entries.items() if mode == b"120000"}
        found = set()
        with open_directory(_directory, target, retain_ancestors=True) as anchor:
            _scan_site(anchor.fd, (), dirs, files, found, links, "source_changed")
            _source_bytes(target, entries)
            anchor.check()
        _require(files == found, "source_changed")
    except (JobSourceRefusal, ConfinedFileError, OSError):
        raise RuntimeRefusal("source_changed") from None
    # The source exporter makes every directory read-only. Only the private
    # build snapshot becomes writable, with symlink traversal disabled.
    for _, _, _, fd in os.fwalk(target, follow_symlinks=False):
        os.fchmod(fd, 0o700)
def _build_artifacts(builder, source, artifact_dir, scratch):
    env = _environment(scratch)
    _builder_run(builder, ["program", "import pip, setuptools.build_meta, wheel, packaging"], cwd=scratch,
                 env=env, reason="build_backend_unavailable")
    _builder_run(builder, ["program", _BUILD, str(artifact_dir)], cwd=source, env=env, reason="build_failed")
    names = []
    with os.scandir(artifact_dir) as entries:
        for entry in entries:
            _require(len(names) < 2 and entry.is_file(follow_symlinks=False), "build_failed")
            names.append(entry.name)
    return {kind: _artifact_name(names, pattern) for kind, pattern in (("wheel", _WHEEL), ("sdist", _SDIST))}
def _artifact_name(names, pattern):
    matches = [name for name in names if _matches(name, pattern) and _displayable(name)]
    _require(len(matches) == 1, "build_failed")
    return matches[0]
def _wheel_end(raw):
    # This pure wheel profile excludes ZIP64, archives with comments and
    # multi-disk ZIPs. Check the central directory bounds before zipfile parses it.
    _require(len(raw) >= 22, "artifact_mismatch")
    signature, disk, start_disk, disk_count, count, size, offset, comment = struct.unpack_from(
        "<4s4H2LH", raw, len(raw) - 22)
    _require(signature == b"PK\x05\x06" and disk == start_disk == comment == 0
             and 0 < disk_count == count <= _ENTRY_LIMIT and size <= 4 * 1024 * 1024
             and offset + size == len(raw) - 22, "artifact_mismatch")
    end = len(raw) - 22
    for _ in range(count):
        _require(offset + 46 <= end and raw[offset:offset + 4] == b"PK\x01\x02", "artifact_mismatch")
        name, extra, comment = struct.unpack_from("<3H", raw, offset + 28)
        _require(0 < name <= 1024, "artifact_mismatch")
        offset += 46 + name + extra + comment
    _require(offset == end, "artifact_mismatch")
    return count
def _wheel_hash(archive, entry):
    digest = hashlib.sha256()
    left = entry.file_size
    with archive.open(entry) as file:
        while left:
            chunk = file.read(min(left, _CHUNK))
            _require(chunk, "artifact_mismatch")
            digest.update(chunk)
            left -= len(chunk)
        _require(not file.read(1), "artifact_mismatch")
    return digest.hexdigest()
def _wheel_files(raw):
    count = _wheel_end(raw)
    files = {}
    total = 0
    dist_info = set()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            _require(len(entries) == count, "artifact_mismatch")
            seen = set()
            for entry in entries:
                parts = _wheel_path(entry)
                _require(parts not in seen, "artifact_mismatch")
                seen.add(parts)
                if parts[0].endswith(".dist-info"):
                    dist_info.add(parts[0])
                if entry.is_dir():
                    continue
                total += entry.file_size
                _require(entry.file_size <= _MEMBER_LIMIT and total <= _INSTALL_LIMIT, "artifact_mismatch")
                files[parts] = _wheel_hash(archive, entry)
    except (OSError, EOFError, zipfile.BadZipFile, RuntimeError, ValueError, zlib.error) as error:
        if isinstance(error, RuntimeRefusal):
            raise
        raise RuntimeRefusal("artifact_mismatch") from None
    _require(len(dist_info) == 1 and all(parts in files for parts in _ORIGIN_FILES), "artifact_mismatch")
    metadata = next(iter(dist_info))
    _require(all((metadata, name) in files for name in ("METADATA", "WHEEL", "RECORD")), "artifact_mismatch")
    del files[(metadata, "RECORD")]
    return files, metadata
def _wheel_path(entry):
    name = entry.orig_filename
    _require(len(name) <= 1024 and entry.filename == name, "artifact_mismatch")
    parts = tuple(name.rstrip("/").split("/"))
    mode = stat.S_IFMT(entry.external_attr >> 16)
    expected_type = stat.S_IFDIR if entry.is_dir() else stat.S_IFREG
    _require(0 < len(parts) <= 32 and mode in (0, expected_type)
             and all(_matches(part, r"[A-Za-z0-9_.+@-]+") and part not in (".", "..") for part in parts)
             and (parts[0] in _PACKAGES or _matches(parts[0], r"aegis_guardrails-[A-Za-z0-9_.+-]+\.dist-info"))
             and (entry.is_dir() or len(parts) >= 2)
             and not any(part == "__pycache__" for part in parts)
             and not name.endswith((".pyc", ".pyo", ".pth")), "artifact_mismatch")
    return parts
def _artifact_data(artifact_root, generation, names):
    values = {}
    files = None
    for kind, name in names.items():
        relative = (generation, name)
        data = _read(artifact_root, relative, _ARTIFACT_LIMIT, "artifact_mismatch")
        if kind == "wheel":
            files = data
        values[kind] = {"path": "/".join(relative), "sha256": _sha(data)}
    return values, files
def _site_tree(root, generation, site, files, metadata):
    expected = set(files)
    optional = {(metadata, name) for name in ("INSTALLER", "REQUESTED", "direct_url.json")}
    allowed = expected | optional | {(metadata, "RECORD")}
    directories = {parts[:count] for parts in allowed for count in range(1, len(parts))}
    found = set()
    site_root = root / generation / site
    try:
        with open_directory(_directory, site_root, retain_ancestors=True) as anchor:
            _scan_site(anchor.fd, (), directories, allowed, found)
            anchor.check()
    except (ConfinedFileError, OSError):
        raise RuntimeRefusal("install_mismatch") from None
    _require(expected <= found and (metadata, "RECORD") in found, "install_mismatch")
    for parts in sorted(found):
        digest = _sha(_read(site_root, parts, _MEMBER_LIMIT, "install_mismatch"))
        _require(parts not in files or digest == files[parts], "install_mismatch")
def _scan_site(fd, prefix, directories, allowed, found, links=frozenset(), reason="install_mismatch",
               terminal=None):
    with os.scandir(fd) as entries:
        for entry in entries:
            parts = (*prefix, entry.name)
            if parts == terminal:
                _require(entry.is_dir(follow_symlinks=False), reason)
            elif parts in directories and entry.is_dir(follow_symlinks=False):
                child = _directory(entry.name, dir_fd=fd)
                try:
                    _scan_site(child, parts, directories, allowed, found, links, reason, terminal)
                finally:
                    os.close(child)
            elif terminal and parts in {("lib",), ("lib64",)} and parts[0] != terminal[0]:
                _require(entry.is_symlink() and os.readlink(entry.name, dir_fd=fd) == terminal[0], reason)
            else:
                regular = entry.is_file(follow_symlinks=False)
                _require(parts in allowed and (entry.is_symlink() if parts in links else regular), reason)
                found.add(parts)
def _layout(runtime, site, empty):
    lib, version, _ = site.split("/")
    terminal = (lib, version, "site-packages")
    directories = {("bin",), (lib,), (lib, version), ("include",), ("include", version),
                   ("include", "site"), ("include", "site", version)}
    bin_names = {"python", "python3", version, "activate", "activate.csh", "activate.fish",
                 "Activate.ps1", "aegis", "aegis-mcp", "aegis-guardrails"}
    leaves = {("pyvenv.cfg",)} | {("bin", name) for name in bin_names}
    with open_directory(_directory, runtime, retain_ancestors=True) as root:
        _scan_site(root.fd, (), directories, leaves, set(), terminal=terminal)
        if empty:
            with open_directory(_directory, runtime / site, retain_ancestors=True) as anchor:
                _scan_site(anchor.fd, (), set(), set(), set())
                anchor.check()
        root.check()
def _runtime_config(runtime, site, base, digest, *, empty=False):
    reason = "install_mismatch"
    try:
        _layout(runtime, site, empty)
        raw = _read(runtime, ("pyvenv.cfg",), 8192, reason)
        _require(_sha(raw) == digest and site.split("/")[1] == base.version, reason)
        fields = _config_fields(raw, reason)
        version = fields.get("version", "")
        _require(_matches(version, r"3\.[0-9]{1,2}\.[0-9]{1,3}(?:[a-z0-9]+)?")
                 and "python" + version.rsplit(".", 1)[0] == base.version
                 and fields["include-system-site-packages"] == "false", reason)
        _home(fields, base, reason)
    except (ConfinedFileError, OSError):
        raise RuntimeRefusal(reason) from None
def _place_packages(scratch, target):
    with open_directory(_directory, scratch / "pip-install", retain_ancestors=True) as staging:
        try:
            scripts = _directory("bin", dir_fd=staging.fd)
        except FileNotFoundError:
            scripts = None
        if scripts is not None:
            try:
                with os.scandir(scripts) as entries:
                    for entry in entries:
                        _require(entry.name in {"aegis", "aegis-mcp", "aegis-guardrails"}
                                 and entry.is_file(follow_symlinks=False), "install_mismatch")
                        os.unlink(entry.name, dir_fd=scripts)
            finally:
                os.close(scripts)
            os.rmdir("bin", dir_fd=staging.fd)
        with open_directory(_directory, scratch, retain_ancestors=True) as source, \
             open_directory(_directory, target.parent, retain_ancestors=True) as destination:
            staging.check()
            source.check()
            destination.check()
            os.rename("pip-install", target.name, src_dir_fd=source.fd, dst_dir_fd=destination.fd)
def _install(builder, artifact, runtime, scratch):
    env = _environment(scratch)
    base = builder[0].base
    _builder_run(builder, ["module", "venv", "--copies", "--without-pip", str(runtime)], cwd=scratch,
                 env=env, reason="install_failed")
    reason = "install_mismatch"
    digest = _sha(_read(runtime, ("pyvenv.cfg",), 8192, reason))
    lib = _entry(runtime / "lib", reason)
    site = f"{'lib' if lib and stat.S_ISDIR(lib.st_mode) else 'lib64'}/{base.version}/site-packages"
    target = runtime / site

    def check():
        _runtime_config(runtime, site, base, digest, empty=True)

    launch = _Launch(base, runtime / "bin" / "python", check, reason)
    # Use the trusted builder's pip. Target installation never launches the candidate.
    _builder_run(builder, ["module", "pip", "install", "--isolated", "--no-index", "--no-deps",
                           "--no-compile", "--no-cache-dir", "--target", str(scratch / "pip-install"), str(artifact)],
                 cwd=scratch, env=env, reason="install_failed")
    launch.check()
    try:
        _place_packages(scratch, target)
    except (OSError, ConfinedFileError):
        raise RuntimeRefusal("install_mismatch") from None
    return site, digest, launch.binding
def _smoke(launch, site_root, scratch):
    env = _environment(scratch)
    # Derive child import targets from the package inventory. Core itself
    # stays independent of the installed CLI and server implementations.
    expected = {
        package if filename == "__init__.py" else ".".join((package, filename[:-3])):
        str(site_root / package / filename)
        for package, filename in _ORIGIN_FILES
    }
    raw = _run(launch, ["-c", _IMPORT_PROBE, str(site_root), *expected], cwd=scratch, env=env,
               reason="install_mismatch", capture=True)
    _require(_json(raw, "install_mismatch") == expected, "install_mismatch")
    env.update(manager_registration_env(scratch / "unused-manager-config.json", "0" * 64))
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    wire = b"".join(json.dumps(row).encode("ascii") + b"\n" for row in requests)
    raw = _run(launch, ["-c", _MCP_BOOT, str(site_root)], cwd=scratch, env=env,
               reason="smoke_failed", stdin=wire, capture=True)
    first, sep, rest = raw.partition(b"\n")
    second, end, trailing = rest.partition(b"\n")
    _require(sep and end and not trailing, "smoke_failed")
    init, listing = (_json(row, "smoke_failed") for row in (first, second))
    _require(_tool_list(init, listing), "smoke_failed")
    return expected, {"server": _SERVER, "tools": list(_TOOLS), "transport": "stdio"}
def _tool_list(init, listing):
    if not all(type(row) is dict and row.get("jsonrpc") == "2.0" and row.get("id") == index
               and type(row.get("result")) is dict and "error" not in row
               for index, row in enumerate((init, listing), 1)):
        return False
    info, tools = init["result"].get("serverInfo"), listing["result"].get("tools")
    return (type(info) is dict and info.get("name") == _SERVER
            and type(tools) is list and len(tools) == len(_TOOLS)
            and all(type(tool) is dict and type(tool.get("name")) is str
                    and type(tool.get("inputSchema")) is dict for tool in tools)
            and sorted(tool["name"] for tool in tools) == _TOOLS)
def _manifest(raw):
    parsed = _json(raw, "invalid_manifest")
    _require(type(parsed) is dict and set(parsed) == {
        "schema", "source", "generation", "artifacts", "site", "python_sha256", "venv_sha256"
    } and parsed["schema"] == _SCHEMA and _matches(parsed["generation"], _GENERATION)
        and _matches(parsed["site"], _SITE) and _matches(parsed["python_sha256"], _DIGEST)
        and _matches(parsed["venv_sha256"], _DIGEST), "invalid_manifest")
    identity = parsed["source"]
    _require(type(identity) is dict and set(identity) == {"commit", "tree"}
             and all(_matches(value, _OID) for value in identity.values()), "invalid_manifest")
    _names(parsed)
    return parsed
def _names(manifest):
    records = manifest["artifacts"]
    _require(type(records) is dict and set(records) == {"wheel", "sdist"}, "invalid_manifest")
    names = {}
    for kind, pattern in (("wheel", _WHEEL), ("sdist", _SDIST)):
        record = records[kind]
        _require(type(record) is dict and set(record) == {"path", "sha256"}
                 and _matches(record["sha256"], _DIGEST)
                 and type(record["path"]) is str, "invalid_manifest")
        parent, sep, name = record["path"].partition("/")
        _require(sep and parent == manifest["generation"] and _matches(name, pattern) and _displayable(name),
                 "invalid_manifest")
        names[kind] = name
    return names
def _verify(paths, roots, manifest, identity, scratch, base, expected_python=None, binding=None):
    _, artifacts, output = paths
    generation = manifest["generation"]
    runtime = output / generation
    interpreter = runtime / "bin" / "python"
    _require(manifest["source"] == identity, "source_changed")
    if expected_python is not None:
        _require(_path(expected_python) == interpreter, "wrong_interpreter")
    actual_artifacts, wheel = _artifact_data(artifacts, generation, _names(manifest))
    _require(actual_artifacts == manifest["artifacts"], "artifact_mismatch")
    files, metadata = _wheel_files(wheel)
    site = manifest["site"]
    _require(manifest["python_sha256"] == base.executable[1], "wrong_interpreter")

    def check():
        _runtime_config(runtime, site, base, manifest["venv_sha256"])
        _site_tree(output, generation, site, files, metadata)
        for anchor in roots:
            anchor.check()

    launch = _Launch(base, interpreter, check, "wrong_interpreter", binding)
    origins, smoke = _smoke(launch, runtime / site, scratch)
    _require(all(_path(value) == Path(value) for value in (str(interpreter), *origins.values())), "invalid_input")
    return {"status": "verified", "interpreter": str(interpreter), "source": identity,
            "artifacts": actual_artifacts, "import_origins": origins, "manager_smoke": smoke}, launch
def _publish(output, manifest, launch):
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
    _manifest(encoded)
    try:
        with confined_file(output, (_MANIFEST,)) as file:
            launch.check()
            file.publish_bytes(encoded, replace=True)
    except ConfinedFileError as error:
        if error.reason == "durability":
            raise RuntimeRefusal("publication_uncertain") from None
        raise
def _stage(paths, roots, identity, reader, entries, builder, scratch):
    source, artifacts, output = paths
    generation = uuid.uuid4().hex
    artifact_dir, runtime = artifacts / generation, output / generation
    export = scratch / "reviewed-source"
    _export(reader, source, identity, entries, export)
    with ExitStack() as cleanup:
        for anchor in roots[1:]:
            anchor.check()
            os.mkdir(generation, mode=0o700, dir_fd=anchor.fd)
            cleanup.callback(shutil.rmtree, f"/proc/self/fd/{anchor.fd}/{generation}")
        names = _build_artifacts(builder, export, artifact_dir, scratch)
        records, wheel = _artifact_data(artifacts, generation, names)
        _wheel_files(wheel)
        with confined_file(scratch, (names["wheel"],)) as captured:
            captured.publish_bytes(wheel)
        site, venv_digest, binding = _install(builder, scratch / names["wheel"], runtime, scratch)
        manifest = {"schema": _SCHEMA, "generation": generation, "source": identity,
                    "artifacts": records, "site": site, "python_sha256": binding[1], "venv_sha256": venv_digest}
        report, launch = _verify(paths, roots, manifest, identity, scratch, builder[0].base, binding=binding)
        _, current_source, _ = _source(source, identity["commit"], scratch)
        _require(current_source == identity, "source_changed")
        try:
            _publish(output, manifest, launch)
        except RuntimeRefusal as error:
            if error.reason == "publication_uncertain":
                cleanup.pop_all()  # The complete generation may already be visible.
            raise
        cleanup.pop_all()
        return report
def build_pin(*, source, commit, artifact_root, output_root, build_python):
    """Build and install offline, then atomically publish a verified manager pin."""
    with _roots(source, artifact_root, output_root, commit) as (paths, roots):
        builder = _builder(_path(build_python), _Base(paths, "invalid_input"))
        with tempfile.TemporaryDirectory(prefix="manager-build-", dir=paths[2]) as directory:
            scratch = Path(directory)
            reader, identity, entries = _source(paths[0], commit, scratch)
            return _stage(paths, roots, identity, reader, entries, builder, scratch)
@contextmanager
def _verified_pin(source, commit, artifact_root, output_root, python):
    with _roots(source, artifact_root, output_root, commit) as (paths, roots):
        manifest = _manifest(_read(paths[2], (_MANIFEST,), _JSON_LIMIT, "invalid_manifest"))
        base = _Base(paths, "install_mismatch")
        with tempfile.TemporaryDirectory(prefix="manager-verify-") as directory:
            scratch = Path(directory)
            _, identity, _ = _source(paths[0], commit, scratch)
            report, launch = _verify(paths, roots, manifest, identity, scratch, base, python)
            _, current_source, _ = _source(paths[0], commit, scratch)
            _require(current_source == identity, "source_changed")
        launch.check()
        yield report, launch
def verify_pin(*, source, commit, artifact_root, output_root, python=None):
    """Verify the current pin and repeat its manager tools/list smoke."""
    with _verified_pin(source, commit, artifact_root, output_root, python) as (report, _):
        return report
class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise RuntimeRefusal("invalid_input")
def main(argv=None):
    """Print a single JSON report or refusal and return the process exit code."""
    parser = _Parser(prog="python -m aegis_core.manager_runtime", allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True)
    for operation in ("build", "verify"):
        command = commands.add_parser(operation, allow_abbrev=False)
        for argument in ("source", "commit", "artifact-root", "output-root"):
            command.add_argument("--" + argument, required=True)
        if operation == "build":
            command.add_argument("--build-python", required=True)
        else:
            command.add_argument("--python")
    try:
        args = vars(parser.parse_args(argv))
        operation = args.pop("operation")
        report = build_pin(**args) if operation == "build" else verify_pin(**args)
    except RuntimeRefusal as error:
        print(json.dumps(error.as_dict(), sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
