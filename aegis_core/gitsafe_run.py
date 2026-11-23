"""Git transport: legacy defaults and strict runners issued only by the facade."""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
import contextvars
from dataclasses import dataclass, replace
from inspect import CO_VARKEYWORDS as _VAR_KEYWORDS
import math
import os
import re
from pathlib import Path
import select
import queue
from threading import Event, Thread
import signal
import stat
import subprocess
from sys import exc_info
import tempfile
import time
from types import MappingProxyType
from typing import Mapping, Optional
from aegis_core.errors import AegisError
from aegis_core.primitives import sanitize_display, key_within, real_key
from aegis_core.redaction import redact_insight_text
from aegis_core import gitsafe_policy, pathlookup
from aegis_core.gitsafe_policy import (
    BASE_ENV,
    LOCAL_ENV,
    GitError,
    outside_roots,
    OID,
    READ_SHAPES,
    strict_refuse,
    bounded_args,
    strict_root,
    strict_environment,
    full_oid,
    ref_name,
    read_shape,
    IDENTITY_ENV,
    ENVIRON_TYPE,
    classify_ambient,
    AMBIENT_ENV,
    LOCATION_ENV,
    Environment,
    environment_refusal,
    environment_layer,
    merge_inputs,
    identity_environment,
    private_headers,
    private_object,
    private_objects,
)
# Existing ChangingEnvironment tests patch the facade's ambient-type boundary.
_ENVIRON_TYPE = ENVIRON_TYPE
HARDENING_KEEP_HOOKS_PATH = (
    "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
    "-c", "core.sshCommand=false", "-c", "credential.helper=",
    "-c", "log.showSignature=false", "-c", f"gpg.program={os.devnull}",
    "-c", f"gpg.openpgp.program={os.devnull}", "-c", f"gpg.x509.program={os.devnull}",
)
DEFAULT_HARDENING = ("-c", f"core.hooksPath={os.devnull}", *HARDENING_KEEP_HOOKS_PATH)
_LANE_OPTIONS = ("-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "core.splitIndex=false",
                 "-c", "core.untrackedCache=false", "-c", "core.sparseCheckout=false",
                 "-c", "merge.renormalize=false", "-c", "commit.gpgsign=false")
_FIXED_CONFIG = frozenset((*DEFAULT_HARDENING[1::2], *_LANE_OPTIONS[1::2], "core.safecrlf=false", "core.attributesFile="))
def _command(argv, cwd, stdin, grant=None):
    """Prove the closed command grammar before repository discovery can spawn."""
    position, pairs = 1, set()
    while position + 1 < len(argv) and argv[position] == "-c":
        pair = argv[position + 1]
        if pair not in _FIXED_CONFIG and not re.fullmatch(r"filter\.[A-Za-z0-9_.-]+\.(?:(?:clean|smudge|process)=|required=false)", pair): strict_refuse()
        pairs.add(pair)
        position += 2
    if not set((*DEFAULT_HARDENING[1::2], *_LANE_OPTIONS[1::2])) <= pairs: strict_refuse()
    args = tuple(argv[position:])
    if args == ("update-ref", "--no-deref", "-z", "--stdin"):
        if grant != (tuple(argv), str(cwd), stdin): strict_refuse()
    elif not read_shape(args): strict_refuse()
    if (args[:len(gitsafe_policy.SNAPSHOT_SOURCE_PREFIX)] == gitsafe_policy.SNAPSHOT_SOURCE_PREFIX) != ("core.attributesFile=" in pairs): strict_refuse()
    return args, pairs
def _argv(args, program, hardening, policy):
    argv = [program, *hardening, *args]
    if policy is not None:
        position = len(hardening) + 1
        while position + 1 < len(argv) and argv[position] == "-c":
            position += 2
        extra = _LANE_OPTIONS if policy.strict_lane else ("-c", "gc.auto=0", "-c", "maintenance.auto=false")
        if policy.strict_lane and tuple(argv[position:position + len(gitsafe_policy.SNAPSHOT_SOURCE_PREFIX)]) == gitsafe_policy.SNAPSHOT_SOURCE_PREFIX:
            extra = (*extra, "-c", "core.attributesFile=")
        argv[position:position] = ["-c", f"core.hooksPath={os.devnull}", *extra]
    return argv
def request_environment(source=None, *, profile="ordinary", scope=None, overrides=None, base=None,
                        roots=(), root=None, repository=None, bindings=None, error=GitError, scrub=False, allowed=None, kind=None):
    """Snapshot the facade's ambient source; all request rules live below transport."""
    replacement = _replacement_environment(source, allow=profile == "ordinary"
        and scope is None and overrides is None and bindings is None
        and (base is None or type(base) is dict and not base), error=error)
    if replacement is not None:
        return gitsafe_policy.request_environment(replacement, base=base)
    return gitsafe_policy.request_environment(os.environ if source is None else source,
        profile=profile, scope=scope, overrides=overrides, base=base, roots=roots, root=root,
        repository=repository, bindings=bindings, error=error, scrub=scrub, allowed=allowed, kind=kind,
        ambient=source is None or type(source) is _ENVIRON_TYPE, environ_type=_ENVIRON_TYPE)
__all__ = ["BASE_ENV", "DEFAULT_HARDENING", "HARDENING_KEEP_HOOKS_PATH", "LOCAL_ENV",
           "capture", "checked", "completed", "custody", "custody_active",
           "execute", "memo_context", "output", "path_text", "query_result", "validate_review_preparation",
           "private_headers", "private_object", "private_objects", "scrubbed", "text", "update_once",
           "strict_active", "lane_update_ref", "validate_update_input", "find_executable", "git_path",
           "LaneRunner", "hashed_blob", "check_ref_name", "CustodyRefusal", "request_environment", "Environment", "outside_roots", "AMBIENT_ENV", "custody_inputs", "merge_inputs", "transport_services", "REPLACEMENT_UNSET"]
_SCRUB = contextvars.ContextVar("aegis_git_scrub", default=False)
_CUSTODY = contextvars.ContextVar("aegis_git_custody", default=None)
REPLACEMENT_UNSET = object()
_MAX_CAPTURE = 128 * 1024 * 1024
_MAX_INPUT = 128 * 1024 * 1024
_CHUNK = 65536
CustodyRefusal = GitError
@dataclass(frozen=True)
class _LaneServices:
    program: object
    error: object
    conflict: object
    executable: object
def _program_supported():
    return os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and {"open", "readlink", "stat"} <= {f.__name__ for f in os.supports_dir_fd} and os.path.isdir("/proc/self/fd")
def _pin_program(path, roots, error, stack):
    """Walk links from held parents; retain the no-follow regular executable fd."""
    import stat
    from aegis_core import storage_confined
    if not _program_supported():
        environment_refusal(error, "unsupported_effect_platform")
    if type(path) is not str or not 0 < len(path) <= 16384 or not os.path.isabs(path): environment_refusal(error, "effect_command_refused")
    pending, directory = path.split("/")[1:], "/"
    try:
        for _ in range(512):
            if not pending: break
            component, pending = pending[0], pending[1:]
            if component in ("", "."): continue
            candidate = os.path.normpath(os.path.join(directory, component))
            if any(key_within(candidate, root) for root in roots): environment_refusal(error, "effect_command_refused")
            with storage_confined.confined_file(directory, ("aegis-program",)) as parent:
                info = os.stat(component, dir_fd=parent._parent, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(component, dir_fd=parent._parent)
                    if len(target) > 16384 or len(pending) + target.count("/") + 1 > 512: environment_refusal(error, "effect_command_refused")
                    pending = target.split("/") + pending
                    directory = "/" if target.startswith("/") else directory
                    continue
                if pending:
                    directory = candidate
                    continue
                fd = os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=parent._parent)
                stack.callback(os.close, fd)
                if not stat.S_ISREG(os.fstat(fd).st_mode) or not os.access(f"/proc/self/fd/{fd}", os.X_OK): environment_refusal(error, "effect_command_refused")
                if os.pread(fd, 4, 0) != b"\x7fELF": environment_refusal(error, "effect_command_refused", path)
                return fd
    except FileNotFoundError:
        environment_refusal(error, "git_failed")
    except (OSError, ValueError, UnicodeError, storage_confined.ConfinedFileError):
        environment_refusal(error, "effect_command_refused")
    environment_refusal(error, "effect_command_refused")
def find_executable(cache, environ, lookup, *, error, profile="ordinary", cwd=None, missing_ok=False, stack=None, ordinary_git=False):
    """Sole resolver; callbacks retain the facade's program-specific PATH lookup."""
    if ordinary_git:
        cache, environ, lookup, error = _git_lookup(cache, environ, cwd, lookup, error)
    environ = request_environment(environ, profile=profile, base={}, root=cwd, error=error) if not isinstance(environ, Environment) else request_environment(environ, profile="strict/effect", error=error)
    roots = environ.roots if isinstance(environ, Environment) else ()
    key = (environ.get("PATH"), environ.get("PATHEXT"), roots)
    found = cache.get(key)
    if not (found and os.path.isfile(found) and os.access(found, os.X_OK)):
        cache.clear()
        found = lookup(environ)
    if not found:
        if missing_ok: return None
        raise error("git is not installed or not on PATH")
    if roots and (not outside_roots(found, roots) or os.name == "nt" and os.path.splitext(found)[1].upper() not in (environ.get("PATHEXT") or ".COM;.EXE;.BAT;.CMD").upper().split(os.pathsep)):
        environment_refusal(error, "effect_command_refused")
    cache[key] = found
    if roots:
        with ExitStack() as temporary:
            fd = _pin_program(found, roots, error, stack if stack is not None else temporary)
            if stack is not None: return f"/proc/{os.getpid()}/fd/{fd}"
    return found
def _git_lookup(cache, environ, cwd, lookup, error):
    replacement = _replacement_environment(environ, error=error)
    if environ is not None:
        return {}, environ, lambda effective: lookup({
            "outside": getattr(effective, "root", cwd), "path": effective.get("PATH", os.defpath),
        }), error
    cache = cache.for_cwd(cwd)
    settings = {"outside": cache.fence, "fence_program": True, "descriptors": False}
    if replacement is None:
        return cache, None, lambda effective: lookup(settings), cache.error(error)
    program = _CUSTODY.get().program
    if program is not None:
        if pathlookup.fenced_program(program, cache.fence, descriptors=False) is None:
            raise error("invalid custody program", code="invalid_custody", process_started=False)
        return {}, None, lambda _: program, cache.error(error)
    return {}, None, lambda effective: lookup(
        dict(settings, path=effective.get("PATH", os.defpath), pathext=effective.get("PATHEXT", ""))), cache.error(error)

def _git_marker_entry(parent, name):
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None

def _git_marker_line(parent, name, read_open, stack, checks, *, gitfile=False):
    fd = read_open(name, parent)
    stack.callback(os.close, fd)
    seen = os.fstat(fd)
    if not stat.S_ISREG(seen.st_mode) or not 0 < seen.st_size <= 4096:
        raise ValueError("invalid Git metadata")
    raw = os.read(fd, seen.st_size + 1)
    if len(raw) != seen.st_size:
        raise ValueError("changed Git metadata")
    checks.append((parent, name, seen))
    try:
        return path_text(raw, gitfile=gitfile, record=True)
    except GitError:
        raise ValueError("invalid Git metadata") from None

def _git_marker_directory(parent, name, stack, checks):
    from aegis_core.pathlookup_fence import open_directory

    fd = open_directory(parent, name)
    stack.callback(os.close, fd)
    if parent is not None:
        checks.append((parent, name, os.fstat(fd)))
    return fd

def _git_marker_location(parent, value, stack, checks):
    if (not value or len(os.fsencode(value)) > 4096
            or any(c in value for c in "\0\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029")):
        raise ValueError("invalid Git metadata path")
    pointer = Path(value)
    parts = pointer.parts
    # Path normalizes these endings, but the preceding component must be a directory.
    if pointer.name and value.endswith(("/", "/.")):
        parts += (".",)
    if len(parts) > 128 or pointer.anchor not in ("", "/"):
        raise ValueError("invalid Git metadata path")
    if pointer.is_absolute():
        parent = _git_marker_directory(None, "/", stack, checks)
        parts = parts[1:]
    for part in parts[:-1]:
        parent = _git_marker_directory(parent, part, stack, checks)
    return parent, parts[-1] if parts else "."

def _review_git_directory(root, marker, read_open, stack, checks):
    parent, name, info = root, ".git", marker
    if stat.S_ISLNK(info.st_mode):
        if not 0 < info.st_size <= 4096:
            raise ValueError("invalid Git metadata link")
        value = os.readlink(name, dir_fd=parent)
        parent, name = _git_marker_location(root, value, stack, checks)
        info = _git_marker_entry(parent, name)
        if info is None:
            raise ValueError("missing Git metadata target")
        checks.append((parent, name, info))
    if stat.S_ISREG(info.st_mode):
        pointer = _git_marker_line(parent, name, read_open, stack, checks, gitfile=True)
        parent, name = _git_marker_location(root, pointer, stack, checks)
    return _git_marker_directory(parent, name, stack, checks)

def _check_preparation_overlap(fd, protected):
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino) in protected:
        raise ValueError("preparation directory overlaps Git metadata")

def _review_git_boundaries(root, protected, read_open, stack, checks):
    marker = _git_marker_entry(root, ".git")
    checks.append((root, ".git", marker))
    if marker is None:
        bare = [(root, name, _git_marker_entry(root, name)) for name in ("HEAD", "objects", "refs")]
        checks.extend(bare)
        if not all(info is not None for _, _, info in bare):
            return
    _check_preparation_overlap(root, protected)
    admin = root if marker is None else _review_git_directory(root, marker, read_open, stack, checks)
    _check_preparation_overlap(admin, protected)
    common = _git_marker_entry(admin, "commondir")
    checks.append((admin, "commondir", common))
    if common is not None:
        pointer = _git_marker_line(admin, "commondir", read_open, stack, checks)
        parent, name = _git_marker_location(admin, pointer, stack, checks)
        _check_preparation_overlap(_git_marker_directory(parent, name, stack, checks), protected)

def _check_git_marker_entries(checks):
    for parent, name, seen in checks:
        current = _git_marker_entry(parent, name)
        if seen is None and current is None:
            continue
        if (current is None or seen is None or not os.path.samestat(current, seen)
                or not stat.S_ISDIR(seen.st_mode) and current.st_ctime_ns != seen.st_ctime_ns):
            raise ValueError("changed Git metadata")

def _review_preparation_ancestors(fd, preparation, stack, checks):
    protected = set()
    for part in reversed(preparation.parts[1:]):
        info = os.fstat(fd)
        protected.add((info.st_dev, info.st_ino))
        parent = _git_marker_directory(fd, "..", stack, checks)
        checks.append((parent, part, info))
        fd = parent
    root = _git_marker_directory(None, "/", stack, checks)
    info = os.fstat(root)
    if not os.path.samestat(info, os.fstat(fd)):
        raise ValueError("changed preparation ancestry")
    protected.add((info.st_dev, info.st_ino))
    return protected

@contextmanager
def _review_preflight_refusal():
    try:
        yield
    except (OSError, ValueError):
        raise GitError("invalid review preparation boundary", code="record_required", process_started=False) from None

def validate_review_preparation(repo, preparation, stack, *, walk, read_open):
    """Check every enclosing marker and referenced Git location before discovery."""
    from aegis_core import storage_confined

    with ExitStack() as paths:
        checks, parents = [], []
        with _review_preflight_refusal():
            state = paths.enter_context(storage_confined.confined_file(preparation, (".preflight",)))
            info = state.parent_stat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("preparation directory is not private")
            protected = _review_preparation_ancestors(state.parent_fd, preparation, paths, checks)

        def inspect(fd, depth):
            with _review_preflight_refusal():
                held = os.dup(fd)
                paths.callback(os.close, held)
                if parents:
                    checks.append((parents[-1], repo.parts[depth - 1], os.fstat(held)))
                parents.append(held)
                _review_git_boundaries(held, protected, read_open, paths, checks)

        source = walk(inspect)
        stack.callback(os.close, source)
        with _review_preflight_refusal():
            _check_git_marker_entries(checks)
        return source, (info.st_dev, info.st_ino)

@dataclass(frozen=True)
class _TransportServices:
    environment: object
    resolve: object
    envelope_type: object
    merge: object
def transport_services():
    return _TransportServices(request_environment, find_executable, Environment, merge_inputs)
def git_path(cwd, name, *, runner, hardening):
    text = runner(["rev-parse", "--git-path", name], cwd, _hardening=hardening)
    if not text: return None
    path = Path(text)
    return path if path.is_absolute() else (Path(cwd) / path).resolve()
def hashed_blob(cwd, data, write, *, runner, hasher, error):
    # From stdin with no --path, hash-object applies no attribute, filter or line-ending
    # conversion: the blob is exactly ``data``, named in the repository's hash format.
    args = ["hash-object", *(["-w"] if write else []), "--no-filters", "--stdin"]
    out = runner(args, cwd, stdin=bytes(data))
    oid = (out or b"").strip().decode("ascii", "replace")
    if not OID.match(oid): raise error(f"git hash-object {'-w ' if write else ''}failed in {cwd}")
    if hasher(bytes(data), len(oid)) != oid: raise error(f"git named the blob {oid}, which does not hash its content")
    return oid
def check_ref_name(cwd, ref, what, *, runner, error, ref_error):
    """Extracted legacy grammar/query, preserving argv and error text."""
    ok = isinstance(ref, str) and ref.startswith("refs/") and not any(ch in ref for ch in "\0\n\r")
    if ok:
        res = runner(["check-ref-format", ref], cwd)
        if res is None: raise error(f"git cannot check the {what} {ref!r}")
        ok = res.returncode == 0
    if not ok: raise ref_error(f"invalid {what}: {ref!r}")
    return ref
@dataclass(frozen=True)
class _Policy:
    scratch: Path
    env: Mapping[str, str]
    stdout_limit: int
    stderr_limit: int
    strict_lane: bool
    services: object = None
    worktree_root: object = None
    boundary: str = "git"
    replace_env: bool = False
    program: Optional[str] = None
@contextmanager
def scrubbed():
    """Drop ambient repository-local GIT_* variables, preserving explicit _env."""
    token = _SCRUB.set(True)
    try:
        yield
    finally:
        _SCRUB.reset(token)
@contextmanager
def custody(*, scratch: Path, env: Optional[Mapping[str, str]] = None,
            stdout_limit: int = 16 * 1024 * 1024, stderr_limit: int = 65536, strict_lane: bool = False, _services=None, worktree_root=None, _boundary=None,
            replace_env=REPLACEMENT_UNSET, program: Optional[str] = None):
    """Bound a dynamic scope to owner-controlled scratch and preserve replacement inputs."""
    outer = _CUSTODY.get()
    inherited = _replacement_environment(allow=replace_env is not False and type(env) is not _ENVIRON_TYPE)
    if not isinstance(strict_lane, bool): raise GitError("invalid custody mode", code="invalid_custody")
    strict_lane = strict_lane or strict_active()
    if replace_env is not REPLACEMENT_UNSET and type(replace_env) is not bool:
        raise GitError("invalid custody environment mode", code="invalid_custody", process_started=False)
    if program is not None and (replace_env is not True or type(program) is not str or not 1 <= len(program) <= 16384
                                or "\0" in program or not Path(program).is_absolute()):
        raise GitError("invalid custody program", code="invalid_custody", process_started=False)
    replace_env = replace_env is True or inherited is not None
    if strict_lane and replace_env:
        raise GitError("replacement environment requires ordinary custody", code="invalid_custody", process_started=False)
    if inherited is not None:
        if program is not None and program != outer.program:
            raise GitError("invalid custody program", code="invalid_custody", process_started=False)
        program = outer.program
    if strict_lane and env is not None: env = strict_environment(env, 64, environ_type=_ENVIRON_TYPE)
    for cap in (stdout_limit, stderr_limit):
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= _MAX_CAPTURE: raise GitError("invalid custody limit", code="invalid_custody")
    if not isinstance(scratch, (str, Path)) or not str(scratch) or len(str(scratch)) > 16384 or "\0" in str(scratch): raise GitError("invalid custody scratch", code="invalid_custody")
    path = Path(scratch)
    if not path.is_absolute() or ".." in path.parts: raise GitError("invalid custody scratch", code="invalid_custody")
    try:
        copied = _custody_environment(env, replace_env) if env is not None or inherited is None else inherited
    except (KeyError, RuntimeError):
        if not replace_env:
            raise
        raise GitError("invalid custody environment", code="invalid_custody", process_started=False) from None
    if inherited is not None and copied != inherited:
        raise GitError("invalid custody environment", code="invalid_custody", process_started=False)
    token = _CUSTODY.set(_Policy(path, copied if inherited is None else inherited, stdout_limit, stderr_limit, strict_lane, _services, worktree_root, _boundary or ("lane" if strict_lane else "git"), replace_env, program))
    try:
        with scrubbed():
            yield
    finally:
        _CUSTODY.reset(token)
def _custody_environment(env, replace_env):
    if env is not None and (not isinstance(env, Mapping) or len(env) > 64):
        raise _custody_environment_error(replace_env)
    copied = {}
    for count, (key, value) in enumerate((env or {}).items(), 1):
        if (replace_env and count > 64 or not isinstance(key, str) or not isinstance(value, str)
                or len(key) > 128 or len(value) > 65536
                or "\0" in key or "\0" in value or "=" in key):
            raise _custody_environment_error(replace_env)
        if replace_env and os.name == "nt":
            key = str.upper(key)
            if len(key) > 128 or key in copied and copied[key] != value:
                raise GitError("invalid custody environment", code="invalid_custody", process_started=False)
        copied[key] = value
    return MappingProxyType(copied)
def _custody_environment_error(replace_env):
    if replace_env:
        return GitError("invalid custody environment", code="invalid_custody", process_started=False)
    return GitError("invalid custody environment", code="invalid_custody")
def custody_inputs():
    """The current caller's scoped input, separate from issued bindings."""
    replacement = _replacement_environment()
    if replacement is not None:
        return replacement
    policy = _CUSTODY.get()
    return {} if policy is None else policy.env
def _replacement_environment(source=None, *, allow=True, error=GitError):
    """Return the only permitted environment when replacement custody is active."""
    policy = _CUSTODY.get()
    if policy is None or not policy.replace_env:
        return None
    if source is not None or not allow:
        raise error("invalid replacement custody override", code="invalid_custody", process_started=False)
    return policy.env
def custody_active() -> bool:
    return _CUSTODY.get() is not None
def strict_active() -> bool:
    policy = _CUSTODY.get()
    return policy is not None and policy.strict_lane
def _strict_argv(argv, cwd, env, stdin, *, lane, grant=None, effect_context=None):
    bounded_args(argv)
    if any(env.get(k) != v for k, v in BASE_ENV.items() if k != "GIT_ALLOW_PROTOCOL"): strict_refuse()
    if strict_root(cwd) != strict_root(lane.cwd) or not argv or argv[0] != lane._lane_binding.program: strict_refuse()
    args, pairs = _command(argv, cwd, stdin, grant)
    shared = args[0] in ("update-ref", "unpack-objects") and grant == (tuple(argv), str(cwd), stdin) if args else False
    real_index = args[0] == "ls-files" and env.get("GIT_INDEX_FILE") == str(lane._lane_binding.paths[2])
    identity = {k: v for k, v in env.items() if k in IDENTITY_ENV}
    if env != lane.environment(identity, args=args, real_index=bool(real_index), shared=shared, effect_context=effect_context): strict_refuse()
    return args, pairs
@dataclass(frozen=True)
class _LaneBinding:
    cwd: Path
    scratch: Path
    services: _LaneServices
    base: object
    paths: object
    program: str
    read_objects: str
    effect_environment: object = None
    worktree_root: object = None
    write_roots: object = ()
    ambient: bool = False
def issue_runner(cwd, scratch, services, effect_fds=None, *, environ=None, write_roots=(), worktree_root=None):
    _replacement_environment(allow=False, error=services.error)
    if type(write_roots) not in (tuple, list) or len(write_roots) > 15: raise services.error("Git operation effect roots unavailable.", code="effect_environment_unavailable", process_started=False, next_action="Supply at most fifteen write roots; no effect process started.")
    write_roots = tuple(write_roots)
    cwd, scratch = Path(strict_root(cwd)), Path(strict_root(scratch))
    if effect_fds is not None:
        from aegis_core import gitops_fds
        gitops_fds.pass_through(effect_fds, error=services.error)
        base = gitops_fds.effect_environment(environ, cwd, error=services.error, worktree_root=worktree_root, roots=(*write_roots, scratch), base=BASE_ENV, scope=custody_inputs(), transport=transport_services(), kind="lane")
    else:
        base = request_environment(environ, profile="strict/effect", root=worktree_root or cwd, roots=(*write_roots, scratch), scope=custody_inputs(), error=services.error, kind="lane")
    base = request_environment(base, profile="strict/effect", bindings={}, error=services.error)
    code = getattr(services.program, "__code__", None)
    if code is None or not (code.co_flags & _VAR_KEYWORDS or "environ" in code.co_varnames[code.co_posonlyargcount:code.co_argcount + code.co_kwonlyargcount]): strict_refuse()
    program, values = services.program(cwd, environ=base), []
    if type(program) is not str or not program: strict_refuse()
    policy = _Policy(scratch, MappingProxyType({}), 16384, 65536, False, boundary="lane")
    try:
        for args in (("--absolute-git-dir",), ("--git-common-dir",), ("--show-toplevel",), ("--git-path", "index")):
            result = capture((program, *DEFAULT_HARDENING, *_LANE_OPTIONS, "rev-parse", *args), cwd=cwd,
                env=base, stdin=None, timeout=60, error=services.error, _policy=policy, effect_fds=effect_fds, worktree_root=base.root if effect_fds is not None else None)
            raw = path_text(result.stdout)
            if result.returncode or not raw or "\n" in raw or "\r" in raw: raise services.error("Lane repository discovery refused.", code="invalid_repository")
            values.append(Path(cwd, raw).resolve())
        git_dir, common, top, index = values
        resolved = scratch.resolve()
        if resolved.is_relative_to(common) or resolved.is_relative_to(top): raise services.error("Lane scratch refused.", code="unsafe_scratch")
        alternate = os.fsencode(str(common / "objects"))
        if len(alternate) > 16383: strict_refuse()
        owned = dict(GIT_DIR=str(git_dir), GIT_COMMON_DIR=str(common), GIT_WORK_TREE=str(top),
            GIT_OBJECT_DIRECTORY=str(scratch / "objects"), GIT_INDEX_FILE=str(scratch / "index"),
            GIT_ALTERNATE_OBJECT_DIRECTORIES='"' + ''.join('\\%03o' % c for c in alternate) + '"')
        base = request_environment(base, profile="strict/effect", bindings=owned, error=services.error)
        read_objects = str(scratch / "objects") if (scratch / "objects").is_dir() else str(common / "objects")
        binding = _LaneBinding(cwd, scratch, services, MappingProxyType(base), (common, top, index), program, read_objects, base, worktree_root, write_roots, environ is None)
        return LaneRunner(cwd, scratch, services, binding, effect_fds)
    except (OSError, ValueError, RuntimeError):
        raise services.error("Lane repository discovery failed.", code="git_failed", process_started=False) from None
@dataclass(frozen=True)
class LaneRunner:
    """Explicit, transferable lane capability; no method reads ambient custody."""
    cwd: Path
    scratch: Path
    services: _LaneServices
    _lane_binding: _LaneBinding
    effect_fds: object = None
    def __post_init__(self):
        error = self._lane_binding.services.error if type(self._lane_binding) is _LaneBinding else CustodyRefusal
        if (type(self._lane_binding) is not _LaneBinding or self.cwd is not self._lane_binding.cwd
                or self.scratch is not self._lane_binding.scratch or self.services is not self._lane_binding.services):
            raise error("Strict lane Git command refused.", code="git_custody_refused", process_started=False)
    def environment(self, env=None, *, args=(), real_index=False, shared=False, effect_context=None):
        supplied = identity_environment(env, args, environ_type=_ENVIRON_TYPE)
        if real_index and (tuple(args) not in READ_SHAPES or args[0] != "ls-files"): strict_refuse()
        effective = {k: v for k, v in self._lane_binding.base.items() if k in LOCATION_ENV}
        effective.update(supplied)
        if args[:len(gitsafe_policy.SNAPSHOT_SOURCE_PREFIX)] == gitsafe_policy.SNAPSHOT_SOURCE_PREFIX:
            effective["GIT_ATTR_NOSYSTEM"] = "1"
        if shared: effective["GIT_OBJECT_DIRECTORY"] = str(self._lane_binding.paths[0] / "objects")
        if real_index: effective["GIT_INDEX_FILE"] = str(self._lane_binding.paths[2])
        if tuple(args) == ("rev-parse", "--git-path", "index"): effective.pop("GIT_INDEX_FILE")
        if args and args[0] not in ("hash-object", "merge-tree", "commit-tree", "unpack-objects", "read-tree", "update-index", "write-tree") and not shared:
            effective["GIT_OBJECT_DIRECTORY"] = self._lane_binding.read_objects
        return request_environment(effect_context if effect_context is not None else self._lane_binding.effect_environment, profile="strict/effect", kind="lane", scope=custody_inputs(), overrides=supplied, bindings=effective, error=self.services.error)
    def policy(self, stdout_limit=16 * 1024 * 1024, stderr_limit=65536):
        if any(type(cap) is not int or not 0 <= cap <= _MAX_CAPTURE for cap in (stdout_limit, stderr_limit)): raise self.services.error("invalid custody limit", code="invalid_custody")
        return _Policy(Path(self.scratch), MappingProxyType({}), stdout_limit, stderr_limit, True, boundary="lane")
    def run(self, args, cwd=None, timeout=60, stdin=None, _hardening=DEFAULT_HARDENING,
            _env=None, tty=False, *, stdout_limit=16 * 1024 * 1024, stderr_limit=65536, options=(), real_index=False, effect_fds=None, _effect_context=None):
        if cwd is not None and strict_root(cwd) != strict_root(self.cwd): strict_refuse()
        args, options, hardening = bounded_args(args), bounded_args(options), bounded_args(_hardening)
        if hardening != DEFAULT_HARDENING or tty is not False or type(real_index) is not bool or len(args) + len(options) > 450: strict_refuse()
        policy = self.policy(stdout_limit, stderr_limit)
        argv = _argv((*options, *args), self._lane_binding.program, hardening, policy)
        return capture(argv, cwd=self.cwd, env=self.environment(_env, args=args, real_index=real_index, effect_context=_effect_context), stdin=stdin, timeout=timeout,
                       error=self.services.error, _lane=self, _policy=policy, effect_fds=self.effect_fds if effect_fds is None else effect_fds, worktree_root=self._lane_binding.worktree_root, write_roots=self._lane_binding.write_roots)
    def run_checked(self, args, cwd=None, **kwargs):
        kwargs.pop("error", None)
        result = self.run(args, cwd, **kwargs)
        if result.returncode: raise self.services.error("Lane Git command failed.", code="git_failed", returncode=result.returncode)
        return result
    def validate(self, argv, cwd, env, stdin, grant, *, effect_fds=None, timeout=60):
        args, pairs = _strict_argv(argv, cwd, env, stdin, lane=self, grant=grant, effect_context=env if effect_fds is not None else None)
        if args[0] not in ("hash-object", "merge-tree"): return argv
        listing = self.run(["config", "--null", "--name-only", "--get-regexp", r"^filter\."], stdout_limit=65536, effect_fds=effect_fds, timeout=timeout, _effect_context=env if effect_fds is not None else None)
        code = "merge_unavailable" if args[0] == "merge-tree" else "conversion_unavailable"
        if listing.returncode not in (0, 1) or bool(listing.stdout) != (listing.returncode == 0): raise self.services.error("Lane conversion observation refused.", code=code)
        if listing.stdout and not listing.stdout.endswith(b"\0"): raise self.services.error("Lane conversion observation refused.", code=code)
        flags, drivers = [], set()
        for key in dict.fromkeys(listing.stdout.split(b"\0")[:-1]):
            driver = key[len(b"filter."):].rpartition(b".")[0] if key.startswith(b"filter.") else b""
            if not driver or len(driver) > 256 or re.fullmatch(rb"[A-Za-z0-9_.-]+", driver) is None: raise self.services.error("Lane conversion observation refused.", code=code)
            if driver in drivers: continue
            if len(flags) + 8 > 512 - len(argv): strict_refuse()
            drivers.add(driver)
            flags.extend(x for name in ("clean", "smudge", "process", "required") for x in
                         ("-c", "filter." + driver.decode("ascii") + "." + name + ("=false" if name == "required" else "=")))
        if args[0] == "merge-tree":
            result = self.run(["config", "--show-scope", "--null", "--name-only", "--get-regexp",
                              r"^merge\..+\.driver$"], stdout_limit=65536, effect_fds=effect_fds, timeout=timeout, _effect_context=env if effect_fds is not None else None)
            if result.returncode == 0 and result.stdout: raise self.services.error("Lane merge driver refused.", code="repository_merge_driver")
            if result.returncode != 1 or result.stdout: raise self.services.error("Lane merge observation refused.", code="merge_unavailable")
        final = (argv[0], *flags, *argv[1:])
        _strict_argv(final, cwd, env, stdin, lane=self, grant=grant, effect_context=env if effect_fds is not None else None)
        return final
    def paths(self):
        return self._lane_binding.paths
    def read_ref(self, cwd, ref, *, effect_fds=None):
        if not ref_name(ref) or self.run(["check-ref-format", ref], cwd, effect_fds=effect_fds).returncode: raise self.services.error("Lane ref observation refused.", code="ref_unreadable")
        result = self.run_checked(["for-each-ref", "--format=%(objectname)%00%(symref)%00%(refname)", ref],
                                  cwd, stdout_limit=65536, effect_fds=effect_fds)
        for line in result.stdout.splitlines():
            fields = line.split(b"\0")
            if len(fields) != 3 or fields[1] or not full_oid(fields[0].decode("ascii", "replace")): raise self.services.error("Lane ref observation refused.", code="ref_unreadable")
            if fields[2] == ref.encode("ascii"): return fields[0].decode("ascii")
        return None
    def private_object_headers(self, cwd, oids, *, env=None, scratch=None):
        return private_headers(cwd, oids, env=env, scratch=scratch, runner=self.run_checked,
            batch=["cat-file", "--batch-check"], custody=None, error=self.services.error, lane=self)
    def read_private_object(self, cwd, oid, *, kind, max_bytes, env=None, scratch=None):
        return private_object(cwd, oid, kind=kind, max_bytes=max_bytes, env=env, scratch=scratch,
            headers=self.private_object_headers, runner=self.run_checked, custody=None, error=self.services.error, lane=self)
    def read_private_objects(self, cwd, oids, *, max_bytes, max_object_bytes, env=None, scratch=None):
        return private_objects(cwd, oids, max_bytes=max_bytes, max_object_bytes=max_object_bytes,
            env=env, scratch=scratch, headers=self.private_object_headers, runner=self.run_checked,
            batch=["cat-file", "--batch"], custody=None, error=self.services.error, lane=self)
    def publish(self, pack, *, shared=False, effect_fds=None):
        if type(shared) is not bool: strict_refuse()
        args, policy = ("unpack-objects", "-q", "--strict"), self.policy()
        argv = tuple(_argv(args, self._lane_binding.program, DEFAULT_HARDENING, policy))
        return capture(argv, cwd=self.cwd, env=self.environment(args=args, shared=shared), stdin=pack, timeout=60,
            error=self.services.error, _lane=self, _policy=policy, _grant=(argv, str(self.cwd), pack) if shared else None, effect_fds=self.effect_fds if effect_fds is None else effect_fds, worktree_root=self._lane_binding.worktree_root, write_roots=self._lane_binding.write_roots)
    def cas(self, ref, new, old, *, effect_fds=None):
        if not ref_name(ref) or not ref.startswith(("refs/aegis/", "refs/heads/lane/")): raise self.services.error("ref not allowed", code="ref_not_allowed")
        if not full_oid(new) or old is not None and not full_oid(old): raise self.services.error("invalid ref object", code="invalid_oid")
        current = self.read_ref(self.cwd, ref, effect_fds=effect_fds)
        if current != old and current != new: raise self.services.conflict("ref compare-and-swap mismatch", ref=ref, expected=old, current=current)
        for oid in (new,) if old is None else (new, old):
            result = self.run(["cat-file", "-t", oid], stdout_limit=16, effect_fds=effect_fds)
            if result.returncode or result.stdout != b"commit\n": raise self.services.error("invalid ref object", code="invalid_object")
        if old is not None:
            result = self.run(["merge-base", "--is-ancestor", old, new], stdout_limit=16, effect_fds=effect_fds)
            if result.returncode: raise self.services.error("ref ancestry refused", code="not_fast_forward" if result.returncode == 1 else "git_failed")
        if current == new: return "already"
        command = (b"create " if old is None else b"update ") + ref.encode("ascii") + b"\0" + new.encode("ascii") + b"\0"
        if old is not None: command += old.encode("ascii") + b"\0"
        def write(args, cwd, *, stdin):
            policy = self.policy()
            argv = tuple(_argv(["update-ref", "--no-deref", "-z", "--stdin"], self._lane_binding.program, DEFAULT_HARDENING, policy))
            return capture(argv, cwd=self.cwd, env=self.environment(args=("update-ref",), shared=True), stdin=command, timeout=60,
                error=self.services.error, _lane=self, _policy=policy, _grant=(argv, str(self.cwd), command), effect_fds=self.effect_fds if effect_fds is None else effect_fds, worktree_root=self._lane_binding.worktree_root, write_roots=self._lane_binding.write_roots)
        return update_once(self.cwd, ref, new, old, command, runner=write,
            observer=lambda cwd, ref: self.read_ref(cwd, ref, effect_fds=effect_fds), error=self.services.error, conflict=self.services.conflict)
def memo_context():
    """Legacy boolean key, or a private-store-aware key in custody scopes."""
    policy = _CUSTODY.get()
    replacement = _replacement_environment()
    if replacement is not None:
        return (_SCRUB.get(), tuple(sorted(replacement.items())), True, policy.program)
    return (_SCRUB.get(), tuple(sorted(policy.env.items()))) if policy is not None else _SCRUB.get()
def _collect_threaded(process, policy, deadline, error):
    """Blocking Windows pipe readers; a bounded queue applies backpressure."""
    events, stopped = queue.Queue(maxsize=4), Event()
    streams = {process.stdout: (bytearray(), policy.stdout_limit),
               process.stderr: (bytearray(), policy.stderr_limit)}
    pending = set(streams)
    def emit(event):
        while not stopped.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0: return
            try:
                events.put(event, timeout=min(0.05, remaining))
                return
            except queue.Full:
                continue
    def read(stream, cap):
        remaining = cap
        try:
            while not stopped.is_set():
                data = os.read(stream.fileno(), min(_CHUNK, remaining + 1))
                if len(data) > remaining:
                    emit((stream, b"", "git_output_limit"))
                    return
                emit((stream, data, None))
                if not data: return
                remaining -= len(data)
        except (OSError, ValueError):
            emit((stream, b"", "git_failed"))
    workers = []
    try:
        for stream, (_, cap) in streams.items():
            worker = Thread(target=read, args=(stream, cap), daemon=True)
            worker.start()
            workers.append(worker)
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise error("git custody timed out", code="git_timeout")
            try:
                stream, data, failure = events.get(timeout=remaining)
            except queue.Empty:
                raise error("git custody timed out", code="git_timeout") from None
            if failure: raise error("git custody pipe failed", code=failure)
            if data:
                streams[stream][0].extend(data)
            else:
                pending.remove(stream)
        return bytes(streams[process.stdout][0]), bytes(streams[process.stderr][0])
    finally:
        stopped.set()
        failed = _finish(process, stop=True) if pending else False
        for worker in workers:
            worker.join(timeout=1)
            failed |= worker.is_alive()
        if failed: raise error("git custody cleanup failed", code="git_cleanup_failed")
def _collect(process, policy, deadline, error):
    if os.name == "nt": return _collect_threaded(process, policy, deadline, error)
    streams = {process.stdout: (bytearray(), policy.stdout_limit),
               process.stderr: (bytearray(), policy.stderr_limit)}
    pending = set(streams)
    while pending:
        if time.monotonic() >= deadline: raise error("git custody timed out", code="git_timeout")
        ready = select.select(list(pending), [], [], max(0, deadline - time.monotonic()))[0]
        for stream in ready:
            target, cap = streams[stream]
            # At the ceiling, read only one sentinel byte to distinguish EOF
            # from overflow; never allocate a whole chunk beyond the allowance.
            data = os.read(stream.fileno(), min(_CHUNK, cap - len(target) + 1))
            if not data:
                pending.remove(stream)
            elif len(data) > cap - len(target):
                raise error("git custody output limit exceeded", code="git_output_limit")
            else:
                target.extend(data)
    return bytes(streams[process.stdout][0]), bytes(streams[process.stderr][0])
def _finish(process, *, stop):
    failed = False
    try:
        if stop:
            # Kill before reaping: the unreaped child pins its group ID.
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        failed = True
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                failed = True
    return failed
def _capture_limits(policy, timeout, stdin, error):
    if policy is not None and policy.strict_lane and stdin is not None and type(stdin) is not bytes: strict_refuse()
    if (policy is None or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 300 or not math.isfinite(timeout)):
        raise error("invalid custody capture", code="invalid_custody")
    if stdin is not None and (not isinstance(stdin, bytes) or len(stdin) > _MAX_INPUT): raise error("git custody input limit exceeded", code="git_input_limit")
def capture(argv, *, cwd, env, stdin, timeout, error=GitError, _lane=None, _policy=None, _grant=None, effect_fds=None, _tty=False, write_roots=(), worktree_root=None):
    replacement = _replacement_environment(env, allow=effect_fds is None and _lane is None and _policy is None, error=error)
    policy = _CUSTODY.get() if _policy is None else _policy
    error = _lane.services.error if _lane is not None else (GitError if policy is not None and policy.strict_lane else error)
    source_envelope = type(env) is Environment
    if policy is not None and policy.strict_lane and _lane is None:
        argv = bounded_args(argv)
        _command(argv, cwd, stdin, _grant)
        if not source_envelope: env = environment_layer(strict_environment(env, environ_type=_ENVIRON_TYPE), allowed=None, error=error, code="git_custody_refused", environ_type=_ENVIRON_TYPE)
    if effect_fds is not None:
        from aegis_core import gitops_fds
        if _lane is not None and _lane._lane_binding.worktree_root is None: gitops_fds.refuse(error, "effect_environment_unavailable")
        argv, env, effect_kw, _lane, _grant = gitops_fds.prepare_capture(argv, env, stdin, timeout, effect_fds, error=error, strict=policy is not None and policy.strict_lane, cwd=cwd, worktree_root=_lane._lane_binding.worktree_root if _lane is not None else worktree_root, custody_root=policy.worktree_root if policy is not None else None, expected_dirs=(_lane._lane_binding.base["GIT_DIR"], str(_lane.paths()[0])) if _lane is not None else None, lane=_lane, grant=_grant, bind=lambda program, values: replace(_lane, _lane_binding=replace(_lane._lane_binding, program=program, effect_environment=values), effect_fds=effect_fds), base=BASE_ENV, roots=gitops_fds.bounded_roots(_lane._lane_binding.write_roots if _lane is not None else write_roots, scratch=policy.scratch if policy is not None else None, error=error), scope=policy.env if policy is not None and (_policy is None or not source_envelope) else None, transport=transport_services(), kind=policy.boundary if policy is not None else "git")
    process, discovery_started, effect_deadline = None, False, time.monotonic() + timeout if effect_fds is not None else None
    try:
        if _lane is not None or policy is not None and policy.strict_lane:
            argv = bounded_args(argv)
            if effect_fds is None and _lane is not None and _lane._lane_binding.ambient: request_environment(profile="strict/effect", root=env.root, error=error)
            env = request_environment(env, profile="strict/effect", root=worktree_root or policy.worktree_root or cwd, roots=(*write_roots, policy.scratch), kind=policy.boundary, scope=policy.env if policy is not None and (_policy is None or not source_envelope) else None, error=error)
            cwd = strict_root(cwd)
            if policy is not None and policy.strict_lane and classify_ambient(policy.env, environ_type=_ENVIRON_TYPE)[1] is not None: strict_refuse()
            if _lane is None:
                services = policy.services
                if services is None or not argv or argv[0] != services.program(cwd, environ=env): strict_refuse()
                args, _ = _command(argv, cwd, stdin, _grant)
        if not isinstance(env, Environment):
            env = request_environment(env, profile="ordinary", base={} if replacement is None else None)
        elif effect_fds is None and not (_lane is not None or policy is not None and policy.strict_lane): env = request_environment(env, profile="strict/effect", kind=policy.boundary if policy is not None else "git", error=error)
        _capture_limits(policy, timeout, stdin, error)
        if _lane is None and policy.strict_lane:
            _lane = issue_runner(cwd, policy.scratch, services, effect_fds, environ=env,
                worktree_root=worktree_root or policy.worktree_root, write_roots=write_roots)
            if not source_envelope: env = _lane.environment(args=args, effect_context=env)
        if _lane is not None: argv = _lane.validate(argv, cwd, env, stdin, _grant, effect_fds=effect_fds, timeout=timeout if effect_fds is not None else 60)
        argv, env, discovery_started, ssh_index = gitops_fds.capture_recipe(argv, env, effect_fds, error=error, cwd=cwd, timeout=timeout, observe=capture, scope=custody, transport=transport_services()) if effect_fds is not None else (argv, env, False, None)
        deadline = effect_deadline if effect_fds is not None else time.monotonic() + timeout
        with ExitStack() as stack:
            source = None if _tty else subprocess.DEVNULL
            if stdin is not None:
                source = stack.enter_context(tempfile.TemporaryFile(dir=policy.scratch))
                for start in range(0, len(stdin), _CHUNK):
                    if time.monotonic() >= deadline: raise error("git custody timed out", code="git_timeout")
                    source.write(memoryview(stdin)[start:start + _CHUNK])
                source.seek(0)
            if time.monotonic() >= deadline: raise error("git custody timed out", code="git_timeout")
            options = dict(cwd=str(cwd), env=env, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name == "posix")
            launch, options, bind = stack.enter_context(gitops_fds.holder_recipe(argv, {**options, **effect_kw}, max(0, deadline - time.monotonic()), error=error, timeout_error=subprocess.TimeoutExpired, transport=transport_services(), ssh_index=ssh_index)) if effect_fds is not None else (argv, options, lambda p: p)
            if effect_fds is None and type(env) is Environment: options["executable"] = find_executable({}, env, lambda effective: argv[0], error=error, stack=stack)
            process = bind(subprocess.Popen(launch, **options))
            stdout, stderr = _collect(process, policy, deadline, error)
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
            return gitops_fds.git_result(subprocess.CompletedProcess(argv, code, stdout, stderr), result_type=subprocess.CompletedProcess, process=process) if effect_fds is not None else subprocess.CompletedProcess(argv, code, stdout, stderr)
    except error as exc:
        if effect_fds is not None: exc.effect_process_started = getattr(exc, "effect_process_started", False) or gitops_fds.effect_started(process)
        exc.process_started = (getattr(exc, "process_started", False) if effect_fds is not None else False) or (gitops_fds.effect_started(process) if effect_fds is not None else process is not None) or discovery_started
        raise
    except subprocess.TimeoutExpired:
        raise error("git custody timed out", code="git_timeout", process_started=(gitops_fds.effect_started(process) if effect_fds is not None else process is not None) or discovery_started, **({"effect_process_started": gitops_fds.effect_started(process)} if effect_fds is not None else {})) from None
    except (OSError, ValueError, RuntimeError):
        raise error("git custody transport failed", code="git_failed", process_started=(gitops_fds.effect_started(process) if effect_fds is not None else process is not None) or discovery_started, **({"effect_process_started": gitops_fds.effect_started(process)} if effect_fds is not None else {})) from None
    finally:
        if process is not None:
            if (gitops_fds.cleanup_holder(process) if effect_fds is not None else _finish(process, stop=process.returncode is None)): raise error("git custody cleanup failed", code="git_cleanup_failed", process_started=True) from None
def execute(args, cwd, *, executable, legacy_runner, error, environ, timeout, stdin, hardening, env, tty,
            legacy_namespace=None, effect_fds=None, write_roots=(), worktree_root=None):
    policy = _CUSTODY.get()
    replacement = _replacement_environment(environ, allow=effect_fds is None and env is None, error=error)
    if effect_fds is not None:
        from aegis_core import gitops_fds
        gitops_fds.pass_through(effect_fds, error=error)
        gitops_fds.effect_inputs(args, stdin, timeout, effect_fds, error=error, hardening=hardening)
        return gitops_fds.execute_effect(args, cwd, environ, env, hardening, _CUSTODY.get(), timeout, stdin, tty, effect_fds,
            error=error, observe=capture, scope=custody, build=_argv, base=BASE_ENV, resolver=executable, issue=issue_runner, identity=lambda values, command: identity_environment(values, command, environ_type=_ENVIRON_TYPE), write_roots=write_roots, worktree_root=worktree_root, preflight=lambda argv: _command(argv, cwd, stdin) if tty is False and tuple(hardening) == DEFAULT_HARDENING and len(args) <= 450 else strict_refuse(), transport=transport_services())
    if strict_active():
        services = policy.services
        if services is None or executable is not services.executable: strict_refuse()
        args, hardening, cwd = bounded_args(args), bounded_args(hardening), strict_root(cwd)
        if hardening != DEFAULT_HARDENING or tty is not False or len(args) > 450: strict_refuse()
        _command(_argv(args, "git", hardening, policy), cwd, stdin)
        supplied = identity_environment({**policy.env, **({} if env is None else strict_environment(env, 6, environ_type=_ENVIRON_TYPE))}, args, environ_type=_ENVIRON_TYPE)
        effective = request_environment(environ, profile="strict/effect", kind="lane", root=worktree_root or policy.worktree_root or cwd,
            roots=(*write_roots, policy.scratch), scope=policy.env, overrides=env, error=error)
        _capture_limits(policy, timeout, stdin, GitError)
        return issue_runner(cwd, policy.scratch, services, effect_fds, environ=effective, worktree_root=worktree_root or policy.worktree_root, write_roots=write_roots).run(args, cwd, timeout, stdin, hardening,
            supplied, tty, stdout_limit=policy.stdout_limit, stderr_limit=policy.stderr_limit, effect_fds=effect_fds)
    argv = _argv(args, executable(), hardening, policy)
    if replacement is not None:
        return capture(argv, cwd=cwd, env=None, stdin=stdin, timeout=timeout, error=error)
    namespace = subprocess if legacy_namespace is None else legacy_namespace
    scrub = _SCRUB.get()
    effective = request_environment(environ, profile="ordinary", scrub=scrub, overrides=env,
                                    scope=policy.env if policy is not None else None)
    if policy is not None: return capture(argv, cwd=cwd, env=effective, stdin=stdin, timeout=timeout, error=error)
    try:
        return legacy_runner(argv, cwd=str(cwd), env=effective, input=stdin,
                             stdin=None if stdin is not None or tty else namespace.DEVNULL,
                             capture_output=True, timeout=timeout, check=False)
    except namespace.TimeoutExpired as exc:
        raise error(f"git {args[0] if args else ''} timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise error(f"cannot run git: {exc}") from exc

def checked(args, cwd, *, runner, error, git_error, timeout, stdin):
    """Legacy conversion by default; custody retains the original typed refusal."""
    lane = getattr(runner, "__self__", None)
    scoped = isinstance(lane, LaneRunner) or custody_active()
    git_error = lane.services.error if isinstance(lane, LaneRunner) else git_error
    try:
        res = runner(args, cwd, timeout=timeout, stdin=stdin)
    except git_error as exc:
        if scoped: raise
        raise error(str(exc)) from exc
    if res.returncode != 0:
        if scoped: raise git_error("git custody command failed", code="git_failed", returncode=res.returncode)
        raise error(f"git {args[0]} failed: {' '.join(res.stderr.decode('utf-8', 'replace').split())[:200]}")
    return res

def completed(args, cwd, *, runner, error, **kwargs):
    """Legacy query fallback, with refusals preserved in opt-in custody mode."""
    lane = getattr(runner, "__self__", None)
    scoped = isinstance(lane, LaneRunner) or custody_active()
    error = lane.services.error if isinstance(lane, LaneRunner) else error
    try:
        result = runner(args, cwd, **kwargs)
        if scoped and result.returncode not in (0, 1): raise error("git custody command failed", code="git_failed", returncode=result.returncode)
        return result
    except error:
        if scoped: raise
        return None

def query_result(result, *, error):
    """A custody query's exit 3 or other failure cannot become a missing answer."""
    if custody_active() and result.returncode not in (0, 1): raise error("git custody command failed", code="git_failed", returncode=result.returncode)
    return result

def output(args, cwd, *, completed, **kwargs):
    result = completed(args, cwd, **kwargs)
    return result.stdout if result is not None and result.returncode == 0 else None

def path_text(out, *, gitfile=False, record=False):
    """Decode on first use without adding the codec to ordinary hook imports."""
    from aegis_core.git_path_codec import path_text as decode_path

    return decode_path(out, gitfile=gitfile, record=record)

def text(args, cwd, *, output, **kwargs):
    out = output(args, cwd, **kwargs)
    if out is None: return None
    if len(args) > 1 and args[0] == "rev-parse" and args[1] in (
            "--git-path", "--git-dir", "--absolute-git-dir", "--git-common-dir", "--show-prefix", "--show-toplevel"):
        return path_text(out)
    value = os.fsdecode(out.strip())
    return value or None


@dataclass(frozen=True)
class _RefUpdateFailure:
    definite: bool
    cause: tuple[Optional[int], Optional[int]]


def update_once(cwd, ref, new, old, command, *, runner, observer, error, conflict):
    """Execute one prevalidated ref transaction and classify its acknowledgment.

    gitsafe.update_ref validates the name/OIDs and constructs command before
    calling this transport helper. Post-spawn output/cleanup errors can lose the
    acknowledgment. Preflight refusals retain their code; a definite rejection
    with the old value intact is explicitly retriable by the caller.
    """
    # Keep snapshot helpers off the ordinary Git import path.
    from aegis_core.team_git_snapshot import failure_observation

    ambient = exc_info()[1]
    try:
        result = runner(["update-ref", "--no-deref", "-z", "--stdin"], cwd, stdin=command)
    except error as exc:
        if exc.code not in ("git_timeout", "git_failed", "ERR_AEGIS", "git_cleanup_failed", "git_output_limit"): raise
        definite = exc.code == "git_failed" and getattr(exc, "effect_process_started", getattr(exc, "process_started", None)) is False
        failure = _RefUpdateFailure(definite, failure_observation(exc, ambient))
    else:
        if result is not None and result.returncode == 0: return "updated"
        failure = _RefUpdateFailure(True, failure_observation(result))
        del result
    current = observer(cwd, ref)
    if current == new: return "already"
    if current != old: raise conflict("ref compare-and-swap mismatch", ref=ref, expected=old, current=current)
    os_errno, status = failure.cause
    if failure.definite:
        raise error("ref update failed", code="ref_update_failed", errno=os_errno, returncode=status)
    raise error("ref update outcome unknown", code="ref_update_unknown", errno=os_errno, returncode=status)

def validate_update_input(single_attempt, new, old, *, error):
    """Original public update_ref validation; strict mode has a fixed refusal."""
    if not isinstance(single_attempt, bool): raise error("invalid single-attempt option", code="invalid_custody")
    if new is None and old is None:
        if strict_active(): strict_refuse()
        raise ValueError("update_ref needs a new value, an expected old value, or both")

def lane_update_ref(cwd, ref, new, old):
    """Compatibility entry for the facade's existing explicit strict scopes."""
    policy = _CUSTODY.get()
    services = None if policy is None else policy.services
    if policy is None or not policy.strict_lane or services is None: strict_refuse()
    runner = issue_runner(cwd, policy.scratch, services)
    return runner.cas(ref, new, old)
