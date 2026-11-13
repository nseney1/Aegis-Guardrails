"""Git transport: legacy defaults and strict runners issued only by the facade."""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import contextvars
from dataclasses import dataclass
import math
import os
import re
from pathlib import Path
import select
import queue
from threading import Event, Thread
import signal
import subprocess
import tempfile
import time
from types import MappingProxyType
from typing import Mapping, Optional

from aegis_core.errors import AegisError
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text

__all__ = ["BASE_ENV", "DEFAULT_HARDENING", "HARDENING_KEEP_HOOKS_PATH", "LOCAL_ENV",
           "capture", "checked", "completed", "custody", "custody_active",
           "execute", "memo_context", "output", "query_result",
           "private_headers", "private_object", "private_objects", "scrubbed", "text", "update_once",
           "strict_active", "lane_update_ref", "validate_update_input", "find_executable", "git_path",
           "LaneRunner", "hashed_blob", "check_ref_name", "CustodyRefusal"]

HARDENING_KEEP_HOOKS_PATH = (
    "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
    "-c", "core.sshCommand=false", "-c", "credential.helper=",
    "-c", "log.showSignature=false", "-c", f"gpg.program={os.devnull}",
    "-c", f"gpg.openpgp.program={os.devnull}", "-c", f"gpg.x509.program={os.devnull}",
)
DEFAULT_HARDENING = ("-c", f"core.hooksPath={os.devnull}", *HARDENING_KEEP_HOOKS_PATH)
BASE_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ALLOW_PROTOCOL": "", "GIT_NO_LAZY_FETCH": "1", "LC_ALL": "C"}
LOCAL_ENV = frozenset((
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX", "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
))
_SCRUB = contextvars.ContextVar("aegis_git_scrub", default=False)
_CUSTODY = contextvars.ContextVar("aegis_git_custody", default=None)
_MAX_CAPTURE = 128 * 1024 * 1024
_MAX_INPUT = 128 * 1024 * 1024
_CHUNK = 65536


class GitError(AegisError):
    """The facade's error hierarchy, shared before any runner can be issued."""
    __module__ = "aegis_core.gitsafe"

CustodyRefusal = GitError


@dataclass(frozen=True)
class _LaneServices:
    program: object
    error: object
    conflict: object
    executable: object


def find_executable(cache, environ, lookup, *, error):
    """Original PATH-keyed cache validation; the facade still owns PATH lookup."""
    key = (environ.get("PATH"), environ.get("PATHEXT"))
    found = cache.get(key)
    if not (found and os.path.isfile(found) and os.access(found, os.X_OK)):
        cache.clear()
        found = None
    if not found:
        found = lookup()
    if not found:
        raise error("git is not installed or not on PATH")
    cache[key] = found
    return found


def git_path(cwd, name, *, runner, hardening):
    text = runner(["rev-parse", "--git-path", name], cwd, _hardening=hardening)
    if not text:
        return None
    path = Path(text)
    return path if path.is_absolute() else (Path(cwd) / path).resolve()


def hashed_blob(cwd, data, write, *, runner, hasher, error):
    # From stdin with no --path, hash-object applies no attribute, filter or line-ending
    # conversion: the blob is exactly ``data``, named in the repository's hash format.
    args = ["hash-object", *(["-w"] if write else []), "--no-filters", "--stdin"]
    out = runner(args, cwd, stdin=bytes(data))
    oid = (out or b"").strip().decode("ascii", "replace")
    if not _OID.match(oid):
        raise error(f"git hash-object {'-w ' if write else ''}failed in {cwd}")
    if hasher(bytes(data), len(oid)) != oid:
        raise error(f"git named the blob {oid}, which does not hash its content")
    return oid


def check_ref_name(cwd, ref, what, *, runner, error, ref_error):
    """Extracted legacy grammar/query, preserving argv and error text."""
    ok = isinstance(ref, str) and ref.startswith("refs/") and not any(ch in ref for ch in "\0\n\r")
    if ok:
        res = runner(["check-ref-format", ref], cwd)
        if res is None:
            raise error(f"git cannot check the {what} {ref!r}")
        ok = res.returncode == 0
    if not ok:
        raise ref_error(f"invalid {what}: {ref!r}")
    return ref


@dataclass(frozen=True)
class _Policy:
    scratch: Path
    env: Mapping[str, str]
    stdout_limit: int
    stderr_limit: int
    strict_lane: bool
    services: object = None


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
            stdout_limit: int = 16 * 1024 * 1024, stderr_limit: int = 65536, strict_lane: bool = False, _services=None):
    """Bound a dynamic scope to existing owner-controlled scratch; nested scopes replace env."""
    if not isinstance(strict_lane, bool):
        raise AegisError("invalid custody mode", code="invalid_custody")
    strict_lane = strict_lane or strict_active()
    if strict_lane and env is not None:
        env = _strict_environment(env, 64)
    for cap in (stdout_limit, stderr_limit):
        if isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= _MAX_CAPTURE:
            raise AegisError("invalid custody limit", code="invalid_custody")
    if not isinstance(scratch, (str, Path)) or not str(scratch) or len(str(scratch)) > 16384 or "\0" in str(scratch):
        raise AegisError("invalid custody scratch", code="invalid_custody")
    path = Path(scratch)
    if not path.is_absolute() or ".." in path.parts:
        raise AegisError("invalid custody scratch", code="invalid_custody")
    if env is not None and (not isinstance(env, Mapping) or len(env) > 64):
        raise AegisError("invalid custody environment", code="invalid_custody")
    copied = {}
    for key, value in (env or {}).items():
        if (not isinstance(key, str) or not isinstance(value, str) or len(key) > 128 or len(value) > 65536
                or "\0" in key or "\0" in value or "=" in key):
            raise AegisError("invalid custody environment", code="invalid_custody")
        copied[key] = value
    token = _CUSTODY.set(_Policy(path, MappingProxyType(copied), stdout_limit, stderr_limit, strict_lane, _services))
    try:
        with scrubbed():
            yield
    finally:
        _CUSTODY.reset(token)


def custody_active() -> bool:
    return _CUSTODY.get() is not None


def strict_active() -> bool:
    policy = _CUSTODY.get()
    return policy is not None and policy.strict_lane


_LANE_OPTIONS = ("-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "core.splitIndex=false",
                 "-c", "core.untrackedCache=false", "-c", "core.sparseCheckout=false",
                 "-c", "merge.renormalize=false", "-c", "commit.gpgsign=false")
_FIXED_CONFIG = frozenset((*DEFAULT_HARDENING[1::2], *_LANE_OPTIONS[1::2], "core.safecrlf=false"))
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_READ_SHAPES = frozenset((
    ("version",), ("read-tree", "--empty"), ("write-tree",),
    ("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
    ("update-index", "-z", "--index-info"),
    ("ls-files", "--stage", "--debug", "-z"),
    ("pack-objects", "--stdout"), ("unpack-objects", "-q", "--strict"),
    ("cat-file", "--batch"), ("cat-file", "--batch-check"),
    ("rev-parse", "--verify", "--quiet", "HEAD"), ("rev-parse", "--show-object-format"),
    ("rev-parse", "--git-path", "index"),
    ("rev-parse", "--git-common-dir", "--show-prefix", "--is-shallow-repository", "--show-toplevel"),
    *(("rev-parse", option) for option in ("--git-common-dir", "--show-prefix", "--show-toplevel")),
    ("check-attr", "-z", "--stdin", "filter", "text", "eol", "ident", "working-tree-encoding", "crlf"),
    ("config", "--null", "--get-regexp", r"^core\.(autocrlf|safecrlf|filemode|symlinks|eol|trustctime|checkstat)$"),
    ("config", "--null", "--name-only", "--get-regexp", r"^filter\."),
    ("config", "--show-scope", "--null", "--name-only", "--get-regexp", r"^merge\..+\.driver$"),
))

def _strict_refuse():
    raise CustodyRefusal("Strict lane Git command refused.", code="git_custody_refused",
        next_action="Use the lane Git APIs or the CAS fast-forward writer.", process_started=False)

def _bounded_args(args):
    from itertools import islice
    if type(args) not in (tuple, list) or len(args) > 512:
        _strict_refuse()
    frozen = args if type(args) is tuple else tuple(islice(args, 513))
    if len(frozen) > 512 or any(type(a) is not str or len(a) > 16384 or "\0" in a for a in frozen):
        _strict_refuse()
    return frozen

def _strict_root(cwd):
    if type(cwd) not in (str, type(Path())):
        _strict_refuse()
    text = str(cwd)
    if len(text) > 16384 or "\0" in text or not os.path.isabs(text) or ".." in Path(text).parts:
        _strict_refuse()
    return text

def _strict_environment(env, limit=512):
    frozen, refusal = _classify_ambient(env, limit=limit, refuse_keys=False)
    if refusal is not None:
        _strict_refuse()
    return frozen

def _full_oid(value):
    return type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value) is not None

def _ref_name(value):
    return (type(value) is str and len(value) <= 240 and value.startswith("refs/")
            and not any(ord(c) < 33 or ord(c) > 126 or c in "~^:?*[\\" for c in value)
            and ".." not in value and "@{" not in value
            and all(p and not p.startswith(".") and not p.endswith((".", ".lock")) for p in value.split("/")))

def _literal_path(value):
    if value.startswith(":(literal)"):
        value = value[len(":(literal)"):]
    return (bool(value) and not value.startswith("/") and len(value) <= 4096
            and all(p not in ("", ".", "..", ".git") for p in value.split("/")))

def _read_shape(args):
    if args in _READ_SHAPES:
        return True
    if len(args) == 2 and args[0] == "read-tree":
        return _full_oid(args[1])
    if len(args) == 2 and args[0] == "check-ref-format":
        return _ref_name(args[1])
    if len(args) == 3 and args[0] == "cat-file" and args[1] in ("blob", "tree", "commit", "-t"):
        return _full_oid(args[2])
    if len(args) == 3 and args[:2] == ("for-each-ref", "--format=%(objectname)%00%(symref)%00%(refname)"):
        return _ref_name(args[2])
    if len(args) == 4 and args[:2] == ("merge-base", "--is-ancestor"):
        return all(_full_oid(x) for x in args[2:])
    if args[:1] == ("ls-tree",):
        if len(args) == 3 and args[1] == "-r":
            return _full_oid(args[2])
        rest = args[2:] if args[1:2] == ("-z",) else args[1:]
        return len(rest) == 3 and _full_oid(rest[0]) and rest[1] == "--" and _literal_path(rest[2])
    if args[:1] == ("hash-object",):
        return (len(args) == 4 and args[1:3] == ("-w", "--stdin")
                and args[3].startswith("--path=") and _literal_path(args[3][7:]))
    if args[:1] == ("commit-tree",):
        return (4 <= len(args) <= 18 and len(args) % 2 == 0 and _full_oid(args[1])
                and all(args[i] == "-p" and _full_oid(args[i + 1]) for i in range(2, len(args), 2)))
    if args[:3] == ("rev-list", "--objects", "--no-object-names"):
        return len(args) == 6 and _full_oid(args[3]) and args[4:] == ("--not", "--all")
    if args[:4] == ("rev-list", "--reverse", "--topo-order", "--no-merges"):
        return len(args) == 5 and len(args[4].split("..")) == 2 and all(_full_oid(x) for x in args[4].split(".."))
    if args[:4] == ("merge-tree", "--write-tree", "--name-only", "-z"):
        rest = args[4:]
        if rest and rest[0].startswith("--merge-base="):
            if not _full_oid(rest[0][13:]):
                return False
            rest = rest[1:]
        return len(rest) == 2 and all(_full_oid(x) for x in rest)
    return False

def _command(argv, cwd, stdin, grant=None):
    """Prove the closed command grammar before repository discovery can spawn."""
    position, pairs = 1, set()
    while position + 1 < len(argv) and argv[position] == "-c":
        pair = argv[position + 1]
        if pair not in _FIXED_CONFIG and not re.fullmatch(r"filter\.[A-Za-z0-9_.-]+\.(?:(?:clean|smudge|process)=|required=false)", pair):
            _strict_refuse()
        pairs.add(pair)
        position += 2
    if not set((*DEFAULT_HARDENING[1::2], *_LANE_OPTIONS[1::2])) <= pairs:
        _strict_refuse()
    args = tuple(argv[position:])
    if args == ("update-ref", "--no-deref", "-z", "--stdin"):
        if grant != (tuple(argv), str(cwd), stdin):
            _strict_refuse()
    elif not _read_shape(args):
        _strict_refuse()
    return args, pairs

def _strict_argv(argv, cwd, env, stdin, *, lane, grant=None):
    _bounded_args(argv)
    if _strict_root(cwd) != _strict_root(lane.cwd) or not argv or argv[0] != lane._lane_binding.program:
        _strict_refuse()
    args, pairs = _command(argv, cwd, stdin, grant)
    shared = args[0] in ("update-ref", "unpack-objects") and grant == (tuple(argv), str(cwd), stdin) if args else False
    real_index = args[0] in ("ls-files", "check-attr") and env.get("GIT_INDEX_FILE") == str(lane._lane_binding.paths[2])
    identity = {k: v for k, v in env.items() if k in _IDENTITY_ENV}
    if "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in env:
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = lane.environment()["GIT_ALTERNATE_OBJECT_DIRECTORIES"]
    if env != lane.environment(identity, args=args, real_index=bool(real_index), shared=shared):
        _strict_refuse()
    return args, pairs

def _argv(args, program, hardening, policy):
    argv = [program, *hardening, *args]
    if policy is not None:
        position = len(hardening) + 1
        while position + 1 < len(argv) and argv[position] == "-c":
            position += 2
        extra = _LANE_OPTIONS if policy.strict_lane else ("-c", "gc.auto=0", "-c", "maintenance.auto=false")
        argv[position:position] = ["-c", f"core.hooksPath={os.devnull}", *extra]
    return argv


_OS_ENV = frozenset(("PATH", "PATHEXT", "HOME", "XDG_CONFIG_HOME", "USERPROFILE", "SYSTEMROOT",
                     "SystemRoot", "WINDIR", "TMPDIR", "TMP", "TEMP"))
_IDENTITY_ENV = frozenset("GIT_" + role + "_" + field for role in ("AUTHOR", "COMMITTER")
                          for field in ("NAME", "EMAIL", "DATE"))
_AMBIENT_REDIRECTS = LOCAL_ENV - {"GIT_NO_REPLACE_OBJECTS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"}
_ENVIRON_TYPE = type(os.environ)

def _classify_ambient(env, *, limit=512, refuse_keys=True):
    """Pure bounded snapshot and deterministic refusal; values never enter diagnostics."""
    from itertools import islice
    if type(env) not in (dict, MappingProxyType, _ENVIRON_TYPE):
        return {}, ("git_custody_refused", "Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")
    if len(env) > limit:
        return {}, ("ambient_environment_too_large", "Ambient environment has too many variables.", "Reduce the environment to at most 512 variables, then retry.")
    try:
        frozen = dict(islice(env.items(), limit + 1))
    except (KeyError, RuntimeError):
        return {}, ("ambient_environment_changed", "Ambient environment changed during inspection.", "Stabilize the environment, then retry.")
    if len(frozen) > limit:
        return {}, ("ambient_environment_too_large", "Ambient environment has too many variables.", "Reduce the environment to at most 512 variables, then retry.")
    if any(type(k) is not str or type(v) is not str for k, v in frozen.items()):
        return {}, ("git_custody_refused", "Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")
    if any(len(key) > 256 for key in frozen):
        return {}, ("ambient_environment_too_large", "Ambient environment variable name exceeds its limit.", "Shorten every environment variable name to at most 256 characters, then retry.")
    if any(len(value) > 65536 for value in frozen.values()):
        return {}, ("ambient_environment_too_large", "Ambient environment value exceeds its limit.", "Reduce every environment value to at most 65,536 characters, then retry.")
    if any("\0" in key or "\0" in value for key, value in frozen.items()):
        return {}, ("git_custody_refused", "Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")
    names = sorted(key for key in frozen if refuse_keys and (key.upper().startswith("GIT_TRACE") or key.upper() in _AMBIENT_REDIRECTS))
    if not names:
        return frozen, None
    displayed = []
    for key in names:
        canonical = sanitize_display(key, max_len=None)
        shown = sanitize_display(redact_insight_text(canonical, max_len=max(1, len(canonical))), max_len=256)
        displayed.append("GIT_TRACE* (" + shown + ")" if key.upper().startswith("GIT_TRACE") and key.upper() not in ("GIT_TRACE", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF") else shown)
    label = ", ".join(displayed)
    return {}, ("ambient_git_environment", "Ambient Git environment refused: " + label + ".", "Unset " + label + " in the environment, then retry.")

def _ambient_environment():
    frozen, refusal = _classify_ambient(os.environ)
    if refusal is not None:
        code, message, action = refusal
        raise CustodyRefusal(message, code=code, next_action=action, process_started=False)
    return frozen

def _identity_environment(env, args):
    supplied = {} if env is None else _strict_environment(env, 6)
    if supplied and (not args or args[0] != "commit-tree" or set(supplied) != _IDENTITY_ENV):
        _strict_refuse()
    for key, value in supplied.items():
        if (not value or len(value) > 256 or any(ord(c) < 32 or 127 <= ord(c) < 160
                or 0xD800 <= ord(c) <= 0xDFFF or c in "<>\u2028\u2029" for c in value)
                or key.endswith("DATE") and not re.fullmatch(r"[0-9]{1,12} [+-](?:[01][0-9]|2[0-3])[0-5][0-9]", value)):
            _strict_refuse()
    return supplied


@dataclass(frozen=True)
class _LaneBinding:
    cwd: Path
    scratch: Path
    services: _LaneServices
    base: object
    paths: object
    program: str
    read_objects: str


def issue_runner(cwd, scratch, services):
    cwd, scratch = Path(_strict_root(cwd)), Path(_strict_root(scratch))
    base = {k: v for k, v in _ambient_environment().items() if k in _OS_ENV}
    program, values = services.program(cwd), []
    if type(program) is not str or not program:
        _strict_refuse()
    policy = _Policy(scratch, MappingProxyType({}), 16384, 65536, False)
    try:
        for args in (("--absolute-git-dir",), ("--git-common-dir",), ("--show-toplevel",), ("--git-path", "index")):
            result = capture((program, *DEFAULT_HARDENING, *_LANE_OPTIONS, "rev-parse", *args), cwd=cwd,
                env={**base, **BASE_ENV}, stdin=None, timeout=60, error=services.error, _policy=policy)
            raw = result.stdout.rstrip(b"\r\n")
            if result.returncode or not raw or b"\0" in raw or b"\n" in raw or b"\r" in raw:
                raise services.error("Lane repository discovery refused.", code="invalid_repository")
            path = Path(os.fsdecode(raw))
            values.append((path if path.is_absolute() else cwd / path).resolve())
        git_dir, common, top, index = values
        resolved = scratch.resolve()
        if resolved.is_relative_to(common) or resolved.is_relative_to(top):
            raise services.error("Lane scratch refused.", code="unsafe_scratch")
        alternate = os.fsencode(str(common / "objects"))
        if len(alternate) > 16383:
            _strict_refuse()
        base.update(BASE_ENV, GIT_DIR=str(git_dir), GIT_COMMON_DIR=str(common), GIT_WORK_TREE=str(top),
            GIT_OBJECT_DIRECTORY=str(scratch / "objects"), GIT_INDEX_FILE=str(scratch / "index"),
            GIT_ALTERNATE_OBJECT_DIRECTORIES='"' + ''.join('\\%03o' % c for c in alternate) + '"')
        read_objects = str(scratch / "objects") if (scratch / "objects").is_dir() else str(common / "objects")
        binding = _LaneBinding(cwd, scratch, services, MappingProxyType(base), (common, top, index), program, read_objects)
        return LaneRunner(cwd, scratch, services, binding)
    except (OSError, ValueError, RuntimeError):
        raise services.error("Lane repository discovery failed.", code="git_failed", process_started=False) from None


@dataclass(frozen=True)
class LaneRunner:
    """Explicit, transferable lane capability; no method reads ambient custody."""
    cwd: Path
    scratch: Path
    services: _LaneServices
    _lane_binding: _LaneBinding

    def __post_init__(self):
        error = self._lane_binding.services.error if type(self._lane_binding) is _LaneBinding else CustodyRefusal
        if (type(self._lane_binding) is not _LaneBinding or self.cwd is not self._lane_binding.cwd
                or self.scratch is not self._lane_binding.scratch or self.services is not self._lane_binding.services):
            raise error("Strict lane Git command refused.", code="git_custody_refused", process_started=False)

    def environment(self, env=None, *, args=(), real_index=False, shared=False):
        supplied = _identity_environment(env, args)
        if real_index and tuple(args) not in _READ_SHAPES or real_index and args[0] not in ("ls-files", "check-attr"):
            _strict_refuse()
        effective = {**self._lane_binding.base, **supplied}
        if shared:
            effective["GIT_OBJECT_DIRECTORY"] = str(self._lane_binding.paths[0] / "objects")
        if real_index:
            effective["GIT_INDEX_FILE"] = str(self._lane_binding.paths[2])
        if tuple(args) == ("rev-parse", "--git-path", "index"):
            effective.pop("GIT_INDEX_FILE")
        if args and args[0] not in ("hash-object", "merge-tree", "commit-tree", "unpack-objects", "read-tree", "update-index", "write-tree") and not shared:
            effective["GIT_OBJECT_DIRECTORY"] = self._lane_binding.read_objects
        return effective

    def policy(self, stdout_limit=16 * 1024 * 1024, stderr_limit=65536):
        if any(type(cap) is not int or not 0 <= cap <= _MAX_CAPTURE for cap in (stdout_limit, stderr_limit)):
            raise self.services.error("invalid custody limit", code="invalid_custody")
        return _Policy(Path(self.scratch), MappingProxyType({}), stdout_limit, stderr_limit, True)

    def run(self, args, cwd=None, timeout=60, stdin=None, _hardening=DEFAULT_HARDENING,
            _env=None, tty=False, *, stdout_limit=16 * 1024 * 1024, stderr_limit=65536, options=(), real_index=False):
        if cwd is not None and _strict_root(cwd) != _strict_root(self.cwd):
            _strict_refuse()
        args, options, hardening = _bounded_args(args), _bounded_args(options), _bounded_args(_hardening)
        if hardening != DEFAULT_HARDENING or tty is not False or type(real_index) is not bool or len(args) + len(options) > 450:
            _strict_refuse()
        policy = self.policy(stdout_limit, stderr_limit)
        argv = _argv((*options, *args), self._lane_binding.program, hardening, policy)
        return capture(argv, cwd=self.cwd, env=self.environment(_env, args=args, real_index=real_index), stdin=stdin, timeout=timeout,
                       error=self.services.error, _lane=self, _policy=policy)

    def run_checked(self, args, cwd=None, **kwargs):
        kwargs.pop("error", None)
        result = self.run(args, cwd, **kwargs)
        if result.returncode:
            raise self.services.error("Lane Git command failed.", code="git_failed", returncode=result.returncode)
        return result

    def validate(self, argv, cwd, env, stdin, grant):
        args, pairs = _strict_argv(argv, cwd, env, stdin, lane=self, grant=grant)
        if args[0] not in ("hash-object", "merge-tree"):
            return argv
        listing = self.run(["config", "--null", "--name-only", "--get-regexp", r"^filter\."], stdout_limit=65536)
        code = "merge_unavailable" if args[0] == "merge-tree" else "conversion_unavailable"
        if listing.returncode not in (0, 1) or bool(listing.stdout) != (listing.returncode == 0):
            raise self.services.error("Lane conversion observation refused.", code=code)
        if listing.stdout and not listing.stdout.endswith(b"\0"):
            raise self.services.error("Lane conversion observation refused.", code=code)
        flags, drivers = [], set()
        for key in dict.fromkeys(listing.stdout.split(b"\0")[:-1]):
            driver = key[len(b"filter."):].rpartition(b".")[0] if key.startswith(b"filter.") else b""
            if not driver or len(driver) > 256 or re.fullmatch(rb"[A-Za-z0-9_.-]+", driver) is None:
                raise self.services.error("Lane conversion observation refused.", code=code)
            if driver in drivers:
                continue
            if len(flags) + 8 > 512 - len(argv):
                _strict_refuse()
            drivers.add(driver)
            flags.extend(x for name in ("clean", "smudge", "process", "required") for x in
                         ("-c", "filter." + driver.decode("ascii") + "." + name + ("=false" if name == "required" else "=")))
        if args[0] == "merge-tree":
            result = self.run(["config", "--show-scope", "--null", "--name-only", "--get-regexp",
                              r"^merge\..+\.driver$"], stdout_limit=65536)
            if result.returncode == 0 and result.stdout:
                raise self.services.error("Lane merge driver refused.", code="repository_merge_driver")
            if result.returncode != 1 or result.stdout:
                raise self.services.error("Lane merge observation refused.", code="merge_unavailable")
        final = (argv[0], *flags, *argv[1:])
        _strict_argv(final, cwd, env, stdin, lane=self, grant=grant)
        return final

    def paths(self):
        return self._lane_binding.paths

    def read_ref(self, cwd, ref):
        if not _ref_name(ref) or self.run(["check-ref-format", ref], cwd).returncode:
            raise self.services.error("Lane ref observation refused.", code="ref_unreadable")
        result = self.run_checked(["for-each-ref", "--format=%(objectname)%00%(symref)%00%(refname)", ref],
                                  cwd, stdout_limit=65536)
        for line in result.stdout.splitlines():
            fields = line.split(b"\0")
            if len(fields) != 3 or fields[1] or not _full_oid(fields[0].decode("ascii", "replace")):
                raise self.services.error("Lane ref observation refused.", code="ref_unreadable")
            if fields[2] == ref.encode("ascii"):
                return fields[0].decode("ascii")
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

    def publish(self, pack, *, shared=False):
        if type(shared) is not bool:
            _strict_refuse()
        args, policy = ("unpack-objects", "-q", "--strict"), self.policy()
        argv = tuple(_argv(args, self._lane_binding.program, DEFAULT_HARDENING, policy))
        return capture(argv, cwd=self.cwd, env=self.environment(args=args, shared=shared), stdin=pack, timeout=60,
            error=self.services.error, _lane=self, _policy=policy, _grant=(argv, str(self.cwd), pack) if shared else None)

    def cas(self, ref, new, old):
        if not _ref_name(ref) or not ref.startswith(("refs/aegis/", "refs/heads/lane/")):
            raise self.services.error("ref not allowed", code="ref_not_allowed")
        if not _full_oid(new) or old is not None and not _full_oid(old):
            raise self.services.error("invalid ref object", code="invalid_oid")
        current = self.read_ref(self.cwd, ref)
        if current != old and current != new:
            raise self.services.conflict("ref compare-and-swap mismatch", ref=ref, expected=old, current=current)
        for oid in (new,) if old is None else (new, old):
            result = self.run(["cat-file", "-t", oid], stdout_limit=16)
            if result.returncode or result.stdout != b"commit\n":
                raise self.services.error("invalid ref object", code="invalid_object")
        if old is not None:
            result = self.run(["merge-base", "--is-ancestor", old, new], stdout_limit=16)
            if result.returncode:
                raise self.services.error("ref ancestry refused", code="not_fast_forward" if result.returncode == 1 else "git_failed")
        if current == new:
            return "already"
        command = (b"create " if old is None else b"update ") + ref.encode("ascii") + b"\0" + new.encode("ascii") + b"\0"
        if old is not None:
            command += old.encode("ascii") + b"\0"
        def write(args, cwd, *, stdin):
            policy = self.policy()
            argv = tuple(_argv(["update-ref", "--no-deref", "-z", "--stdin"], self._lane_binding.program, DEFAULT_HARDENING, policy))
            return capture(argv, cwd=self.cwd, env=self.environment(args=("update-ref",), shared=True), stdin=command, timeout=60,
                error=self.services.error, _lane=self, _policy=policy, _grant=(argv, str(self.cwd), command))
        return update_once(self.cwd, ref, new, old, command, runner=write,
            observer=self.read_ref, error=self.services.error, conflict=self.services.conflict)


def memo_context():
    """Legacy boolean key, or a private-store-aware key in custody scopes."""
    policy = _CUSTODY.get()
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
            if remaining <= 0:
                return
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
                if not data:
                    return
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
            if remaining <= 0:
                raise error("git custody timed out", code="git_timeout")
            try:
                stream, data, failure = events.get(timeout=remaining)
            except queue.Empty:
                raise error("git custody timed out", code="git_timeout") from None
            if failure:
                raise error("git custody pipe failed", code=failure)
            if data:
                streams[stream][0].extend(data)
            else:
                pending.remove(stream)
        return bytes(streams[process.stdout][0]), bytes(streams[process.stderr][0])
    finally:
        stopped.set()
        failed = False
        if pending:
            try:
                _stop(process)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
            for stream in streams:
                try:
                    stream.close()
                except OSError:
                    failed = True
        for worker in workers:
            worker.join(timeout=1)
            failed |= worker.is_alive()
        if failed:
            raise error("git custody cleanup failed", code="git_cleanup_failed")


def _collect(process, policy, deadline, error):
    if os.name == "nt":
        return _collect_threaded(process, policy, deadline, error)
    streams = {process.stdout: (bytearray(), policy.stdout_limit),
               process.stderr: (bytearray(), policy.stderr_limit)}
    pending = set(streams)
    while pending:
        if time.monotonic() >= deadline:
            raise error("git custody timed out", code="git_timeout")
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


def _stop(process):
    # Do not poll/reap before killing the new POSIX session: the unreaped child
    # pins its group id, preventing a reused pid from naming somebody else's job.
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        process.kill()
    process.wait(timeout=5)

def _capture_limits(policy, timeout, stdin, error):
    if policy is not None and policy.strict_lane and stdin is not None and type(stdin) is not bytes:
        _strict_refuse()
    if (policy is None or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 300 or not math.isfinite(timeout)):
        raise error("invalid custody capture", code="invalid_custody")
    if stdin is not None and (not isinstance(stdin, bytes) or len(stdin) > _MAX_INPUT):
        raise error("git custody input limit exceeded", code="git_input_limit")


def capture(argv, *, cwd, env, stdin, timeout, error=AegisError, _lane=None, _policy=None, _grant=None):
    """Bound both pipes, use anonymous scratch stdin, and kill/reap/close on every failure."""
    policy = _CUSTODY.get() if _policy is None else _policy
    error = _lane.services.error if _lane is not None else (GitError if policy is not None and policy.strict_lane else error)
    process = None
    try:
        if _lane is not None or policy is not None and policy.strict_lane:
            argv = _bounded_args(argv)
            env = _strict_environment(env)
            cwd = _strict_root(cwd)
            _ambient_environment()
            if _lane is None:
                services = policy.services
                if services is None or not argv or argv[0] != services.program(cwd):
                    _strict_refuse()
                _command(argv, cwd, stdin, _grant)
        _capture_limits(policy, timeout, stdin, error)
        if _lane is None and policy.strict_lane:
            _lane = issue_runner(cwd, policy.scratch, services)
        if _lane is not None:
            argv = _lane.validate(argv, cwd, env, stdin, _grant)
        deadline = time.monotonic() + timeout
        with ExitStack() as stack:
            source = subprocess.DEVNULL
            if stdin is not None:
                source = stack.enter_context(tempfile.TemporaryFile(dir=policy.scratch))
                for start in range(0, len(stdin), _CHUNK):
                    if time.monotonic() >= deadline:
                        raise error("git custody timed out", code="git_timeout")
                    source.write(memoryview(stdin)[start:start + _CHUNK])
                source.seek(0)
            if time.monotonic() >= deadline:
                raise error("git custody timed out", code="git_timeout")
            process = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=source,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=os.name == "posix")
            stdout, stderr = _collect(process, policy, deadline, error)
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
            return subprocess.CompletedProcess(argv, code, stdout, stderr)
    except error as exc:
        exc.process_started = process is not None
        raise
    except subprocess.TimeoutExpired:
        raise error("git custody timed out", code="git_timeout", process_started=process is not None) from None
    except (OSError, ValueError, RuntimeError):
        raise error("git custody transport failed", code="git_failed", process_started=process is not None) from None
    finally:
        if process is not None:
            cleanup_failed = False
            try:
                if process.returncode is None:
                    _stop(process)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        cleanup_failed = True
            if cleanup_failed:
                raise error("git custody cleanup failed", code="git_cleanup_failed", process_started=True) from None


def execute(args, cwd, *, executable, legacy_runner, error, environ, timeout, stdin, hardening, env, tty,
            legacy_namespace=None):
    """Extracted legacy subprocess recipe, plus the explicitly scoped custody path."""
    policy = _CUSTODY.get()
    if strict_active():
        services = policy.services
        if services is None or executable is not services.executable:
            _strict_refuse()
        args, hardening, cwd = _bounded_args(args), _bounded_args(hardening), _strict_root(cwd)
        if hardening != DEFAULT_HARDENING or tty is not False or len(args) > 450:
            _strict_refuse()
        _command(_argv(args, services.program(cwd), hardening, policy), cwd, stdin)
        supplied = _identity_environment({**policy.env, **({} if env is None else _strict_environment(env, 6))}, args)
        _capture_limits(policy, timeout, stdin, GitError)
        return issue_runner(cwd, policy.scratch, services).run(args, cwd, timeout, stdin, hardening,
            supplied, tty, stdout_limit=policy.stdout_limit, stderr_limit=policy.stderr_limit)
    argv = _argv(args, executable(), hardening, policy)
    namespace = subprocess if legacy_namespace is None else legacy_namespace
    scrub = _SCRUB.get()
    effective = {k: v for k, v in environ.items() if not (scrub and k.upper() in LOCAL_ENV)}
    effective.update(BASE_ENV)
    if policy is not None:
        effective.update(policy.env)
    if env is not None:
        effective.update(env)
    if policy is not None:
        return capture(argv, cwd=cwd, env=effective, stdin=stdin, timeout=timeout, error=error)
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
        if scoped:
            raise
        raise error(str(exc)) from exc
    if res.returncode != 0:
        if scoped:
            raise git_error("git custody command failed", code="git_failed", returncode=res.returncode)
        raise error(f"git {args[0]} failed: {' '.join(res.stderr.decode('utf-8', 'replace').split())[:200]}")
    return res


def completed(args, cwd, *, runner, error, **kwargs):
    """Legacy query fallback, with refusals preserved in opt-in custody mode."""
    lane = getattr(runner, "__self__", None)
    scoped = isinstance(lane, LaneRunner) or custody_active()
    error = lane.services.error if isinstance(lane, LaneRunner) else error
    try:
        result = runner(args, cwd, **kwargs)
        if scoped and result.returncode not in (0, 1):
            raise error("git custody command failed", code="git_failed", returncode=result.returncode)
        return result
    except error:
        if scoped:
            raise
        return None


def query_result(result, *, error):
    """A custody query's exit 3 or other failure cannot become a missing answer."""
    if custody_active() and result.returncode not in (0, 1):
        raise error("git custody command failed", code="git_failed", returncode=result.returncode)
    return result


def output(args, cwd, *, completed, **kwargs):
    result = completed(args, cwd, **kwargs)
    return result.stdout if result is not None and result.returncode == 0 else None


def text(args, cwd, *, output, **kwargs):
    out = output(args, cwd, **kwargs)
    if out is None:
        return None
    value = os.fsdecode(out.strip())
    return value or None


def update_once(cwd, ref, new, old, command, *, runner, observer, error, conflict):
    """Execute one prevalidated ref transaction and classify its acknowledgment.

    gitsafe.update_ref validates the name/OIDs and constructs command before
    calling this transport helper. Post-spawn output/cleanup errors can lose the
    acknowledgment. Preflight refusals retain their code; a definite rejection
    with the old value intact is explicitly retriable by the caller.
    """
    try:
        result = runner(["update-ref", "--no-deref", "-z", "--stdin"], cwd, stdin=command)
    except error as exc:
        if exc.code not in ("git_timeout", "git_failed", "ERR_AEGIS", "git_cleanup_failed", "git_output_limit"):
            raise
        definite = exc.code == "git_failed" and getattr(exc, "process_started", None) is False
        result = None
    else:
        definite = True
    if result is not None and result.returncode == 0:
        return "updated"
    current = observer(cwd, ref)
    if current == new:
        return "already"
    if current != old:
        raise conflict("ref compare-and-swap mismatch", ref=ref, expected=old, current=current)
    if definite:
        raise error("ref update failed", code="ref_update_failed")
    raise error("ref update outcome unknown", code="ref_update_unknown")


def validate_update_input(single_attempt, new, old, *, error):
    """Original public update_ref validation; strict mode has a fixed refusal."""
    if not isinstance(single_attempt, bool):
        raise error("invalid single-attempt option", code="invalid_custody")
    if new is None and old is None:
        if strict_active():
            _strict_refuse()
        raise ValueError("update_ref needs a new value, an expected old value, or both")


def lane_update_ref(cwd, ref, new, old):
    """Compatibility entry for the facade's existing explicit strict scopes."""
    policy = _CUSTODY.get()
    services = None if policy is None else policy.services
    if policy is None or not policy.strict_lane or services is None:
        _strict_refuse()
    runner = issue_runner(cwd, policy.scratch, services)
    return runner.cas(ref, new, old)

def _private_capture(args, cwd, *, env, scratch, limit, stdin, runner, custody, lane):
    if lane is not None:
        if env is not None or scratch is not None:
            _strict_refuse()
        return lane.run_checked(args, cwd, _env=env, stdout_limit=limit, stdin=stdin)
    with custody(scratch=scratch, env=env, stdout_limit=limit):
        return runner(args, cwd, stdin=stdin)

def private_headers(cwd, oids, *, env, scratch, runner, batch, custody, error, lane=None):
    """Bound and verify mixed object metadata; missing is an explicit query result."""
    if type(oids) not in (tuple, list) or len(oids) > 20000:
        raise error("invalid private object request", code="invalid_object")
    if any(not _full_oid(oid) for oid in oids):
        raise error("invalid private object request", code="invalid_object")
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return {}
    limit = sum(len(oid) + 33 for oid in wanted)
    out = _private_capture(batch, cwd, env=env, scratch=scratch, limit=limit,
        stdin=("\n".join(wanted) + "\n").encode("ascii"), runner=runner, custody=custody, lane=lane).stdout
    if len(out) > limit:
        raise error("invalid private object", code="invalid_object")
    lines = out.split(b"\n")
    if len(lines) != len(wanted) + 1 or lines[-1]:
        raise error("invalid private object", code="invalid_object")
    result = {}
    for oid, line in zip(wanted, lines):
        if len(line) > len(oid) + 32:
            raise error("invalid private object", code="invalid_object")
        fields = line.split()
        if fields == [oid.encode("ascii"), b"missing"]:
            result[oid] = None
        elif (len(fields) == 3 and fields[0] == oid.encode("ascii")
              and fields[1] in (b"blob", b"tree", b"commit")
              and len(fields[2]) <= 20 and fields[2].isdigit()):
            result[oid] = (fields[1].decode("ascii"), int(fields[2]))
        else:
            raise error("invalid private object", code="invalid_object")
    return result

def private_object(cwd, oid, *, kind, max_bytes, env, scratch, headers, runner, custody, error, lane=None):
    """One typed object, with a bounded preflight before payload capture."""
    from aegis_core.workspace import git_objects
    if (kind not in ("blob", "tree", "commit") or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int) or not 0 <= max_bytes <= 128 * 1024 * 1024):
        raise error("invalid private object request", code="invalid_object")
    info = headers(cwd, [oid], env=env, scratch=scratch)[oid]
    if info is None or info[0] != kind:
        raise error("invalid private object", code="invalid_object")
    size = info[1]
    if size > max_bytes:
        raise error("private object size limit exceeded", code="git_object_limit")
    data = _private_capture(["cat-file", kind, oid], cwd, env=env, scratch=scratch, limit=size,
        stdin=None, runner=runner, custody=custody, lane=lane).stdout
    if len(data) != size or git_objects.object_id(data, len(oid), kind) != oid:
        raise error("invalid private object", code="invalid_object")
    return data

def private_objects(cwd, oids, *, max_bytes, max_object_bytes, env, scratch, headers,
                    runner, batch, custody, error, lane=None):
    """Batch publication preflight, then exact ordered type, size and hash validation."""
    from aegis_core.workspace import git_objects
    if any(isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= 128 * 1024 * 1024
           for cap in (max_bytes, max_object_bytes)):
        raise error("invalid private object request", code="invalid_object")
    info = headers(cwd, oids, env=env, scratch=scratch)
    if not info:
        return {}
    if any(value is None for value in info.values()):
        raise error("invalid private object", code="invalid_object")
    total = sum(value[1] for value in info.values())
    wire_limit = total + sum(len(oid) + 34 for oid in info)
    if (total > max_bytes or wire_limit > 128 * 1024 * 1024
            or any(value[1] > max_object_bytes for value in info.values())):
        raise error("private object size limit exceeded", code="git_object_limit")
    out = _private_capture(batch, cwd, env=env, scratch=scratch, limit=wire_limit,
        stdin=("\n".join(info) + "\n").encode("ascii"), runner=runner, custody=custody, lane=lane).stdout
    objects, position = {}, 0
    for oid, (kind, size) in info.items():
        header = (oid + " " + kind + " " + str(size) + "\n").encode("ascii")
        start = position + len(header)
        if (out[position:start] != header or size > len(out) - start - 1
                or out[start + size:start + size + 1] != b"\n"):
            raise error("invalid private object", code="invalid_object")
        data = out[start:start + size]
        if git_objects.object_id(data, len(oid), kind) != oid:
            raise error("invalid private object", code="invalid_object")
        objects[oid] = (kind, data)
        position = start + size + 1
    if position != len(out):
        raise error("invalid private object", code="invalid_object")
    return objects
