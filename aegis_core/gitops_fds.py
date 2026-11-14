"""Opt-in effect custody in an isolated Linux subreaper.

The caller owns its receipt. A holder borrows that descriptor and owns a bounded
status pipe; effect programs receive neither. Absence preserves legacy recipes.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from types import MappingProxyType
import ctypes
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import stat
import sys
import time

from aegis_core import storage_confined
from aegis_core.errors import AegisError

_ENVIRON_TYPE = type(os.environ)

__all__ = ["refuse", "bind_runner", "descriptor_supported", "export_receipt",
           "validate_cwd", "scratch_root", "bounded_roots", "effect_started", "cleanup_holder", "effect_executable", "effect_environment", "holder_recipe", "legacy_effect", "capture_recipe", "gh_refusal", "git_result", "effect_inputs", "execute_effect", "pass_through", "prepare_capture"]


def descriptor_supported():
    """Probe Linux subreaper support without changing the calling process."""
    if sys.platform != "linux" or os.name != "posix":
        return False
    try:
        value = ctypes.c_int()
        return ctypes.CDLL(None, use_errno=True).prctl(37, ctypes.byref(value), 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def refuse(error, code="invalid_effect_descriptor"):
    messages = {
        "invalid_effect_descriptor": "Git operation effect descriptor refused.",
        "unsupported_effect_platform": "Git operation effect descriptor platform unavailable.",
        "effect_runner_refused": "Git operation runner does not declare descriptor custody.",
        "effect_command_refused": "Git operation effect command refused.",
        "effect_environment_limit": "Git operation effect environment exceeds supported limits.",
        "invalid_effect_cwd": "Git operation effect repository path refused.",
        "effect_environment_unavailable": "Git operation effect roots unavailable.",
        "unsupported_remote_form": "Git operation remote form is unsupported.",
        "gh_token_missing": "GitHub effect requires an explicit token; no effect process started.",
        "gh_token_host_mismatch": "GitHub effect token does not apply to the selected host; no effect process started.",
        "gh_host_mismatch": "GitHub effect host selections conflict; no effect process started.",
        "gh_not_installed": "GitHub CLI is unavailable; no effect process started.",
        "gh_scratch_unavailable": "GitHub CLI scratch is unavailable; no effect process started.",
        "gh_spawn_failed": "GitHub CLI could not start; no effect process started.",
        "gh_repository_unresolved": "GitHub effect repository is unavailable; no effect process started.",
    }
    actions = {
        "unsupported_remote_form": "Use one positional configured remote or URL; no effect process started.",
        "effect_environment_unavailable": "Supply the custody repository's absolute worktree_root and matching cwd; no effect process started.",
        "invalid_effect_cwd": "Supply an absolute repository directory without parent traversal; no effect process started.",
        "effect_environment_limit": "Reduce the supplied environment to bounded string entries; no effect process started.",
        "gh_token_missing": "Supply an explicit token for the selected GitHub host; no effect process started.",
        "gh_token_host_mismatch": "Supply the token kind applicable to the selected host; no effect process started.",
        "gh_host_mismatch": "Use one matching GH_HOST and --hostname selection; no effect process started.",
        "gh_not_installed": "Install or restore the GitHub CLI; no effect process started.",
        "gh_scratch_unavailable": "Restore temporary-directory access; no effect process started.",
        "gh_spawn_failed": "Restore process and descriptor resources; no effect process started.",
        "gh_repository_unresolved": "Supply a resolvable GitHub repository; no effect process started.",
    }
    raise error(messages[code], code=code, process_started=False, effect_process_started=False,
                next_action=actions.get(code, "Supply a supported request and active receipt; no effect process started.")) from None


_RECEIPT_IDENTITIES = {}


class _ReceiptFDs(tuple):
    def __new__(cls, fd, identity):
        value = super().__new__(cls, (fd,))
        value.identity = identity
        return value


def pass_through(effect_fds, *, error=AegisError):
    """Validate before discovery or spawn; preserve caller ownership even on failure."""
    if effect_fds is None:
        return {}
    if not descriptor_supported():
        refuse(error, "unsupported_effect_platform")
    if type(effect_fds) not in (tuple, _ReceiptFDs) or len(effect_fds) != 1:
        refuse(error)
    fd = effect_fds[0]
    if type(fd) is not int or not 3 <= fd <= 2147483647:
        refuse(error)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or _RECEIPT_IDENTITIES.get((os.getpid(), fd)) != (info.st_dev, info.st_ino)
                or type(effect_fds) is _ReceiptFDs and effect_fds.identity != (os.getpid(), info.st_dev, info.st_ino)):
            refuse(error)
        os.set_inheritable(fd, False)
    except OSError:
        refuse(error)
    return {"pass_fds": tuple(effect_fds)}


def receipt_fds(fd, *, error):
    """Export close-on-exec for the custody holder alone."""
    if not descriptor_supported():
        refuse(error, "unsupported_effect_platform")
    try:
        info = os.fstat(fd)
        _RECEIPT_IDENTITIES[(os.getpid(), fd)] = (info.st_dev, info.st_ino)
        os.set_inheritable(fd, False)
    except OSError:
        refuse(error)
    return _ReceiptFDs(fd, (os.getpid(), info.st_dev, info.st_ino))


def export_receipt(receipt, owners, guard, error):
    """Validate and export under the receipt's original ownership guard."""
    with guard:
        held = owners.get(receipt._key)
        if (not receipt.created or held is None or held[1] != os.getpid()
                or held[2] is not receipt._token):
            raise error("effect_busy")
        return receipt_fds(held[0], error=lambda *a, **kw: error("effect_busy"))


_EFFECT_CONFIG = ("core.fsmonitor=false", "core.hooksPath=" + os.devnull,
                  "core.askPass=", "gc.auto=0", "gc.autoDetach=false", "maintenance.auto=false",
                  "fetch.recurseSubmodules=false", "push.recurseSubmodules=no", "submodule.recurse=false")

def _policy_refusal(error, code, *, started=True):
    messages = {"effect_configuration_unavailable": "Git effect configuration could not be determined.",
                "effect_credential_cache_refused": "Git effect credential cache or daemon helper refused.",
                "effect_ssh_command_refused": "Git effect SSH command cannot be confined.",
                "unsupported_remote_form": "Git operation remote form is unsupported."}
    raise error(messages[code], code=code, process_started=started, effect_process_started=False,
                next_action=("Use one positional configured remote or URL; no effect process started." if code == "unsupported_remote_form"
                             else "Use a bounded owner configuration without detached helpers; no effect process started.")) from None


def _config_values(prefix, env, cwd, timeout, effect_fds, key, *, error, state, observe, scope, pattern=False):
    """Read owner config through the bounded capture sink and its custody holder."""
    try:
        with scope(scratch=Path(cwd), worktree_root=env.root, _boundary=env._proof["kind"], stdout_limit=65536, stderr_limit=65536):
            result = observe([*prefix, "config", "--null", "--get-regexp" if pattern else "--get-all", key],
                cwd=cwd, env=env, stdin=None, timeout=timeout, error=error, effect_fds=effect_fds, worktree_root=env.root)
    except error as exc:
        exc.process_started = state["started"] or getattr(exc, "process_started", False)
        exc.effect_process_started = False
        raise
    state["started"] = True
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return []
    if (result.returncode or not result.stdout.endswith(b"\0") or result.stdout.count(b"\0") > 128):
        _policy_refusal(error, "effect_configuration_unavailable")
    try:
        return result.stdout[:-1].decode("utf-8").split("\0")
    except UnicodeError:
        _policy_refusal(error, "effect_configuration_unavailable")


def _check_helpers(values, error):
    effective = []
    for value in values:
        if not value:
            effective.clear()
        else:
            effective.append(value)
    for helper in effective:
        if len(helper) > 16384:
            _policy_refusal(error, "effect_configuration_unavailable")
        try:
            words = shlex.split(helper.lstrip("!"))
        except ValueError:
            _policy_refusal(error, "effect_configuration_unavailable")
        if (not words or any(re.search(r"(?:^|[/\s;|&()])(?:git-)?credential-cache(?:$|[\s;|&()])", word)
                or os.path.basename(word).lower() == "cache"
                or re.search(r"(?:^|[-_/\s])daemon(?:$|[-_=\s])", word, re.I) for word in words)):
            _policy_refusal(error, "effect_credential_cache_refused")


def _ssh_options(words, error):
    """Positive OpenSSH option grammar: no wrapper or positional command words."""
    if not words or not (words[0] == "ssh" or os.path.isabs(words[0]) and os.path.basename(words[0]) == "ssh"):
        _policy_refusal(error, "effect_ssh_command_refused")
    flags, pairs, position = "46AaCgKkNnqTtVvXxYy", "BbcDEeFIiJLlmpoRWw", 1
    while position < len(words):
        word = words[position]
        if len(word) < 2 or not word.startswith("-") or word.startswith("--"):
            _policy_refusal(error, "effect_ssh_command_refused")
        for offset, char in enumerate(word[1:], 1):
            if char in pairs:
                if offset == len(word) - 1:
                    position += 1
                    if position >= len(words) or not words[position] or words[position].startswith("-"):
                        _policy_refusal(error, "effect_ssh_command_refused")
                break
            if char not in flags:
                _policy_refusal(error, "effect_ssh_command_refused")
        position += 1


def _ssh_policy(prefix, env, cwd, timeout, effect_fds, *, error, observe, scope, args, transport):
    state, deadline = {"started": False}, time.monotonic() + timeout
    records = _config_values(prefix, env, cwd, timeout, effect_fds,
        r"^(credential(\..+)?\.helper|core\.sshcommand|remote\..+\.(url|pushurl)|remote\.pushdefault|branch\..+\.(remote|pushremote)|url\..+\.(insteadof|pushinsteadof)|remotes\..+|submodule\.recurse)$",
        error=error, state=state, observe=observe, scope=scope, pattern=True)
    groups = {}
    for record in records:
        key, separator, value = record.partition("\n")
        if (not separator and key != "submodule.recurse") or len(key) > 16384:
            _policy_refusal(error, "effect_configuration_unavailable")
        groups.setdefault(key, []).append(value if separator else None)
    for key, values in groups.items():
        if key.startswith("credential") and key.endswith(".helper"):
            _check_helpers(values, error)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise error("Git effect configuration timed out.", code="git_timeout", process_started=True,
                    effect_process_started=False, next_action="Observe the reserved effect before recovery.")
    try:
        urls = _remote_urls(args, groups, prefix, env, cwd, remaining, effect_fds,
                            error=error, observe=observe, scope=scope)
    except error as exc:
        exc.process_started, exc.effect_process_started = True, False
        raise
    ssh_remote = any(re.match(r"(?:ssh|git\+ssh|ssh\+git)://", url, re.I)
        or not re.match(r"[A-Za-z0-9][A-Za-z0-9+.-]*::|[A-Za-z0-9][A-Za-z0-9+.-]*://", url) and re.match(r"(?:[^/@:]+@)?[^/:]+:", url)
        for url in urls)
    if not ssh_remote:
        return None, state["started"]
    commands = groups.get("core.sshcommand", [])
    command = commands[-1] if commands else "ssh"
    if not command or len(command) > 16384 or any(c in command for c in "\r\n`$;|&<>()~"):
        _policy_refusal(error, "effect_ssh_command_refused")
    try:
        words = shlex.split(command)
    except ValueError:
        _policy_refusal(error, "effect_ssh_command_refused")
    if (not words or len(words) > 64 or not (words[0] == "ssh" or os.path.isabs(words[0]))):
        _policy_refusal(error, "effect_ssh_command_refused")
    _ssh_options(words, error)
    from aegis_core import pathlookup
    try:
        program = transport.resolve({}, env, lambda effective: words[0] if os.path.isabs(words[0]) else pathlookup.which("ssh", path=effective.get("PATH", os.defpath), outside=effective.root), error=error, missing_ok=True)
    except error as exc:
        exc.process_started, exc.effect_process_started = state["started"], False
        raise
    if program is None:
        _policy_refusal(error, "effect_ssh_command_refused")
    return shlex.join([program, "-o", "IgnoreUnknown=ForkAfterAuthentication", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ForkAfterAuthentication=no",
        "-o", "BatchMode=yes", *words[1:]]), state["started"]


def git_effect(argv, env, effect_fds, *, error=AegisError, cwd=None, timeout=60, observe=None, scope=None, transport=None):
    """Prepare owner-selected transports; the holder owns descendant custody."""
    if effect_fds is None:
        return argv, env, False, None
    if type(cwd) not in (str, type(Path())) or len(str(cwd)) > 16384 or "\0" in str(cwd):
        refuse(error, "effect_command_refused")
    position, command = _git_command(argv, error)
    argv = [*argv[:position], *(x for value in _EFFECT_CONFIG for x in ("-c", value)), *argv[position:]]
    # The facade has already validated and fenced this environment.
    started, ssh_index = False, None
    if command in ("push", "fetch"):
        position += 2 * len(_EFFECT_CONFIG)
        ssh, started = _ssh_policy(argv[:position], env, cwd, timeout, effect_fds, error=error, observe=observe, scope=scope, args=argv[position:], transport=transport)
        argv.insert(position + 1, "--no-recurse-submodules")
        if ssh is not None:
            argv[position:position] = ["-c", "core.sshCommand=" + ssh]
            ssh_index = position + 1
            # GIT_SSH_VARIANT is fixed by the single environment constructor.
    return argv, env, started, ssh_index


def git_result(result, *, result_type, process=None):
    """Preserve exit codes while refusing to echo remote URLs or credentials."""
    position = 1
    while position + 1 < len(result.args) and result.args[position] == "-c":
        position += 2
    if process is not None and not result.returncode and tuple(result.args[position:]) in (("rev-parse", "--git-common-dir"), ("rev-parse", "--git-path", "index")):
        for fd in process.directories["fds"]:
            prefix = f"/proc/{process.pid}/fd/{fd}".encode("ascii")
            if result.stdout.startswith((prefix + b"/", prefix + b"\n")):
                result = result_type(result.args, result.returncode, os.fsencode(os.readlink(f"/proc/self/fd/{fd}")) + result.stdout[len(prefix):], result.stderr)
                break
    if result.returncode and result.args[position:position + 1] in (["push"], ["fetch"]):
        detail = result.stderr.lower() if len(result.stderr) <= 65536 else b""
        message = b"Git operation effect command failed; observe before recovery."
        if b"terminal prompts disabled" in detail or b"authentication failed" in detail:
            message = b"Git operation missing HTTPS credentials; prompts disabled."
        elif b"permission denied" in detail or b"publickey" in detail:
            message = b"Git operation missing SSH credentials; prompts disabled."
        return result_type(result.args, result.returncode, b"", message)
    return result


def spawn_refusal(error, *, timeout=False, started=False):
    """Effect diagnostics never echo untrusted OS exception text or arguments."""
    raise error("Git operation effect timed out." if timeout else "Git operation effect transport failed.",
                code="git_timeout" if timeout else "git_failed", process_started=timeout or started,
                effect_process_started=timeout or started, next_action="Observe the reserved effect before attempting any recovery."
                if timeout or started else "Restore process resources; no effect process started.") from None


def prepare_capture(argv, env, stdin, timeout, effect_fds, *, error, strict, cwd, roots=(), lane=None, base=None, grant=None, bind=None, worktree_root=None, custody_root=None, expected_dirs=None, scope=None, transport=None, kind="git"):
    """Prepare custody before validation can discover/spawn other Git processes."""
    options = pass_through(effect_fds, error=error)
    effect_inputs(argv, stdin, timeout, effect_fds, error=error, transport=transport)
    validate_cwd(cwd, error=error)
    _git_command(argv, error)
    prepared = effect_environment(env, cwd, error=error, roots=roots, base=base, worktree_root=worktree_root, custody_root=custody_root, expected_dirs=expected_dirs, scope=scope, transport=transport, kind=kind)
    if lane is None:
        transport.resolve({}, prepared, lambda effective: argv[0], error=error)
    if lane is not None:
        if not callable(bind): refuse(error, "effect_runner_refused")
        original = tuple(argv)
        program = effect_executable(prepared, cwd, resolver=lane.services.executable, error=error, transport=transport)
        argv = [program, *argv[1:]]
        if grant is not None:
            if grant != (original, str(cwd), stdin):
                raise error("Strict lane Git command refused.", code="git_custody_refused", process_started=False)
            grant = (tuple(argv), str(cwd), stdin)
        lane = bind(program, prepared)
    return argv, prepared, options, lane, grant


def capture_recipe(argv, env, effect_fds, *, error, cwd, timeout, observe, scope, transport):
    return git_effect(argv, env, effect_fds, error=error, cwd=cwd, timeout=timeout, observe=observe, scope=scope, transport=transport)


def gh_refusal(*, error, reason):
    refuse(error, "gh_" + reason)


def _gh_process_error(error, code):
    raise error("GitHub effect transport failed.", code=code, process_started=True,
                next_action="Observe the started request before recovery.") from None


def bind_runner(runner, effect_fds, *, error, worktree_root=None):
    """An injected runner must promise custody for its children and descendants."""
    if not callable(runner) or getattr(runner, "supports_effect_fds", False) is not True or effect_fds is None:
        refuse(error, "effect_runner_refused")
    pass_through(effect_fds, error=error)
    def bound(*args, **kwargs):
        if "effect_fds" in kwargs:
            refuse(error, "effect_runner_refused")
        pass_through(effect_fds, error=error)
        root = kwargs.pop("worktree_root", worktree_root)
        cwd = kwargs.get("cwd", args[2] if len(args) > 2 else None)
        with _root_binding(root, cwd, error=error) as facts:
            if worktree_root is not None:
                with _root_binding(worktree_root, cwd, error=error) as expected:
                    if facts["identity"] != expected["identity"]: refuse(error, "effect_environment_unavailable")
            return runner(*args, **kwargs, effect_fds=effect_fds, worktree_root=root)
    bound.supports_effect_fds = True
    return bound


def effect_inputs(args, stdin, timeout, effect_fds, *, error, hardening=None, envs=(), transport=None):
    """Check bounds before argv/env copies, executable lookup, scratch or spawn."""
    if effect_fds is None:
        return
    import math
    from types import MappingProxyType
    for values in (args, hardening):
        if values is not None and (type(values) not in (tuple, list) or len(values) > 512
                or any(type(v) is not str or len(v) > 16384 or "\0" in v for v in values)):
            refuse(error, "effect_command_refused")
    if args is None or hardening is not None and len(args) + len(hardening) + 1 > 512:
        refuse(error, "effect_command_refused")
    if (stdin is not None and (type(stdin) is not bytes or len(stdin) > 128 * 1024 * 1024)
            or type(timeout) not in (int, float) or not 0 < timeout <= 300 or not math.isfinite(timeout)):
        refuse(error, "effect_command_refused")
    for env in envs:
        if env is None:
            continue
        if (type(env) not in (dict, MappingProxyType, _ENVIRON_TYPE, transport.envelope_type if transport is not None else None) or len(env) > 512
                or any(type(k) is not str or type(v) is not str or len(k) > 256 or len(v) > 65536
                       or "\0" in k or "\0" in v or "=" in k for k, v in env.items())):
            refuse(error, "effect_environment_limit")



@contextmanager
def _directory(path):
    if type(path) not in (str, type(Path())) or not 0 < len(str(path)) <= 16384 or any(c in str(path) for c in "\0\r\n") or str(path).count(os.sep) > 128:
        raise ValueError()
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError()
    try:
        with storage_confined.confined_file(path, (".git",)) as handle:
            # Same-package borrowing, as in team_gitops: the storage context
            # owns the directory descriptor and keeps it open across the yield.
            yield handle._parent
    except storage_confined.ConfinedFileError:
        raise OSError() from None


def _read_record(directory, name, limit):
    # The enclosing directory context owns this borrowed parent descriptor.
    try:
        return storage_confined.ConfinedFile(directory, name).read_bytes(limit)
    except storage_confined.ConfinedFileError as exc:
        if exc.reason == "missing":
            raise FileNotFoundError() from None
        raise ValueError() from None


def _record_path(data, parent, prefix=b""):
    data = data.removesuffix(b"\n").removesuffix(b"\r")
    if not data.startswith(prefix) or not data[len(prefix):].strip() or any(c in data for c in (b"\0", b"\n", b"\r")):
        raise ValueError()
    return os.path.normpath(os.path.join(parent, os.fsdecode(data[len(prefix):].strip())))


def _root_facts(root, cwd, stack, expected):
    if expected is not None and (type(expected) not in (tuple, list) or len(expected) != 2):
        raise ValueError()
    root_fd = stack.enter_context(_directory(root))
    canonical = str(Path(root).resolve(strict=True))
    identity = lambda fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
    if identity(root_fd) != identity(stack.enter_context(_directory(canonical))):
        raise ValueError()
    cwd = canonical if cwd is None else os.path.normpath(str(cwd))
    if os.path.commonpath((canonical, cwd)) != canonical:
        raise ValueError()
    current = root_fd
    # Confined storage has no directory-open API accepting a held parent fd.
    # These child opens must retain that anchor across concurrent path renames.
    for part in Path(cwd).relative_to(canonical).parts:
        current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
        stack.callback(os.close, current)
        try:
            marker = os.stat(".git", dir_fd=current, follow_symlinks=False)
            if stat.S_ISREG(marker.st_mode) and marker.st_size == 0: continue
        except FileNotFoundError:
            continue
        raise ValueError()  # An intervening marker never changes root authority.
    git_path = os.path.join(canonical, ".git")
    try:
        git_fd = os.open(".git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        stack.callback(os.close, git_fd)
    except NotADirectoryError:
        git_path = _record_path(_read_record(root_fd, ".git", 16384), canonical, b"gitdir:")
        git_fd = stack.enter_context(_directory(git_path))
    if not _read_record(git_fd, "HEAD", 4096):
        raise ValueError()
    try:
        common_path = _record_path(_read_record(git_fd, "commondir", 16384), git_path)
        common_fd = stack.enter_context(_directory(common_path))
    except FileNotFoundError:
        common_path, common_fd = git_path, git_fd
    for directory in ("objects", "refs"):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=common_fd)
        stack.callback(os.close, fd)
    identities = (identity(root_fd), identity(git_fd), identity(common_fd))
    if expected is not None and identities[1:] != tuple(identity(stack.enter_context(_directory(p))) for p in expected):
        raise ValueError()
    return {"root": canonical, "identity": identities, "dirs": (git_path, common_path), "cwd_fd": current,
            "fds": (git_fd, common_fd, root_fd)}


@contextmanager
def _root_binding(root, cwd, *, error, expected=None):
    with ExitStack() as stack:
        if cwd is not None: validate_cwd(cwd, error=error)
        try:
            facts = _root_facts(root, cwd, stack, expected)
        except (OSError, ValueError, RuntimeError):
            refuse(error, "effect_environment_unavailable")
        yield facts


def _effect_roots(cwd, roots, error, worktree_root, expected):
    if type(roots) not in (tuple, list) or len(roots) > 16:
        refuse(error, "effect_environment_unavailable")
    for root in roots:
        validate_cwd(root, error=error)
    with _root_binding(worktree_root, cwd, error=error, expected=expected) as facts:
        return tuple(dict.fromkeys(value for p in (facts["root"], cwd or facts["root"], *roots) for value in (os.path.abspath(p), os.path.realpath(p)))), {k: facts[k] for k in ("identity", "dirs")}



def scratch_root(environ, *, error):
    """Linux effect scratch never consults tempfile's ambient-directory cache."""
    selected = environ.get("TMPDIR", "/tmp")
    if not environ._proof["outside"](selected, environ.roots):
        refuse(error, "gh_scratch_unavailable")
    return selected


def bounded_roots(roots, *, scratch=None, error):
    """Bound caller roots before constructing any combined tuple."""
    if type(roots) not in (tuple, list) or len(roots) + (scratch is not None) > 16:
        refuse(error, "effect_environment_unavailable")
    return (*roots, *((scratch,) if scratch is not None else ()))


def effect_environment(source, cwd, *, error, roots=(), overrides=None, base=None, allowed=None, scope=None, worktree_root=None, custody_root=None, expected_dirs=None, transport=None, kind="git"):
    """Bind root descriptors; all value construction belongs to the shared constructor."""
    if transport is None:
        refuse(error, "effect_runner_refused")
    if type(source) is transport.envelope_type:
        source = transport.environment(source, profile="strict/effect", kind=kind, error=error)
    worktree_root = worktree_root if worktree_root is not None else custody_root
    if expected_dirs is None and type(source) is transport.envelope_type:
        owned = source._proof["bindings"]
        if "GIT_DIR" in owned and "GIT_COMMON_DIR" in owned:
            expected_dirs = (owned["GIT_DIR"], owned["GIT_COMMON_DIR"])
    checked, repository = _effect_roots(cwd, roots, error, worktree_root, expected_dirs)
    if custody_root is not None:
        with _root_binding(custody_root, cwd, error=error) as expected:
            if expected["identity"] != repository["identity"]:
                refuse(error, "effect_environment_unavailable")
    if type(source) is transport.envelope_type and source.repository is not None and source.repository["identity"] != repository["identity"]:
        refuse(error, "effect_environment_unavailable")
    return transport.environment(source, profile="strict/effect", root=checked[0], roots=checked,
        repository=repository, scope=scope, overrides=overrides, base=base, allowed=allowed, error=error, kind=kind)


def effect_executable(env, cwd, *, resolver, error, transport):
    """Adapt the facade callback to the sole resolver, including injected callbacks."""
    try:
        return transport.resolve({}, env, lambda effective: resolver(environ=effective, cwd=cwd), error=error)
    except error as exc:
        if getattr(exc, "code", None) not in (None, "ERR_AEGIS"):
            raise
        spawn_refusal(error)


# A constant isolated program, never a file-path execution from the checkout.
# The receipt and status writer reach only this process. close_fds prevents
# either from reaching the effect; setsid separates holder and effect groups.
_HOLDER_SOURCE = r'''
import ctypes, os, signal, subprocess, sys, time
status_fd, duration = int(sys.argv[1]), float(sys.argv[2])
stopping = False
def stop(*_):
    global stopping
    stopping = True
for sig in (signal.SIGUSR1, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, stop)
def report(message):
    try:
        os.write(status_fd, message.encode('ascii'))
    except BrokenPipeError:
        pass  # The owner died; all descendants have already been reaped.
    finally:
        os.close(status_fd)
def kill(pid, group=False):
    try:
        (os.killpg if group else os.kill)(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    report('unsupported')
    sys.exit(125)
try:
    if sys.argv[3] != '-1':
        for key, fd in zip(('GIT_DIR', 'GIT_WORK_TREE'), (sys.argv[3], sys.argv[5])):
            os.putenv(key, '/proc/'+str(os.getpid())+'/fd/'+str(int(fd)))
    command = sys.argv[8:]
    for index, value in enumerate(command):
        prefix = 'core.sshCommand=/proc/self/fd/'+sys.argv[7]+' '
        if sys.argv[7] != '-1' and value.startswith(prefix):
            command[index] = 'core.sshCommand=/proc/'+str(os.getpid())+'/fd/'+sys.argv[7]+' '+value[len(prefix):]
    child = subprocess.Popen(command, executable='/proc/'+str(os.getpid())+'/fd/'+sys.argv[6], close_fds=True, start_new_session=True)
except (OSError, ValueError):
    report('spawn')
    sys.exit(125)
try:
    os.write(status_fd, b'started\n')
except BrokenPipeError:
    pass  # Owner death must not interrupt custody or reaping.
deadline, code, failure, group_killed = time.monotonic()+duration, None, None, False
while True:
    if stopping or time.monotonic() >= deadline:
        failure = failure or ('cancelled' if stopping else 'timeout')
    if failure:
        if not group_killed:
            if code is None:  # Never signal a group ID after its leader was reaped.
                kill(child.pid, True)
            group_killed = True
        # Killing each direct child also reparents its detached children here.
        # Until waitpid reaps them these child PIDs cannot be reused.
        try:
            with open('/proc/self/task/'+str(os.getpid())+'/children') as stream:
                children = stream.read(65536).rsplit(' ', 1)[0].split()
        except OSError:
            children = []  # Retain custody and reap; never exit over an unreadable procfs.
        for pid in children:
            kill(int(pid))
    try:
        pid, status = os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        break
    if pid:
        result = os.waitstatus_to_exitcode(status)
        if pid == child.pid:
            code = result
        if result != 0:
            failure = failure or 'child_failed'
    else:
        time.sleep(0.01)
report(failure if failure in ('timeout', 'cancelled') else 'exit:'+str(code if code is not None else 125))
# The protocol carries negative signal codes without conflating child 124/125
# with timeout/spawn failures. The parent propagates the actual child status.
sys.exit(0)
'''


class _HolderProcess:
    def __init__(self, process, status_fd, error, kind, timeout_error):
        self.raw, self.status_fd, self.error = process, status_fd, error
        self.stdin, self.stdout, self.stderr = process.stdin, process.stdout, process.stderr
        self.kind, self._status, self.started, self.timeout_error = kind, b"", False, timeout_error
        self.pid, self.args, self._code = process.pid, process.args, None

    @property
    def returncode(self):
        return self._code

    def read_status(self):
        if self.status_fd is None:
            return
        try:
            self._status += os.read(self.status_fd, max(0, 65 - len(self._status)))
        except BlockingIOError:
            return
        except OSError:
            self.started = True  # Lost acknowledgment is indeterminate.
        if self._status.startswith(b"started\n"):
            self.started = True

    def wait(self, timeout=None):
        self.raw.wait(timeout=timeout)
        if self._code is None:
            self.read_status()
            message = self._status.removeprefix(b"started\n")
            if message == b"unsupported":
                refuse(self.error, "unsupported_effect_platform")
            if message == b"spawn":
                if self.kind == "gh":
                    refuse(self.error, "gh_spawn_failed")
                spawn_refusal(self.error)
            if message in (b"timeout", b"cancelled"):
                if self.kind == "gh":
                    _gh_process_error(self.error, "gh_timeout")
                spawn_refusal(self.error, timeout=True)
            if not re.fullmatch(rb"exit:-?[0-9]{1,3}", message):
                spawn_refusal(self.error, started=True)
            self._code = int(message[5:])
        return self._code


@contextmanager
def holder_recipe(argv, options, timeout, *, error, timeout_error, kind="git", transport=None, ssh_index=None):
    """Own the status pipe on spawn failure as well as every collection path."""
    if transport is None:
        refuse(error, "effect_runner_refused")
    with ExitStack() as directories:
        env = transport.environment(options["env"], profile="strict/effect", error=error)
        program = transport.resolve({}, env, lambda effective: argv[0], error=error, stack=directories)
        interpreter = transport.resolve({}, env, lambda effective: sys.executable, error=error, stack=directories)
        pinned = [int(program.rsplit("/", 1)[1])]
        ssh_fd, argv = -1, list(argv)
        if ssh_index is not None:
            words = shlex.split(argv[ssh_index][len("core.sshCommand="):])
            ssh = transport.resolve({}, env, lambda effective: words[0], error=error, stack=directories)
            ssh_fd = int(ssh.rsplit("/", 1)[1])
            pinned.append(ssh_fd)
            argv[ssh_index] = "core.sshCommand=" + shlex.join([f"/proc/self/fd/{ssh_fd}", *words[1:]])
        options = {**options, "env": env}
        facts, descriptors = None, (-1, -1, -1)
        if kind == "git":
            facts = directories.enter_context(_root_binding(env.root, options["cwd"], error=error))
            if facts["identity"] != env.repository["identity"]: refuse(error, "effect_environment_unavailable")
            cwd_fd, descriptors = facts["cwd_fd"], facts["fds"]
        else:
            cwd_fd = directories.enter_context(_directory(options["cwd"]))
        options = {**options, "cwd": f"/proc/self/fd/{cwd_fd}"}
        read_fd, write_fd = os.pipe()
        process = None
        try:
            os.set_blocking(read_fd, False)
            command = [sys.executable, "-I", "-c", _HOLDER_SOURCE, str(write_fd), str(timeout), *(str(fd) for fd in descriptors), str(pinned[0]), str(ssh_fd), *argv]
            options = {**options, "executable": interpreter, "pass_fds": tuple(dict.fromkeys((*options["pass_fds"], write_fd, *pinned, *(fd for fd in descriptors if fd >= 0)))), "start_new_session": True}
            def bind(raw):
                nonlocal process
                process = _HolderProcess(raw, read_fd, error, kind, timeout_error)
                process.directories = facts
                os.close(write_fd)
                try:
                    if select.select([read_fd], [], [], timeout)[0]:
                        process.read_status()
                except (OSError, ValueError):
                    if kind == "gh":
                        _gh_process_error(error, "gh_transport_failed")
                    spawn_refusal(error, started=True)  # Lost acknowledgment: never a definite rejection.
                return process
            yield command, options, bind
        finally:
            if process is None:
                os.close(write_fd)
            else:
                failed = cleanup_holder(process)
                process.read_status()
                process.status_fd = None
            os.close(read_fd)
            if process is not None and failed:
                _gh_process_error(error, "gh_cleanup_failed" if kind == "gh" else "git_cleanup_failed")


def effect_started(process):
    """The effect's acknowledgment, independent of the custody holder's spawn."""
    return process is not None and process.started


def cleanup_holder(process):
    """Never SIGKILL the custody holder: request group death and complete reaping."""
    failed = False
    try:
        if process.raw.poll() is None:
            process.raw.send_signal(signal.SIGUSR1)
        process.raw.wait(timeout=5)
    except (OSError, process.timeout_error):
        failed = True
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                failed = True
    return failed


def legacy_effect(argv, *, cwd, env, stdin, tty, timeout, effect_fds, error, observe, scope):
    """Keep legacy effects on the admitted capture sink, including tty stdin."""
    with scope(scratch=Path(cwd), worktree_root=env.root, _boundary=env._proof["kind"], stdout_limit=128 * 1024 * 1024, stderr_limit=128 * 1024 * 1024):
        return observe(argv, cwd=cwd, env=env, stdin=stdin, timeout=timeout,
                       error=error, effect_fds=effect_fds, _tty=tty, worktree_root=env.root)


def execute_effect(args, cwd, environ, env, hardening, policy, timeout, stdin, tty, effect_fds, *, error, observe, scope, build, base, resolver, issue=None, identity=None, write_roots=(), preflight=None, worktree_root=None, transport=None):
    """Resolve and run against one filtered environment, outside the checkout."""
    validate_cwd(cwd, error=error)
    if policy is not None and policy.strict_lane:
        if env is not None and (type(env) not in (dict, MappingProxyType, _ENVIRON_TYPE) or len(env) > 6):
            raise error("Strict lane Git command refused.", code="git_custody_refused", process_started=False)
        identity(transport.merge(policy.env, env or {}, error=error), args)
    effective = effect_environment(environ, cwd, error=error,
        roots=bounded_roots(write_roots, scratch=policy.scratch if policy is not None else None, error=error), base=base, overrides=env, scope=policy.env if policy is not None else None, worktree_root=worktree_root, custody_root=policy.worktree_root if policy is not None else None, transport=transport, kind="lane" if policy is not None and policy.strict_lane else "git")
    if policy is not None and policy.strict_lane:
        if policy.services is None or resolver is not policy.services.executable:
            raise error("Strict lane Git command refused.", code="git_custody_refused", process_started=False)
        preflight(build(args, "git", hardening, policy))
        if env is not None and (type(env) not in (dict, MappingProxyType, _ENVIRON_TYPE) or len(env) > 6):
            raise error("Strict lane Git command refused.", code="git_custody_refused", process_started=False)
        supplied = identity(transport.merge(policy.env, env or {}, error=error), args)
        return issue(cwd, policy.scratch, policy.services, effect_fds, environ=effective, worktree_root=effective.root, write_roots=write_roots).run(args, cwd, timeout,
            stdin, hardening, supplied, tty, stdout_limit=policy.stdout_limit, stderr_limit=policy.stderr_limit, effect_fds=effect_fds)
    argv = build(args, "git", hardening, policy)
    _git_command(argv, error)
    argv[0] = effect_executable(effective, cwd, resolver=resolver, error=error, transport=transport)
    if policy is not None:
        return observe(argv, cwd=cwd, env=effective, stdin=stdin, timeout=timeout, error=error, effect_fds=effect_fds, worktree_root=effective.root, _policy=policy)
    return legacy_effect(argv, cwd=cwd, env=effective, stdin=stdin, tty=tty, timeout=timeout,
                         effect_fds=effect_fds, error=error, observe=observe, scope=scope)


def _refuse_legacy(target, prefix, env, cwd, timeout, effect_fds, *, error, observe, scope):
    """Git only looks for legacy records for slashless remote nicknames."""
    from aegis_core import storage_confined
    if not target or target in (".", "..") or "/" in target:
        return
    if "\\" in target:
        _policy_refusal(error, "unsupported_remote_form")
    try:
        if len(target.encode("utf-8")) > 255:
            return  # No directory entry can have this name.
    except UnicodeError:
        _policy_refusal(error, "unsupported_remote_form")
    with scope(scratch=Path(cwd), worktree_root=env.root, _boundary=env._proof["kind"], stdout_limit=16384, stderr_limit=65536):
        result = observe([*prefix, "rev-parse", "--git-common-dir"], cwd=cwd,
            env=env, stdin=None, timeout=timeout, error=error, effect_fds=effect_fds, worktree_root=env.root)
    raw = result.stdout.rstrip(b"\r\n")
    if result.returncode or not raw or b"\0" in raw or b"\n" in raw or b"\r" in raw:
        _policy_refusal(error, "effect_configuration_unavailable")
    common = Path(cwd, os.fsdecode(raw))
    for directory in ("remotes", "branches"):
        try:
            with storage_confined.confined_file(common, (directory, target)) as record:
                record.read_bytes(0)
        except storage_confined.ConfinedFileError as exc:
            if exc.reason == "missing":
                continue
        _policy_refusal(error, "unsupported_remote_form")


def _remote_urls(args, groups, prefix, env, cwd, timeout, effect_fds, *, error, observe, scope):
    """Select the transport operand, including defaults and owner URL rewrites."""
    pairs = {"--receive-pack", "--exec", "--upload-pack", "--depth", "--deepen",
             "--shallow-since", "--shallow-exclude", "--filter", "--jobs", "-j", "--refmap",
             "--negotiation-tip", "--server-option", "--push-option", "-o"}
    flags = {"--porcelain", "--no-verify", "--no-signed", "--force", "--force-with-lease", "--dry-run",
             "-f", "-n", "-q", "-v", "--quiet", "--verbose", "--tags", "--no-tags", "--prune", "--atomic",
             "--progress", "--no-progress", "--update-head-ok", "--no-recurse-submodules"}
    targets, position, options = [], 1, True
    recurse = groups.get("submodule.recurse", ["false"])[-1]
    if recurse is None or recurse.lower() not in ("false", "no", "off", "0", ""):
        _policy_refusal(error, "unsupported_remote_form")
    while position < len(args):
        word = args[position]
        if word.split("=", 1)[0] in ("--repo", "--multiple", "--all"):
            _policy_refusal(error, "unsupported_remote_form", started=True)
        if options and word.startswith("--recurse-submodules") and word != "--recurse-submodules=no":
            _policy_refusal(error, "unsupported_remote_form")
        if options and word == "--":
            options = False
        elif options and word in pairs:
            if position + 1 >= len(args):
                _policy_refusal(error, "unsupported_remote_form")
            position += 1
        elif options and word.startswith("-"):
            if word not in flags and word.split("=", 1)[0] not in pairs | {"--force-with-lease", "--recurse-submodules"}:
                _policy_refusal(error, "unsupported_remote_form")
        else:
            targets.append(word)
        position += 1
    if targets:
        targets = targets[:1]
    else:
        with scope(scratch=Path(cwd), worktree_root=env.root, _boundary=env._proof["kind"], stdout_limit=16384, stderr_limit=65536):
            result = observe([*prefix, "symbolic-ref", "--quiet", "HEAD"], cwd=cwd,
                env=env, stdin=None, timeout=timeout, error=error, effect_fds=effect_fds, worktree_root=env.root)
        if result.returncode not in (0, 1) or len(result.stdout) > 16384:
            _policy_refusal(error, "effect_configuration_unavailable")
        ref = result.stdout.decode("utf-8", "replace").rstrip("\n")
        branch = ref[11:] if ref.startswith("refs/heads/") else ""
        choices = ((["branch." + branch + ".pushremote"] if branch else []) + ["remote.pushdefault"] if args[0] == "push" else [])
        choices += ["branch." + branch + ".remote"] if branch else []
        remotes = [key[7:-4] for key in groups if key.startswith("remote.") and key.endswith(".url")]
        default = remotes[0] if len(remotes) == 1 else "origin"
        targets = [next((groups[key][-1] for key in choices if key in groups), default)]
    urls = []
    for target in targets:
        if "remotes." + target.lower() in groups:
            _policy_refusal(error, "unsupported_remote_form")
        configured = groups.get("remote." + target + ".url")
        pushurls = groups.get("remote." + target + ".pushurl") if args[0] == "push" else None
        if not configured and not pushurls:
            _refuse_legacy(target, prefix, env, cwd, timeout, effect_fds, error=error, observe=observe, scope=scope)
        selected = configured or [target]
        selected = selected[:1] if args[0] == "fetch" else selected
        for url in pushurls or selected:
            kinds = (".pushinsteadof", ".insteadof") if args[0] == "push" and not pushurls else (".insteadof",)
            for suffix in kinds:
                rewrites = [(old, key[4:-len(suffix)]) for key, values in groups.items()
                            if key.startswith("url.") and key.endswith(suffix) for old in values if url.startswith(old)]
                if rewrites:
                    old, new = max(rewrites, key=lambda pair: len(pair[0]))
                    url = new + url[len(old):]
                    break
            urls.append(url)
    return urls


def _git_command(argv, error):
    position = 1
    while position + 1 < len(argv) and argv[position] == "-c":
        position += 2
    # No global option may redirect configuration or executable selection after
    # the final hardening. Unknown commands could be repository shell aliases.
    commands = {"version", "rev-parse", "merge-base", "diff-tree", "diff-index", "ls-tree", "ls-files",
                "cat-file", "for-each-ref", "check-ref-format", "hash-object", "symbolic-ref", "update-ref",
                "merge-tree", "read-tree", "checkout-index", "status", "write-tree",
                "update-index", "commit-tree", "pack-objects", "unpack-objects", "push", "fetch", "config", "gc"}
    if position >= len(argv) or argv[position] not in commands:
        refuse(error, "effect_command_refused")
    command = argv[position]
    if command == "gc" and list(argv[position:]) != ["gc", "--auto"]:
        refuse(error, "effect_command_refused")
    return position, command


_LOCATION_ENV = frozenset(("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_PREFIX",
    "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_REPLACE_REF_BASE", "GIT_SHALLOW_FILE"))


def validate_cwd(cwd, *, error):
    """Refuse before pathlib/custody can produce a base-class exception."""
    if type(cwd) not in (str, type(Path())) or len(str(cwd)) > 16384 or "\0" in str(cwd) or str(cwd).count(os.sep) > 128:
        refuse(error, "effect_command_refused")
    if not os.path.isabs(cwd) or ".." in Path(cwd).parts:
        refuse(error, "invalid_effect_cwd")
