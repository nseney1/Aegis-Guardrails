"""The gh subprocess transport: safe repository resolution and isolated execution (L0)."""
from __future__ import annotations

from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, NamedTuple, Optional, Sequence, Tuple

from aegis_core import gitsafe, pathlookup
from aegis_core.gitsafe_run import BASE_ENV as _GIT_BASE_ENV, Environment, AMBIENT_ENV, request_environment, find_executable, custody_inputs, transport_services

__all__ = ["GH_TIMEOUT_SECONDS", "GhResult", "GhRunner", "default_gh_runner", "gh_json", "resolve_repo", "effect_runner"]

GH_TIMEOUT_SECONDS = 10.0


class GhResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


GhRunner = Callable[..., Optional[GhResult]]
# Injected runners (github_ruleset / human_gate) own their descendant custody.
# Effects require supports_effect_fds=True and binding through effect_runner;
# the declaration promises a custody holder that reaps every effect descendant.


def effect_runner(runner: GhRunner, effect_fds, *, worktree_root=None) -> GhRunner:
    """Bind one receipt to an explicitly custody-aware injected runner."""
    from aegis_core import gitops_fds
    return gitops_fds.bind_runner(runner, effect_fds, error=gitsafe.GitError, worktree_root=worktree_root)

# scheme://[userinfo@]host[:port]/path and scp-style [user@]host:path. A port is dropped only where it
# is the git transport's (ssh, git); an http(s) port names another API endpoint than gh's host.
_URL_REMOTE = re.compile(r"\A(?P<scheme>https?|ssh|git)://(?:[^/@]*@)?(?P<host>[A-Za-z0-9.-]+)(?::(?P<port>\d+))?/(?P<path>.*)\Z")
_SCP_REMOTE = re.compile(r"\A(?:[^/@:]+@)?(?P<host>[A-Za-z0-9-][A-Za-z0-9.-]+):(?P<path>[^/].*)\Z")
_REPO_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_NO_REPO = "no GitHub repository could be resolved from remote.origin.url"


def resolve_repo(root: Any, *, effect_fds=None, env=None, timeout=GH_TIMEOUT_SECONDS, write_roots=(), worktree_root=None) -> Optional[str]:
    """``owner/repo`` (github.com) or ``host/owner/repo`` (gh's ``[HOST/]OWNER/REPO``) of
    ``remote.origin.url`` read through gitsafe; None for a path remote, a subgroup, no origin or a git
    that cannot answer. Userinfo (a token) never reaches the result."""
    if effect_fds is not None:
        from aegis_core import gitops_fds
        gitops_fds.pass_through(effect_fds, error=gitsafe.GitError)
        gitops_fds.validate_cwd(root, error=gitsafe.GitError)
    try:
        options = {"effect_fds": effect_fds, "_environ": request_environment(request_environment(env, profile="strict/effect", kind="gh").source, profile="strict/effect", root=env.root, roots=env.roots, kind="git") if type(env) is Environment else env, "timeout": timeout, "write_roots": write_roots, "worktree_root": worktree_root} if effect_fds is not None else {}
        with gitsafe.custody(scratch=Path(root).absolute(), stdout_limit=16384, worktree_root=worktree_root) if effect_fds is not None else nullcontext():
            res = gitsafe.run(["config", "--get", "remote.origin.url"], Path(root), **options)
    except gitsafe.GitError:
        if effect_fds is not None:
            raise
        return None
    url = os.fsdecode(res.stdout).strip() if res.returncode == 0 else ""
    found = _URL_REMOTE.match(url) or _SCP_REMOTE.match(url)
    if found is None or (found.re is _URL_REMOTE and found["port"] and found["scheme"].startswith("http")):
        return None
    path = found["path"][:-1] if found["path"].endswith("/") else found["path"]
    parts = (path[:-4] if path.endswith(".git") else path).split("/")
    if len(parts) != 2 or not all(_REPO_SEGMENT.fullmatch(p) and p.strip(".") for p in parts):
        return None
    host = found["host"].lower()
    return "/".join(parts) if host == "github.com" else "/".join((host, *parts))


def default_gh_runner(
    argv: Sequence[str],
    stdin: Optional[bytes] = None,
    cwd: Any = None,
    timeout: float = GH_TIMEOUT_SECONDS, *, effect_fds=None, env=None, write_roots=(), worktree_root=None,
) -> Optional[GhResult]:
    """Run gh for the repository at ``cwd``. gh never runs inside it: resolving ``{owner}/{repo}``
    there would start git under the repository's own config, outside gitsafe. It runs in an empty
    directory below a git ceiling, with the repository passed as ``GH_REPO``.
    effect_fds and worktree_root opt into built-in API calls only; file input is --input -;
    isolated gh config requires environment-token authentication. The caller owns
    its receipt until all effect activity ends; no descriptor is closed here.
    env optionally supplies a bounded dictionary instead of the ambient environment."""
    if effect_fds is None and env is not None and (type(env) is not dict or len(env) > 512
            or any(type(k) is not str or type(v) is not str or len(k) > 256 or len(v) > 65536
                   or "\0" in k or "\0" in v or "=" in k for k, v in env.items())):
        raise gitsafe.GitError("GitHub CLI environment refused.", code="invalid_gh_environment",
                              process_started=False, next_action="Supply a bounded string environment dictionary.")
    environ = env if effect_fds is not None else request_environment(env, profile="ordinary", base={})
    effect_kw = {}
    if effect_fds is not None:
        from aegis_core import gitops_fds
        effect_kw = gitops_fds.pass_through(effect_fds, error=gitsafe.GitError)
        argv, environ, paginate = _gh_command(argv, stdin, timeout, effect_fds, error=gitsafe.GitError, environ=environ, cwd=cwd, public_host=_public_gh_host, base=_GIT_BASE_ENV, roots=write_roots, worktree_root=worktree_root)
        if paginate:
            return _effect_paginate(_EFFECT_RUNNER, argv, stdin, cwd, timeout, effect_fds, environ, error=gitsafe.GitError, result_type=GhResult)
    exe = find_executable({}, environ, lambda effective: pathlookup.which("gh", outside=getattr(effective, "root", cwd), **({"path": effective.get("PATH", "")} if env is not None or effect_fds is not None else {})), error=gitsafe.GitError, missing_ok=True)
    if exe is None:
        if effect_fds is not None:
            gitops_fds.gh_refusal(error=gitsafe.GitError, reason="not_installed")
        return None
    repo = resolve_repo(cwd, **({"effect_fds": effect_fds, "env": environ, "timeout": timeout, "worktree_root": environ.root} if effect_fds is not None else {})) if cwd is not None else None
    if repo is None and any("{owner}" in arg or "{repo}" in arg for arg in argv):
        if effect_fds is not None:
            gitops_fds.gh_refusal(error=gitsafe.GitError, reason="repository_unresolved")
        return GhResult(125, "", _NO_REPO)
    if effect_fds is not None:
        _gh_repo(repo, environ, error=gitsafe.GitError)
    try:
        scratch = tempfile.mkdtemp(prefix="aegis-gh-", **({"dir": gitops_fds.scratch_root(environ, error=gitsafe.GitError)} if effect_fds is not None else {}))
    except OSError as exc:
        if effect_fds is not None:
            gitops_fds.gh_refusal(error=gitsafe.GitError, reason="scratch_unavailable")
        return GhResult(126, "", f"cannot run gh: {exc}")
    ceilings = dict.fromkeys((os.path.dirname(scratch), os.path.dirname(os.path.realpath(scratch))))
    owned = {
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "NO_COLOR": "1",
        "GIT_CEILING_DIRECTORIES": os.pathsep.join(ceilings),
        **({"GH_REPO": repo} if repo is not None else {}),
    }
    if effect_fds is not None:
        owned.update(_gh_bindings(environ, scratch))
    env = request_environment(environ, profile="strict/effect" if effect_fds is not None else "ordinary",
        base=_GIT_BASE_ENV if effect_fds is not None else {}, bindings=owned, kind="gh", error=gitsafe.GitError)
    try:
        if effect_fds is not None:
            with gitops_fds.holder_recipe([exe, *argv], _gh_popen_options(env, scratch, stdin, effect_kw), timeout, error=gitsafe.GitError, timeout_error=subprocess.TimeoutExpired, kind="gh", transport=transport_services()) as (command, options, bind):
                proc = bind(subprocess.Popen(command, **options))
                proc = _gh_collect(proc, stdin, timeout, error=gitsafe.GitError)
        else:
            proc = subprocess.run(
                [exe, *argv],
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                capture_output=True,
                env=env,
                cwd=scratch,
                timeout=timeout,
                check=False, **effect_kw,
            )
    except subprocess.TimeoutExpired:
        return GhResult(124, "", "Git operation gh timed out; observe before recovery." if effect_fds is not None else f"gh timed out after {timeout:g}s")
    except OSError as exc:
        if effect_fds is not None:
            gitops_fds.gh_refusal(error=gitsafe.GitError, reason="spawn_failed")
        return GhResult(126, "", f"cannot run gh: {exc}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if effect_fds is not None and proc.returncode:
        return GhResult(proc.returncode, "", "Git operation gh command failed; observe before recovery.")
    return GhResult(
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


default_gh_runner.supports_effect_fds = True
_EFFECT_RUNNER = default_gh_runner


def gh_json(runner: GhRunner, endpoint: str, cwd: Path) -> Tuple[Any, Optional[str]]:
    result = runner(["api", "--method", "GET", endpoint], None, cwd)
    if result is None:
        return None, "gh is not installed"
    if result.returncode != 0:
        detail = " ".join((result.stderr or result.stdout).split())[:200] or f"exit {result.returncode}"
        return None, f"gh api {endpoint} failed: {detail}"
    try:
        return json.loads(result.stdout), None
    except ValueError:
        return None, f"gh api {endpoint} did not return JSON"


def _public_gh_host(host):
    return host in ("github.com", "github.localhost") or host.endswith(".ghe.com")


def _gh_page_error(error, reason, started=True):
    raise error("GitHub pagination refused.", code="gh_pagination_" + reason,
                process_started=started, next_action="Observe the started request before recovery." if started
                else "Supply a supported pagination request; no effect process started.") from None


def _gh_page_args(argv, error):
    base, endpoint, include, slurp, position = ["api"], None, False, False, 1
    pairs = {"--method", "-X", "--hostname", "--header", "-H"}
    while position < len(argv):
        arg = argv[position]
        if arg in ("--input", "--raw-field", "-f"):
            _gh_page_error(error, "request_refused", False)
        if arg in pairs:
            if arg in ("--method", "-X") and argv[position + 1].upper() != "GET":
                _gh_page_error(error, "request_refused", False)
            base.extend(argv[position:position + 2])
            position += 2
            continue
        if arg in ("--include", "-i"):
            include = True
        elif arg == "--slurp":
            slurp = True
        elif arg != "--paginate":
            if not arg.startswith("-"):
                endpoint = len(base)
            base.append(arg)
        position += 1
    if endpoint is None or include and slurp:
        _gh_page_error(error, "request_refused", False)
    return base, endpoint, include, slurp


def _gh_page_response(stdout, host, error):
    if len(stdout) > 4 * 1024 * 1024:
        _gh_page_error(error, "output_limit")
    delimiters = [(stdout.find(d), d) for d in ("\r\n\r\n", "\n\r\n", "\n\n") if stdout.find(d) >= 0]
    if not delimiters:
        _gh_page_error(error, "response_refused")
    headers, _, body = stdout.partition(min(delimiters)[1])
    if len(headers) > 65536 or not headers.startswith("HTTP/"):
        _gh_page_error(error, "response_refused")
    links = []
    for line in headers.replace("\r\n", "\n").splitlines():
        if line.lower().startswith("link:"):
            links.extend(re.findall(r'<([^>]+)>;\s*rel="next"', line, re.I))
    if len(links) > 1:
        _gh_page_error(error, "response_refused")
    return body, _gh_page_target(links[0], host, error) if links else None


def _gh_page_target(target, host, error):
    if len(target) > 16384:
        _gh_page_error(error, "response_refused")
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(target)
        expected = "api." + host if _public_gh_host(host) else host
        scheme, port = ("http", 80) if host == "github.localhost" else ("https", 443)
        if (parsed.scheme != scheme or parsed.hostname != expected or parsed.port not in (None, port)
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            _gh_page_error(error, "host_refused")
    except ValueError:
        _gh_page_error(error, "host_refused")
    prefix = "/" if _public_gh_host(host) else "/api/v3/"
    if not parsed.path.startswith(prefix):
        _gh_page_error(error, "host_refused")
    return parsed.path[len(prefix):] + ("?" + parsed.query if parsed.query else "")


def _effect_paginate(runner, argv, stdin, cwd, timeout, effect_fds, environ, *, error, result_type):
    """Own pagination in the trusted parent; gh never follows a Link-header host."""
    if stdin is not None:
        _gh_page_error(error, "request_refused", False)
    base, endpoint, include, slurp = _gh_page_args(argv, error)
    deadline, chunks, pages, total, started = time.monotonic() + timeout, [], [], 0, False
    for _ in range(32):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _gh_page_error(error, "timeout", started)
        try:
            result = runner(["api", "--include", *base[1:]], None, cwd, remaining,
                            effect_fds=effect_fds, env=environ, worktree_root=environ.root)
        except error as exc:
            if started:
                exc.process_started = True
                exc.effect_process_started = True
                exc.next_action = "Observe the started request before recovery."
            raise
        started = True
        if result.returncode:
            return result
        body, target = _gh_page_response(result.stdout, environ["GH_HOST"], error)
        total += len(result.stdout)
        if total > 16 * 1024 * 1024:
            _gh_page_error(error, "output_limit")
        if slurp:
            try:
                pages.append(json.loads(body))
            except (ValueError, RecursionError):
                _gh_page_error(error, "response_refused")
        else:
            chunks.append(result.stdout if include else body)
        if target is None:
            try:
                return result_type(0, json.dumps(pages, ensure_ascii=False) if slurp else "".join(chunks), "")
            except (ValueError, RecursionError):
                _gh_page_error(error, "response_refused")
        base[endpoint] = target
    _gh_page_error(error, "page_limit")


def _gh_bindings(env, scratch):
    """Trusted gh scratch bindings; the shared constructor applies these values."""
    owned = {"GH_CONFIG_DIR": scratch, "HOME": scratch, "USERPROFILE": scratch, "XDG_CONFIG_HOME": scratch,
        "GH_PAGER": "", "PAGER": "", "GH_BROWSER": "false", "BROWSER": "false", "GH_EDITOR": "false",
        "GH_FORCE_TTY": "", "GIT_SSH_COMMAND": "false", "GIT_SSH": "false", "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_PARAMETERS": "", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    for index, (key, value) in enumerate((("credential.helper", ""), ("core.askPass", ""), ("core.sshCommand", "false"),
                                        ("gc.auto", "0"), ("maintenance.auto", "false"))):
        owned["GIT_CONFIG_KEY_" + str(index)] = key
        owned["GIT_CONFIG_VALUE_" + str(index)] = value
    owned["GH_ENTERPRISE_TOKEN" if _public_gh_host(env["GH_HOST"]) else "GH_TOKEN"] = "aegis-host-disabled"
    return owned


def _gh_command(argv, stdin, timeout, effect_fds, *, error, environ, cwd=None, public_host, base, roots=(), worktree_root=None):
    """Only the built-in HTTP API is an effect transport; no file/pager/git consumers."""
    if effect_fds is None:
        return argv, environ, False
    from aegis_core import gitops_fds
    if type(environ) is Environment:
        environ = request_environment(environ, profile="strict/effect", bindings={}, kind="gh", error=error)
    if cwd is not None: gitops_fds.validate_cwd(cwd, error=error)
    environ = gitops_fds.effect_environment(environ, cwd, error=error, allowed=AMBIENT_ENV | frozenset((*_GH_TOKENS, "GH_HOST", "GH_REPO")), base=base, roots=roots, worktree_root=worktree_root, scope=custody_inputs(), transport=transport_services(), kind="gh")
    gitops_fds.effect_inputs(argv, stdin, timeout, effect_fds, error=error, envs=(environ,), transport=transport_services())
    import math
    if (type(argv) not in (tuple, list) or not 2 <= len(argv) <= 512
            or any(type(arg) is not str or len(arg) > 16384 or "\0" in arg for arg in argv)
            or argv[0] != "api" or any("{branch}" in arg or ":branch" in arg for arg in argv)
            or stdin is not None and (type(stdin) is not bytes or len(stdin) > 128 * 1024 * 1024)
            or type(timeout) not in (int, float) or not 0 < timeout <= 300 or not math.isfinite(timeout)):
        gitops_fds.refuse(error, "effect_command_refused")
    # A closed flag grammar prevents flag abbreviations and magic-field file
    # loading; --input - is the sole input stream and already belongs to us.
    pairs = {"--method", "-X", "--header", "-H", "--raw-field", "-f", "--hostname"}
    flags = {"--paginate", "--slurp", "--silent", "--include", "-i", "--verbose"}
    position, endpoints, hosts, output, paginate = 1, 0, [], ["api"], False
    while position < len(argv):
        arg = argv[position]
        if arg in pairs or arg == "--input":
            if position + 1 >= len(argv) or arg == "--input" and argv[position + 1] != "-":
                gitops_fds.refuse(error, "effect_command_refused")
            if arg == "--hostname":
                hosts.append(argv[position + 1])
            else:
                output.extend(argv[position:position + 2])
            position += 2
            continue
        if arg in flags:
            paginate |= arg == "--paginate"
            output.append(arg)
            position += 1
            continue
        if arg.startswith("-"):
            gitops_fds.refuse(error, "effect_command_refused")
        if not arg or ":" in arg or arg.startswith("//"):
            gitops_fds.refuse(error, "effect_command_refused")
        output.append(arg)
        endpoints += 1
        position += 1
    if endpoints != 1:
        gitops_fds.refuse(error, "effect_command_refused")
    host = _gh_host(environ.get("GH_HOST", "github.com"), error)
    if len(hosts) > 1:
        gitops_fds.refuse(error, "gh_host_mismatch")
    if hosts:
        explicit = _gh_host(hosts[0], error)
        if "GH_HOST" in environ and explicit != host:
            gitops_fds.refuse(error, "gh_host_mismatch")
        host = explicit
    token_names = ("GH_TOKEN", "GITHUB_TOKEN") if public_host(host) else ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
    token = next((environ.get(name) for name in token_names if environ.get(name)), None)
    if token is None:
        gitops_fds.refuse(error, "gh_token_host_mismatch" if any(environ.get(k) for k in _GH_TOKENS) else "gh_token_missing")
    if any(ord(c) < 33 or ord(c) == 127 for c in token):
        gitops_fds.refuse(error, "gh_token_missing")
    request_env = {"GH_HOST": host}
    request_env[token_names[0]] = token
    _gh_repo(environ.get("GH_REPO"), request_env, error=error)
    if environ.get("GH_REPO"):
        request_env["GH_REPO"] = environ["GH_REPO"]
    return [*output, "--hostname", host], request_environment(environ, profile="strict/effect", bindings={}, overrides=request_env,
        allowed=AMBIENT_ENV | frozenset((token_names[0], "GH_HOST", "GH_REPO")), error=error), paginate


_GH_TOKENS = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")




def _gh_host(host, error):
    from aegis_core import gitops_fds
    if not host or len(host) > 253 or re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host) is None:
        gitops_fds.refuse(error, "gh_host_mismatch")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        gitops_fds.refuse(error, "gh_host_mismatch")
    return host.lower()


def _gh_repo(repo, environ, *, error):
    if repo and repo.count("/") >= 2 and _gh_host(repo.split("/", 1)[0], error) != environ["GH_HOST"]:
        from aegis_core import gitops_fds
        gitops_fds.refuse(error, "gh_host_mismatch")


def _gh_popen_options(env, scratch, stdin, options):
    return {"cwd": scratch, "env": env, "stdin": subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "bufsize": 0, "start_new_session": True, **options}


def _gh_process_error(error, code):
    raise error("GitHub effect transport failed.", code=code, process_started=True,
                next_action="Observe the started request before recovery.") from None


def _gh_collect(process, stdin, timeout, *, error):
    """Bound concurrent pipes; only the holder receives custody and status fds."""
    from aegis_core import gitops_fds
    buffers = {process.stdout.fileno(): (bytearray(), 4 * 1024 * 1024),
               process.stderr.fileno(): (bytearray(), 65536)}
    pending = set(buffers)
    writer = process.stdin.fileno() if process.stdin is not None else None
    data, offset, deadline = memoryview(stdin or b""), 0, time.monotonic() + timeout
    try:
        for fd in (*pending, *((writer,) if writer is not None else ())):
            os.set_blocking(fd, False)
        while pending or writer is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _gh_process_error(error, "gh_timeout")
            if writer is not None and offset == len(data):
                process.stdin.close()
                writer = None
            if not pending and writer is None:
                break
            ready, writable, _ = select.select(list(pending), [writer] if writer is not None else [], [], remaining)
            for fd in ready:
                target, cap = buffers[fd]
                chunk = os.read(fd, min(65536, cap - len(target) + 1))
                if len(chunk) > cap - len(target):
                    _gh_process_error(error, "gh_output_limit")
                if chunk:
                    target.extend(chunk)
                else:
                    pending.remove(fd)
            if writable:
                try:
                    offset += os.write(writer, data[offset:offset + 65536])
                except BrokenPipeError:
                    process.stdin.close()
                    writer = None
        code = process.wait(timeout=max(0, deadline - time.monotonic()))
        return subprocess.CompletedProcess(process.args, code, bytes(buffers[process.stdout.fileno()][0]),
                                           bytes(buffers[process.stderr.fileno()][0]))
    except subprocess.TimeoutExpired:
        _gh_process_error(error, "gh_timeout")
    except (OSError, ValueError):
        _gh_process_error(error, "gh_transport_failed")
    finally:
        if gitops_fds.cleanup_holder(process):
            _gh_process_error(error, "gh_cleanup_failed")
