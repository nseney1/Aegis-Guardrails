"""The gh subprocess transport: safe repository resolution and isolated execution (L0)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Callable, NamedTuple, Optional, Sequence, Tuple

from aegis_core import gitsafe, pathlookup

__all__ = ["GH_TIMEOUT_SECONDS", "GhResult", "GhRunner", "default_gh_runner", "gh_json", "resolve_repo"]

GH_TIMEOUT_SECONDS = 10.0


class GhResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


GhRunner = Callable[..., Optional[GhResult]]
# scheme://[userinfo@]host[:port]/path and scp-style [user@]host:path. A port is dropped only where it
# is the git transport's (ssh, git); an http(s) port names another API endpoint than gh's host.
_URL_REMOTE = re.compile(r"\A(?P<scheme>https?|ssh|git)://(?:[^/@]*@)?(?P<host>[A-Za-z0-9.-]+)(?::(?P<port>\d+))?/(?P<path>.*)\Z")
_SCP_REMOTE = re.compile(r"\A(?:[^/@:]+@)?(?P<host>[A-Za-z0-9-][A-Za-z0-9.-]+):(?P<path>[^/].*)\Z")
_REPO_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_NO_REPO = "no GitHub repository could be resolved from remote.origin.url"


def resolve_repo(root: Any) -> Optional[str]:
    """``owner/repo`` (github.com) or ``host/owner/repo`` (gh's ``[HOST/]OWNER/REPO``) of
    ``remote.origin.url`` read through gitsafe; None for a path remote, a subgroup, no origin or a git
    that cannot answer. Userinfo (a token) never reaches the result."""
    try:
        res = gitsafe.run(["config", "--get", "remote.origin.url"], Path(root))
    except gitsafe.GitError:
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
    timeout: float = GH_TIMEOUT_SECONDS,
) -> Optional[GhResult]:
    """Run gh for the repository at ``cwd``. gh never runs inside it: resolving ``{owner}/{repo}``
    there would start git under the repository's own config, outside gitsafe. It runs in an empty
    directory below a git ceiling, with the repository passed as ``GH_REPO``."""
    exe = pathlookup.which("gh", outside=cwd)
    if exe is None:
        return None
    repo = resolve_repo(cwd) if cwd is not None else None
    if repo is None and any("{owner}" in arg or "{repo}" in arg for arg in argv):
        return GhResult(125, "", _NO_REPO)
    try:
        scratch = tempfile.mkdtemp(prefix="aegis-gh-")
    except OSError as exc:
        return GhResult(126, "", f"cannot run gh: {exc}")
    ceilings = dict.fromkeys((os.path.dirname(scratch), os.path.dirname(os.path.realpath(scratch))))
    env = {
        **os.environ,
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "NO_COLOR": "1",
        "GIT_CEILING_DIRECTORIES": os.pathsep.join(ceilings),
        **({"GH_REPO": repo} if repo is not None else {}),
    }
    try:
        proc = subprocess.run(
            [exe, *argv],
            input=stdin,
            stdin=None if stdin is not None else subprocess.DEVNULL,
            capture_output=True,
            env=env,
            cwd=scratch,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return GhResult(124, "", f"gh timed out after {timeout:g}s")
    except OSError as exc:
        return GhResult(126, "", f"cannot run gh: {exc}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return GhResult(
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


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
