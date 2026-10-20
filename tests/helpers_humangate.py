"""Fixtures for the human_gate tests: real git repositories, real ssh-keygen signatures, a fake gh.

Nothing here reaches the network or the developer's own keys: every key is generated into a
temporary directory, the user-scope git config is a throwaway HOME, and ``FakeGh`` stands in
for the ``gh`` program at the runner boundary.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aegis_core import human_gate

PRINCIPAL = "human@example.com"


def git_ok() -> bool:
    return shutil.which("git") is not None


def signing_ok() -> bool:
    """git with SSH signing (2.34) and ssh-keygen: what a real approval needs."""
    if not git_ok() or shutil.which("ssh-keygen") is None:
        return False
    out = subprocess.run(["git", "version"], capture_output=True, text=True).stdout.split()
    try:
        major, minor = (int(p) for p in out[2].split(".")[:2])
    except (IndexError, ValueError):
        return False
    return (major, minor) >= (2, 34)


def run_git(root: Path, *args: str, env: Optional[Dict[str, str]] = None, stdin: Optional[str] = None,
            check: bool = True) -> subprocess.CompletedProcess:
    full = dict(os.environ)
    full.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
    full.update(env or {})
    return subprocess.run(["git", "-c", "core.autocrlf=false", *args], cwd=str(root), env=full, input=stdin,
                          capture_output=True, text=True, check=check)


def git(root: Path, *args: str, **kw: Any) -> str:
    return run_git(root, *args, **kw).stdout.strip()


def keygen(directory: Path, name: str, passphrase: str = "") -> Tuple[Path, str]:
    """A fresh ed25519 key pair; returns (private key path, public key text)."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-C", name, "-f", str(path)],
                   check=True, capture_output=True)
    return path, (directory / (name + ".pub")).read_text(encoding="utf-8").strip()


def hardware_public_key() -> str:
    """A public key line of an OpenSSH security-key type (touch required); only its type matters."""
    def field(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data
    blob = field(b"sk-ssh-ed25519@openssh.com") + field(b"\x01" * 32) + field(b"ssh:")
    return "sk-ssh-ed25519@openssh.com " + base64.b64encode(blob).decode("ascii") + " hw-key"


def allowed_signers_text(*pubs: str) -> str:
    return "".join(f'{PRINCIPAL} namespaces="git" {pub}\n' for pub in pubs)


class Home:
    """A throwaway HOME whose ~/.gitconfig is the user-scope git config."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True, exist_ok=True)

    @property
    def env(self) -> Dict[str, str]:
        return {"HOME": str(self.path), "USERPROFILE": str(self.path), "GIT_CONFIG_NOSYSTEM": "1"}

    def config(self, key: str, value: str) -> None:
        subprocess.run(["git", "config", "--global", key, value], env={**os.environ, **self.env}, check=True)

    def sign_with(self, key: str, fmt: str = "ssh") -> None:
        self.config("user.name", "Human")
        self.config("user.email", PRINCIPAL)
        self.config("gpg.format", fmt)
        self.config("user.signingkey", key)


class Repo:
    """A repository on ``main`` with a base commit, then a ``work`` branch checked out."""

    def __init__(self, root: Path, home: Home) -> None:
        self.root = root
        self.home = home
        root.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str, **kw: Any) -> str:
        env = dict(self.home.env)
        env.update(kw.pop("env", None) or {})
        return git(self.root, "-c", "user.email=dev@example.com", "-c", "user.name=Dev",
                   "-c", "commit.gpgsign=false", *args, env=env, **kw)

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))

    def commit(self, message: str = "change", sign_key: Optional[Path] = None, allow_empty: bool = False) -> str:
        self.git("add", "-A")
        args = ["commit", "-q", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        if sign_key is not None:
            args = ["-c", "gpg.format=ssh", "-c", f"user.signingkey={sign_key}", *args, "-S"]
        self.git(*args)
        return self.git("rev-parse", "HEAD")

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")

    def branch(self, name: str) -> None:
        self.git("checkout", "-q", "-b", name)


RULE = ("---\nid: trap-sample\ntype: trap\nenforcement: advisory\nhypothesis: sample\n"
        "target_paths:\n  - src/*.py\n---\n# Sample\n\nBody long enough to be a rule body.\n")


def make_repo(tmp_path: Path, signer_pub: Optional[str] = None, name: str = "project") -> Repo:
    """``main`` holds a rule, source and (with ``signer_pub``) an allowed_signers file;
    the ``work`` branch is checked out and holds no change yet."""
    home = Home(tmp_path / "home")
    repo = Repo(tmp_path / name, home)
    repo.write("README.md", "# project\n")
    repo.write("src/app.py", "def app():\n    return 1\n")
    repo.write(".aegis/rules/traps/trap-sample.md", RULE)
    if signer_pub is not None:
        repo.write("allowed_signers", allowed_signers_text(signer_pub))
    repo.commit("base")
    repo.branch("work")
    return repo


class FakeGh:
    """The gh runner boundary: answers `gh api` GETs from ``routes`` and records every call."""

    def __init__(self, default_branch: str = "main", admin: bool = False, rules: Optional[List[Dict[str, Any]]] = None,
                 rulesets: Optional[List[Dict[str, Any]]] = None, owner: str = "octo",
                 owner_type: Optional[str] = "User") -> None:
        self.default_branch = default_branch
        self.admin = admin
        self.rules = rules if rules is not None else []
        self.rulesets = rulesets if rulesets is not None else []
        self.owner = owner
        self.owner_type = owner_type
        self.calls: List[Tuple[Tuple[str, ...], Optional[bytes]]] = []
        self.missing = False

    def __call__(self, argv: Sequence[str], stdin: Optional[bytes] = None, cwd: Any = None):
        if self.missing:
            return None
        argv = tuple(argv)
        self.calls.append((argv, stdin))
        method = argv[argv.index("--method") + 1] if "--method" in argv else "GET"
        path = argv[-1] if stdin is None else argv[argv.index("--input") - 1]
        if method == "GET" and path == "repos/{owner}/{repo}":
            owner = {"login": self.owner, **({} if self.owner_type is None else {"type": self.owner_type})}
            body: Any = {"full_name": f"{self.owner}/proj", "default_branch": self.default_branch,
                         "owner": owner, "permissions": {"admin": self.admin, "push": True}}
        elif method == "GET" and "/rules/branches/" in path:
            body = self.rules
        elif method == "GET" and path.endswith("/rulesets"):
            body = self.rulesets
        elif method == "POST" and path.endswith("/rulesets"):
            body = {"id": 7, "name": json.loads(stdin or b"{}").get("name")}
        else:
            return human_gate.GhResult(1, "", f"unexpected gh call {argv}")
        return human_gate.GhResult(0, json.dumps(body), "")

    @property
    def methods(self) -> List[str]:
        return [c[0][c[0].index("--method") + 1] for c in self.calls if "--method" in c[0]]

    @property
    def posts(self) -> List[Tuple[Tuple[str, ...], Optional[bytes]]]:
        return [c for c in self.calls if "--method" in c[0] and c[0][c[0].index("--method") + 1] != "GET"]


def pull_request_rule(approvals: int = 1, code_owners: bool = True, dismiss_stale: Any = True,
                      last_push: bool = False) -> Dict[str, Any]:
    return {"type": "pull_request", "parameters": {"required_approving_review_count": approvals,
                                                    "require_code_owner_review": code_owners,
                                                    "dismiss_stale_reviews_on_push": dismiss_stale,
                                                    "require_last_push_approval": last_push}}


def checks_rule(*contexts: str, integration_id: Any = human_gate.GITHUB_ACTIONS_APP_ID) -> Dict[str, Any]:
    """Required checks whose source is pinned to GitHub Actions; ``integration_id=None`` omits the source."""
    source = {} if integration_id is None else {"integration_id": integration_id}
    return {"type": "required_status_checks", "parameters": {
        "required_status_checks": [{"context": c, **source} for c in (contexts or ("aegis-check",))]}}


# The Aegis job a required check must name (the scaffold's shape, without a version pin).
AEGIS_WORKFLOW = (
    "name: Aegis\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  aegis-check:\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v7\n      - run: aegis check --ci\n"
)


CODEOWNERS_FULL = (
    "/.aegis/rules/ @octo\n/.aegis/config.json @octo\n/.aegis/team.json @octo\n/.aegis/baseline.json @octo\n"
    "/allowed_signers @octo\n/CODEOWNERS @octo\n/.github/CODEOWNERS @octo\n/.github/workflows/ @octo\n"
    "conftest.py @octo\npytest.ini @octo\n.pytest.ini @octo\npytest.toml @octo\n.pytest.toml @octo\n"
    "tox.ini @octo\nsetup.cfg @octo\npyproject.toml @octo\nsitecustomize.py @octo\n*.pth @octo\nMakefile @octo\n"
    "pytest.* @octo\n_pytest.* @octo\npluggy.* @octo\npy.* @octo\niniconfig.* @octo\n"
    "/pytest/ @octo\n/_pytest/ @octo\n/pluggy/ @octo\n/py/ @octo\n/iniconfig/ @octo\n"
)
