"""A repository for `aegis sync --pr` (R-evidence-13): real git, a local bare origin, a fake gh.

``make`` builds ``main`` holding one trap rule with 25 tp labels merged at the reviewed BASE (a
decided promotion; fp labels make it a decided archive), pushes it to a bare repository next to it and points origin/HEAD at it, as a
clone would have it. Nothing reaches the network: the origin is a directory, and ``FakeGh`` stands
in for gh, recording each call and the branches the origin holds when ``pr create`` runs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional


def git(cwd: Path, *args: str, check: bool = True) -> str:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
    res = subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=str(cwd), env=env, capture_output=True,
                         check=check)
    return res.stdout.decode("utf-8", "replace").strip()


RULE = ("---\nid: {rid}\ntype: trap\nenforcement: advisory\nhypothesis: h\ncreated: '2026-01-01'\n"
        "target_paths:\n  - 'src/*.py'\n---\n# {rid}\n\nRule body for {rid}.\n")


class Repo:
    def __init__(self, root: Path, origin: Path, rule: str) -> None:
        self.root, self.origin, self.rule = root, origin, rule

    @property
    def rule_path(self) -> Path:
        return self.root / ".aegis" / "rules" / "traps" / f"{self.rule}.md"

    def state(self) -> Dict[str, Any]:
        """What must be byte-identical after a refused or failed run."""
        rules = self.root / ".aegis"
        files = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in sorted(rules.rglob("*"))
                 if p.is_file() and "state" not in p.relative_to(rules).parts}
        audit = rules / "state" / "lifecycle.jsonl"  # machine-local: only a move that happened here is logged
        return {"head": git(self.root, "rev-parse", "HEAD"), "branch": git(self.root, "symbolic-ref", "-q", "HEAD",
                                                                           check=False),
                "status": git(self.root, "status", "--porcelain"), "files": files,
                "lifecycle": audit.read_bytes() if audit.is_file() else None,
                "branches": git(self.root, "for-each-ref", "--format=%(refname)", "refs/heads")}

    def origin_branches(self) -> List[str]:
        out = git(self.origin, "for-each-ref", "--format=%(refname:short)", "refs/heads")
        return [line for line in out.splitlines() if line]


def make(tmp_path: Path, rule: str = "trap-decided", labels: int = 25, detections: int = 2, verdict: str = "tp") -> Repo:
    from aegis_core import credit

    root, origin = tmp_path / "repo", tmp_path / "origin.git"
    root.mkdir()
    git(tmp_path, "init", "-q", "--bare", str(origin))
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "dev@example.com")
    git(root, "config", "user.name", "Dev")
    path = root / ".aegis" / "rules" / "traps" / f"{rule}.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(RULE.format(rid=rule).encode("utf-8"))
    (root / "src").mkdir()
    (root / "src" / "app.py").write_bytes(b"x = 1\n")
    (root / ".gitignore").write_bytes(b".aegis/state/\n")
    store = root / ".aegis" / "adjudications" / f"{rule}.jsonl"
    store.parent.mkdir(parents=True)
    store.write_bytes(b"".join(json.dumps({
        "example_id": f"{rule}-{n}", "verdict": verdict, "session": f"s{n % 4}", "repo": f"r{n % 2}",
        "ts": f"2026-09-{1 + n % 28:02d}T00:00:00Z"}).encode("utf-8") + b"\n" for n in range(labels)))
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "remote", "add", "origin", str(origin))
    git(root, "push", "-q", "origin", "main")
    git(root, "remote", "set-head", "origin", "main")
    for n in range(detections):
        credit.record_detection(root, rule, f"src/m{n}.py", "eval", disposition="leaked", rev=f"{n + 1:040x}",
                                ts=f"2026-10-0{n + 1}T00:00:00Z")
    return Repo(root, origin, rule)


class FakeGh:
    """gh at the client boundary: records argv; ``pr create`` answers a URL or fails."""

    def __init__(self, origin: Path, returncode: int = 0) -> None:
        self.origin, self.returncode = origin, returncode
        self.calls: List[List[str]] = []
        self.origin_at_create: Optional[List[str]] = None

    def __call__(self, argv: List[str], cwd: Optional[str] = None) -> Any:
        self.calls.append(list(argv))
        if argv[:2] == ["pr", "create"]:
            self.origin_at_create = Repo(Path(cwd or "."), self.origin, "").origin_branches()
        out = "https://example.invalid/pull/7\n" if self.returncode == 0 else ""
        err = "" if self.returncode == 0 else "gh: could not create the pull request"
        return type("GhResult", (), {"returncode": self.returncode, "stdout": out, "stderr": err})()

    def flag(self, name: str) -> Optional[str]:
        create = next(c for c in self.calls if c[:2] == ["pr", "create"])
        return create[create.index(name) + 1] if name in create else None
