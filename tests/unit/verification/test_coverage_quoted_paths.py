"""R-checks-32: git C-quotes a path with a non-ASCII byte, a tab, a quote or a backslash in its diff
headers. Every changed line must still be attributed to its real repo-relative path; a malformed escape
never raises. Tab and quote names are tested as diff text only, never created on disk."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from aegis_core.verification.coverage_check import parse_changed_lines
from tests import helpers_humangate as hg

HUNK = "@@ -0,0 +1,2 @@\n+a = 1\n+b = 2\n"


def changed_for(header: str) -> dict:
    return parse_changed_lines(f"diff --git a/x b/x\n--- /dev/null\n+++ {header}\n{HUNK}")


@pytest.mark.parametrize("header,path", [
    ('"b/pkg/\\303\\251.py"', "pkg/é.py"),
    ('"b/pkg/\\346\\226\\207\\344\\273\\266.py"', "pkg/文件.py"),
    ('"b/pkg/a\\tb.py"', "pkg/a\tb.py"),
    ('"b/pkg/q\\"d.py"', 'pkg/q"d.py'),
    ('"b/pkg/z\\\\w.py"', "pkg/z/w.py"),
    ("b/pkg/é.py", "pkg/é.py"),
    ("b/pkg/with space.py\t", "pkg/with space.py"),
], ids=["latin", "cjk", "tab", "quote", "backslash", "raw-utf8", "space"])
def test_a_quoted_header_path_is_unquoted(header, path):
    assert changed_for(header) == {path: {1, 2}}


def test_a_malformed_escape_never_raises_and_keeps_the_lines():
    changed = changed_for('"b/pkg/x\\q.py"')
    assert list(changed.values()) == [{1, 2}]
    assert next(iter(changed)).endswith(".py")


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_a_real_diff_of_a_non_ascii_file_attributes_its_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Given a real repository adding é.py, When git's own -p output is parsed, Then both added lines belong
    to é.py (git quotes the name by default; the old parser dropped the file)."""
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write("README.md", "# x\n")
    base = repo.commit("base")
    repo.write("é.py", "a = 1\nb = 2\n")
    head = repo.commit("add")
    raw = subprocess.run(["git", "-c", "core.quotepath=true", "diff-tree", "-r", "-p", "-U0", base, head],
                         cwd=str(repo.root), capture_output=True, check=True,
                         env={**os.environ, **repo.home.env}).stdout
    assert b'"b/\\303\\251.py"' in raw
    assert parse_changed_lines(raw.decode("utf-8", "replace")) == {"é.py": {1, 2}}


@pytest.mark.skipif(not hg.git_ok(), reason="needs git")
def test_coverage_of_a_non_ascii_file_counts_its_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """End to end (R-checks-32 with R-checks-33): a fake coverage run reports lines 1 and 2 of é.py missing,
    so both are executable and uncovered; never a vacuous pass over an empty denominator."""
    import json

    from aegis_core.verification import coverage_check

    home = tmp_path / "home"
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    repo = hg.Repo(tmp_path / "project", hg.Home(home))
    repo.write("README.md", "# x\n")
    repo.commit("base")
    repo.branch("work")
    repo.write("é.py", "a = 1\nb = 2\n")
    repo.commit("add")

    def fake(argv, cwd=None, env=None, timeout=60):
        if argv[3] == "json":
            report = {"files": {"é.py": {"executed_lines": [], "missing_lines": [1, 2]}}}
            Path(argv[argv.index("-o") + 1]).write_bytes(json.dumps(report).encode("utf-8"))
        return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}

    monkeypatch.setattr(coverage_check, "run_external_cmd", fake)
    res = coverage_check.run_diff_coverage(repo.root, "main", "HEAD")
    assert (res["status"], res["executable_lines"], res["covered_lines"], res["ratio"]) == ("reported", 2, 0, 0.0)
    assert res["uncovered_ranges"] == {"é.py": [[1, 2]]}
