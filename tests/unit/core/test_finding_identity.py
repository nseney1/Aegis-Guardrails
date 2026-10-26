"""The identity of a Layer 1 finding (CYC-1), whose one home is aegis_core.primitives.

A finding's ``fp`` is the full SHA-256 hex digest of the UTF-8 (surrogatepass) bytes of
``rule|path|normalized line|occurrence index``, joined by a literal ``|``. A file's lines split at
CRLF, CR and LF only; a line is normalized by trimming it and collapsing its whitespace runs; the
occurrence index counts the earlier lines with the same text (lines are one-based, and a line that
does not exist has index 0). A v1 baseline.json written before the move must keep matching, and the
scanner subtracts merge-base findings by the same key, so none of this may change.

The guards go through baseline and the scanner and hold before and after the move; the cases that
import primitives were red until the helpers lived there.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import List

import pytest

from aegis_core import baseline
from aegis_core.verification import ToolEvidence, scanners

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
# sha256(b"forbid_ast:no-eval|src/a.py|x = eval(y)|2"), recorded before the move
GOLDEN = "b3ac1009fc77e93eb8284e8db39f654e3c07817df1499caed824542e3ec6827e"
BREAKS = "a\r\nb\rc\nd\x0be\x0cf\x1cg\x1dh\x1ei\x85j k l\n"
SPLIT = ["a", "b", "c", "d\x0be\x0cf\x1cg\x1dh\x1ei\x85j k l", ""]
SPACED = " x =\x0b\x0ceval( y )\x1c\x1d\x1e\x1f\x85  　"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)
    for name in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)


# ── guards: through baseline and the scanner, before and after the move ──────

def test_a_fingerprint_is_the_full_sha256_of_the_literally_joined_utf8_fields():
    assert baseline.Finding("forbid_ast:no-eval", "src/a.py", "x = eval(y)", 2, 40, "d").fp == GOLDEN
    # The | is joined as is, never escaped: these two splits of the same text are one finding.
    assert baseline.Finding("r|x", "p", "t", 0, 1, "d").fp == baseline.Finding("r", "x|p", "t", 0, 1, "d").fp
    # A path from a non-UTF-8 file name (a lone surrogate) still has a fingerprint.
    assert baseline.Finding("r", "caf\udce9.py", "t", 0, 1, "d").fp == hashlib.sha256(
        "r|caf\udce9.py|t|0".encode("utf-8", "surrogatepass")).hexdigest()


def test_a_file_splits_at_crlf_cr_and_lf_only(tmp_path):
    (tmp_path / "a.py").write_bytes(BREAKS.encode("utf-8"))
    assert baseline.Sources(tmp_path).lines("a.py") == SPLIT


def test_a_line_is_read_trimmed_with_its_whitespace_collapsed_and_one_based(tmp_path):
    (tmp_path / "a.py").write_bytes(f"x = eval( y )\r\n{SPACED}\r\n".encode("utf-8"))
    sources = baseline.Sources(tmp_path)
    assert sources.line_text("a.py", 1) == sources.line_text("a.py", 2) == "x = eval( y )"
    assert [sources.occurrence("a.py", n) for n in (1, 2)] == [0, 1]
    for missing in (-1, 0, 4):
        assert (sources.line_text("a.py", missing), sources.occurrence("a.py", missing)) == ("", 0)


def _fps(root: Path, lines: List[str], numbers: List[int]) -> List[str]:
    (root / "a.py").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    evidence = ToolEvidence(tool="call_graph", target="a.py", verdict=False, detail="orphan", lines=numbers)
    return [f.fp for f in baseline.collect([("a.py", evidence)], baseline.Sources(root)).findings]


def test_a_baselined_line_survives_a_move_and_not_a_change_and_a_copy_is_another_finding(tmp_path):
    (first,) = _fps(tmp_path, ["def helper(x):", "    return x"], [1])
    (moved,) = _fps(tmp_path, ["import os", "", "def helper(x):", "    return x"], [3])
    (changed,) = _fps(tmp_path, ["def helper(x, y):", "    return x"], [1])
    repeated = _fps(tmp_path, ["def helper(x):", "    return x", "def helper(x):"], [1, 3])
    assert moved == first != changed
    assert repeated == [first, hashlib.sha256(b"call_graph|a.py|def helper(x):|1").hexdigest()]


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                    *args], cwd=str(root), check=True, capture_output=True)


def _flag_keys(argv, cwd, env=None, timeout=60):
    """A scanner stand-in: every line of conf.py holding a key, its snippet masked the same way."""
    lines = (Path(cwd) / "conf.py").read_text(encoding="utf-8").splitlines()
    results = [{"ruleId": "aws-access-token", "level": "error", "message": {"text": "a key"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "conf.py"},
                                                    "region": {"startLine": n, "snippet": {"text": "REDACTED"}}}}]}
               for n, line in enumerate(lines, 1) if "AKIA" in line]
    sarif = {"version": "2.1.0", "runs": [{"results": results}]}
    return {"returncode": 1 if results else 0, "stdout": json.dumps(sarif), "stderr": ""}


@needs_git
def test_a_rotated_key_under_the_same_mask_is_new_and_the_same_key_moved_is_not(tmp_path):
    old, new = "AKIA" + "ABCDEFGHIJKLMN" + "XY", "AKIA" + "QRSTUVWXYZ2345" + "XY"
    assert scanners.mask_secret(old) == scanners.mask_secret(new)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "conf.py").write_bytes(f'KEY = "{old}"\n'.encode("utf-8"))
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    (root / "conf.py").write_bytes(f'"""Settings."""\n\nKEY = "{old}"\n'.encode("utf-8"))
    moved = scanners.run_preset("ruff", root, "HEAD", runner=_flag_keys)
    (root / "conf.py").write_bytes(f'KEY = "{new}"\n'.encode("utf-8"))
    rotated = scanners.run_preset("ruff", root, "HEAD", runner=_flag_keys)
    assert (moved["status"], moved["findings"], moved["subtracted"]) == ("pass", [], 1)
    assert (rotated["status"], len(rotated["findings"]), rotated["subtracted"]) == ("fail", 1, 0)


# ── the helpers in their home (moved from test_baseline.py) ──────────────────

def test_the_fingerprint_is_the_full_hex_of_sha256_over_the_four_fields():
    from aegis_core.primitives import fingerprint

    expected = hashlib.sha256("forbid_ast:no-eval|src/a.py|x = eval(y)|0".encode("utf-8")).hexdigest()
    assert fingerprint("forbid_ast:no-eval", "src/a.py", "x = eval(y)", 0) == expected
    assert len(expected) == 64


@pytest.mark.parametrize("field, other", [
    ("rule", ("import_guard", "src/a.py", "x = eval(y)", 0)),
    ("path", ("forbid_ast:no-eval", "src/b.py", "x = eval(y)", 0)),
    ("text", ("forbid_ast:no-eval", "src/a.py", "x = eval(z)", 0)),
    ("index", ("forbid_ast:no-eval", "src/a.py", "x = eval(y)", 1)),
])
def test_every_field_changes_the_fingerprint(field, other):
    from aegis_core.primitives import fingerprint

    assert fingerprint("forbid_ast:no-eval", "src/a.py", "x = eval(y)", 0) != fingerprint(*other)


def test_text_is_normalized_so_indentation_and_spacing_runs_do_not_matter():
    from aegis_core.primitives import normalize_text

    assert normalize_text("    x  =\teval( y )  \r") == "x = eval( y )"
    assert normalize_text("x = eval(y)") == normalize_text("\t\tx = eval(y)")
    assert normalize_text("x = eval(y)") != normalize_text("x = eval(z)")
    assert normalize_text("   ") == ""


def test_lines_split_where_cpython_counts_them_and_nowhere_else():
    from aegis_core.primitives import split_lines

    # A form feed or a vertical tab does not start a line for the tokenizer, so line numbers
    # from the AST must index the same list: str.splitlines() would shift every later line.
    text = "a\r\nb\rc\nd\x0ce\x0bf\x1cg\u2028h\n"
    assert split_lines(text) == ["a", "b", "c", "d\x0ce\x0bf\x1cg\u2028h", ""]


def test_repeated_lines_are_numbered_by_occurrence():
    from aegis_core.primitives import occurrence_index

    lines = ["import a", "x = eval(1)", "y = 2", "x = eval(1)", "x = eval(1)"]
    assert [occurrence_index(lines, n) for n in (2, 4, 5)] == [0, 1, 2]
    assert occurrence_index(lines, 3) == 0
    # indentation is not part of the text: the same call, deeper, is the same line
    assert occurrence_index(["eval(1)", "    eval(1)"], 2) == 1


def test_an_unknown_line_has_no_text_and_index_zero():
    from aegis_core.primitives import occurrence_index

    assert occurrence_index(["a"], 0) == 0
    assert occurrence_index(["a"], 9) == 0


def test_the_line_index_answers_one_based_and_zero_outside_the_file():
    from aegis_core.primitives import LineIndex

    index = LineIndex(["import a", "x = eval(1)", "y = 2", "    x  =  eval(1)", SPACED])
    assert [index.text(n) for n in (0, 1, 4, 5, 6)] == ["", "import a", "x = eval(1)", "x = eval( y )", ""]
    assert [index.index(n) for n in (-1, 0, 2, 4, 6)] == [0, 0, 0, 1, 0]
