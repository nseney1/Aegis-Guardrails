"""The day-0 card (v4.2 #1): what a repository looks like to Aegis before anything is set up.

Languages, AST drivers, rules by type, the Layer 1 pass rate and the files with the most
findings. It reads and changes nothing (the baseline above all), samples above 2,000
files and says so, and says plainly when no active rule targets any file.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Dict

import pytest

from aegis_cli.formatters.text import render_card
from aegis_core import card, events
from aegis_core._version import __version__
from tests.helpers_checkmodes import NO_EVAL, commit, init_repo, write

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
PERSONA = "---\nid: idiom\ntype: persona\nhypothesis: Prefer small functions.\n---\n# Small functions\n"
PERSONA_PY = PERSONA.replace("id: idiom", "id: idiom-py").replace("---\n#", "target_paths:\n  - '*.py'\n---\n#")
PERSONA_NOWHERE = PERSONA.replace("id: idiom", "id: idiom-go").replace("---\n#", "target_paths:\n  - '*.go'\n---\n#")


@pytest.fixture(autouse=True)
def _own_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = init_repo(tmp_path / "project")
    write(root, "app.py", "def run():\n    return 1\n")
    write(root, "README.md", "# project\n")
    commit(root, "base")
    return root


def _tree(root: Path) -> Dict[str, str]:
    """Every file below ``root`` (the .git directory aside) with a digest of its bytes."""
    found = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".git" not in path.relative_to(root).parts:
            found[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


# ── Content ──────────────────────────────────────────────────────────────────

def test_the_card_counts_languages_by_extension(repo: Path):
    write(repo, "lib/util.py", "def util():\n    return 2\n")
    write(repo, "web/app.ts", "export const x = 1;\n")
    write(repo, "svc/main.go", "package main\n")
    data = card.build(repo).as_dict()
    assert {row["language"]: row["files"] for row in data["languages"]} == {"python": 2, "typescript": 1, "go": 1}
    assert [row["language"] for row in data["languages"]][0] == "python"  # most files first


def test_python_has_its_builtin_driver_and_others_say_whether_one_is_enabled(repo: Path):
    write(repo, "svc/lib.rs", "pub fn f() {}\n")
    drivers = {row["language"]: row for row in card.build(repo).as_dict()["drivers"]}
    assert drivers["python"]["status"] == "ready" and "in-process" in drivers["python"]["driver"]
    assert drivers["rust"]["status"] == "ready" and drivers["rust"]["driver"] == "native Rust (in-process)"
    write(repo, ".aegis/config.json", json.dumps({"v": 1, "ast": {"packaged_drivers": ["rs"]}}))
    drivers = {row["language"]: row for row in card.build(repo).as_dict()["drivers"]}
    assert drivers["rust"]["status"] == "ready" and drivers["rust"]["driver"]


def test_rules_are_counted_by_type_and_active_ones_named(repo: Path):
    write(repo, ".aegis/rules/personas/idiom-py.md", PERSONA_PY)
    write(repo, ".aegis/rules/personas/idiom-go.md", PERSONA_NOWHERE)
    rules = card.build(repo).as_dict()["rules"]
    assert rules["total"] == 3 and rules["by_type"] == {"invariant": 1, "persona": 2}
    assert rules["served"] == 3 and rules["errors"] == 0
    assert rules["active"] == ["idiom-py", "no-eval"]  # no-eval is a forbid_ast gate: it targets every file


def test_a_rule_that_does_not_load_is_counted_and_never_active(repo: Path):
    (repo / ".aegis" / "rules" / "invariants" / "broken.md").write_bytes(
        b"---\nid: broken\ntype: invariant\nforbid_ast:\n  calls: [eval]\n---\nNo \xff here.\n")
    built = card.build(repo)
    rules = built.as_dict()["rules"]
    assert rules["errors"] == 1 and rules["total"] == 2 and "broken" not in rules["active"]
    assert "1 rule file(s) cannot be served" in "\n".join(render_card(built.as_dict()))


def test_an_expired_rule_is_not_active(repo: Path):
    write(repo, ".aegis/rules/personas/idiom-py.md", PERSONA_PY.replace("---\n#", "expired_at: 2020-01-01\n---\n#"))
    assert "idiom-py" not in card.build(repo).as_dict()["rules"]["active"]


def test_layer_1_pass_rate_counts_the_checkable_files(repo: Path):
    write(repo, "bad1.py", "x = eval('1')\n")
    write(repo, "bad2.py", "y = eval('2')\n")
    write(repo, "ok.py", "def ok():\n    return 1\n")
    layer1 = card.build(repo).as_dict()["layer1"]
    assert layer1["checked"] == 4  # app.py, bad1.py, bad2.py, ok.py: the README is not Layer 1's
    assert (layer1["passed"], layer1["failed"], layer1["pass_rate"]) == (2, 2, 0.5)
    assert layer1["findings"] == 2 and layer1["checks_that_could_not_run"] == []


def test_the_files_with_most_findings_come_first_and_at_most_five(repo: Path):
    for number, count in enumerate([1, 3, 2, 5, 4, 6, 1], 1):
        write(repo, f"m{number}.py", "".join(f"v{i} = eval({i})\n" for i in range(count)))
    top = card.build(repo).as_dict()["top_files"]
    assert [(row["path"], row["findings"]) for row in top] == [
        ("m6.py", 6), ("m4.py", 5), ("m5.py", 4), ("m2.py", 3), ("m3.py", 2)]


def test_equal_counts_are_ordered_by_path(repo: Path):
    write(repo, "b.py", "x = eval(1)\n")
    write(repo, "a.py", "x = eval(1)\n")
    assert [row["path"] for row in card.build(repo).as_dict()["top_files"]] == ["a.py", "b.py"]


def test_a_check_that_could_not_run_is_said_and_makes_no_file_fail(repo: Path):
    write(repo, ".aegis/rules/invariants/broken.md", "---\nid: broken\ntype: invariant\nforbid_ast: [eval]\n---\nx\n")
    layer1 = card.build(repo).as_dict()["layer1"]
    assert layer1["failed"] == 0 and layer1["pass_rate"] == 1.0
    assert len(layer1["checks_that_could_not_run"]) == 1
    assert any("could not run" in note for note in card.build(repo).as_dict()["notes"])


def test_an_empty_repository_has_no_pass_rate(tmp_path: Path):
    root = init_repo(tmp_path / "empty", rules=False)
    layer1 = card.build(root).as_dict()["layer1"]
    assert (layer1["checked"], layer1["pass_rate"], layer1["findings"]) == (0, None, 0)
    assert "no file" in "\n".join(render_card(card.build(root).as_dict()))


# ── No active rule ───────────────────────────────────────────────────────────

def test_the_card_says_when_no_active_rule_targets_any_file(tmp_path: Path):
    root = init_repo(tmp_path / "bare", rules=False)
    write(root, ".aegis/rules/personas/idiom-go.md", PERSONA_NOWHERE)
    write(root, "app.py", "x = 1\n")
    commit(root, "base")
    built = card.build(root)
    data = built.as_dict()
    assert data["rules"]["active"] == [] and data["rules"]["total"] == 1
    note = "No active rule targets any file: aegis check enforces no rule until one names files."
    assert note in data["notes"] and note in "\n".join(render_card(built.as_dict()))
    assert "Next: add a rule for your own code with aegis rule create" in "\n".join(render_card(built.as_dict()))


def test_the_note_is_absent_when_a_rule_is_active(repo: Path):
    assert not any("No active rule" in note for note in card.build(repo).as_dict()["notes"])


def test_a_repository_without_rules_says_so_too(tmp_path: Path):
    root = init_repo(tmp_path / "norules", rules=False)
    write(root, "app.py", "x = 1\n")
    data = card.build(root).as_dict()
    assert data["rules"]["total"] == 0
    assert any(note.startswith("No active rule targets any file") for note in data["notes"])


# ── Sampling ─────────────────────────────────────────────────────────────────

def test_the_limit_is_two_thousand():
    assert card.SAMPLE_LIMIT == 2000


def test_up_to_the_limit_every_file_is_taken():
    files = [f"f{i:04}.py" for i in range(2000)]
    assert card.sample(files) == files
    assert card.sample(files[:3], limit=3) == files[:3]


def test_above_the_limit_a_deterministic_even_sample_is_taken():
    files = [f"f{i:04}.py" for i in range(2001)]
    picked = card.sample(files)
    assert len(picked) == 2000 and picked == card.sample(files)
    assert picked == sorted(set(picked)) and set(picked) <= set(files)
    assert picked[0] == files[0]
    spread = [files.index(f) for f in picked]
    assert max(b - a for a, b in zip(spread, spread[1:])) <= 2  # no stretch of the listing is skipped


def test_the_card_says_when_it_sampled(repo: Path):
    for number in range(30):
        write(repo, f"gen/g{number:02}.py", "def g():\n    return 1\n")
    built = card.build(repo, sample_limit=10)
    data = built.as_dict()
    assert data["scope"]["sampled"] is True
    assert data["scope"]["sample_limit"] == 10 and data["scope"]["files_analyzed"] == 10
    assert data["scope"]["files"] == 33  # 30 generated + app.py, README.md, the rule
    assert data["layer1"]["checked"] <= 10
    assert any("sampled" in note.lower() for note in data["notes"])
    assert "Sampled 10 of 33 files" in "\n".join(render_card(built.as_dict()))
    # languages are counted on the whole listing, not on the sample
    assert {row["language"]: row["files"] for row in data["languages"]}["python"] == 31


def test_a_full_run_says_it_was_not_sampled(repo: Path):
    data = card.build(repo).as_dict()
    assert data["scope"]["sampled"] is False and data["scope"]["files_analyzed"] == data["scope"]["files"]
    assert not any("sampled" in note.lower() for note in data["notes"])


# ── Side effects ─────────────────────────────────────────────────────────────

def test_the_card_changes_nothing_and_never_touches_the_baseline(repo: Path):
    write(repo, "bad.py", "x = eval('1')\n")
    write(repo, ".aegis/baseline.json", '{"v": 1, "findings": []}\n')
    before, stamp = _tree(repo), os.stat(repo / ".aegis" / "baseline.json").st_mtime_ns
    card.build(repo)
    card.build(repo).as_dict()
    assert _tree(repo) == before
    assert os.stat(repo / ".aegis" / "baseline.json").st_mtime_ns == stamp


def test_the_card_creates_no_baseline(repo: Path):
    card.build(repo)
    assert not (repo / ".aegis" / "baseline.json").exists()


def test_the_card_writes_no_event_and_no_state(repo: Path):
    card.build(repo)
    assert events.read(repo).rows == []
    assert not (repo / ".aegis" / "state").exists()


def test_the_card_reads_a_broken_baseline_without_complaint(repo: Path):
    write(repo, ".aegis/baseline.json", "{not even json")
    assert card.build(repo).as_dict()["layer1"]["checked"] >= 1


# ── Outside git, and an unreadable rules tree ────────────────────────────────

def test_outside_git_the_files_are_found_by_walking(tmp_path: Path):
    root = tmp_path / "plain"
    write(root, ".aegis/rules/invariants/no-eval.md", NO_EVAL)
    write(root, "app.py", "x = eval('1')\n")
    write(root, "node_modules/dep/index.js", "x\n")
    data = card.build(root).as_dict()
    assert data["scope"]["listing"] == "walk"
    assert [row["path"] for row in data["top_files"]] == ["app.py"]
    assert not any(row["language"] == "javascript" for row in data["languages"])  # vendored code is not counted
    assert any("not a git work tree" in note.lower() for note in data["notes"])


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_an_unsafe_rules_tree_is_reported_and_the_card_still_renders(repo: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, repo / ".aegis" / "rules" / "traps")
    built = card.build(repo)
    data = built.as_dict()
    assert data["rules"]["error"] and data["rules"]["total"] == 0
    assert "rules: cannot be read" in "\n".join(render_card(built.as_dict()))
    assert data["layer1"]["checked"] >= 1


# ── The documents ────────────────────────────────────────────────────────────

def test_the_json_carries_the_envelope(repo: Path):
    data = card.build(repo, now=0).as_dict()
    assert data["source"] == "aegis check --card" and data["aegis_version"] == __version__
    assert data["checked_at"] == "1970-01-01T00:00:00Z" and TS.match(card.build(repo).as_dict()["checked_at"])
    assert data["scope"]["workspace"] == str(repo)
    assert set(data) >= {"languages", "drivers", "rules", "layer1", "top_files", "notes", "scope"}
    json.dumps(data)  # serializable


def test_the_text_card_reads_top_to_bottom(repo: Path):
    write(repo, "bad.py", "x = eval('1')\n")
    text = "\n".join(render_card(card.build(repo).as_dict()))
    for fragment in ("Aegis day-0 card", f"workspace: {repo}", "languages: python 2", "AST drivers: python: built-in",
                     "rules: 1 (invariant 1)", "1 active", "Layer 1: 50% of 2 files pass", "1 finding(s) in 1 file(s)",
                     "files with the most findings:", "1  bad.py"):
        assert fragment in text, fragment
