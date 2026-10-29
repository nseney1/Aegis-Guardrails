"""Rules match the files git reports as changed (the SDK `Governance.scan` path).

`get_changed_files` falls back to `git status --porcelain` when HEAD~1 does not
exist, and `match_rules_to_changes` maps those paths to the rules that target them.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from aegis_core.outcomes.engine import get_changed_files, match_rules_to_changes
from aegis_core.yaml_engine.serializer import dump_frontmatter


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _write_rule(ws: Path, rule_id: str, target_paths: list[str]) -> Path:
    rules = ws / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True, exist_ok=True)
    path = rules / f"{rule_id}.md"
    fm = {"id": rule_id, "type": "trap", "target_paths": target_paths,
          "hypothesis": "h", "prediction": "p"}
    path.write_text(dump_frontmatter(fm, body="Body\n"), encoding="utf-8")
    return path


def _matched_rules(ws: Path) -> set[str]:
    return {c["_name"] for c in match_rules_to_changes(ws, get_changed_files(str(ws)))}


def test_rule_matches_an_unstaged_modification(tmp_path: Path) -> None:
    """`git status --porcelain` lines start with a space for unstaged edits (" M path").

    Stripping that space before slicing off the 3-char status turned " M src/app.py"
    into "rc/app.py", so no rule matched an unstaged edit in a single-commit repo.
    """
    _write_rule(tmp_path, "guard-src", ["src/*.py"])
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    (tmp_path / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")

    assert get_changed_files(str(tmp_path)) == ["src/app.py"]
    assert _matched_rules(tmp_path) == {"guard-src"}


def test_rule_matches_a_renamed_destination(tmp_path: Path) -> None:
    """A staged rename is reported as "R  old -> new"; the rule on the destination must match."""
    _write_rule(tmp_path, "guard-lib", ["lib/*.py"])
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "init")
    (tmp_path / "lib").mkdir()
    _git(tmp_path, "mv", "src/a.py", "lib/a.py")

    assert get_changed_files(str(tmp_path)) == ["lib/a.py"]
    assert _matched_rules(tmp_path) == {"guard-lib"}
