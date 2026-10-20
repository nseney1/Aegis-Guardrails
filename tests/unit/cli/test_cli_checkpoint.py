"""The workspace checkpoint inside `aegis check` (aegis_cli/checkpoint.py).

v3's `aegis checkpoint` is gone (D5): its checks run on every `aegis check`.
- Issues are warnings ([WARN], exit 0) unless --strict ([FAIL], exit 1).
- A paper gate (a gate or invariant rule whose enforcement is not `gate`) always blocks,
  and so does a rule file that cannot be loaded (aegis scan refuses to serve the set).
- Checks: test file per source file, hardcoded /home, /Users, /tmp paths,
  per-test assertions, unhealthy rule fitness from the ledger, rule conventions.
- The checkpoint reads the workspace and never writes to it.
"""
from __future__ import annotations

import json
from pathlib import Path

from aegis_cli.checkpoint import run_checkpoint
from aegis_cli.cli import main


def _exit_code(argv: list[str]) -> int:
    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code


def _clean_workspace(root: Path) -> Path:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(parents=True, exist_ok=True)
    (root / "src" / "math_utils.py").write_text(
        "def multiply(a: int, b: int) -> int:\n    return a * b\n", encoding="utf-8"
    )
    (root / "tests" / "test_math_utils.py").write_text(
        "from src.math_utils import multiply\n\n\ndef test_multiply():\n    assert multiply(2, 3) == 6\n",
        encoding="utf-8",
    )
    state = root / ".aegis" / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "ledger.jsonl").write_text(
        "\n".join(
            json.dumps({"cell": "math-rule", "signal": s, "timestamp": "2026-09-30T12:00:00Z"})
            for s in ("trigger", "tp")
        )
        + "\n",
        encoding="utf-8",
    )
    return root


def _paper_gate(root: Path) -> None:
    invariants = root / ".aegis" / "rules" / "invariants"
    invariants.mkdir(parents=True, exist_ok=True)
    (invariants / "wall-bad.md").write_text(
        "---\nid: wall-bad\ntype: invariant\nenforcement: advisory\n---\n# Bad Wall\n", encoding="utf-8"
    )


class TestRunCheckpoint:
    def test_clean_workspace_has_no_issues(self, tmp_path):
        assert run_checkpoint(_clean_workspace(tmp_path), strict=True) == ([], False)

    def test_empty_workspace_has_no_issues(self, tmp_path):
        assert run_checkpoint(tmp_path, strict=True) == ([], False)

    def test_missing_test_file_warns_unless_strict(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "service.py").write_text("def handle():\n    return 'ok'\n", encoding="utf-8")
        issues, blocking = run_checkpoint(tmp_path, strict=False)
        assert [i["message"] for i in issues] == ["Missing test file for service.py: expected tests/test_service.py"]
        assert blocking is False
        assert run_checkpoint(tmp_path, strict=True)[1] is True

    def test_paper_gate_blocks_even_without_strict(self, tmp_path):
        _clean_workspace(tmp_path)
        _paper_gate(tmp_path)
        issues, blocking = run_checkpoint(tmp_path, strict=False)
        assert blocking is True
        assert "paper_gates" in {i["check"] for i in issues}

    def test_an_unreadable_invariant_is_a_blocking_paper_gate(self, tmp_path):
        """Its enforcement cannot be read, so it cannot be shown to be a gate (b1-verify review)."""
        _clean_workspace(tmp_path)
        invariants = tmp_path / ".aegis" / "rules" / "invariants"
        invariants.mkdir(parents=True)
        (invariants / "invariant-x.md").write_bytes(b"---\nid: invariant-x\nenforcement: gate\n---\n\xff\n")
        issues, blocking = run_checkpoint(tmp_path, strict=False)
        paper = [i for i in issues if i["check"] == "paper_gates"]
        assert [i["file"] for i in paper] == [".aegis/rules/invariants/invariant-x.md"]
        assert paper[0]["message"].startswith(
            "Invariant rule 'invariant-x.md' cannot be read, so it cannot be shown to use 'gate': invalid UTF-8:"
        )
        assert blocking is True

    def test_a_skip_only_test_is_flagged(self, tmp_path):
        _clean_workspace(tmp_path)
        (tmp_path / "tests" / "test_stub.py").write_text(
            "import pytest\n\n\ndef test_unwritten():\n    pytest.skip('TODO')\n", encoding="utf-8"
        )
        issues, _ = run_checkpoint(tmp_path, strict=False)
        assert [i["message"] for i in issues] == [
            "Low assertion density in test_stub.py: tests lacking assertions: test_unwritten"
        ]

    def test_hardcoded_path_is_flagged(self, tmp_path):
        _clean_workspace(tmp_path)
        (tmp_path / "src" / "cache.py").write_text('CACHE = "/home/alice/data/cache.bin"\n', encoding="utf-8")
        (tmp_path / "tests" / "test_cache.py").write_text(
            "from src.cache import CACHE\n\n\ndef test_cache():\n    assert CACHE.endswith('.bin')\n",
            encoding="utf-8",
        )
        issues, _ = run_checkpoint(tmp_path, strict=False)
        assert [(i["check"], i["file"], i["line"]) for i in issues] == [("hardcoded_paths", "src/cache.py", 1)]

    def test_assertion_less_test_is_flagged(self, tmp_path):
        _clean_workspace(tmp_path)
        (tmp_path / "tests" / "test_vacuous.py").write_text(
            "def test_does_nothing():\n    x = 1 + 2\n    y = x * 3\n", encoding="utf-8"
        )
        issues, _ = run_checkpoint(tmp_path, strict=False)
        assert [i["message"] for i in issues] == [
            "Low assertion density in test_vacuous.py: tests lacking assertions: test_does_nothing"
        ]

    def test_unhealthy_rule_fitness_is_flagged_from_the_ledger(self, tmp_path):
        _clean_workspace(tmp_path)
        (tmp_path / ".aegis" / "state" / "ledger.jsonl").write_text(
            "\n".join(
                json.dumps({"cell": "noisy-rule", "signal": s, "timestamp": f"2026-09-30T10:{i:02d}:00Z"})
                # MIN_N (25) false positives: no misfire flag below the one sample gate (R-evidence-8)
                for i, s in enumerate(("trigger",) * 3 + ("fp",) * 25)
            )
            + "\n",
            encoding="utf-8",
        )
        # Legacy outcomes would make the FP rate exactly 50% if read; only the ledger counts.
        evidence = tmp_path / ".aegis" / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / "outcomes.jsonl").write_text(
            "\n".join(json.dumps({"cell_id": "noisy-rule", "outcome": "tp"}) for _ in range(25)) + "\n",
            encoding="utf-8",
        )
        issues, _ = run_checkpoint(tmp_path, strict=True)
        assert [(i["check"], i.get("rule")) for i in issues] == [("rule_fitness", "noisy-rule")]


class TestCheckpointThroughCheck:
    def test_clean_project_passes_strict(self, tmp_path, capsys):
        _clean_workspace(tmp_path)
        assert _exit_code(["check", "--workspace", str(tmp_path), "--strict"]) == 0
        assert "checkpoint: all checks passed" in capsys.readouterr().out

    def test_warnings_exit_zero_and_strict_fails(self, tmp_path, capsys):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "orphaned.py").write_text("def worker():\n    return 1\n", encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(tmp_path)]) == 0
        assert "[WARN] Missing test file for orphaned.py" in capsys.readouterr().out
        assert _exit_code(["check", "--workspace", str(tmp_path), "--strict"]) == 1
        assert "[FAIL] Missing test file for orphaned.py" in capsys.readouterr().out

    def test_paper_gate_fails_check_and_hook_without_strict(self, tmp_path, capsys):
        _clean_workspace(tmp_path)
        _paper_gate(tmp_path)
        assert _exit_code(["check", "--workspace", str(tmp_path)]) == 1
        assert _exit_code(["check", "--workspace", str(tmp_path), "--hook"]) == 1
        out = capsys.readouterr().out
        assert "[FAIL] Invariant rule 'wall-bad.md' enforcement is 'advisory'" in out

    def test_a_rule_left_in_a_v3_directory_fails_check_without_strict(self, tmp_path, capsys):
        """It would silently stop applying; check blocks until it is migrated (#19)."""
        _clean_workspace(tmp_path)
        walls = tmp_path / ".aegis" / "rules" / "walls"
        walls.mkdir(parents=True)
        (walls / "wall-bad.md").write_text(
            "---\nid: wall-bad\ntype: wall\nenforcement: gate\n---\n# Old wall\n", encoding="utf-8"
        )
        assert _exit_code(["check", "--workspace", str(tmp_path)]) == 1
        out = capsys.readouterr().out
        assert "[FAIL] .aegis/rules/walls/wall-bad.md: not served: walls/ is not a rule type directory" in out

    def test_json_reports_issues_in_one_document(self, tmp_path, capsys):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "untested.py").write_text('SECRET = "/home/admin/.keys"\n', encoding="utf-8")
        assert _exit_code(["check", "--workspace", str(tmp_path), "--strict", "--format", "json"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["passed"] is False
        assert {i["check"] for i in payload["checkpoint_issues"]} == {"test_coverage", "hardcoded_paths"}

    def test_nonexistent_workspace_is_an_error(self, tmp_path, capsys):
        # Direct callers: the CLI resolves --workspace before check runs (wave C, AD-4).
        import argparse

        from aegis_cli.verify import run_verify

        missing = tmp_path / "does_not_exist"
        assert run_verify(argparse.Namespace(workspace=str(missing), files=[], strict=True)) == 1
        assert f"workspace does not exist: {missing}" in capsys.readouterr().err

    def test_checkpoint_never_writes_to_the_workspace(self, tmp_path):
        _clean_workspace(tmp_path)
        rule = tmp_path / ".aegis" / "rules" / "traps" / "trap-x.md"
        rule.parent.mkdir(parents=True)
        rule.write_text("---\nid: trap-x\ntype: trap\ndomain: style\nenforcement: advisory\n---\nbody\n", encoding="utf-8")
        before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        _exit_code(["check", "--workspace", str(tmp_path), "--strict"])
        after = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        assert after == before
