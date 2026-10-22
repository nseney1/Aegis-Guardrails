"""Behavioral tests for T9 (PR-Native Output & Opt-in Diff Coverage) and T10 (status blocked_commands)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_cli.formatters.report import (
    format_github_annotations,
    format_github_step_summary,
    format_sarif_report,
)
from aegis_core import events
from aegis_core.verification.coverage_check import (
    evaluate_diff_coverage,
    parse_changed_lines,
    run_diff_coverage,
)


def hdr(path: str) -> str:
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"


class TestDiffCoverage:
    """Diff parsing, coverage evaluation, and isolated .aegis/state coverage execution."""

    def test_parse_changed_lines_from_unified_diff(self):
        diff_text = (
            "diff --git a/aegis_core/foo.py b/aegis_core/foo.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/aegis_core/foo.py\n"
            "+++ b/aegis_core/foo.py\n"
            "@@ -10,0 +11,3 @@ def alpha():\n"
            "+    x = 1\n"
            "+    y = 2\n"
            "+    return x + y\n"
            "@@ -25,2 +28,1 @@ def beta():\n"
            "-    old_a()\n"
            "-    old_b()\n"
            "+    new_call()\n"
            "diff --git a/aegis_core/deleted.py b/aegis_core/deleted.py\n"
            "--- a/aegis_core/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1,5 +0,0 @@\n"
        )
        changed = parse_changed_lines(diff_text)
        assert changed == {"aegis_core/foo.py": {11, 12, 13, 28}}

    # R-checks-32: every body line inside a hunk is content, whatever it starts with.

    def test_an_added_line_starting_with_plus_plus_stays_in_its_file(self):
        diff = hdr("a.py") + "@@ -0,0 +5,3 @@\n+a = 1\n+++ x\n+c = 3\n@@ -20,0 +22,1 @@\n+z = 9\n"
        assert parse_changed_lines(diff) == {"a.py": {5, 6, 7, 22}}

    def test_added_lines_that_look_like_headers_are_counted(self):
        diff = hdr("a.py") + "@@ -0,0 +5,4 @@\n+a = 1\n+++x\n++++ b/x\n+d = 4"
        assert parse_changed_lines(diff) == {"a.py": {5, 6, 7, 8}}

    def test_a_removed_line_starting_with_dash_dash_does_not_reset_the_hunk(self):
        diff = hdr("a.py") + "@@ -5,1 +5,2 @@\n--- old\n+new1 = 1\n+new2 = 2"
        assert parse_changed_lines(diff) == {"a.py": {5, 6}}

    @pytest.mark.parametrize("separator", ["diff --git a/b.py b/b.py\n", ""], ids=["git-header", "bare"])
    def test_a_lookalike_hunk_does_not_hide_the_next_files_headers(self, separator):
        diff = (hdr("a.py") + "@@ -1,1 +1,2 @@\n-+++ b/evil.py\n++++ b/evil.py\n+--- a/z\n"
                + separator + "--- a/b.py\n+++ b/b.py\n@@ -0,0 +1,1 @@\n+x = 1\n")
        assert parse_changed_lines(diff) == {"a.py": {1, 2}, "b.py": {1}}

    def test_countless_headers_deletions_and_no_newline_markers_keep_the_numbering(self):
        diff = (hdr("a.py") + "@@ -3 +3 @@\n-a\n+b\n"
                "@@ -5,2 +4,0 @@\n-gone1\n--- gone2\n"
                "@@ -8,1 +7,1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"
                "@@ -10,0 +9,3 @@\n+a\x0cb\n+c\x1cd\n+e\n")
        assert parse_changed_lines(diff) == {"a.py": {3, 7, 9, 10, 11}}

    def test_evaluate_diff_coverage_pass_fail_and_zero_changed(self):
        changed = {"aegis_core/foo.py": {10, 11, 12, 13, 20}}
        # 4 of 5 covered = 80% -> passes at threshold 0.80
        res_pass = evaluate_diff_coverage(
            changed,
            {"aegis_core/foo.py": {10, 11, 12, 13}},
            threshold=0.80,
        )
        assert res_pass["passed"] is True
        assert res_pass["coverage"] == pytest.approx(0.80)
        assert res_pass["uncovered_ranges"]["aegis_core/foo.py"] == [(20, 20)]

        # 3 of 5 covered = 60% -> fails at threshold 0.80 with contiguous range [12, 13]
        res_fail = evaluate_diff_coverage(
            changed,
            {"aegis_core/foo.py": {10, 11, 20}},
            threshold=0.80,
        )
        assert res_fail["passed"] is False
        assert res_fail["coverage"] == pytest.approx(0.60)
        assert res_fail["uncovered_ranges"]["aegis_core/foo.py"] == [(12, 13)]

        # 0 executable changed lines -> passes with 1.0
        res_empty = evaluate_diff_coverage({}, {}, threshold=0.80)
        assert res_empty["passed"] is True
        assert res_empty["coverage"] == pytest.approx(1.0)

    def test_run_diff_coverage_ignores_repo_root_coverage_json(self, tmp_path: Path):
        # Create a poisoned repo-root coverage.json claiming 100% coverage
        (tmp_path / "coverage.json").write_text(
            json.dumps({
                "files": {
                    "aegis_core/foo.py": {
                        "executed_lines": [1, 2, 3, 4, 5],
                        "missing_lines": [],
                    }
                }
            }),
            encoding="utf-8",
        )

        # Fake runner writes real coverage (0% covered) only into the state_dir json_path
        def fake_runner(cmd, *, cwd=None, env=None, json_path=None):
            assert env is not None
            assert "COVERAGE_FILE" in env
            assert ".aegis" in env["COVERAGE_FILE"]
            if json_path:
                Path(json_path).write_text(
                    json.dumps({
                        "files": {
                            "aegis_core/foo.py": {
                                "executed_lines": [1],
                                "missing_lines": [2, 3, 4, 5],
                            }
                        }
                    }),
                    encoding="utf-8",
                )
            return 0

        res = run_diff_coverage(
            tmp_path,
            base_ref="HEAD~1",
            threshold=0.80,
            runner=fake_runner,
            diff_text=(
                "--- a/aegis_core/foo.py\n"
                "+++ b/aegis_core/foo.py\n"
                "@@ -1,0 +1,5 @@\n"
                "+a = 1\n+b = 2\n+c = 3\n+d = 4\n+e = 5\n"
            ),
        )
        assert res["passed"] is False
        assert res["coverage"] == pytest.approx(0.20)
        assert res["uncovered_ranges"]["aegis_core/foo.py"] == [(2, 5)]


class TestSarifAndGitHubFormatters:
    """SARIF 2.1.0 and GitHub annotations / step-summary formatting."""

    def test_sarif_report_valid_schema_and_routes_lineless_to_step_summary(self, tmp_path: Path):
        report_dict = {
            "findings": [
                {
                    "rule": "no-eval",
                    "path": str(tmp_path / "aegis_core/bad.py"),
                    "line": 14,
                    "col": 5,
                    "message": "Forbidden eval() call",
                    "level": "error",
                },
                {
                    "rule": "repo-gate",
                    "path": "",
                    "line": 0,
                    "message": "Unanchored repository-level gate failure",
                    "level": "error",
                },
            ]
        }

        sarif_raw = format_sarif_report(report_dict, workspace_root=tmp_path)
        sarif = json.loads(sarif_raw)
        assert sarif["version"] == "2.1.0"
        assert "sarif-2.1.0" in sarif["$schema"]
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "aegis_core/bad.py"
        assert loc["region"]["startLine"] == 14
        assert loc["region"]["startColumn"] == 5
        assert "primaryLocationLineHash" in results[0]["partialFingerprints"]

        # Line-less finding must be routed to step_summary, never emitted with startLine: 0
        assert all(
            r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
            for r in results
        )
        assert "Unanchored repository-level gate failure" in sarif["step_summary"]

    def test_github_annotations_and_step_summary(self):
        report_dict = {
            "findings": [
                {
                    "rule": "no-eval",
                    "path": "aegis_core/bad.py",
                    "line": 14,
                    "col": 5,
                    "message": "Forbidden eval() call",
                    "level": "error",
                }
            ]
        }
        annotations = format_github_annotations(report_dict)
        assert any(
            line.startswith("::error ")
            and "file=aegis_core/bad.py" in line
            and "line=14" in line
            and "col=5" in line
            and "title=no-eval" in line
            for line in annotations
        )
        summary_md = format_github_step_summary(report_dict)
        assert "aegis_core/bad.py" in summary_md
        assert "no-eval" in summary_md


class TestStatusBlockedCommands:
    """T10: aegis status reports hook-observed blocked_commands per host."""

    def test_status_counts_blocked_guard_match_events_per_host(self, tmp_path: Path, capsys):
        import argparse
        from aegis_cli.status import run_status

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        events.append(
            ws,
            "guard_match",
            "block",
            {"rule": "git-safety", "tier": "block", "action": "block"},
            host="claude-code",
        )
        events.append(
            ws,
            "guard_match",
            "block",
            {"rule": "git-safety", "tier": "block", "action": "block"},
            host="claude-code",
        )
        events.append(
            ws,
            "guard_match",
            "record",
            {"rule": "git-safety", "tier": "record", "action": "record"},
            host="claude-code",
        )
        events.append(
            ws,
            "guard_match",
            "block",
            {"rule": "git-safety", "tier": "block", "action": "block"},
            host="cursor",
        )

        rc = run_status(argparse.Namespace(_root=ws, json=True))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["blocked_commands"] == {
            "total": 3,
            "by_host": {"claude-code": 2, "cursor": 1},
            "source": "hook-observed",
            "label": "hook-observed",
        }

    def test_status_without_guard_events_reports_zero_blocked_commands(self, tmp_path: Path, capsys):
        import argparse
        from aegis_cli.status import run_status

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        assert run_status(argparse.Namespace(_root=ws, json=True)) == 0
        assert json.loads(capsys.readouterr().out)["blocked_commands"] == {
            "total": 0, "by_host": {}, "source": "hook-observed", "label": "hook-observed"}

    def test_status_has_one_reader_of_blocked_commands(self):
        """run_status is the only status surface; the unreached first-draft collector is gone (R-cli-43)."""
        import aegis_cli.status as status

        assert [name for name in vars(status) if name.startswith("collect")] == []


class TestCheckCliIntegration:
    """CLI integration tests for --format sarif, --coverage, and GITHUB_STEP_SUMMARY."""

    def test_format_sarif_without_ci_errors(self, tmp_path: Path, capsys):
        import argparse
        from aegis_cli.check import CheckCommand

        parser = argparse.ArgumentParser()
        cmd = CheckCommand()
        cmd.configure_parser(parser)
        args = parser.parse_args(["--format", "sarif"])
        args._root = tmp_path

        rc = cmd.execute(args)
        assert rc == 2
        err = capsys.readouterr().err
        assert "invalid choice: 'sarif' (only applies with --ci)" in err

    def test_ci_format_sarif_and_github_step_summary(self, tmp_path: Path, capsys, monkeypatch):
        import argparse
        import subprocess
        from aegis_cli.check import CheckCommand

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=ws, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=ws, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=ws, check=True)
        (ws / "README.md").write_text("hi\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=ws, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=ws, check=True, capture_output=True)

        summary_file = tmp_path / "step_summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

        parser = argparse.ArgumentParser()
        cmd = CheckCommand()
        cmd.configure_parser(parser)
        args = parser.parse_args(["--ci", "--base", "HEAD", "--format", "sarif"])
        args._root = ws

        rc = cmd.execute(args)
        assert rc == 0
        out = capsys.readouterr().out
        sarif = json.loads(out)
        assert sarif["version"] == "2.1.0"
        assert summary_file.is_file()
        assert "Aegis Check Summary" in summary_file.read_text(encoding="utf-8")


