"""Conventional Go package pairing is information, never execution evidence."""
import json

import pytest

from aegis_cli.cli import main
from tests.conftest import symlink_or_skip


def package(root, test_name="other_test.go"):
    directory = root / "cmd"
    directory.mkdir()
    (directory / "main.go").write_text("package main\nfunc Main() {}\n", encoding="utf-8")
    (directory / test_name).write_text("package main\n", encoding="utf-8")
    return directory


@pytest.mark.parametrize("explicit", [False, True])
def test_package_pairing_is_plain_information_and_never_blocks_strict(tmp_path, capsys, explicit):
    package(tmp_path)
    args = ["check", "--workspace", str(tmp_path), "--strict"]
    if explicit:
        (tmp_path / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
        args.append("probe.py")
    assert main(args) == 0
    output = capsys.readouterr()
    assert "[INFO] cmd/main.go: paired by Go package with cmd/other_test.go" in output.out
    assert "tests not executed" in output.out
    assert "[WARN]" not in output.out and "[FAIL]" not in output.out
    assert output.err == ""


@pytest.mark.parametrize("explicit", [False, True])
def test_json_keeps_pairing_information_outside_issues_and_evidence(tmp_path, capsys, explicit):
    package(tmp_path)
    args = ["check", "--workspace", str(tmp_path), "--strict", "--format", "json"]
    if explicit:
        (tmp_path / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
        args.append("probe.py")
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["passed"] is True and result["checkpoint_issues"] == []
    assert result.get("checkpoint_info") == [{
        "check": "test_pairing", "file": "cmd/main.go", "tests": ["cmd/other_test.go"],
        "pairing": "go_package",
        "message": "cmd/main.go: paired by Go package with cmd/other_test.go (conventional pairing; tests not executed)",
    }]
    assert all(row["tool"] != "test_pairing" for row in result["layer1"])


@pytest.mark.parametrize("fmt", ["sarif", "github"])
def test_report_pairing_is_only_a_note(tmp_path, capsys, fmt):
    package(tmp_path)
    assert main(["check", "--workspace", str(tmp_path), "--strict", "--format", fmt]) == 0
    output = capsys.readouterr().out
    if fmt == "sarif":
        report = json.loads(output)["runs"][0]
        assert report["results"] == []
        assert "invocations" in report
        invocation, = report["invocations"]
        assert invocation["executionSuccessful"] is True
        note, = invocation["toolExecutionNotifications"]
        assert note["level"] == "note"
        assert "tests not executed" in note["message"]["text"]
    else:
        assert output.startswith("::notice ")
        assert "::error" not in output and "::warning" not in output
        assert "tests not executed" in output


def test_exact_file_pair_needs_no_package_note(tmp_path, capsys):
    package(tmp_path, "main_test.go")
    assert main(["check", "--workspace", str(tmp_path), "--strict", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report.get("checkpoint_info") == [] and report["checkpoint_issues"] == []


def test_unsafe_pair_never_creates_success_information(tmp_path, capsys):
    directory = package(tmp_path)
    (directory / "other_test.go").unlink()
    outside = tmp_path / "outside.go"
    outside.write_text("package main\n", encoding="utf-8")
    symlink_or_skip(outside, directory / "other_test.go")
    assert main(["check", "--workspace", str(tmp_path), "--strict", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report.get("checkpoint_info") == []
    assert any("symlinked" in row["message"] for row in report["checkpoint_issues"])


def test_aegis_harness_mapping_is_visible_without_claiming_execution(tmp_path, capsys):
    source = tmp_path / "aegis_core/ast/drivers/templates/go_ast.go"
    source.parent.mkdir(parents=True)
    source.write_text("package main\n", encoding="utf-8")
    harness = tmp_path / "tests/unit/core/test_go_ast_driver.py"
    harness.parent.mkdir(parents=True)
    harness.write_text("def test_protocol():\n    assert True\n", encoding="utf-8")
    assert main(["check", "--workspace", str(tmp_path), "--strict", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    note, = result["checkpoint_info"]
    assert result["checkpoint_issues"] == []
    assert note["pairing"] == "python_harness"
    assert note["tests"] == ["tests/unit/core/test_go_ast_driver.py"]
    assert "tests not executed" in note["message"]


def test_pairing_information_cannot_excuse_an_unpaired_source(tmp_path, capsys):
    package(tmp_path)
    (tmp_path / "orphan.ts").write_text("export const value = 1;\n", encoding="utf-8")
    assert main(["check", "--workspace", str(tmp_path), "--strict", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is False
    assert len(report["checkpoint_info"]) == 1
    assert [row["file"] for row in report["checkpoint_issues"]] == ["orphan.ts"]
