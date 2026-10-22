"""R-checks-40: `aegis check FILES --format github|sarif` carries the Layer 1 findings: anchored at the
repository-relative path and line, one report on stdout, and the same verdict as the exit status."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aegis_cli.cli import main
from tests import helpers_humangate as hg

pytestmark = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


@pytest.fixture(autouse=True)
def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_BASE_REF", "GITHUB_EVENT_PATH", "GITHUB_STEP_SUMMARY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
    (root / "src" / "bad.py").write_bytes(b"import unapproved_third_party_pkg_xyz\n")
    (root / "src" / "good.py").write_bytes(b"import json\n")
    return root


def _check(ws: Path, capsys, *argv: str):
    try:
        rc = main(["check", "--workspace", str(ws), *argv])
    except SystemExit as exc:
        rc = int(exc.code or 0)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def test_a_failing_file_is_one_anchored_sarif_result(ws, capsys):
    rc, out, _ = _check(ws, capsys, "src/bad.py", "--format", "sarif")
    log = json.loads(out)
    (result,) = log["runs"][0]["results"]
    region = result["locations"][0]["physicalLocation"]
    assert rc == 1 and (result["ruleId"], result["level"]) == ("import_guard", "error")
    assert (region["artifactLocation"]["uri"], region["region"]["startLine"]) == ("src/bad.py", 1)
    rc, out, _ = _check(ws, capsys, "src/good.py", "--format", "sarif")
    assert rc == 0 and json.loads(out)["runs"][0]["results"] == []


def test_a_failing_file_is_one_error_annotation_and_stdout_holds_only_commands(ws, capsys):
    rc, out, _ = _check(ws, capsys, "src/bad.py", "--format", "github")
    lines = out.splitlines()
    assert rc == 1 and all(line.startswith("::") for line in lines)
    errors = [line for line in lines if line.startswith("::error file=src/bad.py,line=1,")]
    assert len(errors) == 1 and "title=import_guard::" in errors[0]
    rc, out, _ = _check(ws, capsys, "src/good.py", "--format", "github")
    assert rc == 0 and "::error" not in out


def test_the_step_summary_says_failed_and_names_the_location(ws, capsys, monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    for fmt in ("github", "sarif"):
        rc, _out, _ = _check(ws, capsys, "src/bad.py", "--format", fmt)
        text = summary.read_text(encoding="utf-8")
        assert rc == 1 and "FAILED" in text and "src/bad.py:1" in text
        summary.unlink()


@pytest.mark.parametrize("fmt", ["github", "sarif"])
@pytest.mark.parametrize("extra,named", [(["--full", "--plan", "p"], "--full"), (["--dry-run"], "--dry-run")],
                         ids=["layer2", "dry-run"])
def test_layer2_and_dry_run_do_not_take_a_machine_format(ws, capsys, fmt, extra, named):
    rc, out, err = _check(ws, capsys, "src/bad.py", "--format", fmt, *extra)
    assert (rc, out) == (2, "") and named in err


@pytest.mark.parametrize("fmt", ["github", "sarif"])
@pytest.mark.parametrize("mode", [["--record"], ["--card"], ["--lane", "x"]], ids=["record", "card", "lane"])
def test_the_modes_of_their_own_refuse_a_machine_format(ws, capsys, fmt, mode):
    rc, out, err = _check(ws, capsys, *mode, "--format", fmt)
    assert rc == 2 and "--ci" in err and f"--format {fmt}" in err


def test_a_baselined_finding_is_no_annotation(ws, capsys):
    subprocess.run(["git", "add", "-A"], cwd=ws, check=True)
    assert _check(ws, capsys, "--write-baseline")[0] == 0
    rc, out, _ = _check(ws, capsys, "src/bad.py", "--format", "github")
    assert rc == 0 and "::error" not in out


def test_a_blocking_checkpoint_issue_fails_the_summary(ws, capsys, monkeypatch, tmp_path):
    rules = ws / ".aegis" / "rules" / "invariants"
    rules.mkdir(parents=True)
    (rules / "broken.md").write_bytes(b"---\nid: [unterminated\n---\nbody\n")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    rc, out, _ = _check(ws, capsys, "src/good.py", "--format", "github")
    text = summary.read_text(encoding="utf-8")
    assert rc == 1 and "FAILED" in text and "No findings reported." not in text
    assert all(line.startswith("::") for line in out.splitlines())
