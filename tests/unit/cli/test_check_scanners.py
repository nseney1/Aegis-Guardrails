"""R-checks-19: `aegis check --ci` runs the ruff/gitleaks presets named by the user-scope `scanners`
key on the head and on the merge-base export, and fails only on what the change introduces.

POSIX only: the fake scanners are scripts found on a trusted PATH directory, which Windows does not
run as programs; the planted-binary case reuses R-checks-15's POSIX-only fixture."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Tuple

import pytest

from aegis_cli.cli import main
from tests import helpers_humangate as hg

pytestmark = [
    pytest.mark.skipif(os.name == "nt", reason="fake scanners are POSIX scripts on PATH"),
    pytest.mark.skipif(not hg.git_ok(), reason="needs git"),
]

# Reports every line holding `needle` as `rule` (S307 for ruff, aws-access-token for gitleaks), with
# absolute file:// URIs like ruff, and gitleaks' redacted snippet; exit 1 when it found something.
FAKE_SCANNER = r'''
import json, os, sys
needle, rule, redact = {needle!r}, {rule!r}, {redact!r}
target = sys.argv[-1]
results = []
for top, dirs, files in os.walk(target):
    dirs[:] = sorted(d for d in dirs if d != ".git")
    for name in sorted(files):
        path = os.path.join(top, name)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for number, line in enumerate(fh, 1):
                if needle in line:
                    region = {{"startLine": number}}
                    if redact:
                        region["snippet"] = {{"text": "REDACTED"}}
                    results.append({{"ruleId": rule, "level": "error", "message": {{"text": "flagged"}},
                                    "locations": [{{"physicalLocation": {{
                                        "artifactLocation": {{"uri": "file://" + os.path.abspath(path)}},
                                        "region": region}}}}]}})
print(json.dumps({{"version": "2.1.0", "runs": [{{"tool": {{"driver": {{"name": "fake"}}}}, "results": results}}]}}))
sys.exit(1 if results else 0)
'''


def _program(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(f"#!{sys.executable}\n{body}".encode("utf-8"))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake HOME and a trusted PATH directory outside the repository holding only git."""
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_EVENT_PATH", "GITHUB_BASE_REF", "GITHUB_STEP_SUMMARY", "GITHUB_EVENT_NAME"):
        monkeypatch.delenv(name, raising=False)
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    os.symlink(shutil.which("git"), trusted / "git")
    monkeypatch.setenv("PATH", str(trusted))
    return trusted


def _configure(*names: str) -> None:
    cfg = Path(os.environ["HOME"]) / ".aegis" / "config.json"
    cfg.write_bytes(json.dumps({"v": 1, "scanners": list(names)}).encode("utf-8"))


def _fake(trusted: Path, name: str, needle: str = "eval(", rule: str = "S307", redact: bool = False) -> None:
    _program(trusted / name, FAKE_SCANNER.format(needle=needle, rule=rule, redact=redact))


def _repo(tmp_path: Path, base_text: str, head_text: str, path: str = "src/app.py") -> hg.Repo:
    repo = hg.Repo(tmp_path / "project", hg.Home(tmp_path / "home"))
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE)
    repo.write(path, base_text)
    repo.commit("base")
    repo.branch("work")
    repo.write(path, head_text)
    repo.commit("feat: change")
    return repo


def _ci(repo: hg.Repo, capsys, monkeypatch, *extra: str) -> Tuple[int, str, str]:
    monkeypatch.chdir(repo.root)
    try:
        rc = main(["check", "--ci", "--base", "main", *extra])
    except SystemExit as exc:
        rc = int(exc.code or 0)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _doc(out: str) -> dict:
    return json.loads(out)


def test_only_the_finding_the_change_adds_fails(tmp_path, env, capsys, monkeypatch):
    _configure("ruff")
    _fake(env, "ruff")
    repo = _repo(tmp_path, "x = eval(a)\n", "x = eval(a)\ny = eval(b)\n")
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert rc == 1 and _doc(out)["status"] == "fail"
    assert (result["name"], result["status"], result["subtracted"]) == ("ruff", "fail", 1)
    assert [(f["path"], f["line"], f["rule_id"]) for f in result["findings"]] == [("src/app.py", 2, "S307")]
    rc, out, _ = _ci(repo, capsys, monkeypatch)
    assert rc == 1 and ": FAILED" in out.splitlines()[0]
    assert "[FAIL:scanner/ruff] src/app.py:2 S307" in out


def test_identical_lines_count_by_occurrence_and_a_moved_finding_is_not_new(tmp_path, env, capsys, monkeypatch):
    _configure("ruff")
    _fake(env, "ruff")
    repo = _repo(tmp_path, "a = eval(x)\na = eval(x)\n", "a = eval(x)\na = eval(x)\na = eval(x)\n")
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert (rc, len(result["findings"]), result["subtracted"]) == (1, 1, 2)

    moved = _repo(tmp_path / "moved", "a = eval(x)\n", "\n\n# moved\na = eval(x)\n")
    rc, out, _ = _ci(moved, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert (rc, result["status"], result["findings"]) == (0, "pass", [])


def test_without_the_key_nothing_runs_and_one_line_says_so(tmp_path, env, capsys, monkeypatch):
    marker = tmp_path / "ran"
    _program(env / "ruff", f"open({str(marker)!r}, 'w').close()\n")
    repo = _repo(tmp_path, "x = 1\n", "x = eval(a)\n")
    rc, out, _ = _ci(repo, capsys, monkeypatch)
    assert rc == 0 and "scanners: none configured" in out.splitlines()
    assert not marker.exists()
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    assert "scanners" not in _doc(out)


def test_an_unknown_preset_name_is_ignored(tmp_path, env, capsys, monkeypatch):
    _configure("bandit")
    repo = _repo(tmp_path, "x = 1\n", "x = 2\n")
    rc, out, _ = _ci(repo, capsys, monkeypatch)
    assert rc == 0 and "scanners: none configured" in out.splitlines()


def test_a_missing_scanner_is_unverified_reported_and_never_blocks(tmp_path, env, capsys, monkeypatch):
    _configure("ruff")
    repo = _repo(tmp_path, "x = 1\n", "x = eval(a)\n")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    rc, out, _ = _ci(repo, capsys, monkeypatch)
    assert rc == 0 and "PASSED" in out.splitlines()[0]
    assert any(line.startswith("  [UNVERIFIED:scanner/ruff]") for line in out.splitlines())
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "github")
    assert rc == 0 and [line for line in out.splitlines() if line.startswith("::warning title=scanner unverified::")]
    assert "::error" not in out
    assert "UNVERIFIED" in summary.read_text(encoding="utf-8") and "ruff" in summary.read_text(encoding="utf-8")


@pytest.mark.parametrize("body", ["print('this is not sarif')\n", "import sys\nsys.exit(2)\n"],
                         ids=["garbage", "exit-2-no-sarif"])
def test_output_that_is_not_a_completed_scan_is_unverified(tmp_path, env, capsys, monkeypatch, body):
    _configure("ruff")
    _program(env / "ruff", body)
    repo = _repo(tmp_path, "x = 1\n", "x = eval(a)\n")
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert (rc, result["status"], result["findings"]) == (0, "unverified", [])


def test_a_scanner_the_repository_planted_never_runs(tmp_path, env, capsys, monkeypatch):
    _configure("ruff")
    marker = tmp_path / "planted-ran"
    repo = _repo(tmp_path, "x = 1\n", "x = eval(a)\n")
    _program(repo.root / "ruff", f"open({str(marker)!r}, 'w').close()\n")
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", str(env)]))
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert not marker.exists(), "a program the repository planted ran"
    assert (rc, result["status"]) == (0, "unverified")


def test_a_rotated_key_under_the_same_mask_is_a_new_finding(tmp_path, env, capsys, monkeypatch):
    _configure("gitleaks")
    _fake(env, "gitleaks", needle="AKIA", rule="aws-access-token", redact=True)
    old, new = "AKIA" + "ABCDEFGHIJKLMN" + "XY", "AKIA" + "QRSTUVWXYZ2345" + "XY"  # same 4+2 mask
    repo = _repo(tmp_path, f'KEY = "{old}"\n', f'KEY = "{new}"\n', path="conf.py")
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert (rc, result["status"], len(result["findings"]), result["subtracted"]) == (1, "fail", 1, 0)
    assert old not in out and new not in out


def test_the_security_suppressions_a_change_adds_are_reported(tmp_path, env, capsys, monkeypatch):
    _configure("ruff")
    _fake(env, "ruff")
    repo = _repo(tmp_path, "x = 1  # nosec\n", "x = 1  # nosec\ny = 2  # nosec\nz = eval(a)  # noqa: S307\n")
    rc, out, _ = _ci(repo, capsys, monkeypatch, "--format", "json")
    (result,) = _doc(out)["scanners"]
    assert result["suppressions"] == {"count": 3, "delta": 2}
    rc, out, _ = _ci(repo, capsys, monkeypatch)
    assert "scanners: 3 security suppression(s) in tracked files (+2 since the merge base)" in out.splitlines()
