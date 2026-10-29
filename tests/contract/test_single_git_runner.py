"""Only the central transport resolves git; evidence owns the default branch name."""
from pathlib import Path
from tests.contract.test_process_ratchets import runner_violations

REPO = Path(__file__).resolve().parents[2]


def test_single_git_runner():
    assert runner_violations(REPO, "git") == []


def test_git_guard_detects_resolution_private_reach_and_remote_literal(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "new.py").write_text("from shutil import which as locate\nfrom aegis_core import gitsafe as gs\nlocate('git')\ngs._x([])\nREF = 'refs/remotes/origin/HEAD'\n", encoding="utf-8")
    findings = runner_violations(tmp_path, "git")
    assert len(findings) == 3
    assert [x.split(':')[1] for x in findings] == ["3", "4", "5"]
