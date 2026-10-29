"""GitHub argv belongs to ghcli; command-safety pattern strings are data."""
from pathlib import Path
from tests.contract.test_process_ratchets import runner_violations

REPO = Path(__file__).resolve().parents[2]


def test_single_gh_runner():
    assert runner_violations(REPO, "gh") == []


def test_gh_guard_detects_argv_but_not_a_pattern_string(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "new.py"
    path.write_text("PATTERN = 'gh api'\nARGV = ['gh', 'api', '/repos']\n", encoding="utf-8")
    assert runner_violations(tmp_path, "gh") == ["aegis_core/new.py:2: gh argv outside transport"]
