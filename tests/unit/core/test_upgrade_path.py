"""The supported workspace layout has no retired state."""
from aegis_core.workspace.discovery import unmigrated_state
from pathlib import Path
import subprocess

from tests.contract.test_legacy_ratchet import REQUIRED_WORDS


def test_private_retired_files_are_ignored(tmp_path):
    root = Path(__file__).resolve().parents[3]
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_bytes((root / ".gitignore").read_bytes())
    paths = [".aegis/receipt_key", *[".aegis/evidence/" + name + ".jsonl" for name in ("signals", "fitness", "sessions_processed")]]
    for path in paths:
        done = subprocess.run(["git", "check-ignore", "--no-index", path], cwd=tmp_path, capture_output=True, text=True)
        assert done.returncode == 0 and done.stdout.strip() == path, path


def test_v4_discovery_and_coverage_still_skip_retained_state(tmp_path):
    from aegis_core.ast.detect import iter_project_files
    from aegis_core.metrics import calculate_coverage, calculate_governance_grade
    from aegis_core.verification.checkpoint_checks import find_python_files

    (tmp_path / ".aegis/rules/traps").mkdir(parents=True)
    (tmp_path / ".aegis/rules/traps/t.md").write_text("---\nid: t\ntype: trap\ntarget_paths: ['*.py']\n---\nBody\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    before = calculate_coverage(str(tmp_path)), calculate_governance_grade(str(tmp_path))
    retained = tmp_path / ("." + REQUIRED_WORDS[0]) / "drivers/old.py"
    retained.parent.mkdir(parents=True)
    retained.write_text("def obsolete(): pass\n")
    assert retained not in list(iter_project_files(tmp_path))
    assert retained not in find_python_files(tmp_path, ".")
    assert (calculate_coverage(str(tmp_path)), calculate_governance_grade(str(tmp_path))) == before


def test_a_modern_workspace_has_no_retired_state(tmp_path):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    assert unmigrated_state(tmp_path) == []
