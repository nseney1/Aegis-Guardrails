"""Temporary workspaces must not inherit an enclosing checkout's Git state."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_core import gitsafe, storage


# Match the subprocess hang ceiling in test_polyglot_recipes; no timing budget.
_HANG_CEILING = 600.0


def _init_repo(path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("needs git")
    path.mkdir()
    subprocess.run([git, "init", "--quiet"], cwd=str(path), check=True,
                   capture_output=True, timeout=_HANG_CEILING)
    return path


def test_session_ceiling_preserves_checkout_discovery(tmp_path_factory, repo_root):
    basetemp = tmp_path_factory.getbasetemp().resolve()
    ceiling = basetemp if Path(repo_root).resolve() in basetemp.parents else basetemp.parent
    assert str(ceiling) in os.environ["GIT_CEILING_DIRECTORIES"].split(os.pathsep)


def test_collect_only_preserves_existing_basetemp(tmp_path, repo_root):
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_probe.py").write_text(
        "def test_body():\n"
        "    assert False, 'collect-only executed a test body'\n",
        encoding="utf-8",
    )
    basetemp = tmp_path / "run"
    basetemp.mkdir()
    sentinel = basetemp / "sentinel.txt"
    sentinel.write_text("keep existing artifacts", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-p", "tests.conftest", "--collect-only",
         str(suite), "-q", "-n", "0",
         "-p", "no:cacheprovider", "--rootdir", str(suite), "--confcutdir", str(suite),
         "--basetemp", str(basetemp)],
        cwd=repo_root, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING,
    )

    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    assert "1 test collected" in result.stdout
    assert sentinel.is_file(), "collect-only removed the existing basetemp sentinel"
    assert sentinel.read_text(encoding="utf-8") == "keep existing artifacts"


@pytest.mark.parametrize("basetemp_name", [".tmp", ".pytest_cache/run", "tests/.tmp"])
def test_serial_basetemp_preserves_checkout_and_isolates_temp_workspaces(tmp_path, repo_root, basetemp_name):
    checkout = _init_repo(tmp_path / "checkout")
    suite = checkout / "tests"
    suite.mkdir()
    shutil.copyfile(Path(repo_root) / "tests" / "conftest.py", suite / "conftest.py")
    source = suite / "unit" / "core"
    source.mkdir(parents=True)
    (source / "test_probe.py").write_text(
        "from pathlib import Path\n"
        "from aegis_core import gitsafe\n"
        "def test_discovery(tmp_path):\n"
        "    checkout = Path(__file__).resolve().parents[3]\n"
        "    common_dir = gitsafe.common_dir(Path(__file__).parent)\n"
        "    assert common_dir is not None, 'checkout discovery was blocked'\n"
        "    assert common_dir.resolve() == (checkout / '.git').resolve()\n"
        "    assert gitsafe.common_dir(tmp_path) is None\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (repo_root, env.get("PYTHONPATH"))))
    basetemp = checkout / basetemp_name
    basetemp.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", str(source / "test_probe.py"), "-q", "-n", "0",
         "-p", "no:cacheprovider", "--rootdir", str(checkout), "--confcutdir", str(checkout),
         "--basetemp", str(basetemp)],
        cwd=str(checkout), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=_HANG_CEILING,
    )

    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr


def test_ceiling_blocks_enclosing_repository(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path / "outer")
    ceiling = repo / "ceiling"
    workspace = ceiling / "workspace"
    workspace.mkdir(parents=True)

    monkeypatch.delenv("GIT_CEILING_DIRECTORIES", raising=False)
    assert gitsafe.common_dir(workspace).resolve() == (repo / ".git").resolve()
    assert storage.ledger_site(workspace, create=False).shared is True

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling.resolve()))
    assert gitsafe.common_dir(workspace) is None
    assert storage.ledger_site(workspace, create=False).shared is False


def test_repository_inside_tmp_path_is_still_found(tmp_path):
    repo = _init_repo(tmp_path / "inner")
    workspace = repo / "workspace"
    workspace.mkdir()

    assert gitsafe.common_dir(workspace).resolve() == (repo / ".git").resolve()
    assert storage.ledger_site(workspace, create=False).shared is True


@pytest.mark.parametrize("separator", [
    pytest.param(":", id="posix-colon",
                 marks=pytest.mark.skipif(os.name == "nt", reason="colon is not a Windows path character")),
    pytest.param(";", id="windows-semicolon",
                 marks=pytest.mark.skipif(os.name != "nt", reason="Windows uses semicolon as its path separator")),
])
@pytest.mark.parametrize("location", ["parent", "basetemp"])
def test_separator_in_basetemp_refuses_before_test_body(tmp_path, repo_root, separator, location):
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_probe.py").write_text(
        "from pathlib import Path\n"
        "def test_body():\n"
        "    Path(__file__).with_name('body-ran').write_text('ran', encoding='utf-8')\n",
        encoding="utf-8",
    )
    parent = tmp_path / ("ceiling" + separator + "entry" if location == "parent" else "ceiling")
    parent.mkdir()
    basetemp = parent / ("run" + separator + "entry" if location == "basetemp" else "run")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "pytest", "-p", "tests.conftest", str(suite / "test_probe.py"),
         "-q", "-n", "0", "-p", "no:cacheprovider", "--confcutdir", str(suite),
         "--basetemp", str(basetemp)],
        cwd=repo_root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=_HANG_CEILING,
    )

    assert result.returncode == pytest.ExitCode.TESTS_FAILED, result.stdout + result.stderr
    assert "UsageError" in result.stdout
    assert ("choose --basetemp outside paths containing the path separator " + repr(separator)) in result.stdout
    assert not (suite / "body-ran").exists()
