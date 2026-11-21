"""Hosted pytest startup and the strict Git environment contract."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from aegis_core import gitsafe
from tests.helpers_team_git import strict_program_guard


_REFUSAL_KEYS = ("LD_LIBRARY_PATH", "LD_PRELOAD", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT")


@pytest.mark.parametrize("workers", [0, 2])
def test_hosted_loader_environment_leaves_git_suite_runnable(tmp_path, workers):
    root = Path(__file__).resolve().parents[2]
    contract = "tests/contract/test_hosted_test_environment.py"
    selection = [
        f"{contract}::test_isolated_python_child_starts_after_loader_cleanup",
        f"{contract}::test_explicit_git_environment_still_refuses",
    ]
    expected = 1 + len(_REFUSAL_KEYS)
    if shutil.which("git") and strict_program_guard(optional=True):
        selection.append(
            "tests/unit/core/test_team_git.py::test_cold_publish_uses_private_destination_and_explicit_shared_publication"
        )
        expected += 1
    # Model the hosted launcher without importing unrelated shell selectors
    # or test-runner settings from the outer process.
    startup_keys = ("PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR")
    environment = {key: os.environ[key] for key in startup_keys if key in os.environ}
    environment.update(
        HOME=str(tmp_path), USERPROFILE=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / ".config"),
        LD_LIBRARY_PATH=str(Path(sys.base_prefix) / "lib"),
    )
    child = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-n", str(workers), "-p", "no:cacheprovider",
         "--basetemp", str(tmp_path / "child"), *selection],
        cwd=root, env=environment, capture_output=True, text=True, timeout=120,
    )
    ambient_refusal = "ambient_git_environment" in child.stdout
    status = child.returncode
    all_passed = f"{expected} passed" in child.stdout
    assert status == 0, f"child pytest exit {status}, ambient Git refusal: {ambient_refusal}"
    assert all_passed, "child did not pass every selected case"


def test_isolated_python_child_starts_after_loader_cleanup():
    inherited = "LD_LIBRARY_PATH" in os.environ
    assert not inherited, "pytest retained the toolchain loader variable"
    child = subprocess.run(
        [sys.executable, "-I", "-c", "import os; assert 'LD_LIBRARY_PATH' not in os.environ"],
        capture_output=True, timeout=30,
    )
    status = child.returncode
    assert status == 0, "isolated Python failed after clearing the toolchain loader variable"


@pytest.mark.parametrize("key", _REFUSAL_KEYS)
def test_explicit_git_environment_still_refuses(tmp_path, key):
    previous = os.environ.get(key)
    os.environ[key] = "test-owned-value"
    try:
        with pytest.raises(gitsafe.GitError) as caught:
            gitsafe.custody_program(tmp_path)
        assert caught.value.code == "ambient_git_environment"
        assert caught.value.process_started is False
    finally:
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous
