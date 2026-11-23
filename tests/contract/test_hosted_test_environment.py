"""Hosted pytest startup and the strict Git environment contract."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe
from tests.helpers_team_git import strict_program_guard


_REFUSAL_KEYS = ("LD_LIBRARY_PATH", "LD_PRELOAD", "GIT_SSH_COMMAND", "GIT_CONFIG_COUNT")
_CONTRACT = "tests/contract/test_hosted_test_environment.py"
_ISOLATED = _CONTRACT + "::test_isolated_python_child_starts_after_loader_cleanup"
_REFUSAL = _CONTRACT + "::test_explicit_git_environment_still_refuses"
_PUBLISH = (
    "tests/unit/core/test_team_git.py"
    "::test_cold_publish_uses_private_destination_and_explicit_shared_publication"
)
_STARTUP_KEYS = ("PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP", "TMPDIR")
_STARTUP_ADVICE = "check hosted startup and collection"
_MAX_SELECTION = 64
_NODE_ID_MAX = 512
_NODE_ID = re.compile(
    r"tests/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.py"
    r"(?:::[A-Za-z_][A-Za-z0-9_]*)+"
    r"(?:\[[A-Za-z0-9_., -]+\])?\Z"
)


class HostedProbeVerdict:
    """A hosted process outcome with source-owned diagnostics."""

    def __init__(self, code, mode, *, status=None, advice=False):
        self.code = code
        self.mode = mode
        self.status = status
        self.advice = advice

    def public_text(self):
        text = f"hosted-probe mode={self.mode} code={self.code}"
        if self.status is not None:
            text += f" status={self.status}"
        if self.advice:
            text += f"\nadvice={_STARTUP_ADVICE}"
        return text

    def __repr__(self):
        return self.public_text()


def _mode(workers):
    if type(workers) is not int or workers < 0:
        return None
    return "serial" if workers == 0 else "xdist"


def _valid_node_id(value):
    return (type(value) is str and 0 < len(value) <= _NODE_ID_MAX
            and "\n" not in value and "\r" not in value and "\x00" not in value
            and _NODE_ID.fullmatch(value) is not None)


def _hosted_environment(home):
    environment = {key: os.environ[key] for key in _STARTUP_KEYS if key in os.environ}
    environment.update(
        HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / ".config"),
        LD_LIBRARY_PATH=str(Path(sys.base_prefix) / "lib"),
    )
    return environment


def _run_hosted_child(cwd, selection, workers, scratch, timeout):
    """Run the selected hosted probes and use only the process outcome."""
    mode = _mode(workers)
    if (mode is None or type(timeout) is not int or not 0 < timeout <= 180
            or type(selection) not in (list, tuple) or not 0 < len(selection) <= _MAX_SELECTION
            or any(not _valid_node_id(item) for item in selection)):
        return HostedProbeVerdict("selection_invalid", mode or "unknown")
    command = [
        sys.executable, "-m", "pytest", "-q", "-n", str(workers), "-p", "no:cacheprovider",
        "--basetemp", str(Path(scratch) / "child"), *selection,
    ]
    try:
        completed = subprocess.run(
            command, cwd=str(cwd), env=_hosted_environment(Path(scratch)),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return HostedProbeVerdict("child_timeout", mode, advice=True)
    except (OSError, ValueError):
        return HostedProbeVerdict("child_startup", mode, advice=True)
    if completed.returncode != 0:
        return HostedProbeVerdict("child_exit", mode, status=completed.returncode)
    return HostedProbeVerdict("accepted", mode)


@pytest.mark.parametrize("workers", [0, 2])
def test_hosted_loader_environment_leaves_git_suite_runnable(tmp_path, workers):
    root = Path(__file__).resolve().parents[2]
    selection = [_ISOLATED, _REFUSAL]
    if shutil.which("git") and strict_program_guard(optional=True):
        selection.append(_PUBLISH)
    verdict = _run_hosted_child(root, selection, workers, tmp_path, 120)
    assert verdict.code == "accepted", verdict.public_text()


def test_isolated_python_child_starts_after_loader_cleanup():
    inherited = "LD_LIBRARY_PATH" in os.environ
    assert not inherited, "pytest retained the toolchain loader variable"
    child = subprocess.run(
        [sys.executable, "-I", "-c", "import os; assert 'LD_LIBRARY_PATH' not in os.environ"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30,
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


def _worker_mode(workers):
    return "serial" if workers == 0 else "xdist"


def _assert_startup_advice(verdict, workers, code):
    assert verdict.public_text() == (
        f"hosted-probe mode={_worker_mode(workers)} code={code}\n"
        "advice=check hosted startup and collection"
    )


@pytest.mark.parametrize("workers", [0, 2])
def test_hosted_child_launch_failure_uses_startup_advice(tmp_path, workers):
    node = "tests/test_probe.py::test_one"
    verdict = _run_hosted_child(tmp_path / "missing-cwd", [node], workers, tmp_path, 60)
    _assert_startup_advice(verdict, workers, "child_startup")


@pytest.mark.parametrize("workers", [0, 2])
@pytest.mark.parametrize("times_out", [False, True], ids=["zero-exit", "timeout"])
def test_hosted_child_checks_process_outcome(tmp_path, monkeypatch, workers, times_out):
    selection = ["tests/test_probe.py::test_probe"]
    process_api = subprocess
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if times_out:
            raise process_api.TimeoutExpired(
                command, kwargs["timeout"], output=b"stdout marker", stderr=b"stderr marker",
            )
        # This process boundary supplies a status and creates no output files.
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        "tests.contract.test_hosted_test_environment.subprocess",
        SimpleNamespace(run=run, DEVNULL=process_api.DEVNULL, TimeoutExpired=process_api.TimeoutExpired),
    )
    verdict = _run_hosted_child(tmp_path, selection, workers, tmp_path, 60)
    if times_out:
        _assert_startup_advice(verdict, workers, "child_timeout")
    else:
        assert verdict.public_text() == f"hosted-probe mode={_worker_mode(workers)} code=accepted"
    [(command, options)] = calls
    assert command == [
        sys.executable, "-m", "pytest", "-q", "-n", str(workers), "-p", "no:cacheprovider",
        "--basetemp", str(tmp_path / "child"), *selection,
    ]
    assert options["cwd"] == str(tmp_path)
    assert options["env"]["HOME"] == str(tmp_path)
    assert options["timeout"] == 60
    assert options["stdin"] == options["stdout"] == options["stderr"] == process_api.DEVNULL
    assert "capture_output" not in options


@pytest.fixture
def probe_file(tmp_path):
    suite = tmp_path / "tests"
    suite.mkdir()
    return suite / "test_probe.py"


@pytest.mark.parametrize("workers", [0, 2])
def test_hosted_child_uses_exit_status_and_retries(tmp_path, probe_file, workers):
    selection = ["tests/test_probe.py::test_probe"]
    probe_file.write_text(
        "import sys\n"
        "def test_probe():\n"
        "    print('1 passed')\n"
        "    sys.stderr.write('stderr marker\\n')\n"
        "    raise AssertionError('child failure marker')\n",
        encoding="utf-8",
    )
    first = _run_hosted_child(tmp_path, selection, workers, tmp_path, 60)
    assert first.public_text() == f"hosted-probe mode={_worker_mode(workers)} code=child_exit status=1"
    probe_file.write_text("def test_probe():\n    pass\n", encoding="utf-8")
    retry = _run_hosted_child(tmp_path, selection, workers, tmp_path, 60)
    assert retry.public_text() == f"hosted-probe mode={_worker_mode(workers)} code=accepted"
    assert first.public_text() == f"hosted-probe mode={_worker_mode(workers)} code=child_exit status=1"


def test_hosted_children_keep_scratch_independent(tmp_path, probe_file):
    selection = ["tests/test_probe.py::test_probe"]
    probe_file.write_text(
        "from pathlib import Path\n"
        "def test_probe(tmp_path):\n"
        "    scratch = Path.home().resolve()\n"
        "    assert scratch / 'child' in tmp_path.parents\n"
        "    (scratch / 'ran').write_text('ran', encoding='ascii')\n",
        encoding="utf-8",
    )
    runs = [(0, tmp_path / "serial"), (2, tmp_path / "xdist")]
    for _, scratch in runs:
        scratch.mkdir()
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [
            pool.submit(_run_hosted_child, tmp_path, selection, workers, scratch, 60)
            for workers, scratch in runs
        ]
        results = [future.result(timeout=90) for future in pending]
    for (workers, scratch), verdict in zip(runs, results):
        assert verdict.public_text() == f"hosted-probe mode={_worker_mode(workers)} code=accepted"
        assert (scratch / "ran").read_text(encoding="ascii") == "ran"
