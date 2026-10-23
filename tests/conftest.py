"""Shared fixtures for the Soma regression suite.

The suite deliberately avoids requiring pyyaml: several invariants under test
exist precisely because `soma_mcp/` must work on a bare interpreter.
"""
import os
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

try:
    import tests
    if hasattr(tests, "__path__") and TESTS_DIR not in tests.__path__:
        tests.__path__.insert(0, TESTS_DIR)
except ImportError:
    pass


@pytest.fixture(autouse=True)
def _no_real_gh(monkeypatch):
    """The trust tier (``aegis doctor``) reads GitHub through the user's own gh. No test reaches
    the network or the developer's gh: without a stand-in the answer is "gh is not installed"
    (tier C). A test of tier detection or ``doctor --github`` installs its own fake runner. The stub
    has the real runner's signature; the fixture's value is the real runner."""
    from aegis_core import human_gate

    real = human_gate.default_gh_runner
    monkeypatch.setattr(human_gate, "default_gh_runner", lambda argv, stdin=None, cwd=None, timeout=None: None)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    return real


@pytest.fixture
def real_gh_runner(monkeypatch, _no_real_gh):
    """The real gh runner, for a test that puts a fake gh on PATH (or leaves none there):
    ``_no_real_gh_on_path`` still finds only a gh under pytest's temporary root."""
    from aegis_core import human_gate

    monkeypatch.setattr(human_gate, "default_gh_runner", _no_real_gh)
    return _no_real_gh


@pytest.fixture(autouse=True)
def _no_real_gh_on_path(monkeypatch, tmp_path_factory):
    """``aegis doctor --release`` finds gh itself (``pathlookup.which``). Runner images put gh
    beside git (/usr/bin), so a PATH built from git's directory still holds the real gh. Only a
    gh that a test placed under pytest's temporary root is ever found."""
    from aegis_core import pathlookup

    real_which = pathlookup.which
    root = os.path.realpath(str(tmp_path_factory.getbasetemp()))

    def which(name, *args, **kwargs):
        found = real_which(name, *args, **kwargs)
        if found and os.path.splitext(os.path.basename(str(name)))[0].lower() == "gh":
            if not os.path.realpath(found).startswith(root + os.sep):
                return None
        return found

    monkeypatch.setattr(pathlookup, "which", which)


@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT


def require_bash():
    """Path to bash, or skip. Prefers /bin/bash: on macOS that is 3.2, the
    oldest supported shell and the one that surfaced SOMA-C03. Windows has
    no /bin/bash for native processes; Git Bash is found on PATH or Git installation."""
    if os.name == "nt":
        for git_bash in (r"C:\Program Files\Git\usr\bin\bash.exe", r"C:\Program Files (x86)\Git\usr\bin\bash.exe"):
            if os.path.exists(git_bash):
                return git_bash
    path = "/bin/bash" if os.path.exists("/bin/bash") else shutil.which("bash")
    if not path:
        pytest.skip("bash is not available")
    return path


@pytest.fixture(scope="session")
def bash():
    return require_bash()


def symlink_or_skip(target, link, target_is_directory: bool = False):
    """Create a symlink, or skip: Windows needs Developer Mode or admin
    rights (WinError 1314)."""
    try:
        os.symlink(str(target), str(link), target_is_directory=target_is_directory)
    except (OSError, NotImplementedError):
        # On POSIX a failure here is a test bug; don't let it hide the
        # symlink-escape security tests behind a skip.
        if os.name != "nt":
            raise
        pytest.skip("symlinks are unavailable")


@pytest.fixture
def fake_home(tmp_path):
    """An isolated HOME so installer tests never touch the real one."""
    home = tmp_path / "home"
    home.mkdir()
    return home


def run(cmd, cwd=REPO_ROOT, env=None, stdin=subprocess.DEVNULL, timeout=120):
    """Run a command and return CompletedProcess with text output."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
        # Under Git Bash resolve_home() prefers USERPROFILE, so a HOME-only
        # override would still point the installer at the real profile (BUG-010).
        if "HOME" in env and "USERPROFILE" not in env:
            full_env["USERPROFILE"] = env["HOME"]
    return subprocess.run(
        cmd, cwd=cwd, env=full_env, stdin=stdin,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
    )


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def iter_source_files(root, extensions):
    """Yield absolute paths under root matching extensions, skipping caches."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in {"__pycache__", ".git", "node_modules", ".pytest_cache"}
        ]
        for fn in filenames:
            if any(fn.endswith(ext) for ext in extensions):
                yield os.path.join(dirpath, fn)


# Variables the shell that launched pytest may export: AEGIS_WORKSPACE would aim
# CLI and MCP calls at the developer's real workspace, the others change host
# identity, the Layer-2 backend and scan budgets. Tests that need one set it.
_DEVELOPER_ENV = ("AEGIS_WORKSPACE", "AEGIS_CLIENT", "AEGIS_LLM_CMD", "AEGIS_MAX_JIT_TOKENS")


@pytest.fixture(autouse=True)
def _no_developer_aegis_env(monkeypatch):
    for key in _DEVELOPER_ENV:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def hermetic_environment_and_mcp_isolation():
    """Restore os.environ and reset MCP server singletons between tests."""
    old_env = dict(os.environ)
    yield
    # Restore os.environ
    os.environ.clear()
    os.environ.update(old_env)

    # Reset MCP server singletons if aegis_mcp.server is loaded
    for mod_name in ("aegis_mcp.server", "aegis_mcp.server"):
        if mod_name in sys.modules:
            mcp_server = sys.modules[mod_name]
            if hasattr(mcp_server, "_session_tokens") and isinstance(mcp_server._session_tokens, set):
                mcp_server._session_tokens.clear()
            if hasattr(mcp_server, "_tool_call_times") and hasattr(mcp_server._tool_call_times, "clear"):
                mcp_server._tool_call_times.clear()
            if hasattr(mcp_server, "_session_token"):
                mcp_server._session_token = None


