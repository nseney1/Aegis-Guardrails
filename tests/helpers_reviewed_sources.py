"""One Git-index inventory for source censuses, independent of ambient Git state.

Call reviewed_python_paths during collection and retain the returned tuple.
Only membership is frozen: callers reread those files so edits and deletions fail
their normal checks. An absent or broken index never permits a live-tree scan.
"""
from __future__ import annotations

from contextlib import contextmanager
from importlib.machinery import FileFinder
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from aegis_core.git_path_codec import MAX_PATH_BYTES as GITFILE_MAX_BYTES, path_text
from aegis_core.gitsafe_policy import GitError
from aegis_core.primitives import key_within, real_key, real_path, sanitize_display
from aegis_core.redaction import redact_command_secrets

GIT_TIMEOUT = 60
REVIEWED_ROOTS = ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk", "tests", ".github/scripts")
_ACTIVE_CENSUSES = getattr(sys, "_aegis_reviewed_source_censuses", [])
_AUTHORITY = getattr(sys, "_aegis_reviewed_source_authority", {"paths": {}, "history": {}})
_HELPER_FILE = real_key(__file__)
_FILL_CACHE_CODE = FileFinder._fill_cache.__code__
_FIND_SPEC_CODE = FileFinder.find_spec.__code__


def _census_callers():
    """Find census code through ordinary dependencies, retaining no frame objects."""
    callers = {}
    frame = sys._getframe(2)
    try:
        while frame is not None:
            filename = frame.f_code.co_filename
            spelling = os.path.normcase(os.path.abspath(filename)).replace("\\", "/")
            if (spelling.endswith("/tests/helpers_reviewed_sources.py") and not callers
                    and real_key(filename) == _HELPER_FILE):
                return None  # The nearest authored caller is the trusted helper.
            if spelling.endswith(("/tests/unit/core/test_redaction.py", "/tests/unit/core/test_insights.py")):
                module_key = real_key(filename)
                if module_key is not None:
                    callers[module_key] = str(Path(module_key).parents[3])
            frame = frame.f_back
    finally:
        del frame
    return callers


def _display_path(path):
    return redact_command_secrets(sanitize_display(path, max_len=None))[:512]


def _audit_enumeration(event, args):
    if event not in {"os.scandir", "os.listdir", "glob.glob", "glob.glob/2"}:
        return
    if event == "glob.glob" and sys.version_info >= (3, 10):
        return  # glob/2 supplies the authoritative root_dir and dir_fd.
    if event == "os.listdir":
        frame = sys._getframe(1)
        try:
            if (frame.f_code is _FILL_CACHE_CODE and frame.f_back is not None
                    and frame.f_back.f_code is _FIND_SPEC_CODE):
                return
        finally:
            del frame
    callers = _census_callers()
    if callers is None:
        return
    active = tuple(_ACTIVE_CENSUSES)
    if not active and not callers:
        return
    path = args[0]
    try:
        base = None
        if event == "glob.glob/2":
            base = args[2]
            if args[3] is not None:
                base = os.path.join(os.readlink(f"/proc/self/fd/{args[3]}"), os.fsdecode(base or "."))
        if isinstance(path, int):
            path = os.readlink(f"/proc/self/fd/{path}")
        candidate = os.path.join(os.fsdecode(base or "."), os.fsdecode(path or "."))
        if event in {"glob.glob", "glob.glob/2"}:
            # Resolve only the directory preceding the first glob component.
            # Windows 3.9 cannot resolve '*'; splitdrive protects the '?'
            # inside an extended-length drive prefix from the magic test.
            drive, tail = os.path.splitdrive(candidate)
            while any(char in tail for char in "*?["):
                parent = os.path.dirname(tail)
                if parent == tail:
                    break
                tail = parent
            candidate = drive + tail or "."
        resolved = real_key(candidate)
        if resolved is None:
            raise ValueError("unresolvable enumeration path")
    except (OSError, ValueError, RuntimeError):
        # A descriptor without a supported physical-path probe cannot establish
        # that enumeration is external. Refuse rather than leak an OS exception.
        failure = AssertionError("live-tree census enumeration is forbidden: cannot resolve " + _display_path(path))
        for state in active:
            state["violations"].append(failure)
        raise failure from None
    failure = None
    for module_file, root in callers.items():
        if key_within(resolved, root):
            message = "live-tree census enumeration is forbidden: " + _display_path(resolved)
            _AUTHORITY["history"].setdefault(module_file, []).append(message)
            failure = AssertionError(message)
    for state in active:
        if key_within(resolved, state["root"]):
            failure = AssertionError("live-tree census enumeration is forbidden: " + _display_path(resolved))
            state["violations"].append(failure)
    if failure is not None:
        raise failure


# Audit hooks cannot be removed. Share both installation and active state across
# reloads/runpy namespaces, as conftest does for its process write census.
if not hasattr(sys, "_aegis_reviewed_source_censuses"):
    sys._aegis_reviewed_source_censuses = _ACTIVE_CENSUSES
    sys._aegis_reviewed_source_authority = _AUTHORITY
    sys.addaudithook(_audit_enumeration)


@contextmanager
def census_guard(root, *, module_file=None, absolute_labels=False):
    """Refuse any enumeration recorded during this census module's lifetime."""
    violations = []
    root_key = real_key(root)
    assert root_key is not None, "invalid census checkout"
    module_key = None if module_file is None else real_key(module_file)
    assert module_file is None or module_key is not None, "invalid census module"
    history = _AUTHORITY["history"].get(module_key, ())
    assert not history, history[0] if history else ""
    state = {"root": root_key, "violations": violations, "expected": None,
             "module": module_key, "checked": False, "pending": 0}
    _ACTIVE_CENSUSES.append(state)
    normal_exit = False
    try:
        if module_key is not None:
            root = Path(root_key)
            state["expected"] = tuple(
                (label, hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest())
                for label, text in reviewed_source_rows(
                    root, reviewed_python_paths(root), absolute_labels=absolute_labels))
        yield
        normal_exit = True
    finally:
        _ACTIVE_CENSUSES[:] = [entry for entry in _ACTIVE_CENSUSES if entry is not state]
        # os.walk or a caller may swallow an exception. The context still fails.
        if violations:
            raise violations[0]
        history = _AUTHORITY["history"].get(module_key, ())
        assert not history, history[0] if history else ""
        if normal_exit and state["expected"] is not None:
            assert state["checked"], "census did not check its source rows"


def reviewed_source_rows(root: Path, paths, *, absolute_labels=False):
    """Read canonical rows one at a time from frozen membership."""
    return ((root / name if absolute_labels else name, (root / name).read_text(encoding="utf-8"))
            for name in paths)


def check_census_rows(rows):
    """Yield rows validated against the pre-body label and source-digest snapshot.

    Sources passed or rebound by a caller cannot turn this off. Standalone scan
    fixtures outside a live census retain their ordinary synthetic inputs.
    """
    for state in reversed(_ACTIVE_CENSUSES):
        if state["expected"] is not None:
            state["checked"] = False
            state["pending"] += 1
            return _checked_census_rows(rows, state)
    return iter(rows)


def _checked_census_rows(rows, state):
    """Keep this iterator bound to its creating census across interleaved scans."""
    expected = state["expected"]
    count = 0
    for row in rows:
        if (count >= len(expected) or not isinstance(row, tuple) or len(row) != 2
                or row[0] != expected[count][0] or not isinstance(row[1], str)
                or hashlib.sha256(row[1].encode("utf-8", "surrogatepass")).digest() != expected[count][1]):
            failure = AssertionError("census rows must equal the frozen inventory")
            state["violations"].append(failure)
            raise failure
        count += 1
        yield row
    if count != len(expected):
        failure = AssertionError("census rows must equal the frozen inventory")
        state["violations"].append(failure)
        raise failure
    state["pending"] -= 1
    state["checked"] = state["pending"] == 0


def freeze_fixture_sources(root: Path, rows) -> tuple:
    """Give parse-budget fixtures a real frozen index and matching on-disk text."""
    for name, text in rows:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(root, "init", "-q")
    git(root, "add", ".")
    return reviewed_python_paths(root)


def run_census_fixture(root: Path, caller: str, rows):
    """Run a census on real indexed fixture rows without patching module globals."""
    freeze_fixture_sources(root, rows)
    repository = Path(real_path(__file__)).parents[1]
    module_file = root / "tests" / "unit" / "core" / caller
    module_file.parent.mkdir(parents=True, exist_ok=True)
    # Copy after staging, so the harness itself does not add a parsed source.
    module_file.write_bytes((repository / "tests" / "unit" / "core" / caller).read_bytes())
    program = (
        "import importlib\nfrom pathlib import Path\nimport pytest\n"
        "module = importlib.import_module('tests.unit.core.' + sys.argv[2][:-3])\n"
        "module.__file__ = sys.argv[3]\n"
        "exec(compile(Path(module.__file__).read_text(encoding='utf-8'), module.__file__, 'exec'), module.__dict__)\n"
        "entry = ('test_no_module_imports_a_private_name_of_redaction' if sys.argv[2] == 'test_redaction.py'\n"
        "         else 'test_every_name_in_insights_all_is_used_outside_the_module')\n"
        "with pytest.MonkeyPatch.context() as patcher:\n    getattr(module, entry)(patcher)\n"
    )
    return run_isolated_test(program, caller, module_file, cwd=Path.cwd())


def git_environment(environ=None) -> dict:
    """Ignore all inherited Git selectors and host configuration, including case variants."""
    env = {key: value for key, value in (os.environ if environ is None else environ).items()
           if not key.upper().startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    return env


def _check_git_census_targets(cwd, args, callers):
    """Keep census code from taking a second, live index through this runner."""
    if callers is None:
        return  # Initial inventory capture is attributed to the trusted helper.
    active = tuple(_ACTIVE_CENSUSES)
    roots = list(callers.items()) + [(None, state["root"]) for state in active]
    if not roots:
        return
    redirects = any(arg.startswith("-C") or arg.partition("=")[0] in {"--git-dir", "--work-tree"}
                    for arg in args)
    targets = [cwd]
    for arg in args:
        candidates = (arg, arg.partition("=")[2]) if arg.startswith("--") else (arg,)
        targets.extend(candidate for candidate in candidates if os.path.isabs(candidate))
    failure = None
    for module_file, root in roots:
        for target in targets:
            resolved = real_key(target)
            if redirects or resolved is None or key_within(resolved, root):
                label = resolved if resolved is not None else target
                message = "live-tree census enumeration is forbidden: " + _display_path(label)
                if module_file is not None:
                    _AUTHORITY["history"].setdefault(module_file, []).append(message)
                failure = AssertionError(message)
                break
    if failure is not None:
        for state in active:
            state["violations"].append(failure)
        raise failure


def git(cwd: Path, *args: str):
    """Run Git against this checkout; malformed gitfiles refuse with status 128."""
    git_dir = cwd / ".git"
    command = ["git", f"--git-dir={git_dir}", f"--work-tree={cwd}",
               "-c", "user.email=t@example.com", "-c", "user.name=T", "-c", "core.fsmonitor=false",
               "-c", "core.safecrlf=false", "-c", "core.autocrlf=false", "-c", "core.excludesFile=", *args]
    try:
        if git_dir.is_file():
            # Linked worktrees and submodules use one bounded gitdir pointer line.
            with git_dir.open("rb") as marker:
                data = marker.read(GITFILE_MAX_BYTES + 1)
            pointer = path_text(data, gitfile=True)
            git_dir = (cwd / pointer).resolve(strict=True)
            if not git_dir.is_dir():
                raise ValueError("invalid Git directory")
    except (GitError, OSError, ValueError, RuntimeError):
        raise subprocess.CalledProcessError(128, command, output=b"", stderr=b"invalid Git marker\n") from None
    _check_git_census_targets(cwd, args, _census_callers())
    command[1] = f"--git-dir={git_dir}"
    return subprocess.run(command, cwd=cwd, env=git_environment(), stdin=subprocess.DEVNULL,
                          check=True, capture_output=True, timeout=GIT_TIMEOUT)


def reviewed_python_paths(root: Path) -> tuple:
    """Retain each checkout's first collection-time index, without requiring history."""
    root_key = real_key(root)
    assert root_key is not None, "invalid census checkout"
    if root_key in _AUTHORITY["paths"]:
        return _AUTHORITY["paths"][root_key]
    if not os.path.lexists(root / ".git"):
        raise subprocess.CalledProcessError(128, ["git", "ls-files", "--cached"],
                                            output=b"", stderr=b"missing Git marker\n")
    listed = git(root, "ls-files", "--cached", "-z", "--", *REVIEWED_ROOTS)
    names = (os.fsdecode(name) for name in listed.stdout.split(b"\0") if name)
    paths = tuple(sorted({name for name in names
                          if name.endswith(".py") and "__pycache__" not in Path(name).parts}))
    return _AUTHORITY["paths"].setdefault(root_key, paths)


def run_isolated_test(program: str, *args, env=None, cwd=None, import_path=None):
    """Bootstrap repository tests in a fresh child, including competing regular packages."""
    repository = Path(real_path(__file__)).parents[1]
    program = (
        "import json, sys\n"
        "sys.path[:] = json.loads(sys.argv[1])\n"
        "import tests\n"
        f"tests_dir = {str(repository / 'tests')!r}\n"
        "if tests_dir not in tests.__path__:\n"
        "    tests.__path__ = [tests_dir, *tests.__path__]\n"
    ) + program
    return subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", program,
         json.dumps(sys.path if import_path is None else import_path), *map(str, args)],
        cwd=repository if cwd is None else cwd, env=git_environment() if env is None else env,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=False,
    )
