"""Name foundation source drift before the slower replay fails without a path.

This catches accidental or lane edits and verifier drift, refusing links
strictly below the repository root; active checkout tampering and races are outside
its threat model, and replay verify_source is authoritative.
"""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

import pytest


TOOL = "tools/hierarchy_foundation_acceptance.py"
MANIFEST = "tests/fixtures/hierarchy_native_foundation/manifest.json"


def _repository_root():
    try:
        lexical_file = Path(__file__).absolute()
        lexical_root = lexical_file.parents[2]
        root = lexical_root.resolve()  # Root/ancestor aliases are legitimate.
        for component in (lexical_file.parents[1], lexical_file.parent, lexical_file):
            info = component.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                    or not (stat.S_ISREG(info.st_mode) if component == lexical_file else stat.S_ISDIR(info.st_mode))):
                raise AssertionError(f"test location: environment fault (unsafe test path component: {component})")
        if lexical_file.resolve().parents[2] != root:
            raise AssertionError("test location: environment fault (lexical and resolved repository roots differ)")
        return root
    except (OSError, RuntimeError) as exc:
        raise AssertionError(f"test location: environment fault ({exc})") from exc


def _require(condition, name, reason):
    assert condition, f"{name}: needs successor pin ({reason})"


def _environment(condition, name, reason):
    assert condition, f"{name}: environment fault ({reason})"


def _relative(name, owner):
    # Match the replay tool's relative(), including Windows spellings on POSIX.
    _require(type(name) is str and 0 < len(name) <= 200, owner, "invalid relative path")
    _require(not any(char in name for char in ("\\", "\0", ":"))
             and not PurePosixPath(name).is_absolute()
             and all(part not in ("", ".", "..") for part in name.split("/")),
             owner, f"invalid relative path: {name!r}")
    return name


def _checked_path(name, limit, directory=False):
    parts = _relative(name, name).split("/")
    path = REPO.joinpath(*parts)
    try:
        root = REPO.lstat()
    except OSError as exc:
        raise AssertionError(f"{name}: environment fault (repository root: {exc})") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode)
            or getattr(root, "st_file_attributes", 0) & reparse_flag):
        raise AssertionError(f"{name}: environment fault (repository root is not a plain directory)")
    # Normalize only the root. Keep every path below it lexical so links and
    # Windows junctions remain visible to lstat before opening any input.
    identities = [(root.st_dev, root.st_ino)]
    for index in range(1, len(parts) + 1):
        component = REPO.joinpath(*parts[:index])
        info = component.lstat()
        _environment(not stat.S_ISLNK(info.st_mode), name, "symlink component")
        _environment(not getattr(info, "st_file_attributes", 0) & reparse_flag,
                     name, "reparse point component")
        is_directory = component != path or directory
        _environment(stat.S_ISDIR(info.st_mode) if is_directory else stat.S_ISREG(info.st_mode),
                     name, "expected directory" if is_directory else "expected regular file")
        identities.append((info.st_dev, info.st_ino))
    if not directory:
        _require(info.st_size <= limit, name, f"size exceeds MAX_FILE ({limit})")
    return path, identities


def _read_file(name, limit):
    try:
        path, before = _checked_path(name, limit)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)  # A raced-in FIFO must not block.
        # Opening just the leaf needs search permission on ancestors, not read
        # permission. O_NOFOLLOW protects the leaf on platforms providing it.
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            _environment(stat.S_ISREG(opened.st_mode), name, "expected regular file")
            _require(opened.st_size <= limit, name, f"size exceeds MAX_FILE ({limit})")
            _, after = _checked_path(name, limit)
            if before != after:
                raise AssertionError(f"{name}: environment fault (path identity changed before read)")
            # Windows lstat/fstat use different Win32 identity sources. Compare
            # descriptor identities only on POSIX; both still check type/size.
            if os.name == "posix" and before[-1] != (opened.st_dev, opened.st_ino):
                raise AssertionError(f"{name}: environment fault (opened file identity changed before read)")
            raw = stream.read(limit + 1)
        _require(len(raw) <= limit, name, f"size exceeds MAX_FILE ({limit})")
        return raw
    except FileNotFoundError as exc:
        raise AssertionError(f"{name}: needs successor pin (missing file)") from exc
    except OSError as exc:
        raise AssertionError(f"{name}: environment fault (cannot read file: {exc})") from exc


def _constant(name, kind):
    value = CONSTANTS.get(name)
    _environment(type(value) is kind, TOOL, f"cannot read literal constant {name}")
    return value


def _sha_constant(name):
    value = _constant(name, str)
    _environment(re.fullmatch(r"[a-f0-9]{64}", value), TOOL, f"invalid digest constant {name}")
    return value


def _authenticate_manifest(raw):
    actual = hashlib.sha256(raw).hexdigest()
    _require(actual == MANIFEST_SHA256, MANIFEST,
             f"expected {MANIFEST_SHA256}, got {actual}")


def _manifest_check():
    raw = _read_file(MANIFEST, MAX_FILE)
    _authenticate_manifest(raw)
    return raw


def _unique_pairs(items):
    result = {}
    for name, value in items:
        _require(name not in result, MANIFEST, f"duplicate JSON key: {name}")
        result[name] = value
    return result


def _manifest_pins():
    try:
        value = json.loads(MANIFEST_RAW, object_pairs_hook=_unique_pairs)
    except (ValueError, RecursionError) as exc:
        raise AssertionError(f"{MANIFEST}: needs successor pin (malformed manifest)") from exc
    _require(type(value) is dict, MANIFEST, "malformed manifest")
    pins = value.get("source_files")
    _require(type(pins) is dict and 0 < len(pins) <= 32, MANIFEST, "malformed source_files map")
    for name, sha in pins.items():
        _relative(name, MANIFEST)
        _require(type(sha) is str and re.fullmatch(r"[a-f0-9]{64}", sha),
                 MANIFEST, f"malformed source digest: {name}")
    return pins


def _source_pins():
    # Best-effort path diagnostics; the real caller cross-check decides drift.
    pins = _manifest_pins()
    for function in SOURCE.body:
        if not (isinstance(function, ast.FunctionDef) and function.name == "verify_source"):
            continue
        for node in function.body:
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                    and any(isinstance(target, ast.Name) and target.id == "pins" for target in node.targets)):
                for key, value in zip(node.value.keys, node.value.values):
                    if key is None:
                        _environment(isinstance(value, ast.Name) and value.id == "expected", TOOL,
                                     f"cannot model pins entry **{ast.dump(value)}")
                        continue
                    label = repr(key.value) if isinstance(key, ast.Constant) else ast.dump(key)
                    _environment(isinstance(key, ast.Constant) and type(key.value) is str
                                 and isinstance(value, ast.Name) and value.id in CONSTANTS, TOOL,
                                 f"cannot model pins entry {label}: {ast.dump(value)}")
                    pins[_relative(key.value, TOOL)] = _sha_constant(value.id)
                return pins
    raise AssertionError(f"{TOOL}: environment fault (cannot model pins entry <no pins literal>)")


def _collect_pins():
    global REPO, SOURCE, CONSTANTS, MAX_FILE, MANIFEST_SHA256, MANIFEST_RAW
    REPO = _repository_root()
    # Bootstrap before MAX_FILE is available, then enforce its extracted value.
    tool_raw = _read_file(TOOL, 1048576)
    try:
        SOURCE = ast.parse(tool_raw, filename=TOOL)
    except (SyntaxError, ValueError) as exc:
        raise AssertionError(f"{TOOL}: environment fault (invalid source AST)") from exc
    CONSTANTS = {
        target.id: node.value.value
        for node in SOURCE.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets if isinstance(target, ast.Name)
    }
    MAX_FILE = _constant("MAX_FILE", int)
    _environment(MAX_FILE > 0, TOOL, "invalid MAX_FILE")
    _require(len(tool_raw) <= MAX_FILE, TOOL, f"size exceeds MAX_FILE ({MAX_FILE})")
    MANIFEST_SHA256 = _sha_constant("MANIFEST_SHA256")
    MANIFEST_RAW = _read_file(MANIFEST, MAX_FILE)
    # Authenticate these exact bytes before constructing any parameter cases.
    _authenticate_manifest(MANIFEST_RAW)
    return _source_pins()


def _fixture_paths(raw):
    base = MANIFEST.rsplit("/", 1)[0]
    try:
        files = json.loads(raw, object_pairs_hook=_unique_pairs)["files"]
    except (ValueError, KeyError, TypeError) as exc:
        raise AssertionError(f"{base}: environment fault (invalid fixture files map)") from exc
    _environment(type(files) is dict and 0 < len(files) <= 32, base, "invalid fixture files map")
    known = {MANIFEST}
    pending, visited, name = [base], 0, base
    try:
        for relative in files:
            name = base + "/" + _relative(relative, MANIFEST)
            _checked_path(name, MAX_FILE)
            known.add(name)
        # corpus_names() enumerates even unlisted directories. Guard each one
        # before iterdir, without following links or reparse points to inspect it.
        while pending:
            name = pending.pop()
            folder, _ = _checked_path(name, MAX_FILE, directory=True)
            for path in folder.iterdir():
                name = path.relative_to(REPO).as_posix()
                visited += 1
                _environment(visited <= 128, base, "fixture traversal bound exceeded")
                if stat.S_ISDIR(path.lstat().st_mode):
                    pending.append(name)
                elif name not in known:
                    _checked_path(name, MAX_FILE)
    except OSError as exc:
        raise AssertionError(f"{name}: environment fault ({exc})") from exc


DRIVER = '''import json, runpy, sys
from pathlib import Path
m = runpy.run_path("tools/hierarchy_foundation_acceptance.py", run_name="rf14_crosscheck")
entry = m["inspect_legacy"]
real_verify = entry.__globals__["verify_source"]
phase = "before verify_source"
class SourceVerified(BaseException):
    pass
def observed(expected):
    global phase
    phase = "verify_source"
    real_verify(expected)
    raise SourceVerified()
entry.__globals__["verify_source"] = observed
try:
    entry(Path("tests/fixtures/hierarchy_native_foundation").resolve())
except SourceVerified:
    print(json.dumps({"ok": True}))
except m["AcceptanceError"] as exc:
    print("phase: " + phase, file=sys.stderr)
    print(json.dumps({"code": exc.code}))
else:
    raise RuntimeError("entry path returned without completing verify_source")
'''


def _verifier_check():
    raw = _manifest_check()
    _read_file(TOOL, MAX_FILE)
    _fixture_paths(raw)
    for name in sorted(PINS):
        try:
            _checked_path(name, MAX_FILE)
        except OSError as exc:
            raise AssertionError(f"{name}: environment fault ({exc})") from exc
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    try:
        result = subprocess.run([sys.executable, "-I", "-B", "-c", DRIVER], cwd=REPO, env=env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssertionError(f"contract/verifier: environment fault ({type(exc).__name__}: {exc})") from exc
    _environment(result.returncode == 0, "contract/verifier",
                 f"exit {result.returncode}: {result.stderr[-1000:]}")
    lines = result.stdout.splitlines()
    _environment(len(lines) == 1, "contract/verifier", "expected one JSON response line")
    try:
        response = json.loads(lines[0])
    except ValueError as exc:
        raise AssertionError("contract/verifier: environment fault (invalid JSON response)") from exc
    _environment(type(response) is dict and (
        (set(response) == {"ok"} and response["ok"] is True)
        or (set(response) == {"code"} and type(response["code"]) is str and bool(response["code"]))),
        "contract/verifier", "invalid verifier response")
    if response.get("ok") is True:
        return
    _environment(response["code"] == "FOUNDATION_SOURCE_MISMATCH", "contract/verifier",
                 f"{response['code']}; {result.stderr.strip()}")
    failures = []
    for name, expected in sorted(PINS.items()):
        try:
            test_pinned_source(name, expected)
        except AssertionError as exc:
            failures.append(str(exc))
    assert not failures, "\n".join(failures)
    raise AssertionError("contract/verifier drift: verify_source rejects the tree but no pinned path in this test "
                         "differs (run the replay; update the contract test)")


try:
    PINS = _collect_pins()
    COLLECTION_ERROR = None
except AssertionError as exc:
    PINS = {}
    COLLECTION_ERROR = str(exc)

if COLLECTION_ERROR is None:
    def test_manifest_pin():
        _manifest_check()

    def test_verifier_crosscheck():
        _verifier_check()

    CASES = sorted(PINS.items())
else:
    CASES = [("<collection>", None)]


@pytest.mark.parametrize("name,expected", CASES, ids=[name for name, _ in CASES])
def test_pinned_source(name, expected):
    if COLLECTION_ERROR is not None:
        raise AssertionError(COLLECTION_ERROR)
    _manifest_check()
    actual = hashlib.sha256(_read_file(name, MAX_FILE)).hexdigest()
    assert actual == expected, (
        f"{name}: needs successor pin (expected {expected}, got {actual})"
    )
