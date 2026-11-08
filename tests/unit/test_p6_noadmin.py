"""P6's public worker at controlled Win32 boundaries; never Windows acceptance."""
from __future__ import annotations

import ctypes as C
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace

import pytest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github/scripts/p6_noadmin.py"
DWORD, BOOL, HANDLE = C.c_uint32, C.c_int32, C.c_void_p
SCALAR_CLASSES = {8, 9, 20, 21, 26}


class SidAttributes(C.Structure):
    _fields_ = [("sid", HANDLE), ("attributes", DWORD)]


class Groups(C.Structure):
    _fields_ = [("count", DWORD), ("groups", SidAttributes * 1)]


class NativeFunction:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class WindowsBoundary:
    """Keep real ctypes buffers and token proofs; replace only native OS calls."""

    def __init__(self, problem=None, scalar_length=4, scalar_phase=0, scalar_kind=20,
                 boolean_length=1, boolean_value=1, boolean_padding=0xA5, boolean_phase=1,
                 privilege_luid=(23, 0), enabled_luid=None, privilege_phase=1):
        self.problem, self.scalar_length, self.scalar_phase = problem, scalar_length, scalar_phase
        self.scalar_kind = scalar_kind
        self.boolean_length, self.boolean_value = boolean_length, boolean_value
        self.boolean_padding, self.boolean_phase = boolean_padding, boolean_phase
        self.privilege_luid, self.enabled_luid = privilege_luid, enabled_luid
        self.privilege_phase, self.privilege_lookups = privilege_phase, []
        self.error, self.active, self.impersonations, self.reverts = 0, False, 0, 0
        self.closed, self.scalar_queries, self.modified_tokens = [], [], []
        self.boolean_queries = []
        self.junction_opens, self.functions = 0, {}
        self.user = C.create_string_buffer(bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<I", 1001))
        self.admin = C.create_string_buffer(bytes([1, 2, 0, 0, 0, 0, 0, 5]) + struct.pack("<II", 32, 544))
        self.medium = C.create_string_buffer(bytes([1, 1, 0, 0, 0, 0, 0, 16]) + struct.pack("<I", 8192))
        self.high = C.create_string_buffer(bytes([1, 1, 0, 0, 0, 0, 0, 16]) + struct.pack("<I", 12288))

    def dll(self, name, **kwargs):
        assert name in ("kernel32", "advapi32") and kwargs == {"use_last_error": True}
        return self

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self.functions:
            self.functions[name] = NativeFunction(lambda *args: self.call(name, args))
        return self.functions[name]

    def fail(self, error=5):
        self.error = error
        return 0

    @staticmethod
    def pointer(buffer):
        return C.cast(buffer, HANDLE)

    def information(self, kind):
        if kind == 1:
            sid = self.admin if self.active and self.problem == "wrong_user" else self.user
            return bytes(SidAttributes(self.pointer(sid), 0))
        if kind in (2, 11):
            sid = self.admin if kind == 2 or self.problem == "wrong_restrict" else self.user
            attributes = (4 if self.problem == "admin_enabled" else 0x10) if kind == 2 else 0
            return bytes(Groups(1, (SidAttributes * 1)(SidAttributes(self.pointer(sid), attributes))))
        if kind == 3:
            luid = (99, 0) if self.problem == "privilege_enabled" else self.privilege_luid
            if self.active and self.impersonations == self.privilege_phase and self.enabled_luid is not None:
                luid = self.enabled_luid
            return struct.pack("<IIiI", 1, *luid, 2)
        if kind == 25:
            sid = self.high if self.active and self.problem == "high_integrity" else self.medium
            return bytes(SidAttributes(self.pointer(sid), 0x20))
        if kind == 21:
            return bytes([0 if self.problem == "not_filtered" else self.boolean_value])
        values = {8: 1 if self.problem == "token_type" else 2,
                  9: 1 if self.problem == "identification" else 2,
                  20: int(self.problem == "elevated"),
                  26: int(self.problem == "ui_access")}
        return struct.pack("<I", values[kind])

    def token_information(self, handle, kind, output, length, returned):
        data = self.information(kind)
        C.cast(returned, C.POINTER(DWORD))[0] = len(data)
        if kind in SCALAR_CLASSES:
            self.scalar_queries.append((kind, length, bool(output)))
            # The captured Windows worker returned ERROR_BAD_LENGTH, not 122,
            # for the NULL/zero TokenElevation sizing call.
            if not output or length != 4:
                return self.fail(24)
            if kind == 21:
                aligned = C.cast(output, HANDLE).value % C.alignment(DWORD) == 0
                self.boolean_queries.append({"capacity": length, "aligned": aligned})
                assert aligned, "TokenHasRestrictions requires DWORD-aligned storage"
                C.memset(output, self.boolean_padding, length)
                if self.impersonations == self.boolean_phase:
                    if self.problem == "boolean_failure":
                        return self.fail()
                    C.cast(returned, C.POINTER(DWORD))[0] = self.boolean_length
            elif kind == self.scalar_kind and self.impersonations == self.scalar_phase:
                if self.problem == "scalar_failure":
                    return self.fail()
                C.cast(returned, C.POINTER(DWORD))[0] = self.scalar_length
        elif not output or length < len(data):
            return self.fail(24 if self.problem == "variable_bad_length" else 122)
        C.memmove(output, data, len(data))
        return 1

    def call(self, name, args):
        if name == "GetLastError":
            return self.error
        if name in ("GetCurrentProcess", "GetCurrentThread"):
            return 41
        if name == "OpenProcessToken":
            C.cast(args[2], C.POINTER(HANDLE))[0] = HANDLE(101)
            return 1
        if name == "OpenThreadToken":
            if not self.active:
                return self.fail(1008)
            C.cast(args[3], C.POINTER(HANDLE))[0] = HANDLE(103)
            return 1
        if name == "GetTokenInformation":
            return self.token_information(*args)
        if name == "CreateWellKnownSid":
            sid = self.admin if args[0] == 26 else self.medium
            length = 16 if args[0] == 26 else 12
            C.memmove(args[2], sid, length)
            C.cast(args[3], C.POINTER(DWORD))[0] = length
            return 1
        if name == "GetLengthSid":
            return 8 + C.string_at(args[0], 2)[1] * 4
        if name == "IsValidSid":
            return 1
        if name == "CreateRestrictedToken":
            assert args[0].value == 101 and args[1] == 5 and args[2] == args[6] == 1
            C.cast(args[8], C.POINTER(HANDLE))[0] = HANDLE(102)
            return 1
        if name == "SetTokenInformation":
            self.modified_tokens.append(args[0].value)
            assert args[0].value == 102
            return 1
        if name == "ImpersonateLoggedOnUser":
            self.impersonations += 1
            self.active = True
            return 1
        if name == "RevertToSelf":
            self.reverts += 1
            if self.problem == "revert_failure":
                return self.fail()
            self.active = False
            return 1
        if name == "CheckTokenMembership":
            C.cast(args[2], C.POINTER(BOOL))[0] = int(self.problem == "admin_membership")
            return 1
        if name == "LookupPrivilegeValueW":
            assert args[:2] == (None, "SeChangeNotifyPrivilege")
            self.privilege_lookups.append(self.active)
            if self.problem == "lookup_prepare_failure" or self.active and self.problem == "lookup_active_failure":
                return self.fail(6)
            C.memmove(args[2], struct.pack("<Ii", *self.privilege_luid), 8)
            return 1
        if name == "CloseHandle":
            self.closed.append(args[0].value)
            return 1
        if name == "GetVolumePathNameW":
            args[1].value = "X:\\"
            return 1
        if name == "GetDriveTypeW":
            return 3
        if name == "GetVolumeInformationW":
            C.cast(args[3], C.POINTER(DWORD))[0] = 17
            args[6].value = "NTFS"
            return 1
        if name == "CreateFileW":
            self.junction_opens += 1
            self.error = 5
            # Stop at the real junction helper's native boundary. These controls
            # must retain FAIL and cannot manufacture Windows acceptance.
            return C.c_void_p(-1).value
        raise AssertionError("unexpected Windows API call: " + name)


@pytest.fixture
def run_worker(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("p6_noadmin", SCRIPT)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    version = SimpleNamespace(major=10, minor=0, build=26100, platform_version=(10, 0, 26100))
    modeled_sys = SimpleNamespace(**vars(sys))
    modeled_sys.platform = "win32"
    modeled_sys.getwindowsversion = lambda: version
    monkeypatch.setattr(probe, "sys", modeled_sys)

    def run(junction=None, **options):
        boundary = WindowsBoundary(**options)
        monkeypatch.setattr(C, "WinDLL", boundary.dll, raising=False)
        if junction is not None:
            # Replace only the product helper the worker loads by path; its own checks still run.
            monkeypatch.setattr(probe, "load", lambda path, name: junction(boundary))
        fatal_calls = []

        def fatal_exit(code):
            fatal_calls.append(code)
            raise SystemExit(code)

        monkeypatch.setattr(os, "_exit", fatal_exit)
        root = tmp_path / "evidence"
        root.mkdir()
        try:
            code = probe.worker({"source": str(REPO), "evidence": str(root)})
        except SystemExit as error:
            code = error.code
        report = json.loads((root / "worker-result.json").read_text())
        (root / "controlled-boundary.json").write_text(json.dumps({
            "active": boundary.active, "impersonations": boundary.impersonations,
            "reverts": boundary.reverts, "closed": boundary.closed,
            "privilege_lookups": boundary.privilege_lookups,
            "junction_opens": boundary.junction_opens, "fatal_calls": fatal_calls,
        }, indent=2, sort_keys=True) + "\n")
        assert report["status"] == "FAIL" and report["windows_acceptance"] is False
        return boundary, code, report, fatal_calls

    return run


@pytest.mark.parametrize("luid", [(0x12345678, 7), (0x12345678, -7)])
def test_privilege_lookup_before_impersonation_preserves_complete_local_luid(run_worker, luid):
    boundary, code, report, fatal = run_worker(problem="lookup_active_failure", privilege_luid=luid)
    assert code == 1 and report["error"] == "CreateFileW failed: Windows error 5"
    assert report["junction_called"] and boundary.junction_opens == 1
    assert boundary.privilege_lookups == [False]
    for phase in ("preflight", "operation"):
        assert report["token"][phase]["privileges"] == [{"low": luid[0], "high": luid[1], "attributes": 2}]
    assert not boundary.active and boundary.impersonations == boundary.reverts == 2
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1
    assert boundary.closed.count(103) == 2 and not fatal


def test_privilege_lookup_prepare_failure_stops_before_impersonation_and_closes_owned_handles(run_worker):
    boundary, code, report, fatal = run_worker(problem="lookup_prepare_failure")
    assert code == 1 and (report["error_type"], report["error"]) == (
        "RuntimeError", "LookupPrivilegeValueW failed: Windows error 6")
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert boundary.privilege_lookups == [False]
    assert not boundary.active and boundary.impersonations == boundary.reverts == 0
    assert "preflight" not in report["token"] and "operation" not in report["token"]
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1
    assert 103 not in boundary.closed and not fatal


@pytest.mark.parametrize("phase", [1, 2])
@pytest.mark.parametrize("unexpected", [(0x12345679, -7), (0x12345678, -8)])
def test_privilege_allowlist_rejects_each_mismatched_luid_part_in_both_proofs(run_worker, phase, unexpected):
    boundary, code, report, fatal = run_worker(
        privilege_luid=(0x12345678, -7), enabled_luid=unexpected, privilege_phase=phase)
    assert code == 1 and report["error"] == "unexpected enabled privilege"
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert not boundary.active and boundary.reverts == phase
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1
    assert boundary.closed.count(103) == phase and not fatal


def test_fixed_width_scalars_avoid_bad_length_sizing_and_reach_the_junction_boundary(run_worker):
    boundary, code, report, fatal = run_worker()
    assert code == 1 and report["error"] == "CreateFileW failed: Windows error 5"
    assert report["junction_called"] and boundary.junction_opens == 1
    assert {kind for kind, _, _ in boundary.scalar_queries} == SCALAR_CLASSES
    assert all(length == 4 and supplied for _, length, supplied in boundary.scalar_queries)
    assert report["token"]["preflight"]["filtered"] == report["token"]["operation"]["filtered"] == 1
    assert boundary.modified_tokens == [102] and not boundary.active and boundary.reverts == 2
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1 and not fatal


@pytest.mark.parametrize("value,padding", [(1, 0xA5), (2, 0x5A), (0x80, 0xFF), (0xFF, 0)])
def test_restrictions_boolean_uses_only_the_first_aligned_byte(run_worker, value, padding):
    boundary, code, report, fatal = run_worker(boolean_value=value, boolean_padding=padding)
    assert code == 1 and report["error"] == "CreateFileW failed: Windows error 5"
    assert report["junction_called"] and boundary.junction_opens == 1
    assert boundary.boolean_queries == [{"capacity": 4, "aligned": True}] * 2
    assert report["token"]["preflight"]["filtered"] == report["token"]["operation"]["filtered"] == value
    assert boundary.modified_tokens == [102] and not boundary.active and boundary.reverts == 2
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1 and not fatal


@pytest.mark.parametrize("padding", [1, 0xA5, 0xFF])
def test_zero_restrictions_boolean_cannot_be_made_true_by_padding(run_worker, padding):
    boundary, code, report, fatal = run_worker(boolean_value=0, boolean_padding=padding)
    assert code == 1 and report["error"] == "effective token is not filtered"
    assert report["token"]["preflight"]["filtered"] == 0
    assert boundary.boolean_queries == [{"capacity": 4, "aligned": True}]
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert not boundary.active and boundary.reverts == 1
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1 and not fatal


@pytest.mark.parametrize("phase", [1, 2])
@pytest.mark.parametrize("length", [0, 2, 4, 8, 65536])
def test_restrictions_boolean_rejects_every_other_return_length(run_worker, phase, length):
    boundary, code, report, fatal = run_worker(boolean_length=length, boolean_phase=phase)
    assert code == 1 and (report["error_type"], report["error"]) == (
        "RuntimeError", "GetTokenInformation class 21 invalid BOOLEAN width: " + str(length))
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert not boundary.active and boundary.reverts == phase
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1
    assert boundary.closed.count(103) == phase and not fatal


@pytest.mark.parametrize("phase", [1, 2])
def test_restrictions_boolean_api_error_stops_before_junction_and_restores_identity(run_worker, phase):
    boundary, code, report, fatal = run_worker(problem="boolean_failure", boolean_phase=phase)
    assert code == 1 and report["error"] == "GetTokenInformation failed: Windows error 5"
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert not boundary.active and boundary.reverts == phase
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1
    assert boundary.closed.count(103) == phase and not fatal


@pytest.mark.parametrize("kind", sorted(SCALAR_CLASSES - {21}))
@pytest.mark.parametrize("length", [0, 1, 2, 3, 8])
@pytest.mark.parametrize("phase", [1, 2])
def test_other_fixed_width_token_classes_still_require_a_complete_dword(run_worker, kind, length, phase):
    boundary, code, report, fatal = run_worker(scalar_kind=kind, scalar_length=length, scalar_phase=phase)
    assert code == 1 and report["error"] == "GetTokenInformation invalid DWORD width"
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert not boundary.active and boundary.reverts == phase
    assert boundary.closed.count(101) == boundary.closed.count(102) == 1
    assert boundary.closed.count(103) == phase and not fatal


@pytest.mark.parametrize("length", [0, 3, 8])
def test_scalar_return_width_must_be_exact_before_any_token_restriction(run_worker, length):
    boundary, code, report, fatal = run_worker(scalar_length=length)
    assert code == 1 and (report["error_type"], report["error"]) == (
        "RuntimeError", "GetTokenInformation invalid DWORD width")
    assert not report["junction_called"] and not boundary.modified_tokens
    assert boundary.closed == [101] and not boundary.active and not fatal


def test_fixed_size_query_failure_remains_explicit_and_closes_the_original_handle(run_worker):
    boundary, code, report, fatal = run_worker(problem="scalar_failure")
    assert code == 1 and report["error"] == "GetTokenInformation failed: Windows error 5"
    assert not report["junction_called"] and boundary.closed == [101] and not fatal


def test_variable_size_sid_query_keeps_its_strict_sizing_contract(run_worker):
    boundary, code, report, fatal = run_worker(problem="variable_bad_length")
    assert code == 1 and report["error"] == "GetTokenInformation size failed: Windows error 24"
    assert not report["junction_called"] and not boundary.scalar_queries
    assert boundary.closed == [101] and not fatal


def test_bad_scalar_width_in_effective_token_reverts_and_closes_both_owned_handles(run_worker):
    boundary, code, report, fatal = run_worker(scalar_length=3, scalar_phase=1)
    assert code == 1 and report["error"] == "GetTokenInformation invalid DWORD width"
    assert not report["junction_called"] and not boundary.active and boundary.reverts == 1
    assert 101 in boundary.closed and 102 in boundary.closed and 103 in boundary.closed and not fatal


@pytest.mark.parametrize("problem,message", [
    ("elevated", "elevated effective token"),
    ("ui_access", "effective token has UIAccess"),
    ("not_filtered", "effective token is not filtered"),
    ("admin_enabled", "Administrators SID is not deny-only"),
    ("admin_membership", "effective Administrators membership is enabled"),
    ("privilege_enabled", "unexpected enabled privilege"),
    ("token_type", "effective token cannot impersonate"),
    ("identification", "effective token cannot impersonate"),
    ("high_integrity", "effective token requires medium integrity"),
    ("wrong_user", "effective token user differs"),
    ("wrong_restrict", "user restricting SID differs"),
])
def test_denied_token_proofs_still_prevent_junction_creation_and_restore_identity(run_worker, problem, message):
    boundary, code, report, fatal = run_worker(problem=problem)
    assert code == 1 and report["error"] == message
    assert not report["junction_called"] and boundary.junction_opens == 0
    assert not boundary.active and boundary.reverts == 1
    assert 101 in boundary.closed and 102 in boundary.closed and not fatal


def test_failed_reversion_remains_terminal_without_closing_unrestored_token_handles(run_worker):
    boundary, code, report, fatal = run_worker(problem="revert_failure")
    assert code == 3 and fatal == [3] and report["error"] == "RevertToSelf failed: Windows error 5"
    assert not report["junction_called"] and boundary.active
    assert 101 not in boundary.closed and 102 not in boundary.closed


def python39_junction(monkeypatch, destination=None):
    """A followable directory link stands in for the product junction. Under the restricted
    token, Python 3.9's Windows Path.resolve lets _getfinalpathname's WinError 5 escape
    (pathlib catches only FileNotFoundError); 3.10+ resolves through os.path.realpath."""
    resolve, lstat, rmdir = Path.resolve, Path.lstat, Path.rmdir
    created = []

    def install(boundary):
        def restricted_resolve(path, *args, **kwargs):
            if boundary.active:
                raise PermissionError(13, "Access is denied", str(path))
            return resolve(path, *args, **kwargs)

        def junction_lstat(path):
            info = lstat(path)
            if path not in created:
                return info
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            return SimpleNamespace(**(fields | {"st_reparse_tag": 0xA0000003, "st_file_attributes": 0x400}))

        def cleanup_boundary(path):
            if path in created:
                # Stop before cleanup so this control keeps FAIL and cannot manufacture acceptance.
                raise RuntimeError("modeled cleanup boundary")
            return rmdir(path)

        def create_directory_junction(target, link):
            os.symlink(destination or target, link, target_is_directory=True)
            created.append(link)

        monkeypatch.setattr(Path, "resolve", restricted_resolve)
        monkeypatch.setattr(Path, "lstat", junction_lstat)
        monkeypatch.setattr(Path, "rmdir", cleanup_boundary)
        return SimpleNamespace(create_directory_junction=create_directory_junction)

    return install


@pytest.mark.parametrize("elsewhere,message", [(False, "modeled cleanup boundary"),
                                               (True, "junction target differs")])
def test_junction_target_check_survives_python39_resolution_under_the_token(run_worker, monkeypatch, tmp_path,
                                                                           elsewhere, message):
    """P6 on Python 3.9 (Validate runs 41454378514, 41482747131): the worker verifies the junction
    target without Path.resolve under the token and still rejects a junction that points elsewhere."""
    from tests.conftest import symlink_or_skip

    symlink_or_skip(tmp_path, tmp_path / "link-probe", target_is_directory=True)
    destination = None
    if elsewhere:
        destination = tmp_path / "elsewhere"
        destination.mkdir()
        # A matching sentinel leaves the target comparison as the only check that can reject it.
        (destination / "sentinel.txt").write_text("P6 owned sentinel\n", encoding="utf-8")
    boundary, code, report, fatal = run_worker(junction=python39_junction(monkeypatch, destination))
    assert code == 1 and (report["error_type"], report["error"]) == ("RuntimeError", message)
    assert report["junction_called"] and report["junction"]["tag"] == 0xA0000003
    assert not boundary.active and boundary.impersonations == boundary.reverts == 2 and not fatal


# P6 diagnostic regression controls. Existing test/helper prefix above is frozen.
_P6_BASELINE_WORKER = "def worker(config):\n    root, source = Path(config['evidence']), Path(config['source'])\n    result = {'status': 'FAIL', 'windows_acceptance': False, 'scope': 'M0 P6 junction rights only',\n              'token': {}, 'junction_called': False, 'platform': sys.platform}\n    token = None\n    # Open diagnostics before impersonation; no junction handle is pre-opened.\n    with (root / 'worker-result.json').open('w', encoding='utf-8') as output:\n        try:\n            require(sys.platform == 'win32', 'P6 requires Windows; no Windows acceptance on this host')\n            windows_facts(root, result)\n            junction = load(source / 'aegis_core/verification/windows_junction.py', 'p6_product_junction')\n            token = Token(result['token'])\n            token.prepare()\n            token.enter()\n            try:\n                token.proof('preflight')\n            finally:\n                token.revert()\n            token.enter()\n            try:\n                token.proof('operation')\n                fixture = root / 'fixture'\n                fixture.mkdir()\n                target = fixture / 'target'\n                target.mkdir()\n                sentinel = target / 'sentinel.txt'\n                sentinel.write_text('P6 owned sentinel\\n', encoding='utf-8')\n                require(sentinel.read_text(encoding='utf-8') == 'P6 owned sentinel\\n', 'restricted ordinary-file control failed')\n                link = fixture / 'junction'\n                result['junction_called'] = True\n                junction.create_directory_junction(target, link)\n                owned = link.lstat()\n                destination = os.readlink(link)\n                result['junction'] = {'device': owned.st_dev, 'inode': owned.st_ino,\n                    'tag': getattr(owned, 'st_reparse_tag', None), 'target': destination,\n                    'attributes': getattr(owned, 'st_file_attributes', None)}\n                require(result['junction']['tag'] == 0xA0000003 and result['junction']['attributes'] & 0x400,\n                        'created entry is not a mount-point junction')\n                # Python 3.9's Path.resolve() raises under this token; 3.10+ resolve() is realpath.\n                require(Path(os.path.realpath(link)) == Path(os.path.realpath(target)), 'junction target differs')\n                require((link / 'sentinel.txt').read_text(encoding='utf-8') == 'P6 owned sentinel\\n', 'junction traversal failed')\n                current = link.lstat()\n                require((current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino)\n                        and os.readlink(link) == destination and current.st_reparse_tag == 0xA0000003,\n                        'owned junction changed before cleanup')\n                link.rmdir()\n                require(not os.path.lexists(link) and sentinel.read_text(encoding='utf-8') == 'P6 owned sentinel\\n',\n                        'junction cleanup changed its target')\n                result['junction_removed_target_preserved'] = True\n            finally:\n                token.revert()\n            token.close()\n            result.update(status='PASS', windows_acceptance=True)\n        except BaseException as exc:\n            result.update(status='FAIL', windows_acceptance=False, error_type=type(exc).__name__,\n                          error=str(exc), traceback=traceback.format_exc())\n        finally:\n            if token is not None and not token.fatal:\n                try:\n                    token.revert()\n                    token.close()\n                except BaseException as exc:\n                    result.update(status='FAIL', windows_acceptance=False, error_type=type(exc).__name__, error=str(exc))\n            output.write(json.dumps(result, indent=2, sort_keys=True) + '\\n')\n            output.flush()\n    if token is not None and token.fatal:\n        os._exit(3)  # Required shutdown after failed reversion; diagnostics already flushed.\n    return 0 if result['status'] == 'PASS' else 1"
_P6_MODELLED = "MODELLED_WIN32_REAL_TEMP_FILESYSTEM_NOT_NATIVE_ACCEPTANCE"


class _P6TraceBoundary(WindowsBoundary):
    def __init__(self, root, second_revert=False, verification_failure=False,
                 first_revert=False, close_failure=False):
        super().__init__()
        self.root = root
        self.trace = []
        self.second_revert = second_revert
        self.verification_failure = verification_failure
        self.first_revert, self.close_failure = first_revert, close_failure

    def _argument(self, value):
        obj = getattr(value, "_obj", value)
        if isinstance(obj, C.c_void_p):
            return ("handle", obj.value)
        if isinstance(obj, C.Structure):
            fields = []
            for name, _kind in obj._fields_:
                item = getattr(obj, name)
                if name.lower() == "sid" and item:
                    size = 8 + C.string_at(item, 2)[1] * 4
                    item = ("sid-bytes", C.string_at(item, size).hex())
                fields.append((name, item))
            return ("structure", tuple(fields))
        if isinstance(obj, C.Array):
            return ("buffer", C.sizeof(obj), obj._type_.__name__)
        if hasattr(obj, "value"):
            return ("scalar", obj.value)
        if type(obj) is str:
            return obj.replace(str(self.root), "<EVIDENCE>")
        if obj is None or type(obj) in (int, bool):
            return obj
        return ("pointer-kind", type(obj).__name__)

    def call(self, name, args):
        def arguments():
            if name in ("IsValidSid", "GetLengthSid") and args[0]:
                size = 8 + C.string_at(args[0], 2)[1] * 4
                return (("sid-bytes", C.string_at(args[0], size).hex()),)
            return tuple(self._argument(arg) for arg in args)
        before = arguments()
        if name == "RevertToSelf" and (self.first_revert or self.second_revert and self.reverts == 1):
            self.problem = "revert_failure"
        if name == "CloseHandle" and self.close_failure and args[0].value in (101, 102):
            result = self.fail(6)
        elif name == "OpenThreadToken" and self.verification_failure and self.reverts and not self.active:
            C.cast(args[3], C.POINTER(HANDLE))[0] = HANDLE(103)
            result = 1
        else:
            result = super().call(name, args)
        self.trace.append((name, before, arguments(), result))
        return result


def _p6_diagnostic_case(parent, monkeypatch, *, baseline=False, fault=None, attributes=None,
                        second_revert=False, verification_failure=False, capacity=False,
                        hostile=False, observable=False, formatter_failure=False,
                        unattributed=False, writer_failure=False, mutation=None, observe_lifetime=False,
                        first_revert=False, close_failure=False, capture_fault=False):
    """Public worker with only OS boundaries replaced; each invocation owns a fresh root."""
    import io
    import stat

    parent.mkdir()
    (parent / ".keep").touch()
    home, root = parent / "home", parent / "evidence"
    home.mkdir()
    root.mkdir()
    events, fs_trace, format_calls = [], [], []
    source = SCRIPT.read_text()
    worker_source = _P6_BASELINE_WORKER
    if unattributed:
        needle = "                link = fixture / 'junction'\n"
        inserted = needle + "                raise ValueError('modelled between-step failure')\n"
        if baseline:
            assert worker_source.count(needle) == 1
            worker_source = worker_source.replace(needle, inserted)
        else:
            assert source.count(needle) == 1
            source = source.replace(needle, inserted)
    if capacity and not baseline:
        if capacity is True or capacity == "events":
            source = source.replace("EVENT_LIMIT = 64", "EVENT_LIMIT = 1")
        if capacity is True or capacity == "errors":
            source = source.replace("ERROR_LIMIT = 4", "ERROR_LIMIT = 1")
    if capture_fault and not baseline:
        needle = "        self._refs = [None] * self.ERROR_LIMIT\n"
        replacement = ("        class UnavailableEvents(list):\n"
                       "            def append(self, value):\n"
                       "                raise RuntimeError('modelled diagnostic storage failure')\n"
                       "        self.data['events'] = UnavailableEvents()\n" + needle)
        assert source.count(needle) == 1
        source = source.replace(needle, replacement)
    if mutation is not None and not baseline:
        for old, new in mutation:
            assert source.count(old) == 1, "guard does not identify exactly one owned source location"
            source = source.replace(old, new)
    path = parent / "probe.py"
    path.write_text(source)
    path.chmod(0o400)
    source_pin = path.read_bytes()
    spec = importlib.util.spec_from_file_location("p6_diagnostic_case", path)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    if baseline:
        before_path = parent / "baseline-worker.py"
        before_path.write_text(worker_source + "\n")
        before_path.chmod(0o400)
        sealed = before_path.read_bytes()
        exec(compile(sealed, str(before_path), "exec"), probe.__dict__)
        assert before_path.read_bytes() == sealed and stat.S_IMODE(before_path.stat().st_mode) == 0o400
    boundary = _P6TraceBoundary(root, second_revert, verification_failure, first_revert, close_failure)
    roles = {str(root): "EVIDENCE_ROOT", str(root / "worker-result.json"): "RESULT",
             str(root / "fixture"): "FIXTURE_DIR", str(root / "fixture/target"): "TARGET_DIR",
             str(root / "fixture/target/sentinel.txt"): "SENTINEL_FILE", str(root / "fixture/junction"): "JUNCTION_ENTRY"}

    def role(path):
        if isinstance(path, (str, bytes, Path)):
            return roles.get(os.fsdecode(path))
        return None

    denial_path = root / ("fixture" if fault == "fixture_mkdir" else "fixture/target" if fault == "target_mkdir" else "fixture/target/sentinel.txt")
    if hostile or observable or formatter_failure:
        class ControlledPermission(PermissionError):
            def __str__(self):
                events.append("str")
                if formatter_failure:
                    raise ValueError("original formatter failure")
                return "modelled observable exception"
            def __repr__(self):
                events.append("repr")
                raise AssertionError("new repr")
            def __eq__(self, other):
                events.append("eq")
                raise AssertionError("new equality")
            def __hash__(self):
                events.append("hash")
                raise AssertionError("new hash")
        if hostile:
            def trapped(name):
                def read(self):
                    events.append(name)
                    raise AssertionError("hostile attribute read")
                return property(read)
            for name in ("errno", "winerror", "filename", "filename2", "__context__", "__cause__"):
                setattr(ControlledPermission, name, trapped(name))
        denial = ControlledPermission(13, "modelled denial", str(denial_path))
    elif observe_lifetime:
        class LifetimePermission(PermissionError):
            pass
        denial = LifetimePermission(13, "modelled denial", str(denial_path))
    else:
        denial = PermissionError(13, "modelled denial", str(denial_path))
    reference = None
    if observe_lifetime:
        import weakref
        reference = weakref.ref(denial)
    for key, value in (attributes or {}).items():
        setattr(denial, key, value)
    originals = {name: getattr(os, name) for name in ("mkdir", "stat", "lstat", "readlink", "rmdir")}
    original_open = io.open

    def fs(name):
        original = originals[name]
        def call(path, *args, **kwargs):
            owned = role(path)
            if owned:
                fs_trace.append((name, owned, args, tuple(sorted(kwargs.items())), boundary.active))
            if name == "mkdir" and owned == {"fixture_mkdir": "FIXTURE_DIR", "target_mkdir": "TARGET_DIR"}.get(fault):
                raise denial
            return original(path, *args, **kwargs)
        return call

    class Writer:
        def __init__(self, stream):
            self.stream = stream
        def write(self, data):
            format_calls.append("write")
            if writer_failure:
                raise OSError(5, "modelled result write failure")
            return self.stream.write(data)
        def flush(self):
            format_calls.append("flush")
            return self.stream.flush()
        def __enter__(self):
            self.stream.__enter__()
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)

    def opened(path, *args, **kwargs):
        owned = role(path)
        mode = args[0] if args else kwargs.get("mode", "r")
        if owned:
            fs_trace.append(("open", owned, mode, tuple(sorted(kwargs.items())), boundary.active))
        if owned == "SENTINEL_FILE" and ((fault == "sentinel_write" and "w" in mode)
                                        or (fault == "sentinel_read_verify" and "r" in mode)):
            raise denial
        stream = original_open(path, *args, **kwargs)
        return Writer(stream) if owned == "RESULT" and "w" in mode else stream

    caught, code = None, None
    with monkeypatch.context() as patch:
        for key in ("HOME", "USERPROFILE"):
            patch.setenv(key, str(home))
        if os.name == "posix":
            import pwd
            patch.setattr(pwd, "getpwuid", lambda uid: pwd.struct_passwd(("fixture", "x", uid, uid, "", str(home), "")))
        for key in tuple(os.environ):
            if key in ("CLAUDECODE", "CLAUDE_PID") or key.startswith("CLAUDE_CODE_"):
                patch.delenv(key, raising=False)
        modeled_sys = SimpleNamespace(**vars(sys))
        modeled_sys.platform = "win32"
        modeled_sys.getwindowsversion = lambda: SimpleNamespace(major=10, minor=0, build=26100, platform_version=(10, 0, 26100))
        patch.setattr(probe, "sys", modeled_sys)
        patch.setattr(C, "WinDLL", boundary.dll, raising=False)
        for name in originals:
            patch.setattr(os, name, fs(name))
        patch.setattr(io, "open", opened)
        original_format = probe.traceback.format_exc
        def formatted():
            format_calls.append("traceback")
            return original_format()
        patch.setattr(probe.traceback, "format_exc", formatted)
        def exited(value):
            format_calls.append(("fatal_exit", value))
            raise SystemExit(value)
        patch.setattr(os, "_exit", exited)
        try:
            code = probe.worker({"source": str(REPO), "evidence": str(root)})
        except SystemExit as error:
            code = error.code
        except BaseException as error:
            caught = error
    result_path = root / "worker-result.json"
    data = result_path.read_text() if result_path.is_file() else ""
    report = json.loads(data) if data else None
    assert path.read_bytes() == source_pin and stat.S_IMODE(path.stat().st_mode) == 0o400
    summary = {"qualification": _P6_MODELLED, "code": code,
               "escape": type(caught).__name__ if caught is not None else None,
               "native_calls": boundary.trace, "filesystem_calls": fs_trace,
               "format_calls": format_calls, "exception_calls": events}
    (parent / "boundary-trace.json").write_text(json.dumps(summary, indent=2) + "\n")
    denial = None  # Release the controller's reference; the worker must retain none after its writer.
    return probe, boundary, report, summary, root, reference


def _p6_pair(tmp_path, monkeypatch, **options):
    before = _p6_diagnostic_case(tmp_path / "before", monkeypatch, baseline=True, **options)
    after = _p6_diagnostic_case(tmp_path / "candidate", monkeypatch, **options)
    assert before[3] == after[3], "diagnostics changed delegated calls, cleanup or formatter behavior"
    for key in ("status", "windows_acceptance", "junction_called", "token"):
        assert before[2][key] == after[2][key]
    assert before[2]["status"] == after[2]["status"] == "FAIL"
    assert before[2]["windows_acceptance"] is after[2]["windows_acceptance"] is False
    if "error" in before[2]:
        assert before[2]["error_type"] == after[2]["error_type"]
        assert before[2]["error"].replace(str(before[4]), "<EVIDENCE>") == after[2]["error"].replace(str(after[4]), "<EVIDENCE>")
    diagnostic = after[2].get("diagnostic")
    assert type(diagnostic) is dict, "missing P6_CACHED_PROGRESS_V1 diagnostic after healthy public prerequisites"
    assert diagnostic["schema"] == "P6_CACHED_PROGRESS_V1"
    assert diagnostic["coverage"] == "SELECTED_WORKER_STEPS_AND_ERROR_OBSERVATIONS"
    assert len(diagnostic["events"]) <= 64 and len(diagnostic["errors"]) <= 4
    assert len(json.dumps(diagnostic, indent=2).encode()) <= 16384
    encoded = json.dumps(diagnostic)
    assert str(after[4]) not in encoded and "PRIVATE_CANARY" not in encoded
    return after, diagnostic


def test_worker_diagnostic_records_setup_before_product_denial(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch)
    assert after[3]["code"] == 1 and after[2]["junction_called"]
    complete = {event["operation"] for event in diagnostic["events"] if event["event"] == "completed"}
    assert {"preflight_proof", "operation_proof", "fixture_mkdir", "target_mkdir", "sentinel_write", "sentinel_read_verify"} <= complete
    assert diagnostic["errors"][0]["operation"] == "junction_create"


@pytest.mark.parametrize("fault,role", [("fixture_mkdir", "FIXTURE_DIR"), ("target_mkdir", "TARGET_DIR"),
                                      ("sentinel_write", "SENTINEL_FILE"), ("sentinel_read_verify", "SENTINEL_FILE")])
def test_worker_diagnostic_records_owned_filesystem_denial(tmp_path, monkeypatch, fault, role):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault=fault)
    assert after[3]["code"] == 1 and not after[2]["junction_called"] and not after[1].active
    error = diagnostic["errors"][0]
    assert error["operation"] == fault and error["exception_type"] == "PermissionError"
    assert error["errno"] == 13 and type(error["errno"]) is int
    assert error["filename_role"] == role
    assert {"operation": fault, "event": "attempted"} in diagnostic["events"]
    assert {"operation": fault, "event": "completed"} not in diagnostic["events"]
    assert diagnostic["reported_error"] == error["ordinal"]


def test_worker_diagnostic_links_body_error_to_operation_revert_failure(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", second_revert=True)
    assert after[3]["code"] == 3 and after[1].active
    assert 101 not in after[1].closed and 102 not in after[1].closed
    body, recovery = diagnostic["errors"]
    assert body["operation"] == "fixture_mkdir" and recovery["operation"] == "operation_revert"
    assert recovery["prior_error"] == body["ordinal"] and recovery["phase"] == "recovery"
    assert diagnostic["reported_error"] == recovery["ordinal"]
    assert after[2]["error"] == "RevertToSelf failed: Windows error 5"


def test_worker_diagnostic_first_seen_outer_error_is_unattributed(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, unattributed=True)
    assert after[3]["code"] == 1 and not after[2]["junction_called"]
    assert diagnostic["capture_status"] == "UNKNOWN"
    assert len(diagnostic["errors"]) == 1
    assert diagnostic["errors"][0]["operation"] == "UNATTRIBUTED_WORKER_STATEMENT"
    assert diagnostic["errors"][0]["phase"] == "outer"
    assert diagnostic["reported_error"] == diagnostic["errors"][0]["ordinal"]


def test_worker_diagnostic_overflow_is_sticky_unknown_and_keeps_counts(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", second_revert=True, capacity=True)
    assert after[3]["code"] == 3 and diagnostic["capture_status"] == "UNKNOWN"
    assert len(diagnostic["events"]) == len(diagnostic["errors"]) == 1
    assert diagnostic["omitted_events"] > 0 and diagnostic["omitted_errors"] == 1
    assert diagnostic["reported_error"] is None and diagnostic["reported_error_state"] == "OMITTED"


@pytest.mark.parametrize("hostile,observable,formatter_failure", [(True, False, False), (False, True, False), (False, False, True)])
def test_worker_diagnostic_hostile_exception_adds_no_calls(tmp_path, monkeypatch, hostile, observable, formatter_failure):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", hostile=hostile,
                                 observable=observable, formatter_failure=formatter_failure)
    assert diagnostic["capture_status"] == "UNKNOWN"
    assert diagnostic["errors"][0]["exception_type"] == "UNKNOWN"
    assert diagnostic["errors"][0]["errno"] is None
    assert not any(value in ("errno", "winerror", "filename", "filename2", "eq", "hash", "repr") for value in after[3]["exception_calls"])


@pytest.mark.parametrize("field,value", [("errno", True), ("errno", "PRIVATE_CANARY"), ("errno", 2**40),
                                         ("errno", -(2**31)-1), ("winerror", False), ("winerror", -1), ("winerror", 2**32)])
def test_worker_diagnostic_rejects_malformed_exception_attributes(tmp_path, monkeypatch, field, value):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", attributes={field: value})
    assert after[3]["code"] == 1 and diagnostic["capture_status"] == "UNKNOWN"
    assert diagnostic["errors"][0][field] is None and diagnostic["errors"][0][field + "_state"] == "UNSUPPORTED"


@pytest.mark.parametrize("field,value", [("errno", -(2**31)), ("errno", 2**31-1), ("winerror", 0), ("winerror", 2**32-1)])
def test_worker_diagnostic_preserves_exact_numeric_domains(tmp_path, monkeypatch, field, value):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", attributes={field: value})
    assert after[3]["code"] == 1
    assert diagnostic["errors"][0][field] == value and type(diagnostic["errors"][0][field]) is int


def test_worker_diagnostic_reversion_verification_keeps_original_chain(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, verification_failure=True)
    assert after[3]["code"] == 3 and not after[1].active
    assert 101 not in after[1].closed and 102 not in after[1].closed
    assert diagnostic["errors"][0]["operation"] == "preflight_revert"
    assert diagnostic["errors"][0]["exception_type"] == "RevertFailed"
    assert "restoration verification failed" in after[2]["error"]
    assert "direct cause" in after[2]["traceback"]


def _p6_lifetime_contract(tmp_path, monkeypatch, writer_failure=False, mutation=None):
    import gc

    enabled = gc.isenabled()
    gc.disable()
    try:
        before = _p6_diagnostic_case(tmp_path / "before", monkeypatch, baseline=True,
                                     fault="fixture_mkdir", observe_lifetime=True, writer_failure=writer_failure)
        after = _p6_diagnostic_case(tmp_path / "candidate", monkeypatch, fault="fixture_mkdir",
                                    observe_lifetime=True, writer_failure=writer_failure, mutation=mutation)
        assert before[3] == after[3]
        assert before[5]() is None and after[5]() is None, "worker retained its exception after the writer"
        if writer_failure:
            assert before[3]["escape"] == after[3]["escape"] == "OSError"
            assert after[2] is None
        else:
            assert after[3]["code"] == 1 and after[2]["status"] == "FAIL"
    finally:
        if enabled:
            gc.enable()


@pytest.mark.parametrize("writer_failure", [False, True])
def test_worker_diagnostic_exception_references_clear_after_writer(tmp_path, monkeypatch, writer_failure):
    _p6_lifetime_contract(tmp_path, monkeypatch, writer_failure)


@pytest.mark.parametrize("guard", ["event", "operation_revert", "fallback", "exact_type", "integer_type",
                                  "filename", "event_overflow", "error_overflow", "deduplicate", "clear",
                                  "capture_containment"])
def test_worker_diagnostic_readonly_guard_copies(tmp_path, monkeypatch, guard):
    import hashlib

    changes = {
        "event": [("self.data['events'].append({'operation': operation, 'event': event})", "pass")],
        "operation_revert": [("self._steps[operation] = _P6Step(self, operation, phase)",
                               "self._steps[operation] = _P6Step(self, 'preflight_revert' if operation == 'operation_revert' else operation, phase)")],
        "fallback": [("operation='UNATTRIBUTED_WORKER_STATEMENT', phase='outer'", "operation='sentinel_read_verify', phase='outer'")],
        "exact_type": [("if type(error) is kind:", "if isinstance(error, kind):")],
        "integer_type": [("if type(value) is int and lower <= value <= upper:", "if isinstance(value, int) and lower <= value <= upper:")],
        "filename": [("return role\n", "return filename\n")],
        "event_overflow": [("self.data['omitted_events'] += 1\n                self.unknown()", "self.data['omitted_events'] += 1")],
        "error_overflow": [("self.data['omitted_errors'] += 1\n                self.unknown()", "self.data['omitted_errors'] += 1")],
        "deduplicate": [("if self._pending is not None and self._pending[0] is error:", "if False:"),
                        ("if known is error:", "if False:")],
        "clear": [("self._refs[index] = None", "pass"), ("self._pending = None\n\n\ndef worker", "pass\n\n\ndef worker")],
        "capture_containment": [("except Exception:\n            self.unknown()\n\n    def _role", "except Exception:\n            raise\n\n    def _role")],
    }
    # Two exact-type loops intentionally share one identity guard; mutate both only in the owned copy.
    if guard == "exact_type":
        old, new = changes[guard][0]
        source = SCRIPT.read_text()
        assert source.count(old) == 2
        first = source.index(old)
        end = source.index(old, first + len(old)) + len(old)
        changes[guard] = [(source[first:end], source[first:end].replace(old, new))]

    def contract(root, mutation=None):
        root.mkdir()
        if guard == "clear":
            return _p6_lifetime_contract(root, monkeypatch, mutation=mutation)
        options = {"fault": "fixture_mkdir"}
        if guard == "operation_revert" or guard == "error_overflow":
            options["second_revert"] = True
        if guard == "fallback":
            options = {"unattributed": True}
        if guard == "exact_type":
            options["hostile"] = True
        if guard == "integer_type":
            options["attributes"] = {"errno": True}
        if guard == "event_overflow":
            options["capacity"] = "events"
        if guard == "error_overflow":
            options["capacity"] = "errors"
        if guard == "capture_containment":
            options["capture_fault"] = True
        after, diagnostic = _p6_pair(root, monkeypatch, mutation=mutation, **options)
        if guard == "event":
            assert {"operation": "fixture_mkdir", "event": "attempted"} in diagnostic["events"]
        elif guard == "operation_revert":
            assert diagnostic["errors"][1]["operation"] == "operation_revert"
        elif guard == "fallback":
            assert diagnostic["errors"][0]["operation"] == "UNATTRIBUTED_WORKER_STATEMENT"
        elif guard == "integer_type":
            assert diagnostic["errors"][0]["errno"] is None
        elif guard in ("event_overflow", "error_overflow"):
            assert diagnostic["capture_status"] == "UNKNOWN"
        elif guard == "deduplicate":
            assert len(diagnostic["errors"]) == 1
        elif guard == "filename":
            assert diagnostic["errors"][0]["filename_role"] == "FIXTURE_DIR"
        elif guard == "exact_type":
            assert diagnostic["errors"][0]["exception_type"] == "UNKNOWN"
        assert after[2]["status"] == "FAIL" and after[2]["windows_acceptance"] is False

    contract(tmp_path / "pristine")
    with pytest.raises(AssertionError):
        contract(tmp_path / "mutant", changes[guard])
    copies = [tmp_path / "mutant/candidate/probe.py"]
    assert all(path.is_file() and path.stat().st_mode & 0o777 == 0o400 for path in copies)
    (tmp_path / ".keep").touch()
    (tmp_path / "guard-result.json").write_text(json.dumps({
        "guard": guard, "classification": _P6_MODELLED, "result": "PUBLIC_ORACLE_REJECTED_MUTANT",
        "copies": [{"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), "mode": p.stat().st_mode & 0o777} for p in copies]
    }, indent=2) + "\n")


def test_worker_diagnostic_preflight_revert_failure_keeps_fatal_contract(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, first_revert=True)
    assert after[3]["code"] == 3 and after[1].active
    assert after[1].impersonations == after[1].reverts == 1
    assert 101 not in after[1].closed and 102 not in after[1].closed
    assert diagnostic["errors"][0]["operation"] == "preflight_revert"
    assert diagnostic["reported_error"] == diagnostic["errors"][0]["ordinal"]


def test_worker_diagnostic_final_close_error_selects_recovery_record(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", close_failure=True)
    assert after[3]["code"] == 1 and not after[1].active
    body, recovery = diagnostic["errors"]
    assert body["operation"] == "fixture_mkdir"
    assert recovery["operation"] == "final_token_close" and recovery["phase"] == "recovery"
    assert recovery["prior_error"] == body["ordinal"]
    assert diagnostic["reported_error"] == recovery["ordinal"]
    assert "Windows error 6" in after[2]["error"]
    assert {"operation": "final_revert", "event": "completed"} in diagnostic["events"]
    assert {"operation": "final_token_close", "event": "completed"} not in diagnostic["events"]


def test_worker_diagnostic_capture_fault_cannot_skip_final_revert_or_close(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", capture_fault=True)
    assert after[3]["code"] == 1 and not after[1].active
    assert 101 in after[1].closed and 102 in after[1].closed
    assert diagnostic["capture_status"] == "UNKNOWN" and diagnostic["events"] == []
    assert diagnostic["errors"][0]["operation"] == "fixture_mkdir"


def _p6_r5_faults(fault):
    """Inject diagnostic-only failures in sealed owned copies, never native behavior."""
    if fault in ("append_once", "append_always"):
        needle = "        self._refs = [None] * self.ERROR_LIMIT\n"
        injected = ("        class UnavailableErrors(list):\n"
                    "            failed = False\n"
                    "            def append(self, row):\n"
                    "                if not self.failed or " + str(fault == "append_always") + ":\n"
                    "                    self.failed = True\n"
                    "                    raise MemoryError('modelled diagnostic append failure')\n"
                    "                return super().append(row)\n"
                    "        self.data['errors'] = UnavailableErrors()\n")
        return [(needle, injected + needle)]
    if fault in ("publication", "cancellation"):
        kind = "MemoryError" if fault == "publication" else "KeyboardInterrupt"
        injected = ("\n\ndef unavailable_publication(self, *flags):\n"
                    "    raise " + kind + "('modelled final publication failure')\n"
                    "_P6Diagnostic.final_events = unavailable_publication\n")
    elif fault == "reported":
        injected = ("\n\noriginal_reported = _P6Diagnostic.reported\n"
                    "def unavailable_reported(self, error):\n"
                    "    if getattr(self, 'reported_once', False):\n"
                    "        raise MemoryError('modelled final selection publication failure')\n"
                    "    self.reported_once = True\n"
                    "    return original_reported(self, error)\n"
                    "_P6Diagnostic.reported = unavailable_reported\n")
    else:
        assert fault == "clear_allocation"
        # The module has only one range() call: diagnostic clear(), after token work and writing.
        injected = ("\n\ndef range(*args):\n"
                    "    raise MemoryError('modelled clear iterator allocation failure')\n")
    needle = "\n\ndef worker(config):\n"
    return [(needle, injected + needle)]


def _p6_r5_ordinals(diagnostic):
    stored = {row["ordinal"] for row in diagnostic["errors"]}
    selected = diagnostic["reported_error"]
    assert selected is None or selected in stored, "selected ordinal has no committed error row"
    for row in diagnostic["errors"]:
        assert row["prior_error"] is None or row["prior_error"] in stored, "recovery links an uncommitted error row"
    assert diagnostic["reported_error_state"] != "RECORDED" or selected in stored


@pytest.mark.parametrize("fault", ["append_once", "append_always"])
@pytest.mark.parametrize("recovery_failure", [False, True])
def test_worker_r5_append_failure_never_publishes_phantom_ordinals(tmp_path, monkeypatch, fault, recovery_failure):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", second_revert=recovery_failure,
                                 mutation=_p6_r5_faults(fault))
    _p6_r5_ordinals(diagnostic)
    assert after[1].impersonations == 2 and after[3]["code"] == (3 if recovery_failure else 1)
    assert diagnostic["capture_status"] == "UNKNOWN" and diagnostic["omitted_errors"] == 0
    if not recovery_failure or fault == "append_always":
        assert diagnostic["reported_error"] is None and diagnostic["reported_error_state"] == "UNAVAILABLE"
    else:
        assert diagnostic["errors"][0]["operation"] == "operation_revert"
        assert diagnostic["errors"][0]["prior_error"] is None


@pytest.mark.parametrize("close_failure", [False, True])
def test_worker_r5_final_publication_failure_preserves_public_failure(tmp_path, monkeypatch, close_failure):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", close_failure=close_failure,
                                 mutation=_p6_r5_faults("publication"))
    assert after[1].impersonations == after[1].reverts == 2 and not after[1].active
    assert after[3]["code"] == 1 and diagnostic["capture_status"] == "UNKNOWN"
    assert after[2]["error_type"] == ("RuntimeError" if close_failure else "PermissionError")
    _p6_r5_ordinals(diagnostic)


@pytest.mark.parametrize("writer_failure,fatal", [(False, False), (True, False), (False, True)])
def test_worker_r5_clear_allocation_failure_preserves_writer_and_fatal_sequence(tmp_path, monkeypatch, writer_failure, fatal):
    options = dict(fault="fixture_mkdir", writer_failure=writer_failure, first_revert=fatal,
                   mutation=_p6_r5_faults("clear_allocation"))
    before = _p6_diagnostic_case(tmp_path / "before", monkeypatch, baseline=True, **options)
    after = _p6_diagnostic_case(tmp_path / "candidate", monkeypatch, **options)
    assert before[3] == after[3], "clear allocation replaced writer failure or bypassed fatal exit"
    assert after[1].impersonations >= 1
    if writer_failure:
        assert after[3]["escape"] == "OSError" and after[2] is None
    else:
        assert after[3]["code"] == (3 if fatal else 1)
        assert after[2]["status"] == "FAIL" and after[2]["windows_acceptance"] is False


def test_worker_r5_final_publication_cancellation_propagates(tmp_path, monkeypatch):
    before = _p6_diagnostic_case(tmp_path / "before", monkeypatch, baseline=True, fault="fixture_mkdir")
    after = _p6_diagnostic_case(tmp_path / "candidate", monkeypatch, fault="fixture_mkdir",
                                mutation=_p6_r5_faults("cancellation"))
    assert before[3]["native_calls"] == after[3]["native_calls"]
    assert not after[1].active and 101 in after[1].closed and 102 in after[1].closed
    assert after[3]["escape"] == "KeyboardInterrupt" and after[2] is None


def test_worker_r5_failed_final_selection_never_reports_previous_body_error(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", close_failure=True,
                                 mutation=_p6_r5_faults("reported"))
    assert after[2]["error_type"] == "RuntimeError" and "Windows error 6" in after[2]["error"]
    assert diagnostic["capture_status"] == "UNKNOWN"
    assert diagnostic["reported_error"] is None and diagnostic["reported_error_state"] == "UNAVAILABLE"


@pytest.mark.parametrize("guard", ["committed_rows", "capture_not_omission", "publication_after_close_error",
                                  "publication_after_close_success", "allocation_free_clear",
                                  "cancel_propagation", "selection_reset", "selection_before_events"])
def test_worker_r5_sealed_guard_copies(tmp_path, monkeypatch, guard):
    import hashlib

    mutation = {
        # Revert the complete record-publication transaction, including its failed-capture ticket.
        "committed_rows": [("self.data['errors'].append(row)\n            self._refs[ordinal - 1] = error",
                            "self._refs[ordinal - 1] = error\n            self.data['errors'].append(row)"),
                           ("self._pending = (error, None, 'UNAVAILABLE')", "pass")],
        "capture_not_omission": [("self._pending = (error, None, 'UNAVAILABLE')",
                                  "self._pending = (error, None, 'OMITTED')")],
        "publication_after_close_error": [("except Exception:\n                        diagnostic.unknown()\n                    result.update",
                                            "except Exception:\n                        raise\n                    result.update")],
        "publication_after_close_success": [("except Exception:\n                        diagnostic.unknown()\n            if diagnostic.data",
                                              "except Exception:\n                        raise\n            if diagnostic.data")],
        "allocation_free_clear": [("index = 0\n        self._refs[index] = None",
                                    "for index in range(len(self._refs)):\n            self._refs[index] = None")],
        "cancel_propagation": [("except Exception:\n                        diagnostic.unknown()\n            if diagnostic.data",
                                 "except BaseException:\n                        diagnostic.unknown()\n            if diagnostic.data")],
        "selection_reset": [("self.data['reported_error'] = None\n        self.data['reported_error_state'] = 'UNAVAILABLE'",
                              "self.data['reported_error_state'] = 'UNAVAILABLE'")],
        "selection_before_events": [("diagnostic.selecting(exc)\n                        diagnostic.final_events(revert_attempted, revert_completed, close_attempted, close_completed)",
                                      "diagnostic.final_events(revert_attempted, revert_completed, close_attempted, close_completed)\n                        diagnostic.selecting(exc)")],
    }[guard]

    def contract(root, changes=()):
        root.mkdir()
        if guard == "cancel_propagation":
            after = _p6_diagnostic_case(root / "candidate", monkeypatch, fault="fixture_mkdir",
                                        mutation=_p6_r5_faults("cancellation") + list(changes))
            assert not after[1].active and 101 in after[1].closed and 102 in after[1].closed
            assert after[3]["escape"] == "KeyboardInterrupt", "publication suppressed cancellation"
            return
        fault = ("append_always" if guard in ("committed_rows", "capture_not_omission") else
                 "clear_allocation" if guard == "allocation_free_clear" else
                 "reported" if guard in ("selection_reset", "selection_before_events") else "publication")
        close_failure = guard in ("publication_after_close_error", "selection_reset", "selection_before_events")
        faults = _p6_r5_faults(fault)
        if guard == "selection_before_events":
            faults += _p6_r5_faults("publication")
        after, diagnostic = _p6_pair(root, monkeypatch, fault="fixture_mkdir", close_failure=close_failure,
                                     mutation=faults + list(changes))
        assert after[1].impersonations == after[1].reverts == 2 and not after[1].active
        _p6_r5_ordinals(diagnostic)
        if guard in ("committed_rows", "capture_not_omission", "selection_reset", "selection_before_events"):
            assert diagnostic["reported_error"] is None and diagnostic["reported_error_state"] == "UNAVAILABLE"
        if fault != "clear_allocation":
            assert diagnostic["capture_status"] == "UNKNOWN"

    contract(tmp_path / "pristine")
    with pytest.raises(AssertionError) as rejected:
        contract(tmp_path / "mutant", mutation)
    path = tmp_path / "mutant/candidate/probe.py"
    assert path.is_file() and path.stat().st_mode & 0o777 == 0o400
    (tmp_path / ".keep").touch()
    (tmp_path / "guard-result.json").write_text(json.dumps({
        "classification": _P6_MODELLED, "guard": guard, "result": "PUBLIC_ORACLE_REJECTED_MUTANT",
        "oracle": str(rejected.value).splitlines()[0], "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "mode": path.stat().st_mode & 0o777,
    }, indent=2) + "\n")


def test_worker_r5_failed_final_events_and_selection_leave_no_stale_ordinal(tmp_path, monkeypatch):
    after, diagnostic = _p6_pair(tmp_path, monkeypatch, fault="fixture_mkdir", close_failure=True,
                                 mutation=_p6_r5_faults("publication") + _p6_r5_faults("reported"))
    assert after[2]["error_type"] == "RuntimeError" and "Windows error 6" in after[2]["error"]
    assert diagnostic["capture_status"] == "UNKNOWN"
    assert diagnostic["reported_error"] is None and diagnostic["reported_error_state"] == "UNAVAILABLE"
