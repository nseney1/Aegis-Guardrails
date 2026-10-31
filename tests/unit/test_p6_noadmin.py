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
                 boolean_length=1, boolean_value=1, boolean_padding=0xA5, boolean_phase=1):
        self.problem, self.scalar_length, self.scalar_phase = problem, scalar_length, scalar_phase
        self.scalar_kind = scalar_kind
        self.boolean_length, self.boolean_value = boolean_length, boolean_value
        self.boolean_padding, self.boolean_phase = boolean_padding, boolean_phase
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
            return struct.pack("<IIII", 1, 99 if self.problem == "privilege_enabled" else 23, 0, 2)
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
            C.memmove(args[2], struct.pack("<II", 23, 0), 8)
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

    def run(**options):
        boundary = WindowsBoundary(**options)
        monkeypatch.setattr(C, "WinDLL", boundary.dll, raising=False)
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
        assert report["status"] == "FAIL" and report["windows_acceptance"] is False
        return boundary, code, report, fatal_calls

    return run


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
