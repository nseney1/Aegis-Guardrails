#!/usr/bin/env python3
"""External M0 P6: restricted-token junction creation; no Vitest or acquisition."""
from __future__ import annotations

import argparse
import contextlib
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import traceback


HELPER_SHA = 'db2995e528007c2bb17fabada5e708c3107e83607efd4a6acad4ad35d0f9cf7b'
DWORD, BOOL, HANDLE = C.c_uint32, C.c_int32, C.c_void_p


class LUID(C.Structure):
    _fields_ = [('LowPart', DWORD), ('HighPart', C.c_int32)]


class LUID_AND_ATTRIBUTES(C.Structure):
    _fields_ = [('Luid', LUID), ('Attributes', DWORD)]


class SID_AND_ATTRIBUTES(C.Structure):
    _fields_ = [('Sid', HANDLE), ('Attributes', DWORD)]


class TOKEN_GROUPS(C.Structure):
    _fields_ = [('GroupCount', DWORD), ('Groups', SID_AND_ATTRIBUTES * 1)]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RevertFailed(RuntimeError):
    pass


class Token:
    """Restrict a copied token; never adjust the original or enable a privilege."""
    def __init__(self, record):
        self.record, self.original, self.restricted = record, HANDLE(), HANDLE()
        self.active = self.fatal = False
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.adv = C.WinDLL('advapi32', use_last_error=True)
        declarations = {
            'GetCurrentProcess': (self.kernel, HANDLE, []),
            'GetCurrentThread': (self.kernel, HANDLE, []),
            'GetLastError': (self.kernel, DWORD, []),
            'CloseHandle': (self.kernel, BOOL, [HANDLE]),
            'OpenProcessToken': (self.adv, BOOL, [HANDLE, DWORD, C.POINTER(HANDLE)]),
            'OpenThreadToken': (self.adv, BOOL, [HANDLE, DWORD, BOOL, C.POINTER(HANDLE)]),
            'GetTokenInformation': (self.adv, BOOL, [HANDLE, DWORD, HANDLE, DWORD, C.POINTER(DWORD)]),
            'CreateWellKnownSid': (self.adv, BOOL, [DWORD, HANDLE, HANDLE, C.POINTER(DWORD)]),
            'GetLengthSid': (self.adv, DWORD, [HANDLE]),
            'IsValidSid': (self.adv, BOOL, [HANDLE]),
            'CreateRestrictedToken': (self.adv, BOOL, [HANDLE, DWORD, DWORD, HANDLE, DWORD, HANDLE,
                                                     DWORD, HANDLE, C.POINTER(HANDLE)]),
            'SetTokenInformation': (self.adv, BOOL, [HANDLE, DWORD, HANDLE, DWORD]),
            'ImpersonateLoggedOnUser': (self.adv, BOOL, [HANDLE]),
            'RevertToSelf': (self.adv, BOOL, []),
            'CheckTokenMembership': (self.adv, BOOL, [HANDLE, HANDLE, C.POINTER(BOOL)]),
            'LookupPrivilegeValueW': (self.adv, BOOL, [C.c_wchar_p, C.c_wchar_p, C.POINTER(LUID)]),
        }
        for name, (dll, result, arguments) in declarations.items():
            function = getattr(dll, name)
            function.restype, function.argtypes = result, arguments

    def checked(self, name, *args):
        function = getattr(self.kernel if name == 'CloseHandle' else self.adv, name)
        require(function(*args), name + ' failed: Windows error ' + str(self.kernel.GetLastError()))

    def query(self, token, kind):
        size = DWORD()
        first = self.adv.GetTokenInformation(token, kind, None, 0, C.byref(size))
        require(not first and self.kernel.GetLastError() == 122 and 0 < size.value <= 65536,
                'GetTokenInformation size failed: Windows error ' + str(self.kernel.GetLastError()))
        buffer = C.create_string_buffer(size.value)
        self.checked('GetTokenInformation', token, kind, buffer, len(buffer), C.byref(size))
        require(0 < size.value <= len(buffer), 'GetTokenInformation invalid result length')
        return buffer, size.value

    def scalar(self, token, kind):
        value, size = DWORD(), DWORD()
        self.checked('GetTokenInformation', token, kind, C.byref(value), C.sizeof(value), C.byref(size))
        require(size.value == C.sizeof(value), 'GetTokenInformation invalid DWORD width')
        return value.value

    def has_restrictions(self, token):
        # Class 21 returns a BOOLEAN at a DWORD-aligned address, not a DWORD:
        # https://github.com/microsoft/win32metadata/discussions/2308
        value, size = DWORD(), DWORD()
        self.checked('GetTokenInformation', token, 21, C.byref(value), C.sizeof(value), C.byref(size))
        require(size.value == C.sizeof(C.c_ubyte),
                'GetTokenInformation class 21 invalid BOOLEAN width: ' + str(size.value))
        return C.c_ubyte.from_buffer(value).value

    def sid_bytes(self, pointer):
        require(pointer and self.adv.IsValidSid(pointer), 'invalid token SID')
        size = self.adv.GetLengthSid(pointer)
        require(8 <= size <= 68, 'invalid token SID length')
        return C.string_at(pointer, size)

    def one_sid(self, token, kind):
        value, size = self.query(token, kind)
        require(size >= C.sizeof(SID_AND_ATTRIBUTES), 'truncated token SID attributes')
        row = SID_AND_ATTRIBUTES.from_buffer(value)
        return self.sid_bytes(row.Sid), row.Attributes

    def groups(self, token, kind):
        value, size = self.query(token, kind)
        require(size >= 4, 'truncated token groups')
        count = DWORD.from_buffer(value).value
        offset = TOKEN_GROUPS.Groups.offset
        require(offset + count * C.sizeof(SID_AND_ATTRIBUTES) <= size, 'truncated token groups array')
        rows = (SID_AND_ATTRIBUTES * count).from_buffer(value, offset)
        return [{'sid': self.sid_bytes(row.Sid).hex(), 'attributes': row.Attributes} for row in rows]

    def privileges(self, token):
        value, size = self.query(token, 3)
        require(size >= 4, 'truncated token privileges')
        count = DWORD.from_buffer(value).value
        require(4 + count * C.sizeof(LUID_AND_ATTRIBUTES) <= size, 'truncated token privileges array')
        rows = (LUID_AND_ATTRIBUTES * count).from_buffer(value, 4)
        return [{'low': p.Luid.LowPart, 'high': p.Luid.HighPart, 'attributes': p.Attributes} for p in rows]

    def no_thread_token(self):
        handle = HANDLE()
        opened = self.adv.OpenThreadToken(self.kernel.GetCurrentThread(), 8, True, C.byref(handle))
        error = self.kernel.GetLastError()
        if opened:
            self.checked('CloseHandle', handle)
        require(not opened and error == 1008, 'unexpected effective thread token')

    def prepare(self):
        self.no_thread_token()
        self.checked('OpenProcessToken', self.kernel.GetCurrentProcess(), 0x8A, C.byref(self.original))
        user, _ = self.one_sid(self.original, 1)
        require(user not in [bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack('<I', rid)
                             for rid in (18, 19, 20)], 'service identity is not standard-user evidence')
        self.user = C.create_string_buffer(user)
        self.admin, self.medium = C.create_string_buffer(68), C.create_string_buffer(68)
        for kind, target in ((26, self.admin), (67, self.medium)):
            size = DWORD(len(target))
            self.checked('CreateWellKnownSid', kind, None, target, C.byref(size))
        self.record['original'] = {'user_sid': user.hex(), 'elevated': self.scalar(self.original, 20),
            'integrity_sid': self.one_sid(self.original, 25)[0].hex(),
            'groups': self.groups(self.original, 2), 'privileges': self.privileges(self.original)}
        deny = SID_AND_ATTRIBUTES(C.cast(self.admin, HANDLE), 0)
        restrict = SID_AND_ATTRIBUTES(C.cast(self.user, HANDLE), 0)
        self.checked('CreateRestrictedToken', self.original, 5, 1, C.byref(deny), 0, None,
                     1, C.byref(restrict), C.byref(self.restricted))
        integrity = self.one_sid(self.original, 25)[0]
        require(struct.unpack('<I', integrity[-4:])[0] >= 8192, 'will not raise a low-integrity token')
        label = SID_AND_ATTRIBUTES(C.cast(self.medium, HANDLE), 0x20)
        self.checked('SetTokenInformation', self.restricted, 25, C.byref(label),
                     C.sizeof(label) + self.adv.GetLengthSid(self.medium))
        allowed = LUID()
        self.checked('LookupPrivilegeValueW', None, 'SeChangeNotifyPrivilege', C.byref(allowed))
        self.change_notify_luid = (allowed.LowPart, allowed.HighPart)

    def enter(self):
        self.checked('ImpersonateLoggedOnUser', self.restricted)
        self.active = True

    def proof(self, label):
        token = HANDLE()
        self.checked('OpenThreadToken', self.kernel.GetCurrentThread(), 8, True, C.byref(token))
        try:
            user, _ = self.one_sid(token, 1)
            integrity, _ = self.one_sid(token, 25)
            groups, restricted = self.groups(token, 2), self.groups(token, 11)
            row = {'user_sid': user.hex(), 'integrity_sid': integrity.hex(), 'groups': groups,
                   'restricting_sids': restricted, 'elevated': self.scalar(token, 20),
                   'ui_access': self.scalar(token, 26), 'type': self.scalar(token, 8),
                   'impersonation_level': self.scalar(token, 9), 'filtered': self.has_restrictions(token)}
            self.record[label] = row
            require(user == self.sid_bytes(self.user), 'effective token user differs')
            require(row['type'] == 2 and row['impersonation_level'] >= 2, 'effective token cannot impersonate')
            require(row['filtered'] != 0, 'effective token is not filtered')
            require(row['elevated'] == 0, 'elevated effective token')
            require(row['ui_access'] == 0, 'effective token has UIAccess')
            require(integrity == self.sid_bytes(self.medium), 'effective token requires medium integrity')
            admin = self.sid_bytes(self.admin).hex()
            require(all(g['attributes'] & 0x10 and not g['attributes'] & 4 for g in groups if g['sid'] == admin),
                    'Administrators SID is not deny-only')
            require(len(restricted) == 1 and restricted[0]['sid'] == user.hex(), 'user restricting SID differs')
            member = BOOL()
            self.checked('CheckTokenMembership', None, self.admin, C.byref(member))
            require(not member.value, 'effective Administrators membership is enabled')
            row['privileges'] = self.privileges(token)
            require(all(not p['attributes'] & 2 or (p['low'], p['high']) == self.change_notify_luid
                        for p in row['privileges']), 'unexpected enabled privilege')
        finally:
            self.checked('CloseHandle', token)

    def revert(self):
        if self.active:
            if not self.adv.RevertToSelf():
                self.fatal = True
                raise RevertFailed('RevertToSelf failed: Windows error ' + str(self.kernel.GetLastError()))
            self.active = False
            try:
                self.no_thread_token()
            except BaseException as exc:
                self.fatal = True
                raise RevertFailed('restoration verification failed: ' + str(exc)) from exc

    def close(self):
        if not self.fatal:
            for handle in (self.restricted, self.original):
                if handle.value:
                    self.checked('CloseHandle', handle)
                    handle.value = None


def windows_facts(root, result):
    version = sys.getwindowsversion()
    result['windows'] = {'major': version.major, 'minor': version.minor, 'build': version.build,
                         'platform_version': list(version.platform_version)}
    kernel = C.WinDLL('kernel32', use_last_error=True)
    declarations = {
        'GetLastError': (DWORD, []),
        'GetVolumePathNameW': (BOOL, [C.c_wchar_p, C.c_wchar_p, DWORD]),
        'GetDriveTypeW': (DWORD, [C.c_wchar_p]),
        'GetVolumeInformationW': (BOOL, [C.c_wchar_p, C.c_wchar_p, DWORD, C.POINTER(DWORD),
                                        C.POINTER(DWORD), C.POINTER(DWORD), C.c_wchar_p, DWORD]),
    }
    for name, (restype, argtypes) in declarations.items():
        function = getattr(kernel, name)
        function.restype, function.argtypes = restype, argtypes
    volume, filesystem, serial = C.create_unicode_buffer(32768), C.create_unicode_buffer(261), DWORD()
    require(kernel.GetVolumePathNameW(str(root.resolve(strict=True)), volume, len(volume)),
            'GetVolumePathNameW failed: Windows error ' + str(kernel.GetLastError()))
    drive_type = kernel.GetDriveTypeW(volume.value)
    require(kernel.GetVolumeInformationW(volume.value, None, 0, C.byref(serial), None, None,
                                         filesystem, len(filesystem)),
            'GetVolumeInformationW failed: Windows error ' + str(kernel.GetLastError()))
    result['volume'] = {'root': volume.value, 'filesystem': filesystem.value,
                        'drive_type': drive_type, 'serial': serial.value}
    require(drive_type == 3, 'P6 requires a local fixed volume')
    require(filesystem.value.upper() == 'NTFS', 'P6 requires NTFS for the scoped fixture')


def validate_receipt(receipt, source, facts, audit, tree):
    require(receipt.get('schema') == 'aegis-language-source/v1' and receipt.get('status') == 'PASS'
            and receipt.get('validation') == 'tracked bytes equal Git blobs', 'invalid source receipt')
    require(receipt.get('source') == str(source) and receipt.get('audit') == audit
            and receipt.get('tree') == tree, 'source receipt identity differs')
    expected = receipt.get('files')
    require(isinstance(expected, dict) and set(expected) == set(facts['files']), 'receipt tracked file set differs')
    require(receipt.get('index_sha256') == facts['index'].get('sha256'), 'source receipt index differs')
    for name, actual in facts['files'].items():
        row = expected[name]
        mode = row.get('git_mode')
        require(mode in ('100644', '100755', '120000'), 'unsupported receipt mode: ' + name)
        kind = 'symlink' if mode == '120000' else 'file'
        require(actual.get('kind') == kind, 'source receipt file kind differs: ' + name)
        if kind == 'symlink':
            data = os.fsencode(actual['target'])
            digest, size = hashlib.sha256(data).hexdigest(), len(data)
        else:
            digest, size = actual['sha256'], actual['size']
        require(digest == row.get('sha256') and size == row.get('bytes'), 'source receipt raw bytes differ: ' + name)



class _P6Step:
    def __init__(self, diagnostic, operation, phase):
        self.diagnostic, self.operation, self.phase = diagnostic, operation, phase

    def __enter__(self):
        self.diagnostic.event(self.operation, 'attempted')

    def __exit__(self, kind, error, tb):
        if error is None:
            self.diagnostic.event(self.operation, 'completed')
        else:
            self.diagnostic.error(error, self.operation, self.phase)
        return False


class _P6Diagnostic:
    """Bounded cached facts only. No OS queries, exception formatting or authority."""
    EVENT_LIMIT = 64
    ERROR_LIMIT = 4
    OPERATIONS = (
        'result_open', 'platform_check', 'windows_facts', 'product_load', 'token_construct',
        'token_prepare', 'preflight_enter', 'preflight_proof', 'preflight_revert',
        'operation_enter', 'operation_proof', 'fixture_mkdir', 'target_mkdir', 'sentinel_write',
        'sentinel_read_verify', 'junction_create', 'junction_lstat', 'junction_readlink',
        'junction_tag_verify', 'junction_target_verify', 'junction_traversal_verify',
        'junction_lstat_recheck', 'junction_identity_verify', 'junction_remove',
        'target_preservation_verify', 'operation_revert', 'normal_token_close',
        'final_revert', 'final_token_close')

    def __init__(self, config):
        self.data = {'schema': 'P6_CACHED_PROGRESS_V1',
            'coverage': 'SELECTED_WORKER_STEPS_AND_ERROR_OBSERVATIONS',
            'capture_status': 'COMPLETE', 'events': [], 'errors': [],
            'reported_error': None, 'reported_error_state': 'NONE',
            'omitted_events': 0, 'omitted_errors': 0}
        self._refs = [None] * self.ERROR_LIMIT
        self._pending = None
        self._capture_failed = False
        self._roles = []
        root, source = config.get('evidence'), config.get('source')
        if type(root) is str and type(source) is str:
            fixture = os.path.join(root, 'fixture')
            target = os.path.join(fixture, 'target')
            self._roles = [(root, 'EVIDENCE_ROOT'), (fixture, 'FIXTURE_DIR'), (target, 'TARGET_DIR'),
                (os.path.join(target, 'sentinel.txt'), 'SENTINEL_FILE'),
                (os.path.join(fixture, 'junction'), 'JUNCTION_ENTRY'),
                (os.path.join(fixture, 'junction', 'sentinel.txt'), 'JUNCTION_SENTINEL'),
                (os.path.join(source, 'aegis_core', 'verification', 'windows_junction.py'), 'PRODUCT_MODULE')]
        self._steps = {}
        for operation in self.OPERATIONS:
            phase = ('recovery' if 'revert' in operation or 'close' in operation else
                     'preflight' if operation.startswith('preflight_') else
                     'outer' if operation in self.OPERATIONS[:6] else 'operation')
            self._steps[operation] = _P6Step(self, operation, phase)

    def unknown(self):
        self.data['capture_status'] = 'UNKNOWN'

    def step(self, operation):
        return self._steps[operation]

    def event(self, operation, event):
        try:
            if len(self.data['events']) < self.EVENT_LIMIT:
                self.data['events'].append({'operation': operation, 'event': event})
            else:
                self.data['omitted_events'] += 1
                self.unknown()
        except Exception:
            self.unknown()

    def _role(self, filename):
        if filename is None:
            return 'NONE'
        if type(filename) is str:
            for value, role in self._roles:
                if filename == value:
                    return role
        self.unknown()
        return 'UNKNOWN'

    def _number(self, value, lower, upper):
        if value is None:
            return None, 'ABSENT'
        if type(value) is int and lower <= value <= upper:
            return value, 'PRESENT'
        self.unknown()
        return None, 'UNSUPPORTED'

    def error(self, error, operation=None, phase=None):
        try:
            if self._capture_failed:
                return None
            if operation is None and phase is None:
                return self._capture_error(error)
            return self._capture_error(error, operation, 'outer' if phase is None else phase)
        except Exception:
            # This last-resort path only writes existing slots: no ticket allocation or helper call.
            self._capture_failed = True
            self.data['capture_status'] = 'UNKNOWN'
            self._pending = None
            return None

    def _capture_error(self, error, operation='UNATTRIBUTED_WORKER_STATEMENT', phase='outer'):
        try:
            if self._pending is not None and self._pending[0] is error:
                return self._pending[1]
            for index, known in enumerate(self._refs):
                if known is error:
                    self._pending = (error, index + 1)
                    return index + 1
            previous = self._pending[1] if self._pending is not None else None
            if len(self.data['errors']) >= self.ERROR_LIMIT:
                self.data['omitted_errors'] += 1
                self.unknown()
                self._pending = (error, None, 'OMITTED')
                return None
            ordinal = len(self.data['errors']) + 1
            label, os_error = 'UNKNOWN', None
            for kind, name in (
                (OSError, 'OSError'), (PermissionError, 'PermissionError'),
                (FileExistsError, 'FileExistsError'), (FileNotFoundError, 'FileNotFoundError'),
                (NotADirectoryError, 'NotADirectoryError'), (IsADirectoryError, 'IsADirectoryError'),
                (BlockingIOError, 'BlockingIOError'), (InterruptedError, 'InterruptedError'),
                (TimeoutError, 'TimeoutError'), (ProcessLookupError, 'ProcessLookupError')):
                if type(error) is kind:
                    label, os_error = name, True
                    break
            if os_error is None:
                for kind, name in (
                    (RuntimeError, 'RuntimeError'), (ValueError, 'ValueError'), (TypeError, 'TypeError'),
                    (KeyError, 'KeyError'), (AssertionError, 'AssertionError'), (ImportError, 'ImportError'),
                    (ModuleNotFoundError, 'ModuleNotFoundError'), (KeyboardInterrupt, 'KeyboardInterrupt'),
                    (SystemExit, 'SystemExit'), (MemoryError, 'MemoryError'), (RevertFailed, 'RevertFailed')):
                    if type(error) is kind:
                        label, os_error = name, False
                        break
            row = {'ordinal': ordinal, 'operation': operation, 'phase': phase, 'exception_type': label,
                   'is_oserror': os_error, 'errno': None, 'errno_state': 'ABSENT',
                   'winerror': None, 'winerror_state': 'ABSENT',
                   'filename_role': 'NONE', 'filename2_role': 'NONE',
                   'prior_error': previous if phase == 'recovery' else None}
            if label == 'UNKNOWN':
                self.unknown()
                row.update(errno_state='UNSUPPORTED', winerror_state='UNSUPPORTED',
                           filename_role='UNKNOWN', filename2_role='UNKNOWN')
            elif os_error:
                row['errno'], row['errno_state'] = self._number(getattr(error, 'errno', None), -(2**31), 2**31 - 1)
                row['winerror'], row['winerror_state'] = self._number(getattr(error, 'winerror', None), 0, 2**32 - 1)
                row['filename_role'] = self._role(getattr(error, 'filename', None))
                row['filename2_role'] = self._role(getattr(error, 'filename2', None))
            if operation == 'UNATTRIBUTED_WORKER_STATEMENT':
                self.unknown()
            self.data['errors'].append(row)
            self._refs[ordinal - 1] = error
            self._pending = (error, ordinal)
            return ordinal
        except Exception:
            self.unknown()
            self._pending = (error, None, 'UNAVAILABLE')
            return None

    def selecting(self, error):
        self.data['reported_error'] = None
        self.data['reported_error_state'] = 'UNAVAILABLE'
        self.error(error)

    def reported(self, error):
        ordinal = self.error(error)
        self.data['reported_error'] = ordinal
        self.data['reported_error_state'] = ('RECORDED' if ordinal is not None else
            self._pending[2] if self._pending is not None and self._pending[0] is error else 'UNAVAILABLE')

    def final_events(self, revert_attempted, revert_completed, close_attempted, close_completed):
        for operation, attempted, completed in (
                ('final_revert', revert_attempted, revert_completed),
                ('final_token_close', close_attempted, close_completed)):
            if attempted:
                self.event(operation, 'attempted')
            if completed:
                self.event(operation, 'completed')

    def clear(self):
        # Fixed slots avoid allocating an iterator while preserving a writer failure.
        index = 0
        self._refs[index] = None
        if self.ERROR_LIMIT > 1:
            self._refs[1] = None
        if self.ERROR_LIMIT > 2:
            self._refs[2] = None
        if self.ERROR_LIMIT > 3:
            self._refs[3] = None
        self._pending = None


def worker(config):
    root, source = (Path(config['evidence']), Path(config['source']))
    result = {'status': 'FAIL', 'windows_acceptance': False, 'scope': 'M0 P6 junction rights only', 'token': {}, 'junction_called': False, 'platform': sys.platform}
    token = None
    diagnostic = _P6Diagnostic(config)
    result['diagnostic'] = diagnostic.data
    diagnostic.event('result_open', 'attempted')
    with (root / 'worker-result.json').open('w', encoding='utf-8') as output:
        diagnostic.event('result_open', 'completed')
        try:
            with diagnostic.step('platform_check'):
                require(sys.platform == 'win32', 'P6 requires Windows; no Windows acceptance on this host')
            with diagnostic.step('windows_facts'):
                windows_facts(root, result)
            with diagnostic.step('product_load'):
                junction = load(source / 'aegis_core/verification/windows_junction.py', 'p6_product_junction')
            with diagnostic.step('token_construct'):
                token = Token(result['token'])
            with diagnostic.step('token_prepare'):
                token.prepare()
            with diagnostic.step('preflight_enter'):
                token.enter()
            try:
                with diagnostic.step('preflight_proof'):
                    token.proof('preflight')
            except BaseException as exc:
                diagnostic.error(exc)
                raise
            finally:
                with diagnostic.step('preflight_revert'):
                    token.revert()
            with diagnostic.step('operation_enter'):
                token.enter()
            try:
                with diagnostic.step('operation_proof'):
                    token.proof('operation')
                fixture = root / 'fixture'
                with diagnostic.step('fixture_mkdir'):
                    fixture.mkdir()
                target = fixture / 'target'
                with diagnostic.step('target_mkdir'):
                    target.mkdir()
                sentinel = target / 'sentinel.txt'
                with diagnostic.step('sentinel_write'):
                    sentinel.write_text('P6 owned sentinel\n', encoding='utf-8')
                with diagnostic.step('sentinel_read_verify'):
                    require(sentinel.read_text(encoding='utf-8') == 'P6 owned sentinel\n', 'restricted ordinary-file control failed')
                link = fixture / 'junction'
                result['junction_called'] = True
                with diagnostic.step('junction_create'):
                    junction.create_directory_junction(target, link)
                with diagnostic.step('junction_lstat'):
                    owned = link.lstat()
                with diagnostic.step('junction_readlink'):
                    destination = os.readlink(link)
                result['junction'] = {'device': owned.st_dev, 'inode': owned.st_ino, 'tag': getattr(owned, 'st_reparse_tag', None), 'target': destination, 'attributes': getattr(owned, 'st_file_attributes', None)}
                with diagnostic.step('junction_tag_verify'):
                    require(result['junction']['tag'] == 2684354563 and result['junction']['attributes'] & 1024, 'created entry is not a mount-point junction')
                with diagnostic.step('junction_target_verify'):
                    require(Path(os.path.realpath(link)) == Path(os.path.realpath(target)), 'junction target differs')
                with diagnostic.step('junction_traversal_verify'):
                    require((link / 'sentinel.txt').read_text(encoding='utf-8') == 'P6 owned sentinel\n', 'junction traversal failed')
                with diagnostic.step('junction_lstat_recheck'):
                    current = link.lstat()
                with diagnostic.step('junction_identity_verify'):
                    require((current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino) and os.readlink(link) == destination and (current.st_reparse_tag == 2684354563), 'owned junction changed before cleanup')
                with diagnostic.step('junction_remove'):
                    link.rmdir()
                with diagnostic.step('target_preservation_verify'):
                    require(not os.path.lexists(link) and sentinel.read_text(encoding='utf-8') == 'P6 owned sentinel\n', 'junction cleanup changed its target')
                result['junction_removed_target_preserved'] = True
            except BaseException as exc:
                diagnostic.error(exc)
                raise
            finally:
                with diagnostic.step('operation_revert'):
                    token.revert()
            with diagnostic.step('normal_token_close'):
                token.close()
            result.update(status='PASS', windows_acceptance=True)
        except BaseException as exc:
            diagnostic.selecting(exc)
            result.update(status='FAIL', windows_acceptance=False, error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
            diagnostic.reported(exc)
        finally:
            cleanup_error = None
            cleanup_operation = None
            revert_attempted = revert_completed = close_attempted = close_completed = False
            if token is not None and (not token.fatal):
                try:
                    revert_attempted = True
                    try:
                        token.revert()
                    except BaseException as exc:
                        cleanup_error, cleanup_operation = (exc, 'final_revert')
                        raise
                    revert_completed = True
                    close_attempted = True
                    try:
                        token.close()
                    except BaseException as exc:
                        cleanup_error, cleanup_operation = (exc, 'final_token_close')
                        raise
                    close_completed = True
                except BaseException as exc:
                    try:
                        if cleanup_error is exc:
                            diagnostic.error(exc, cleanup_operation, 'recovery')
                        diagnostic.selecting(exc)
                        diagnostic.final_events(revert_attempted, revert_completed, close_attempted, close_completed)
                    except Exception:
                        diagnostic.unknown()
                    result.update(status='FAIL', windows_acceptance=False, error_type=type(exc).__name__, error=str(exc))
                    try:
                        diagnostic.reported(exc)
                    except Exception:
                        diagnostic.unknown()
                else:
                    try:
                        diagnostic.final_events(revert_attempted, revert_completed, close_attempted, close_completed)
                    except Exception:
                        diagnostic.unknown()
            if diagnostic.data['reported_error_state'] == 'UNAVAILABLE':
                diagnostic.unknown()
            try:
                output.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
                output.flush()
            finally:
                diagnostic.clear()
                cleanup_error = None
    if token is not None and token.fatal:
        os._exit(3)
    return 0 if result['status'] == 'PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path, help=argparse.SUPPRESS)
    for name in ('source', 'owner-helper', 'source-receipt', 'evidence'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--expected-audit')
    parser.add_argument('--expected-tree')
    parser.add_argument('--expected-receipt-sha256')
    args = parser.parse_args(argv)
    if args.worker:
        return worker(json.loads(args.worker.read_text(encoding='utf-8')))
    for name in ('source', 'owner_helper', 'source_receipt', 'evidence', 'expected_audit', 'expected_tree',
                 'expected_receipt_sha256'):
        if getattr(args, name) is None:
            parser.error('--' + name.replace('_', '-') + ' is required')
    root = args.evidence.absolute()
    root.mkdir(parents=True, exist_ok=False)
    result = {'status': 'FAIL', 'windows_acceptance': False, 'source_audit': args.expected_audit,
              'source_tree': args.expected_tree, 'expected_receipt_sha256': args.expected_receipt_sha256,
              'worker_bound_s': 45, 'platform': sys.platform}
    helper = before_source = before_tools = None
    inputs = {}
    old_term = signal.getsignal(signal.SIGTERM)
    def stopped(signum, _frame):
        raise KeyboardInterrupt('termination signal ' + str(signum))
    signal.signal(signal.SIGTERM, stopped)
    try:
        require(hashlib.sha256(args.owner_helper.read_bytes()).hexdigest() == HELPER_SHA, 'ownership helper differs')
        helper = load(args.owner_helper, 'p6_owner_helper')
        source = args.source.resolve(strict=True)
        env = helper.neutral_environment(root, Path(sys.executable), source)
        git_path = shutil.which('git', path=env['PATH'])
        require(git_path is not None, 'Git unavailable')
        before_source = helper.source_facts(source, git_path, env)
        save(root / 'source-before.json', before_source)
        require(before_source['head'] == args.expected_audit and before_source['tree'] == args.expected_tree
                and before_source['status'] == '', 'source identity or clean status differs')
        tool_paths = (Path(sys.executable), Path(sys.executable).resolve(strict=True),
                      Path(git_path), Path(git_path).resolve(strict=True), args.owner_helper,
                      args.owner_helper.resolve(strict=True), Path(__file__).resolve(strict=True))
        before_tools = {str(p): helper.fact(p) for p in tool_paths}
        save(root / 'tools-before.json', {'python_version': sys.version, 'invoked_python': sys.executable,
            'resolved_python': str(Path(sys.executable).resolve()), 'invoked_git': git_path,
            'resolved_git': str(Path(git_path).resolve()), 'files': before_tools})
        receipt_fact = helper.fact(args.source_receipt)
        inputs['source-receipt'] = (args.source_receipt, receipt_fact, 'source receipt changed')
        save(root / 'source-receipt-before.json', receipt_fact)
        require(receipt_fact.get('kind') == 'file', 'source receipt requires an actual regular file')
        receipt_bytes = args.source_receipt.read_bytes()
        require(receipt_fact.get('sha256') == args.expected_receipt_sha256
                and hashlib.sha256(receipt_bytes).hexdigest() == args.expected_receipt_sha256,
                'source receipt digest differs from producer output')
        receipt = json.loads(receipt_bytes.decode('utf-8'))
        save(root / 'source-receipt.json', receipt)
        validate_receipt(receipt, source, before_source, args.expected_audit, args.expected_tree)
        require(sys.platform == 'win32' and os.name == 'nt', 'P6 requires Windows; no Windows acceptance on this host')
        config = root / 'worker-config.json'
        save(config, {'source': str(source), 'evidence': str(root)})
        inputs['worker-config'] = (config, helper.fact(config), 'worker configuration changed')
        save(root / 'worker-config-before.json', inputs['worker-config'][1])
        command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), '--worker', str(config)]
        save(root / 'command.json', {'argv': command, 'cwd': str(root), 'timeout_s': 45})
        with (root / 'stdout.log').open('wb') as stdout, (root / 'stderr.log').open('wb') as stderr:
            owner = helper.OwnedTree(source, root)
            try:
                process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, **owner.flags)
                owner.attach(process)
                result['worker_exit'] = process.wait(timeout=45)
            finally:
                owner.close()
        require(result['worker_exit'] == 0, 'restricted-token worker failed; preserve its diagnostics')
        report = json.loads((root / 'worker-result.json').read_text(encoding='utf-8'))
        require(report['status'] == 'PASS' and report['windows_acceptance'], 'worker did not establish P6')
        result.update(status='PASS', windows_acceptance=True)
    except BaseException as exc:
        result.update(status='FAIL', windows_acceptance=False, error_type=type(exc).__name__,
                      error=str(exc), traceback=traceback.format_exc())
    finally:
        with helper.defer_stops(result) if helper is not None else contextlib.nullcontext():
            if helper is not None:
                checks = []
                if before_source is not None:
                    checks.append(('source', before_source, lambda: helper.source_facts(source, git_path, env), 'product source changed'))
                if before_tools is not None:
                    checks.append(('tools', before_tools, lambda: {p: helper.fact(Path(p)) for p in before_tools}, 'source/tool/helper witnesses changed'))
                for name, (path, before, message) in inputs.items():
                    checks.append((name, before, lambda path=path: helper.fact(path), message))
                for name, before, read, message in checks:
                    try:
                        after = read()
                        save(root / (name + '-after.json'), after)
                        require(before == after, message)
                    except BaseException as exc:
                        detail = type(exc).__name__ + ': ' + str(exc)
                        result.update(status='FAIL', windows_acceptance=False, witness_error=detail)
                        result.setdefault('witness_errors', []).append(detail)
            if result.get('deferred_signals'):
                result.update(status='FAIL', windows_acceptance=False)
            save(root / 'execution.json', result)
            files = {p.name: {'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in root.iterdir() if p.is_file() and p.name != 'manifest.json'}
            save(root / 'manifest.json', {'status': result['status'], 'windows_acceptance': result['windows_acceptance'],
                                        'helper_sha256': HELPER_SHA, 'files': files, 'excludes': ['fixture', 'HOME/cache']})
        signal.signal(signal.SIGTERM, old_term)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
