"""Recorded process census and fixed refusals for the session stop port.

Host grammar is an injected public port. Kernel birth, boot and namespace facts
come exclusively from kernel_identity. Reads are bounded and descriptor anchored.
No function in this module imports tools or starts a model.
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import time
from typing import NamedTuple, Optional

from aegis_core import kernel_identity, storage_confined

MAX_RECORDS = 10000
ENDPOINT_NAMESPACE_CHANGED = 'endpoint namespace changed; preserve custody and retry'
MAX_NAMESPACE_DEPTH = 256
MAX_NAMESPACE_MANIFEST = 32768
PID_NAMESPACE_REFUSAL = 'stop unsupported without matching PID namespace and caller procfs view; preserve custody, stop the host manually in its original PID namespace, and have the owner reconcile this endpoint before retrying'
CURRENT_PID_NAMESPACE = object()
PIDFD_REFUSAL = 'stop could not obtain a safe process handle; preserve custody, restore pidfd availability and retry stop, or stop the host manually and have the owner reconcile this endpoint'
OWNING_CHAIN_REFUSAL = 'stop owning chain is unverified; preserve custody, stop the host and descendants manually, and have the owner reconcile this endpoint before retrying'
KILL_WAIT_SECONDS = 5.0
POLL_SECONDS = 0.05
STOP_EXIT_PROOFS = ('original_pidfd_exit', 'qualified_namespace_ESRCH', 'matching_birth_zombie', 'matching_partial_birth_zombie', 'confirmed_instance_exit', 'signal_ESRCH')
STOP_COVERAGE = (None, 'argv_boundaries_unavailable', 'session_instance_unresolved_after_exit')
ROOT_STOP = "ROOT is the owner's session; the launcher does not stop it"
MAILBOX_WAKE_PENDING = 'mailbox wake admission is pending; wait for the producer to finish, or preserve and reconcile its marker before retrying'
CLEANUP_BINDING_CHANGED = 'cleanup binding changed; preserve the worktree and inspect the successor binding before rerunning cleanup'
NO_EXPECTED_BINDING = object()
STATUS_SCHEMA = 'aegis.hierarchy-launch-status/v1'


class SessionRefused(ValueError):
    """Fixed envelope: no caller paths, arguments or OS diagnostics escape."""
    code = "invalid_evidence"

    def __init__(self, *ignored):
        self.reason = {
            "invalid_evidence": "session evidence is invalid or unavailable",
            "unsupported_platform": "session descriptors are unsupported",
            "pid_namespace_unavailable": "PID namespace identity is unavailable",
            "pidfd_unavailable": "safe process handle is unavailable",
            "custody_busy": "stop custody is busy",
            "custody_unavailable": "stop custody is unavailable",
            "custody_exit_unproven": "stop custody exit is unproven",
            "census_unavailable": "process census is incomplete",
            "launch_record_limit": "launch record limit reached",
        }[self.code]
        self.next_action = {"actor": "owner", "command": "preserve evidence and restore the refused session prerequisite"}
        super().__init__(self.reason)


class UnsupportedPlatform(SessionRefused):
    code = "unsupported_platform"


class CustodyBusy(SessionRefused):
    code = "custody_busy"


class PidNamespaceUnavailable(SessionRefused):
    code = "pid_namespace_unavailable"

    def __init__(self, pids=()):
        super().__init__()
        require(type(pids) in (tuple, list, set) and len(pids) <= MAX_RECORDS)
        require(all(type(pid) is int and 0 < pid < 2 ** 22 for pid in pids))
        self.pids = sorted(set(pids))


class PidfdUnavailable(SessionRefused):
    code = "pidfd_unavailable"


class CustodyUnavailable(SessionRefused):
    code = "custody_unavailable"


class CensusUnavailable(SessionRefused):
    code = "census_unavailable"

    def __init__(self, message=None, unresolved_pids=None, coverage=None):
        super().__init__()
        self.unresolved_pids, self.coverage = unresolved_pids or {}, coverage


class LaunchRecordLimit(SessionRefused):
    code = "launch_record_limit"

    def __init__(self, endpoint, count):
        super().__init__()
        self.count = count


class CustodyExitUnproven(SessionRefused):
    code = "custody_exit_unproven"

    def __init__(self, base, endpoint, pid, attempted, unsupported=False):
        super().__init__()
        require(type(attempted) in (tuple, list, set) and len(attempted) <= MAX_RECORDS)
        require(all(type(value) is int and 0 < value < 2 ** 22 for value in attempted))
        self.pids = sorted(set(attempted))


def safe_reason(error):
    return error.reason if isinstance(error, SessionRefused) else "session evidence is invalid or unavailable"


def guarded(function):
    @wraps(function)
    def run(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SessionRefused:
            raise
        except Exception:
            raise SessionRefused() from None
    return run


def require(condition, message=""):
    if not condition:
        if "unsupported" in message:
            raise UnsupportedPlatform()
        if message in ("stop custody is busy",) or message.startswith("stop custody endpoint is busy:"):
            raise CustodyBusy()
        raise SessionRefused()


def text(value, label, limit=4096):
    require(type(value) is str and 0 < len(value) <= limit and "\0" not in value)
    require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value))
    return value


def integer(value, label, minimum=1, maximum=1000000):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def safe_path(value):
    spelling = str(value) if isinstance(value, Path) else value
    text(spelling, "path", 32768)
    require("\\" not in spelling)
    path = Path(spelling)
    require(path.is_absolute() and ".." not in path.parts and len(path.parts) <= 128)
    require(all(len(part) <= 255 and len(part.encode("utf-8")) <= 255 for part in path.parts[1:]))
    return path


def quoted(endpoint):
    text(endpoint, "endpoint", 256)
    return endpoint.replace("/", "%2F")


class ProcessSnapshot(NamedTuple):
    pid: int
    pgid: int
    state: str
    uid: int
    start_time: str
    cmdline: bytes
    argv: tuple
    ppid: int
    euid: int

class ProcessObservation(NamedTuple):
    kind: str
    pid: int
    snapshot: object = None
    partial: object = None
    reason: str = ''
    proof: str = ''

class ProcessIdentity(NamedTuple):
    pid: int
    start_time: str
    uid: int
    euid: int


PROCESS_IDENTITY_FIELDS = ('pid', 'start_time', 'uid', 'euid')
STORED_PROCESS_FIELDS = ('pid', 'pgid', 'state', 'uid', 'start_time', 'cmdline_sha256', 'ppid', 'euid')

class IdentityWitness(NamedTuple):
    """Negative census evidence; missing UIDs never supply instance or signal authority."""
    pid: int
    start_time: str
    uid: Optional[int]
    euid: Optional[int]

class StoredProcess(NamedTuple):
    pid: int
    pgid: int
    state: str
    uid: int
    start_time: str
    cmdline_sha256: str
    ppid: int
    euid: int

class ProcessCensus(list):

    def __init__(self, rows, argv_boundaries, unavailable=None, complete=True, births=None, identities=None):
        require(isinstance(rows, (tuple, list)) and len(rows) <= MAX_RECORDS)
        require(unavailable is None or type(unavailable) is dict and len(unavailable) + len(rows) <= MAX_RECORDS)
        require(births is None or type(births) is dict and len(births) <= MAX_RECORDS)
        require(identities is None or type(identities) is dict and len(identities) <= MAX_RECORDS)
        super().__init__(rows)
        self.argv_boundaries = argv_boundaries
        self.unavailable = unavailable or {}
        self.complete = complete
        self.births = {} if births is None else births
        self.identities = {} if identities is None else identities
        for row in self:
            self.births.setdefault(row.pid, set()).add(row.start_time)
            remember_census_identity(self.identities, process_identity(row))
        for pid, observation in self.unavailable.items():
            facts = observation.partial or {}
            if facts.get('coherent_birth') and facts.get('start_time'):
                self.births.setdefault(pid, set()).add(facts['start_time'])
                if any((type(facts.get(key)) is int for key in ('uid', 'euid'))):
                    remember_census_identity(self.identities, IdentityWitness(pid, facts['start_time'], facts.get('uid'), facts.get('euid')))

def binding_identity(binding):
    return {key: binding[key] for key in ('host', 'session', 'generation')} if binding is not None else None

@guarded
def metadata_json(raw, label):
    """Bound bytes and numeric tokens before parsing; errors never repeat untrusted keys/values."""
    require(label in ('launch record', 'stop custody', 'endpoint namespace'), 'invalid metadata kind')
    require(isinstance(raw, bytes) and len(raw) <= 262144, 'invalid ' + label + ' JSON')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SessionRefused('duplicate key')
            result[key] = value
        return result

    def integer_token(value):
        if len(value.lstrip('-')) > 128:
            raise SessionRefused('integer token limit')
        return int(value)

    def float_token(value):
        if len(value) > 128:
            raise SessionRefused('float token limit')
        number = float(value)
        if not math.isfinite(number):
            raise SessionRefused('non-finite number')
        return number

    def constant(_value):
        raise SessionRefused('non-finite number')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_int=integer_token, parse_float=float_token, parse_constant=constant)
    except json.JSONDecodeError as exc:
        safe_syntax = ('Expecting property name enclosed in double quotes', 'Expecting value', "Expecting ':' delimiter", "Expecting ',' delimiter", 'Extra data', 'Unterminated string starting at', 'Invalid \\uXXXX escape')
        if exc.msg in safe_syntax:
            raise SessionRefused('%s: line %d column %d (char %d)' % (exc.msg, exc.lineno, exc.colno, exc.pos)) from None
        raise SessionRefused('invalid ' + label + ' JSON') from None
    except (ValueError, UnicodeError, RecursionError):
        raise SessionRefused('invalid ' + label + ' JSON') from None

def process_identity(row):
    return ProcessIdentity(row.pid, row.start_time, row.uid, row.euid)

def remember_census_identity(identities, identity):
    if identity.pid not in identities:
        require(len(identities) < MAX_RECORDS, 'process census exceeds identity limit')
        identities[identity.pid] = set()
    values = identities[identity.pid]
    require(identity in values or len(values) < MAX_RECORDS, 'process census exceeds identity limit')
    values.add(identity)

def running_pid_namespace(record):
    return record.get('pid_namespace') if record.get('schema') == 'aegis.hierarchy-running-wake/v3' else None

def same_process_identity(expected, current):
    return process_identity(expected) == process_identity(current)

def validate_pid_namespace(value):
    require(isinstance(value, dict) and value.keys() in ({'device', 'inode'}, {'device', 'inode', 'boot'}) and (type(value['device']) is int) and (0 <= value['device'] < 2 ** 64) and (type(value['inode']) is int) and (0 < value['inode'] < 2 ** 64), 'invalid PID namespace identity')
    if value.get('boot') is not None:
        require(isinstance(value['boot'], str) and len(value['boot']) == 36 and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value['boot']), 'invalid PID namespace boot')
    return value

class SystemCalls:
    """Invocation-local OS port; explicit operations remain visible to the census."""
    O_RDONLY, O_WRONLY, O_RDWR = os.O_RDONLY, os.O_WRONLY, os.O_RDWR
    O_CREAT, O_EXCL = os.O_CREAT, os.O_EXCL
    O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
    O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
    O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

    def __getattr__(self, name):
        if name == "pidfd_open":
            return getattr(os, "pidfd_open")
        raise AttributeError("unsupported OS operation")

    def getpid(self):
        return os.getpid()

    def geteuid(self):
        return os.geteuid()


    def close(self, fd):
        return os.close(fd)


    def fsdecode(self, data):
        return os.fsdecode(data)

    def kill(self, pid, number):
        return os.kill(pid, number)

    def killpg(self, group, number):
        return os.killpg(group, number)


class CanonicalIdentity:
    """A narrow borrowed port; all parsing remains in kernel_identity."""
    def process_identity(self, pid):
        return kernel_identity.process_identity(pid)

    def scope(self):
        return kernel_identity.scope()

    def boot_id(self):
        return kernel_identity.boot_id()


class SessionCensus:
    GRAMMAR_OVERSIZE = 'host_grammar_oversize'

    def __init__(self, hosts, *, system=None, signals=None, clock=None, ports=None, identity=None, roles=None):
        self.hosts = hosts
        self.os = SystemCalls() if system is None else system
        self.signal = signal if signals is None else signals
        self.time = time if clock is None else clock
        self.ports = ports
        self.roles = roles
        self.identity = CanonicalIdentity() if identity is None else identity

    @guarded
    def endpoint_parts(self, endpoint):
        require(self.roles is not None)
        return self.roles.endpoint_parts(endpoint)

    @guarded
    def current_pid_namespace(self):
        try:
            facts = self.identity.scope()
            pid = self.os.getpid()
            # The canonical reader parses namespace/birth/boot. This stat supplies
            # only the legacy device field and checks that the held link agrees.
            with self.directory_descriptor(Path("/proc") / str(pid) / "ns", verify=True) as directory:
                info = os.stat("pid", dir_fd=directory)
            inode = int(facts["pid_namespace"][5:-1])
            status = self.proc_bytes(pid, "status", 65536)
            namespace_pids = [line.split() for line in status.splitlines() if line.startswith(b"NSpid:")]
            if (info.st_ino != inode or namespace_pids != [[b"NSpid:", str(pid).encode("ascii")]]
                    or self.identity.scope() != facts):
                return None
            return {"device": info.st_dev, "inode": inode, "boot": facts["boot_id"]}
        except (kernel_identity.IdentityError, SessionRefused, OSError):
            return None

    @guarded
    def proc_bytes(self, pid, name, limit):
        integer(pid, "pid", maximum=2 ** 22 - 1)
        require(name in ("stat", "status", "cmdline"))
        with storage_confined.confined_file(Path("/proc"), (str(pid), name)) as handle:
            return handle.read_bytes(limit)

    @guarded
    def read_process_once(self, pid, argv_boundaries="proven"):
        integer(pid, "pid", maximum=2 ** 22 - 1)
        if argv_boundaries != "proven":
            rows = self.ps_census(pid)
            return (ProcessObservation('PRESENT', pid, rows[0]) if rows else
                    self.process_existence(pid, 'argv_boundaries_unavailable'))
        data, errors, partial = {}, [], {}
        try:
            birth_before = self.identity.process_identity(pid)
        except kernel_identity.IdentityError:
            birth_before = None
        for name, filename in (("before", "stat"), ("status", "status"), ("cmdline", "cmdline"), ("after", "stat")):
            try:
                data[name] = self.proc_bytes(pid, filename, 262144 if filename == "cmdline" else 65536 if filename == "status" else 4096)
            except SessionRefused:
                errors.append("unreadable process evidence")
        try:
            birth_after = self.identity.process_identity(pid)
        except kernel_identity.IdentityError:
            birth_after = None
        fields = data.get("before", b"").rpartition(b") ")[2].split()
        after = data.get("after", b"").rpartition(b") ")[2].split()
        valid = len(fields) >= 20 and all(len(fields[i]) <= 20 and fields[i].isdigit() for i in (1, 2, 19))
        coherent = (valid and birth_before is not None and birth_after == birth_before
                    and int(fields[19]) == birth_before["start_ticks"]
                    and len(after) >= 20 and after[19:20] == fields[19:20])
        terminal = (valid and birth_before is None and birth_after is None and len(after) >= 20
                    and fields[0] in (b'Z', b'X', b'x') and after[0] in (b'Z', b'X', b'x')
                    and fields[19:20] == after[19:20])
        coherent = coherent or terminal
        if coherent:
            partial.update(start_time=fields[19].decode('ascii'), ppid=int(fields[1]),
                           pgid=int(fields[2]), state=self.os.fsdecode(fields[0]))
        else:
            errors.append("unstable birth evidence")
        partial.update(coherent_birth=coherent, exit_observed=coherent and (fields[0] in (b'Z', b'X', b'x') or after[0] in (b'Z', b'X', b'x')))
        if coherent and after[1:3] != fields[1:3]:
            errors.append("unstable parent/group evidence")
        uids = next((line.split()[1:] for line in data.get("status", b"").splitlines() if line.startswith(b"Uid:")), [])
        if len(uids) >= 2 and all(len(x) <= 10 and x.isdigit() for x in uids[:2]):
            partial.update(uid=int(uids[0]), euid=int(uids[1]))
        else:
            errors.append("missing real/effective status UIDs")
        if "cmdline" in data:
            raw = data["cmdline"]
            # Bound atom count before splitting/allocating argv.
            if raw.count(b"\0") + int(bool(raw) and not raw.endswith(b"\0")) > 4096:
                errors.append("argv limit")
            else:
                arguments = raw.split(b"\0")
                partial.update(cmdline=raw, argv=tuple(self.os.fsdecode(a) for a in (arguments[:-1] if not arguments[-1] else arguments)))
            if raw and not raw.endswith(b"\0"):
                errors.append("truncated cmdline")
        if errors:
            return self.process_existence(pid, "evidence_unavailable: " + "; ".join(errors), partial)
        row = ProcessSnapshot(pid, partial["pgid"], partial["state"], partial["uid"], partial["start_time"],
                              partial["cmdline"], partial["argv"], partial["ppid"], partial["euid"])
        return ProcessObservation("PRESENT", pid, row)

    @guarded
    def census_kernel_thread(self, row):
        if row.pgid != 0:
            return False
        try:
            samples = [self.proc_bytes(row.pid, "stat", 4096).rpartition(b") ")[2].split() for _ in range(2)]
            return all(len(f) >= 20 and f[19] == row.start_time.encode("ascii") and f[2] == b"0"
                       and len(f[6]) <= 20 and f[6].isdigit() and int(f[6]) & 0x00200000 for f in samples)
        except SessionRefused:
            return False

    @guarded
    def ps_census(self, pid=None):
        """Lossy diagnostics come from an explicit adapter; they grant no stop authority."""
        require(self.ports is not None and callable(self.ports.process_rows), 'process diagnostics unsupported')
        rows = self.ports.process_rows(pid)
        return ProcessCensus(rows, 'unproven', complete=getattr(rows, 'complete', True))

    @guarded
    def process_census(self, session):
        if not self.launch_descriptor_capable():
            return self.ps_census()
        rows, unavailable, births, identities = [], {}, {}, {}
        with self.directory_descriptor(Path("/proc"), verify=True) as directory:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not entry.name.isascii() or not entry.name.isdigit():
                        continue
                    require(len(entry.name) <= 10 and len(rows) + len(unavailable) < MAX_RECORDS)
                    observation, include = self.census_observation(int(entry.name), births, identities)
                    if not include:
                        continue
                    if observation.kind == "PRESENT":
                        rows.append(observation.snapshot)
                    elif observation.kind == "UNAVAILABLE":
                        unavailable[observation.pid] = observation
        return ProcessCensus(rows, "proven", unavailable, births=births, identities=identities)

    @guarded
    def ancestors(self):
        mine, pid = set(), self.os.getpid()
        while pid > 1 and pid not in mine:
            require(len(mine) < MAX_RECORDS)
            mine.add(pid)
            observation = self.read_process(pid)
            require(observation.kind == "PRESENT")
            pid = observation.snapshot.ppid
        return mine


    @guarded
    def require_pid_namespace(self, expected=CURRENT_PID_NAMESPACE, pids=()):
        current = self.current_pid_namespace()
        if current is None or (expected is not CURRENT_PID_NAMESPACE and expected != current):
            raise PidNamespaceUnavailable(pids)
        return current

    @guarded
    def process_group_exited(self, group, namespace=CURRENT_PID_NAMESPACE):
        """Only a kernel ESRCH proves group absence; enumeration cannot close a fork/exit race."""
        namespace = self.require_pid_namespace(namespace)
        try:
            self.os.killpg(group, 0)
        except OSError as exc:
            self.require_pid_namespace(namespace)
            return exc.errno == errno.ESRCH
        self.require_pid_namespace(namespace)
        return False

    @guarded
    def retained_groups_exited(self, observed):
        require(len(observed.get('owned_groups', ())) <= MAX_RECORDS, 'stop custody exceeds group limit')
        namespace = observed.get('pid_namespace')
        self.require_pid_namespace(namespace)
        pending = sorted((group for group in observed.get('owned_groups', ()) if not self.process_group_exited(group, namespace)))
        observed['unresolved_groups'] = pending
        return not pending

    @contextmanager
    def launch_directory(self, base, endpoint):
        """Pin every edge through enumeration/read, including the witness for legacy absence."""
        require(self.launch_descriptor_capable(), 'launch record descriptors unsupported on this platform')
        self.endpoint_parts(endpoint)
        base = safe_path(base)
        parts = (*base.parts[1:], 'launches', quoted(endpoint))
        descriptors, edges, missing = ([], [], None)
        try:
            descriptors.append(os.open(base.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            for index, part in enumerate(parts):
                parent = descriptors[-1]
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                except FileNotFoundError:
                    if index < len(base.parts) - 1:
                        raise
                    missing = (parent, part)
                    break
                descriptors.append(child)
                info = os.fstat(child)
                edges.append((parent, part, (info.st_dev, info.st_ino)))
            yield (None if missing else descriptors[-1])
            for parent, name, identity in edges:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity, 'launch directory changed while reading')
            if missing:
                try:
                    os.stat(missing[1], dir_fd=missing[0], follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise SessionRefused('launch directory appeared while reading')
        except OSError as exc:
            reason = ': symlink or non-directory' if exc.errno in (errno.ELOOP, errno.ENOTDIR) else ''
            raise SessionRefused('launch directory unreadable' + reason) from exc
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @guarded
    def launch_descriptor_capable(self):
        return kernel_identity.descriptor_supported()

    @guarded
    def launch_record_paths(self, base, endpoint):
        folder, paths, records = (Path(base) / 'launches' / quoted(endpoint), [], 0)
        with self.launch_directory(base, endpoint) as directory:
            if directory is not None:
                with os.scandir(directory) as entries:
                    for count, entry in enumerate(entries):
                        require(count < MAX_RECORDS + 64, 'launch directory entry limit reached')
                        if entry.name.endswith('.json'):
                            info = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                            require(stat.S_ISREG(info.st_mode), 'invalid launch record entry')
                            records += 1
                            if records <= MAX_RECORDS:
                                paths.append(folder / entry.name)
        if records > MAX_RECORDS:
            raise LaunchRecordLimit(endpoint, records)
        return sorted(paths)


    @guarded
    def procfs_exit_evidence_supported(self, observation):
        return observation.proof != 'process_visibility_denied'

    @guarded
    def process_existence(self, pid, reason, partial=None):
        """Missing metadata alone proves nothing; qualified numeric ESRCH is a distinct observation."""
        namespace = self.current_pid_namespace()
        if namespace is None:
            return ProcessObservation('UNAVAILABLE', pid, partial=partial, reason=PID_NAMESPACE_REFUSAL, proof='pid_namespace_unavailable')
        try:
            self.os.kill(pid, 0)
        except ProcessLookupError:
            if self.current_pid_namespace() != namespace:
                return ProcessObservation('UNAVAILABLE', pid, partial=partial, reason=PID_NAMESPACE_REFUSAL, proof='pid_namespace_unavailable')
            return ProcessObservation('CONFIRMED_ABSENT', pid, partial=partial, proof='qualified_namespace_ESRCH')
        except PermissionError:
            return ProcessObservation('UNAVAILABLE', pid, partial=partial, reason=reason + '; existence_unknown', proof='process_visibility_denied')
        return ProcessObservation('UNAVAILABLE', pid, partial=partial, reason=reason + '; existence_live')

    @guarded
    def read_process(self, pid, argv_boundaries='proven'):
        """Retry a torn multipart observation once, never turn unreadable evidence into absence."""
        first = self.read_process_once(pid, argv_boundaries)
        if first.kind == 'UNAVAILABLE' and first.reason.partition('; existence_')[0] == 'evidence_unavailable: unstable parent/group evidence':
            return self.read_process_once(pid, argv_boundaries)
        return first

    @guarded
    def census_observation(self, pid, births=None, identities=None):
        """Settle empty discovery samples, never retained or pre-signal observations.
        Only proven terminal/kernel-only rows are filtered; new births supply no exit authority.
        """
        observation = self.read_process(pid)
        for attempt in range(4):
            if births is not None:
                facts = observation.partial or {}
                birth = observation.snapshot.start_time if observation.kind == 'PRESENT' else facts.get('start_time') if facts.get('coherent_birth') else None
                if birth is not None:
                    births.setdefault(pid, set()).add(birth)
                    if identities is not None:
                        if observation.kind == 'PRESENT':
                            remember_census_identity(identities, process_identity(observation.snapshot))
                        elif any((type(facts.get(key)) is int for key in ('uid', 'euid'))):
                            remember_census_identity(identities, IdentityWitness(pid, birth, facts.get('uid'), facts.get('euid')))
            if observation.kind != 'PRESENT':
                return (observation, True)
            row = observation.snapshot
            if not self.our_uid(row) or (row.cmdline and row.argv):
                return (observation, True)
            if row.state in ('Z', 'X', 'x') or self.census_kernel_thread(row):
                return (observation, False)
            if attempt == 3:
                break
            self.time.sleep(0.005)
            observation = self.read_process(pid)
        return (observation, True)

    @guarded
    def argv_names_session(self, argv, session):
        if not self.argv_relevant(argv, session):
            return False
        if self.argv_grammar_bounded(argv):
            return self.hosts.names_session(argv, session)
        if self.grammar_reach(argv):
            return True
        for atom in argv:
            if atom == session or any(found.group() == session for found in self.hosts.SESSION_UUID_OCCURRENCE.finditer(atom)):
                return True
            for word in re.finditer(r'\S+', atom):
                start, end = word.span()
                if any(end - begin == len(session) and atom.startswith(session, begin) for begin in (start, atom.find('=', start, end) + 1) if begin >= start):
                    return True
        return False

    def grammar_reach(self, argv):
        """Total negative evidence, using public names; never parse/copy an unbounded argv."""
        if type(argv) not in (tuple, list) or any(type(atom) is not str or '\0' in atom for atom in argv):
            return True
        def program_is(atom, names):
            separator, drive = (r'[/\\]', r'(?:[A-Za-z]:)?') if os.name == 'nt' else ('/', '')
            return any(re.search(r'(?:^|' + separator + ')' + drive + re.escape(name) + r'(?:' + separator + r'\.?)*$', atom) for name in names)
        index = 0
        if argv and program_is(argv[0], ('env',)):
            index = 1
            while index < len(argv) and re.match(r'[A-Za-z_][A-Za-z0-9_]*=', argv[index]):
                index += 1
            if index == len(argv) or argv[index].startswith('-'):
                return True
        for kind in self.hosts.TEAM_HOSTS:
            entry = self.hosts.entry(kind)
            if index < len(argv) and program_is(argv[index], entry['entrypoints']['program_basenames'] + ['node']):
                return True
            selectors = entry['session_selectors']
            if any(position and (any(atom == option or atom.startswith(option + '=') for option in selectors['options']) or
                                 any(atom == command[-1] for command in selectors['commands'])) for position, atom in enumerate(argv)):
                return True
        return False

    def grammar_uncertain(self, argv):
        return not self.argv_grammar_bounded(argv) and self.grammar_reach(argv)

    def session_verdict(self, host, argv, session, boundaries='proven'):
        if not self.argv_grammar_bounded(argv):
            return 'HOLD' if self.grammar_reach(argv) else 'NOT_OWNED'
        return self.hosts.session_verdict(host, argv, session, boundaries)

    def descendant_verdict(self, argv, session):
        if not self.argv_grammar_bounded(argv):
            return 'HOLD' if self.grammar_reach(argv) else 'CLEAR'
        return self.hosts.descendant_verdict(argv, session)

    def selects_other_session(self, argv, session):
        return self.descendant_verdict(argv, session) != 'CLEAR'

    def argv_relevant(self, argv, session):
        return any(session in atom for atom in argv)

    @guarded
    def partial_argv(self, observation):
        facts = observation.partial or {}
        raw, argv = facts.get('cmdline'), facts.get('argv')
        return argv if (type(raw) is bytes and len(raw) <= 262144 and raw.endswith(b'\0') and type(argv) in (tuple, list) and len(argv) <= 4096 and facts.get('coherent_birth')
                        and not any(error in observation.reason for error in ('argv limit', 'truncated cmdline', 'unstable birth evidence', 'unstable parent/group evidence'))) else None

    def argv_grammar_bounded(self, argv):
        """Use the injected registry's public limits before invoking its grammar."""
        return (type(argv) in (tuple, list) and len(argv) <= self.hosts.MAX_ARGV_ATOMS
                and all(type(atom) is str and len(atom) <= self.hosts.MAX_ARGV_ATOM_CHARS and '\0' not in atom for atom in argv)
                and sum(map(len, argv)) <= self.hosts.MAX_ARGV_CHARS)

    @guarded
    def our_uid(self, row):
        return row.uid == row.euid == self.os.geteuid()

    @guarded
    def owns_process(self, row, session, host, boundaries):
        return (self.our_uid(row) and self.argv_relevant(row.argv, session) and
                self.session_verdict(host, row.argv, session, boundaries) == 'OWNED')

    @guarded
    def unresolved(self, observed, pid, stage, reason):
        previous = observed['unresolved'].get(pid)
        entry = {'pid': pid, 'stage': stage, 'reason': previous['reason'] if previous is not None and previous['reason'] in (self.GRAMMAR_OVERSIZE, 'cmdline_unavailable') else reason}
        if reason == 'signal_command_line_not_authorized':
            entry['signal_refusal'] = reason
        elif previous is not None and 'signal_refusal' in previous:
            entry['signal_refusal'] = previous['signal_refusal']
        observed['unresolved'][pid] = entry

    @guarded
    def retain_candidate(self, observed, row, reason, missing=False):
        """Discovery retains uncertainty, never promotes diagnostic ps fields to a proven identity."""
        if row.pid not in observed['candidates']:
            proven = observed['argv_boundaries'] == 'proven'
            observed['candidates'][row.pid] = row if proven and (not missing) else None
            if not proven or missing:
                partial = dict(pid=row.pid, pgid=row.pgid, ppid=row.ppid, uid=row.uid, euid=row.euid, coherent_birth=proven)
                if proven:
                    partial.update(start_time=row.start_time, state=row.state, exit_observed=row.state.startswith('Z'))
                observed['initial_unavailable'][row.pid] = partial
            observed['checkpoint_pending'] = True
        self.unresolved(observed, row.pid, 'census', reason)

    @guarded
    def session_processes(self, session, excluded, host=None, unowned=None, observed=None):
        """Owned roots only; retain unresolved candidates independently from attempted signals."""
        if host is not None:
            self.hosts.entrypoints(host)
        state = observed if observed is not None else {}
        namespace = self.require_pid_namespace()
        census = self.process_census(session)
        state.update(census={row.pid: row for row in census}, argv_boundaries=census.argv_boundaries, census_births=census.births, census_identities=census.identities, census_complete=census.complete, candidates={}, unresolved={}, resolved={}, handles={}, blocked=set(), identity_lost=set(), initial_unavailable={}, group_candidates=set(), numeric=False, pid_namespace=namespace)
        found, partial_argv = [], {pid: self.partial_argv(observation) for pid, observation in getattr(census, 'unavailable', {}).items()}
        if census.argv_boundaries != 'proven':
            state['coverage'] = 'argv_boundaries_unavailable'
        for row in census:
            if row.pid in excluded or row.state.startswith('Z'):
                continue
            if self.our_uid(row) and (not row.cmdline or not row.argv):
                self.retain_candidate(state, row, 'cmdline_unavailable', missing=True)
                continue
            if not self.argv_relevant(row.argv, session):
                continue
            if self.grammar_uncertain(row.argv):
                if self.our_uid(row):
                    self.retain_candidate(state, row, self.GRAMMAR_OVERSIZE)
                elif unowned is not None:
                    unowned.append(row.pid)
                continue
            if not self.argv_names_session(row.argv, session):
                continue
            verdict = self.session_verdict(host, row.argv, session, census.argv_boundaries)
            if self.our_uid(row) and verdict == 'OWNED':
                found.append((row.pid, row.pgid))
                state['candidates'][row.pid] = row
            else:
                if unowned is not None:
                    unowned.append(row.pid)
                if census.argv_boundaries == 'proven' and self.our_uid(row) and (verdict == 'HOLD'):
                    self.retain_candidate(state, row, 'host_grammar_unavailable')
        for pid, observation in getattr(census, 'unavailable', {}).items():
            facts = observation.partial or {}
            argv = partial_argv[pid]
            if argv is not None and not self.argv_relevant(argv, session):
                continue
            if pid in excluded or (facts.get('coherent_birth') and (facts.get('exit_observed') or
                    all(type(facts.get(key)) is int for key in ('uid', 'euid')) and any(facts[key] != self.os.geteuid() for key in ('uid', 'euid')))):
                continue
            state['candidates'][pid] = None
            state['initial_unavailable'][pid] = facts
            reason = 'cmdline_unavailable' if argv is None else self.GRAMMAR_OVERSIZE if argv and self.grammar_uncertain(argv) else observation.reason
            self.unresolved(state, pid, 'census', reason)
            if unowned is not None and argv is not None and self.argv_names_session(argv, session):
                unowned.append(pid)
        require(len(state['candidates']) <= MAX_RECORDS, 'stop custody exceeds evidence limit')
        owners = {pid for pid, _ in found}
        for pid, row in state['candidates'].items():
            if row is not None:
                continue
            facts = state['initial_unavailable'].get(pid, {})
            linked = partial_argv.get(pid) is not None and self.argv_names_session(partial_argv[pid], session)
            parent, seen = (facts.get('ppid'), set())
            while not linked and parent is not None and (parent not in seen):
                require(len(seen) < MAX_RECORDS, 'process ancestry exceeds evidence limit')
                seen.add(parent)
                if parent in owners:
                    linked = True
                ancestor = state['census'].get(parent)
                parent = ancestor.ppid if ancestor is not None else None
            if linked:
                birth = facts.get('start_time') if facts.get('coherent_birth') else None
                state['group_candidates'].add((pid, birth))
        if observed is None and (state.get('coverage') or state['unresolved']):
            raise CensusUnavailable('process census unresolved: ' + (state.get('coverage') or ','.join(map(str, sorted(state['unresolved'])))), state['unresolved'], state.get('coverage'))
        return found

    @guarded
    def original_exit(self, expected, observed):
        self.require_pid_namespace(observed.get('pid_namespace'))
        handle = observed['handles'].get(expected.pid)
        if handle is None or not handle['verified']:
            return False
        poller = select.poll()
        poller.register(handle['fd'], select.POLLIN)
        if any((event & select.POLLIN for _, event in poller.poll(0))):
            self.resolve_process(observed, expected.pid, 'original_pidfd_exit')
            return True
        return False

    @guarded
    def signal_command_authorized(self, expected, current, boundaries, session, host):
        """Command authority is separate from lifetime identity, including retained/recovered signals."""
        if boundaries != 'proven' or current.kind != 'PRESENT':
            return False
        row = current.snapshot
        if not row.cmdline or not row.argv:
            return False
        if self.owns_process(row, session, host, boundaries):
            return True
        captured = getattr(expected, 'cmdline', None)
        if captured is not None:
            return row.cmdline == captured
        digest = getattr(expected, 'cmdline_sha256', None)
        return digest is not None and hashlib.sha256(row.cmdline).hexdigest() == digest

    @guarded
    def process_state(self, expected, current, boundaries, session, host, unowned, require_host=True, parent=None, retained=False):
        if current is None:
            current = self.process_existence(expected.pid, 'evidence_unavailable: reader returned None')
        if isinstance(current, ProcessSnapshot):
            current = ProcessObservation('PRESENT', expected.pid, current)
        if current.kind == 'CONFIRMED_ABSENT':
            return 'gone'
        if current.kind != 'PRESENT':
            return 'unavailable'
        if boundaries != 'proven':
            return 'unavailable'
        row = current.snapshot
        if same_process_identity(expected, row) and row.state.startswith('Z'):
            return 'gone'
        if row.start_time != expected.start_time or (not retained and row.pgid != expected.pgid) or (not self.our_uid(row)) or ((row.uid, row.euid) != (expected.uid, expected.euid)) or (parent is not None and row.ppid != parent):
            return 'changed'
        if row.cmdline == b'' and row.argv == ():
            return 'unavailable'
        if self.grammar_uncertain(row.argv):
            return 'unavailable'
        if not same_process_identity(expected, row) or (require_host and (not self.owns_process(row, session, host, boundaries))) or (not require_host and self.selects_other_session(row.argv, session)):
            return 'changed'
        return 'authorized'

    @guarded
    def unchanged_process(self, expected, boundaries, session, host, unowned, require_host=True, parent=None, retained=False):
        return self.process_state(expected, self.read_process(expected.pid, boundaries), boundaries, session, host, unowned, require_host, parent, retained) == 'authorized'

    @guarded
    def note_identity_loss(self, expected, observation, observed):
        if observed is None or observed['argv_boundaries'] != 'proven':
            return
        facts = observation.snapshot._asdict() if observation.kind == 'PRESENT' else observation.partial or {}
        birth = facts.get('start_time') if observation.kind == 'PRESENT' or facts.get('coherent_birth') else None
        changed = birth is not None and (birth != expected.start_time or any(facts.get(key) is not None and facts[key] != getattr(expected, key) for key in ('uid', 'euid')))
        if changed and expected.pid not in observed['identity_lost']:
            self.latch_blocked(observed, expected.pid, True)

    @guarded
    def numeric_absence_blocked(self, observed, pid):
        """Classification latches forbid signals; lost birth/UID identity also forbids numeric exit."""
        if pid not in observed['blocked']:
            return False
        expected = observed['candidates'].get(pid)
        partial = observed['initial_unavailable'].get(pid, {})
        birth = expected.start_time if expected is not None else partial.get('start_time') if partial.get('coherent_birth') else None
        return pid in observed['identity_lost'] or birth is None

    @guarded
    def retained_state(self, expected, boundaries, session, host, unowned, observed=None):
        self.require_pid_namespace(observed.get('pid_namespace') if observed is not None else CURRENT_PID_NAMESPACE)
        if observed is not None and self.original_exit(expected, observed):
            return 'gone'
        current = self.read_process(expected.pid, boundaries)
        self.note_identity_loss(expected, current, observed)
        if observed is not None:
            if current.kind == 'CONFIRMED_ABSENT' and self.numeric_absence_blocked(observed, expected.pid):
                return 'unavailable'
        result = self.process_state(expected, current, boundaries, session, host, unowned, require_host=False, retained=True)
        if observed is not None and result == 'gone':
            self.resolve_process(observed, expected.pid, current.proof or 'matching_birth_zombie')
        return result

    @guarded
    def descendant_lineage(self, member, census, owners, session):
        """A candidate chain can be unresolved without becoming signal authority."""
        chain, seen, verdict, group = ([], set(), 'CLEAR', member.pgid)
        while member.pid not in seen:
            seen.add(member.pid)
            chain.append(member)
            if member.pid in owners:
                return (chain, verdict)
            if not self.our_uid(member):
                return (chain, 'UNKNOWN')
            selection = self.descendant_verdict(member.argv, session)
            if selection == 'OTHER':
                return ([], 'OTHER')
            if selection == 'HOLD':
                verdict = 'HOLD'
            member = census.get(member.ppid)
            if member is None or member.pgid != group:
                return (chain, 'UNKNOWN')
        return (chain, 'UNKNOWN')

    @guarded
    def descendant_chain(self, member, census, owners, session):
        chain, verdict = self.descendant_lineage(member, census, owners, session)
        return chain if verdict == 'CLEAR' else []

    @guarded
    def process_depth(self, member, census):
        seen = set()
        while member.pid not in seen:
            seen.add(member.pid)
            member = census.get(member.ppid)
            if member is None:
                break
        return len(seen)

    @contextmanager
    def directory_descriptor(self, path, create=False, durable_from=None, verify=False, witnesses=None):
        """Pin every directory in the chain. A pathname check cannot protect a subsequent open."""
        require(self.launch_descriptor_capable(), 'descriptors unsupported')
        path = safe_path(path)
        if witnesses is not None:
            require(len(path.parts) <= MAX_NAMESPACE_DEPTH, 'endpoint namespace exceeds depth limit')
            verify = True
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors, edges = ([fd] if verify else [], [])
        try:
            current = Path(path.anchor)
            for part in path.parts[1:]:
                current = current / part
                if create:
                    made = False
                    try:
                        os.mkdir(part, 448, dir_fd=fd)
                    except FileExistsError:
                        pass
                    else:
                        made = True
                    if made or (durable_from is not None and (current == durable_from or durable_from in current.parents)):
                        os.fsync(fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                if verify:
                    descriptors.append(child)
                    info = os.fstat(child)
                    edges.append((fd, part, (info.st_dev, info.st_ino)))
                else:
                    os.close(fd)
                fd = child
            if witnesses is not None:
                witnesses.extend(edges)
            yield fd
            for parent, name, identity in edges if witnesses is None else ():
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity, 'directory namespace changed while inspecting')
        finally:
            for descriptor in reversed(descriptors) if verify else (fd,):
                os.close(descriptor)

__all__ = ['SessionRefused', 'UnsupportedPlatform', 'CustodyBusy', 'PidNamespaceUnavailable', 'PidfdUnavailable', 'CustodyUnavailable', 'CensusUnavailable', 'LaunchRecordLimit', 'CustodyExitUnproven', 'guarded', 'require', 'text', 'integer', 'safe_path', 'quoted', 'safe_reason', 'MAX_RECORDS', 'ENDPOINT_NAMESPACE_CHANGED', 'MAX_NAMESPACE_DEPTH', 'MAX_NAMESPACE_MANIFEST', 'PID_NAMESPACE_REFUSAL', 'CURRENT_PID_NAMESPACE', 'PIDFD_REFUSAL', 'OWNING_CHAIN_REFUSAL', 'KILL_WAIT_SECONDS', 'POLL_SECONDS', 'STOP_EXIT_PROOFS', 'STOP_COVERAGE', 'ROOT_STOP', 'MAILBOX_WAKE_PENDING', 'CLEANUP_BINDING_CHANGED', 'NO_EXPECTED_BINDING', 'STATUS_SCHEMA', 'ProcessSnapshot', 'ProcessObservation', 'ProcessIdentity', 'IdentityWitness', 'StoredProcess', 'ProcessCensus', 'binding_identity', 'metadata_json', 'process_identity', 'remember_census_identity', 'running_pid_namespace', 'same_process_identity', 'validate_pid_namespace', 'SessionCensus', 'PROCESS_IDENTITY_FIELDS', 'STORED_PROCESS_FIELDS']
