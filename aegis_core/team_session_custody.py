"""Endpoint fences, resume/wake records and durable original-instance custody.

All cross-family helpers are supplied by the runtime adapter.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import uuid

from aegis_core import kernel_identity
from aegis_core.team_session_census import (
    SessionRefused,
    UnsupportedPlatform,
    CustodyBusy,
    PidNamespaceUnavailable,
    PidfdUnavailable,
    CustodyUnavailable,
    CensusUnavailable,
    LaunchRecordLimit,
    CustodyExitUnproven,
    guarded,
    require,
    text,
    integer,
    safe_path,
    quoted,
    safe_reason,
    MAX_RECORDS,
    ENDPOINT_NAMESPACE_CHANGED,
    MAX_NAMESPACE_DEPTH,
    MAX_NAMESPACE_MANIFEST,
    PID_NAMESPACE_REFUSAL,
    CURRENT_PID_NAMESPACE,
    PIDFD_REFUSAL,
    OWNING_CHAIN_REFUSAL,
    KILL_WAIT_SECONDS,
    POLL_SECONDS,
    STOP_EXIT_PROOFS,
    STOP_COVERAGE,
    ROOT_STOP,
    MAILBOX_WAKE_PENDING,
    CLEANUP_BINDING_CHANGED,
    NO_EXPECTED_BINDING,
    STATUS_SCHEMA,
    ProcessSnapshot,
    ProcessObservation,
    ProcessIdentity,
    PROCESS_IDENTITY_FIELDS,
    STORED_PROCESS_FIELDS,
    IdentityWitness,
    StoredProcess,
    ProcessCensus,
    binding_identity,
    metadata_json,
    process_identity,
    remember_census_identity,
    running_pid_namespace,
    same_process_identity,
    validate_pid_namespace,
    SessionCensus,
)

class EndpointFence:
    """The locked descriptor and every witnessed namespace edge; no global descriptor registry."""

    def __init__(self, runtime, descriptor, directory, edges, anchor):
        self.runtime = runtime
        require(type(edges) in (list, tuple) and len(edges) < MAX_NAMESPACE_DEPTH)
        self.fd, self.directory, self.edges, self.anchor = (descriptor, directory, tuple(edges), anchor)
        root = os.fstat(edges[0][0] if edges else directory)
        self.identities = ((root.st_dev, root.st_ino), *(identity for _, _, identity in edges))
        require(len(self.identities) <= MAX_NAMESPACE_DEPTH and all((type(value) is int and 0 <= value < 2 ** 64 for pair in self.identities for value in pair)), ENDPOINT_NAMESPACE_CHANGED)

    def __index__(self):
        return self.fd

    def __str__(self):
        return str(self.fd)

    def fileno(self):
        return self.fd

    def check(self):
        try:
            root = os.stat(self.anchor, follow_symlinks=False)
            require(stat.S_ISDIR(root.st_mode) and (root.st_dev, root.st_ino) == self.identities[0], ENDPOINT_NAMESPACE_CHANGED)
            for index, (parent, name, identity) in enumerate(self.edges):
                held = os.fstat(parent)
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require((held.st_dev, held.st_ino) == self.identities[index] and stat.S_ISDIR(current.st_mode) and ((current.st_dev, current.st_ino) == identity), ENDPOINT_NAMESPACE_CHANGED)
            locked, directory = (os.fstat(self.fd), os.fstat(self.directory))
            require(stat.S_ISDIR(locked.st_mode) and (locked.st_dev, locked.st_ino) == (directory.st_dev, directory.st_ino) == self.identities[-1], ENDPOINT_NAMESPACE_CHANGED)
        except (OSError, ValueError):
            raise SessionRefused(ENDPOINT_NAMESPACE_CHANGED) from None

    def manifest(self):
        return json.dumps(self.identities, separators=(',', ':'))

    def require_manifest(self, raw):
        try:
            require(isinstance(raw, str) and len(raw) <= MAX_NAMESPACE_MANIFEST and raw.isascii(), ENDPOINT_NAMESPACE_CHANGED)
            value = metadata_json(raw.encode('ascii'), 'endpoint namespace')
            require(isinstance(value, list) and len(value) == len(self.identities) and all((isinstance(pair, list) and len(pair) == 2 and all((type(number) is int and 0 <= number < 2 ** 64 for number in pair)) for pair in value)), ENDPOINT_NAMESPACE_CHANGED)
            require(tuple((tuple(pair) for pair in value)) == self.identities, ENDPOINT_NAMESPACE_CHANGED)
        except (ValueError, RecursionError):
            raise SessionRefused(ENDPOINT_NAMESPACE_CHANGED) from None

class StopCustody:
    """Endpoint-local, pre-effect custody. A lost launcher must not lose a possibly signalled orphan.

    Descriptors cannot survive a new invocation. Recovery therefore uses the original boot/birth/raw/UID
    evidence and retains the numeric-PID residual race; an observed replacement latches loss of identity.
    The lock serializes read/merge/write, and the hidden subdirectory is outside immutable launch records.
    """

    @guarded
    def __init__(self, runtime, launches, endpoint, binding, create=True):
        self.runtime = runtime
        runtime.endpoint_parts(endpoint)
        self.base = safe_path(launches.base if hasattr(launches, 'base') else launches)
        self.endpoint = endpoint
        self.folder = safe_path(self.base / 'launches' / quoted(endpoint) / '.stop-custody')
        self.path, self.binding = (self.folder / 'state.json', binding)
        self.fd, self.directory_fd, self.parent_fd = (None, None, None)
        self.namespace = []
        self.entered = False

    def __enter__(self):
        self.entered = True
        return self

    @contextmanager
    def read_directory(self):
        if self.directory_fd is not None:
            yield self.directory_fd
        else:
            with self.runtime.directory_descriptor(self.folder, verify=True) as directory:
                yield directory

    @guarded
    def prepare(self):
        try:
            self.prepare_directory()
        except BaseException:
            self.close()
            raise

    def prepare_directory(self):
        require(self.runtime.launch_descriptor_capable(), 'descriptors unsupported')
        if self.directory_fd is None:
            fd = os.open(self.folder.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.namespace.append((self.folder.anchor, fd))
            current = Path(self.folder.anchor)
            for part in self.folder.parts[1:]:
                current = current / part
                made = False
                try:
                    os.mkdir(part, 448, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    made = True
                durable = self.folder.parent.parent
                if made or current == durable or durable in current.parents:
                    os.fsync(fd)
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                self.namespace.append((part, fd))
            self.parent_fd, self.directory_fd = (self.namespace[-2][1], self.namespace[-1][1])
        info = os.fstat(self.directory_fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 448, 'invalid stop custody directory')
        self.check_namespace()

    @guarded
    def check_namespace(self):
        for index in range(1, len(self.namespace)):
            name, child = self.namespace[index]
            try:
                info = os.stat(name, dir_fd=self.namespace[index - 1][1], follow_symlinks=False)
            except FileNotFoundError as exc:
                raise SessionRefused('stop custody namespace changed') from exc
            require(stat.S_ISDIR(info.st_mode) and self.directory_identity(info) == self.directory_identity(os.fstat(child)), 'stop custody namespace changed')

    @guarded
    def lock(self):
        require(self.runtime.launch_descriptor_capable(), 'descriptors unsupported')
        import fcntl
        try:
            with self.read_directory() as directory:
                self.fd = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 384, dir_fd=directory)
            self.private(os.fstat(self.fd))
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise CustodyBusy() from exc
            return self
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
            self.fd = None
            raise

    def __exit__(self, *unused):
        self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        for _, descriptor in reversed(self.namespace):
            os.close(descriptor)
        self.namespace.clear()
        self.directory_fd = self.parent_fd = None

    @staticmethod
    def private(info):
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and (stat.S_IMODE(info.st_mode) == 384) and (info.st_nlink == 1), 'invalid stop custody file')

    def boot(self):
        return self.runtime.identity.boot_id()

    @staticmethod
    def encode(facts):
        require(type(facts) is dict and len(facts) <= len(STORED_PROCESS_FIELDS) + 3)
        facts = dict(facts)
        facts.pop('argv', None)
        raw = facts.pop('cmdline', None)
        if raw is not None:
            facts['cmdline_sha256'] = hashlib.sha256(raw).hexdigest()
        return facts

    @staticmethod
    def decode(facts):
        require(isinstance(facts, dict), 'invalid stop custody evidence')
        allowed = set(STORED_PROCESS_FIELDS) | {'coherent_birth', 'exit_observed'}
        require(facts.keys() <= allowed, 'unexpected stop custody evidence')
        facts = dict(facts)
        for key, value in facts.items():
            if key in ('pid', 'pgid', 'ppid', 'uid', 'euid'):
                ceiling = 2 ** 22 - 1 if key in ('pid', 'pgid', 'ppid') else 2 ** 32 - 2
                require(type(value) is int and (1 if key == 'pid' else 0) <= value <= ceiling, 'invalid stop custody ' + key)
            elif key in ('coherent_birth', 'exit_observed'):
                require(type(value) is bool, 'invalid stop custody ' + key)
            elif key == 'cmdline_sha256':
                require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None, 'invalid stop custody cmdline digest')
            elif key == 'state':
                require(isinstance(value, str) and value in tuple('RSDZTtXxKWPI') and (len(value) == 1), 'invalid stop custody state')
            elif key == 'start_time':
                require(isinstance(value, str) and re.fullmatch('[0-9]{1,20}', value) is not None and (0 < int(value) < 2 ** 64), 'invalid stop custody start_time')
            else:
                require(isinstance(value, str) and value and ('\x00' not in value), 'invalid stop custody ' + key)
        return facts

    @guarded
    def read(self):
        try:
            return self.read_evidence()
        except (PidNamespaceUnavailable, CustodyExitUnproven):
            raise
        except (ValueError, OSError, KeyError, UnicodeError, RecursionError) as exc:
            raise SessionRefused(self.runtime.custody_refusal(self.base, self.endpoint, exc)) from exc

    @guarded
    def read_evidence(self):
        with self.runtime.custody_namespace(self.base, self.endpoint) as present:
            if not present:
                return None
            return self.read_pinned_evidence()

    @guarded
    def read_pinned_evidence(self):
        """Read and validate without creating a directory/lock or interpreting unreadability as absence."""
        try:
            with self.read_directory() as directory:
                directory_info = os.fstat(directory)
                require(directory_info.st_uid == os.geteuid() and stat.S_IMODE(directory_info.st_mode) == 448, 'invalid stop custody directory')
                try:
                    os.stat('state.json', dir_fd=directory, follow_symlinks=False)
                    try:
                        fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                    except FileNotFoundError as exc:
                        raise SessionRefused('stop custody disappeared while reading') from exc
                    try:
                        info = os.fstat(fd)
                        self.private(info)
                        require(info.st_size <= 262144, 'invalid stop custody bytes: bounded ASCII required')
                        with self.runtime.descriptor_stream(os.dup(fd), 'rb') as stream:
                            raw = stream.read(262145)
                        require(len(raw) <= 262144 and raw.isascii(), 'invalid stop custody bytes: bounded ASCII required')
                        require(self.identity(os.fstat(fd)) == self.identity(info), 'stop custody changed while reading')
                        require(self.identity(os.stat("state.json", dir_fd=directory, follow_symlinks=False)) ==
                                self.identity(info), 'stop custody replaced while reading')
                    finally:
                        os.close(fd)
                finally:
                    require(self.identity(os.fstat(directory)) == self.identity(directory_info), 'stop custody directory changed while reading')
        except FileNotFoundError:
            return None
        saved = metadata_json(raw, 'stop custody')
        entries = self.decode_record(saved)
        namespace = saved.get('pid_namespace')
        attempted = [entry['pid'] for entry, _, _ in entries if entry['attempted']]
        self.runtime.require_pid_namespace(namespace, attempted)
        boot = self.boot()
        if boot is not None and saved['boot'] != boot:
            require(not saved['active'], 'stop custody boot changed with active evidence: ' + str(self.path))
        for entry, expected, partial in entries:
            if not entry['resolved']:
                continue
            self.runtime.require_pid_namespace(namespace, attempted)
            birth = expected.start_time if expected is not None else partial.get('start_time') if partial.get('coherent_birth') else None
            current = self.runtime.read_process(entry['pid'])
            self.runtime.require_pid_namespace(namespace, attempted)
            if not self.runtime.procfs_exit_evidence_supported(current):
                raise CustodyExitUnproven(self.base, self.endpoint, entry['pid'], attempted, unsupported=True)
            if current.kind == 'CONFIRMED_ABSENT':
                continue
            row = current.snapshot if current.kind == 'PRESENT' else None
            original = expected._asdict() if expected is not None else partial
            if row is not None and birth is not None and (row.start_time == birth) and row.state.startswith('Z') and all((original.get(key) is None or original[key] == getattr(row, key) for key in ('uid', 'euid'))):
                continue
            facts = current.partial or {}
            if birth is not None and facts.get('coherent_birth') and (facts.get('start_time') == birth) and facts.get('exit_observed') and all(original.get(key) is None or original[key] == facts.get(key) for key in ('uid', 'euid')):
                continue
            raise CustodyExitUnproven(self.base, self.endpoint, entry['pid'], attempted)
        self.runtime.require_pid_namespace(namespace, attempted)
        return (saved, entries)

    @guarded
    def decode_record(self, saved):
        """One schema for every publication and read; physical exit validation remains read-time work."""
        self.exact_fields(saved, ('schema', 'binding', 'boot', 'active', 'entries', 'coverage', *(('pid_namespace',) if isinstance(saved, dict) and 'pid_namespace' in saved else ()), *(('groups',) if isinstance(saved, dict) and 'groups' in saved else ())))
        if saved.get('pid_namespace') is not None:
            validate_pid_namespace(saved['pid_namespace'])
        groups = saved.get('groups', [])
        require(isinstance(groups, list) and len(groups) <= MAX_RECORDS and all((type(group) is int and 0 < group < 2 ** 22 for group in groups)) and (groups == sorted(set(groups))), 'invalid stop custody groups')
        require(saved['schema'] == 'aegis.hierarchy-stop-custody/v2' and type(saved['active']) is bool and isinstance(saved['entries'], list) and (len(saved['entries']) <= MAX_RECORDS) and (saved['coverage'] in STOP_COVERAGE), 'invalid stop custody')
        require(saved['boot'] is None or (isinstance(saved['boot'], str) and saved['boot']), 'stop custody boot identity unavailable')
        self.exact_fields(saved['binding'], ('host', 'session', 'generation'))
        require(saved['binding']['host'] in self.runtime.hosts.TEAM_HOSTS and text(saved['binding']['session'], 'stop custody session', 256), 'invalid stop custody binding')
        integer(saved['binding']['generation'], 'stop custody generation', maximum=2 ** 31 - 1)
        entries, seen, previous = ([], set(), {})
        for entry in saved['entries']:
            self.exact_fields(entry, ('pid', 'snapshot', 'partial', 'attempted', 'blocked', 'identity_lost', 'resolved'))
            pid = entry['pid']
            require(type(pid) is int and 0 < pid < 2 ** 22, 'invalid stop custody pid')
            require(all((type(entry[key]) is bool for key in ('attempted', 'blocked', 'identity_lost'))) and (entry['resolved'] is None or entry['resolved'] in STOP_EXIT_PROOFS), 'invalid stop custody state')
            facts = self.decode(entry['snapshot']) if entry['snapshot'] is not None else None
            if facts is not None:
                require(facts.keys() == set(STORED_PROCESS_FIELDS) and facts['pid'] == pid, 'invalid stop custody snapshot')
            require(not entry['attempted'] or facts is not None, 'attempted stop custody has no identity')
            partial = self.decode(entry['partial'])
            key = custody_instance(entry)
            require(key not in seen and (pid not in previous or previous[pid]), 'invalid stop custody pid')
            seen.add(key)
            previous[pid] = bool(entry['resolved'])
            entries.append((entry, StoredProcess(**facts) if facts is not None else None, partial))
        if not saved['active']:
            require(not groups and saved['coverage'] is None and all((entry['resolved'] for entry, _, _ in entries)), 'inactive stop custody has unresolved evidence')
        return entries

    @staticmethod
    def exact_fields(record, names):
        require(isinstance(record, dict) and record.keys() == set(names), 'invalid stop custody fields')

    @guarded
    def restore(self, observed, attempted):
        fresh = {key: observed[key] for key in ('census', 'argv_boundaries')}
        fresh.update({key: dict(observed[key]) for key in ('candidates', 'initial_unavailable', 'unresolved')})
        retained = self.read()
        if retained is None:
            return
        saved, entries = retained
        self.runtime.require_pid_namespace(saved.get('pid_namespace'))
        self.runtime.require_pid_namespace(observed.get('pid_namespace', CURRENT_PID_NAMESPACE))
        observed['pid_namespace'] = saved['pid_namespace']
        observed['committed_exits'] = {custody_instance(entry) for entry, _, _ in entries if entry['resolved']}
        observed['retained_custody'] = True
        observed['custody_boot'] = saved['boot']
        observed['retained_exit_evidence'] = bool(entries) and (not saved['active'])
        if not saved['active']:
            return
        observed['retained_active'] = True
        for group in saved.get('groups', ()):
            self.runtime.retain_group(observed, group)
        observed['recovered'] = {entry['pid'] for entry, _, _ in entries if entry['attempted']}
        observed['checkpoint_pending'] = True
        require(saved['binding'] == self.binding, self.runtime.custody_refusal(self.base, self.endpoint, 'unresolved stop custody belongs to another binding'))
        latest = {entry['pid']: (entry, expected, partial) for entry, expected, partial in entries}
        for entry, _, _ in entries:
            if latest[entry['pid']][0] is not entry:
                require(entry['resolved'] is not None, 'unresolved prior process incarnation')
                observed.setdefault('retired_instances', {})[custody_instance(entry)] = entry
                self.runtime.remember_retired_group(observed, entry)
                if entry['attempted']:
                    observed.setdefault('historical_pids', set()).add(entry['pid'])
        entries = list(latest.values())
        for entry, expected, partial in entries:
            pid = entry['pid']
            observed['candidates'][pid] = expected
            observed['initial_unavailable'][pid] = partial
            if entry['attempted']:
                attempted.add(pid)
            for key in ('blocked', 'identity_lost'):
                if entry[key]:
                    observed[key].add(pid)
            if entry['resolved']:
                observed['resolved'][pid] = entry['resolved']
                observed['unresolved'].pop(pid, None)
            else:
                self.runtime.unresolved(observed, pid, 'recovery', 'original_instance_pending')
        self.runtime.advance_resolved_instances(observed, fresh)
        self.runtime.latch_census_replacements(observed)
        for entry, expected, partial in entries:
            if entry['resolved']:
                continue
            pid = entry['pid']
            current = observed['census'].get(pid)
            if expected is not None and current is not None and (self.runtime.process_state(expected, current, observed['argv_boundaries'], self.binding['session'], self.binding['host'], [], require_host=False, retained=entry['attempted']) == 'changed'):
                observed['resolved'].pop(pid, None)
                self.runtime.unresolved(observed, pid, 'recovery', 'original_instance_replaced')
                self.runtime.latch_blocked(observed, pid, current.start_time != expected.start_time)

    @guarded
    def save(self, observed, attempted, active=True):
        namespace = self.runtime.require_pid_namespace(observed.get('pid_namespace', CURRENT_PID_NAMESPACE))
        observed['pid_namespace'] = namespace
        self.runtime.remember_candidate_groups(observed)
        require(observed.get('coverage') in STOP_COVERAGE, 'invalid stop custody coverage')
        attempted = set(attempted) | observed.get('possible_attempts', set())
        retired = observed.get('retired_instances', {})
        require(len(retired) + len(observed['candidates']) <= MAX_RECORDS, 'stop custody exceeds evidence limit')
        instances = dict(retired)
        for pid, row in sorted(observed['candidates'].items()):
            require(len(instances) < MAX_RECORDS, 'stop custody exceeds evidence limit')
            entry = self.runtime.custody_entry(observed, pid, attempted)
            require(custody_instance(entry) not in instances, 'duplicate stop custody incarnation')
            instances[custody_instance(entry)] = entry
        observed['instances'] = instances
        entries = list(instances.values())
        boot = self.boot()
        if boot is None:
            boot = observed.get('custody_boot')
        data = dict(schema='aegis.hierarchy-stop-custody/v2', binding=self.binding, boot=boot, active=active, pid_namespace=namespace, entries=entries, coverage=observed.get('coverage'))
        require(len(observed.get('owned_groups', ())) <= MAX_RECORDS, 'stop custody exceeds group limit')
        groups = sorted(observed.get('owned_groups', ())) if active else []
        if groups:
            data['groups'] = groups
        self.decode_record(data)
        require(serialized_size(data) < 262144, 'stop custody exceeds evidence limit')
        buffer = bytearray()
        for chunk in json.JSONEncoder(sort_keys=True).iterencode(data):
            require(len(buffer) + len(chunk) < 262144, 'stop custody exceeds evidence limit')
            buffer.extend(chunk.encode('ascii'))
        buffer.append(10)
        raw = bytes(buffer)
        self.runtime.require_pid_namespace(namespace)
        self.prepare()
        if self.entered and self.fd is None:
            self.lock()
        temporary = '.' + uuid.uuid4().hex + '.tmp'
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.directory_fd)
        try:
            with self.runtime.descriptor_stream(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                written = os.fstat(stream.fileno())
            os.replace(temporary, 'state.json', src_dir_fd=self.directory_fd, dst_dir_fd=self.directory_fd)
            published = self.commit_identity()
            require(published[:3] == (written.st_dev, written.st_ino, len(raw)), 'stop custody changed during durable commit')
            os.fsync(self.directory_fd)
            self.check_namespace()
            require(self.commit_identity() == published and self.read_committed_bytes(published) == raw, 'stop custody changed during durable commit')
            observed['custody_boot'] = boot
        finally:
            try:
                os.unlink(temporary, dir_fd=self.directory_fd)
            except FileNotFoundError:
                pass

    @guarded
    def commit_identity(self):
        self.check_namespace()
        info = os.stat('state.json', dir_fd=self.directory_fd, follow_symlinks=False)
        self.private(info)
        return self.identity(info)

    @staticmethod
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)

    @staticmethod
    def directory_identity(info):
        return (info.st_dev, info.st_ino)

    @guarded
    def read_committed_bytes(self, expected):
        with self.read_directory() as directory:
            require(self.directory_identity(os.fstat(directory)) == self.directory_identity(os.fstat(self.directory_fd)), 'stop custody directory changed during durable commit')
            fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                self.private(info)
                raw = os.read(fd, 262145)
                require(self.identity(info) == expected and self.identity(os.fstat(fd)) == expected, 'stop custody changed during durable commit')
                return raw
            finally:
                os.close(fd)

class CustodyRuntime(SessionCensus):
    @guarded
    def stop_custody(self, launches, endpoint, binding, create=True):
        return StopCustody(self, launches, endpoint, binding, create=create)

    def running_wake_recovery(self, base, endpoint):
        return "running wake unavailable; preserve evidence and reconcile before retrying"

    def custody_refusal(self, base, endpoint, cause=None):
        return "stop custody unavailable; preserve evidence and reconcile before retrying"


    @guarded
    def running_wake_publication_capable(self):
        return self.launch_descriptor_capable()

    @guarded
    def resume_admission_name(self, identifier):
        return isinstance(identifier, str) and len(identifier) == 55 and (re.fullmatch('[0-9]{8}T[0-9]{12}Z-[0-9a-f]{32}', identifier) is not None)

    @guarded
    def validate_resume_admission(self, record):
        StopCustody.exact_fields(record, ('schema', 'binding', 'at', 'admission_attempted', *(('failure',) if isinstance(record, dict) and 'failure' in record else ())))
        require(record.get('failure') in (None, 'host spawn failed'), 'invalid resume admission failure')
        require(record['schema'] == 'aegis.hierarchy-resume-admission/v1' and type(record['admission_attempted']) is bool and isinstance(record['at'], str) and (re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z', record['at']) is not None), 'invalid resume admission')
        StopCustody.exact_fields(record['binding'], ('host', 'session', 'generation'))
        require(record['binding']['host'] in self.hosts.TEAM_HOSTS, 'invalid resume admission host')
        text(record['binding']['session'], 'resume admission session', 256)
        integer(record['binding']['generation'], 'resume admission generation', maximum=2 ** 31 - 1)
        return record

    @guarded
    def read_resume_admission(self, base, endpoint, identifier):
        """Legacy histories have no sidecar. New metadata never changes their public record shape."""
        self.endpoint_parts(endpoint)
        if not self.resume_admission_name(identifier):
            return None
        require(self.launch_descriptor_capable(), 'resume admission descriptors unsupported on this platform')
        folder = Path(base) / 'launches' / quoted(endpoint) / '.resume-admissions'
        try:
            with self.directory_descriptor(folder, verify=True) as directory:
                fd = os.open(identifier, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with self.descriptor_stream(fd, 'rb') as stream:
                    before = os.fstat(fd)
                    StopCustody.private(before)
                    require(before.st_size <= 4096, 'resume admission exceeds evidence limit')
                    raw = stream.read(4097)
                    require(len(raw) <= 4096 and StopCustody.identity(os.fstat(fd)) == StopCustody.identity(before), 'resume admission changed or exceeds evidence limit')
                    require(StopCustody.identity(os.stat(identifier, dir_fd=directory, follow_symlinks=False)) == StopCustody.identity(before), 'resume admission replaced while reading')
            return self.validate_resume_admission(metadata_json(raw, 'launch record'))
        except FileNotFoundError:
            return None

    @guarded
    def write_resume_admission(self, launches, endpoint, identifier, known, at, attempted, spawn_failed=False):
        self.endpoint_parts(endpoint)
        require(self.launch_descriptor_capable(), 'resume admission descriptors unsupported on this platform')
        require(self.resume_admission_name(identifier), 'invalid resume admission identity')
        record = self.validate_resume_admission(dict(schema='aegis.hierarchy-resume-admission/v1', binding=known, at=at, admission_attempted=attempted, **{'failure': 'host spawn failed'} if spawn_failed else {}))
        raw = json.dumps(record, sort_keys=True).encode('ascii')
        require(len(raw) <= 4096, 'resume admission exceeds evidence limit')
        folder = launches.folder(endpoint) / '.resume-admissions'
        with self.directory_descriptor(folder, create=True, durable_from=launches.base / 'launches', verify=True) as directory:
            previous = self.read_resume_admission(launches.base, endpoint, identifier)
            require(previous is None or (previous['binding'] == known and previous['at'] == at), 'resume admission identity changed')
            temporary = '.admission-' + uuid.uuid4().hex
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=directory)
                with self.descriptor_stream(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
                os.rename(temporary, identifier, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
        return record

    @guarded
    def write_running_wake(self, launches, endpoint, known, wake_id, pid, expected=None):
        self.endpoint_parts(endpoint)
        require(self.running_wake_publication_capable(), 'running wake atomic publication unsupported on this platform')
        namespace = self.require_pid_namespace(running_pid_namespace(expected) if expected is not None else CURRENT_PID_NAMESPACE)
        observation = self.read_process(pid)
        row = observation.snapshot if observation.kind == 'PRESENT' else None
        record = dict(schema='aegis.hierarchy-running-wake/v3', binding=known, wake_id=wake_id, driver_pid=os.getpid(), host_pid=pid, pid_namespace=namespace, snapshot=StopCustody.encode(process_identity(row)._asdict()) if row is not None else None)
        self.validate_running_wake(record)
        self.require_pid_namespace(namespace)
        self.publish_wake_record(launches, endpoint, record, expected=expected)
        return record

    @contextmanager
    def descriptor_stream(self, fd, mode):
        """Own the descriptor even if constructing its non-owning stream fails."""
        try:
            with os.fdopen(fd, mode, closefd=False) as stream:
                yield stream
        except SessionRefused:
            raise
        except Exception:
            raise SessionRefused() from None
        finally:
            os.close(fd)

    @guarded
    def publish_wake_record(self, launches, endpoint, record, expected=None):
        self.endpoint_parts(endpoint)
        require(self.running_wake_publication_capable(), 'running wake atomic publication unsupported on this platform')
        self.validate_running_wake(record)
        name = '.running-wake'
        raw = json.dumps(record, sort_keys=True).encode('ascii')
        require(len(raw) <= 262144, 'running wake exceeds evidence limit')
        with self.directory_descriptor(launches.folder(endpoint), create=True, durable_from=launches.base / 'launches', verify=True):
            with self.launch_directory(launches.base, endpoint) as directory:
                temporary, published, identity = ('.running-wake-' + uuid.uuid4().hex + '.tmp', False, None)
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=directory)
                    with self.descriptor_stream(fd, 'wb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                        written = os.fstat(stream.fileno())
                        identity = (written.st_dev, written.st_ino)
                        if expected is None:
                            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
                        else:
                            require(self.read_running_wake(launches.base, endpoint) == expected, 'running wake identity changed')
                            os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
                        published = True
                        if expected is None:
                            os.unlink(temporary, dir_fd=directory)
                        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        require(stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity and (current.st_size == len(raw)), 'running wake changed during publication')
                        os.fsync(directory)
                except BaseException:
                    if published and expected is None:
                        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        require((current.st_dev, current.st_ino) == identity, 'running wake replaced during publication')
                        os.unlink(name, dir_fd=directory)
                    raise
                finally:
                    try:
                        os.unlink(temporary, dir_fd=directory)
                    except FileNotFoundError:
                        pass

    @guarded
    def validate_running_wake(self, record):
        StopCustody.exact_fields(record, ('schema', 'binding', 'wake_id', 'driver_pid', 'host_pid', 'snapshot', *(('pid_namespace',) if isinstance(record, dict) and 'pid_namespace' in record else ())))
        require(record['schema'] in ('aegis.hierarchy-running-wake/v1', 'aegis.hierarchy-running-wake/v2', 'aegis.hierarchy-running-wake/v3'), 'invalid running wake')
        StopCustody.exact_fields(record['binding'], ('host', 'session', 'generation'))
        require(record['binding']['host'] in self.hosts.TEAM_HOSTS, 'invalid running wake host')
        text(record['binding']['session'], 'running wake session', 256)
        integer(record['binding']['generation'], 'running wake generation', maximum=2 ** 31 - 1)
        require(isinstance(record['wake_id'], str) and re.fullmatch('wake-[0-9a-f]{32}', record['wake_id']) is not None, 'invalid running wake identity')
        integer(record['driver_pid'], 'running wake pid', maximum=2 ** 22 - 1)
        if record.get('pid_namespace') is not None:
            validate_pid_namespace(record['pid_namespace'])
        if record['schema'] == 'aegis.hierarchy-running-wake/v2':
            require(record['host_pid'] is None and record['snapshot'] is None, 'invalid wake admission')
        elif record['schema'] != 'aegis.hierarchy-running-wake/v3' or record['host_pid'] is not None:
            integer(record['host_pid'], 'running wake pid', maximum=2 ** 22 - 1)
        else:
            require(record['snapshot'] is None, 'invalid wake admission')
        if record['snapshot'] is not None:
            facts = StopCustody.decode(record['snapshot'])
            names = STORED_PROCESS_FIELDS if record['schema'] == 'aegis.hierarchy-running-wake/v1' else PROCESS_IDENTITY_FIELDS
            require(facts.keys() == set(names) and facts['pid'] == record['host_pid'], 'invalid running wake snapshot')
        return record

    @guarded
    def read_running_wake(self, base, endpoint):
        try:
            raw = self.read_launch_record(base, endpoint, '.running-wake')
            return self.validate_running_wake(metadata_json(raw, 'launch record')) if raw is not None else None
        except (ValueError, OSError, KeyError, UnicodeError, RecursionError) as exc:
            raise SessionRefused(self.running_wake_recovery(base, endpoint)) from exc

    @guarded
    def clear_running_wake(self, base, endpoint, expected):
        with self.launch_directory(base, endpoint) as directory:
            current = self.read_running_wake(base, endpoint)
            if current is None:
                return
            require(current == expected, 'running wake identity changed')
            self.require_pid_namespace(running_pid_namespace(current))
            os.unlink('.running-wake', dir_fd=directory)
            os.fsync(directory)

    @contextmanager
    def directory_fence(self, path, create=False, admission=None):
        require(self.launch_descriptor_capable(), 'endpoint namespace descriptors unsupported on this platform')
        path, edges = (Path(path), [])
        with ExitStack() as stack:
            try:
                directory = stack.enter_context(self.directory_descriptor(path, create=create, witnesses=edges))
                descriptor = directory if admission is None else admission
                fence = EndpointFence(self, descriptor, directory, edges, path.anchor)
            except OSError:
                raise SessionRefused(ENDPOINT_NAMESPACE_CHANGED) from None
            fence.check()
            yield fence
            fence.check()

    @contextmanager
    def endpoint_namespace(self, root, endpoint, create=False, admission=None):
        self.endpoint_parts(endpoint)
        with self.directory_fence(Path(root) / 'bindings' / endpoint, create=create, admission=admission) as fence:
            yield fence

    @guarded
    def mailbox_wake_inspection_capable(self):
        return self.launch_descriptor_capable()

    @guarded
    def mailbox_wake_pending(self, mailbox, endpoint):
        """Inspect admission, never marker content or its symlink target. Call under the writer fence."""
        require(self.mailbox_wake_inspection_capable(), 'mailbox wake inspection unsupported on this platform; preserve the worktree and reconcile the marker manually')
        self.endpoint_parts(endpoint)
        try:
            with self.directory_descriptor(mailbox.root, verify=True) as directory:
                try:
                    os.stat('.wake-' + quoted(endpoint) + '.lock', dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                return True
        except (ValueError, OSError) as exc:
            raise SessionRefused('mailbox wake inspection unavailable; preserve the worktree and reconcile the producer and marker before retrying') from exc

    @contextmanager
    def stop_endpoint_lock(self, root, endpoint, create=False, blocking=False):
        """Shared with handoff. Lock order: mailbox writer (handoff only), endpoint, custody.

        Bindings already have a directory. Locking that inode creates no file for an otherwise no-op stop.
        Direct mailbox bind/draft callers are outside this serialization contract.
        """
        with self.endpoint_namespace(root, endpoint, create=create) as fence:
            import fcntl
            try:
                fcntl.flock(fence.fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError as exc:
                raise CustodyBusy() from exc
            fence.check()
            yield fence

    @guarded
    def require_resolved_custody(self, base, endpoint):
        if self.unresolved_stop_custody(base, endpoint):
            retained = self.stop_custody(base, endpoint, None, create=False).read()
            lost = retained is not None and any((entry['identity_lost'] for entry, _, _ in retained[1]))
            blocked = retained is not None and any((entry['blocked'] and (not entry['resolved']) for entry, _, _ in retained[1]))
            cause = 'original process identity lost' if lost else 'original process identity blocked' if blocked else None
            raise SessionRefused(self.custody_refusal(base, endpoint, cause))

    @contextmanager
    def recorded_endpoint_lock(self, launches, endpoint, identifier, action, known, **options):
        """Record admission failures without catching an outcome from inside the admitted operation."""
        with ExitStack() as stack:
            try:
                admission = stack.enter_context(self.stop_endpoint_lock(launches.mailbox.root, endpoint, **options))
            except (OSError, ValueError) as exc:
                launches.refuse(endpoint, identifier, action, safe_reason(exc), **known)
            yield admission

    @guarded
    def recorded_custody_check(self, launches, endpoint, identifier, action, known):
        try:
            self.require_resolved_custody(str(launches.base), endpoint)
        except (OSError, ValueError) as exc:
            launches.refuse(endpoint, identifier, action, safe_reason(exc), **known)

    @contextmanager
    def custody_namespace(self, base, endpoint):
        """Absence is witnessed beneath held parents, including every base ancestor."""
        with self.launch_directory(base, endpoint) as parent:
            if parent is None:
                yield False
                return
            try:
                child = os.open('.stop-custody', os.O_RDONLY | os.O_DIRECTORY |
                                     os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                yield False
                try:
                    os.stat('.stop-custody', dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return
                raise SessionRefused()
            except OSError:
                raise SessionRefused() from None
            try:
                before = os.fstat(child)
                yield True
                after = os.stat('.stop-custody', dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(after.st_mode) and (before.st_dev, before.st_ino) ==
                        (after.st_dev, after.st_ino))
            finally:
                os.close(child)

    @guarded
    def unresolved_stop_custody(self, base, endpoint):
        """Read-only consumer check. False means absent or validated resolved custody; unknown always refuses.

        The explicit base/endpoint confines discovery. A session-only census cannot find an orphan retained by
        an interrupted stop, and checking this must not create state in a legacy base with no custody file.
        """
        try:
            base = safe_path(text(base, 'base'))
            self.endpoint_parts(endpoint)
            retained = self.stop_custody(base, endpoint, None, create=False).read()
            return retained[0]['active'] if retained is not None else False
        except (ValueError, OSError, KeyError, UnicodeError, RecursionError) as exc:
            if safe_reason(exc).startswith('stop custody unavailable for ' + endpoint + ':'):
                raise
            raise SessionRefused(self.custody_refusal(base, endpoint, exc)) from exc


    @guarded
    def read_launch_record(self, base, endpoint, name):
        require(isinstance(name, str) and len(name) <= 255 and ('\x00' not in name) and (name.endswith('.json') or name == '.running-wake') and (name == Path(name).name), 'invalid launch record name')
        with self.launch_directory(base, endpoint) as directory:
            if name == '.running-wake' and directory is None:
                return None
            require(directory is not None, 'launch directory disappeared while reading')
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                if name == '.running-wake':
                    return None
                raise
            try:
                info = os.fstat(fd)
                if name == '.running-wake':
                    StopCustody.private(info)
                require(stat.S_ISREG(info.st_mode) and info.st_size <= 262144, 'launch record exceeds evidence limit')
                with self.descriptor_stream(os.dup(fd), 'rb') as stream:
                    raw = stream.read(262145)
                require(len(raw) <= 262144 and StopCustody.identity(os.fstat(fd)) == StopCustody.identity(info), 'launch record changed or exceeds evidence limit')
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                require(StopCustody.identity(current) == StopCustody.identity(info), 'launch record replaced while reading')
                return raw
            finally:
                os.close(fd)


def custody_instance(entry):
    facts = entry['snapshot'] if entry['snapshot'] is not None else entry['partial']
    birth = facts.get('start_time') if entry['snapshot'] is not None or facts.get('coherent_birth') else None
    return (entry['pid'], birth)


@guarded
def serialized_size(value, depth=0):
    """Exact ASCII JSON size with default separators, before encoder allocation."""
    require(depth <= 8)
    if value is None:
        return 4
    if type(value) is bool:
        return 4 if value else 5
    if type(value) is int:
        require(-(2 ** 64) < value < 2 ** 64)
        return len(str(value))
    if type(value) is str:
        require(len(value) <= 262144)
        size = 2
        for char in value:
            point = ord(char)
            size += (2 if char in '\"\\\b\f\n\r\t' else 1 if 32 <= point < 127
                     else 6 if point <= 65535 else 12)
            require(size < 262144)
        return size
    require(type(value) in (dict, list) and len(value) <= MAX_RECORDS)
    size = 2
    if type(value) is dict:
        for index, (key, item) in enumerate(value.items()):
            require(type(key) is str)
            size += (2 if index else 0) + serialized_size(key, depth + 1) + 2 + serialized_size(item, depth + 1)
            require(size < 262144)
    else:
        for index, item in enumerate(value):
            size += (2 if index else 0) + serialized_size(item, depth + 1)
            require(size < 262144)
    return size


def read_resume_admission(runtime, base, endpoint, identifier):
    """Resume adapters share this record reader rather than re-defining its schema."""
    return runtime.read_resume_admission(base, endpoint, identifier)


def write_resume_admission(runtime, launches, endpoint, identifier, known, at, attempted, spawn_failed=False):
    return runtime.write_resume_admission(launches, endpoint, identifier, known, at, attempted, spawn_failed)


def validate_resume_admission(runtime, record):
    return runtime.validate_resume_admission(record)


class NamespaceOS:
    """Namespace fence for an injected producer's OS port; stop never signals groups.

    This preserves the producer seam in the ported range. StopRuntime's own
    delivery path exclusively uses pidfds and never delegates signals here.
    """
    def __init__(self, runtime, provider, namespace):
        self.runtime, self.provider, self.namespace = runtime, provider, namespace

    def __getattr__(self, name):
        return getattr(self.provider, name)

    def kill(self, pid, number):
        return self.dispatch(self.provider.kill, pid, number)

    def killpg(self, group, number):
        return self.dispatch(self.provider.killpg, group, number)

    @guarded
    def dispatch(self, operation, identifier, number):
        self.runtime.require_pid_namespace(self.namespace)
        try:
            result = operation(identifier, number)
        except OSError:
            self.runtime.require_pid_namespace(self.namespace)
            raise
        self.runtime.require_pid_namespace(self.namespace)
        return result


__all__ = ['EndpointFence', 'StopCustody', 'CustodyRuntime', 'custody_instance', 'serialized_size',
           'read_resume_admission', 'write_resume_admission', 'validate_resume_admission', 'NamespaceOS']
