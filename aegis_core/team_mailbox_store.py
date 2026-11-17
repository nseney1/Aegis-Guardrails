"""Mailbox storage: held roots, bounded reads, exclusive publication and locks.

Only owner-selected roots are trusted. Every component is opened relative to a
held directory with O_NOFOLLOW; a rename cannot redirect an in-flight operation.
The mailbox root and its parent are retained until close, so sibling briefs and
delivery ledgers have the same confinement boundary as the legacy wire format.
Reads never create state. Hard links, special files and writable directories
are refused. All descriptors have one closer; no fdopen wrapper is needed.
"""
from contextlib import contextmanager, nullcontext
import errno
import hashlib
import os
from pathlib import Path
import stat
from threading import Lock, local
import uuid
import weakref

try:
    import pwd
except ImportError:
    pwd = None

from aegis_core.workspace.layout import UserLayout
from aegis_core.team_mailbox_primitives import (
    BusyError, MailboxRefusal, MAX_BYTES, MAX_RECORDS, MAX_STATUS_EVIDENCE_BYTES, MAX_RELEASE_WARNINGS,
    SHA256, SLUG, LockReleaseWarning, bounded_tree, lock_path, matching, require, safe_path, strict_json, validate_warnings, witness_record,
)

__all__ = ["Store", "descriptor_supported", "initialize_store"]


def descriptor_supported():
    names = {function.__name__ for function in os.supports_dir_fd}
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and {"open", "mkdir", "link", "unlink", "stat", "rmdir"} <= names
            and os.scandir in os.supports_fd)


@contextmanager
def refusals():
    try:
        yield
    except OSError as error:
        reason = {errno.ENOENT: "missing", errno.EEXIST: "exists", errno.ELOOP: "unsafe_path",
                  errno.ENOTDIR: "unsafe_path"}.get(error.errno, "io")
        raise MailboxRefusal(reason) from None


def _close_all(descriptors):
    # Close once, including on a partially failed constructor.
    for fd in descriptors:
        try:
            os.close(fd)
        except OSError:
            pass


def _open_absolute(path):
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            parent, fd = fd, child
            os.close(parent)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _regular(info):
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, reason="unsafe_path")


def _private_directory(fd, *, mode=None):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022 and (mode is None or stat.S_IMODE(info.st_mode) == mode),
            reason="unsafe_path")


def _account_home():
    """Use the effective owner's account record, independently of process HOME."""
    require(pwd is not None, reason="missing")
    try:
        record = pwd.getpwuid(os.geteuid())
    except (KeyError, OSError):
        raise MailboxRefusal("missing") from None
    home = getattr(record, "pw_dir", None)
    require(type(home) is str and bool(home), reason="missing")
    try:
        return safe_path(home)
    except MailboxRefusal:
        raise MailboxRefusal("missing") from None


def _write(fd, raw):
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        require(count > 0, reason="io")
        view = view[count:]
    os.fsync(fd)


class _WitnessStage(str):
    """A synchronous host port can write only through its live stage descriptor."""
    def __new__(cls, path, store, fd):
        stage = super().__new__(cls, str(path))
        stage.store, stage.fd = store, fd
        return stage

    def _publish(self, raw, sha256):
        store = self.store
        require(getattr(store._local, "stage", None) is self
                and self.fd in getattr(store._local, "directories", ())
                and getattr(store._local, "evidence", None) is not None)
        path = Path(self) / (sha256 + ".status")
        if not store.exists(path, parent=self.fd):
            store.publish(path, raw, limit=MAX_STATUS_EVIDENCE_BYTES, parent=self.fd)
        require(hashlib.sha256(store.read(path, limit=MAX_STATUS_EVIDENCE_BYTES, parent=self.fd)).hexdigest() == sha256)
        return str(path)


class Store:
    """Use as a context or close explicitly. Paths are lexical names under held roots."""
    def __init__(self, root, *, delivery_roots=()):
        require(descriptor_supported(), reason="unsupported_platform")
        self.root = safe_path(root)
        require(type(delivery_roots) in (tuple, list) and len(delivery_roots) <= 256)
        self.delivery_roots = tuple(safe_path(path) for path in delivery_roots)
        self.fd = self.parent_fd = None
        self._local = local()
        self.warnings = []
        self._warnings_guard = Lock()
        self._warning_reservations = 0
        try:
            with refusals():
                self.parent_fd = _open_absolute(self.root.parent)
                _private_directory(self.parent_fd)
                self.fd = os.open(self.root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=self.parent_fd)
                _private_directory(self.fd)
            self._finalizer = weakref.finalize(self, _close_all, (self.fd, self.parent_fd))
        except BaseException:
            _close_all(fd for fd in (self.fd, self.parent_fd) if fd is not None)
            self.fd = self.parent_fd = None
            raise

    def __enter__(self):
        require(self.fd is not None, reason="closed")
        return self

    def __exit__(self, *error):
        self.close()

    def close(self):
        if self.fd is not None:
            self._finalizer()
            self.fd = self.parent_fd = None

    def _parts(self, path):
        require(self.fd is not None, reason="closed")
        path = safe_path(path)
        try:
            return self.fd, path.relative_to(self.root).parts
        except ValueError:
            try:
                return self.parent_fd, path.relative_to(self.root.parent).parts
            except ValueError:
                raise MailboxRefusal("unsafe_path") from None

    @contextmanager
    def creation(self, kind):
        """The validated caller declares which tree it is creating."""
        require(type(kind) is str and kind in ("mailbox", "delivery-ledger", "evidence-destination"))
        previous = getattr(self._local, "creation_kind", "evidence-destination")
        self._local.creation_kind = kind
        try:
            yield
        finally:
            self._local.creation_kind = previous

    def _leaf_only(self):
        return getattr(self._local, "creation_kind", "evidence-destination") == "evidence-destination"

    @contextmanager
    def _warning_listener(self, warnings):
        validate_warnings(warnings, limit=MAX_RELEASE_WARNINGS)
        previous = getattr(self._local, "warning_listeners", ())
        if warnings is None or warnings is self.warnings or any(warnings is sink for sink in previous):
            yield
            return
        self._local.warning_listeners = (*previous, warnings)
        try:
            yield
        finally:
            self._local.warning_listeners = previous

    def drain_warnings(self):
        """Drain the one Store sink without replacing its observable list."""
        with self._warnings_guard:
            result = self.warnings[:]
            self.warnings.clear()
            return result

    @contextmanager
    def _release_slot(self, path):
        current = getattr(self._local, "release_slot", None)
        if current is not None and current["path"] == path:
            yield current
            return
        with self._warnings_guard:
            require(len(self.warnings) + self._warning_reservations < MAX_RELEASE_WARNINGS, reason="too_large")
            for sink in getattr(self._local, "warning_listeners", ()):
                require(len(sink) + self._warning_reservations < MAX_RELEASE_WARNINGS, reason="too_large")
            self._warning_reservations += 1
        slot = None
        try:
            slot = {"path": path, "warning": LockReleaseWarning(path).as_dict(), "recorded": False}
            self._local.release_slot = slot
            yield slot
        finally:
            self._local.release_slot = current
            with self._warnings_guard:
                if slot is None or not slot["recorded"]:
                    self._warning_reservations -= 1

    def _record_release_warning(self, slot):
        with self._warnings_guard:
            if slot["recorded"]:
                return
            self.warnings.append(slot["warning"])
            self._warning_reservations -= 1
            slot["recorded"] = True
        for sink in getattr(self._local, "warning_listeners", ()):
            sink.append(slot["warning"])

    @contextmanager
    def evidence_transaction(self, warnings=None):
        """Owner first; nested operations share exclusion, commit and warnings."""
        with self._warning_listener(warnings):
            transaction = getattr(self._local, "evidence", None)
            if transaction is not None:
                yield transaction
                return
            transaction = {"committed": False}
            with self.owner_lock(transaction):
                self._local.evidence = transaction
                try:
                    yield transaction
                    transaction["committed"] = True
                finally:
                    self._local.evidence = None

    @contextmanager
    def _mutation_directory(self, path, create, **options):
        with self.evidence_transaction():
            if create and self._leaf_only() and path not in (self.root, self.root.parent) and options.get("parent") is None:
                options.pop("parent", None)
                with self.directory(path.parent) as parent:
                    with self.directory(path, create=True, parent=parent, **options) as fd:
                        yield fd
            else:
                with self.directory(path, create=create, **options) as fd:
                    yield fd

    def _directory_parts(self, path, create, verification, temporary, temporary_parent, parent, held):
        require(verification is None or type(verification) is dict and not create)
        base, parts = self._parts(path)
        active = getattr(self._local, "directories", set())
        require(type(held) is bool and (not held or parent is not None))
        if parent is not None:
            require(type(parent) is int and parent in active and temporary_parent is None)
            base, parts = parent, () if held else (safe_path(path).name,)
        if temporary_parent is not None:
            require(temporary and type(temporary_parent) is int and temporary_parent in active and not held)
            base, parts = temporary_parent, (safe_path(path).name,)
        require(not temporary or temporary_parent is not None or
                create and safe_path(path).parent == self.root)
        return base, parts, active

    @contextmanager
    def directory(self, path, create=False, *, verification=None, temporary=False, undo=None, temporary_parent=None,
                  parent=None, held=False):
        path = safe_path(path)
        if (create or temporary or undo is not None) and (getattr(self._local, "evidence", None) is None or
                create and self._leaf_only() and path not in (self.root, self.root.parent) and parent is None):
            with self._mutation_directory(path, create, verification=verification, temporary=temporary,
                                          undo=undo, temporary_parent=temporary_parent, parent=parent, held=held) as fd:
                yield fd
            return
        base, parts, active = self._directory_parts(path, create, verification, temporary, temporary_parent, parent, held)
        with refusals():
            fd = os.dup(base)
            created = []
            failed = True
            ready = False
            try:
                _private_directory(fd)
                if verification is not None:
                    info = os.fstat(fd)
                    verification.update(path=safe_path(path), chain=[(info.st_dev, info.st_ino)], names=[], tail=())
                for index, component in enumerate(parts):
                    if create:
                        anchor = os.dup(fd)
                        try:
                            os.mkdir(component, 0o700, dir_fd=fd)
                        except FileExistsError:
                            os.close(anchor)
                        except BaseException:
                            os.close(anchor)
                            raise
                        else:
                            created.append((anchor, component))
                    try:
                        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    except FileNotFoundError:
                        if verification is None:
                            raise
                        verification["tail"] = parts[index:]
                        break
                    parent, fd = fd, child
                    os.close(parent)
                    _private_directory(fd)
                    if verification is not None:
                        info = os.fstat(fd)
                        verification["chain"].append((info.st_dev, info.st_ino))
                        verification["names"].append(component)
                require(not temporary or temporary_parent is not None or len(created) == 1, reason="exists")
                self._local.directories = active | {fd}
                ready = True
                yield fd
                failed = False
            finally:
                try:
                    if failed and undo is not None:
                        for name in reversed(undo):
                            os.unlink(name, dir_fd=fd)
                    if temporary and ready:
                        with os.scandir(fd) as entries:
                            for entry in entries:
                                if entry.is_dir(follow_symlinks=False):
                                    with self.directory(safe_path(path) / entry.name, temporary=True, temporary_parent=fd):
                                        pass
                                else:
                                    os.unlink(entry.name, dir_fd=fd)
                        if temporary_parent is not None:
                            os.rmdir(parts[0], dir_fd=base)
                        else:
                            os.rmdir(created[-1][1], dir_fd=created[-1][0])
                            failed = False
                    if failed:
                        for parent, name in reversed(created):
                            os.rmdir(name, dir_fd=parent)
                finally:
                    self._local.directories = getattr(self._local, "directories", set()) - {fd}
                    _close_all((fd, *(parent for parent, _name in created)))

    def mkdir(self, path):
        with self.directory(path, create=True):
            pass

    def disjoint_directories(self, first, second):
        """Compare verified no-follow ancestors, including not-yet-created tails."""
        left, right = {}, {}

        def inside(parent, child):
            if parent["path"] == child["path"] or parent["path"] in child["path"].parents:
                return True
            anchor = parent["chain"][-1]
            if anchor not in child["chain"]:
                return False
            index = child["chain"].index(anchor)
            suffix = tuple(child["names"][index:]) + child["tail"]
            return suffix[:len(parent["tail"])] == parent["tail"]

        with self.directory(first, verification=left), self.directory(second, verification=right):
            require(not inside(left, right) and not inside(right, left))

    def exists(self, path, *, parent=None):
        path = safe_path(path)
        require(parent is None or type(parent) is int and parent in getattr(self._local, "directories", ()))
        try:
            with self.directory(path.parent) if parent is None else nullcontext(parent) as parent:
                with refusals():
                    info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        require(not info.st_mode & 0o022, reason="unsafe_path")
                    else:
                        _regular(info)
                    return True
        except MailboxRefusal as error:
            if error.reason == "missing":
                return False
            raise

    def entries(self, path, *, missing=False, parent=None):
        """Stream the census under a cap before allocating a sortable name list."""
        result = []
        opened = False
        require(parent is None or type(parent) is int and parent in getattr(self._local, "directories", ()))
        try:
            with self.directory(path) if parent is None else nullcontext(parent) as parent:
                opened = True
                with refusals(), os.scandir(parent) as entries:
                    for entry in entries:
                        require(len(result) < MAX_RECORDS, reason="too_large")
                        _regular(entry.stat(follow_symlinks=False))
                        result.append(Path(path) / entry.name)
        except MailboxRefusal as error:
            if missing and error.reason == "missing" and not opened:
                return []
            raise
        return sorted(result)

    def require_room(self, directory, needed=1):
        """Use the reader's entry census, including acknowledgments and pending files."""
        require(type(needed) is int and 0 <= needed <= MAX_RECORDS)
        directory = safe_path(directory)
        entries = self.entries(directory, missing=True)
        # Our ledger lock is removed before the operation returns. Other
        # recognized pending/control entries receive no publication credit.
        owned_lock = (str(directory) in getattr(self._local, "held", ())
                      and any(path.name == ".write.lock" for path in entries))
        require(len(entries) - int(owned_lock) + needed <= MAX_RECORDS, reason="too_large")

    def admit(self, path, raw, retained_bytes, max_bytes):
        """Preflight a complete append against the validated reader's byte total."""
        require(type(raw) is bytes and type(retained_bytes) is int and type(max_bytes) is int)
        require(0 <= retained_bytes <= max_bytes and len(raw) <= MAX_BYTES
                and retained_bytes + len(raw) <= max_bytes, reason="too_large")
        self.require_room(safe_path(path).parent)

    def read(self, path, *, limit=MAX_BYTES, parent=None):
        require(type(limit) is int and 0 <= limit <= 67108864)
        path = safe_path(path)
        require(parent is None or type(parent) is int and parent in getattr(self._local, "directories", ()))
        with self.directory(path.parent) if parent is None else nullcontext(parent) as parent, refusals():
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                _regular(before)
                require(before.st_size <= limit, reason="too_large")
                raw = bytearray()
                while len(raw) <= limit:
                    chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                require(len(raw) <= limit, reason="too_large")
                after = os.fstat(fd)
                _regular(after)
                require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns))
                return bytes(raw)
            finally:
                os.close(fd)

    def read_json(self, path):
        return strict_json(self.read(path))

    def _mutation_publish(self, path, raw, limit, parent, undo):
        undo = [] if undo is None else undo
        with self.evidence_transaction():
            with self.directory(path.parent, create=parent is None, undo=undo,
                                parent=parent, held=parent is not None) as directory:
                self.publish(path, raw, limit=limit, parent=directory, undo=undo)

    def publish(self, path, raw, *, limit=MAX_BYTES, parent=None, undo=None):
        require(type(raw) is bytes and type(limit) is int)
        require(len(raw) <= limit <= 67108864, reason="too_large")
        path = safe_path(path)
        require(parent is None or type(parent) is int and parent in getattr(self._local, "directories", ()))
        if getattr(self._local, "evidence", None) is None or parent is None or undo is None:
            return self._mutation_publish(path, raw, limit, parent, undo)
        with self.directory(path.parent, create=True) if parent is None else nullcontext(parent) as parent, refusals():
            pending = ".pending-" + uuid.uuid4().hex
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                try:
                    _write(fd, raw)
                finally:
                    os.close(fd)
                os.link(pending, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                if undo is not None:
                    undo.append(path.name)
            finally:
                os.unlink(pending, dir_fd=parent)
            os.fsync(parent)

    def witnesses(self, worktrees, directory, observe, *, expected=None, warnings=None):
        """Stage an entire observation batch under one exclusion, then commit or undo."""
        require(type(worktrees) is list and len(worktrees) <= 256)
        validate_warnings(warnings, limit=MAX_RELEASE_WARNINGS)
        if expected is not None:
            require(type(expected) is list)
            require(len(expected) <= 256, reason="too_large")
            require(len(expected) == len(worktrees))
            expected = [witness_record(source, worktree) for source, worktree in zip(expected, worktrees)]
            bounded_tree(expected)
        directory = safe_path(directory)
        stage = self.root / (".pending-witness-" + uuid.uuid4().hex)
        results, artifacts, undo, total = [], {}, [], 0
        with self.creation("evidence-destination"), self.evidence_transaction(warnings) as transaction, self.publication_lock(self.root, transaction), self.witness_lock(directory, transaction) as anchor:
            with self.directory(directory, create=True, undo=undo, parent=anchor) as parent:
                with self.directory(stage, create=True, temporary=True) as stage_fd:
                    for index, worktree in enumerate(worktrees):
                        capability = _WitnessStage(stage, self, stage_fd)
                        self._local.stage = capability
                        try:
                            result = witness_record(observe("source_witness", safe_path(worktree), capability), worktree)
                        finally:
                            self._local.stage = None
                        if expected is not None:
                            require(all(result[key] == expected[index][key] for key in
                                        ("worktree", "source_revision", "source_tree", "dirty_state_sha256", "dirty_entries")))
                        if "dirty_evidence" in result:
                            sha = result["dirty_state_sha256"]
                            artifact = stage / (sha + ".status")
                            require(safe_path(result["dirty_evidence"]) == artifact)
                            if sha not in artifacts:
                                raw = self.read(artifact, limit=MAX_STATUS_EVIDENCE_BYTES - total, parent=stage_fd)
                                require(hashlib.sha256(raw).hexdigest() == sha)
                                artifacts[sha], total = raw, total + len(raw)
                            result["dirty_evidence"] = str(directory / artifact.name)
                        else:
                            require(result["dirty_entries"] == 0)
                        results.append(result)
                    bounded_tree(results)
                    require({path.name for path in self.entries(stage, parent=stage_fd)} == {sha + ".status" for sha in artifacts})
                    pending = []
                    for sha, raw in artifacts.items():
                        path = directory / (sha + ".status")
                        if self.exists(path, parent=parent):
                            require(hashlib.sha256(self.read(path, limit=MAX_STATUS_EVIDENCE_BYTES, parent=parent)).hexdigest() == sha)
                        else:
                            pending.append((path, raw))
                    for path, raw in pending:
                        self.publish(path, raw, limit=MAX_STATUS_EVIDENCE_BYTES, parent=parent, undo=undo)
                # All evidence is published and staging cleanup has completed.
                transaction["committed"] = True
        return results

    @contextmanager
    def owner_lock(self, transaction):
        """Serialize every evidence destination in the existing Aegis user plane."""
        layout = UserLayout(_account_home())
        path = safe_path(layout.aegis_dir)
        with refusals():
            parent = _open_absolute(path)
            try:
                _private_directory(parent, mode=0o700)
                self._local.directories = getattr(self._local, "directories", set()) | {parent}
                self._local.owner = (path, parent)
                with self.publication_lock(path, transaction, parent=parent, owner=True):
                    yield
            finally:
                self._local.directories = getattr(self._local, "directories", set()) - {parent}
                self._local.owner = None
                _close_all((parent,))

    @contextmanager
    def witness_lock(self, directory, transaction):
        """One stable existing parent; never create evidence ancestors.

        Hold this parent for both locking and leaf creation, so a concurrent
        ancestor rename cannot redirect either operation to a different tree.
        """
        directory = safe_path(directory)
        with self.directory(directory.parent) as parent:
            with self.publication_lock(directory.parent, transaction, destination=directory, parent=parent):
                yield parent

    @contextmanager
    def publication_lock(self, directory, transaction, *, destination=None, parent=None, owner=False):
        with self._release_slot(lock_path(directory, destination, owner=owner)) as slot:
            completed = False
            try:
                with self.lock(directory, destination=destination, parent=parent, owner=owner):
                    yield
                    completed = True
            except (MailboxRefusal, OSError):
                if completed:
                    self._record_release_warning(slot)
                if not completed or not transaction["committed"]:
                    raise

    def publish_status_evidence(self, directory, raw, sha256, *, warnings=None):
        """Bound and verify content-addressed status evidence under the held root."""
        validate_warnings(warnings, limit=MAX_RELEASE_WARNINGS)
        require(type(raw) is bytes)
        require(len(raw) <= MAX_STATUS_EVIDENCE_BYTES, reason="too_large")
        matching(sha256, SHA256, "status digest")
        require(hashlib.sha256(raw).hexdigest() == sha256)
        if isinstance(directory, _WitnessStage):
            return directory._publish(raw, sha256)
        path = safe_path(directory) / (sha256 + ".status")
        undo = []
        with self.creation("evidence-destination"), self.evidence_transaction(warnings), self.directory(path.parent, create=True, undo=undo) as parent:
            if self.exists(path, parent=parent):
                require(hashlib.sha256(self.read(path, limit=MAX_STATUS_EVIDENCE_BYTES, parent=parent)).hexdigest() == sha256)
            else:
                self.publish(path, raw, limit=MAX_STATUS_EVIDENCE_BYTES, parent=parent, undo=undo)
        return str(path)

    @contextmanager
    def lock(self, directory, create=False, *, destination=None, parent=None, owner=False):
        """No polling: one typed BusyError. Reentrant only in this thread/context."""
        directory = safe_path(directory)
        if not owner and getattr(self._local, "evidence", None) is None:
            with self.evidence_transaction():
                with self.lock(directory, create=create, destination=destination, parent=parent):
                    yield
            return
        require(not owner or getattr(self._local, "owner", None) == (directory, parent))
        path = lock_path(directory, destination, owner=owner)
        name = path.name
        key = str(directory if destination is None and not owner else path)
        held = getattr(self._local, "held", set())
        require(parent is None or type(parent) is int and parent in getattr(self._local, "directories", ()))
        if key in held:
            yield
            return
        with self._release_slot(path) as slot:
            with self.directory(directory, create=create) if parent is None else nullcontext(parent) as parent, refusals():
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=parent)
                except FileExistsError:
                    try:
                        _regular(os.stat(name, dir_fd=parent, follow_symlinks=False))
                    except FileNotFoundError:
                        # The observed contender released between O_EXCL and stat.
                        pass
                    raise BusyError(path) from None
                completed = False
                try:
                    # The lock is a coordination claim, not authority or authentication.
                    os.close(fd)
                    self._local.held = held | {key}
                    yield
                    completed = True
                finally:
                    self._local.held = getattr(self._local, "held", set()) - {key}
                    try:
                        os.unlink(name, dir_fd=parent)
                    except (MailboxRefusal, OSError):
                        self._record_release_warning(slot)
                        if not completed:
                            raise


def initialize_store(root, raw, folders):
    """Create an exclusive root and roll back this call's entries on failure."""
    require(descriptor_supported(), reason="unsupported_platform")
    root = safe_path(root)
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, reason="too_large")
    require(type(folders) is list and len(folders) <= MAX_RECORDS)
    for parts in folders:
        require(type(parts) is tuple and len(parts) == 2)
        for part in parts:
            matching(part, SLUG, "folder component")
    created = []
    with Store(UserLayout(_account_home()).aegis_dir) as owner, owner.evidence_transaction() as transaction:
        with refusals():
            parent = _open_absolute(root.parent)
            fd, root_created, manifest_created = None, False, False
            try:
                _private_directory(parent)
                os.mkdir(root.name, 0o700, dir_fd=parent)
                root_created = True
                fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                for parts in folders:
                    current = os.dup(fd)
                    try:
                        for part in parts:
                            anchor = os.dup(current)
                            try:
                                os.mkdir(part, 0o700, dir_fd=current)
                            except FileExistsError:
                                os.close(anchor)
                            except BaseException:
                                os.close(anchor)
                                raise
                            else:
                                created.append((anchor, part))
                            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                            previous, current = current, child
                            os.close(previous)
                    finally:
                        os.close(current)
                record = os.open("manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                manifest_created = True
                try:
                    _write(record, raw)
                finally:
                    os.close(record)
                os.fsync(fd)
                os.fsync(parent)
            except BaseException:
                if manifest_created:
                    os.unlink("manifest.json", dir_fd=fd)
                for anchor, name in reversed(created):
                    os.rmdir(name, dir_fd=anchor)
                if root_created:
                    os.rmdir(root.name, dir_fd=parent)
                raise
            finally:
                _close_all(anchor for anchor, _name in created)
                _close_all(number for number in (fd, parent) if number is not None)
    return owner.drain_warnings()
