"""Public confined-file storage contract, including races and refusal cleanup."""
import errno
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from aegis_core import storage


def make_store(root):
    if not storage.confined_descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    return root.resolve()


class _CapabilityName:
    def __init__(self, name):
        self.__name__ = name


def install_confined_os(monkeypatch, *, present, follow=True, name="posix",
                        nofollow=True, directory=True, open_impl=None,
                        close_impl=None, mkdir_impl=None):
    """Replace this module's os seam. Process-wide os stays untouched.

    Requested directory flags are always present on the seam: the host constant
    when it exists, otherwise a distinct non-zero sentinel. Real opens on a
    POSIX host therefore keep the host flag bits.
    """
    values = {
        "name": name,
        "supports_dir_fd": tuple(_CapabilityName(item) for item in present),
        "supports_follow_symlinks": tuple(_CapabilityName(item) for item in (("stat",) if follow else ())),
        "fsencode": os.fsencode,
        "open": os.open if open_impl is None else open_impl,
        "close": os.close if close_impl is None else close_impl,
        "fstat": os.fstat,
        "stat": os.stat,
        "mkdir": os.mkdir if mkdir_impl is None else mkdir_impl,
        "fsync": os.fsync,
    }
    if nofollow:
        values["O_NOFOLLOW"] = os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 1
    if directory:
        values["O_DIRECTORY"] = os.O_DIRECTORY if hasattr(os, "O_DIRECTORY") else 2
    if hasattr(os, "O_RDONLY"):
        values["O_RDONLY"] = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        values["O_CLOEXEC"] = os.O_CLOEXEC
    monkeypatch.setattr("aegis_core.storage_confined.os", SimpleNamespace(**values))


def _tracked_directory_io(live):
    def opened(path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.discard(fd)
        os.close(fd)

    return opened, closed


class ModuleOS(SimpleNamespace):
    def __getattr__(self, name):
        return getattr(os, name)


LIFETIME_ERRNOS = ("EACCES", "EIO", "ENOENT", "ELOOP", "ENOTDIR", "ESTALE", "EEXIST", "ENOSPC")
LIFETIME_PHASES = {
    "message": ("open_root", "open", "walk_close", "close", "body", "body_close"),
    "manager": ("open_root", "open", "walk_close", "close", "mkdir", "fsync", "stat", "body", "body_close"),
    "codec": ("open_root", "open", "walk_close", "close", "stat", "body"),
    "clock": ("open_root", "open", "walk_close", "close", "stat", "body"),
    "memo": ("open_root", "open", "walk_close", "close", "stat", "body"),
    "config": ("open_root", "open", "walk_close", "close", "stat", "body"),
    "decisions": ("open_root", "open", "walk_close", "close", "stat", "body"),
    "confined": ("open_root", "open", "walk_close", "close", "mkdir", "fsync", "stat", "body", "body_close"),
}


class LifetimeFault(ModuleOS):
    """Caller-owned OS boundary; shared os and builtin I/O remain untouched."""

    def __init__(self, root, caller, phase, number):
        super().__init__()
        self.root, self.caller, self.phase, self.number = root, caller, phase, number
        self.phase = {"open_close_errno": "open_close", "stat_close_errno": "stat_close"}.get(phase, phase)
        self.cleanup_number = number if phase in ("open_close_errno", "stat_close_errno") else errno.EIO
        self.file = root / "data"
        self.fired = False
        self.cleanup_fired = False
        self.opened = set()

    def fail(self):
        self.fired = True
        raise OSError(self.number, "rf32 lifetime fault")

    def matches(self, fd, path):
        try:
            held, named = os.fstat(fd), path.stat()
        except FileNotFoundError:
            return False
        return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)

    def open(self, path, flags, *args, **kwargs):
        if not self.fired and self.phase == "open_root" and path == self.root.anchor:
            self.fail()
        fd = os.open(path, flags, *args, **kwargs)
        self.opened.add(fd)
        if (not self.fired and self.phase in ("open", "open_close", "reopen")
                and flags & os.O_DIRECTORY and self.matches(fd, self.root)):
            os.close(fd)
            self.fail()
        return fd

    def close(self, fd):
        target = self.root.parent if self.phase in ("walk_close", "open_close", "close_both") else self.root
        if self.caller == "confined" and self.phase in ("close", "body_close", "stat_close"):
            target = self.root / "made"
        closing = (not self.fired and self.phase in ("walk_close", "close", "body_close", "close_both")
                   and self.matches(fd, target))
        cleanup = not self.cleanup_fired and self.phase in ("open_close", "stat_close") and self.matches(fd, target)
        if self.phase == "close_both" and not self.cleanup_fired and self.matches(fd, self.root):
            cleanup = True
        os.close(fd)
        if cleanup:
            self.cleanup_fired = True
            raise OSError(self.cleanup_number, "rf32 cleanup fault")
        if closing:
            self.fail()

    def fstat(self, fd):
        target = self.file if self.caller in ("clock", "memo", "config") else self.root
        if self.caller == "confined":
            target = self.root / "made"
        if not self.fired and self.phase in ("stat", "stat_close") and self.matches(fd, target):
            self.fail()
        return os.fstat(fd)

    def mkdir(self, path, mode=0o777, *, dir_fd=None):
        if not self.fired and self.phase == "mkdir":
            if self.number == errno.EEXIST:
                os.mkdir(path, mode, dir_fd=dir_fd)
            self.fail()
        return os.mkdir(path, mode, dir_fd=dir_fd)

    def fsync(self, fd):
        if not self.fired and self.phase == "fsync":
            self.fail()
        return os.fsync(fd)

    def fdopen(self, fd, *args, **kwargs):
        if not self.fired and self.phase == "body" and self.caller in ("codec", "config", "decisions"):
            self.fail()
        return os.fdopen(fd, *args, **kwargs)

    def utime(self, *args, **kwargs):
        if not self.fired and self.phase == "body" and self.caller == "clock":
            self.fail()
        return os.utime(*args, **kwargs)

    def stat(self, path, *args, **kwargs):
        if not self.fired and self.phase == "body" and self.caller == "memo" and path == self.file.name:
            self.fail()
        if not self.fired and kwargs.get("dir_fd") is not None and not kwargs.get("follow_symlinks", True):
            if ((self.phase == "verify" and path == self.root.name)
                    or (self.phase == "recheck" and path == self.root.parent.name)):
                self.fail()
        return os.stat(path, *args, **kwargs)

    def lstat(self, path, *args, **kwargs):
        # Model an external temporary store at the OS metadata boundary. This
        # sandbox places synthetic Git markers in its ancestors. Markers in
        # the store itself remain real and visible to placement validation.
        if Path(path).name == ".git" and Path(path).parent in self.root.parents:
            raise FileNotFoundError(errno.ENOENT, "external store ancestor has no Git marker")
        return os.lstat(path, *args, **kwargs)

    def directory(self, opener, root, **kwargs):
        return self.delegate(self.open, root, policy=kwargs.get("policy"),
                             on_missing=kwargs.get("on_missing"), retain_ancestors=kwargs.get("retain_ancestors", False),
                             close_fd=self.close, stat_fd=self.fstat, stat_entry=self.stat,
                             cleanup_fd=kwargs.get("cleanup_fd"))


class ManagerParentCloseFault(LifetimeFault):
    def __init__(self, root, *, release, reuse=None):
        super().__init__(root, "manager", "walk_close", errno.EIO)
        self.release, self.reuse = release, reuse
        self.parent_fd = None
        self.parent_retries = 0
        self.cleanup_number = errno.ENOSPC

    def close(self, fd):
        if fd == self.parent_fd:
            self.parent_retries += 1
            return os.close(fd)
        if not self.fired and self.matches(fd, self.root.parent):
            self.parent_fd = fd
            if self.release:
                os.close(fd)
                if self.reuse is not None:
                    # Model another thread taking this number as soon as it is released.
                    os.dup2(self.reuse, fd)
            self.fail()
        if self.fired and not self.cleanup_fired and self.release and self.matches(fd, self.root):
            os.close(fd)
            self.cleanup_fired = True
            raise OSError(self.cleanup_number, "rf32 cleanup fault")
        os.close(fd)


def lifetime_setup(parent, caller, phase, number):
    root = parent / "bound"
    root.mkdir(mode=0o700)
    if caller == "message":
        root = parent / ".aegis"
        (root / "state/messages").mkdir(parents=True, mode=0o700)
    if caller == "manager" and phase in ("mkdir", "fsync", "reopen"):
        root.rmdir()
    fault = LifetimeFault(root, caller, phase, number)
    if caller in ("clock", "memo", "decisions"):
        fault.file.write_bytes(b"ledger" if caller == "memo" else b"")
        fault.file.chmod(0o600)
    if caller == "config":
        fault.file.write_bytes((Path(__file__).resolve().parents[3] /
                               "tools/hierarchy_templates/model-bindings.json").read_bytes())
    return fault


def lifetime_invoke(fault, modules):
    from aegis_core.workspace.base import Workspace
    module = modules[fault.caller]
    if fault.caller == "message":
        with module.message_store(Workspace(fault.root.parent)):
            if fault.phase in ("body", "body_close"):
                if fault.phase == "body":
                    fault.fail()
                raise ValueError("rf32 body fault")
        return "ok"
    if fault.caller == "manager":
        manager = module.ManagerStore(fault.root)
        if fault.phase in ("mkdir", "fsync", "reopen"):
            manager.append({"event": "probe"})
        elif fault.phase in ("body", "body_close"):
            def body(rows):
                if fault.phase == "body":
                    fault.fail()
                raise ValueError("rf32 body fault")
            manager.transaction(body)
        else:
            manager.read()
        return "ok"
    if fault.caller == "codec":
        store = module.Store(fault.root)
        try:
            if fault.phase == "body":
                store.write({"schema": "aegis.msg/1", "kind": "text", "meta": {
                    "from": "test", "host": "test", "session": "test", "created_at": ""},
                    "fields": {}, "body": "probe", "spans": [], "refs": {}})
        finally:
            store.close()
        return "ok"
    if fault.caller == "clock":
        return "none" if module.filesystem_now(fault.file, fault.file.stat().st_dev) is None else "ok"
    if fault.caller == "memo":
        module.reset()
        info = fault.file.stat()
        size, mtime, ctime = storage.file_generation(info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        identity = (info.st_dev, info.st_ino)
        before = SimpleNamespace(identity=identity, size=size, mtime_ns=mtime, ctime_ns=ctime,
                                 started_ns=max(mtime, ctime) + 3_000_000_000, ancestors=())
        report = storage.FileReport(identity, size, mtime_ns=mtime, ctime_ns=ctime)
        key = (str(fault.root), "rule", "host", "session", None)
        try:
            module.remember(str(fault.root), [key], fault.file, before, [], report)
            return "hit" if module.contains(str(fault.root), [key], SimpleNamespace(path=fault.file, ancestors=())) else "miss"
        finally:
            module.reset()
    if fault.caller == "config":
        module.validate_bindings(fault.file, host_kinds=("codex-cli", "claude-code"))
        return "ok"
    if fault.caller == "decisions":
        assert list(module.read_decisions(fault.file)) == []
        return "ok"
    with module.confined_file(fault.root, ("made", "data"), create_parents=True) as handle:
        if fault.phase in ("stat", "stat_close"):
            handle.parent_stat()
        if fault.phase == "body":
            fault.fail()
        if fault.phase == "body_close":
            raise ValueError("rf32 body fault")
    return "ok"


def lifetime_surface(fault, modules):
    from aegis_core.message_codec import CodecError
    try:
        return ("ok", None, None, lifetime_invoke(fault, modules), None)
    except Exception as error:
        code = error.code if isinstance(error, (storage.ConfinedFileError, CodecError)) else None
        detail = error.detail if isinstance(error, CodecError) else None
        return (type(error).__name__, getattr(error, "errno", None), code, str(error), detail)


def lifetime_assert_closed(fault):
    for fd in fault.opened:
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF



# Recorded against integration tip 27e02ad06cdde9f9dc20501d53e12ddb4a6ad5b9.
# Rows index the immutable surfaces in errno order LIFETIME_ERRNOS. The recording
# lives in writer evidence; collection and execution never require Git history.
TIP_SURFACES = (('PermissionError', 'EACCES', None, '[Errno {errno}] rf32 lifetime fault'),
 ('OSError', 'EIO', None, '[Errno {errno}] rf32 lifetime fault'),
 ('CodecError',
  None,
  'E_AUTH',
  'store access refused: unsafe directory or platform lacks anchored file operations; use a supported real directory'),
 ('OSError', 'ESTALE', None, '[Errno {errno}] rf32 lifetime fault'),
 ('FileExistsError', 'EEXIST', None, '[Errno {errno}] rf32 lifetime fault'),
 ('OSError', 'ENOSPC', None, '[Errno {errno}] rf32 lifetime fault'),
 ('FileNotFoundError', 'ENOENT', None, '[Errno {errno}] rf32 lifetime fault'),
 ('OSError', 'ELOOP', None, '[Errno {errno}] rf32 lifetime fault'),
 ('NotADirectoryError', 'ENOTDIR', None, '[Errno {errno}] rf32 lifetime fault'),
 ('ManagerError', None, None, 'unsafe_store'),
 ('ok', None, None, 'ok'),
 ('OSError', 'EBADF', None, '[Errno {errno}] Bad file descriptor'),
 ('CodecError', None, 'E_AUTH', 'store operation unavailable; check permissions, free space, write access and file descriptor limits'),
 ('ok', None, None, 'none'),
 ('ok', None, None, 'miss'),
 ('ModelSelectionError', None, None, 'invalid_bindings'),
 ('ModelSelectionError', None, None, 'unsafe_decision_path'),
 ('ConfinedFileError', None, 'CONFINED_IO', 'confined file I/O failed'),
 ('ConfinedFileError', None, 'CONFINED_MISSING', 'confined file path missing'),
 ('ConfinedFileError', None, 'CONFINED_UNSAFE', 'unsafe confined file path; regular file and directories required'),
 ('ConfinedFileError', None, 'CONFINED_EXISTS', 'confined file already exists'),
 ('ConfinedFileError', None, 'CONFINED_DURABILITY', 'confined file durability flush failed'),
 ('OSError', 'EIO', None, '[Errno {errno}] rf32 cleanup fault'),
 ('PermissionError', 'EACCES', None, '[Errno {errno}] rf32 cleanup fault'),
 ('OSError', 'ESTALE', None, '[Errno {errno}] rf32 cleanup fault'),
 ('FileExistsError', 'EEXIST', None, '[Errno {errno}] rf32 cleanup fault'),
 ('OSError', 'ENOSPC', None, '[Errno {errno}] rf32 cleanup fault'),
 ('FileNotFoundError', 'ENOENT', None, '[Errno {errno}] rf32 cleanup fault'),
 ('OSError', 'ELOOP', None, '[Errno {errno}] rf32 cleanup fault'),
 ('NotADirectoryError', 'ENOTDIR', None, '[Errno {errno}] rf32 cleanup fault'))

TIP_LIFETIME_CASES = {('message', 'open_root'): (0, 1, 2, 2, 2, 3, 4, 5),
 ('message', 'open'): (0, 1, 2, 2, 2, 3, 4, 5),
 ('message', 'walk_close'): (0, 1, 2, 2, 2, 3, 4, 5),
 ('message', 'close'): (0, 1, 2, 2, 2, 3, 4, 5),
 ('message', 'body'): (0, 1, 2, 2, 2, 3, 4, 5),
 ('message', 'body_close'): (0, 1, 2, 2, 2, 3, 4, 5),
 ('manager', 'open_root'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('manager', 'open'): (9, 9, 10, 9, 9, 9, 9, 9),
 ('manager', 'walk_close'): (11, 11, 11, 11, 11, 11, 11, 11),
 ('manager', 'close'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('manager', 'mkdir'): (0, 1, 6, 7, 8, 3, 10, 5),
 ('manager', 'fsync'): (0, 1, 6, 7, 8, 3, 10, 5),
 ('manager', 'stat'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('manager', 'body'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('manager', 'body_close'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('codec', 'open_root'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('codec', 'open'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('codec', 'walk_close'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('codec', 'close'): (10, 10, 10, 10, 10, 10, 10, 10),
 ('codec', 'stat'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('codec', 'body'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('clock', 'open_root'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'open'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'walk_close'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'close'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'stat'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'body'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('memo', 'open_root'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'open'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'walk_close'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'close'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'stat'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'body'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('config', 'open_root'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'open'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'walk_close'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'close'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'stat'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'body'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('decisions', 'open_root'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('decisions', 'open'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('decisions', 'walk_close'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('decisions', 'close'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('decisions', 'stat'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('decisions', 'body'): (0, 1, 10, 7, 8, 3, 4, 5),
 ('confined', 'open_root'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('confined', 'open'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('confined', 'walk_close'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('confined', 'close'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('confined', 'mkdir'): (17, 17, 18, 19, 19, 17, 10, 17),
 ('confined', 'fsync'): (21, 21, 21, 21, 21, 21, 21, 21),
 ('confined', 'stat'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('confined', 'body'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('confined', 'body_close'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('message', 'open_close'): (22, 22, 22, 22, 22, 22, 22, 22),
 ('manager', 'open_close'): (22, 22, 22, 22, 22, 22, 22, 22),
 ('manager', 'stat_close'): (22, 22, 22, 22, 22, 22, 22, 22),
 ('codec', 'open_close'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('codec', 'stat_close'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('clock', 'open_close'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'stat_close'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('memo', 'open_close'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'stat_close'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('config', 'open_close'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'stat_close'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('decisions', 'open_close'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('decisions', 'stat_close'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('confined', 'open_close'): (17, 17, 17, 17, 17, 17, 17, 17),
 ('confined', 'stat_close'): (17, 17, 17, 17, 17, 17, 17, 17),
 ('message', 'open_close_errno'): (23, 22, 2, 2, 2, 24, 25, 26),
 ('manager', 'open_close_errno'): (23, 22, 27, 28, 29, 24, 25, 26),
 ('manager', 'stat_close_errno'): (23, 22, 27, 28, 29, 24, 25, 26),
 ('codec', 'open_close_errno'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('codec', 'stat_close_errno'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('clock', 'open_close_errno'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('clock', 'stat_close_errno'): (13, 13, 13, 13, 13, 13, 13, 13),
 ('memo', 'open_close_errno'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('memo', 'stat_close_errno'): (14, 14, 14, 14, 14, 14, 14, 14),
 ('config', 'open_close_errno'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('config', 'stat_close_errno'): (15, 15, 15, 15, 15, 15, 15, 15),
 ('decisions', 'open_close_errno'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('decisions', 'stat_close_errno'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('confined', 'open_close_errno'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('confined', 'stat_close_errno'): (17, 17, 18, 19, 19, 17, 20, 17),
 ('manager', 'reopen'): (0, 1, 6, 7, 8, 3, 4, 5),
 ('codec', 'verify'): (12, 12, 2, 2, 2, 2, 12, 12),
 ('decisions', 'verify'): (16, 16, 16, 16, 16, 16, 16, 16),
 ('memo', 'recheck'): (14, 14, 14, 14, 14, 14, 14, 14)}


LIFETIME_NUMBERS = {"EACCES": errno.EACCES, "EIO": errno.EIO, "ENOENT": errno.ENOENT,
                    "ELOOP": errno.ELOOP, "ENOTDIR": errno.ENOTDIR, "ESTALE": getattr(errno, "ESTALE", errno.ENOENT),
                    "EEXIST": errno.EEXIST, "ENOSPC": errno.ENOSPC, "EBADF": errno.EBADF}


@pytest.mark.parametrize("caller,phase,injected,expected_index", [
    (caller, phase, number, expected)
    for (caller, phase), expectations in TIP_LIFETIME_CASES.items()
    for number, expected in zip(LIFETIME_ERRNOS, expectations)
])
def test_directory_lifetime_matches_tip(tmp_path, monkeypatch, caller, phase, injected, expected_index):
    from aegis_core import credit_memo, manager_store, message_codec_store, model_select, storage_confined
    root = make_store(tmp_path)
    fault = lifetime_setup(root, caller, phase, LIFETIME_NUMBERS[injected])
    fault.delegate = storage_confined.open_directory
    modules = {"message": storage, "manager": manager_store, "codec": message_codec_store,
               "clock": credit_memo, "memo": credit_memo, "config": model_select,
               "decisions": model_select, "confined": storage_confined}
    # Owned module references leave shared os untouched; the shared walk uses
    # injected open/close_fd/stat_fd callables.
    if caller == "message":
        monkeypatch.setattr("aegis_core.storage_confined.open_directory", fault.directory)
    elif caller == "manager":
        monkeypatch.setattr("aegis_core.manager_store.open_directory", fault.directory)
        monkeypatch.setattr("aegis_core.manager_store.os", fault)
    elif caller == "codec":
        monkeypatch.setattr("aegis_core.message_codec_store.open_directory", fault.directory)
        monkeypatch.setattr("aegis_core.message_codec_store.os", fault)
    elif caller in ("clock", "memo"):
        monkeypatch.setattr("aegis_core.credit_memo.open_directory", fault.directory)
        monkeypatch.setattr("aegis_core.credit_memo.os", fault)
    elif caller in ("config", "decisions"):
        monkeypatch.setattr("aegis_core.model_select.open_directory", fault.directory)
        monkeypatch.setattr("aegis_core.model_select.os", fault)
    else:
        monkeypatch.setattr("aegis_core.storage_confined.os", fault)
    if (caller, phase) == ("manager", "walk_close"):
        # Round 1d: safe cleanup cannot repeat the tip's second close of the
        # released parent. With successful child cleanup, keep the first error.
        expected_index = TIP_LIFETIME_CASES["manager", "close"][LIFETIME_ERRNOS.index(injected)]
    kind, number, code, message = TIP_SURFACES[expected_index]
    expected_errno = LIFETIME_NUMBERS[number] if number is not None else None
    detail = {2: "", 12: "operation"}.get(expected_index)
    if caller == "message" and phase in ("open_root", "open") and injected == "ENOENT":
        detail = "workspace"
    expected = (kind, expected_errno, code, message.format(errno=expected_errno), detail)
    try:
        assert lifetime_surface(fault, modules) == expected
        assert fault.fired
        if phase in ("open_close", "stat_close", "open_close_errno", "stat_close_errno"):
            assert fault.cleanup_fired
        lifetime_assert_closed(fault)
        fault.phase = "off"
        assert lifetime_surface(fault, modules) == ("ok", None, None, "hit" if caller == "memo" else "ok", None)
        lifetime_assert_closed(fault)
    finally:
        for fd in fault.opened:
            try:
                os.fstat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                os.close(fd)


def test_message_command_directory_close_preserves_tip_refusal(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main
    from aegis_core import message_codec, storage_confined
    root = make_store(tmp_path)
    fault = lifetime_setup(root, "message", "close", errno.EIO)
    store = message_codec.Store(fault.root / "state/messages")
    try:
        rid = store.write({"schema": "aegis.msg/1", "kind": "text", "meta": {
            "from": "test", "host": "test", "session": "test", "created_at": ""},
            "fields": {}, "body": "probe", "spans": [], "refs": {}})
    finally:
        store.close()
    fault.delegate = storage_confined.open_directory
    monkeypatch.setattr("aegis_core.storage_confined.open_directory", fault.directory)
    assert main(["--workspace", str(root), "msg", "verify", rid]) == 2
    captured = capsys.readouterr()
    # Exact stdout/stderr/exit status recorded against the same integration tip.
    assert captured.out == ('{"error":{"code":"E_AUTH","message":"store operation unavailable; '
                            'check permissions, free space, write access and file descriptor limits"}}\n')
    assert captured.err == ""
    assert fault.fired


def test_manager_operation_directory_close_preserves_tip_oserror(tmp_path, monkeypatch):
    from aegis_core import manager_store, storage_confined
    fault = lifetime_setup(make_store(tmp_path), "manager", "close", errno.EIO)
    fault.delegate = storage_confined.open_directory
    monkeypatch.setattr("aegis_core.manager_store.open_directory", fault.directory)
    monkeypatch.setattr("aegis_core.manager_store.os", fault)
    with pytest.raises(OSError) as refused:
        manager_store.ManagerStore(fault.root).read()
    assert type(refused.value) is OSError
    assert refused.value.errno == errno.EIO
    assert str(refused.value) == "[Errno {}] rf32 lifetime fault".format(errno.EIO)
    assert fault.fired


def lifetime_message_publish(root):
    from aegis_core import message_codec as codec
    from aegis_core.workspace.base import Workspace
    value = codec.compose("text", b'{"fields":{},"body":"probe","refs":{}}',
                          {"from": "test", "host": "test", "session": "test", "created_at": ""})
    return Workspace(root), value, codec.record_id(value)


@pytest.mark.parametrize("phase", ["walk_close", "close_both"])
def test_message_ancestor_close_fails_after_publication(tmp_path, monkeypatch, phase):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    fault = lifetime_setup(root, "message", phase, errno.EIO)
    fault.delegate = storage_confined.open_directory
    monkeypatch.setattr("aegis_core.storage_confined.open_directory", fault.directory)
    workspace, value, rid = lifetime_message_publish(root)
    with pytest.raises(OSError) as refused:
        with storage.message_store(workspace, write=True) as store:
            assert store.write(value) == rid
    assert str(refused.value) == "[Errno {}] rf32 lifetime fault".format(errno.EIO)
    assert fault.fired
    if phase == "close_both":
        assert fault.cleanup_fired
    lifetime_assert_closed(fault)
    with storage.message_store(workspace, write=True) as store:
        assert store.read(rid) == value
        assert store.write(value) == rid
    lifetime_assert_closed(fault)


def test_clock_ancestor_close_fails_after_timestamp_update(tmp_path, monkeypatch):
    from aegis_core import credit_memo, storage_confined
    if not credit_memo.filesystem_clock_supported():
        pytest.skip("requires descriptor-based filesystem clock")
    fault = lifetime_setup(make_store(tmp_path), "clock", "walk_close", errno.EIO)
    os.utime(fault.file, ns=(1_000_000_000, 1_000_000_000))
    before = fault.file.stat()
    fault.delegate = storage_confined.open_directory
    monkeypatch.setattr("aegis_core.credit_memo.open_directory", fault.directory)
    monkeypatch.setattr("aegis_core.credit_memo.os", fault)
    assert credit_memo.filesystem_now(fault.file, before.st_dev) is None
    assert fault.file.stat().st_mtime_ns != before.st_mtime_ns
    assert fault.fired
    lifetime_assert_closed(fault)
    assert credit_memo.filesystem_now(fault.file, before.st_dev) == fault.file.stat().st_mtime_ns
    lifetime_assert_closed(fault)


@pytest.mark.parametrize("release", [False, True], ids=["before_release", "after_release"])
def test_manager_parent_close_does_not_retry_reusable_descriptor(tmp_path, monkeypatch, release):
    from aegis_core import manager_store, storage_confined
    root = make_store(tmp_path)
    target = root / "bound"
    target.mkdir(mode=0o700)
    source = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    fault = ManagerParentCloseFault(target, release=release, reuse=source if release else None)
    fault.delegate = storage_confined.open_directory
    monkeypatch.setattr("aegis_core.manager_store.open_directory", fault.directory)
    monkeypatch.setattr("aegis_core.manager_store.os", fault)
    manager = manager_store.ManagerStore(target)
    try:
        with pytest.raises(OSError) as refused:
            manager.read()
        expected_number = errno.ENOSPC if release else errno.EIO
        expected_message = "rf32 cleanup fault" if release else "rf32 lifetime fault"
        assert type(refused.value) is OSError
        assert refused.value.errno == expected_number
        assert str(refused.value) == "[Errno {}] {}".format(expected_number, expected_message)
        assert fault.parent_retries == 0
        assert fault.cleanup_fired is release
        assert fault.matches(fault.parent_fd, root)
    finally:
        os.close(source)
        if fault.parent_fd is not None and not fault.parent_retries:
            os.close(fault.parent_fd)
    lifetime_assert_closed(fault)
    assert manager.read() == []
    lifetime_assert_closed(fault)


@pytest.mark.parametrize("caller", ["manager", "message"])
@pytest.mark.parametrize("phase", ["open", "close"])
def test_nested_directory_failure_propagates_unchanged(tmp_path, monkeypatch, caller, phase):
    from aegis_core import manager_store, storage_confined
    from aegis_core.workspace.base import Workspace
    root = make_store(tmp_path)
    (root / "nested").mkdir()
    fault = lifetime_setup(root, caller, "off", errno.EIO)
    nested = LifetimeFault(root / "nested", "nested", phase, errno.ENOENT)
    nested.delegate = storage_confined.open_directory
    failures = []

    def body(*args):
        try:
            with nested.directory(os.open, nested.root):
                pass
        except storage_confined.ConfinedFileError as error:
            failures.append(error)
            raise

    if caller == "manager":
        manager = manager_store.ManagerStore(fault.root)
        monkeypatch.setattr("aegis_core.manager_store.os", fault)
    else:
        workspace = Workspace(root)
    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        if caller == "manager":
            manager.transaction(body)
        else:
            with storage.message_store(workspace):
                body()
    assert failures == [refused.value]
    assert refused.value.code == "CONFINED_MISSING"
    assert refused.value.errno == errno.ENOENT
    lifetime_assert_closed(nested)
    if caller == "manager":
        assert manager.read() == []
        lifetime_assert_closed(fault)
    else:
        with storage.message_store(workspace) as reopened:
            assert reopened.fd is not None


def test_message_command_workspace_detail_preserves_tip_refusal(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import main
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    fault = lifetime_setup(root, "message", "open", errno.ENOENT)
    fault.delegate = storage_confined.open_directory
    monkeypatch.setattr("aegis_core.storage_confined.open_directory", fault.directory)
    assert main(["--workspace", str(root), "msg", "verify", "0" * 64]) == 2
    captured = capsys.readouterr()
    assert captured.out == '{"error":{"code":"E_AUTH","message":"workspace is not initialized; run aegis init"}}\n'
    assert captured.err == ""
    assert fault.fired
    lifetime_assert_closed(fault)


@pytest.mark.parametrize("case", ["ancestor_link", "leaf_link", "owner", "group_write",
                                  "other_write", "missing"])
def test_directory_walk_refusals_and_retry(tmp_path, monkeypatch, case):
    from conftest import symlink_or_skip
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    parent = root / "parent"
    parent.mkdir()
    target = parent / "leaf"
    target.mkdir(mode=0o700)
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def private(info):
        expected_uid = os.getuid() + (1 if case == "owner" else 0)
        if info.st_uid != expected_uid or info.st_mode & 0o022:
            raise storage_confined.ConfinedFileError("unsafe")

    reason = "unsafe"
    if case == "ancestor_link":
        parent.rename(root / "original")
        symlink_or_skip(root / "original", parent, target_is_directory=True)
    elif case == "leaf_link":
        target.rename(parent / "original")
        symlink_or_skip(parent / "original", target, target_is_directory=True)
    elif case == "missing":
        target.rmdir()
        reason = "missing"
    elif case in ("group_write", "other_write"):
        target.chmod(0o720 if case == "group_write" else 0o702)
    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=opened, close=closed))
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(storage_confined.os.open, target, policy=private)
        assert refused.value.reason == reason
        assert not live
    with storage_confined.open_directory(storage_confined.os.open, root) as held:
        assert held.identity == (root.stat().st_dev, root.stat().st_ino)
    assert not live


def test_directory_walk_unsupported_refuses_before_open(tmp_path, monkeypatch):
    from aegis_core import storage_confined

    def opened(*args, **kwargs):
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=("mkdir", "link", "rename", "unlink", "stat"),
                        open_impl=opened)
    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        storage_confined.open_directory(opened, tmp_path)
    assert refused.value.reason == "unsupported"


_WALK_PRESENT = ("open", "mkdir", "link", "rename", "unlink", "stat")
_PUBLICATION_ONLY = ("mkdir", "link", "rename", "unlink")


@pytest.mark.parametrize("case", ["open", "stat", "nofollow_stat", "O_NOFOLLOW", "O_DIRECTORY", "posix"])
def test_walk_refuses_each_missing_primitive_before_io(tmp_path, monkeypatch, case):
    """Invariant: a walk refuses before I/O when its own primitive is absent."""
    from aegis_core import storage_confined

    def opened(*args, **kwargs):
        pytest.fail("opened")

    present = [item for item in _WALK_PRESENT if item != case]
    install_confined_os(
        monkeypatch, present=tuple(present), follow=case != "nofollow_stat",
        name="nt" if case == "posix" else "posix", nofollow=case != "O_NOFOLLOW",
        directory=case != "O_DIRECTORY", open_impl=opened)
    spelling = str(tmp_path)
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(opened, tmp_path)
        assert refused.value.reason == "unsupported"
        assert refused.value.code == "CONFINED_UNSUPPORTED"
        assert str(refused.value) == "unsupported platform: confined file operations unavailable"
        assert refused.value.directory_stage == "prepare"
        assert spelling not in str(refused.value)
        assert refused.value.__cause__ is None


def test_walk_refuses_absent_nofollow_stat_while_publication_stays_available(tmp_path, monkeypatch):
    """No-follow stat is the walk's own requirement, even when publication is available."""
    from aegis_core import storage_confined

    def opened(*args, **kwargs):
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=_WALK_PRESENT, follow=False, open_impl=opened)
    assert storage_confined.descriptor_supported() is True
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(opened, tmp_path)
        assert refused.value.reason == "unsupported"
        assert refused.value.code == "CONFINED_UNSUPPORTED"


def test_invalid_root_still_precedes_a_missing_walk_primitive(monkeypatch):
    from aegis_core import storage_confined

    def opened(*args, **kwargs):
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=(), open_impl=opened)
    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        storage_confined.open_directory(opened, "relative")
    assert refused.value.reason == "invalid_path"
    assert str(refused.value) == "invalid confined file path"


@pytest.mark.parametrize("case", [
    "mkdir", "link", "rename", "unlink", "open", "stat", "posix", "O_NOFOLLOW", "O_DIRECTORY", "complete",
])
def test_publication_gate_keeps_its_full_predicate(monkeypatch, case):
    """Publication still requires mkdir, link, rename, unlink, open and stat."""
    from aegis_core import storage_confined
    present = [item for item in _WALK_PRESENT if item != case]
    install_confined_os(
        monkeypatch, present=tuple(present), name="nt" if case == "posix" else "posix",
        nofollow=case != "O_NOFOLLOW", directory=case != "O_DIRECTORY")
    assert storage_confined.descriptor_supported() is (case == "complete")


def test_walk_reads_when_publication_primitives_are_absent(tmp_path, monkeypatch):
    """Permit a read when open and no-follow stat exist. Keep publication closed."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    nested = root / "parent" / "leaf"
    nested.mkdir(parents=True)
    live = set()
    opened, closed = _tracked_directory_io(live)

    def module_open(*args, **kwargs):
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=("open", "stat"), open_impl=module_open)
    assert storage_confined.descriptor_supported() is False
    expected = (nested.stat().st_dev, nested.stat().st_ino)
    for _ in range(2):
        with storage_confined.open_directory(
                opened, nested, close_fd=closed, stat_fd=os.fstat, stat_entry=os.stat) as held:
            assert held.identity == expected
            assert held.fd in live
        assert not live
    barrier = Barrier(2, timeout=5)

    def once():
        barrier.wait()
        with storage_confined.open_directory(
                os.open, nested, close_fd=os.close, stat_fd=os.fstat, stat_entry=os.stat) as held:
            return held.identity

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(once) for _ in range(2)]
        assert [future.result(timeout=10) for future in futures] == [expected, expected]
    missing = root / "missing"
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(
                opened, missing, close_fd=closed, stat_fd=os.fstat, stat_entry=os.stat)
        assert refused.value.reason == "missing"
        assert refused.value.code == "CONFINED_MISSING"
        assert not live and not missing.exists()
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            with storage_confined.confined_file(root, ("state", "file"), create_parents=True):
                pytest.fail("publication admitted")
        assert refused.value.reason == "unsupported"
        assert refused.value.code == "CONFINED_UNSUPPORTED"
        assert not (root / "state").exists()


def test_walk_without_publication_still_refuses_a_swapped_ancestor(tmp_path, monkeypatch):
    from conftest import symlink_or_skip
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    parent, outside = root / "parent", root / "outside"
    parent.mkdir()
    (parent / "leaf").mkdir()
    outside.mkdir()
    (outside / "leaf").mkdir()
    live = set()
    opened, closed = _tracked_directory_io(live)

    def module_open(*args, **kwargs):
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=("open", "stat"), open_impl=module_open)
    parent.rename(root / "original")
    symlink_or_skip(root / "original", parent, target_is_directory=True)
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(
                opened, parent / "leaf", close_fd=closed, stat_fd=os.fstat, stat_entry=os.stat)
        assert refused.value.reason == "unsafe"
        assert refused.value.code == "CONFINED_UNSAFE"
        assert not live
    with storage_confined.open_directory(
            opened, root, close_fd=closed, stat_fd=os.fstat, stat_entry=os.stat) as held:
        assert held.identity == (root.stat().st_dev, root.stat().st_ino)
    assert not live


def test_caller_creation_does_not_require_publication_primitives(tmp_path, monkeypatch):
    """A caller handler still creates when descriptor-relative mkdir exists.

    Link, rename and unlink stay unnecessary. A failed attempt closes
    descriptors and can retry.
    """
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    target = root / "created"
    live = set()
    opened, closed = _tracked_directory_io(live)

    def module_open(*args, **kwargs):
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=("open", "stat", "mkdir"), open_impl=module_open)

    def failed(parent, name, observations):
        raise OSError(errno.EIO, "token=secret\nprivate path")

    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(
                opened, target, on_missing=failed, close_fd=closed,
                stat_fd=os.fstat, stat_entry=os.stat)
        assert refused.value.reason == "io"
        assert refused.value.code == "CONFINED_IO"
        assert str(refused.value) == "confined file I/O failed"
        assert not live and not target.exists()

    def create(parent, name, observations):
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)

    with storage_confined.open_directory(
            opened, target, on_missing=create, close_fd=closed,
            stat_fd=os.fstat, stat_entry=os.stat) as held:
        assert held.fd in live
        assert stat.S_ISDIR(os.fstat(held.fd).st_mode)
    assert not live
    assert (target.stat().st_mode & 0o777) == 0o700


def _read_seam(monkeypatch, live, mkdir_calls):
    def opened(path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.discard(fd)
        os.close(fd)

    def trapped_mkdir(*args, **kwargs):
        mkdir_calls.append(args)
        raise NotImplementedError("dir_fd mkdir")

    install_confined_os(
        monkeypatch, present=("open", "stat"), open_impl=opened, close_impl=closed,
        mkdir_impl=trapped_mkdir)
    return opened, closed


def test_creation_without_dir_fd_mkdir_refuses_before_handler(tmp_path, monkeypatch):
    """Reads stay open. Creation refuses before the handler or the walk mkdir."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    existing = root / "existing"
    existing.mkdir(mode=0o700)
    missing = root / "missing"
    present = root / "present"
    present.mkdir(mode=0o700)
    live = set()
    mkdir_calls = []
    handler_calls = []
    opened, closed = _read_seam(monkeypatch, live, mkdir_calls)
    expected = (existing.stat().st_dev, existing.stat().st_ino)

    for _ in range(2):
        with storage_confined.open_directory(
                opened, existing, close_fd=closed, stat_fd=os.fstat, stat_entry=os.stat) as held:
            assert held.identity == expected
        assert not live

    def handler(parent, name, observations):
        handler_calls.append(name)
        raise AssertionError("handler")

    spelling = str(missing)
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(
                opened, missing, on_missing=handler, close_fd=closed,
                stat_fd=os.fstat, stat_entry=os.stat)
        assert refused.value.reason == "unsupported"
        assert refused.value.code == "CONFINED_UNSUPPORTED"
        assert str(refused.value) == "unsupported platform: confined file operations unavailable"
        assert spelling not in str(refused.value)
        assert refused.value.__cause__ is None
        assert handler_calls == []
        assert mkdir_calls == []
        assert not live and not missing.exists()
    barrier = Barrier(2, timeout=5)

    def once():
        barrier.wait()
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(
                os.open, missing, on_missing=handler, close_fd=os.close,
                stat_fd=os.fstat, stat_entry=os.stat)
        return refused.value.reason

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(once) for _ in range(2)]
        assert [future.result(timeout=10) for future in futures] == ["unsupported", "unsupported"]
    assert handler_calls == [] and not missing.exists()
    for parts in (("missing-parent",), ("present",)):
        for _ in range(2):
            with pytest.raises(storage_confined.ConfinedFileError) as refused:
                storage_confined._open_parent(root, parts, True)
            assert refused.value.reason == "unsupported"
            assert refused.value.code == "CONFINED_UNSUPPORTED"
            assert refused.value.__cause__ is None
            assert mkdir_calls == []
            assert not live
    assert not (root / "missing-parent").exists() and present.is_dir()


def test_manager_creation_without_dir_fd_mkdir_is_a_stable_refusal(tmp_path, monkeypatch):
    """Manager append and transaction refuse before creating a missing store."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    from aegis_core.manager_policy import ManagerError
    from aegis_core.manager_store import ManagerStore
    root = make_store(tmp_path)
    store_dir = root / "audit"
    live = set()
    mkdir_calls = []
    _read_seam(monkeypatch, live, mkdir_calls)
    store = ManagerStore(store_dir)
    calls = []

    def callback(rows):
        calls.append(rows)
        return {"kind": "scan"}, "done"

    for _ in range(2):
        with pytest.raises(ManagerError, match="^unsafe_store$") as refused:
            store.append({"kind": "scan"})
        assert type(refused.value.__cause__) is storage_confined.ConfinedFileError
        assert refused.value.__cause__.reason == "unsupported"
        assert not store_dir.exists() and mkdir_calls == [] and not live
        with pytest.raises(ManagerError, match="^unsafe_store$") as refused:
            store.transaction(callback)
        assert calls == []
        assert type(refused.value.__cause__) is storage_confined.ConfinedFileError
        assert refused.value.__cause__.reason == "unsupported"
        assert not store_dir.exists()
    barrier = Barrier(2, timeout=5)

    def once():
        barrier.wait()
        with pytest.raises(ManagerError, match="^unsafe_store$") as refused:
            ManagerStore(store_dir).append({"kind": "scan"})
        return refused.value.__cause__.reason

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(once) for _ in range(2)]
        assert [future.result(timeout=10) for future in futures] == ["unsupported", "unsupported"]
    assert not store_dir.exists() and mkdir_calls == []


def test_manager_read_of_missing_store_without_dir_fd_mkdir_stays_empty(tmp_path, monkeypatch):
    """A read registers no creating handler, so a missing store stays absent.

    Append and transaction still refuse before any mkdir. A store that already
    exists still reads. Retry and concurrent reads create nothing.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    from aegis_core.manager_policy import ManagerError
    from aegis_core.manager_store import ManagerStore
    root = make_store(tmp_path)
    missing = root / "missing-audit"
    existing = root / "existing-audit"
    row = ManagerStore(existing).append({"kind": "scan"})
    live = set()
    mkdir_calls = []
    _read_seam(monkeypatch, live, mkdir_calls)
    store = ManagerStore(missing)
    for _ in range(2):
        assert store.read() == []
        assert not missing.exists() and mkdir_calls == [] and not live
    assert ManagerStore(existing).read() == [row]
    assert existing.is_dir() and (existing / "audit.jsonl").is_file()
    with pytest.raises(ManagerError, match="^unsafe_store$") as refused:
        store.append({"kind": "scan"})
    assert type(refused.value.__cause__) is storage_confined.ConfinedFileError
    assert refused.value.__cause__.reason == "unsupported"
    assert not missing.exists() and mkdir_calls == [] and not live
    calls = []

    def callback(rows):
        calls.append(rows)
        return {"kind": "scan"}, "done"

    with pytest.raises(ManagerError, match="^unsafe_store$") as refused:
        store.transaction(callback)
    assert calls == []
    assert type(refused.value.__cause__) is storage_confined.ConfinedFileError
    assert refused.value.__cause__.reason == "unsupported"
    assert not missing.exists() and mkdir_calls == []
    barrier = Barrier(2, timeout=5)

    def once():
        barrier.wait()
        return ManagerStore(missing).read()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(once) for _ in range(2)]
        assert [future.result(timeout=10) for future in futures] == [[], []]
    assert not missing.exists() and mkdir_calls == [] and not live


def test_manager_missing_read_stays_empty_and_append_creates_with_dir_fd_mkdir(tmp_path):
    """With descriptor-relative mkdir, a missing read stays empty and append creates."""
    from aegis_core.manager_store import ManagerStore
    root = make_store(tmp_path)
    store_dir = root / "audit"
    store = ManagerStore(store_dir)
    for _ in range(2):
        assert store.read() == []
        assert not store_dir.exists()
    row = store.append({"kind": "scan"})
    assert store_dir.is_dir()
    assert (store_dir.stat().st_mode & 0o777) == 0o700
    assert store.read() == [row]


def test_unsupported_walk_refusal_is_stable_across_threads(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    calls = []

    def opened(*args, **kwargs):
        calls.append(args)
        pytest.fail("opened")

    install_confined_os(monkeypatch, present=_PUBLICATION_ONLY, open_impl=opened)
    barrier = Barrier(2, timeout=5)

    def once():
        barrier.wait()
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(opened, tmp_path)
        return refused.value.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(once) for _ in range(2)]
        assert [future.result(timeout=10) for future in futures] == ["CONFINED_UNSUPPORTED"] * 2
    assert calls == []


@pytest.mark.parametrize("after_open", [False, True])
def test_directory_walk_ancestor_swap_is_confined(tmp_path, monkeypatch, after_open):
    from conftest import symlink_or_skip
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    parent, moved, outside = (root / name for name in ("parent", "moved", "outside"))
    parent.mkdir()
    (parent / "leaf").mkdir()
    outside.mkdir()
    (outside / "leaf").mkdir()
    expected = (parent / "leaf").stat()

    def opened(path, flags, *args, **kwargs):
        if path != "parent":
            return os.open(path, flags, *args, **kwargs)
        if after_open:
            fd = os.open(path, flags, *args, **kwargs)
        parent.rename(moved)
        symlink_or_skip(outside, parent, target_is_directory=True)
        return fd if after_open else os.open(path, flags, *args, **kwargs)

    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=opened))
    if not after_open:
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(storage_confined.os.open, parent / "leaf")
        assert refused.value.reason == "unsafe"
    else:
        with storage_confined.open_directory(storage_confined.os.open, parent / "leaf", retain_ancestors=True) as held:
            assert held.identity == (expected.st_dev, expected.st_ino)
            assert held.observations[-1] == (expected.st_dev, expected.st_ino, expected.st_uid, expected.st_mode)
            with pytest.raises(storage_confined.ConfinedFileError) as refused:
                held.check()
            assert refused.value.reason == "unsafe"


@pytest.mark.parametrize("failure", ["open", "fstat", "stat", "policy"])
def test_directory_walk_failure_closes_descriptors(tmp_path, monkeypatch, failure):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    live = set()

    def opened(*args, **kwargs):
        if failure == "open" and live:
            raise OSError("untrusted token=secret")
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def failed(*args, **kwargs):
        raise OSError("untrusted token=secret")

    replacements = {failure: failed} if failure in ("fstat", "stat") else {}
    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=opened, close=closed, **replacements))
    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        storage_confined.open_directory(storage_confined.os.open, root, policy=failed if failure == "policy" else None)
    assert refused.value.reason == "io"
    assert str(refused.value) == "confined file I/O failed"
    assert not live


def test_directory_walk_concurrent_creation_reopens_the_winning_directory(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    target = root / "created"
    barrier = Barrier(2, timeout=5)

    def missing(parent, name, observations):
        info = os.fstat(parent)
        assert observations[-1] == (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        barrier.wait()
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass

    def bind():
        with storage_confined.open_directory(os.open, target, on_missing=missing) as held:
            return held.identity

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(bind) for _ in range(2)]
        identities = [future.result(timeout=10) for future in futures]
    info = target.stat()
    assert identities == [(info.st_dev, info.st_ino)] * 2
    assert info.st_mode & 0o777 == 0o700


def test_directory_walk_missing_callback_failure_closes_and_can_retry(tmp_path):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def failed(*args):
        raise OSError("token=secret\nprivate path")

    def create(parent, name, observations):
        os.mkdir(name, mode=0o700, dir_fd=parent)

    target = root / "missing"
    for _ in range(2):
        with pytest.raises(storage_confined.ConfinedFileError) as refused:
            storage_confined.open_directory(opened, target, on_missing=failed, close_fd=closed)
        assert refused.value.reason == "io"
        assert str(refused.value) == "confined file I/O failed"
        assert not live and not target.exists()
    with storage_confined.open_directory(opened, target, on_missing=create, close_fd=closed) as held:
        assert held.fd in live
    assert not live


@pytest.mark.parametrize("operation", ["close", "detach"])
def test_directory_walk_cleanup_attempts_every_descriptor_on_close_error(tmp_path, operation):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    live, failures = set(), []

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)
        if not failures:
            failures.append(fd)
            raise OSError("token=secret\nclose failed")

    held = storage_confined.open_directory(opened, root, retain_ancestors=True, close_fd=closed)
    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        if operation == "close":
            held.close()
        else:
            held.detach()
    assert refused.value.reason == "io"
    assert not live
    held.close()
    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        held.check()
    assert refused.value.reason == "closed"


def test_directory_walk_detach_transfers_only_leaf_ownership(tmp_path):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    with storage_confined.open_directory(os.open, root, retain_ancestors=True) as held:
        fd = held.detach()
        assert held.fd is None
    try:
        assert (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == held.identity
    finally:
        os.close(fd)


@pytest.mark.parametrize("spelling", ["relative", "/" + "x" * 32768, "/\ud800", b"/bytes"],
                         ids=["relative", "oversize", "invalid_unicode", "bytes"])
def test_directory_walk_invalid_root_refuses_before_open(spelling):
    from aegis_core import storage_confined

    def forbidden(*args, **kwargs):
        pytest.fail("opened an invalid root")

    with pytest.raises(storage_confined.ConfinedFileError) as refused:
        storage_confined.open_directory(forbidden, spelling)
    assert refused.value.reason == "invalid_path"
    assert str(refused.value) == "invalid confined file path"


@pytest.mark.parametrize("number,detail", [(errno.ENOENT, ""), (errno.ENOTDIR, ""),
    (errno.ELOOP, ""), (getattr(errno, "ESTALE", errno.ENOENT), ""), (errno.EIO, "operation")],
    ids=["missing", "not_directory", "symlink", "stale", "io"])
def test_directory_walk_preserves_codec_refusal_mapping(tmp_path, monkeypatch, number, detail):
    from aegis_core import message_codec as codec
    root = make_store(tmp_path)

    def failed(*args, **kwargs):
        raise OSError(number, "token=secret\nprivate path")

    monkeypatch.setattr("aegis_core.message_codec_store.os", ModuleOS(open=failed))
    with pytest.raises(codec.CodecError) as refused:
        codec.Store(root)
    assert refused.value.code == "E_AUTH"
    assert refused.value.detail == detail
    assert str(refused.value) == (
        "store operation unavailable; check permissions, free space, write access and file descriptor limits"
        if detail else "store access refused: unsafe directory or platform lacks anchored file operations; use a supported real directory")


def test_directory_walk_codec_cleanup_preserves_the_policy_refusal(tmp_path, monkeypatch):
    from aegis_core import message_codec as codec
    root = make_store(tmp_path)
    root.chmod(0o777)
    live, leaves = set(), set()

    def opened(path, *args, **kwargs):
        fd = os.open(path, *args, **kwargs)
        live.add(fd)
        if path == root.name:
            leaves.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)
        if fd in leaves:
            raise OSError(errno.EIO, "token=secret\nclose failed")

    monkeypatch.setattr("aegis_core.message_codec_store.os", ModuleOS(open=opened, close=closed))
    try:
        with pytest.raises(codec.CodecError) as refused:
            codec.Store(root)
        assert refused.value.code == "E_AUTH"
        assert str(refused.value) == "store access refused; use a private store directory"
        assert leaves and not live
    finally:
        root.chmod(0o700)


def test_boundary_is_loaded_only_when_its_public_api_is_used():
    from pathlib import Path
    import subprocess
    import sys
    source = ("import sys; sys.path.insert(0, sys.argv[1]); "
              "from aegis_core import storage; "
              "assert 'aegis_core.storage_confined' not in sys.modules; "
              "assert callable(storage.confined_file); "
              "assert 'aegis_core.storage_confined' in sys.modules")
    result = subprocess.run([sys.executable, "-I", "-c", source, str(Path(__file__).resolve().parents[3])],
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_parent_fd_is_read_only_borrowed_and_refuses_after_exit(tmp_path):
    root = make_store(tmp_path)
    parent = root / "parent"
    parent.mkdir()
    with storage.confined_file(root, ("parent", "file")) as handle:
        handle.publish_bytes(b"held")
        descriptor = handle.parent_fd
        info = handle.parent_stat()
        assert (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == (info.st_dev, info.st_ino)
        with pytest.raises(AttributeError):
            handle.parent_fd = descriptor
        parent.rename(root / "moved")
        parent.mkdir()
        (parent / "file").write_bytes(b"replacement")
        assert handle.parent_fd == descriptor
        assert os.stat("file", dir_fd=handle.parent_fd, follow_symlinks=False).st_size == len(b"held")
    with pytest.raises(storage.ConfinedFileError) as refused:
        handle.parent_fd
    assert refused.value.code == "CONFINED_CLOSED"
    assert str(refused.value) == "confined file context is closed"
    with pytest.raises(OSError) as closed:
        os.fstat(descriptor)
    assert closed.value.errno == errno.EBADF


def test_read_publish_and_exclusive_creation(tmp_path):
    root = make_store(tmp_path)
    with storage.confined_file(root, ("state", "config"), create_parents=True) as handle:
        with pytest.raises(storage.ConfinedFileError) as missing:
            handle.read_bytes(8)
        assert missing.value.reason == "missing"
        handle.publish_bytes(b"original")
        assert handle.read_bytes(8) == b"original"
        with pytest.raises(storage.ConfinedFileError) as exists:
            handle.publish_bytes(b"other")
        assert exists.value.reason == "exists"
        assert handle.read_bytes(8) == b"original"
        handle.publish_bytes(b"new", replace=True, mode=0o640)
        assert handle.read_bytes(3) == b"new"
        assert handle.parent_stat().st_mode & 0o777 == 0o700
    assert (root / "state/config").stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize("parts", [(), "state/file", ("..",), (".",), ("a/b",),
                                  ("a\\b",), ("/absolute",), ("\x00secret",),
                                  ("x" * 256,), ("é" * 128,), ("\ud800",),
                                  ("x",) * 129, (None,)])
def test_invalid_components_refuse_without_echo(tmp_path, parts):
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(tmp_path, parts):
            pytest.fail("invalid path admitted")
    assert refused.value.reason == "invalid_path"
    assert str(refused.value) == "invalid confined file path"


def test_unsupported_platform_refuses_without_io(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(tmp_path, ("file",)):
            pytest.fail("unsupported platform admitted")
    assert refused.value.reason == "unsupported"


@pytest.mark.parametrize("limit", [-1, True, 1.5, "10"])
def test_invalid_read_bound_refuses_before_open(tmp_path, monkeypatch, limit):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(limit)
    assert refused.value.reason == "invalid_limit"


def test_size_checked_before_read_and_growth_bounded(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"12345")
    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr(storage_confined, "os", ModuleOS(read=lambda *a: pytest.fail("read oversized file")))
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(4)
        assert refused.value.reason == "too_large"
        target.write_bytes(b"1234")
        calls = []

        def growing(fd, count):
            calls.append(count)
            return b"x" * count

        monkeypatch.setattr(storage_confined, "os", ModuleOS(read=growing))
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(4)
        assert refused.value.reason == "too_large" and calls == [5]


@pytest.mark.parametrize("fault,code", [
    ("policy", "CONFINED_UNSAFE"),
    ("size", "CONFINED_TOO_LARGE"),
    ("read", "CONFINED_IO"),
    ("read-after-replace", "CONFINED_CHANGED"),
    ("rewrite", "CONFINED_CHANGED"),
    ("replace", "CONFINED_CHANGED"),
    ("unlink", "CONFINED_MISSING"),
    ("stat", "CONFINED_IO"),
])
def test_checked_read_validates_generation_closes_and_can_retry(tmp_path, monkeypatch, fault, code):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    opened, closed, checked, consumed = [], [], [], []

    def open_at(*args, **kwargs):
        if fault == "size":
            target.write_bytes(b"larger")
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def close(fd):
        closed.append(fd)
        os.close(fd)

    def policy(info):
        checked.append(info)
        assert info.st_ino == target.stat().st_ino
        if fault == "policy":
            raise storage.ConfinedFileError("unsafe")

    def read(fd, count):
        consumed.append(fd)
        assert checked and checked[0].st_ino == os.fstat(fd).st_ino
        if fault == "read":
            raise OSError(errno.EIO, "private-value")
        if fault == "read-after-replace":
            replacement = target.with_suffix(".new")
            replacement.write_bytes(b"other")
            replacement.replace(target)
            raise OSError(errno.EIO, "private-value")
        data = os.read(fd, count)
        if data and fault == "replace":
            replacement = target.with_suffix(".new")
            replacement.write_bytes(b"other")
            replacement.replace(target)
        if data and fault == "unlink":
            target.unlink()
        return data

    def stat_at(*args, **kwargs):
        if fault == "stat" and consumed:
            raise OSError(errno.EIO, "private-value")
        info = os.stat(*args, **kwargs)
        if fault == "rewrite" and consumed:
            target.write_bytes(b"other")
            os.utime(target, ns=(0, 0))
        return info

    with storage.confined_file(root, ("file",)) as handle:
        if fault == "size":
            target.write_bytes(b"four")
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=open_at, close=close, read=read, stat=stat_at))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(4 if fault == "size" else 5, policy=policy)
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == code and "private-value" not in str(caught.value)
        assert len(opened) == 1 and closed == opened
        if fault in ("size", "policy"):
            assert not consumed
        if fault == "size":
            assert not checked
            target.write_bytes(b"first")
        if fault == "unlink":
            target.write_bytes(b"first")
        seen = []
        raw, info = handle.read_checked(5, policy=seen.append)
        assert raw == target.read_bytes()
        assert seen == [info] and info.st_ino == target.stat().st_ino and info.st_size == len(raw)


def test_checked_read_unsupported_name_probe_refuses_before_open(tmp_path, monkeypatch):
    from aegis_core import storage_confined

    parent_fd = 1  # Simulated handle. The absent capability must prevent any I/O.
    opens = []

    def open_at(*args, **kwargs):
        assert kwargs["dir_fd"] is None
        opens.append(args)
        return parent_fd

    install_confined_os(monkeypatch, present=("open", "stat", "mkdir", "link", "rename", "unlink"),
                        follow=False, open_impl=open_at, close_impl=lambda fd: None)
    with pytest.raises(storage.ConfinedFileError) as owned:
        storage_confined.read_checked_file(Path(tmp_path.anchor), ("file",), 5)
    assert owned.value.code == "CONFINED_UNSUPPORTED" and opens == []
    with storage.confined_file(Path(tmp_path.anchor), ("file",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(5, policy=lambda _: pytest.fail("checked policy"))
    assert caught.value.code == "CONFINED_UNSUPPORTED" and len(opens) == 1


@pytest.mark.parametrize("fault,code", [
    ("unsafe", "CONFINED_UNSAFE"), ("missing", "CONFINED_MISSING"),
    ("changed", "CONFINED_CHANGED"), ("io", "CONFINED_IO"),
    ("unreadable", "CONFINED_UNSAFE"),
    ("definite-missing", "CONFINED_MISSING"), ("definite-unsafe", "CONFINED_UNSAFE"),
])
def test_checked_read_classifies_failed_open(tmp_path, monkeypatch, fault, code):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    target.chmod(0o600)
    uid = target.stat().st_uid
    replacement = root / "replacement"
    replacement.write_bytes(b"other")
    replacement.chmod(0o600)
    name_checks = []

    def fail_open(name, flags, *, dir_fd):
        assert name == target.name and flags & os.O_NOFOLLOW and dir_fd == handle.parent_fd
        if fault == "changed" or fault.startswith("definite-"):
            replacement.replace(target)
        if fault == "definite-missing":
            raise OSError(errno.ENOENT, "private-value")
        if fault == "definite-unsafe":
            raise OSError(errno.ELOOP, "private-value")
        if fault == "unreadable":
            target.chmod(0o000)
            raise OSError(errno.EACCES, "private-value")
        if fault in ("missing", "unsafe"):
            target.unlink()
            if fault == "unsafe":
                target.mkdir()
        raise OSError(errno.EIO, "private-value")

    def stat_at(name, *, dir_fd, follow_symlinks):
        assert name == target.name and dir_fd == handle.parent_fd and follow_symlinks is False
        name_checks.append(name)
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def reject_policy(info):
        pytest.fail("failed open reached record policy")

    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=fail_open, stat=stat_at))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(5, owner_uid=uid, policy=reject_policy)
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == code and "private-value" not in str(caught.value)
        assert len(name_checks) == (1 if fault.startswith("definite-") else 2)
        if fault == "unsafe":
            target.rmdir()
        if fault == "unreadable":
            target.chmod(0o600)
        target.write_bytes(b"first")
        assert handle.read_checked(5, policy=lambda info: None)[0] == b"first"


def test_checked_read_refuses_initial_oversize_before_open_io(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    opens = []

    def open_at(*args, **kwargs):
        opens.append(args)
        raise OSError(errno.EIO, "private-value")

    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=open_at))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(4, policy=lambda _: pytest.fail("descriptor policy ran"))
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == "CONFINED_TOO_LARGE"
        assert opens == []
        assert handle.read_checked(5, policy=lambda _: None)[0] == b"first"


@pytest.mark.parametrize("fault,code", [
    ("missing", "CONFINED_MISSING"), ("unsafe", "CONFINED_UNSAFE"),
    ("changed", "CONFINED_CHANGED"), ("stable", "CONFINED_IO"),
    ("oversize", "CONFINED_TOO_LARGE"), ("nonprivate", "CONFINED_UNSAFE"),
])
def test_checked_read_classifies_failed_fstat_and_closes(tmp_path, monkeypatch, fault, code):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    target.chmod(0o600)
    uid = target.stat().st_uid
    replacement = root / "replacement"
    replacement.write_bytes(b"other")
    replacement.chmod(0o600)
    closed, inspected = [], []

    def inspect(fd):
        inspected.append(fd)
        if fault == "changed":
            replacement.replace(target)
        elif fault == "oversize":
            target.write_bytes(b"longer")
        elif fault == "nonprivate":
            target.chmod(0o640)
        elif fault in ("missing", "unsafe"):
            target.unlink()
            if fault == "unsafe":
                target.mkdir()
        raise OSError(errno.EIO, "private-value")

    def close(fd):
        os.close(fd)
        closed.append(fd)

    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(fstat=inspect, close=close))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(5, owner_uid=uid, policy=lambda _: pytest.fail("descriptor policy ran"))
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == code and "private-value" not in str(caught.value)
        assert closed == inspected and len(closed) == 1
        if fault == "unsafe":
            target.rmdir()
        target.write_bytes(b"first")
        assert handle.read_checked(5, policy=lambda _: None)[0] == b"first"


@pytest.mark.parametrize("fault,code", [
    ("stable", "CONFINED_IO"), ("changed", "CONFINED_CHANGED"), ("detached", "CONFINED_CHANGED"),
    ("nonprivate", "CONFINED_UNSAFE"), ("oversize", "CONFINED_TOO_LARGE"),
])
def test_checked_read_classifies_name_io_after_opened_stat(tmp_path, monkeypatch, fault, code):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    target.chmod(0o600)
    replacement = root / "replacement"
    replacement.write_bytes(b"other")
    replacement.chmod(0o600)
    opened, closed = [], []

    def open_at(name, flags, *, dir_fd):
        if fault == "changed":
            replacement.replace(target)
        fd = os.open(name, flags, dir_fd=dir_fd)
        opened.append(fd)
        if fault == "detached":
            target.unlink()
        elif fault == "nonprivate":
            os.fchmod(fd, 0o640)
        elif fault == "oversize":
            target.write_bytes(b"longer")
        return fd

    def stat_at(name, *, dir_fd, follow_symlinks):
        assert name == target.name and dir_fd == handle.parent_fd and follow_symlinks is False
        if opened:
            raise OSError(errno.EIO, "private-value")
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def close(fd):
        os.close(fd)
        closed.append(fd)
        if fault in ("nonprivate", "oversize"):
            raise OSError(errno.EIO, "private-value")

    with storage.confined_file(root, ("file",)) as handle:
        _, expected = handle.read_checked(5, owner_uid=target.stat().st_uid)
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=open_at, stat=stat_at, close=close))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(5, owner_uid=expected.st_uid, expected=expected,
                                policy=lambda _: pytest.fail("descriptor policy ran"))
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == code and "private-value" not in str(caught.value)
        assert closed == opened and len(closed) == 1
        if fault == "nonprivate":
            target.chmod(0o600)
        if fault in ("detached", "oversize"):
            target.write_bytes(b"first")
            target.chmod(0o600)
        assert handle.read_checked(5, owner_uid=expected.st_uid)[0] == target.read_bytes()


def test_checked_read_keeps_descriptor_policy_off_named_metadata(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    target.chmod(0o600)
    opened_stats = []

    def inspect(fd):
        info = os.fstat(fd)
        opened_stats.append(info)
        return info

    with storage.confined_file(root, ("file",)) as handle:
        uid = target.stat().st_uid
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(
            open=lambda *a, **k: pytest.fail("opened a foreign record")))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(5, owner_uid=uid + 1, policy=lambda _: pytest.fail("descriptor policy ran"))
        assert caught.value.code == "CONFINED_UNSAFE"

        def policy(info):
            assert len(opened_stats) == 1 and info is opened_stats[0]

        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(fstat=inspect))
        raw, info = handle.read_checked(5, owner_uid=uid, policy=policy)
        assert raw == b"first" and info is opened_stats[0]
        assert len(opened_stats) == 2


@pytest.mark.parametrize("surface", ["borrowed", "owned"])
@pytest.mark.parametrize("defect,later_name,code", [
    ("mode", "restored", "CONFINED_UNSAFE"),
    ("size", "restored", "CONFINED_TOO_LARGE"),
    ("mode", "different", "CONFINED_UNSAFE"),
    ("size", "different", "CONFINED_TOO_LARGE"),
    ("mode", "missing", "CONFINED_UNSAFE"),
    ("size", "missing", "CONFINED_TOO_LARGE"),
    ("detached", "different", "CONFINED_CHANGED"),
    ("detached", "missing", "CONFINED_MISSING"),
    ("detached", "io", "CONFINED_CHANGED"),
])
def test_checked_read_descriptor_defect_precedes_competing_name(
        tmp_path, monkeypatch, surface, defect, later_name, code):
    from aegis_core import storage_confined

    root = make_store(tmp_path)
    parent = root / "records"
    parent.mkdir()
    target = parent / "file"
    target.write_bytes(b"first")
    target.chmod(0o600)
    uid = target.stat().st_uid
    replacement = parent / "replacement"
    replacement.write_bytes(b"other")
    replacement.chmod(0o600)
    live = {}
    closed, name_checks, inspected = [], [], []

    def open_at(name, flags, *, dir_fd):
        fd = os.open(name, flags, dir_fd=dir_fd)
        assert fd not in live
        live[fd] = name
        return fd

    def inspect(fd):
        assert live[fd] == target.name and not inspected
        if defect == "mode":
            os.fchmod(fd, 0o640)
        elif defect == "size":
            target.write_bytes(b"too long")
        else:
            target.unlink()
        info = os.fstat(fd)
        inspected.append(info)
        if later_name == "restored":
            if defect == "mode":
                os.fchmod(fd, 0o600)
            else:
                target.write_bytes(b"first")
        elif defect != "detached":
            target.rename(parent / "displaced")
        if later_name == "different":
            replacement.replace(target)
        return info

    def stat_at(name, *, dir_fd, follow_symlinks):
        assert name == target.name and live[dir_fd] == parent.name and follow_symlinks is False
        name_checks.append(name)
        if inspected and later_name == "io":
            raise OSError(errno.EIO, "private-value")
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def close(fd):
        name = live.pop(fd)
        os.close(fd)
        closed.append(name)
        if name == target.name:
            raise OSError(errno.EIO, "private-value")

    def policy(info):
        pytest.fail("refused record reached descriptor policy")

    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(
        open=open_at, fstat=inspect, stat=stat_at, close=close,
        read=lambda *args: pytest.fail("refused record reached byte consumption")))
    parts = (parent.name, target.name)
    with pytest.raises(storage.ConfinedFileError) as caught:
        if surface == "owned":
            storage_confined.read_checked_file(root, parts, 5, owner_uid=uid, policy=policy)
        else:
            with storage.confined_file(root, parts) as handle:
                handle.read_checked(5, owner_uid=uid, policy=policy)
    assert caught.value.code == code and "private-value" not in str(caught.value)
    assert len(inspected) == 1 and inspected[0].st_nlink == (0 if defect == "detached" else 1)
    assert len(name_checks) == (2 if defect == "detached" else 1)
    assert not live and closed.count(target.name) == closed.count(parent.name) == 1


@pytest.mark.parametrize("read_fault,change,name_io,fd_io,close_io,code", [
    (None, "rewrite", True, False, False, "CONFINED_CHANGED"),
    ("io", "rewrite", True, False, False, "CONFINED_CHANGED"),
    (None, None, True, True, False, "CONFINED_IO"),
    (None, None, True, False, False, "CONFINED_IO"),
    (None, "unlink", False, True, False, "CONFINED_MISSING"),
    (None, "unlink", False, False, True, "CONFINED_MISSING"),
    (None, None, False, True, False, "CONFINED_IO"),
    ("io", None, False, False, False, "CONFINED_IO"),
    ("short", None, False, False, True, "CONFINED_CHANGED"),
    (None, None, False, False, True, "CONFINED_IO"),
])
def test_checked_read_decides_from_both_observations_and_leaf_cleanup(
        tmp_path, monkeypatch, read_fault, change, name_io, fd_io, close_io, code):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    opened, closed, reads, final_fstats = [], [], [], []

    def open_at(name, flags, *, dir_fd):
        fd = os.open(name, flags, dir_fd=dir_fd)
        opened.append(fd)
        return fd

    def read(fd, count):
        if not reads:
            reads.append(fd)
            if change == "rewrite":
                os.utime(target, ns=(0, 0))
            if change == "unlink":
                target.unlink()
            if read_fault == "io":
                raise OSError(errno.EIO, "private-value")
            if read_fault == "short":
                return b""
        return os.read(fd, count)

    def stat_at(name, *, dir_fd, follow_symlinks):
        assert name == target.name and dir_fd == handle.parent_fd and follow_symlinks is False
        if reads and name_io:
            raise OSError(errno.EIO, "private-value")
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def fstat(fd):
        if reads:
            final_fstats.append(fd)
            if fd_io:
                raise OSError(errno.EIO, "private-value")
        return os.fstat(fd)

    def close(fd):
        os.close(fd)
        closed.append(fd)
        if close_io:
            raise OSError(errno.EIO, "private-value")

    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(
            open=open_at, read=read, stat=stat_at, fstat=fstat, close=close))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(5)
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == code and "private-value" not in str(caught.value)
        assert len(opened) == 1 and closed == reads == final_fstats == opened
        if change == "unlink":
            target.write_bytes(b"first")
        assert handle.read_checked(5)[0] == b"first"


@pytest.mark.parametrize("fault,code", [
    ("ancestor-close", "CONFINED_IO"),
    ("ancestor-close-and-missing-leaf", "CONFINED_MISSING"),
    ("missing-parent", "CONFINED_MISSING"),
    ("parent-policy", "CONFINED_UNSAFE"),
    ("missing-leaf", "CONFINED_MISSING"),
    ("read-io", "CONFINED_IO"),
    ("close-only", "CONFINED_IO"),
])
def test_checked_file_preserves_decision_through_parent_cleanup(tmp_path, monkeypatch, fault, code):
    from aegis_core import storage_confined

    root = make_store(tmp_path)
    directory = root / "records"
    directory.mkdir()
    parts = ("records", "absent", "file") if fault == "missing-parent" else ("records", "file")
    target = root.joinpath(*parts)
    if fault not in ("missing-parent", "ancestor-close-and-missing-leaf"):
        target.write_bytes(b"first")
    close_name = root.name if fault.startswith("ancestor-close") else directory.name
    opened, closed, live = [], [], {}

    def open_at(name, flags, *, dir_fd):
        fd = os.open(name, flags, dir_fd=dir_fd)
        assert fd not in live
        live[fd] = name
        opened.append(name)
        return fd

    def close(fd):
        name = live.pop(fd)
        os.close(fd)
        closed.append(name)
        if name == close_name:
            raise OSError(errno.EIO, "private-value")

    def read(fd, count):
        if fault == "read-io":
            raise OSError(errno.EIO, "private-value")
        data = os.read(fd, count)
        if data and fault == "missing-leaf":
            target.unlink()
        return data

    def parent_policy(info):
        assert info.st_ino == directory.stat().st_ino
        if fault == "parent-policy":
            raise storage.ConfinedFileError("unsafe")

    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=open_at, read=read, close=close))
    with pytest.raises(storage.ConfinedFileError) as caught:
        storage_confined.read_checked_file(root, parts, 5, parent_policy=parent_policy)
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    assert caught.value.code == code and "private-value" not in str(caught.value)
    assert not live and sorted(closed) == sorted(opened) and closed.count(close_name) == 1
    if fault.startswith("ancestor-close"):
        assert target.name not in opened
    if fault.endswith("missing-leaf") or fault == "missing-parent":
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(b"first")
    assert storage_confined.read_checked_file(root, parts, 5)[0] == b"first"


@pytest.mark.parametrize("fault,code", [
    ("short", "CONFINED_CHANGED"), ("growth", "CONFINED_CHANGED"),
    ("replace", "CONFINED_CHANGED"), ("unlink", "CONFINED_MISSING"),
])
def test_checked_read_refuses_length_drift_and_detached_inode(tmp_path, monkeypatch, fault, code):
    root = make_store(tmp_path)
    target = root / "file"
    target.write_bytes(b"first")
    replacement = root / "replacement"
    replacement.write_bytes(b"other")
    opened, closed, checked, counts = [], [], [], []

    def open_at(name, flags, *, dir_fd):
        fd = os.open(name, flags, dir_fd=dir_fd)
        opened.append(fd)
        return fd

    def inspect_opened(fd):
        if fault == "replace":
            replacement.replace(target)
        if fault == "unlink":
            target.unlink()
        return os.fstat(fd)

    def close(fd):
        closed.append(fd)
        os.close(fd)

    def policy(info):
        checked.append(info)
        if info.st_nlink != 1:
            raise storage.ConfinedFileError("unsafe")

    def read(fd, count):
        assert checked and fd == opened[0]
        counts.append(count)
        if fault == "short":
            return os.read(fd, 2) if len(counts) == 1 else b""
        if len(counts) == 1:
            target.write_bytes(b"first-and-more")
        return os.read(fd, count)

    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(
            open=open_at, close=close, fstat=inspect_opened, read=read))
        with pytest.raises(storage.ConfinedFileError) as caught:
            handle.read_checked(8, policy=policy)
        monkeypatch.setattr("aegis_core.storage_confined.os", os)
        assert caught.value.code == code
        assert len(opened) == 1 and opened == closed
        if fault in ("replace", "unlink"):
            assert not checked and not counts
        else:
            assert counts[0] == 6
        target.write_bytes(b"first")
        raw, info = handle.read_checked(8, policy=policy)
        assert raw == b"first" and len(raw) == info.st_size


@pytest.mark.parametrize("component", [0, 1, 2])
@pytest.mark.parametrize("operation", ["read", "exclusive", "replace"])
def test_symlinks_at_every_component_refuse(tmp_path, component, operation):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "root")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"keep")
    parts = ("one", "two", "file")
    parent = root.joinpath(*parts[:component])
    parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(outside if component < 2 else outside / "secret",
                    parent / parts[component], target_is_directory=component < 2)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, parts, create_parents=True) as handle:
            if operation == "read":
                handle.read_bytes(100)
            else:
                handle.publish_bytes(b"bad", replace=operation == "replace")
    assert refused.value.reason == "unsafe"
    assert (outside / "secret").read_bytes() == b"keep"
    assert sorted(p.name for p in outside.iterdir()) == ["secret"]


@pytest.mark.parametrize("operation", ["read", "exclusive", "replace"])
def test_held_parent_survives_ancestor_rename(tmp_path, operation):
    from conftest import symlink_or_skip
    root = make_store(tmp_path / "root")
    root.mkdir()
    parent = root / "one/two"
    parent.mkdir(parents=True)
    if operation != "exclusive":
        (parent / "file").write_bytes(b"old")
    outside = tmp_path / "outside"
    outside.mkdir()
    with storage.confined_file(root, ("one", "two", "file")) as handle:
        (root / "one").rename(root / "moved")
        symlink_or_skip(outside, root / "one", target_is_directory=True)
        if operation == "read":
            assert handle.read_bytes(3) == b"old"
        else:
            handle.publish_bytes(b"new", replace=operation == "replace")
    assert not list(outside.iterdir())
    assert (root / "moved/two/file").read_bytes() == (b"old" if operation == "read" else b"new")


@pytest.mark.parametrize("failure", ["read", "write", "fstat", "fchmod", "fsync", "link", "replace"])
def test_failures_close_every_descriptor_and_remove_temporary(tmp_path, monkeypatch, failure):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    (root / "file").write_bytes(b"old")
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def failed(*args, **kwargs):
        raise OSError("token=secret\nuntrusted")

    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=opened, close=closed, **{failure: failed}))
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, ("file",)) as handle:
            if failure in ("read", "fstat"):
                handle.read_bytes(3)
            else:
                if failure == "link":
                    (root / "file").unlink()
                handle.publish_bytes(b"new", replace=failure != "link")
    assert refused.value.reason == ("durability" if failure == "fsync" else "io")
    assert str(refused.value) == ("confined file durability flush failed" if failure == "fsync"
                                  else "confined file I/O failed")
    assert not live
    assert sorted(p.name for p in root.iterdir()) == ([] if failure == "link" else ["file"])


def test_nonregular_file_refuses_without_blocking(tmp_path):
    root = make_store(tmp_path)
    os.mkfifo(root / "fifo")
    with storage.confined_file(root, ("fifo",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.read_bytes(10)
        assert refused.value.reason == "unsafe"


def test_handle_refuses_after_context_exit(tmp_path):
    root = make_store(tmp_path)
    with storage.confined_file(root, ("file",)) as handle:
        handle.publish_bytes(b"ok")
    for operation in (lambda: handle.read_bytes(2), lambda: handle.publish_bytes(b"bad")):
        with pytest.raises(storage.ConfinedFileError) as refused:
            operation()
        assert refused.value.reason == "closed"


@pytest.mark.parametrize("root_name", ["relative", "../escape"])
def test_untrusted_roots_refuse(tmp_path, root_name):
    make_store(tmp_path)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root_name, ("file",), create_parents=True):
            pytest.fail("invalid root admitted")
    assert refused.value.reason == "invalid_path"


def test_missing_roots_are_not_created(tmp_path):
    root = make_store(tmp_path / "missing")
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, ("state", "file"), create_parents=True):
            pytest.fail("missing root admitted")
    assert refused.value.reason == "missing" and not root.exists()


@pytest.mark.parametrize("root_name", ["/" + "x" * 32768, "/\ud800", b"/bytes"],
                         ids=["oversize", "invalid-unicode", "bytes"])
def test_invalid_root_spellings_refuse_before_open(tmp_path, monkeypatch, root_name):
    from aegis_core import storage_confined
    make_store(tmp_path)
    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root_name, ("file",)):
            pytest.fail("invalid root admitted")
    assert refused.value.reason == "invalid_path"


@pytest.mark.parametrize("argument,value,reason", [("data", bytearray(b"bad"), "invalid_data"),
    ("mode", -1, "invalid_mode"), ("mode", 0o1000, "invalid_mode"), ("mode", True, "invalid_mode")])
def test_invalid_publication_refuses_before_mutation(tmp_path, monkeypatch, argument, value, reason):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    with storage.confined_file(root, ("file",)) as handle:
        monkeypatch.setattr(storage_confined, "os", ModuleOS(open=lambda *a, **k: pytest.fail("opened")))
        kwargs = {"data": b"ok", argument: value}
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.publish_bytes(**kwargs)
    assert refused.value.reason == reason and not list(root.iterdir())


def test_zero_progress_write_refuses_and_cleans_temporary(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    monkeypatch.setattr(storage_confined, "os", ModuleOS(write=lambda *a: 0))
    with storage.confined_file(root, ("file",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.publish_bytes(b"ok")
    assert refused.value.reason == "io" and not list(root.iterdir())


def test_temporary_collision_preserves_the_unowned_file(tmp_path, monkeypatch):
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    collision = root / ".confined-collision"
    collision.write_bytes(b"keep")
    monkeypatch.setattr(storage_confined, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="collision")))
    with storage.confined_file(root, ("file",)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.publish_bytes(b"bad")
    assert refused.value.reason == "exists"
    assert collision.read_bytes() == b"keep" and not (root / "file").exists()


def test_concurrent_exclusive_publish_has_one_winner(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from aegis_core import storage_confined
    root = make_store(tmp_path)
    barrier = Barrier(2, timeout=5)

    def linked(*args, **kwargs):
        barrier.wait()
        return os.link(*args, **kwargs)

    def publish(data):
        with storage.confined_file(root, ("file",)) as handle:
            try:
                handle.publish_bytes(data)
                return "published", data
            except storage.ConfinedFileError as error:
                return error.reason, data

    monkeypatch.setattr(storage_confined, "os", ModuleOS(link=linked))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(publish, data) for data in (b"first", b"second")]
        outcomes = [future.result(timeout=10) for future in futures]
    assert sorted(reason for reason, _ in outcomes) == ["exists", "published"]
    assert (root / "file").read_bytes() == next(data for reason, data in outcomes if reason == "published")
    assert sorted(p.name for p in root.iterdir()) == ["file"]


def test_leaf_swap_during_publication_cannot_write_outside(tmp_path, monkeypatch):
    from conftest import symlink_or_skip
    from aegis_core import storage_confined
    root = make_store(tmp_path / "root")
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    target = root / "file"
    target.write_bytes(b"old")

    def replaced(*args, **kwargs):
        target.unlink()
        symlink_or_skip(outside, target)
        return os.replace(*args, **kwargs)

    monkeypatch.setattr(storage_confined, "os", ModuleOS(replace=replaced))
    with storage.confined_file(root, ("file",)) as handle:
        handle.publish_bytes(b"new", replace=True)
    assert outside.read_bytes() == b"keep" and target.read_bytes() == b"new"
    assert not target.is_symlink()


class DurabilityOS(ModuleOS):
    """Observe real boundary calls and inject a failure at one named flush."""

    def __init__(self, root, fail_flush=None):
        super().__init__()
        self.root = root
        self.fail_flush = fail_flush
        self.events = []
        self.live = {}

    def open(self, path, flags, *args, **kwargs):
        fd = os.open(path, flags, *args, **kwargs)
        spelling = os.fspath(path)
        self.live[fd] = ("root" if spelling == self.root.name else
                         "temporary" if spelling.startswith(".confined-") else spelling)
        return fd

    def close(self, fd):
        self.events.append(("close", self.live.pop(fd)))
        os.close(fd)

    def mkdir(self, path, mode, *, dir_fd):
        self.events.append(("mkdir", path, self.live[dir_fd]))
        return os.mkdir(path, mode, dir_fd=dir_fd)

    def write(self, fd, data):
        self.events.append(("write", self.live[fd]))
        return os.write(fd, data)

    def fsync(self, fd):
        label = self.live[fd]
        self.events.append(("fsync", label))
        if label == self.fail_flush:
            raise OSError("token=secret\nuntrusted flush failure")
        return os.fsync(fd)

    def link(self, source, destination, **kwargs):
        self.events.append(("link", "temporary", destination))
        return os.link(source, destination, **kwargs)

    def replace(self, source, destination, **kwargs):
        self.events.append(("replace", "temporary", destination))
        return os.replace(source, destination, **kwargs)

    def unlink(self, path, **kwargs):
        self.events.append(("unlink", "temporary"))
        return os.unlink(path, **kwargs)


@pytest.mark.parametrize("replace", [False, True])
def test_publication_flushes_every_created_entry_in_order(tmp_path, monkeypatch, replace):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    proxy = DurabilityOS(root)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with storage.confined_file(root, ("one", "two", "file"), create_parents=True) as handle:
        handle.publish_bytes(b"new", replace=replace)
    events = [event for event in proxy.events if event[0] != "close"]
    assert events == [
        ("mkdir", "one", "root"), ("fsync", "root"),
        ("mkdir", "two", "one"), ("fsync", "one"),
        ("write", "temporary"), ("fsync", "temporary"),
        ("replace" if replace else "link", "temporary", "file"),
        ("unlink", "temporary"), ("fsync", "two"),
    ]
    for directory in ("root", "one", "two"):
        assert proxy.events.index(("fsync", directory)) < proxy.events.index(("close", directory))
    assert not proxy.live
    assert (root / "one/two/file").read_bytes() == b"new"
    assert sorted(p.name for p in (root / "one/two").iterdir()) == ["file"]


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("fail_flush", ["root", "one", "temporary", "two"])
def test_each_durability_failure_refuses_and_cleans(tmp_path, monkeypatch, replace, fail_flush):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    proxy = DurabilityOS(root, fail_flush=fail_flush)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, ("one", "two", "file"), create_parents=True) as handle:
            handle.publish_bytes(b"new", replace=replace)
    assert refused.value.reason == "durability"
    assert refused.value.code == "CONFINED_DURABILITY"
    assert str(refused.value) == "confined file durability flush failed"
    assert not proxy.live
    flushes = [event[1] for event in proxy.events if event[0] == "fsync"]
    expected = ["root", "one", "temporary", "two"]
    assert flushes == expected[:expected.index(fail_flush) + 1]
    parent = root / "one/two"
    if parent.exists():
        assert not any(p.name.startswith(".confined-") for p in parent.iterdir())
    if fail_flush == "two":
        assert (parent / "file").read_bytes() == b"new"
    else:
        assert not (parent / "file").exists()


def assert_publication_flushes(proxy, directories, replace, name):
    assert [event[1] for event in proxy.events if event[0] == "fsync"] == [
        *directories[:-1], "temporary", directories[-1],
    ]
    publication = ("replace" if replace else "link", "temporary", name)
    for directory in directories[:-1]:
        flushed = proxy.events.index(("fsync", directory))
        assert flushed < proxy.events.index(publication)
        assert flushed < proxy.events.index(("close", directory))
    assert not proxy.live


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("fail_flush", ["root", "one", "two"])
def test_retry_flushes_reused_ancestor_containers(tmp_path, monkeypatch, replace, fail_flush):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    parts = ("one", "two", "three", "file")
    proxy = DurabilityOS(root, fail_flush=fail_flush)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with pytest.raises(storage.ConfinedFileError) as refused:
        with storage.confined_file(root, parts, create_parents=True) as handle:
            handle.publish_bytes(b"new", replace=replace)
    assert refused.value.reason == "durability"
    assert refused.value.code == "CONFINED_DURABILITY"
    assert str(refused.value) == "confined file durability flush failed"
    assert not proxy.live and not root.joinpath(*parts).exists()
    failed_depth = ("root", "one", "two").index(fail_flush)
    assert root.joinpath(*parts[:failed_depth + 1]).is_dir()

    proxy.fail_flush = None
    proxy.events.clear()
    with storage.confined_file(root, parts, create_parents=True) as handle:
        handle.publish_bytes(b"new", replace=replace)
    assert_publication_flushes(proxy, ("root", "one", "two", "three"), replace, "file")
    assert root.joinpath(*parts).read_bytes() == b"new"
    assert sorted(path.name for path in root.joinpath(*parts[:-1]).iterdir()) == ["file"]


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("racing_component", ["one", "two", "three"])
def test_concurrent_creator_entries_are_flushed(tmp_path, monkeypatch, replace, racing_component):
    from aegis_core import storage_confined
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    proxy = DurabilityOS(root)
    original_mkdir = proxy.mkdir
    appeared = []

    def mkdir(path, mode, *, dir_fd):
        if path == racing_component:
            # Interleave another caller's creation before our mkdir observes it;
            # that caller has not yet flushed the containing directory.
            os.mkdir(path, mode, dir_fd=dir_fd)
            appeared.append(path)
        return original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(proxy, "mkdir", mkdir)
    monkeypatch.setattr(storage_confined, "os", proxy)
    with storage.confined_file(root, ("one", "two", "three", "file"), create_parents=True) as handle:
        handle.publish_bytes(b"new", replace=replace)
    assert appeared == [racing_component]
    assert_publication_flushes(proxy, ("root", "one", "two", "three"), replace, "file")
    assert (root / "one/two/three/file").read_bytes() == b"new"


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("failed_depth", [0, 1])
def test_profile_retry_flushes_reused_ancestor_containers(tmp_path, monkeypatch, force, failed_depth):
    import json
    from aegis_core import storage_confined, team_profile as profile
    root = make_store(tmp_path / "trusted-root")
    root.mkdir()
    directories = ("root", *profile.REPO_PATH[:-1])
    proxy = DurabilityOS(root, fail_flush=directories[failed_depth])
    monkeypatch.setattr(storage_confined, "os", proxy)
    with pytest.raises(profile.ProfileError) as refused:
        profile.initialize(root, "solo", force=force)
    assert str(refused.value) == "unsafe or unreadable profile path"
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.file == str(root.joinpath(*profile.REPO_PATH))
    assert not proxy.live and not root.joinpath(*profile.REPO_PATH).exists()
    assert root.joinpath(*profile.REPO_PATH[:failed_depth + 1]).is_dir()

    proxy.fail_flush = None
    proxy.events.clear()
    document = profile.initialize(root, "solo", force=force)
    assert_publication_flushes(proxy, directories, force, profile.REPO_PATH[-1])
    assert json.loads(root.joinpath(*profile.REPO_PATH).read_bytes()) == document
    assert sorted(path.name for path in root.joinpath(*profile.REPO_PATH[:-1]).iterdir()) == [profile.REPO_PATH[-1]]


@pytest.mark.parametrize("kind", ["regular", "missing", "symlink", "fifo", "directory",
                                  "parent-swapped", "concurrent-remover"])
def test_confined_removal_cases_and_retry(tmp_path, monkeypatch, kind):
    from conftest import symlink_or_skip
    root = make_store(tmp_path)
    parent = root / "parent"
    parent.mkdir()
    target = parent / "private-value"
    outside = root / "outside"
    outside.mkdir()
    (outside / target.name).write_bytes(b"keep")
    if kind == "symlink":
        symlink_or_skip(outside / target.name, target)
    elif kind == "fifo":
        os.mkfifo(target)
    elif kind == "directory":
        target.mkdir()
    elif kind != "missing":
        target.write_bytes(b"receipt")
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def inspected(*args, **kwargs):
        info = os.stat(*args, **kwargs)
        if kind == "parent-swapped" and not (root / "moved").exists():
            parent.rename(root / "moved")
            symlink_or_skip(outside, parent, target_is_directory=True)
        return info

    def removed(*args, **kwargs):
        if kind == "concurrent-remover":
            os.unlink(*args, **kwargs)
        return os.unlink(*args, **kwargs)

    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(
        open=opened, close=closed, stat=inspected, unlink=removed))
    with storage.confined_file(root, ("parent", target.name)) as handle:
        if kind in ("symlink", "fifo", "directory", "parent-swapped"):
            for _ in range(2):
                with pytest.raises(storage.ConfinedFileError) as refused:
                    handle.remove()
                assert refused.value.reason == "unsafe"
                assert refused.value.code == "CONFINED_UNSAFE"
                assert "private-value" not in str(refused.value)
        else:
            assert handle.remove() == ("removed" if kind == "regular" else "missing")
            assert handle.remove() == "missing"
    assert not live
    assert (outside / target.name).read_bytes() == b"keep"
    if kind == "parent-swapped":
        assert (root / "moved" / target.name).read_bytes() == b"receipt"
        parent.unlink()
        (root / "moved").rename(parent)
    elif kind in ("symlink", "fifo"):
        target.unlink()
    elif kind == "directory":
        target.rmdir()
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    if kind in ("symlink", "fifo", "directory"):
        target.write_bytes(b"receipt")
    with storage.confined_file(root, ("parent", target.name)) as handle:
        expected = "removed" if target.exists() else "missing"
        assert handle.remove() == expected


@pytest.mark.parametrize("failure", ["unlink", "fsync", "fstat"])
def test_confined_removal_io_failure_closes_and_retries(tmp_path, monkeypatch, failure):
    root = make_store(tmp_path)
    target = root / "private-value"
    target.write_bytes(b"receipt")
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    def failed(*args, **kwargs):
        raise OSError("token=private-value\nfailed")

    methods = {"unlink": os.unlink, "fsync": os.fsync, "fstat": os.fstat, failure: failed}
    monkeypatch.setattr("aegis_core.storage_confined.os", ModuleOS(open=opened, close=closed, **methods))
    with storage.confined_file(root, (target.name,)) as handle:
        with pytest.raises(storage.ConfinedFileError) as refused:
            handle.remove()
        assert refused.value.reason == "io" and refused.value.code == "CONFINED_IO"
        assert str(refused.value) == "confined file I/O failed"
    assert not live
    assert target.exists() is (failure != "fsync")
    monkeypatch.setattr("aegis_core.storage_confined.os", os)
    with storage.confined_file(root, (target.name,)) as handle:
        expected = "removed" if target.exists() else "missing"
        assert handle.remove() == expected
        assert handle.remove() == "missing"


def test_concurrent_confined_removers_and_closed_handle(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    root = make_store(tmp_path)
    (root / "file").write_bytes(b"receipt")
    barrier = Barrier(2, timeout=5)

    def remove():
        with storage.confined_file(root, ("file",)) as handle:
            barrier.wait()
            return handle.remove()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(remove) for _ in range(2)]
        assert sorted(future.result(timeout=10) for future in futures) == ["missing", "removed"]
    with storage.confined_file(root, ("file",)) as handle:
        assert handle.remove() == "missing"
    with pytest.raises(storage.ConfinedFileError) as refused:
        handle.remove()
    assert refused.value.reason == "closed"
