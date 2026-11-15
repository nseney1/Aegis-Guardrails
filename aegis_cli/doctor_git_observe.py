"""Held scratch custody and bounded descriptor-based workspace observation."""
from __future__ import annotations
import contextvars, errno, os, shutil, stat, sys, types
from pathlib import Path
from aegis_core.storage_confined import ConfinedFileError, confined_file, descriptor_supported
from aegis_cli import doctor_git_report as report

MAX_HEAVY, PEAK_BYTES, RESERVE_BYTES, LARGE_BYTES, MAX_DEPTH, MAX_ENTRIES, PROBE = (
    3, 8 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024, 50 * 1024 * 1024, 3, 256, "aegis-doctor-probe")
_confined, _scandir = confined_file, os.scandir
_HELD = contextvars.ContextVar("aegis_doctor_held", default=None)
SCRATCH = contextvars.ContextVar("aegis_doctor_scratch", default=None)
_OVERFLOW = object()
# Selection and both containment checks share a scratch-to-root step bound.
_ANCESTRY_LIMIT = report.VALUE_MAX
__all__ = [
    'descriptor_support',
    'SCRATCH',
    'close_fd',
    'validated_scratch',
    'use_scratch',
    'trusted_root',
    'disk_rows',
    'scratch_rows',
    'walk',
    'MAX_HEAVY',
    'PEAK_BYTES',
    'RESERVE_BYTES',
    'LARGE_BYTES',
    'MAX_DEPTH',
    'MAX_ENTRIES',
    'PROBE',
]

def descriptor_support():
    return descriptor_supported()

def _disk_usage(path):
    if isinstance(path, int) and not isinstance(path, bool):
        info = os.statvfs(path)
        return types.SimpleNamespace(total=info.f_blocks * info.f_frsize, used=0, free=info.f_bavail * info.f_frsize)
    return shutil.disk_usage(path)

def _scratch_env():
    return os.environ

def close_fd(fd):
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0: return
    try: os.close(fd)
    except OSError: return

def _stat_pair(path):
    try: info = os.stat(path)
    except OSError: return None
    return (info.st_dev, info.st_ino)

def _bind_fd(fd, dev, ino):
    if not isinstance(fd, int) or isinstance(fd, bool) or fd < 0 or os.name != "posix" or not os.path.isdir("/proc/self/fd"): return None
    link = "/proc/self/fd/%d" % fd
    return link if _stat_pair(link) == (dev, ino) else None

def _private_dir(info):
    mode = info.st_mode
    if not hasattr(os, "geteuid") or info.st_uid != os.geteuid(): return False
    if mode & (stat.S_IWOTH | stat.S_ISVTX | stat.S_IWGRP): return False
    return bool(mode & stat.S_IWUSR and mode & stat.S_IXUSR)

def _acl_free(fd):
    if sys.platform != "linux" or not callable(getattr(os, "getxattr", None)): return False
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try: value = os.getxattr(fd, name)
        except (OSError, ValueError, NotImplementedError) as exc:
            if getattr(exc, "errno", None) == errno.ENODATA: continue
            raise ConfinedFileError("io") from None
        if not isinstance(value, bytes): raise ConfinedFileError("io")
        return False
    return True

def _inside_root(link, root):
    root_id, seen, current = _stat_pair(root), set(), link
    if root_id is None: return True
    for _step in range(_ANCESTRY_LIMIT):
        ident = _stat_pair(current)
        if ident is None or ident in seen or ident == root_id: return True
        seen.add(ident)
        parent = _stat_pair(current + "/..")
        if parent is None or parent == ident: return parent is None
        current += "/.."
    return True

def _held_inside_root(root, fd, top):
    """Check held ancestry without depending on procfs or ACL support."""
    try:
        root_id = _stat_pair(root)
        if root_id is None or top is None: raise ConfinedFileError("io")
        seen = set()
        for step in range(_ANCESTRY_LIMIT):
            info = os.fstat(fd) if step == 0 else os.stat(
                "/".join(("..",) * step), dir_fd=fd, follow_symlinks=False)
            ident = (info.st_dev, info.st_ino)
            if ident == root_id: return True
            if ident == top: return False
            if ident in seen: break
            seen.add(ident)
    except (OSError, ValueError, NotImplementedError):
        raise ConfinedFileError("io") from None
    raise ConfinedFileError("io")

def _scratch_ok(root, fd, dev, ino):
    if not isinstance(fd, int) or isinstance(fd, bool): return None
    try: info = os.fstat(fd)
    except OSError: raise ConfinedFileError("io") from None
    if (info.st_dev, info.st_ino) != (dev, ino) or not stat.S_ISDIR(info.st_mode): return None
    if not _private_dir(info): return None
    shared = tuple(_stat_pair(path) for path in ("/", "/tmp", "/var/tmp"))
    if (dev, ino) in shared or _held_inside_root(root, fd, shared[0]): return None
    if (sys.platform != "linux" or not callable(getattr(os, "getxattr", None))
            or not os.path.isdir("/proc/self/fd")):
        raise ConfinedFileError("unsupported")
    if not _acl_free(fd): return None
    link = _bind_fd(fd, dev, ino)
    if link is None: raise ConfinedFileError("io")
    if _inside_root(link, root): return None
    if not os.access(link, os.W_OK | os.X_OK, effective_ids=True): return None
    return link

def _scratch_bad(code):
    code = report.scratch_refusal(code)[0]
    return types.SimpleNamespace(path=None, fd=None, dev=None, ino=None, code=code, shown=None, owned=False, bind=None)

def _hold_scratch(path):
    fd = None
    try:
        with _confined(Path(path), (PROBE,)) as handle:
            parent = getattr(handle, "_parent", None)
            if isinstance(parent, bool) or not isinstance(parent, int) or parent < 0: raise ConfinedFileError("io")
            fd = os.dup(parent)
        os.set_inheritable(fd, False); info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode): raise ConfinedFileError("io")
        return fd, info.st_dev, info.st_ino
    except BaseException:
        close_fd(fd)
        raise

def validated_scratch(root):
    kind, value = _scratch_choice()
    if kind != "path": return _scratch_bad("scratch_unsafe")
    shown, refused = report.display(value)
    if refused or not shown: return _scratch_bad("scratch_unsafe")
    if not descriptor_support(): return _scratch_bad("scratch_unsupported")
    try: fd, dev, ino = _hold_scratch(value)
    except (ConfinedFileError, OSError, ValueError, NotImplementedError) as exc:
        return _scratch_bad(_scratch_error(exc))
    accepted = False
    try:
        bind = _scratch_ok(root, fd, dev, ino)
        if not isinstance(bind, str): return _scratch_bad("scratch_unsafe")
        accepted = True
        return types.SimpleNamespace(path=value, fd=fd, dev=dev, ino=ino, code=None, shown=shown, owned=True, bind=bind)
    except (OSError, ValueError, NotImplementedError) as exc:
        return _scratch_bad(_scratch_error(exc))
    finally:
        if not accepted: close_fd(fd)

def _scratch_error(exc):
    reason = getattr(exc, "reason", None)
    number = getattr(exc, "errno", None)
    if reason == "missing" or number == errno.ENOENT:
        return "scratch_missing"
    if reason in ("unsafe", "invalid_path") or number in (errno.ELOOP, errno.ENOTDIR):
        return "scratch_unsafe"
    # Confined helpers deliberately discard OS errno for generic I/O refusals.
    # That cannot establish a safety violation; keep the advice neutral.
    return "scratch_unsupported"

def use_scratch(root):
    bound = SCRATCH.get()
    if bound is not None:
        return bound, False
    return validated_scratch(root), True

def trusted_root(root):
    try:
        path = Path(root)
        if not path.is_absolute(): path = Path.cwd() / path
        resolved = path.resolve()
    except (OSError, ValueError, RuntimeError): return None
    if not resolved.is_dir(): return None
    return resolved

def disk_rows(rows, disk, scratch):
    target = scratch.fd if not scratch.code else None
    if target is None:
        rows.append(report.row("disk_budget", "warn", "disk_unknown", report.SCRATCH_ACT, "scratch filesystem is unknown"))
        return
    try:
        free = _disk_usage(target).free
    except (OSError, AttributeError, ValueError):
        rows.append(report.row("disk_budget", "warn", "disk_unknown", report.RETRY, "scratch filesystem is unknown"))
        return
    if isinstance(free, bool) or not isinstance(free, int):
        rows.append(report.row("disk_budget", "warn", "disk_unreadable", report.RETRY, "free space could not be read"))
        return
    peak = PEAK_BYTES if isinstance(PEAK_BYTES, int) and not isinstance(PEAK_BYTES, bool) and PEAK_BYTES > 0 else 1
    reserve = RESERVE_BYTES if isinstance(RESERVE_BYTES, int) and not isinstance(RESERVE_BYTES, bool) and RESERVE_BYTES >= 0 else 0
    heavy = MAX_HEAVY if isinstance(MAX_HEAVY, int) and not isinstance(MAX_HEAVY, bool) and MAX_HEAVY > 0 else 1
    slots = min(heavy, max(0, (free - reserve) // peak))
    disk.update(free=free, reserve=reserve, peak=peak, budget_slots=slots)
    if slots <= 0:
        rows.append(report.row("disk_budget", "warn", "disk_low", report.DISK, "no heavy slot fits in the free space"))
        return
    rows.append(report.row("disk_budget", "pass", "disk_budget", report.NONE, f"{slots} heavy slots fit"))

def _scratch_choice():
    env = _scratch_env()
    selected, join = None, None
    if hasattr(env, "__contains__") and "AEGIS_SCRATCH" in env:
        selected, join = env["AEGIS_SCRATCH"], "as-is"
    elif hasattr(env, "__contains__") and "XDG_CACHE_HOME" in env and env["XDG_CACHE_HOME"]:
        selected, join = env["XDG_CACHE_HOME"], "xdg"
    else:
        for key in ("HOME", "USERPROFILE"):
            if hasattr(env, "__contains__") and key in env and env[key]:
                selected, join = env[key], "home"
                break
    if not isinstance(selected, str) or not selected:
        return ("code", "scratch_unusable")
    if len(selected) > report.VALUE_MAX:
        return ("code", "value_too_long")
    if "\n" in selected or "\r" in selected or "\x00" in selected:
        return ("code", "multiline_refused")
    if join == "as-is":
        path = selected
    elif join == "xdg":
        path = str(Path(selected) / "aegis")
    else:
        path = str(Path(selected) / ".cache" / "aegis")
    if len(path) > report.VALUE_MAX or "\n" in path or "\r" in path or "\x00" in path:
        return ("code", "multiline_refused" if "\n" in path or "\r" in path or "\x00" in path else "value_too_long")
    parts = Path(path).parts
    if not os.path.isabs(path) or ".." in parts or len(parts) > _ANCESTRY_LIMIT:
        return ("code", "scratch_unusable")
    return ("path", path)

def scratch_rows(rows, disk, scratch):
    if scratch.code:
        code, action, detail = report.scratch_refusal(scratch.code)
        rows.append(report.row("scratch", "warn", code, action, detail))
        return
    disk["scratch"] = scratch.shown
    rows.append(report.row("scratch", "pass", "scratch_outside", report.NONE, "scratch is outside the workspace"))

def _directory_identity(root, parts):
    with _confined(Path(root), (*(parts or ()), PROBE)) as handle:
        info = handle.parent_stat()
    return (info.st_dev, info.st_ino)

class _Snap:
    def __init__(self, name, mode, size):
        self.name = name
        self.mode = mode
        self.size = size

class _Bad:
    def __init__(self, code, name=None):
        self.code = code
        self.name = name

def _held_descriptor():
    fd = getattr(_HELD.get(), "_parent", None)
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        return None
    return fd

def _entry_cap():
    return MAX_ENTRIES if isinstance(MAX_ENTRIES, int) and not isinstance(MAX_ENTRIES, bool) and MAX_ENTRIES > 0 else 1

def _read_dir(target, limit):
    iterator = _scandir(target)
    found = []
    try:
        source = iterator if hasattr(iterator, "__next__") else iter(iterator)
        for _ in range(limit + 1):
            try:
                found.append(next(source))
            except StopIteration:
                break
        return found
    finally:
        close = getattr(iterator, "close", None)
        if close is not None: close()

def _snapshot(entry):
    fd = _held_descriptor()
    if fd is None:
        return entry
    name = getattr(entry, "name", None)
    _shown, code = _entry_name(entry)
    if code:
        return _Bad(code, name if isinstance(name, str) else None)
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError:
        return _Bad("unreadable_path", name)
    return _Snap(name, info.st_mode, info.st_size)

def _list_checked(root, parts, limit):
    path = Path(root).joinpath(*parts)
    with _confined(Path(root), (*(parts or ()), PROBE)) as handle:
        token = _HELD.set(handle)
        try:
            fd = _held_descriptor()
            target = fd if fd is not None else path
            held_id = None
            if fd is not None:
                try:
                    info = os.fstat(fd)
                except OSError:
                    return "unreadable_path"
                held_id = (info.st_dev, info.st_ino)
            for _attempt in (0, 1):
                before = _directory_identity(root, parts)
                if held_id is not None and before != held_id:
                    continue
                try:
                    entries = _read_dir(target, limit)
                except OSError:
                    return "unreadable_path"
                after = _directory_identity(root, parts)
                if held_id is not None:
                    if after != held_id:
                        continue
                elif before != after:
                    continue
                overflow = len(entries) > limit
                chosen = [_snapshot(entry) for entry in entries[:limit]]
                if overflow:
                    chosen.append(_OVERFLOW)
                return chosen
            return "path_changed"
        finally:
            _HELD.reset(token)

def _entry_name(entry):
    name = getattr(entry, "name", None)
    if not isinstance(name, str) or not 1 <= len(name) <= 255:
        return None, "value_too_long"
    if name in (".", "..") or any(char in name for char in ("/", "\\")) or any(char in report.LINE_BREAKS for char in name):
        return None, "multiline_refused"
    return name, None

def _entry_parts(parts, name):
    return parts + (name,) if isinstance(name, str) else parts

def _path_refusal(code, parts):
    if code in report.LIMIT_CODES:
        return report.limit_row(code, parts)
    action = {
        "path_changed": report.RETRY, "symlink_refused": report.NO_FOLLOW,
        "descriptor_unsupported": report.PLATFORM, "unreadable_path": report.INSPECT,
        "multiline_refused": report.RENAME, "value_too_long": report.RENAME,
    }.get(code, report.RETRY)
    detail = {
        "path_changed": "a directory changed while it was listed",
        "symlink_refused": "a symlink was not followed",
        "descriptor_unsupported": "untrusted paths were not opened",
        "unreadable_path": "a directory could not be read",
        "multiline_refused": "a directory entry was refused",
        "value_too_long": "a directory entry was refused",
    }.get(code, "a path was refused")
    if parts:
        shown = report.location(parts, prefix=detail + " (", suffix=")")
        detail = f"{detail} ({shown})"
    return report.row("disk_walk", "warn", code, action, detail)

def _file_rows(root, parts, name, mode, size, rows, state, depth):
    location = parts + (name,)
    if stat.S_ISLNK(mode):
        shown = report.location(location, prefix="symlink ", suffix=" was not followed")
        rows.append(report.row("disk_walk", "warn", "symlink_refused", report.NO_FOLLOW, f"symlink {shown} was not followed"))
        return
    limit = LARGE_BYTES if isinstance(LARGE_BYTES, int) and not isinstance(LARGE_BYTES, bool) else 1
    if stat.S_ISREG(mode) and size >= limit:
        shown = report.location(location, prefix="large file ")
        rows.append(report.row("disk_walk", "warn", "large_path", report.NO_DELETE, f"large file {shown}"))
        return
    depth_limit = MAX_DEPTH if isinstance(MAX_DEPTH, int) and not isinstance(MAX_DEPTH, bool) else 1
    if stat.S_ISDIR(mode):
        if depth + 1 >= depth_limit or state["capped"]:
            rows.append(_path_refusal("depth_capped" if depth + 1 >= depth_limit else "scan_capped", location))
        else:
            _walk_dir(root, location, rows, state, depth + 1)

def _consider(root, parts, entry, rows, state, depth):
    if isinstance(entry, _Bad):
        rows.append(_path_refusal(entry.code, _entry_parts(parts, entry.name)))
        return
    shown, code = _entry_name(entry)
    if code or not shown:
        rows.append(_path_refusal(code or "value_too_long", _entry_parts(parts, getattr(entry, "name", None))))
        return
    location = parts + (entry.name,)
    if isinstance(entry, _Snap):
        _file_rows(root, parts, entry.name, entry.mode, entry.size, rows, state, depth)
        return
    try:
        linked = bool(entry.is_symlink())
    except OSError:
        rows.append(_path_refusal("unreadable_path", location))
        return
    if linked:
        shown = report.location(location, prefix="symlink ", suffix=" was not followed")
        rows.append(report.row("disk_walk", "warn", "symlink_refused", report.NO_FOLLOW, f"symlink {shown} was not followed"))
        return
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        rows.append(_path_refusal("unreadable_path", location))
        return
    _file_rows(root, parts, entry.name, info.st_mode, info.st_size, rows, state, depth)

def _walk_dir(root, parts, rows, state, depth):
    if state["capped"]: return
    cap = _entry_cap()
    if state["entries"] + state["hold"] >= cap:
        probe = []
        if parts:
            try: probe = _list_checked(root, parts, 0)
            except ConfinedFileError as exc: probe = exc
        if probe:
            state["capped"] = True
            rows.append(_path_refusal(probe if isinstance(probe, str) else "scan_capped" if isinstance(probe, list) else _confined_code(probe), parts))
        return
    remaining = cap - state["entries"] - state["hold"]
    state["hold"] += remaining
    try:
        listed = _list_checked(root, parts, remaining)
    except ConfinedFileError as exc:
        rows.append(_path_refusal(_confined_code(exc), parts))
        return
    finally:
        state["hold"] -= remaining
    if isinstance(listed, str):
        rows.append(_path_refusal(listed, parts))
        return
    body, overflow = [], False
    for entry in listed:
        if entry is _OVERFLOW:
            overflow = True
            break
        body.append(entry)
    state["hold"] += len(body); local = len(body)
    try:
        for entry in body:
            if state["entries"] >= cap:
                if not state["capped"]:
                    state["capped"] = True; rows.append(_path_refusal("scan_capped", parts))
                return
            state["hold"] -= 1
            local -= 1
            state["entries"] += 1
            _consider(root, parts, entry, rows, state, depth)
        if overflow and not state["capped"]:
            state["capped"] = True
            rows.append(_path_refusal("scan_capped", parts))
    finally:
        state["hold"] -= local

def _confined_code(exc):
    reason = getattr(exc, "reason", "")
    return "symlink_refused" if reason == "unsafe" else "descriptor_unsupported" if reason == "unsupported" else "unreadable_path"

def walk(root, rows):
    if not descriptor_support():
        rows.append(report.row("disk_walk", "warn", "descriptor_unsupported", report.PLATFORM, "untrusted paths were not opened"))
        return
    _walk_dir(root, (), rows, {"entries": 0, "capped": False, "hold": 0}, 0)
