"""Derived mailbox cache; pinned message files remain the only truth.

New/changed files receive full pinned validation. Unchanged stat keys reuse
VALIDITY; every read still checks routing, IDs, limits, entry types and replies.
The source hash is refreshed only on source stat changes; the manifest digest
is fixed per instance, like the wrapped Mailbox's loaded manifest.

Residuals: same-user forged VALID OR INVALID cached headers with matching stat
keys, and ancestors of briefs, readiness.worktree or scan_workspace replaced by
symlinks, can escape ordinary reads.
Phase-0 callers must shadow every read with compare(). verify() rereads, hashes
and fully validates every message; it detects/repairs forged cache headers and
refuses bad brief paths with the pinned error. Hash history is not authenticated;
discarding a cache loses previous observations. There is no transactional read
snapshot during concurrent mailbox mutation.

POSIX keys include ctime. On Windows st_ctime_ns is creation time, so reuse uses
the ADR baseline (relpath, size, mtime_ns, inode); preserved-mtime in-place edits
there require verify(). Ownership/mode checks are skipped without os.getuid.
Where dir_fd is supported, cache ancestors are opened without following links,
and all cache operations use the verified directory descriptor. Else path checks
are the fallback and do not protect against concurrent directory replacement.
Cache files must be private, regular and singly linked. Old temp cleanup is
best effort. Log size checks/appends hold a bounded nonblocking flock; without
fcntl, concurrent appenders can exceed the cap. Full/busy logs are reported in
differences. Budget failures disable encoding per instance until the entry count
grows; reads then fall back to full validation. A new instance also retries.
Write failures warn and populate last_write_error, never invalidate a good read.
Python 3.9 stdlib only; inbox and the doctor CLI are outside this increment.
"""
from __future__ import annotations

import copy
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time
import uuid
import warnings

from tools import hierarchy_mailbox as hm

try:
    import fcntl
except ImportError:
    fcntl = None


SCHEMA = "aegis.mailbox-index/v2"
MAX_CACHE_BYTES = 64 * 1024 * 1024
MAX_DIVERGENCE_BYTES = 1024 * 1024
TEMP_MAX_AGE_SECONDS = 3600
DIR_FD = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")
LOG_LOCK_TIMEOUT_SECONDS = 0.05
LOG_LOCK_POLL_SECONDS = 0.005


class IndexDivergence(ValueError):
    """The pinned scan did not reproduce the index's problem."""


class UnsafeCache(ValueError):
    """A cache filesystem refusal; never downgraded to a write warning."""


class _BudgetExceeded(OSError):
    def __init__(self):
        super().__init__(errno.EFBIG, "cache disabled for this mailbox size; reads fall back to full validation; "
                         "see MAX_CACHE_BYTES in tools/hierarchy_mailbox_index.py")


def _unsafe(path, reason):
    return UnsafeCache("unsafe mailbox cache (" + reason + "): " + str(path)
                       + "; move it aside and rebuild in a private directory")


def _private(path, metadata, *, directory=False):
    if stat.S_ISLNK(metadata.st_mode):
        raise _unsafe(path, "symlink")
    if not (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)):
        raise _unsafe(path, "wrong file type")
    if not directory and metadata.st_nlink != 1:
        raise _unsafe(path, "multiple hard links")
    if hasattr(os, "getuid"):
        if metadata.st_uid != os.getuid():
            raise _unsafe(path, "not owned by the current uid")
        if metadata.st_mode & (0o022 if directory else 0o077):
            raise _unsafe(path, "group/world writable" if directory else "group/world readable or writable")


class _Directory:
    """All cache names are constants or generated basenames, never cache input."""
    def __init__(self, path):
        self.path, self.fd = path, None
        if DIR_FD:
            descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in path.parts[1:]:
                    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                    try:
                        child = os.open(part, flags, dir_fd=descriptor)
                    except FileNotFoundError:
                        try:
                            os.mkdir(part, 0o700, dir_fd=descriptor)
                        except FileExistsError:
                            pass  # Another reader created the same cache directory.
                        child = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                _private(path, os.fstat(descriptor), directory=True)
                self.fd, descriptor = descriptor, None
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise _unsafe(path, "symlink or non-directory ancestor") from exc
                raise
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        else:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            _private(path, path.lstat(), directory=True)
        self.sweep()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)

    def _fallback(self):
        try:
            hm.safe_path(self.path)
        except ValueError as exc:
            raise _unsafe(self.path, "symlink") from exc
        _private(self.path, self.path.lstat(), directory=True)

    def metadata(self, name):
        if self.fd is None:
            self._fallback()
        try:
            value = (os.stat(name, dir_fd=self.fd, follow_symlinks=False) if self.fd is not None
                     else (self.path / name).lstat())
        except FileNotFoundError:
            return None
        _private(self.path / name, value)
        return value

    def open(self, name, flags):
        self.metadata(name)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = (os.open(name, flags, 0o600, dir_fd=self.fd) if self.fd is not None
                      else os.open(str(self.path / name), flags, 0o600))
        try:
            _private(self.path / name, os.fstat(descriptor))
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def replace(self, source, destination):
        self.metadata(destination)
        if self.fd is not None:
            os.replace(source, destination, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        else:
            self._fallback()
            os.replace(str(self.path / source), str(self.path / destination))

    def unlink(self, name):
        if self.fd is not None:
            os.unlink(name, dir_fd=self.fd)
        else:
            self._fallback()
            os.unlink(str(self.path / name))

    def sweep(self):
        try:
            names = os.listdir(self.fd if self.fd is not None else self.path)
        except OSError:
            return
        cutoff = time.time() - TEMP_MAX_AGE_SECONDS
        for name in names:
            if name.startswith(".index-") and name.endswith(".tmp"):
                try:
                    metadata = self.metadata(name)
                    if metadata is not None and metadata.st_mtime < cutoff:
                        self.unlink(name)
                except (OSError, UnsafeCache):
                    pass  # Optional cleanup; these files are never cache inputs.


def _json_tree(value, depth=0):
    """One walk of parsed message values: ASCII keys and encoder-safe numbers."""
    hm.require(depth <= 64, "cache nesting limit exceeded")
    if isinstance(value, dict):
        for key, item in value.items():
            hm.require(key.isascii(), "non-ASCII cache key")
            _json_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _json_tree(item, depth + 1)
    elif isinstance(value, float):
        hm.require(math.isfinite(value), "non-finite cached number")


def _same_order(left, right):
    if isinstance(left, dict) and isinstance(right, dict):
        return list(left) == list(right) and all(_same_order(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same_order(a, b) for a, b in zip(left, right))
    return not isinstance(left, (dict, list)) and not isinstance(right, (dict, list))


def _copy_json(value):
    if isinstance(value, dict):
        return {key: _copy_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_json(item) for item in value]
    return value  # JSON scalar values are immutable.


def _dump(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _cache_bytes(value):
    prefix = _dump({key: item for key, item in value.items() if key != "entries"})[:-1] + b',"entries":{'
    parts, size = [prefix], len(prefix) + 3  # Closing braces and newline.
    if size > MAX_CACHE_BYTES:
        raise _BudgetExceeded()
    for offset, (relpath, entry) in enumerate(value["entries"].items()):
        part = (b"," if offset else b"") + _dump(relpath) + b":" + _dump(entry)
        size += len(part)
        if size > MAX_CACHE_BYTES:
            raise _BudgetExceeded()
        parts.append(part)
    parts.append(b"}}\n")
    return b"".join(parts)


class MailboxIndex:
    def __init__(self, mailbox, directory=None):
        self.mailbox = mailbox
        try:
            self.directory = mailbox.outside_mailbox(
                directory if directory is not None else mailbox.root.parent / "mailbox-index",
                "mailbox index directory")
        except ValueError as exc:
            raise UnsafeCache(str(exc) + "; choose a private directory outside the mailbox") from exc
        self.cache_path = self.directory / "index.json"
        self.content_changed, self.last_write_error = [], None
        self._state, self._disk_key = None, None
        self._source_key, self._source_sha = None, None
        self._budget_count, self._budget_error = None, None
        self._manifest_sha = hm.digest(mailbox.manifest)
        folders = {mailbox.root / e.split("/")[0] / e.split("/")[1] for e in mailbox.manifest["endpoints"]}
        folders |= {mailbox.root / "across" / role for role in hm.ACROSS_ROLES}
        self._folders = [(folder, folder.relative_to(mailbox.root).as_posix()) for folder in sorted(folders)]
        self._folder_names = {name for _, name in self._folders}
        self._folder_paths = tuple(dict.fromkeys(
            part for folder, _ in self._folders for part in (folder, *folder.parents)))

    @staticmethod
    def _key(metadata):
        baseline = [metadata.st_size, metadata.st_mtime_ns, metadata.st_ino]
        return baseline if os.name == "nt" else baseline + [metadata.st_ctime_ns]

    def _directory(self):
        return _Directory(self.directory)

    def _binding(self):
        source = Path(hm.__file__)
        key = MailboxIndex._key(source.stat())
        if key != self._source_key:
            self._source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
            self._source_key = key
        return {"schema": SCHEMA, "mailbox_root": str(self.mailbox.root),
                "manifest_sha256": self._manifest_sha, "source_sha256": self._source_sha}

    def _schema(self, value, binding):
        hm.fields(value, set(binding) | {"entries"})
        hm.require(all(value[k] == expected for k, expected in binding.items()), "stale cache binding")
        entries = value["entries"]
        hm.require(isinstance(entries, dict) and len(entries) <= hm.MAX_RECORDS, "invalid cache entries")
        for relpath, entry in entries.items():
            path = Path(relpath)
            hm.require(not path.is_absolute() and ".." not in path.parts and "\x00" not in relpath
                       and len(path.parts) == 3 and path.suffix == ".md" and path.as_posix() == relpath
                       and path.parent.as_posix() in self._folder_names
                       and not path.name.startswith(".pending-"), "invalid cache relative path")
            hm.fields(entry, {"key", "message", "sha256", "valid", "destination"})
            key = entry["key"]
            hm.require(isinstance(key, list) and len(key) == (3 if os.name == "nt" else 4)
                       and all(type(i) is int for i in key) and key[0] >= 0 and key[2] >= 0,
                       "invalid cache stat key")
            hm.require(entry["valid"] is True and isinstance(entry["message"], dict), "invalid cache entry")
            hm.require(isinstance(entry["destination"], str) and entry["destination"].isascii(),
                       "invalid cached destination")
            hm.matching(entry["sha256"], hm.SHA256, "cached sha256")
            _json_tree(entry["message"])
        return value

    def _load(self, store, binding):
        try:
            metadata = store.metadata("index.json")
        except OSError:
            return None
        if metadata is None or metadata.st_size > MAX_CACHE_BYTES:
            return None
        disk_key = MailboxIndex._key(metadata)
        if self._state is not None and disk_key == self._disk_key:
            if all(self._state[k] == expected for k, expected in binding.items()):
                return self._state
        try:
            with os.fdopen(store.open("index.json", os.O_RDONLY), "rb") as stream:
                opened_key = MailboxIndex._key(os.fstat(stream.fileno()))
                raw = stream.read(MAX_CACHE_BYTES + 1)
            hm.require(len(raw) <= MAX_CACHE_BYTES, "cache byte limit exceeded")
            value = self._schema(hm.strict_json(raw.decode("utf-8")), binding)
        except UnsafeCache:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
            return None
        self._state, self._disk_key = value, opened_key
        return value

    def _read_message(self, path):
        try:
            raw = hm.read_bytes(path)
        except ValueError as exc:
            if str(exc) == "file unavailable: " + str(path) and not path.exists():
                raise FileNotFoundError(errno.ENOENT, str(exc), str(path)) from exc
            raise
        text = raw.decode("utf-8")
        hm.require(text.startswith("---\n"), "missing header")
        header, body = text[4:].split("\n---\n\n", 1)
        message = hm.strict_json(header)
        message["body"] = body
        return message, hashlib.sha256(raw).hexdigest()

    def _scan(self, old, *, verify):
        records, entries, changes, dirty = {}, {}, [], False
        # Absolute/traversal checks were established by Mailbox and its manifest.
        # Check the pinned safe_path symlink invariant once per distinct ancestor.
        for part in self._folder_paths:
            hm.require(not part.is_symlink(), "symlink paths are not supported: " + str(part))
        for folder, folder_rel in self._folders:
            for path in sorted(folder.iterdir()):
                metadata = path.lstat()
                hm.require(not stat.S_ISLNK(metadata.st_mode), "symlink mailbox entry is not supported")
                if path.name.startswith(".pending-"):
                    continue
                hm.require(path.suffix == ".md", "unexpected mailbox entry: " + str(path))
                hm.require(len(records) < hm.MAX_RECORDS, "mailbox exceeds record limit")
                hm.require(stat.S_ISREG(metadata.st_mode), "input must be a regular file")
                relpath = folder_rel + "/" + path.name
                key = self._key(metadata)
                previous = old.get(relpath)
                if previous is not None and previous["key"] == key and not verify:
                    entry = previous
                    message = entry["message"]
                else:
                    message, sha = self._read_message(path)
                    destination = self.mailbox.validate_message(message, stored=True)
                    entry = {"key": key, "message": message, "sha256": sha, "valid": True,
                             "destination": destination.relative_to(self.mailbox.root).as_posix()}
                    dirty = True
                    if previous is not None:
                        if sha != previous["sha256"]:
                            changes.append({"kind": "content_changed", "path": str(path),
                                            "old_sha256": previous["sha256"], "new_sha256": sha})
                        elif verify and (hm.encoded(message) != hm.encoded(previous["message"])
                                         or not _same_order(message, previous["message"])):
                            changes.append({"kind": "cache_header_changed", "path": str(path),
                                            "old_header_sha256": hm.digest(previous["message"]),
                                            "new_header_sha256": hm.digest(message)})
                hm.require(entry["destination"] == folder_rel, "message is in the wrong routing folder")
                hm.require(message["message_id"] not in records, "duplicate message_id in history")
                entries[relpath] = entry
                records[message["message_id"]] = {"path": str(path), "message": message}
        for record in records.values():
            if "in_reply_to" in record["message"]:
                self.mailbox.reply(record["message"], records)
        return records, entries, changes, dirty or len(entries) != len(old)

    def _write(self, store, value):
        raw = _cache_bytes(value)
        temporary = ".index-" + uuid.uuid4().hex + ".tmp"
        descriptor = store.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                owned = os.fstat(stream.fileno())
                if store.fd is not None:
                    store.replace(temporary, "index.json")
                    written_key = MailboxIndex._key(os.fstat(stream.fileno()))
                else:
                    written_key = None
            if store.fd is None:
                store.replace(temporary, "index.json")
                published = store.metadata("index.json")
                if published is not None and (published.st_dev, published.st_ino) == (owned.st_dev, owned.st_ino):
                    written_key = MailboxIndex._key(published)
            self._state, self._disk_key = value, written_key
            self._budget_count, self._budget_error = None, None
        finally:
            try:
                store.unlink(temporary)
            except OSError:
                pass  # Crash leftovers are never trusted and are swept after the age bound.

    def _write_warning(self, error):
        self.last_write_error = str(error)
        warnings.warn("mailbox cache write failed: " + str(error), RuntimeWarning, stacklevel=3)

    def _read(self, *, verify=False):
        store, error = None, None
        self.last_write_error = None
        try:
            try:
                store = self._directory()
            except OSError as exc:
                error = exc
            binding = self._binding()
            if store is not None and self._budget_count is not None:
                try:
                    store.metadata("index.json")  # Unsafe cache files must still refuse.
                except OSError:
                    pass  # An unreadable cache remains disposable.
                state = None
            else:
                state = self._load(store, binding) if store is not None else None
            old = state["entries"] if state is not None else {}
            try:
                try:
                    result = self._scan(old, verify=verify)
                except FileNotFoundError:
                    result = self._scan(old, verify=verify)  # One bounded listing/lstat race retry.
            except (OSError, ValueError, TypeError, KeyError) as exc:
                self.mailbox.messages()
                raise IndexDivergence("mailbox index divergence: " + str(exc)
                                      + "; run compare() or verify()") from exc
            records, entries, changes, dirty = result
            self.content_changed = [v for v in changes if v["kind"] == "content_changed"]
            if store is not None and (state is None or dirty):
                if self._budget_count is not None and len(entries) <= self._budget_count:
                    self.last_write_error = self._budget_error
                else:
                    try:
                        self._write(store, {**binding, "entries": entries})
                    except _BudgetExceeded as exc:
                        self._budget_count, self._budget_error = len(entries), str(exc)
                        self._state, self._disk_key = None, None
                        error = exc
                    except OSError as exc:
                        error = exc
            if error is not None:
                self._write_warning(error)
            return records, changes
        finally:
            if store is not None:
                store.close()

    def messages(self):
        return _copy_json(self._read()[0])

    def get(self, message_id):
        return copy.deepcopy(self._read()[0].get(message_id))

    def verify(self):
        return self._read(verify=True)[1]

    def _log_divergence(self, differences):
        store = self._directory()
        try:
            with os.fdopen(store.open("divergence.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND), "ab") as stream:
                raw = hm.encoded({"at": hm.timestamp(), "differences": differences}) + b"\n"
                descriptor = stream.fileno()
                if fcntl is not None:
                    deadline = time.monotonic() + LOG_LOCK_TIMEOUT_SECONDS
                    while True:
                        try:
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                return "busy"
                            time.sleep(LOG_LOCK_POLL_SECONDS)
                try:
                    metadata = os.fstat(descriptor)
                    _private(self.directory / "divergence.jsonl", metadata)
                    if metadata.st_size + len(raw) > MAX_DIVERGENCE_BYTES:
                        return "full"
                    stream.write(raw)
                    stream.flush()
                    os.fsync(descriptor)
                finally:
                    if fcntl is not None:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
            return None
        finally:
            store.close()


def compare(mailbox, index):
    """Compare canonical bytes AND recursive key order; log one record per mismatch.

    Identical fail-closed errors compare equal. Phase-0 callers must compare every
    indexed read until the ADR exit gate. Unsafe log files refuse; a full log adds
    divergence_log_full or divergence_log_busy without appending.
    """
    def outcome(call):
        try:
            return {"result": call()}
        except Exception as exc:
            return {"error": {"type": type(exc).__module__ + "." + type(exc).__qualname__,
                              "message": str(exc)}}

    indexed, pinned = outcome(index.messages), outcome(mailbox.messages)
    differences = []
    if hm.encoded(indexed) != hm.encoded(pinned):
        differences.append({"kind": "mailbox_index_divergence", "index_sha256": hm.digest(indexed),
                            "pinned_sha256": hm.digest(pinned)})
    if not _same_order(indexed, pinned):
        differences.append({"kind": "mailbox_index_key_order"})
    if differences:
        status = index._log_divergence(differences)
        if status is not None:
            differences.append({"kind": "divergence_log_" + status, "limit": MAX_DIVERGENCE_BYTES})
    return differences
