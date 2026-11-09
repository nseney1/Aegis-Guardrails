"""In-process derived mailbox index; Python 3.9 stdlib only.

No cache directory, persisted entries, lock, log or filesystem writes. Legacy
mailbox-index files are never opened. Each instance learns only from bytes read
and validated in this process. Keys are (relpath, size, mtime_ns, ctime_ns, inode).

Every operation lists the pinned routing folders and checks all source files.
Unchanged files are opened without reading bytes to detect lost read access;
their descriptor/path stat keys must agree. Every header, including unreturned
records on get/inbox, receives pinned validate_message(stored=True) again. This
deliberately retains the full validator cost to cover brief, readiness.worktree
and scan_workspace safety without a second validator. Only new/changed keys
cause message bytes to be read and parsed. Returned values are independent copies.

Default shadow mode compares against pinned reads, retries a mismatch once, and
returns/raises the pinned outcome. compare() and last_divergence hold hash-only
diagnostics in memory. Indexed mode remains explicit opt-in after phase-0 owner
acceptance. inbox delegates entirely to pinned Mailbox.inbox with a read view.

verify() rehashes/revalidates all files and reports content_changed against this
instance's previous observations; a new process has no historical baseline.
Stat keys are freshness observations, not authenticated history or an atomic
snapshot. Concurrent changes get one rescan, then pinned error equivalence or
IndexDivergence. Filesystems with colliding/weak timestamps need forced verify.
"""
from copy import deepcopy
import hashlib
import os
import stat

from tools import hierarchy_mailbox as hm


class IndexDivergence(ValueError):
    """The pinned scan did not reproduce an indexed failure."""


class _ChangedDuringRead(Exception):
    pass


class _InboxView:
    """Use pinned inbox expansion/bindings/ready checks without mutating Mailbox."""
    def __init__(self, mailbox, read):
        self._mailbox, self._read = mailbox, read

    def __getattr__(self, name):
        return getattr(self._mailbox, name)

    def messages(self):
        return self._read()


class MailboxIndex:
    def __init__(self, mailbox, *, mode="shadow"):
        hm.require(mode in ("shadow", "indexed"), "unknown mailbox index mode; valid modes: shadow, indexed")
        self.mailbox, self.mode = mailbox, mode
        self._entries = {}
        self.content_changed, self.last_divergence = [], []

    @staticmethod
    def _key(relpath, metadata):
        return (relpath, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_ino)

    def _read_message(self, path):
        try:
            raw = hm.read_bytes(path)
        except ValueError as exc:
            if str(exc) == "file unavailable: " + str(path) and not path.exists():
                raise _ChangedDuringRead() from exc
            raise
        text = raw.decode("utf-8")
        hm.require(text.startswith("---\n"), "missing header")
        header, body = text[4:].split("\n---\n\n", 1)
        message = hm.strict_json(header)
        message["body"] = body
        return message, hashlib.sha256(raw).hexdigest()

    def _probe(self, path, relpath, key):
        # Open without reading: a cached record must not bypass read permissions.
        with hm.safe_path(path).open("rb") as stream:
            metadata = os.fstat(stream.fileno())
            hm.require(stat.S_ISREG(metadata.st_mode), "input must be a regular file")
            if self._key(relpath, metadata) != key:
                raise _ChangedDuringRead()
        if self._key(relpath, path.lstat()) != key:
            raise _ChangedDuringRead()

    def _scan(self, force):
        records, entries, changes = {}, {}, []
        root = self.mailbox.root
        folders = {root / endpoint.split("/")[0] / endpoint.split("/")[1]
                   for endpoint in self.mailbox.manifest["endpoints"]}
        folders |= {root / "across" / role for role in hm.ACROSS_ROLES}
        for folder in sorted(folders):
            hm.safe_path(folder)
            for path in sorted(folder.iterdir()):
                if path.name.startswith(".pending-"):
                    hm.require(not path.is_symlink(), "symlink mailbox entry is not supported")
                    continue
                metadata = path.lstat()
                hm.require(not stat.S_ISLNK(metadata.st_mode), "symlink mailbox entry is not supported")
                hm.require(path.suffix == ".md", "unexpected mailbox entry: " + str(path))
                hm.require(len(records) < hm.MAX_RECORDS, "mailbox exceeds record limit")
                hm.require(stat.S_ISREG(metadata.st_mode), "input must be a regular file")
                relpath = path.relative_to(root).as_posix()
                key = self._key(relpath, metadata)
                previous = self._entries.get(relpath)
                if not force and previous is not None and previous["key"] == key:
                    self._probe(path, relpath, key)
                    message, sha = previous["message"], previous["sha256"]
                else:
                    message, sha = self._read_message(path)
                    if self._key(relpath, path.lstat()) != key:
                        raise _ChangedDuringRead()
                destination = self.mailbox.validate_message(message, stored=True)
                hm.require(destination == folder, "message is in the wrong routing folder")
                hm.require(message["message_id"] not in records, "duplicate message_id in history")
                records[message["message_id"]] = {"path": str(path), "message": message}
                entries[relpath] = {"key": key, "message": message, "sha256": sha}
                if previous is not None and previous["sha256"] != sha:
                    changes.append({"kind": "content_changed", "path": str(path),
                                    "old_sha256": previous["sha256"], "new_sha256": sha})
        for record in records.values():
            if "in_reply_to" in record["message"]:
                self.mailbox.reply(record["message"], records)
        return records, entries, changes

    def _read_index(self, *, force=False):
        error = None
        for attempt in range(2):
            try:
                records, entries, changes = self._scan(force)
                self._entries = entries  # Commit only a completely validated observation.
                self.content_changed = changes
                return records
            except (_ChangedDuringRead, FileNotFoundError) as exc:
                error = exc
                if attempt == 0:
                    continue
            except Exception as exc:
                error = exc
            break
        self.mailbox.messages()  # Raise exactly the pinned type/text if it also fails.
        raise IndexDivergence("mailbox index divergence: " + type(error).__name__
                              + "; run compare() or verify() again") from error

    def _indexed_messages(self):
        return deepcopy(self._read_index())

    def _shadow(self, read, pinned):
        indexed, expected, differences = _observe(read, pinned)
        self.last_divergence = differences
        return _unwrap(expected)

    def messages(self):
        if self.mode == "indexed":
            return self._indexed_messages()
        return self._shadow(self._indexed_messages, self.mailbox.messages)

    def get(self, message_id):
        def read():
            return deepcopy(self._read_index().get(message_id))

        if self.mode == "indexed":
            return read()
        return self._shadow(read, lambda: self.mailbox.messages().get(message_id))

    def inbox(self, endpoint, *, include_briefs=False, limit=20, after=None):
        kwargs = {"include_briefs": include_briefs, "limit": limit, "after": after}

        def read():
            return hm.Mailbox.inbox(_InboxView(self.mailbox, self._indexed_messages), endpoint, **kwargs)

        if self.mode == "indexed":
            return read()
        return self._shadow(read, lambda: self.mailbox.inbox(endpoint, **kwargs))

    def verify(self):
        changes = [{"kind": "verification_unavailable"}]
        observations = []

        def read():
            nonlocal changes
            records = self._read_index(force=True)
            batch = self.content_changed
            observations.extend(batch if not observations else
                                (item for item in batch if item not in observations))
            changes = observations
            self.content_changed = deepcopy(changes)
            return records

        if self.mode == "indexed":
            read()
        else:
            self._shadow(read, self.mailbox.messages)
        return deepcopy(changes)


def _capture(call):
    try:
        return call(), None
    except Exception as exc:
        return None, exc


def _frame(outcome):
    result, error = outcome
    if error is not None:
        return {"error": {"type": type(error).__module__ + "." + type(error).__qualname__, "message": str(error)}}
    return {"result": result}


def _canonical(outcome):
    try:
        return hm.encoded(_frame(outcome))
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        return hm.encoded({"encoding_error": type(exc).__name__, "message": str(exc)})


def _same_order(left, right):
    if isinstance(left, dict) and isinstance(right, dict):
        return list(left) == list(right) and all(_same_order(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same_order(a, b) for a, b in zip(left, right))
    return not isinstance(left, (dict, list)) and not isinstance(right, (dict, list))


def _differences(indexed, pinned):
    left, right = _canonical(indexed), _canonical(pinned)
    differences = []
    if left != right:
        differences.append({"kind": "mailbox_index_divergence", "index_sha256": hashlib.sha256(left).hexdigest(),
                            "pinned_sha256": hashlib.sha256(right).hexdigest()})
    if not _same_order(_frame(indexed), _frame(pinned)):
        differences.append({"kind": "mailbox_index_key_order"})
    return differences


def _observe(read, pinned):
    indexed, expected = _capture(read), _capture(pinned)
    differences = _differences(indexed, expected)
    if differences:
        indexed, expected = _capture(read), _capture(pinned)
        differences = _differences(indexed, expected)
    return indexed, expected, differences


def _unwrap(outcome):
    result, error = outcome
    if error is not None:
        raise error
    return result


def compare(mailbox, index):
    """Return canonical/order differences in memory; never read or write a cache."""
    _, _, differences = _observe(index._indexed_messages, mailbox.messages)
    index.last_divergence = differences
    return differences
