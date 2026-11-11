"""In-process mailbox index; Python 3.9 stdlib only, no persistence.

Every call enumerates routing folders with scandir and refreshes deduplicated
lstat tuples keyed by absolute strings. Per ADR ~21:02Z, directories use
(device, inode, mode, uid); timestamps do not invalidate records, while child
lstats and live listings still observe access. Message freshness uses relpath, size,
mtime_ns, ctime_ns, inode and device. Check/access outcomes additionally bind
inspected paths through the mailbox root, brief/readiness branches, manifest and
process credentials. Proper ancestors of the root never enter dependency keys
or confirmations. A live pinned safe_path preflight checks those ancestors for
symlinks once per scan without binding their directory timestamps to records.
Changed dependencies re-read their dependent messages, then rerun pinned
validation with before/after confirmation. Directory
enumeration and credential observations always run; missing observations do not
authorize partial reuse. Non-POSIX bytes are hashed before parsed reuse.
Without checked descriptor reads, bytes come from pinned read_bytes and stored
validation runs every call; POSIX metadata/access reuse is unavailable.
Pathlib-ignored lstat outcomes share the constant None/not-a-symlink probe key;
permission and other real I/O failures still propagate to the pinned oracle.
Each fresh header receives one pinned stored validation per scan attempt.

Per the ADR access-probe addendum, unchanged access outcomes are reusable.
Accepted risks: a privileged mandatory-policy reload is not detected for
unreturned records with unchanged keys/credentials. Under the ADR ~10:05Z
correction (v5.0-teams-mailbox-structure-adr-20261109.md:370-376), a same-stat
content edit of an unreturned
record is also unobserved: preserving size, mtime_ns and ctime_ns can occur in a
lazy mmap writeback window or under a privileged actor; ctime cannot normally
be restored by a writer. This is the accepted keyed-reuse limit. Returned records
are always opened/read in the current call, hash-compared, and copied. Check-time
races retry once before reconciling to PIN; no routing entry is skipped.
Fallback retains keyed candidates for re-observation on the next call, evicting
headers contradicted by observed hashes even when PIN raises.
Dependencies are observed only when a current routing entry needs the path;
no deferred error objects, tracebacks or per-path error map are retained.
Successful full PIN reconciliation retires deleted paths. Changed live records
keep their old SHA baseline while header/dependency reuse is invalidated.
Every completed scan binds reply dependencies to its resolved target. A retained
reply with a different target loses parsed reuse but keeps its SHA baseline.
Normal scans retry once to reread/revalidate it; PIN reconciliation uses the
same invalidation helper before the next indexed read.
Inbox expansion/bindings/ready
remain live pinned code. Only its returned page is deep-copied.

Default shadow compares canonical bytes/order, retries mismatches once, and
returns/raises the pinned outcome. Diagnostics are in memory. Indexed mode
requires owner phase-0 acceptance. verify forces reading/parsing/checks and
reports content_changed against this instance's last observation, or unavailable
verification after canonical reconciliation. Unreported hash changes survive
memo clearing; verify reports retained fallback/retry evidence. Successful
ordinary reads expose and acknowledge new changes through content_changed.
Evidence coalesces the first old and latest new SHA per known path. History
admits new paths after a complete pinned-validated scan, or retains an already
observed candidate SHA during reconciliation. Every canonical fallback return
reports unavailable PIN-byte coverage: neither canonical equality nor a later
read establishes PIN's original raw bytes. Matched shadow reads return the
indexed value with its own byte history; final divergence returns PIN's value
with unavailable coverage until verify reports it. Clearing a populated memo
also preserves coverage-loss state until a successful full verify reports it.
It retains at most
10,000 detailed paths within a 32 MiB accounting budget (including a conservative
per-path allowance and 32 KiB summary reserve). Overflow retains eight bounded
path samples with hashes and saturating counters; verify reports
content_change_overflow. Truncated samples carry a digest of the full path and
are never presented as complete content_changed paths. Only successful verify
acknowledges overflow facts/counters; live sample baselines remain at their
latest SHA until a successful scan establishes deletion. Persistent capacity
loss can report overflow again. Facts promoted from samples into detailed
pending entries retain that verify-only acknowledgement rule.
Successful scans retire deleted paths from detailed history, refunding their
budget; pending retired facts move to the bounded summary. Unbaselined returned
paths make verification explicitly unavailable for all returned records, with
bounded current-path diagnostics. An unbaselined read after coverage loss counts
conservatively in omitted_changes and separately in unbaselined_reads: without
an old SHA it is a possible change, never evidence of unchanged bytes.
These are observations, not atomic snapshots or authenticated history. Weak
POSIX timestamps require verify.
"""
from copy import deepcopy
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import NamedTuple

if __package__:
    from . import hierarchy_mailbox as hm
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import hierarchy_mailbox as hm


class _ChangedDuringRead(Exception):
    pass


class _ObservedByteContradiction(Exception):
    pass


class _ChangedCheckObservation(Exception):
    pass


class _PinnedCallError(Exception):
    def __init__(self, error):
        self.error = error


class _ScanResult(NamedTuple):
    records: dict
    entries: dict
    changes: list
    observations: dict
    folders: set
    context: tuple
    fresh: set
    by_path: dict
    folder_paths: dict


_MISSING = object()
MAX_EVIDENCE_ENTRIES = 10000
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
EVIDENCE_SUMMARY_BYTES = 32768
MAX_EVIDENCE_SAMPLE_PATHS = 8
MAX_EVIDENCE_SAMPLE_PATH_BYTES = 1024
MAX_EVIDENCE_COUNT = (1 << 63) - 1


def _checked_reads_supported():
    # Windows pathname stat and fstat do not supply interchangeable inode/device
    # keys on all supported Python versions. Keep its pinned byte-read path;
    # parsed reuse still requires a matching hash and live pinned validation.
    return os.name == "posix" and bool(getattr(os, "O_NOFOLLOW", 0))


class _Evidence:
    """Bound history and pending facts together, including rejected-input churn."""
    def __init__(self):
        self.hashes, self.pending, self.samples = {}, {}, {}
        # pending[path] holds (first old SHA, verify-only acknowledgement).
        self.bytes = EVIDENCE_SUMMARY_BYTES
        self.overflow = self.saturated = False
        self.counts = {"omitted_changes": 0, "omitted_baseline_observations": 0, "unbaselined_reads": 0}

    @staticmethod
    def _path_key(path):
        return hashlib.sha256(os.fsencode(path)).hexdigest()

    def _count(self, field):
        self.overflow = True
        count = self.counts[field]
        self.counts[field] = min(count + 1, MAX_EVIDENCE_COUNT)
        self.saturated |= count >= MAX_EVIDENCE_COUNT

    @classmethod
    def path_sample(cls, path):
        low, high = 0, len(path)
        while low < high:
            middle = (low + high + 1) // 2
            if len(hm.encoded(path[:middle])) <= MAX_EVIDENCE_SAMPLE_PATH_BYTES:
                low = middle
            else:
                high = middle - 1
        return {"path": path[:low], "path_sha256": cls._path_key(path), "path_truncated": low != len(path)}

    def _omit(self, path, old, sha, *, changed):
        self._count("omitted_changes" if changed else "omitted_baseline_observations")
        key = self._path_key(path)
        if key in self.samples:
            if changed:
                self.samples[key].update(new_sha256=sha, changed=True)
        elif len(self.samples) < MAX_EVIDENCE_SAMPLE_PATHS:
            self.samples[key] = {**self.path_sample(path), "old_sha256": old,
                                 "new_sha256": sha, "changed": changed}

    @staticmethod
    def _cost(path):
        return 2 * len(hm.encoded(path)) + 1024

    def prune(self, live):
        # Only a complete successful scan can establish that a path is gone.
        for path in self.hashes.keys() - live.keys():
            sha = self.hashes.pop(path)
            self.bytes -= self._cost(path)
            if path in self.pending:
                self._omit(path, self.pending.pop(path)[0], sha, changed=True)
        live_samples = {self._path_key(path) for path in live} if self.samples else set()
        for key, item in list(self.samples.items()):
            if key not in live_samples and not item["changed"]:
                del self.samples[key]

    def covered(self, path):
        return path in self.hashes or self._path_key(path) in self.samples

    def admit(self, path, sha):
        if path in self.hashes:
            return True
        # Reserve two path representations, three SHA values, and fixed container
        # overhead. Pending updates then need no additional budget or allocation
        # proportional to the number of observations.
        cost = self._cost(path)
        if len(self.hashes) >= MAX_EVIDENCE_ENTRIES or self.bytes + cost > MAX_EVIDENCE_BYTES:
            self._omit(path, sha, sha, changed=False)
            return False
        self.hashes[path] = sha
        self.bytes += cost
        sample = self.samples.pop(self._path_key(path), None) if self.samples else None
        if sample is not None and sample["changed"]:
            self.pending[path] = (sample["old_sha256"], True)
        return True

    def observe(self, path, sha, baseline=None, *, uncovered=False):
        if path not in self.hashes:
            sample = self.samples.get(self._path_key(path)) if self.samples else None
            if sample is not None:
                if sample["new_sha256"] != sha:
                    self._omit(path, sample["new_sha256"], sha, changed=True)
                return
            # Never create history for a rejected, previously unknown path.
            if baseline is None:
                if uncovered and self.overflow:
                    self._count("omitted_changes")
                    self._count("unbaselined_reads")
                return
            if not self.admit(path, baseline):
                if baseline != sha:
                    self._omit(path, baseline, sha, changed=True)
                return
        previous = self.hashes[path]
        if previous != sha:
            self.pending.setdefault(path, (previous, False))
            self.hashes[path] = sha

    def checkpoint(self):
        return {path: self.hashes[path] for path in self.pending}

    @staticmethod
    def _change(path, old, sha):
        return {"kind": "content_changed", "path": path, "old_sha256": old, "new_sha256": sha}

    def changes(self, before=None):
        result = [self._change(path, old, self.hashes[path]) for path, (old, _) in self.pending.items()
                  if before is None or before.get(path, _MISSING) != self.hashes[path]]
        result.extend(self._change(item["path"], item["old_sha256"], item["new_sha256"])
                      for item in self.samples.values() if item["changed"] and not item["path_truncated"])
        if self.overflow:
            result.append({"kind": "content_change_overflow", "overflow": True, **self.counts,
                           "counts_saturated": self.saturated,
                           "paths": [dict(item) for item in self.samples.values()]})
        return result

    def acknowledge_new(self, before):
        for path in self.pending.keys() - before.keys():
            if not self.pending[path][1]:
                del self.pending[path]

    def acknowledge_all(self, live):
        self.pending.clear()
        live_samples = {self._path_key(path) for path in live} if self.samples else set()
        for key, item in list(self.samples.items()):
            if key not in live_samples:
                del self.samples[key]
            else:
                item.update(old_sha256=item["new_sha256"], changed=False)
        self.overflow = self.saturated = False
        self.counts = dict.fromkeys(self.counts, 0)

    def stats(self):
        return {"entries": len(self.hashes),
                "pending_entries": len(self.pending) + sum(item["changed"] for item in self.samples.values()),
                "bytes": self.bytes, "max_entries": MAX_EVIDENCE_ENTRIES, "max_bytes": MAX_EVIDENCE_BYTES,
                "summary_paths": len(self.samples), "max_summary_paths": MAX_EVIDENCE_SAMPLE_PATHS,
                "max_total_paths": MAX_EVIDENCE_ENTRIES + MAX_EVIDENCE_SAMPLE_PATHS, "overflow": self.overflow}


def _stat_key(value):
    if value is None:
        return None
    if stat.S_ISDIR(value.st_mode):
        return (getattr(value, "st_dev", None), value.st_ino, value.st_mode, getattr(value, "st_uid", None))
    return (value.st_ino, value.st_mode, getattr(value, "st_uid", None), value.st_size,
            value.st_mtime_ns, value.st_ctime_ns, getattr(value, "st_dev", None))


class _Observations:
    """String-keyed snapshot; one lstat per unchanged inspected path per call."""
    def __init__(self, previous):
        self.previous = previous
        self.values, self.metadata = {}, {}
        self.changed, self.unknown, self.used = set(), set(), set()

    @staticmethod
    def lstat(path):
        try:
            return os.lstat(path)
        except ValueError:
            # Path.is_symlink treats unencodable names as not-a-symlink.
            return None
        except OSError as exc:
            # Match pathlib's probe ignore set, not arbitrary I/O failures.
            if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP) or getattr(
                    exc, "winerror", None) in (21, 123, 1921):
                return None
            raise

    def observe(self, path, *, used=True):
        if used:
            self.used.add(path)
        if path not in self.metadata:
            value = self.lstat(path)
            key = _stat_key(value)
            self.metadata[path], self.values[path] = value, key
            if key != self.previous.get(path, _MISSING):
                self.changed.add(path)
            if key is not None and None in key:
                self.unknown.add(path)
        return self.metadata[path]

    def stable(self, paths):
        self.used.update(paths)
        # Listing/validation selects dependencies before any fallible probe.
        # An obsolete dependency never needs an error placeholder or traceback.
        for path in paths:
            if path not in self.metadata:
                self.observe(path, used=False)
        return ((not self.changed or self.changed.isdisjoint(paths))
                and (not self.unknown or self.unknown.isdisjoint(paths)))

    def confirm(self, paths):
        for path in paths:
            if _stat_key(self.lstat(path)) != self.values[path]:
                raise _ChangedCheckObservation()

    def snapshot(self):
        return {path: self.values[path] for path in self.used}


class _InboxView:
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
        self._evidence = _Evidence()
        self._keep_changes = False
        self._baseline_gap = False
        self._clear()
        self.content_changed, self.last_divergence = [], []
        self.last_reconciliation = None

    def _clear(self):
        if getattr(self, "_by_path", None):
            self._baseline_gap = True
        self._entries, self._by_path = {}, {}
        self._observations, self._folder_checks, self._folder_paths = {}, set(), {}
        self._folder_layout = None
        self._scope_root, self._above_root = None, set()
        self._context, self._fresh_reads = None, None
        self.content_changed = []

    def _evict_contradicted(self):
        # A matching stat key cannot override bytes we already saw change.
        # Run before PIN too: an oracle error must not leave a valid-looking
        # cached header available to a later read of some other message.
        for path, entry in list(self._by_path.items()):
            latest = self._evidence.hashes.get(path)
            if latest is None and self._evidence.samples:
                sample = self._evidence.samples.get(self._evidence._path_key(path))
                if sample is not None:
                    latest = sample["new_sha256"]
            if latest is not None and latest != entry["sha256"]:
                self._by_path.pop(path)
                self._entries.pop(entry["relpath"], None)

    @staticmethod
    def _key(relpath, metadata):
        return (relpath, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_ino)

    def _read_message(self, path, *, previous=None):
        try:
            raw = (hm.read_bytes(path) if previous is None else
                   self._read_raw(path, previous["key"], previous["device"]))
        except ValueError as exc:
            if str(exc) == "file unavailable: " + str(path) and not os.path.exists(path):
                raise _ChangedDuringRead() from exc
            raise
        sha = hashlib.sha256(raw).hexdigest()
        self._remember_hash(path, sha)
        if previous is not None and previous["sha256"] == sha:
            return previous["message"], sha
        return self._parse_message(path, raw), sha

    def _read_raw(self, path, key=None, device=None):
        if not _checked_reads_supported():
            return hm.read_bytes(path)
        hm.safe_path(path)
        if key is None:
            metadata = os.lstat(path)
            relative = Path(path).relative_to(self.mailbox.root).as_posix()
            key, device = self._key(relative, metadata), metadata.st_dev
        with self._open_checked(path, key, device) as stream:
            raw = stream.read(hm.MAX_BYTES + 1)
        hm.require(len(raw) <= hm.MAX_BYTES, "input exceeds 262144 bytes")
        return raw

    def _remember_hash(self, path, sha):
        path = os.fspath(path)
        previous = self._by_path.get(path)
        if previous is not None and previous["sha256"] != sha:
            self._by_path.pop(path)
            self._entries.pop(previous["relpath"], None)
        self._evidence.observe(path, sha, None if previous is None else previous["sha256"],
                               uncovered=self._baseline_gap)

    def _admit_hash(self, path, sha):
        if not self._evidence.admit(path, sha) and not self._evidence.covered(path):
            # A bounded sample still supplies a baseline; beyond that cap there
            # is no safe claim of coverage, including after _clear() on fallback.
            self._baseline_gap = True

    def evidence_stats(self):
        """Return bounded-retention counters; bytes includes reserved overhead."""
        return self._evidence.stats()

    def _parse_message(self, path, raw):
        text = raw.decode("utf-8")
        hm.require(text.startswith("---\n"), "missing header")
        header, body = text[4:].split("\n---\n\n", 1)
        message = hm.strict_json(header)
        message["body"] = body
        return message

    def _open_checked(self, path, key, device):
        hm.require(_checked_reads_supported(), "checked mailbox reads unavailable")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            hm.require(stat.S_ISREG(metadata.st_mode), "input must be a regular file")
            if self._key(key[0], metadata) != key or metadata.st_dev != device:
                raise _ChangedDuringRead()
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise

    def _probe(self, path, key, device):
        with self._open_checked(path, key, device):
            pass

    def _admit_returned(self, records, candidate=None):
        for record in records:
            path = record["path"]
            # The canonical PIN API returns parsed values, not its raw bytes.
            # Keep observations below, but never treat value equality as a
            # byte witness, including known-path A/B/A formatting schedules.
            self._baseline_gap = True
            if self.last_reconciliation is not None:
                self.last_reconciliation["baseline_unavailable"] = True
            try:
                if candidate is not None and candidate[0] == path and candidate[2] == hm.digest(record["message"]):
                    if _stat_key(os.lstat(path)) != candidate[3]:
                        # PIN may have read a different raw encoding of the
                        # same message. Retain the observed SHA, disclaim PIN's.
                        self._baseline_gap = True
                        if self.last_reconciliation is not None:
                            self.last_reconciliation["baseline_unavailable"] = True
                    self._admit_hash(path, candidate[1])
                    continue
                if not self._evidence.covered(path):
                    # No original byte witness: even a canonically equal
                    # re-read could contain a newer frontmatter encoding.
                    raise _ChangedDuringRead()
                raw = self._read_raw(path)
                sha = hashlib.sha256(raw).hexdigest()
                self._remember_hash(path, sha)
                if hm.encoded(self._parse_message(path, raw)) != hm.encoded(record["message"]):
                    raise _ChangedDuringRead()
                self._admit_hash(path, sha)
            except Exception:
                # Keep the canonical outcome; never invent a baseline for bytes
                # that cannot be matched to it. Report the gap on verification.
                self._baseline_gap = True
                if self.last_reconciliation is not None:
                    self.last_reconciliation["baseline_unavailable"] = True

    def _paths(self, path, message=None):
        # Cold/changed entries only. No Path objects enter the hot dictionaries.
        inspected = [Path(path)]
        if message is not None:
            if "brief" in message:
                inspected.append(Path(message["brief"]["path"]))
            if "readiness" in message:
                inspected.extend(Path(message["readiness"][field]) for field in ("worktree", "scan_workspace"))
        return tuple(dict.fromkeys(value for item in inspected for part in (item, *item.parents)
                                   for value in (str(part),) if value not in self._above_root))

    def _reconcile_reply_dependencies(self, entries, records, observed=None):
        invalidated = False
        for relpath, entry in list(entries.items()):
            message = entry["message"]
            if "in_reply_to" not in message:
                continue
            target = records[message["in_reply_to"]]["path"]
            if entry.get("reply_target") == target:
                continue
            if observed is not None and entry is not self._entries.get(relpath):
                # This header was read and validated in the current scan.
                dependencies = tuple(dict.fromkeys(self._paths(entry["path"], message) + self._paths(target)))
                observed.stable(dependencies)
                observed.confirm(dependencies)
                entry["paths"], entry["reply_target"] = dependencies, target
            else:
                # A reused header is not validated against a different binding.
                # Retain _by_path's SHA baseline, but make the next read fresh.
                entries.pop(relpath)
                self._entries.pop(relpath, None)
                invalidated = True
        return invalidated

    @staticmethod
    def _identity():
        names = ("getuid", "geteuid", "getgid", "getegid", "getgroups")
        if not all(hasattr(os, name) for name in names):
            return None
        return tuple(tuple(value) if isinstance(value, list) else value
                     for value in (getattr(os, name)() for name in names))

    def _list_folders(self, context):
        root = context[0]
        layout_key = context[:2]
        if self._folder_layout is None or self._folder_layout[0] != layout_key:
            relatives = {endpoint.split("/")[0] + "/" + endpoint.split("/")[1]
                         for endpoint in self.mailbox.manifest["endpoints"]}
            relatives |= {"across/" + role for role in hm.ACROSS_ROLES}
            folders = [(os.path.join(root, *relative.split("/")), relative) for relative in relatives]
            # Match Path ordering by components, not the separator in full strings.
            folders.sort(key=lambda pair: tuple(os.path.normcase(part) for part in pair[1].split("/")))
            self._folder_layout = layout_key, folders
        return self._folder_layout[1]

    def _list_folder(self, folder, observed):
        folder_paths = self._folder_paths.get(folder)
        if folder_paths is None:
            folder_paths = self._paths(folder)
        stable_folder = observed.stable(folder_paths)
        if folder not in self._folder_checks or not stable_folder:
            hm.safe_path(folder)
            observed.confirm(folder_paths)
        with os.scandir(folder) as listing:
            names = sorted((item.name for item in listing), key=os.path.normcase)
        return folder_paths, names

    def _observe_entry(self, path, name, observed, record_count):
        metadata = observed.observe(path)
        if name.startswith(".pending-"):
            hm.require(metadata is None or not stat.S_ISLNK(metadata.st_mode),
                       "symlink mailbox entry is not supported")
            return None
        if metadata is None:
            raise _ChangedDuringRead()
        hm.require(not stat.S_ISLNK(metadata.st_mode), "symlink mailbox entry is not supported")
        hm.require(name.endswith(".md") and len(name) > 3, "unexpected mailbox entry: " + path)
        hm.require(record_count < hm.MAX_RECORDS, "mailbox exceeds record limit")
        hm.require(stat.S_ISREG(metadata.st_mode), "input must be a regular file")
        return metadata

    def _confirm_entry(self, path, key, metadata, message, sha, dependencies, observed, fresh, validated):
        if path not in fresh:
            self._probe(path, key, metadata.st_dev)
        if not validated:
            destination = os.fspath(self.mailbox.validate_message(message, stored=True))
        else:
            # A new dependency may turn into a link between PIN's validation
            # and its first observation. Reuse PIN's path check first.
            destination = None
            for dependency in dependencies:
                value = observed.metadata[dependency]
                if value is not None and stat.S_ISLNK(value.st_mode):
                    hm.safe_path(dependency)
        try:
            observed.confirm(dependencies)
        except _ChangedCheckObservation as exc:
            if path in fresh:
                # Retain this observed SHA; a canonical fallback still
                # disclaims the bytes PIN actually read.
                exc.candidate = (path, sha, hm.digest(message), _stat_key(metadata))
            raise
        return destination

    def _validate_entry(self, path, relpath, metadata, observed, fresh, *, force, same_limit, reusable_context):
        key = self._key(relpath, metadata)
        previous = self._entries.get(relpath)
        reuse = (not force and same_limit and previous is not None and previous["key"] == key
                 and previous["path"] == path and previous["device"] == metadata.st_dev)
        # The accepted POSIX key policy permits reuse before hashing. Other
        # platforms must hash first; a changed header may drop old dependencies.
        stable = reuse and _checked_reads_supported() and observed.stable(previous["paths"])
        if stable:
            message, sha = previous["message"], previous["sha256"]
        else:
            message, sha = self._read_message(path, previous=previous if reuse else None)
            fresh.add(path)
            if self._key(relpath, os.lstat(path)) != key:
                raise _ChangedDuringRead()
        validated = False
        if reuse and previous["sha256"] == sha:
            dependencies = previous["paths"]
            stable = observed.stable(dependencies)
        else:
            destination = os.fspath(self.mailbox.validate_message(message, stored=True))
            validated = True
            dependencies = self._paths(path, message)
            observed.stable(dependencies)
            stable = False
        checked = force or not stable or not reusable_context
        if checked:
            confirmed = self._confirm_entry(path, key, metadata, message, sha, dependencies,
                                            observed, fresh, validated)
            if not validated:
                destination = confirmed
        else:
            destination = previous["destination"]
        if reuse and previous["sha256"] == sha and not checked:
            return previous
        return {"key": key, "message": message, "sha256": sha, "path": path,
                "device": metadata.st_dev, "paths": dependencies, "relpath": relpath,
                "destination": destination, "record": {"path": path, "message": message}}

    def _scan(self, force):
        records, entries, by_path = {}, {}, {}
        checkpoint = self._evidence.checkpoint()
        fresh = set()
        root = os.fspath(self.mailbox.root)
        if self._scope_root != root:
            self._scope_root = root
            self._above_root = {str(path) for path in self.mailbox.root.parents}
            self._observations, self._folder_checks, self._folder_paths = {}, set(), {}
        hm.safe_path(self.mailbox.root.parent)
        observed = _Observations(self._observations)
        identity = self._identity()
        context = (root, hm.digest(self.mailbox.manifest), hm.MAX_BYTES, identity)
        reusable_context = identity is not None and context == self._context and _checked_reads_supported()
        same_limit = self._context is not None and self._context[2] == hm.MAX_BYTES
        folder_checks, folder_paths_used = set(), {}
        for folder, folder_rel in self._list_folders(context):
            folder_paths, names = self._list_folder(folder, observed)
            folder_paths_used[folder] = folder_paths
            folder_checks.add(folder)
            for name in names:
                path = os.path.join(folder, name)
                metadata = self._observe_entry(path, name, observed, len(records))
                if metadata is None:
                    continue
                relpath = folder_rel + "/" + name
                entry = self._validate_entry(path, relpath, metadata, observed, fresh, force=force,
                                             same_limit=same_limit, reusable_context=reusable_context)
                hm.require(entry["destination"] == folder, "message is in the wrong routing folder")
                identifier = entry["message"]["message_id"]
                hm.require(identifier not in records, "duplicate message_id in history")
                records[identifier], entries[relpath], by_path[path] = entry["record"], entry, entry
        for record in records.values():
            if "in_reply_to" in record["message"]:
                self.mailbox.reply(record["message"], records)
        if self._reconcile_reply_dependencies(entries, records, observed):
            raise _ChangedCheckObservation()
        self._evidence.prune(by_path)
        for path, entry in by_path.items():
            if path in fresh or path not in self._evidence.hashes:
                self._admit_hash(path, entry["sha256"])
        return _ScanResult(records, entries, self._evidence.changes(checkpoint), observed.snapshot(), folder_checks,
                           context, fresh, by_path, folder_paths_used)

    def _read_index(self, *, force=False):
        self.last_reconciliation = None
        error = None
        for attempt in range(2):
            try:
                scan = self._scan(force)
                self._entries, self._by_path, self._fresh_reads = scan.entries, scan.by_path, scan.fresh
                self._observations, self._folder_checks, self._context = scan.observations, scan.folders, scan.context
                self._folder_paths = scan.folder_paths
                self.content_changed = deepcopy(scan.changes)
                return scan.records
            except (_ChangedDuringRead, _ChangedCheckObservation, FileNotFoundError) as exc:
                error = exc
                if attempt == 0:
                    continue
            except Exception as exc:
                error = exc
            break
        return self._reconcile(self.mailbox.messages, lambda records: records.values(),
                               error=error, attempts=attempt + 1, full_history=True,
                               candidate=getattr(error, "candidate", None))

    def _reconcile(self, pinned, select, *, error, attempts, full_history=False, candidate=None):
        self._keep_changes = True
        # Keyed entries remain candidates only. Next call re-lists, re-stats and
        # re-checks context/dependencies before reuse. Canonical bytes below
        # are already materialized and must not use those older entries here.
        self._fresh_reads = None
        self.content_changed = []
        self._evict_contradicted()
        self.last_reconciliation = {"kind": "pinned_fallback", "attempts": attempts,
                                    "error_type": type(error).__module__ + "." + type(error).__qualname__}
        result = pinned()
        selected = select(result)
        if full_history:
            live = {record["path"]: record for record in selected}
            self._evidence.prune(live)
        self._admit_returned(selected, candidate)
        self._evict_contradicted()
        if full_history:
            self._retain_live_entries(result, live)
        return result

    def _retain_live_entries(self, records, live):
        # Only a successful full canonical history establishes obsolescence.
        # Delete only absent paths. A changed live record's last SHA may be its
        # sole baseline when bounded history omitted it; invalidate its parsed
        # header for reuse, but retain that SHA until current bytes are read.
        for path, entry in list(self._by_path.items()):
            if path not in live:
                self._by_path.pop(path)
                self._entries.pop(entry["relpath"], None)
            elif entry["message"] != live[path]["message"]:
                self._entries.pop(entry["relpath"], None)
        self._reconcile_reply_dependencies(self._entries, records)
        dependencies = {path for paths in self._folder_paths.values() for path in paths}
        dependencies.update(path for entry in self._entries.values() for path in entry["paths"])
        self._observations = {path: value for path, value in self._observations.items() if path in dependencies}

    def _materialize(self, selected):
        if self._fresh_reads is None:
            return  # The canonical fallback already read/validated these bytes.
        for record in selected:
            path = record["path"]
            if path in self._fresh_reads:
                continue
            entry = self._by_path[path]
            with self._open_checked(path, entry["key"], entry["device"]) as stream:
                raw = stream.read(hm.MAX_BYTES + 1)
            if len(raw) > hm.MAX_BYTES:
                raise _ChangedDuringRead()
            sha = hashlib.sha256(raw).hexdigest()
            self._remember_hash(path, sha)
            if sha != entry["sha256"]:
                raise _ObservedByteContradiction()
            self._fresh_reads.add(path)

    def _return_checked(self, read, pinned, select):
        error = None
        for attempt in range(2):
            try:
                result, selected = read()
                self._materialize(selected)
                return deepcopy(result)
            except _PinnedCallError as exc:
                # PIN reads history before expansion/cursor checks. Reconcile
                # instead of surfacing a later error ahead of a read failure.
                self._keep_changes = True
                error = exc.error
                break
            except (_ChangedDuringRead, FileNotFoundError) as exc:
                self._keep_changes = True
                if self.last_reconciliation is not None:
                    raise
                error = exc
                if attempt == 0:
                    continue
            except Exception as exc:
                self._keep_changes = True
                if self.last_reconciliation is not None:
                    raise  # Already the canonical exception; preserve its diagnostics.
                error = exc
            break
        return self._reconcile(pinned, select, error=error, attempts=attempt + 1)

    def _indexed_messages(self):
        def read():
            records = self._read_index()
            return records, records.values()

        return self._return_checked(read, self.mailbox.messages, lambda records: records.values())

    def _shadow(self, read, pinned, select):
        indexed, expected, differences = _observe(read, pinned)
        self.last_divergence = differences
        if not differences and indexed[1] is None:
            return indexed[0]  # Equality proves values, not PIN's byte provenance.
        result = _unwrap(expected)
        if differences:
            self._keep_changes = True
            selected = list(select(result))
            if selected:
                self._baseline_gap = True
                self._admit_returned(selected)
        return result

    def _call(self, read, pinned, select):
        checkpoint = self._evidence.checkpoint()
        self._keep_changes = False
        result = read() if self.mode == "indexed" else self._shadow(read, pinned, select)
        changes = self._evidence.changes(checkpoint)
        self.content_changed = deepcopy(changes)
        # A scan alone cannot acknowledge evidence: materialization, inbox
        # expansion or the shadow oracle may still fail. Retried/fallback facts
        # and older unreported facts remain available to verify.
        if not self._keep_changes and (self.mode == "indexed" or not self.last_divergence):
            self._evidence.acknowledge_new(checkpoint)
        return result

    def messages(self):
        return self._call(self._indexed_messages, self.mailbox.messages, lambda records: records.values())

    def get(self, message_id):
        def selected():
            records = self._read_index()
            try:
                record = records.get(message_id)
            except Exception as exc:
                raise _PinnedCallError(exc) from exc
            return record, (record,) if record is not None else ()

        def read():
            return self._return_checked(selected, lambda: self.mailbox.messages().get(message_id),
                                        lambda record: (record,) if record is not None else ())

        return self._call(read, lambda: self.mailbox.messages().get(message_id),
                          lambda record: (record,) if record is not None else ())

    def inbox(self, endpoint, *, include_briefs=False, limit=20, after=None):
        kwargs = {"include_briefs": include_briefs, "limit": limit, "after": after}
        message_failed = False

        def records():
            nonlocal message_failed
            try:
                result = self._read_index()
            except Exception:
                message_failed = True
                raise
            # Pinned expansion adds brief_text to selected record dictionaries.
            return {key: dict(record) for key, record in result.items()} if include_briefs else result

        def selected():
            nonlocal message_failed
            message_failed = False
            try:
                result = hm.Mailbox.inbox(_InboxView(self.mailbox, records), endpoint, **kwargs)
            except Exception as exc:
                if message_failed:
                    raise
                raise _PinnedCallError(exc) from exc
            return result, result["messages"]

        def read():
            return self._return_checked(selected, lambda: self.mailbox.inbox(endpoint, **kwargs),
                                        lambda page: page["messages"])

        return self._call(read, lambda: self.mailbox.inbox(endpoint, **kwargs), lambda page: page["messages"])

    def verify(self):
        completed, reconciled = False, False

        def read():
            nonlocal completed, reconciled
            records = self._read_index(force=True)
            completed = True
            reconciled |= self.last_reconciliation is not None
            return records

        if self.mode == "indexed":
            read()
        else:
            self._shadow(read, self.mailbox.messages, lambda records: records.values())
        result = self._evidence.changes()
        stable = completed and not reconciled and (self.mode == "indexed" or not self.last_divergence)
        unavailable = not stable or self._baseline_gap
        if unavailable:
            reason = "baseline_unavailable" if self._baseline_gap else "pinned_reconciliation"
            marker = {"kind": "verification_unavailable", "reason": reason}
            if self._baseline_gap:
                gaps = [path for path in self._by_path if not self._evidence.covered(path)]
                marker.update(scope="all_returned_records", unbaselined_paths=len(gaps),
                              paths=[self._evidence.path_sample(path) for path in gaps[:MAX_EVIDENCE_SAMPLE_PATHS]],
                              paths_complete=stable and len(gaps) <= MAX_EVIDENCE_SAMPLE_PATHS)
            result.append(marker)
        if stable:
            self._baseline_gap = False  # The historical gap was reported; current baselines are now established.
        self.content_changed = deepcopy([item for item in result if item["kind"] == "content_changed"])
        if not unavailable:
            self._evidence.acknowledge_all(self._by_path)
        return result


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
