"""Descriptor-bound proposal transactions and immutable per-decision public files.

All mutations share the existing workspace lock inode. Hold descriptors from the
trusted absolute root through publication: ancestor replacement never redirects
an operation. Unsupported platforms refuse explicitly. Decisions are untrusted
queue state and confer no rule-write authority. This module never installs rules.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import uuid

from aegis_core.errors import LockTimeoutError, PathTraversalError
from aegis_core.insights.keys import insights_path
from aegis_core.primitives import strict_loads, parse_utc, utc_stamp
from aegis_core.storage import file_lock
from aegis_core.storage_confined import descriptor_supported
from aegis_core.workspace.layout import WorkspaceLayout, UserLayout
from aegis_core.proposals.model import (
    DECISIONS, TERMINAL, MAX_PROPOSAL_BYTES, Proposal, ProposalError,
    bounded_tuple, checked_id, checked_key, clean_text, parse_proposal, stored,
)

MAX_ROWS = 4096
# Public directories and the shared private log each own this quota. A workspace
# can read their union (at most 2 * MAX_ROWS); another worktree cannot invalidate
# its public quota merely by appending to the independently bounded private log.
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_ROW_BYTES = 65536
MAX_ANCESTORS = 128


@contextmanager
def _errors():
    try:
        yield
    except LockTimeoutError:
        raise ProposalError("timeout") from None
    except PathTraversalError:
        raise ProposalError("unsafe") from None
    except OSError as error:
        code = {errno.ENOENT: "missing", errno.EEXIST: "exists", errno.ELOOP: "unsafe",
                errno.ENOTDIR: "unsafe"}.get(error.errno, "io")
        raise ProposalError(code) from None


def _flags():
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@contextmanager
def _root(path):
    if not descriptor_supported():
        raise ProposalError("unsupported")
    spelling = str(path)
    if (len(spelling) > 32768 or not path.is_absolute() or ".." in path.parts
            or "\x00" in spelling):
        raise ProposalError("invalid")
    try:
        os.fsencode(spelling)
    except UnicodeError:
        raise ProposalError("invalid") from None
    fd = os.open(path.anchor, _flags())
    try:
        for component in path.parts[1:]:
            child = os.open(component, _flags(), dir_fd=fd)
            parent, fd = fd, child
            os.close(parent)
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _directory(parent, name, create=False, private=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        _flush(parent)
    fd = os.open(name, _flags(), dir_fd=parent)
    try:
        info = os.fstat(fd)
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ProposalError("unsafe")
        yield fd
    finally:
        os.close(fd)


def _flush(fd):
    try:
        os.fsync(fd)
    except OSError:
        raise ProposalError("durability") from None


def _read(directory, name, limit, durable=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProposalError("unsafe")
        if info.st_size > limit:
            raise ProposalError("too_large")
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(chunks)))
            if not chunk:
                if durable:
                    _flush(fd)
                    _flush(directory)
                return bytes(chunks)
            chunks.extend(chunk)
        raise ProposalError("too_large")
    finally:
        os.close(fd)


def _optional_read(directory, name, limit):
    try:
        return _read(directory, name, limit)
    except FileNotFoundError:
        return None


def _publish(directory, name, data, replacing=False):
    # The caller has already bounded encoded bytes and holds the workspace lock.
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        info = None
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProposalError("unsafe")
        if not replacing:
            raise ProposalError("exists")
    temporary = ".proposal-" + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                 0o600, dir_fd=directory)
    try:
        try:
            os.fchmod(fd, 0o600)
            remaining = memoryview(data)
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0:
                    raise ProposalError("io")
                remaining = remaining[count:]
            _flush(fd)
        finally:
            os.close(fd)
        if replacing:
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        else:
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
    _flush(directory)


def _names(directory, suffix, reserve=0):
    names = []
    if reserve > MAX_ROWS:
        raise ProposalError("too_large")
    # Bound before sorting or allocating an untrusted directory's complete listing.
    with os.scandir(directory) as entries:
        count = 0
        for entry in entries:
            count += 1
            if count > MAX_ROWS - reserve:
                raise ProposalError("too_large")
            if entry.name.endswith(suffix):
                if len(entry.name) > 160:
                    raise ProposalError("invalid")
                names.append(entry.name)
    return sorted(names)


def _space_for_directory(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        reserve = 0
    except FileNotFoundError:
        reserve = 1
    _names(directory, ".md", reserve=reserve)


def _log_rows(raw):
    if len(raw) > MAX_LOG_BYTES:
        raise ProposalError("too_large")
    rows = []
    with io.BytesIO(raw) as lines:
        while True:
            line = lines.readline(MAX_ROW_BYTES + 1)
            if len(line) > MAX_ROW_BYTES:
                raise ProposalError("too_large")
            if not line:
                break
            if not line.strip():
                continue
            row = _json(line)
            if "proposal_ids" in row:
                if len(rows) >= MAX_ROWS:
                    raise ProposalError("too_large")
                row = _validate_row(row)
                # Historical proposal rows used the insight event name. Keep
                # their bytes immutable and project the new event in memory.
                if row["event"] == "decision" and row.get("insight_ids"):
                    row = dict(row, event="proposal_decision")
                rows.append(row)
    return rows


def _json(data, code="decision"):
    if len(data) > MAX_ROW_BYTES:
        raise ProposalError("too_large")
    try:
        value = strict_loads(data)
    except (ValueError, UnicodeError, RecursionError):
        raise ProposalError(code) from None
    if type(value) is not dict:
        raise ProposalError(code)
    return value


def _validate_row(row):
    required = {"v", "ts", "event", "decision", "proposal_ids", "revisions", "evidence_ids", "operation_id"}
    allowed = required | {"reason", "rule_id", "rule_digest", "until", "insight_ids"}
    if type(row) is not dict:
        raise ProposalError("decision")
    try:
        if (not required <= row.keys() or not row.keys() <= allowed or type(row["v"]) is not int
                or row["v"] != 1 or type(row["event"]) is not str
                or row["event"] not in ("decision", "proposal_decision")
                or type(row["decision"]) is not str or row["decision"] not in DECISIONS
                or type(row["ts"]) is not str or len(row["ts"]) > 32 or parse_utc(row["ts"]) is None):
            raise ProposalError("decision")
        ids = bounded_tuple(row["proposal_ids"], 64, checked_id)
        checked_id(row["operation_id"])
        bounded_tuple(row["evidence_ids"], 256, checked_key)
        if (not ids or type(row["revisions"]) is not dict or set(row["revisions"]) != set(ids)
                or any(type(v) is not int or not 1 <= v <= 1000000 for v in row["revisions"].values())):
            raise ProposalError("decision")
        if "insight_ids" in row:
            bounded_tuple(row["insight_ids"], 256, checked_id)
        if row["event"] == "proposal_decision" and not row.get("insight_ids"):
            raise ProposalError("decision")
        if "reason" in row and (type(row["reason"]) is not str or not row["reason"]
                                or clean_text(row["reason"], 300) != row["reason"]):
            raise ProposalError("decision")
        if row["decision"] == "reject" and not row.get("reason"):
            raise ProposalError("decision")
        if "rule_id" in row:
            checked_id(row["rule_id"])
        if "rule_digest" in row and not _digest(row["rule_digest"]):
            raise ProposalError("decision")
        if row["decision"] == "snooze":
            _until(row.get("until"))
        elif "until" in row:
            raise ProposalError("decision")
    except (ProposalError, ValueError):
        raise ProposalError("decision") from None
    return row


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _until(value):
    if type(value) is not str or len(value) != 10:
        raise ProposalError("decision")
    try:
        result = date.fromisoformat(value)
    except ValueError:
        raise ProposalError("decision") from None
    if result.isoformat() != value:
        raise ProposalError("decision")
    return result


class ProposalStore:
    """Use an owner-selected absolute workspace and optional absolute home root.

    ``write`` exclusively creates or compares a digest before replacing a pending
    draft. Identical retries are no-ops. ``decide`` records queue state only, with
    a required idempotency operation id. ``merge`` unions complete ancestry; it
    creates a pending draft and leaves source decisions to the caller. Multi-file
    rule installation/recovery belongs to the separate acceptance layer.
    """

    def __init__(self, root, *, home=None, timeout=5.0):
        if not isinstance(root, (str, Path)) or (home is not None and not isinstance(home, (str, Path))):
            raise ProposalError("invalid")
        if not 1 <= len(str(root)) <= 32768:
            raise ProposalError("invalid")
        self.root = Path(root)
        try:
            spelling = str(home) if home is not None else str(Path.home())
            if not 1 <= len(spelling) <= 32768:
                raise ProposalError("invalid")
            # This is an owner-selected root. Derived private components still
            # open from its descriptor with nofollow checks on every component.
            self.home = Path(spelling).resolve()
        except (OSError, RuntimeError, ValueError):
            raise ProposalError("invalid") from None
        if type(timeout) not in (int, float) or not 0 < timeout <= 30:
            raise ProposalError("invalid")
        self.timeout = timeout

    @contextmanager
    def _session(self, write=False):
        aegis_name = WorkspaceLayout(self.root).aegis_dir.name
        with _errors(), _root(self.root) as root, _directory(root, aegis_name, create=write) as aegis:
            with _directory(aegis, "state", create=True) as state:
                with file_lock(Path("lock"), timeout=self.timeout, dir_fd=state):
                    with _directory(aegis, "proposals", create=write) as proposals:
                        yield proposals

    def _read(self, directory, pid, durable=False):
        raw = _read(directory, pid + ".md", MAX_PROPOSAL_BYTES, durable=durable)
        return stored(parse_proposal(raw, pid), raw)

    def _ancestry(self, directory, proposal, snapshot=None):
        visiting, seen = set(), set()

        def visit(p):
            if p.id in visiting or len(seen) >= MAX_ANCESTORS:
                raise ProposalError("ancestry")
            if p.id in seen:
                return
            visiting.add(p.id)
            seen.add(p.id)
            for pid in p.parent_proposals:
                try:
                    parent = snapshot.get(pid) if snapshot is not None else self._read(directory, pid).proposal
                    if parent is None:
                        raise ProposalError("ancestry")
                except (FileNotFoundError, ProposalError):
                    raise ProposalError("ancestry") from None
                if (not set(parent.source_lineage) <= set(p.source_lineage)
                        or not set(parent.evidence_ids) <= set(p.evidence_ids)
                        or not set(parent.insight_ids) <= set(p.insight_ids)):
                    raise ProposalError("ancestry")
                visit(parent)
            visiting.remove(p.id)

        visit(proposal)

    @contextmanager
    def _private(self, create=False):
        # Only derive the log basename using the existing workspace-identity API.
        # Never reopen its pathname: all components are walked from trusted home.
        path = insights_path(self.root, home=self.home)
        with _root(self.home) as home, _directory(home, UserLayout(self.home).aegis_dir.name, create, True) as aegis:
            with _directory(aegis, "insights", create, True) as directory:
                with file_lock(Path(path.stem + ".lock"), timeout=self.timeout, dir_fd=directory):
                    yield directory, path.name

    def _private_rows(self, reconcile=None):
        try:
            with self._private() as (directory, name):
                raw = _optional_read(directory, name, MAX_LOG_BYTES)
                rows = _log_rows(raw or b"")
                if reconcile is not None and any(row["operation_id"] == reconcile for row in rows):
                    if _read(directory, name, MAX_LOG_BYTES, durable=True) != raw:
                        raise ProposalError("stale")
                return rows, raw
        except FileNotFoundError:
            return [], None

    def _rows(self, directory, reconcile=None, snapshot=False):
        rows = []
        try:
            with _directory(directory, "decisions") as decisions:
                for name in _names(decisions, ".json"):
                    raw = _read(decisions, name, MAX_ROW_BYTES)
                    row = _validate_row(_json(raw))
                    if row.get("insight_ids"):
                        raise ProposalError("decision")
                    if row["operation_id"] == reconcile:
                        if _read(decisions, name, MAX_ROW_BYTES, durable=True) != raw:
                            raise ProposalError("stale")
                    rows.append(row)
        except FileNotFoundError:
            pass
        private, raw = self._private_rows(reconcile=reconcile)
        # Both lists were bounded independently before allocation/append.
        rows.extend(private)
        if len({r["operation_id"] for r in rows}) != len(rows):
            raise ProposalError("decision")
        rows.sort(key=lambda row: (row["ts"], row["operation_id"]))
        # Only reuse these bytes while the caller holds the shared log lock.
        return (rows, raw, len(private)) if snapshot else rows

    def read(self, proposal_id):
        pid = checked_id(proposal_id)
        with self._session() as directory:
            saved = self._read(directory, pid)
            self._ancestry(directory, saved.proposal)
            return saved

    def list(self):
        with self._session() as directory:
            result = [self._read(directory, checked_id(name[:-3])) for name in _names(directory, ".md")]
            snapshot = {saved.proposal.id: saved.proposal for saved in result}
            for saved in result:
                self._ancestry(directory, saved.proposal, snapshot=snapshot)
            return result

    def _terminal(self, proposal, rows):
        return [r for r in rows if r["revisions"].get(proposal.id) == proposal.revision and r["decision"] in TERMINAL]

    def state(self, proposal_id):
        pid = checked_id(proposal_id)
        with self._session() as directory:
            p = self._read(directory, pid).proposal
            self._ancestry(directory, p)
            terminal = self._terminal(p, self._rows(directory))
            if not terminal:
                return p.status
            row = terminal[-1]
            if row["decision"] == "snooze" and _until(row["until"]) <= datetime.now(timezone.utc).date():
                return p.status
            return {"accept": "accepted", "reject": "rejected", "noise": "rejected",
                    "snooze": "snoozed", "merge-into-rule": "merged"}[row["decision"]]

    def resume(self, proposal_id):
        """Resume an expired snooze as one deterministic, actionable successor.

        The snoozed file and its decision are immutable. Repeated/concurrent
        calls return the same successor, including later edits to its draft.
        """
        pid = checked_id(proposal_id)
        with self._session(write=True) as directory:
            original = self._read(directory, pid)
            parent = original.proposal
            self._ancestry(directory, parent)
            terminal = self._terminal(parent, self._rows(directory))
            if (not terminal or terminal[-1]["decision"] != "snooze"
                    or _until(terminal[-1]["until"]) > datetime.now(timezone.utc).date()):
                raise ProposalError("terminal")
            key = hashlib.sha256((pid + "\n" + original.digest).encode()).hexdigest()[:40]
            # A generated alphabetic digest cannot resemble a credential token.
            # User-supplied identities still pass the unchanged redaction refusal.
            key = key.translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))
            prefix = "ins" if parent.source == "insight" else parent.source
            successor = replace(parent, id=f"{prefix}-{key}",
                                revision=parent.revision + 1, parent_proposals=(pid,))
            existing = _optional_read(directory, successor.id + ".md", MAX_PROPOSAL_BYTES)
            if existing is not None:
                saved = self._read(directory, successor.id, durable=True)
                if (saved.proposal.parent_proposals != (pid,) or saved.proposal.revision != successor.revision
                        or saved.proposal.candidate_key != parent.candidate_key):
                    raise ProposalError("exists")
                self._ancestry(directory, saved.proposal)
                return saved
            return self._write(directory, successor, None)

    def _write(self, directory, proposal, expected_digest, legacy_retry=None):
        raw = proposal.to_bytes()
        canonical = parse_proposal(raw, proposal.id)
        rows = self._rows(directory)
        if self._terminal(proposal, rows):
            raise ProposalError("terminal")
        existing = _optional_read(directory, proposal.id + ".md", MAX_PROPOSAL_BYTES)
        if existing is not None:
            old = parse_proposal(existing, proposal.id)
            if self._terminal(old, rows):
                raise ProposalError("terminal")
            identical = (existing == raw or (set(old.insight_ids) == set(canonical.insight_ids)
                         and replace(old, insight_ids=canonical.insight_ids) == canonical))
            if not identical and old.legacy and legacy_retry is not None:
                try:
                    comparison = legacy_retry() if callable(legacy_retry) else legacy_retry
                except ProposalError:
                    # An unbuildable historical form is just a failed match.
                    comparison = None
                if comparison is not None:
                    self._check_legacy_retry(proposal, comparison)
                    identical = (set(old.insight_ids) == set(comparison.insight_ids)
                                 and replace(old, insight_ids=comparison.insight_ids) == comparison)
            if identical:
                if _read(directory, proposal.id + ".md", MAX_PROPOSAL_BYTES, durable=True) != existing:
                    raise ProposalError("stale")
                return stored(old, existing)
            if expected_digest is None:
                raise ProposalError("exists")
            if hashlib.sha256(existing).hexdigest() != expected_digest:
                raise ProposalError("stale")
            protected = ("id", "source", "kind", "candidate_key", "revision", "evidence_ids", "labels",
                         "parent_proposals", "source_lineage", "insight_ids", "amends")
            if any(getattr(old, f) != getattr(proposal, f) for f in protected):
                raise ProposalError("provenance")
        elif expected_digest is not None:
            raise ProposalError("stale")
        else:
            _names(directory, ".md", reserve=1)
        self._ancestry(directory, proposal)
        _publish(directory, proposal.id + ".md", raw, replacing=existing is not None)
        return stored(canonical, raw)

    def _check_legacy_retry(self, proposal, legacy_retry):
        if (not isinstance(legacy_retry, Proposal)
                or any(getattr(legacy_retry, field) != getattr(proposal, field) for field in (
                    "id", "source", "candidate_key", "evidence_ids", "target_paths", "revision",
                    "parent_proposals", "source_lineage", "insight_ids", "status", "type", "enforcement", "amends",
                    "labels", "prediction"))):
            raise ProposalError("invalid")

    def write(self, proposal, *, expected_digest=None, legacy_retry=None):
        """Publish a proposal, optionally recognizing a lazily built legacy retry."""
        if not isinstance(proposal, Proposal) or (expected_digest is not None and not _digest(expected_digest)):
            raise ProposalError("invalid")
        if legacy_retry is not None:
            if expected_digest is not None or proposal.source != "insight":
                raise ProposalError("invalid")
            if not callable(legacy_retry):
                self._check_legacy_retry(proposal, legacy_retry)
        proposal.to_bytes()  # enforce bounds before opening or creating directories
        with self._session(write=True) as directory:
            return self._write(directory, proposal, expected_digest, legacy_retry=legacy_retry)

    def merge(self, proposal_ids, destination_id):
        ids = bounded_tuple(proposal_ids, 64, checked_id)
        destination_id = checked_id(destination_id)
        if not ids or destination_id in ids:
            raise ProposalError("ancestry")
        with self._session(write=True) as directory:
            parents = [self._read(directory, pid).proposal for pid in ids]
            for parent in parents:
                self._ancestry(directory, parent)
            first = parents[0]
            proposal = replace(first, id=destination_id, source="mine", status="needs_draft", do="",
                hypothesis="", prediction="", labels=(), revision=max(p.revision for p in parents) + 1,
                parent_proposals=ids, source_lineage=tuple(sorted({"mine"} | {s for p in parents for s in p.source_lineage})),
                evidence_ids=tuple(sorted({e for p in parents for e in p.evidence_ids})),
                insight_ids=tuple(sorted({i for p in parents for i in p.insight_ids})))
            return self._write(directory, proposal, None)

    def decide(self, proposal_ids, *, decision, operation_id, reason=None, rule_id=None, rule_digest=None, until=None):
        if type(decision) is not str or decision not in DECISIONS:
            raise ProposalError("decision")
        ids = bounded_tuple(proposal_ids, 64, checked_id)
        checked_id(operation_id)
        if not ids:
            raise ProposalError("decision")
        if reason is not None:
            reason = clean_text(reason, 300)
            if len(reason) == 0:
                raise ProposalError("reason")
        if decision == "reject" and reason is None:
            raise ProposalError("reason")
        if rule_id is not None:
            checked_id(rule_id)
        if rule_digest is not None and not _digest(rule_digest):
            raise ProposalError("decision")
        if decision == "snooze":
            if until is None:
                until = (datetime.now(timezone.utc).date() + timedelta(days=30)).isoformat()
            _until(until)
        elif until is not None:
            raise ProposalError("decision")
        with self._session(write=True) as directory:
            proposals = [self._read(directory, pid).proposal for pid in ids]
            for p in proposals:
                self._ancestry(directory, p)
            private = any(p.private for p in proposals)
            row = {"v": 1, "ts": utc_stamp(), "event": "proposal_decision" if private else "decision", "decision": decision,
                   "proposal_ids": list(ids), "revisions": {p.id: p.revision for p in proposals},
                   "evidence_ids": sorted({e for p in proposals for e in p.evidence_ids}), "operation_id": operation_id}
            if private:
                row["insight_ids"] = sorted({i for p in proposals for i in p.insight_ids})
            for name, value in (("reason", reason), ("rule_id", rule_id), ("rule_digest", rule_digest), ("until", until)):
                if value is not None:
                    row[name] = value
            _validate_row(row)
            self._rows(directory)  # Refuse malformed history before creating a new shared lock.
            if not private:
                _space_for_directory(directory, "decisions")
            # file_lock is reentrant by inode. Keep the shared log lock from the
            # authoritative history/quota read through either publication path.
            with self._private(create=True) as (private_dir, name):
                rows, previous_bytes, private_count = self._rows(directory, reconcile=operation_id, snapshot=True)
                for previous in rows:
                    if previous["operation_id"] == operation_id:
                        if {k: v for k, v in previous.items() if k != "ts"} != {k: v for k, v in row.items() if k != "ts"}:
                            raise ProposalError("operation")
                        return previous
                if any(self._terminal(p, rows) for p in proposals):
                    raise ProposalError("terminal")
                raw = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
                if len(raw) > MAX_ROW_BYTES:
                    raise ProposalError("too_large")
                if private:
                    existing = previous_bytes or b""
                    if private_count >= MAX_ROWS or len(existing) + len(raw) > MAX_LOG_BYTES:
                        raise ProposalError("too_large")
                    # Keep the private JSONL container with a separate proposal event.
                    if existing and not existing.endswith(b"\n"):
                        raise ProposalError("decision")
                    _publish(private_dir, name, existing + raw, replacing=previous_bytes is not None)
                else:
                    with _directory(directory, "decisions", create=True) as decisions:
                        _names(decisions, ".json", reserve=1)
                        stamp = row["ts"].replace("-", "").replace(":", "")
                        _publish(decisions, stamp + "-" + operation_id + ".json", raw)
                return row
