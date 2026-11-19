"""Opt-in loop subscriptions and stat-only inbox nudges, without host calls."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import time

from hierarchy_mailbox import ACROSS_ROLES, Mailbox, strict_json
from hierarchy_subscriptions import MAX_CONFIG, MAX_ENTRIES, SubscriptionError, notify, supported, validate
from hierarchy_workspace import Store
from aegis_core.primitives import json_preflight, sanitize_display
from aegis_core.redaction import redact_insight_text
from aegis_core.storage import ConfinedFileError, confined_file

MAX_NUDGE_ENTRIES = 8192
MAX_NUDGE_DESCRIPTORS = 64
PASS_DESCRIPTOR_RESERVE = 64


class NudgeError(ValueError):
    """Fixed nudge refusals, reported as recoverable holds rather than CLI errors."""

    def __init__(self, reason):
        self.code = "NUDGE_" + reason
        super().__init__({"LIMIT": "nudge descriptor or metadata budget exhausted",
                          "UNSUPPORTED": "nudge metadata polling unavailable",
                          "IO": "nudge metadata I/O refused"}[reason])


def nudge_refusal(error, fallback):
    """Classify exhaustion before normalization, including suppressed contexts."""
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, OSError) and current.errno in {errno.EMFILE, errno.ENFILE}:
            return NudgeError("LIMIT")
        if isinstance(current, NudgeError) and current.code == "NUDGE_LIMIT":
            return current
        pending.extend(link for link in (current.__cause__, current.__context__) if link is not None)
    return error if isinstance(error, NudgeError) else NudgeError(fallback)


class SubscriptionParser(argparse.ArgumentParser):
    """Syntax errors in opted-in invocations never display supplied arguments."""

    def error(self, message):
        error = SubscriptionError("INVALID")
        print(json.dumps({"code": error.code, "error": str(error)}, sort_keys=True))
        self.exit(2)


def _display(value):
    return redact_insight_text(sanitize_display(value, max_len=None), max_len=8192)[:400]


def configure(args):
    """Refuse new option values without argparse echoing supplied text."""
    value = getattr(args, "nudge_seconds", None)
    if value is not None:
        if len(value) > 32768:
            raise SubscriptionError("LIMIT")
        if not value or not value.isascii() or not value.isdecimal():
            raise SubscriptionError("INVALID")
        digits = value.lstrip("0")
        if not digits:
            raise SubscriptionError("INVALID")
        # Beyond the interval the poll cannot run. Compare lengths before int()
        # so neither integer parsing nor a later float conversion can overflow.
        args.nudge_seconds = (args.interval if len(digits) > len(str(args.interval))
                              else min(int(digits), args.interval))
    if args.subscriptions is not None:
        args.subscription_runner = LoopSubscriptions(args.store, args.subscriptions)


def configuration_path(value):
    """Bound the spelling before path parsing; do not resolve untrusted aliases."""
    if type(value) is not str or not 1 <= len(value) <= 32768 or "\x00" in value:
        raise SubscriptionError("PATH")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SubscriptionError("PATH")
    return path


def registered_mailboxes(store):
    """Let Store select its reader; retain every registered root for placement."""
    try:
        ledger = Store(store).load()
        return sorted((row for row in ledger.initiatives.values()
                       if "mailbox_root" in row),
                      key=lambda row: (row["priority"], row["id"]))
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError):
        raise SubscriptionError("IO") from None


def active_mailboxes(store):
    """Use the same active, provisioned initiatives as the durable sweep."""
    return [row for row in registered_mailboxes(store) if row["state"] == "active" and "delivery_dir" in row]


def _storage_error(error):
    reason = {"too_large": "LIMIT", "unsupported": "UNSUPPORTED", "invalid_path": "PATH"}.get(error.reason, "IO")
    return SubscriptionError(reason)


class LoopSubscriptions:
    """Validate before serving; pass frozen per-mailbox configuration to SUB-1."""

    def __init__(self, store, source):
        if not supported():
            raise SubscriptionError("UNSUPPORTED")
        self.store = store
        source = configuration_path(source)
        try:
            with confined_file(source.parent, (source.name,)) as target:
                self.raw = target.read_bytes(MAX_CONFIG)
        except ConfinedFileError as error:
            raise _storage_error(error) from None
        try:
            text = json_preflight(self.raw, max_bytes=MAX_CONFIG, max_depth=16,
                                  max_nodes=200000, max_items=10000, max_string=32768, max_atom=32)
            self.configuration = strict_json(text)
        except (ValueError, UnicodeError, RecursionError):
            raise SubscriptionError("INVALID") from None
        initiatives = active_mailboxes(store)
        if not initiatives:
            raise SubscriptionError("MAILBOX")
        if (type(self.configuration) is not dict or type(self.configuration.get("subscriptions")) is not list
                or len(self.configuration["subscriptions"]) > MAX_ENTRIES):
            raise SubscriptionError("INVALID")
        unmatched = {}
        for number, entry in enumerate(self.configuration["subscriptions"]):
            if (type(entry) is not dict or type(entry.get("subscriber")) is not str
                    or not 1 <= len(entry["subscriber"]) <= 200 or entry["subscriber"] in unmatched):
                raise SubscriptionError("INVALID", number)
            unmatched[entry["subscriber"]] = number
        for row in initiatives:
            try:
                selected = self._configuration(Mailbox(row["mailbox_root"]))
                for entry in selected["subscriptions"]:
                    unmatched.pop(entry["subscriber"], None)
            except SubscriptionError:
                raise
            except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError):
                raise SubscriptionError("MAILBOX") from None
        if unmatched:
            raise SubscriptionError("INVALID", min(unmatched.values()))
        self.sha256 = hashlib.sha256(self.raw).hexdigest()

    def _configuration(self, mailbox):
        # SUB-1 validates the public schema and each subscriber's actual routes.
        configuration = {**self.configuration, "subscriptions": []}
        validate(configuration, mailbox)
        for number, entry in enumerate(self.configuration["subscriptions"]):
            if entry["subscriber"] in mailbox.manifest["endpoints"]:
                try:
                    validate({**configuration, "subscriptions": [entry]}, mailbox)
                except SubscriptionError:
                    raise SubscriptionError("INVALID", number) from None
                configuration["subscriptions"].append(entry)
        return configuration

    def _bytes(self, configuration):
        if len(configuration["subscriptions"]) == len(self.configuration["subscriptions"]):
            return self.raw
        chunks, size = [], 0
        for chunk in json.JSONEncoder(ensure_ascii=True, separators=(",", ":")).iterencode(configuration):
            size += len(chunk)
            if size > MAX_CONFIG:
                raise SubscriptionError("LIMIT")
            chunks.append(chunk.encode("ascii"))
        return b"".join(chunks)

    def _notify(self, root, registered):
        # HM brief references must remain outside the mailbox, within its parent.
        # The shared state namespace includes SUB-1's mailbox identity in cursors.
        root = configuration_path(root)
        try:
            mailbox = Mailbox(root)
            configuration = self._configuration(mailbox)
        except SubscriptionError:
            raise
        except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError):
            raise SubscriptionError("MAILBOX") from None
        state = root.parent / "subscriptions"
        try:
            for row in registered:
                Mailbox(row["mailbox_root"]).outside_mailbox(state, "subscription state directory")
        except (ValueError, OSError, UnicodeError):
            raise SubscriptionError("PATH") from None
        if not configuration["subscriptions"]:
            return None
        raw = self._bytes(configuration)
        name = "configuration-" + hashlib.sha256(raw).hexdigest() + ".json"
        try:
            with confined_file(root.parent, (state.name, name), create_parents=True) as target:
                info = target.parent_stat()
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise SubscriptionError("IO")
                try:
                    target.publish_bytes(raw)
                except ConfinedFileError as error:
                    if error.reason != "exists":
                        raise
                    if target.read_bytes(MAX_CONFIG) != raw:
                        raise SubscriptionError("STATE")
            return notify(root, state, state / name)
        except ConfinedFileError as error:
            raise _storage_error(error) from None

    def run(self, work):
        """A refusal is a hold; independent mailboxes and later steps still run."""
        totals = {key: 0 for key in ("published", "recovered", "matched", "held")}
        work.subscription_suppressed_complete = True
        before = len(work.holds)
        try:
            registered = registered_mailboxes(self.store)
            initiatives = [row for row in registered if row["state"] == "active" and "delivery_dir" in row]
        except SubscriptionError as error:
            work.hold("notify", error.code, str(error), "owner")
            initiatives = []
        for row in initiatives:
            try:
                summary = self._notify(row["mailbox_root"], registered)
                if summary is None:
                    continue
                for key in totals:
                    totals[key] += summary[key]
                work.subscription_suppressed.extend({"initiative": _display(row["id"]), **item}
                                                    for item in summary["subscription_suppressed"])
            except SubscriptionError as error:
                work.hold("notify", error.code, str(error), "owner", initiative=_display(row["id"]))
        failed = len(work.holds) != before
        if failed:
            # SUB-1 may publish before raising for a later subscriber. Its API
            # supplies no partial summary, so zero would assert an unobserved fact.
            totals = {key: None for key in totals}
            work.subscription_suppressed_complete = False
        work.steps.append({"step": "notify", "state": "hold" if failed else "ok", "exit": 2 if failed else 0,
                           "complete": not failed, **totals})


def descriptor_capacity():
    """Cap watchers and leave a fixed reserve above current process descriptor use."""
    try:
        import resource
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except (ImportError, OSError, ValueError) as error:
        raise nudge_refusal(error, "UNSUPPORTED") from None
    for folder in ("/proc/self/fd", "/dev/fd"):
        try:
            count = 0
            with os.scandir(folder) as entries:
                for _ in entries:
                    count += 1
                    if count > MAX_NUDGE_ENTRIES:
                        raise NudgeError("LIMIT")
            available = MAX_NUDGE_DESCRIPTORS if limit == resource.RLIM_INFINITY else limit - count - PASS_DESCRIPTOR_RESERVE
            return max(0, min(MAX_NUDGE_DESCRIPTORS, available))
        except OSError as error:
            refusal = nudge_refusal(error, "UNSUPPORTED")
            if refusal.code == "NUDGE_LIMIT":
                raise refusal from None
            continue
    raise NudgeError("UNSUPPORTED")


def path_polling_supported():
    return callable(getattr(os, "stat", None))


def release_nudge(args):
    """Reclaim watcher capacity after a failed launch; never retry that step here."""
    watcher = getattr(args, "nudge_watcher", None)
    if watcher is not None:
        watcher.close()
    args.nudge_watcher = None
    return NudgeError("LIMIT")


class InboxNudge:
    """Share confined ancestors where available; interval polling is stat-only.

    Observe directory entries as well as held directories so renaming or replacing
    a component causes a nudge. No entry names or message bodies are enumerated.
    """

    def __init__(self, roots):
        self.descriptors, self.entries = [], []
        self.directories, self.paths = {}, {}
        self.closed, self.confined = False, supported()
        if not path_polling_supported():
            raise NudgeError("UNSUPPORTED")
        self.budget = descriptor_capacity() if self.confined else 0
        try:
            for root in roots:
                root = configuration_path(str(root))
                mailbox = Mailbox(root)
                folders = {tuple(endpoint.split("/")[:2]) for endpoint in mailbox.manifest["endpoints"]}
                folders.update(("across", role) for role in ACROSS_ROLES)
                for parts in sorted(folders):
                    self._watch(root.joinpath(*parts))
            self.baseline = self.snapshot()
        except BaseException:
            self.close()
            raise

    def _watch(self, path):
        if max(len(self.entries), len(self.paths)) + len(path.parts) > MAX_NUDGE_ENTRIES:
            raise NudgeError("LIMIT")
        if not self.confined:
            for ancestor in reversed(path.parents):
                self.paths.setdefault(ancestor, False)
            self.paths[path] = True
            if len(self.paths) > MAX_NUDGE_ENTRIES:
                raise NudgeError("LIMIT")
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        directory = Path(path.anchor)
        if directory not in self.directories:
            self.directories[directory] = self._open_directory(path.anchor, flags)
        descriptor = self.directories[directory]
        for component in path.parts[1:]:
            directory = directory / component
            if directory not in self.directories:
                child = self._open_directory(component, flags, dir_fd=descriptor)
                self.entries.append((descriptor, component, False))
                self.directories[directory] = child
            descriptor = self.directories[directory]
        if path not in self.paths:
            self.entries.append((descriptor, ".", True))
            self.paths[path] = True

    def _open_directory(self, *args, **kwargs):
        if len(self.descriptors) >= self.budget:
            raise NudgeError("LIMIT")
        descriptor = os.open(*args, **kwargs)
        self.descriptors.append(descriptor)
        return descriptor

    def snapshot(self):
        values = []
        if self.confined:
            entries = ((os.stat(name, dir_fd=directory, follow_symlinks=False), metadata)
                       for directory, name, metadata in self.entries)
        else:
            entries = ((os.stat(path, follow_symlinks=False), metadata) for path, metadata in self.paths.items())
        for info, metadata in entries:
            identity = (info.st_dev, info.st_ino, info.st_mode)
            values.append(identity + (info.st_size, info.st_mtime_ns, info.st_ctime_ns) if metadata else identity)
        return values

    def wait(self, interval, seconds, stopped):
        deadline = time.monotonic() + interval
        poll = time.monotonic() + seconds
        while not stopped():
            now = time.monotonic()
            if now >= deadline:
                return
            if now >= poll:
                try:
                    if self.snapshot() != self.baseline:
                        return
                except OSError:
                    return  # A removed directory is also a change; the next pass reports it.
                poll = now + seconds
            time.sleep(min(0.2, max(0.0, min(deadline, poll) - now)))

    def close(self):
        self.closed = True
        while self.descriptors:
            os.close(self.descriptors.pop())
        self.directories.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def prepare_nudge(args):
    """Snapshot before a pass, so mail arriving during its steps is observed too."""
    try:
        roots = [row["mailbox_root"] for row in active_mailboxes(args.store)]
        return InboxNudge(roots), None
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError) as error:
        fallback = "UNSUPPORTED" if isinstance(error, SubscriptionError) and error.code == "SUBSCRIPTIONS_UNSUPPORTED" else "IO"
        return None, nudge_refusal(error, fallback)

