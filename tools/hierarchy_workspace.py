#!/usr/bin/env python3
"""Workspace controller: initiative registry, shared capacity ledger and lease check.

One mailbox root per initiative keeps histories small and independent, but per-root
counters cannot enforce a workspace-wide cap, and leases in independent clones cannot
see each other. This store is the single place for both, written only by this tool.

Root runs it directly. Grants never come from anything a model session can call; the
adapter exposes read-only views at most. Priority order is the owner's: each change
names its source, and the tool applies the order without judging it.

It is a record kept under one OS user, not a security boundary: a same-user process can
edit the files. A hash chain would not change that, so damage is only detected when it
breaks the history. A clear lease check is advice, not a lock, because Aegis leases are
cooperative and the check and the claim are separate steps.

Ordinary events retain the v1 encoding. A request with supersedes uses v2 and
atomically withdraws its queued predecessor, inheriting that row's queue sequence.
Both versions replay here and in the dispatcher. Older readers refuse a v2 store
with "wrong event schema or sequence"; they must be upgraded before reading it.
Holder identity is nominal free text, under this controller's same-user authority.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from statistics import median
import sys
import time

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from hierarchy_mailbox import (GIT_ID, MAX_BYTES, MAX_RECORDS, MAX_WRITERS, SHA256, SLUG, Mailbox, encoded,  # noqa: E402
                               integer, matching, parse_time, publish_file, read_json, safe_path, strings,
                               strict_json, text, timestamp)

from hierarchy_workspace_display import (MAX_DISPLAY, _ArgumentParser, _AUTH_SCHEME, _DISPLAY_ALLOWLIST,  # noqa: E402
                                         _DISPLAY_CREDENTIALS, _DISPLAY_HASH_CHUNK, _KEYS, _NB, _PEM_HEAD,
                                         _PEM_TAIL, _Refusal, _SCHEMES, _SECRET_REDACTIONS, _UNTRUSTED_DISPLAY_FIELDS,
                                         _credential_match, _display, _display_fields, _display_refusals,
                                         _display_response, require)


EVENT_SCHEMA = "aegis.hierarchy-workspace-event/v1"
SUPERSEDE_EVENT_SCHEMA = "aegis.hierarchy-workspace-event/v2"
REPLAY_SCHEMAS = frozenset((EVENT_SCHEMA, SUPERSEDE_EVENT_SCHEMA))
# Ceilings for a store's limits. They are the owner's current limits, and raising them is an owner
# decision after measuring the machine, so it takes a reviewed code change. MAX_WRITERS is 5 by
# owner-writers-5 (requests/root-c6-owner-decisions-20261102.json) and lives in hierarchy_mailbox,
# because a manifest's writer_limit is built from the store's and the two must agree.
MAX_HEAVY = 3
# Heavy-Tests is the owner's single named slot where cargo builds and tests run ("only allow one",
# owner-heavy-tests-slot). It is independent of heavy, the 3 test slots, so at most 4 test jobs run
# at once and at most 1 of them is cargo.
MAX_HEAVY_TESTS = 1
# Every store initialized before Heavy-Tests existed has no heavy_tests_limit, and must load unchanged.
DEFAULT_HEAVY_TESTS = 1
MAX_PRIORITY = 1000
MAX_VIEW_ROWS = 100
MAX_EVIDENCE_BYTES = 67108864
KINDS = ("writer", "heavy", "heavy-tests")
INITIATIVE_STATES = {"active", "paused", "done"}
EVENT_NAME = re.compile(r"(\d{8})\.json")
# Pinned mailbox validators can include paths or JSON keys in their exceptions.
# Keep their validation and portable I/O behavior, but own diagnostics locally.
_PATH_REFUSAL_PREFIXES = ("symlink paths are not supported: ", "file unavailable: ")
safe_path = _display_refusals(safe_path, trusted_values=True, value_prefixes=_PATH_REFUSAL_PREFIXES)
read_json = _display_refusals(read_json, trusted_values=True,
                              value_prefixes=(*_PATH_REFUSAL_PREFIXES, "duplicate JSON key: "))
strict_json = _display_refusals(strict_json, trusted_values=True, value_prefixes=("duplicate JSON key: ",))
# Labels passed to these validators are source literals, never request values.
text = _display_refusals(text, trusted_values=True)
integer = _display_refusals(integer, trusted_values=True)
matching = _display_refusals(matching, trusted_values=True)
strings = _display_refusals(strings, trusted_values=True)
parse_time = _display_refusals(parse_time, trusted_values=True)


def fields(value, required, optional=()):
    """Keep the pinned field contract, displaying each unexpected raw key."""
    require(isinstance(value, dict), "expected a JSON object")
    require(set(required) <= value.keys(), "missing fields: " + ", ".join(sorted(set(required) - value.keys())))
    require(value.keys() <= set(required) | set(optional),
            "unexpected fields: " + ", ".join(_display(key) for key in sorted(
                value.keys() - set(required) - set(optional))))


def absolute(value, label):
    path = Path(text(value, label))
    require(path.is_absolute() and ".." not in path.parts, label + " must be absolute")
    return value


def evidence_reference(value):
    fields(value, {"path", "sha256"})
    matching(value["sha256"], SHA256, "evidence sha256")
    absolute(value["path"], "evidence path")


def verify_evidence(value):
    """Only this controller reads evidence, and only to prove a release or revalidation has it."""
    evidence_reference(value)
    try:
        path = safe_path(value["path"])
        require(path.stat().st_size <= MAX_EVIDENCE_BYTES, "terminal evidence exceeds the size limit")
        raw = path.read_bytes()
    except (OSError, _Refusal) as exc:
        if isinstance(exc, _Refusal) and not isinstance(exc.__cause__, OSError):
            raise
        raise _Refusal("terminal evidence is unavailable: " + _display(value["path"]), displayed=True) from exc
    require(hashlib.sha256(raw).hexdigest() == value["sha256"], "terminal evidence does not match its hash")


def validate_initiative(data):
    fields(data, {"id", "project", "repository", "priority", "target_branch"},
           {"touched_paths", "blocked_by", "checkouts", "lanes", "mailbox_root", "delivery_dir", "source"})
    if "source" in data:
        text(data["source"], "source")
    matching(data["id"], SLUG, "initiative id")
    matching(data["project"], SLUG, "project")
    text(data["repository"], "repository", 256)
    integer(data["priority"], "priority", maximum=MAX_PRIORITY)
    text(data["target_branch"], "target_branch", 256)
    validate_lists(data)
    for name in ("mailbox_root", "delivery_dir"):
        if name in data:
            absolute(data[name], name)


def validate_lists(data):
    if "touched_paths" in data:
        strings(data["touched_paths"], "touched paths")
    if "blocked_by" in data:
        strings(data["blocked_by"], "blocked_by")
    if "lanes" in data:
        strings(data["lanes"], "lanes")
    if "checkouts" in data:
        strings(data["checkouts"], "checkouts")
        for checkout in data["checkouts"]:
            absolute(checkout, "checkout")


class Ledger:
    """State rebuilt by replaying immutable events. Every rule runs on replay too, so a bad edit fails loudly."""

    def __init__(self):
        self.seq = 0
        self.limits = None
        self.initiatives = {}
        self.requests = {}
        self.open_holders = set()
        self.granted_counts = dict.fromkeys(KINDS, 0)

    def initiative(self, identifier):
        require(identifier in self.initiatives, "initiative is not registered: " + _display(identifier))
        return self.initiatives[identifier]

    def request(self, identifier):
        require(identifier in self.requests, "unknown request: " + _display(identifier))
        return self.requests[identifier]

    def held(self, kind):
        return [r for r in self.requests.values() if r["kind"] == kind and r["state"] == "granted"]

    def unresolved(self, initiative):
        return [b for b in initiative["blocked_by"]
                if b not in self.initiatives or self.initiatives[b]["state"] != "done"]

    def apply(self, event):
        require(event["kind"] in APPLY, "unknown workspace event: " + _display(event["kind"]))
        require(event["kind"] == "init" or self.limits is not None, "workspace store is not initialized")
        APPLY[event["kind"]](self, event["data"], event)
        self.seq = event["seq"]


def apply_init(ledger, data, _event):
    fields(data, {"writer_limit", "heavy_limit"}, {"heavy_tests_limit"})
    integer(data["writer_limit"], "writer_limit", maximum=MAX_WRITERS)
    integer(data["heavy_limit"], "heavy_limit", maximum=MAX_HEAVY)
    heavy_tests = integer(data.get("heavy_tests_limit", DEFAULT_HEAVY_TESTS), "heavy_tests_limit",
                          maximum=MAX_HEAVY_TESTS)
    require(ledger.limits is None, "workspace store is already initialized")
    ledger.limits = {"writer": data["writer_limit"], "heavy": data["heavy_limit"], "heavy-tests": heavy_tests}


LIMIT_FIELDS = {"writer_limit": ("writer", MAX_WRITERS), "heavy_limit": ("heavy", MAX_HEAVY),
                "heavy_tests_limit": ("heavy-tests", MAX_HEAVY_TESTS)}


def apply_set_limits(ledger, data, _event):
    """A reviewed change to an initialized store's limits. Lowering below the work already granted would
    leave the replayed ledger over capacity, and accepted work is never preempted, so that is refused."""
    fields(data, {"source"}, set(LIMIT_FIELDS))
    text(data["source"], "source")
    changes = sorted(data.keys() - {"source"})
    require(changes, "set-limits needs at least one limit")
    for name in changes:
        kind, ceiling = LIMIT_FIELDS[name]
        integer(data[name], name, maximum=ceiling)
        held = ledger.granted_counts[kind]
        require(data[name] >= held, "%s %d is below the %d granted %s requests" % (name, data[name], held, kind))
    for name in changes:
        ledger.limits[LIMIT_FIELDS[name][0]] = data[name]


def require_unclaimed_lanes(ledger, repository, lanes, identifier):
    for other in ledger.initiatives.values():
        if other["id"] != identifier and other["repository"] == repository:
            taken = sorted(set(lanes) & set(other["lanes"]))
            require(not taken, "lane already belongs to initiative " + other["id"] + ": "
                    + ", ".join(_display(lane) for lane in taken))


def apply_register(ledger, data, event):
    validate_initiative(data)
    require(data["id"] not in ledger.initiatives, "initiative already registered: " + data["id"])
    require_unclaimed_lanes(ledger, data["repository"], data.get("lanes", []), data["id"])
    ledger.initiatives[data["id"]] = {
        "touched_paths": [], "blocked_by": [], "checkouts": [], "lanes": [], **data, "state": "active",
        "base_moved": None, "registered_at": event["at"]}


def apply_update(ledger, data, _event):
    fields(data, {"initiative", "source"}, {"priority", "state", "blocked_by", "touched_paths", "checkouts", "lanes"})
    initiative = ledger.initiative(data["initiative"])
    text(data["source"], "source")
    validate_lists(data)
    require_unclaimed_lanes(ledger, initiative["repository"], data.get("lanes", []), initiative["id"])
    if "priority" in data:
        integer(data["priority"], "priority", maximum=MAX_PRIORITY)
    if "state" in data:
        require(isinstance(data["state"], str) and data["state"] in INITIATIVE_STATES, "invalid initiative state")
        if data["state"] == "done":
            require(not any(r["initiative"] == initiative["id"] and r["state"] in ("queued", "granted")
                            for r in ledger.requests.values()),
                    "initiative still holds capacity or queued requests: " + initiative["id"])
    initiative.update({key: value for key, value in data.items() if key not in ("initiative", "source")})


def apply_request(ledger, data, event):
    fields(data, {"request_id", "initiative", "kind", "holder"}, {"reference", "supersedes"})
    initiative = ledger.initiative(data["initiative"])
    require(initiative["state"] == "active", "initiative is not active: " + initiative["id"])
    require(isinstance(data["kind"], str) and data["kind"] in KINDS, "invalid kind")
    text(data["holder"], "holder", 256)
    if "reference" in data:
        text(data["reference"], "reference")
    require(data["request_id"] not in ledger.requests, "duplicate request id")
    previous = None
    if "supersedes" in data:
        identifier = text(data["supersedes"], "supersedes", 12)
        require(re.fullmatch(r"req-[0-9]{8}", identifier) is not None, "invalid supersedes")
        require(event["schema"] == SUPERSEDE_EVENT_SCHEMA, "supersedes requires workspace event v2")
        require(identifier in ledger.requests, "superseded request does not exist")
        previous = ledger.requests[identifier]
        require(all(previous[key] == data[key] for key in ("initiative", "holder", "kind")),
                "superseded request must have the same initiative, holder and kind")
        require(previous["state"] != "granted",
                identifier + " is granted: accepted work is never preempted; wait for its release")
        require(previous["state"] == "queued", "superseded request is not queued")
    holder = (data["kind"], data["holder"])
    require(previous is not None or holder not in ledger.open_holders, "holder already has an open request")
    replacement = {**data, "state": "queued", "seq": previous["seq"] if previous is not None else event["seq"],
                   "requested_at": event["at"], "reserved_repository": initiative["repository"],
                   "reserved_paths": list(initiative["touched_paths"])}
    if previous is not None:
        previous.update(state="withdrawn", closed_at=event["at"], superseded_by=data["request_id"])
    ledger.requests[data["request_id"]] = replacement
    ledger.open_holders.add(holder)


def apply_withdraw(ledger, data, event):
    fields(data, {"request_id", "source"})
    text(data["source"], "source")
    request = ledger.request(data["request_id"])
    require(request["state"] == "queued", "request is not queued: " + _display(data["request_id"]))
    request.update(state="withdrawn", closed_at=event["at"])
    ledger.open_holders.remove((request["kind"], request["holder"]))


def apply_grant(ledger, data, event):
    fields(data, {"request_id"})
    request = ledger.request(data["request_id"])
    require(request["state"] == "queued", "request is not queued: " + _display(data["request_id"]))
    require(ledger.granted_counts[request["kind"]] < ledger.limits[request["kind"]], "ledger grant exceeds capacity")
    request.update(state="granted", granted_at=event["at"])
    ledger.granted_counts[request["kind"]] += 1


def apply_release(ledger, data, event):
    fields(data, {"request_id", "evidence"})
    evidence_reference(data["evidence"])
    request = ledger.request(data["request_id"])
    require(request["state"] == "granted", "request is not granted: " + _display(data["request_id"]))
    request.update(state="released", closed_at=event["at"], evidence=data["evidence"])
    ledger.open_holders.remove((request["kind"], request["holder"]))
    ledger.granted_counts[request["kind"]] -= 1


def apply_merge(ledger, data, event):
    fields(data, {"repository", "branch", "commit", "source"}, {"initiative"})
    text(data["repository"], "repository", 256)
    text(data["branch"], "branch", 256)
    matching(data["commit"], GIT_ID, "commit")
    text(data["source"], "source")
    if "initiative" in data:
        ledger.initiative(data["initiative"])
    for initiative in ledger.initiatives.values():
        if (initiative["repository"] == data["repository"] and initiative["target_branch"] == data["branch"]
                and initiative["state"] != "done" and initiative["id"] != data.get("initiative")):
            initiative["base_moved"] = {"commit": data["commit"], "at": event["at"], "source": data["source"]}


def apply_clear(ledger, data, _event):
    fields(data, {"initiative", "base_commit", "evidence", "source"})
    text(data["source"], "source")
    evidence_reference(data["evidence"])
    initiative = ledger.initiative(data["initiative"])
    require(initiative["base_moved"] is not None, "initiative has no moved base: " + initiative["id"])
    require(initiative["base_moved"]["commit"] == data["base_commit"],
            "revalidation does not match the latest moved base")
    initiative["base_moved"] = None


APPLY = {"init": apply_init, "register": apply_register, "update": apply_update, "request": apply_request,
         "withdraw": apply_withdraw, "grant": apply_grant, "release": apply_release, "merge": apply_merge,
         "clear_base_moved": apply_clear, "set_limits": apply_set_limits}


def _memo_supported():
    return (os.name == "posix" and all(hasattr(os, name) for name in ("O_PATH", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            and {"open", "stat"} <= {function.__name__ for function in os.supports_dir_fd}
            and os.scandir in os.supports_fd)


def _event_key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Store:
    def __init__(self, path):
        self.path = safe_path(path)
        self.events = self.path / "events"
        self._memo = None

    @contextmanager
    def _event_directory(self):
        """Walk from the filesystem root with no-follow descriptors; never reopen by pathname."""
        safe_path(self.events)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        search_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = None
        ancestors = []
        try:
            descriptor = os.open(self.events.anchor, search_flags)
            for index, component in enumerate(self.events.parts[1:], 1):
                info = os.fstat(descriptor)
                ancestors.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid))
                child = os.open(component, flags if index == len(self.events.parts) - 1 else search_flags,
                                dir_fd=descriptor)
                parent, descriptor = descriptor, child
                os.close(parent)
            info = os.fstat(descriptor)
            ancestors.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid))
            credentials = (os.getuid(), os.geteuid(), os.getgid(), os.getegid(), tuple(os.getgroups()))
            yield descriptor, (tuple(ancestors), credentials)
        except OSError as exc:
            raise _Refusal("workspace event directory is unavailable", displayed=True) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _read_event(self, directory, path, key):
        """Bound bytes before parsing, and bind them to the observed file identity."""
        descriptor = None
        try:
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode), "input must be a regular file")
            require(_event_key(info) == key, "workspace event changed while reading")
            require(info.st_size <= MAX_BYTES, "input exceeds 262144 bytes")
            raw = bytearray()
            while len(raw) <= MAX_BYTES:
                try:
                    chunk = os.read(descriptor, MAX_BYTES + 1 - len(raw))
                except InterruptedError:
                    continue
                if not chunk:
                    break
                raw.extend(chunk)
            require(len(raw) == info.st_size and _event_key(os.fstat(descriptor)) == key
                    and _event_key(os.stat(path.name, dir_fd=directory, follow_symlinks=False)) == key,
                    "workspace event changed while reading")
            return strict_json(raw.decode("utf-8"))
        except OSError as exc:
            raise _Refusal("workspace event is unavailable", displayed=True) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @contextmanager
    def lock(self):
        lock = safe_path(self.path / ".write.lock")
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise _Refusal("workspace store is busy; inspect an abandoned lock before retrying", displayed=True) from exc
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(encoded({"pid": os.getpid(), "created_at": timestamp()}))
            yield
        finally:
            try:
                os.close(fd)
            finally:
                lock.unlink()

    def load(self, *, for_report=False):
        """Replay strictly; reports alone may represent damaged request-event times as null.

        Reducers still validate every state transition. Null prevents an invalid
        timestamp from leaking through a report's capacity view and makes the
        affected request's timing unknown without rewriting the durable event.
        """
        require(self.events.is_dir(), "workspace store is not initialized")
        if not _memo_supported():
            # Preserve the portable reader; metadata reuse needs checked descriptor reads.
            self._memo = None
            return self._replay(sorted(self.events.iterdir()), read_json, for_report)
        with self._event_directory() as (directory, context):
            paths = []
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = self.events / entry.name
                    if entry.name.startswith(".pending-"):
                        safe_path(path)
                        continue
                    require(len(paths) < MAX_RECORDS, "workspace event history exceeds record limit")
                    paths.append(path)
            paths.sort()
            keys = []
            for path in paths:
                info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode), "symlink paths are not supported: " + _display(path))
                keys.append((path.name, _event_key(info)))
            previous, self._memo = self._memo, None
            ledger = None
            # MB-1: in-process bytes only; full file lstat keys include ctime, mode and uid.
            # Directory identities exclude timestamps; lock-file churn must not invalidate replay.
            # Same-stat rewrites share MB-1's accepted metadata-observation limit.
            if not for_report and previous is not None:
                old_context, old_keys, old_ledger = previous
                if context == old_context and keys[:len(old_keys)] == old_keys:
                    ledger = deepcopy(old_ledger)
            result = self._replay(paths, lambda path: self._read_event(directory, path, keys[int(path.stem) - 1][1]),
                                  for_report, ledger)
            if not for_report:
                self._memo = (context, keys, deepcopy(result))
            return result

    def _replay(self, paths, reader, for_report, ledger=None):
        ledger = Ledger() if ledger is None else ledger
        replayed = ledger.seq
        count = 0
        for path in paths:
            if path.name.startswith(".pending-"):
                # Never read, but a planted symlink still fails loudly. Events get the same check inside
                # read_json; checking them here too walked every ancestor twice per event on a full store.
                safe_path(path)
                continue
            name = EVENT_NAME.fullmatch(path.name)
            require(name is not None, "unexpected workspace store entry: " + _display(path.name))
            count += 1
            require(count <= MAX_RECORDS, "workspace event history exceeds record limit")
            require(int(name.group(1)) == count, "nonconsecutive workspace event: " + _display(path.name))
            if count <= replayed:
                continue
            try:
                event = reader(path)
                fields(event, {"schema", "seq", "at", "kind", "data"})
                require(event["schema"] in REPLAY_SCHEMAS and event["seq"] == count, "wrong event schema or sequence")
                try:
                    parse_time(event["at"])
                except ValueError:
                    if not (for_report and event["kind"] in ("request", "grant", "release", "withdraw")):
                        raise
                    event = {**event, "at": None}
                ledger.apply(event)
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                detail = exc.message if isinstance(exc, _Refusal) else _display(exc)
                raise _Refusal("malformed workspace event: " + _display(path) + ": " + detail, displayed=True) from exc
        require(ledger.limits is not None, "workspace store is not initialized")
        return ledger

    def append(self, ledger, kind, data):
        """Apply first, so a refused change writes nothing. Hard-link publication refuses a duplicate sequence."""
        # Runs under the store lock. One event past the limit would make every later load fail,
        # including the release that frees capacity, so a full store refuses and stays readable.
        require(ledger.seq < MAX_RECORDS, "workspace event history limit reached")
        schema = SUPERSEDE_EVENT_SCHEMA if kind == "request" and "supersedes" in data else EVENT_SCHEMA
        event = {"schema": schema, "seq": ledger.seq + 1, "at": timestamp(), "kind": kind, "data": data}
        ledger.apply(event)
        publish_file(self.events / ("%08d.json" % event["seq"]), encoded(event) + b"\n")
        return event


def capacity_view(ledger):
    view = {}
    for kind in KINDS:
        held = ledger.held(kind)
        view[kind] = {"limit": ledger.limits[kind], "used": len(held), "free": ledger.limits[kind] - len(held),
                      "holders": [request_view(r) for r in held][:MAX_VIEW_ROWS]}
    queued = sorted((r for r in ledger.requests.values() if r["state"] == "queued"),
                    key=lambda r: (ledger.initiatives[r["initiative"]]["priority"], r["seq"]))
    view["queue"] = [request_view(r) for r in queued][:MAX_VIEW_ROWS]
    return view


def request_view(request):
    return {key: request[key] for key in ("request_id", "initiative", "kind", "holder", "state", "requested_at")}


def initiative_view(ledger, identifier):
    initiative = ledger.initiative(identifier)
    counts = {state: {kind: sum(1 for r in ledger.requests.values() if r["initiative"] == identifier
                                and r["kind"] == kind and r["state"] == state) for kind in KINDS}
              for state in ("granted", "queued")}
    return {key: initiative[key] for key in ("id", "project", "repository", "priority", "state", "target_branch",
                                             "touched_paths", "lanes", "base_moved")} | {
        "blocked_by": ledger.unresolved(initiative), "holds": counts["granted"], "queued": counts["queued"]}


@_display_response
def grant_next(store, kind, outside=None):
    """`outside` counts heavy work this ledger does not hold. It runs inside the same lock as the grant, so two
    callers counting at the same moment cannot both see room for one slot."""
    require(kind in KINDS, "invalid kind")
    with store.lock():
        ledger = store.load()
        others = outside(ledger) if outside is not None else []
        waiting, eligible = [], []
        for request in ledger.requests.values():
            if request["kind"] != kind or request["state"] != "queued":
                continue
            initiative = ledger.initiatives[request["initiative"]]
            blockers = ledger.unresolved(initiative)
            if initiative["state"] != "active":
                waiting.append({**request_view(request), "reason": "initiative is " + initiative["state"]})
            elif blockers:
                waiting.append({**request_view(request), "reason": "blocked", "blocked_by": blockers})
            else:
                eligible.append(request)
        answer = {"kind": kind, "granted": None, "waiting": waiting[:MAX_VIEW_ROWS]}
        if len(ledger.held(kind)) + len(others) >= ledger.limits[kind]:
            # Full means full: a higher priority request waits, because accepted work is never preempted.
            return 3, {**answer, "reason": "capacity_full", "outside": others[:MAX_VIEW_ROWS],
                       "holders": [request_view(r) for r in ledger.held(kind)][:MAX_VIEW_ROWS]}
        if not eligible:
            return 3, {**answer, "reason": "all_blocked" if waiting else "queue_empty"}
        chosen = min(eligible, key=lambda r: (ledger.initiatives[r["initiative"]]["priority"], r["seq"]))
        store.append(ledger, "grant", {"request_id": chosen["request_id"]})
        return 0, {**answer, "granted": {**request_view(chosen), "granted_at": chosen["granted_at"]},
                   "capacity": capacity_view(ledger)}


def lease_tools():
    """The real Aegis reader and overlap rule, so this check cannot drift from the claim's own."""
    root = str(TOOLS.parent)
    package = TOOLS.parent / "aegis_core"
    error = "the Aegis lease reader is unavailable from this checkout"
    # These helpers are source-checkout tools. An installed wheel or a reader
    # cached by an embedding host must not supply another revision's lease rules.
    require(package.resolve() == package, error)
    for name in ("__init__.py", "match.py", "team.py", "team_paths.py"):
        path = package / name
        require(path.is_file() and path.resolve().is_relative_to(package), error)

    def check_loaded():
        expected = {"aegis_core": package / "__init__.py",
                    "aegis_core.match": package / "match.py", "aegis_core.team": package / "team.py",
                    "aegis_core.team_paths": package / "team_paths.py"}
        for name, module in tuple(sys.modules.items()):
            if name == "aegis_core" or name.startswith("aegis_core."):
                origin = getattr(module, "__file__", None)
                require(origin is not None and Path(origin).resolve().is_relative_to(package), error)
                resolved = Path(origin).resolve()
                require(name not in expected or resolved == expected[name].resolve(), error)
                search = getattr(module, "__path__", None)
                if search is not None:
                    require(tuple(Path(entry).resolve() for entry in search) == (resolved.parent,), error)
        loaded = sys.modules.get("aegis_core")
        for name in ("match", "team", "team_paths"):
            if loaded is not None and hasattr(loaded, name):
                cached = sys.modules.get("aegis_core." + name)
                require(cached is not None and getattr(loaded, name) is cached, error)

    check_loaded()
    sys.path[:] = [root] + [entry for entry in sys.path if entry != root]
    try:
        from aegis_core import match, team, team_paths
    except ImportError as exc:
        raise _Refusal(error, displayed=True) from exc
    check_loaded()
    return match, team, team_paths


@_display_response
def check_paths(ledger, identifier, paths):
    initiative = ledger.initiative(identifier)
    _, team, team_paths = lease_tools()
    try:
        requested = team_paths.claim_paths(paths)
    except team_paths.LeasePathError as exc:
        # The claim parser bounds inputs before normalization and owns these
        # trusted diagnostics, which never echo request values.
        raise _Refusal(str(exc), displayed=True) from exc
    # The public claim also accepts tuples. Display responses expect JSON arrays.
    if isinstance(paths, tuple):
        paths = list(paths)
    return _check_path_overlap(ledger, initiative, paths, requested, team, team_paths)


@_display_response
def check_initiative_paths(ledger, identifier):
    """Inspect a registered declaration with the lease reader's legacy semantics."""
    initiative = ledger.initiative(identifier)
    paths = initiative["touched_paths"]
    _, team, team_paths = lease_tools()
    try:
        requested = team_paths.stored_paths(paths) if paths else team_paths.PathSet((), ())
    except team_paths.LeasePathError:
        # A readable ledger can retain a scope no lease reader can interpret.
        # Inventory it as a conflict; it is not a malformed new request.
        requested = None
    return _check_path_overlap(ledger, initiative, paths, requested, team, team_paths)


def _check_path_overlap(ledger, initiative, paths, requested, team, team_paths):
    identifier = initiative["id"]

    def stored_overlap(scope):
        if not scope or not paths:
            return False  # An undeclared workspace scope reserves no paths.
        if requested is None:
            return True  # An unreadable requested scope cannot prove disjointness.
        try:
            parsed = team_paths.stored_paths(scope)
        except team_paths.LeasePathError:
            # Like an unreadable lease, an unparseable stored scope cannot prove
            # disjointness. Keep legacy declarations/reservations fail-closed.
            return True
        return team_paths.overlap(parsed, requested)

    now = int(time.time())
    peers = [i for i in ledger.initiatives.values()
             if i["repository"] == initiative["repository"] and i["state"] != "done"]
    # Seeing a lease through a checkout proves nothing about who holds it, because linked worktrees
    # share lease refs. A lease is this initiative's own only if its lane is assigned here and it is
    # visible through this initiative's checkout. Everything else conflicts: unsure means conflict.
    assigned = {lane: peer["id"] for peer in peers for lane in peer["lanes"]}
    ordered = ([initiative] + [peer for peer in peers if peer["id"] != identifier]) if paths else []
    visible_here, seen, conflicts, own_overlaps, unreadable_checkouts = set(), set(), [], [], []
    checked = 0
    for peer in ordered:
        for checkout in peer["checkouts"]:
            try:
                found = team.read_leases(Path(checkout))
            except Exception as exc:  # Any failure to read counts as a conflict: unsure means conflict.
                unreadable_checkouts.append({"initiative": peer["id"], "checkout": checkout, "error": str(exc)})
                continue
            checked += 1
            for lease in found.leases:
                key = (lease.lane, lease.oid)
                if peer["id"] == identifier:
                    visible_here.add(key)
                if (key in seen or lease.expired(now)
                        or (requested is not None and not team_paths.overlap(lease.path_set, requested))):
                    continue
                seen.add(key)
                row = {"lane": lease.lane, "paths": list(lease.paths), "owner": lease.owner, "initiative": peer["id"],
                       "assigned_to": assigned.get(lease.lane), "checkout": checkout, "expires_at": lease.expires_at}
                mine = assigned.get(lease.lane) == identifier and key in visible_here
                (own_overlaps if mine else conflicts).append(row)
            for bad in found.unreadable:
                key = (bad.lane, bad.oid)
                if key not in seen:
                    seen.add(key)
                    conflicts.append({"lane": bad.lane, "initiative": peer["id"],
                                      "checkout": checkout, "unreadable": bad.error})
    declared = [peer["id"] for peer in peers if peer["id"] != identifier
                and stored_overlap(peer["touched_paths"])]
    # A lease's expiry or a successor's updated declaration is not terminal evidence for
    # the original capacity claim. Replay pins scope at request time, including old stores.
    reserved = [{"request_id": r["request_id"], "initiative": r["initiative"], "holder": r["holder"],
                 "paths": r["reserved_paths"]} for r in ledger.held("writer")
                if r["initiative"] != identifier and r["reserved_repository"] == initiative["repository"]
                and stored_overlap(r["reserved_paths"])]
    conflict = requested is None or bool(conflicts or unreadable_checkouts or reserved)
    result = {
        "initiative": identifier, "paths": paths, "conflict": conflict, "conflicts": conflicts[:MAX_VIEW_ROWS],
        "reserved_conflicts": reserved[:MAX_VIEW_ROWS],
        "unreadable_checkouts": unreadable_checkouts[:MAX_VIEW_ROWS], "own_overlaps": own_overlaps[:MAX_VIEW_ROWS],
        "declared_overlaps": declared, "checked_checkouts": checked,
        "note": "A clear result is advice, not a lock: run the check and the lease claim one after another."}
    if requested is None:
        result["reason"] = "stored_paths_unreadable"
    return (3 if conflict else 0), result


@_display_response
def check_delivery(ledger, identifier):
    initiative = ledger.initiative(identifier)
    blockers = ledger.unresolved(initiative)
    ready = initiative["state"] == "active" and not blockers and initiative["base_moved"] is None
    return (0 if ready else 3), {"initiative": identifier, "ready": ready, "state": initiative["state"],
                                 "blocked_by": blockers, "base_moved": initiative["base_moved"]}


def mailbox_facts(initiative):
    if "mailbox_root" not in initiative:
        return None
    try:
        mailbox = Mailbox(initiative["mailbox_root"])
        status = mailbox.status()
        facts = {"messages": status["messages"], "open_job_requests": len(status["open_job_requests"]),
                 "accepted_writers": len(status["accepted_writers"])}
        if "delivery_dir" in initiative:
            summary = mailbox.delivery(initiative["delivery_dir"])["endpoints"]
            facts["unread"] = sum(row["unread_count"] for row in summary.values())
        return facts
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        return {"error": _display(exc)}


def queue_facts(ledger, now):
    """Lifetime facts, with busy time summed in slot-seconds (including open grants).

    An invalid, future or reversed timestamp makes that request's timing unknown;
    its state still counts. Missing samples are null, not a claim of zero latency.
    The report clock is shared by all rows and never written back to the ledger.
    """
    current = parse_time(now)
    result = {}
    for kind in KINDS:
        rows = [r for r in ledger.requests.values() if r["kind"] == kind]
        waits, ages, busy = [], [], []
        unknown = 0
        for row in rows:
            try:
                requested = parse_time(row["requested_at"])
                granted = parse_time(row["granted_at"]) if "granted_at" in row else None
                closed = parse_time(row["closed_at"]) if "closed_at" in row else None
                points = [requested] + ([granted] if granted is not None else [])
                points += ([closed] if closed is not None else []) + [current]
                require(points == sorted(points), "invalid request timing")
                require(row["state"] not in ("granted", "released") or granted is not None,
                        "missing grant timing")
                require(row["state"] not in ("released", "withdrawn") or closed is not None,
                        "missing closure timing")
            except (ValueError, TypeError, KeyError, OverflowError):
                unknown += 1
                continue
            if row["state"] == "queued":
                ages.append((current - requested).total_seconds())
            if granted is not None:
                waits.append((granted - requested).total_seconds())
                busy.append(((closed if closed is not None else current) - granted).total_seconds())
        result[kind] = {
            "queued": sum(r["state"] == "queued" for r in rows),
            "open": sum(r["state"] in ("queued", "granted") for r in rows),
            "oldest_queued_seconds": max(ages) if ages else None,
            "queue_wait_seconds": {"count": len(waits), "p50": median(waits) if waits else None,
                                   "max": max(waits) if waits else None},
            "busy_seconds": sum(busy) if busy else None,
            "withdrawn_count": sum(r["state"] == "withdrawn" for r in rows),
            "superseded_count": sum("superseded_by" in r for r in rows),
            "timing_unknown": unknown}
    return result


def report(ledger):
    """One view across all initiatives, built by this script. It is a listing, not a judgment."""
    ordered = sorted(ledger.initiatives.values(), key=lambda i: (i["priority"], i["id"]))
    rows = [{**initiative_view(ledger, i["id"]), "mailbox": mailbox_facts(i)} for i in ordered]
    now = timestamp()
    return {"generated_by": "script", "generated_at": now, "capacity": capacity_view(ledger), "initiatives": rows,
            "queue_facts": queue_facts(ledger, now)}


def report_text(data):
    capacity = data["capacity"]
    lines = ["Workspace status, generated by script at " + data["generated_at"],
             "Writers %d/%d, heavy jobs %d/%d, Heavy-Tests %d/%d, queued %d" % (
                 capacity["writer"]["used"], capacity["writer"]["limit"], capacity["heavy"]["used"],
                 capacity["heavy"]["limit"], capacity["heavy-tests"]["used"], capacity["heavy-tests"]["limit"],
                 len(capacity["queue"])), ""]
    for row in data["initiatives"]:
        notes = []
        if row["blocked_by"]:
            notes.append("blocked by " + ", ".join(row["blocked_by"]))
        if row["base_moved"]:
            notes.append("base moved to " + row["base_moved"]["commit"][:12])
        mailbox = row["mailbox"]
        if mailbox is not None:
            notes.append("mailbox error" if "error" in mailbox else "unread " + str(mailbox.get("unread", "not tracked")))
        lines.append("%4d  %-24s %-10s %-7s writers %d heavy %d heavy-tests %d queued %d  %s" % (
            row["priority"], row["id"], row["project"], row["state"], row["holds"]["writer"], row["holds"]["heavy"],
            row["holds"]["heavy-tests"], sum(row["queued"].values()), "; ".join(notes)))
    if "queue_facts" in data:
        for kind in KINDS:
            lines.append(kind + " queue facts: " + json.dumps(data["queue_facts"][kind], sort_keys=True))
    return "\n".join(lines)


@_display_refusals
def run(args):
    store = Store(args.store)
    command = args.command
    if command == "init":
        request = read_json(args.request)
        require(not store.path.exists(), "workspace store already exists")
        ledger = Ledger()
        event = {"schema": EVENT_SCHEMA, "seq": 1, "at": timestamp(), "kind": "init", "data": request}
        ledger.apply(event)
        store.events.mkdir(parents=True, mode=0o700)
        publish_file(store.events / "00000001.json", encoded(event) + b"\n")
        return 0, {"store": str(store.path), "limits": ledger.limits}
    if command == "grant-next":
        return grant_next(store, args.kind)
    if command in {"status", "report", "check-delivery", "check-paths"}:
        ledger = store.load(for_report=True) if command == "report" else store.load()
        if command == "status":
            return 0, {"capacity": capacity_view(ledger), "initiatives": ledger.initiatives, "seq": ledger.seq}
        if command == "report":
            data = report(ledger)
            return 0, report_text(data) if args.format == "text" else data
        if command == "check-delivery":
            return check_delivery(ledger, args.initiative)
        request = read_json(args.request)
        fields(request, {"initiative", "paths"})
        return check_paths(ledger, request["initiative"], request["paths"])
    request = read_json(args.request)
    with store.lock():
        ledger = store.load()
        if command == "register":
            store.append(ledger, "register", request)
            return 0, {"initiative": ledger.initiatives[request["id"]]}
        if command == "update":
            store.append(ledger, "update", request)
            return 0, {"initiative": ledger.initiatives[request["initiative"]]}
        if command == "request":
            event = store.append(ledger, "request", {**request, "request_id": "req-%08d" % (ledger.seq + 1)})
            return 0, {"request": request_view(ledger.requests[event["data"]["request_id"]])}
        if command == "withdraw":
            store.append(ledger, "withdraw", request)
            return 0, {"request": request_view(ledger.requests[request["request_id"]])}
        if command == "release":
            fields(request, {"request_id", "evidence"})
            verify_evidence(request["evidence"])
            store.append(ledger, "release", request)
            return 0, {"request": request_view(ledger.requests[request["request_id"]]), "capacity": capacity_view(ledger)}
        if command == "mark-merge":
            before = {i["id"]: i["base_moved"] for i in ledger.initiatives.values()}
            store.append(ledger, "merge", request)
            marked = [i["id"] for i in ledger.initiatives.values() if i["base_moved"] != before[i["id"]]]
            return 0, {"marked": marked}
        if command == "set-limits":
            store.append(ledger, "set_limits", request)
            return 0, {"limits": ledger.limits, "capacity": capacity_view(ledger)}
        fields(request, {"initiative", "base_commit", "evidence", "source"})
        verify_evidence(request["evidence"])
        store.append(ledger, "clear_base_moved", request)
        return 0, {"initiative": ledger.initiatives[request["initiative"]]}


def main(argv=None):
    parser = _ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", required=True, help="Absolute path to the workspace store")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "register", "update", "request", "withdraw", "release", "check-paths", "mark-merge",
                 "clear-base-moved", "set-limits"):
        commands.add_parser(name).add_argument("--request", required=True, help="Absolute path to a strict JSON request")
    commands.add_parser("grant-next").add_argument("--kind", required=True)
    commands.add_parser("status")
    commands.add_parser("check-delivery").add_argument("--initiative", required=True)
    commands.add_parser("report").add_argument("--format", choices=("json", "text"), default="json")
    try:
        args = parser.parse_args(argv)
        code, result = run(args)
    except _Refusal as exc:
        code, result = 2, {"error": exc.message}
    except Exception:
        code, result = 2, {"error": "WORKSPACE_REFUSED",
                           "next_action": "inspect the workspace inputs and retry"}
    print(result if isinstance(result, str) else json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
