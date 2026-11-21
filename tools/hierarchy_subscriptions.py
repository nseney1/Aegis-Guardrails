#!/usr/bin/env python3
"""Model-free, reference-only mailbox subscriptions; no authority or host calls."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

if __package__:
    from . import hierarchy_mailbox as hm
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import hierarchy_mailbox as hm

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aegis_core.primitives import json_preflight, sanitize_display
from aegis_core.redaction import redact_insight_text
from aegis_core.errors import LockTimeoutError
from aegis_core.storage import ConfinedFileError, confined_file, file_lock

SCHEMA = "aegis.team-subscriptions/v1"
STATE = "aegis.subscription-cursor/v1"
NOTICE = "aegis.subscription-notice/v1"
BODY = ("Notice from the notify step: these messages matched your subscription. "
        "This grants no approval, lease or instruction. Read them through your own mailbox access.")
MAX_CONFIG = 262144
MAX_STATE = 4 * 1024 * 1024
MAX_BATCH = 50
MAX_ENTRIES = 256
MAX_FILTERS = 64
MAX_BUDGET = 3600
REFUSALS = {
    "INVALID": "invalid subscriptions configuration",
    "STATE": "invalid subscription cursor",
    "LIMIT": "subscription size limit exceeded",
    "IO": "subscription I/O refused",
    "MAILBOX": "subscription mailbox refused",
    "MAILBOX_LOCKED": "mailbox write lock requires operator inspection",
    "DURABILITY": "subscription notice durability flush failed",
    "BUSY": "subscription writer busy",
    "UNSUPPORTED": "subscription descriptor operations unavailable",
    "PATH": "invalid subscription path",
    "CLOCK": "invalid subscription clock",
}


class SubscriptionError(ValueError):
    """Fixed refusal code and diagnostic; never echoes OS or model input."""
    def __init__(self, reason, entry=None):
        self.code = "SUBSCRIPTIONS_" + reason
        super().__init__(REFUSALS[reason] if entry is None else "invalid subscription entry " + str(entry))


class MailboxLockHold(SubscriptionError):
    """HM owns the lock; a live or abandoned holder requires operator inspection."""
    recovery = "Confirm no live mailbox writer, then manually remove only this root's .write.lock and retry notify."

    def __init__(self, root):
        super().__init__("MAILBOX_LOCKED")
        self.lock_path = root / ".write.lock"


def supported():
    """Fail closed where descriptor confinement and crash-safe locking are unavailable."""
    names = {function.__name__ for function in os.supports_dir_fd}
    return (os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW")
            and {"open", "stat", "rename", "link", "unlink"} <= names)


def _path(value):
    spelling = str(value) if isinstance(value, Path) else value
    if type(spelling) is not str or not 1 <= len(spelling) <= 32768 or "\x00" in spelling:
        raise SubscriptionError("PATH")
    path = Path(spelling)
    if not path.is_absolute() or ".." in path.parts:
        raise SubscriptionError("PATH")
    return path


@contextmanager
def _directory(path):
    """Anchor at the filesystem root and retain each opened directory through traversal."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            previous, fd = fd, child
            os.close(previous)
        yield fd
    finally:
        os.close(fd)


def _read(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SubscriptionError("IO")
        if info.st_size > limit:
            raise SubscriptionError("LIMIT")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
        raise SubscriptionError("LIMIT")
    finally:
        os.close(fd)


def _write(directory, state_path, name, raw, *, replace=True):
    if len(raw) > MAX_STATE:
        raise SubscriptionError("LIMIT")
    try:
        with confined_file(state_path, (name,)) as target:
            expected, actual = os.fstat(directory), target.parent_stat()
            if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
                raise SubscriptionError("PATH")
            try:
                target.publish_bytes(raw, replace=replace)
            except ConfinedFileError as error:
                if replace or error.reason != "exists":
                    raise
                if target.read_bytes(MAX_STATE) != raw:
                    raise SubscriptionError("STATE") from None
    except ConfinedFileError as error:
        raise SubscriptionError("LIMIT" if error.reason == "too_large" else "IO") from None


@contextmanager
def _locked(directory):
    try:
        with file_lock(Path(".subscriptions.lock"), timeout=0, dir_fd=directory):
            yield
    except LockTimeoutError:
        raise SubscriptionError("BUSY") from None


@contextmanager
def _mailbox_writer(root):
    entered = False
    try:
        with hm.writer_lock(root):
            entered = True
            yield
    except ValueError as error:
        if not entered and isinstance(error.__cause__, FileExistsError):
            raise MailboxLockHold(root) from None
        raise


def _placed_mailbox(root, state_path, mailbox=None):
    if mailbox is None:
        try:
            mailbox = hm.Mailbox(root)
        except ValueError:
            raise SubscriptionError("MAILBOX") from None
    elif Path(mailbox.root) != Path(root):
        raise SubscriptionError("MAILBOX")
    try:
        mailbox.outside_mailbox(state_path, "subscription state directory")
    except ValueError:
        raise SubscriptionError("PATH") from None
    return mailbox


def _json(raw, reason):
    try:
        text = json_preflight(raw, max_bytes=MAX_STATE if reason == "STATE" else MAX_CONFIG,
                              max_depth=16, max_nodes=200000, max_items=hm.MAX_RECORDS,
                              max_string=32768, max_atom=32)
        return hm.strict_json(text)
    except (ValueError, UnicodeError, RecursionError):
        raise SubscriptionError(reason) from None


def _encoded(value, limit=MAX_STATE):
    """Cap serialized output before allocating its complete representation."""
    chunks, size = [], 0
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    for chunk in encoder.iterencode(value):
        size += len(chunk)
        if size > limit:
            raise SubscriptionError("LIMIT")
        chunks.append(chunk.encode("ascii"))
    return b"".join(chunks)


def _fields(value, required, optional=()):
    if type(value) is not dict or len(value) > len(required) + len(optional):
        raise ValueError()
    if not set(required) <= value.keys() <= set(required) | set(optional):
        raise ValueError()


def _endpoint(value, endpoints):
    if type(value) is not str or not 1 <= len(value) <= 200:
        raise ValueError()
    parts = hm.endpoint_parts(value)
    if value not in endpoints:
        raise ValueError()
    return parts


def _allowed(subscriber, endpoint):
    if subscriber == endpoint:
        return True
    left, right = hm.endpoint_parts(subscriber), hm.endpoint_parts(endpoint)
    return left[0] == right[0] and any({left[1], right[1]} == set(pair) for pair in hm.VERTICAL_ROUTES)


def _pattern(value, endpoints):
    if type(value) is not str or not 1 <= len(value) <= 200:
        raise ValueError()
    if "*" not in value:
        _endpoint(value, endpoints)
        return [value]
    parts = value.split("/")
    if len(parts) != 3 or parts[2] != "*" or parts[1] != "lane":
        raise ValueError()
    hm.matching(parts[0], hm.SLUG, "team")
    matched = [endpoint for endpoint in endpoints if endpoint.startswith(value[:-1])]
    if not matched:
        raise ValueError()
    return matched


def validate(configuration, mailbox):
    """Validate the entire configuration before any publication; return normalized entries."""
    try:
        _fields(configuration, {"schema", "subscriptions"})
        if configuration["schema"] != SCHEMA:
            raise ValueError()
        entries = configuration["subscriptions"]
        if type(entries) is not list or len(entries) > MAX_ENTRIES:
            raise ValueError()
    except (ValueError, TypeError):
        raise SubscriptionError("INVALID") from None
    subscribers, result = set(), []
    endpoints = mailbox.manifest["endpoints"]
    for number, entry in enumerate(entries):
        try:
            _fields(entry, {"subscriber", "match"}, {"budget", "batch_size"})
            subscriber = entry["subscriber"]
            parts = _endpoint(subscriber, endpoints)
            if parts[1] not in {"orchestrator", "root"} or subscriber in subscribers:
                raise ValueError()
            mailbox.route(parts[0] + "/router", subscriber)
            filters = entry["match"]
            if type(filters) is not list or not 1 <= len(filters) <= MAX_FILTERS:
                raise ValueError()
            for filter_ in filters:
                _fields(filter_, set(), {"type", "from", "to", "in_reply_to_type"})
                for key, value in filter_.items():
                    if key in {"type", "in_reply_to_type"}:
                        if type(value) is not str or value not in hm.MESSAGE_TYPES:
                            raise ValueError()
                    elif any(not _allowed(subscriber, endpoint) for endpoint in _pattern(value, endpoints)):
                        raise ValueError()
            budget = entry.get("budget", {"notices_per_hour": 6})
            _fields(budget, {"notices_per_hour"})
            notices = budget["notices_per_hour"]
            if type(notices) is not int or not 1 <= notices <= MAX_BUDGET:
                raise ValueError()
            batch_size = entry.get("batch_size", MAX_BATCH)
            if type(batch_size) is not int or not 1 <= batch_size <= MAX_BATCH:
                raise ValueError()
            result.append({"subscriber": subscriber, "match": filters, "budget": {"notices_per_hour": notices},
                           "batch_size": batch_size})
            subscribers.add(subscriber)
        except (ValueError, TypeError, KeyError):
            raise SubscriptionError("INVALID", number) from None
    return result


def matches(entry, message, records):
    """Envelope-only OR matching; authorize both ends even with broad/type-only filters."""
    subscriber = entry["subscriber"]
    if (message["message_id"].startswith("notice-") or message["from"] == subscriber
            or not all(_allowed(subscriber, message[key]) for key in ("from", "to"))):
        return False
    for filter_ in entry["match"]:
        if message["type"] in {"ack", "job_receipt"} and filter_.get("type") != message["type"]:
            continue
        matched = True
        for key, value in filter_.items():
            if key == "in_reply_to_type":
                original = records.get(message.get("in_reply_to"), {}).get("message", {})
                matched &= original.get("type") == value
            elif key in {"from", "to"} and value.endswith("/*"):
                matched &= message[key].startswith(value[:-1])
            else:
                matched &= message.get(key) == value
        if matched:
            return True
    return False


def notice_id(subscriber, hashes):
    """Unambiguous canonical encoding of the subscriber and sorted matched record hashes."""
    return "notice-" + hm.digest([subscriber, sorted(hashes)])


def _record_bytes(mailbox, record):
    """Read one record by descriptor. The size limit is applied before the body is kept."""
    path = _path(record["path"])
    try:
        relative = path.relative_to(mailbox.root)
    except ValueError:
        raise SubscriptionError("MAILBOX") from None
    with _directory(mailbox.root / relative.parent) as directory:
        return _read(directory, relative.name, hm.MAX_BYTES)


def _reference_from_verified(record, digest):
    """Build a reference from an envelope the caller already verified.

    The digest is that caller's hash of the verified bytes. This does not parse.
    """
    message = record["message"]
    reference = {key: message[key] for key in ("message_id", "type", "from", "to")}
    reference["sha256"] = digest
    if message["type"] in {"brief", "dispatch"}:
        reference["brief"] = message["brief"]
    return reference


def _reference(mailbox, record, raw=None):
    """Verify, then build. Callers that have not verified keep this path."""
    if raw is None:
        raw = _record_bytes(mailbox, record)
    _verify_record(raw, record)
    return _reference_from_verified(record, hashlib.sha256(raw).hexdigest())


def _verify_record(raw, record):
    # Bind the hash to the same validated envelope returned by the mailbox.
    try:
        header, body = raw[4:].decode("utf-8").split("\n---\n\n", 1)
        parsed = _json(header, "MAILBOX")
        parsed["body"] = body
        if not raw.startswith(b"---\n") or parsed != record["message"]:
            raise ValueError()
        if "sha256" in record and hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SubscriptionError("MAILBOX") from None


def _flush_notice(mailbox, record):
    """Confirm and flush the actual routing directory before saving completion."""
    path = _path(record["path"])
    expected = mailbox.route(record["message"]["from"], record["message"]["to"])
    if path.parent != expected:
        raise SubscriptionError("STATE")
    with _directory(expected) as directory:
        _verify_record(_read(directory, path.name, hm.MAX_BYTES), record)
        try:
            os.fsync(directory)
        except OSError:
            raise SubscriptionError("DURABILITY") from None


def _sha(value):
    return type(value) is str and len(value) == 64 and hm.SHA256.fullmatch(value) is not None


def _count(value):
    return type(value) is int and 0 <= value <= hm.MAX_RECORDS


def _clock(value):
    return type(value) in (int, float) and 0 <= value <= 253402300799 and math.isfinite(value)


def _reference_fields(ref, subscriber):
    _fields(ref, {"message_id", "type", "from", "to", "sha256"}, {"brief"})
    hm.matching(ref["message_id"], hm.SLUG, "message_id")
    if not _sha(ref["sha256"]):
        raise ValueError()
    if type(ref["type"]) is not str or ref["type"] not in hm.MESSAGE_TYPES:
        raise ValueError()
    if ref["message_id"].startswith("notice-") or ref["from"] == subscriber:
        raise ValueError()
    if not all(_allowed(subscriber, ref[key]) for key in ("from", "to")):
        raise ValueError()
    if "brief" in ref:
        _fields(ref["brief"], {"path", "sha256"})
        _path(ref["brief"]["path"])
        if not _sha(ref["brief"]["sha256"]):
            raise ValueError()


def _pending(value, subscriber, backlog):
    _fields(value, {"hashes", "references", "held_count", "previously_held", "message_id"})
    hashes, refs = value["hashes"], value["references"]
    if (type(hashes) is not list or not 1 <= len(hashes) <= hm.MAX_RECORDS or not all(_sha(h) for h in hashes)
            or hashes != sorted(set(hashes)) or value["message_id"] != notice_id(subscriber, hashes)
            or type(refs) is not list or not 1 <= len(refs) <= MAX_BATCH
            or not all(_count(value[key]) for key in ("held_count", "previously_held"))):
        raise ValueError()
    for ref in refs:
        _reference_fields(ref, subscriber)
        if ref != backlog.get(ref["sha256"]):
            raise ValueError()
    if len({ref["sha256"] for ref in refs}) != len(refs) or value["held_count"] != len(hashes) - len(refs):
        raise ValueError()
    if hashes != sorted(backlog):
        raise ValueError()


def _load_cursor(directory, name, subscriber, identity):
    try:
        raw = _read(directory, name, MAX_STATE)
    except FileNotFoundError:
        return {"schema": STATE, "subscriber": subscriber, "identity": identity,
                "seen": [], "sent": [], "held": 0, "backlog": [], "pending": None}
    value = _json(raw, "STATE")
    try:
        _fields(value, {"schema", "subscriber", "identity", "seen", "sent", "held", "backlog", "pending"})
        if value["schema"] != STATE or value["subscriber"] != subscriber or value["identity"] != identity:
            raise ValueError()
        seen, sent = value["seen"], value["sent"]
        if (type(seen) is not list or len(seen) > hm.MAX_RECORDS or not all(_sha(h) for h in seen)
                or seen != sorted(set(seen)) or type(sent) is not list or len(sent) > MAX_BUDGET
                or not all(_clock(at) for at in sent) or sent != sorted(sent) or not _count(value["held"])):
            raise ValueError()
        backlog = value["backlog"]
        if type(backlog) is not list or len(backlog) > hm.MAX_RECORDS:
            raise ValueError()
        for ref in backlog:
            _reference_fields(ref, subscriber)
        by_hash = {ref["sha256"]: ref for ref in backlog}
        if len(by_hash) != len(backlog) or set(by_hash) & set(seen) or value["held"] > len(backlog):
            raise ValueError()
        if value["pending"] is not None:
            _pending(value["pending"], subscriber, by_hash)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise SubscriptionError("STATE") from None
    return value


def save_cursor(directory, state_path, name, cursor):
    """Durably save after publish; the durable pending plan precedes publication."""
    _write(directory, state_path, name, _encoded(cursor))


def publish_notice(mailbox, request):
    """Borrow only the existing router binding and pinned publication API."""
    return mailbox.publish(request)


def _packet(pending):
    value = {"schema": NOTICE, "references": pending["references"],
             "held_count": pending["held_count"], "previously_held": pending["previously_held"]}
    return _encoded(value, hm.MAX_BYTES - 1) + b"\n"


def _finish(mailbox, records, directory, state_path, name, cursor, now):
    pending, subscriber = cursor["pending"], cursor["subscriber"]
    identifier = pending["message_id"]
    seen = set(cursor["seen"])
    new_hashes = {ref["sha256"] for ref in pending["references"]} - seen
    if len(seen) + len(new_hashes) > hm.MAX_RECORDS:
        raise SubscriptionError("LIMIT")
    raw = _packet(pending)
    packet_name = identifier + ".md"
    _write(directory, state_path, packet_name, raw, replace=False)
    brief = {"path": str(state_path / packet_name), "sha256": hashlib.sha256(raw).hexdigest()}
    prior = records.get(identifier)
    expected = {"from": subscriber.split("/")[0] + "/router", "to": subscriber,
                "type": "info", "body": BODY, "brief": brief}
    if prior is not None:
        if any(prior["message"].get(key) != value for key, value in expected.items()):
            raise SubscriptionError("STATE")
    else:
        binding = mailbox.current_binding(expected["from"])
        published = publish_notice(mailbox, {"message_id": identifier, "host": binding["host"], "session": binding["session"],
                                            "binding_generation": binding["generation"], **expected})
    _flush_notice(mailbox, prior if prior is not None else published)
    cursor["seen"] = sorted(seen | new_hashes)
    cursor["sent"].append(now)
    sent_hashes = {ref["sha256"] for ref in pending["references"]}
    cursor["backlog"] = [ref for ref in cursor["backlog"] if ref["sha256"] not in sent_hashes]
    cursor["held"] = pending["held_count"]
    cursor["pending"] = None
    save_cursor(directory, state_path, name, cursor)
    return prior is not None, len(pending["references"]), pending["held_count"]


def _subscriber(mailbox, records, directory, state_path, entry, now):
    subscriber = entry["subscriber"]
    identity = hm.digest(str(mailbox.root))
    name = hm.digest([identity, subscriber]) + ".json"
    cursor = _load_cursor(directory, name, subscriber, identity)
    if cursor["sent"] and now < cursor["sent"][-1]:
        raise SubscriptionError("CLOCK")
    cursor["sent"] = [at for at in cursor["sent"] if now - at < 3600]
    if cursor["pending"] is not None:
        if (cursor["pending"]["message_id"] not in records
                and len(cursor["sent"]) >= entry["budget"]["notices_per_hour"]):
            return {"published": 0, "recovered": 0, "matched": 0,
                    "held": len(cursor["backlog"]), "suppressed": "budget"}
        recovered, count, held = _finish(mailbox, records, directory, state_path, name, cursor, now)
        return {"published": int(not recovered), "recovered": int(recovered), "matched": count, "held": held}
    candidates = {ref["sha256"]: ref for ref in cursor["backlog"]}
    seen = set(cursor["seen"])
    for record in records.values():
        if matches(entry, record["message"], records):
            # Bind the re-read bytes to the envelope before the seen check.
            # A file replaced with an older seen body must refuse, not disappear.
            # Only the reference build is skipped, and it uses this digest.
            raw = _record_bytes(mailbox, record)
            _verify_record(raw, record)
            digest = hashlib.sha256(raw).hexdigest()
            if digest not in seen:
                candidates[digest] = _reference_from_verified(record, digest)
    if len(candidates) > hm.MAX_RECORDS:
        raise SubscriptionError("LIMIT")
    candidates = [candidates[key] for key in sorted(candidates)]
    cursor["backlog"] = candidates
    if not candidates:
        return {"published": 0, "recovered": 0, "matched": 0, "held": 0}
    if len(cursor["sent"]) >= entry["budget"]["notices_per_hour"]:
        cursor["held"] = len(candidates)
        save_cursor(directory, state_path, name, cursor)  # No cursor advancement: every match remains eligible.
        return {"published": 0, "recovered": 0, "matched": 0, "held": len(candidates), "suppressed": "budget"}
    hashes = sorted(ref["sha256"] for ref in candidates)
    batch_size = entry["batch_size"]
    cursor["pending"] = {"hashes": hashes, "references": candidates[:batch_size],
                         "held_count": max(0, len(candidates) - batch_size), "previously_held": cursor["held"],
                         "message_id": notice_id(subscriber, hashes)}
    _packet(cursor["pending"])  # Refuse an oversized packet before freezing a retry plan.
    _write(directory, state_path, name, _encoded(cursor))  # Durable intent; seen/sent remain unchanged.
    recovered, count, held = _finish(mailbox, records, directory, state_path, name, cursor, now)
    return {"published": int(not recovered), "recovered": int(recovered), "matched": count, "held": held}


def _display(value):
    return redact_insight_text(sanitize_display(value, max_len=None), max_len=8192)[:400]


def notify(root, state_dir, subscriptions, *, now=None, mailbox=None):
    """Run one pass. State is owner-controlled and within the mailbox parent for HM briefs.

    The state lock serializes all subscribers in this state directory; HM's writer
    lock additionally serializes against all other mailbox publishers. Exceptions
    release HM's lock; abrupt termination needs confirmed operator lock recovery
    before a pass can reconcile pending work. Notify never breaks HM's lock.
    """
    if not supported():
        raise SubscriptionError("UNSUPPORTED")
    if now is None:
        now = time.time()
    if not _clock(now):
        raise SubscriptionError("CLOCK")
    root, state_path, source = _path(root), _path(state_dir), _path(subscriptions)
    try:
        state_path.relative_to(root.parent)
    except ValueError:
        raise SubscriptionError("PATH") from None
    try:
        mailbox = _placed_mailbox(root, state_path, mailbox)
        with _directory(source.parent) as parent:
            config_raw = _read(parent, source.name, MAX_CONFIG)
            configuration = _json(config_raw, "INVALID")
        with _directory(state_path) as directory, _locked(directory):
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise SubscriptionError("IO")
            try:
                with _mailbox_writer(root):
                    entries = validate(configuration, mailbox)
                    records = mailbox.messages()
                    summary = {"schema": "aegis.subscriptions-status/v1", "configuration_sha256": hashlib.sha256(config_raw).hexdigest(),
                               "published": 0, "recovered": 0, "matched": 0, "held": 0, "subscription_suppressed": []}
                    for entry in entries:
                        result = _subscriber(mailbox, records, directory, state_path, entry, now)
                        for key in ("published", "recovered", "matched", "held"):
                            summary[key] += result[key]
                        if result.get("suppressed"):
                            summary["subscription_suppressed"].append({"subscriber": _display(entry["subscriber"]),
                                                                      "reason": result["suppressed"], "held": result["held"]})
                    return summary
            except SubscriptionError:
                raise
            except ValueError:
                raise SubscriptionError("MAILBOX") from None
    except SubscriptionError:
        raise
    except (OSError, UnicodeError):
        raise SubscriptionError("IO") from None
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise SubscriptionError("STATE") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SubscriptionError("INVALID")


def main(argv=None):
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    command = commands.add_parser("notify")
    for flag in ("--root", "--state-dir", "--subscriptions"):
        command.add_argument(flag, required=True)
    try:
        args = parser.parse_args(argv)
        result = notify(args.root, args.state_dir, args.subscriptions)
    except SubscriptionError as error:
        result = {"code": error.code, "error": str(error)}
        if isinstance(error, MailboxLockHold):
            result.update(hold=True, lock_path=_display(str(error.lock_path)), recovery=error.recovery)
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
