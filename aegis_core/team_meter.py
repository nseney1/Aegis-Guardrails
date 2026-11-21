"""Read-only active time from descriptor-confined host transcripts.

The host registry supplies discovery and home policy. A discovered pathname is
never reopening authority: every component is opened without following links,
from the trusted home, with held parents across concurrent rename/replacement.
Files: 128 MiB; decoded UTF-8 lines: 262144 bytes, 10000 records; JSON depth: 128,
nodes/items per line: 10000. Limits precede parsing and include blank/bad lines.
Legacy in-bound records, malformed counts, turn accounting and missing discovery
retain their successful values. Operational failures have fixed typed envelopes.
An injected home is trusted caller policy; None resolves the registry home at each call.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import errno
from functools import wraps
import json
import os
from pathlib import Path
import stat

from aegis_core import team_host_registry as hosts
from aegis_core.primitives import json_preflight
from aegis_core.storage import confined_descriptor_supported as descriptor_supported
from aegis_core.team_host_plan import absolute_path

__all__ = ["MeterRefusal", "find_transcript", "measure", "descriptor_supported", "MAX_LINE_BYTES",
           "MAX_TRANSCRIPT_BYTES", "MAX_RECORDS", "SESSION_LIMIT_SECONDS", "ROOT_LIMIT_SECONDS", "WARN_FRACTION"]

SESSION_LIMIT_SECONDS = 3600
ROOT_LIMIT_SECONDS = 5400
WARN_FRACTION = 0.8
MAX_TRANSCRIPT_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = hosts.MAX_EVENT_BYTES
MAX_RECORDS = hosts.MAX_EVENTS_PER_STREAM
_NEXT = {
    "unknown_host": "Choose a declared transcript-capable host kind.",
    "invalid_session": "Supply a bounded session identifier without glob characters.",
    "invalid_limit": "Supply an integer active-time limit between 1 and 86400 seconds.",
    "unsafe_path": "Choose a regular transcript below the trusted absolute host home, without symlinks.",
    "unsupported_platform": "Use descriptor-relative no-follow filesystem support.",
    "transcript_unavailable": "Restore the local transcript and retry the read.",
    "transcript_limit": "Reduce the transcript to the documented byte, record and JSON limits.",
    "invalid_timestamp": "Use consistently timezone-aware or consistently naive turn timestamps.",
    "invalid_record": "Use scalar event kind values in transcript records.",
}


class MeterRefusal(ValueError):
    """Fixed refusal, numeric code 1; no path, record or OS diagnostic is echoed."""
    def __init__(self, reason):
        self.reason, self.code, self.status = reason, 1, "refused"
        self.next_action = _NEXT[reason]
        super().__init__("meter refused: " + reason)

    def as_dict(self):
        return {"status": self.status, "reason": self.reason, "code": self.code, "next_action": self.next_action}


def _require(condition, reason):
    if not condition:
        raise MeterRefusal(reason)


def _guarded(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MeterRefusal:
            raise
        except hosts.HostRefusal as error:
            reason = {"unsupported_platform": "unsupported_platform", "unsafe_path": "unsafe_path",
                      "too_large": "transcript_limit"}.get(error.reason, "transcript_unavailable")
            raise MeterRefusal(reason) from None
        except OSError as error:
            reason = "unsafe_path" if error.errno in (errno.ELOOP, errno.ENOTDIR) else "transcript_unavailable"
            raise MeterRefusal(reason) from None
        except (ValueError, OverflowError, RecursionError):
            raise MeterRefusal("invalid_timestamp") from None
        except RuntimeError:
            raise MeterRefusal("transcript_unavailable") from None
    return call


def _valid_session(session):
    return type(session) is str and len(session) <= 128 and hosts.SESSION.fullmatch(session) is not None


def _valid_host(host):
    return type(host) is str and host in hosts.HOST_KINDS and hosts.family(host) in ("codex", "claude")


def _home(host):
    spec = hosts.entry(host)["home"]
    return absolute_path(os.environ.get(spec["variable"]) or Path.home() / spec["owner_folder"], limit=4096)


@contextmanager
def _opened(home, path):
    home, path = absolute_path(home, limit=4096), absolute_path(path, limit=4096)
    _require(descriptor_supported(), "unsupported_platform")
    _require(len(path.parts) <= 128, "unsafe_path")
    for part in path.parts[1:]:
        _require(len(part) <= 255 and not any(0xD800 <= ord(char) <= 0xDFFF for char in part), "unsafe_path")
        _require(len(part.encode("utf-8")) <= 255, "unsafe_path")
    try:
        relative = path.relative_to(home)
    except ValueError:
        raise MeterRefusal("unsafe_path") from None
    _require(bool(relative.parts), "unsafe_path")
    parent = os.open(home.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        for part in (*home.parts[1:], *relative.parts[:-1]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                            getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
            old, parent = parent, child
            os.close(old)
        fd = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        try:
            _require(stat.S_ISREG(os.fstat(fd).st_mode), "unsafe_path")
            yield fd
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _moment(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _line_size(text):
    """Check UTF-8 replacement-decoded bytes without an encoded allocation."""
    _require(len(text) <= MAX_LINE_BYTES, "transcript_limit")
    size = 0
    for char in text:
        code = ord(char)
        size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
        _require(size <= MAX_LINE_BYTES, "transcript_limit")
    return size


def _read_records(home, path):
    records, malformed, total, count = [], 0, 0, 0
    with _opened(home, path) as fd:
        _require(os.fstat(fd).st_size <= MAX_TRANSCRIPT_BYTES, "transcript_limit")
        # The enclosing descriptor context owns fd even if fdopen raises.
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace", newline=None, closefd=False) as stream:
            while True:
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                total, count = total + _line_size(line), count + 1
                _require(total <= MAX_TRANSCRIPT_BYTES and count <= MAX_RECORDS,
                         "transcript_limit")
                if not line.strip():
                    continue
                text = line
                try:
                    json_preflight(text, max_bytes=MAX_LINE_BYTES, max_depth=128,
                                   max_nodes=10000, max_items=10000, max_string=MAX_LINE_BYTES, max_atom=128)
                except ValueError as error:
                    if str(error) in ("size", "nesting", "nodes", "container", "string", "atom"):
                        raise MeterRefusal("transcript_limit") from None
                    malformed += 1
                    continue
                try:
                    record = json.loads(text)
                except ValueError:
                    malformed += 1
                    continue
                if isinstance(record, dict) and isinstance(record.get("timestamp"), str):
                    try:
                        _moment(record["timestamp"])
                    except ValueError:
                        malformed += 1
                        continue
                    records.append(record)
    return records, malformed


def _span(start, end):
    start, end = _moment(start), _moment(end)
    _require((start.tzinfo is None) == (end.tzinfo is None), "invalid_timestamp")
    return max(0.0, (end - start).total_seconds())


def _codex_turns(records):
    active, turns, unknown = 0.0, 0, []
    started = last = None
    for record in records:
        payload = record.get("payload") if record.get("type") == "event_msg" else None
        kind = payload.get("type") if isinstance(payload, dict) else None
        _require(type(kind) not in (list, dict), "invalid_record")
        if kind == "task_started":
            if started is not None:
                unknown.append({"started_at": started, "last_record_at": last})
            started = record["timestamp"]
        elif kind in ("task_complete", "turn_aborted") and started is not None:
            active += _span(started, record["timestamp"])
            turns += 1
            started = None
        last = record["timestamp"]
    open_turn = started is not None
    if open_turn:
        unknown.append({"started_at": started, "last_record_at": last})
    return active, turns, unknown, open_turn


def _claude_prompt(record):
    if record.get("type") != "user" or record.get("isMeta"):
        return False
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return True
    return isinstance(content, list) and any(isinstance(part, dict) and part.get("type") == "text" for part in content)


def _claude_turns(records):
    active, turns, unknown = 0.0, 0, []
    started = last = None
    replied = open_turn = False
    for record in records + [None]:
        if record is None or _claude_prompt(record):
            if started is not None:
                if replied:
                    active += _span(started, last)
                    turns += 1
                else:
                    unknown.append({"started_at": started, "last_record_at": last})
                    open_turn = record is None
            if record is not None:
                started, last, replied = record["timestamp"], record["timestamp"], False
            continue
        if started is not None and record.get("type") in ("assistant", "user"):
            last = record["timestamp"]
            replied = replied or record.get("type") == "assistant"
    return active, turns, unknown, open_turn


def _find_transcript(host, session, home):
    found = hosts.transcripts(host, home, session)
    best, newest = None, None
    for path in found:
        with _opened(home, path) as fd:
            modified = os.fstat(fd).st_mtime
        if newest is None or modified > newest:
            best, newest = path, modified
    return best


@_guarded
def find_transcript(host, session, *, home=None):
    """Preserve positional calls; an owner may inject the trusted host home."""
    if not _valid_host(host) or not _valid_session(session):
        return None
    _require(descriptor_supported(), "unsupported_platform")
    selected_home = _home(host) if home is None else absolute_path(home, limit=4096)
    return _find_transcript(host, session, selected_home)


@_guarded
def measure(host, session, transcript=None, limit=SESSION_LIMIT_SECONDS, *, home=None):
    _require(_valid_host(host), "unknown_host")
    _require(_valid_session(session), "invalid_session")
    _require(type(limit) is int and 0 < limit <= 86400, "invalid_limit")
    answer = {"host": host, "session": session, "limit": limit, "active_seconds": None, "turns": 0, "open_turn": False,
              "unknown_intervals": [], "malformed_lines": 0, "transcript": None, "state": "no_transcript"}
    _require(descriptor_supported(), "unsupported_platform")
    home = _home(host) if home is None else absolute_path(home, limit=4096)
    path = absolute_path(transcript, limit=4096) if transcript is not None else _find_transcript(host, session, home)
    if path is None:
        return answer
    records, malformed = _read_records(home, path)
    active, turns, unknown, open_turn = (_claude_turns if hosts.family(host) == "claude" else _codex_turns)(records)
    possible = active + sum(_span(row["started_at"], row["last_record_at"]) for row in unknown)
    if active >= limit:
        state = "rotate_now"
    elif active >= limit * WARN_FRACTION or possible >= limit:
        state = "rotate_soon"
    else:
        state = "ok"
    return {**answer, "active_seconds": round(active, 3), "turns": turns, "open_turn": open_turn,
            "unknown_intervals": unknown, "malformed_lines": malformed, "transcript": str(path), "state": state}
