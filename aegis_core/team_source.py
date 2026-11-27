"""Pinned object-only source views, using the public bounded gitsafe transport.

Successful pages retain the legacy structured source data. Diagnostics are fixed,
input-free envelopes. The authorized TA-4e round-1b exception refuses grep output
over 4194304 bytes instead of returning a legacy partial prefix. Blobs are bounded
at 16777216 bytes before payload capture; metadata and stderr at 65536 bytes.
Only the latest decoded file may be cached, under a retained-size ceiling.
The repository is an owner-selected absolute root, never a tool argument.
Structured grep builds one immutable commit-pinned request with a literal pattern record.
The raw entry points validate immutable snapshots of allowed non-grep reads.
"""
from __future__ import annotations

from array import array
from functools import wraps
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from threading import RLock
from typing import NamedTuple, Optional

from aegis_core import gitsafe, team_git, team_host_registry
from aegis_core.team_host_plan import absolute_path

__all__ = ["SourceRefusal", "SourceViews", "TOOL_SPECS", "relative_path", "GIT_TIMEOUT_SECONDS",
           "MAX_BLOB_BYTES", "MAX_CACHED_BYTES", "RESPONSE_BYTES", "MAX_SHOW_LINES", "DEFAULT_SHOW_LINES",
           "MAX_LINE_CHARS", "MAX_GREP_MATCHES", "DEFAULT_GREP_MATCHES", "MAX_MATCH_CHARS",
           "MAX_GREP_OUTPUT_BYTES", "MAX_GREP_PATHS", "MAX_PATH_CHARS", "MAX_PATTERN_CHARS"]

GIT_TIMEOUT_SECONDS = 30
MAX_BLOB_BYTES = 16777216
MAX_CACHED_BYTES = 16777216
RESPONSE_BYTES = 196608
MAX_SHOW_LINES = 2000
DEFAULT_SHOW_LINES = 400
MAX_LINE_CHARS = 4096
MAX_GREP_MATCHES = 500
DEFAULT_GREP_MATCHES = 100
MAX_MATCH_CHARS = 256
MAX_GREP_OUTPUT_BYTES = 4194304
MAX_GREP_PATHS = 64
MAX_PATH_CHARS = 1024
MAX_PATTERN_CHARS = 256
_LINE_INDEX_STRIDE = 256
_LINE_BLOCK = re.compile(rf"(?:[^\n]*\n){{{_LINE_INDEX_STRIDE}}}")
_OID = re.compile(r"[0-9a-f]{40}\Z")
_NEXT = {
    "invalid_arguments": "Supply the documented source-view fields and page limits.",
    "invalid_path": "Supply a bounded relative path inside the repository.",
    "invalid_commit": "Supply a full lowercase 40-character commit id.",
    "unknown_commit": "Choose a commit present in the local source repository.",
    "unknown_path": "Choose a file present at the selected commit.",
    "page_out_of_range": "Choose a start line within the selected file.",
    "binary_file": "Choose a text file for source_show.",
    "source_repository": "Choose an available local Git repository at an absolute path.",
    "source_partial_clone": "Supply a repository with every required object already local.",
    "source_blob_limit": "Choose a file no larger than the source blob byte limit.",
    "source_grep_output_limit": (
        "Narrow paths and the fixed string, then retry. Output over the capture cap refuses the whole "
        "result before the post-capture returned-match limit; a capture that fits can still truncate at "
        "that limit. For a known eligible blob, use paged source_show."),
    "source_git_output_limit": "Reduce the source query to its documented output limits.",
    "source_timeout": "Restore local repository responsiveness, then retry the read.",
    "source_git_failed": "Restore the local source objects, then retry the read.",
    "invalid_environment": "Supply bounded string environment entries, then retry the read.",
}
_COMMIT = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
_PATH = {"type": "string", "maxLength": MAX_PATH_CHARS}
TOOL_SPECS = {
    "source_show": (
        "Show one file at an exact commit, a page of lines at a time. Reads the commit, never the working tree. "
        "Changes nothing.",
        {"commit": _COMMIT, "path": _PATH, "start_line": {"type": "integer", "minimum": 1},
         "max_lines": {"type": "integer", "minimum": 1, "maximum": MAX_SHOW_LINES}}, ["commit", "path"]),
    "source_grep": (
        "Search an exact commit for a fixed string (not a regular expression), optionally under some paths. Reads "
        "the commit, never the working tree. Changes nothing.",
        {"commit": _COMMIT, "pattern": {"type": "string", "maxLength": MAX_PATTERN_CHARS},
         "paths": {"type": "array", "maxItems": MAX_GREP_PATHS, "items": _PATH},
         "limit": {"type": "integer", "minimum": 1, "maximum": MAX_GREP_MATCHES}}, ["commit", "pattern"]),
}


class SourceRefusal(ValueError):
    """Fixed refusal contract; untrusted diagnostics and partial output are excluded."""
    def __init__(self, reason):
        self.reason, self.code, self.status = reason, 1, "refused"
        self.next_action = _NEXT[reason]
        super().__init__("source refused: " + reason)

    def as_dict(self):
        return {"status": self.status, "reason": self.reason, "code": self.code, "next_action": self.next_action}


def _require(condition, reason="invalid_arguments"):
    if not condition:
        raise SourceRefusal(reason)


def _guarded(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SourceRefusal:
            raise
        except team_host_registry.HostRefusal:
            raise SourceRefusal("invalid_environment") from None
        except (OSError, ValueError, UnicodeError, OverflowError, RecursionError):
            raise SourceRefusal("source_git_failed") from None
    return call


def _fields(value, required, optional=()):
    _require(type(value) is dict and len(value) <= len(required) + len(optional))
    _require(required <= value.keys() <= required | set(optional))


def relative_path(value):
    _require(type(value) is str and 0 < len(value) <= MAX_PATH_CHARS, "invalid_path")
    _require(not PurePosixPath(value).is_absolute() and not value.startswith("-") and "\\" not in value
             and "\0" not in value and all(part not in ("", ".", "..") for part in value.split("/")), "invalid_path")
    _require(not any(0xD800 <= ord(char) <= 0xDFFF for char in value), "invalid_path")
    return value


def _rendered_size(value):
    return len(json.dumps(json.dumps(value)))


_GREP_PREFIX = (
    "grep", "-z", "-n", "-I", "-F", "--no-color", "--no-column", "--no-textconv",
    "--no-recurse-submodules", "--full-name", "-f", "-",
)


class _ReadRequest(NamedTuple):
    arguments: tuple[str, ...]
    data: Optional[bytes]


class _SourceBlob(NamedTuple):
    spec: str
    blob: str
    text: str
    total: int
    offsets: array


def _index_blob(spec, blob, text):
    total = text.count("\n") + int(bool(text) and not text.endswith("\n"))
    # Each checkpoint starts a real line. Line 1 needs no stored offset.
    count = max(0, total - 1) // _LINE_INDEX_STRIDE
    empty = array("L")
    entry = _SourceBlob(spec, blob, text, total, empty)
    retained = sys.getsizeof(entry) + sum(map(sys.getsizeof, entry))
    if retained + count * empty.itemsize > MAX_CACHED_BYTES:
        return entry, False
    if count:
        offsets = array("L", [0]) * count
        position = 0
        # Match complete blocks in C and publish the offsets only after filling them.
        for index in range(count):
            position = _LINE_BLOCK.match(text, position).end()
            offsets[index] = position
        entry = entry._replace(offsets=offsets)
        retained += sys.getsizeof(offsets) - sys.getsizeof(empty)
    return entry, retained <= MAX_CACHED_BYTES


def _argument_snapshot(arguments, maximum):
    _require(type(arguments) in (tuple, list))
    count = len(arguments)
    _require(count <= maximum)
    if type(arguments) is tuple:
        return arguments
    try:
        # A concurrent append cannot extend the copy. A shrink during the copy refuses.
        return tuple(arguments[index] for index in range(count))
    except IndexError:
        raise SourceRefusal("invalid_arguments") from None


def _read_command(arguments, data):
    """Validate the public non-grep grammar on a bounded operand snapshot."""
    _require(data is None or type(data) is bytes and len(data) <= MAX_PATTERN_CHARS * 4 + 1)
    args = _argument_snapshot(arguments, 3)
    _require(all(type(arg) is str and len(arg) <= MAX_PATH_CHARS + 41 and "\0" not in arg for arg in args))
    if args in (("rev-parse", "--show-toplevel"),
                ("config", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$")):
        return _ReadRequest(args, data)
    if (len(args) == 3 and (args[:2] in (("cat-file", "-t"), ("cat-file", "-s"), ("cat-file", "blob"),
                                        ("rev-parse", "--verify")))):
        oid, separator, path = args[2].partition(":")
        _require(len(oid) == 40 and _OID.fullmatch(oid) is not None)
        if separator:
            _require(args[:2] in (("cat-file", "-t"), ("rev-parse", "--verify")))
            relative_path(path)
        return _ReadRequest(args, data)
    raise SourceRefusal("invalid_arguments")


def _committed_search(commit: str, paths: tuple[str, ...], pattern: str) -> _ReadRequest:
    """Build a grep request from validated structured arguments."""
    # Git strips one CR before the record's LF. Supply that CR separately from the literal.
    ending = b"\r\n" if pattern.endswith("\r") else b"\n"
    return _ReadRequest((*_GREP_PREFIX, commit, "--", *paths), pattern.encode("utf-8") + ending)


class SourceViews:
    @_guarded
    def __init__(self, repository, *, planned=None, child_environment=None):
        _require(child_environment is None or callable(child_environment))
        try:
            self.repository = absolute_path(repository, limit=4096)
        except team_host_registry.HostRefusal:
            raise SourceRefusal("source_repository") from None
        self.planned = planned
        self.child_environment = child_environment
        self._show_cache = None
        self._cache_lock = RLock()
        top = self.git("rev-parse", "--show-toplevel", check=False)
        _require(top.returncode == 0, "source_repository")
        promisors = self.git("config", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$", check=False)
        _require(promisors.returncode in (0, 1), "source_git_failed")
        _require(not promisors.stdout.strip(), "source_partial_clone")

    def argv(self, *arguments):
        """Return arguments without the program, passed whole to gitsafe.run."""
        return team_git.object_read_argv("-C", str(self.repository), "-c", "submodule.recurse=false",
                                         "-c", "grep.column=false", "--literal-pathspecs", *arguments)

    @_guarded
    def read_environment(self):
        try:
            environment = team_git.object_read_env()
            if self.planned is False or self.child_environment is None:
                result = team_host_registry.child_environment(environment, "no-host")
            else:
                result = self.child_environment(environment, "no-host")
            _require(type(result) is dict, "invalid_environment")
            return team_git.object_read_env(result, environ={})
        except team_git.GitRefusal:
            raise SourceRefusal("invalid_environment") from None

    def _run(self, request, *, limit, overflow="source_git_output_limit"):
        _require(type(limit) is int and 0 <= limit <= max(65536, MAX_BLOB_BYTES, MAX_GREP_OUTPUT_BYTES))
        try:
            with gitsafe.custody(scratch=Path(tempfile.gettempdir()), stdout_limit=limit, stderr_limit=65536):
                # Build the child environment from the sanitized mapping alone.
                return gitsafe.run(self.argv(*request.arguments), self.repository, timeout=GIT_TIMEOUT_SECONDS,
                                   stdin=request.data, _env=self.read_environment(), _environ={})
        except gitsafe.GitError as error:
            reason = {"git_timeout": "source_timeout", "git_output_limit": overflow,
                      "invalid_environment": "invalid_environment"}.get(error.code, "source_git_failed")
            raise SourceRefusal(reason) from None

    @_guarded
    def git(self, *arguments, check=True, output_limit=65536, data=None):
        """Run an allowed non-grep read."""
        result = self._run(_read_command(arguments, data), limit=output_limit)
        _require(not check or result.returncode == 0, "source_git_failed")
        return result

    @_guarded
    def bounded(self, arguments, data, limit):
        return self._bounded(_read_command(arguments, data), limit)

    def _bounded(self, request, limit):
        result = self._run(request, limit=limit, overflow="source_grep_output_limit")
        _require(not any(line.startswith((b"error:", b"fatal:")) for line in result.stderr.splitlines()),
                 "source_git_failed")
        return result.stdout, len(result.stdout) == limit, result.returncode

    def commit(self, value):
        _require(type(value) is str and len(value) == 40 and _OID.fullmatch(value) is not None, "invalid_commit")
        kind = self.git("cat-file", "-t", value, check=False)
        _require(kind.returncode == 0 and kind.stdout.strip() == b"commit", "unknown_commit")
        return value

    def _show_blob(self, spec):
        with self._cache_lock:
            if self._show_cache is not None and self._show_cache.spec == spec:
                return self._show_cache
            self._show_cache = None
            kind = self.git("cat-file", "-t", spec, check=False)
            _require(kind.returncode == 0 and kind.stdout.strip() == b"blob", "unknown_path")
            blob = self.git("rev-parse", "--verify", spec).stdout.decode("ascii").strip()
            _require(len(blob) == 40 and _OID.fullmatch(blob) is not None, "source_git_failed")
            raw_size = self.git("cat-file", "-s", blob).stdout.strip()
            _require(0 < len(raw_size) <= 20 and raw_size.isdigit(), "source_git_failed")
            size = int(raw_size)
            _require(size <= MAX_BLOB_BYTES, "source_blob_limit")
            raw = self.git("cat-file", "blob", blob, output_limit=size).stdout
            _require(len(raw) == size, "source_git_failed")
            _require(b"\0" not in raw[:8000], "binary_file")
            text = raw.decode("utf-8", errors="replace")
            entry, cacheable = _index_blob(spec, blob, text)
            if cacheable:
                self._show_cache = entry
            return entry

    @_guarded
    def show(self, arguments):
        _fields(arguments, {"commit", "path"}, {"start_line", "max_lines"})
        path = relative_path(arguments["path"])
        start = arguments.get("start_line", 1)
        _require(type(start) is int and start >= 1)
        limit = arguments.get("max_lines", DEFAULT_SHOW_LINES)
        _require(type(limit) is int and 1 <= limit <= MAX_SHOW_LINES)
        commit = self.commit(arguments["commit"])
        _, blob, text, total, offsets = self._show_blob(commit + ":" + path)
        _require(start <= max(total, 1), "page_out_of_range")
        page, cut, used = [], [], _rendered_size({"commit": commit, "path": path, "blob": blob})
        position, skip = 0, start - 1
        if offsets:
            block, skip = divmod(skip, _LINE_INDEX_STRIDE)
            if block:
                position = offsets[block - 1]
        for _ in range(skip):
            position = text.find("\n", position) + 1
        for number in range(start, min(total, start + limit - 1) + 1):
            end = text.find("\n", position)
            end = len(text) if end < 0 else end
            shortened = end - position > MAX_LINE_CHARS
            line = text[position:min(end, position + MAX_LINE_CHARS)]
            position = end + 1
            used += _rendered_size(line)
            if page and used > RESPONSE_BYTES:
                break
            page.append(line)
            if shortened:
                cut.append(number)
        last = start + len(page) - 1
        return {"commit": commit, "path": path, "blob": blob, "start_line": start, "total_lines": total,
                "lines": page, "cut_lines": cut, "next_start_line": last + 1 if last < total else None}

    @_guarded
    def grep(self, arguments):
        _fields(arguments, {"commit", "pattern"}, {"paths", "limit"})
        pattern = arguments.get("pattern")
        _require(type(pattern) is str and 0 < len(pattern) <= MAX_PATTERN_CHARS and "\n" not in pattern
                 and "\0" not in pattern and not any(0xD800 <= ord(char) <= 0xDFFF for char in pattern))
        paths = arguments.get("paths", [])
        _require(type(paths) is list)
        paths = _argument_snapshot(paths, MAX_GREP_PATHS)
        for path in paths:
            relative_path(path)
        limit = arguments.get("limit", DEFAULT_GREP_MATCHES)
        _require(type(limit) is int and 1 <= limit <= MAX_GREP_MATCHES)
        commit = self.commit(arguments.get("commit"))
        output, truncated, code = self._bounded(_committed_search(commit, paths, pattern), MAX_GREP_OUTPUT_BYTES)
        _require(code in (0, 1), "source_git_failed")
        prefix = (commit + ":").encode("ascii")
        matches, used = [], _rendered_size({"commit": commit, "pattern": pattern, "paths": paths})
        for row in BytesIO(output):
            if not row.endswith(b"\n"):
                break
            raw = row[:-1]
            if len(matches) == limit:
                truncated = True
                break
            parts = raw.split(b"\0", 3)
            _require(len(parts) == 3 and parts[0].startswith(prefix) and 0 < len(parts[1]) <= 20
                     and parts[1].isdigit(), "source_git_failed")
            match = {"path": parts[0][len(prefix):].decode("utf-8", errors="replace")[:MAX_PATH_CHARS],
                     "line": int(parts[1]), "text": parts[2].decode("utf-8", errors="replace")[:MAX_MATCH_CHARS]}
            used += _rendered_size(match)
            if used > RESPONSE_BYTES:
                truncated = True
                break
            matches.append(match)
        return {"commit": commit, "pattern": pattern, "paths": list(paths), "matches": matches, "truncated": truncated}

    def call(self, name, arguments):
        _require(type(name) is str and name in ("source_show", "source_grep"))
        return self.show(arguments) if name == "source_show" else self.grep(arguments)
