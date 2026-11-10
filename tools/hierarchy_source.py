"""Pinned, read-only source views for a role that reads source and writes none.

A Reviewer needs to read the exact commit it judges. A shell gives it far more than that, so the mailbox adapter
offers two views instead: show one file at one commit, a page at a time, and grep one commit for a fixed string.
Both read Git objects only, never the working tree, the index or untracked files. The repository is fixed when
the adapter starts, so no tool argument can point a view at another one.

A writer may share the repository's own configuration, so nothing in it may run a command or reshape output:
- Every call refuses all transports, including explicitly enabled protocols, so a promisor remote cannot be fetched from, and
  its configured upload-pack or ssh command never runs. A partial clone is refused at startup anyway, because
  its views would depend on objects it does not have.
- Only plumbing that applies no filters runs: cat-file for blobs, and grep without textconv, columns or
  submodule recursion. Global and system configuration is ignored.
- Each git run has a deadline and its output a byte bound, and each answer is bounded by its rendered size.
"""
import json
import os
from pathlib import PurePosixPath
import selectors
import subprocess
import sys
import tempfile
import time

from hierarchy_mailbox import GIT_ID, fields, require, text
from hierarchy_git import object_read_argv, object_read_env


GIT_TIMEOUT_SECONDS = 30
MAX_BLOB_BYTES = 16777216
MAX_CACHED_BYTES = 16777216
# The answer as the adapter sends it, JSON-encoded twice, stays under one MCP frame.
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
GIT_SETTINGS = ("-c", "submodule.recurse=false", "-c", "grep.column=false", "--literal-pathspecs")
TIMED_OUT = "git timed out in the source repository"
COMMIT = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
PATH = {"type": "string", "maxLength": MAX_PATH_CHARS}
TOOL_SPECS = {
    "source_show": (
        "Show one file at an exact commit, a page of lines at a time. Reads the commit, never the working tree. "
        "Changes nothing.",
        {"commit": COMMIT, "path": PATH, "start_line": {"type": "integer", "minimum": 1},
         "max_lines": {"type": "integer", "minimum": 1, "maximum": MAX_SHOW_LINES}}, ["commit", "path"]),
    "source_grep": (
        "Search an exact commit for a fixed string (not a regular expression), optionally under some paths. Reads "
        "the commit, never the working tree. Changes nothing.",
        {"commit": COMMIT, "pattern": {"type": "string", "maxLength": MAX_PATTERN_CHARS},
         "paths": {"type": "array", "maxItems": MAX_GREP_PATHS, "items": PATH},
         "limit": {"type": "integer", "minimum": 1, "maximum": MAX_GREP_MATCHES}}, ["commit", "pattern"]),
}


def relative_path(value):
    text(value, "path", MAX_PATH_CHARS)
    path = PurePosixPath(value)
    # A leading dash could be read as an option even after "--" in some plumbing, so it is refused outright.
    require(value and not path.is_absolute() and not value.startswith("-") and "\\" not in value
            and all(part not in ("", ".", "..") for part in value.split("/")),
            "path must be relative and stay inside the repository")
    return value


def rendered_size(value):
    """What a value adds to the adapter's answer, which JSON-encodes the result and then that text again."""
    return len(json.dumps(json.dumps(value)))


class SourceViews:
    def __init__(self, repository):
        self.repository = repository
        self._show_cache = None
        top = self.git("rev-parse", "--show-toplevel", check=False)
        require(top.returncode == 0, "--source-repo is not a git repository: " + str(repository))
        promisors = self.git("config", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor)$",
                             check=False)
        require(not promisors.stdout.strip(),
                "--source-repo is a partial clone; source views need every object locally: " + str(repository))

    def argv(self, *arguments):
        return object_read_argv("-C", str(self.repository), *GIT_SETTINGS, *arguments)

    def git(self, *arguments, check=True):
        try:
            result = subprocess.run(self.argv(*arguments), capture_output=True, timeout=GIT_TIMEOUT_SECONDS,
                                    env=object_read_env(), check=False)
        except subprocess.TimeoutExpired as exc:
            raise ValueError(TIMED_OUT) from exc
        require(not check or result.returncode == 0, "git failed in the source repository")
        return result

    def bounded(self, arguments, data, limit):
        """Run git with a deadline over the whole run, reading at most limit bytes of output.

        Errors go to a file rather than a pipe, so a chatty git cannot block on a pipe nobody reads. git grep
        exits 1, as for no match, even when it could not read an object, so any error line is a failure."""
        errors = tempfile.TemporaryFile()
        process = subprocess.Popen(self.argv(*arguments), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=errors, env=object_read_env())
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        chunks, size, cut = [], 0, False
        try:
            process.stdin.write(data)
            process.stdin.close()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    left = deadline - time.monotonic()
                    require(left > 0, TIMED_OUT)
                    if not selector.select(left):
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= limit:
                        cut = True
                        break
        finally:
            if process.poll() is None:
                process.kill()
            process.stdout.close()
            code = process.wait()
            errors.seek(0)
            failed = any(line.startswith((b"error:", b"fatal:")) for line in errors.read(65536).splitlines())
            errors.close()
        require(cut or not failed, "git failed in the source repository")
        return b"".join(chunks), cut, code

    def commit(self, value):
        require(isinstance(value, str) and GIT_ID.fullmatch(value) is not None,
                "commit must be a full 40-character commit id")
        kind = self.git("cat-file", "-t", value, check=False)
        require(kind.returncode == 0 and kind.stdout.strip() == b"commit", "commit not found in the source repository")
        return value

    def _show_lines(self, spec, path):
        # One connection retains only its latest file, keyed by immutable commit/path.
        # Keep commit and argument checks in show(), including on cache hits.
        if self._show_cache is not None and self._show_cache[0] == spec:
            return self._show_cache[1:]
        self._show_cache = None
        kind = self.git("cat-file", "-t", spec, check=False)
        require(kind.returncode == 0 and kind.stdout.strip() == b"blob", "path not found at that commit: " + path)
        blob = self.git("rev-parse", "--verify", spec).stdout.decode("ascii").strip()
        size = int(self.git("cat-file", "-s", blob).stdout)
        require(size <= MAX_BLOB_BYTES, "file is larger than %d bytes" % MAX_BLOB_BYTES)
        raw = self.git("cat-file", "blob", blob).stdout
        require(b"\0" not in raw[:8000], "binary file; source_show returns text only")
        lines = raw.decode("utf-8", errors="replace").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        cached = (spec, blob, lines)
        retained = (sys.getsizeof(cached) + sys.getsizeof(spec) + sys.getsizeof(blob)
                    + sys.getsizeof(lines) + sum(sys.getsizeof(line) for line in lines))
        if retained <= MAX_CACHED_BYTES:
            self._show_cache = cached
        return blob, lines

    def show(self, arguments):
        fields(arguments, {"commit", "path"}, {"start_line", "max_lines"})
        commit = self.commit(arguments["commit"])
        path = relative_path(arguments["path"])
        start = arguments.get("start_line", 1)
        require(type(start) is int and start >= 1, "start line must be at least 1")
        limit = arguments.get("max_lines", DEFAULT_SHOW_LINES)
        require(type(limit) is int and 1 <= limit <= MAX_SHOW_LINES,
                "max lines must be between 1 and %d" % MAX_SHOW_LINES)
        blob, lines = self._show_lines(commit + ":" + path, path)
        require(start <= max(len(lines), 1), "start line is past the end of the file")
        page, cut, used = [], [], rendered_size({"commit": commit, "path": path, "blob": blob})
        for number in range(start, min(len(lines), start + limit - 1) + 1):
            line = lines[number - 1]
            shortened = len(line) > MAX_LINE_CHARS
            line = line[:MAX_LINE_CHARS]
            used += rendered_size(line)
            # A page always holds at least one line, so a reader always makes progress.
            if page and used > RESPONSE_BYTES:
                break
            page.append(line)
            if shortened:
                cut.append(number)
        last = start + len(page) - 1
        return {"commit": commit, "path": path, "blob": blob, "start_line": start, "total_lines": len(lines),
                "lines": page, "cut_lines": cut, "next_start_line": last + 1 if last < len(lines) else None}

    def grep(self, arguments):
        fields(arguments, {"commit", "pattern"}, {"paths", "limit"})
        commit = self.commit(arguments["commit"])
        pattern = arguments["pattern"]
        require(isinstance(pattern, str) and 0 < len(pattern) <= MAX_PATTERN_CHARS and "\n" not in pattern
                and "\0" not in pattern, "pattern must be 1 to %d characters" % MAX_PATTERN_CHARS)
        paths = arguments.get("paths", [])
        require(isinstance(paths, list) and len(paths) <= MAX_GREP_PATHS, "paths must be a list of at most %d"
                % MAX_GREP_PATHS)
        paths = [relative_path(path) for path in paths]
        limit = arguments.get("limit", DEFAULT_GREP_MATCHES)
        require(type(limit) is int and 1 <= limit <= MAX_GREP_MATCHES,
                "limit must be between 1 and %d" % MAX_GREP_MATCHES)
        # -z separates the name, line number and text with NUL, so no file name can forge a match, and the
        # explicit flags override any output setting in the repository's config. -I skips binary files. The
        # pattern comes from stdin, so it can never be read as an option.
        output, truncated, code = self.bounded(
            ["grep", "-z", "-n", "-I", "-F", "--no-color", "--no-column", "--no-textconv", "--no-recurse-submodules",
             "--full-name", "-f", "-", commit, "--", *paths], pattern.encode("utf-8") + b"\n", MAX_GREP_OUTPUT_BYTES)
        # Exit 1 means no match. Anything else, unless this side stopped it, is a failure, not an empty answer.
        require(truncated or code in (0, 1), "git grep failed in the source repository")
        rows = output.split(b"\n")
        # The last piece is empty after a final newline, or a partial line when output was cut.
        rows.pop()
        prefix = (commit + ":").encode("ascii")
        matches, used = [], rendered_size({"commit": commit, "pattern": pattern, "paths": paths})
        for raw in rows:
            if len(matches) == limit:
                truncated = True
                break
            parts = raw.split(b"\0")
            require(len(parts) == 3 and parts[0].startswith(prefix) and parts[1].isdigit(),
                    "git grep returned unexpected output")
            match = {"path": parts[0][len(prefix):].decode("utf-8", errors="replace")[:MAX_PATH_CHARS],
                     "line": int(parts[1]), "text": parts[2].decode("utf-8", errors="replace")[:MAX_MATCH_CHARS]}
            used += rendered_size(match)
            if used > RESPONSE_BYTES:
                truncated = True
                break
            matches.append(match)
        return {"commit": commit, "pattern": pattern, "paths": paths, "matches": matches, "truncated": truncated}

    def call(self, name, arguments):
        return self.show(arguments) if name == "source_show" else self.grep(arguments)
