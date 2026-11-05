"""Pinned, read-only source views for a role that reads source and writes none.

A Reviewer needs to read the exact commit it judges. A shell gives it far more than that, so the mailbox adapter
offers two views instead: show one file at one commit, a page at a time, and grep one commit for a fixed string.
Both read Git objects only, never the working tree, the index or untracked files. The repository is fixed when
the adapter starts, so no tool argument can point a view at another one.

Only plumbing that applies no filters runs: cat-file for blobs, and grep without textconv. Global and system Git
configuration is ignored, so a user's aliases, pagers or hooks cannot change what a view returns.
"""
import os
from pathlib import PurePosixPath
import subprocess

from hierarchy_mailbox import GIT_ID, fields, require, text


GIT_TIMEOUT_SECONDS = 30
MAX_BLOB_BYTES = 16777216
SHOW_PAGE_BYTES = 65536
MAX_SHOW_LINES = 2000
DEFAULT_SHOW_LINES = 400
MAX_LINE_CHARS = 4096
MAX_GREP_MATCHES = 500
DEFAULT_GREP_MATCHES = 100
MAX_MATCH_CHARS = 256
MAX_GREP_PATHS = 64
MAX_PATH_CHARS = 1024
MAX_PATTERN_CHARS = 256
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_LITERAL_PATHSPECS": "1",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1"}
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


class SourceViews:
    def __init__(self, repository):
        self.repository = repository
        top = self.git("rev-parse", "--show-toplevel", check=False)
        require(top.returncode == 0, "--source-repo is not a git repository: " + str(repository))

    def git(self, *arguments, check=True, data=None):
        result = subprocess.run(["git", "-C", str(self.repository), "-c", "core.fsmonitor=false", *arguments],
                                input=data, capture_output=True, timeout=GIT_TIMEOUT_SECONDS,
                                env={**os.environ, **GIT_ENV})
        require(not check or result.returncode == 0, "git failed in the source repository")
        return result

    def commit(self, value):
        require(isinstance(value, str) and GIT_ID.fullmatch(value) is not None,
                "commit must be a full 40-character commit id")
        kind = self.git("cat-file", "-t", value, check=False)
        require(kind.returncode == 0 and kind.stdout.strip() == b"commit", "commit not found in the source repository")
        return value

    def show(self, arguments):
        fields(arguments, {"commit", "path"}, {"start_line", "max_lines"})
        commit = self.commit(arguments["commit"])
        path = relative_path(arguments["path"])
        start = arguments.get("start_line", 1)
        require(type(start) is int and start >= 1, "start line must be at least 1")
        limit = arguments.get("max_lines", DEFAULT_SHOW_LINES)
        require(type(limit) is int and 1 <= limit <= MAX_SHOW_LINES,
                "max lines must be between 1 and %d" % MAX_SHOW_LINES)
        spec = commit + ":" + path
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
        require(start <= max(len(lines), 1), "start line is past the end of the file")
        page, cut, used = [], [], 0
        for number in range(start, min(len(lines), start + limit - 1) + 1):
            line = lines[number - 1]
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
                cut.append(number)
            used += len(line.encode("utf-8")) + 1
            # A page always holds at least one line, so a reader always makes progress.
            if page and used > SHOW_PAGE_BYTES:
                cut = [n for n in cut if n < number]
                break
            page.append(line)
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
        # -z separates the name, line number and text with NUL, so no file name can forge a match. -I skips
        # binary files. The pattern comes from a file on stdin, so it can never be read as an option.
        argv = ["git", "-C", str(self.repository), "-c", "core.fsmonitor=false", "grep", "-z", "-n", "-I", "-F",
                "--no-color", "--no-textconv", "--full-name", "-f", "-", commit, "--", *paths]
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={**os.environ, **GIT_ENV})
        matches, truncated = [], False
        try:
            process.stdin.write(pattern.encode("utf-8") + b"\n")
            process.stdin.close()
            prefix = (commit + ":").encode("ascii")
            for raw in process.stdout:
                if len(matches) == limit:
                    truncated = True
                    break
                name, number, line = raw.rstrip(b"\n").split(b"\0", 2)
                require(name.startswith(prefix), "git grep returned an unexpected name")
                matches.append({"path": name[len(prefix):].decode("utf-8", errors="replace"), "line": int(number),
                                "text": line.decode("utf-8", errors="replace")[:MAX_MATCH_CHARS]})
        finally:
            if truncated:
                process.kill()
            process.stdout.close()
            code = process.wait(timeout=GIT_TIMEOUT_SECONDS)
        # Exit 1 means no match. Anything else, unless this side stopped it, is a failure, not an empty answer.
        require(truncated or code in (0, 1), "git grep failed in the source repository")
        return {"commit": commit, "pattern": pattern, "paths": paths, "matches": matches, "truncated": truncated}

    def call(self, name, arguments):
        return self.show(arguments) if name == "source_show" else self.grep(arguments)
