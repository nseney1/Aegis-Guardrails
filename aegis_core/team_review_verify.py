"""Read-only review verification behind the public copy facade.

The facade supplies descriptor and manifest helpers. This module walks the
copy, counts every problem, and retains the ordered prefix.
"""
from __future__ import annotations

import errno
import hashlib
import stat

from aegis_core.team_review_files import ProblemPrefix, strict_json

__all__ = ["verify_copy"]

_HEX = "0123456789abcdef"
_FILE_NAMES = ("changes.diff", "commits.txt", "base.files.jsonl", "candidate.files.jsonl")
_FILE_SUFFIXES = (" became a symlink", " is missing", " changed")
_SIDE_NAMES = ("base", "candidate")
_SIDE_SUFFIXES = (" became a symlink", " is missing", " is writable")
_PROVED = frozenset((
    "manifest.json does not match the recorded hash",
    ".git became a symlink",
    ".git is missing",
    "the manifest has no record of .git, so it cannot be checked",
    ".git changed",
    ".git is writable",
    *(name + suffix for name in _FILE_NAMES for suffix in _FILE_SUFFIXES),
    *(name + suffix for name in _SIDE_NAMES for suffix in _SIDE_SUFFIXES),
))


def _proved(text, broken):
    if type(text) is not str or broken(text) or len(text) > 200:
        return False
    if any(ord(char) < 32 or ord(char) > 126 for char in text):
        return False
    return text in _PROVED


def _hex_field(value, size, host):
    if type(value) is not str or len(value) != size or any(char not in _HEX for char in value) or host.broken(value):
        raise host.refusal("manifest_shape")
    return value


def _side_commit(manifest, side, host):
    record = manifest.get(side)
    if type(record) is not dict:
        raise host.refusal("manifest_shape")
    return _hex_field(record.get("commit"), 40, host), _hex_field(record.get("listing_sha256"), 64, host)


def _file_problem(dir_fd, name, expected, prefix, host):
    info = host.stat_leaf(dir_fd, name)
    if info is not None and stat.S_ISLNK(info.st_mode):
        prefix.add(name + " became a symlink", proved=True)
        return
    if info is None or not stat.S_ISREG(info.st_mode):
        prefix.add(name + " is missing", proved=True)
        return
    if host.digest_at(dir_fd, name) != expected:
        prefix.add(name + " changed", proved=True)


def _listing_rows(dir_fd, side, expected, prefix, host):
    name = side + ".files.jsonl"
    info = host.stat_leaf(dir_fd, name)
    if info is None or not stat.S_ISREG(info.st_mode):
        suffix = " became a symlink" if info and stat.S_ISLNK(info.st_mode) else " is missing"
        prefix.add(name + suffix, proved=True)
        return []
    try:
        fd = host.open_readonly(name, dir_fd)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            prefix.add(name + " became a symlink", proved=True)
            return []
        raise
    with host.held(fd):
        info = host.file_fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            prefix.add(name + " is missing", proved=True)
            return []
        if info.st_size > host.max_listing_bytes:
            raise host.refusal("limit_exceeded")
        raw = b"".join(host.read_chunks(fd, info.st_size))
    if hashlib.sha256(raw).hexdigest() != expected:
        prefix.add(name + " changed", proved=True)
    try:
        limit = 6 * host.max_path_bytes + host.max_header_bytes
        if sum(1 for line in host.records(raw, b"\n", limit) if line) > host.max_entries:
            raise host.refusal("limit_exceeded")
        return [strict_json(line.decode("ascii")) for line in host.records(raw, b"\n", limit) if line]
    except (UnicodeError, ValueError):
        raise host.refusal("manifest_shape") from None


def _walk_files(dir_fd, side, relative_prefix, expected, prefix, seen, depth, host):
    if depth > host.max_walk_depth:
        raise host.refusal("limit_exceeded")
    entries = [(name, host.file_stat(name, dir_fd=dir_fd, follow_symlinks=False)) for name in host.names(dir_fd)]
    for name, info in entries:
        relative = name if not relative_prefix else relative_prefix + "/" + name
        shown = side + "/" + relative
        if stat.S_ISLNK(info.st_mode):
            prefix.add(shown + " became a symlink")
        elif info.st_mode & 0o222:
            prefix.add(shown + " is writable")
        if stat.S_ISDIR(info.st_mode):
            continue
        if len(seen) == host.max_entries:
            raise host.refusal("limit_exceeded")
        seen.add(relative)
        if relative not in expected:
            prefix.add(shown + " was added")
        elif not stat.S_ISLNK(info.st_mode) and host.digest_at(dir_fd, name) != expected[relative]:
            prefix.add(shown + " changed")
    for name, info in entries:
        if not stat.S_ISDIR(info.st_mode):
            continue
        relative = name if not relative_prefix else relative_prefix + "/" + name
        with host.held(host.open_directory(name, dir_fd)) as child:
            _walk_files(child, side, relative, expected, prefix, seen, depth + 1, host)


def _side_problems(dir_fd, side, expected_listing, prefix, host):
    rows = _listing_rows(dir_fd, side, expected_listing, prefix, host)
    expected = {row["path"]: row["sha256"] for row in rows
                if type(row) is dict and type(row.get("path")) is str and type(row.get("sha256")) is str}
    info = host.stat_leaf(dir_fd, side)
    if info is not None and stat.S_ISLNK(info.st_mode):
        prefix.add(side + " became a symlink", proved=True)
        return
    if info is None or not stat.S_ISDIR(info.st_mode):
        prefix.add(side + " is missing", proved=True)
        return
    if stat.S_IMODE(info.st_mode) & 0o222:
        prefix.add(side + " is writable", proved=True)
    seen = set()
    with host.held(host.open_directory(side, dir_fd)) as child:
        _walk_files(child, side, "", expected, prefix, seen, 0, host)
    for relative in sorted(set(expected) - seen):
        prefix.add("%s/%s is missing" % (side, relative))


def _remember_mode(text, rendered, limit, prefix, host):
    if len(rendered) < limit:
        rendered.append((text, host.single_line(text)))
        return
    prefix.observe_past_cap(text)


def _git_problems(dir_fd, manifest, prefix, host):
    info = host.stat_leaf(dir_fd, ".git")
    if info is not None and stat.S_ISLNK(info.st_mode):
        prefix.add(".git became a symlink", proved=True)
        return
    if info is None or not stat.S_ISDIR(info.st_mode):
        prefix.add(".git is missing", proved=True)
        return
    if "git_scaffold_sha256" not in manifest:
        prefix.add("the manifest has no record of .git, so it cannot be checked", proved=True)
        return
    # Summaries are known only after the hash walk, and they stay ahead of mode
    # details. Keep a bounded rendered window; later modes are counted without
    # being stored, then the summaries are published first.
    rendered = []
    limit = host.max_problems

    def on_writable(text):
        _remember_mode(text, rendered, limit, prefix, host)

    if host.scaffold_sha(dir_fd, on_writable) != manifest["git_scaffold_sha256"]:
        prefix.add(".git changed", proved=True)
    if stat.S_IMODE(info.st_mode) & 0o222:
        prefix.add(".git is writable", proved=True)
    for text, shown in rendered:
        prefix.add(text, validated=True, rendered=shown)


def _added_problems(dir_fd, prefix, host):
    for name in sorted(host.names(dir_fd)):
        if name not in host.known:
            prefix.add(name + " was added")


def verify_copy(out, expect_manifest, host):
    if not host.descriptor_support():
        raise host.refusal("unsupported_platform")
    if expect_manifest is not None and type(expect_manifest) is not str:
        raise host.refusal("invalid_input")
    if type(expect_manifest) is str and (len(expect_manifest) > 64 or host.broken(expect_manifest)):
        raise host.refusal("invalid_input")
    prefix = ProblemPrefix(host.max_problems, host.single_line, lambda text: _proved(text, host.broken))
    dest = host.absolute_path(out)
    with host.held(host.walk(dest, "not_review_copy")) as fd:
        manifest, raw = host.read_manifest(fd)
        recorded = hashlib.sha256(raw).hexdigest()
        base_commit, base_listing = _side_commit(manifest, "base", host)
        candidate_commit, candidate_listing = _side_commit(manifest, "candidate", host)
        diff_hash = _hex_field(manifest.get("diff_sha256"), 64, host)
        commits_hash = _hex_field(manifest.get("commits_sha256"), 64, host)
        if expect_manifest is not None and recorded != expect_manifest:
            prefix.add("manifest.json does not match the recorded hash", proved=True)
        _git_problems(fd, manifest, prefix, host)
        _file_problem(fd, "changes.diff", diff_hash, prefix, host)
        _file_problem(fd, "commits.txt", commits_hash, prefix, host)
        _side_problems(fd, "base", base_listing, prefix, host)
        _side_problems(fd, "candidate", candidate_listing, prefix, host)
        _added_problems(fd, prefix, host)
    body = {"ok": prefix.count == 0, "manifest_sha256": recorded, "base": base_commit,
            "candidate": candidate_commit, "problems": prefix.kept, "problem_count": prefix.count}
    if prefix.count:
        body.update(host.refusal_envelope("copy_differs"))
    return (3 if prefix.count else 0), body
