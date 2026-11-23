"""Lossless Git path framing shared by discovery and effect custody."""
from __future__ import annotations

import sys
from aegis_core.gitsafe_policy import GitError

__all__ = ["MAX_PATH_BYTES", "path_text"]

MAX_PATH_BYTES = 65536


def path_text(out, *, gitfile=False, record=False):
    """Decode a Git path using the framing for its source.

    Strip trailing CR/LF from gitfiles and commondir records and require one
    nonempty path line. Command output loses only one final LF and can contain
    newlines or be empty. None retains the query's unavailable answer.
    """
    if out is None:
        return None
    if len(out) > MAX_PATH_BYTES:
        raise GitError("Git path output exceeds its byte limit.", code="git_path_limit")
    record = record or gitfile
    if record:
        out = out.rstrip(b"\r\n")
    elif out.endswith(b"\n"):
        out = out[:-1]
    if gitfile:
        if not out.startswith(b"gitdir: "):
            raise GitError("Git path framing is invalid.", code="git_path_invalid")
        out = out[8:]
    if not record and b"\0" in out:
        raise GitError("Git path framing is invalid.", code="git_path_invalid")
    try:
        value = out.decode(sys.getfilesystemencoding(), "strict")
    except UnicodeError:
        raise GitError("Git path is not decodable.", code="git_path_encoding") from None
    if record and (not value or any(char in value for char in "\0\n\r")):
        raise GitError("Git path record must contain one nonempty line.", code="git_path_record_invalid")
    return value
