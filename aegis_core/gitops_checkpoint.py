"""Observation checkpoint operations on an already-held per-request flock.

Empty bytes mean unobserved; !\n reserves the observer; one complete result
after that marker is authoritative. Interrupted observations fail closed.
This module never acquires ownership and never imports the custody transport.
"""
from __future__ import annotations

import json
import os

from aegis_core.gitops_rows import (GitOpsError, pairs, same_intent,
                                   terminal_bytes, valid_row)

__all__ = ["inspect", "reserve", "publish", "reset", "reset_retired"]


def inspect(effect, intent, *, max_row_bytes, flush):
    """Read a bounded saved observation, flushing it before replay if requested."""
    size = os.fstat(effect).st_size
    if size == 0:
        return None
    if not 2 < size <= max_row_bytes + 3:
        raise GitOpsError("checkpoint_stuck")
    os.lseek(effect, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) < size:
        chunk = os.read(effect, min(8192, size - len(data)))
        if not chunk:
            raise GitOpsError("checkpoint_stuck")
        data.extend(chunk)
    try:
        if not data.startswith(b"!\n") or not data.endswith(b"\n") or data.count(b"\n") != 2:
            raise ValueError("checkpoint framing")
        row = json.loads(data[2:-1].decode("ascii"), object_pairs_hook=pairs)
        if not valid_row(row) or row["kind"] != "result" or not same_intent(row, intent):
            raise ValueError("checkpoint binding")
    except (ValueError, UnicodeError, RecursionError):
        raise GitOpsError("checkpoint_stuck") from None
    # Complete bytes can survive a failed prior fsync, so replay must flush.
    if flush is not None:
        flush(effect)
    return row


def reserve(effect, intent, *, max_row_bytes, write, flush, truncate):
    """Durably reserve before invoking the observer; roll back only before it ran."""
    if terminal_bytes(intent) > max_row_bytes:
        raise GitOpsError("invalid_result", result_cause="capacity")
    os.lseek(effect, 0, os.SEEK_SET)
    try:
        if write(effect, b"!\n") != 2:
            raise GitOpsError("journal_io")
        flush(effect)
    except (OSError, GitOpsError):
        try:
            reset(effect, truncate=truncate, flush=flush)
        except OSError:
            pass
        raise


def publish(effect, result, *, append):
    """Persist the authoritative result while retaining the effect flock."""
    append(effect, result, 2)
    return result


def reset(effect, *, truncate, flush):
    """Clear an unavailable observation's reservation before a later pass."""
    truncate(effect, 0)
    flush(effect)


def reset_retired(directory, name, effect, *, truncate, flush):
    """Reset only a newly admitted intent's verified same-inode retired checkpoint."""
    info = os.fstat(effect)
    if info.st_size == 0:
        return
    writable = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        fresh = os.fstat(writable)
        if (fresh.st_dev, fresh.st_ino) != (info.st_dev, info.st_ino):
            raise GitOpsError("unsafe_journal")
        reset(writable, truncate=truncate, flush=flush)
    finally:
        os.close(writable)
