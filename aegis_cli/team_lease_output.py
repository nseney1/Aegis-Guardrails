"""Invocation-local lease responses, published only after custody cleanup."""
from __future__ import annotations

import io
import json
import sys

from aegis_core import gitsafe, team
from aegis_cli import sanitize_display

__all__ = ["Response", "PendingResponse", "operation"]

_OUTPUT_LIMIT = 2 * 1024 * 1024


def _limit():
    raise gitsafe.GitError("liveness_unknown", code="git_output_limit") from None


def _measure_json(value, budget, depth=0):
    """Measure indent=2, ensure_ascii JSON before allocating escaped strings."""
    if budget < 0 or depth > 64:
        _limit()
    if isinstance(value, str):
        if len(value) + 2 > budget:
            _limit()
        size = 2
        for char in value:
            point = ord(char)
            size += (2 if char in '\\"\b\f\n\r\t' else 6 if point < 32 or 127 <= point <= 65535
                     else 12 if point > 65535 else 1)
            if size > budget:
                _limit()
        return size
    if isinstance(value, (dict, list, tuple)):
        if not value:
            if budget < 2:
                _limit()
            return 2
        # Every entry consumes separators and indentation before its value.
        size = 2 + 2 * len(value) + 2 * depth + len(value) * (2 * (depth + 1))
        if size > budget:
            _limit()
        entries = value.items() if isinstance(value, dict) else enumerate(value)
        for key, item in entries:
            if isinstance(value, dict):
                if not isinstance(key, str):
                    raise gitsafe.GitError("liveness_unknown", code="git_failed")
                size += _measure_json(key, budget - size, depth + 1) + 2
            size += _measure_json(item, budget - size, depth + 1)
        return size
    if value is not None and type(value) not in (bool, int, float):
        raise gitsafe.GitError("liveness_unknown", code="git_failed")
    try:
        # Operational numbers are small; bound integer conversion first too.
        if isinstance(value, int) and value.bit_length() > 3 * _OUTPUT_LIMIT:
            _limit()
        size = len(json.dumps(value))
    except (ValueError, OverflowError):
        raise gitsafe.GitError("liveness_unknown", code="git_failed") from None
    if size > budget:
        _limit()
    return size


class Response:
    """Preserve immediate output for commands outside the custody adapter."""

    def __init__(self, code=0):
        self.code = code

    def write(self, value, stream="stdout"):
        getattr(sys, stream).write(value)

    def line(self, value, stream="stdout"):
        self.write(value, stream)
        self.write("\n", stream)

    def json(self, payload):
        self.line(json.dumps(payload, indent=2))

    def warn(self, warnings):
        for warning in warnings:
            self.line("Warning: " + sanitize_display(warning, max_len=None), "stderr")

    def publish(self):
        return self.code


class PendingResponse(Response):
    """Explicit response with independent per-stream character ceilings."""

    def __init__(self, code=0):
        super().__init__(code)
        self._streams = {"stdout": io.StringIO(), "stderr": io.StringIO()}

    def write(self, value, stream="stdout"):
        target = self._streams[stream]
        if len(value) > _OUTPUT_LIMIT - target.tell():
            _limit()
        target.write(value)

    def line(self, value, stream="stdout"):
        # Reserve the newline before retaining any of the line.
        if len(value) + 1 > _OUTPUT_LIMIT - self._streams[stream].tell():
            _limit()
        super().line(value, stream)

    def json(self, payload):
        _measure_json(payload, _OUTPUT_LIMIT - self._streams["stdout"].tell() - 1)
        super().json(payload)

    def publish(self):
        sys.stdout.write(self._streams["stdout"].getvalue())
        sys.stderr.write(self._streams["stderr"].getvalue())
        return self.code


def operation(root, handler, args, now, refused=None):
    """Keep observations, mutation and response preparation inside one custody."""
    with team.lease_custody(root):
        try:
            pending = handler(args, root, now)
        except team.LeaseRefused as exc:
            if refused is None:
                raise
            try:
                pending = refused(args, root, now, exc, pending=True)
            except Exception:
                raise gitsafe.GitError("liveness_unknown", code="git_failed") from None
    return pending.publish()
