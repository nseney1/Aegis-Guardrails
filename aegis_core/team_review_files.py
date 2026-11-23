"""Shared manifest parsing and bounded diagnostic retention for review copies.

Verification counts every problem and keeps the ordered visible prefix. Rendering
past that prefix is skipped only for a proved single-line constant.
"""
from __future__ import annotations

import json

__all__ = ["ProblemPrefix", "strict_json"]


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("nonfinite")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


class ProblemPrefix:
    """Count every diagnostic and retain only an ordered prefix of rendered text."""

    def __init__(self, limit, render, proof):
        if type(limit) is not int or limit < 0:
            raise ValueError("limit")
        self.limit = limit
        self._render = render
        self._proof = proof
        self.kept = []
        self.count = 0

    def add(self, text, *, proved=False, validated=False, rendered=None):
        self.count += 1
        if len(self.kept) < self.limit:
            shown = rendered if rendered is not None else self._render(text)
            self.kept.append(shown)
            return
        if validated or (proved and self._proof(text)):
            return
        self._render(text)

    def observe_past_cap(self, text, *, proved=False, validated=False):
        """Count a diagnostic that cannot fit even before later summaries."""
        self.count += 1
        if validated or (proved and self._proof(text)):
            return
        self._render(text)
