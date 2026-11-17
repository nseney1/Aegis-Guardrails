"""Bounded regular-language proofs over renderer-supplied optional characters.

This module never parses terminal escapes. Single-character lookbehinds retain
their flags; other assertions are relaxed. The graph accepts a superset, so only a negative result
proves that no attributable match can involve visible text. Positive/unknown
results still require the caller's exact matcher or its fail-closed policy.
"""
from __future__ import annotations

from itertools import chain
import re
import sre_parse

__all__ = ["compile_possible", "max_match_width", "may_match_visible", "overlapping_matches", "project_window"]

_UNBOUNDED = sre_parse.parse(r'[\s\S]*').getwidth()[1]
_GRAPH_LIMIT = 32768
_REPEAT_LIMIT = 2048
_CATEGORIES = dict(CATEGORY_DIGIT=r'\d', CATEGORY_NOT_DIGIT=r'\D', CATEGORY_SPACE=r'\s',
                   CATEGORY_NOT_SPACE=r'\S', CATEGORY_WORD=r'\w', CATEGORY_NOT_WORD=r'\W')


def max_match_width(patterns, *, unbounded_cap):
    """Derive finite widths; an unbounded row uses the caller's documented cap."""
    widths = (sre_parse.parse(pattern.pattern, pattern.flags).getwidth()[1] for pattern in patterns)
    return max(unbounded_cap if width == _UNBOUNDED else width for width in widths)


def _atom(op, value, flags):
    if op == sre_parse.ANY:
        return re.compile('.', flags)
    if op == sre_parse.NOT_LITERAL:
        return re.compile('[^' + re.escape(chr(value)) + ']', flags)
    parts = []
    for code, argument in value if op == sre_parse.IN else [(op, value)]:
        if code == sre_parse.LITERAL:
            part = re.escape(chr(argument))
        elif code == sre_parse.RANGE:
            part = re.escape(chr(argument[0])) + '-' + re.escape(chr(argument[1]))
        elif code == sre_parse.NEGATE:
            part = '^'
        elif code == sre_parse.CATEGORY and str(argument) in _CATEGORIES:
            part = _CATEGORIES[str(argument)]
        else:
            return None
        parts.append(part)
    expression = '[' + ''.join(parts) + ']' if op == sre_parse.IN else ''.join(parts)
    return re.compile(expression, flags)


def compile_possible(patterns, *, carried_patterns=()):
    """Compile trusted shared rows with explicit graph/repetition size limits.

    Unsupported or too-large grammars return unknown, never a negative proof.
    Node zero accepts; an epsilon node has no matcher. Each consuming node
    uses re itself for character classes and flags, including Unicode folding.
    """
    graph, supported = [(None, ())], True

    def node(matcher, targets):
        nonlocal supported
        if len(graph) >= _GRAPH_LIMIT:
            supported = False
            return 0
        graph.append((matcher, tuple(targets)))
        return len(graph) - 1

    def build(sequence, after, flags):
        nonlocal supported
        for op, value in reversed(sequence):
            if not supported:
                return after
            if op == sre_parse.SUBPATTERN:
                after = build(value[3], after, (flags | value[1]) & ~value[2])
            elif op == sre_parse.BRANCH:
                after = node(None, [build(branch, after, flags) for branch in value[1]])
            elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
                minimum, maximum, body = value
                if maximum > _REPEAT_LIMIT:
                    supported = False
                    return after
                tail = after
                for count in range(maximum, 0, -1):
                    if not supported:
                        return after
                    entry = build(body, tail, flags)
                    tail = node(None, (entry, after)) if count > minimum else entry
                after = tail
            elif op in (sre_parse.ASSERT, sre_parse.ASSERT_NOT) and value[0] == -1:
                body = value[1]
                matcher = _atom(*body[0], flags) if len(body) == 1 and body.getwidth() == (1, 1) else None
                if matcher is None:
                    supported = False
                    return after
                after = node((op == sre_parse.ASSERT, matcher), (after,))
            elif op not in (sre_parse.ASSERT, sre_parse.ASSERT_NOT, sre_parse.AT):
                matcher = _atom(op, value, flags)
                if matcher is None:
                    supported = False
                    return after
                after = node(matcher, (after,))
        return after

    roots = tuple(build(sre_parse.parse(pattern.pattern, pattern.flags), 0, pattern.flags) for pattern in patterns)
    carried = tuple(build(sre_parse.parse(pattern.pattern, pattern.flags), 0, pattern.flags)
                    for pattern in carried_patterns)
    return (tuple(graph), roots, carried) if supported else None


def may_match_visible(grammar, text, runs, charge, *, start_at=0):
    """Return False only after proving no match touches a visible character.

    Each graph-state visit is charged before expansion. An unknown grammar or
    exhausted budget returns True conservatively. Optional final characters
    can be skipped; visible characters are mandatory. No variant strings are
    materialized. Merging (node, touched-visible) states loses no possibility.
    """
    if grammar is None:
        return True
    graph, roots, carried_roots = grammar
    states = set()

    def units():
        previous_end, previous_kind, optional = -1, None, False
        for start, end, kind, visible, replacement, _sealed in runs:
            boundary = start != previous_end or kind != previous_kind or optional
            for offset, char in enumerate(text[start:end] if replacement is None else replacement):
                yield char, visible, boundary and offset == 0
            previous_end, previous_kind, optional = end, kind, not visible

    previous = {None}
    for position, (char, visible, boundary) in enumerate(chain(units(), [(None, False, False)])):
        starts = chain(roots, carried_roots if boundary else ()) if position >= start_at else ()
        pending = list(states | {(root, False) for root in starts})
        visited, after = set(), set(states) if char is not None and not visible else set()
        while pending:
            state, touched = pending.pop()
            if (state, touched) in visited:
                continue
            if not charge(1):
                return True
            visited.add((state, touched))
            if state == 0:
                if touched:
                    return True
                continue
            matcher, targets = graph[state]
            if matcher is None:
                pending.extend((target, touched) for target in targets)
            elif isinstance(matcher, tuple):
                positive, predicate = matcher
                if any((prior is not None and predicate.fullmatch(prior) is not None) == positive
                       for prior in previous):
                    pending.extend((target, touched) for target in targets)
            elif char is not None and matcher.fullmatch(char) is not None:
                after.update((target, touched or visible) for target in targets)
        states = after
        if char is not None:
            previous = {char} if visible else previous | {char}
    return False


def overlapping_matches(pattern, text, pos, endpos, charge):
    """Charge each search before scanning; include starts within earlier matches."""
    while pos <= endpos:
        if not charge(endpos - pos + 1):
            return
        match = pattern.search(text, pos, endpos)
        if match is None:
            return
        yield match
        pos = match.start() + 1


def _source_position(source_map, position):
    """Search existing renderer runs without copying a whole-input index."""
    left, right = 0, len(source_map)
    while left < right:
        middle = (left + right) // 2
        if source_map[middle][1] <= position:
            left = middle + 1
        else:
            right = middle
    source, offset, _length = source_map[left - 1]
    return source + position - offset


def project_window(pending, limit, source_map):
    """Project detection bounds, retaining the suppressed finals themselves."""
    left, right, first_final, last_final = pending
    right = min(right, limit)
    start, end = first_final, last_final
    if left < right:
        start = min(start, _source_position(source_map, left))
        end = max(end, _source_position(source_map, right - 1) + 1)
    return start, end, left, right
