"""Bounded iterative Rust tokenizer; strings/comments never become executable tokens."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import NamedTuple

from aegis_core.ast.driver_errors import ASTDriverError
from .literals import decode_string, number

MAX_DEPTH = 512
_LIFETIME = re.compile(r"'[A-Za-z_]\w*")
_PUNCT = ('..=', '::', '->', '=>', '..', '&&', '||', '==', '!=', '<=', '>=', '+=', '-=', '*=', '/=', '&=', '|=', '^=')
_PUNCT_BY_HEAD = {head: tuple(p for p in _PUNCT if p[0] == head) for head in {p[0] for p in _PUNCT}}
_CLOSE = {')': '(', ']': '[', '}': '{'}
_BLOCK_EDGE = re.compile(r'/\*|\*/')
_WHITESPACE = re.compile(r'[ \t\n\r\v\f\u0085\u200e\u200f\u2028\u2029]+')
_SPACES = ' \t\n\r\v\f\u0085\u200e\u200f\u2028\u2029'
_ASCII_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_NUMERIC_PIECE = re.compile(r'[0-9A-Za-z_]+')
_QUOTED_EDGE = {'"': re.compile(r'["\\]'), "'": re.compile(r"['\\\r\n]")}


class Token(NamedTuple):
    kind: str
    value: str
    line: int
    col: int
    start: int
    end: int
    raw: bool = False


# Keep the public tuple unchanged while avoiding its Python constructor wrapper.
_TOKEN_NEW = tuple.__new__


@dataclass
class Lexed:
    tokens: list[Token]
    comments: list[Token]
    pairs: dict[int, int]
    scalars: dict[int, str] = field(default_factory=dict)


def error(detail, line):
    raise ASTDriverError(f'{detail} at line {line}', reason='syntax')


def _block(source, start, line):
    depth, i = 1, start + 2
    while i < len(source):
        edge = _BLOCK_EDGE.search(source, i)
        if edge is None:
            break
        i = edge.end()
        if edge[0] == '/*':
            depth += 1
            if depth > MAX_DEPTH:
                error('comment nesting limit exceeded', line)
        else:
            depth -= 1
            if not depth:
                return i
    error('unterminated block comment', line)


def _raw(source, start, prefix, line):
    i = start + len(prefix)
    while i < len(source) and source[i] == '#':
        i += 1
    if i == len(source) or source[i] != '"':
        return None
    hashes = i - start - len(prefix)
    if hashes > 255:
        error('invalid raw string delimiter', line)
    closing = source.find('"' + '#' * hashes, i + 1)
    if closing < 0:
        error('unterminated raw string', line)
    end = closing + 1 + hashes
    decode_string(source[start:end], line)
    return end


def _quoted(source, start, prefix, line):
    quote_at = start + len(prefix)
    quote, i = source[quote_at], quote_at + 1
    while i < len(source):
        edge = _QUOTED_EDGE[quote].search(source, i)
        if edge is None:
            break
        i = edge.end()
        if edge[0] == '\\':
            i += 1
        elif edge[0] == quote:
            end = i
            decode_string(source[start:end], line)
            return end
        else:
            error('unterminated character', line)
    error('unterminated string', line)


def _literal(source, i, line):
    for prefix, kind in (('br', 'bytes'), ('cr', 'cstring'), ('r', 'string')):
        if source.startswith(prefix, i):
            end = _raw(source, i, prefix, line)
            if end is not None:
                return kind, end
    for prefix, kind in (('b', 'bytes'), ('c', 'cstring'), ('', 'string')):
        at = i + len(prefix)
        if source.startswith(prefix, i) and at < len(source) and source[at] in ('"', "'"):
            if prefix == '' and source[at] == "'":
                lifetime = _LIFETIME.match(source, i)
                if lifetime and source[lifetime.end():lifetime.end() + 1] != "'":
                    return 'lifetime', lifetime.end()
                kind = 'char'
            return kind, _quoted(source, i, prefix, line)
    return None


def _numeric_end(source, start):
    i = _NUMERIC_PIECE.match(source, start).end()
    if source[i:i + 1] == '.' and source[i + 1:i + 2] != '.' and source[i + 1:i + 2].isdigit():
        i += 1
        i = _NUMERIC_PIECE.match(source, i).end()
    if i > start and source[i - 1] in 'eE' and source[i:i + 1] in ('+', '-'):
        i += 1
        match = _NUMERIC_PIECE.match(source, i)
        i = match.end() if match else i
    return i


def _next(source, i, line):
    ch, start = source[i], i
    if (i == 0 or (i == 1 and source[0] == '\ufeff')) and source.startswith('#!', i) and not source.startswith('#![', i):
        ending = source.find('\n', i)
        return 'comment', ending if ending >= 0 else len(source), None, None
    if ch == '/' and source.startswith('//', i):
        ending = source.find('\n', i)
        return 'comment', ending if ending >= 0 else len(source), None, None
    if ch == '/' and source.startswith('/*', i):
        return 'comment', _block(source, i, line), None, None
    literal = _literal(source, i, line) if ch in ('b', 'c', 'r', '"', "'") else None
    if literal:
        return *literal, None, None
    if ch.isdigit():
        end = _numeric_end(source, i)
        text = source[i:end]
        return 'number', end, text, number(text, line)
    raw = ch == 'r' and source.startswith('r#', i)
    if raw:
        i += 2
        ch = source[i:i + 1]
    if ch and (ch == '_' or ch.isidentifier()):
        match = _ASCII_IDENTIFIER.match(source, i)
        i = match.end() if match else i + 1
        if not match or (i < len(source) and not source[i].isascii()):
            while i < len(source) and ('x' + source[i]).isidentifier():
                i += 1
        return 'ident', i, source[start + 2:i] if raw else None, None
    for punctuation in _PUNCT_BY_HEAD.get(ch, ()):
        if source.startswith(punctuation, start):
            return 'punct', start + len(punctuation), punctuation, None
    if ch in '()[]{}.,;:=+-*/%&|^!<>?@#$~':
        return 'punct', start + 1, source[start], None
    error('invalid character', line)


def tokenize(source: str) -> Lexed:
    """Tokenize Rust with locations, comment tokens and a precomputed delimiter map."""
    tokens, comments, pairs, stack, scalars = [], [], {}, [], {}
    i, line, col = (1 if source.startswith('\ufeff') else 0), 1, 0
    while i < len(source):
        if source[i] in _SPACES:
            end = _WHITESPACE.match(source, i).end()
            segment = source[i:end]
            count = segment.count('\n')
            line += count
            col = len(segment) - segment.rfind('\n') - 1 if count else col + end - i
            i = end
            continue
        kind, end, value, scalar = _next(source, i, line)
        token = _TOKEN_NEW(Token, (kind, source[i:end] if value is None else value, line, col, i, end,
                                  kind == 'ident' and value is not None))
        if kind == 'comment':
            comments.append(token)
        else:
            index = len(tokens)
            if scalar is not None:
                scalars[index] = scalar
            if token.value in ('(', '[', '{') and kind == 'punct':
                stack.append(index)
                if len(stack) > MAX_DEPTH:
                    error('delimiter nesting limit exceeded', line)
            elif token.value in (')', ']', '}') and kind == 'punct':
                if not stack or tokens[stack[-1]].value != _CLOSE[token.value]:
                    error('mismatched delimiter', line)
                opening = stack.pop()
                pairs[opening], pairs[index] = index, opening
            tokens.append(token)
        if kind in ('ident', 'number', 'punct', 'lifetime'):
            col += end - i
        else:
            segment = token.value
            count = segment.count('\n')
            line += count
            col = len(segment) - segment.rfind('\n') - 1 if count else col + end - i
        i = end
    if stack:
        error('unclosed delimiter', tokens[stack[-1]].line)
    return Lexed(tokens, comments, pairs, scalars)
