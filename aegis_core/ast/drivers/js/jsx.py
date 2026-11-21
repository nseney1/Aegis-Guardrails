"""JSX element scanning for the JavaScript and TypeScript lexer."""
from __future__ import annotations

import re

from aegis_core.ast.drivers.js.values import (
    MAX_DEPTH,
    identifier_part,
    identifier_start,
    line_breaks,
)

__all__ = ['JSXScanner']
# Characters a JSX attribute list may contain; a TSX generic built only from them is also a JSX tag.
_JSX_ATTRIBUTE_RUN = re.compile(r'[A-Za-z0-9_$.,:\-\[\]|& \t\r\n\f\v]*')
_JSX_CLOSING_NAME = re.compile(r'</\s*([A-Za-z_$][A-Za-z0-9_$]*)')
# A TSX generic signature (`<T>(x: T) => T`) in a type reads as an opening tag. Its head reads as type
# parameters (`<T>`, `<T = U>`, `<T, U = {}>`, `<T extends {}>`; comments and quoted types aside) and its
# text starts with `(`, after whitespace and comments.
_COMMENT = re.compile(r'//[^\r\n\u2028\u2029]*|/\*[\s\S]*?\*/')
_QUOTED = re.compile(r'"(?:[^"\\\r\n]|\\.)*"|\'(?:[^\'\\\r\n]|\\.)*\'')
_GENERIC_HEAD = re.compile(r'[\s\ufeff]*(?:$|[=,]|[\s\S]*\bextends\b)')
# A comment still open at the end of a tag head: the tag ended at a `>` inside it (`<T/*>*/>`).
_OPEN_COMMENT = re.compile(r'/\*(?![\s\S]*?\*/)|//[^\r\n\u2028\u2029]*\Z')
_SIGNATURE_START = re.compile(r'(?:[\s\ufeff]+|//[^\r\n\u2028\u2029]*|/\*[\s\S]*?\*/)*\(')
_SIGNATURE_SCAN = 4096
_JSX_TYPE_ARGUMENT = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.,[]|& \t\r\n')


class JSXScanner:
    """JSX modes of the lexer; the state they use lives on the lexer itself."""

    def jsx_candidate(self):
        source, start = self.source, self.i + 1
        if start < len(source) and source[start].isspace():
            self.error('unsupported_lexical_context:jsx_angle')
        if start >= len(source) or not (identifier_start(source[start]) or source[start] == '>'):
            return False
        if self.tsx:
            head = _JSX_ATTRIBUTE_RUN.match(source, start)
            text = head[0]
            generic = ',' in text or 'extends' in text.split() or text.startswith('const ')
            if generic and head.end() < len(source) and source[head.end()] == '>':
                if self.closing_names is None:
                    self.closing_names = {match[1] for match in _JSX_CLOSING_NAME.finditer(source)}
                if text.split()[0].rstrip(',') in self.closing_names:
                    self.error('unsupported_lexical_context:tsx_generic_or_jsx')
                return False
        return True

    def jsx_type_arguments(self):
        begin, line, depth = self.i, self.line, 0
        while self.i < len(self.source):
            ch = self.source[self.i]
            if ch in '<>':
                depth += 1 if ch == '<' else -1
                if depth + len(self.frames) + len(self.jsx_elements) > MAX_DEPTH:
                    self.error('limit:depth')
            elif ch not in _JSX_TYPE_ARGUMENT:
                self.error('unsupported_lexical_context:jsx_type_argument')
            self.i += 1
            if depth == 0:
                self.line += line_breaks(self.source[begin:self.i])
                self.emit('jsx', self.source[begin:self.i], begin, line)
                return
        self.error('syntax:unterminated_jsx_type_argument', begin, line)

    def begin_jsx(self, return_mode):
        begin, line = self.i, self.line
        self.jsx_closing = self.source.startswith('</', self.i)
        self.i += 2 if self.jsx_closing else 1
        start = self.i
        while self.i < len(self.source) and (identifier_part(self.source[self.i]) or self.source[self.i] in '.:-'):
            self.i += 1
        self.jsx_tag, self.jsx_return, self.jsx_head = self.source[start:self.i], return_mode, self.i
        self.emit('jsx', self.source[begin:self.i], begin, line)
        self.mode = 'jsx_tag'

    def jsx(self):
        source, begin, line = self.source, self.i, self.line
        ch = source[self.i]
        if ch == '<' and self.mode == 'jsx_tag' and self.tsx:
            self.jsx_type_arguments()
        elif ch == '{':
            self.i += 1
            self.emit('punct', '{', begin, line, 'jsx_expression')
            # Keep the enclosing tag's state: a JSX element inside the expression overwrites it.
            self.push('}', 'jsx_expression', (self.mode, self.jsx_tag, self.jsx_return, self.jsx_closing, self.jsx_head))
            self.mode, self.expr, self.statement, self.previous = 'code', True, False, '{'
        elif self.mode == 'jsx_text':
            if ch == '<':
                self.begin_jsx('jsx_text')
            else:
                while self.i < len(source) and source[self.i] not in '<{':
                    self.i += 1
                self.line += line_breaks(source[begin:self.i])
                self.emit('jsx', source[begin:self.i], begin, line)
        elif ch in '\"\'':
            quote = ch
            self.i += 1
            while self.i < len(source) and source[self.i] != quote:
                self.i += 1
            if self.i >= len(source):
                self.error('syntax:unterminated_jsx_attribute')
            self.i += 1
            self.line += line_breaks(source[begin:self.i])
            self.emit('jsx', source[begin:self.i], begin, line)
        elif ch == '>' or source.startswith('/>', self.i):
            self_closing = ch == '/'
            self.i += 2 if self_closing else 1
            if self.jsx_closing:
                if not self.jsx_elements or self.jsx_elements[-1][0] != self.jsx_tag:
                    self.error('syntax:mismatched_jsx_tag')
                _, self.mode = self.jsx_elements.pop()
            elif self_closing:
                self.mode = self.jsx_return
            else:
                if len(self.jsx_elements) + len(self.frames) >= MAX_DEPTH:
                    self.error('limit:depth')
                self.jsx_elements.append((self.jsx_tag, self.jsx_return))
                self.mode = 'jsx_text'
                if self.tsx and self.generic_signature_tag(begin):
                    self.error('unsupported_lexical_context:tsx_generic_or_jsx')
            self.emit('jsx', source[begin:self.i], begin, line)
            self.expr, self.statement, self.previous = False, False, 'jsx'
        else:
            self.line += ch in '\r\n\u2028\u2029' and not (ch == '\n' and self.i and source[self.i - 1] == '\r')
            self.i += 1
            self.emit('jsx', ch, begin, line)

    def generic_signature_tag(self, end):
        """Whether the opening tag whose `>` is at `end` may be a generic signature `<T>(x: T) => T` in a type.

        Read as JSX, the code up to a matching `</T>` would be JSX text. So is a tag that ended inside a comment
        in its head (`<T/*>*/>`), whose real end the lexer cannot see. A dotted, dashed or namespaced name
        cannot be a type parameter, and parenthesized text followed by a child element or expression
        (`(optional)</b>`, `({count})</span>`) is JSX, as a signature's parameters are never followed so.
        """
        head = _QUOTED.sub('', self.source[self.jsx_head:end])
        if _OPEN_COMMENT.search(head):
            return True
        if any(ch in self.jsx_tag for ch in '.-:'):
            return False
        head = _COMMENT.sub(' ', head)
        start = _SIGNATURE_START.match(self.source, self.i)
        return bool(start and _GENERIC_HEAD.match(head)) and not self.jsx_parenthesized_text(start.end())

    def jsx_parenthesized_text(self, cursor):
        """Whether the text after a `(` ending at `cursor` closes its parentheses before a child element or expression.

        Quoted strings and comments are skipped so that they cannot close the parentheses early; an unmatched
        quote, a template literal or a scan past _SIGNATURE_SCAN characters counts as a signature.
        """
        source, depth = self.source, 1
        limit = min(len(source), cursor + _SIGNATURE_SCAN)
        while cursor < limit:
            ch = source[cursor]
            skip = (_QUOTED if ch in '"\'' else _COMMENT if ch == '/' else None)
            match = skip.match(source, cursor) if skip else None
            if match:
                cursor = match.end()
                continue
            if ch in '"\'`':
                return False
            depth += (ch == '(') - (ch == ')')
            cursor += 1
            if not depth:
                while cursor < limit and source[cursor].isspace():
                    cursor += 1
                return cursor < limit and source[cursor] in '<{'
        return False
