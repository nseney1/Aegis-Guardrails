"""Bounded, iterative lexical modes for JavaScript, TypeScript and JSX."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import NamedTuple

from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.drivers.js.values import (
    decode_string,
    identifier_part,
    identifier_start,
    unicode_escape,
)

__all__ = ['MAX_DEPTH', 'MAX_SOURCE_BYTES', 'JSLexError', 'Token', 'tokenize']
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 256
_IDENT = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')
_D = r'\d(?:_?\d)*'
_NUMBER = re.compile(r'(?:0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*n?|0[bB][01](?:_?[01])*n?|0[oO][0-7](?:_?[0-7])*n?|(?:0|[1-9](?:_?\d)*)(?:\.(?:' + _D + r')?)?(?:[eE][+-]?' + _D + r')?n?|\.' + _D + r'(?:[eE][+-]?' + _D + r')?)')
_OPS = ('>>>=', '===', '!==', '**=', '&&=', '||=', '??=', '>>>', '...', '=>', '?.', '++', '--', '**', '&&', '||', '??', '==', '!=', '<=', '>=', '<<', '>>', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=')
_OPERATOR = re.compile('|'.join(re.escape(operator) for operator in _OPS))
_CODE_TAIL = r'(?P<number>' + _NUMBER.pattern + r')|(?P<slash>/(?![/*])=?)|(?P<punct>' + '|'.join(re.escape(op) for op in _OPS if op[0] not in '/<') + '|[' + re.escape('()[]{};,:.?=+-*%&|^!~>@') + '])'
_WHITESPACE_PREFIX = r'(?P<prefix>[ \t\r\n\f\v]*)(?:'
_WHITESPACE_FALLBACK = r')|(?P<space>[ \t\r\n\f\v]+)'
_CODE = re.compile(_WHITESPACE_PREFIX + r'(?P<word>[A-Za-z_$][A-Za-z0-9_$]*)|' + _CODE_TAIL + _WHITESPACE_FALLBACK)
_CONTROL = frozenset(('if', 'while', 'for', 'switch', 'with', 'catch'))
_METHOD_PREFIX = frozenset(('{', ',', 'get', 'set', 'async', '*'))
# `*`, `++` and `--` take the structural path: generator markers and restricted-production ASI need context.
_FAST_OPERATORS = frozenset((';', ',', '=', '.', '?.', '+', '-', '>', '>>', '>>>', '&&', '||', '??', '==', '!=', '===', '!==', '+=', '-=', '*=', '%=', '&', '|', '^', '~', '&=', '|=', '^=', '**', '**=', '&&=', '||=', '??='))
_PREFIX = frozenset(('return', 'throw', 'yield', 'await', 'delete', 'typeof', 'void', 'new', 'in', 'instanceof', 'case'))
# Words that sloppy scripts may also use as identifiers, so a following `/` or `<` is ambiguous.
_CONTEXTUAL_OPERANDS = frozenset(('await', 'yield', 'let'))
_NON_LABEL = _PREFIX | _CONTROL | {'const', 'let', 'var', 'function', 'class', 'export', 'default', 'try', 'else', 'do', 'finally'}
_TYPE_DECLARATIONS = frozenset(('interface', 'enum', 'namespace', 'module'))
_TYPE_BODIES = _TYPE_DECLARATIONS | {'function', 'class'}
_SYNTAX_WORDS = _NON_LABEL | _TYPE_DECLARATIONS | {'break', 'continue', 'async', 'declare', 'abstract', 'import'}
_LINE_END = re.compile(r'[\r\n\u2028\u2029]')
_STRING_MARKS = {'"': re.compile(r'["\\\r\n\u2028\u2029]'), "'": re.compile(r"['\\\r\n\u2028\u2029]")}
_TEMPLATE_MARKS = re.compile(r'\\[\s\S]?|`|\$\{')
_TEMPLATE_CHUNK_EDGE = re.compile(r'\\|`|\$\{|[\r\n\u2028\u2029]')
_SIMPLE = r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*'
# Each blank run is optional at exactly one position, so a failed match backtracks in linear time.
_FLAT_ARGUMENTS = r'[ \t]*(?:' + _SIMPLE + r'(?:[ \t]*,[ \t]*' + _SIMPLE + r')*[ \t]*)?'
_DECLARATION = r'(?P<decl_word>const|let|var)[ \t]+(?P<decl_name>' + _IDENT.pattern + r')[ \t]*=(?!=|>)'
_COMPACT_CODE = re.compile(_WHITESPACE_PREFIX + r'(?P<declaration>' + _DECLARATION + r')|(?P<reference>' + _SIMPLE + r')(?P<call>\((?P<arguments>' + _FLAT_ARGUMENTS + r')\))?(?P<delimiter>[ \t]*[;,])?|' + _CODE_TAIL + _WHITESPACE_FALLBACK)
_GROUP = re.compile(r'(?P<opens>\({3,})(?P<body>' + _SIMPLE + r'(?:\(' + _FLAT_ARGUMENTS + r'\))?)(?P<closes>\){3,})')
_PAREN_RUN = re.compile(r'\(+')
_PLAIN_QUOTED = r'''(?:"[^"\\\r\n\u2028\u2029]*"|'[^'\\\r\n\u2028\u2029]*')'''
_PLAIN_REGEX = r'/(?![/*])(?:\\[^\r\n\u2028\u2029]|\[(?:\\[^\r\n\u2028\u2029]|[^\\\]\r\n\u2028\u2029])*\]|[^/\\\[\r\n\u2028\u2029])+/'
_SAFE_WORD = r'(?!(?:' + '|'.join(sorted(_SYNTAX_WORDS)) + r')\b)[A-Za-z_$][A-Za-z0-9_$]*'
_PLAIN_REF = _SAFE_WORD + r'(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*'
_PLAIN_ATOM = rf'(?:{_PLAIN_QUOTED}|{_PLAIN_REGEX}|(?:0|[1-9][0-9]*)|{_PLAIN_REF})'
_PLAIN_PROPERTY = r'(?:\.\.\.' + _PLAIN_REF + r'|(?:[A-Za-z_$][A-Za-z0-9_$]*|' + _PLAIN_QUOTED + r')[ \t]*:[ \t]*' + _PLAIN_ATOM + '|' + _SAFE_WORD + ')'
_FLAT_OBJECT = re.compile(r'{[ \t]*(?:' + _PLAIN_PROPERTY + r'(?:[ \t]*,[ \t]*' + _PLAIN_PROPERTY + r')*[ \t]*(?:,[ \t]*)?)?}')
_CONST_ENUM = re.compile(r'[ \t\r\n\f\v]+enum(?![\w$\\])')
_PLAIN_QUOTED_MATCH = re.compile(_PLAIN_QUOTED)
# Characters a JSX attribute list may contain; a TSX generic built only from them is also a JSX tag.
_JSX_ATTRIBUTE_RUN = re.compile(r'[A-Za-z0-9_$.,:\-\[\]|& \t\r\n\f\v]*')
_JSX_CLOSING_NAME = re.compile(r'</\s*([A-Za-z_$][A-Za-z0-9_$]*)')
_JSX_TYPE_ARGUMENT = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.,[]|& \t\r\n')


def line_breaks(text):
    return text.count('\n') + text.count('\r') - text.count('\r\n') + text.count('\u2028') + text.count('\u2029')


class JSLexError(ASTDriverError):
    def __init__(self, reason, line, offset):
        self.reason, self.line, self.offset = reason, line, offset
        super().__init__(f'{reason} at line {line}, offset {offset}')


class Token(NamedTuple):
    kind: str
    value: str
    line: int
    start: int
    end: int
    role: str = ''
    arguments: tuple | None = None


# The public NamedTuple is unchanged; avoid its Python __new__ wrapper per token.
_TOKEN_NEW = tuple.__new__


class Lexer:
    def __init__(self, source, path, *, compact=False):
        self.source, self.path, self.i, self.line = source, path, 0, 1
        self.compact = compact
        self.tokens, self.frames, self.jsx_elements = [], [], []
        self.mode, self.expr, self.statement, self.previous = 'code', True, True, ''
        self.control, self.function, self.body, self.class_pending = False, None, None, None
        self.declaration_prefix, self.decorator_prefix = False, False
        self.class_fields = {}
        self.module_clause, self.type_angles = None, 0
        self.label_pending, self.case_pending, self.ternaries = False, False, {}
        self.jsx_tag, self.jsx_closing, self.jsx_return = '', False, 'code'
        extension = PurePosixPath(path).suffix.lower()
        self.typescript = extension in ('.ts', '.tsx', '.mts', '.cts')
        self.jsx_allowed = extension in ('.jsx', '.tsx', '.js', '.mjs', '.cjs')
        self.tsx, self.module_goal = extension == '.tsx', extension in ('.mjs', '.mts')
        # (token count, source offset) right after an arrow body's `}`; see operand_start.
        self.arrow_close, self.closing_names = None, None
        # (end of the `(` run, `)` count or -1) of the last failed transparent-group attempt.
        self.group_skip = (-1, -1)
        self.generator_pending, self.body_generator, self.class_kind = None, False, None
        # Frame depths: generator parameters/bodies, strict class bodies, concise arrows, for-statement heads.
        self.generator_frames, self.strict_frames, self.arrow_markers, self.for_heads = set(), set(), set(), set()

    def error(self, reason, offset=None, line=None):
        raise JSLexError(reason, self.line if line is None else line, self.i if offset is None else offset)

    def emit(self, kind, value, begin, line, role=''):
        self.tokens.append(_TOKEN_NEW(Token, (kind, value, line, begin, self.i, role, None)))

    def push(self, close, role, resume='code'):
        if len(self.frames) + len(self.jsx_elements) >= MAX_DEPTH:
            self.error('limit:depth')
        self.frames.append((close, role, resume))

    def run(self):
        source = self.source
        size = len(source)
        if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
            self.error('too_large')
        while self.i < size:
            if self.mode == 'code':
                self.code()
            elif self.mode == 'template':
                self.template()
            else:
                self.jsx()
        if self.mode == 'template' or any(f[1] == 'template' for f in self.frames):
            self.error('syntax:unterminated_template')
        if self.jsx_elements or self.mode.startswith('jsx'):
            self.error('syntax:unterminated_jsx')
        if self.frames:
            self.error('syntax:unclosed_delimiter')
        if self.class_pending:
            self.error('syntax:incomplete_class')
        if self.function:
            self.error('syntax:incomplete_function')
        return self.tokens

    def code(self):
        source, tokens, frames = self.source, self.tokens, self.frames
        scanner = (_COMPACT_CODE if self.compact else _CODE).scanner(source, self.i)
        size = len(source)
        while match := scanner.match():
            match_end = scan_end = match.end()
            begin, end, kind = self.i, match_end, match.lastgroup
            delimiter = kind == 'delimiter'
            if delimiter:
                kind = 'call' if match['call'] else 'reference'
                end = match_end = match.end(kind)
            prefix = match['prefix']
            if prefix:
                if '\n' in prefix or '\r' in prefix:
                    self.line += prefix.count('\n') + prefix.count('\r') - prefix.count('\r\n')
                begin += len(prefix)
                self.i = begin
            if kind == 'declaration':
                if self.compact_declaration(match, begin, end):
                    continue
                kind, value, end = 'word', match['decl_word'], match.end('decl_word')
            else:
                value = match['reference'] if kind == 'call' else match[kind]
            if kind in ('word', 'reference', 'call'):
                end = match.end('reference') if kind == 'call' else end
                dotted = '.' in value
                head = value.split('.', 1)[0] if dotted else value
                if self.class_fields:
                    self.class_member_line(head)
                if end < size and (source[end] == '\\' or ord(source[end]) > 127):
                    self.identifier()
                    return
                syntax_word = head in _SYNTAX_WORDS
                if syntax_word:
                    value, end, dotted = head, begin + len(head), False
                elif kind == 'call' and self.compact_call(value, match['arguments'], match_end):
                    if delimiter and not self.fast_operator(match['delimiter'][-1], scan_end - 1, scan_end):
                        return
                    continue
                self.i = end
                role = 'reference' if dotted else (self.identifier_role() if syntax_word else '')
                tokens.append(_TOKEN_NEW(Token, ('identifier', value, self.line, begin, end, role, None)))
                if syntax_word:
                    self.after_word(value)
                else:
                    self.label_pending, self.expr, self.statement = self.statement and role != 'reference', False, False
                    self.declaration_prefix, self.previous = False, value.rsplit('.', 1)[-1] if dotted else value
                if end != match_end:
                    return
                if delimiter:
                    if syntax_word or not self.fast_operator(match['delimiter'][-1], scan_end - 1, scan_end):
                        return
            elif kind == 'space':
                if '\n' in value or '\r' in value:
                    self.line += value.count('\n') + value.count('\r') - value.count('\r\n')
                self.i = end
            elif kind == 'number':
                if self.class_fields:
                    self.class_member_line('')
                self.number(match, value)
            elif kind == 'slash':
                self.operand_start('/')
                if self.i != end:
                    return
            else:
                if value in _FAST_OPERATORS and self.body is None and not self.class_fields:
                    tokens.append(_TOKEN_NEW(Token, ('punct', value, self.line, begin, end, '', None)))
                    self.i, self.previous = end, value
                    self.expr = value not in ('.', '?.')
                    self.statement = value == ';'
                    if value == ';':
                        self.declaration_prefix, self.module_clause = False, None
                    if self.arrow_markers or self.module_clause:
                        self.after_operator(value)
                elif value == '{' and self.compact and self.compact_object():
                    return
                elif value == '(' and self.compact and self.expr and not self.control and self.function is None and self.body is None and source.startswith('(((', begin) and self.compact_group():
                    return
                elif value == '(' and not self.control and self.function is None and self.previous != 'import' and (not frames or frames[-1][1] not in ('class_decl', 'class_expr', 'object')):
                    if len(frames) + len(self.jsx_elements) >= MAX_DEPTH:
                        self.error('limit:depth')
                    frames.append((')', 'expression', 'code'))
                    self.i = end
                    tokens.append(_TOKEN_NEW(Token, ('punct', '(', self.line, begin, end, 'expression', None)))
                    self.expr, self.statement, self.previous = True, False, '('
                elif value == ')' and frames and frames[-1][1] == 'expression':
                    frames.pop()
                    if self.arrow_markers:
                        self.arrow_markers.discard(len(frames) + 1)
                    self.i = end
                    tokens.append(_TOKEN_NEW(Token, ('punct', ')', self.line, begin, end, 'expression', None)))
                    self.expr, self.statement, self.previous = False, False, ')'
                else:
                    self.punctuation(value)
                if self.mode != 'code':
                    return
        if self.i < size:
            self.code_boundary()

    def fast_operator(self, value, begin, end):
        """Share the ordinary punctuation transition with co-scanned delimiters."""
        if value not in _FAST_OPERATORS or self.body is not None or self.class_fields:
            return False
        self.tokens.append(_TOKEN_NEW(Token, ('punct', value, self.line, begin, end, '', None)))
        self.i, self.previous = end, value
        self.expr, self.statement = value not in ('.', '?.'), value == ';'
        if value == ';':
            self.declaration_prefix, self.module_clause = False, None
        if self.arrow_markers or self.module_clause:
            self.after_operator(value)
        return True

    def code_boundary(self):
        source, i = self.source, self.i
        ch = source[i]
        if (i == 0 and ch == '\ufeff') or ch.isspace():
            self.line += ch in '\u2028\u2029'
            self.i += 1
        elif ch == '#' and (i == 0 or (i == 1 and source[0] == '\ufeff')) and source.startswith('#!', i) or ch == '/' and source.startswith('//', i):
            self.comment(False)
        elif ch == '/' and source.startswith('/*', i):
            self.comment(True)
        elif ch in '\"\'':
            if self.class_fields:
                self.class_member_line('')
            self.string()
        elif ch == '`':
            self.i += 1
            self.emit('template_start', '`', i, self.line)
            self.push('`', 'template', 'tagged' if not self.expr else 'literal')
            self.mode = 'template'
        elif ch.isdigit() or (ch == '.' and i + 1 < len(source) and source[i + 1].isdigit()):
            self.number()
        elif ch in '\\#' or (ord(ch) > 127 and identifier_start(ch)):
            self.identifier()
        elif ch in '/<':
            self.operand_start(ch)
        else:
            self.punctuation()

    def operand_start(self, ch):
        """Read `/` or `<` as a regex/JSX start or an operator; ambiguous contexts fail closed (AC-35)."""
        source, i = self.source, self.i
        if ch == '<' and source.startswith('<!--', i):
            self.error('unsupported_lexical_context:html_comment')  # an Annex B comment only in scripts
        start = ch == '/' or self.jsx_allowed
        if start and self.arrow_close is not None and self.after_arrow_body():
            # An arrow function is never a binary operand; only ASI can make this a new statement.
            if _LINE_END.search(source, self.arrow_close[1], i) is None:
                self.error('unsupported_lexical_context:arrow_body_operator')
            self.expr = self.statement = True
        elif start and self.expr and self.previous in _CONTEXTUAL_OPERANDS and not self.keyword_operand():
            self.error('unsupported_lexical_context:contextual_' + self.previous)
        elif start and not self.expr and self.previous == 'of' and self.for_of_keyword():
            self.expr = True
        if ch == '/' and self.expr:
            if self.typescript and self.previous in ('>', '>>', '>>>'):
                self.error('unsupported_lexical_context:type_angle_slash')
            self.regex()
        elif ch == '<' and self.jsx_allowed and self.expr and self.jsx_candidate():
            self.begin_jsx('code')
        elif ch == '/' and self.body is None and not self.class_fields:
            operator = '/=' if source.startswith('/=', i) else '/'
            self.i += len(operator)
            self.emit('punct', operator, i, self.line)
            if self.arrow_markers or self.module_clause:
                self.after_operator(operator)
            self.expr, self.statement, self.previous = True, False, operator
        else:
            self.punctuation()

    def after_arrow_body(self):
        """True while only comments follow the `}` that closed an arrow function body."""
        tokens = self.tokens
        for index in range(self.arrow_close[0], len(tokens)):
            if tokens[index].kind != 'comment':
                self.arrow_close = None
                return False
        return True

    def keyword_operand(self):
        """Prove that `await`/`yield` is an operator, not a sloppy-script identifier."""
        word = self.previous
        if word == 'let':
            return False  # `let` cannot start a declaration with `/` or `<`; it is an identifier or invalid
        if self.module_goal:
            return True  # .mjs/.mts are modules: both words are reserved
        if word == 'await':
            return False
        if self.strict_frames:
            return True  # class code is strict: `yield` is reserved
        depth = len(self.frames)
        while depth and depth not in self.arrow_markers:  # a concise arrow body hides the generator
            role = self.frames[depth - 1][1]
            if role in ('function_decl', 'function_expr'):
                return depth in self.generator_frames
            if role == 'function_arrow' or role.startswith('parameters_'):
                return False
            depth -= 1
        return False

    def for_of_keyword(self):
        """True when the identifier `of` just read is the keyword of a `for (… of …)` head."""
        if not self.frames or self.frames[-1][1] != 'control' or len(self.frames) not in self.for_heads:
            return False
        tokens, index, run = self.tokens, len(self.tokens) - 1, 0
        while tokens[index].kind == 'comment' or (tokens[index].kind == 'identifier' and tokens[index].value == 'of' and not tokens[index].role):
            run += tokens[index].kind != 'comment'
            index -= 1
        before = tokens[index]
        if before.kind in ('identifier', 'flat_call') and before.value not in _SYNTAX_WORDS or before.kind == 'punct' and before.value in (')', ']', '}'):
            return run == 1  # `for (x of …)`: the first `of` after a complete binding target
        if before.kind == 'punct' and before.value == '(' or before.kind == 'identifier' and before.value in ('var', 'let', 'const'):
            return run == 2  # `for (of of …)` / `for (const of of …)`
        return False

    def compact_declaration(self, match, begin, end):
        """Coalesce scanner work, retaining the same three ordinary declaration tokens."""
        word, name = match['decl_word'], match['decl_name']
        if (not self.statement or self.body is not None or self.function is not None or self.control
                or self.class_fields or self.module_clause or self.decorator_prefix or self.declaration_prefix
                or self.class_pending or self.type_angles or self.label_pending or self.case_pending
                or self.generator_frames or self.strict_frames or self.arrow_markers or self.for_heads
                or self.previous in ('.', '?.', ':') or name in _SYNTAX_WORDS
                or self.frames and self.frames[-1][1] not in ('block', 'function_decl', 'function_expr', 'function_arrow')):
            return False
        self.tokens.extend((
            _TOKEN_NEW(Token, ('identifier', word, self.line, begin, match.end('decl_word'), '', None)),
            _TOKEN_NEW(Token, ('identifier', name, self.line, match.start('decl_name'), match.end('decl_name'), '', None)),
            _TOKEN_NEW(Token, ('punct', '=', self.line, end - 1, end, '', None)),
        ))
        self.i, self.expr, self.statement, self.previous = end, True, False, '='
        self.label_pending, self.declaration_prefix = False, False
        return True

    def compact_call(self, word, raw_arguments, end):
        """Cache an unambiguous flat call while retaining every normalized fact."""
        if self.control or self.function is not None or self.body is not None or self.module_clause or self.decorator_prefix or word == 'require' or self.previous == '?.':
            return False
        depth = len(self.frames)
        parent = self.frames[-1][1] if depth else ''
        if parent in ('class_decl', 'class_expr') and not self.class_fields.get(depth):
            return False
        if parent == 'object' and self.previous in _METHOD_PREFIX:
            return False
        trimmed = raw_arguments.strip()
        if ',' in trimmed:
            arguments = tuple(part.strip() for part in trimmed.split(','))
            if any(part.split('.', 1)[0] in _SYNTAX_WORDS for part in arguments):
                return False
        else:
            if trimmed.split('.', 1)[0] in _SYNTAX_WORDS:
                return False
            arguments = (trimmed,) if trimmed else ()
        if depth + len(self.jsx_elements) >= MAX_DEPTH:
            self.error('limit:depth')
        if self.previous != '.':
            self.tokens.append(_TOKEN_NEW(Token, ('flat_call', word, self.line, self.i, end, 'expression', arguments)))
            self.i, self.expr, self.statement, self.previous = end, False, False, ')'
            self.declaration_prefix = False
            return True
        cursor, parts, literal = len(self.tokens), [word], None
        while cursor >= 2 and self.tokens[cursor - 1].kind == 'punct' and self.tokens[cursor - 1].value == '.' and self.tokens[cursor - 2].kind == 'identifier':
            parts.append(self.tokens[cursor - 2].value)
            cursor -= 2
        if self.previous == '.' and len(parts) == 1:
            if cursor >= 2 and self.tokens[cursor - 1].kind == 'punct' and self.tokens[cursor - 1].value == '.' and self.tokens[cursor - 2].kind in ('regex', 'string', 'number'):
                literal = self.tokens[cursor - 2]
                cursor -= 1
            else:
                return False  # a computed/factory receiver needs the structural path
        if parts[-1] in _SYNTAX_WORDS:
            return False
        before = self.tokens[cursor - 1].value if cursor else ''
        if parent == 'object' and before in _METHOD_PREFIX:
            return False
        first = literal or (self.tokens[cursor] if cursor < len(self.tokens) else None)
        line, begin = (first.line, first.start) if first else (self.line, self.i)
        del self.tokens[cursor:]
        target = ('.' if literal else '') + '.'.join(reversed(parts))
        self.tokens.append(_TOKEN_NEW(Token, ('flat_call', target, line, begin, end, 'expression', arguments)))
        self.i, self.expr, self.statement, self.previous = end, False, False, ')'
        self.declaration_prefix = False
        return True

    def compact_object(self):
        """Keep a call-free, mutation-free object atom for lazy field extraction."""
        if not self.expr or self.statement or self.control or self.function is not None or self.body or self.class_pending or self.module_clause or self.previous in ('=>', 'const', 'let', 'var'):
            return False
        match = _FLAT_OBJECT.match(self.source, self.i)
        if not match:
            return False
        cursor = self.after_trivia(match.end())
        if cursor < len(self.source) and (self.source[cursor] == ':' or (self.source[cursor] == '=' and not self.source.startswith(('==', '=>'), cursor))):
            return False  # a binding/assignment pattern needs its structural tokens
        if len(self.frames) + len(self.jsx_elements) >= MAX_DEPTH:
            self.error('limit:depth')
        self.tokens.append(_TOKEN_NEW(Token, ('flat_object', match[0], self.line, self.i, match.end(), 'object', None)))
        self.i, self.expr, self.statement, self.previous = match.end(), False, False, '}'
        return True

    def after_trivia(self, cursor):
        source = self.source
        while cursor < len(source):
            if source[cursor].isspace():
                cursor += 1
            elif source.startswith('/*', cursor):
                closing = source.find('*/', cursor + 2)
                if closing < 0:
                    return cursor
                cursor = closing + 2
            elif source.startswith('//', cursor):
                closing = _LINE_END.search(source, cursor + 2)
                cursor = closing.end() if closing else len(source)
            else:
                break
        return cursor

    def compact_group(self):
        """Normalize only transparent groups around one flat atom/simple call.

        Parentheses around operators, nested calls, comments, strings and arrows
        are untouched. The original depth is checked before omitting redundant
        delimiters; public tokenization retains every delimiter by default.
        """
        run_end, closes = self.group_skip
        if self.i < run_end and (closes < 0 or run_end - self.i > closes):
            return False  # this `(` run already failed for every start at least this far from its end
        match = _GROUP.match(self.source, self.i)
        if not match:
            self.group_skip = (_PAREN_RUN.match(self.source, self.i).end(), -1)
            return False
        if len(match['closes']) < len(match['opens']):
            self.group_skip = (match.start('body'), len(match['closes']))
            return False
        body, depth = match['body'], len(match['opens'])
        if any(m[0] in _SYNTAX_WORDS for m in _IDENT.finditer(body)):
            self.group_skip = (match.start('body'), -1)
            return False
        if len(self.frames) + len(self.jsx_elements) + depth + ('(' in body) > MAX_DEPTH:
            self.error('limit:depth')
        start, end = self.i, match.start('closes') + depth
        self.tokens.append(_TOKEN_NEW(Token, ('punct', '(', self.line, start, start + 1, 'expression', None)))
        opening = body.find('(')
        if opening >= 0 and body[:opening] != 'require':
            raw_arguments = body[opening + 1:-1]
            arguments = tuple(part.strip() for part in raw_arguments.split(',')) if raw_arguments.strip() else ()
            self.tokens.append(_TOKEN_NEW(Token, ('flat_call', body[:opening], self.line, match.start('body'),
                                                 match.end('body'), 'expression', arguments)))
        elif opening < 0:
            self.tokens.append(_TOKEN_NEW(Token, ('identifier', body, self.line, match.start('body'),
                                                 match.end('body'), 'reference' if '.' in body else '', None)))
        else:
            # require() still needs structural import/binding extraction.
            for token in Lexer(body, self.path, compact=True).run():
                self.tokens.append(_TOKEN_NEW(Token, (token.kind, token.value, self.line,
                                                     match.start('body') + token.start,
                                                     match.start('body') + token.end, token.role, token.arguments)))
        self.tokens.append(_TOKEN_NEW(Token, ('punct', ')', self.line, end - 1, end, 'expression', None)))
        self.i, self.expr, self.statement, self.previous = end, False, False, ')'
        self.declaration_prefix = False
        return True

    def comment(self, block):
        begin, line = self.i, self.line
        if block:
            end = self.source.find('*/', begin + 2)
        else:
            terminator = _LINE_END.search(self.source, begin)
            end = terminator.start() if terminator else -1
        if block and end < 0:
            self.error('syntax:unterminated_comment')
        self.i = end + 2 if block else (len(self.source) if end < 0 else end)
        text = self.source[begin:self.i]
        self.line += line_breaks(text)
        self.emit('comment', text, begin, line)

    def string(self):
        source, begin, line = self.source, self.i, self.line
        quote = source[self.i]
        marks = _STRING_MARKS[quote]
        self.i += 1
        while True:
            marker = marks.search(source, self.i)
            if marker is None:
                self.error('syntax:unterminated_string', begin, line)
            self.i = marker.start()
            ch = source[self.i]
            if ch == quote:
                break
            if ch in '\r\n\u2028\u2029':
                self.error('syntax:unterminated_string', begin, line)
            self.i += 1
            if self.i >= len(source):
                self.error('syntax:unterminated_string', begin, line)
            if source.startswith('\r\n', self.i):
                self.i += 1
            if source[self.i] in '\n\r\u2028\u2029':
                self.line += 1
            self.i += 1
        self.i += 1
        try:
            value = decode_string(source[begin:self.i])
        except ValueError as exc:
            self.error(str(exc), begin, line)
        self.emit('string', value, begin, line)
        self.module_clause = None
        self.expr, self.statement, self.previous = False, False, 'string'

    def number(self, match=None, raw=None):
        begin = self.i
        match = _NUMBER.match(self.source, begin) if match is None else match
        if match is None:
            self.error('syntax:invalid_number')
        self.i = match.end()
        raw = match[0] if raw is None else raw
        bigint_float = raw.endswith('n') and ('.' in raw or ('e' in raw.lower() and not raw.lower().startswith(('0x', '0b', '0o'))))
        if (self.i < len(self.source) and (identifier_part(self.source[self.i]) or self.source[self.i] == '\\')) or bigint_float:
            self.error('syntax:invalid_number', begin)
        self.emit('number', raw, begin, self.line)
        self.expr, self.statement, self.previous = False, False, 'number'

    def identifier(self):
        begin, line, output = self.i, self.line, []
        private = self.source[self.i] == '#'
        self.i += private
        match = _IDENT.match(self.source, self.i)
        if match:
            output.append(match[0])
            self.i = match.end()
        tail = not match or (self.i < len(self.source) and (self.source[self.i] == '\\' or ord(self.source[self.i]) > 127))
        while tail and self.i < len(self.source):
            ch = self.source[self.i]
            if ch == '\\':
                try:
                    ch, end = unicode_escape(self.source, self.i)
                except ValueError as exc:
                    self.error('syntax:invalid_identifier:' + str(exc))
                if not (identifier_part(ch) if output else identifier_start(ch)):
                    self.error('syntax:invalid_identifier')
                output.append(ch)
                self.i = end
            elif (identifier_part(ch) if output else identifier_start(ch)):
                output.append(ch)
                self.i += 1
            else:
                break
        if not output:
            self.error('syntax:invalid_identifier')
        word = ('#' if private else '') + ''.join(output)
        if self.class_fields:
            self.class_member_line(word)
        self.emit('identifier', word, begin, line, self.identifier_role() if word in _SYNTAX_WORDS else '')
        self.after_word(word)

    def class_member_line(self, word):
        depth = len(self.frames)
        if self.class_fields.get(depth) and not self.expr and self.tokens and self.tokens[-1].line < self.line and word not in ('in', 'instanceof', 'as', 'satisfies'):
            self.class_fields[depth] = False

    def identifier_role(self):
        if self.frames and self.frames[-1][1] == 'module':
            return 'module_binding'
        if self.previous in ('.', '?.'):
            return 'property_name'
        if self.frames and self.frames[-1][1] in ('class_decl', 'class_expr', 'object') and self.previous in ('{', ',', ';', 'get', 'set', 'static', 'async', '*'):
            cursor = self.i
            while cursor < len(self.source) and self.source[cursor].isspace():
                cursor += 1
            if cursor < len(self.source) and self.source[cursor] in ':(=;?!}':
                return 'property_name'
        return ''

    def after_word(self, word):
        declaration = self.statement or self.declaration_prefix
        if self.tokens[-1].role in ('module_binding', 'property_name'):
            self.expr, self.statement, self.previous = False, False, word
            return
        self.label_pending = self.statement and word not in _NON_LABEL
        if word == 'case' or (word == 'default' and self.previous != 'export' and self.statement):
            self.case_pending = True
        if word in ('import', 'export') and self.statement:
            self.module_clause = word
        elif self.module_clause == 'export' and word in _TYPE_DECLARATIONS | {'const', 'let', 'var', 'function', 'class', 'default'}:
            self.module_clause = None
        type_declaration = self.typescript and word in _TYPE_DECLARATIONS and (self.statement or self.declaration_prefix)
        if type_declaration:
            cursor = self.i
            while cursor < len(self.source) and self.source[cursor].isspace():
                cursor += 1
            type_declaration = cursor < len(self.source) and self.source[cursor] not in '.?(=;,[!'
        if word in _CONTROL and self.previous not in ('.', '?.'):
            self.control = True
            self.expr, self.statement = True, False
        elif word == 'function':
            self.function = (self.statement or self.declaration_prefix, len(self.frames))
            self.expr, self.statement = True, False
        elif word == 'class' or type_declaration:
            self.class_pending = (self.statement or self.declaration_prefix or self.decorator_prefix, len(self.frames), word)
            self.decorator_prefix = False
            self.expr, self.statement = True, False
        elif word in ('else', 'do', 'try', 'finally', 'break', 'continue'):
            self.expr, self.statement = True, True
        else:
            self.expr, self.statement = word in _PREFIX or word in ('const', 'let', 'var', 'default', 'import'), False
        if word in ('export', 'default', 'async', 'declare', 'abstract'):
            self.declaration_prefix = declaration if word == 'async' else True
        elif word == 'const' and declaration and self.typescript and _CONST_ENUM.match(self.source, self.i):
            self.declaration_prefix = True  # TS `const enum E {}` is a declaration, like `enum`
        elif word not in _TYPE_BODIES:
            self.declaration_prefix = False
        self.previous = word

    def regex(self):
        begin, line, in_class = self.i, self.line, False
        self.i += 1
        while self.i < len(self.source):
            ch = self.source[self.i]
            if ch in '\r\n\u2028\u2029':
                self.error('syntax:unterminated_regex', begin, line)
            if ch == '\\':
                if self.i + 1 >= len(self.source) or self.source[self.i + 1] in '\r\n\u2028\u2029':
                    self.error('syntax:unterminated_regex', begin, line)
                self.i += 2
                continue
            if ch == '[':
                in_class = True
            elif ch == ']':
                in_class = False
            elif ch == '/' and not in_class:
                self.i += 1
                break
            self.i += 1
        else:
            self.error('syntax:unterminated_regex', begin, line)
        flag = self.i
        while self.i < len(self.source) and identifier_part(self.source[self.i]):
            self.i += 1
        flags = self.source[flag:self.i]
        if len(set(flags)) != len(flags) or any(c not in 'dgimsuvy' for c in flags) or ('u' in flags and 'v' in flags):
            self.error('syntax:invalid_regex_flags', begin, line)
        self.emit('regex', self.source[begin:self.i], begin, line)
        self.expr, self.statement, self.previous = False, False, 'regex'

    def template(self):
        begin, line = self.i, self.line
        edge = _TEMPLATE_CHUNK_EDGE.search(self.source, self.i) if self.compact else None
        simple = self.compact and (edge is None or edge[0] in ('`', '${'))
        if simple:
            self.i = edge.start() if edge else len(self.source)
            chunk = ''
        else:
            self.i = next((m.start() for m in _TEMPLATE_MARKS.finditer(self.source, self.i) if m[0][0] != '\\'), len(self.source))
            chunk = self.source[begin:self.i]
            self.line += line_breaks(chunk)
        if self.compact and self.frames[-1][2] == 'literal' and self.source.startswith('${', self.i):
            self.frames[-1] = ('`', 'template', 'interpolated')
        if simple and self.frames[-1][2] == 'literal':
            chunk = self.source[begin:self.i]
        if chunk:
            if not simple and '\\' in chunk and self.frames[-1][2] != 'tagged':
                try:
                    decode_string('`' + chunk + '`')
                except ValueError as exc:
                    self.error('syntax:template_escape:' + str(exc), begin, line)
            if not self.compact or self.frames[-1][2] == 'literal':
                self.emit('template_text', chunk, begin, line)
        if self.i >= len(self.source):
            self.error('syntax:unterminated_template', begin, line)
        begin = self.i
        if self.source[self.i] == '`':
            self.i += 1
            self.emit('template_end', '`', begin, self.line)
            self.frames.pop()
            self.mode, self.expr, self.statement, self.previous = 'code', False, False, 'template'
        else:
            self.i += 2
            self.emit('punct', '${', begin, self.line, 'interpolation')
            self.push('}', 'interpolation', 'template')
            self.mode, self.expr, self.statement, self.previous = 'code', True, False, '${'

    def brace_role(self):
        if self.previous == 'static' and self.frames and self.frames[-1][1].startswith('class'):
            return 'block'
        if self.control and self.previous == 'catch':
            self.control = False
            return 'block'
        if self.module_clause:
            return 'module'
        if self.class_pending and self.class_pending[1] == len(self.frames):
            declaration, _, kind = self.class_pending
            self.class_pending = None
            self.class_kind = kind
            if kind in ('namespace', 'module'):
                return 'block'
            return 'class_decl' if declaration else 'class_expr'
        if self.previous == '=>':
            self.body = None
            self.arrow_markers.discard(len(self.frames))
            return 'function_arrow'
        if self.body and self.previous != ':' and not self.type_angles:
            role, self.body = self.body, None
            return role
        if self.statement:
            return 'block'
        if self.expr:
            return 'object'
        self.error('unsupported_lexical_context:brace')

    def punctuation(self, operator=None):
        begin, line, ch = self.i, self.line, self.source[self.i]
        was_expr = self.expr
        if ch == '-' and self.source.startswith('-->', begin) and _LINE_END.search(self.source, self.tokens[-1].end if self.tokens else 0, begin):
            self.error('unsupported_lexical_context:html_comment')
        if ch in '([{':
            role = 'expression'
            if ch == '(':
                if self.previous == 'import':
                    self.module_clause = None
                if self.control:
                    role, self.control = 'control', False
                elif self.function is not None and self.function[1] == len(self.frames):
                    role = 'parameters_decl' if self.function[0] else 'parameters_expr'
                    self.function = None
                elif self.frames and len(self.tokens) >= 2:
                    last = len(self.tokens) - 1
                    while last >= 0 and self.tokens[last].kind == 'comment':
                        last -= 1
                    before_index = last - 1
                    while before_index >= 0 and self.tokens[before_index].kind == 'comment':
                        before_index -= 1
                    before = self.tokens[before_index].value if before_index >= 0 else ''
                    parent = self.frames[-1][1]
                    computed_key = last >= 0 and self.tokens[last].role == 'property_key'
                    if (parent.startswith('class') and not self.class_fields.get(len(self.frames))) or (parent == 'object' and (computed_key or before in _METHOD_PREFIX)):
                        role = 'parameters_method'
            elif ch == '{':
                role = self.brace_role()
            elif ch == '[':
                role = 'array' if was_expr else 'index'
                if self.frames and self.frames[-1][1] in ('class_decl', 'class_expr', 'object') and self.previous in ('{', ',', ';', 'get', 'set', 'async', '*'):
                    role = 'property_key'
            self.i += 1
            self.tokens.append(_TOKEN_NEW(Token, ('punct', ch, line, begin, self.i, role, None)))
            self.push({'(': ')', '[': ']', '{': '}'}[ch], role)
            self.open_context(role, ch)
            self.expr, self.statement, self.previous = True, ch == '{' and role != 'object', ch
            return
        if ch in ')]}':
            if not self.frames or self.frames[-1][0] != ch:
                self.error('syntax:unbalanced_delimiter')
            _, role, resume = self.frames.pop()
            if role.startswith('parameters_') or self.generator_frames or self.strict_frames or self.for_heads or self.arrow_markers:
                self.close_context(role)
            if role in ('class_decl', 'class_expr'):
                del self.class_fields[len(self.frames) + 1]
            self.i += 1
            self.tokens.append(_TOKEN_NEW(Token, ('punct', ch, line, begin, self.i, role, None)))
            if role == 'function_arrow':
                self.arrow_close = (len(self.tokens), self.i)
            if role in ('interpolation', 'jsx_expression'):
                self.mode = resume
            if role.startswith('parameters_'):
                self.body = 'function_decl' if role == 'parameters_decl' else 'function_expr'
                self.type_angles = 0
            self.statement = role in ('block', 'control', 'function_decl', 'class_decl')
            self.expr, self.previous = self.statement, ch
            return
        if operator is None:
            match = _OPERATOR.match(self.source, begin)
            operator = match[0] if match else ch
        if ch not in ';,:.?=+-*/%&|^!~<>@':
            self.error('unsupported_lexical_context:character')
        self.i += len(operator)
        self.tokens.append(_TOKEN_NEW(Token, ('punct', operator, line, begin, self.i, '', None)))
        if operator == '*' and (self.function is not None or self.frames and self.frames[-1][1] in ('object', 'class_decl', 'class_expr') and self.previous in _METHOD_PREFIX):
            self.generator_pending = len(self.frames)
        self.after_operator(operator)
        if self.body:
            if operator == '<':
                self.type_angles += 1
            elif operator in ('>', '>>', '>>>'):
                self.type_angles = max(0, self.type_angles - len(operator))
        if operator == '@':
            self.decorator_prefix = True
        if operator == ';':
            self.body, self.declaration_prefix, self.module_clause = None, False, None
        if len(self.frames) in self.class_fields and operator in ('=', ';'):
            self.class_fields[len(self.frames)] = operator == '='
        label = False
        if operator == '?':
            self.ternaries[len(self.frames)] = self.ternaries.get(len(self.frames), 0) + 1
        if operator == ':':
            count = self.ternaries.get(len(self.frames), 0)
            if count:
                self.ternaries[len(self.frames)] = count - 1
            else:
                label = self.label_pending or self.case_pending
                self.case_pending = False
        self.statement = operator == ';' or label
        line_before = next((t.line for t in reversed(self.tokens) if t.kind != 'comment' and t.start < begin), line) if operator in ('++', '--') else line
        self.expr = operator not in ('.', '?.', '++', '--') and not (operator == '!' and not was_expr)
        if operator in ('++', '--'):
            self.expr = was_expr or line_before < line
        self.previous = operator

    def open_context(self, role, ch):
        depth = len(self.frames)
        if role == 'control' and self.previous == 'for':
            self.for_heads.add(depth)
        if role.startswith('parameters_') and self.generator_pending == depth - 1:
            self.generator_frames.add(depth)
            self.generator_pending = None
        if ch == '{' and role.startswith('function_') and self.body_generator:
            self.generator_frames.add(depth)
            self.body_generator = False
        if role in ('class_decl', 'class_expr'):
            self.class_fields[depth] = False
            if self.class_kind == 'class':
                self.strict_frames.add(depth)
            self.class_kind = None

    def close_context(self, role):
        depth = len(self.frames) + 1
        if role.startswith('parameters_'):
            self.body_generator = depth in self.generator_frames
        self.generator_frames.discard(depth)
        self.strict_frames.discard(depth)
        self.for_heads.discard(depth)
        self.arrow_markers.discard(depth)

    def after_operator(self, operator):
        depth = len(self.frames)
        if operator == '=>':
            self.arrow_markers.add(depth)
        elif operator in (';', ','):
            self.arrow_markers.discard(depth)
        if operator == '=' and self.module_clause == 'import':
            self.module_clause = None  # TS `import name = Namespace.member` has no module body.

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
        self.jsx_tag, self.jsx_return = self.source[start:self.i], return_mode
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
            self.push('}', 'jsx_expression', self.mode)
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
            self.emit('jsx', source[begin:self.i], begin, line)
            self.expr, self.statement, self.previous = False, False, 'jsx'
        else:
            self.line += ch in '\r\n\u2028\u2029' and not (ch == '\n' and self.i and source[self.i - 1] == '\r')
            self.i += 1
            self.emit('jsx', ch, begin, line)


def tokenize(source: str, path: str = 'fixture.ts', *, compact: bool = False) -> list[Token]:
    """Tokenize source without execution; unsupported lexical ambiguity is an error.

    Compact extraction normalizes inert groups, calls, objects and opaque template text.
    The default stream retains all source tokens, including every raw template chunk.
    """
    return Lexer(source, path, compact=compact).run()
