"""Token-level JavaScript extraction; statement forms cannot hide executable tokens."""
from __future__ import annotations

import heapq
import re
from bisect import bisect_right

from aegis_core.ast.drivers.js.tokenizer import JSLexError, tokenize
from aegis_core.ast.drivers.js.values import (
    UNKNOWN,
    decode_string,
    identifier_value,
    render,
)
from aegis_core.ast.schema import (
    CallSiteNode,
    DefinitionNode,
    ImportNode,
    MutationPoint,
    NormalizedAST,
)

CAPABILITIES = ['allow_comments', 'args', 'decorators']
_NOT_CALL = frozenset(('if', 'for', 'while', 'switch', 'catch', 'with', 'function', 'typeof', 'delete', 'void', 'return', 'throw', 'await', 'yield', 'new', 'else', 'try', 'finally', 'do', 'case', 'break', 'continue'))
_INCOMPLETE = _NOT_CALL | {'const', 'let', 'var', 'export', 'default', 'async', 'declare', 'abstract'}
_NON_OPERAND = _INCOMPLETE | {'import', 'in', 'instanceof', 'as', 'extends', 'from'}
_ALLOW = re.compile(r'\baegis:\s*allow(?:\[([^\]]+)\])?(?:\s*[:\-]?\s*(.*))?$', re.IGNORECASE)
_COMMENT_LINES = re.compile(r'\r\n|[\r\n\u2028\u2029]')
_MUTATIONS = {'===': ('!==', 'cmpop'), '!==': ('===', 'cmpop'), '==': ('!=', 'cmpop'), '!=': ('==', 'cmpop'), '<=': ('>=', 'cmpop'), '>=': ('<=', 'cmpop'), '<': ('>', 'cmpop'), '>': ('<', 'cmpop'), '&&': ('||', 'boolop'), '||': ('&&', 'boolop'), '+': ('-', 'binop'), '-': ('+', 'binop'), '*': ('/', 'binop'), '/': ('*', 'binop')}


def comment_overrides(tokens):
    result = {}
    for token in tokens:
        if token.kind != 'comment':
            continue
        text = token.value[2:-2] if token.value.startswith('/*') else token.value[2:]
        for offset, line in enumerate(_COMMENT_LINES.split(text)):
            match = _ALLOW.search(line)
            if match:
                rules = sorted({r.strip() for r in match[1].split(',') if r.strip()}) if match[1] else None
                result.setdefault(token.line + offset, []).append({'rules': rules, 'reason': (match[2] or '').strip()})
    return result


class Extractor:
    def __init__(self, source, path, *, compact=True):
        self.source, self.path = source, path
        all_tokens = tokenize(source, path, compact=compact)
        self.comments = comment_overrides(all_tokens)
        self.tokens = [t for t in all_tokens if t.kind != 'comment']
        self.pairs, self.reverse = {}, {}
        self.imports, self.definitions, self.calls = [], [], []
        self.require_sources, self.bound, self.modules, self.definition_opens = {}, set(), set(), set()
        self.require_bindings, self.uncertain_bindings = {}, {}
        self.ranges, self.decorators = [], []
        self.import_indices, self.class_indices, self.function_indices = [], [], []
        self.binding_indices, self.decorator_indices, self.call_indices, self.new_indices = [], [], [], []
        self.function_bindings = set()
        self.mutation_indices, self.mutations = [], []
        self.syntax = []
        self.build_pairs()

    def build_pairs(self):
        stack, braces, binding = [], 0, None
        tokens, syntax, pairs, reverse = self.tokens, self.syntax, self.pairs, self.reverse
        imports, classes, functions = self.import_indices, self.class_indices, self.function_indices
        bindings, decorators, calls = self.binding_indices, self.decorator_indices, self.call_indices
        news, mutations, function_bindings = self.new_indices, self.mutation_indices, self.function_bindings
        for index, token in enumerate(tokens):
            kind, value = token.kind, token.value
            if kind == 'identifier':
                syntax.append(value)
                if token.role not in ('module_binding', 'property_name'):
                    if value in ('import', 'export', 'require'):
                        imports.append(index)
                    elif value == 'class':
                        classes.append(index)
                    elif value in ('const', 'let', 'var'):
                        bindings.append(index)
                        if braces == 0:
                            binding = index
                    elif value == 'new':
                        news.append(index)
            elif kind == 'punct':
                syntax.append(value)
                if value in _MUTATIONS:
                    mutations.append(index)
                if value == '@':
                    decorators.append(index)
                elif value == ';' and braces == 0:
                    binding = None
                elif value == '=>' and braces == 0 and binding is not None:
                    function_bindings.add(binding)
                elif value == '(':
                    if token.role.startswith('parameters_'):
                        functions.append(index)
                        if token.role == 'parameters_expr' and braces == 0 and binding is not None:
                            function_bindings.add(binding)
                    elif token.role != 'control' and index:
                        before = tokens[index - 1]
                        if before.kind in ('identifier', 'flat_call') or (before.kind == 'punct' and before.value in (')', ']', '}', '>', '>>', '>>>', '!', '?.')):
                            calls.append(index)
                if value in {'(', '[', '{', '${'}:
                    stack.append(index)
                    braces += value in ('{', '${')
                elif value in {')', ']', '}'}:
                    begin = stack.pop()
                    pairs[begin], reverse[index] = index, begin
                    braces -= value == '}'
            else:
                syntax.append('')
                if kind == 'flat_call':
                    calls.append(index)
                elif kind == 'template_start':
                    if index:
                        calls.append(index)
                    stack.append(index)
                elif kind == 'template_end':
                    begin = stack.pop()
                    pairs[begin], reverse[index] = index, begin

    def value(self, index):
        return self.syntax[index] if 0 <= index < len(self.syntax) else ''

    def segments(self, begin, end):
        current, index = begin, begin
        while index < end:
            if self.value(index) == ',':
                yield current, index
                current = index + 1
            if index in self.pairs:
                index = self.pairs[index]
            elif self.value(index) == '<':
                index = self.generic_end(index, end) or index
            index += 1
        if current < end:
            yield current, end

    def unparen(self, begin, end):
        while begin < end and self.value(begin) == '(' and self.pairs.get(begin) == end - 1:
            begin, end = begin + 1, end - 1
        return begin, end

    def literal(self, begin, end):
        begin, end = self.unparen(begin, end)
        return render(self.tokens[begin:end])

    def module_argument(self, opening):
        end = self.pairs[opening]
        first = next(self.segments(opening + 1, end), (end, end))
        begin, stop = self.unparen(*first)
        if stop == begin + 1 and self.tokens[begin].kind == 'string':
            return self.tokens[begin].value.removeprefix('node:')
        if (begin < stop and self.tokens[begin].kind == 'template_start' and self.tokens[stop - 1].kind == 'template_end'
                and all(t.kind == 'template_text' for t in self.tokens[begin + 1:stop - 1])):
            return decode_string('`' + ''.join(t.value for t in self.tokens[begin + 1:stop - 1]) + '`').removeprefix('node:')
        return UNKNOWN

    def add_import(self, source, line, symbols=(), aliases=(), type_only=False):
        self.imports.append(ImportNode(source, tuple(symbols), line, type_only, tuple(aliases)))
        self.modules.add(source)
        self.bound.update(symbols)
        self.bound.update(bound for bound, _ in aliases)

    def import_members(self, begin, end):
        symbols, aliases = [], []
        for start, stop in self.segments(begin, end):
            items = self.tokens[start:stop]
            if items and items[0].value == 'type' and len(items) > 1 and items[1].value != 'as':
                items = items[1:]
            if not items:
                continue
            original = items[0].value
            binding = items[-1].value if len(items) >= 3 and items[-2].value in ('as', ':') else original
            symbols.append(binding)
            if original != binding:
                aliases.append((binding, original))
        return symbols, aliases

    def prepare_require_bindings(self):
        declarations = sorted(self.binding_indices + [i for i in self.import_indices if self.value(i) == 'import' and self.value(i + 2) == '='])
        for index in declarations:
            for begin, end in self.segments(index + 1, self.statement_end(index)):
                cursor = begin
                while cursor < end and self.value(cursor) != '=':
                    cursor = self.pairs.get(cursor, cursor) + 1
                value_begin, value_end = self.unparen(cursor + 1, end)
                if self.value(value_begin) == 'require' and self.value(value_begin + 1) == '(' and self.pairs[value_begin + 1] == value_end - 1:
                    self.require_bindings[value_begin] = (begin, cursor)

    def require_members(self, begin, end, module):
        symbols, aliases = [], []
        for start, stop in self.segments(begin, end):
            original, cursor, _ = self.object_key(start, stop)
            binding = cursor + 1 if self.value(cursor) == ':' else start
            if binding >= stop or self.tokens[binding].kind != 'identifier':
                continue
            name = self.value(binding)
            symbols.append(name)
            if self.value(binding + 1) == '=':
                self.uncertain_bindings[name] = '<computed>'
            elif original is None:
                self.uncertain_bindings[name] = module + '.<computed>'
            if original and original != name:
                aliases.append((name, original))
        return symbols, aliases

    def require_binding(self, call_index, module):
        declaration = self.require_bindings.get(call_index)
        if declaration is None:
            return (), ()
        begin, end = declaration
        if self.value(begin) == '{':
            return self.require_members(begin + 1, self.pairs[begin], module)
        if begin < end and self.tokens[begin].kind == 'identifier':
            return (), ((self.value(begin), module),)
        return (), ()

    def static_import(self, index):
        start, cursor = index + 1, index + 1
        if cursor >= len(self.tokens):
            raise JSLexError('syntax:incomplete_import', self.tokens[index].line, self.tokens[index].start)
        if self.value(start + 1) == '=' and self.value(start + 2) not in ('require', 'import'):
            return  # TS namespace aliases name existing code, not an imported module.
        type_only = self.value(cursor) == 'type' and self.value(cursor + 1) not in ('from', ',', '=')
        cursor += type_only
        if cursor >= len(self.tokens):
            raise JSLexError('syntax:incomplete_import', self.tokens[index].line, self.tokens[index].start)
        if self.tokens[cursor].kind == 'string':
            self.add_import(self.tokens[cursor].value.removeprefix('node:'), self.tokens[index].line, type_only=type_only)
            return
        module_index = None
        while cursor < len(self.tokens) and self.value(cursor) != ';':
            if self.value(cursor) == 'from' and cursor + 1 < len(self.tokens) and self.tokens[cursor + 1].kind == 'string':
                module_index = cursor + 1
                break
            if self.value(cursor) in ('require', 'import') and self.value(cursor + 1) == '(':
                return  # import x = require(...): the call path records the binding
            if cursor > start and self.value(cursor) in ('import', 'export', 'const', 'let', 'var', 'function', 'class'):
                break
            if cursor in self.pairs:
                cursor = self.pairs[cursor]
                if self.tokens[index].value == 'export' and self.value(cursor + 1) != 'from':
                    return
            cursor += 1
        if module_index is None:
            if self.tokens[index].value == 'import':
                raise JSLexError('syntax:incomplete_import', self.tokens[index].line, self.tokens[index].start)
            return
        module = self.tokens[module_index].value.removeprefix('node:')
        if self.tokens[index].value == 'export':
            self.add_import(module, self.tokens[index].line, type_only=type_only)
            return
        symbols, aliases = [], []
        cursor = start + type_only
        if cursor < module_index - 1 and self.tokens[cursor].kind == 'identifier':
            aliases.append((self.value(cursor), module))
            cursor += 1
        while cursor < module_index - 1:
            if self.value(cursor) == '{':
                names, renames = self.import_members(cursor + 1, self.pairs[cursor])
                symbols.extend(names)
                aliases.extend(renames)
                cursor = self.pairs[cursor]
            elif self.value(cursor) == '*' and self.value(cursor + 1) == 'as':
                aliases.append((self.value(cursor + 2), module))
            cursor += 1
        self.add_import(module, self.tokens[index].line, symbols, aliases, type_only)

    def collect_imports(self):
        if any(self.value(i) == 'require' for i in self.import_indices):
            self.prepare_require_bindings()
        for index in self.import_indices:
            token = self.tokens[index]
            if token.value in ('require', 'import') and self.value(index + 1) == '(' and self.value(index - 1) not in ('.', '?.'):
                opening = index + 1
                if self.tokens[opening].role.startswith('parameters_'):
                    continue
                module = self.module_argument(opening)
                symbols, aliases = self.require_binding(index, module)
                self.require_sources[opening] = module
                self.add_import(module, token.line, symbols, aliases)
            elif (token.value == 'import' and self.value(index + 1) not in ('(', '.')) or (token.value == 'export' and self.value(index + 1) in ('{', '*', 'type')):
                self.static_import(index)

    def exported(self, index):
        cursor = index - 1
        while cursor >= 0 and self.value(cursor) not in (';', '{', '}'):
            if self.value(cursor) == 'export':
                return True
            if self.tokens[cursor].line < self.tokens[index].line - 3:
                break
            cursor -= 1
        return False

    def definition_decorators(self, index):
        names = []
        position = bisect_right(self.decorator_ends, index - 1) - 1
        while position >= 0:
            start, end, name = self.decorators[position]
            between = self.tokens[end + 1:index]
            if any(t.value in (';', '{', '}') for t in between):
                break
            names.append(name)
            index, position = start, position - 1
        return tuple(reversed(names))

    def collect_decorators(self):
        for index in self.decorator_indices:
            cursor, parts = index + 1, []
            while cursor < len(self.tokens) and (self.tokens[cursor].kind == 'identifier' if len(parts) % 2 == 0 else self.value(cursor) == '.'):
                parts.append(self.value(cursor))
                cursor += 1
            if parts:
                end = self.pairs.get(cursor, cursor - 1) if self.value(cursor) == '(' else cursor - 1
                self.decorators.append((index, end, ''.join(parts)))
        self.decorator_ends = [end for _, end, _ in self.decorators]

    def next_body(self, opening):
        cursor = self.pairs[opening] + 1
        while cursor < len(self.tokens) and self.value(cursor) not in (';', '}'):
            token = self.tokens[cursor]
            if token.value == '{' and token.role.startswith('function_'):
                return cursor, self.pairs[cursor]
            if cursor in self.pairs:
                cursor = self.pairs[cursor]
            cursor += 1
        return opening, self.pairs[opening]

    def collect_classes(self):
        classes = []
        for index in self.class_indices:
            token = self.tokens[index]
            name = self.value(index + 1) if index + 1 < len(self.tokens) and self.tokens[index + 1].kind == 'identifier' else 'default'
            cursor = index + 1
            while cursor < len(self.tokens):
                if self.value(cursor) == '{' and self.tokens[cursor].role.startswith('class_'):
                    classes.append((cursor, self.pairs[cursor], name))
                    break
                cursor = self.pairs.get(cursor, cursor) + 1
            self.definitions.append(DefinitionNode(name, 'class', token.line, self.exported(index), decorators=self.definition_decorators(index)))
        return classes

    def collect_functions(self, classes):
        class_names = self.scope_map(classes, self.function_indices)
        for index in self.function_indices:
            token = self.tokens[index]
            name_index = index - 1
            if self.value(name_index) in ('>', '>>', '>>>'):
                name_index = self.generic_base(name_index)
            if name_index < 0 or self.tokens[name_index].kind not in ('identifier', 'string'):
                continue
            name, kind, class_name = self.tokens[name_index].value, 'function', None
            if name in ('function', 'async'):
                continue
            if token.role == 'parameters_method':
                class_name = class_names[index]
                kind = 'method'
            self.definition_opens.add(index)
            self.definitions.append(DefinitionNode(name, kind, self.tokens[name_index].line, self.exported(name_index), class_name, self.definition_decorators(name_index)))
            _, end = self.next_body(index)
            self.ranges.append((index, end, name))

    def statement_end(self, index):
        cursor = index + 1
        while cursor < len(self.tokens) and self.value(cursor) != ';':
            token, previous = self.tokens[cursor], self.tokens[cursor - 1]
            if token.line > previous.line:
                terminal = previous.kind in ('identifier', 'flat_call', 'number', 'string', 'regex', 'template_end', 'jsx') or self.value(cursor - 1) in (')', ']', '}', '!', '++', '--')
                start = token.kind in ('identifier', 'flat_call', 'number', 'string', 'regex', 'jsx')
                if terminal and start and self.value(cursor - 1) not in _INCOMPLETE and self.value(cursor) not in ('in', 'instanceof', 'as', 'satisfies', 'of'):
                    break
            if cursor in self.pairs:
                cursor = self.pairs[cursor]
            elif self.value(cursor) == '<':
                cursor = self.generic_end(cursor, len(self.tokens)) or cursor
            cursor += 1
        return cursor

    def collect_binding(self, name_index, end, declaration):
        cursor = name_index + 1
        if self.tokens[name_index].kind != 'identifier':
            return
        while cursor < end and self.value(cursor) != '=':
            cursor = self.pairs.get(cursor, cursor) + 1
        if self.value(cursor) != '=':
            return
        value_start, cursor = cursor + 1, cursor + 1
        if self.value(cursor) == 'async':
            cursor += 1
        if self.value(cursor) == '<':
            closing = self.generic_end(cursor, end)
            if closing:
                cursor = closing + 1
        arrow = self.value(cursor + 1) == '=>'
        if self.value(cursor) == '(':
            after = self.pairs[cursor] + 1
            while after < end and self.value(after) not in ('=>', ';', '=', '{'):
                after += 1
            arrow = self.value(after) == '=>'
            if arrow:
                self.definition_opens.add(cursor)
        if not arrow and self.value(cursor) != 'function':
            return
        name = self.value(name_index)
        self.definitions.append(DefinitionNode(name, 'function', self.tokens[name_index].line, self.exported(declaration), decorators=self.definition_decorators(declaration)))
        self.ranges.append((value_start, end - 1, name))

    def collect_bindings(self):
        for index in self.binding_indices:
            if index not in self.function_bindings:
                continue
            for begin, end in self.segments(index + 1, self.statement_end(index)):
                self.collect_binding(begin, end, index)

    def scope_map(self, ranges, sites):
        """Sweep ordered definition ranges and sites; each range is visited once."""
        starts, active, result = iter(ranges), [], {}
        pending = next(starts, None)
        for index in sites:
            while pending and pending[0] <= index:
                _, end, name = pending
                active.append((end, name))
                pending = next(starts, None)
            while active and active[-1][0] < index:
                active.pop()
            result[index] = active[-1][1] if active else None
        return result

    def generic_base(self, index):
        depth = 0
        while index >= 0:
            value = self.value(index)
            if value in ('>', '>>', '>>>'):
                depth += len(value)
                if depth > 256:
                    raise JSLexError('limit:depth', self.tokens[index].line, self.tokens[index].start)
            elif value == '<':
                depth -= 1
                if depth == 0:
                    return index - 1
            elif value in (';', '=', '/', '+', '-'):
                return -1
            index -= 1
        return -1

    def generic_end(self, index, end, *, require_call=True):
        if self.value(index) != '<' or self.path.rsplit('.', 1)[-1].lower() not in ('ts', 'tsx', 'mts', 'cts'):
            return None
        depth, cursor = 0, index
        while cursor < end:
            value = self.value(cursor)
            if self.tokens[cursor].kind == 'flat_call':
                return None
            if value == '<':
                depth += 1
                if depth > 256:
                    raise JSLexError('limit:depth', self.tokens[cursor].line, self.tokens[cursor].start)
            elif value in ('>', '>>', '>>>'):
                depth -= len(value)
                if depth <= 0:
                    return cursor if depth == 0 and (not require_call or self.value(cursor + 1) == '(') else None
            elif value in (';', '=', '/'):
                return None
            if cursor in self.pairs and not self.type_group(cursor):
                return None
            cursor = self.pairs.get(cursor, cursor) + 1
        return None

    def type_group(self, opening):
        closing = self.pairs[opening]
        for cursor in range(opening, closing + 1):
            value = self.value(cursor)
            if self.tokens[cursor].kind == 'flat_call':
                return False
            if value in ('+', '/', '%', '!', '&&', '||', '??', '**', '++', '--', '='):
                return False
            if value != '(':
                continue
            end = self.pairs[cursor]
            signature = self.value(end + 1) in ('=>', ':')
            prefix = self.value(cursor - 1)
            if self.tokens[cursor - 1].kind == 'identifier' and prefix not in ('import', 'new', 'typeof', 'keyof', 'readonly', 'unique') and not signature:
                return False
            if not signature and prefix != 'import':
                index = cursor + 1
                while index < end:
                    if self.value(index) == ',':
                        return False
                    index = self.pairs.get(index, index) + 1
        return True

    def target(self, index):
        if self.value(index) == '?.':
            index -= 1
        while self.value(index) == '!':
            index -= 1
        if self.value(index) in ('>', '>>', '>>>'):
            index = self.generic_base(index)
        parts, start = [], index
        while index >= 0:
            token = self.tokens[index]
            if token.kind == 'identifier':
                if token.role == 'reference':
                    parts.extend(reversed(token.value.split('.')))
                else:
                    parts.append(token.value)
                start = index
            elif token.kind == 'flat_call':
                return ('.' + '.'.join(reversed(parts)) if parts else '<computed>'), index
            elif token.value == ']':
                opening = self.reverse[index]
                if token.role == 'array':
                    return ('.' + '.'.join(reversed(parts)) if parts else '<computed>'), opening
                parts.append(self.tokens[opening + 1].value if index == opening + 2 and self.tokens[opening + 1].kind == 'string' else '<computed>')
                index, start = opening - 1, opening - 1
                continue
            elif token.value == ')':
                if token.role == 'control':
                    return '', index
                opening = self.reverse[index]
                if opening in self.require_sources and self.value(opening - 1) == 'require':
                    parts.append(self.require_sources[opening])
                    start = opening - 1
                    break
                if parts:
                    grouped = self.grouped_target(opening, index)
                    if grouped is not None:
                        index = grouped
                        continue
                    return '.' + '.'.join(reversed(parts)), opening
                grouped = self.grouped_target(opening, index)
                if grouped is None:
                    return '<computed>', opening
                index = grouped
                continue
            elif token.value == '!' and token.kind == 'punct':
                index -= 1
                continue
            else:
                if parts:
                    return '.' + '.'.join(reversed(parts)), max(0, index)
                return '', index
            if self.value(index - 1) not in ('.', '?.'):
                break
            index -= 2
        if not parts:
            return '', start
        parts.reverse()
        return self.reference_target(parts), start

    def reference_target(self, parts):
        if parts[0] in self.uncertain_bindings:
            return '.'.join([self.uncertain_bindings[parts[0]], *parts[1:]])
        if len(parts) > 1 and parts[0] not in self.known_receivers:
            return '.' + '.'.join(parts[1:])
        return '.'.join(parts)

    def grouped_target(self, opening, closing):
        before = self.tokens[opening - 1] if opening else None
        if before and ((before.kind == 'identifier' and before.value not in _NOT_CALL | {'return', 'throw', 'await', 'yield', 'new', 'case'}) or self.value(opening - 1) in (')', ']', '>', '>>', '?.')):
            return None  # a called function's result is not one of its arguments
        segments = list(self.segments(opening + 1, closing))
        if not segments:
            return None
        begin, end = segments[-1]
        allowed = {'.', '?.', '!', '[', ']', '(', ')'}
        if any(t.kind not in ('identifier', 'string', 'number') and not (t.kind == 'punct' and t.value in allowed) for t in self.tokens[begin:end]):
            return None
        return end - 1

    def arrow_parameters(self, opening):
        after = self.pairs[opening] + 1
        if self.value(after) == ':':
            after += 1
            while after < len(self.tokens) and self.value(after) not in ('=>', ';', '=', '{', ','):
                after = self.pairs.get(after, after) + 1
        return self.value(after) == '=>'

    def constructor_site(self, start, opening, claimed):
        while self.value(start - 1) == '(' and self.pairs[start - 1] < opening:
            start -= 1
        new = start - 1 if self.value(start - 1) == 'new' else None
        while new is not None and new in claimed:
            new = new - 1 if self.value(new - 1) == 'new' else None
        return new

    def object_key(self, start, stop):
        token, cursor = self.tokens[start], start
        if token.kind == 'identifier' and token.value in ('get', 'set', 'async') and start + 1 < stop:
            next_token = self.tokens[start + 1]
            if next_token.kind in ('identifier', 'string', 'number') or self.value(start + 1) in ('[', '*'):
                cursor += 1
        if self.value(cursor) == '*':
            cursor += 1
        if cursor >= stop:
            return None, cursor, False
        token = self.tokens[cursor]
        if token.kind == 'punct' and token.value == '[':
            closing = self.pairs[cursor]
            key = self.tokens[cursor + 1].value if closing == cursor + 2 and self.tokens[cursor + 1].kind == 'string' else None
            return key, closing + 1, True
        if token.kind in ('identifier', 'string'):
            return token.value, cursor + 1, False
        if token.kind == 'number':
            key = render([token])
            # Numeric property names use NumberToString; unsupported spellings
            # stay uncertain rather than inventing a distinct, absent field.
            key = key.removesuffix('.0') if key != UNKNOWN and 'e' not in key.lower() and len(key.split('.')[0]) <= 21 else None
            return key, cursor + 1, False
        return None, cursor, False

    def object_fields(self, begin, end):
        fields, uncertain = {}, False
        for start, stop in self.segments(begin + 1, end - 1):
            first = self.tokens[start]
            if first.kind == 'punct' and first.value == '...':
                fields = dict.fromkeys(fields, UNKNOWN)
                uncertain = True
                continue
            key, cursor, computed = self.object_key(start, stop)
            if key is None:
                fields = dict.fromkeys(fields, UNKNOWN)
                uncertain = True
            else:
                fields[key] = self.literal(cursor + 1, stop) if self.value(cursor) == ':' else UNKNOWN
                if key == '__proto__' and not computed and self.value(cursor) == ':':
                    uncertain = True  # inherited unknown fields cannot overwrite explicit own fields
        return fields, uncertain

    def opaque_fields(self, begin, end):
        if begin >= end:
            return False
        token = self.tokens[begin]
        if end == begin + 1 and (token.kind in ('string', 'number') or token.value in ('true', 'false', 'null')):
            return False
        if token.value == '[' and token.kind == 'punct' and self.pairs[begin] == end - 1:
            return False
        return token.kind != 'template_start' or self.literal(begin, end) == UNKNOWN

    def arguments(self, opening):
        args, named, previous_unknown, spread = {}, {}, False, False
        for position, (begin, end) in enumerate(self.segments(opening + 1, self.pairs[opening])):
            if self.value(begin) == '...':
                args['*'], spread = UNKNOWN, True
                continue
            object_begin, object_end = self.unparen(begin, end)
            args[f'#{position}'] = UNKNOWN if spread else render(self.tokens[object_begin:object_end])
            if self.tokens[object_begin].kind == 'flat_object' and object_end == object_begin + 1:
                fragment = Extractor('(' + self.tokens[object_begin].value + ')', self.path, compact=False)
                fields, unknown = fragment.object_fields(1, len(fragment.tokens) - 1)
            elif self.value(object_begin) == '{' and self.pairs[object_begin] == object_end - 1:
                fields, unknown = self.object_fields(object_begin, object_end)
            else:
                if self.opaque_fields(object_begin, object_end):
                    named = dict.fromkeys(named, UNKNOWN)
                    args['**'], previous_unknown = UNKNOWN, True
                continue
            if unknown:
                named = dict.fromkeys(named, UNKNOWN)
                args['**'] = UNKNOWN
            for key, value in fields.items():
                named[key] = UNKNOWN if key in named or previous_unknown else value
            previous_unknown |= unknown
        if spread:
            named = dict.fromkeys(named, UNKNOWN)
        return {**args, **named}

    def collect_calls(self, scopes):
        called_new, ordinary, constructors = set(), [], []
        for index in self.call_indices:
            token = self.tokens[index]
            caller = scopes[index] if scopes is not None else None
            if token.kind == 'flat_call':
                target = token.value if '.' not in token.value and not self.uncertain_bindings else self.reference_target(token.value.split('.'))
                if len(token.arguments) == 1:
                    value = token.arguments[0]
                    args = {'#0': identifier_value(value)}
                    if value not in ('true', 'false', 'null'):
                        args['**'] = UNKNOWN
                else:
                    args, opaque = {}, False
                    for position, value in enumerate(token.arguments):
                        args[f'#{position}'] = identifier_value(value)
                        opaque |= value not in ('true', 'false', 'null')
                    if opaque:
                        args['**'] = UNKNOWN
                before = self.syntax[index - 1] if index else ''
                new = self.constructor_site(index, index, called_new) if before in ('new', '(') else None
                if new is not None:
                    called_new.add(new)
                ordinary.append((index, CallSiteNode(target, token.line, caller, args, kind='new' if new is not None else None)))
            elif token.kind == 'punct' and token.value == '(' and index not in self.definition_opens and token.role not in ('control', 'parameters_decl', 'parameters_expr', 'parameters_method'):
                if self.arrow_parameters(index):
                    continue
                target, start = self.target(index - 1)
                if not target or target in _NOT_CALL:
                    continue
                new = self.constructor_site(start, index, called_new)
                if new is not None:
                    called_new.add(new)
                ordinary.append((index, CallSiteNode(target, self.tokens[start].line, caller, self.arguments(index), kind='new' if new is not None else None)))
            elif token.kind == 'template_start':
                target, start = self.target(index - 1)
                if target and target not in _NOT_CALL:
                    ordinary.append((index, CallSiteNode(target, self.tokens[start].line, caller, {'#0': UNKNOWN, '*': UNKNOWN})))
        for index in self.new_indices:
            token = self.tokens[index]
            if index in called_new:
                continue
            end = index + 1
            if end >= len(self.tokens):
                continue
            if self.value(end) == '(':
                end = self.pairs[end]
            elif self.tokens[end].kind != 'identifier':
                continue
            while end + 1 < len(self.tokens):
                if self.value(end + 1) in ('.', '?.') and end + 2 < len(self.tokens):
                    end += 2
                elif self.value(end + 1) == '[':
                    end = self.pairs[end + 1]
                else:
                    break
            target, _ = self.target(end) if self.value(end) != 'new' else ('<computed>', end)
            constructors.append((index, CallSiteNode(target, token.line, scopes[index] if scopes is not None else None, {}, kind='new')))
        self.calls = [node for _, node in heapq.merge(ordinary, constructors)]

    def mutation_operand(self, index, *, left):
        if not 0 <= index < len(self.tokens):
            return False
        token = self.tokens[index]
        if token.kind == 'identifier':
            return token.value not in _NON_OPERAND if left else True
        if token.kind in ('number', 'string', 'regex', 'flat_call', 'flat_object'):
            return True
        if left:
            return token.kind == 'template_end' or (token.kind == 'punct' and token.value in (')', ']', '}', '!', '++', '--') and token.role not in ('control', 'parameters_decl', 'parameters_expr', 'parameters_method', 'block', 'class_decl', 'function_decl'))
        return token.kind == 'template_start' or (token.kind == 'punct' and token.value in ('(', '[', '{', '!', '~', '+', '-'))

    def collect_mutations(self, scopes):
        if not self.mutation_indices:
            return
        starts = [0] + [match.end() for match in _COMMENT_LINES.finditer(self.source)]
        typescript = self.path.rsplit('.', 1)[-1].lower() in ('ts', 'tsx', 'mts', 'cts')
        type_end = -1
        for index in self.mutation_indices:
            token = self.tokens[index]
            if typescript and token.value in ('<', '>') and index <= type_end:
                continue
            previous = self.tokens[index - 1] if index else None
            following = self.tokens[index + 1] if index + 1 < len(self.tokens) else None
            if previous and previous.kind in ('identifier', 'number', 'string', 'regex', 'flat_call', 'flat_object'):
                left = previous.kind != 'identifier' or previous.value not in _NON_OPERAND
            else:
                left = self.mutation_operand(index - 1, left=True)
            if typescript and token.value == '<':
                closing = self.generic_end(index, len(self.tokens), require_call=left)
                if closing is not None:
                    type_end = closing
                    continue
            right = following and (following.kind in ('identifier', 'number', 'string', 'regex', 'flat_call', 'flat_object', 'template_start') or self.mutation_operand(index + 1, left=False))
            if not left or not right:
                continue
            if typescript and token.value in ('<', '>') and previous.kind not in ('number', 'string') and following.kind not in ('number', 'string'):
                continue  # ambiguous type/assertion angles are not safe mutation sites
            replacement, kind = _MUTATIONS[token.value]
            point = MutationPoint(token.line, token.start - starts[token.line - 1], token.value, replacement, kind)
            object.__setattr__(point, 'byte_offset', token.start)
            object.__setattr__(point, 'function_scope', scopes[index] if scopes is not None else None)
            self.mutations.append(point)

    def run(self):
        self.collect_imports()
        self.known_receivers = self.bound | self.modules | {'globalThis', 'window', 'Reflect', 'Object', 'JSON', 'Math'}
        self.collect_decorators()
        classes = self.collect_classes()
        self.collect_functions(classes)
        function_count = len(self.ranges)
        self.collect_bindings()
        scopes = None
        if self.ranges:
            ranges = heapq.merge(self.ranges[:function_count], self.ranges[function_count:])
            scopes = self.scope_map(ranges, heapq.merge(self.call_indices, self.new_indices, self.mutation_indices))
        self.collect_calls(scopes)
        self.collect_mutations(scopes)
        language = 'typescript' if self.path.rsplit('.', 1)[-1].lower() in ('ts', 'tsx', 'mts', 'cts') else 'javascript'
        metadata = {'capabilities': CAPABILITIES, 'allow_comments': self.comments,
                    'decorators': list(dict.fromkeys(name for _, _, name in self.decorators))}
        return NormalizedAST(self.path, language, self.definitions, self.calls, self.imports, self.mutations, metadata=metadata)


def parse(source: str, path: str) -> NormalizedAST:
    """Extract normalized facts using source tokens; never execute repository code."""
    return Extractor(source, path).run()
