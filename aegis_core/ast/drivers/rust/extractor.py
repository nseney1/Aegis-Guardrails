"""Token-based Rust extraction with explicit uncertainty and opaque macro input."""
from __future__ import annotations

from pathlib import PurePosixPath
import re

from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.schema import CallSiteNode, DefinitionNode, ImportNode, MutationPoint, NormalizedAST
from .literals import UNKNOWN, render
from .tokenizer import error, tokenize

CAPABILITIES = ('allow_comments', 'args', 'decorators', 'test_module')
MAX_SOURCE_BYTES = 2 * 1024 * 1024
_CONTROL = {'if', 'while', 'match', 'for', 'loop', 'else', 'unsafe', 'async', 'move', 'const', 'fn', 'struct', 'enum', 'trait', 'impl', 'mod', 'use'}
_ALLOW = re.compile(r'aegis:\s*allow(?:\[([^\]]*)\])?\s*(.*)')
_MUTATIONS = {'==': ('!=', 'comparison'), '!=': ('==', 'comparison'), '<=': ('>', 'comparison'),
              '>=': ('<', 'comparison'), '<': ('>=', 'comparison'), '>': ('<=', 'comparison'),
              '&&': ('||', 'logical'), '||': ('&&', 'logical'), '+': ('-', 'binop'),
              '-': ('+', 'binop'), '*': ('/', 'binop'), '/': ('*', 'binop')}


def _module_path(path):
    parts = list(PurePosixPath(path.replace('\\', '/')).parts)
    if 'src' not in parts:
        return []  # integration roots are owned/mapped separately by the T5 adapter
    parts = parts[parts.index('src') + 1:]
    if parts:
        parts[-1] = parts[-1].removesuffix('.rs')
    if parts and parts[-1] in ('lib', 'main', 'mod'):
        parts.pop()
    return parts


def _allows(comments):
    rows = {}
    for token in comments:
        for offset, line in enumerate(token.value.split('\n')):
            match = _ALLOW.search(line)
            if match:
                names = [name.strip() for name in match[1].split(',') if name.strip()] if match[1] is not None else None
                reason = match[2].strip()
                if reason.endswith('*/'):
                    reason = reason[:-2].rstrip()
                rows.setdefault(token.line + offset, []).append({'rules': names, 'reason': reason})
    return rows


class Extractor:
    def __init__(self, source, path):
        self.source, self.path = source, path
        self.lexed = tokenize(source)
        self.t, self.pairs = self.lexed.tokens, self.lexed.pairs
        self.skip, self.imports, self.definitions, self.calls = set(), [], [], []
        self.groups, self.attributes, self.scopes = {}, {}, {}
        self.decorators, self.tests, self.local = [], [], set()
        self.opaque, self.control_blocks, self.import_sources, self.matches = {}, set(), set(), set()
        self.test_module, self.import_bindings = False, set()
        self.generic_punct = set()

    def lexical_regions(self):
        depth, pending, i = 0, {}, 0
        while i < len(self.t):
            value = self.t[i].value
            if value == '!' and i > 0 and self.t[i - 1].kind == 'ident':
                declaration = self.t[i - 1].value == 'macro_rules' and not self.t[i - 1].raw
                opening = i + 2 if declaration else i + 1
                if opening in self.pairs and self.pairs[opening] > opening:
                    end = self.pairs[opening]
                    self.opaque[opening] = end
                    self.skip.update(range(opening + 1, end + 1))
                    i = end + 1
                    continue
            if value in ('if', 'while', 'for', 'match') and not self.t[i].raw:
                pending[depth] = value
            elif value in ('(', '[', '{'):
                if value == '{' and depth in pending:
                    self.control_blocks.add(i)
                    if pending[depth] == 'match':
                        self.matches.add(i)
                    del pending[depth]
                depth += 1
            elif value in (')', ']', '}'):
                depth -= 1
                pending.pop(depth + 1, None)
            elif value == ';':
                pending.pop(depth, None)
            i += 1

    def text(self, lo, hi):
        return ''.join(token.value for token in self.t[lo:hi])

    def split(self, lo, hi, *, expressions=False):
        start, i, operand = lo, lo, True
        while i < hi:
            token = self.t[i]
            value = token.value
            if value == ',':
                if start < i:
                    yield start, i
                start = i + 1
                operand = True
            elif i in self.pairs and self.pairs[i] > i:
                i = self.pairs[i]
                operand = False
            elif value == '<' and i > lo and self.t[i - 1].value == '::':
                i = self._angle_end(i)
                if i > hi:
                    error('invalid generic arguments', token.line)
                operand = False
                continue
            elif expressions and value == '|' and operand:
                i += 1
                while i < hi and self.t[i].value != '|':
                    i = self.pairs[i] + 1 if i in self.pairs and self.pairs[i] > i else i + 1
                if i == hi:
                    error('unclosed closure parameters', token.line)
                # A closure body can itself begin with another closure. Only its
                # parameter region is skipped here; executable body facts stay visible.
            elif expressions and value == '||' and operand:
                pass
            elif expressions and operand and not token.raw and value in ('async', 'move', 'static'):
                pass
            else:
                operand = value in (':', '=', '=>')
            i += 1
        if start < hi:
            yield start, hi

    def _import(self, module, name, alias, line):
        group = self.groups.setdefault((module, line), [[], []])
        if name and alias != '_':
            group[0].append(alias or name)
        if alias and alias != '_':
            group[1].append((alias, name or module))

    def _use_leaf(self, prefix, lo, hi, line):
        tokens = self.t[lo:hi]
        values = [token.value for token in tokens]
        if not values or any(token.kind != 'ident' and token.value not in ('::', '*') for token in tokens):
            error('invalid use tree', line)
        alias = None
        at = next((index for index, token in enumerate(tokens) if token.value == 'as' and not token.raw), None)
        if at is not None:
            if at != len(values) - 2:
                error('invalid use alias', line)
            alias, values = values[-1], values[:at]
        segments = [value for value in values if value != '::']
        path = values[1:] if values[:1] == ['::'] else values
        if not path or any((v != '::' if index % 2 else v == '::') for index, v in enumerate(path)) or path[-1] == '::':
            error('invalid use path', line)
        full = prefix + segments
        if not full:
            error('invalid use tree', line)
        name = full[-1]
        if name == 'self':
            if len(full) < 2:
                error('invalid use self root', line)
            module = '::'.join(full[:-1])
            group = self.groups.setdefault((module, line), [[], []])
            if alias != '_':
                bound = alias or full[-2]
                group[0].append(bound)
                group[1].append((bound, module))
        elif alias and alias != '_' and (name[:1].islower() or '::'.join(full[:-1]) == name):
            self._import('::'.join(full), None, alias, line)
        else:
            self._import('::'.join(full[:-1]), name, alias, line)

    def use(self, start, end):
        work = [([], start + 1, end)]
        while work:
            prefix, lo, hi = work.pop()
            for first, last in self.split(lo, hi):
                group = next((i for i in range(first, last) if self.t[i].value == '{'), None)
                if group is None:
                    self._use_leaf(prefix, first, last, self.t[start].line)
                else:
                    if self.pairs[group] != last - 1:
                        error('invalid use group', self.t[group].line)
                    head = [t.value for t in self.t[first:group] if t.value != '::']
                    work.append((prefix + head, group + 1, last - 1))

    def imports_and_attributes(self):
        i = 0
        while i < len(self.t):
            if i in self.opaque:
                i = self.opaque[i] + 1
                continue
            value = self.t[i].value
            if value == '#' and i + 1 < len(self.t):
                opening = i + 2 if self.t[i + 1].value == '!' else i + 1
                if opening < len(self.t) and self.t[opening].value == '[':
                    end = self.pairs[opening]
                    name, _ = self.path_at(opening + 1)
                    if not name:
                        error('invalid attribute', self.t[i].line)
                    self.attributes[i] = (end, name, self.text(opening + 1, end))
                    self.skip.update(range(i, end + 1))
                    if name and name not in self.decorators:
                        self.decorators.append(name)
                    i = end
            elif value == 'use' and not self.t[i].raw:
                end = i + 1
                while end < len(self.t) and self.t[end].value != ';':
                    if self.t[end].value == '{':
                        end = self.pairs[end]
                    end += 1
                if end == len(self.t):
                    error('invalid use: missing semicolon', self.t[i].line)
                self.use(i, end)
                self.skip.update(range(i, end + 1))
                i = end
            elif value == 'extern' and not self.t[i].raw and i + 2 < len(self.t) and self.t[i + 1].value == 'crate':
                end = next((j for j in range(i + 2, len(self.t)) if self.t[j].value == ';'), len(self.t))
                values = [t.value for t in self.t[i + 2:end]]
                if len(values) not in (1, 3) or (len(values) == 3 and values[1] != 'as'):
                    error('invalid extern crate', self.t[i].line)
                self._import(values[0], None, values[-1] if len(values) == 3 else values[0], self.t[i].line)
                self.skip.update(range(i, end + 1))
                i = end
            i += 1
        self.imports = [ImportNode(module, tuple(names), line, aliases=tuple(aliases))
                        for (module, line), (names, aliases) in self.groups.items()]
        self.import_sources = {item.source for item in self.imports}
        self.import_bindings = {name for item in self.imports for name in item.imported_symbols}
        self.import_bindings.update(name for item in self.imports for name, _ in item.aliases)

    def _angle_end(self, start):
        depth, i = 0, start
        while i < len(self.t):
            value = self.t[i].value
            if value in ('<', '>'):
                self.generic_punct.add(i)
            depth += value == '<'
            depth -= value == '>'
            if depth == 0:
                return i + 1
            if value in (';', '{', '}'):
                if value == '{':
                    error('unsupported_lexical_context: const expression in type', self.t[i].line)
                error('invalid generic arguments', self.t[start].line)
            i += 1
        error('unclosed generic arguments', self.t[start].line)

    def path_at(self, start):
        i, parts = start, []
        if i < len(self.t) and self.t[i].value in ('::', '.'):
            parts.append(self.t[i].value)
            i += 1
        if i >= len(self.t) or self.t[i].kind != 'ident':
            return '', start
        parts.append(self.t[i].value)
        i += 1
        while i < len(self.t) and self.t[i].value in ('::', '.'):
            separator = self.t[i].value
            if separator == '::' and i + 1 < len(self.t) and self.t[i + 1].value == '<':
                i = self._angle_end(i + 1)
                continue
            if i + 1 == len(self.t) or self.t[i + 1].kind != 'ident':
                break
            parts.extend((separator, self.t[i + 1].value))
            i += 2
        return ''.join(parts), i

    def _body(self, start):
        i = start
        while i < len(self.t) and self.t[i].value not in ('{', ';', '='):
            if self.t[i].value == '<':
                i = self._angle_end(i)
                continue
            if self.t[i].value in ('(', '['):
                i = self.pairs[i]
            i += 1
        return i

    def _validate_types(self, lo, hi):
        for index in range(lo, hi):
            if self.t[index].value != '[' or index not in self.pairs:
                continue
            closing = self.pairs[index]
            separator = next((i for i in range(index + 1, closing) if self.t[i].value == ';'), None)
            if separator is not None and any(self.t[i].value in ('(', '{') for i in range(separator + 1, closing)):
                error('unsupported_lexical_context: const expression in type', self.t[index].line)

    def _impl_type(self, start, end):
        if start >= end:
            error('invalid impl header', self.t[start - 1].line)
        if self.t[start].value == '<':
            start = self._angle_end(start)
        i, target = start, start
        while i < end:
            if self.t[i].value == '<':
                i = self._angle_end(i)
                continue
            if self.t[i].value == 'for':
                target = i + 1
            i += 1
        name, _ = self.path_at(target)
        return name or '<impl>'

    def _exported(self, start):
        i = start - 1
        while i >= 0 and self.t[i].value in ('const', 'async', 'unsafe', 'extern'):
            i -= 1
        if i >= 0 and self.t[i].value == ')':
            i = self.pairs[i] - 1
        return i >= 0 and self.t[i].value == 'pub'

    def _enum_fields(self, opening):
        for lo, hi in self.split(opening + 1, self.pairs[opening]):
            end = lo
            while end < hi and self.t[end].value != '=':
                end = self.pairs[end] + 1 if end in self.pairs and self.pairs[end] > end else end + 1
            self._validate_types(lo, end)
            self.skip.update(range(lo, end))

    def _type_alias(self, start):
        if start + 1 < len(self.t) and self.t[start + 1].kind == 'ident':
            self.local.add(self.t[start + 1].value)
        end = start + 1
        while end < len(self.t) and self.t[end].value != ';':
            if self.t[end].value == '{':
                error('unsupported_lexical_context: block in type', self.t[end].line)
            if self.t[end].value == '<':
                end = self._angle_end(end)
                continue
            end += 1
        self._validate_types(start, end)
        self.skip.update(range(start, end + 1))

    def definitions_and_scopes(self):
        context, pending, i = [], [], 0
        while i < len(self.t):
            while context and i > context[-1][0]:
                context.pop()
            if i in self.attributes:
                end, name, raw = self.attributes[i]
                if i + 1 < len(self.t) and self.t[i + 1].value != '!':
                    pending.append((name, raw))
                i = end + 1
                continue
            if i in self.skip:
                i += 1
                continue
            value = self.t[i].value
            if value == 'type' and not self.t[i].raw:
                self._type_alias(i)
            elif value == 'impl' and not self.t[i].raw:
                end = self._body(i + 1)
                name = self._impl_type(i + 1, end)
                if end < len(self.t) and self.t[end].value == '{':
                    context.append((self.pairs[end], 'impl', name))
                self.skip.update(range(i, end + 1))
            elif value in ('fn', 'struct', 'enum', 'trait', 'mod', 'const', 'static', 'macro_rules') and not self.t[i].raw:
                if value == 'const' and i + 1 < len(self.t) and self.t[i + 1].value == 'fn':
                    i += 1
                    continue
                i = self.definition(i, context, pending)
                pending = []
            elif value not in ('pub', 'unsafe', 'async', 'extern') and value not in ('(', ')', 'crate'):
                pending = []
            i += 1

    def definition(self, i, context, pending):
        keyword = self.t[i].value
        name_at = i + 2 if keyword == 'macro_rules' else i + 1
        if keyword == 'static' and name_at < len(self.t) and self.t[name_at].value == 'mut':
            name_at += 1
        if name_at >= len(self.t) or self.t[name_at].kind != 'ident':
            if keyword == 'fn' and name_at < len(self.t) and self.t[name_at].value == '(':
                return i  # function pointer type, not a declaration
            if keyword in ('fn', 'struct', 'enum', 'trait', 'mod', 'static', 'macro_rules'):
                error('invalid ' + keyword + ' declaration', self.t[i].line)
            return i
        name = self.t[name_at].value
        self.local.add(name)
        owner = next((name for _, kind, name in reversed(context) if kind == 'impl'), None)
        modules = [name for _, kind, name in context if kind == 'mod']
        attrs = tuple(name for name, _ in pending)
        exported = self._exported(i)
        kind = 'method' if keyword == 'fn' and owner else {'fn': 'function', 'struct': 'class', 'trait': 'class',
                                                        'enum': 'class', 'mod': 'module'}.get(keyword, keyword)
        self.definitions.append(DefinitionNode(name, kind, self.t[i].line, exported, owner, attrs))
        end = self._body(name_at + 1)
        self._validate_types(name_at + 1, end)
        if keyword == 'fn':
            parameters = name_at + 1
            if parameters < len(self.t) and self.t[parameters].value == '<':
                parameters = self._angle_end(parameters)
            if parameters >= len(self.t) or self.t[parameters].value != '(':
                error('invalid function header', self.t[i].line)
        if keyword == 'fn' and 'test' in attrs:
            module = _module_path(self.path) + modules
            self.tests.append({'name': name, 'module': '::'.join(module), 'id': '::'.join(module + [name]), 'line': self.t[i].line})
        if keyword == 'macro_rules' and end < len(self.t) and self.t[end].value == '{':
            self.skip.update(range(i, self.pairs[end] + 1))
            return self.pairs[end]
        self.skip.update(range(i, min(end + 1, len(self.t))))
        if end < len(self.t) and self.t[end].value == '{':
            if keyword == 'mod' and any(raw == 'cfg(test)' for _, raw in pending):
                self.test_module = True
            if keyword in ('fn', 'mod'):
                scope = '::'.join(([owner] if owner else modules) + [name])
                self.scopes[end] = (self.pairs[end], scope) if keyword == 'fn' else None
                context.append((self.pairs[end], keyword if keyword == 'fn' else 'mod', name))
            elif keyword == 'struct':
                self._validate_types(end + 1, self.pairs[end])
                self.skip.update(range(end, self.pairs[end] + 1))
            elif keyword == 'enum':
                self._enum_fields(end)
        return i

    def struct_fields(self, opening):
        result = {}
        parts = list(self.split(opening + 1, self.pairs[opening], expressions=True))
        for index, (lo, hi) in enumerate(parts):
            if self.t[lo].value == '..':
                if index != len(parts) - 1:
                    error('invalid struct update position', self.t[lo].line)
                result['**'] = UNKNOWN
                continue
            name = self.t[lo].value
            if self.t[lo].kind != 'ident' or (hi > lo + 1 and self.t[lo + 1].value != ':'):
                error('invalid struct field', self.t[lo].line)
            if name in result:
                error('duplicate field ' + name, self.t[lo].line)
            result[name] = self.value(lo + 2, hi) if hi > lo + 1 else UNKNOWN
        return result

    def value(self, lo, hi):
        if hi == lo + 1 and lo in self.lexed.scalars:
            result = self.lexed.scalars[lo]
        elif hi == lo + 2 and self.t[lo].value in ('-', '+') and lo + 1 in self.lexed.scalars:
            result = self.lexed.scalars[lo + 1]
            if result != UNKNOWN and self.t[lo].value == '-':
                result = '-' + result
        else:
            result = render(self.t[lo:hi])
        if result == 'None' and ('None' in self.local or 'None' in self.import_bindings):
            return UNKNOWN
        return result

    def pattern_regions(self):
        for opening in self.matches:
            for lo, hi in self.split(opening + 1, self.pairs[opening]):
                i = lo
                while i < hi:
                    if self.t[i].value in ('if', '=>'):
                        self.skip.update(range(lo, i))
                        break
                    i = self.pairs[i] + 1 if i in self.pairs and self.pairs[i] > i else i + 1
        for start, token in enumerate(self.t):
            if token.value not in ('let', 'for') or token.raw or start in self.skip:
                continue
            end = start + 1
            marker = '=' if token.value == 'let' else 'in'
            while end < len(self.t) and self.t[end].value not in (marker, ';'):
                end = self.pairs[end] + 1 if end in self.pairs and self.pairs[end] > end else end + 1
            self.skip.update(range(start + 1, end))

    def arguments(self, opening):
        result, named, updates = {}, {}, set()
        for index, (lo, hi) in enumerate(self.split(opening + 1, self.pairs[opening], expressions=True)):
            result['#' + str(index)] = self.value(lo, hi)
            _, at = self.path_at(lo)
            if at < hi and self.t[at].value == '{' and self.pairs[at] == hi - 1:
                for key, value in self.struct_fields(at).items():
                    result[key] = UNKNOWN if key in named else value
                    named[key] = index
                    if key == '**':
                        updates.add(index)
        for key, owner in named.items():
            if key != '**' and any(index != owner for index in updates):
                result[key] = UNKNOWN
        return result

    def _synthetic_import(self, target, line):
        path = target.removeprefix('::').split('::')
        intrinsic = {'Self', 'self', 'super', 'crate'}
        external = path[0] not in self.local and path[0] not in self.import_bindings and path[0] not in intrinsic
        if len(path) > 1 and (path[0] in ('std', 'core', 'alloc') or external):
            source = '::'.join(path[:-1])
            if source not in self.import_sources:
                self.imports.append(ImportNode(source, line=line))
                self.import_sources.add(source)

    def call_sites(self):
        contexts, i = [], 0
        while i < len(self.t):
            while contexts and i > contexts[-1][0]:
                contexts.pop()
            if i in self.scopes and self.scopes[i]:
                contexts.append(self.scopes[i])
            if i in self.skip:
                i += 1
                continue
            previous = self.t[i - 1].value if i else ''
            value = self.t[i].value
            receiver = value == '.' and previous in (')', ']', '}', '?')
            if (self.t[i].kind != 'ident' and not receiver and value != '::') or previous in ('::', '.'):
                i += 1
                continue
            target, end = self.path_at(i)
            if (target in _CONTROL and not self.t[i].raw) or not target or end == len(self.t):
                i += 1
                continue
            following = self.t[end].value
            kind, args = None, None
            if following == '!' and end + 1 < len(self.t) and self.t[end + 1].value in ('(', '[', '{'):
                target, kind, args = target + '!', 'macro', {'*': UNKNOWN}
                self.skip.update(range(end + 1, self.pairs[end + 1] + 1))
            elif following == '(':
                args = self.arguments(end)
            elif following == '{' and self._construct(end):
                kind, args = 'construct', self.struct_fields(end)
            if args is not None:
                self.calls.append(CallSiteNode(target, self.t[i].line, contexts[-1][1] if contexts else '<module>', args, kind=kind))
                self._synthetic_import(target, self.t[i].line)
            i = max(i + 1, end)

    def _construct(self, opening):
        closing = self.pairs[opening]
        after = self.t[closing + 1].value if closing + 1 < len(self.t) else ''
        if opening in self.control_blocks or after in ('=>', '='):
            return False
        if closing == opening + 1:
            return True
        inner = self.t[opening + 1: min(opening + 3, closing)]
        return inner[0].value == '..' or (inner[0].kind == 'ident' and (len(inner) == 1 or inner[1].value in (':', ',')))

    def mutations(self):
        rows = []
        for index, token in enumerate(self.t):
            if index in self.skip or index in self.generic_punct or token.kind != 'punct' or token.value not in _MUTATIONS:
                continue
            replacement, kind = _MUTATIONS[token.value]
            rows.append(MutationPoint(token.line, token.col, token.value, replacement, kind))
        return rows

    def parse(self):
        self.lexical_regions()
        self.imports_and_attributes()
        self.definitions_and_scopes()
        self.pattern_regions()
        self.call_sites()
        return NormalizedAST(self.path, 'rust', self.definitions, self.calls, self.imports,
                             mutation_points=self.mutations(),
                             metadata={'capabilities': list(CAPABILITIES), 'allow_comments': _allows(self.lexed.comments),
                                       'decorators': self.decorators, 'test_module': self.test_module,
                                       'test_functions': self.tests})


def parse(source: str, path: str) -> NormalizedAST:
    """Extract supported Rust syntax; unresolved values never become definite literals."""
    try:
        size = len(source.encode('utf-8'))
    except UnicodeError as exc:
        raise ASTDriverError('invalid Unicode source', reason='syntax') from exc
    if size > MAX_SOURCE_BYTES:
        raise ASTDriverError('Rust source exceeds 2 MiB; exclude this path in the rule (aegis doctor)', reason='too_large')
    return Extractor(source, path).parse()
