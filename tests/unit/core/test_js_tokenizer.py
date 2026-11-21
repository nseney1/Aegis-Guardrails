"""JavaScript lexical boundaries through the public tokenizer."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_core.ast.driver_errors import ASTDriverError


def tokens(source, path='fixture.tsx'):
    from aegis_core.ast.drivers.js.tokenizer import tokenize
    return tokenize(source, path)


@pytest.mark.parametrize('source,eval_count', [
    (r'if (x) /eval\(x\)/.test(s)', 0),
    ('f(x) / eval(code) / 2', 1),
    (r'if(x) {} /eval\(x\)/.test(s)', 0),
    ('const f = function() {} / eval(code)', 1),
    ('const x = {a: /eval/}; eval(code)', 1),
    ('const s = `raw eval(x) ${eval(x)} ${`inner ${eval(y)}`}`', 2),
    ('const x = <A attr={() => eval(x)}>eval(x)<B>{eval(y)}</B></A>', 2),
    ('const x = <><A />{eval(x)}</>', 1),
    (r'\u0065val(code)', 1),
    (r'try {} catch {} /eval\(x\)/.test(s)', 0),
    (r'label: {} /eval\(x\)/.test(s)', 0),
    (r'switch(x) { case 1: {} /eval\(x\)/.test(s); break; }', 0),
    ('const x = <A>{<B>{eval(x)}</B>}</A>', 1),
    ('const x = <A value={eval(x)} next={eval(y)} />', 2),
    (r'const plain = `λ text`; const text = `\${eval(hidden)} \` raw ${eval(actual)}`;', 1),
    ('const ratio = call(value) / /eval(hidden)/.test(text); eval(actual);', 1),
])
def test_executable_identifiers_survive_lexical_modes(source, eval_count):
    assert sum(t.kind == 'identifier' and t.value == 'eval' for t in tokens(source)) == eval_count


@pytest.mark.parametrize('source,reason', [
    ('"unterminated', 'unterminated_string'),
    ('/* unterminated', 'unterminated_comment'),
    ('`unterminated ${x}', 'unterminated_template'),
    ('const r = /unterminated', 'unterminated_regex'),
    ('const x = <A>{x}</B>', 'jsx'),
    ('f(]', 'delimiter'),
    ('f(0x)', 'number'),
    ('f(1__0)', 'number'),
    ('f(1.0n)', 'number'),
    (r'\u0020bad()', 'identifier'),
    ('const r = /\\\neval(x)/', 'unterminated_regex'),
    ('class MissingBody', 'class'),
    ('function missing(', 'delimiter'),
    ('const x = `\\uZZZZ`', 'escape'),
    ('const f = () => {} / eval(code)', 'unsupported_lexical_context:arrow_body_operator'),
    ('`text\\', 'syntax:template_escape:unterminated_string'),
])
def test_malformed_boundaries_fail_with_a_reason(source, reason):
    with pytest.raises(ASTDriverError, match=reason):
        tokens(source)


def test_crlf_bom_comments_and_unicode_have_source_lines():
    result = tokens('\ufeffconst α = 1;\r\n// aegis: allow[r] fixture\r\nα();', 'fixture.js')
    assert [(t.value, t.line) for t in result if t.kind == 'identifier' and t.value == 'α'] == [('α', 1), ('α', 3)]
    assert any(t.kind == 'comment' and t.line == 2 for t in result)


def test_nesting_limit_is_explicit_and_not_a_python_recursion_error():
    with pytest.raises(ASTDriverError, match='depth'):
        tokens('(' * 300 + 'x' + ')' * 300)


def test_typescript_assertions_are_not_jsx():
    result = tokens('const x = <Thing>eval(code); f<Thing<string>>(x);', 'fixture.ts')
    assert any(t.kind == 'identifier' and t.value == 'eval' for t in result)


def test_return_type_objects_and_nested_generics_preserve_real_body_boundaries():
    result = tokens('function f<T>(x:T):Promise<{x:T}> { return x; } /eval\\(x\\)/.test(s);', 'fixture.ts')
    assert not any(t.kind == 'identifier' and t.value == 'eval' for t in result)


def test_private_identifiers_and_string_surrogates_decode_without_execution():
    result = tokens(r'class A { #secret() {} run() { this.#secret(); } } f("\ud83d\ude00");')
    assert sum(t.value == '#secret' for t in result) == 2
    assert next(t.value for t in result if t.kind == 'string') == '😀'


@pytest.mark.parametrize('path', ['fixture.ts', 'fixture.tsx', 'fixture.mts', 'fixture.cts'])
def test_ambiguous_type_instantiation_cannot_swallow_executable_division(path):
    with pytest.raises(ASTDriverError, match='unsupported_lexical_context:type_angle_slash'):
        tokens('const value = f<T> /* boundary */ / eval(code) / 2;', path)


def test_javascript_relational_regex_and_called_generic_division_remain_distinct():
    assert not any(t.value == 'eval' for t in tokens(r'const value = a > /eval\(code\)/;', 'fixture.js'))
    assert any(t.value == 'eval' for t in tokens('const value = f<T>() / eval(code) / 2;', 'fixture.ts'))


def test_compact_groups_preserve_depth_limit_and_default_token_stream():
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    assert sum(t.value == '(' for t in tokenize('(((f(value))))')) == 4
    with pytest.raises(ASTDriverError, match='limit:depth'):
        tokenize('(' * 256 + 'f(value)' + ')' * 256, compact=True)


@pytest.mark.parametrize('operator', ['>>>=', '===', '!==', '**=', '&&=', '||=', '??=', '>>>', '...', '=>', '?.', '++', '--', '**', '&&', '||', '??', '==', '!=', '<=', '>=', '<<', '>>', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^='])
def test_operator_tokens_use_the_longest_spelling(operator):
    assert operator in [token.value for token in tokens('left ' + operator + ' right;')]


def test_whitespace_prefixes_and_unicode_identifier_tails_keep_exact_positions():
    source = 'first \r\n  seco\\u006ed();\t αβ();'
    assert [(t.value, t.line, t.start, t.end) for t in tokens(source) if t.kind == 'identifier'] == [
        ('first', 1, 0, 5), ('second', 2, 10, 21), ('αβ', 2, 26, 28),
    ]


def test_large_code_regions_preserve_whole_identifiers_numbers_and_operator_positions():
    name, number = 'identifier' * 500, '1' * 2000
    source = 'const first=1;' * 200 + name + '(' + number + '); left === right;'
    result = tokens(source)
    assert any(t.value == name and t.end - t.start == len(name) for t in result)
    assert any(t.value == number and t.end - t.start == len(number) for t in result)
    point = next(t for t in result if t.value == '===')
    assert source[point.start:point.end] == '==='


@pytest.mark.parametrize('spaces', [511, 1023, 2047, 2048, 2049])
def test_crlf_boundaries_and_literal_modes_after_large_whitespace_prefixes(spaces):
    source = ' ' * spaces + '\r\nconst value="eval(code)"; eval(code);'
    assert [(t.value, t.line) for t in tokens(source) if t.kind == 'identifier' and t.value == 'eval'] == [('eval', 2)]


@pytest.mark.parametrize('suffix,reason', [('\0eval(code)', 'unsupported_lexical_context:character'), ('"unterminated', 'syntax:unterminated_string')])
def test_invalid_boundaries_after_large_code_regions_keep_the_original_offset(suffix, reason):
    from aegis_core.ast.drivers.js.tokenizer import JSLexError

    prefix = 'let value=0;' * 200
    with pytest.raises(JSLexError) as error:
        tokens(prefix + suffix)
    assert error.value.reason == reason and error.value.offset == len(prefix)


def test_exact_source_bound_accepts_plain_and_escaped_string_literals():
    from aegis_core.ast.drivers.js.tokenizer import MAX_SOURCE_BYTES

    count = MAX_SOURCE_BYTES // 2 - 1
    assert tokens('"' + 'x' * (MAX_SOURCE_BYTES - 2) + '"')[0].value == 'x' * (MAX_SOURCE_BYTES - 2)
    assert tokens('"' + '\\"' * count + '"')[0].value == '"' * count


class _CountingPattern:
    """Delegate to a compiled pattern while counting match attempts."""

    def __init__(self, pattern):
        self.pattern, self.calls = pattern, 0

    def match(self, *args):
        self.calls += 1
        return self.pattern.match(*args)


def test_compact_group_scans_each_parenthesis_run_a_bounded_number_of_times(monkeypatch):
    # P2 (linear time): a failed transparent-group attempt must not be retried at every '(' of the same run.
    from aegis_core.ast.drivers.js import tokenizer

    counter = _CountingPattern(tokenizer._GROUP)
    monkeypatch.setattr(tokenizer, '_GROUP', counter)
    with pytest.raises(tokenizer.JSLexError, match='limit:depth'):
        tokenizer.tokenize('x = ' + '(' * 100_000, 'fixture.ts', compact=True)
    assert counter.calls <= 2
    counter.calls = 0
    unit = '(' * 255 + ')' * 255 + ';'
    assert tokenizer.tokenize(unit * 200, 'fixture.ts', compact=True)
    assert counter.calls <= 2 * 200


@pytest.mark.parametrize('source,expected', [
    ('f(' + ' ' * 50_000 + '!)', ['f', '(', '!', ')']),
    ('x = {' + ' ' * 50_000 + '!}', ['x', '=', '{', '!', '}']),
    ('x = (((f(' + ' ' * 50_000 + '!flag))))', ['x', '=', '(', '(', '(', 'f', '(', '!', 'flag', ')', ')', ')', ')']),
], ids=['call', 'object', 'group'])
def test_compact_patterns_keep_public_tokens_after_long_blank_runs(source, expected):
    # A subprocess ceiling catches hangs; the frozen performance harness owns P2 timing.
    code = 'import json, sys; from aegis_core.ast.drivers.js.tokenizer import tokenize; print(json.dumps([t.value for t in tokenize(sys.stdin.read(), "fixture.ts", compact=True)]))'
    completed = subprocess.run([sys.executable, '-c', code], input=source, text=True, capture_output=True, check=True, timeout=10)
    assert json.loads(completed.stdout) == expected


@pytest.mark.parametrize('source', [
    'call(value) / other / 2; value /= 3;',
    'class A { value = call(x) / other; }',
    'function f() { return call(x) / other; }',
    'function* f() { yield call(x) / other; }',
])
def test_division_paths_keep_operator_spellings_and_exact_source_spans(source):
    result = tokens(source, 'fixture.ts')
    divisions = [token for token in result if token.value in ('/', '/=')]
    assert divisions and all(source[t.start:t.end] == t.value and t.line == 1 for t in divisions)
    assert [t.start for t in divisions] == [index for index, char in enumerate(source) if char == '/']


def test_compact_templates_keep_literals_modules_nested_calls_and_public_raw_tokens():
    from aegis_core.ast.drivers.js import parse
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    source = ('const cp = require(`node:child_process`); import(`node:fs`);\n'
              'cp.exec(`plain`); require(`node:${name}`).exec(code);\n'
              'tag`raw ${inside(value + 1)} ${`inner ${other(item)}`} tail`;')
    tree = parse(source, 'fixture.ts')
    assert [node.source for node in tree.imports] == ['child_process', 'fs', '<expr>']
    assert [(node.target, node.args) for node in tree.call_sites] == [
        ('require', {'#0': "'node:child_process'"}), ('import', {'#0': "'node:fs'"}),
        ('cp.exec', {'#0': "'plain'"}), ('require', {'#0': '<expr>', '**': '<expr>'}),
        ('<expr>.exec', {'#0': 'code', '**': '<expr>'}), ('tag', {'#0': '<expr>', '*': '<expr>'}),
        ('inside', {'#0': '<expr>', '**': '<expr>'}), ('other', {'#0': 'item', '**': '<expr>'}),
    ]
    assert [(point.original_op, point.byte_offset, point.function_scope) for point in tree.mutation_points] == [
        ('+', source.index('+'), None),
    ]
    raw = [token for token in tokenize(source, 'fixture.ts') if token.kind == 'template_text']
    assert [token.value for token in raw] == ['node:child_process', 'node:fs', 'plain', 'node:', 'raw ', ' ', 'inner ', ' tail']
    assert all(source[token.start:token.end] == token.value for token in raw)
    assert [token.value for token in tokenize(source, 'fixture.ts', compact=True) if token.kind == 'template_text'] == [
        'node:child_process', 'node:fs', 'plain',
    ]


@pytest.mark.parametrize('source', [
    'const value = left / right; let other=2; var third =3;',
    'let value = /pattern/;', 'var value = <A />;',
    'function f(){const value = left / right;}', 'if(ready){const value = left;}',
    'for (let value = 0; value < 1; value++) {}', 'export const value = left;',
    'label: const value = left;', 'switch(x){case 0: const value=left;}',
    'function* f(){const value=left;}', 'class A { value = left; method(){const value = left;} }',
    'const {value} = left;', 'const value\n=left;', 'const value /* boundary */ = left;',
    r'const val\u0075e = left;', 'const λ = left;', 'const enum E { A }',
    'const value == left;', 'const value => left;',
])
def test_declaration_scanning_preserves_exact_default_and_compact_tokens(source):
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    assert tokenize(source, 'fixture.tsx', compact=True) == tokenize(source, 'fixture.tsx')


@pytest.mark.parametrize('source', [
    'first; second, third;', 'first \t ; second \t, third;',
    'first\n; second\r\n, third;', 'first /* retain */; second // retain\n, third;',
    'const first = one, second = two;',
    'function f(a,b) { return one; }',
    'class C { field = one; method() { return two; } }',
    'const f = () => one, other = two;',
    'for (let x = one; two; three) {}',
    'require(value);', "import type from 'worker'; type;",
    'value++; other + +third; value / divisor;',
])
def test_compact_reference_delimiters_preserve_complete_public_tokens(source):
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    assert tokenize(source, 'fixture.tsx', compact=True) == tokenize(source, 'fixture.tsx')


@pytest.mark.parametrize('separator', [';', ','])
def test_compact_call_delimiters_keep_inner_call_and_punctuation_spans(separator):
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    source = 'client.run(first, second) \t ' + separator + ' next'
    tokens = tokenize(source, 'fixture.ts', compact=True)
    closing = source.index(')') + 1
    delimiter = source.index(separator, closing)
    following = source.index('next')
    assert [tuple(token) for token in tokens] == [
        ('flat_call', 'client.run', 1, 0, closing, 'expression', ('first', 'second')),
        ('punct', separator, 1, delimiter, delimiter + 1, '', None),
        ('identifier', 'next', 1, following, len(source), '', None),
    ]


@pytest.mark.parametrize('newline', ['\n', '\r', '\r\n', '\u2028', '\u2029'])
@pytest.mark.parametrize('escaped', [False, True])
def test_template_chunks_keep_physical_lines_and_raw_spans(newline, escaped):
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    first = 'first' + ('\\' if escaped else '') + newline + 'second '
    source = 'const text=`' + first + '${visible(value + 1)} tail`;\nlast();'
    for compact in (False, True):
        result = tokenize(source, 'fixture.ts', compact=compact)
        chunks = [t for t in result if t.kind == 'template_text']
        assert [(t.value, t.line) for t in chunks] == ([] if compact else [(first, 1), (' tail', 2)])
        assert all(source[t.start:t.end] == t.value for t in chunks)
        assert [(t.value, t.line) for t in result if t.value in ('visible', 'last')] == [('visible', 2), ('last', 3)]


@pytest.mark.parametrize('source,expected', [
    ('const text=``; finish();', ['finish']),
    ('const text=`plain λ`; finish();', ['finish']),
    ('const text=`${one()}${two()}`; finish();', ['one', 'two', 'finish']),
    ('const text=`outer ${`inner ${one()}`} ${two()} tail`; finish();', ['one', 'two', 'finish']),
    (r'const text=`escaped \` \${hidden()}`; finish();', ['finish']),
    (r'const text=`\\${visible()}`; finish();', ['visible', 'finish']),
    (r'const text=`\\\${hidden()}`; finish();', ['finish']),
    (r'tag`\uZZZZ ${visible()} tail`; finish();', ['tag', 'visible', 'finish']),
    ('const cp=require(`node:child_process`); cp.exec(`plain`);', ['require', 'cp.exec']),
])
def test_template_boundaries_preserve_nested_calls_and_constant_literals(source, expected):
    from aegis_core.ast.drivers.js import parse
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    assert [site.target for site in parse(source, 'fixture.ts').call_sites] == expected
    assert all(source[t.start:t.end] == t.value for t in tokenize(source) if t.kind == 'template_text')


@pytest.mark.parametrize('source,reason', [
    (r'const text=`\uZZZZ`;', 'template_escape'),
    ('const text=`plain', 'unterminated_template'),
    ('const text=`tail\\', 'template_escape'),
    ('const text=`${one()', 'unterminated_template'),
    ('tag`tail\\', 'unterminated_template'),
])
def test_template_failures_keep_typed_boundaries_in_both_token_modes(source, reason):
    from aegis_core.ast.drivers.js.tokenizer import tokenize

    errors = []
    for compact in (False, True):
        with pytest.raises(ASTDriverError, match=reason) as raised:
            tokenize(source, 'fixture.ts', compact=compact)
        error = raised.value
        errors.append((error.reason, error.line, error.offset, str(error)))
    assert errors[0] == errors[1]


@pytest.mark.parametrize('unit', ['x', '\n', '\\\r\n'])
def test_large_template_chunks_keep_exact_tokens_with_a_bounded_process(unit):
    source = '`' + unit * ((2 * 1024 * 1024 - 2) // len(unit)) + '`'
    code = ('import json,sys; from aegis_core.ast.drivers.js.tokenizer import tokenize; '
            's=sys.stdin.buffer.read().decode("utf-8"); a=tokenize(s,compact=False); b=tokenize(s,compact=True); '
            'assert a==b; print(json.dumps([len(a),a[1].start,a[1].end,len(a[1].value)]))')
    completed = subprocess.run([sys.executable, '-c', code], input=source.encode('utf-8'),
                               capture_output=True, check=True, timeout=20)
    assert json.loads(completed.stdout) == [3, 1, len(source) - 1, len(source) - 2]


@pytest.mark.parametrize('source', [
    'const x = <D><B icon={<C />} />eval(x)<E />{eval(y)}</D>',
    'const x = <D><B icon={<C />}>eval(x)</B>{eval(y)}</D>',
    'const x = <D><B icon={<C />} />{eval(y)}</D>',
    'const x = <D><B render={() => <C><F /></C>} />eval(x){eval(y)}</D>',
    'const x = <D><B a={x ? <C /> : null} b="s" />eval(x)<E>{eval(y)}</E></D>',
    'const x = <B icon={<C />} />; eval(y)',
    'const x = <D>{<C />}eval(x)<E />{eval(y)}</D>',
])
def test_jsx_inside_an_attribute_expression_keeps_the_enclosing_tag(source):
    # The text after the tag is still JSX text (eval(x) is not code); only {eval(y)} is.
    assert sum(t.kind == 'identifier' and t.value == 'eval' for t in tokens(source)) == 1


@pytest.mark.parametrize('source', [
    'const a = b as { x: number }; eval(code)',
    'const a = [1] satisfies { x: number }[]; eval(code)',
    'const a = (m as { arg?: { e?: unknown } } | undefined)?.arg; eval(code)',
    'const f = <T extends { id: string }>(x: T) => x; eval(code)',
    'function f<T extends { id: string }>(x: T) { return x; } eval(code)',
    'type P<T> = T extends { a?: infer M } ? M : never; eval(code)',
    'function g(u: readonly { id: string }[]) {} eval(code)',
    'const h = (t): t is { a: number } => true; eval(code)',
    'const a = b as {\n  x: number;\n}; eval(code)',
    'const a = b as { f: <T>(x: T) => T }; eval(code)',
])
def test_typescript_type_literals_after_type_operators_are_read_as_types(source):
    assert sum(t.kind == 'identifier' and t.value == 'eval' for t in tokens(source, 'fixture.ts')) == 1


@pytest.mark.parametrize('source', [
    'class A extends B { m() { eval(code) } }',
    'class C extends D<{ x: 1 }> { m() { eval(code) } }',
    'const o = { extends: { a: 1 }, is: { b: 2 }, as: { c: 3 } }; eval(code)',
    'const a = [1, 2] as const; eval(code)',
    "import * as ns from 'x'; eval(code)",
    'export { a as b }; eval(code)',
    'const a = x as (A | B); eval(code)',
    'const a = { k: 1 } satisfies Record<string, number>; eval(code)',
])
@pytest.mark.parametrize('path', ['fixture.ts', 'fixture.tsx', 'fixture.js'])
def test_type_operator_words_keep_their_other_meanings(source, path):
    assert sum(t.kind == 'identifier' and t.value == 'eval' for t in tokens(source, path)) == 1


def test_a_brace_after_as_still_fails_closed_in_javascript():
    with pytest.raises(ASTDriverError, match='unsupported_lexical_context:brace'):
        tokens('const a = b as { x: number }; eval(code)', 'fixture.js')


# After a newline (ASI) or a property name the `{` opens a block; read as a type literal it would hide its calls.
@pytest.mark.parametrize('source', [
    'x.as\n{ eval(code) }',
    'x?.satisfies\n{ eval(code) }',
    'x.extends\n{ eval(code) }',
    'x.readonly\n{ eval(code) }',
    'x.is\n{ eval(code) }',
    'as\n{ eval(code) }',
    'x = is /*\n*/ { eval(code) }',
    # Not valid TypeScript, but after a property name the `{` must not open a type literal either.
    'x?.is { eval(code) }',
    'x./*c*/as { eval(code) }',
    # Valid type literals that also fail closed: on the next line it looks like the block above,
    # and the lexer does not look through a comment before `{`.
    'const a = b as\n{ x: number }; eval(code)',
    'const a = b as /* c */ { x: number }; eval(code)',
])
@pytest.mark.parametrize('path', ['fixture.ts', 'fixture.tsx', 'fixture.mts', 'fixture.cts'])
def test_a_brace_after_a_newline_comment_or_property_name_fails_closed(source, path):
    with pytest.raises(ASTDriverError, match='unsupported_lexical_context:brace'):
        tokens(source, path)


# In a type literal `<` opens a generic signature, never a JSX element.
@pytest.mark.parametrize('source', [
    'const a = b as { f: <T>(x: T) => T }; eval(code)',
    'const a = b satisfies { f: <T>(x: T) => T }; eval(code)',
    'type A = B extends { g: <T>(x: T) => T } ? 1 : 2; eval(code)',
    'const h = (t): t is { g: <T>(x: T) => T } => true; eval(code)',
])
def test_jsx_cannot_start_inside_a_tsx_type_literal(source):
    with pytest.raises(ASTDriverError, match='unsupported_lexical_context:tsx_type_literal_angle'):
        tokens(source, 'fixture.tsx')


def test_frame_depth_kinds_live_in_one_table():
    import aegis_core.ast.drivers.js.tokenizer as tokenizer

    source = Path(tokenizer.__file__).read_text(encoding='utf-8')
    tree = ast.parse(source)
    assignments = [
        node for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == '_FRAME_DEPTHS' for target in node.targets)
    ]
    assert len(assignments) == 1
    lexer = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Lexer')
    methods = {node.name: node for node in lexer.body if isinstance(node, ast.FunctionDef)}
    frame_names = {name for name, _ in tokenizer._FRAME_DEPTHS}
    for method in ('code', 'compact_declaration', 'punctuation', 'close_context'):
        names = {
            node.id if isinstance(node, ast.Name) else node.attr
            for node in ast.walk(methods[method]) if isinstance(node, (ast.Name, ast.Attribute))
        }
        assert '_FRAME_DEPTHS' not in names, method
        # Only the arrow and generator lexical transitions need kind-specific state here.
        assert names & frame_names <= {'arrow_markers', 'generator_frames'}, method

    first, second = tokenizer.Lexer('', 'a.js'), tokenizer.Lexer('', 'b.js')
    owned, other = first.frame_depths, second.frame_depths
    assert len(owned) == len(other) == len(tokenizer._FRAME_DEPTHS)
    assert len({id(depths) for depths in owned + other}) == 2 * len(frame_names)
    assert all(depths == set() for depths in owned + other)
    blockers = [depths for (_, blocks), depths in zip(tokenizer._FRAME_DEPTHS, owned) if blocks]
    assert tuple(map(id, first.declaration_depths)) == tuple(map(id, blockers))


@pytest.mark.parametrize('source', ['(!x)', '[!x]'], ids=['expression-fast-close', 'punctuation-close'])
def test_frame_depth_table_extension_cleans_up_on_close(source):
    import aegis_core.ast.drivers.js.tokenizer as tokenizer

    spec = importlib.util.spec_from_file_location('test_frame_tokenizer', tokenizer.__file__)
    isolated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated)

    class LexerWithSyntheticMarker(isolated.Lexer):
        def after_operator(self, operator):
            super().after_operator(operator)
            if operator == '!':
                self.synthetic_frames.update((0, len(self.frames)))

        def run(self):
            result = super().run()
            assert self.synthetic_frames == {0}
            return result

    expected = tokenizer.tokenize(source, 'fixture.js')
    isolated._FRAME_DEPTHS = (*isolated._FRAME_DEPTHS, ('synthetic_frames', True))
    isolated.Lexer = LexerWithSyntheticMarker
    assert isolated.tokenize(source, 'fixture.js') == expected


def test_frame_depth_refusal_does_not_echo_input_and_retry_is_fresh():
    from aegis_core.ast.drivers.js.tokenizer import JSLexError, tokenize

    marker = 'ZQMARK'
    source = 'function* g() { yield ' + marker + ' ]'
    with pytest.raises(JSLexError) as caught:
        tokenize(source, 'fixture.js')
    assert caught.value.reason == 'syntax:unbalanced_delimiter'
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value.args)
    retried = tokenize('function* g() { yield /a/ }', 'fixture.js')
    assert [(token.kind, token.value) for token in retried if token.kind == 'regex'] == [('regex', '/a/')]


def test_frame_depth_tokenization_is_isolated_across_threads():
    from concurrent.futures import ThreadPoolExecutor

    from aegis_core.ast.drivers.js.tokenizer import JSLexError, tokenize

    good, bad = 'function* g() { yield /a/ }', 'function h() { yield /a/ }'

    def once(_index):
        accepted = tokenize(good, 'fixture.js')
        assert any(token.kind == 'regex' and token.value == '/a/' for token in accepted)
        with pytest.raises(JSLexError) as caught:
            tokenize(bad, 'fixture.js')
        assert caught.value.reason == 'unsupported_lexical_context:contextual_yield'
        assert 'yield /a/' not in str(caught.value)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(once, range(8)))


# case, source, path
_FRAME_MATRIX = (
    ('generator-open-template', 'function* g() { return `x ${yield /a/}` }', 'fixture.js'),
    ('generator-open-regex', 'function* g() { yield /a/ }', 'fixture.js'),
    ('generator-open-block', 'function* g() { { yield /a/ } }', 'fixture.js'),
    ('generator-open-call', 'function* g() { f(yield /a/) }', 'fixture.js'),
    ('generator-nested-template', 'function* g() { function* h() { return `x ${yield /a/}` } return `y ${yield /b/}` }', 'fixture.js'),
    ('generator-nested-regex', 'function* g() { function* h() { yield /a/ } yield /b/ }', 'fixture.js'),
    ('generator-nested-block', 'function* g() { function* h() { { yield /a/ } } { yield /b/ } }', 'fixture.js'),
    ('generator-nested-call', 'function* g() { function* h() { f(yield /a/) } f(yield /b/) }', 'fixture.js'),
    ('generator-close-template', 'function* g() { return `x ${yield /a/}` }', 'fixture.js'),
    ('generator-close-regex', 'function* g() { yield /a/ }', 'fixture.js'),
    ('generator-close-block', 'function* g() { { yield /a/ } }', 'fixture.js'),
    ('generator-close-call', 'function* g() { f(yield /a/) }', 'fixture.js'),
    ('generator-mismatched-template', 'function* g() { return `x ${yield /a/}` ]', 'fixture.js'),
    ('generator-mismatched-regex', 'function* g() { yield /a/ ]', 'fixture.js'),
    ('generator-mismatched-block', 'function* g() { { yield /a/ } ]', 'fixture.js'),
    ('generator-mismatched-call', 'function* g() { f(yield /a/) ]', 'fixture.js'),
    ('generator-discard-template', 'function* g() { return `x ${yield /a/}` } function h() { return `y ${yield /b/}` }', 'fixture.js'),
    ('generator-discard-regex', 'function* g() { yield /a/ } function h() { yield /b/ }', 'fixture.js'),
    ('generator-discard-block', 'function* g() { { yield /a/ } } function h() { { yield /b/ } }', 'fixture.js'),
    ('generator-discard-call', 'function* g() { f(yield /a/) } function h() { f(yield /b/) }', 'fixture.js'),
    ('strict-open-template', 'class A { m() { return `x ${yield /a/}` } }', 'fixture.js'),
    ('strict-open-regex', 'class A { m() { return yield /a/ } }', 'fixture.js'),
    ('strict-open-block', 'class A { m() { { return yield /a/ } } }', 'fixture.js'),
    ('strict-open-call', 'class A { m() { f(yield /a/) } }', 'fixture.js'),
    ('strict-nested-template', 'class A { m() { class B { n() { return `x ${yield /a/}` } } return `y ${yield /b/}` } }', 'fixture.js'),
    ('strict-nested-regex', 'class A { m() { class B { n() { return yield /a/ } } return yield /b/ } }', 'fixture.js'),
    ('strict-nested-block', 'class A { m() { class B { n() { { return yield /a/ } } } { return yield /b/ } } }', 'fixture.js'),
    ('strict-nested-call', 'class A { m() { class B { n() { f(yield /a/) } } f(yield /b/) } }', 'fixture.js'),
    ('strict-close-template', 'class A { m() { return `x ${yield /a/}` } }', 'fixture.js'),
    ('strict-close-regex', 'class A { m() { return yield /a/ } }', 'fixture.js'),
    ('strict-close-block', 'class A { m() { { return yield /a/ } } }', 'fixture.js'),
    ('strict-close-call', 'class A { m() { f(yield /a/) } }', 'fixture.js'),
    ('strict-mismatched-template', 'class A { m() { return `x ${yield /a/}` ] }', 'fixture.js'),
    ('strict-mismatched-regex', 'class A { m() { return yield /a/ ] }', 'fixture.js'),
    ('strict-mismatched-block', 'class A { m() { { return yield /a/ } ] }', 'fixture.js'),
    ('strict-mismatched-call', 'class A { m() { f(yield /a/) ] }', 'fixture.js'),
    ('strict-discard-template', 'class A { m() { return `x ${yield /a/}` } } function h() { return `y ${yield /b/}` }', 'fixture.js'),
    ('strict-discard-regex', 'class A { m() { return yield /a/ } } function h() { yield /b/ }', 'fixture.js'),
    ('strict-discard-block', 'class A { m() { { return yield /a/ } } } function h() { { yield /b/ } }', 'fixture.js'),
    ('strict-discard-call', 'class A { m() { f(yield /a/) } } function h() { f(yield /b/) }', 'fixture.js'),
    ('arrow-open-template', 'function* g() { const f = () => `x ${yield /a/}` }', 'fixture.js'),
    ('arrow-open-regex', 'function* g() { const f = () => yield /a/ }', 'fixture.js'),
    ('arrow-open-block', 'function* g() { const f = () => { yield /a/ } }', 'fixture.js'),
    ('arrow-open-call', 'function* g() { f(() => yield /a/) }', 'fixture.js'),
    ('arrow-nested-template', 'function* g() { f(x => [y => `x ${yield /a/}`]) }', 'fixture.js'),
    ('arrow-nested-regex', 'function* g() { f(x => [y => yield /a/]) }', 'fixture.js'),
    ('arrow-nested-block', 'function* g() { f(x => [y => (() => { return /a/ })()]) }', 'fixture.js'),
    ('arrow-nested-call', 'function* g() { f(x => h(y => yield /a/)) }', 'fixture.js'),
    ('arrow-close-template', 'const f = `x ${y => y}`', 'fixture.js'),
    ('arrow-close-regex', 'const f = [x => /a/]', 'fixture.js'),
    ('arrow-close-block', '{ x => x }', 'fixture.js'),
    ('arrow-close-call', 'f(x => x)', 'fixture.js'),
    ('arrow-mismatched-template', 'const f = () => `x ${1}` ]', 'fixture.js'),
    ('arrow-mismatched-regex', 'const f = () => /a/ ]', 'fixture.js'),
    ('arrow-mismatched-block', 'const f = () => { const x = 1 ]', 'fixture.js'),
    ('arrow-mismatched-call', 'const f = () => f(1) ]', 'fixture.js'),
    ('arrow-discard-template', 'function* g() { const x = `x ${y => y}`; return `y ${yield /a/}` }', 'fixture.js'),
    ('arrow-discard-regex', 'function* g() { const x = [y => y]; return [yield /a/]; }', 'fixture.js'),
    ('arrow-discard-block', 'function* g() { { y => y }\n{ yield /a/ } }', 'fixture.js'),
    ('arrow-discard-call', 'function* g() { f(y => y); f(yield /a/) }', 'fixture.js'),
    ('for_head-open-template', 'function h() { return `x ${for (const a of /b/) {}}` }', 'fixture.js'),
    ('for_head-open-regex', 'for (const x of /a/) {}', 'fixture.js'),
    ('for_head-open-block', 'for (const x of /a/) { const z = 1 }', 'fixture.js'),
    ('for_head-open-call', 'for (const x of /a/) { f(1) }', 'fixture.js'),
    ('for_head-nested-template', 'for (const x of `x ${function () { for (const y of /b/) {} }}`) {}', 'fixture.js'),
    ('for_head-nested-regex', 'for (const x of (() => { for (const y of /b/) {} return /a/ })()) {}', 'fixture.js'),
    ('for_head-nested-block', 'for (const x of (() => { for (const y of /b/) { const z = 1 } return x })()) {}', 'fixture.js'),
    ('for_head-nested-call', 'for (const x of f(() => { for (const y of /b/) {} })) {}', 'fixture.js'),
    ('for_head-close-template', 'for (const x of `a`) {}', 'fixture.js'),
    ('for_head-close-regex', 'for (const x of /a/) {}', 'fixture.js'),
    ('for_head-close-block', 'for (const x of /a/) { const z = 1 }', 'fixture.js'),
    ('for_head-close-call', 'for (const x of /a/) { f(1) }', 'fixture.js'),
    ('for_head-mismatched-template', 'for (const x of `a`) ]', 'fixture.js'),
    ('for_head-mismatched-regex', 'for (const x of /a/ ]', 'fixture.js'),
    ('for_head-mismatched-block', 'for (const x of /a/) { ]', 'fixture.js'),
    ('for_head-mismatched-call', 'for (const x of /a/) { f(1) ]', 'fixture.js'),
    ('for_head-discard-template', 'for (const x of /a/) {} if (b of /c/) {}', 'fixture.js'),
    ('for_head-discard-regex', 'for (const x of /a/) {} if (b of /c/) {}', 'fixture.js'),
    ('for_head-discard-block', 'for (const x of /a/) { const z = 1 } if (b of /c/) {}', 'fixture.js'),
    ('for_head-discard-call', 'for (const x of /a/) { f(1) } if (b of /c/) {}', 'fixture.js'),
    ('type_literal-open-template', 'const a = b as { f: `x ${<T>() => 1}` }', 'fixture.tsx'),
    ('type_literal-open-regex', 'const a = b as { f: /a/, g: <T>() => 1 }', 'fixture.tsx'),
    ('type_literal-open-block', 'const a = b as { f: { g: <T>() => 1 } }', 'fixture.tsx'),
    ('type_literal-open-call', 'const a = b as { f: g(<T>() => 1) }', 'fixture.tsx'),
    ('type_literal-nested-template', 'const a = b as { f: c as { h: `x ${<T>() => 1}` } }', 'fixture.tsx'),
    ('type_literal-nested-regex', 'const a = b as { f: c as { g: /a/ }, h: <T>() => 1 }', 'fixture.tsx'),
    ('type_literal-nested-block', 'const a = b as { f: c as { g: { h: <T>() => 1 } } }', 'fixture.tsx'),
    ('type_literal-nested-call', 'const a = b as { f: c as { g: h(<T>() => 1) } }', 'fixture.tsx'),
    ('type_literal-close-template', 'const a = b as { f: `a` }; eval(code)', 'fixture.ts'),
    ('type_literal-close-regex', 'const a = b as { f: /a/ }; eval(code)', 'fixture.ts'),
    ('type_literal-close-block', 'const a = b as { f: { x: 1 } }; eval(code)', 'fixture.ts'),
    ('type_literal-close-call', 'const a = b as { f: g(1) }; eval(code)', 'fixture.ts'),
    ('type_literal-mismatched-template', 'const a = b as { f: `a` ]', 'fixture.ts'),
    ('type_literal-mismatched-regex', 'const a = b as { f: /a/ ]', 'fixture.ts'),
    ('type_literal-mismatched-block', 'const a = b as { f: { x: 1 } ]', 'fixture.ts'),
    ('type_literal-mismatched-call', 'const a = b as { f: g(1) ]', 'fixture.ts'),
    ('type_literal-discard-template', 'const a = b as { f: `a` }; const c = <A />', 'fixture.tsx'),
    ('type_literal-discard-regex', 'const a = b as { f: /a/ }; const c = <A />', 'fixture.tsx'),
    ('type_literal-discard-block', 'const a = b as { f: { x: 1 } }; const c = <A />', 'fixture.tsx'),
    ('type_literal-discard-call', 'const a = b as { f: g(1) }; const c = <A />', 'fixture.tsx'),
)


def _frame_outcome(tokenize, error_type, source, path, compact):
    try:
        return ('tokens', tokenize(source, path, compact=compact))
    except error_type as exc:
        return ('refusal', type(exc).__name__, exc.reason, exc.line, exc.offset,
                exc.limit_bytes, exc.code, exc.message, exc.args, str(exc))


@pytest.mark.parametrize('case,source,path', _FRAME_MATRIX, ids=[row[0] for row in _FRAME_MATRIX])
@pytest.mark.parametrize('compact', [False, True], ids=['default', 'compact'])
def test_frame_depth_kind_matrix(case, source, path, compact):
    from aegis_core.ast.drivers.js.tokenizer import JSLexError, tokenize

    golden = _FRAME_GOLDEN_COMPACT.get(case, _FRAME_GOLDEN_DEFAULT[case]) if compact else _FRAME_GOLDEN_DEFAULT[case]
    assert _frame_outcome(tokenize, JSLexError, source, path, compact) == golden


# Complete baseline results from 3015c09094f9559384aa96d9ebfcb22a23933172.
# Compact rows absent from the second table match their default snapshot.
_FRAME_GOLDEN_DEFAULT = {
    'generator-open-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'return', 1, 16, 22, '', None), ('template_start', '`', 1, 23, 24, '', None),
            ('template_text', 'x ', 1, 24, 26, '', None), ('punct', '${', 1, 26, 28, 'interpolation', None),
            ('identifier', 'yield', 1, 28, 33, '', None), ('regex', '/a/', 1, 34, 37, '', None),
            ('punct', '}', 1, 37, 38, 'interpolation', None), ('template_end', '`', 1, 38, 39, '', None),
            ('punct', '}', 1, 40, 41, 'function_decl', None),
        ],
    ),
    'generator-open-regex': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'yield', 1, 16, 21, '', None), ('regex', '/a/', 1, 22, 25, '', None),
            ('punct', '}', 1, 26, 27, 'function_decl', None),
        ],
    ),
    'generator-open-block': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('punct', '{', 1, 16, 17, 'block', None), ('identifier', 'yield', 1, 18, 23, '', None),
            ('regex', '/a/', 1, 24, 27, '', None), ('punct', '}', 1, 28, 29, 'block', None),
            ('punct', '}', 1, 30, 31, 'function_decl', None),
        ],
    ),
    'generator-open-call': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'f', 1, 16, 17, '', None), ('punct', '(', 1, 17, 18, 'expression', None),
            ('identifier', 'yield', 1, 18, 23, '', None), ('regex', '/a/', 1, 24, 27, '', None),
            ('punct', ')', 1, 27, 28, 'expression', None), ('punct', '}', 1, 29, 30, 'function_decl', None),
        ],
    ),
    'generator-nested-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'function', 1, 16, 24, '', None), ('punct', '*', 1, 24, 25, '', None),
            ('identifier', 'h', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_decl', None),
            ('punct', ')', 1, 28, 29, 'parameters_decl', None), ('punct', '{', 1, 30, 31, 'function_decl', None),
            ('identifier', 'return', 1, 32, 38, '', None), ('template_start', '`', 1, 39, 40, '', None),
            ('template_text', 'x ', 1, 40, 42, '', None), ('punct', '${', 1, 42, 44, 'interpolation', None),
            ('identifier', 'yield', 1, 44, 49, '', None), ('regex', '/a/', 1, 50, 53, '', None),
            ('punct', '}', 1, 53, 54, 'interpolation', None), ('template_end', '`', 1, 54, 55, '', None),
            ('punct', '}', 1, 56, 57, 'function_decl', None), ('identifier', 'return', 1, 58, 64, '', None),
            ('template_start', '`', 1, 65, 66, '', None), ('template_text', 'y ', 1, 66, 68, '', None),
            ('punct', '${', 1, 68, 70, 'interpolation', None), ('identifier', 'yield', 1, 70, 75, '', None),
            ('regex', '/b/', 1, 76, 79, '', None), ('punct', '}', 1, 79, 80, 'interpolation', None),
            ('template_end', '`', 1, 80, 81, '', None), ('punct', '}', 1, 82, 83, 'function_decl', None),
        ],
    ),
    'generator-nested-regex': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'function', 1, 16, 24, '', None), ('punct', '*', 1, 24, 25, '', None),
            ('identifier', 'h', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_decl', None),
            ('punct', ')', 1, 28, 29, 'parameters_decl', None), ('punct', '{', 1, 30, 31, 'function_decl', None),
            ('identifier', 'yield', 1, 32, 37, '', None), ('regex', '/a/', 1, 38, 41, '', None),
            ('punct', '}', 1, 42, 43, 'function_decl', None), ('identifier', 'yield', 1, 44, 49, '', None),
            ('regex', '/b/', 1, 50, 53, '', None), ('punct', '}', 1, 54, 55, 'function_decl', None),
        ],
    ),
    'generator-nested-block': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'function', 1, 16, 24, '', None), ('punct', '*', 1, 24, 25, '', None),
            ('identifier', 'h', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_decl', None),
            ('punct', ')', 1, 28, 29, 'parameters_decl', None), ('punct', '{', 1, 30, 31, 'function_decl', None),
            ('punct', '{', 1, 32, 33, 'block', None), ('identifier', 'yield', 1, 34, 39, '', None),
            ('regex', '/a/', 1, 40, 43, '', None), ('punct', '}', 1, 44, 45, 'block', None),
            ('punct', '}', 1, 46, 47, 'function_decl', None), ('punct', '{', 1, 48, 49, 'block', None),
            ('identifier', 'yield', 1, 50, 55, '', None), ('regex', '/b/', 1, 56, 59, '', None),
            ('punct', '}', 1, 60, 61, 'block', None), ('punct', '}', 1, 62, 63, 'function_decl', None),
        ],
    ),
    'generator-nested-call': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'function', 1, 16, 24, '', None), ('punct', '*', 1, 24, 25, '', None),
            ('identifier', 'h', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_decl', None),
            ('punct', ')', 1, 28, 29, 'parameters_decl', None), ('punct', '{', 1, 30, 31, 'function_decl', None),
            ('identifier', 'f', 1, 32, 33, '', None), ('punct', '(', 1, 33, 34, 'expression', None),
            ('identifier', 'yield', 1, 34, 39, '', None), ('regex', '/a/', 1, 40, 43, '', None),
            ('punct', ')', 1, 43, 44, 'expression', None), ('punct', '}', 1, 45, 46, 'function_decl', None),
            ('identifier', 'f', 1, 47, 48, '', None), ('punct', '(', 1, 48, 49, 'expression', None),
            ('identifier', 'yield', 1, 49, 54, '', None), ('regex', '/b/', 1, 55, 58, '', None),
            ('punct', ')', 1, 58, 59, 'expression', None), ('punct', '}', 1, 60, 61, 'function_decl', None),
        ],
    ),
    'generator-close-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'return', 1, 16, 22, '', None), ('template_start', '`', 1, 23, 24, '', None),
            ('template_text', 'x ', 1, 24, 26, '', None), ('punct', '${', 1, 26, 28, 'interpolation', None),
            ('identifier', 'yield', 1, 28, 33, '', None), ('regex', '/a/', 1, 34, 37, '', None),
            ('punct', '}', 1, 37, 38, 'interpolation', None), ('template_end', '`', 1, 38, 39, '', None),
            ('punct', '}', 1, 40, 41, 'function_decl', None),
        ],
    ),
    'generator-close-regex': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'yield', 1, 16, 21, '', None), ('regex', '/a/', 1, 22, 25, '', None),
            ('punct', '}', 1, 26, 27, 'function_decl', None),
        ],
    ),
    'generator-close-block': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('punct', '{', 1, 16, 17, 'block', None), ('identifier', 'yield', 1, 18, 23, '', None),
            ('regex', '/a/', 1, 24, 27, '', None), ('punct', '}', 1, 28, 29, 'block', None),
            ('punct', '}', 1, 30, 31, 'function_decl', None),
        ],
    ),
    'generator-close-call': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'f', 1, 16, 17, '', None), ('punct', '(', 1, 17, 18, 'expression', None),
            ('identifier', 'yield', 1, 18, 23, '', None), ('regex', '/a/', 1, 24, 27, '', None),
            ('punct', ')', 1, 27, 28, 'expression', None), ('punct', '}', 1, 29, 30, 'function_decl', None),
        ],
    ),
    'generator-mismatched-template': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 40,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 40',
        ('syntax:unbalanced_delimiter at line 1, offset 40',), 'syntax:unbalanced_delimiter at line 1, offset 40',
    ),
    'generator-mismatched-regex': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 26,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 26',
        ('syntax:unbalanced_delimiter at line 1, offset 26',), 'syntax:unbalanced_delimiter at line 1, offset 26',
    ),
    'generator-mismatched-block': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 30,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 30',
        ('syntax:unbalanced_delimiter at line 1, offset 30',), 'syntax:unbalanced_delimiter at line 1, offset 30',
    ),
    'generator-mismatched-call': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 29,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 29',
        ('syntax:unbalanced_delimiter at line 1, offset 29',), 'syntax:unbalanced_delimiter at line 1, offset 29',
    ),
    'generator-discard-template': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 75,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 75',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 75',), 'unsupported_lexical_context:contextual_yield at line 1, offset 75',
    ),
    'generator-discard-regex': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 49,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 49',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 49',), 'unsupported_lexical_context:contextual_yield at line 1, offset 49',
    ),
    'generator-discard-block': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 55,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 55',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 55',), 'unsupported_lexical_context:contextual_yield at line 1, offset 55',
    ),
    'generator-discard-call': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 54,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 54',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 54',), 'unsupported_lexical_context:contextual_yield at line 1, offset 54',
    ),
    'strict-open-template': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'return', 1, 16, 22, '', None),
            ('template_start', '`', 1, 23, 24, '', None), ('template_text', 'x ', 1, 24, 26, '', None),
            ('punct', '${', 1, 26, 28, 'interpolation', None), ('identifier', 'yield', 1, 28, 33, '', None),
            ('regex', '/a/', 1, 34, 37, '', None), ('punct', '}', 1, 37, 38, 'interpolation', None),
            ('template_end', '`', 1, 38, 39, '', None), ('punct', '}', 1, 40, 41, 'function_expr', None),
            ('punct', '}', 1, 42, 43, 'class_decl', None),
        ],
    ),
    'strict-open-regex': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'return', 1, 16, 22, '', None),
            ('identifier', 'yield', 1, 23, 28, '', None), ('regex', '/a/', 1, 29, 32, '', None),
            ('punct', '}', 1, 33, 34, 'function_expr', None), ('punct', '}', 1, 35, 36, 'class_decl', None),
        ],
    ),
    'strict-open-block': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('punct', '{', 1, 16, 17, 'block', None),
            ('identifier', 'return', 1, 18, 24, '', None), ('identifier', 'yield', 1, 25, 30, '', None),
            ('regex', '/a/', 1, 31, 34, '', None), ('punct', '}', 1, 35, 36, 'block', None),
            ('punct', '}', 1, 37, 38, 'function_expr', None), ('punct', '}', 1, 39, 40, 'class_decl', None),
        ],
    ),
    'strict-open-call': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'f', 1, 16, 17, '', None),
            ('punct', '(', 1, 17, 18, 'expression', None), ('identifier', 'yield', 1, 18, 23, '', None),
            ('regex', '/a/', 1, 24, 27, '', None), ('punct', ')', 1, 27, 28, 'expression', None),
            ('punct', '}', 1, 29, 30, 'function_expr', None), ('punct', '}', 1, 31, 32, 'class_decl', None),
        ],
    ),
    'strict-nested-template': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'class', 1, 16, 21, '', None),
            ('identifier', 'B', 1, 22, 23, '', None), ('punct', '{', 1, 24, 25, 'class_decl', None),
            ('identifier', 'n', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_method', None),
            ('punct', ')', 1, 28, 29, 'parameters_method', None), ('punct', '{', 1, 30, 31, 'function_expr', None),
            ('identifier', 'return', 1, 32, 38, '', None), ('template_start', '`', 1, 39, 40, '', None),
            ('template_text', 'x ', 1, 40, 42, '', None), ('punct', '${', 1, 42, 44, 'interpolation', None),
            ('identifier', 'yield', 1, 44, 49, '', None), ('regex', '/a/', 1, 50, 53, '', None),
            ('punct', '}', 1, 53, 54, 'interpolation', None), ('template_end', '`', 1, 54, 55, '', None),
            ('punct', '}', 1, 56, 57, 'function_expr', None), ('punct', '}', 1, 58, 59, 'class_decl', None),
            ('identifier', 'return', 1, 60, 66, '', None), ('template_start', '`', 1, 67, 68, '', None),
            ('template_text', 'y ', 1, 68, 70, '', None), ('punct', '${', 1, 70, 72, 'interpolation', None),
            ('identifier', 'yield', 1, 72, 77, '', None), ('regex', '/b/', 1, 78, 81, '', None),
            ('punct', '}', 1, 81, 82, 'interpolation', None), ('template_end', '`', 1, 82, 83, '', None),
            ('punct', '}', 1, 84, 85, 'function_expr', None), ('punct', '}', 1, 86, 87, 'class_decl', None),
        ],
    ),
    'strict-nested-regex': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'class', 1, 16, 21, '', None),
            ('identifier', 'B', 1, 22, 23, '', None), ('punct', '{', 1, 24, 25, 'class_decl', None),
            ('identifier', 'n', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_method', None),
            ('punct', ')', 1, 28, 29, 'parameters_method', None), ('punct', '{', 1, 30, 31, 'function_expr', None),
            ('identifier', 'return', 1, 32, 38, '', None), ('identifier', 'yield', 1, 39, 44, '', None),
            ('regex', '/a/', 1, 45, 48, '', None), ('punct', '}', 1, 49, 50, 'function_expr', None),
            ('punct', '}', 1, 51, 52, 'class_decl', None), ('identifier', 'return', 1, 53, 59, '', None),
            ('identifier', 'yield', 1, 60, 65, '', None), ('regex', '/b/', 1, 66, 69, '', None),
            ('punct', '}', 1, 70, 71, 'function_expr', None), ('punct', '}', 1, 72, 73, 'class_decl', None),
        ],
    ),
    'strict-nested-block': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'class', 1, 16, 21, '', None),
            ('identifier', 'B', 1, 22, 23, '', None), ('punct', '{', 1, 24, 25, 'class_decl', None),
            ('identifier', 'n', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_method', None),
            ('punct', ')', 1, 28, 29, 'parameters_method', None), ('punct', '{', 1, 30, 31, 'function_expr', None),
            ('punct', '{', 1, 32, 33, 'block', None), ('identifier', 'return', 1, 34, 40, '', None),
            ('identifier', 'yield', 1, 41, 46, '', None), ('regex', '/a/', 1, 47, 50, '', None),
            ('punct', '}', 1, 51, 52, 'block', None), ('punct', '}', 1, 53, 54, 'function_expr', None),
            ('punct', '}', 1, 55, 56, 'class_decl', None), ('punct', '{', 1, 57, 58, 'block', None),
            ('identifier', 'return', 1, 59, 65, '', None), ('identifier', 'yield', 1, 66, 71, '', None),
            ('regex', '/b/', 1, 72, 75, '', None), ('punct', '}', 1, 76, 77, 'block', None),
            ('punct', '}', 1, 78, 79, 'function_expr', None), ('punct', '}', 1, 80, 81, 'class_decl', None),
        ],
    ),
    'strict-nested-call': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'class', 1, 16, 21, '', None),
            ('identifier', 'B', 1, 22, 23, '', None), ('punct', '{', 1, 24, 25, 'class_decl', None),
            ('identifier', 'n', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_method', None),
            ('punct', ')', 1, 28, 29, 'parameters_method', None), ('punct', '{', 1, 30, 31, 'function_expr', None),
            ('identifier', 'f', 1, 32, 33, '', None), ('punct', '(', 1, 33, 34, 'expression', None),
            ('identifier', 'yield', 1, 34, 39, '', None), ('regex', '/a/', 1, 40, 43, '', None),
            ('punct', ')', 1, 43, 44, 'expression', None), ('punct', '}', 1, 45, 46, 'function_expr', None),
            ('punct', '}', 1, 47, 48, 'class_decl', None), ('identifier', 'f', 1, 49, 50, '', None),
            ('punct', '(', 1, 50, 51, 'expression', None), ('identifier', 'yield', 1, 51, 56, '', None),
            ('regex', '/b/', 1, 57, 60, '', None), ('punct', ')', 1, 60, 61, 'expression', None),
            ('punct', '}', 1, 62, 63, 'function_expr', None), ('punct', '}', 1, 64, 65, 'class_decl', None),
        ],
    ),
    'strict-close-template': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'return', 1, 16, 22, '', None),
            ('template_start', '`', 1, 23, 24, '', None), ('template_text', 'x ', 1, 24, 26, '', None),
            ('punct', '${', 1, 26, 28, 'interpolation', None), ('identifier', 'yield', 1, 28, 33, '', None),
            ('regex', '/a/', 1, 34, 37, '', None), ('punct', '}', 1, 37, 38, 'interpolation', None),
            ('template_end', '`', 1, 38, 39, '', None), ('punct', '}', 1, 40, 41, 'function_expr', None),
            ('punct', '}', 1, 42, 43, 'class_decl', None),
        ],
    ),
    'strict-close-regex': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'return', 1, 16, 22, '', None),
            ('identifier', 'yield', 1, 23, 28, '', None), ('regex', '/a/', 1, 29, 32, '', None),
            ('punct', '}', 1, 33, 34, 'function_expr', None), ('punct', '}', 1, 35, 36, 'class_decl', None),
        ],
    ),
    'strict-close-block': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('punct', '{', 1, 16, 17, 'block', None),
            ('identifier', 'return', 1, 18, 24, '', None), ('identifier', 'yield', 1, 25, 30, '', None),
            ('regex', '/a/', 1, 31, 34, '', None), ('punct', '}', 1, 35, 36, 'block', None),
            ('punct', '}', 1, 37, 38, 'function_expr', None), ('punct', '}', 1, 39, 40, 'class_decl', None),
        ],
    ),
    'strict-close-call': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'f', 1, 16, 17, '', None),
            ('punct', '(', 1, 17, 18, 'expression', None), ('identifier', 'yield', 1, 18, 23, '', None),
            ('regex', '/a/', 1, 24, 27, '', None), ('punct', ')', 1, 27, 28, 'expression', None),
            ('punct', '}', 1, 29, 30, 'function_expr', None), ('punct', '}', 1, 31, 32, 'class_decl', None),
        ],
    ),
    'strict-mismatched-template': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 40,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 40',
        ('syntax:unbalanced_delimiter at line 1, offset 40',), 'syntax:unbalanced_delimiter at line 1, offset 40',
    ),
    'strict-mismatched-regex': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 33,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 33',
        ('syntax:unbalanced_delimiter at line 1, offset 33',), 'syntax:unbalanced_delimiter at line 1, offset 33',
    ),
    'strict-mismatched-block': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 37,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 37',
        ('syntax:unbalanced_delimiter at line 1, offset 37',), 'syntax:unbalanced_delimiter at line 1, offset 37',
    ),
    'strict-mismatched-call': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 29,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 29',
        ('syntax:unbalanced_delimiter at line 1, offset 29',), 'syntax:unbalanced_delimiter at line 1, offset 29',
    ),
    'strict-discard-template': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 77,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 77',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 77',), 'unsupported_lexical_context:contextual_yield at line 1, offset 77',
    ),
    'strict-discard-regex': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 58,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 58',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 58',), 'unsupported_lexical_context:contextual_yield at line 1, offset 58',
    ),
    'strict-discard-block': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 64,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 64',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 64',), 'unsupported_lexical_context:contextual_yield at line 1, offset 64',
    ),
    'strict-discard-call': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 56,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 56',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 56',), 'unsupported_lexical_context:contextual_yield at line 1, offset 56',
    ),
    'arrow-open-template': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 43,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 43',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 43',), 'unsupported_lexical_context:contextual_yield at line 1, offset 43',
    ),
    'arrow-open-regex': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 38,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 38',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 38',), 'unsupported_lexical_context:contextual_yield at line 1, offset 38',
    ),
    'arrow-open-block': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 40,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 40',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 40',), 'unsupported_lexical_context:contextual_yield at line 1, offset 40',
    ),
    'arrow-open-call': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 30,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 30',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 30',), 'unsupported_lexical_context:contextual_yield at line 1, offset 30',
    ),
    'arrow-nested-template': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 40,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 40',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 40',), 'unsupported_lexical_context:contextual_yield at line 1, offset 40',
    ),
    'arrow-nested-regex': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 35,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 35',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 35',), 'unsupported_lexical_context:contextual_yield at line 1, offset 35',
    ),
    'arrow-nested-block': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'f', 1, 16, 17, '', None), ('punct', '(', 1, 17, 18, 'expression', None),
            ('identifier', 'x', 1, 18, 19, '', None), ('punct', '=>', 1, 20, 22, '', None),
            ('punct', '[', 1, 23, 24, 'array', None), ('identifier', 'y', 1, 24, 25, '', None),
            ('punct', '=>', 1, 26, 28, '', None), ('punct', '(', 1, 29, 30, 'expression', None),
            ('punct', '(', 1, 30, 31, 'expression', None), ('punct', ')', 1, 31, 32, 'expression', None),
            ('punct', '=>', 1, 33, 35, '', None), ('punct', '{', 1, 36, 37, 'function_arrow', None),
            ('identifier', 'return', 1, 38, 44, '', None), ('regex', '/a/', 1, 45, 48, '', None),
            ('punct', '}', 1, 49, 50, 'function_arrow', None), ('punct', ')', 1, 50, 51, 'expression', None),
            ('punct', '(', 1, 51, 52, 'expression', None), ('punct', ')', 1, 52, 53, 'expression', None),
            ('punct', ']', 1, 53, 54, 'array', None), ('punct', ')', 1, 54, 55, 'expression', None),
            ('punct', '}', 1, 56, 57, 'function_decl', None),
        ],
    ),
    'arrow-nested-call': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:contextual_yield', 1, 36,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:contextual_yield at line 1, offset 36',
        ('unsupported_lexical_context:contextual_yield at line 1, offset 36',), 'unsupported_lexical_context:contextual_yield at line 1, offset 36',
    ),
    'arrow-close-template': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'f', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('template_start', '`', 1, 10, 11, '', None),
            ('template_text', 'x ', 1, 11, 13, '', None), ('punct', '${', 1, 13, 15, 'interpolation', None),
            ('identifier', 'y', 1, 15, 16, '', None), ('punct', '=>', 1, 17, 19, '', None),
            ('identifier', 'y', 1, 20, 21, '', None), ('punct', '}', 1, 21, 22, 'interpolation', None),
            ('template_end', '`', 1, 22, 23, '', None),
        ],
    ),
    'arrow-close-regex': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'f', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('punct', '[', 1, 10, 11, 'array', None),
            ('identifier', 'x', 1, 11, 12, '', None), ('punct', '=>', 1, 13, 15, '', None),
            ('regex', '/a/', 1, 16, 19, '', None), ('punct', ']', 1, 19, 20, 'array', None),
        ],
    ),
    'arrow-close-block': (
        'tokens', [
            ('punct', '{', 1, 0, 1, 'block', None), ('identifier', 'x', 1, 2, 3, '', None),
            ('punct', '=>', 1, 4, 6, '', None), ('identifier', 'x', 1, 7, 8, '', None),
            ('punct', '}', 1, 9, 10, 'block', None),
        ],
    ),
    'arrow-close-call': (
        'tokens', [
            ('identifier', 'f', 1, 0, 1, '', None), ('punct', '(', 1, 1, 2, 'expression', None),
            ('identifier', 'x', 1, 2, 3, '', None), ('punct', '=>', 1, 4, 6, '', None),
            ('identifier', 'x', 1, 7, 8, '', None), ('punct', ')', 1, 8, 9, 'expression', None),
        ],
    ),
    'arrow-mismatched-template': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 25,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 25',
        ('syntax:unbalanced_delimiter at line 1, offset 25',), 'syntax:unbalanced_delimiter at line 1, offset 25',
    ),
    'arrow-mismatched-regex': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 20,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 20',
        ('syntax:unbalanced_delimiter at line 1, offset 20',), 'syntax:unbalanced_delimiter at line 1, offset 20',
    ),
    'arrow-mismatched-block': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 30,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 30',
        ('syntax:unbalanced_delimiter at line 1, offset 30',), 'syntax:unbalanced_delimiter at line 1, offset 30',
    ),
    'arrow-mismatched-call': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 21,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 21',
        ('syntax:unbalanced_delimiter at line 1, offset 21',), 'syntax:unbalanced_delimiter at line 1, offset 21',
    ),
    'arrow-discard-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'const', 1, 16, 21, '', None), ('identifier', 'x', 1, 22, 23, '', None),
            ('punct', '=', 1, 24, 25, '', None), ('template_start', '`', 1, 26, 27, '', None),
            ('template_text', 'x ', 1, 27, 29, '', None), ('punct', '${', 1, 29, 31, 'interpolation', None),
            ('identifier', 'y', 1, 31, 32, '', None), ('punct', '=>', 1, 33, 35, '', None),
            ('identifier', 'y', 1, 36, 37, '', None), ('punct', '}', 1, 37, 38, 'interpolation', None),
            ('template_end', '`', 1, 38, 39, '', None), ('punct', ';', 1, 39, 40, '', None),
            ('identifier', 'return', 1, 41, 47, '', None), ('template_start', '`', 1, 48, 49, '', None),
            ('template_text', 'y ', 1, 49, 51, '', None), ('punct', '${', 1, 51, 53, 'interpolation', None),
            ('identifier', 'yield', 1, 53, 58, '', None), ('regex', '/a/', 1, 59, 62, '', None),
            ('punct', '}', 1, 62, 63, 'interpolation', None), ('template_end', '`', 1, 63, 64, '', None),
            ('punct', '}', 1, 65, 66, 'function_decl', None),
        ],
    ),
    'arrow-discard-regex': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'const', 1, 16, 21, '', None), ('identifier', 'x', 1, 22, 23, '', None),
            ('punct', '=', 1, 24, 25, '', None), ('punct', '[', 1, 26, 27, 'array', None),
            ('identifier', 'y', 1, 27, 28, '', None), ('punct', '=>', 1, 29, 31, '', None),
            ('identifier', 'y', 1, 32, 33, '', None), ('punct', ']', 1, 33, 34, 'array', None),
            ('punct', ';', 1, 34, 35, '', None), ('identifier', 'return', 1, 36, 42, '', None),
            ('punct', '[', 1, 43, 44, 'array', None), ('identifier', 'yield', 1, 44, 49, '', None),
            ('regex', '/a/', 1, 50, 53, '', None), ('punct', ']', 1, 53, 54, 'array', None),
            ('punct', ';', 1, 54, 55, '', None), ('punct', '}', 1, 56, 57, 'function_decl', None),
        ],
    ),
    'arrow-discard-block': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('punct', '{', 1, 16, 17, 'block', None), ('identifier', 'y', 1, 18, 19, '', None),
            ('punct', '=>', 1, 20, 22, '', None), ('identifier', 'y', 1, 23, 24, '', None),
            ('punct', '}', 1, 25, 26, 'block', None), ('punct', '{', 2, 27, 28, 'block', None),
            ('identifier', 'yield', 2, 29, 34, '', None), ('regex', '/a/', 2, 35, 38, '', None),
            ('punct', '}', 2, 39, 40, 'block', None), ('punct', '}', 2, 41, 42, 'function_decl', None),
        ],
    ),
    'arrow-discard-call': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'f', 1, 16, 17, '', None), ('punct', '(', 1, 17, 18, 'expression', None),
            ('identifier', 'y', 1, 18, 19, '', None), ('punct', '=>', 1, 20, 22, '', None),
            ('identifier', 'y', 1, 23, 24, '', None), ('punct', ')', 1, 24, 25, 'expression', None),
            ('punct', ';', 1, 25, 26, '', None), ('identifier', 'f', 1, 27, 28, '', None),
            ('punct', '(', 1, 28, 29, 'expression', None), ('identifier', 'yield', 1, 29, 34, '', None),
            ('regex', '/a/', 1, 35, 38, '', None), ('punct', ')', 1, 38, 39, 'expression', None),
            ('punct', '}', 1, 40, 41, 'function_decl', None),
        ],
    ),
    'for_head-open-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('identifier', 'h', 1, 9, 10, '', None),
            ('punct', '(', 1, 10, 11, 'parameters_decl', None), ('punct', ')', 1, 11, 12, 'parameters_decl', None),
            ('punct', '{', 1, 13, 14, 'function_decl', None), ('identifier', 'return', 1, 15, 21, '', None),
            ('template_start', '`', 1, 22, 23, '', None), ('template_text', 'x ', 1, 23, 25, '', None),
            ('punct', '${', 1, 25, 27, 'interpolation', None), ('identifier', 'for', 1, 27, 30, '', None),
            ('punct', '(', 1, 31, 32, 'control', None), ('identifier', 'const', 1, 32, 37, '', None),
            ('identifier', 'a', 1, 38, 39, '', None), ('identifier', 'of', 1, 40, 42, '', None),
            ('regex', '/b/', 1, 43, 46, '', None), ('punct', ')', 1, 46, 47, 'control', None),
            ('punct', '{', 1, 48, 49, 'block', None), ('punct', '}', 1, 49, 50, 'block', None),
            ('punct', '}', 1, 50, 51, 'interpolation', None), ('template_end', '`', 1, 51, 52, '', None),
            ('punct', '}', 1, 53, 54, 'function_decl', None),
        ],
    ),
    'for_head-open-regex': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('punct', '}', 1, 22, 23, 'block', None),
        ],
    ),
    'for_head-open-block': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('identifier', 'const', 1, 23, 28, '', None), ('identifier', 'z', 1, 29, 30, '', None),
            ('punct', '=', 1, 31, 32, '', None), ('number', '1', 1, 33, 34, '', None),
            ('punct', '}', 1, 35, 36, 'block', None),
        ],
    ),
    'for_head-open-call': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('identifier', 'f', 1, 23, 24, '', None), ('punct', '(', 1, 24, 25, 'expression', None),
            ('number', '1', 1, 25, 26, '', None), ('punct', ')', 1, 26, 27, 'expression', None),
            ('punct', '}', 1, 28, 29, 'block', None),
        ],
    ),
    'for_head-nested-template': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('template_start', '`', 1, 16, 17, '', None),
            ('template_text', 'x ', 1, 17, 19, '', None), ('punct', '${', 1, 19, 21, 'interpolation', None),
            ('identifier', 'function', 1, 21, 29, '', None), ('punct', '(', 1, 30, 31, 'parameters_expr', None),
            ('punct', ')', 1, 31, 32, 'parameters_expr', None), ('punct', '{', 1, 33, 34, 'function_expr', None),
            ('identifier', 'for', 1, 35, 38, '', None), ('punct', '(', 1, 39, 40, 'control', None),
            ('identifier', 'const', 1, 40, 45, '', None), ('identifier', 'y', 1, 46, 47, '', None),
            ('identifier', 'of', 1, 48, 50, '', None), ('regex', '/b/', 1, 51, 54, '', None),
            ('punct', ')', 1, 54, 55, 'control', None), ('punct', '{', 1, 56, 57, 'block', None),
            ('punct', '}', 1, 57, 58, 'block', None), ('punct', '}', 1, 59, 60, 'function_expr', None),
            ('punct', '}', 1, 60, 61, 'interpolation', None), ('template_end', '`', 1, 61, 62, '', None),
            ('punct', ')', 1, 62, 63, 'control', None), ('punct', '{', 1, 64, 65, 'block', None),
            ('punct', '}', 1, 65, 66, 'block', None),
        ],
    ),
    'for_head-nested-regex': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('punct', '(', 1, 16, 17, 'expression', None),
            ('punct', '(', 1, 17, 18, 'expression', None), ('punct', ')', 1, 18, 19, 'expression', None),
            ('punct', '=>', 1, 20, 22, '', None), ('punct', '{', 1, 23, 24, 'function_arrow', None),
            ('identifier', 'for', 1, 25, 28, '', None), ('punct', '(', 1, 29, 30, 'control', None),
            ('identifier', 'const', 1, 30, 35, '', None), ('identifier', 'y', 1, 36, 37, '', None),
            ('identifier', 'of', 1, 38, 40, '', None), ('regex', '/b/', 1, 41, 44, '', None),
            ('punct', ')', 1, 44, 45, 'control', None), ('punct', '{', 1, 46, 47, 'block', None),
            ('punct', '}', 1, 47, 48, 'block', None), ('identifier', 'return', 1, 49, 55, '', None),
            ('regex', '/a/', 1, 56, 59, '', None), ('punct', '}', 1, 60, 61, 'function_arrow', None),
            ('punct', ')', 1, 61, 62, 'expression', None), ('punct', '(', 1, 62, 63, 'expression', None),
            ('punct', ')', 1, 63, 64, 'expression', None), ('punct', ')', 1, 64, 65, 'control', None),
            ('punct', '{', 1, 66, 67, 'block', None), ('punct', '}', 1, 67, 68, 'block', None),
        ],
    ),
    'for_head-nested-block': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('punct', '(', 1, 16, 17, 'expression', None),
            ('punct', '(', 1, 17, 18, 'expression', None), ('punct', ')', 1, 18, 19, 'expression', None),
            ('punct', '=>', 1, 20, 22, '', None), ('punct', '{', 1, 23, 24, 'function_arrow', None),
            ('identifier', 'for', 1, 25, 28, '', None), ('punct', '(', 1, 29, 30, 'control', None),
            ('identifier', 'const', 1, 30, 35, '', None), ('identifier', 'y', 1, 36, 37, '', None),
            ('identifier', 'of', 1, 38, 40, '', None), ('regex', '/b/', 1, 41, 44, '', None),
            ('punct', ')', 1, 44, 45, 'control', None), ('punct', '{', 1, 46, 47, 'block', None),
            ('identifier', 'const', 1, 48, 53, '', None), ('identifier', 'z', 1, 54, 55, '', None),
            ('punct', '=', 1, 56, 57, '', None), ('number', '1', 1, 58, 59, '', None),
            ('punct', '}', 1, 60, 61, 'block', None), ('identifier', 'return', 1, 62, 68, '', None),
            ('identifier', 'x', 1, 69, 70, '', None), ('punct', '}', 1, 71, 72, 'function_arrow', None),
            ('punct', ')', 1, 72, 73, 'expression', None), ('punct', '(', 1, 73, 74, 'expression', None),
            ('punct', ')', 1, 74, 75, 'expression', None), ('punct', ')', 1, 75, 76, 'control', None),
            ('punct', '{', 1, 77, 78, 'block', None), ('punct', '}', 1, 78, 79, 'block', None),
        ],
    ),
    'for_head-nested-call': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('identifier', 'f', 1, 16, 17, '', None),
            ('punct', '(', 1, 17, 18, 'expression', None), ('punct', '(', 1, 18, 19, 'expression', None),
            ('punct', ')', 1, 19, 20, 'expression', None), ('punct', '=>', 1, 21, 23, '', None),
            ('punct', '{', 1, 24, 25, 'function_arrow', None), ('identifier', 'for', 1, 26, 29, '', None),
            ('punct', '(', 1, 30, 31, 'control', None), ('identifier', 'const', 1, 31, 36, '', None),
            ('identifier', 'y', 1, 37, 38, '', None), ('identifier', 'of', 1, 39, 41, '', None),
            ('regex', '/b/', 1, 42, 45, '', None), ('punct', ')', 1, 45, 46, 'control', None),
            ('punct', '{', 1, 47, 48, 'block', None), ('punct', '}', 1, 48, 49, 'block', None),
            ('punct', '}', 1, 50, 51, 'function_arrow', None), ('punct', ')', 1, 51, 52, 'expression', None),
            ('punct', ')', 1, 52, 53, 'control', None), ('punct', '{', 1, 54, 55, 'block', None),
            ('punct', '}', 1, 55, 56, 'block', None),
        ],
    ),
    'for_head-close-template': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('template_start', '`', 1, 16, 17, '', None),
            ('template_text', 'a', 1, 17, 18, '', None), ('template_end', '`', 1, 18, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('punct', '}', 1, 22, 23, 'block', None),
        ],
    ),
    'for_head-close-regex': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('punct', '}', 1, 22, 23, 'block', None),
        ],
    ),
    'for_head-close-block': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('identifier', 'const', 1, 23, 28, '', None), ('identifier', 'z', 1, 29, 30, '', None),
            ('punct', '=', 1, 31, 32, '', None), ('number', '1', 1, 33, 34, '', None),
            ('punct', '}', 1, 35, 36, 'block', None),
        ],
    ),
    'for_head-close-call': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('identifier', 'f', 1, 23, 24, '', None), ('punct', '(', 1, 24, 25, 'expression', None),
            ('number', '1', 1, 25, 26, '', None), ('punct', ')', 1, 26, 27, 'expression', None),
            ('punct', '}', 1, 28, 29, 'block', None),
        ],
    ),
    'for_head-mismatched-template': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 21,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 21',
        ('syntax:unbalanced_delimiter at line 1, offset 21',), 'syntax:unbalanced_delimiter at line 1, offset 21',
    ),
    'for_head-mismatched-regex': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 20,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 20',
        ('syntax:unbalanced_delimiter at line 1, offset 20',), 'syntax:unbalanced_delimiter at line 1, offset 20',
    ),
    'for_head-mismatched-block': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 23,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 23',
        ('syntax:unbalanced_delimiter at line 1, offset 23',), 'syntax:unbalanced_delimiter at line 1, offset 23',
    ),
    'for_head-mismatched-call': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 28,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 28',
        ('syntax:unbalanced_delimiter at line 1, offset 28',), 'syntax:unbalanced_delimiter at line 1, offset 28',
    ),
    'for_head-discard-template': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('punct', '}', 1, 22, 23, 'block', None), ('identifier', 'if', 1, 24, 26, '', None),
            ('punct', '(', 1, 27, 28, 'control', None), ('identifier', 'b', 1, 28, 29, '', None),
            ('identifier', 'of', 1, 30, 32, '', None), ('punct', '/', 1, 33, 34, '', None),
            ('identifier', 'c', 1, 34, 35, '', None), ('punct', '/', 1, 35, 36, '', None),
            ('punct', ')', 1, 36, 37, 'control', None), ('punct', '{', 1, 38, 39, 'block', None),
            ('punct', '}', 1, 39, 40, 'block', None),
        ],
    ),
    'for_head-discard-regex': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('punct', '}', 1, 22, 23, 'block', None), ('identifier', 'if', 1, 24, 26, '', None),
            ('punct', '(', 1, 27, 28, 'control', None), ('identifier', 'b', 1, 28, 29, '', None),
            ('identifier', 'of', 1, 30, 32, '', None), ('punct', '/', 1, 33, 34, '', None),
            ('identifier', 'c', 1, 34, 35, '', None), ('punct', '/', 1, 35, 36, '', None),
            ('punct', ')', 1, 36, 37, 'control', None), ('punct', '{', 1, 38, 39, 'block', None),
            ('punct', '}', 1, 39, 40, 'block', None),
        ],
    ),
    'for_head-discard-block': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('identifier', 'const', 1, 23, 28, '', None), ('identifier', 'z', 1, 29, 30, '', None),
            ('punct', '=', 1, 31, 32, '', None), ('number', '1', 1, 33, 34, '', None),
            ('punct', '}', 1, 35, 36, 'block', None), ('identifier', 'if', 1, 37, 39, '', None),
            ('punct', '(', 1, 40, 41, 'control', None), ('identifier', 'b', 1, 41, 42, '', None),
            ('identifier', 'of', 1, 43, 45, '', None), ('punct', '/', 1, 46, 47, '', None),
            ('identifier', 'c', 1, 47, 48, '', None), ('punct', '/', 1, 48, 49, '', None),
            ('punct', ')', 1, 49, 50, 'control', None), ('punct', '{', 1, 51, 52, 'block', None),
            ('punct', '}', 1, 52, 53, 'block', None),
        ],
    ),
    'for_head-discard-call': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('regex', '/a/', 1, 16, 19, '', None),
            ('punct', ')', 1, 19, 20, 'control', None), ('punct', '{', 1, 21, 22, 'block', None),
            ('identifier', 'f', 1, 23, 24, '', None), ('punct', '(', 1, 24, 25, 'expression', None),
            ('number', '1', 1, 25, 26, '', None), ('punct', ')', 1, 26, 27, 'expression', None),
            ('punct', '}', 1, 28, 29, 'block', None), ('identifier', 'if', 1, 30, 32, '', None),
            ('punct', '(', 1, 33, 34, 'control', None), ('identifier', 'b', 1, 34, 35, '', None),
            ('identifier', 'of', 1, 36, 38, '', None), ('punct', '/', 1, 39, 40, '', None),
            ('identifier', 'c', 1, 40, 41, '', None), ('punct', '/', 1, 41, 42, '', None),
            ('punct', ')', 1, 42, 43, 'control', None), ('punct', '{', 1, 44, 45, 'block', None),
            ('punct', '}', 1, 45, 46, 'block', None),
        ],
    ),
    'type_literal-open-template': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 25,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 25',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 25',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 25',
    ),
    'type_literal-open-regex': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 28,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 28',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 28',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 28',
    ),
    'type_literal-open-block': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 25,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 25',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 25',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 25',
    ),
    'type_literal-open-call': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 22,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 22',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 22',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 22',
    ),
    'type_literal-nested-template': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 35,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 35',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 35',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 35',
    ),
    'type_literal-nested-regex': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 40,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 40',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 40',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 40',
    ),
    'type_literal-nested-block': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 35,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 35',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 35',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 35',
    ),
    'type_literal-nested-call': (
        'refusal', 'JSLexError', 'unsupported_lexical_context:tsx_type_literal_angle', 1, 32,
        None, 'ERR_AEGIS', 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 32',
        ('unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 32',), 'unsupported_lexical_context:tsx_type_literal_angle at line 1, offset 32',
    ),
    'type_literal-close-template': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('template_start', '`', 1, 20, 21, '', None), ('template_text', 'a', 1, 21, 22, '', None),
            ('template_end', '`', 1, 22, 23, '', None), ('punct', '}', 1, 24, 25, 'object', None),
            ('punct', ';', 1, 25, 26, '', None), ('identifier', 'eval', 1, 27, 31, '', None),
            ('punct', '(', 1, 31, 32, 'expression', None), ('identifier', 'code', 1, 32, 36, '', None),
            ('punct', ')', 1, 36, 37, 'expression', None),
        ],
    ),
    'type_literal-close-regex': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('regex', '/a/', 1, 20, 23, '', None), ('punct', '}', 1, 24, 25, 'object', None),
            ('punct', ';', 1, 25, 26, '', None), ('identifier', 'eval', 1, 27, 31, '', None),
            ('punct', '(', 1, 31, 32, 'expression', None), ('identifier', 'code', 1, 32, 36, '', None),
            ('punct', ')', 1, 36, 37, 'expression', None),
        ],
    ),
    'type_literal-close-block': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('punct', '{', 1, 20, 21, 'object', None), ('identifier', 'x', 1, 22, 23, '', None),
            ('punct', ':', 1, 23, 24, '', None), ('number', '1', 1, 25, 26, '', None),
            ('punct', '}', 1, 27, 28, 'object', None), ('punct', '}', 1, 29, 30, 'object', None),
            ('punct', ';', 1, 30, 31, '', None), ('identifier', 'eval', 1, 32, 36, '', None),
            ('punct', '(', 1, 36, 37, 'expression', None), ('identifier', 'code', 1, 37, 41, '', None),
            ('punct', ')', 1, 41, 42, 'expression', None),
        ],
    ),
    'type_literal-close-call': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('identifier', 'g', 1, 20, 21, '', None), ('punct', '(', 1, 21, 22, 'expression', None),
            ('number', '1', 1, 22, 23, '', None), ('punct', ')', 1, 23, 24, 'expression', None),
            ('punct', '}', 1, 25, 26, 'object', None), ('punct', ';', 1, 26, 27, '', None),
            ('identifier', 'eval', 1, 28, 32, '', None), ('punct', '(', 1, 32, 33, 'expression', None),
            ('identifier', 'code', 1, 33, 37, '', None), ('punct', ')', 1, 37, 38, 'expression', None),
        ],
    ),
    'type_literal-mismatched-template': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 24,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 24',
        ('syntax:unbalanced_delimiter at line 1, offset 24',), 'syntax:unbalanced_delimiter at line 1, offset 24',
    ),
    'type_literal-mismatched-regex': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 24,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 24',
        ('syntax:unbalanced_delimiter at line 1, offset 24',), 'syntax:unbalanced_delimiter at line 1, offset 24',
    ),
    'type_literal-mismatched-block': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 29,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 29',
        ('syntax:unbalanced_delimiter at line 1, offset 29',), 'syntax:unbalanced_delimiter at line 1, offset 29',
    ),
    'type_literal-mismatched-call': (
        'refusal', 'JSLexError', 'syntax:unbalanced_delimiter', 1, 25,
        None, 'ERR_AEGIS', 'syntax:unbalanced_delimiter at line 1, offset 25',
        ('syntax:unbalanced_delimiter at line 1, offset 25',), 'syntax:unbalanced_delimiter at line 1, offset 25',
    ),
    'type_literal-discard-template': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('template_start', '`', 1, 20, 21, '', None), ('template_text', 'a', 1, 21, 22, '', None),
            ('template_end', '`', 1, 22, 23, '', None), ('punct', '}', 1, 24, 25, 'object', None),
            ('punct', ';', 1, 25, 26, '', None), ('identifier', 'const', 1, 27, 32, '', None),
            ('identifier', 'c', 1, 33, 34, '', None), ('punct', '=', 1, 35, 36, '', None),
            ('jsx', '<A', 1, 37, 39, '', None), ('jsx', ' ', 1, 39, 40, '', None),
            ('jsx', '/>', 1, 40, 42, '', None),
        ],
    ),
    'type_literal-discard-regex': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('regex', '/a/', 1, 20, 23, '', None), ('punct', '}', 1, 24, 25, 'object', None),
            ('punct', ';', 1, 25, 26, '', None), ('identifier', 'const', 1, 27, 32, '', None),
            ('identifier', 'c', 1, 33, 34, '', None), ('punct', '=', 1, 35, 36, '', None),
            ('jsx', '<A', 1, 37, 39, '', None), ('jsx', ' ', 1, 39, 40, '', None),
            ('jsx', '/>', 1, 40, 42, '', None),
        ],
    ),
    'type_literal-discard-block': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('punct', '{', 1, 20, 21, 'object', None), ('identifier', 'x', 1, 22, 23, '', None),
            ('punct', ':', 1, 23, 24, '', None), ('number', '1', 1, 25, 26, '', None),
            ('punct', '}', 1, 27, 28, 'object', None), ('punct', '}', 1, 29, 30, 'object', None),
            ('punct', ';', 1, 30, 31, '', None), ('identifier', 'const', 1, 32, 37, '', None),
            ('identifier', 'c', 1, 38, 39, '', None), ('punct', '=', 1, 40, 41, '', None),
            ('jsx', '<A', 1, 42, 44, '', None), ('jsx', ' ', 1, 44, 45, '', None),
            ('jsx', '/>', 1, 45, 47, '', None),
        ],
    ),
    'type_literal-discard-call': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('identifier', 'g', 1, 20, 21, '', None), ('punct', '(', 1, 21, 22, 'expression', None),
            ('number', '1', 1, 22, 23, '', None), ('punct', ')', 1, 23, 24, 'expression', None),
            ('punct', '}', 1, 25, 26, 'object', None), ('punct', ';', 1, 26, 27, '', None),
            ('identifier', 'const', 1, 28, 33, '', None), ('identifier', 'c', 1, 34, 35, '', None),
            ('punct', '=', 1, 36, 37, '', None), ('jsx', '<A', 1, 38, 40, '', None),
            ('jsx', ' ', 1, 40, 41, '', None), ('jsx', '/>', 1, 41, 43, '', None),
        ],
    ),
}

_FRAME_GOLDEN_COMPACT = {
    'generator-open-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'return', 1, 16, 22, '', None), ('template_start', '`', 1, 23, 24, '', None),
            ('punct', '${', 1, 26, 28, 'interpolation', None), ('identifier', 'yield', 1, 28, 33, '', None),
            ('regex', '/a/', 1, 34, 37, '', None), ('punct', '}', 1, 37, 38, 'interpolation', None),
            ('template_end', '`', 1, 38, 39, '', None), ('punct', '}', 1, 40, 41, 'function_decl', None),
        ],
    ),
    'generator-nested-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'function', 1, 16, 24, '', None), ('punct', '*', 1, 24, 25, '', None),
            ('identifier', 'h', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_decl', None),
            ('punct', ')', 1, 28, 29, 'parameters_decl', None), ('punct', '{', 1, 30, 31, 'function_decl', None),
            ('identifier', 'return', 1, 32, 38, '', None), ('template_start', '`', 1, 39, 40, '', None),
            ('punct', '${', 1, 42, 44, 'interpolation', None), ('identifier', 'yield', 1, 44, 49, '', None),
            ('regex', '/a/', 1, 50, 53, '', None), ('punct', '}', 1, 53, 54, 'interpolation', None),
            ('template_end', '`', 1, 54, 55, '', None), ('punct', '}', 1, 56, 57, 'function_decl', None),
            ('identifier', 'return', 1, 58, 64, '', None), ('template_start', '`', 1, 65, 66, '', None),
            ('punct', '${', 1, 68, 70, 'interpolation', None), ('identifier', 'yield', 1, 70, 75, '', None),
            ('regex', '/b/', 1, 76, 79, '', None), ('punct', '}', 1, 79, 80, 'interpolation', None),
            ('template_end', '`', 1, 80, 81, '', None), ('punct', '}', 1, 82, 83, 'function_decl', None),
        ],
    ),
    'generator-close-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'return', 1, 16, 22, '', None), ('template_start', '`', 1, 23, 24, '', None),
            ('punct', '${', 1, 26, 28, 'interpolation', None), ('identifier', 'yield', 1, 28, 33, '', None),
            ('regex', '/a/', 1, 34, 37, '', None), ('punct', '}', 1, 37, 38, 'interpolation', None),
            ('template_end', '`', 1, 38, 39, '', None), ('punct', '}', 1, 40, 41, 'function_decl', None),
        ],
    ),
    'strict-open-template': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'return', 1, 16, 22, '', None),
            ('template_start', '`', 1, 23, 24, '', None), ('punct', '${', 1, 26, 28, 'interpolation', None),
            ('identifier', 'yield', 1, 28, 33, '', None), ('regex', '/a/', 1, 34, 37, '', None),
            ('punct', '}', 1, 37, 38, 'interpolation', None), ('template_end', '`', 1, 38, 39, '', None),
            ('punct', '}', 1, 40, 41, 'function_expr', None), ('punct', '}', 1, 42, 43, 'class_decl', None),
        ],
    ),
    'strict-nested-template': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'class', 1, 16, 21, '', None),
            ('identifier', 'B', 1, 22, 23, '', None), ('punct', '{', 1, 24, 25, 'class_decl', None),
            ('identifier', 'n', 1, 26, 27, '', None), ('punct', '(', 1, 27, 28, 'parameters_method', None),
            ('punct', ')', 1, 28, 29, 'parameters_method', None), ('punct', '{', 1, 30, 31, 'function_expr', None),
            ('identifier', 'return', 1, 32, 38, '', None), ('template_start', '`', 1, 39, 40, '', None),
            ('punct', '${', 1, 42, 44, 'interpolation', None), ('identifier', 'yield', 1, 44, 49, '', None),
            ('regex', '/a/', 1, 50, 53, '', None), ('punct', '}', 1, 53, 54, 'interpolation', None),
            ('template_end', '`', 1, 54, 55, '', None), ('punct', '}', 1, 56, 57, 'function_expr', None),
            ('punct', '}', 1, 58, 59, 'class_decl', None), ('identifier', 'return', 1, 60, 66, '', None),
            ('template_start', '`', 1, 67, 68, '', None), ('punct', '${', 1, 70, 72, 'interpolation', None),
            ('identifier', 'yield', 1, 72, 77, '', None), ('regex', '/b/', 1, 78, 81, '', None),
            ('punct', '}', 1, 81, 82, 'interpolation', None), ('template_end', '`', 1, 82, 83, '', None),
            ('punct', '}', 1, 84, 85, 'function_expr', None), ('punct', '}', 1, 86, 87, 'class_decl', None),
        ],
    ),
    'strict-close-template': (
        'tokens', [
            ('identifier', 'class', 1, 0, 5, '', None), ('identifier', 'A', 1, 6, 7, '', None),
            ('punct', '{', 1, 8, 9, 'class_decl', None), ('identifier', 'm', 1, 10, 11, '', None),
            ('punct', '(', 1, 11, 12, 'parameters_method', None), ('punct', ')', 1, 12, 13, 'parameters_method', None),
            ('punct', '{', 1, 14, 15, 'function_expr', None), ('identifier', 'return', 1, 16, 22, '', None),
            ('template_start', '`', 1, 23, 24, '', None), ('punct', '${', 1, 26, 28, 'interpolation', None),
            ('identifier', 'yield', 1, 28, 33, '', None), ('regex', '/a/', 1, 34, 37, '', None),
            ('punct', '}', 1, 37, 38, 'interpolation', None), ('template_end', '`', 1, 38, 39, '', None),
            ('punct', '}', 1, 40, 41, 'function_expr', None), ('punct', '}', 1, 42, 43, 'class_decl', None),
        ],
    ),
    'arrow-close-template': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'f', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('template_start', '`', 1, 10, 11, '', None),
            ('punct', '${', 1, 13, 15, 'interpolation', None), ('identifier', 'y', 1, 15, 16, '', None),
            ('punct', '=>', 1, 17, 19, '', None), ('identifier', 'y', 1, 20, 21, '', None),
            ('punct', '}', 1, 21, 22, 'interpolation', None), ('template_end', '`', 1, 22, 23, '', None),
        ],
    ),
    'arrow-discard-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('punct', '*', 1, 8, 9, '', None),
            ('identifier', 'g', 1, 10, 11, '', None), ('punct', '(', 1, 11, 12, 'parameters_decl', None),
            ('punct', ')', 1, 12, 13, 'parameters_decl', None), ('punct', '{', 1, 14, 15, 'function_decl', None),
            ('identifier', 'const', 1, 16, 21, '', None), ('identifier', 'x', 1, 22, 23, '', None),
            ('punct', '=', 1, 24, 25, '', None), ('template_start', '`', 1, 26, 27, '', None),
            ('punct', '${', 1, 29, 31, 'interpolation', None), ('identifier', 'y', 1, 31, 32, '', None),
            ('punct', '=>', 1, 33, 35, '', None), ('identifier', 'y', 1, 36, 37, '', None),
            ('punct', '}', 1, 37, 38, 'interpolation', None), ('template_end', '`', 1, 38, 39, '', None),
            ('punct', ';', 1, 39, 40, '', None), ('identifier', 'return', 1, 41, 47, '', None),
            ('template_start', '`', 1, 48, 49, '', None), ('punct', '${', 1, 51, 53, 'interpolation', None),
            ('identifier', 'yield', 1, 53, 58, '', None), ('regex', '/a/', 1, 59, 62, '', None),
            ('punct', '}', 1, 62, 63, 'interpolation', None), ('template_end', '`', 1, 63, 64, '', None),
            ('punct', '}', 1, 65, 66, 'function_decl', None),
        ],
    ),
    'for_head-open-template': (
        'tokens', [
            ('identifier', 'function', 1, 0, 8, '', None), ('identifier', 'h', 1, 9, 10, '', None),
            ('punct', '(', 1, 10, 11, 'parameters_decl', None), ('punct', ')', 1, 11, 12, 'parameters_decl', None),
            ('punct', '{', 1, 13, 14, 'function_decl', None), ('identifier', 'return', 1, 15, 21, '', None),
            ('template_start', '`', 1, 22, 23, '', None), ('punct', '${', 1, 25, 27, 'interpolation', None),
            ('identifier', 'for', 1, 27, 30, '', None), ('punct', '(', 1, 31, 32, 'control', None),
            ('identifier', 'const', 1, 32, 37, '', None), ('identifier', 'a', 1, 38, 39, '', None),
            ('identifier', 'of', 1, 40, 42, '', None), ('regex', '/b/', 1, 43, 46, '', None),
            ('punct', ')', 1, 46, 47, 'control', None), ('punct', '{', 1, 48, 49, 'block', None),
            ('punct', '}', 1, 49, 50, 'block', None), ('punct', '}', 1, 50, 51, 'interpolation', None),
            ('template_end', '`', 1, 51, 52, '', None), ('punct', '}', 1, 53, 54, 'function_decl', None),
        ],
    ),
    'for_head-nested-template': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('template_start', '`', 1, 16, 17, '', None),
            ('punct', '${', 1, 19, 21, 'interpolation', None), ('identifier', 'function', 1, 21, 29, '', None),
            ('punct', '(', 1, 30, 31, 'parameters_expr', None), ('punct', ')', 1, 31, 32, 'parameters_expr', None),
            ('punct', '{', 1, 33, 34, 'function_expr', None), ('identifier', 'for', 1, 35, 38, '', None),
            ('punct', '(', 1, 39, 40, 'control', None), ('identifier', 'const', 1, 40, 45, '', None),
            ('identifier', 'y', 1, 46, 47, '', None), ('identifier', 'of', 1, 48, 50, '', None),
            ('regex', '/b/', 1, 51, 54, '', None), ('punct', ')', 1, 54, 55, 'control', None),
            ('punct', '{', 1, 56, 57, 'block', None), ('punct', '}', 1, 57, 58, 'block', None),
            ('punct', '}', 1, 59, 60, 'function_expr', None), ('punct', '}', 1, 60, 61, 'interpolation', None),
            ('template_end', '`', 1, 61, 62, '', None), ('punct', ')', 1, 62, 63, 'control', None),
            ('punct', '{', 1, 64, 65, 'block', None), ('punct', '}', 1, 65, 66, 'block', None),
        ],
    ),
    'for_head-close-template': (
        'tokens', [
            ('identifier', 'for', 1, 0, 3, '', None), ('punct', '(', 1, 4, 5, 'control', None),
            ('identifier', 'const', 1, 5, 10, '', None), ('identifier', 'x', 1, 11, 12, '', None),
            ('identifier', 'of', 1, 13, 15, '', None), ('template_start', '`', 1, 16, 17, '', None),
            ('template_end', '`', 1, 18, 19, '', None), ('punct', ')', 1, 19, 20, 'control', None),
            ('punct', '{', 1, 21, 22, 'block', None), ('punct', '}', 1, 22, 23, 'block', None),
        ],
    ),
    'type_literal-close-template': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('template_start', '`', 1, 20, 21, '', None), ('template_text', 'a', 1, 21, 22, '', None),
            ('template_end', '`', 1, 22, 23, '', None), ('punct', '}', 1, 24, 25, 'object', None),
            ('punct', ';', 1, 25, 26, '', None), ('flat_call', 'eval', 1, 27, 37, 'expression', ('code',)),
        ],
    ),
    'type_literal-close-regex': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('regex', '/a/', 1, 20, 23, '', None), ('punct', '}', 1, 24, 25, 'object', None),
            ('punct', ';', 1, 25, 26, '', None), ('flat_call', 'eval', 1, 27, 37, 'expression', ('code',)),
        ],
    ),
    'type_literal-close-block': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('flat_object', '{ x: 1 }', 1, 20, 28, 'object', None), ('punct', '}', 1, 29, 30, 'object', None),
            ('punct', ';', 1, 30, 31, '', None), ('flat_call', 'eval', 1, 32, 42, 'expression', ('code',)),
        ],
    ),
    'type_literal-close-call': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('identifier', 'g', 1, 20, 21, '', None), ('punct', '(', 1, 21, 22, 'expression', None),
            ('number', '1', 1, 22, 23, '', None), ('punct', ')', 1, 23, 24, 'expression', None),
            ('punct', '}', 1, 25, 26, 'object', None), ('punct', ';', 1, 26, 27, '', None),
            ('flat_call', 'eval', 1, 28, 38, 'expression', ('code',)),
        ],
    ),
    'type_literal-discard-block': (
        'tokens', [
            ('identifier', 'const', 1, 0, 5, '', None), ('identifier', 'a', 1, 6, 7, '', None),
            ('punct', '=', 1, 8, 9, '', None), ('identifier', 'b', 1, 10, 11, '', None),
            ('identifier', 'as', 1, 12, 14, '', None), ('punct', '{', 1, 15, 16, 'object', None),
            ('identifier', 'f', 1, 17, 18, '', None), ('punct', ':', 1, 18, 19, '', None),
            ('flat_object', '{ x: 1 }', 1, 20, 28, 'object', None), ('punct', '}', 1, 29, 30, 'object', None),
            ('punct', ';', 1, 30, 31, '', None), ('identifier', 'const', 1, 32, 37, '', None),
            ('identifier', 'c', 1, 38, 39, '', None), ('punct', '=', 1, 40, 41, '', None),
            ('jsx', '<A', 1, 42, 44, '', None), ('jsx', ' ', 1, 44, 45, '', None),
            ('jsx', '/>', 1, 45, 47, '', None),
        ],
    ),
}
