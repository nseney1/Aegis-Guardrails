"""JavaScript lexical boundaries through the public tokenizer."""
import json
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
