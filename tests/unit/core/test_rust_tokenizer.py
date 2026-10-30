"""Rust lexical boundaries through the native tokenizer's public entry point."""
import pytest

from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.drivers.rust.tokenizer import tokenize


def values(source):
    return [token.value for token in tokenize(source).tokens]


def test_nested_comments_raw_strings_and_lifetimes_preserve_code_positions():
    source = '\ufeff/* outer /* hidden() */ still hidden */\r\n' + '''fn f<'a>(x: &'a str) {
    let fake = r###"fake() r#"inner"#"###;
    let letter = '\\u{61}'; real(); // visible comment
}'''
    result = tokenize(source)
    assert [token.line for token in result.tokens if token.value == 'real'] == [4]
    assert 'fake' in [token.value for token in result.tokens]
    assert 'hidden' not in [token.value for token in result.tokens]
    assert "'a" in [token.value for token in result.tokens]
    assert len(result.comments) == 2
    assert any(token.kind == 'string' and 'fake()' in token.value for token in result.tokens)


def test_raw_identifiers_byte_and_c_strings_are_indivisible():
    result = tokenize('r#type(br##"not_a_call()"##, b\'x\', c"also_not()", cr#"raw()"#);')
    assert result.tokens[0].value == 'type'
    assert [t.kind for t in result.tokens if t.kind in ('bytes', 'cstring')] == ['bytes', 'bytes', 'cstring', 'cstring']
    assert 'not_a_call' not in [t.value for t in result.tokens]


@pytest.mark.parametrize('source,reason', [
    ('/* no close', 'unterminated block comment'),
    ('r##"no close"#', 'unterminated raw string'),
    ('"no close', 'unterminated string'),
    ("'\\x4z'", 'invalid escape'),
    ('fn f() { call(]; }', 'mismatched delimiter'),
    ('fn f() {', 'unclosed delimiter'),
    ('fn f() { \x00 }', 'invalid character'),
])
def test_lexical_errors_fail_closed_with_line(source, reason):
    with pytest.raises(ASTDriverError, match=reason + '.*line 1'):
        tokenize(source)


def test_iterative_nesting_has_an_explicit_bound():
    with pytest.raises(ASTDriverError, match='nesting limit'):
        tokenize('(' * 513 + ')' * 513)


def test_numbers_do_not_swallow_ranges_or_method_calls():
    assert values('0..10; 16u8; 0x10_u64; 1_000; 1.5f32; 1.to_string();') == [
        '0', '..', '10', ';', '16u8', ';', '0x10_u64', ';', '1_000', ';',
        '1.5f32', ';', '1', '.', 'to_string', '(', ')', ';']


def test_shebang_is_opaque_but_inner_attributes_remain_tokens():
    result = tokenize('#!/usr/bin/env fake(call())\n#![allow(dead_code)]\nfn f() {}')
    assert 'fake' not in [t.value for t in result.tokens]
    assert 'allow' in [t.value for t in result.tokens]


@pytest.mark.parametrize('source', ['b"é"', 'br#"é"#', 'c"\\0"', 'cr#"\x00"#'])
def test_invalid_byte_and_c_strings_fail_closed(source):
    with pytest.raises(ASTDriverError, match='invalid'):
        tokenize(source)


def test_ascii_unicode_and_raw_identifier_spans_keep_all_token_fields():
    source = 'ascii é1 a\u0301b r#type r#é1 r#a\u0301b::call(0x10_u8);'
    expected = [
        ('ident', 'ascii', False, 'ascii'), ('ident', 'é1', False, 'é1'),
        ('ident', 'a\u0301b', False, 'a\u0301b'), ('ident', 'type', True, 'r#type'),
        ('ident', 'é1', True, 'r#é1'), ('ident', 'a\u0301b', True, 'r#a\u0301b'),
        ('punct', '::', False, '::'), ('ident', 'call', False, 'call'),
        ('punct', '(', False, '('), ('number', '0x10_u8', False, '0x10_u8'),
        ('punct', ')', False, ')'), ('punct', ';', False, ';'),
    ]
    result = tokenize(source)
    assert len(result.tokens) == len(expected)
    cursor = 0
    for token, (kind, value, raw, text) in zip(result.tokens, expected):
        start = source.index(text, cursor)
        assert tuple(token) == (kind, value, 1, start, start, start + len(text), raw)
        cursor = start + len(text)
    assert result.pairs == {8: 10, 10: 8}


@pytest.mark.parametrize('literal', ['0b102', '0x', '1e+'])
def test_invalid_numbers_outside_call_arguments_still_fail_closed(literal):
    with pytest.raises(ASTDriverError, match='invalid.*literal.*line 1') as raised:
        tokenize('const BAD: u8 = ' + literal + ';')
    assert raised.value.reason == 'syntax'


def test_validated_numeric_facts_preserve_raw_tokens_and_the_legacy_lexed_constructor():
    from aegis_core.ast.drivers.rust.tokenizer import Lexed

    result = tokenize('sink(0x10_u8, -0.0, +1unknown);')
    numbers = [(index, token) for index, token in enumerate(result.tokens) if token.kind == 'number']
    assert [token.value for _, token in numbers] == ['0x10_u8', '0.0', '1unknown']
    assert result.scalars == {index: value for (index, _), value in zip(numbers, ['16', '0.0', '<expr>'])}
    legacy = Lexed(result.tokens, result.comments, result.pairs)
    assert legacy.scalars == {}
    assert legacy.tokens == result.tokens and legacy.comments == result.comments and legacy.pairs == result.pairs
