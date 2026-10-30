"""Native Rust extraction and conservative literal semantics through parse()."""
import ast

import pytest

from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.drivers.rust import CAPABILITIES, parse
from aegis_core.ast.schema import NormalizedAST


def calls(source):
    return parse(source, 'src/lib.rs').call_sites


def test_grouped_imports_aliases_globs_and_extern_crates():
    tree = parse('''pub use std::{process::{Command as Cmd, Stdio}, io::{self, Read}, fmt::*};
use crate::helpers::thing as _;
extern crate sha1_smol as hash;
fn run() { Cmd::new("sh"); hash::Sha1::new(); }
''', 'src/lib.rs')
    modules = {item.source: item for item in tree.imports}
    assert modules['std::process'].imported_symbols == ('Cmd', 'Stdio')
    assert modules['std::process'].aliases == (('Cmd', 'Command'),)
    assert modules['std::io'].imported_symbols == ('io', 'Read')
    assert modules['std::fmt'].imported_symbols == ('*',)
    assert modules['crate::helpers'].imported_symbols == ()
    assert modules['sha1_smol'].aliases == (('hash', 'sha1_smol'),)
    assert {c.target for c in tree.call_sites} >= {'Cmd::new', 'hash::Sha1::new'}


def test_absolute_paths_synthetic_imports_and_local_modules():
    tree = parse('''mod local { pub fn f() {} }
fn run() { std::process::Command::new("sh"); external::client::open(); local::f(); }
''', 'src/lib.rs')
    assert 'std::process::Command::new' in {c.target for c in tree.call_sites}
    sources = {item.source for item in tree.imports}
    assert 'std::process::Command' in sources
    assert 'external::client' in sources
    assert not any(source.startswith('local') for source in sources)


def test_strings_nested_comments_and_macro_bodies_cannot_forge_calls():
    tree = parse('''/* /* Command::new("sh") */ hidden() */
const TEXT: &str = r##"Command::new("sh")"##;
macro_rules! wrapped { () => { hidden() } }
fn run() { println!("{}", hidden()); wrapped!(); real(); }
''', 'src/lib.rs')
    assert {c.target for c in tree.call_sites} == {'println!', 'wrapped!', 'real'}
    assert next(c for c in tree.call_sites if c.target == 'println!').args == {'*': '<expr>'}


def test_calls_turbofish_methods_and_constructors_scan_inner_expressions():
    tree = parse('''fn run() {
  let v = parse::<Vec<String>>(source());
  client.danger_accept_invalid_certs(true).finish();
  factory().danger_accept_invalid_hostnames(false);
  sink(Config { insecure: true, ..base() });
}''', 'src/lib.rs')
    targets = {c.target for c in tree.call_sites}
    assert targets >= {'parse', 'source', 'client.danger_accept_invalid_certs', '.finish',
                       'factory', '.danger_accept_invalid_hostnames', 'sink', 'Config', 'base'}
    construct = next(c for c in tree.call_sites if c.target == 'Config')
    assert construct.kind == 'construct'
    assert construct.args == {'insecure': 'True', '**': '<expr>'}
    assert next(c for c in tree.call_sites if c.target == 'sink').args == {
        '#0': '<expr>', 'insecure': 'True', '**': '<expr>'}


def test_explicit_struct_fields_win_update_and_conflicting_arguments_are_unknown():
    tree = parse('''fn run() {
 sink(Config { safe: false, ..base }, Config { safe: true });
 other(Config { safe: true, ..base });
}''', 'fixture.rs')
    assert next(c for c in tree.call_sites if c.target == 'sink').args['safe'] == '<expr>'
    assert next(c for c in tree.call_sites if c.target == 'other').args['safe'] == 'True'


@pytest.mark.parametrize('source', ['fn f() { X { a: 1, a: 2 }; }', 'fn f() { use std::{process; }; }',
                                    'fn f() { X { ..base, a: 1 }; }'])
def test_invalid_struct_fields_and_use_trees_fail_closed(source):
    with pytest.raises(ASTDriverError, match='duplicate field|invalid use|struct update'):
        parse(source, 'bad.rs')


def test_control_flow_blocks_are_not_constructors():
    tree = parse('fn f() { if ready { run(); } while ready { tick(); } match value { _ => finish() } }', 'fixture.rs')
    assert not any(c.kind == 'construct' for c in tree.call_sites)
    assert {c.target for c in tree.call_sites} >= {'run', 'tick', 'finish'}


def test_definitions_attributes_impl_scopes_and_test_modules():
    tree = parse('''#![allow(dead_code)]
pub struct Client;
enum Choice { One }
trait Work { fn run(&self); }
impl Client { #[inline] pub fn run(&self) { send(); } }
const LIMIT: i32 = 1;
static FLAG: bool = true;
#[cfg(test)] mod tests { #[test] fn smoke() { check(); } }
''', 'src/a/mod.rs')
    definitions = {(d.name, d.kind): d for d in tree.definitions}
    assert definitions['Client', 'class'].is_exported
    assert definitions['run', 'method'].class_name == 'Client'
    assert definitions['run', 'method'].decorators == ('inline',)
    assert {d.name for d in tree.definitions} >= {'Choice', 'Work', 'LIMIT', 'FLAG', 'tests', 'smoke'}
    assert tree.metadata['test_module'] is True
    assert tree.metadata['test_functions'][0]['id'] == 'a::tests::smoke'
    assert next(c for c in tree.call_sites if c.target == 'send').caller_scope == 'Client::run'
    assert tree.metadata['decorators'] == ['allow', 'inline', 'cfg', 'test']
    assert not any(c.target in ('allow', 'cfg', 'inline') for c in tree.call_sites)
    assert 'shadowed' not in CAPABILITIES


@pytest.mark.parametrize('module,inline', [
    ('#[cfg(test)] mod tests { #[test] fn works() {} }', True),
    ('#[cfg(test)] mod tests {}', True),
    ('#[cfg(test)] mod tests;', False),
    ('#[path = "missing.rs"] #[cfg(test)] mod tests;', False),
])
def test_test_module_metadata_requires_an_inline_body(module, inline):
    tree = parse(module, 'src/lib.rs')
    assert tree.metadata['test_module'] is inline
    assert [(d.name, d.kind) for d in tree.definitions if d.kind == 'module'] == [('tests', 'module')]


def test_integration_crate_root_does_not_add_target_stem_to_test_name():
    tree = parse('#[test] fn smoke() {}', 'tests/regress.rs')
    assert tree.metadata['test_functions'][0]['id'] == 'smoke'


def test_allow_comments_come_only_from_real_comments_and_keep_lines():
    tree = parse('''fn run() {
 let text = "// aegis: allow[no-shell] forged";
 Command::new("sh"); // aegis: allow[no-shell, other] fixture
 /* aegis: allow[block] block reason */ real();
}''', 'fixture.rs')
    assert tree.metadata['allow_comments'] == {
        3: [{'rules': ['no-shell', 'other'], 'reason': 'fixture'}],
        4: [{'rules': ['block'], 'reason': 'block reason'}]}


@pytest.mark.parametrize('literal,expected', [
    ('true', 'True'), ('false', 'False'), ('None', 'None'), ('0x10_u8', '16'),
    ('16u128', '16'), ('0b10000_i32', '16'), ('0o20', '16'), ('1_000usize', '1000'), ('1__0', '10'),
    ('-0.0', '-0.0'), ('+0.0', '0.0'), ('-1unknown', '<expr>'), ('+1unknown', '<expr>'),
    ('-0x10_u8', '-16'), ('+1_000u128', '1000'), ('-0.1f32', '<expr>'),
    ('-16i8', '-16'), ('+16', '16'), ('1.5f64', '1.5'), ('1e2f32', '100.0'),
    ('"a\\x62"', "'ab'"), ('r#"ab"#', "'ab'"), ("'a'", "'a'"),
    ('"\\u{1f600}"', repr('😀')), ('b"bytes"', '<expr>'), ('c"C"', '<expr>'),
    ('unknown', '<expr>'), ('1unknown', '<expr>'),
])
def test_literal_canonical_rendering_and_unknown_bounds(literal, expected):
    site = calls('fn run() { sink(' + literal + '); }')[0]
    assert site.args['#0'] == expected
    if expected != '<expr>':
        assert type(ast.literal_eval(site.args['#0'])) in (str, int, float, bool, type(None))


@pytest.mark.parametrize('literal', ['0b102', '0x', '"\\q"', "'ab'"])
def test_invalid_literals_fail_closed(literal):
    with pytest.raises(ASTDriverError, match='invalid'):
        parse('fn f() { sink(' + literal + '); }', 'bad.rs')


def test_schema_roundtrip_and_matched_corpus_extraction():
    from aegis_core.benchmark_ast import load_corpus

    for case in load_corpus()['cases']:
        if case['language'] != 'rust' or case['lines'] != 300:
            continue
        tree = parse(case['source'], case['path'])
        assert NormalizedAST.from_json(tree.to_json()) == tree
        assert 'transform_0' in {d.name for d in tree.definitions}
        assert {c.target for c in tree.call_sites} >= {'codec::max', 'codec::min'}
        assert ('codec', 'std::cmp') in tree.imports[0].aliases
        assert tree.metadata['capabilities'] == list(CAPABILITIES)


def test_native_source_limit_uses_utf8_bytes_and_typed_advisory_reason():
    limit = 2 * 1024 * 1024
    assert parse(' ' * limit, 'large.rs').definitions == ()
    for text in (' ' * (limit + 1), '// ' + '😀' * (limit // 4)):
        with pytest.raises(ASTDriverError, match='2 MiB.*aegis doctor') as raised:
            parse(text, 'large.rs')
        assert raised.value.reason == 'too_large'


def test_macro_input_cannot_forge_imports_attributes_or_definitions():
    tree = parse('''macro_rules! generated { () => { use evil::Call; #[cfg(test)] mod tests {} } }
fn run() { opaque!(use hidden::Call; #[test] fn forged() {}); real(); }
''', 'fixture.rs')
    assert not any(i.source.startswith(('evil', 'hidden')) for i in tree.imports)
    assert not {'forged', 'tests'} & {d.name for d in tree.definitions}
    assert not tree.metadata['test_module']
    assert tree.metadata['test_functions'] == []
    assert tree.metadata['decorators'] == []


def test_generic_impl_const_functions_static_mut_and_visibility():
    tree = parse('''struct Client<T> { value: T }
impl<T> Work<T> for Client<T> {
 #[inline] pub(crate) const fn run(&self) { send(); }
}
static mut FLAG: bool = false;
''', 'fixture.rs')
    methods = [d for d in tree.definitions if d.name == 'run']
    assert len(methods) == 1
    method = methods[0]
    assert method.kind == 'method' and method.class_name == 'Client'
    assert method.is_exported and method.decorators == ('inline',)
    assert next(c for c in tree.call_sites if c.target == 'send').caller_scope == 'Client::run'
    assert 'FLAG' in {d.name for d in tree.definitions}
    assert 'mut' not in {d.name for d in tree.definitions}


def test_empty_struct_expressions_and_control_flow_empty_blocks_are_distinct():
    tree = parse('''fn f() {
 if ready {} while ready {} if a == Config {}
 let a = Config {}; sink(Config {}); if (Config {}) == a { finish(); }
}''', 'fixture.rs')
    assert [c.target for c in tree.call_sites if c.kind == 'construct'] == ['Config', 'Config', 'Config']


def test_pattern_structs_and_tuple_variants_are_not_executed_calls():
    tree = parse('''fn f(value: Option<Config>) {
 let Config {a, b} = other;
 match value { Some(Config {a,b}) if check() => work(), None => finish() }
}''', 'fixture.rs')
    assert {c.target for c in tree.call_sites} == {'check', 'work', 'finish'}


def test_float_suffix_rounding_and_overflow_cannot_supply_false_values():
    tree = parse('fn f() { sink(0.1f32, 1.5f32, 1e999f64); }', 'fixture.rs')
    assert tree.call_sites[0].args == {'#0': '<expr>', '#1': '1.5', '#2': '<expr>'}


def test_single_shorthand_struct_field_is_retained_as_unknown():
    tree = parse('fn f() { sink(Config { insecure }); }', 'fixture.rs')
    assert next(c for c in tree.call_sites if c.target == 'Config').args == {'insecure': '<expr>'}
    assert next(c for c in tree.call_sites if c.target == 'sink').args['insecure'] == '<expr>'


@pytest.mark.parametrize('source', ['use std process;', 'use std::;', 'fn broken { real(); }',
                                    'fn broken', 'impl', '#[] fn f() {}'])
def test_malformed_use_and_function_headers_fail_closed(source):
    with pytest.raises(ASTDriverError, match='invalid'):
        parse(source, 'bad.rs')


def test_string_crlf_normalization_and_physical_comment_lines():
    tree = parse('fn f() { sink("a\r\nb", r#"c\r\nd"#); }\n// ignored\u2028aegis: allow[x] physical\nreal();', 'fixture.rs')
    assert tree.call_sites[0].args == {'#0': repr('a\nb'), '#1': repr('c\nd')}
    assert tree.metadata['allow_comments'] == {4: [{'rules': ['x'], 'reason': 'physical'}]}


def test_enum_variant_type_positions_are_opaque_but_discriminant_calls_remain():
    tree = parse('''enum Choice {
  Value(String), Callback(fn(i32) -> i32), Record { field: Config },
  Discriminant = compute(),
}
type Function = fn(i32) -> i32;
fn f() { run(); }
''', 'fixture.rs')
    assert {c.target for c in tree.call_sites} == {'compute', 'run'}


def test_unknown_struct_update_in_another_argument_cannot_supply_a_known_field():
    tree = parse('fn f() { sink(Config { ..base }, Config { safe: true }); other(Config { safe: true, ..base }); }', 'fixture.rs')
    assert next(c for c in tree.call_sites if c.target == 'sink').args['safe'] == '<expr>'
    assert next(c for c in tree.call_sites if c.target == 'other').args['safe'] == 'True'


def test_file_defined_none_is_not_assumed_to_be_the_prelude_variant():
    tree = parse('const None: i32 = 7; fn f() { sink(None); }', 'fixture.rs')
    assert tree.call_sites[0].args['#0'] == '<expr>'


def test_invalid_unicode_input_has_a_typed_syntax_error():
    with pytest.raises(ASTDriverError, match='invalid Unicode') as raised:
        parse('fn f() { "\ud800"; }', 'bad.rs')
    assert raised.value.reason == 'syntax'


@pytest.mark.parametrize('source', ['fn f(x: [u8; dangerous()]) {}',
                                    'struct S { x: [u8; dangerous()] }',
                                    'struct S<const N: usize = { dangerous() }>;'])
def test_unsupported_executable_type_expressions_fail_closed(source):
    with pytest.raises(ASTDriverError, match='unsupported_lexical_context'):
        parse(source, 'types.rs')


def test_public_evaluator_resolves_aliases_literals_and_overrides():
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = '''use std::process::{Command as Cmd};
    fn f() { Cmd::new("sh"); Cmd::new("git"); } // aegis: allow[shell] fixture
'''
    tree = parse(source, 'fixture.rs')
    findings = evaluate_forbid_ast_structured(tree, {'calls': [{'name': 'std::process::Command::new', 'where': {'#0': 'sh'}}]}, source=source, rule_id='shell')
    assert len(findings) == 1 and findings[0]['unknown'] is False
    assert findings[0]['override'] == 'fixture'


def test_raw_identifier_keywords_are_names_instead_of_syntax():
    tree = parse('''use r#type::r#fn as r#struct;
fn r#if() { r#struct(); }
fn run() { r#if(); r#fn(); }
''', 'fixture.rs')
    assert {c.target for c in tree.call_sites} == {'struct', 'if', 'fn'}
    assert 'if' in {d.name for d in tree.definitions}
    assert tree.imports[0].source == 'type::fn'
    assert tree.imports[0].aliases == (('struct', 'type::fn'),)


def test_self_use_binds_the_module_for_the_public_evaluator():
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    tree = parse('use std::io::{self, Read}; fn f() { io::danger(); }', 'fixture.rs')
    findings = evaluate_forbid_ast_structured(tree, {'calls': ['std::io::danger']}, source='')
    assert len(findings) == 1 and findings[0]['unknown'] is False


def test_explicit_import_alias_roots_do_not_become_synthetic_external_modules():
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    tree = parse('use std::process::Command as Cmd; struct Client; impl Client { fn f() { Cmd::new("git"); Self::new(); crate::helper(); } }', 'fixture.rs')
    assert not any(item.source in ('Cmd', 'Self', 'crate') for item in tree.imports)
    assert evaluate_forbid_ast_structured(tree, {'imports': ['Cmd']}, source='') == []


def test_mutation_points_preserve_operators_without_strings_comments_or_type_angles():
    tree = parse('''fn f(x: i32) {
 if x == 1 && x > 0 { sink(x + 1); }
 parse::<Vec<u8>>(); // fake != comparison
 let text = "fake <= comparison";
}''', 'fixture.rs')
    mutations = {(m.original_op, m.replacement_op, m.mutation_type) for m in tree.mutation_points}
    assert mutations == {('==', '!=', 'comparison'), ('&&', '||', 'logical'),
                         ('>', '<=', 'comparison'), ('+', '-', 'binop')}
    assert {(m.line, m.col) for m in tree.mutation_points} == {(2, 6), (2, 11), (2, 16), (2, 29)}


def test_type_aliases_and_raw_macro_input_are_not_executed_code():
    tree = parse('''type Handler = Box<dyn Fn(i32) -> i32>;
fn f() { r#macro_rules!(use forged::Call;); real(); Handler::new(); }
''', 'fixture.rs')
    assert {c.target for c in tree.call_sites} == {'macro_rules!', 'real', 'Handler::new'}
    assert not any(item.source in ('forged', 'Handler') for item in tree.imports)


@pytest.mark.parametrize('expression', [
    'make::<i32,u8>()',
    'make::<Vec<(i32,u8)>,Option<Result<i32,u8>>>()',
    '|a,b| a==b',
    'move |a,b| compare::<i32,u8>(a,b)',
    '|a: (u8,u8),b: u8| a.0==b',
    '|a,b| |c,d| a==c',
    'left | right', 'left || right', 'left & right',
    'left < right', 'left > right',
])
def test_nested_expression_commas_preserve_public_positional_predicates(expression):
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = 'fn f(){sink(' + expression + ',false,true);}'
    tree = parse(source, 'fixture.rs')
    site = next(c for c in tree.call_sites if c.target == 'sink')
    assert site.args == {'#0': '<expr>', '#1': 'False', '#2': 'True'}
    for position, value, count in [('#1', False, 1), ('#2', True, 1),
                                   ('#2', False, 0), ('#3', True, 0)]:
        findings = evaluate_forbid_ast_structured(
            tree, {'calls': [{'name': 'sink', 'where': {position: value}}]}, source=source)
        assert len(findings) == count
        assert all(finding['unknown'] is False for finding in findings)


def test_closure_parameter_boundaries_preserve_executable_body_facts():
    source = 'fn f(){sink(|a,b| dangerous(a,b)==other(),false,true);}'
    tree = parse(source, 'fixture.rs')
    assert [c.target for c in tree.call_sites] == ['sink', 'dangerous', 'other']
    assert [(m.original_op, m.col) for m in tree.mutation_points] == [('==', source.index('=='))]


def test_unclosed_closure_parameters_fail_closed_instead_of_shifting_arguments():
    with pytest.raises(ASTDriverError, match='unclosed closure parameters') as raised:
        parse('fn f(){sink(|a,b,false,true);}', 'bad.rs')
    assert raised.value.reason == 'syntax'


@pytest.mark.parametrize('declaration,bound', [
    ('use std::io::{self};', 'io'),
    ('use std::io::{self as stream};', 'stream'),
    ('use std::io as stream;', 'stream'),
    ('use std::io::{self as io};', 'io'),
])
def test_whole_module_aliases_do_not_invent_qualified_child_imports(declaration, bound):
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = declaration + ' fn f(){' + bound + '::stdout();}'
    tree = parse(source, 'fixture.rs')
    for pattern, count in [('io', 1), ('std::io', 1), ('std', 1),
                           ('std::io::io', 0), ('std::io::Read', 0), ('other::io', 0)]:
        findings = evaluate_forbid_ast_structured(tree, {'imports': [pattern]}, source=source)
        assert len(findings) == count, pattern
        assert all(finding['unknown'] is False for finding in findings)
    findings = evaluate_forbid_ast_structured(tree, {'calls': ['std::io::stdout']}, source=source)
    assert len(findings) == 1 and findings[0]['unknown'] is False


def test_a_real_same_named_child_import_keeps_its_full_qualification():
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = 'use crate::io::{io as child}; fn f(){child::open();}'
    tree = parse(source, 'fixture.rs')
    for spec in ({'imports': ['crate::io::io']}, {'calls': ['crate::io::io::open']}):
        findings = evaluate_forbid_ast_structured(tree, spec, source=source)
        assert len(findings) == 1 and findings[0]['unknown'] is False


@pytest.mark.parametrize('declaration,bound,member', [
    ('use Hash::{Hash};', 'Hash', True),
    ('use Hash::{Hash as Named};', 'Named', True),
    ('use Hash::{self};', 'Hash', False),
    ('use Hash::{self as Namespace};', 'Namespace', False),
])
def test_single_prefix_same_named_member_and_self_alias_keep_distinct_origins(declaration, bound, member):
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = declaration + ' fn f(){' + bound + '::run();}'
    tree = parse(source, 'fixture.rs')
    for kind, pattern in [('calls', 'Hash::Hash::run'), ('imports', 'Hash::Hash')]:
        findings = evaluate_forbid_ast_structured(tree, {kind: [pattern]}, source=source)
        assert len(findings) == int(member)
        assert all(finding['unknown'] is False for finding in findings)


def test_single_prefix_mixed_self_and_same_named_member_do_not_cross_qualify():
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = 'use Hash::{self as Ns, Hash as Named}; fn f(){Ns::run("namespace"); Named::run("member");}'
    tree = parse(source, 'fixture.rs')
    for value, count in [('namespace', 0), ('member', 1)]:
        findings = evaluate_forbid_ast_structured(
            tree, {'calls': [{'name': 'Hash::Hash::run', 'where': {'#0': value}}]}, source=source)
        assert len(findings) == count


@pytest.mark.parametrize('pattern,guard', [
    ('| None', ''), ('| None | Some(_)', ''), ('| None', ' if allowed()==true'),
])
def test_match_or_patterns_are_not_closure_parameter_lists(pattern, guard):
    source = 'fn f(value: Option<u8>){match value {' + pattern + guard + ' => finish(), _ => other()}}'
    tree = parse(source, 'fixture.rs')
    assert [c.target for c in tree.call_sites] == (['allowed'] if guard else []) + ['finish', 'other']
    assert all(c.kind is None for c in tree.call_sites)
    assert [m.original_op for m in tree.mutation_points] == (['=='] if guard else [])


def test_match_arm_closure_bodies_keep_inner_calls_and_mutations():
    source = '''fn f(value: bool) {
 let choose: fn(u8,u8)->bool = match value {
  true => |a,b| { inner(a,b); a==b },
  false => |a,b| { other(a,b); a!=b },
 };
}'''
    tree = parse(source, 'fixture.rs')
    assert [c.target for c in tree.call_sites] == ['inner', 'other']
    assert all(c.caller_scope == 'f' and c.kind is None for c in tree.call_sites)
    assert [m.original_op for m in tree.mutation_points] == ['==', '!=']


@pytest.mark.parametrize('declaration,bound', [
    ('use m::r#as;', 'as'),
    ('use m::r#as as renamed;', 'renamed'),
    ('use m::r#as as r#type;', 'type'),
    ('use m::{r#as, ordinary as other};', 'as'),
])
def test_raw_as_names_remain_identifiers_beside_real_alias_delimiters(declaration, bound):
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = 'mod m {pub fn r#as(){}} ' + declaration + ' fn f(){r#' + bound + '();}'
    tree = parse(source, 'fixture.rs')
    assert [c.target for c in tree.call_sites] == [bound]
    findings = evaluate_forbid_ast_structured(tree, {'calls': ['m::as']}, source=source)
    assert len(findings) == 1 and findings[0]['unknown'] is False


@pytest.mark.parametrize('capture', ['', 'move '])
@pytest.mark.parametrize('body', ['', 'dangerous(); if a==b {other();}'])
def test_async_blocks_do_not_create_calls_but_keep_body_facts(capture, body):
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = 'fn f(){let fut=async ' + capture + '{' + body + '};}'
    tree = parse(source, 'fixture.rs')
    assert [c.target for c in tree.call_sites] == (['dangerous', 'other'] if body else [])
    assert [m.original_op for m in tree.mutation_points] == (['=='] if body else [])
    assert evaluate_forbid_ast_structured(tree, {'calls': ['move', 'async']}, source=source) == []


def test_raw_move_identifiers_keep_genuine_calls_and_constructors():
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    source = 'struct r#move {enabled: bool} fn f(){r#move {enabled:true}; r#move();}'
    tree = parse(source, 'fixture.rs')
    assert [(c.target, c.kind) for c in tree.call_sites] == [('move', 'construct'), ('move', None)]
    findings = evaluate_forbid_ast_structured(tree, {'calls': ['move']}, source=source)
    assert len(findings) == 2 and all(finding['unknown'] is False for finding in findings)
