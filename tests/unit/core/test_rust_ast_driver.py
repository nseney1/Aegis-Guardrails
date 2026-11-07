"""Tests for Rust Normalized AST Driver and polyglot verification integration."""
from pathlib import Path
import pytest

from aegis_core.ast.runner import ASTDriverRegistry, ASTDriverRunner
from aegis_core.ast.schema import NormalizedAST
from aegis_core.verification.call_graph import check_normalized


RUST_CODE = """// Sample Rust Code for AST Driver testing
use std::collections::HashMap;
use crate::service::{DataProcessor, Config};

pub struct Worker {
    id: usize,
}

impl Worker {
    pub fn new(id: usize) -> Self {
        Worker { id }
    }

    pub fn process(&self, count: usize) -> bool {
        if self.id == count && count > 0 {
            execute_task();
            true
        } else {
            false
        }
    }
}

fn execute_task() {
    log_info();
}

fn log_info() {}

fn dead_uncalled_fn() {
    panic!("never called");
}
"""


def test_rust_ast_driver_runner_integration(tmp_path: Path):
    source_file = tmp_path / "worker.rs"
    source_file.write_text(RUST_CODE, encoding="utf-8")

    registry = ASTDriverRegistry()
    runner = ASTDriverRunner(registry=registry)

    ast: NormalizedAST = runner.parse_file(source_file, workspace_root=tmp_path)
    assert ast.language == "rust"
    assert len(ast.definitions) >= 5

    def_names = [d.name for d in ast.definitions]
    assert "Worker" in def_names
    assert "new" in def_names
    assert "process" in def_names
    assert "execute_task" in def_names
    assert "dead_uncalled_fn" in def_names

    # Check method flags
    proc_def = next(d for d in ast.definitions if d.name == "process")
    assert proc_def.is_method is True
    assert proc_def.class_name == "Worker"
    assert proc_def.is_exported is True

    # Check imports
    assert any(i.source == 'std::collections' and 'HashMap' in i.imported_symbols for i in ast.imports)

    # Check call sites
    callees = [c.target for c in ast.call_sites]
    assert "execute_task" in callees
    assert "log_info" in callees

    # Check mutations
    assert len(ast.mutation_points) >= 2
    op_pairs = [(m.original_op, m.replacement_op) for m in ast.mutation_points]
    assert ("==", "!=") in op_pairs
    assert (">", "<=") in op_pairs


def test_rust_call_graph_reachability(tmp_path: Path):
    source_file = tmp_path / "worker.rs"
    source_file.write_text(RUST_CODE, encoding="utf-8")

    registry = ASTDriverRegistry()
    runner = ASTDriverRunner(registry=registry)
    ast = runner.parse_file(source_file, workspace_root=tmp_path)

    # Calling check_normalized with fast_mode=False checks reachability across repo
    evidence = check_normalized(ast, str(tmp_path), fast_mode=False)
    assert evidence.tool == "call_graph"
    # dead_uncalled_fn is uncalled, so verdict is False (orphan detected)
    assert evidence.verdict is False
    assert "dead_uncalled_fn" in evidence.detail


def test_a_malformed_use_statement_fails_closed():
    """A stray brace cannot supply verification evidence from a partial parse."""
    from aegis_core.ast.driver_errors import ASTDriverError
    from aegis_core.ast.drivers.rust import parse

    with pytest.raises(ASTDriverError, match='mismatched delimiter at line 1') as error:
        parse("use crate::net::client};\nfn run() {}\n", "lib.rs")
    assert error.value.reason == 'syntax'


@pytest.mark.parametrize('expression,targets', [
    ('rt.block_on(async { let x = 1; tokio::time::sleep(d).await; x })',
     ['rt.block_on', 'tokio::time::sleep']),
    ('tokio::time::timeout(d, async { tokio::time::sleep(d).await })',
     ['tokio::time::timeout', 'tokio::time::sleep']),
    ('cvt(unsafe { libc::open(p, 0) })', ['cvt', 'libc::open']),
    ('f(const { 1 })', ['f']),
    ('f(const { inner() })', ['f', 'inner']),
    ('f(loop { break 1 })', ['f']),
    ('f(loop { break inner() })', ['f', 'inner']),
    ("f('work: loop { break 'work inner() })", ['f', 'inner']),
    ('f(async move { tokio::time::sleep(d).await })', ['f', 'tokio::time::sleep']),
    ('f({ inner(); 1 })', ['f', 'inner']),
    ('f({ x })', ['f']),
    ('f({})', ['f']),
])
def test_rust_block_arguments_preserve_nested_calls(expression, targets):
    from aegis_core.ast.drivers.rust import parse

    tree = parse('fn run() { ' + expression + '; }', 'src/lib.rs')
    assert [call.target for call in tree.call_sites] == targets
    assert all(call.kind != 'construct' for call in tree.call_sites)
    assert all(call.caller_scope == 'run' for call in tree.call_sites)
    # Block expressions cannot supply named struct fields to the outer call.
    assert all(key.startswith('#') for key in tree.call_sites[0].args)
    if 'libc::open' in targets:
        assert tree.call_sites[1].args == {'#0': '<expr>', '#1': '0'}


@pytest.mark.parametrize('name', ['Point', 'r#async'])
def test_rust_struct_arguments_preserve_fields_and_construct_calls(name):
    from aegis_core.ast.drivers.rust import parse

    tree = parse('fn run() { f(' + name + ' { x: 1, y: inner() }); }', 'src/lib.rs')
    assert [call.target for call in tree.call_sites] == ['f', name.removeprefix('r#'), 'inner']
    assert tree.call_sites[0].args == {'#0': '<expr>', 'x': '1', 'y': '<expr>'}
    assert tree.call_sites[1].kind == 'construct'
    assert tree.call_sites[1].args == {'x': '1', 'y': '<expr>'}


@pytest.mark.parametrize('name', ['Point', 'r#async'])
@pytest.mark.parametrize('argument', [True, False])
def test_rust_malformed_struct_fields_still_fail_closed(name, argument):
    from aegis_core.ast.driver_errors import ASTDriverError
    from aegis_core.ast.drivers.rust import parse

    expression = name + ' { x: 1, broken 2 }'
    if argument:
        expression = 'f(' + expression + ')'
    with pytest.raises(ASTDriverError, match='^invalid struct field at line 1$') as raised:
        parse('fn run() { ' + expression + '; }', 'src/lib.rs')
    assert raised.value.reason == 'syntax'


def test_rust_unrecognised_struct_shape_has_argument_and_statement_parity():
    from aegis_core.ast.drivers.rust import parse

    for expression, targets in [('f(Point { broken 2 })', ['f']), ('Point { broken 2 }', [])]:
        tree = parse('fn run() { ' + expression + '; }', 'src/lib.rs')
        assert [call.target for call in tree.call_sites] == targets
        assert all(call.kind != 'construct' for call in tree.call_sites)


def test_rust_struct_field_attributes_preserve_fields_updates_and_nested_calls():
    from aegis_core.ast.drivers.rust import parse

    tree = parse('''fn build() {
    let cfg = Config {
        name: n,
        #[cfg(feature = "llm")]
        planner: Planner::new(),
        #[allow(unused)] ..Default::default()
    };
    run(Config { #[cfg(test)] a: 1, b: 2 });
}''', 'src/lib.rs')
    assert [call.target for call in tree.call_sites] == [
        'Config', 'Planner::new', 'Default::default', 'run', 'Config']
    constructs = [call for call in tree.call_sites if call.kind == 'construct']
    assert [call.args for call in constructs] == [
        {'name': '<expr>', 'planner': '<expr>', '**': '<expr>'}, {'a': '1', 'b': '2'}]
    assert tree.call_sites[3].args == {'#0': '<expr>', 'a': '1', 'b': '2'}


@pytest.mark.parametrize('attributes', [
    '#[cfg(any())]',
    '#[cfg_attr(all(), allow(unused))] #[doc = "hidden()"]',
    '#![allow(unused)]',
])
@pytest.mark.parametrize('argument', [True, False])
def test_rust_leading_field_attributes_preserve_shorthand_and_update(attributes, argument):
    from aegis_core.ast.drivers.rust import parse

    expression = 'Config { ' + attributes + ' a, ' + attributes + ' ..Default::default() }'
    if argument:
        expression = 'consume(' + expression + ')'
    tree = parse('fn run() { ' + expression + '; }', 'src/lib.rs')
    assert [call.target for call in tree.call_sites] == (
        ['consume', 'Config', 'Default::default'] if argument else ['Config', 'Default::default'])
    construct = next(call for call in tree.call_sites if call.kind == 'construct')
    assert construct.args == {'a': '<expr>', '**': '<expr>'}
    if argument:
        assert tree.call_sites[0].args == {'#0': '<expr>', 'a': '<expr>', '**': '<expr>'}


@pytest.mark.parametrize('field', ['a', '..Default::default()'])
def test_rust_attributed_single_field_and_update_are_constructs(field):
    from aegis_core.ast.drivers.rust import parse

    tree = parse('fn run() { consume(Config { #[allow(unused)] ' + field + ' }); }', 'src/lib.rs')
    assert [call.target for call in tree.call_sites] == (
        ['consume', 'Config'] if field == 'a' else ['consume', 'Config', 'Default::default'])
    assert tree.call_sites[1].kind == 'construct'
    assert tree.call_sites[1].args == ({'a': '<expr>'} if field == 'a' else {'**': '<expr>'})


@pytest.mark.parametrize('fields', [
    '#[cfg(any())] a: 1, #[allow(unused)] broken 2',
    '#[cfg(any())] a: 1, #[allow(unused)]',
])
@pytest.mark.parametrize('argument', [True, False])
def test_rust_malformed_attributed_struct_fields_fail_closed(fields, argument):
    from aegis_core.ast.driver_errors import ASTDriverError
    from aegis_core.ast.drivers.rust import parse

    expression = 'Config { ' + fields + ' }'
    if argument:
        expression = 'consume(' + expression + ')'
    with pytest.raises(ASTDriverError, match='^invalid struct field at line 1$') as raised:
        parse('fn run() { ' + expression + '; }', 'src/lib.rs')
    assert raised.value.reason == 'syntax'


@pytest.mark.parametrize('fields,detail', [
    ('#[allow(unused)] a: 1, #[allow(unused)] a: 2', 'duplicate field a'),
    ('#[allow(unused)] ..base, #[allow(unused)] a: 1', 'invalid struct update position'),
])
def test_rust_attributed_struct_fields_keep_duplicate_and_update_errors(fields, detail):
    from aegis_core.ast.driver_errors import ASTDriverError
    from aegis_core.ast.drivers.rust import parse

    with pytest.raises(ASTDriverError, match='^' + detail + ' at line 1$') as raised:
        parse('fn run() { consume(Config { ' + fields + ' }); }', 'src/lib.rs')
    assert raised.value.reason == 'syntax'


@pytest.mark.parametrize('source,targets', [
    ('''fn run(value: Choice) { match value {
        #[cfg(any())] Choice::Named { #[cfg(any())] hidden, shown, .. }
            if guard() => handle(shown),
        #[allow(unused)] Choice::Tuple(a, b) => fallback(a, b),
        _ => finish()
    } }''', ['guard', 'handle', 'fallback', 'finish']),
    ('''fn run(value: Choice) {
        let Choice::Named { #[cfg(any())] hidden, shown, .. } = value else { fallback(); };
        handle(shown);
    }''', ['fallback', 'handle']),
    ('''fn run() {
        let values = (#[cfg(any())] first(), #[allow(unused)] second());
        consume(values);
    }''', ['first', 'second', 'consume']),
])
def test_rust_attributes_in_arms_patterns_and_tuples_preserve_only_body_calls(source, targets):
    from aegis_core.ast.drivers.rust import parse

    tree = parse(source, 'src/lib.rs')
    assert [call.target for call in tree.call_sites] == targets
    assert all(call.kind != 'construct' for call in tree.call_sites)


@pytest.mark.parametrize('source', [
    'fn ppm_rgb(bytes: &[u8]) -> Result<([u32; 2], &[u8])> { body() }',
    'fn run() -> Result<[([u8; 2], (u8, u8)); 4]> { body() }',
    'fn run(values: [([u8; 2], (u8, u8)); 4]) { body(); }',
    'struct Data { values: [([u8; 2], (u8, u8)); 4] } fn run() { body(); }',
    'enum Data { Values([([u8; 2], (u8, u8)); 4]) } fn run() { body(); }',
    'type Data = [([u8; 2], (u8, u8)); 4]; fn run() { body(); }',
    'type Data = Result<([u32; 2], &[u8])>; fn run() { body(); }',
    'type Data = [fn(u8) -> Result<[u8; 2]>; 4]; fn run() { body(); }',
    'fn run() { body::<Result<[([u8; 2], (u8, u8)); 4]>>(); }',
    'fn run() -> Result<([Vec<[u8; 2]>; 4], fn(u8) -> u8)> { body() }',
    'fn run() -> Result<[u8; module::COUNT]> { body() }',
    'fn run() -> Result<[u8; COUNT + 1]> { body() }',
    'type Data = [u8; COUNT * 2]; fn run() { body(); }',
    'fn run() { body::<[u8; COUNT + 1]>(); }',
    'fn run() -> Result<[u8; !0usize]> { body() }',
    'type Data = [u8; !COUNT]; fn run() { body(); }',
    'fn run() { body::<[u8; !0usize]>(); }',
    'fn run() { body::<Kind![]>(); }',
    'type Data = Kind!([[]]); fn run() { body(); }',
    'fn run() -> Result<Kind!([[]])> { body() }',
    'type Data = [Kind!(); 2]; fn run() { body(); }',
    'type Data = Kind!([u8; inner![]]); fn run() { body(); }',
])
def test_public_rust_extraction_preserves_nested_array_types_and_body_calls(source):
    from aegis_core.ast.policy import extract_normalized_ast

    tree = extract_normalized_ast('src/array_types.rs', code=source)
    assert tree.language == 'rust'
    assert [call.target for call in tree.call_sites] == ['body']


@pytest.mark.parametrize('source,detail', [
    ('fn run() -> Result<([u8; 2], &[u8]) { body() }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run() -> Result<([u8; 2], &[u8]> { body() }', 'unclosed delimiter'),
    ('type Data = Result<[u8; 2];', 'invalid generic arguments'),
    ('fn run() -> Result<(u8; u8)> { body() }', 'invalid generic arguments'),
    ('fn run() -> Result<(u8>, u8)> { body() }', 'invalid generic arguments'),
    ('fn run() -> Result<[Vec<u8; 2>; 4]> { body() }', 'invalid generic arguments'),
    ('fn run() -> Result<[u8; 2; 3]> { body() }', 'invalid array type'),
    ('fn run() { body::<[u8; 2; 3]>(); }', 'invalid array type'),
    ('type Data = [u8; 2; 3];', 'invalid array type'),
    ('fn run() -> Result<[; 2]> { body() }', 'invalid array type'),
    ('fn run() { body::<[u8; ]>(); }', 'invalid array type'),
    ('type Data = [; 2];', 'invalid array type'),
    ('type Data = [u8; ];', 'invalid array type'),
    ('fn run() -> Result<[]> { body() }', 'invalid array type'),
    ('fn run() -> Result<[u8; dangerous()]> { body() }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run() -> Result<[([u8; 2], u8); dangerous()]> { body() }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run() -> Result<[u8; { dangerous() }]> { body() }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run() { body::<Result<[u8; dangerous()]>>(); }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run() -> Result<[u8; dangerous![]]> { body() }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run(values: [([u8; dangerous![]], u8); 4]) {}',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = [u8; dangerous![]];',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = Result<[([u8; 2], u8); dangerous![]]>;',
     'unsupported_lexical_context: const expression in type'),
    ('fn run() { body::<Result<[u8; dangerous![]]>>(); }',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = [([u8; 2], u8); dangerous()];',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = ([u8; 2], Holder<{ dangerous() }>);',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = ([u8; 2], { dangerous() });',
     'unsupported_lexical_context: block in type'),
    ('type Data = [Kind!([u8; dangerous()]); 2]; fn run() { body(); }',
     'unsupported_lexical_context: const expression in type'),
    ('fn run(values: [Kind!([u8; dangerous()]); 2]) { body(); }',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = Kind!([u8; dangerous()]); fn run() { body(); }',
     'unsupported_lexical_context: const expression in type'),
    ('type Data = Kind!([u8; dangerous(); 0]); fn run() { body(); }',
     'unsupported_lexical_context: const expression in type'),
])
def test_public_rust_nested_array_types_keep_malformed_and_executable_types_closed(source, detail):
    from aegis_core.ast.policy import ASTExtractionError, extract_normalized_ast

    with pytest.raises(ASTExtractionError) as raised:
        extract_normalized_ast('src/array_types.rs', code=source)
    assert str(raised.value) == f'cannot verify src/array_types.rs: ASTDriverError: {detail} at line 1'
    assert raised.value.__cause__.reason == 'syntax'
