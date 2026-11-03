"""Native JS/TS extraction and policy outcomes, without Node or repository execution."""
import pytest

from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.policy import evaluate_forbid_ast_structured
from aegis_core.ast.schema import NormalizedAST


def parse(source, path='fixture.ts'):
    from aegis_core.ast.drivers.js import parse
    return parse(source, path)


def findings(source, spec, path='fixture.ts'):
    return evaluate_forbid_ast_structured(parse(source, path), spec, source=source)


def facts_with_checked_positions(source, path='fixture.ts'):
    tree = parse(source, path)
    for point in tree.mutation_points:
        assert source[point.byte_offset:point.byte_offset + len(point.original_op)] == point.original_op
        assert point.col == point.byte_offset - source.rfind('\n', 0, point.byte_offset) - 1
    facts = tree.to_dict()
    for point in facts['mutation_points']:
        point.pop('col')  # spacing changes columns; exact positions were checked above
    return facts


def test_import_variants_aliases_and_round_trip():
    source = '''import {
exec as run,
} from 'node:child_process';
const cp = require('node:child_process');
const {execSync: launch} = require('child_process');
run('a'); cp.exec('b'); launch('c');
'''
    tree = parse(source)
    assert tree.metadata['capabilities'] == ['allow_comments', 'args', 'decorators']
    assert NormalizedAST.from_dict(tree.to_dict()).to_dict() == tree.to_dict()
    assert [i.line for i in tree.imports if 'child_process' in i.source] == [1, 4, 5]
    assert len(findings(source, {'calls': ['child_process.exec', 'child_process.execSync']})) == 3


@pytest.mark.parametrize('obj,unknown,hit', [
    ('{shell: true}', False, True),
    ('{shell: false}', False, False),
    ('{shell: false, ...opts}', True, True),
    ('{...opts, shell: true}', False, True),
    ('{shell: true, shell: false}', False, False),
    ('{shell: false, [key]: value}', True, True),
    ('{[key]: value, shell: false}', False, False),
    ('{get shell() { return false }}', True, True),
])
def test_object_fields_follow_source_order_and_uncertainty(obj, unknown, hit):
    result = findings('spawn("x", [], ' + obj + ')', {'calls': [{'name': 'spawn', 'where': {'shell': True}}]})
    assert bool(result) is hit
    if hit:
        assert result[0]['unknown'] is unknown


def test_separate_object_arguments_cannot_supply_a_definite_field():
    result = findings('spawn({shell:true}, {shell:false})', {'calls': [{'name': 'spawn', 'where': {'shell': True}}]})
    assert result[0]['unknown'] is True


@pytest.mark.parametrize('value,condition,unknown,hit', [
    ('0x10', 16, False, True), ('1_000', 1000, False, True),
    ('16n', 16, True, True), ('9007199254740993', 9007199254740993, True, True),
    ('0xden', 222, True, True),
    ('true', 1, False, False), ('"16"', 16, False, False),
    (r'"a\u0062"', 'ab', False, True),
])
def test_literal_semantics_are_typed(value, condition, unknown, hit):
    result = findings('danger(' + value + ')', {'calls': [{'name': 'danger', 'where': {'#0': condition}}]})
    assert bool(result) is hit
    if hit:
        assert result[0]['unknown'] is unknown


def test_calls_in_templates_jsx_optional_chains_and_generics():
    source = '''const a = `${eval(code)}`;
const b = <A onClick={() => eval(code)}>{eval(code)}</A>;
obj?.run<Type<string>>(code); obj['danger'](code); (0, eval)(code);
'''
    tree = parse(source, 'fixture.tsx')
    assert sum(c.target == 'eval' for c in tree.call_sites) == 4
    assert any(c.target.endswith('run') for c in tree.call_sites)
    assert any(c.target.endswith('danger') for c in tree.call_sites)


def test_definitions_decorators_and_constructor_sites():
    source = '''@sealed
export class Worker {
  @ns.checked('x')
  run(value: string): void { eval(value); }
}
export const start = (x: number) => new Worker();
export default function finish() { new Worker; }
'''
    tree = parse(source)
    assert {'Worker', 'run', 'start', 'finish'} <= {d.name for d in tree.definitions}
    assert next(d for d in tree.definitions if d.name == 'run').class_name == 'Worker'
    assert {'sealed', 'ns.checked'} <= set(tree.decorators)
    assert sum(c.kind == 'new' for c in tree.call_sites) == 2
    assert not any(c.target in ('run', 'finish') for c in tree.call_sites)


def test_import_unknown_and_nonexecuting_text():
    source = r'''import(name); require(other);
const a = "eval(code)"; const b = /eval\(code\)/;
// eval(code)
'''
    assert len(findings(source, {'imports': ['child_process']})) == 2
    assert findings(source, {'calls': ['eval']}) == []


def test_optional_calls_non_null_assertions_and_parenthesized_members_are_not_lost():
    tree = parse('eval?.(code); obj.run?.(code); obj!.danger(code); (obj.danger)(code); (0, (eval))(code);')
    assert [c.target for c in tree.call_sites] == ['eval', '.run', '.danger', '.danger', 'eval']


def test_async_arrow_parameters_and_factory_results_do_not_invent_calls():
    tree = parse('items.map(async (x) => eval(x)); factory(eval)(code);')
    assert not any(c.target == 'async' for c in tree.call_sites)
    assert [c.target for c in tree.call_sites].count('eval') == 1
    assert tree.call_sites[-1].target == '<computed>'


def test_quoted_method_definition_and_nested_call_keep_their_names():
    tree = parse('class X { "run"(code) { eval(code) } }')
    assert next(d for d in tree.definitions if d.name == 'run').class_name == 'X'
    assert [c.target for c in tree.call_sites] == ['eval']


def test_overrides_only_come_from_comment_tokens_on_the_same_line():
    source = '''eval(code); // aegis: allow[r] fixture
eval("// aegis: allow[r] fake");
eval(code); /* aegis: allow[r] block */
'''
    result = evaluate_forbid_ast_structured(parse(source), {'calls': ['eval']}, rule_id='r', source=source)
    assert [r['override'] for r in result] == ['fixture', None, 'block']


@pytest.mark.parametrize('path,language', [
    ('a.ts', 'typescript'), ('a.tsx', 'typescript'), ('a.mts', 'typescript'), ('a.cts', 'typescript'),
    ('a.js', 'javascript'), ('a.jsx', 'javascript'), ('a.mjs', 'javascript'), ('a.cjs', 'javascript'),
])
def test_language_identity_is_extension_based(path, language):
    tree = parse('eval(code)', path)
    assert tree.language == language and tree.file_path == path


def test_import_reexports_type_only_and_assignment_bindings():
    source = '''import type { Thing as T } from 'types';
import fs, {readFile as read} from 'node:fs';
import cp = require('node:child_process');
export {x as y} from 'worker'; export * from 'others';
cp.exec('x'); require('child_process').exec('y'); read('z');
'''
    tree = parse(source)
    assert tree.imports[0].is_type_only is True
    assert [i.source for i in tree.imports] == ['types', 'fs', 'child_process', 'worker', 'others', 'child_process']
    assert len(findings(source, {'calls': ['child_process.exec']})) == 2
    assert len(findings(source, {'calls': ['fs.readFile']})) == 1


@pytest.mark.parametrize('source', ['import', "import {x} from", 'import x from', 'import x', 'import type', 'export type'])
def test_incomplete_imports_are_explicit_syntax_errors(source):
    with pytest.raises(ASTDriverError, match='import'):
        parse(source)


def test_multiple_module_arrow_bindings_and_asi_declarations_have_distinct_scopes():
    source = '''export const first = (x) => eval(x), second = (x) => eval(x);
const third = (x) => { eval(x) }
const fourth = function(x) { eval(x) }
'''
    tree = parse(source)
    assert {'first', 'second', 'third', 'fourth'} <= {d.name for d in tree.definitions}
    assert [c.caller_scope for c in tree.call_sites if c.target == 'eval'] == ['first', 'second', 'third', 'fourth']


def test_object_methods_are_definitions_but_value_calls_are_not_dropped():
    tree = parse('const x = {run(value) { eval(value) }, value: eval(code)};')
    assert sum(c.target == 'eval' for c in tree.call_sites) == 2
    assert not any(c.target == 'run' for c in tree.call_sites)


def test_spread_positions_and_cross_object_fields_remain_unknown():
    tree = parse('danger(...items, true, {shell:true}); danger({...opts}, {shell:true});')
    assert tree.call_sites[0].args['#1'] == '<expr>'
    assert tree.call_sites[0].args['shell'] == '<expr>'
    assert tree.call_sites[1].args['shell'] == '<expr>'


def test_computed_callee_and_member_ambiguity_is_retained():
    tree = parse('obj[key](code); obj["eval"](code); (choice ? one : two)(code);')
    assert tree.call_sites[0].target.endswith('<computed>')
    assert tree.call_sites[1].target.endswith('eval')
    assert tree.call_sites[2].target == '<computed>'


def test_size_limit_is_the_utf8_byte_size_and_exact_bound_is_accepted():
    from aegis_core.ast.drivers.js.tokenizer import MAX_SOURCE_BYTES, JSLexError

    assert parse('//' + 'x' * (MAX_SOURCE_BYTES - 2)).call_sites == ()
    with pytest.raises(JSLexError) as error:
        parse('//' + 'x' * (MAX_SOURCE_BYTES - 1))
    assert error.value.reason == 'too_large'
    with pytest.raises(JSLexError) as error:
        parse('//' + 'é' * (MAX_SOURCE_BYTES // 2))
    assert error.value.reason == 'too_large'


@pytest.mark.parametrize('literal', ['"("', '")"', '"{"', '"class"', '"import"', '"new"', '"@"'])
def test_decoded_literal_values_are_never_reinterpreted_as_code_tokens(literal):
    tree = parse('danger(' + literal + '); eval(code);')
    assert [c.target for c in tree.call_sites] == ['danger', 'eval']
    assert tree.definitions == () and tree.imports == ()


def test_declared_import_named_methods_and_file_wide_builtin_binding():
    source = 'function eval(x) { return x; } class X { import(x) { return x; } } eval(code);'
    tree = parse(source)
    assert tree.imports == ()
    assert findings(source, {'calls': [{'name': 'eval', 'builtin': True}]}) == []


@pytest.mark.parametrize('source', [
    'function f(x=eval(code)) { return x; }',
    'function* f() { yield* eval(code); }',
    'async function f() { return await(eval(code)); }',
    'if(x) (eval(code));',
    'while(x) (eval(code));',
    'function f() { return(eval(code)); }',
    'class X { static { eval(code); } }',
    'class X { [eval(code)]() {} }',
    'enum X { Value = eval(code) }',
    'const f = <T,>(x:T) => eval(code);',
])
def test_common_executable_contexts_do_not_hide_or_invent_calls(source):
    tree = parse(source, 'fixture.tsx')
    assert [c.target for c in tree.call_sites] == ['eval']


def test_literal_receivers_and_grouped_constructors_keep_sites_and_lines():
    tree = parse('"x".danger();\n[one].danger();\nnew (Worker)();')
    assert [(c.target, c.line) for c in tree.call_sites] == [('.danger', 1), ('.danger', 2), ('Worker', 3)]
    assert tree.call_sites[-1].kind == 'new'


def test_non_null_asserted_expression_still_uses_division_context():
    assert [c.target for c in parse('const x = value! / eval(code) / 2;').call_sites] == ['eval']


@pytest.mark.parametrize('name', ['type', 'from'])
def test_contextual_type_names_preserve_runtime_import_aliases(name):
    source = f"import {name} from 'worker'; import {{{name} as t}} from 'other'; {name}(); t();"
    tree = parse(source)
    assert not tree.imports[0].is_type_only
    assert tree.imports[0].aliases == ((name, 'worker'),)
    patterns = ['worker', f'other.{name}']
    assert [row['pattern'] for row in findings(source, {'calls': patterns})] == patterns
    typed = parse("import type Name from 'types';").imports[0]
    assert typed.is_type_only and typed.aliases == (('Name', 'types'),)


@pytest.mark.parametrize('source', [
    'spawn("x", [], opts)',
    'spawn("x", [], {__proto__: options})',
    'spawn("x", [], {__proto__: {shell:true}})',
    'spawn(unknown, {shell:true})',
])
def test_unknown_argument_fields_and_inherited_properties_cannot_be_definite_safe(source):
    result = findings(source, {'calls': [{'name': 'spawn', 'where': {'shell': True}}]})
    assert result and result[0]['unknown'] is True


def test_explicit_own_property_overrides_an_unknown_prototype():
    assert findings('spawn({shell:false, __proto__: options})', {'calls': [{'name': 'spawn', 'where': {'shell': True}}]}) == []


def test_identifier_name_keywords_in_properties_and_imports_are_not_statements():
    source = '''import {class as Class, import as load, function as func} from 'worker';
obj.class(); obj.function(); obj.import(); obj.if();
const x = {class() { eval(code); }, import: 1, "[": true};
class X { if() { eval(code); } function() { eval(code); } }
'''
    tree = parse(source)
    assert len(tree.imports) == 1 and tree.imports[0].source == 'worker'
    assert sum(c.target == 'eval' for c in tree.call_sites) == 3
    assert not any(d.name in ('as', 'func') for d in tree.definitions)
    assert {c.target for c in tree.call_sites} >= {'.class', '.function', '.import', '.if'}


def test_string_keys_that_look_like_punctuation_are_plain_properties():
    tree = parse('danger({"[":true, "...":false, "{":1, "}":2});')
    assert tree.call_sites[0].args['['] == 'True'
    assert tree.call_sites[0].args['...'] == 'False'


def test_parenthesized_object_literal_retains_known_fields():
    result = findings('spawn(({shell:true}))', {'calls': [{'name': 'spawn', 'where': {'shell': True}}]})
    assert result and result[0]['unknown'] is False


@pytest.mark.parametrize('depth', [3, 8, 48, 120])
@pytest.mark.parametrize('template', [
    'const x = {open}eval(code){close} / 2;',
    'f({open}obj.run(value, other){close});',
    '({open}eval{close})(code);',
    'if({open}eval(code){close}) /not_code/.test(value);',
])
def test_redundant_groupings_preserve_extracted_facts(depth, template):
    deep = template.format(open='(' * depth, close=')' * depth)
    shallow = template.format(open='(', close=')')
    assert facts_with_checked_positions(deep) == facts_with_checked_positions(shallow)


@pytest.mark.parametrize('module', ["(('node:child_process'))", '`node:child_process`'])
def test_static_module_literals_are_decoded_through_transparent_groups(module):
    source = 'const cp = require(' + module + '); cp.exec("x"); import(' + module + ');'
    tree = parse(source)
    assert [node.source for node in tree.imports] == ['child_process', 'child_process']
    assert len(findings(source, {'calls': ['child_process.exec']})) == 1


def test_unknown_module_receiver_retains_its_suffix_and_uncertainty():
    tree = parse('require(name).exec(code);')
    assert [node.source for node in tree.imports] == ['<expr>']
    assert tree.call_sites[-1].target == '<expr>.exec'


@pytest.mark.parametrize('expression', [
    'eval(code) + other', 'eval(code), other', 'choice ? eval(code) : other',
    'eval(/* argument */ code)', 'eval("code")', 'eval(inner(code))',
])
def test_group_compaction_preserves_nonflat_expressions(expression):
    assert facts_with_checked_positions('(((' + expression + ')));') == facts_with_checked_positions('(' + expression + ');')


@pytest.mark.parametrize('obj', [
    '{get "shell"() { return false }}', '{set "shell"(value) {}}',
    '{async shell() {}}', '{async [key]() {}}', '{get [key]() {}}',
    '{*shell() {}}', '{async *shell() {}}', '{0x10:true}', '{1.0:true}',
])
def test_accessor_method_and_numeric_keys_cannot_be_treated_as_absent(obj):
    key = '16' if '0x10' in obj else '1' if '1.0' in obj else 'shell'
    result = findings('danger(' + obj + ')', {'calls': [{'name': 'danger', 'where': {key: True}}]})
    assert result


@pytest.mark.parametrize('newline', ['\r', '\r\n', '\u2028', '\u2029'])
def test_javascript_line_terminators_end_comments_and_preserve_call_lines(newline):
    tree = parse('// nonexecuting eval(code)' + newline + 'eval(code);')
    assert [(node.target, node.line) for node in tree.call_sites] == [('eval', 2)]


@pytest.mark.parametrize('source,path', [
    ('/* first\rsecond */ eval(code);', 'fixture.js'),
    ('const value = `first\u2028${eval(code)}`;', 'fixture.ts'),
    ('const value = <A>first\r{eval(code)}</A>;', 'fixture.jsx'),
    ('const value = <A value="first\u2029second">{eval(code)}</A>;', 'fixture.tsx'),
])
def test_multiline_lexical_modes_keep_ecmascript_line_numbers(source, path):
    assert next(node.line for node in parse(source, path).call_sites if node.target == 'eval') == 2


@pytest.mark.parametrize('space', ['\v', '\f', '\u0085'])
def test_comment_override_line_mapping_does_not_use_python_only_line_breaks(space):
    source = 'eval(code); /* comment' + space + 'aegis: allow[r] fixture */\neval(code);'
    result = evaluate_forbid_ast_structured(parse(source), {'calls': ['eval']}, rule_id='r', source=source)
    assert [row['override'] for row in result] == ['fixture', None]


@pytest.mark.parametrize('source', [
    'namespace Name { eval(code); }',
    'export namespace Name { eval(code); }',
    'module Name { eval(code); }',
    'declare module "worker" { function run():void; } eval(code);',
])
def test_namespace_statement_bodies_do_not_turn_executable_calls_into_methods(source):
    assert [node.target for node in parse(source).call_sites] == ['eval']


@pytest.mark.parametrize('declaration', [
    'const zero=0, cp = require("child_process"); cp.exec(code);',
    'let zero=0, {exec: run} = require("child_process"); run(code);',
    'const cp: typeof import("child_process") = require("child_process"); cp.exec(code);',
    'const {["exec"]: run} = require("child_process"); run(code);',
    'const zero=0, {exec:run}\n = require("child_process"); run(code);',
    'const zero=0, {exec:run} /* boundary */ = require("child_process"); run(code);',
    'const zero=0, {exec:run} // boundary\n = require("child_process"); run(code);',
])
def test_commonjs_declarators_preserve_the_actual_local_binding(declaration):
    assert findings(declaration, {'calls': ['child_process.exec']})


def test_default_commonjs_binding_preserves_unknown_fallback_callee():
    tree = parse('const {exec: run = fallback} = require("child_process"); run(code);')
    assert tree.call_sites[-1].target == '<computed>'


def test_asi_ends_commonjs_bindings_and_module_function_scopes():
    source = 'const cp = require("child_process")\ncp.exec(code)\nconst fn = () => eval(code)\neval(code)'
    tree = parse(source)
    assert findings(source, {'calls': ['child_process.exec']})
    assert [node.caller_scope for node in tree.call_sites if node.target == 'eval'] == ['fn', None]


def test_generic_type_argument_commas_do_not_shift_real_argument_positions():
    source = 'danger(factory<A,B>(code), true);'
    result = findings(source, {'calls': [{'name': 'danger', 'where': {'#1': True}}]})
    assert result and result[0]['unknown'] is False


def test_module_generic_arrow_is_a_definition_with_a_caller_scope():
    tree = parse('export const fn = <T,>(value:T) => eval(value);')
    assert next(node for node in tree.definitions if node.name == 'fn').is_exported
    assert next(node for node in tree.call_sites if node.target == 'eval').caller_scope == 'fn'


@pytest.mark.parametrize('first', ['one < eval(code)', 'one < (left + right)', 'one < (left, right)'])
def test_relational_arguments_are_not_misread_as_generic_type_lists(first):
    result = findings('danger(' + first + ', other > (value), true);', {'calls': [{'name': 'danger', 'where': {'#2': True}}]})
    assert result and result[0]['unknown'] is False


def test_nested_and_disjoint_definition_scopes_cover_only_their_actual_sites():
    source = '''const outer = function named(value=seed()) {
  function inner() { nested(); new Child; }
  after();
};
tail(); new Outside();
class Container { run() { methodCall(); } }
'''
    tree = parse(source)
    assert [(node.target, node.caller_scope) for node in tree.call_sites] == [
        ('seed', 'named'), ('nested', 'inner'), ('Child', 'inner'),
        ('after', 'named'), ('tail', None), ('Outside', None), ('methodCall', 'run'),
    ]
    assert next(node.class_name for node in tree.definitions if node.name == 'run') == 'Container'


def test_async_function_expression_keeps_division_and_module_binding_context():
    tree = parse('const fn = async function() {} / eval(code) / 2;')
    assert [node.target for node in tree.call_sites] == ['eval']
    assert any(node.name == 'fn' for node in tree.definitions)


def test_class_field_expressions_keep_calls_between_real_method_declarations():
    tree = parse('class X { field=f(x)+g(y); other=h(z)\nmethod(){ return k(q); } }')
    assert [node.target for node in tree.call_sites] == ['f', 'g', 'h', 'k']
    assert {node.name for node in tree.definitions if node.kind == 'method'} == {'method'}


@pytest.mark.parametrize('source', [
    'f(value); ns.run(other, true, null, undefined);',
    'import * as cp from "child_process"; cp.exec(value);',
    'factory(value)(other); factory(value).run(other); (factory(value))(other);',
    'new Worker(value); new ns.Worker(other); new Empty();',
    'class X { run(value) { f(value); } field=f(value)+g(other); }',
    'const x={run(value){ f(value); }, field:g(value)}; const fn=(value)=>h(value);',
    '@ns.checked(value) class X { @checked(other) run(value) { f(value); } }',
    'const x=<A value={f(value)}>{`${g(other)}`}</A>;',
    '/word/.test(value); "text".run(other); 1..run(value);',
])
def test_call_compaction_preserves_complete_facts_across_transparent_spacing(source):
    import re

    spaced = re.sub(r'([A-Za-z_$][A-Za-z0-9_$]*)\(', r'\1 (', source)
    assert facts_with_checked_positions(source, 'fixture.tsx') == facts_with_checked_positions(spaced, 'fixture.tsx')


@pytest.mark.parametrize('value', ['undefined', 'NaN', 'Infinity'])
def test_unsupported_identifier_values_remain_unknown_with_or_without_call_spacing(value):
    for spacing in ('', ' '):
        result = findings('danger' + spacing + '(' + value + ')', {'calls': [{'name': 'danger', 'where': {'#0': value}}]})
        assert result and result[0]['unknown'] is True


def test_operator_mutations_preserve_positions_and_public_application():
    from aegis_core.verification import mutation_tester

    source = 'const café = 1;\r\nfunction first(x) { return x === 10 && x <= 20; }\nfunction second(x) { return x + 1; }'
    tree = parse(source)
    assert [(p.original_op, p.replacement_op, p.mutation_type) for p in tree.mutation_points] == [
        ('===', '!==', 'cmpop'), ('&&', '||', 'boolop'), ('<=', '>=', 'cmpop'), ('+', '-', 'binop'),
    ]
    first = mutation_tester.collect_mutations_from_ast(tree, target_function='first')
    assert [p.original_op for p in first] == ['===', '&&', '<=']
    point = first[0]
    assert (point.line, point.col, point.byte_offset) == (2, 29, source.index('==='))
    assert mutation_tester.apply_mutation_point(source, point) == source.replace('===', '!==', 1)


def test_mutations_only_come_from_executable_operator_tokens():
    source = '''const a="x === y"; const b=/x === y/; // x === y
const c=`x === y ${left !== right}`;
const d=<A>x === y {left == right}</A>;
'''
    assert [p.original_op for p in parse(source, 'fixture.tsx').mutation_points] == ['!==', '==']


def test_binary_mutations_do_not_include_unary_generator_or_import_tokens():
    source = 'import * as ns from "worker"; function* gen(){ yield* values; } const a=-value; const b=+value; const c=left+right;'
    assert [(p.original_op, p.replacement_op) for p in parse(source).mutation_points] == [('+', '-')]


def test_generic_angles_are_not_value_mutations_and_numeric_comparisons_are():
    source = 'class Box<T> {} factory<T>(value); const x=<T>value; if(value > 16) eval(code);'
    assert [(p.original_op, p.replacement_op) for p in parse(source).mutation_points] == [('>', '<')]


def test_numeric_literal_type_arguments_and_assertions_are_not_comparisons():
    tree = parse('factory<16>(value); const x=<16>value;')
    assert tree.mutation_points == ()


def test_redundant_group_compaction_preserves_require_imports_and_real_positions():
    source = 'const cp = (((require(name))));\n(((worker.run(value))));'
    tree = parse(source)
    assert [node.source for node in tree.imports] == ['<expr>']
    assert [(node.target, node.line) for node in tree.call_sites] == [('require', 1), ('.run', 2)]


@pytest.mark.parametrize('source', [
    'danger({shell:false,...opts,shell:true});',
    'danger({__proto__:options,shell:false,encoding:"utf8"});',
    'danger({pattern:/eval(code)[{}]/,shell:false}); eval(code);',
    'const obj={field:true}; const fn=()=>{field:false};',
    'const x={left:{shell:true}}; danger(({shell:true}));',
    'const equal=({shell:true}) === {shell:false};',
    'const zero=0,{exec:run}=require("child_process"); run(code);',
    'const zero=0,{exec:run}:Options=require("child_process"); run(code);',
])
def test_flat_objects_preserve_complete_facts_when_an_inert_comment_disables_compaction(source):
    assert facts_with_checked_positions(source) == facts_with_checked_positions(source.replace('{', '{/* boundary */', 1))


@pytest.mark.parametrize('source,reason', [
    ('const obj={value:"\\uZZZZ"}', 'unicode'),
    ('const obj={value:1.0n}', 'number'),
    ('const obj={pattern:/unterminated}', 'unterminated_regex'),
    ('const obj={value:/* unterminated}', 'unterminated_comment'),
])
def test_flat_object_candidates_preserve_lexical_errors(source, reason):
    with pytest.raises(ASTDriverError, match=reason):
        parse(source)


def test_flat_object_depth_uses_the_original_nesting():
    assert parse('[' * 255 + '{shell:true}' + ']' * 255).call_sites == ()
    with pytest.raises(ASTDriverError, match='depth'):
        parse('[' * 256 + '{shell:true}' + ']' * 256)


def test_literal_receiver_calls_keep_the_receiver_start_line():
    tree = parse('const value=/word/\n.test(input);\n"first\\\nsecond".run(value);')
    assert [(node.target, node.line) for node in tree.call_sites] == [('.test', 1), ('.run', 3)]


@pytest.mark.parametrize('source', [
    'const obj={/* before */ run(value){ eval(value); }};',
    'const obj={run /* name */ (value){ eval(value); }};',
    'const obj={get /* key */ [name] /* params */ () { eval(value); }};',
])
def test_comments_between_object_method_tokens_preserve_the_method_boundary(source):
    assert [node.target for node in parse(source).call_sites] == ['eval']


@pytest.mark.parametrize('literal,expected', [
    (r'"\x61"', 'a'), (r'"\u{61}"', 'a'), (r'"\v"', '\v'),
    (r'"\0"', '\0'), (r'"\q"', 'q'), ('"a\\\r\nb"', 'ab'),
    (r'"\ud83d\ude00"', '😀'), (r'"\ud800"', '\ud800'),
    (r'"\\uZZZZ"', '\\uZZZZ'),
])
def test_javascript_string_escapes_keep_their_semantics_across_json_subset_decoding(literal, expected):
    result = findings('danger(' + literal + ')', {'calls': [{'name': 'danger', 'where': {'#0': expected}}]})
    assert result and result[0]['unknown'] is False


def test_repeated_flat_calls_keep_independent_argument_dictionaries():
    tree = parse('first(value); second(value);')
    tree.call_sites[0].args['#0'] = 'changed'
    assert tree.call_sites[1].args['#0'] == 'value'


@pytest.mark.parametrize('source,expected', [
    ('first(true); second(false);', [('first', None), ('second', None)]),
    ('head(); obj.new\nnext(); tail();', [('head', None), ('next', None), ('tail', None)]),
    ('head(); obj. /* boundary */ new\nnext(); tail();', [('head', None), ('next', 'new'), ('tail', None)]),
    ('head(); new Worker(value); tail();', [('head', None), ('Worker', 'new'), ('tail', None)]),
    ('head(); new Worker; factory(value)(other); tail();', [('head', None), ('Worker', 'new'), ('factory', None), ('<computed>', None), ('tail', None)]),
    ('head(); tag`plain ${nested()}`; tail();', [('head', None), ('tag', None), ('nested', None), ('tail', None)]),
])
def test_ordered_call_facts_preserve_constructor_and_property_new_contexts(source, expected):
    tree = parse(source)
    assert [(site.target, site.kind) for site in tree.call_sites] == expected


@pytest.mark.parametrize('source,expected', [
    ('new (factory(value));', [('<computed>', 'new'), ('factory', None)]),
    ('new (Worker);', [('Worker', 'new')]),
    ('new obj[key];', [('.<computed>', 'new')]),
    ('new Worker().run(value);', [('Worker', 'new'), ('.run', None)]),
    ('new (factory(value))(other);', [('factory', None), ('<computed>', 'new')]),
    ('new new Worker();', [('<computed>', 'new'), ('Worker', 'new')]),
    ('new new Worker()(value);', [('Worker', 'new'), ('<computed>', 'new')]),
])
def test_constructed_factory_results_and_grouped_callees_keep_all_invocations(source, expected):
    assert [(node.target, node.kind) for node in parse(source).call_sites] == expected


@pytest.mark.parametrize('receiver', ['(cp)', '(0, cp)', '((cp))'])
def test_grouped_known_import_receivers_keep_their_module_identity(receiver):
    source = 'import * as cp from "child_process"; ' + receiver + '.exec("x");'
    result = findings(source, {'calls': ['child_process.exec']})
    assert result and result[0]['unknown'] is False


@pytest.mark.parametrize('name', ['True', 'False', 'None'])
def test_python_literal_spellings_are_unknown_javascript_references(name):
    result = findings('spawn({shell:' + name + '})', {'calls': [{'name': 'spawn', 'where': {'shell': True}}]})
    assert result and result[0]['unknown'] is True


# AC-35 / AST-H3 (review round 1): a regex or JSX start must never swallow a later executable call.
# Every source below is valid JavaScript/TypeScript that runs `eval` (checked with node or the TS grammar).
@pytest.mark.parametrize('source,path', [
    ("const f = () => {}\n/'/.test(s); eval(x); // '", 'fixture.js'),
    ("const f = a => {}\n/'/.test(s); eval(x); // '", 'fixture.ts'),
    ("const f = () => {} /* gap\n */ /'/.test(s); eval(x); // '", 'fixture.js'),
    ("const f = () => {}\n<a>'</a>; eval(x); // '", 'fixture.jsx'),
    ('const el = <a title="x,y">(hi)</a>; eval(x); y = 1 / 2;', 'fixture.jsx'),
    ('const el = <a title="x,y">(hi)</a>; eval(x); y = 1 / 2;', 'fixture.js'),
    ('const el = <a title="x,y">(hi)</a>; eval(x); y = 1 / 2;', 'fixture.tsx'),
    ("const el = <_a>'</_a>; eval(x); // '", 'fixture.jsx'),
    ("a = b\n++/'/.lastIndex; eval(x) // '", 'fixture.js'),
    ("a = b /* gap\n */ --/'/.lastIndex; eval(x) // '", 'fixture.js'),
    ("x = ++/'/.lastIndex; eval(x) // '", 'fixture.js'),
    ("for (const c of /'/.source) eval(x); // '", 'fixture.js'),
    ("for (of of /'/.source) eval(x); // '", 'fixture.js'),
    ("for (const c of <a>'</a>.props) eval(x); // '", 'fixture.jsx'),
])
def test_ac35_regex_and_jsx_starts_cannot_hide_following_calls(source, path):
    assert 'eval' in [node.target for node in parse(source, path).call_sites]


# Guard for the contextual-keyword fix: where `await`/`yield` is provably a keyword (module goal, a generator
# body, or strict class code) the regex/JSX reading must be kept rather than failing closed.
@pytest.mark.parametrize('source,path', [
    ("const m = await /'/.exec(s); eval(x); // '", 'fixture.mjs'),
    ("function* g() { yield /'/; eval(x); } // '", 'fixture.js'),
    ("const o = { *g() { yield /'/; eval(x); } }; // '", 'fixture.js'),
    ("class A { *g() { if (x) { yield /'/; eval(x); } } } // '", 'fixture.js'),
    ("function* C() { yield <div>'</div>; eval(x); } // '", 'fixture.jsx'),
])
def test_ac35_provable_keyword_contexts_keep_regex_and_jsx_operands(source, path):
    assert 'eval' in [node.target for node in parse(source, path).call_sites]


@pytest.mark.parametrize('source,path,reason', [
    ('const f = () => {} < x', 'fixture.jsx', 'arrow_body_operator'),
    ('var await = 1; x = await / 2; eval(y); z = 1 / 3', 'fixture.cjs', 'contextual_await'),
    ('var yield = 1; x = yield / 2; eval(y); z = 1 / 3', 'fixture.js', 'contextual_yield'),
    ('var let = 1; x = let / 2; eval(y); z = 1 / 3', 'fixture.js', 'contextual_let'),
    ('var yield = 1; x = yield <b; eval(y); z = c >d; w = e </b>/;', 'fixture.jsx', 'contextual_yield'),
    ('function* g() { const f = () => yield / 2; eval(y); z = 1 / 3 }', 'fixture.js', 'contextual_yield'),
    ('function* o() { function i(a = yield / 2, b = eval(y), c = 1 / 3) {} }', 'fixture.js', 'contextual_yield'),
    ("const a = < div>'</div>; eval(x); // '", 'fixture.jsx', 'jsx_angle'),
    ("const a = <T extends object>(x) => '</T>/g; eval(y); // ';", 'fixture.tsx', 'tsx_generic_or_jsx'),
    ('const a = <T extends object>(x)</T>; eval(y); z = 1 / 2;', 'fixture.tsx', 'tsx_generic_or_jsx'),
    ('var x = 1\n--> `\neval(y)\n--> `', 'fixture.js', 'html_comment'),
    ('var x = 1; <!-- `\neval(y)\n<!-- `', 'fixture.js', 'html_comment'),
])
def test_ac35_ambiguous_lexical_contexts_fail_closed(source, path, reason):
    from aegis_core.ast.drivers.js.tokenizer import JSLexError

    with pytest.raises(JSLexError) as error:
        parse(source, path)
    assert error.value.reason == 'unsupported_lexical_context:' + reason


@pytest.mark.parametrize('source,path', [
    ('export const enum E { A }\neval(x);', 'fixture.ts'),
    ('const enum E { A = 1 }\neval(x);', 'fixture.ts'),
    ('declare const enum E { A }\neval(x);', 'fixture.ts'),
    ('import foo = Bar.Baz;\neval(x);', 'fixture.ts'),
    ('import foo = Bar.Baz\nfunction f() { eval(x); }', 'fixture.ts'),
    ('export import foo = Bar;\neval(x);', 'fixture.ts'),
    ('const f = <T extends object>(x: T) => eval(x);', 'fixture.tsx'),
    ('const h = <const T extends readonly unknown[]>(x: T) => eval(x);', 'fixture.tsx'),
    ('const el = <Foo<string> prop={eval(x)} />;', 'fixture.tsx'),
    ('const el = <Foo<Map<string, number[]>> prop={eval(x)} />;', 'fixture.tsx'),
])
def test_valid_typescript_forms_parse_without_inventing_imports(source, path):
    tree = parse(source, path)
    assert [node.target for node in tree.call_sites] == ['eval']
    assert tree.imports == ()
