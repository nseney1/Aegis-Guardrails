"""Callable rewrites must not erase source-derived refusal coverage."""
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import os
import re
import subprocess
import sys
from threading import Barrier

import pytest

from tests import helpers_refusal_inventory
from tests.helpers_refusal_inventory import reachable_refusal_pairs as _reachable_refusal_pairs


REPO = Path(__file__).resolve().parents[2]


def test_real_tree_inventory_matches_the_pre_change_golden():
    """Pin admitted pairs and history without Git history or a host file."""
    # The same admitted payload, embedded so history-less snapshots need no
    # external artifact. Its hash below prevents changing the admitted bytes.
    admitted = {'pairs': {'mailbox_publish_record': [['E_AUTH', ''], ['E_AUTH', 'attribution'], ['E_AUTH', 'binding'], ['E_AUTH', 'cited_reference'], ['E_AUTH', 'identity'], ['E_AUTH', 'lock'], ['E_AUTH', 'mailbox_lock'], ['E_AUTH', 'message_id'], ['E_AUTH', 'operation'], ['E_AUTH', 'private'], ['E_AUTH', 'reference'], ['E_AUTH', 'scope'], ['E_FORMAT', ''], ['E_FORMAT', 'number'], ['E_HASH', ''], ['E_LIMIT', ''], ['E_LIMIT', 'digest_floor'], ['E_LIMIT', 'digest_inbox'], ['E_LIMIT', 'digest_page'], ['E_LIMIT', 'digest_view'], ['E_LIMIT', 'grants'], ['E_LIMIT', 'history'], ['E_LIMIT', 'record'], ['E_REF', ''], ['E_REF', 'resolution'], ['E_SELECTOR', ''], ['E_SELECTOR', 'option']], 'mailbox_read_record': [['E_AUTH', ''], ['E_AUTH', 'attribution'], ['E_AUTH', 'binding'], ['E_AUTH', 'cited_reference'], ['E_AUTH', 'identity'], ['E_AUTH', 'mailbox_lock'], ['E_AUTH', 'operation'], ['E_AUTH', 'private'], ['E_AUTH', 'reference'], ['E_AUTH', 'scope'], ['E_FORMAT', ''], ['E_HASH', ''], ['E_LIMIT', ''], ['E_LIMIT', 'digest_floor'], ['E_LIMIT', 'digest_inbox'], ['E_LIMIT', 'digest_page'], ['E_LIMIT', 'digest_view'], ['E_LIMIT', 'history'], ['E_LIMIT', 'record'], ['E_REF', ''], ['E_REF', 'resolution'], ['E_SELECTOR', ''], ['E_SELECTOR', 'option']], 'mailbox_digest': [['E_AUTH', ''], ['E_AUTH', 'attribution'], ['E_AUTH', 'binding'], ['E_AUTH', 'cited_reference'], ['E_AUTH', 'identity'], ['E_AUTH', 'mailbox_lock'], ['E_AUTH', 'operation'], ['E_AUTH', 'private'], ['E_AUTH', 'reference'], ['E_AUTH', 'scope'], ['E_FORMAT', ''], ['E_HASH', ''], ['E_LIMIT', ''], ['E_LIMIT', 'digest_floor'], ['E_LIMIT', 'digest_inbox'], ['E_LIMIT', 'digest_limit'], ['E_LIMIT', 'digest_max_chars'], ['E_LIMIT', 'digest_page'], ['E_LIMIT', 'digest_view'], ['E_LIMIT', 'digest_view_minimum'], ['E_LIMIT', 'history'], ['E_LIMIT', 'record'], ['E_REF', ''], ['E_REF', 'resolution'], ['E_SELECTOR', ''], ['E_SELECTOR', 'option']]}, 'history': {'mailbox_publish_record': ['binding history exceeds record limit', 'mailbox exceeds record limit', 'mailbox history limit reached'], 'mailbox_read_record': ['binding history exceeds record limit', 'mailbox exceeds record limit'], 'mailbox_digest': ['binding history exceeds record limit', 'mailbox exceeds record limit']}}
    admitted_digest = hashlib.sha256(json.dumps(admitted, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert admitted_digest == "405adca8d9bc0a5d3c9dac324b851d9fc534c5e9bc8548ece2aa59095c321d87"
    pairs, history = _reachable_refusal_pairs()
    for tool, rows in admitted["pairs"].items():
        assert helpers_refusal_inventory.RefusalRows(pairs[tool]) >= {tuple(row) for row in rows}
        assert helpers_refusal_inventory.HistoryRows(history[tool]) >= set(admitted["history"][tool])
    payload = {"pairs": {tool: [list(row) for row in sorted(rows)] for tool, rows in pairs.items()},
               "history": {tool: sorted(rows) for tool, rows in history.items()}}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    # ROUND-5f admits the symbolic representation; the embedded historical
    # payload above remains covered. Widening contributors are recorded in the
    # integration golden. This digest is an oracle, never an analyzer input.
    assert digest == "fd988e56e554cb3104e7d6f0ecd99a34ebe67864849b1c46ef87ea54fd7d0bca"


def insert(source, name, body):
    nodes = ast.parse(source).body
    for part in name.split("."):
        function = next(node for node in nodes
                        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == part)
        nodes = function.body
    lines = source.splitlines(keepends=True)
    indent = " " * function.body[0].col_offset
    lines.insert(function.body[0].lineno - 1,
                 "".join(indent + line + "\n" for line in body.splitlines()))
    return "".join(lines)


@pytest.fixture
def inventory(closed_inventory):
    """Exercise the public entry with a small valid inventory in both domains.

    Real production sources have separate golden, boundary and planted-refusal
    controls. Alias permutations need the same binding semantics, not repeated
    parsing of unrelated production functions.
    """
    def analyze(body, extra, *, guidance=""):
        sources, codec_sources, _expected = closed_inventory(body, extra, guidance)
        return _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)[0]["mailbox_digest"]
    analyze.layer = closed_inventory.layer
    def escape_lines(body, extra, guidance=""):
        sources, codec_sources, _expected = closed_inventory(body, extra, guidance)
        texts = (sources["records"], sources["guidance"]) if analyze.layer == "adapter" else (
            codec_sources["codec"], codec_sources["views"])
        return {node.lineno for text in texts for node in ast.walk(ast.parse(text)) if hasattr(node, "lineno")}
    analyze.escape_lines = escape_lines
    return analyze


PROBE = 'def inventory_probe(codec=None):\n    raise CodecError("E_AUTH", detail="alias_probe")\n'


ROUND5M_OWNERS = ('class Root:\n    @classmethod\n    def alias(receiver):\n'
                  '        raise CodecError("E_AUTH", detail="alias_probe")\n'
                  'class Other(Root):\n    @classmethod\n    def alias(receiver):\n        pass\n'
                  'class Harmless:\n    @classmethod\n    def alias(receiver):\n        pass\n'
                  'class C(Other):\n    @classmethod\n    def run(receiver):\n        super().alias()\n')


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5n_nested_body_does_not_supply_an_enclosing_nonlocal_binding(closed_inventory):
    extra = (ROUND5M_OWNERS + 'def outer():\n    def erase():\n'
             '        def nested():\n            nonlocal Harmless\n            del Harmless.alias\n')
    sources, codec_sources, _expected = closed_inventory('C.run()', extra)
    line = next(node.lineno for node in ast.walk(ast.parse(sources['records'])) if isinstance(node, ast.Nonlocal))
    with pytest.raises(helpers_refusal_inventory.RefusalInventoryError) as failure:
        _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert failure.value.sites == ('unsupported form Nonlocal at inventory.py:' + str(line),)


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("header", [
    'def factory(arg=(Harmless := Safe)):\n    pass',
    'def factory(*, arg=(Harmless := Safe)):\n    pass',
    'def factory(arg: (Harmless := Safe)):\n    pass',
    'def factory() -> (Harmless := Safe):\n    pass',
    '@(Harmless := (lambda target: target))\ndef factory():\n    pass',
    'class Child((Harmless := Safe)):\n    pass',
    'factory = lambda arg=(Harmless := Safe): None',
], ids=['positional_default', 'keyword_default', 'parameter_annotation', 'return_annotation',
        'decorator', 'class_base', 'lambda_default'])
@pytest.mark.parametrize("nested_first", [False, True], ids=['header_first', 'nested_first'])
def test_round5n_header_binding_registers_in_its_evaluation_scope(inventory, header, nested_first):
    nested = 'def nested():\n    nonlocal Harmless\n    del Harmless.alias\n'
    body = nested + header + '\n' if nested_first else header + '\n' + nested
    extra = (ROUND5M_OWNERS + 'class Safe:\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'def outer():\n' + ''.join('    ' + line + '\n' for line in body.splitlines()))
    # Header expressions execute in the enclosing scope. No ordinary Name
    # store supplies this binding; a nested declaration must still find it.
    rows = inventory('C.run()', extra)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("binding", [
    pytest.param('match value:\n    case Harmless:\n        pass', id='match_capture',
                 marks=pytest.mark.skipif(not hasattr(ast, "Match"), reason="requires Python's match AST")),
    pytest.param('try:\n    pass\nexcept BaseException as Harmless:\n    pass', id='except_as'),
    pytest.param('del Harmless', id='bare_del'),
    pytest.param('match value:\n    case [*Harmless]:\n        pass', id='match_star',
                 marks=pytest.mark.skipif(not hasattr(ast, "Match"), reason="requires Python's match AST")),
    pytest.param('match value:\n    case {**Harmless}:\n        pass', id='mapping_rest',
                 marks=pytest.mark.skipif(not hasattr(ast, "Match"), reason="requires Python's match AST")),
])
@pytest.mark.parametrize("outer_store", [True, False], ids=['outer_store', 'no_outer_store'])
@pytest.mark.parametrize("nested_first", [False, True], ids=['binding_first', 'nested_first'])
def test_round5n_nonlocal_stops_at_nearest_binding_scope(inventory, binding, outer_store, nested_first):
    nested = 'def nested():\n    nonlocal Harmless\n    del Harmless.alias\n'
    erase = nested + binding + '\n' if nested_first else binding + '\n' + nested
    extra = (ROUND5M_OWNERS + 'class Safe:\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'def outer():\n' + ('    Harmless = Safe\n' if outer_store else '') +
             '    def erase(value):\n' + ''.join('        ' + line + '\n' for line in erase.splitlines()))
    # The census includes all writes. Do not invoke the closure and let a
    # callback/Match escape supply UNKNOWN independently of its owner proof.
    rows = inventory('C.run()', extra)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5n_free_variable_still_uses_a_proven_nearest_binding(inventory):
    extra = (ROUND5M_OWNERS + 'class Safe:\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'def outer():\n    Harmless = Safe\n    def erase():\n'
             '        def nested():\n            del Harmless.alias\n')
    assert set(inventory('C.run()', extra)) == set()


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("deletion", ['del Harmless.alias', 'delattr(Harmless, "alias")'], ids=['del', 'delattr'])
def test_round5n_free_variable_uses_the_unproven_nearest_binding(inventory, deletion):
    extra = (ROUND5M_OWNERS + 'class Safe:\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'def outer():\n    Harmless = Safe\n    def erase():\n        del Harmless\n'
             '        def nested():\n            ' + deletion + '\n')
    rows = inventory('C.run()', extra)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.skipif(not hasattr(ast, "Match"), reason="requires Python's match AST")
@pytest.mark.parametrize("pattern", ['Harmless', 'object() as Harmless'], ids=['capture', 'class_pattern'])
@pytest.mark.parametrize("deletion", ['del Harmless.alias', 'delattr(Harmless, "alias")'], ids=['del', 'delattr'])
def test_round5m_pattern_owner_never_falls_through_to_outer_class(inventory, pattern, deletion):
    extra = (ROUND5M_OWNERS + 'def erase(value):\n    match value:\n        case ' + pattern + ':\n'
             '            pass\n    ' + deletion + '\n')
    # Census all analyzed writes without a callback or Match escape supplying
    # coverage independently. The member lookup must lose its shadowing proof.
    rows = inventory('C.run()', extra)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("binding", [
    '[delattr(Harmless, "alias") for Harmless in (value,)]',
    '(Harmless := value)\ndel Harmless.alias',
    'try:\n    raise value\nexcept BaseException as Harmless:\n    del Harmless.alias',
    'with value as Harmless:\n    del Harmless.alias',
    'for Harmless in (value,):\n    del Harmless.alias',
    'del Harmless\ndel Harmless.alias',
    'Harmless: object\ndel Harmless.alias',
], ids=['comprehension', 'walrus', 'except_as', 'with_as', 'for_target', 'deleted_local', 'annotation_only'])
def test_round5m_unproven_local_owner_never_falls_through(inventory, binding):
    extra = ROUND5M_OWNERS + 'def erase(value):\n' + ''.join(
        '    ' + line + '\n' for line in binding.splitlines())
    rows = inventory('C.run()', extra)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5m_unshadowed_outer_owner_remains_precise(inventory):
    extra = ROUND5M_OWNERS + 'def erase():\n    del Harmless.alias\n'
    assert set(inventory('C.run()', extra)) == set()


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("mutation", [
    'setattr(*(guidance, "detail"), "alias_probe")',
    'layout = (guidance, "detail")\nsetattr(*layout, "alias_probe")',
    'install = setattr\ninstall(*(guidance, "detail"), "alias_probe")',
    'setattr(*(guidance,), "detail", "alias_probe")',
    'setattr(guidance, *("detail",), "alias_probe")',
], ids=['literal_prefix', 'opaque_layout', 'alias', 'single_prefix', 'spread_name'])
def test_round5m_unpacked_mutator_name_never_uses_a_raw_argument_index(closed_inventory, mutation):
    sources, codec_sources, _expected = closed_inventory(
        'raise CodecError("E_AUTH", detail=guidance.detail)',
        'import hierarchy_mailbox_records_guidance as guidance\n' + mutation + '\n',
        'detail = "decoy"\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs['mailbox_digest']


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("parameter", ["access", "_access", "mailbox", "connection", "store", "codec", "target"])
@pytest.mark.parametrize("use_default", [False, True], ids=["argument", "default"])
def test_round5l_parameter_mutations_cannot_guess_module_owners(closed_inventory, parameter, use_default):
    default = '=guidance' if use_default else ''
    argument = '' if use_default else 'guidance'
    extra = ('import hierarchy_mailbox_records_guidance as guidance\n'
             'def install(' + parameter + default + '):\n'
             '    ' + parameter + '.exported = guidance.inventory_probe\n'
             'install(' + argument + ')\n'
             'from hierarchy_mailbox_records_guidance import exported\n')
    sources, codec_sources, _expected = closed_inventory('exported()', extra,
        'def exported():\n    pass\n' + PROBE)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"])
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("mutation", ['del access.alias', 'delattr(access, "alias")',
                                      'remove = delattr\n    remove(access, "alias")'])
def test_round5l_parameter_deletion_cannot_keep_super_shadowing(inventory, mutation):
    extra = ('class Root:\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class B(Root):\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'class C(B):\n    @classmethod\n    def run(receiver):\n        super().alias()\n'
             'def erase(access=B):\n    ' + mutation + '\nerase()\n')
    rows = inventory('C.run()', extra)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("mutation", ['access.__bool__ = inventory_probe',
                                      'setattr(access, "__bool__", inventory_probe)'])
def test_round5l_parameter_stored_hook_cannot_guess_instance_storage(closed_inventory, mutation):
    extra = ('def inventory_probe(receiver):\n    raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class _RecordAccess:\n    pass\n'
             'def install(access=_RecordAccess):\n    ' + mutation + '\ninstall()\n')
    sources, codec_sources, _expected = closed_inventory('if access:\n    pass', extra)
    sources['records'] = sources['records'].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs['mailbox_digest']


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("mutation,read", [
    ('*guidance.exported, = [guidance.inventory_probe]', 'exported[0]()'),
    ('(*guidance.exported,), = ([guidance.inventory_probe],)', 'exported[0]()'),
    ('for *guidance.exported, in ([guidance.inventory_probe],):\n    pass', 'exported[0]()'),
    ('ignored = [None for *guidance.exported, in ([guidance.inventory_probe],)]', 'exported[0]()'),
    ('ignored = [None for guidance.exported in [guidance.inventory_probe]]', 'exported()'),
    ('def unused():\n    ignored = [None for *guidance.exported, in ([guidance.inventory_probe],)]', 'exported[0]()'),
    ('def unused():\n    ignored = [None for guidance.exported in [guidance.inventory_probe]]', 'exported()'),
    ('*guidance.exported[0], = [guidance.inventory_probe]', 'exported[0][0]()'),
    ('for *guidance.exported[0], in ([guidance.inventory_probe],):\n    pass', 'exported[0][0]()'),
])
def test_round5l_starred_storage_is_in_the_mutation_census(closed_inventory, mutation, read):
    original = '[exported]' if 'exported[0]' in mutation else 'exported'
    guidance = 'def exported():\n    pass\n' + PROBE
    if original != 'exported':
        guidance += 'exported = ' + original + '\n'
    sources, codec_sources, _expected = closed_inventory(read,
        'import hierarchy_mailbox_records_guidance as guidance\n' + mutation + '\n'
        'from hierarchy_mailbox_records_guidance import exported\n', guidance)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs['mailbox_digest'])
    assert ("E_AUTH", "alias_probe") in pairs['mailbox_digest']


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("mutator", ['delattr', 'setattr'])
@pytest.mark.parametrize("through_alias", [False, True], ids=['decorated', 'alias'])
def test_round5l_decorated_mutators_cannot_preserve_original_bindings(inventory, mutator, through_alias):
    extra = ('class Root:\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class B(Root):\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'class C(B):\n    @classmethod\n    def run(receiver):\n        super().alias()\n'
             'def decorate(fn):\n    return ' + mutator + '\n'
             '@decorate\ndef mutate(owner, name, value=None):\n    pass\n')
    callee = 'mutate'
    if through_alias:
        extra += 'alias = mutate\n'
        callee = 'alias'
    arguments = 'B, "alias"' if mutator == 'delattr' else 'B, "alias", Root.alias'
    rows = inventory('C.run()', extra + callee + '(' + arguments + ')\n')
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(rows)
    assert ("E_AUTH", "alias_probe") in rows


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("annotated", [False, True], ids=["assign", "annassign"])
@pytest.mark.parametrize("through_member", [False, True], ids=["direct_import", "member_alias"])
def test_round5k_module_replacement_invalidates_from_import(closed_inventory, annotated, through_member):
    body = 'access.alias()' if through_member else 'exported()'
    sources, codec_sources, _expected = closed_inventory(body, "")
    sources["guidance"] = ('def exported():\n    pass\n' +
        ('class A:\n    detail = "decoy"\n    def emit(receiver):\n'
         '        raise CodecError("E_AUTH", detail=receiver.detail)\n' if through_member else PROBE))
    value = 'guidance.A.emit' if through_member else 'guidance.inventory_probe'
    annotation = ': object' if annotated else ''
    sources["records"] += ('\nimport hierarchy_mailbox_records_guidance as guidance\n'
        'guidance.exported' + annotation + ' = ' + value + '\n'
        'from hierarchy_mailbox_records_guidance import exported\n')
    if through_member:
        sources["records"] = sources["records"].replace('def digest():', 'def digest(access):') + (
            'class _RecordAccess:\n    detail = "alias_probe"\n    def alias(receiver):\n        pass\n'
            '_RecordAccess.alias = exported\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("deletion", ["del", "delattr", "alias", "conditional_del", "conditional_delattr"])
def test_round5k_deletion_invalidates_super_shadowing(inventory, deletion):
    extra = ('class Root:\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class B(Root):\n    @classmethod\n    def alias(receiver):\n        pass\n'
             'class C(B):\n    @classmethod\n    def run(receiver):\n        super().alias()\n')
    suffix = {'del': 'del B.alias\n', 'delattr': 'delattr(B, "alias")\n',
              'alias': 'remove = delattr\nremove(B, "alias")\n',
              'conditional_del': 'if False:\n    del B.alias\n',
              'conditional_delattr': 'if False:\n    delattr(B, "alias")\n'}[deletion]
    assert ("E_AUTH", "alias_probe") in inventory('C.run()', extra + suffix)


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("hook,body", [
    ('__bool__', 'if access:\n    pass'), ('__len__', 'len(access)'),
    ('__getattr__', 'access.absent'), ('__getattribute__', 'access.harmless'),
    ('__iter__', 'for item in access:\n    pass'), ('__enter__', 'with access:\n    pass'),
    ('__exit__', 'with access:\n    pass'), ('__call__', 'access()'),
])
def test_round5k_stored_implicit_hook_consults_mutation_census(closed_inventory, hook, body):
    extra = ('def inventory_probe(receiver, *args):\n    raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class _RecordAccess:\n    harmless = 1\n'
             '_RecordAccess.' + hook + ' = inventory_probe\n')
    sources, codec_sources, _expected = closed_inventory(body, extra)
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("setter", ['setattr', 'install', 'opaque_install'])
def test_round5k_mutator_calls_invalidate_implicit_reads(closed_inventory, setter):
    setup = 'install = setattr\n' if setter == 'install' else 'from opaque import setter as opaque_install\n' if setter == 'opaque_install' else ''
    extra = ('def inventory_probe(receiver):\n    raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class _RecordAccess:\n    pass\n' + setup + setter + '(_RecordAccess, "__bool__", inventory_probe)\n')
    sources, codec_sources, _expected = closed_inventory('if access:\n    pass', extra)
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5k_unbound_local_is_not_proven_by_a_global_binding(inventory):
    extra = PROBE + 'def relay():\n    inventory_probe: object\n    inventory_probe()\n'
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(inventory('relay()', extra))


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5k_single_binding_on_an_unrelated_owner_stays_precise(closed_inventory):
    extra = ('class _RecordAccess:\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class Other:\n    def alias(receiver):\n        pass\n'
             'def harmless(receiver):\n    pass\ndef unused():\n    Other.alias = harmless\n')
    sources, codec_sources, _expected = closed_inventory('_RecordAccess.alias()', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert set(pairs["mailbox_digest"]) == {("E_AUTH", "alias_probe")}


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5k_augmented_attribute_write_invalidates_scalar_precision(inventory):
    extra = ('class Holder:\n    detail = "decoy"\n    @classmethod\n    def emit(receiver):\n'
             '        raise CodecError("E_AUTH", detail=receiver.detail)\nHolder.detail += "_probe"\n')
    assert ("E_AUTH", "decoy_probe") in inventory('Holder.emit()', extra)


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5k_replaced_builtin_has_an_implicit_original_binding(inventory):
    # These are analyzed source bytes; the process builtins are never patched.
    extra = ('import builtins\ndef inventory_probe(receiver):\n'
             '    raise CodecError("E_AUTH", detail="alias_probe")\n'
             'builtins.len = inventory_probe\n')
    assert ("E_AUTH", "alias_probe") in inventory('len(())', extra)


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("inherited", [False, True], ids=["direct", "inherited"])
@pytest.mark.parametrize("form", ["assign", "annassign", "reexport", "classmethod", "annotated_classmethod"])
def test_round5j_projected_class_store_uses_descriptor_binding(closed_inventory, inherited, form):
    sources, codec_sources, _expected = closed_inventory('access.alias()', "")
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    emitter = ('class A:\n    detail = "decoy"\n    def emit(receiver):\n'
               '        raise CodecError("E_AUTH", detail=receiver.detail)\n')
    if form == "reexport":
        sources["guidance"] = emitter + 'exported = A.emit\n'
        emitter = 'from hierarchy_mailbox_records_guidance import exported\n'
        value = 'exported'
    else:
        value = 'classmethod(A.emit)' if 'classmethod' in form else 'A.emit'
    owner = 'Base' if inherited else '_RecordAccess'
    extra = emitter + 'class ' + owner + ':\n    detail = "alias_probe"\n    def alias(receiver):\n        pass\n'
    if inherited:
        extra += 'class _RecordAccess(Base):\n    pass\n'
    annotation = ': object' if form in ('annassign', 'annotated_classmethod') else ''
    sources["records"] += '\n' + extra + owner + '.alias' + annotation + ' = ' + value + '\n'
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    # ROUND-5k: the placeholder plus replacement are two bindings. Keep the
    # concrete transported receiver and add UNKNOWN instead of claiming exact.
    assert {("E_AUTH", "alias_probe"), (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY)} <= set(pairs["mailbox_digest"])


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("form", ["function", "staticmethod"])
def test_round5j_projected_instance_store_does_not_bind(closed_inventory, form):
    value = 'A.emit' if form == 'function' else 'A.exported'
    extra = ('class A:\n    def emit(detail="alias_probe"):\n'
             '        raise CodecError("E_AUTH", detail=detail)\n')
    if form == 'staticmethod':
        extra += '    exported = staticmethod(emit)\n'
    extra += 'class _RecordAccess:\n    def alias(receiver):\n        pass\n'
    sources, codec_sources, _expected = closed_inventory('access.alias = ' + value + '\naccess.alias()', extra)
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    # ROUND-5l: access is a parameter, so its storage owner is unproved. Keep
    # the instance's concrete call environment and require UNKNOWN as well.
    assert set(pairs["mailbox_digest"]) == {
        ("E_AUTH", "alias_probe"), (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY)}


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5j_class_store_in_classmethod_keeps_storage_kind(closed_inventory):
    extra = ('class A:\n    detail = "decoy"\n    def emit(receiver):\n'
             '        raise CodecError("E_AUTH", detail=receiver.detail)\n'
             'class _RecordAccess:\n    detail = "alias_probe"\n'
             '    def alias(receiver):\n        pass\n'
             '    @classmethod\n    def configure(receiver):\n        receiver.alias = A.emit\n')
    sources, codec_sources, _expected = closed_inventory('_RecordAccess.configure()\naccess.alias()', extra)
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert {("E_AUTH", "alias_probe"), (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY)} <= set(pairs["mailbox_digest"])


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5j_cross_module_class_store_reaches_existing_instance(closed_inventory):
    sources, codec_sources, _expected = closed_inventory('install()\naccess.alias()', "")
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):') + (
        'class _RecordAccess:\n    detail = "alias_probe"\n    def alias(receiver):\n        pass\n'
        'from hierarchy_mailbox_records_guidance import install\n')
    sources["guidance"] = ('from hierarchy_mailbox_records import _RecordAccess\n'
                           'class A:\n    detail = "decoy"\n    def emit(receiver):\n'
                           '        raise CodecError("E_AUTH", detail=receiver.detail)\n'
                           'def install():\n    _RecordAccess.alias = A.emit\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert {("E_AUTH", "alias_probe"), (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY)} <= set(pairs["mailbox_digest"])


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5j_unproven_storage_widens_without_losing_candidates(closed_inventory):
    extra = ('class A:\n    detail = "decoy"\n    def emit(receiver):\n'
             '        raise CodecError("E_AUTH", detail=receiver.detail)\n'
             'class _RecordAccess:\n    detail = "alias_probe"\n    def alias(receiver):\n        pass\n')
    body = 'holder = opaque_factory()\nholder.alias = A.emit\naccess.alias()'
    sources, codec_sources, _expected = closed_inventory(body, extra)
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"])


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5j_distinct_attribute_sources_keep_distinct_graph_nodes(closed_inventory):
    extra = ('class A:\n    def first(receiver):\n        raise CodecError("E_AUTH", detail="first_probe")\n'
             '    def second(receiver):\n        raise CodecError("E_AUTH", detail="second_probe")\n'
             'class _RecordAccess:\n    def first(receiver):\n        pass\n'
             '    def second(receiver):\n        pass\n')
    body = '_RecordAccess.first = A.first\n_RecordAccess.second = A.second\naccess.first()\naccess.second()'
    sources, codec_sources, _expected = closed_inventory(body, extra)
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert {("E_AUTH", "first_probe"), ("E_AUTH", "second_probe"),
            (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY)} <= set(pairs["mailbox_digest"])


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
@pytest.mark.parametrize("flow", ["if", "for", "while", "try", "with"])
def test_round5j_conditional_super_member_keeps_later_mro(inventory, flow):
    alias = '    @classmethod\n    def alias(receiver):\n        pass\n'
    wrappers = {'if': '    if False:\n', 'for': '    for item in ():\n', 'while': '    while False:\n',
                'try': '    try:\n        raise LookupError\n', 'with': '    try:\n        with manager():\n'}
    indent = '        ' if flow == 'with' else '    '
    conditional = wrappers[flow] + ''.join(indent + line + '\n' for line in alias.splitlines())
    if flow in ('try', 'with'):
        conditional += '    except Exception:\n        pass\n'
    extra = ('class Root:\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class B(Root):\n' + conditional +
             'class C(B):\n    @classmethod\n    def run(receiver):\n        super().alias()\n')
    assert ("E_AUTH", "alias_probe") in inventory('C.run()', extra)


@pytest.mark.parametrize("form", ["class_body", "nested_class", "inherited_class"])
def test_round5i_class_attribute_keeps_constructor_kind(closed_inventory, form):
    emitter = ('class Emitter:\n    def __init__(receiver, detail):\n'
               '        raise CodecError("E_AUTH", detail=detail)\n')
    if form == "nested_class":
        extra = 'class Holder:\n' + ''.join('    ' + line + '\n' for line in emitter.splitlines())
        body = 'Holder.Emitter("alias_probe")'
    else:
        extra = emitter + ('class Parent:\n    callback = Emitter\nclass Holder(Parent):\n    pass\n'
                           if form == "inherited_class" else 'class Holder:\n    callback = Emitter\n')
        body = 'Holder.callback("alias_probe")'
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("interface", ["mailbox", "access"])
@pytest.mark.parametrize("form", ["direct", "chain", "reexport"])
@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5i_unbound_function_binds_to_destination(closed_inventory, interface, form):
    sources, codec_sources, _expected = closed_inventory(interface + '.alias()', "")
    sources["records"] = sources["records"].replace('def digest():', 'def digest(' + interface + '):')
    source_class = ('class A:\n    detail = "decoy"\n    def emit(receiver):\n'
                    '        raise CodecError("E_AUTH", detail=receiver.detail)\n')
    if form == "reexport":
        sources["guidance"] = source_class + 'exported = A.emit\n'
        setup, alias = 'from hierarchy_mailbox_records_guidance import exported\n', 'exported'
    elif form == "chain":
        setup, alias = source_class + 'first = A.emit\nsecond = first\n', 'second'
    else:
        setup, alias = source_class, 'A.emit'
    name, module = ('Mailbox', 'mailbox') if interface == "mailbox" else ('_RecordAccess', 'records')
    sources[module] += '\n' + setup + 'class ' + name + ':\n    detail = "alias_probe"\n    alias = ' + alias + '\n'
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert set(pairs["mailbox_digest"]) == {("E_AUTH", "alias_probe")}


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5i_super_preserves_already_bound_classmethod(inventory):
    extra = ('class A:\n    detail = "alias_probe"\n    @classmethod\n    def emit(receiver):\n'
             '        raise CodecError("E_AUTH", detail=receiver.detail)\n'
             'class B:\n    detail = "decoy"\n    alias = A.emit\n'
             'class C(B):\n    @classmethod\n    def run(receiver):\n        super().alias()\n')
    assert set(inventory('C.run()', extra)) == {("E_AUTH", "alias_probe")}


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5i_super_uses_c3_after_the_declaring_class(inventory):
    extra = ('class Root:\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="decoy")\n'
             'class Left(Root):\n    @classmethod\n    def run(receiver):\n        super().alias()\n'
             'class Right(Root):\n    @classmethod\n    def alias(receiver):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class Final(Left, Right):\n    pass\n')
    assert set(inventory('Final.run()', extra)) == {("E_AUTH", "alias_probe")}


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5i_staticmethod_read_returns_a_plain_function(closed_inventory):
    sources, codec_sources, _expected = closed_inventory('access.alias()', "")
    sources["records"] = sources["records"].replace('def digest():', 'def digest(access):') + (
        'class A:\n    @staticmethod\n    def emit(receiver):\n'
        '        raise CodecError("E_AUTH", detail=receiver.detail)\n'
        'class _RecordAccess:\n    detail = "alias_probe"\n    alias = A.emit\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert set(pairs["mailbox_digest"]) == {("E_AUTH", "alias_probe")}


def test_round5i_unproven_stored_descriptor_kind_widens(inventory):
    assert ("E_AUTH", "alias_probe") in inventory(
        'Holder.alias()', 'class Holder:\n    alias = opaque_descriptor_factory()\n')


@pytest.mark.parametrize("closed_inventory", ["adapter"], indirect=True)
def test_round5i_plain_function_argument_keeps_its_interface_identity(inventory):
    extra = ('class A:\n    def emit():\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'def relay(access):\n    access()\n')
    assert set(inventory('relay(A.emit)', extra)) == {("E_AUTH", "alias_probe")}


@pytest.mark.parametrize("body,extra", [
    ("inventory_probe()", ""),
    ("probe_alias = inventory_probe\nprobe_alias()", ""),
    ("first = inventory_probe\nsecond = first\nsecond()", ""),
    ("run_probe(inventory_probe)", "def run_probe(callback):\n    callback()\n"),
    ("run_probe(callback=inventory_probe)", "def run_probe(*, callback):\n    callback()\n"),
    ("probe_alias = lambda: inventory_probe()\nprobe_alias()", ""),
    ("probe_alias: object = inventory_probe\nprobe_alias()", ""),
    ("probe_alias = inventory_probe\ndef nested():\n    probe_alias()\nnested()", ""),
], ids=["direct", "local_alias", "alias_chain", "callback", "keyword_callback", "lambda_wrapper",
        "annotated_alias", "closure_alias"])
def test_callable_forms_keep_the_same_refusal(inventory, body, extra):
    assert ("E_AUTH", "alias_probe") in inventory(body, PROBE + extra)


def test_cross_module_import_alias_keeps_the_refusal(inventory):
    module = "hierarchy_mailbox_records_guidance" if inventory.layer == "adapter" else "aegis_core.message_codec_views"
    body = "from " + module + " import inventory_probe as imported_probe\nlocal_probe = imported_probe\nlocal_probe()"
    assert ("E_AUTH", "alias_probe") in inventory(body, "", guidance=PROBE)


@pytest.mark.parametrize("body,extra", [
    ("unknown.inventory_probe()", 'class First:\n    ' + PROBE.replace("\n", "\n    ").rstrip() +
     '\nclass Second:\n    def inventory_probe(self):\n        pass\n'),
    ('getattr(probes, "inventory_probe")()', PROBE),
    ('dispatch = {"probe": inventory_probe}\ndispatch[key]()', PROBE),
    ('probe_alias = inventory_probe if condition else other\nprobe_alias()', PROBE),
    ('probe_alias = factory()\nprobe_alias()', PROBE + 'def factory():\n    return inventory_probe\n'),
    ('run_probe(getattr(probes, "inventory_probe"))', PROBE + 'def run_probe(callback):\n    callback()\n'),
    ('dispatch = {"probe": inventory_probe}\nrun_probe(dispatch[key])',
     PROBE + 'def run_probe(callback):\n    callback()\n'),
    ('dynamic_alias = getattr(probes, "inventory_probe")\nrun_probe(dynamic_alias)',
     PROBE + 'def run_probe(callback):\n    relay = callback\n    relay()\n'),
], ids=["ambiguous_tail", "getattr_dispatch", "dict_dispatch", "conditional_alias", "factory_alias",
        "getattr_callback", "dict_callback", "aliased_dynamic_callback"])
def test_unknown_refusal_calls_keep_every_candidate(inventory, body, extra):
    assert ("E_AUTH", "alias_probe") in inventory(body, extra)


def test_alias_probe_requires_coverage_and_allows_a_corrected_retry(inventory):
    baseline = inventory("pass", "")
    required = inventory("probe_alias = inventory_probe\nprobe_alias()", PROBE)
    with pytest.raises(AssertionError, match="uncovered refusal"):
        assert not required - baseline, "uncovered refusal"
    accepted = baseline | {("E_AUTH", "alias_probe")}
    assert not required - accepted
    assert inventory("probe_alias = inventory_probe\nprobe_alias()", PROBE) == required


def test_helper_rename_preserves_inventory(inventory):
    direct = inventory("inventory_probe()", PROBE)
    renamed = inventory("renamed_probe()", PROBE.replace("inventory_probe", "renamed_probe"))
    assert direct == renamed


def test_refusal_constructor_alias_is_not_erased(inventory):
    probe = ('def inventory_probe(codec=None):\n'
             '    refusal = CodecError\n'
             '    raise refusal("E_AUTH", detail="alias_probe")\n')
    assert ("E_AUTH", "alias_probe") in inventory("inventory_probe()", probe)


def test_aliased_call_binds_the_refusal_detail(inventory):
    probe = ('def inventory_probe(codec, detail):\n'
             '    raise CodecError("E_AUTH", detail=detail)\n')
    assert ("E_AUTH", "alias_probe") in inventory(
        'probe_alias = inventory_probe\nprobe_alias(None, "alias_probe")', probe)


def test_mailbox_boundary_alias_is_not_erased(tmp_path, monkeypatch):
    """Boundary string discovery has its own traversal; exercise that too."""
    files = ["tools/" + name + ".py" for name in
             ("hierarchy_mailbox", "hierarchy_mailbox_mcp", "hierarchy_mailbox_pager", "hierarchy_mailbox_records",
              "hierarchy_mailbox_records_guidance")]
    files += ["aegis_core/message_codec" + suffix + ".py" for suffix in ("", "_format", "_store", "_views")]
    for relative in files:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((REPO / relative).read_text(encoding="utf-8"), encoding="utf-8")
    mailbox = tmp_path / "tools/hierarchy_mailbox.py"
    source = insert(mailbox.read_text(encoding="utf-8"), "Mailbox.messages",
                    "boundary_alias = boundary_probe\nboundary_alias()")
    mailbox.write_text(source + '\ndef boundary_probe():\n    raise ValueError("inventory boundary marker")\n',
                       encoding="utf-8")
    guidance = tmp_path / "tools/hierarchy_mailbox_records_guidance.py"
    with guidance.open("a", encoding="utf-8") as stream:
        stream.write('\nPINNED_REFUSALS = (("inventory boundary marker", "E_AUTH", "alias_probe"),)\n')
    monkeypatch.setattr(helpers_refusal_inventory, "_REPO", tmp_path)
    pairs, _history = _reachable_refusal_pairs()
    assert all(("E_AUTH", "alias_probe") in required for required in pairs.values())


@pytest.mark.parametrize("layer", ["codec", "mailbox"])
def test_adapter_boundary_method_alias_preserves_inventory(layer):
    sources = [(REPO / "tools" / (name + ".py")).read_text(encoding="utf-8")
               for name in ("hierarchy_mailbox_records", "hierarchy_mailbox_records_guidance")]
    codec_sources = None
    if layer == "codec":
        codec_sources = {key: (REPO / "aegis_core" / (name + ".py")).read_text(encoding="utf-8")
                         for key, name in (("codec", "message_codec"), ("format", "message_codec_format"),
                                           ("store", "message_codec_store"), ("views", "message_codec_views"))}
        codec_sources["codec"] = insert(codec_sources["codec"], "read_view",
                                         'raise CodecError("E_AUTH", detail="boundary_probe")')
    baseline = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    if layer == "codec":
        assert ("E_AUTH", "boundary_probe") in baseline[0]["mailbox_digest"]
        sources[0] = insert(sources[0], "_value_view", "codec_alias = codec\nread_alias = codec_alias.read_view")
        assert "codec.read_view(value, store=reader, **options)" in sources[0]
        sources[0] = sources[0].replace("codec.read_view(value, store=reader, **options)",
                                        "read_alias(value, store=reader, **options)")
    else:
        assert "history = mailbox.messages()" in sources[0]
        sources[0] = sources[0].replace("history = mailbox.messages()",
                                        "mailbox_alias = mailbox\n    history_alias = mailbox_alias.messages\n    history = history_alias()")
    assert _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources) == baseline


def test_namespace_alias_roundtrip_resolves_or_refuses_without_recursing(inventory):
    baseline = inventory("pass", "")
    try:
        required = inventory("codec_alias = codec\ncodec = codec_alias\ncodec_alias.read_view(None)", "")
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error))
    else:
        # ROUND-5e keeps a cyclic namespace UNKNOWN rather than dropping its
        # possible refusals. The original baseline remains covered.
        assert required >= baseline
        if required != baseline:
            assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(required)


@pytest.mark.parametrize("body", [
    'reject = lambda detail: CodecError("E_AUTH", detail=detail)\nraise reject("alias_probe")',
    'reject = lambda code: CodecError(code, detail="alias_probe")\nraise reject("E_AUTH")',
], ids=["detail_parameter", "code_parameter"])
def test_lambda_refusal_values_are_found_or_explicitly_refused(inventory, body):
    try:
        required = inventory(body, "")
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error))
    else:
        assert ("E_AUTH", "alias_probe") in required


def test_class_method_alias_keeps_the_refusal(inventory):
    probe = ('class InventoryProbe:\n'
             '    def refusal(self):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             '    alias = refusal\n')
    assert ("E_AUTH", "alias_probe") in inventory("InventoryProbe().alias()", probe)


def test_unpacking_alias_preserves_the_refusal(inventory):
    assert ("E_AUTH", "alias_probe") in inventory("probe_alias, = (inventory_probe,)\nprobe_alias()", PROBE)


def test_ambiguous_tail_sees_refusals_through_a_class_alias(inventory):
    probe = ('class First:\n'
             '    def refusal(self):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             '    alias = refusal\n'
             '    def inventory_probe(self):\n'
             '        self.alias()\n'
             'class Second:\n'
             '    def inventory_probe(self):\n'
             '        pass\n')
    assert ("E_AUTH", "alias_probe") in inventory("unknown.inventory_probe()", probe)


def test_concurrent_analyses_do_not_share_callable_bindings(inventory):
    def analyze(detail):
        return inventory("probe_alias = inventory_probe\nprobe_alias()",
                         PROBE.replace("alias_probe", detail))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(analyze, detail) for detail in ("first_probe", "second_probe")]
        results = [future.result(timeout=30) for future in futures]
    assert ("E_AUTH", "first_probe") in results[0]
    assert ("E_AUTH", "second_probe") not in results[0]
    assert ("E_AUTH", "second_probe") in results[1]
    assert ("E_AUTH", "first_probe") not in results[1]


_ESCAPE_CASES = [
    ("bool_alias", "alias = inventory_probe or other\nalias()", PROBE, ""),
    ("imported_reexport", "from MODULE import exported as alias\nalias()", "",
     PROBE + "exported = inventory_probe\n"),
    ("import_then_reassign", "from MODULE import harmless as alias\nalias = inventory_probe\nalias()",
     PROBE, "def harmless():\n    pass\n"),
    ("constructor_alias_ambiguity", "unknown.inventory_probe()",
     'class First:\n    def inventory_probe(self):\n        reject = CodecError\n'
     '        raise reject("E_AUTH", detail="alias_probe")\n'
     'class Second:\n    def inventory_probe(self):\n        pass\n', ""),
    ("positional_default", "run_probe()", PROBE +
     "def run_probe(callback=inventory_probe):\n    callback()\n", ""),
    ("keyword_only_default", "run_probe()", PROBE +
     "def run_probe(*, callback=inventory_probe):\n    callback()\n", ""),
    ("annotated_class_alias", "InventoryProbe().alias()",
     'class InventoryProbe:\n    def refusal(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     '    alias: object = refusal\n', ""),
    ("callback_argument_detail", "run_probe(inventory_probe)",
     'def inventory_probe(detail):\n    raise CodecError("E_AUTH", detail=detail)\n'
     'def run_probe(callback):\n    callback("alias_probe")\n', ""),
    ("alias_chain_reassignment", "first = inventory_probe\nsecond = first\nfirst = other\nsecond()",
     PROBE + "def other():\n    pass\n", ""),
    ("for_binding", "for callback in (inventory_probe,):\n    callback()", PROBE, ""),
    ("walrus_binding", "(alias := inventory_probe)\nalias()", PROBE, ""),
    ("module_lambda", "alias()", PROBE + "alias = lambda: inventory_probe()\n", ""),
    ("module_attribute_alias", "import MODULE as exported_module\nexported_module.exported()", "",
     PROBE + "exported = inventory_probe\n"),
    ("qualified_module_import", "import MODULE\nMODULE.inventory_probe()",
     "def inventory_probe():\n    pass\n", PROBE),
    ("class_constructor_alias", "alias = InventoryProbe\nalias()",
     'class InventoryProbe:\n    def __init__(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n', ""),
]


@pytest.mark.parametrize("case,body,extra,guidance", _ESCAPE_CASES,
                         ids=[case[0] for case in _ESCAPE_CASES])
def test_formal_0314_escapes_are_complete_or_refused(inventory, case, body, extra, guidance):
    module = ("hierarchy_mailbox_records_guidance" if inventory.layer == "adapter"
              else "aegis_core.message_codec_views")
    try:
        required = inventory(body.replace("MODULE", module), extra, guidance=guidance)
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error)), case
        assert int(str(error).rsplit(":", 1)[1]) in inventory.escape_lines(body, extra, guidance), case
    else:
        # ROUND-5g requires unknown callback arguments to stay UNKNOWN. A
        # covering superset is complete even when its stored rows are symbolic.
        assert required >= inventory("inventory_probe()", PROBE), case


def test_formal_0314_cross_inventory_import_keeps_qualified_identity():
    sources = [(REPO / "tools" / (name + ".py")).read_text(encoding="utf-8")
               for name in ("hierarchy_mailbox_records", "hierarchy_mailbox_records_guidance")]
    codec_sources = {key: (REPO / "aegis_core" / (name + ".py")).read_text(encoding="utf-8")
                     for key, name in (("codec", "message_codec"), ("format", "message_codec_format"),
                                       ("store", "message_codec_store"), ("views", "message_codec_views"))}
    codec_sources["codec"] = insert(codec_sources["codec"], "read_view",
                                     'raise CodecError("E_AUTH", detail="alias_probe")')
    sources[0] = insert(sources[0], "_value_view",
                        "from aegis_core.message_codec import read_view as imported_read")
    sources[0] = sources[0].replace("codec.read_view(value, store=reader, **options)",
                                    "imported_read(value, store=reader, **options)")
    try:
        required, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error))
    else:
        assert ("E_AUTH", "alias_probe") in required["mailbox_digest"]


def test_enumerated_unused_callback_has_zero_invocations(inventory):
    baseline = inventory("pass", "")
    extra = PROBE + "def discard(callback):\n    pass\n"
    assert inventory("discard(inventory_probe)", extra) == baseline


def test_enumerated_constructor_targets_do_not_lose_the_refusal(inventory):
    body = ('reject = CodecError if condition else harmless\n'
            'raise reject("E_AUTH", detail="alias_probe")')
    extra = 'def harmless(*args, **kwargs):\n    pass\n'
    try:
        required = inventory(body, extra)
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error))
    else:
        assert ("E_AUTH", "alias_probe") in required


def test_decoder_hook_marks_an_escaping_wrapper_as_refusing(inventory):
    body = "from opaque_decoder import consume\nconsume(decode_probe)"
    extra = ('import json\n' + PROBE + 'def decode_probe():\n'
             '    json.loads("NaN", parse_constant=inventory_probe)\n')
    assert ("E_AUTH", "alias_probe") in inventory(body, extra)


def test_unknown_receiver_sees_class_alias_targets(inventory):
    extra = ('class InventoryProbe:\n'
             '    def refusal(self):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             '    inventory_alias: object = refusal\n')
    try:
        required = inventory("unknown.inventory_alias()", extra)
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error))
    else:
        assert ("E_AUTH", "alias_probe") in required


def test_unused_lambda_body_has_zero_invocations(inventory):
    assert inventory("probe_alias = lambda: inventory_probe()", PROBE) == inventory("pass", "")


@pytest.mark.parametrize("method", ["__init__", "__new__"])
def test_inherited_constructor_alias_keeps_the_refusal(inventory, method):
    extra = ('class InventoryParent:\n'
             '    def ' + method + '(self):\n'
             '        raise CodecError("E_AUTH", detail="alias_probe")\n'
             'class InventoryChild(InventoryParent):\n'
             '    pass\n')
    try:
        required = inventory("alias = InventoryChild\nalias()", extra)
    except AssertionError as error:
        assert re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", str(error))
    else:
        assert ("E_AUTH", "alias_probe") in required


@pytest.fixture(params=["adapter", "codec"])
def closed_inventory(request):
    """Small valid public inventories isolate the construct gate from the tree census."""
    def analyze(body, extra=PROBE, guidance=""):
        records = ('from aegis_core import message_codec as codec\n'
                   'import hierarchy_mailbox_records as root\n'
                   'def is_absolute():\n    return True\n'
                   'def publish():\n    pass\n'
                   'def read():\n    pass\n'
                   'def digest():\n    codec.read_view(None)\n'
                   'def call():\n    writer_lock()\n'
                   'def _checked():\n    pass\n'
                   'def _store_path():\n    root.is_absolute()\n')
        sources = {name: "" for name in ("records", "guidance", "mailbox", "mcp", "pager")}
        codec_sources = {name: "" for name in ("codec", "format", "store", "views")}
        codec_sources["codec"] = "def read_view(value):\n    pass\n"
        if request.param == "adapter":
            sources["records"] = insert(records, "digest", body) + "\n" + extra
            sources["guidance"] = guidance
            file = "tools/hierarchy_mailbox_records.py"
            other_file = "tools/hierarchy_mailbox_records_guidance.py"
            planted = sources["records"]
        else:
            sources["records"] = records
            codec_sources["codec"] = insert("def read_view(value):\n    pass\n", "read_view", body) + "\n" + extra
            codec_sources["views"] = guidance
            file = "aegis_core/message_codec.py"
            other_file = "aegis_core/message_codec_views.py"
            planted = codec_sources["codec"]
        expected = ["unsupported form " + construct + " at " + path + ":" + str(index)
                    for path, text in ((file, planted), (other_file, guidance))
                    for index, line in enumerate(text.splitlines(), 1)
                    for construct in re.findall(r"# escape: ([A-Za-z]+)", line)]
        return sources, codec_sources, expected
    analyze.layer = request.param
    return analyze


_CLOSED_CASES = [
    ("conditional_module", "alias()", PROBE +
     "alias = inventory_probe  # escape: Assign\nif False:\n    alias = harmless\ndef harmless():\n    pass\n", ""),
    ("conditional_class", "Holder().alias()", PROBE +
     "class Holder:\n    alias = inventory_probe  # escape: Assign\n    if False:\n        alias = harmless\n", ""),
    ("conditional_with", "alias = inventory_probe  # escape: Assign\nwith manager:\n    if False:\n        alias = harmless\nalias()", PROBE, ""),
    ("conditional_try", "alias = inventory_probe  # escape: Assign\ntry:\n    alias = harmless\nexcept Exception:\n    pass\nalias()", PROBE, ""),
    ("conditional_loop", "alias = inventory_probe  # escape: Assign\nfor item in ():\n    alias = harmless\nalias()", PROBE, ""),
    ("wildcard", "inventory_probe()", "from MODULE import *  # escape: ImportFrom\n", PROBE),
    ("opaque_receiver", "obj = opaque_factory()\nobj.run()  # escape: Call",
     'class First:\n    def run(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Second:\n    def run(self):\n        pass\n', ""),
    ("imported_opaque_receiver", "from opaque import obj\nobj.run()  # escape: Call",
     'class First:\n    def run(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Second:\n    def run(self):\n        pass\n', ""),
    ("opaque_self_member", "from opaque import obj\nobj.run()  # escape: Call", PROBE +
     'class Holder:\n    def __init__(self):\n        self.run = inventory_probe\n', ""),
    ("opaque_module_member", "from opaque import obj\nobj.inventory_probe()  # escape: Call", PROBE, ""),
    ("argon_indexed_receiver", "items = get_items()\nholder = items[0]\nholder.inventory_probe()  # escape: Call",
     'class First:\n    def inventory_probe(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Second:\n    def inventory_probe(self):\n        pass\n', ""),
    ("argon_closure_rebinding", "first = inventory_probe  # escape: Assign\ndef nested():\n    first()\nnested()\nfirst = harmless", PROBE +
     'def harmless():\n    pass\n', ""),
    ("argon_kwarg_relay", "relay(callback=inventory_probe)  # escape: keyword", PROBE +
     'def relay(**kwargs):\n    invoke(**kwargs)\ndef invoke(callback):\n    callback()\n', ""),
    ("global_write", "setup()\nalias()", PROBE +
     "alias = harmless\ndef setup():\n    global alias\n    alias = inventory_probe  # escape: Assign\ndef harmless():\n    pass\n", ""),
    ("nonlocal_write", "outer()", PROBE +
     "def outer():\n    alias = harmless\n    def setup():\n        nonlocal alias\n        alias = inventory_probe  # escape: Assign\n    setup()\n    alias()\ndef harmless():\n    pass\n", ""),
    ("star_forward", "relay(inventory_probe)  # escape: Call", PROBE +
     "def relay(*callbacks):\n    consume(*callbacks)\n", ""),
    ("kwstar_forward", "relay(callback=inventory_probe)  # escape: keyword", PROBE +
     "def relay(**callbacks):\n    consume(**callbacks)\n", ""),
    ("rebound_builtin", "from opaque import consume as callable\ncallable(inventory_probe)  # escape: Call", PROBE, ""),
    ("builtin_dispatch", "isinstance(inventory_probe, Executor)  # escape: Call", PROBE +
     'class Meta(type):\n    def __instancecheck__(cls, callback):\n        callback()\n'
     'class Executor(metaclass=Meta):\n    pass\n', ""),
    ("rich_comparison", "inventory_probe == Executor()  # escape: Compare", PROBE +
     "class Executor:\n    def __eq__(self, callback):\n        callback()\n", ""),
    ("unmodeled_node", "async def wait_probe():\n    await inventory_probe  # escape: Await\nwait_probe()", PROBE, ""),
    ("mixed_consumers", "consumer = discard if flag else functools.reduce\nconsumer(inventory_probe, [1, 2])  # escape: Call", PROBE +
     "import functools\ndef discard(callback, values):\n    pass\n", ""),
    ("escaping_default_wrapper", "consume(relay)  # escape: Call", PROBE +
     "def relay(callback=inventory_probe):\n    callback()\n", ""),
    ("escaping_omitted_alternative", "relay(harmless)\nconsume(relay)  # escape: Call", PROBE +
     "def harmless():\n    pass\ndef relay(callback=inventory_probe):\n    callback()\n", ""),
    ("escaping_holder", "consume(Holder())  # escape: Call", PROBE +
     'class Holder:\n    def __init__(self, callback=inventory_probe):\n        self.callback = callback\n', ""),
    ("escaping_module", "import MODULE as exported\nconsume(exported)  # escape: Call", "", PROBE),
    ("cross_domain_callback", "from MODULE import relay\nrelay('decoy', inventory_probe)  # escape: Call",
     'def inventory_probe(detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n',
     'def relay(ignored, callback):\n    callback("alias_probe")\n'),
    ("inherited_exception", 'alias = Reject\nraise alias("E_AUTH", detail="alias_probe")',
     "class Reject(CodecError):  # escape: ClassDef\n    pass\n", ""),
]


@pytest.mark.parametrize("case,body,extra,guidance", _CLOSED_CASES, ids=[row[0] for row in _CLOSED_CASES])
def test_unknown_formal_0721_candidates_are_complete(closed_inventory, case, body, extra, guidance):
    module = ("hierarchy_mailbox_records_guidance" if closed_inventory.layer == "adapter"
              else "aegis_core.message_codec_views")
    sources, codec_sources, expected = closed_inventory(body, extra.replace("MODULE", module), guidance)
    # The import may be in the callable body, rather than the appended module.
    sources = {name: text.replace("MODULE", module) for name, text in sources.items()}
    codec_sources = {name: text.replace("MODULE", module) for name, text in codec_sources.items()}
    assert expected, case
    if case == "unmodeled_node":
        with pytest.raises(helpers_refusal_inventory.RefusalInventoryError) as failure:
            _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
        assert all(site in failure.value.sites for site in expected)
    else:
        pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
        assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"], case


@pytest.mark.skipif(not hasattr(ast, "Match"), reason="requires Python's match AST")
def test_unmodeled_statement_cannot_capture_a_refusing_callable(closed_inventory):
    sources, codec_sources, expected = closed_inventory(
        "match inventory_probe:  # escape: Match\n    case callback:\n        callback()")
    with pytest.raises(helpers_refusal_inventory.RefusalInventoryError) as failure:
        _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert all(site in failure.value.sites for site in expected)


@pytest.mark.parametrize("expression,construct", [
    ("[inventory_probe for item in (0,)]", "ListComp"),
    ("{inventory_probe for item in (0,)}", "SetComp"),
    ("{item: inventory_probe for item in (0,)}", "DictComp"),
    ("(inventory_probe for item in (0,))", "GeneratorExp"),
])
def test_unknown_comprehension_keeps_its_callable_candidates(closed_inventory, expression, construct):
    sources, codec_sources, expected = closed_inventory("holders = " + expression + "  # escape: " + construct)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_class_member_alias_carries_refusal_capability(closed_inventory):
    sources, codec_sources, expected = closed_inventory(
        "consume(Holder())  # escape: Call", PROBE + "class Holder:\n    callback = inventory_probe\n")
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("nested", [False, True], ids=["module", "nested"])
def test_callback_summary_keeps_every_unknown_argument_branch(closed_inventory, nested):
    module = ("hierarchy_mailbox_records_guidance" if closed_inventory.layer == "adapter"
              else "aegis_core.message_codec_views")
    callback = ('def callback(choice):\n'
                '    if choice:\n        raise CodecError("E_AUTH", detail="callback_true")\n'
                '    raise CodecError("E_LIMIT", detail="callback_false")\n')
    body = "from " + module + " import relay\nrelay(callback)"
    if nested:
        body = callback + body
        callback = ""
    sources, codec_sources, _expected = closed_inventory(
        body, callback, "def relay(callback):\n    callback(False)\n")
    trace = []
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources, callback_trace=trace)
    expected = {("E_AUTH", "callback_true"), ("E_LIMIT", "callback_false")}
    # ROUND-5h keeps the function-local import UNKNOWN; the concrete callback
    # summary still has to retain both branches, independently of that row.
    assert pairs["mailbox_digest"] >= expected
    assert any(entry == "mailbox_digest" and name.endswith(".callback") and
               helpers_refusal_inventory.RefusalRows(map(tuple, emitted)) >= expected
               for entry, name, _file, _line, emitted in trace)


def test_callback_summary_keeps_repeated_helper_argument_values(closed_inventory):
    module = ("hierarchy_mailbox_records_guidance" if closed_inventory.layer == "adapter"
              else "aegis_core.message_codec_views")
    extra = ('def callback():\n    emit("callback_first")\n    emit("callback_second")\n'
             'def emit(reason):\n    raise CodecError("E_AUTH", detail=reason)\n')
    sources, codec_sources, _expected = closed_inventory(
        "from " + module + " import relay\nrelay(callback)", extra,
        "def relay(callback):\n    callback()\n")
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    # Function-local imports are UNKNOWN under the closed binding allowlist.
    assert pairs["mailbox_digest"] >= {("E_AUTH", "callback_first"), ("E_AUTH", "callback_second")}


def test_real_tree_callback_sites_return_pairs_without_refusals():
    pairs, history = _reachable_refusal_pairs()
    assert pairs and history


def test_callback_summary_keeps_the_publish_commit_seam():
    trace = []
    pairs, _history = _reachable_refusal_pairs(callback_trace=trace)
    required = {("E_AUTH", "lock"), ("E_LIMIT", "grants")}
    assert required <= pairs["mailbox_publish_record"]
    assert any(entry == "mailbox_publish_record" and callback.endswith(".commit") and
               required <= helpers_refusal_inventory.RefusalRows(map(tuple, emitted)) for entry, callback, _file, _line, emitted in trace)


@pytest.mark.parametrize("body,extra", [
    ('alias = Reject\nalias("alias_probe")',
     'class Reject:\n    def __init__(receiver, detail="decoy"):\n        raise CodecError("E_AUTH", detail=detail)\n'),
    ('Reject.refusal(None, "alias_probe")',
     'class Reject:\n    def refusal(self, detail=None):\n        raise CodecError("E_AUTH", detail=detail)\n'),
], ids=["arbitrary_receiver_name", "unbound_method"])
def test_receiver_binding_follows_call_semantics(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    # Constructor calls contribute UNKNOWN under ROUND-5h.
    assert pairs["mailbox_digest"] >= {("E_AUTH", "alias_probe")}


@pytest.mark.parametrize("body,extra", [
    ("inventory_probe()", PROBE),
    ("alias = inventory_probe\nalias()", PROBE),
    ("relay(inventory_probe)", PROBE + "def relay(callback):\n    callback()\n"),
    ("relay(callback=inventory_probe)", PROBE + "def relay(*, callback):\n    callback()\n"),
    ("relay()", PROBE + "def relay(callback=inventory_probe):\n    callback()\n"),
    ("inventory_probe is None\ninventory_probe()", PROBE),
    ("callable(inventory_probe)\ninventory_probe()", PROBE),
    ("import builtins as proven\nproven.callable(inventory_probe)\ninventory_probe()", PROBE),
    ("Holder().run()", PROBE +
     "class Holder:\n    def __init__(self):\n        self.callback = inventory_probe\n    def run(self):\n        self.callback()\n"),
], ids=["direct", "alias", "positional", "keyword", "default", "identity", "builtin", "builtin_module", "self_member"])
def test_closed_constructs_preserve_pairs_or_refuse_the_bridge(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    # ROUND-3b models ordinary bridges. Both layers must produce the exact pair.
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    # Constructor calls contribute UNKNOWN under ROUND-5h.
    assert pairs["mailbox_digest"] >= {("E_AUTH", "alias_probe")}


def test_refused_site_census_is_independent_of_hash_seed():
    """The public refusal census must survive unordered binding traversal."""
    script = (
        'import json\n'
        'from tests.helpers_refusal_inventory import reachable_refusal_pairs, RefusalInventoryError\n'
        'try:\n    pairs, history = reachable_refusal_pairs()\n'
        'except RefusalInventoryError as error:\n    print(json.dumps(error.sites))\n'
        'else:\n    print(json.dumps({"pairs": {key: sorted(rows) for key, rows in pairs.items()}, '
        '"history": {key: sorted(rows) for key, rows in history.items()}}, sort_keys=True))\n'
    )
    results = [subprocess.run([sys.executable, "-c", script], cwd=REPO,
                              env=dict(os.environ, PYTHONHASHSEED=seed),
                              # The full protocol closure can contend with two
                              # other CI workers. This bounds a stuck child;
                              # equality of the output is the tested behavior.
                              check=True, capture_output=True, text=True, timeout=300).stdout
               for seed in ("1", "2")]
    assert results[0] == results[1]
    payload = json.loads(results[0])
    if isinstance(payload, dict):
        assert payload["pairs"]
    else:
        assert payload and all(re.fullmatch(r"unsupported form [A-Za-z]+ at [A-Za-z0-9_./-]+:[1-9][0-9]*", site)
                               for site in payload)


def test_argon_nested_mailbox_helper_is_found_or_refused(tmp_path, monkeypatch):
    """Boundary traversal must account for a helper declared inside messages."""
    files = ["tools/" + name + ".py" for name in
             ("hierarchy_mailbox", "hierarchy_mailbox_mcp", "hierarchy_mailbox_pager", "hierarchy_mailbox_records",
              "hierarchy_mailbox_records_guidance")]
    files += ["aegis_core/message_codec" + suffix + ".py" for suffix in ("", "_format", "_store", "_views")]
    for relative in files:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((REPO / relative).read_text(encoding="utf-8"), encoding="utf-8")
    mailbox = tmp_path / "tools/hierarchy_mailbox.py"
    source = insert(mailbox.read_text(encoding="utf-8"), "Mailbox.messages",
                    'def inventory_inner():\n    raise ValueError("inventory boundary marker")\ninventory_inner()')
    mailbox.write_text(source, encoding="utf-8")
    nested = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "inventory_inner")
    guidance = tmp_path / "tools/hierarchy_mailbox_records_guidance.py"
    with guidance.open("a", encoding="utf-8") as stream:
        stream.write('\nPINNED_REFUSALS = (("inventory boundary marker", "E_AUTH", "alias_probe"),)\n')
    monkeypatch.setattr(helpers_refusal_inventory, "_REPO", tmp_path)
    try:
        pairs, _history = _reachable_refusal_pairs()
    except helpers_refusal_inventory.RefusalInventoryError as refusal:
        assert ("unsupported form FunctionDef at tools/hierarchy_mailbox.py:" + str(nested.lineno)) in refusal.sites
    else:
        assert all(("E_AUTH", "alias_probe") in required for required in pairs.values())


_ROUND4_CASES = [
    ("data_receiver", "import copy\nobj = copy.copy(First())\nobj.inventory_probe()",
     'class First:\n    def inventory_probe(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Second:\n    def inventory_probe(self):\n        pass\n', ""),
    ("registered_callback_wrapper", "consume(spawn)",
     'import threading\n' + PROBE + 'def spawn():\n    threading.Thread(target=inventory_probe).start()\n', ""),
    ("default_thread", "relay(harmless)\nimport threading\nthreading.Thread(target=relay).run()",
     PROBE + 'def harmless():\n    pass\ndef relay(callback=inventory_probe):\n    callback()\n', ""),
    ("default_exitstack", "relay(harmless)\nfrom contextlib import ExitStack\nwith ExitStack() as stack:\n    stack.callback(relay)",
     PROBE + 'def harmless():\n    pass\ndef relay(callback=inventory_probe):\n    callback()\n', ""),
    ("thread_primitive", 'import threading\nthreading.Thread(target=require, args=(False, "E_AUTH"), '
     'kwargs={"detail": "alias_probe"}).start()', "", ""),
    ("partial_primitive", 'from functools import partial\ncallback = partial(require, False, "E_AUTH", '
     'detail="alias_probe")\ncallback()', "", ""),
    ("registered_primitive", 'from contextlib import ExitStack\nwith ExitStack() as stack:\n'
     '    stack.callback(require, False, "E_AUTH", detail="alias_probe")', "", ""),
    ("staticmethod", 'Holder().refusal("alias_probe")',
     'class Holder:\n    @staticmethod\n    def refusal(detail="decoy"):\n'
     '        raise CodecError("E_AUTH", detail=detail)\n', ""),
    ("classmethod", 'Holder.refusal("alias_probe")',
     'class Holder:\n    @classmethod\n    def refusal(cls, detail="decoy"):\n'
     '        raise CodecError("E_AUTH", detail=detail)\n', ""),
    ("inherited_instancecheck", 'isinstance(inventory_probe, Child)', PROBE +
     'class Meta(type):\n    def __instancecheck__(cls, callback):\n        callback()\n'
     'class Parent(metaclass=Meta):\n    pass\nclass Child(Parent):\n    pass\n', ""),
    ("inherited_subclasscheck", 'issubclass(InventoryProbe, Child)',
     'class InventoryProbe:\n    def __init__(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Meta(type):\n    def __subclasscheck__(cls, callback):\n        callback()\n'
     'class Parent(metaclass=Meta):\n    pass\nclass Child(Parent):\n    pass\n', ""),
    ("field_carrier_comparison", 'Holder() == Executor()', PROBE +
     'class Holder:\n    def __init__(self):\n        self.callback = inventory_probe\n'
     'class Executor:\n    def __eq__(self, holder):\n        holder.callback()\n', ""),
    ("callable_carrier_comparison", 'Holder() == Executor()', PROBE +
     'class Holder:\n    def __call__(self):\n        inventory_probe()\n'
     'class Executor:\n    def __eq__(self, callback):\n        callback()\n', ""),
    ("class_carrier_comparison", 'Holder == Executor()', PROBE +
     'class Holder:\n    callback = inventory_probe\n'
     'class Executor:\n    def __eq__(self, holder):\n        holder.callback()\n', ""),
    ("module_carrier_comparison", 'import MODULE as holder\nholder == Executor()',
     'class Executor:\n    def __eq__(self, holder):\n        holder.inventory_probe()\n', PROBE),
    ("conditional_module_definition", 'selected()',
     'def selected():\n    raise CodecError("E_AUTH", detail="alias_probe")\n'
     'if False:\n    def selected():\n        pass\n', ""),
    ("conditional_nested_definition", 'def selected():\n    raise CodecError("E_AUTH", detail="alias_probe")\n'
     'if False:\n    def selected():\n        pass\nselected()', "", ""),
    ("conditional_method_definition", 'Holder().selected()',
     'class Holder:\n    def selected(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     '    if False:\n        def selected(self):\n            pass\n', ""),
    ("conditional_class_definition", 'Holder()',
     'class Holder:\n    def __init__(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'if False:\n    class Holder:\n        def __init__(self):\n            pass\n', ""),
]

_ROUND4_CASES.extend([
    ("comprehension_receiver", "obj = [First() for _ in (0,)][0]\nobj.inventory_probe()",
     'class First:\n    def inventory_probe(self):\n        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Second:\n    def inventory_probe(self):\n        pass\n', ""),
    ("loop_carried_binding", "alias = harmless\nfor _ in (0, 1):\n    alias()\n    alias = inventory_probe",
     PROBE + 'def harmless():\n    pass\n', ""),
    ("keyword_builtin_callback", "min([1], key=inventory_probe)",
     'def inventory_probe(item):\n    raise CodecError("E_AUTH", detail="alias_probe")\n', ""),
    ("branch_join", 'from contextlib import ExitStack\nwith ExitStack() as stack:\n    stack.callback(callback, True)',
     'def callback(choice):\n    reason = "decoy"\n    if choice:\n        reason = "alias_probe"\n'
     '    raise CodecError("E_AUTH", detail=reason)\n', ""),
])


_ROUND4_CASES.extend([
    ("instance_function_field", 'Holder().callback("E_AUTH", detail="alias_probe")',
     'def callback(code, *, detail):\n    raise CodecError(code, detail=detail)\n'
     'class Holder:\n    def __init__(self):\n        self.callback = callback\n', ""),
    ("metaclass_callback_arguments", "isinstance(inventory_probe, Child)",
     'def inventory_probe(detail):\n    raise CodecError("E_AUTH", detail=detail)\n'
     'class Meta(type):\n    def __instancecheck__(cls, callback):\n        callback("alias_probe")\n'
     'class Parent(metaclass=Meta):\n    pass\nclass Child(Parent):\n    pass\n', ""),
    ("inherited_metaclass_refusal", "isinstance(0, Child)",
     'class Meta(type):\n    def __instancecheck__(cls, item):\n'
     '        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Parent(metaclass=Meta):\n    pass\nclass Child(Parent):\n    pass\n', ""),
    ("class_function_descriptor", 'Holder().refusal("alias_probe")',
     'def refusal(receiver, detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n'
     'class Holder:\n    refusal = refusal\n', ""),
])


for _declaration in ("global", "nonlocal"):
    for _binding in ("def", "class", "import"):
        _setup = ('def alias():\n    raise CodecError("E_AUTH", detail="alias_probe")' if _binding == "def" else
                  'class alias:\n    def __init__(self):\n        raise CodecError("E_AUTH", detail="alias_probe")'
                  if _binding == "class" else 'from MODULE import inventory_probe as alias')
        _setup = "\n".join("    " + line for line in _setup.splitlines())
        _outer = 'def harmless():\n    pass\n'
        if _declaration == "global":
            _extra = _outer + 'alias = harmless\ndef setup():\n    global alias\n' + _setup + '\n'
            _body = 'setup()\nalias()'
        else:
            _extra = (_outer + 'def outer():\n    alias = harmless\n    def setup():\n        nonlocal alias\n' +
                      "\n".join("    " + line for line in _setup.splitlines()) + '\n    setup()\n    alias()\n')
            _body = 'outer()'
        _ROUND4_CASES.append((_declaration + '_' + _binding, _body, _extra, PROBE if _binding == "import" else ""))

for _primitive, _invoke in (
    ("require", 'reject(False, "E_AUTH", detail="alias_probe")'),
    ("CodecError", 'raise reject("E_AUTH", detail="alias_probe")'),
    ("ValueError", 'raise reject("inventory primitive marker")'),
):
    _ROUND4_CASES.append(("cross_domain_" + _primitive, 'from MODULE import relay\nrelay(' + _primitive + ')', '',
                          'PINNED_REFUSALS = (("inventory primitive marker", "E_AUTH", "alias_probe"),)\n'
                          'def relay(reject):\n    ' + _invoke + '\n'))


@pytest.mark.parametrize("case,body,extra,peer", _ROUND4_CASES, ids=[row[0] for row in _ROUND4_CASES])
def test_round4_resolution_preserves_reported_refusals(closed_inventory, case, body, extra, peer):
    module = ("hierarchy_mailbox_records_guidance" if closed_inventory.layer == "adapter"
              else "aegis_core.message_codec_views")
    sources, codec_sources, _expected = closed_inventory(body, extra, peer)
    header = 'from aegis_core.message_codec_format import CodecError, require\n'
    sources = {name: (header + text.replace("MODULE", module) if text else text) for name, text in sources.items()}
    codec_sources = {name: (header + text.replace("MODULE", module) if text else text)
                     for name, text in codec_sources.items()}
    codec_sources["format"] = ('class CodecError(ValueError):\n'
                               '    def __init__(self, code, *, detail=None):\n        self.code, self.detail = code, detail\n'
                               'def require(condition, code="E_FORMAT", *, detail=None):\n'
                               '    if not condition:\n        raise CodecError(code, detail=detail)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"], case


def test_resolution_status_has_one_issuer():
    """Binding evidence cannot be promoted to a proof by a domain walker."""
    tree = ast.parse(Path(helpers_refusal_inventory.__file__).read_text(encoding="utf-8"))
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    declarations = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "_Resolution"]
    assert len(declarations) == 1
    issuers = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
              and n.func.id in ("_Resolution", "_Invocation")]
    assert issuers
    for node in issuers:
        owner = parents[node]
        while not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = parents[owner]
        assert owner.name == "resolve"
        assert isinstance(parents[owner], ast.ClassDef) and parents[owner].name == "_CallableModel"


def test_scalar_defaults_join_only_calls_that_omit_them(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'emit("alias_probe")\nemit()',
        'def emit(detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert pairs["mailbox_digest"] == {("E_AUTH", "alias_probe"), ("E_AUTH", "decoy")}


def test_defining_modules_keep_distinct_callable_identities(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'inventory_probe()', PROBE, 'def inventory_probe():\n    pass\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_receiver_fields_supply_their_proven_refusal_detail(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'Holder().run()',
        'class Holder:\n    def __init__(receiver):\n        receiver.detail = "alias_probe"\n'
        '    def run(receiver):\n        raise CodecError("E_AUTH", detail=receiver.detail)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("primitive", ["require", "CodecError", "ValueError"])
def test_unmodelled_consumer_includes_the_primitive_summary(closed_inventory, primitive):
    # ROUND-5c B supersedes the old unsupported-consumer refusal. Concrete
    # primitive invocations supply the source-derived summary, not a new golden.
    invocation = ('require(False, "E_AUTH", detail="alias_probe")' if primitive == "require" else
                  'raise CodecError("E_AUTH", detail="alias_probe")' if primitive == "CodecError" else
                  'raise ValueError("inventory primitive marker")')
    sources, codec_sources, _expected = closed_inventory(
        "consume(" + primitive + ")", 'def elsewhere():\n    ' + invocation + '\n'
        'PINNED_REFUSALS = (("inventory primitive marker", "E_AUTH", "alias_probe"),)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'require(condition=False, code="E_AUTH", detail="alias_probe")',
    'raise CodecError(code="E_AUTH", detail="alias_probe")',
], ids=["require", "constructor"])
def test_primitive_keywords_use_the_resolved_argument_environment(closed_inventory, body):
    sources, codec_sources, _expected = closed_inventory(body, "")
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


_ROUND5_CASES = [
    ("conditional_field", "Holder().callback()", PROBE +
     'def harmless():\n    pass\nclass Holder:\n'
     '    def callback(self):\n        inventory_probe()\n'
     '    def __init__(self):\n        if False:\n            self.callback = harmless\n'),
    ("inherited_conditional_field", "Holder().callback()", PROBE +
     'def harmless():\n    pass\nclass Parent:\n    def callback(self):\n        inventory_probe()\n'
     'class Holder(Parent):\n    def __init__(self):\n        if False:\n            self.callback = harmless\n'),
    ("classmethod_assignment", 'Holder.refusal("alias_probe")',
     'class Holder:\n    def refusal(cls, detail="decoy"):\n        raise CodecError("E_AUTH", detail=detail)\n'
     '    refusal = classmethod(refusal)\n'),
    ("staticmethod_assignment", "Holder.alias()", PROBE + 'class Holder:\n    alias = staticmethod(inventory_probe)\n'),
    ("callable_default", "relay(harmless)\nimport atexit\natexit.register(relay)", PROBE +
     'def harmless():\n    pass\nclass Holder:\n    def __call__(self):\n        inventory_probe()\n'
     'def relay(callback=Holder()):\n    callback()\n'),
    ("parameter_rebinding", "relay()", PROBE +
     'def harmless():\n    pass\ndef relay(callback=inventory_probe):\n'
     '    if False:\n        callback = harmless\n    callback()\n'),
    ("parameter_definition", "relay()", PROBE +
     'def relay(callback=inventory_probe):\n    if False:\n        def callback():\n            pass\n    callback()\n'),
    ("parameter_import", "relay()", PROBE +
     'def relay(callback=inventory_probe):\n    if False:\n        from opaque import callback\n    callback()\n'),
    ("opaque_arguments", 'import copy\nobj = copy.copy(First())\nobj.probe("alias_probe")',
     'class First:\n    def probe(self, detail="decoy"):\n        raise CodecError("E_AUTH", detail=detail)\n'
     'class Second:\n    def probe(self, detail="decoy"):\n        pass\n'),
    ("keyword_unpack", 'emit(**{"detail": "alias_probe"})',
     'def emit(detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n'),
    ("registered_star", 'from contextlib import ExitStack\narguments = (False, "E_AUTH")\n'
     'with ExitStack() as stack:\n    stack.callback(require, *arguments, detail="alias_probe")', ""),
    ("registered_partial", 'from functools import partial\narguments = (False, "E_AUTH")\n'
     'partial(require, *arguments, detail="alias_probe")()', ""),
    ("registered_thread", 'import threading\narguments = (False, "E_AUTH")\nkeywords = {"detail": "alias_probe"}\n'
     'threading.Thread(target=require, args=arguments, kwargs=keywords).start()', ""),
    ("method_carrier", "Holder() == Executor()", PROBE +
     'class Holder:\n    def run(self):\n        inventory_probe()\n'
     'class Executor:\n    def __eq__(self, holder):\n        holder.run()\n'),
    ("inherited_carrier", "Holder() == Executor()", PROBE +
     'class Parent:\n    callback = staticmethod(inventory_probe)\nclass Holder(Parent):\n    pass\n'
     'class Executor:\n    def __eq__(self, holder):\n        holder.callback()\n'),
    ("class_method_carrier", "Holder == Executor()", PROBE +
     'class Holder:\n    @staticmethod\n    def run():\n        inventory_probe()\n'
     'class Executor:\n    def __eq__(self, holder):\n        holder.run()\n'),
    ("opaque_metaclass", "import copy\nisinstance(0, Child)",
     'import copy\nclass Meta(type):\n    def __instancecheck__(cls, value):\n'
     '        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Parent(metaclass=copy.copy(Meta)):\n    pass\nclass Child(Parent):\n    pass\n'),
    ("opaque_subclass", "import copy\nissubclass(int, Child)",
     'import copy\nclass Meta(type):\n    def __subclasscheck__(cls, value):\n'
     '        raise CodecError("E_AUTH", detail="alias_probe")\n'
     'class Parent(metaclass=copy.copy(Meta)):\n    pass\nclass Child(Parent):\n    pass\n'),
]

for _flow, _statement in (
    ("for_state", 'for _ in (0,):\n        reason = "alias_probe"'),
    ("while_state", 'while choice:\n        reason = "alias_probe"\n        break'),
    ("handler_state", 'try:\n        operation()\n    except Exception:\n        reason = "alias_probe"'),
    ("async_for_state", 'async for _ in stream:\n        reason = "alias_probe"'),
):
    _ROUND5_CASES.append((_flow, 'from contextlib import ExitStack\nwith ExitStack() as stack:\n    stack.callback(callback, True)',
                          ('async ' if _flow == "async_for_state" else '') +
                          'def callback(choice):\n    reason = "decoy"\n    ' + _statement +
                          '\n    raise CodecError("E_AUTH", detail=reason)\n'))


@pytest.mark.parametrize("case,body,extra", _ROUND5_CASES, ids=[row[0] for row in _ROUND5_CASES])
def test_round5_reported_call_protocols_preserve_refusals(closed_inventory, case, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    header = 'from aegis_core.message_codec_format import CodecError, require\n'
    sources = {name: header + text if text else text for name, text in sources.items()}
    codec_sources = {name: header + text if text else text for name, text in codec_sources.items()}
    codec_sources["format"] = ('class CodecError(ValueError):\n'
                               '    def __init__(self, code, *, detail=None):\n        self.code, self.detail = code, detail\n'
                               'def require(condition, code="E_FORMAT", *, detail=None):\n'
                               '    if not condition:\n        raise CodecError(code, detail=detail)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"], case


@pytest.mark.parametrize("root", ["publish", "read", "digest", "call", "_checked", "_store_path"])
def test_round5_root_bindings_keep_conditional_definitions(closed_inventory, root):
    sources, codec_sources, _expected = closed_inventory("pass", "")
    sources["records"] += ('\nif active:\n    def ' + root + '(*args, **kwargs):\n'
                           '        raise CodecError("E_AUTH", detail="alias_probe")\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    entry = {"publish": "mailbox_publish_record", "read": "mailbox_read_record", "digest": "mailbox_digest"}.get(root)
    assert all(("E_AUTH", "alias_probe") in rows for name, rows in pairs.items() if entry is None or name == entry)


_PROTOCOL_CASES = [
    ("explicit", 'inventory_probe()', PROBE),
    ("decorator", 'wrapped()', PROBE + 'def decorate(callback):\n    return inventory_probe\n'
     '@decorate\ndef wrapped():\n    pass\n'),
    ("descriptor", 'Holder().value', PROBE +
     'class Descriptor:\n    def __get__(self, instance, owner):\n        inventory_probe()\n'
     'class Holder:\n    value = Descriptor()\n'),
    ("operator", 'Holder() + 1', PROBE + 'class Holder:\n    def __add__(self, other):\n        inventory_probe()\n'),
    ("comparison", 'Holder() == 1', PROBE + 'class Holder:\n    def __eq__(self, other):\n        inventory_probe()\n'),
    ("containment", '1 in Holder()', PROBE + 'class Holder:\n    def __contains__(self, other):\n        inventory_probe()\n'),
    ("bool", 'if Holder():\n    pass', PROBE + 'class Holder:\n    def __bool__(self):\n        inventory_probe()\n'),
    ("len", 'len(Holder())', PROBE + 'class Holder:\n    def __len__(self):\n        inventory_probe()\n'),
    ("iteration", 'for _ in Holder():\n    pass', PROBE + 'class Holder:\n    def __iter__(self):\n        inventory_probe()\n'),
    ("context_manager", 'with Holder():\n    pass', PROBE +
     'class Holder:\n    def __enter__(self):\n        inventory_probe()\n    def __exit__(self, *args):\n        pass\n'),
    ("attribute_hook", 'Holder().value', PROBE +
     'class Holder:\n    def __getattr__(self, name):\n        inventory_probe()\n'),
    ("registration", 'import atexit\natexit.register(inventory_probe)', PROBE),
    ("storage_attribute", 'holder = Holder()\nholder.callback = inventory_probe\nholder.callback()',
     PROBE + 'class Holder:\n    pass\n'),
    ("storage_subscript", 'slots = {}\nslots["callback"] = inventory_probe\nslots["callback"]()', PROBE),
    ("storage_slice", 'slots = []\nslots[:] = [inventory_probe]\nslots[0]()', PROBE),
    ("defaults", 'relay()', PROBE + 'class Holder:\n    def __call__(self):\n        inventory_probe()\n'
     'def relay(callback=Holder()):\n    callback()\n'),
]


@pytest.mark.parametrize("protocol,body,extra", _PROTOCOL_CASES, ids=[row[0] for row in _PROTOCOL_CASES])
def test_call_protocol_table_has_a_positive_case(closed_inventory, protocol, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"], protocol


@pytest.mark.parametrize("protocol,body,extra", [
    ("suspension", 'async def invoke():\n    await Holder()\ninvoke()', PROBE +
     'class Holder:\n    def __await__(self):\n        inventory_probe()\n'),
    ("other_protocol", 'Holder()', PROBE + 'class Holder:\n    def __del__(self):\n        inventory_probe()\n'),
    ("other_protocol", 'exec("inventory_probe()")', PROBE),
    ("other_protocol", 'if Child:\n    pass', PROBE +
     'class Meta(type):\n    def __bool__(cls):\n        inventory_probe()\n'
     'class Child(metaclass=Meta):\n    pass\n'),
    ("other_protocol", 'Child.callback()', PROBE +
     'class Meta(type):\n    callback = staticmethod(inventory_probe)\n'
     'class Child(metaclass=Meta):\n    pass\n'),
    ("other_protocol", 'pass', PROBE +
     'def create(name, bases, namespace):\n    inventory_probe()\n'
     'class Child(metaclass=create):\n    pass\n'),
    ("other_protocol", 'type("Child", (), {"__call__": inventory_probe})()()', PROBE),
])
def test_escape_gated_protocol_rows_refuse_loudly(closed_inventory, protocol, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    with pytest.raises(helpers_refusal_inventory.RefusalInventoryError, match="unsupported form"):
        _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)


def test_protocol_table_has_no_uncovered_or_ignored_row():
    table = helpers_refusal_inventory._CallableModel.CALL_PROTOCOLS
    assert set(table) == {row[0] for row in _PROTOCOL_CASES} | {"suspension", "other_protocol"}
    assert all(mode in {"MODELLED", "ESCAPE-GATED"} for mode, _kinds, _hooks in table.values())
    assert all(name in helpers_refusal_inventory.__doc__ for name in table)


@pytest.mark.parametrize("body,extra", [
    ('Holder()', 'class Meta(type):\n    def __call__(cls):\n        inventory_probe()\n'
     'class Holder(metaclass=Meta):\n    pass\n'),
    ('"alias_probe" + Holder()', 'class Holder:\n    def __radd__(self, detail="decoy"):\n'
     '        raise CodecError("E_AUTH", detail=detail)\n'),
    ('Holder().alias_probe', 'class Holder:\n    def __getattr__(self, name):\n'
     '        raise CodecError("E_AUTH", detail=name)\n'),
    ('holder = Holder()\nholder.value = "alias_probe"',
     'class Descriptor:\n    def __set__(self, instance, value):\n        raise CodecError("E_AUTH", detail=value)\n'
     'class Holder:\n    value = Descriptor()\n'),
], ids=["metaclass_call", "reflected_arguments", "attribute_arguments", "descriptor_set_arguments"])
def test_protocol_invocations_transport_their_arguments(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'from contextlib import ExitStack\nwith ExitStack() as stack:\n    stack.callback(require, *unknown_arguments)',
    'import threading\nthreading.Thread(target=require, args=unknown_arguments, kwargs=unknown_keywords)',
    'from functools import partial\npartial(require, *unknown_arguments)',
    'from contextlib import ExitStack\nwith ExitStack() as stack:\n'
    '    stack.callback(require, *unknown_arguments, detail="alias_probe")',
])
def test_unknown_registration_arguments_never_establish_primitive_defaults(closed_inventory, body):
    sources, codec_sources, _expected = closed_inventory(body, "")
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    # ROUND-5e retains the uncertainty as a row, rather than substituting the
    # primitive's E_FORMAT/empty defaults or raising a new refusal.
    assert (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"])
    assert ("E_FORMAT", "") not in set(pairs["mailbox_digest"])


@pytest.mark.parametrize("body,extra", [
    ('relay("decoy")\nconsume(relay)',
     'def relay(detail="alias_probe"):\n    raise CodecError("E_AUTH", detail=detail)\n'),
    ('(alias()\n if (alias := inventory_probe)\n else None)', PROBE),
    ('[alias()\n for _ in (0,)\n if (alias := inventory_probe)]', PROBE),
    ('import copy\ncls = copy.copy(Child)\nisinstance(0, cls)', PROBE +
     'class Meta(type):\n    def __instancecheck__(cls, value):\n        inventory_probe()\n'
     'class Child(metaclass=Meta):\n    pass\n'),
], ids=["scalar_callback_default", "walrus_condition", "walrus_comprehension", "copied_metaclass"])
def test_argon1649_call_protocols_keep_every_refusal(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('@decorate\ndef unused():\n    pass',
     'def decorate(callback):\n    inventory_probe()\n    return callback\n'),
    ('def unused(value=inventory_probe()):\n    pass', ''),
], ids=["decorator_evaluation", "default_evaluation"])
def test_definition_protocols_execute_without_invoking_the_definition(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('Holder().run()',
     'class Result:\n    def run(self):\n        inventory_probe()\n'
     'class Meta(type):\n    def __call__(cls):\n        return Result()\n'
     'class Holder(metaclass=Meta):\n    pass\n'),
    ('for _ in Holder():\n    pass',
     'class Result:\n    def __next__(self):\n        inventory_probe()\n'
     'class Holder:\n    def __iter__(self):\n        return Result()\n'),
    ('Holder().callback()',
     'class Holder:\n    @property\n    def callback(self):\n        return inventory_probe\n'),
    ('Holder()()',
     'class Meta(type):\n    def __call__(cls):\n        return inventory_probe\n'
     'class Holder(metaclass=Meta):\n    pass\n'),
    ('Holder()()', 'class Holder:\n    def __new__(cls):\n        return inventory_probe\n'),
    ('for item in Holder():\n    if item:\n        pass',
     'class Final:\n    def __bool__(self):\n        inventory_probe()\n'
     'class Result:\n    def __next__(self):\n        return Final()\n'
     'class Holder:\n    def __iter__(self):\n        return Result()\n'),
    ('holder = Holder()\nholder.value = 1',
     'class Holder:\n    @property\n    def value(self):\n        return None\n'
     '    @value.setter\n    def value(self, value):\n        inventory_probe()\n'),
    ('Holder().run()',
     'class Result:\n    def run(self):\n        inventory_probe()\n'
     '@external_decorator\nclass Holder:\n    pass\n'),
], ids=["metaclass_result", "iteration_result", "descriptor_result", "metaclass_callable", "constructor_callable", "returned_carrier_chain",
        "class_body_descriptor_callback", "unknown_class_decorator"])
def test_protocol_results_retain_their_callable_candidates(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("branching", [False, True], ids=["nested", "branching"])
def test_recursive_callback_arguments_widen_before_cache_representation(closed_inventory, branching):
    calls = ('    relay((value, 0))\n    relay((value, 1))\n' if branching else '    relay((value,))\n')
    sources, codec_sources, _expected = closed_inventory(
        'from contextlib import ExitStack\nwith ExitStack() as stack:\n    stack.callback(relay, ())',
        PROBE + 'def relay(value):\n' + calls + '    inventory_probe()\n')
    script = ('import json,sys\n'
              'from tests.helpers_refusal_inventory import reachable_refusal_pairs\n'
              'sources,codec=json.load(sys.stdin)\n'
              'pairs,history=reachable_refusal_pairs(sources=sources,codec_sources=codec)\n'
              'print(json.dumps(sorted(pairs["mailbox_digest"])))\n')
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO,
                            input=json.dumps([sources, codec_sources]), check=True,
                            capture_output=True, text=True, timeout=10)
    assert helpers_refusal_inventory.covers_refusal(json.loads(result.stdout), ("E_AUTH", "alias_probe"))


@pytest.mark.parametrize("consumer,method", [
    ('len(holder)', '__len__(self)'),
    ('float(holder)', '__float__(self)'),
    ('hash(holder)', '__hash__(self)'),
    ('abs(holder)', '__abs__(self)'),
    ('format(holder, "alias_probe")', '__format__(self, detail="decoy")'),
], ids=["len", "float", "hash", "abs", "format"])
@pytest.mark.parametrize("producer", ['copy.copy(Holder())', 'opaque_factory()'], ids=["copy", "opaque"])
def test_native_protocols_keep_opaque_receiver_candidates(closed_inventory, consumer, method, producer):
    body = 'import copy\nholder = ' + producer + '\n' + consumer
    detail = 'detail' if consumer.startswith('format') else '"alias_probe"'
    extra = 'class Holder:\n    def ' + method + ':\n        raise CodecError("E_AUTH", detail=' + detail + ')\n'
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('holder = Holder()\nholder.callback = inventory_probe\nholder.callback()', ''),
    ('slots = {}\nslots["callback"] = inventory_probe\nslots["callback"]()', ''),
    ('slots = []\nslots[:] = [inventory_probe]\nslots[0]()', ''),
    ('slots = []\nslots[0:1] = [inventory_probe]\nslots[:][0]()', ''),
    ('slots = {}\nslots[key] = inventory_probe\nalias = slots\nalias[key]()', ''),
    ('slots = []\nalias = slots\nalias[:] = [inventory_probe]\nslots[0]()', ''),
    ('slots = []\nslots[:] = [inventory_probe]\nfor callback in slots:\n    callback()', ''),
    ('slots = []\nslots[:] = [inventory_probe]\ncallback, = slots\ncallback()', ''),
    ('slots = {}\nslots[key] = inventory_probe\nrelay(slots)',
     'def relay(values):\n    values[key]()\n'),
    ('holder = Holder()\nholder.callback = inventory_probe\nalias = holder\nalias.callback()', ''),
    ('Holder().install()\nHolder().run()',
     'class Holder:\n    def install(receiver):\n        receiver.callback = inventory_probe\n'
     '    def run(receiver):\n        receiver.callback()\n'),
    ('holder = Holder()\nholder.board = Holder()\nholder.board.callback = inventory_probe\n'
     'holder.board.callback()', ''),
    ('holder = Holder()\nholder.callback = inventory_probe\nopaque_factory().callback()', ''),
    ('slots = {}\nslots[key] = inventory_probe\nopaque_factory()[key]()', ''),
    ('slots = []\nslots[:] = [inventory_probe]\nfor callback in opaque_factory():\n    callback()', ''),
    ('install()\nconsume()',
     'def install():\n    holder = opaque_factory()\n    holder.callback = inventory_probe\n'
     'def consume():\n    opaque_factory().callback()\n'),
    ('slots = {}\nslots[key] = inventory_probe\nrelay(opaque_factory())',
     'def relay(values):\n    values[key]()\n'),
    ('holder = Holder()\nholder.detail = "alias_probe"\nemit(holder.detail)',
     'def emit(detail):\n    raise CodecError("E_AUTH", detail=detail)\n'),
    ('holder = Holder()\nholder.callback = inventory_probe\nconsume(holder)', ''),
    ('slots = {}\nslots[key] = "alias_probe"\nemit(slots[key])',
     'def emit(detail):\n    raise CodecError("E_AUTH", detail=detail)\n'),
], ids=["attribute", "subscript", "slice", "slice_read", "container_alias", "slice_alias",
        "iteration", "unpack", "parameter", "attribute_alias", "cross_method", "nested_attribute",
        "opaque_attribute", "opaque_container", "opaque_iteration", "module_attribute", "module_container",
        "attribute_argument", "stored_carrier", "slot_argument"])
def test_storage_projection_keeps_every_visible_refusal(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + 'class Holder:\n    pass\n' + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_opaque_metaclass_hooks_keep_the_class_receiver(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'isinstance(0, Child)',
        'import copy\nclass Meta(type):\n    detail = "decoy"\n'
        '    def __instancecheck__(cls, value):\n        raise CodecError("E_AUTH", detail=cls.detail)\n'
        'class Parent(metaclass=copy.copy(Meta)):\n    pass\n'
        'class Child(Parent):\n    detail = "alias_probe"\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_constructor_slot_rebinding_is_escape_gated(closed_inventory):
    sources, codec_sources, expected = closed_inventory(
        'Holder("alias_probe")',
        'def make(receiver, detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n'
        'class Holder:\n    __init__ = make  # escape: Assign\n')
    with pytest.raises(helpers_refusal_inventory.RefusalInventoryError) as failure:
        _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert all(site in failure.value.sites for site in expected)


def test_conditional_data_does_not_return_its_callable_condition(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'selected = None if inventory_probe else None\nconsume(selected)', PROBE)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert pairs["mailbox_digest"] == set()


def test_generated_constructor_projects_stored_primitive(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'Holder(require).callback(False, "E_AUTH", detail="alias_probe")',
        'from dataclasses import dataclass\n@dataclass\nclass Holder:\n    callback: object\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('arguments = [None]\narguments[:] = ["alias_probe"]\nemit(*arguments)', ''),
    ('arguments = []\narguments[:] = factory()\nemit(*arguments)',
     'def factory():\n    return ("alias_probe",)\n'),
    ('arguments = []\nfrom contextlib import ExitStack\nwith ExitStack() as stack:\n'
     '    arguments[:] = stack.enter_context(factory())\n    emit(*arguments)',
     'from contextlib import contextmanager\n@contextmanager\ndef factory():\n    yield ("alias_probe",)\n'),
], ids=["literal", "factory", "context_manager"])
def test_slice_storage_transports_unpacked_arguments(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body,
        'def emit(detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n' + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_unknown_unpacking_keeps_explicit_callback_keywords(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'relay(callback=require, **unknown_options)',
        'def relay(*, callback):\n    callback(False, "E_AUTH", detail="alias_probe")\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('import math\nmath.isfinite(Holder())',
     'class Holder:\n    def __float__(self):\n        inventory_probe()\n'),
    ('import json\njson.loads("{}", object_hook=inventory_probe)', ''),
])
def test_data_consumers_keep_hooks_and_callback_keywords(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_data_consumer_unknown_primitive_callback_includes_its_summary(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'import json\njson.loads("{}", object_hook=require)',
        'def elsewhere():\n    require(False, "E_AUTH", detail="alias_probe")\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'from opaque import factory\nslots = {}\nslots[key] = inventory_probe\nalias = factory()\nalias[key]()',
    'from opaque import alias\nslots = {}\nslots[key] = inventory_probe\nalias[key]()',
    'first = {}\nsecond = {}\nfirst[key] = harmless\nsecond[key] = inventory_probe\n'
    'alias = first if choice else opaque_factory()\nalias[key]()',
], ids=["imported_factory", "imported_alias", "known_and_unknown"])
def test_unknown_storage_aliases_join_the_whole_module(closed_inventory, body):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + 'def harmless():\n    pass\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('slots = [harmless]\nalias = opaque_factory()\nalias[0] = inventory_probe\nslots[0]()', ''),
    ('alias = Holder()\nalias[0] = inventory_probe\nslots[0]()',
     'slots = [harmless]\nclass Holder:\n    def __new__(cls):\n        return slots\n'),
    ('alias = Holder()\nalias[0] = inventory_probe\nslots[0]()',
     'slots = [harmless]\nclass Meta(type):\n    def __call__(cls):\n        return slots\n'
     'class Holder(metaclass=Meta):\n    pass\n'),
], ids=["opaque_write", "constructor_alias", "metaclass_alias"])
def test_unknown_storage_writes_join_known_reads(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + 'def harmless():\n    pass\n' + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_json_callback_return_keeps_the_primitive_call_environment(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'import json\nreturned = json.loads("{}", object_hook=lambda value: require)\n'
        'returned(False, "E_AUTH", detail="alias_probe")', '')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'slots = {"callback": require}\nread = slots.__getitem__  # escape: Attribute\n'
    'read("callback")(False, "E_AUTH", detail="alias_probe")',
    'slots = {}\nwrite = slots.__setitem__\nwrite("callback", require)  # escape: Call\n'
    'slots["callback"](False, "E_AUTH", detail="alias_probe")',
], ids=["native_getter_alias", "native_setter_alias"])
def test_unmodelled_native_storage_methods_cannot_launder_primitives(closed_inventory, body):
    sources, codec_sources, expected = closed_inventory(body, '')
    with pytest.raises(helpers_refusal_inventory.RefusalInventoryError) as failure:
        _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert all(site in failure.value.sites for site in expected)


def test_container_conversion_retains_the_stored_callable(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'slots = [require]\nconverted = list(slots)\nconverted[0](False, "E_AUTH", detail="alias_probe")', '')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'slots = []\nslots.append(inventory_probe)\nslots[0]()',
    'slots = {}\nslots.update(callback=inventory_probe)\nslots.get("callback")()',
    'slots = opaque_factory()\nslots.append(inventory_probe)\nslots.get("callback")()',
    'slots = []\nslots.extend([inventory_probe])\nnext(iter(slots))()',
    'slots = []\nslots.insert(0, inventory_probe)\nslots.pop()()',
    'slots = set()\nslots.add(inventory_probe)\nfor callback in slots.copy():\n    callback()',
    'slots = {}\nslots.setdefault("callback", inventory_probe)\nfor callback in slots.values():\n    callback()',
    'slots = {}\nwrite = slots.update\nwrite(callback=inventory_probe)\nfor callback in slots.items():\n    callback[1]()',
    'slots = dict.fromkeys([inventory_probe])\nfor callback in sorted(set(slots.keys())):\n    callback()',
], ids=["append", "update_get", "unknown_append_get", "extend_iter", "insert_pop", "add_copy",
        "setdefault_values", "update_alias_items", "fromkeys_keys_set_sorted"])
def test_round5c_native_store_read_keeps_the_callback(closed_inventory, body):
    sources, codec_sources, _expected = closed_inventory(body, PROBE)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'opaque_factory().get("callback")  # escape: Call',
    'external(opaque_factory().get)  # escape: Attribute',
], ids=["direct", "passed_method"])
def test_round5c_unknown_native_receiver_with_refusing_tail_still_refuses(closed_inventory, body):
    sources, codec_sources, expected = closed_inventory(
        body,
        'class Refusing:\n    def get(self, key):\n        raise CodecError("E_AUTH", detail="alias_probe")\n')
    with pytest.raises(helpers_refusal_inventory.RefusalInventoryError) as failure:
        _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert all(site in failure.value.sites for site in expected)


def test_round5c_unmodelled_callee_invokes_lambda_argument(closed_inventory):
    sources, codec_sources, _expected = closed_inventory('external(lambda: inventory_probe())', PROBE)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_round5c_primitive_data_arguments_contribute_nothing(closed_inventory):
    sources, codec_sources, _expected = closed_inventory('external(1, "plain", None, False)', '')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert pairs["mailbox_digest"] == set()


def test_round5c_repeated_return_projection_keeps_the_callback(closed_inventory):
    definitions = ['def layer0():\n    return (inventory_probe, None)\n']
    for index in range(1, 21):
        previous = 'layer' + str(index - 1) + '()'
        definitions.append('def layer' + str(index) + '():\n    if choice:\n        return ' + previous + '\n    return ' + previous + '\n')
    sources, codec_sources, _expected = closed_inventory(
        'callback, _unused = layer20()\ncallback()', PROBE + ''.join(definitions))
    script = ('import json,sys\nfrom tests.helpers_refusal_inventory import reachable_refusal_pairs\n'
              'sources,codec=json.load(sys.stdin)\n'
              'pairs,_history=reachable_refusal_pairs(sources=sources,codec_sources=codec)\n'
              'print(json.dumps(sorted(pairs["mailbox_digest"])))\n')
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO,
                            input=json.dumps([sources, codec_sources]), check=True,
                            capture_output=True, text=True, timeout=10)
    assert helpers_refusal_inventory.covers_refusal(json.loads(result.stdout), ("E_AUTH", "alias_probe"))


@pytest.mark.parametrize("case", ["cycle", "depth", "candidates", "budget"])
def test_round5d_widening_returns_the_module_pool(closed_inventory, monkeypatch, case):
    # A pool member outside the concrete call proves that UNKNOWN retained the
    # whole module pool rather than pruning the difficult binding's candidates.
    extra = PROBE + 'def pool_member():\n    raise CodecError("E_AUTH", detail="pool_probe")\n'
    if case == "cycle":
        body = 'slots = []\nslots.append(slots)\nslots.append(inventory_probe)\nslots[0][0]()'
    elif case == "depth":
        extra += 'alias0 = inventory_probe\n' + ''.join(
            'alias' + str(i) + ' = alias' + str(i - 1) + '\n' for i in range(1, 161))
        body = 'alias160()'
    elif case == "candidates":
        extra += ''.join('def candidate' + str(i) + '():\n    pass\n' for i in range(70))
        body = 'callbacks = [' + ','.join('candidate' + str(i) for i in range(70)) + ', inventory_probe]\ncallbacks[0]()'
    else:
        monkeypatch.setattr(helpers_refusal_inventory, "INVENTORY_WORK_BUDGET", 0)
        body = 'inventory_probe()'
    sources, codec_sources, _expected = closed_inventory(body, extra)
    stats, trace = {}, []
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources,
                                             analysis_stats=stats, callback_trace=trace)
    assert stats["status"] == "UNKNOWN"
    assert stats["widened_slots"] > 0
    assert stats["budget_exhausted"] is (case == "budget")
    assert {("E_AUTH", "alias_probe"), ("E_AUTH", "pool_probe")} <= pairs["mailbox_digest"]
    assert any(target.startswith("widened.") and helpers_refusal_inventory.covers_refusal(emitted, ("E_AUTH", "pool_probe"))
               for _tool, target, _path, _line, emitted in trace)


def test_round5d_widening_does_not_omit_a_computed_detail(closed_inventory, monkeypatch):
    monkeypatch.setattr(helpers_refusal_inventory, "INVENTORY_WORK_BUDGET", 0)
    sources, codec_sources, _expected = closed_inventory(
        'emit("alias_probe")',
        'def emit(suffix):\n    raise CodecError("E_AUTH", detail="prefix_" + suffix)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "prefix_alias_probe") in pairs["mailbox_digest"]


def test_round5d_call_paths_share_the_global_depth_bound(closed_inventory, monkeypatch):
    monkeypatch.setattr(helpers_refusal_inventory, "INVENTORY_DEPTH_BOUND", 24)
    monkeypatch.setattr(helpers_refusal_inventory, "INVENTORY_WORK_BUDGET", 500000)
    extra = PROBE + 'def layer0():\n    inventory_probe()\n'
    extra += ''.join('def layer' + str(i) + '():\n    layer' + str(i - 1) + '()\n' for i in range(1, 81))
    sources, codec_sources, _expected = closed_inventory('layer80()', extra)
    stats = {}
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources, analysis_stats=stats)
    assert stats["status"] == "UNKNOWN"
    assert stats["widened_slots"] > 0
    assert not stats["budget_exhausted"]
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_round5e_wildcards_match_whole_fields_only():
    any_value = helpers_refusal_inventory.ANY
    rows = helpers_refusal_inventory.RefusalRows({("E_AUTH", any_value)})
    assert ("E_AUTH", "computed detail") in rows
    assert ("E_LIMIT", "computed detail") not in rows
    assert {("E_AUTH", "new detail")} <= rows
    assert not {("E_AUTH", "new detail")} - rows
    assert ("E_AUTH", "computed detail") in rows.copy()
    assert rows & {("E_AUTH", "new detail")} == {("E_AUTH", "new detail")}
    assert ("E_LIMIT", "anything") in helpers_refusal_inventory.RefusalRows({(any_value, any_value)})
    assert ("E_AUTH", "computed detail") not in helpers_refusal_inventory.RefusalRows({("E_AUTH", "prefix" + any_value)})
    assert ("E_AUTH", "computed detail") not in helpers_refusal_inventory.RefusalRows({("E_AUTH", any_value + "suffix")})
    assert ("E_AUTH", "computed detail") not in helpers_refusal_inventory.RefusalRows({("prefix" + any_value, any_value)})
    assert not rows.isdisjoint({("E_AUTH", "computed detail")})
    messages = helpers_refusal_inventory.HistoryRows({any_value})
    assert {"computed history"} <= messages
    assert not {"computed history"} - messages
    assert "computed history" in messages.copy() | {"literal"}
    assert messages & {"computed history"} == {"computed history"}
    assert "computed history" not in helpers_refusal_inventory.HistoryRows({"prefix" + any_value})


@pytest.mark.parametrize("code", ['"E_AUTH"', '"E_" + suffix'], ids=["known_code", "unknown_code"])
def test_round5e_wildcards_keep_known_contributors(closed_inventory, monkeypatch, code):
    monkeypatch.setattr(helpers_refusal_inventory, "INVENTORY_WORK_BUDGET", 0)
    sources, codec_sources, _expected = closed_inventory(
        'emit("alias_probe")', 'def emit(suffix):\n    raise CodecError(' + code + ', detail="prefix_" + suffix)\n')
    stats, trace = {}, []
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources,
                                             analysis_stats=stats, callback_trace=trace)
    expected = ("E_AUTH", helpers_refusal_inventory.ANY) if code == '"E_AUTH"' else (
        helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY)
    assert expected in set(pairs["mailbox_digest"])
    assert ("E_AUTH", "prefix_alias_probe") in pairs["mailbox_digest"]
    assert stats["pool_complete"] and stats["wildcard_rows"] > 0
    owner = "records" if closed_inventory.layer == "adapter" else "codec"
    assert any(target == owner + ".emit" for _tool, target, _path, _line, _rows in trace)
    assert any(target.startswith("widened.") for _tool, target, _path, _line, _rows in trace)


@pytest.mark.parametrize("code,detail", [('{}', '"known"'), ('"E_AUTH"', '{}')], ids=["mutable_code", "mutable_detail"])
def test_round5e_mutable_callback_values_return_wildcards(closed_inventory, code, detail):
    sources, codec_sources, _expected = closed_inventory(
        'from contextlib import ExitStack\nwith ExitStack() as stack:\n'
        '    stack.callback(CodecError, ' + code + ', detail=' + detail + ')', '')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    any_value = helpers_refusal_inventory.ANY
    expected = (any_value, any_value) if code == '{}' else ("E_AUTH", any_value)
    assert expected in set(pairs["mailbox_digest"])


def test_round5e_virtual_source_keeps_its_contributor(closed_inventory, monkeypatch):
    monkeypatch.setattr(helpers_refusal_inventory, "INVENTORY_WORK_BUDGET", 0)
    sources, codec_sources, _expected = closed_inventory('pass', '')
    codec_sources["extra"] = 'def extra_probe():\n    raise CodecError("E_AUTH", detail="extra_probe")\n'
    trace = []
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources, callback_trace=trace)
    assert ("E_AUTH", "extra_probe") in pairs["mailbox_digest"]
    assert any(target == "extra.extra_probe" for _tool, target, _path, _line, _rows in trace)


# ROUND-5g: closed sources prevent the real tree's admitted wildcard from
# hiding a missing invocation or a guessed decoy argument.
def test_round5g_opaque_classmethod_preserves_receiver(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'import copy\ncopy.copy(Holder()).alias("alias_probe")',
        'def emit(cls, detail="decoy"):\n    raise CodecError("E_AUTH", detail=detail)\n'
        'class Holder:\n    alias = classmethod(emit)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("primitive", ["require", "CodecError"])
@pytest.mark.parametrize("known_call", [False, True], ids=["no_other_call", "decoy_call"])
def test_round5g_unknown_primitive_callback_arguments(closed_inventory, primitive, known_call):
    body = 'from external_consumer import consume\nconsume(' + primitive + ')'
    if known_call:
        body += '\n' + primitive + ('(False, "E_FORMAT", detail="decoy")' if primitive == "require" else
                                    '("E_FORMAT", detail="decoy")')
    sources, codec_sources, _expected = closed_inventory(body, '')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("graph", ["local", "codec", "boundary", "computed_detail", "computed_code",
                                   "computed_message", "computed_table"])
def test_round5g_replacement_call_traverses_full_graph(closed_inventory, graph):
    sources, codec_sources, _expected = closed_inventory('pass', '')
    if graph == "local":
        relay = 'raise CodecError("E_AUTH", detail="alias_probe")'
    elif graph == "codec":
        relay = 'codec.read_view(None)'
        codec_sources["codec"] = 'def read_view(value):\n    raise CodecError("E_AUTH", detail="alias_probe")\n'
    else:
        relay = 'mailbox.boundary_probe()'
        sources["mailbox"] = 'def boundary_probe():\n    raise ValueError("boundary probe")\n'
        row = '("boundary probe", "E_AUTH", "alias_probe")'
        if graph == "computed_detail":
            row = '("boundary probe", "E_AUTH", "prefix_" + suffix)'
        elif graph == "computed_code":
            row = '("boundary probe", "E_" + code_suffix, "alias_probe")'
        elif graph == "computed_message":
            row = '("boundary" + " probe", "E_AUTH", "alias_probe")'
        sources["guidance"] = 'suffix="alias_probe"\ncode_suffix="AUTH"\nPINNED_REFUSALS = (' + row + ',)\n'
        if graph == "computed_table":
            sources["guidance"] = 'def build_table():\n    return (' + row + ',)\nPINNED_REFUSALS=build_table()\n'
        sources["records"] += '\nimport hierarchy_mailbox as mailbox\n'
    sources["records"] += ('\ndef relay():\n    ' + relay + '\n'
                           'if condition:\n    def call():\n        relay()\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    detail = "prefix_alias_probe" if graph == "computed_detail" else "alias_probe"
    assert all(("E_AUTH", detail) in rows for rows in pairs.values())


def test_round5g_nested_exception_reaches_outer_handler(closed_inventory):
    sources, codec_sources, _expected = closed_inventory(
        'external(callback)',
        'def callback():\n    reason = "decoy"\n    try:\n        try:\n'
        '            reason = "alias_probe"\n            opaque_operation()\n'
        '            reason = "decoy"\n        finally:\n            pass\n'
        '    except Exception:\n        raise CodecError("E_AUTH", detail=reason)\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body", [
    'slots = []\nslots += [inventory_probe]\nslots[0]()',
    'slots = {}\nslots |= {"callback": inventory_probe}\nslots["callback"]()',
    'slots = set()\nslots |= {inventory_probe}\nfor callback in slots:\n    callback()',
    'holder = Holder()\nholder.slots = []\nholder.slots += [inventory_probe]\nholder.slots[0]()',
    'slots = {"callbacks": []}\nslots["callbacks"] += [inventory_probe]\nslots["callbacks"][0]()',
], ids=["list", "dict", "set", "attribute", "subscript"])
def test_round5g_augmented_storage_keeps_callback(closed_inventory, body):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + 'class Holder:\n    pass\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def test_round5g_summary_control_flow_uses_shared_budget(closed_inventory):
    sequence = repr(tuple(range(16)))
    nested = ''.join('    ' * (i + 1) + 'for step' + str(i) + ' in ' + sequence + ':\n' for i in range(4))
    extra = 'def callback():\n' + nested + '                    reason = "decoy"\n    inventory_probe()\n' + PROBE
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    script = ('import json,sys\nfrom tests import helpers_refusal_inventory as helper\n'
              'helper.INVENTORY_WORK_BUDGET=5000\n'
              'sources,codec=json.load(sys.stdin)\nstats={}\n'
              'pairs,_=helper.reachable_refusal_pairs(sources=sources,codec_sources=codec,analysis_stats=stats)\n'
              'assert helper.covers_refusal(pairs["mailbox_digest"],("E_AUTH","alias_probe"))\n'
              'assert stats["budget_exhausted"],stats\nassert stats["work_used"]<=5000,stats\n')
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO, input=json.dumps([sources, codec_sources]),
                            check=False, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("body,extra", [
    ('Holder().callback', 'class Holder:\n    callback = property(inventory_probe)\n'),
    ('from contextlib import contextmanager\ncm = contextmanager(generator)\nwith cm():\n    pass',
     'def generator():\n    raise CodecError("E_AUTH", detail="alias_probe")\n    yield\n'),
], ids=["property", "contextmanager"])
def test_round5g_unmodelled_wrapper_keeps_refusal(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, PROBE + extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("body,extra", [
    ('"alias_probe" == Executor() == "decoy"',
     'class Executor:\n    def __eq__(self, other):\n        raise CodecError("E_AUTH", detail=other)\n'),
    ('Box() in Holder() in Executor()',
     'class Box:\n    pass\nclass Holder:\n    def __contains__(self, other):\n        return True\n'
     'class Executor:\n    def __contains__(self, other):\n        raise CodecError("E_AUTH", detail=other.detail)\n'
     'Holder.detail = "alias_probe"\nBox.detail = "decoy"\n'),
], ids=["comparison", "containment"])
def test_round5g_chain_keeps_each_adjacent_operand(closed_inventory, body, extra):
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("field", ["detail", "code"])
def test_round5g_unenumerable_attribute_is_unknown(closed_inventory, field):
    arguments = '"E_AUTH", detail=self.detail' if field == "detail" else 'self.code, detail="alias_probe"'
    body = 'suffix="alias_probe"\nHolder("prefix_" + suffix).run()'
    extra = ('class Holder:\n    def __init__(self, value):\n        self.' + field + ' = value\n'
             '    def run(self):\n        raise CodecError(' + arguments + ')\n')
    sources, codec_sources, _expected = closed_inventory(body, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    expected = ("E_AUTH", "prefix_alias_probe") if field == "detail" else ("prefix_alias_probe", "alias_probe")
    assert expected in pairs["mailbox_digest"]


@pytest.mark.parametrize("wrapper", ["staticmethod", "classmethod"])
@pytest.mark.parametrize("kind", ["instance", "constructor"])
def test_round5h_wrappers_keep_unknown_callable_kinds(closed_inventory, wrapper, kind):
    method = "__call__" if kind == "instance" else "__init__"
    extra = ('class Emitter:\n    def ' + method + '(self, owner_or_detail, detail=None):\n'
             '        raise CodecError("E_AUTH", detail=owner_or_detail if detail is None else detail)\n'
             'class Holder:\n    callback = ' + wrapper + '(Emitter' + ('()' if kind == "instance" else '') + ')\n')
    sources, codec_sources, _expected = closed_inventory('Holder.callback("alias_probe")', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("binding", [
    'reason, = ("alias_probe",)',
    '[reason] = ["alias_probe"]',
    'first, *reason = ("head", "alias_probe")',
    'first, (reason,) = (0, ("alias_probe",))',
    'for reason, in (("alias_probe",),):\n    pass',
    'for first, (reason,) in ((0, ("alias_probe",)),):\n    pass',
    '[(reason := item) for item in ("alias_probe",)]',
    '(reason := "alias_probe")',
    'reason += "alias_probe"',
    'with opaque_manager() as reason:\n    pass',
    'try:\n    opaque_raise()\nexcept Exception as reason:\n    pass',
    'from external_details import reason',
    'import external_details as reason',
    'del reason',
], ids=["tuple", "list", "starred", "nested", "loop_tuple", "loop_nested", "comprehension",
        "walrus", "augmented", "with_as", "except_as", "from_import", "import", "delete"])
def test_round5h_binding_allowlist_invalidates_every_name(closed_inventory, binding):
    extra = ('def callback():\n    reason="decoy"\n' +
             ''.join('    ' + line + '\n' for line in binding.splitlines()) +
             '    raise CodecError("E_AUTH", detail=reason)\n')
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]
    assert (("E_AUTH", helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"]) or
            (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"]))


@pytest.mark.parametrize("scope", ["global", "nonlocal"])
def test_round5h_scope_declarations_keep_unknown_bindings(closed_inventory, scope):
    if scope == "global":
        extra = ('reason="decoy"\ndef callback():\n    global reason\n    reason="alias_probe"\n'
                 '    raise CodecError("E_AUTH", detail=reason)\n')
    else:
        extra = ('def callback():\n    reason="decoy"\n    def nested():\n        nonlocal reason\n'
                 '        reason="alias_probe"\n        raise CodecError("E_AUTH", detail=reason)\n    nested()\n')
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]
    assert (("E_AUTH", helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"]) or
            (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"]))


def test_round5h_match_capture_is_unknown(closed_inventory):
    if sys.version_info < (3, 10):
        pytest.skip("match captures require Python 3.10 syntax")
    extra = ('def callback():\n    reason="decoy"\n    match opaque_value():\n'
             '        case {"detail": reason}:\n            pass\n'
             '    raise CodecError("E_AUTH", detail=reason)\n')
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("read", ["B.alias()", "B().alias()", "local=B.alias\nlocal()"],
                         ids=["class_read", "instance_read", "alias_read"])
def test_round5h_reexported_bound_method_retains_original_receiver(closed_inventory, read):
    extra = ('class A:\n    detail="alias_probe"\n    @classmethod\n    def emit(cls):\n'
             '        raise CodecError("E_AUTH", detail=cls.detail)\n'
             'class B:\n    detail="decoy"\n    alias=A.emit\n')
    sources, codec_sources, _expected = closed_inventory(read, extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("expression", [
    '((reason := "alias_probe"), opaque_operation(), (reason := "decoy"))',
    'consume((reason := "alias_probe"), opaque_operation(), (reason := "decoy"))',
    '[(reason := "alias_probe"), opaque_operation(), (reason := "decoy")]',
    '{"first": (reason := "alias_probe"), "call": opaque_operation(), "last": (reason := "decoy")}',
], ids=["tuple", "arguments", "list", "dict"])
@pytest.mark.parametrize("nested", [False, True], ids=["handler", "nested_finally"])
def test_round5h_expression_exception_keeps_intermediate_state(closed_inventory, expression, nested):
    body = 'try:\n    ' + expression + '\nfinally:\n    pass' if nested else expression
    extra = ('def callback():\n    reason="decoy"\n    try:\n' +
             ''.join('        ' + line + '\n' for line in body.splitlines()) +
             '    except Exception:\n        raise CodecError("E_AUTH", detail=reason)\n')
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("declaration", ["type reason = str", "def callback[reason]():\n    raise CodecError(\"E_AUTH\", detail=reason)"],
                         ids=["store_field", "name_field"])
def test_round5h_unlisted_binding_nodes_default_to_unknown(closed_inventory, declaration):
    if sys.version_info < (3, 12):
        pytest.skip("type alias and type parameter syntax require Python 3.12")
    if declaration.startswith("type "):
        extra = ('def callback():\n    reason="decoy"\n    ' + declaration + '\n'
                 '    raise CodecError("E_AUTH", detail=reason)\n')
    else:
        extra = 'reason="decoy"\n' + declaration + '\n'
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("kind", ["args", "kwargs"])
def test_round5h_unmodelled_parameter_roles_are_unknown(closed_inventory, kind):
    if kind == "args":
        extra = ('reasons=("decoy",)\ndef callback():\n    emit("alias_probe")\n'
                 'def emit(*reasons):\n    raise CodecError("E_AUTH", detail=reasons[0])\n')
    else:
        extra = ('reasons={"detail":"decoy"}\ndef callback():\n    emit(detail="alias_probe")\n'
                 'def emit(**reasons):\n    raise CodecError("E_AUTH", detail=reasons["detail"])\n')
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


@pytest.mark.parametrize("field", ["code", "detail"])
def test_round5h_unknown_binding_cannot_regain_precision_through_member(closed_inventory, field):
    module = "hierarchy_mailbox_records_guidance" if closed_inventory.layer == "adapter" else "aegis_core.message_codec_views"
    arguments = 'namespace.code, detail="alias_probe"' if field == "code" else '"E_AUTH", detail=namespace.detail'
    sources, codec_sources, _expected = closed_inventory(
        'import ' + module + ' as namespace\nraise CodecError(' + arguments + ')', '',
        'code="E_AUTH"\ndetail="alias_probe"\n')
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    expected = (helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) if field == "code" else (
        "E_AUTH", helpers_refusal_inventory.ANY)
    assert expected in set(pairs["mailbox_digest"]) or (
        helpers_refusal_inventory.ANY, helpers_refusal_inventory.ANY) in set(pairs["mailbox_digest"])


@pytest.mark.parametrize("argument", ["action", "[action]"], ids=["direct", "container"])
def test_round5h_unknown_binding_forwarded_to_consumer_keeps_pool(closed_inventory, argument):
    extra = (PROBE + 'def callback():\n    with opaque_manager() as action:\n        external(' + argument + ')\n')
    sources, codec_sources, _expected = closed_inventory('external(callback)', extra)
    pairs, _history = _reachable_refusal_pairs(sources=sources, codec_sources=codec_sources)
    assert ("E_AUTH", "alias_probe") in pairs["mailbox_digest"]


def _guidance_module():
    """Load the record-guidance renderer without inserting a path at import time."""
    import importlib.util
    path = REPO / "tools" / "hierarchy_mailbox_records_guidance.py"
    spec = importlib.util.spec_from_file_location("closed_table_guidance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_closed_table_rejects_wildcard_and_malformed_rows():
    """The loader refuses wildcard, multiline, and oversized rows before use."""
    helper = helpers_refusal_inventory
    long_code = "E_" + ("A" * 40)
    cases = (
        ((("mailbox_digest", helper.ANY, "binding", "accepted-action"),), "wildcard_row"),
        ((("mailbox_digest", "E_AUTH", helper.ANY, "accepted-action"),), "wildcard_row"),
        ((("mailbox_digest", "E_AUTH*", "binding", "accepted-action"),), "wildcard_row"),
        ((("mailbox_digest", "E_AUTH", "bad\nline", "accepted-action"),), "multiline_field"),
        ((("mailbox_digest", "E_AUTH", "binding", "accepted-action"),) * 2, "duplicate_row"),
        ((("other_tool", "E_AUTH", "binding", "accepted-action"),), "unknown_tool"),
        ((("mailbox_digest", "E_AUTH", "binding", "unlisted-kind"),), "unknown_kind"),
        ("not-a-table", "malformed_table"),
        ((("mailbox_digest", "E_AUTH"),), "malformed_row"),
        ((("mailbox_digest", long_code, "binding", "accepted-action"),), "field_limit"),
        (tuple(("mailbox_digest", "E_AUTH", "d" + str(index), "pinned-no-action") for index in range(257)), "table_limit"),
    )
    for rows, code in cases:
        with pytest.raises(helper.ClosedRefusalError) as failure:
            helper.load_closed_refusal_table(rows)
        assert failure.value.code == code
        text = str(failure.value)
        assert "\n" not in text and "\r" not in text
        assert "SECRET" not in text and "bad" not in text and helper.ANY not in text
        assert long_code not in text
    # A refusal does not keep a partial table: the same loader accepts the closed rows on retry.
    loaded = helper.load_closed_refusal_table(helper.CLOSED_REFUSAL_TABLE)
    assert loaded[("mailbox_digest", "E_AUTH", "binding")] == "accepted-action"


def test_missing_refusal_row_fails_and_explicit_retry_passes():
    """A new detail that a wildcard would cover fails until an explicit row exists."""
    helper = helpers_refusal_inventory
    table = helper.load_closed_refusal_table(helper.CLOSED_REFUSAL_TABLE)
    missing = ("mailbox_digest", "E_AUTH", "brand_new")
    assert helper.covers_refusal([(helper.ANY, helper.ANY)], ("E_AUTH", "brand_new"))
    assert helper.closed_refusal_gaps([missing], table) == (missing,)
    repaired = helper.CLOSED_REFUSAL_TABLE + (("mailbox_digest", "E_AUTH", "brand_new", "pinned-no-action"),)
    retried = helper.load_closed_refusal_table(repaired)
    assert helper.closed_refusal_gaps([missing], retried) == ()
    assert helper.closed_refusal_gaps([missing], table) == (missing,)


def test_wildcard_emission_cannot_satisfy_the_closed_table():
    """An ANY row, even placed by hand, does not cover a concrete triple."""
    helper = helpers_refusal_inventory
    planted = {( "mailbox_digest", helper.ANY, helper.ANY): "accepted-action",
               ("mailbox_digest", "E_AUTH", helper.ANY): "accepted-action"}
    missing = ("mailbox_digest", "E_AUTH", "brand_new")
    wildcard = ("mailbox_digest", helper.ANY, helper.ANY)
    assert helper.closed_refusal_gaps([missing], planted) == (missing,)
    assert helper.closed_refusal_gaps([wildcard], planted) == (wildcard,)
    assert helper.covers_refusal([(helper.ANY, helper.ANY)], ("E_AUTH", "brand_new"))


def test_every_closed_row_matches_renderer_disposition():
    """Each explicit row is an accepted action or a pinned no-action, matching the renderer."""
    helper = helpers_refusal_inventory
    guidance = _guidance_module()
    table = helper.load_closed_refusal_table(helper.CLOSED_REFUSAL_TABLE)

    class Rendered:
        def __init__(self, code, detail):
            self.code, self.detail = code, detail

        def as_dict(self):
            return {"error": {"code": self.code, "message": "m"}}

    saw_action = saw_no_action = False
    for (tool, code, detail), kind in sorted(table.items()):
        assert helper.closed_refusal_gaps([(tool, code, detail)], table) == ()
        payload = guidance.error_result(Rendered(code, detail), tool=tool, max_chars=guidance.MAX_CHARS)
        action = payload["error"].get("next_action")
        if kind == "accepted-action":
            assert type(action) is str and "\n" not in action and "\r" not in action
            saw_action = True
        else:
            assert kind == "pinned-no-action" and action is None
            saw_no_action = True
        neighbor = (tool, code, "not_a_row")
        assert helper.closed_refusal_gaps([neighbor], table) == (neighbor,)
    assert saw_action and saw_no_action


def test_closed_table_lists_bounded_refusals_and_pins():
    """The real-tree inventory checks concrete bounded rows and explicit pins."""
    helper = helpers_refusal_inventory
    table = helper.load_closed_refusal_table(helper.CLOSED_REFUSAL_TABLE)
    pairs, _history = _reachable_refusal_pairs()
    concrete = {(tool, code, detail) for tool, rows in pairs.items()
                for code, detail in rows if helper.ANY not in (code, detail)}
    assert concrete <= set(table)
    assert set(helper.PINNED_EXPLICIT_REFUSALS) <= set(table)
    assert all(helper.ANY not in field for key in table for field in key)


def test_real_tree_refuses_a_dropped_row_then_retries(monkeypatch):
    """Dropping one explicit row refuses the real tree; restoring the table retries."""
    helper = helpers_refusal_inventory
    original = helper.CLOSED_REFUSAL_TABLE
    dropped = ("mailbox_digest", "E_AUTH", "binding", "accepted-action")
    assert dropped in original
    monkeypatch.setattr(helpers_refusal_inventory, "CLOSED_REFUSAL_TABLE",
                        tuple(row for row in original if row != dropped))
    with pytest.raises(helper.ClosedRefusalError) as failure:
        _reachable_refusal_pairs()
    assert failure.value.code == "untabled_refusal"
    assert failure.value.triples == (("mailbox_digest", "E_AUTH", "binding"),)
    assert "\n" not in str(failure.value)
    monkeypatch.setattr(helpers_refusal_inventory, "CLOSED_REFUSAL_TABLE", original)
    pairs, _history = _reachable_refusal_pairs()
    assert ("E_AUTH", "binding") in pairs["mailbox_digest"]


def test_closed_table_checks_are_isolated_across_threads():
    """Concurrent checks keep each input table and its exact gaps independent."""
    helper = helpers_refusal_inventory
    original = helper.CLOSED_REFUSAL_TABLE
    row = ("mailbox_digest", "E_AUTH", "binding", "accepted-action")
    triple = row[:3]
    missing = tuple(candidate for candidate in original if candidate != row)
    repaired = missing + (row,)
    invalid = repaired + ((triple[0], triple[1], helper.ANY, row[3]),)
    cases = (
        (original, ()),
        (missing, (triple,)),
        (repaired, ()),
        (invalid, None),
    )
    start = Barrier(len(cases))

    def once(case):
        rows, expected = case
        start.wait(timeout=10)
        if expected is None:
            with pytest.raises(helper.ClosedRefusalError) as failure:
                helper.load_closed_refusal_table(rows)
            assert failure.value.code == "wildcard_row"
            assert failure.value.triples == ()
        else:
            table = helper.load_closed_refusal_table(rows)
            assert helper.closed_refusal_gaps([triple], table) == expected

    with ThreadPoolExecutor(max_workers=len(cases)) as pool:
        list(pool.map(once, cases, timeout=30))
