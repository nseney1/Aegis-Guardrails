"""Unknown target segments retain uncertainty while known suffixes prune matches."""
from __future__ import annotations

import pytest

from aegis_core.ast.policy import evaluate_forbid_ast_structured
from aegis_core.ast.schema import CallSiteNode, ImportNode, NormalizedAST


def tree(*, target=None, imported=None, args=None):
    return NormalizedAST(version='1.0', language='typescript', file_path='app.ts',
                         call_sites=[] if target is None else [CallSiteNode(target=target, args=args or {}, line=3)],
                         imports=[] if imported is None else [ImportNode(source=imported, line=2)],
                         metadata={'capabilities': ['args']})


@pytest.mark.parametrize('source', ['<expr>', '<computed>'])
def test_unknown_import_sources_are_advisory_for_each_restriction(source):
    found = evaluate_forbid_ast_structured(tree(imported=source),
                                           {'imports': ['child_process', 'fs']}, source='')
    assert [(row['pattern'], row['unknown'], row['line']) for row in found] == [
        ('child_process', True, 2), ('fs', True, 2)]


@pytest.mark.parametrize('target,pattern,unknown', [
    ('<expr>.exec', 'child_process.exec', True),
    ('child_process.<computed>', 'child_process.exec', True),
    ('<computed>.exec', 'child_process.exec', True),
    ('<expr>', 'child_process.exec', True),
    ('module.<expr>.exec', 'module.exec', True),
    ('<expr>.exec', '.exec', False),
    ('<computed>.exec', '.exec', False),
    ('child_process.<computed>', '.exec', True),
])
def test_possible_unknown_calls_are_kept(target, pattern, unknown):
    found = evaluate_forbid_ast_structured(tree(target=target), {'calls': [pattern]}, source='')
    assert [(row['pattern'], row['unknown'], row['line']) for row in found] == [(pattern, unknown, 3)]


@pytest.mark.parametrize('target,pattern', [
    ('<expr>.safe', 'child_process.exec'), ('fs.<computed>', 'child_process.exec'),
    ('child_process.<computed>.safe', 'child_process.exec'), ('<expr>.safe', '.exec'),
])
def test_known_call_segments_rule_out_incompatible_patterns(target, pattern):
    assert evaluate_forbid_ast_structured(tree(target=target), {'calls': [pattern]}, source='') == []


def test_known_false_argument_prunes_an_unknown_call_target():
    assert evaluate_forbid_ast_structured(tree(target='<expr>.exec', args={'shell': 'False'}),
        {'calls': [{'name': 'child_process.exec', 'where': {'shell': True}}]}, source='') == []


def test_known_harmless_import_remains_a_non_match():
    assert evaluate_forbid_ast_structured(tree(imported='safe'), {'imports': ['child_process']}, source='') == []
