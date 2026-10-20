"""R-checks-10: a ``where`` gives a definite answer only for call sites whose arguments were recorded.

Only the Python driver records call arguments. A site from another driver carries an empty
argument map, which says nothing about the call, so a ``where`` over it is UNKNOWN (advisory)
instead of a silent pass or a conviction without evidence.
"""
from __future__ import annotations

import pytest

from aegis_core.ast.policy import evaluate_forbid_ast, evaluate_forbid_ast_structured, extract_normalized_ast
from aegis_core.ast.schema import CallSiteNode, NormalizedAST


def _ts(*sites: CallSiteNode) -> NormalizedAST:
    return NormalizedAST(file_path="app.ts", language="typescript", call_sites=sites)


def _spec(where=None) -> dict:
    return {"calls": [{"name": "exec", **({"where": where} if where is not None else {})}]}


@pytest.mark.parametrize("where", [{"shell": True}, {"shell": {"absent": True}}, {"shell": {"not": False}}],
                         ids=["literal", "absent", "not"])
def test_a_site_without_recorded_arguments_is_unknown(where):
    """Given a typescript site with no recorded arguments, When a where is evaluated,
    Then nothing is confirmed and the site is reported once as unverified."""
    norm = _ts(CallSiteNode(target="exec", line=3))
    confirmed, unverified = evaluate_forbid_ast_structured(norm, _spec(where), rule_id="r")
    assert confirmed == []
    assert [(u["line"], u["status"]) for u in unverified] == [(3, "unverified")]
    assert evaluate_forbid_ast(norm, _spec(where)) == []


@pytest.mark.parametrize("args,where,hit", [
    ({"shell": "True"}, {"shell": True}, True),
    ({"shell": "False"}, {"shell": True}, False),
    ({"shell": "True"}, {"shell": {"absent": True}}, False),
], ids=["literal-hit", "literal-miss", "absent-miss"])
def test_a_non_python_site_that_records_arguments_is_judged_normally(args, where, hit):
    norm = _ts(CallSiteNode(target="exec", line=3, args=args))
    confirmed, unverified = evaluate_forbid_ast_structured(norm, _spec(where), rule_id="r")
    assert ([c["line"] for c in confirmed], unverified) == (([3], []) if hit else ([], []))


@pytest.mark.parametrize("where,hit", [({"shell": {"absent": True}}, True), ({"shell": True}, False)],
                         ids=["absent", "literal"])
def test_a_python_call_with_no_arguments_stays_a_definite_answer(where, hit):
    norm = extract_normalized_ast("mod.py", code="exec()\n")
    confirmed, unverified = evaluate_forbid_ast_structured(norm, _spec(where), rule_id="r")
    assert ([c["line"] for c in confirmed], unverified) == (([1], []) if hit else ([], []))


def test_a_real_python_exec_with_an_unmatched_positional_is_neither_hit_nor_unknown():
    norm = extract_normalized_ast("mod.py", code="exec('print(1)')\n")
    assert evaluate_forbid_ast_structured(norm, _spec({"#0": {"in": ["rm", "ls"]}}), rule_id="r") == ([], [])


def test_a_rule_without_where_still_matches_a_non_python_site():
    norm = _ts(CallSiteNode(target="exec", line=3))
    assert evaluate_forbid_ast(norm, _spec()) == ["Forbidden call 'exec' matched rule forbid_ast.calls"]
