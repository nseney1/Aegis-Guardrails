"""M1 contracts exercised through schema serialization and policy evaluation."""
from __future__ import annotations

import pytest

from aegis_core.ast.drivers.python import parse_python_ast
from aegis_core.ast.policy import evaluate_forbid_ast_structured, extract_normalized_ast, parse_allow_comments
from aegis_core.ast.schema import CallSiteNode, ImportNode, NormalizedAST


def _tree(*, target="danger", args=None, imports=(), metadata=None):
    return NormalizedAST(
        file_path="fixture.go", language="go", imports=imports,
        call_sites=[CallSiteNode(target, line=1, args=args or {})],
        metadata={"capabilities": ["args"], **(metadata or {})},
    )


def _where(value, condition):
    return evaluate_forbid_ast_structured(
        _tree(args={"value": value}),
        {"calls": [{"name": "danger", "where": {"value": condition}}]}, source="",
    )


@pytest.mark.parametrize("value,condition", [
    ("0x10", 16), ("1_000", 1000), ("16.0", 16), ("-0x10", -16),
    ("0x10", {"in": [15, 16]}), ("0x10", {"not": {"in": [17]}}),
    ("'a\\n'", "a\n"), ('"a\\u0062"', "ab"),
])
def test_equivalent_supported_literals_are_confirmed(value, condition):
    findings = _where(value, condition)
    assert len(findings) == 1
    assert findings[0]["unknown"] is False


@pytest.mark.parametrize("value,condition", [
    ("True", 1), ("1", True), ("'16'", 16), ("16", "16"),
    ("False", {"in": [0]}), ("'1'", {"in": [1, True]}),
    ("1", {"not": {"not": True}}),
])
def test_literals_keep_boolean_string_and_numeric_types_distinct(value, condition):
    assert _where(value, condition) == []


@pytest.mark.parametrize("value", ["<expr>", "16u999", "16n", "1e10000"])
def test_unsupported_numeric_kinds_remain_unknown(value):
    for condition in (16, {"in": [16]}, {"not": 16}):
        assert _where(value, condition)[0]["unknown"] is True


def test_driver_capability_controls_where_even_with_nonempty_args():
    legacy = _tree(args={"value": "16"}, metadata={"capabilities": []})
    findings = evaluate_forbid_ast_structured(
        legacy, {"calls": [{"name": "danger", "where": {"value": 16}}]}, source="",
    )
    assert findings[0]["unknown"] is True
    python = parse_python_ast("danger(value=16)", file_path="fixture.py")
    assert python.metadata["capabilities"] == ["allow_comments", "args", "decorators"]
    assert evaluate_forbid_ast_structured(
        python, {"calls": [{"name": "danger", "where": {"value": 16}}]}, source="",
    )[0]["unknown"] is False


@pytest.mark.parametrize("target,pattern,imports", [
    ("Cmd::new", "std::process::Command::new", [ImportNode("std::process", ("Command",), aliases=(("Cmd", "Command"),))]),
    ("exec.Command", "os/exec.Command", [ImportNode("os/exec", aliases=(("exec", "os/exec"),))]),
    ("fs.readFile", "node:fs/promises.readFile", [ImportNode("node:fs/promises", aliases=(("fs", "node:fs/promises"),))]),
    ("client.danger", ".danger", []),
    ("renamed", ".danger", [ImportNode("pkg", aliases=(("renamed", "client.danger"),))]),
])
def test_canonical_names_and_receiver_patterns_match(target, pattern, imports):
    tree = _tree(target=target, imports=imports)
    findings = evaluate_forbid_ast_structured(tree, {"calls": [pattern]}, source="source spelling")
    assert len(findings) == 1
    assert findings[0]["unknown"] is False
    assert tree.call_sites[0].target == target
    assert findings[0]["snippet"] == "source spelling"


def test_leading_dot_requires_a_receiver():
    assert evaluate_forbid_ast_structured(_tree(), {"calls": [".danger"]}, source="") == []


@pytest.mark.parametrize("source,pattern", [
    ("node:fs/promises", "fs"), ("os/exec", "os.exec"),
    ("std::process", "std.process"),
])
def test_import_separators_are_canonical(source, pattern):
    tree = _tree(imports=[ImportNode(source)])
    assert len(evaluate_forbid_ast_structured(tree, {"imports": [pattern]}, source="")) == 1
    assert tree.imports[0].source == source


@pytest.mark.parametrize("source", ["./fs", "../fs", ".fs"])
def test_relative_import_never_matches_bare_restriction(source):
    tree = _tree(imports=[ImportNode(source, ("fs",))])
    assert evaluate_forbid_ast_structured(tree, {"imports": ["fs"]}, source="") == []


def test_unresolved_import_is_advisory_for_each_restriction():
    tree = _tree(imports=[ImportNode("<expr>", line=3), ImportNode("safe", line=4)])
    findings = evaluate_forbid_ast_structured(tree, {"imports": ["fs", "os/exec"]}, source="")
    assert [(f["pattern"], f["line"], f["unknown"]) for f in findings] == [
        ("fs", 3, True), ("os/exec", 3, True),
    ]


def test_new_optional_fields_round_trip_and_keep_comment_lines_usable():
    tree = _tree(metadata={"allow_comments": {"1": [{"rules": ["rule"], "reason": "fixture"}]}},
                 target="danger")
    data = tree.to_dict()
    data["call_sites"][0]["kind"] = "construct"
    restored = NormalizedAST.from_json(NormalizedAST.from_dict(data).to_json())
    assert restored.version == "1.0"
    assert restored.to_dict()["call_sites"][0]["kind"] == "construct"
    assert restored.metadata["allow_comments"] == {1: [{"rules": ["rule"], "reason": "fixture"}]}
    finding, = evaluate_forbid_ast_structured(restored, {"calls": ["danger"]}, rule_id="rule", source="danger()")
    assert finding["override"] == "fixture"


def test_nonpython_source_does_not_override_parser_comment_metadata():
    source = 'danger("// aegis: allow[rule] fake")'
    finding, = evaluate_forbid_ast_structured(_tree(), {"calls": ["danger"]}, rule_id="rule", source=source)
    assert finding["override"] is None
    assert parse_allow_comments(source, "go") == {}
    parsed = _tree(metadata={"allow_comments": {1: [{"rules": ["rule"], "reason": "real comment"}]}})
    finding, = evaluate_forbid_ast_structured(parsed, {"calls": ["danger"]}, rule_id="rule", source=source)
    assert finding["override"] == "real comment"


def test_python_allow_comments_keep_same_line_scope_and_rule_filter():
    source = "danger()  # aegis: allow[rule] reason\ndanger()\n"
    tree = parse_python_ast(source, file_path="fixture.py")
    findings = evaluate_forbid_ast_structured(tree, {"calls": ["danger"]}, rule_id="rule", source=source)
    assert [f["override"] for f in findings] == ["reason", None]
    assert evaluate_forbid_ast_structured(tree, {"calls": ["danger"]}, rule_id="other", source=source)[0]["override"] is None


@pytest.mark.parametrize("kind", ["new", "construct", "macro"])
def test_construction_kind_is_diagnostic_only(kind):
    tree = NormalizedAST.from_dict({"file_path": "f.go", "language": "go", "call_sites": [{"target": "danger", "kind": kind}]})
    assert tree.to_dict()["call_sites"][0]["kind"] == kind
    assert len(evaluate_forbid_ast_structured(tree, {"calls": ["danger"]}, source="")) == 1


def test_python_allow_metadata_serializes_with_rule_filter_intact():
    tree = extract_normalized_ast("missing_fixture.py", code="danger() # aegis: allow[rule] reason")
    restored = NormalizedAST.from_json(tree.to_json())
    finding, = evaluate_forbid_ast_structured(restored, {"calls": ["danger"]}, rule_id="rule")
    assert finding["override"] == "reason"
    finding, = evaluate_forbid_ast_structured(restored, {"calls": ["danger"]}, rule_id="other")
    assert finding["override"] is None


@pytest.mark.parametrize("sign", [1, -1])
def test_python_large_integer_preserves_value(sign):
    number = sign * (10 ** 70 + 16)
    tree = parse_python_ast(f"danger(value={number})", file_path="fixture.py")
    findings = evaluate_forbid_ast_structured(
        tree, {"calls": [{"name": "danger", "where": {"value": number}}]}, source="",
    )
    assert len(findings) == 1
    assert findings[0]["unknown"] is False


def test_python_unicode_symbolic_argument_remains_matchable():
    tree = parse_python_ast("danger(value=变量)", file_path="fixture.py")
    finding, = evaluate_forbid_ast_structured(
        tree, {"calls": [{"name": "danger", "where": {"value": "变量"}}]}, source="",
    )
    assert finding["unknown"] is False


def test_malformed_comment_rule_string_cannot_override_by_substring():
    tree = _tree(metadata={"allow_comments": {1: [{"rules": "other-rule", "reason": "invalid"}]}})
    finding, = evaluate_forbid_ast_structured(tree, {"calls": ["danger"]}, rule_id="rule", source="danger()")
    assert finding["override"] is None
