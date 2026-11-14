"""M1 contracts exercised through schema serialization and policy evaluation."""
from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core.ast import policy, schema
from aegis_core.ast.drivers import python as python_driver
from aegis_core.ast.drivers.python import parse_python_ast
from aegis_core.ast.policy import ASTExtractionError, evaluate_forbid_ast_structured, extract_normalized_ast, parse_allow_comments
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


def test_structured_evaluator_keeps_language_driver_headroom():
    tree = ast.parse(Path(policy.__file__).read_text(encoding="utf-8"))
    evaluator = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "evaluate_forbid_ast_structured")
    # Restore at least the pre-driver budget without changing the shared ratchet.
    assert evaluator.end_lineno - evaluator.lineno + 1 <= 65
    assert sum(isinstance(node, ast.stmt) for node in ast.walk(evaluator)) <= 52


@pytest.mark.parametrize("language", ["python", "javascript", "typescript", "rust", "go"])
@pytest.mark.parametrize("supplied_source", [False, True], ids=["file", "supplied"])
@pytest.mark.parametrize("parser_comments", [False, True], ids=["no-metadata", "metadata"])
def test_structured_findings_preserve_bytes_and_inputs(
    tmp_path, language, supplied_source, parser_comments,
):
    lines = [
        "from first import run as dispatch",
        "from second import run",
        "dispatch()",
        "run()  # aegis: allow[rule] source reason",
        "dynamic()",
    ]
    source = "\n".join(lines) + "\n"
    target = tmp_path / "fixture.txt"
    target.write_bytes(source.encode("utf-8"))
    metadata = {"capabilities": ["args"], "decorators": ["dispatch"]}
    if parser_comments:
        metadata["allow_comments"] = {4: [{"rules": ["rule"], "reason": "parser reason"}]}
    tree = NormalizedAST.from_dict({
        "file_path": str(target), "language": language,
        "imports": [
            {"source": "first", "imported_symbols": ["run"],
             "aliases": [["dispatch", "run"]], "is_namespace": False, "line": 1},
            {"source": "second", "imported_symbols": ["run"], "is_namespace": False, "line": 2},
        ],
        "call_sites": [
            {"target": "dynamic", "line": 5, "args": {"value": "<expr>"}},
            {"target": "dispatch", "line": 3},
            {"target": "run", "line": 4},
        ],
        "metadata": metadata,
    })
    spec = {"imports": ["second", "first"],
            "calls": ["second.run", "first.run", {"name": "dynamic", "where": {"value": True}}],
            "decorators": ["first.run"]}
    before = tree.to_json(), json.dumps(spec)
    override = ("source reason" if language == "python" and supplied_source
                else "parser reason" if parser_comments
                else "source reason" if language == "python" else None)
    expected = [
        {"rule": "rule", "kind": kind, "pattern": pattern, "path": str(target), "line": line,
         "snippet": " ".join(lines[line - 1].split()) if line else "",
         "unknown": unknown, "override": reason}
        for kind, pattern, line, unknown, reason in [
            ("imports", "second", 2, False, None),
            ("imports", "first", 1, False, None),
            ("calls", "second.run", 4, False, override),
            ("calls", "first.run", 3, False, None),
            ("calls", "dynamic", 5, True, None),
            ("decorators", "first.run", 0, False, None),
        ]
    ]
    for _ in range(2):
        findings = evaluate_forbid_ast_structured(
            tree, spec, rule_id="rule", source=source if supplied_source else None,
        )
        assert json.dumps(findings) == json.dumps(expected)
        assert (tree.to_json(), json.dumps(spec)) == before


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


@pytest.fixture
def python_parse_calls(monkeypatch):
    calls = []

    def parse(source, filename="<unknown>", **kwargs):
        calls.append((source, filename))
        return ast.parse(source, filename=filename, **kwargs)

    # Replace only these modules' references; pytest and other AST users keep the real module.
    local_ast = SimpleNamespace(**vars(ast))
    local_ast.parse = parse
    monkeypatch.setattr(policy, "ast", local_ast)
    monkeypatch.setattr(python_driver, "ast", local_ast)
    monkeypatch.setattr(schema, "ast", local_ast)
    return calls


@pytest.mark.parametrize("input_kind", ["code", "utf8-file", "bom-file", "latin1-file", "crlf-file"])
def test_python_policy_parses_once_and_preserves_normalized_output(tmp_path, python_parse_calls, input_kind):
    source = (
        "# coding: utf-8\n"
        "import subprocess as sp\n"
        "from functools import lru_cache as cache\n"
        "__all__ = ['Worker']\n"
        "@decorate\n"
        "class Worker:\n"
        "    @cache(maxsize=16)\n"
        "    async def run(self, value):\n"
        "        sp.run('café', shell=True)  # aegis: allow[z-rule, a-rule] reviewed\n"
        "        return value + 1 if value < 16 else 0\n"
    )
    target = tmp_path / "fixture.py"
    if input_kind == "bom-file":
        target.write_bytes(b"\xef\xbb\xbf" + source.encode("utf-8"))
    elif input_kind == "latin1-file":
        source = source.replace("utf-8", "latin-1")
        target.write_bytes(source.encode("latin-1"))
    elif input_kind == "crlf-file":
        source = source.replace("\n", "\r\n")
        target.write_bytes(source.encode("utf-8"))
    elif input_kind == "utf8-file":
        target.write_bytes(source.encode("utf-8"))

    result = extract_normalized_ast(target, code=source if input_kind == "code" else None)

    assert python_parse_calls == [(source, str(target))]
    expected = parse_python_ast(source, file_path=str(target)).to_dict()
    expected["metadata"].update({
        "decorators": ["decorate", "cache"],
        "allow_comments": {9: [{"rules": ["a-rule", "z-rule"], "reason": "reviewed"}]},
    })
    assert result.to_dict() == expected
    findings = evaluate_forbid_ast_structured(
        result, {"calls": ["subprocess.run"], "decorators": ["functools.lru_cache"]},
        rule_id="a-rule", source=source,
    )
    assert [(f["kind"], f["override"], f["unknown"]) for f in findings] == [
        ("calls", "reviewed", False), ("decorators", None, False),
    ]


@pytest.mark.parametrize("from_file", [False, True], ids=["source", "path"])
def test_python_parsing_wrapper_still_parses_once(tmp_path, python_parse_calls, from_file):
    target = tmp_path / "wrapper.py"
    source = "import os\nos.getcwd()\n"
    target.write_bytes(source.encode("utf-8"))

    result = parse_python_ast(target) if from_file else parse_python_ast(source, file_path=str(target))

    assert python_parse_calls == [(source, str(target))]
    assert result.file_path == str(target)
    assert [site.target for site in result.call_sites] == ["os.getcwd"]


@pytest.mark.parametrize("entrypoint", ["driver", "policy"])
@pytest.mark.parametrize("source", ["def (:\n", "  unexpected()\n"], ids=["syntax", "indentation"])
def test_python_parse_errors_keep_exact_wrapping(entrypoint, source, python_parse_calls):
    path = "broken.py"
    with pytest.raises(SyntaxError) as syntax:
        ast.parse(source, filename=path)

    if entrypoint == "driver":
        error_type = ValueError
        message = f"Failed to parse Python AST for {path}: {syntax.value}"
        extract = lambda: parse_python_ast(source, file_path=path)
    else:
        error_type = ASTExtractionError
        message = f"cannot verify {path}: {type(syntax.value).__name__}: {syntax.value}"
        extract = lambda: extract_normalized_ast(path, code=source)

    with pytest.raises(error_type) as error:
        extract()

    assert str(error.value) == message
    assert type(error.value.__cause__) is type(syntax.value)
    assert str(error.value.__cause__) == str(syntax.value)
    assert python_parse_calls == [(source, path)]
    if entrypoint == "policy":
        assert error.value.code == "AST_UNVERIFIABLE"


@pytest.mark.parametrize("entrypoint", ["driver", "policy"])
def test_python_unsafe_encoding_is_refused_before_parsing(tmp_path, python_parse_calls, entrypoint):
    target = tmp_path / "unsafe.py"
    target.write_bytes(b"# coding: utf-7\nimport os\n")
    reason = "source encoding 'utf-7' does not decode ASCII to itself"

    with pytest.raises(UnicodeError if entrypoint == "driver" else ASTExtractionError) as error:
        if entrypoint == "driver":
            parse_python_ast(target)
        else:
            extract_normalized_ast(target)

    assert str(error.value) == (reason if entrypoint == "driver" else f"cannot verify {target}: UnicodeError: {reason}")
    assert python_parse_calls == []
    if entrypoint == "policy":
        assert error.value.code == "AST_UNVERIFIABLE"
        assert type(error.value.__cause__) is UnicodeError


@pytest.mark.parametrize("working_tree", [
    "def plain():\n    pass\n",
    "@forbidden.deco\ndef plain():\n    pass\n",
    "def (:\n",
    None,
], ids=["plain", "decorated", "broken", "missing"])
@pytest.mark.parametrize("roundtrip", [False, True], ids=["parsed", "serialized"])
def test_python_decorator_free_supplied_text_is_authoritative(
    tmp_path, python_parse_calls, working_tree, roundtrip,
):
    target = tmp_path / "staged.py"
    if working_tree is not None:
        target.write_bytes(working_tree.encode("utf-8"))
    staged = "def plain():\n    pass\n"
    tree = extract_normalized_ast(target, code=staged)
    if roundtrip:
        tree = NormalizedAST.from_json(tree.to_json())

    for forbidden in (["forbidden.deco"], ["another.deco"]):
        assert evaluate_forbid_ast_structured(tree, {"decorators": forbidden}, source=staged) == []
    assert tree.decorators == ()
    assert python_parse_calls == [(staged, str(target))]
    assert tree.to_dict()["metadata"]["decorators"] == []


def test_python_decorator_free_file_evaluation_never_reparses(tmp_path, python_parse_calls):
    target = tmp_path / "plain.py"
    source = "def plain():\n    pass\n"
    target.write_bytes(source.encode("utf-8"))
    tree = extract_normalized_ast(target)

    for forbidden in (["forbidden.deco"], ["another.deco"]):
        assert evaluate_forbid_ast_structured(tree, {"decorators": forbidden}) == []
    assert python_parse_calls == [(source, str(target))]


@pytest.mark.parametrize("endings", [
    ("\r", "\r", "\r", "\r"),
    ("\r", "\r\n", "\n", "\r"),
    ("\r\n", "\r", "\r", "\n"),
], ids=["cr-only", "mixed-cr-first", "mixed-crlf-first"])
def test_python_allow_comments_use_parser_line_numbers(endings):
    lines = [
        "# coding: utf-8",
        "import subprocess",
        'subprocess.run("ls", shell=True) # aegis: allow[rule] reviewed',
        'subprocess.run("pwd", shell=True)',
    ]
    source = "".join(line + ending for line, ending in zip(lines, endings))
    tree = extract_normalized_ast("cr.py", code=source)
    assert parse_allow_comments(source) == {3: [{"rules": {"rule"}, "reason": "reviewed"}]}
    assert tree.metadata["allow_comments"] == {3: [{"rules": ["rule"], "reason": "reviewed"}]}
    for text in (None, source):
        findings = evaluate_forbid_ast_structured(
            tree, {"calls": ["subprocess.run"]}, rule_id="rule", source=text,
        )
        assert [(f["line"], f["override"]) for f in findings] == [(3, "reviewed"), (4, None)]
        assert evaluate_forbid_ast_structured(
            tree, {"calls": ["subprocess.run"]}, rule_id="other", source=text,
        )[0]["override"] is None
