"""Qualified policies keep the source of each locally bound import name."""
from __future__ import annotations

import pytest

from aegis_core.ast.policy import evaluate_forbid_ast, evaluate_forbid_ast_structured, extract_normalized_ast
from aegis_core.ast.schema import NormalizedAST


def _tree(source: str, representation: str) -> NormalizedAST:
    tree = extract_normalized_ast("origins.py", code=source)
    if representation == "json":
        return NormalizedAST.from_json(tree.to_json())
    if representation == "mapping":
        return NormalizedAST.from_dict(tree.to_dict())
    return tree


@pytest.mark.parametrize("representation", ["native", "json", "mapping"])
@pytest.mark.parametrize(
    "source, expected",
    [
        (
            'from posixpath import basename\nfrom ntpath import basename as WinBase\nbasename("x")\nWinBase("x")\n',
            {"posixpath.basename": [3], "ntpath.basename": [4]},
        ),
        (
            'from posixpath import basename\nfrom posixpath import basename as LocalBase\nbasename("x")\nLocalBase("x")\n',
            {"posixpath.basename": [3, 4], "ntpath.basename": []},
        ),
        (
            'import posixpath\nimport ntpath\nposixpath.basename("x")\nntpath.basename("x")\n',
            {"posixpath.basename": [3], "ntpath.basename": [4]},
        ),
        (
            'import posixpath as posix\nimport ntpath as win\nposix.basename("x")\nwin.basename("x")\n',
            {"posixpath.basename": [3], "ntpath.basename": [4]},
        ),
        (
            "import source_a as n\nfrom source_b import source_a\nn.run()\nsource_a.run()\n",
            {"source_b.source_a.run": [4]},
        ),
        (
            "from first import item as used\nfrom second import item as used\nused()\n",
            {"first.item": [3], "second.item": [3]},
        ),
        (
            "from subprocess import Popen as run, run\nrun([])\n",
            {"subprocess.Popen": [2], "subprocess.run": [2]},
        ),
        (
            "from subprocess import Popen as run, Popen as run\nrun([])\n",
            {"subprocess.Popen": [2], "subprocess.run": []},
        ),
    ],
    ids=["distinct-origins", "same-origin", "direct", "namespaces", "opaque-namespace",
         "conservative-rebinding", "surplus-plain-binding", "duplicate-alias-pairs"],
)
def test_call_findings_follow_the_bound_import(source, expected, representation):
    tree = _tree(source, representation)
    findings = evaluate_forbid_ast_structured(tree, {"calls": list(expected)}, source=source)
    actual = {pattern: [f["line"] for f in findings if f["pattern"] == pattern] for pattern in expected}
    assert actual == expected


@pytest.mark.parametrize("representation", ["native", "json", "mapping"])
def test_duplicate_aliases_do_not_invent_a_plain_import(representation):
    source = "from subprocess import Popen as run, Popen as run\nrun([])\n"
    assert evaluate_forbid_ast(_tree(source, representation), {"imports": ["subprocess.run"]}) == []


@pytest.mark.parametrize("representation", ["native", "json", "mapping"])
def test_builtin_alias_keeps_its_own_origin(representation):
    source = ("from builtins import eval as real_eval\nfrom custom import eval as app_eval\n"
              "real_eval('x')\napp_eval('x')\n")
    findings = evaluate_forbid_ast_structured(
        _tree(source, representation), {"calls": [{"name": "eval", "builtin": True}]}, source=source,
    )
    assert [(f["pattern"], f["line"]) for f in findings] == [("eval", 3)]


@pytest.mark.parametrize("representation", ["native", "json", "mapping"])
@pytest.mark.parametrize("bound, expected", [("first_marker", "first.marker"), ("second_marker", "second.marker")])
def test_decorator_alias_keeps_its_own_origin(bound, expected, representation):
    source = ("from first import marker as first_marker\nfrom second import marker as second_marker\n"
              f"@{bound}\ndef decorated():\n    pass\n")
    assert evaluate_forbid_ast(_tree(source, representation), {"decorators": ["first.marker", "second.marker"]}) == [
        f"Forbidden decorator '{expected}' matched rule forbid_ast.decorators",
    ]


def test_go_namespace_bindings_keep_their_normalized_driver_contract():
    # The public normalized contract emitted by the Go driver; no compiler is needed.
    tree = NormalizedAST.from_dict({
        "file_path": "origins.go", "language": "go",
        "imports": [
            {"source": "crypto/sha1", "imported_symbols": ["weak"], "aliases": [["weak", "crypto/sha1"]]},
            {"source": "crypto/sha256", "imported_symbols": ["strong"], "aliases": [["strong", "crypto/sha256"]]},
        ],
        "call_sites": [{"target": "weak.New", "line": 3}, {"target": "strong.New", "line": 4}],
    })
    findings = evaluate_forbid_ast_structured(tree, {"calls": ["crypto/sha1.New", "crypto/sha256.New"]}, source="")
    assert [(f["pattern"], f["line"]) for f in findings] == [("crypto/sha1.New", 3), ("crypto/sha256.New", 4)]


@pytest.mark.parametrize('representation', ['native', 'json', 'mapping'])
@pytest.mark.parametrize('source,pattern,count', [
    ("from copy import copy as cp; cp('member')", 'copy.copy', 1),
    ("import copy as cp; cp('namespace')", 'copy.copy', 0),
    ("from copy import copy; copy('member')", 'copy.copy', 1),
    ("import copy; copy('namespace')", 'copy.copy', 0),
    ("import copy as cp; cp.copy('member')", 'copy.copy', 1),
    ("from copy import copy as cp; cp.copy('child')", 'copy.copy.copy', 1),
])
def test_python_same_named_members_and_namespaces_keep_distinct_origins(source, pattern, count, representation):
    tree = _tree(source, representation)
    findings = evaluate_forbid_ast_structured(tree, {'calls': [pattern]}, source=source)
    assert len(findings) == count
    assert all(finding['unknown'] is False for finding in findings)


@pytest.mark.parametrize('representation', ['native', 'json', 'mapping'])
@pytest.mark.parametrize('source', [
    "import ns, {copy as cp} from 'copy'; ns('namespace'); cp('member');",
    "import ns, {copy} from 'copy'; ns('namespace'); copy('member');",
    "import * as ns from 'copy'; ns('namespace'); ns.copy('member');",
])
def test_js_same_named_members_and_namespaces_keep_distinct_origins(source, representation):
    from aegis_core.ast.drivers.js import parse

    tree = parse(source, 'origins.js')
    if representation == 'json':
        tree = NormalizedAST.from_json(tree.to_json())
    elif representation == 'mapping':
        tree = NormalizedAST.from_dict(tree.to_dict())
    for value, count in [('namespace', 0), ('member', 1)]:
        findings = evaluate_forbid_ast_structured(
            tree, {'calls': [{'name': 'copy.copy', 'where': {'#0': value}}]}, source=source)
        assert len(findings) == count
        assert all(finding['unknown'] is False for finding in findings)
