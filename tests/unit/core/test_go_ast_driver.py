"""The packaged Go executable's public NDJSON protocol and normalized output."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from aegis_core.pathlookup import which
from aegis_core.ast.schema import NormalizedAST

TEMPLATES = Path(__file__).resolve().parents[3] / "aegis_core/ast/drivers/templates"


@pytest.fixture(scope="session")
def go_driver_binary(tmp_path_factory):
    """Compile once per focused session, with the packaged sources binding its key."""
    compiler = which("go", outside=TEMPLATES.parents[3])
    if compiler is None:
        pytest.skip("Go >=1.21 is required for the real packaged-driver checks")
    source = (TEMPLATES / "go_ast.go").read_bytes()
    module = (TEMPLATES / "go.mod").read_bytes()
    key = hashlib.sha256(source + module).hexdigest()
    build = tmp_path_factory.mktemp("go-driver") / key
    build.mkdir()
    (build / "go_ast.go").write_bytes(source)
    (build / "go.mod").write_bytes(module)
    binary = build / ("go_ast.exe" if os.name == "nt" else "go_ast")
    env = {**os.environ, "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off",
           "GOFLAGS": "", "GOENV": "off", "GO111MODULE": "on", "CGO_ENABLED": "0"}
    completed = subprocess.run([compiler, "build", "-trimpath", "-o", str(binary), "."],
                               cwd=build, env=env, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=120)
    assert completed.returncode == 0, completed.stderr
    return binary


def exchange(binary, requests):
    # Python 3.9 on Windows cannot reliably launch with an empty environment.
    env = {"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {}
    completed = subprocess.run([str(binary)], input="".join(json.dumps(r) + "\n" for r in requests),
                               capture_output=True, text=True, encoding="utf-8", timeout=10,
                               cwd=binary.parent, env=env)
    assert completed.returncode == 0, completed.stderr
    return [json.loads(line) for line in completed.stdout.splitlines()]


def test_real_go_driver_hello_and_multiple_parse(go_driver_binary, tmp_path):
    first, second = tmp_path / "first.go", tmp_path / "second.go"
    first.write_text("package fixture\nfunc First() { println(16) }\n", encoding="utf-8")
    second.write_text("package fixture\nfunc Second() { println(true) }\n", encoding="utf-8")

    replies = exchange(go_driver_binary, [
        {"aegis_ast": 2, "op": "hello"},
        {"op": "parse", "id": 1, "path": str(first)},
        {"op": "parse", "id": 2, "path": str(second)},
    ])

    assert replies[0] == {"aegis_ast": 2, "op": "hello", "driver": "go_ast",
                          "driver_version": "2.0.0", "languages": ["go"],
                          "capabilities": ["allow_comments", "args"]}
    assert [(r["id"], r["ok"], r["ast"]["file_path"]) for r in replies[1:]] == [
        (1, True, str(first)), (2, True, str(second))]
    assert [r["ast"]["call_sites"][0]["args"] for r in replies[1:]] == [
        {"#0": "16"}, {"#0": "True"}]


def parse_source(binary, directory, source):
    path = directory / "fixture.go"
    path.write_text(source, encoding="utf-8")
    return exchange(binary, [{"aegis_ast": 2, "op": "hello"},
                             {"op": "parse", "id": 1, "path": str(path)}])[1]


def test_import_bindings_calls_constructors_and_cross_argument_uncertainty(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
import tls "crypto/tls"
import ex "os/exec"
import _ "net/http/pprof"
import . "fmt"
var command = ex.Command("echo")
func Example() {
 ex.Command("sh", "-c", "echo hi")
 _ = &tls.Config{InsecureSkipVerify: true}
 sink(tls.Config{InsecureSkipVerify: true}, tls.Config{InsecureSkipVerify: false})
 client.Close()
}
''')

    assert response["ok"] is True
    ast = response["ast"]
    assert ast["version"] == "1.0"
    assert ast["metadata"]["capabilities"] == ["allow_comments", "args"]
    imports = {i["source"]: i for i in ast["imports"]}
    assert imports["os/exec"]["aliases"] == [["ex", "os/exec"]]
    assert imports["crypto/tls"]["aliases"] == [["tls", "crypto/tls"]]
    for path in ("net/http/pprof", "fmt"):
        assert imports[path]["imported_symbols"] == []
        assert imports[path].get("aliases", []) == []
    commands = [c for c in ast["call_sites"] if c["target"] == "os/exec.Command"]
    assert [c["args"] for c in commands] == [{"#0": repr("echo")},
                                              {"#0": repr("sh"), "#1": repr("-c"), "#2": repr("echo hi")}]
    assert commands[1]["caller_scope"] == "Example"
    constructs = [c for c in ast["call_sites"] if c["target"] == "crypto/tls.Config"]
    assert len(constructs) == 3
    assert constructs[0]["kind"] == "construct"
    assert constructs[0]["args"]["InsecureSkipVerify"] == "True"
    sink = next(c for c in ast["call_sites"] if c["target"] == "sink")
    assert sink["args"] == {"#0": "<expr>", "#1": "<expr>", "InsecureSkipVerify": "<expr>"}
    assert any(c["target"] == ".Close" for c in ast["call_sites"])
    normalized = NormalizedAST.from_dict(ast)
    assert normalized.language == "go"
    assert NormalizedAST.from_json(normalized.to_json()) == normalized


def test_default_import_name_heuristics_preserve_raw_source_spelling(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
import "example.test/go-widget-go.v2"
func Example() { widget.Danger() }
''')

    assert response["ok"] is True
    assert response["ast"]["imports"][0]["aliases"] == [["widget", "example.test/go-widget-go.v2"]]
    assert response["ast"]["call_sites"][0]["target"] == "example.test/go-widget-go.v2.Danger"


def test_local_and_parameter_shadowing_do_not_resolve_to_imports(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
import ex "os/exec"
type Client struct{}
func (Client) Command(command string) {}
func Imported() { ex.Command("real") }
func Parameter(ex Client) { ex.Command("parameter") }
func Local() { ex := Client{}; ex.Command("local") }
''')

    assert response["ok"] is True
    calls = {call["caller_scope"]: call["target"] for call in response["ast"]["call_sites"]
             if call["target"].endswith(".Command")}
    assert calls == {"Imported": "os/exec.Command", "Parameter": ".Command", "Local": ".Command"}
    from aegis_core.ast.policy import evaluate_forbid_ast_structured

    findings = evaluate_forbid_ast_structured(NormalizedAST.from_dict(response['ast']),
                                               {'calls': ['os/exec.Command']}, source='')
    assert [finding['line'] for finding in findings] == [5]
    methods = evaluate_forbid_ast_structured(NormalizedAST.from_dict(response['ast']),
                                             {'calls': ['.Command']}, source='')
    assert [finding['line'] for finding in methods] == [5, 6, 7]


@pytest.mark.parametrize("value", [
    "ab", "'", '"', "both '\" quotes", "\\escape", "\t\n\r", "\x00\x07\x08\x0b\x0c\x1b\x1f",
    "\x7f\x80\x85\x9f", "\xa0\u2000\u202f", "café Καλημέρα", "😀", "\u200b\u2028\u2029",
])
def test_strings_use_python_repr_and_round_trip_semantically(go_driver_binary, tmp_path, value):
    response = parse_source(go_driver_binary, tmp_path,
                            "package fixture\nfunc Example() { sink(" +
                            json.dumps(value, ensure_ascii=False) + ") }\n")

    assert response["ok"] is True
    rendered = response["ast"]["call_sites"][0]["args"]["#0"]
    assert ast.literal_eval(rendered) == value
    assert rendered == repr(value)


def test_literals_decode_and_preserve_numeric_types_and_precision(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, r'''package fixture
func Example() {
 sink(0, 0x0, 0_0, 16, 0x10, 1_000, 0b10000, 0o20, -16, +16, 0.5, 0x1p4, 0.1,
      1i, true, false, nil, "a\x62", "ab", `ab`, 'a', unknown)
}
''')

    assert response["ok"] is True
    args = response["ast"]["call_sites"][0]["args"]
    expected = ["0", "0", "0", "16", "16", "1000", "16", "16", "-16", "16", "0.5", "16",
                "<expr>", "<expr>", "True", "False", "None", repr("ab"), repr("ab"), repr("ab"), "97", "<expr>"]
    assert args == {f"#{i}": value for i, value in enumerate(expected)}


def test_unicode_controls_and_invalid_utf8_string_bytes(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, r'''package fixture
func Example() { sink("\u0061", "\n", "\xff", "\U0001f600") }
''')

    assert response["ok"] is True
    args = response["ast"]["call_sites"][0]["args"]
    assert args == {"#0": repr("a"), "#1": repr("\n"), "#2": "<expr>", "#3": repr("😀")}


def test_comments_come_from_comment_nodes_and_cannot_be_forged_by_strings(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
func Example() {
 sink(true) // aegis: allow[r1,r2] fixture
 /* aegis: allow[r3] block fixture */ sink(false)
 sink("// aegis: allow[forged] string")
 // aegis: allow blanket
 sink(true)
}
''')

    assert response["ok"] is True
    assert response["ast"]["metadata"]["allow_comments"] == {
        "3": [{"rules": ["r1", "r2"], "reason": "fixture"}],
        "4": [{"rules": ["r3"], "reason": "block fixture"}],
        "6": [{"rules": None, "reason": "blanket"}],
    }


def test_spreads_unkeyed_composites_and_unknown_fields_remain_unknown(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
func Example() {
 sink(values...)
 sink(Config{true})
 sink(map[string]bool{"shell": true})
}
''')

    assert response["ok"] is True
    calls = [c for c in response["ast"]["call_sites"] if c["target"] == "sink"]
    assert calls[0]["args"] == {"#0": "<expr>", "*": "<expr>"}
    assert calls[1]["args"] == {"#0": "<expr>", "**": "<expr>"}
    assert calls[2]["args"] == {"#0": "<expr>", "**": "<expr>"}


@pytest.mark.parametrize("source", [
    "package fixture\nfunc Example( {\n",
    "package fixture\nvar x = Config{Unsafe: true, Unsafe: false}\n",
    "package fixture\nvar x = map[string]int{\"x\": 1, \"x\": 2}\n",
    "package fixture\nvar x = 0xG\n",
])
def test_syntax_and_invalid_duplicate_fields_fail_closed(go_driver_binary, tmp_path, source):
    response = parse_source(go_driver_binary, tmp_path, source)

    assert response["ok"] is False
    assert response["error"]["kind"] == "syntax"
    assert response["error"]["line"] >= 1
    assert response["error"]["message"]


def test_io_failure_does_not_break_later_parse(go_driver_binary, tmp_path):
    valid = tmp_path / "valid.go"
    valid.write_text("package fixture\nfunc Valid() {}\n", encoding="utf-8")
    replies = exchange(go_driver_binary, [
        {"aegis_ast": 2, "op": "hello"},
        {"op": "parse", "id": 7, "path": str(tmp_path / "missing.go")},
        {"op": "parse", "id": 9, "path": str(valid)},
    ])

    assert replies[1]["id"] == 7
    assert replies[1]["ok"] is False
    assert replies[1]["error"]["kind"] == "io"
    assert replies[2]["id"] == 9
    assert replies[2]["ok"] is True


def test_source_size_limit_is_reasoned_and_next_file_still_parses(go_driver_binary, tmp_path):
    oversized, valid = tmp_path / "large.go", tmp_path / "valid.go"
    oversized.write_bytes(b"package fixture\n//" + b"x" * (8 * 1024 * 1024))
    valid.write_text("package fixture\n", encoding="utf-8")
    replies = exchange(go_driver_binary, [{"aegis_ast": 2, "op": "hello"},
        {"op": "parse", "id": 1, "path": str(oversized)},
        {"op": "parse", "id": 2, "path": str(valid)}])

    assert replies[1]["error"]["kind"] == "limit"
    assert replies[1]["ok"] is False
    assert replies[2]["ok"] is True
    assert all(len(json.dumps(reply).encode("utf-8")) <= 8 * 1024 * 1024 for reply in replies)


def test_bom_crlf_and_mutation_locations_round_trip(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path,
                            "\ufeffpackage fixture\r\nfunc Compare(a, b int) bool { return a == b }\r\n")

    assert response["ok"] is True
    ast = response["ast"]
    assert ast["definitions"][0]["name"] == "Compare"
    assert ast["definitions"][0]["line"] == 2
    assert ast["mutation_points"][0]["original_op"] == "=="
    assert ast["mutation_points"][0]["replacement_op"] == "!="
    assert NormalizedAST.from_dict(ast).mutation_points[0].line == 2


def test_empty_allow_directives_and_repeated_nonconstant_map_keys_are_valid(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
func Example(key string) {
 sink(true) // aegis: allow
 sink(false) // aegis: allow[]
 sink(map[string]int{key: 1, key: 2})
}
''')

    assert response["ok"] is True
    assert response["ast"]["metadata"]["allow_comments"] == {
        "3": [{"rules": None, "reason": ""}], "4": [{"rules": [], "reason": ""}]}


def test_response_larger_than_eight_mib_is_a_small_limit_error(go_driver_binary, tmp_path):
    # Raw Go backslashes expand in both Python repr and the JSON envelope.
    source = 'package fixture\nfunc Example() { sink(`' + "\\" * 2_200_000 + '`) }\n'
    assert len(source.encode("utf-8")) < 8 * 1024 * 1024
    response = parse_source(go_driver_binary, tmp_path, source)

    assert response["ok"] is False
    assert response["error"] == {"kind": "limit", "message": "response exceeds 8 MiB"}
    assert len(json.dumps(response).encode("utf-8")) < 1024


def test_shadowed_predeclared_names_are_unknown_while_unbound_names_are_literals(go_driver_binary, tmp_path):
    response = parse_source(go_driver_binary, tmp_path, '''package fixture
func Shadowed(true bool, false bool, nil any) { sink(true, false, nil) }
func Unbound() { sink(true, false, nil) }
''')

    assert response["ok"] is True
    calls = response["ast"]["call_sites"]
    assert calls[0]["caller_scope"] == "Shadowed"
    assert calls[0]["args"] == {"#0": "<expr>", "#1": "<expr>", "#2": "<expr>"}
    assert calls[1]["caller_scope"] == "Unbound"
    assert calls[1]["args"] == {"#0": "True", "#1": "False", "#2": "None"}
