"""Optional AST source benchmarks preserve the default and never time unavailable parsers."""
import hashlib
import importlib.resources
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_cli.cli import main
from aegis_core import benchmark, events
from aegis_core.ast.schema import NormalizedAST

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "aegis_core/benchmark_corpus/ast.json"
SIZES = [300, 600, 1200, 2500, 5000]
AST_SHA256 = "34fe5d8b9cf92237421c0d2ea9f86fa328d606f4caf5e33fc68dc2becaff86b8"


class Ticks:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.calls * 0.002


def test_matched_corpus_expands_deterministically_with_case_digests():
    from aegis_core import benchmark_ast

    corpus = benchmark_ast.load_corpus()
    assert corpus == benchmark_ast.load_corpus()
    assert corpus["sha256"] == json.loads(MANIFEST.read_text())["sha256"] == AST_SHA256
    assert len(corpus["cases"]) == 25
    for case in corpus["cases"]:
        assert len(case["source"].splitlines()) == case["lines"]
        assert case["lines"] in SIZES and "__ID__" not in case["source"]
        content = {key: case[key] for key in ("language", "lines", "path", "source")}
        expected = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=True).encode("ascii")).hexdigest()
        assert case["sha256"] == expected
    groups = {language: [c["blocks"] for c in corpus["cases"] if c["language"] == language]
              for language in ("python", "typescript", "javascript", "go", "rust")}
    assert all(counts == groups["python"] for counts in groups.values())


@pytest.mark.parametrize("kind,reason", [("path", "unsafe path"), ("digest", "digest mismatch"),
    ("layout", "unknown layout"), ("size", "sizes"), ("block", "source block"),
    ("extension", "extension"), ("header", "header"), ("language", "languages")])
def test_damaged_manifest_is_rejected_before_measurement(kind, reason):
    from aegis_core import benchmark_ast

    data = json.loads(MANIFEST.read_text())
    if kind == "path": data["languages"]["python"]["path"] = "../escape.py"
    elif kind == "digest": data["sha256"] = "0" * 64
    elif kind == "layout": data["extra"] = True
    elif kind == "size": data["sizes"][0] = True
    elif kind == "block": data["languages"]["python"]["block"] = ""
    elif kind == "extension": data["languages"]["python"]["path"] = "src/sample.rs"
    elif kind == "header": data["languages"]["python"]["header"] = 7
    else: del data["languages"]["rust"]
    with pytest.raises(benchmark_ast.ASTBenchmarkError, match=reason):
        benchmark_ast.load_corpus(json.dumps(data).encode())


@pytest.mark.parametrize("raw", [b"not json", b"\xff", b'{"v":1,"v":1}', b"[]"])
def test_invalid_manifest_bytes_have_a_clear_error(raw):
    from aegis_core import benchmark_ast

    with pytest.raises(benchmark_ast.ASTBenchmarkError, match="AST benchmark corpus"):
        benchmark_ast.load_corpus(raw)


def test_python_source_timings_use_real_extraction_and_exclude_io():
    from aegis_core import benchmark_ast

    clock = Ticks()
    result = benchmark_ast.measure("python", 2, clock=clock, summarize=benchmark.summarize)
    assert result["language"] == "python" and result["implementation"] == "python-stdlib-ast"
    assert "I/O excluded" in result["mode"] and result["acceptance"] == "not evaluated"
    assert [row["lines"] for row in result["cases"]] == SIZES
    assert clock.calls == 20  # five cases, two timed runs, two reads each; witness warm-up untimed
    for row in result["cases"]:
        assert row["latency_ms"] == {"p50": 2.0, "p95": 2.0, "min": 2.0, "max": 2.0}
        assert row["ms_per_line"] == round(2.0 / row["lines"], 9)
        assert row["witness"]["definitions"] > 0 and row["witness"]["imports"] > 0
        assert row["witness"]["calls"] > row["witness"]["definitions"]


@pytest.mark.parametrize("language", ["typescript", "javascript", "rust"])
def test_native_source_timings_use_real_extraction_and_matching_corpus(language):
    from aegis_core import benchmark_ast

    clock = Ticks()
    result = benchmark_ast.measure(language, 2, clock=clock, summarize=benchmark.summarize)
    assert result["language"] == language and result["implementation"] == ("aegis-native-rust" if language == "rust" else "aegis-native-js")
    assert result["corpus_sha256"] == AST_SHA256 and result["acceptance"] == "not evaluated"
    assert "I/O excluded" in result["mode"]
    assert clock.calls == 20
    assert [row["lines"] for row in result["cases"]] == SIZES
    for row in result["cases"]:
        assert row["latency_ms"] == {"p50": 2.0, "p95": 2.0, "min": 2.0, "max": 2.0}
        assert row["witness"]["imports"] > 0
        assert row["witness"]["calls"] > row["witness"]["definitions"] > 0


@pytest.mark.parametrize("language", ["typescript", "javascript"])
def test_invalid_native_js_with_valid_corpus_digest_is_a_benchmark_error(tmp_path, monkeypatch, language):
    from aegis_core import benchmark_ast

    data = json.loads(MANIFEST.read_text())
    # The native extractor is token-level: only lexical errors fail closed (spec 5.3.1, AC-5).
    old, malformed = "function transform_", "/* function transform_"
    data["languages"][language]["block"] = data["languages"][language]["block"].replace(old, malformed)
    cases = [{key: case[key] for key in ("language", "lines", "path", "source")}
             for case in benchmark_ast.load_corpus()["cases"]]
    for case in cases:
        if case["language"] == language:
            case["source"] = case["source"].replace(old, malformed)
    data["sha256"] = hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":"),
                                              ensure_ascii=True).encode("ascii")).hexdigest()
    resource = tmp_path / "benchmark_corpus"
    resource.mkdir()
    (resource / "ast.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(importlib.resources, "files", lambda package: tmp_path)
    with pytest.raises(benchmark_ast.ASTBenchmarkError, match="AST benchmark parsing failed"):
        benchmark_ast.measure(language, 1, clock=Ticks(), summarize=benchmark.summarize)


def test_invalid_python_with_a_valid_digest_is_a_clear_benchmark_error(tmp_path, monkeypatch):
    from aegis_core import benchmark_ast

    data = json.loads(MANIFEST.read_text())
    old, malformed = "def transform_", "def !transform_"
    data["languages"]["python"]["block"] = data["languages"]["python"]["block"].replace(old, malformed)
    cases = [{key: case[key] for key in ("language", "lines", "path", "source")}
             for case in benchmark_ast.load_corpus()["cases"]]
    for case in cases:
        if case["language"] == "python":
            case["source"] = case["source"].replace(old, malformed)
    data["sha256"] = hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":"),
                                              ensure_ascii=True).encode("ascii")).hexdigest()
    resource = tmp_path / "benchmark_corpus"
    resource.mkdir()
    (resource / "ast.json").write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(importlib.resources, "files", lambda package: tmp_path)
    assert benchmark_ast.load_corpus()["sha256"] == data["sha256"]
    with pytest.raises(benchmark.BenchmarkError, match="AST benchmark parsing failed"):
        benchmark.run_benchmark(1, ast_language="python")


@pytest.mark.parametrize("ast", [NormalizedAST(), NormalizedAST(language="rust"),
    NormalizedAST(definitions=["transform_0"], imports=["json"], calls=["unrelated"])])
def test_empty_or_wrong_extraction_cannot_supply_a_witness(ast):
    from aegis_core import benchmark_ast

    with pytest.raises(benchmark_ast.ASTBenchmarkError, match="python extraction witness failed"):
        benchmark_ast.check_witness(ast)


@pytest.mark.parametrize("language", ["typescript", "javascript"])
def test_empty_native_js_extraction_cannot_supply_a_witness(language):
    from aegis_core import benchmark_ast

    with pytest.raises(benchmark_ast.ASTBenchmarkError, match=language + " extraction witness failed"):
        benchmark_ast.check_witness(NormalizedAST(language=language), language)


def test_cli_selection_is_reported_and_recorded_without_changing_layer1(tmp_path, capsys):
    (tmp_path / ".aegis").mkdir()
    rc = main(["benchmark", "--workspace", str(tmp_path), "--runs", "1", "--ast-language", "python", "--json"])
    out = capsys.readouterr()
    assert (rc, out.err) == (0, "")
    doc = json.loads(out.out)
    assert doc["corpus"]["sha256"] == "87b60f1de624fdfbbb2ac2047845ec36d32ebb3f8c18636dbf56bc6ca55fc908"
    assert doc["layer1"]["files"] == 24 and doc["layer1"]["checks"] == 48
    assert doc["ast"]["language"] == "python" and len(doc["ast"]["cases"]) == 5
    assert "AST source parsing" in doc["measures"][-1]
    row, = events.read(tmp_path, "benchmark").rows
    assert row["detail"]["ast"] == doc["ast"]


@pytest.mark.parametrize("language", ["go"])
def test_unavailable_cli_selection_is_an_error_and_writes_no_event(tmp_path, capsys, language):
    (tmp_path / ".aegis").mkdir()
    rc = main(["benchmark", "--workspace", str(tmp_path), "--ast-language", language, "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 1 and doc["status"] == "error"
    assert doc["error"] == language + " native parser implementation unavailable"
    assert events.read(tmp_path).rows == []


@pytest.mark.parametrize("language", ["typescript", "javascript", "rust"])
def test_native_js_cli_selection_records_extraction_without_claiming_acceptance(tmp_path, capsys, language):
    (tmp_path / ".aegis").mkdir()
    rc = main(["benchmark", "--workspace", str(tmp_path), "--runs", "1", "--ast-language", language, "--json"])
    output = capsys.readouterr()
    assert rc == 0 and output.err == ""
    doc = json.loads(output.out)
    assert doc["ast"]["language"] == language and doc["ast"]["acceptance"] == "not evaluated"
    assert doc["ast"]["corpus_sha256"] == AST_SHA256
    row, = events.read(tmp_path, "benchmark").rows
    assert row["detail"]["ast"] == doc["ast"]


def test_default_run_never_imports_the_ast_benchmark_helper(tmp_path):
    script = ("import sys; from aegis_core import benchmark; benchmark.run_benchmark(1); "
              "assert 'aegis_core.benchmark_ast' not in sys.modules")
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          cwd=tmp_path, env=dict(os.environ, PYTHONPATH=os.pathsep.join(
                              [str(ROOT), os.environ.get("PYTHONPATH", "")])), timeout=30)
    assert proc.returncode == 0, proc.stderr
