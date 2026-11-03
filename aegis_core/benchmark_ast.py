"""Matched AST source fixtures and optional measurements; no performance acceptance claim.

Native Python and JS/TS parsers have language-specific extraction witnesses.
Unavailable implementations and legacy parsers are never timed.
"""
from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import PurePosixPath

from aegis_core.primitives import safe_parts, strict_loads

__all__ = ["ASTBenchmarkError", "LANGUAGES", "SIZES", "load_corpus", "check_witness", "measure"]

LANGUAGES = {"python": ".py", "typescript": ".ts", "javascript": ".js", "go": ".go", "rust": ".rs"}
SIZES = [300, 600, 1200, 2500, 5000]


class ASTBenchmarkError(ValueError):
    """The corpus or parser cannot provide an honest measurement."""


def _digest(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _expand(language, spec, size):
    count, remainder = divmod(size - len(spec["header"].splitlines()), len(spec["block"].splitlines()))
    source = spec["header"] + "".join(spec["block"].replace("__ID__", str(i)) for i in range(count))
    source += ("# remainder\n" if language == "python" else "// remainder\n") * remainder
    return {"language": language, "lines": size, "path": spec["path"], "source": source}


def load_corpus(raw=None):
    """Read and validate the packaged manifest, or explicit fixture bytes, before expansion."""
    if raw is None:
        try:
            raw = importlib.resources.files("aegis_core").joinpath("benchmark_corpus").joinpath("ast.json").read_bytes()
        except OSError as exc:
            raise ASTBenchmarkError("AST benchmark corpus is missing: " + str(exc)) from exc
    try:
        data = strict_loads(raw)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ASTBenchmarkError("AST benchmark corpus is invalid JSON: " + str(exc)) from exc
    keys = {"v", "name", "sizes", "languages", "sha256"}
    if (not isinstance(data, dict) or set(data) != keys or type(data["v"]) is not int or data["v"] != 1 or
            data["name"] != "aegis-ast-matched-v1"):
        raise ASTBenchmarkError("AST benchmark corpus has an unknown layout")
    if data["sizes"] != SIZES or any(type(size) is not int for size in data["sizes"]):
        raise ASTBenchmarkError("AST benchmark corpus has invalid sizes")
    languages = data["languages"]
    if not isinstance(languages, dict) or set(languages) != set(LANGUAGES):
        raise ASTBenchmarkError("AST benchmark corpus has invalid languages")
    cases = []
    for language, spec in sorted(languages.items()):
        if not isinstance(spec, dict) or set(spec) != {"path", "header", "block"}:
            raise ASTBenchmarkError("AST benchmark corpus has an invalid source block layout")
        if safe_parts(spec["path"], windows=True) is None:
            raise ASTBenchmarkError("AST benchmark corpus has an unsafe path")
        if PurePosixPath(spec["path"]).suffix != LANGUAGES[language]:
            raise ASTBenchmarkError("AST benchmark corpus has a mismatched extension")
        for key in ("header", "block"):
            text = spec[key]
            if (not isinstance(text, str) or not text.endswith("\n") or
                    any(c in text for c in "\r\v\f\x85\u2028\u2029") or
                    not 1 <= len(text.splitlines()) <= 30):
                raise ASTBenchmarkError("AST benchmark corpus has an invalid " + key + " source block")
        if "__ID__" not in spec["block"]:
            raise ASTBenchmarkError("AST benchmark corpus source block lacks an identifier")
        cases.extend(_expand(language, spec, size) for size in SIZES)
    digest = _digest(cases)
    if not isinstance(data["sha256"], str) or data["sha256"] != digest:
        raise ASTBenchmarkError("AST benchmark corpus digest mismatch")
    for case in cases:
        case["sha256"] = _digest(case)
        spec = languages[case["language"]]
        case["blocks"] = (case["lines"] - len(spec["header"].splitlines())) // len(spec["block"].splitlines())
    return {"name": data["name"], "sha256": digest, "cases": cases}


def check_witness(parsed, language="python"):
    """Require recognizable extraction, including the import alias and its source-spelled calls."""
    source, names = ({"python": ("json", ("dumps", "loads")), "rust": ("std::cmp", ("max", "min"))}
                     .get(language, ("querystring", ("stringify", "parse"))))
    separator = '::' if language == 'rust' else '.'
    if (getattr(parsed, "language", None) != language or
            "transform_0" not in {d.name for d in parsed.definitions} or
            source not in {i.source for i in parsed.imports} or
            not any(("codec", source) in i.aliases for i in parsed.imports) or
            not {"codec" + separator + name for name in names} <= {c.target for c in parsed.call_sites}):
        raise ASTBenchmarkError(language + " extraction witness failed")
    return {"definitions": len(parsed.definitions), "imports": len(parsed.imports), "calls": len(parsed.call_sites)}


def measure(language, runs, *, clock, summarize):
    """Time source parsing after an untimed witnessed warm-up; file I/O is excluded."""
    if not isinstance(language, str) or language not in LANGUAGES:
        raise ASTBenchmarkError("unknown AST benchmark language: " + str(language))
    if language not in ("python", "typescript", "javascript", "rust"):
        raise ASTBenchmarkError(language + " native parser implementation unavailable")
    if type(runs) is not int or not 1 <= runs <= 1000:
        raise ASTBenchmarkError("AST benchmark runs must be a whole number from 1 to 1000")
    from aegis_core.ast.driver_errors import ASTDriverError
    if language == "python":
        from aegis_core.ast.drivers.python import parse_python_ast as parse
    elif language == 'rust':
        from aegis_core.ast.drivers.rust import parse
    else:
        from aegis_core.ast.drivers.js import parse

    corpus = load_corpus()
    rows = []
    for case in corpus["cases"]:
        if case["language"] != language:
            continue
        source, path = case["source"], case["path"]
        try:
            check_witness(parse(source, path), language)
            timings = []
            for _ in range(runs):
                start = clock()
                parsed = parse(source, path)
                elapsed = clock() - start
                witness = check_witness(parsed, language)
                timings.append(elapsed)
        except (ValueError, OSError, ASTDriverError) as exc:
            raise ASTBenchmarkError("AST benchmark parsing failed: " + str(exc)) from exc
        latency = summarize(timings)
        rows.append({"lines": case["lines"], "path": path, "sha256": case["sha256"], "runs": runs,
                     "latency_ms": latency, "ms_per_line": round(latency["p50"] / case["lines"], 9),
                     "witness": witness})
    implementation = 'python-stdlib-ast' if language == 'python' else 'aegis-native-rust' if language == 'rust' else 'aegis-native-js'
    return {"language": language, "implementation": implementation, "corpus_sha256": corpus["sha256"],
            "mode": "in-process source parsing; I/O excluded; untimed witnessed warm-up",
            "acceptance": "not evaluated", "cases": rows}
