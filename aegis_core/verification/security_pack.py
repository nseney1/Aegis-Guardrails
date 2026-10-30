"""First-party Python AST security rule pack and delta-aware evaluator (v4.3 T7)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from aegis_core.ast.policy import (
    ASTExtractionError,
    _new_findings,
    evaluate_forbid_ast_structured,
    extract_normalized_ast,
)
from aegis_core.ast.source import decode_python_source
from aegis_core.match import is_test_path, workspace_files

__all__ = ["evaluate_security_pack"]

_REQ_METHODS = ("request", "get", "post", "put", "delete", "head", "options", "patch")
_SUB_FUNCS = ("run", "Popen", "call", "check_call", "check_output")


def _rule(rid: str, name: str, description: str, calls: List[Any]) -> Dict[str, Any]:
    # enforcement is read by rule_integrity's weakening levels: it is not decoration.
    return {
        "id": rid, "name": name, "severity": "high", "enforcement": "gate", "domain": "security",
        "description": description, "forbid_ast": {"calls": calls},
    }


PYTHON_SECURITY_RULES: List[Dict[str, Any]] = [
    _rule("sec-py-eval-exec", "Forbid Builtin eval and exec",
          "Disallow builtin eval() and exec() calls to prevent arbitrary code execution.",
          [{"name": "eval", "builtin": True}, {"name": "exec", "builtin": True}]),
    _rule("sec-py-pickle-loads", "Forbid Unsafe Deserialization (pickle/marshal)",
          "Disallow pickle and marshal load/loads on untrusted data.",
          ["pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "_pickle.loads", "_pickle.load"]),
    _rule("sec-py-yaml-unsafe-load", "Forbid Unsafe YAML Load",
          "Disallow yaml.unsafe_load, yaml.full_load, and yaml.load without SafeLoader/CSafeLoader/BaseLoader.",
          ["yaml.unsafe_load", "yaml.full_load", {"name": "yaml.load", "where": {"Loader|#1": {"not": {"in": ["SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"]}}}}]),
    _rule("sec-py-subprocess-shell", "Forbid Shell Execution in subprocess and os",
          "Disallow os.system, os.popen, and subprocess calls with shell=True.",
          ["os.system", "os.popen", *({"name": f"subprocess.{fn}", "where": {"shell": True}} for fn in _SUB_FUNCS)]),
    _rule("sec-py-weak-hash-md5-sha1", "Forbid Weak Hash Algorithms (MD5/SHA1)",
          "Disallow hashlib.md5, hashlib.sha1, and hashlib.new('md5'|'sha1') unless usedforsecurity=False.",
          [{"name": "hashlib.md5", "where": {"usedforsecurity": {"not": False}}},
           {"name": "hashlib.sha1", "where": {"usedforsecurity": {"not": False}}},
           {"name": "hashlib.new", "where": {"name|#0": {"in": ["md5", "sha1", "MD5", "SHA1"]}, "usedforsecurity": {"not": False}}}]),
    _rule("sec-py-tempfile-mktemp", "Forbid Insecure tempfile.mktemp",
          "Disallow tempfile.mktemp() due to race conditions; use NamedTemporaryFile or mkstemp.",
          ["tempfile.mktemp"]),
    # Bare method names: a Session's s.get(..., verify=False) is the same call; the literal
    # verify=False keeps dict.get and friends out.
    _rule("sec-py-requests-verify-false", "Forbid Disabling TLS Verification in requests",
          "Disallow verify=False in requests HTTP calls.",
          [{"name": m, "where": {"verify": False}} for m in _REQ_METHODS]),
]


def _record(finding: Mapping[str, Any], rel_path: str, rule: Mapping[str, Any]) -> Dict[str, Any]:
    return {"rule_id": finding["rule"], "file": rel_path, "line": finding["line"], "kind": finding["kind"],
            "pattern": finding["pattern"], "snippet": finding["snippet"], "severity": rule["severity"]}


def evaluate_security_pack(
    workspace_root: Union[str, Path], changed_files: Iterable[str], base_sources: Mapping[str, Optional[Union[str, bytes]]],
) -> Dict[str, Any]:
    """The pack's findings in what ``changed_files`` introduce over ``base_sources`` (each path's
    source text or bytes at the base, read through gitsafe; None or absent: a new file).

    Every changed Python file inside the workspace is evaluated, reported unverified (one
    ``kind: "file"`` record when it cannot be read or parsed) or absent (deleted), never
    skipped as clean. Test files are reported in ``exempted_test_findings``."""
    root = Path(workspace_root).resolve()
    violations: List[Dict[str, Any]] = []
    exempted_test_findings: List[Dict[str, Any]] = []
    unverified_findings: List[Dict[str, Any]] = []
    for rel_path in sorted(f for f in workspace_files(root, changed_files) if f.endswith(".py")):
        full_path = root.joinpath(*rel_path.split("/"))
        if not full_path.is_file():
            continue
        try:
            head_ast = extract_normalized_ast(str(full_path), workspace_root=str(root))
        except ASTExtractionError as exc:  # exc.reason: str(exc) names the absolute path
            unverified_findings.append({"rule_id": "", "file": rel_path, "line": 0, "kind": "file",
                                        "status": "unverified", "reason": exc.reason, "severity": "high"})
            continue
        base_text = base_sources.get(rel_path)
        try:
            base_text = decode_python_source(base_text) if isinstance(base_text, bytes) else base_text
            base_ast = extract_normalized_ast(rel_path, code=base_text) if base_text is not None else None
        except (ASTExtractionError, SyntaxError, UnicodeError):
            base_ast = None  # a base that does not parse accounts for nothing: every head finding is new
        is_test = is_test_path(rel_path)
        for rule in PYTHON_SECURITY_RULES:
            rid, spec = rule["id"], rule["forbid_ast"]
            head = evaluate_forbid_ast_structured(head_ast, spec, rule_id=rid)
            base = evaluate_forbid_ast_structured(base_ast, spec, rule_id=rid, source=base_text) if base_ast is not None else None
            for hit in _new_findings(head, base):
                (exempted_test_findings if is_test else violations).append(_record(hit, rel_path, rule))
            if not is_test:
                unverified_findings.extend(dict(_record(f, rel_path, rule), status="unverified")
                                           for f in head if f["unknown"] and f["override"] is None)
    return {"passed": not violations, "violations": violations, "exempted_test_findings": exempted_test_findings,
            "unverified_findings": unverified_findings}
