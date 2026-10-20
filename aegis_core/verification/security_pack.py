"""First-party Python AST security rule pack and delta-aware evaluator (v4.3 T7)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from aegis_core import gitsafe
from aegis_core.ast.policy import (
    ASTExtractionError,
    evaluate_forbid_ast_delta,
    evaluate_forbid_ast_structured,
    extract_normalized_ast,
)
from aegis_core.ast.schema import NormalizedAST
from aegis_core.match import is_test_path as _match_is_test_path
from aegis_core.packs import PACK_VERSION, bundle_digest, text_digest
from aegis_core.yaml_engine.serializer import dump_frontmatter

__all__ = ["PYTHON_SECURITY_RULES", "build_python_security_pack", "evaluate_security_pack", "is_test_path"]

_REQ_METHODS = ("request", "get", "post", "put", "delete", "head", "options", "patch")
_SUB_FUNCS = ("run", "Popen", "call", "check_call", "check_output")
_XML_CALLS = [
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.iterparse",
    "xml.etree.ElementTree.XMLParser", "xml.etree.cElementTree.parse", "xml.etree.cElementTree.fromstring",
    "xml.etree.cElementTree.iterparse", "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser",
]
_SKIP_DIRS = frozenset({".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules", ".tox", ".mypy_cache", ".pytest_cache"})


def _rule(rid: str, name: str, description: str, calls: List[Any]) -> Dict[str, Any]:
    return {
        "id": rid, "name": name, "tier": "invariant", "severity": "high",
        "enforcement": "gate", "domain": "security", "description": description,
        "forbid_ast": {"calls": calls},
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
    _rule("sec-py-xml-etree", "Forbid Vulnerable stdlib XML Parsers",
          "Disallow vulnerable stdlib XML parsers (xml.etree, minidom, sax); prefer defusedxml.",
          _XML_CALLS),
    _rule("sec-py-weak-hash-md5-sha1", "Forbid Weak Hash Algorithms (MD5/SHA1)",
          "Disallow hashlib.md5, hashlib.sha1, and hashlib.new('md5'|'sha1') unless usedforsecurity=False.",
          [{"name": "hashlib.md5", "where": {"usedforsecurity": {"not": False}}},
           {"name": "hashlib.sha1", "where": {"usedforsecurity": {"not": False}}},
           {"name": "hashlib.new", "where": {"name|#0": {"in": ["'md5'", "'sha1'"]}, "usedforsecurity": {"not": False}}}]),
    _rule("sec-py-tempfile-mktemp", "Forbid Insecure tempfile.mktemp",
          "Disallow tempfile.mktemp() due to race conditions; use NamedTemporaryFile or mkstemp.",
          ["tempfile.mktemp"]),
    _rule("sec-py-requests-verify-false", "Forbid Disabling TLS Verification in requests",
          "Disallow verify=False in requests HTTP calls.",
          [{"name": f"requests.{m}", "where": {"verify": False}} for m in _REQ_METHODS]),
]


def is_test_path(rel_path: str) -> bool:
    return _match_is_test_path(rel_path)


def build_python_security_pack() -> Dict[str, Any]:
    rules: List[Dict[str, str]] = []
    for r in sorted(PYTHON_SECURITY_RULES, key=lambda item: item["id"]):
        meta = {k: r[k] for k in ("id", "name", "severity", "enforcement", "domain", "description", "forbid_ast")}
        text = dump_frontmatter({**meta, "type": "invariant"}, f"# {r['name']}\n\n{r['description']}\n")
        rules.append({"path": f"invariants/{r['id']}.md", "text": text, "sha256": text_digest(text)})
    return {"v": PACK_VERSION, "rules": rules, "sha256": bundle_digest(rules)}


def _load_base_ast(root_str: str, rel_path: str, base_ref: Any, base_map: Optional[Mapping[str, str]]) -> Optional[NormalizedAST]:
    code: Optional[str] = None
    if base_map is not None and rel_path in base_map:
        code = base_map[rel_path]
    elif isinstance(base_ref, (str, Path)) and os.path.isdir(str(base_ref)):
        cand = Path(base_ref) / rel_path
        code = cand.read_text(encoding="utf-8", errors="replace") if cand.is_file() else None
    elif isinstance(base_ref, str) and base_ref.strip():
        try:
            res = gitsafe.run(["show", f"{base_ref.strip()}:{rel_path}"], root_str)
            code = res.stdout.decode("utf-8", "replace") if res.returncode == 0 else None
        except Exception:
            code = None
    if code is None:
        return None
    try:
        return extract_normalized_ast(rel_path, code=code)
    except ASTExtractionError:
        return None


def evaluate_security_pack(
    workspace_root: Union[str, Path],
    base_ref: Optional[Union[str, Path, Mapping[str, str]]] = None,
    changed_files: Optional[Iterable[str]] = None,
    *,
    base_sources: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    root_str = str(Path(workspace_root).resolve())
    base_map = base_ref if isinstance(base_ref, Mapping) else base_sources
    if changed_files is not None:
        rel_files = sorted({f.replace("\\", "/").lstrip("./") for f in changed_files if f.endswith(".py")})
    else:
        rel_files = []
        for dirpath, dirnames, filenames in os.walk(root_str):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel_files.extend(os.path.relpath(os.path.join(dirpath, fn), root_str).replace("\\", "/") for fn in filenames if fn.endswith(".py"))
        rel_files.sort()

    violations: List[Dict[str, Any]] = []
    exempted_test_findings: List[Dict[str, Any]] = []
    unverified_findings: List[Dict[str, Any]] = []
    for rel_path in rel_files:
        full_path = os.path.join(root_str, rel_path)
        if not os.path.isfile(full_path):
            continue
        try:
            head_ast = extract_normalized_ast(full_path, workspace_root=root_str)
        except ASTExtractionError:
            continue
        if head_ast is None:
            continue
        base_ast = _load_base_ast(root_str, rel_path, base_ref, base_map) if (base_ref is not None or base_map is not None) else None
        is_test = is_test_path(rel_path)
        for rule in PYTHON_SECURITY_RULES:
            rid, spec = rule["id"], rule["forbid_ast"]
            for hit in evaluate_forbid_ast_delta(spec, head_ast, base_ast, rule_id=rid):
                (exempted_test_findings if is_test else violations).append({**hit, "file": rel_path, "severity": rule["severity"]})
            if not is_test:
                _, unv = evaluate_forbid_ast_structured(head_ast, spec, rule_id=rid)
                unverified_findings.extend({**u, "file": rel_path, "severity": rule["severity"]} for u in unv)
    return {"passed": not violations, "violations": violations, "exempted_test_findings": exempted_test_findings, "unverified_findings": unverified_findings}
