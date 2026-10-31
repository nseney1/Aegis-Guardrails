"""First-party per-language security rules and delta-aware shared-session evaluation."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from aegis_core.ast.policy import (
    ASTExtractionError,
    _new_findings,
    evaluate_forbid_ast_structured,
    extract_normalized_ast,
    is_size_limit_error,
)
from aegis_core.ast.source import decode_python_source
from aegis_core.match import is_test_path, workspace_files
from aegis_core.primitives import is_within

__all__ = ["evaluate_security_pack", "SECURITY_RULES_BY_LANGUAGE", "PACK_EXTENSIONS"]

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


_SHELLS = ["sh", "bash", "zsh", "/bin/sh", "/bin/bash", "cmd", "cmd.exe", "powershell", "pwsh"]
JS_SECURITY_RULES = [
    _rule("sec-js-eval", "Forbid dynamic JavaScript execution", "Disallow eval, Function and VM execution.",
          [{"name": "eval", "builtin": True}, {"name": "Function", "builtin": True},
           *[f"vm.{name}" for name in ("runInThisContext", "runInNewContext", "runInContext", "compileFunction", "Script")]]),
    _rule("sec-js-child-process-shell", "Forbid child-process shells", "Disallow implicit and explicit shell execution.",
          ["child_process.exec", "child_process.execSync",
           *[{"name": f"child_process.{name}", "where": {"shell": True}}
             for name in ("spawn", "spawnSync", "execFile", "execFileSync")]]),
    _rule("sec-js-weak-hash", "Forbid weak hashes", "Disallow MD5 and SHA1 hashes.",
          [{"name": "crypto.createHash", "where": {"#0": {"in": ["md5", "sha1", "MD5", "SHA1"]}}}]),
    _rule("sec-js-tls-reject-unauthorized", "Require TLS certificate verification", "Disallow rejectUnauthorized false.",
          [{"name": name, "where": {"rejectUnauthorized": False}}
           for name in ("https.request", "https.get", "https.Agent", "tls.connect", "tls.createSecureContext")]),
    {**_rule("sec-js-node-serialize", "Forbid node-serialize", "Disallow unsafe node-serialize deserialization.", []),
     "forbid_ast": {"imports": ["node-serialize"]}},
]
GO_SECURITY_RULES = [
    _rule("sec-go-exec-shell", "Forbid shell commands", "Disallow shells invoked through os/exec.",
          [{"name": f"os/exec.{name}", "where": {position: {"in": _SHELLS}}}
           for name, position in (("Command", "#0"), ("CommandContext", "#1"))]),
    _rule("sec-go-weak-hash", "Forbid weak hashes", "Disallow MD5 and SHA1 hashes.",
          [f"crypto/{algorithm}.{name}" for algorithm in ("md5", "sha1") for name in ("New", "Sum")]),
    _rule("sec-go-tls-insecure", "Require TLS certificate verification", "Disallow InsecureSkipVerify true.",
          [{"name": "crypto/tls.Config", "where": {"InsecureSkipVerify": True}}]),
    _rule("sec-go-ssh-insecure-hostkey", "Require SSH host verification", "Disallow InsecureIgnoreHostKey.",
          ["golang.org/x/crypto/ssh.InsecureIgnoreHostKey"]),
]
RUST_SECURITY_RULES = [
    _rule("sec-rs-command-shell", "Forbid shell commands", "Disallow shells invoked through process::Command.",
          [{"name": "std::process::Command::new", "where": {"#0": {"in": _SHELLS}}}]),
    _rule("sec-rs-tls-danger", "Require TLS verification", "Disallow disabled certificate or hostname verification.",
          [{"name": f".{name}", "where": {"#0": True}}
           for name in ("danger_accept_invalid_certs", "danger_accept_invalid_hostnames")]),
    # Weak hashes are omitted: Git-compatible SHA1 failed the approved precision gate.

]
SECURITY_RULES_BY_LANGUAGE = {"python": PYTHON_SECURITY_RULES, "javascript": JS_SECURITY_RULES,
                            "typescript": JS_SECURITY_RULES, "go": GO_SECURITY_RULES, "rust": RUST_SECURITY_RULES}
_PACK_LANGUAGES = {".py": "python", ".go": "go", ".rs": "rust",
                   **{ext: "typescript" for ext in (".ts", ".tsx", ".mts", ".cts")},
                   **{ext: "javascript" for ext in (".js", ".jsx", ".mjs", ".cjs")}}
PACK_EXTENSIONS = frozenset(_PACK_LANGUAGES)


def _record(finding: Mapping[str, Any], rel_path: str, rule: Mapping[str, Any]) -> Dict[str, Any]:
    return {"rule_id": finding["rule"], "file": rel_path, "line": finding["line"], "kind": finding["kind"],
            "pattern": finding["pattern"], "snippet": finding["snippet"], "severity": rule["severity"]}


def _unverified_file(path: str, reason: str) -> dict[str, Any]:
    return {'rule_id': '', 'file': path, 'line': 0, 'kind': 'file',
            'status': 'unverified', 'reason': reason, 'severity': 'high'}


def _base_tree(rel_path: str, source: str | bytes | None, session: Any) -> tuple[Any, str | None]:
    """Parse bounded base bytes with the head's driver, without loading repository code."""
    if source is None:
        return None, None
    extension = Path(rel_path).suffix.lower()
    text = decode_python_source(source) if isinstance(source, bytes) and extension == '.py' else (
        source.decode('utf-8') if isinstance(source, bytes) else source)
    if extension != '.go':
        return extract_normalized_ast(rel_path, code=text), text
    from tempfile import TemporaryDirectory
    from aegis_core.ast.runner import SOURCE_LIMIT_BYTES, ASTDriverError
    from aegis_core.storage import atomic_write_bytes

    data = text.encode('utf-8')
    if len(data) > SOURCE_LIMIT_BYTES:
        raise ASTDriverError('base source exceeds 2 MiB', reason='too_large')
    with TemporaryDirectory(prefix='aegis-security-base-') as temporary:
        path = Path(temporary) / 'base.go'
        atomic_write_bytes(path, data)
        tree = session.runner.parse_file(path, workspace_root=session.workspace_root, confine_root=temporary)
    return tree, text


def evaluate_security_pack(
    workspace_root: Union[str, Path], changed_files: Iterable[str], base_sources: Mapping[str, Optional[Union[str, bytes]]],
    *, session: Any = None,
) -> Dict[str, Any]:
    """Evaluate introduced security findings with a check-local shared AST session.

    Missing drivers are unverified; configured driver and source errors fail closed in
    Layer 1. Test paths remain visible as exemptions. An invalid base suppresses nothing.
    A caller checking an index snapshot supplies its repository-bound session.
    """
    from aegis_core.ast.runner import ASTDriverError, enforce_source_size
    from aegis_core.ast.session import ASTParseSession

    root = Path(workspace_root).resolve()
    if session is None:
        with ASTParseSession(str(root)) as owned_session:
            return evaluate_security_pack(root, changed_files, base_sources, session=owned_session)
    violations: List[Dict[str, Any]] = []
    exempted_test_findings: List[Dict[str, Any]] = []
    unverified_findings: List[Dict[str, Any]] = []
    for rel_path in sorted(f for f in workspace_files(root, changed_files) if Path(f).suffix.lower() in PACK_EXTENSIONS):
        full_path = root.joinpath(*rel_path.split("/"))
        if not full_path.is_file():
            continue
        if not is_within(full_path, root, unresolvable=False):
            unverified_findings.append(_unverified_file(rel_path, 'source escapes workspace'))
            continue
        extension = full_path.suffix.lower()
        try:
            if extension != '.py':
                enforce_source_size(full_path)
            head_ast = session.get(str(full_path))
        except (ASTExtractionError, ASTDriverError, OSError) as exc:
            reason = 'too_large' if is_size_limit_error(exc) else getattr(exc, 'reason', str(exc))
            unverified_findings.append(_unverified_file(rel_path, reason))
            continue
        if head_ast is None:
            unverified_findings.append(_unverified_file(rel_path, f'no_driver:{extension}'))
            continue
        try:
            base_ast, base_text = _base_tree(rel_path, base_sources.get(rel_path), session)
        except (ASTExtractionError, ASTDriverError, SyntaxError, UnicodeError):
            base_ast, base_text = None, None
        is_test = is_test_path(rel_path)
        for rule in SECURITY_RULES_BY_LANGUAGE[_PACK_LANGUAGES[extension]]:
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
