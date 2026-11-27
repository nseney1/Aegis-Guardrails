"""Decide exact-tree reuse (TP-4-a) from owner evidence and untrusted results."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Optional, Tuple, Union
import xml.etree.ElementTree as ElementTree

from aegis_core import storage
from aegis_core.primitives import json_preflight, parse_utc, redact_display_secrets, sanitize_display, strict_loads
from aegis_core.redaction import RedactionRefusal

__all__ = [
    "DECISIONS", "DEFAULT_SHARD", "EMPTY_STATUS", "GATE_RECEIPT_SCHEMA", "GATE_SCHEMA",
    "GateRefusal", "JUNIT_KEEP", "MAX_COMMAND_STEPS", "MAX_COMMAND_WORDS", "MAX_DEPTH",
    "MAX_ITEMS", "MAX_JUNIT_BYTES", "MAX_NODES", "MAX_RECEIPT_BYTES", "MAX_RECEIPTS",
    "MAX_REVIEWS", "MAX_SHARDS", "MAX_STRING", "NEXT_ACTIONS", "RECEIPT_SCHEMAS",
    "REFUSALS", "RESULT_SCHEMA", "decide_reuse", "decide_reuse_files", "descriptor_supported",
    "evidence_digest", "format_gate_label", "junit_counts", "load_receipt", "parse_json", "validate_command",
    "validate_gate_config",
]

GATE_SCHEMA = "aegis.team.gate.reuse/v1"
GATE_RECEIPT_SCHEMA = "aegis.team.gate.receipt/v1"
RESULT_SCHEMA = "aegis.hierarchy-job-result/v1"
RECEIPT_SCHEMAS = (GATE_RECEIPT_SCHEMA, RESULT_SCHEMA)
DECISIONS = ("reuse", "run", "hold")
DEFAULT_SHARD = "default"
JUNIT_KEEP = "run/junit.xml"
EMPTY_STATUS = hashlib.sha256(b"").hexdigest()

MAX_RECEIPT_BYTES = 262144
MAX_JUNIT_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 16
MAX_NODES = 8192
MAX_ITEMS = 256
MAX_STRING = 4096
MAX_RECEIPTS = 128
MAX_SHARDS = 64
MAX_REVIEWS = 32
MAX_COMMAND_STEPS = 16
MAX_COMMAND_WORDS = 256
_MAX_XML_ELEMENTS = 65536
_MAX_XML_DEPTH = 64

_NATIVE_PATH_TYPE = type(Path())
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_SHARD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_NONNEG_INT = re.compile(r"[0-9]{1,12}\Z")
_UTC_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_XML_DECLARATION = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)
_LINE_BREAKS = frozenset("\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029\x00")
_JUNIT_ATTRS = ("tests", "failures", "errors", "skipped")
_JUNIT_OUTCOMES = {"failure": "failures", "error": "errors", "skipped": "skipped"}
_JUNIT_SUITES = ("testsuite", "testsuites")
_JUNIT_PARENTS = {"testsuite": (None, *_JUNIT_SUITES), "testsuites": (None, *_JUNIT_SUITES),
                  "testcase": ("testsuite",), **dict.fromkeys(_JUNIT_OUTCOMES, ("testcase",))}
_TEST_KEYS = ("total", "passed", "failed", "errors", "skipped")
_JUNIT_PATHS = (JUNIT_KEEP, "junit.xml")
_SELECTORS = ("impacted", "whole", "list")
_STATES = ("completed", "failed", "refused", "timed_out", "cancelled", "started", "running", "queued")
_NONTERMINAL_STATES = frozenset(("started", "running", "queued"))
_REVIEW_VERDICTS = ("accept", "reject", "confirmed", "unavailable", "skipped")
_BUILTIN_VOTING_ROLES = frozenset(("reviewer.correctness", "reviewer.security"))
_DERIVATION_FIELDS = {"derived_by", "dirty_content_sha256", "host_plan", "expected_tree", "changed_paths"}
_JOB_FIELDS = _DERIVATION_FIELDS | {
    "job", "recipe", "recipes_sha256", "python", "commit", "failed_launch", "source_export",
    "resolved_by_root", "capacity", "merge",
}

REFUSALS = {
    "unsupported_platform": "anchored gate receipt operations are unavailable on this platform",
    "unsafe_root": "trusted gate root must be an absolute directory path",
    "unsafe_path": "gate receipt or artifact path must be a confined regular file",
    "missing_receipt": "gate receipt file is missing",
    "io_error": "confined gate receipt read failed",
    "limit_exceeded": "gate input exceeds bounded size or structural limits",
    "invalid_json": "gate receipt JSON is malformed or contains duplicate keys",
    "invalid_tree": "requested tree must be a 40-character or 64-character hex object ID",
    "invalid_command": "configured local command must be a bounded non-empty argv sequence",
    "invalid_gate_config": "gate configuration is malformed or incomplete",
    "unsupported_runner": "staged gates require the local runner; remote runner plugins are superseded",
    "invalid_shards": "required shards must be a non-empty list of unique shard identifiers",
    "invalid_receipt": "gate receipt fails structural or provenance validation",
    "invalid_review": "review result or review policy fails validation",
    "multiline_value": "single-line gate field contains a line break or NUL character",
}

NEXT_ACTIONS = {
    "unsupported_platform": "Use a platform with POSIX directory descriptors to read file-backed gate evidence.",
    "unsafe_root": "Supply an absolute resolved directory as the trusted receipt root.",
    "unsafe_path": "Store gate receipts and JUnit files as plain regular files beneath the trusted root.",
    "missing_receipt": "Supply the missing completed receipt or JUnit artifact.",
    "io_error": "Inspect filesystem permissions under the trusted receipt root and retry the read.",
    "limit_exceeded": "Reduce receipt, JUnit or configuration size within documented bounds.",
    "invalid_json": "Replace the malformed receipt with valid strict UTF-8 JSON.",
    "invalid_tree": "Pass the exact 40-hex or 64-hex Git tree OID to evaluate.",
    "invalid_command": "Configure a non-empty local command argv sequence without NUL bytes.",
    "invalid_gate_config": "Provide a valid policy.gates object with name, runner, selector and must_pass.",
    "unsupported_runner": "Set policy.gates[].runner to local and configure a local command.",
    "invalid_shards": "Provide between 1 and 64 unique shard identifiers.",
    "invalid_receipt": "Replace invalid gate evidence using a verified owner record, receipt, or JUnit artifact.",
    "invalid_review": "Supply bounded review results that match the repository review policy.",
    "multiline_value": "Use single-line values without control line breaks or NUL characters.",
}

_USAGE_CODES = frozenset((
    "unsafe_root", "invalid_tree", "invalid_command", "invalid_gate_config",
    "unsupported_runner", "invalid_shards", "multiline_value",
))

_DECISION_ACTIONS = {
    "exact_tree_pass": "Reuse the verified exact-tree local gate PASS.",
    "reuse_disabled": "Run the configured local gate; exact-tree reuse is disabled by policy.",
    "missing_evidence": "Run the configured local gate to record exact-tree evidence.",
    "partial_evidence": "Run the missing or incomplete gate shards before reusing this tree.",
    "stale_tree": "Run the configured local gate on the requested tree.",
    "stale_dirty_tree": "Commit or clean local modifications and rerun the gate on a clean tree.",
    "stale_command": "Run the gate with the current configured local command.",
    "stale_config": "Run the gate under the current policy.gates configuration.",
    "stale_evidence": "Run the configured local gate to replace stale receipt evidence.",
    "stale_incomplete": "Run the configured local gate afresh to replace incomplete evidence.",
    "missing_test_evidence": "Run the configured local gate with test-count reporting enabled.",
    "red_evidence": "Rerun the gate to record a newer exact-tree PASS across all shards.",
    "review_unavailable": "Complete the required voting reviews before reusing or advancing this gate.",
    "review_blocked": "Address the blocking review findings and rerun the gate on the updated tree.",
}

class GateRefusal(ValueError):
    """Structured input-free refusal; never echoes untrusted text or OS errors."""

    def __init__(self, code: str, *, usage: Optional[bool] = None) -> None:
        selected = code if type(code) is str and code in REFUSALS else "invalid_receipt"
        super().__init__(REFUSALS[selected])
        self.code = self.reason = selected
        self.status = "refused"
        self.exit_code = 2 if (usage if usage is not None else selected in _USAGE_CODES) else 1
        self.next_action = NEXT_ACTIONS[selected]

    def as_dict(self) -> dict:
        return {
            "schema": GATE_SCHEMA, "status": "refused", "reusable": False, "decision": "refused",
            "code": self.code, "reason": self.reason, "message": REFUSALS[self.code],
            "next_action": self.next_action, "exit_code": self.exit_code,
        }

@dataclass(frozen=True)
class _Admission:
    before: dict
    command: tuple
    gate: dict
    shard: str
    attempt: Optional[int]
    expects_tests: bool
    artifact_dir: Optional[str]
    job: Optional[str]
    origin: Optional[str]

@dataclass(frozen=True)
class _Completion:
    state: str
    finished: Optional[datetime]
    stamp: Optional[str]
    digest: str
    verified: bool
    settled: bool

@dataclass(frozen=True)
class _Receipt:
    admitted: _Admission
    finished: Optional[datetime]
    execution: str
    outstanding: bool
    counts: Optional[dict] = None
    junit: Optional[tuple] = None
    missing_tests: bool = False
    has_xml: bool = False
    xml_red: bool = False

def descriptor_supported() -> bool:
    """Whether confined no-follow directory-descriptor reads are available."""
    return bool(storage.confined_descriptor_supported())

def _require(condition: bool, code: str) -> None:
    if not condition:
        raise GateRefusal(code)

def _utf8_size(value, budget, code):
    size = len(value)
    _require(size <= budget, "limit_exceeded")
    if not value.isascii():
        for point in map(ord, value):
            _require(not 0xD800 <= point <= 0xDFFF, code)
            size += (point >= 128) + (point >= 2048) + (point >= 65536)
            _require(size <= budget, "limit_exceeded")
    return size

def _check_value_bounds(value: object, *, default_code: str = "invalid_receipt", inline=False) -> None:
    """Charge input UTF-8 and enforce structural bounds before serialization."""
    nodes, size = 0, 0
    def visit(current, depth, xml=False):
        nonlocal nodes, size
        nodes += 1
        _require(nodes <= MAX_NODES and depth <= MAX_DEPTH, "limit_exceeded")
        kind = type(current)
        if kind in (dict, list, tuple):
            _require(len(current) <= MAX_ITEMS, "limit_exceeded")
        if kind is dict:
            for key, child in current.items():
                _require(type(key) is str, default_code)
                visit(key, depth)
                visit(child, depth + 1, inline and depth == 0 and key == "junit_xml")
        elif kind in (list, tuple):
            for child in current:
                visit(child, depth + 1)
        elif kind is str:
            _require(len(current) <= (MAX_RECEIPT_BYTES if xml else MAX_STRING), "limit_exceeded")
            size += _utf8_size(current, MAX_RECEIPT_BYTES - size, default_code)
        elif kind is bytes:
            _require(xml, default_code)
            _require(len(current) <= MAX_JUNIT_BYTES, "limit_exceeded")
        elif kind is int:
            _require(current.bit_length() <= 128, "limit_exceeded")
        elif kind is float:
            _require(math.isfinite(current), default_code)
        elif kind not in (bool, type(None)):
            raise GateRefusal(default_code)
    visit(value, 0)

def parse_json(raw: Union[bytes, str], *, inline=False) -> object:
    """Preflight byte and token bounds before allocating a strict JSON value."""
    try:
        text = json_preflight(
            raw, max_bytes=MAX_RECEIPT_BYTES, max_depth=MAX_DEPTH, max_nodes=MAX_NODES,
            max_items=MAX_ITEMS, max_string=MAX_RECEIPT_BYTES if inline else MAX_STRING, max_atom=64,
        )
    except ValueError as error:
        raise GateRefusal("invalid_json" if str(error) == "invalid" else "limit_exceeded") from None
    try:
        return strict_loads(text)
    except (ValueError, RecursionError):
        raise GateRefusal("invalid_json") from None

def _single_line(value: object, code: str, *, max_len: int = MAX_STRING) -> str:
    _require(type(value) is str, code)
    _require(len(value) <= max_len, "limit_exceeded")
    for char in value:
        if char in _LINE_BREAKS:
            raise GateRefusal("multiline_value", usage=code in _USAGE_CODES)
        _require(not (0xD800 <= ord(char) <= 0xDFFF), code)
    _require(len(value) > 0, code)
    return value

def _utc_order(value, code):
    if value is None:
        return None
    stamp = _single_line(value, code, max_len=32)
    _require(_UTC_STAMP.fullmatch(stamp) is not None, code)
    whole, _, fraction = stamp[:-1].partition(".")
    # Python 3.9 accepts six fractional digits in fromisoformat.
    parsed = parse_utc(whole + "." + fraction.ljust(6, "0") + "Z", lenient=True)
    _require(parsed is not None, code)
    return parsed

def _label(value, code, limit):
    try:
        canonical = sanitize_display(value, max_len=None)
        redacted = redact_display_secrets(canonical, limit=len(canonical))
        return sanitize_display(redacted, max_len=limit)
    except RedactionRefusal:
        raise GateRefusal(code) from None

def format_gate_label(value: object, *, limit: int = 128) -> str:
    """Canonicalize, then redact, then truncate single-line gate display text."""
    _require(type(limit) is int and 16 <= limit <= MAX_STRING, "invalid_gate_config")
    return _label(_single_line(value, "invalid_gate_config"), "invalid_gate_config", limit)

def _shard_id(value: object, code: str = "invalid_shards") -> str:
    checked = _single_line(value, code, max_len=64)
    _require(_SHARD_ID.fullmatch(checked) is not None, code)
    _require(_label(checked, code, 128) == checked, code)
    return checked

def _validate_shards(values: object, code: str = "invalid_shards") -> tuple:
    _require(type(values) in (list, tuple) and bool(values), code)
    _require(len(values) <= MAX_SHARDS, "limit_exceeded")
    normalized = tuple(_shard_id(item, code) for item in values)
    _require(len(set(normalized)) == len(normalized), code)
    return normalized

def _effective_gate(spec, layout, code):
    declared = spec.get("shards")
    if layout is not None:
        layout = _validate_shards(layout, code)
        _require(declared is None or tuple(declared) == layout, code)
    return {**spec, "shards": list(layout or declared or (DEFAULT_SHARD,))}

def _parse_gate_spec(gate: object, *, code: str = "invalid_gate_config") -> dict:
    _check_value_bounds(gate, default_code=code)
    required = {"name", "runner", "selector", "must_pass"}
    allowed = required | {"tests", "python", "reuse_identical_tree", "shards"}
    _require(type(gate) is dict and required <= gate.keys() <= allowed, code)
    name = _single_line(gate["name"], code)
    runner = _single_line(gate["runner"], code, max_len=64)
    _require(_IDENTIFIER.fullmatch(runner) is not None, code)
    if runner != "local":
        raise GateRefusal("unsupported_runner" if code == "invalid_gate_config" else code)
    selector = gate["selector"]
    _require(type(selector) is str and selector in _SELECTORS, code)
    tests = gate.get("tests", ())
    _require(type(tests) in (list, tuple) and (selector == "impacted" or bool(tests) == (selector == "list")), code)
    for entry in tests:
        path_part = _single_line(entry, code).partition("::")[0].replace("\\", "/")
        _require(not path_part.startswith("/") and ".." not in path_part.split("/"), code)
    python_val = _single_line(gate["python"], code) if "python" in gate else None
    must_pass, reuse = gate["must_pass"], gate.get("reuse_identical_tree", False)
    _require(type(must_pass) is bool and type(reuse) is bool, code)
    result = {
        "name": name, "shown_name": _label(name, code, 128), "runner": runner, "selector": selector,
        "tests": list(tests), "python": python_val, "must_pass": must_pass, "reuse_identical_tree": reuse,
    }
    if "shards" in gate:
        shard_code = "invalid_shards" if code == "invalid_gate_config" else code
        result["shards"] = list(_validate_shards(gate["shards"], shard_code))
    return result

def validate_gate_config(gate: object) -> dict:
    """Validate a policy.gates entry and return an independent normalized dict."""
    return _parse_gate_spec(gate)

def _validate_argv(words: object, code: str) -> tuple:
    _require(type(words) in (list, tuple) and bool(words), code)
    _require(len(words) <= MAX_COMMAND_WORDS, "limit_exceeded")
    for word in words:
        _require(type(word) is str and len(word) > 0, code)
        _require(len(word) <= MAX_STRING, "limit_exceeded")
        _require("\x00" not in word and not any(0xD800 <= ord(c) <= 0xDFFF for c in word), code)
    _require(not words[0].startswith("-"), code)
    return tuple(words)

def validate_command(command: object, *, code: str = "invalid_command") -> tuple:
    """Normalize a local gate command (single argv or step list) to nested tuples."""
    _require(type(command) in (list, tuple) and len(command) > 0, code)
    if type(command[0]) is str:
        return (_validate_argv(command, code),)
    _require(len(command) <= MAX_COMMAND_STEPS, "limit_exceeded")
    return tuple(_validate_argv(step, code) for step in command)

class _BoundedXml(ElementTree.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.tags, self.elements, self.known_failure = [], 0, False

    def start(self, tag, attrs):
        self.elements += 1
        _require(self.elements <= _MAX_XML_ELEMENTS and len(self.tags) < _MAX_XML_DEPTH, "limit_exceeded")
        parent = self.tags[-1] if self.tags else None
        _require(not tag.startswith("{") and (parent != "testcase" or tag in _JUNIT_OUTCOMES), "invalid_receipt")
        _require(tag not in _JUNIT_PARENTS or parent in _JUNIT_PARENTS[tag], "invalid_receipt")
        self.known_failure |= tag in ("failure", "error")
        self.tags.append(tag)
        return super().start(tag, attrs)

    def end(self, tag):
        self.tags.pop()
        return super().end(tag)

def _suite_counts(suite):
    observed, descendants = dict.fromkeys(_JUNIT_ATTRS, 0), False
    for child in suite:
        if child.tag in _JUNIT_SUITES:
            descendants = True
            for attr, count in _suite_counts(child).items():
                observed[attr] += count
        elif child.tag == "testcase":
            descendants = True
            observed["tests"] += 1
            _require(len(child) <= 1, "invalid_receipt")
            if len(child):
                observed[_JUNIT_OUTCOMES[child[0].tag]] += 1
    for attr in _JUNIT_ATTRS:
        if attr in suite.attrib:
            raw = suite.attrib[attr]
            _require(_NONNEG_INT.fullmatch(raw) is not None, "invalid_receipt")
            count = int(raw)
            _require(not descendants or count == observed[attr], "invalid_receipt")
            observed[attr] = count
    _require(sum(observed[attr] for attr in _JUNIT_ATTRS[1:]) <= observed["tests"], "invalid_receipt")
    return observed

def junit_counts(raw: object) -> Tuple[Optional[dict], Optional[str]]:
    """Read bounded UTF-8 JUnit and reconcile summaries with available cases."""
    return _junit_counts(raw, _BoundedXml())

def _junit_counts(raw, builder):
    _require(type(raw) is bytes, "invalid_receipt")
    if len(raw) > MAX_JUNIT_BYTES:
        return None, "oversized_junit"
    try:
        content = raw.decode("utf-8")
    except UnicodeError:
        return None, "non_utf8_junit"
    if _XML_DECLARATION.search(content):
        return None, "unsafe_xml_declaration"
    try:
        root = ElementTree.fromstring(content, parser=ElementTree.XMLParser(target=builder))
        _require(root.tag in _JUNIT_SUITES, "invalid_receipt")
        sums = _suite_counts(root)
    except GateRefusal as error:
        return None, error.code
    except (ElementTree.ParseError, ValueError, RecursionError, LookupError):
        return None, "malformed_junit_xml"
    passed = sums["tests"] - sum(sums[attr] for attr in _JUNIT_ATTRS[1:])
    return {"total": sums["tests"], "passed": passed, "failed": sums["failures"],
            "errors": sums["errors"], "skipped": sums["skipped"]}, None

def _trusted_root(root: object) -> Path:
    _require(type(root) in (str, _NATIVE_PATH_TYPE), "unsafe_root")
    spelling = str(root)
    _require(0 < len(spelling) <= 32768 and "\x00" not in spelling, "unsafe_root")
    if not descriptor_supported():
        raise GateRefusal("unsupported_platform")
    base = Path(spelling)
    _require(base.is_absolute() and ".." not in base.parts, "unsafe_root")
    try:
        # This context opens the parent only and never accesses the sentinel.
        with storage.confined_file(base, (".root-check",)):
            return base
    except storage.ConfinedFileError as error:
        code = {"unsupported": "unsupported_platform", "io": "io_error"}.get(error.reason, "unsafe_root")
        raise GateRefusal(code, usage=False) from None

def _relative_parts(path: object) -> tuple:
    _require(type(path) is str and 0 < len(path) <= MAX_STRING, "unsafe_path")
    _require(not any(c in _LINE_BREAKS or c in "\\:" for c in path), "unsafe_path")
    _require(path.count("/") < 128, "unsafe_path")
    parts = tuple(path.split("/"))
    for part in parts:
        _require(0 < len(part) <= 255 and part not in (".", ".."), "unsafe_path")
        try:
            _require(len(part.encode("utf-8")) <= 255, "unsafe_path")
        except UnicodeError:
            raise GateRefusal("unsafe_path") from None
    return parts

def _read_confined(base: Path, path: object, max_bytes: int) -> bytes:
    parts = _relative_parts(path)
    try:
        with storage.confined_file(base, parts) as handle:
            return handle.read_bytes(max_bytes)
    except storage.ConfinedFileError as error:
        mapping = {"unsupported": "unsupported_platform", "missing": "missing_receipt",
                   "too_large": "limit_exceeded", "unsafe": "unsafe_path", "invalid_path": "unsafe_path"}
        raise GateRefusal(mapping.get(error.reason, "io_error")) from None

def _evidence_object(item, code="invalid_receipt") -> dict:
    receipt = code == "invalid_receipt"
    data = parse_json(item, inline=True) if receipt and type(item) in (bytes, str) else item
    _require(type(data) is dict, code)
    _check_value_bounds(data, default_code=code, inline=receipt)
    return data

def load_receipt(root: object, relative_path: object) -> dict:
    """Read and parse a single confined JSON receipt beneath the trusted root."""
    return _evidence_object(_read_confined(_trusted_root(root), relative_path, MAX_RECEIPT_BYTES))

def _object_digest(data: dict) -> str:
    digest = hashlib.sha256()
    xml = data.get("junit_xml")
    if type(xml) is bytes:
        # Distinguish legacy byte-valued XML from JSON string values.
        digest.update(b"inline-junit-bytes\0")
        digest.update(hashlib.sha256(xml).digest())
        data = {**data, "junit_xml": None}
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    for chunk in encoder.iterencode(data):
        digest.update(chunk.encode("ascii"))
    return digest.hexdigest()

def _result_digest(item: object, data: dict) -> str:
    if type(item) in (str, bytes):
        return hashlib.sha256(item.encode("utf-8") if type(item) is str else item).hexdigest()
    return _object_digest(data)

def evidence_digest(item: object) -> str:
    """Hash exact serialized JSON bytes or canonical in-memory object evidence."""
    return _result_digest(item, _evidence_object(item))

def _witness_tree(witness: object) -> Tuple[str, bool]:
    needed = {"worktree", "source_revision", "source_tree", "dirty_content_sha256", "dirty_state_sha256", "dirty_entries"}
    _require(type(witness) is dict and witness.keys() == needed, "invalid_receipt")
    _single_line(witness["worktree"], "invalid_receipt")
    rev, tree = witness["source_revision"], witness["source_tree"]
    _require(type(rev) is str and _OID.fullmatch(rev) is not None, "invalid_receipt")
    _require(type(tree) is str and _OID.fullmatch(tree) is not None and len(rev) == len(tree), "invalid_receipt")
    state, content, entries = (witness[key] for key in ("dirty_state_sha256", "dirty_content_sha256", "dirty_entries"))
    _require(all(type(d) is str and _SHA256.fullmatch(d) is not None for d in (state, content)), "invalid_receipt")
    _require(type(entries) is int and 0 <= entries <= 10**9, "invalid_receipt")
    return tree, state == content == EMPTY_STATUS and entries == 0

def _sha256(value, code="invalid_receipt"):
    _require(type(value) is str and _SHA256.fullmatch(value) is not None, code)
    return value

def _kept_junit(kept, root, artifact_dir):
    """Validate declarations without opening files. A null copy denotes a reported error."""
    _require(type(kept) is list, "invalid_receipt")
    seen, junit = set(), None
    for row in kept:
        _require(type(row) is dict and "path" in row, "invalid_receipt")
        path = row["path"]
        _relative_parts(path)
        _require(path not in seen, "invalid_receipt")
        seen.add(path)
        size = row.get("bytes", 0)
        _require(type(size) is int and size >= 0, "invalid_receipt")
        copy = digest = None
        if "error" in row:
            _require(row.keys() <= {"path", "error", "bytes"}, "invalid_receipt")
            _require(type(row["error"]) is str and bool(row["error"]), "invalid_receipt")
        else:
            _require(row.keys() == {"path", "copy", "sha256", "bytes"}, "invalid_receipt")
            digest = _sha256(row["sha256"])
            _require(root is not None and artifact_dir is not None, "invalid_receipt")
            copy = artifact_dir + "/" + path
            _require(row["copy"] in (copy, str(root.joinpath(*_relative_parts(copy)))), "unsafe_path")
        if path in _JUNIT_PATHS:
            _require(junit is None, "invalid_receipt")
            _require(copy is None or size <= MAX_JUNIT_BYTES, "limit_exceeded")
            junit = (path, copy, digest, size)
    return junit

def _reconcile_junit(counts, raw):
    report = _BoundedXml()
    observed, problem = _junit_counts(raw, report)
    if problem is not None:
        code = "limit_exceeded" if problem in ("oversized_junit", "limit_exceeded") else "invalid_receipt"
        raise GateRefusal(code)
    _require(counts is None or counts == observed, "invalid_receipt")
    return observed, report.known_failure

def _failed_tests(counts):
    return counts is not None and (not counts["passed"] or counts["failed"] > 0 or counts["errors"] > 0)

def _outcome(record, root=None):
    counts, junit, xml_red, unresolved = record.counts, record.junit, record.xml_red, False
    if junit is not None:
        _path, copy, digest, size = junit
        unresolved = copy is None or root is None
        if not unresolved:
            raw = _read_confined(root, copy, MAX_JUNIT_BYTES)
            _require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, "invalid_receipt")
            counts, kept_red = _reconcile_junit(counts, raw)
            xml_red |= kept_red
    if record.execution != "pass":
        return record.execution, None
    if xml_red or (not record.has_xml and _failed_tests(counts)):
        return "red", counts
    if unresolved or record.missing_tests or (record.admitted.expects_tests and counts is None):
        return "missing_tests", None
    return ("pass", counts) if record.admitted.origin == "direct" and not record.has_xml else ("incomplete", None)

def _attempt(value, code):
    _require(value is None or (type(value) is int and 0 <= value < 2**63), code)
    return value

def _parse_admission(row):
    _check_value_bounds(row)
    required = {"before", "command", "gate", "shard", "attempt", "expects_tests"}
    allowed = required | {"artifact_dir", "job", "shards", "origin"}
    _require(type(row) is dict and required <= row.keys() <= allowed, "invalid_receipt")
    _witness_tree(row["before"])
    _require(type(row["expects_tests"]) is bool, "invalid_receipt")
    directory, job, origin = row.get("artifact_dir"), row.get("job"), row.get("origin")
    _require(origin in (None, "direct", "producer") and (job is None or origin != "direct"), "invalid_receipt")
    for path in (directory, job):
        if path is not None:
            _relative_parts(path)
    layout = row.get("shards")
    _require("shards" not in row or layout is not None, "invalid_receipt")
    spec = _effective_gate(_parse_gate_spec(row["gate"], code="invalid_receipt"), layout, "invalid_receipt")
    return _Admission(row["before"], validate_command(row["command"], code="invalid_receipt"), spec,
                      _shard_id(row["shard"], "invalid_receipt"), _attempt(row["attempt"], "invalid_receipt"),
                      row["expects_tests"], directory, job, "producer" if job is not None else origin)

def _parse_completion(row):
    _check_value_bounds(row)
    required = {"state", "result_sha256", "verified", "settled"}
    _require(type(row) is dict and required <= row.keys() <= required | {"finished_at"}, "invalid_receipt")
    state, stamp = row["state"], row.get("finished_at")
    _require(type(state) is str and state in _STATES, "invalid_receipt")
    _require(type(row["verified"]) is bool and type(row["settled"]) is bool, "invalid_receipt")
    return _Completion(state, _utc_order(stamp, "invalid_receipt"), stamp, _sha256(row["result_sha256"]),
                       row["verified"], row["settled"])

def _evidence_map(value, limit, code):
    value = {} if value is None else value
    _require(type(value) is dict, code)
    _require(len(value) <= limit, "limit_exceeded")
    for key in value:
        _single_line(key, code, max_len=128)
    return value

def _account_payloads(items, digests, code, *, required=False):
    expected = Counter(digests)
    supplied = defaultdict(list)
    for item in items:
        data = _evidence_object(item, code)
        digest = _result_digest(item, data)
        _require(len(supplied[digest]) < expected[digest], code)
        supplied[digest].append(data)
    _require(all(len(supplied.get(digest, ())) == expected[digest] for digest in (expected if required else supplied)), code)
    return supplied

def _bind_receipts(receipts, admissions, completions, root):
    admissions = {key: _parse_admission(row) for key, row in
                  _evidence_map(admissions, MAX_RECEIPTS, "invalid_receipt").items()}
    completions = {key: _parse_completion(row) for key, row in
                   _evidence_map(completions, MAX_RECEIPTS, "invalid_receipt").items()}
    _require(completions.keys() <= admissions.keys(), "invalid_receipt")
    supplied = _account_payloads(receipts, (row.digest for row in completions.values()), "invalid_receipt")
    records = []
    for key, row in admissions.items():
        done = completions.get(key)
        matches = supplied.get(done.digest) if done is not None else None
        records.append(_validate_receipt(row, done, matches.pop() if matches else None, root))
    return records

def _check_steps(data, admitted, completed):
    if "command" in data:
        _require(validate_command(data["command"], code="invalid_receipt") == admitted.command, "invalid_receipt")
    steps = data.get("steps", [])
    _require(type(steps) is list and len(steps) <= len(admitted.command), "invalid_receipt")
    for step, argv in zip(steps, admitted.command):
        _require(type(step) is dict and {"argv", "exit_code"} <= step.keys(), "invalid_receipt")
        _require(_validate_argv(step["argv"], "invalid_receipt") == argv, "invalid_receipt")
        status, timeout, leftovers = step["exit_code"], step.get("timed_out"), step.get("stopped_leftovers", False)
        _require(status is None or type(status) is int, "invalid_receipt")
        _require(type(timeout) is bool and type(leftovers) is bool, "invalid_receipt")
        seconds = step.get("seconds", 0)
        _require(type(seconds) in (int, float) and seconds >= 0, "invalid_receipt")
        _require(not completed or (status == 0 and not timeout), "invalid_receipt")
    if completed and len(steps) != len(admitted.command):
        _require("steps" not in data and "command" in data and data["schema"] == GATE_RECEIPT_SCHEMA, "invalid_receipt")
    if (launch := data.get("failed_launch")) is not None:
        _require(not completed and type(launch) is dict and launch.keys() == {"step", "argv", "error"}, "invalid_receipt")
        _require(type(launch["step"]) is int and launch["step"] >= len(steps) + 1, "invalid_receipt")
        _require(type(launch["error"]) is str and len(steps) < len(admitted.command), "invalid_receipt")
        _require(_validate_argv(launch["argv"], "invalid_receipt") == admitted.command[len(steps)], "invalid_receipt")

def _job_provenance(data, admitted):
    """Check producer fields used to attest source and execution, including partial records."""
    code = "invalid_receipt"
    if data.get("recipes_sha256") is not None:
        _sha256(data["recipes_sha256"])
    if data.get("recipe") is not None:
        _single_line(data["recipe"], code)
    commit, state = data.get("commit"), data.get("state")
    _require(commit is None or (type(commit) is str and _OID.fullmatch(commit) and state != "completed"), code)
    _require(data.get("provenance_unverified", True) is True, code)
    _require("resolved_by_root" not in data or (data["resolved_by_root"] is True and state == "failed"), code)
    if _DERIVATION_FIELDS & data.keys():
        _require(_DERIVATION_FIELDS <= data.keys() and data["derived_by"] == "runner", code)
        plan, expected, paths = data["host_plan"], data["expected_tree"], data["changed_paths"]
        _require(type(plan) is dict and plan.keys() == {"path", "sha256", "team"}, code)
        for text in (plan["path"], plan["team"]):
            _require(type(text) is str and bool(text) and not _LINE_BREAKS.intersection(text), code)
        _sha256(plan["sha256"])
        _sha256(data["dirty_content_sha256"])
        if expected is None:
            _require(paths is None and state != "completed", code)
        else:
            _require(type(expected) is str and _OID.fullmatch(expected), code)
            _require(type(paths) is list and all(type(path) is str and path and "\x00" not in path for path in paths), code)
    if "source_export" in data:
        export = data["source_export"]
        needed = {"commit", "tree", "entries", "bytes"}
        _require(type(export) is dict and needed <= export.keys() <= needed | {"removed", "git_stub"}, code)
        _require(export["commit"] == admitted.before["source_revision"] and
                 export["tree"] == admitted.before["source_tree"], code)
        _require(all(type(export[k]) is int and export[k] >= 0 for k in ("entries", "bytes")), code)
        _require(all(type(export.get(k, False)) is bool for k in ("removed", "git_stub")), code)
    if (python := data.get("python")) is not None:
        _require(type(python) is dict and python.keys() <= {"version", "executable", "error"}, "invalid_receipt")
        _require(all(value is None or type(value) is str for value in python.values()), "invalid_receipt")

def _validate_receipt(admitted, completion, data, root):
    identity = (admitted, completion.finished if completion else None, _execution_outcome(admitted, completion, data),
                completion is None or not completion.settled)
    if data is None:
        return _Receipt(*identity)
    schema, state, status = data.get("schema"), data.get("state"), data.get("exit_code")
    _require(type(schema) is str and schema in RECEIPT_SCHEMAS, "invalid_receipt")
    _require(admitted.origin is None or (admitted.origin == "direct") == (schema == GATE_RECEIPT_SCHEMA), "invalid_receipt")
    allowed = {"schema", "tree", "command", "steps", "gate", "shard", "state", "exit_code", "attempt",
               "finished_at", "tests", "junit_xml", "kept", "before", "after", "dirty", "reason",
               "process_stopped_confirmed", "provenance_unverified"}
    if schema == RESULT_SCHEMA:
        allowed |= _JOB_FIELDS
        _require(admitted.job is not None and data.get("job") == admitted.job, "invalid_receipt")
        _job_provenance(data, admitted)
    _require(data.keys() <= allowed, "invalid_receipt")
    _require(state == completion.state and data.get("finished_at") == completion.stamp, "invalid_receipt")
    _require("attempt" not in data or _attempt(data["attempt"], "invalid_receipt") == admitted.attempt, "invalid_receipt")
    _require("shard" not in data or _shard_id(data["shard"], "invalid_receipt") == admitted.shard, "invalid_receipt")
    if schema == GATE_RECEIPT_SCHEMA and state == "completed":
        _require({"gate", "tree", "shard"} <= data.keys(), "invalid_receipt")
    if "gate" in data:
        spec = _parse_gate_spec(data["gate"], code="invalid_receipt")
        _require(_effective_gate(spec, admitted.gate["shards"], "invalid_receipt") == admitted.gate, "invalid_receipt")
    if "tree" in data:
        _require(data["tree"] == admitted.before["source_tree"], "invalid_receipt")
    completed = state == "completed"
    _check_steps(data, admitted, completed)
    no_exit = state in _NONTERMINAL_STATES or state == "refused"
    valid_exit = status is None if no_exit else type(status) is int and (status == 0) == completed
    _require(valid_exit, "invalid_receipt")
    for witness in (data.get("before"), data.get("after")):
        if witness is not None:
            _witness_tree(witness)
    _require(data.get("before") is None or data["before"] == admitted.before, "invalid_receipt")
    flags = ("process_stopped_confirmed", "dirty", "provenance_unverified")
    _require(all(type(data.get(flag, False)) is bool for flag in flags), "invalid_receipt")
    _require(data.get("reason") is None or (not completed and type(data["reason"]) is str), "invalid_receipt")
    summary = counts = data.get("tests")
    if summary is not None:
        _require(type(summary) is dict and summary.keys() == set(_TEST_KEYS), "invalid_receipt")
        _require(all(type(val) is int and 0 <= val <= 10**12 for val in summary.values()), "invalid_receipt")
        _require(summary["total"] == sum(summary[k] for k in _TEST_KEYS[1:]), "invalid_receipt")
    xml_red = False
    if (inline := data.get("junit_xml")) is not None:
        counts, xml_red = _reconcile_junit(counts, inline.encode("utf-8") if type(inline) is str else inline)
    junit = _kept_junit(data.get("kept", []), root, admitted.artifact_dir)
    producer_tests = schema == RESULT_SCHEMA and admitted.expects_tests
    missing = producer_tests and (summary is None or junit is None or junit[0] != JUNIT_KEEP)
    return _Receipt(*identity, counts, junit, missing, junit is not None or "junit_xml" in data, xml_red)

def _execution_outcome(admitted, completion, data):
    if completion is None or completion.state in _NONTERMINAL_STATES:
        return "incomplete"
    if completion.verified and completion.state != "completed":
        return "red"
    if (not completion.verified or data is None or not completion.settled
            or not data.get("process_stopped_confirmed") or data.get("provenance_unverified")
            or data.get("before") is None or data.get("after") is None):
        return "incomplete"
    return "red" if data["after"] != admitted.before or data.get("dirty") else "pass"

def _stale_reason(admitted, tree, command, gate):
    observed, clean = _witness_tree(admitted.before)
    if observed != tree:
        return "stale_tree"
    if not clean:
        return "stale_dirty_tree"
    if admitted.command != command:
        return "stale_command"
    return "stale_config" if admitted.gate != gate or admitted.shard not in gate["shards"] else None

def _attempt_order(entries, code):
    """Return trusted ordinals after checking all available ordering evidence."""
    if len(entries) == 1:
        return [0]
    attempts, finishes = zip(*entries)
    if all(attempt is None for attempt in attempts):
        _require(None not in finishes, code)
        return finishes
    _require(None not in attempts, code)
    known = sorted((attempt, finish) for attempt, finish in entries if finish is not None)
    for left, right in zip(known, known[1:]):
        _require(left[0] == right[0] or left[1] <= right[1], code)
    return attempts

def _parse_review_policy(policy: object):
    if policy is None:
        return None, _BUILTIN_VOTING_ROLES
    _check_value_bounds(policy, default_code="invalid_review")
    _require(type(policy) is dict, "invalid_review")
    _require(policy.keys() <= {"require_cross_family", "cap", "mode", "extra_lens_blocks_on", "lenses"}, "invalid_review")
    _require(type(policy.get("require_cross_family", False)) is bool, "invalid_review")
    cap = policy.get("cap")
    _require(cap is None or (type(cap) is int and 1 <= cap <= 1000000), "invalid_review")
    _require(policy.get("mode", "full") in ("full", "delta"), "invalid_review")
    _require(policy.get("extra_lens_blocks_on", "confirmed") == "confirmed", "invalid_review")
    lens_names, required_voting = set(), set(_BUILTIN_VOTING_ROLES)
    lenses = policy.get("lenses", ())
    _require(type(lenses) in (list, tuple) and len(lenses) <= MAX_REVIEWS, "invalid_review")
    for item in lenses:
        _require(type(item) is dict and {"name", "voting"} <= item.keys(), "invalid_review")
        _require(item.keys() <= {"name", "host_pref", "voting", "pinned_family"}, "invalid_review")
        name = _single_line(item["name"], "invalid_review", max_len=64)
        _require(_IDENTIFIER.fullmatch(name) is not None and name not in lens_names
                 and name not in _BUILTIN_VOTING_ROLES and name != "lens.extra", "invalid_review")
        _require(type(item["voting"]) is bool and type(item.get("pinned_family", False)) is bool, "invalid_review")
        lens_names.add(name)
        if item["voting"]:
            required_voting.add(name)
    return lens_names, required_voting

def _review_groups(reviews, evidence, lenses, required):
    code = "invalid_review"
    declared = _evidence_map(evidence, MAX_REVIEWS, code)
    reviews = () if reviews is None else reviews
    _require(type(reviews) in (list, tuple), code)
    _require(len(reviews) <= MAX_REVIEWS, "limit_exceeded")
    digests = {key: _sha256(row["result_sha256"], code) for key, row in declared.items()
               if type(row) is dict and "result_sha256" in row}
    supplied = _account_payloads(reviews, digests.values(), code, required=True)
    groups = {}
    for key, row in declared.items():
        _check_value_bounds(row, default_code=code)
        fields = {"role", "reviewer", "family", "tree", "attempt"}
        _require(type(row) is dict and fields <= row.keys() <= fields | {"finished_at", "result_sha256", "verified"}, code)
        for field in ("role", "reviewer", "family", "tree"):
            _single_line(row[field], code, max_len=64)
        role = row["role"]
        _require(_IDENTIFIER.fullmatch(role) and _OID.fullmatch(row["tree"]), code)
        _require(lenses is None or role in required or role in lenses or role == "lens.extra", code)
        finished = _utc_order(row.get("finished_at"), code)
        attempt = _attempt(row["attempt"], code)
        _require(type(row.get("verified", False)) is bool, code)
        digest = digests.get(key)
        verdict = "unavailable" if digest is None else _review_verdict(row, supplied[digest].pop(), role in required)
        bucket = groups.setdefault((row["tree"], role), {})
        vote = (digest, key if digest is None else None)
        if vote not in bucket or verdict != "unavailable":
            bucket[vote] = (attempt, finished, row["family"], verdict)
    return groups

def _review_verdict(row, data, voting):
    fields = ("role", "reviewer", "family", "tree", "finished_at")
    _require(all(data.get(key) == row.get(key) for key in fields), "invalid_review")
    _require(_attempt(data.get("attempt"), "invalid_review") == row["attempt"], "invalid_review")
    _require(data.get("voting", voting) is voting and data.get("optional", not voting) is (not voting), "invalid_review")
    verdict, state = data.get("verdict"), data.get("state")
    _require(type(verdict) is str and verdict in _REVIEW_VERDICTS, "invalid_review")
    _require(type(state) is str and state in _STATES, "invalid_review")
    return verdict if state == "completed" and row.get("verified") is True else "unavailable"

def _evaluate_reviews(reviews, evidence, policy, tree):
    lenses, required, cross_family, author, security_pin = policy
    unavailable, accepted, blocked = [], set(), False
    groups = _review_groups(reviews, evidence, lenses, required)
    for (review_tree, role), votes in sorted(groups.items()):
        records = votes.values()
        ordinals = _attempt_order([(attempt, finish) for attempt, finish, _family, _vote in records], "invalid_review")
        if review_tree != tree:
            continue
        latest = max(ordinals)
        current = [(row[2], row[3]) for order, row in zip(ordinals, records) if order == latest]
        if role in required:
            pin = security_pin if role == "reviewer.security" else None
            blocked |= any(verdict in ("reject", "confirmed") for _, verdict in current)
            if all(verdict == "accept" and (family == pin if pin is not None else
                   not cross_family or (author is not None and family != author)) for family, verdict in current):
                accepted.add(role)
        else:
            # Only a strictly later decisive verdict can clear a confirmed block.
            decisive = [(order, row[3] == "confirmed") for order, row in zip(ordinals, records)
                        if row[3] in ("confirmed", "accept", "reject")]
            blocked |= bool(decisive) and max(decisive)[1]
            if any(verdict in ("unavailable", "skipped") for _, verdict in current):
                unavailable.append(_label(role, "invalid_review", 64))
    if blocked or (any(item is not None for item in (lenses, reviews, evidence, security_pin)) and required - accepted):
        return ("review_blocked" if blocked else "review_unavailable"), []
    return "ok", unavailable

def _choose_receipt(current, root):
    evaluated = [_outcome(record, root) for record in current]
    if len(evaluated) == 1:
        return evaluated[0]
    outcomes = {state for state, _ in evaluated}
    outcome = next((state for state in ("red", "incomplete", "missing_tests") if state in outcomes), None)
    _require(outcome is not None, "invalid_receipt")
    return outcome, None

def _classify_shards(records, tree, command, gate, root):
    by_shard, stale_reasons = {shard: [] for shard in gate["shards"]}, []
    for record in records:
        stale = _stale_reason(record.admitted, tree, command, gate)
        if stale is None:
            by_shard[record.admitted.shard].append(record)
        else:
            stale_reasons.append(stale)
    states = {name: [] for name in ("pass", "red", "incomplete", "missing_tests")}
    orders = {shard: _attempt_order([(row.admitted.attempt, row.finished) for row in bucket], "invalid_receipt")
              for shard, bucket in by_shard.items() if bucket}
    superseded, totals, excludes_counts = 0, None, False
    states.update(outstanding=False, missing=[shard for shard in by_shard if shard not in orders])
    for shard, order in orders.items():
        latest, bucket = max(order), by_shard[shard]
        current = [record for record, ordinal in zip(bucket, order) if ordinal == latest]
        outcome, counts = _choose_receipt(current, root)
        states[outcome].append(shard)
        states["outstanding"] |= any(record.outstanding for record in current)
        superseded += sum(_outcome(record)[0] == "pass" for record, ordinal in zip(bucket, order) if ordinal < latest)
        excludes_counts |= any(record.has_xml for record in current)
        if counts is not None and not excludes_counts:
            totals = {key: counts[key] + (totals[key] if totals is not None else 0) for key in _TEST_KEYS}
    return states, stale_reasons, superseded, None if excludes_counts else totals

def _request(items, tree, command, gate, required_shards, review_policy, author_family, security_family):
    try:
        _require(type(items) in (list, tuple), "invalid_receipt")
        _require(len(items) <= MAX_RECEIPTS, "limit_exceeded")
        _require(type(tree) is str and _OID.fullmatch(tree) is not None, "invalid_tree")
        command = validate_command(command)
        gate = _effective_gate(_parse_gate_spec(gate), required_shards, "invalid_shards")
        lenses, required = _parse_review_policy(review_policy)
        cross_family = review_policy is not None and review_policy.get("require_cross_family", False)
        author, pin = (None if family is None else _single_line(family, "invalid_review", max_len=64)
                       for family in (author_family, security_family))
    except GateRefusal as error:
        raise GateRefusal(error.code, usage=True) from None
    return tree, command, gate, (lenses, required, cross_family, author, pin)

def _recovery_action(states, action):
    guard = "Verify owner attempt state before launching any gate run." if states is None else ""
    if states and states["outstanding"]:
        guard = "Wait for all outstanding gate attempts to settle before launching any gate run."
    fix = "Fix the failing gate run." if states and states["red"] else ""
    return " ".join(filter(None, (guard, fix, "" if guard else action)))

def decide_reuse(receipts: object, *, tree: object, command: object, gate: object,
                 required_shards: object = None, root: object = None, reviews: object = None,
                 review_policy: object = None, admissions: object = None, completions: object = None,
                 review_evidence: object = None, author_family: object = None, security_family: object = None) -> dict:
    """Evaluate owner evidence keyed by attempt ID, with admissions captured before execution.
    Only origin="direct" permits reuse. A bound job implies "producer".
    Supply empty admissions for no attempts and security_family for a trusted profile pin.
    """
    request = _request(receipts, tree, command, gate, required_shards, review_policy, author_family, security_family)
    return _decide(receipts, request, root, admissions, completions, reviews, review_evidence)

def _decide(receipts, request, root, admissions, completions, reviews, review_evidence, *, files=False):
    tree, command, gate_spec, policy = request
    try:
        root = _trusted_root(root) if files or root is not None else None
        if files:
            receipts = [_read_confined(root, path, MAX_RECEIPT_BYTES) for path in receipts]
        records = _bind_receipts(receipts, admissions, completions, root)
        review_state, unavailable_reviews = _evaluate_reviews(reviews, review_evidence, policy, tree)
        states, stale_reasons, superseded, totals = _classify_shards(records, tree, command, gate_spec, root)
    except GateRefusal as error:
        if error.exit_code == 1:
            error.next_action = f"{NEXT_ACTIONS[error.code]} Re-evaluate after repair before launching any gate run."
        raise
    unready = set(states["incomplete"] + states["missing_tests"])
    decision, state, reason = _disposition(gate_spec, states, stale_reasons, review_state)
    action = _recovery_action(states if admissions is not None else None, _DECISION_ACTIONS[reason])
    return {
        "schema": GATE_SCHEMA, "status": "ok", "reusable": decision == "reuse", "decision": decision,
        "evidence_state": state, "reason": reason, "next_action": action,
        "gate_name": gate_spec["shown_name"], "tree": tree, "required_shards": list(gate_spec["shards"]),
        "passed_shards": states["pass"], "missing_shards": states["missing"], "red_shards": states["red"],
        "incomplete_shards": [shard for shard in gate_spec["shards"] if shard in unready], "stale_count": len(stale_reasons),
        "superseded_pass_count": superseded, "tests": totals, "unavailable_reviews": unavailable_reviews,
    }

def _disposition(gate, states, stale, review):
    if not gate["reuse_identical_tree"]:
        return "run", "reuse_disabled", "reuse_disabled"
    if states["red"]:
        return "run", "red", "red_evidence"
    incomplete = states["incomplete"] or states["missing_tests"]
    if states["pass"] and (states["missing"] or incomplete):
        return "run", "partial", "partial_evidence"
    if incomplete:
        return "run", "stale", "missing_test_evidence" if states["missing_tests"] else "stale_incomplete"
    if states["missing"]:
        if stale:
            return "run", "stale", stale[0] if len(set(stale)) == 1 else "stale_evidence"
        return "run", "missing", "missing_evidence"
    if review != "ok":
        return ("hold" if review == "review_unavailable" else "run"), review, review
    return "reuse", "pass", "exact_tree_pass"

def decide_reuse_files(root: object, receipt_paths: object, *, tree: object, command: object,
                       gate: object, required_shards: object = None, reviews: object = None,
                       review_policy: object = None, admissions: object = None, completions: object = None,
                       review_evidence: object = None, author_family: object = None, security_family: object = None) -> dict:
    """Evaluate a declared set of confined receipt files."""
    request = _request(receipt_paths, tree, command, gate, required_shards, review_policy, author_family, security_family)
    return _decide(receipt_paths, request, root, admissions, completions, reviews, review_evidence, files=True)
