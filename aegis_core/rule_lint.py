"""Read-only mining lint of exact accepted-rule bytes and final destinations.

Checks 1--5 refuse drafts; 6--7 warn. No proposal, rule, ledger or decision is written.
Filesystem candidates use bounded confined reads; rule sets use the runtime inventory.
Unsupported platforms report a fixed refusal. In-memory lint works on every host.

Example and command analysis lives in rule_lint_grammar. Confined rule and source
capture lives in rule_lint_capture. This module keeps the public API, the served-text
decisions, the gate dry run and report assembly.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import errno
import hashlib
from pathlib import Path
import re
import unicodedata

from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.policy import ASTExtractionError, evaluate_forbid_ast_structured, extract_normalized_ast
from aegis_core.ast.source import decode_python_source
from aegis_core import scan as scan_service
from aegis_core.guidance_grammar import heading_has_slot, raw_do_instruction_span, raw_evidence_span
from aegis_core.guidance_projection import contains_control_characters, detail_instruction_visible
from aegis_core.packs import MAX_RULE_BYTES, PackPathError, parse_pack_path
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text
from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry, RuleInventoryError, inventory_rules
from aegis_core.rule_lint_capture import (
    RULE_PREFIX as _PREFIX,
    SOURCE_EXTENSIONS as _SOURCE_EXTENSIONS,
    capture_rules,
    capture_sources,
    documentation as _documentation,
    workspace_root as _workspace_root,
)
from aegis_core.rule_lint_grammar import (
    COMMAND_ROLES as _ROLES,
    CommandToken as _CommandToken,
    SLOT_REF as _REF,
    command_findings,
    command_roles,
    quiet_parse as _quiet_parse,
)
from aegis_core.rules import Rule, load_rules, rule_path_id
from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry
from aegis_core.storage import ConfinedFileError, confined_file
from aegis_core.storage import confined_descriptor_supported as descriptor_supported
from aegis_core.verification.forbid_ast_spec import forbid_ast_spec_error
from aegis_core.workspace.confinement import iter_confined_files
from aegis_core.yaml_engine.frontmatter import split_frontmatter

__all__ = [
    "LintFinding", "LintResult", "display_text", "lint_rule", "lint_workspace",
    "descriptor_supported", "MAX_RULE_BYTES", "MAX_RULES", "MAX_RULE_TOTAL",
    "MAX_SOURCE_BYTES", "MAX_SOURCE_FILES", "MAX_SOURCE_TOTAL", "MAX_ENTRIES",
    "MAX_SELECTIONS",
]

MAX_RULES = 2048
MAX_RULE_TOTAL = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
MAX_SOURCE_FILES = 512
MAX_SOURCE_TOTAL = 8 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_SELECTIONS = 256

@dataclass(frozen=True)
class LintFinding:
    """A fixed code/message; suggestions contain only built-in slot identities."""

    check: int
    code: str
    severity: str
    message: str
    suggestions: tuple[str, ...] = ()


@dataclass(frozen=True)
class LintResult:
    """Draft readiness, separate from the CLI's always-zero report-only status."""

    path: str
    findings: tuple[LintFinding, ...]
    gate_hits: int | None = None
    checked_files: int = 0

    @property
    def ok(self):
        return not any(f.severity == "error" for f in self.findings)


def display_text(value):
    """Canonicalize, redact, then truncate a bounded untrusted display label."""
    if type(value) is not str or len(value) > 1024:
        return "<invalid path>"
    text = sanitize_display(unicodedata.normalize("NFKC", value), max_len=None)
    text = "".join(c for c in text if unicodedata.category(c) not in {"Cf", "Cs"})
    text = " ".join(text.split())
    if len(text) > 4096:
        return "<invalid path>"
    text = redact_insight_text(text, max_len=0)
    end = 240
    for marker in re.finditer(r"\[REDACTED[^\]]*\]", text):
        if marker.start() < end < marker.end():
            end = marker.start()
            break
    return text[:end]


def _finding(check, code, message, severity="error", suggestions=()):
    return LintFinding(check, code, severity, message, tuple(sorted(set(suggestions))))


def _refusal(path, code):
    return LintResult(display_text(path), (_finding(0, code, "lint input refused: " + code),))


def _load(data, path):
    if _destination(path) is None:
        return None
    entry = RuleInventoryEntry(path, path, data, hashlib.sha256(data).hexdigest(), len(data))
    try:
        loaded = load_rules("/", inventory=RuleInventory((entry,), "lint"))
    except (ValueError, RecursionError, UnicodeError):
        return None
    if len(loaded.rules) != 1:
        return None
    rule = loaded.rules[0]
    return rule if _accepted(rule, path) else None


def _destination(path):
    if type(path) is not str or len(path) > 1024 or not path.startswith(_PREFIX):
        return None
    try:
        return parse_pack_path(path[len(_PREFIX):])
    except PackPathError:
        return None


def _accepted(rule, path):
    destination = _destination(path)
    if destination is None:
        return False
    if (not rule.ok or rule.expired or rule.legacy_keys
            or rule.meta.get("id") != destination.id or rule.meta.get("type") != destination.type):
        return False
    return True


def _guidance(body):
    """Derive retained text and the Do prefix only from scan's raw grammar."""
    decision, _, end = raw_evidence_span([body], heading_has_slot, contains_control_characters)
    retained = body[:end] if decision == 1 else body
    span = raw_do_instruction_span([retained], heading_has_slot, contains_control_characters)
    prefix = retained[:span[3]] if decision >= 0 and span[0] == 1 else None
    return retained, prefix


def _content(rule, body, retained, prefix, commands):
    findings = []
    for field in ("hypothesis", "prediction"):
        value = rule.meta.get(field)
        if not isinstance(value, str) or not value.strip():
            findings.append(_finding(2, "required_content", "hypothesis and prediction must be non-empty text"))
    fields = tuple(str(rule.meta.get(k, "")) for k in ("hypothesis", "prediction")) + (retained,)
    guidance = "\n\n".join(fields)
    known = set(DEFAULT_SLOTS)
    references = list(_REF.finditer(guidance))
    if any(ref[1] not in known for ref in references) or "${SLOT" in _REF.sub("", guidance):
        findings.append(_finding(3, "unknown_slot", "unknown slot or incomplete ${SLOT.*} placeholder"))
    if prefix is None or not all(
            detail_instruction_visible(body, prefix,
                                       SlotRegistry({**DEFAULT_SLOTS, **profile, **commands}).sanitized())
            for profile in PLATFORM_SLOT_PROFILES.values()):
        findings.append(_finding(2, "do_window", "first Do instruction must fit the rendered 300-character Detail window"))
    return findings, fields


def _canonical_head(tokens):
    words = list(tokens)
    if words and words[0].value == "$":
        words = words[1:]
    wrapped = False
    while words and (slot := _REF.fullmatch(words[0].value)):
        if slot[1] in _ROLES:
            return ()
        wrapped = True
        words = words[1:]
    if wrapped and (not words or words[0].value.startswith("-")):
        return ()
    if words and not _REF.fullmatch(words[0].value):
        program = words[0].value.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
        words[0] = _CommandToken(program)
        if re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)*)?", program):
            index = 1
            while index < len(words) and words[index].value in {"-B", "-E", "-I", "-s", "-S", "-u", "-O", "-OO", "-q", "-v", "-b", "-bb"}:
                index += 1
            if index + 1 < len(words) and words[index].value == "-m":
                words = words[index + 1:]
    if words and wrapped:
        words[0] = _CommandToken(words[0].value, wrapped=True)
    return tuple(words)


def _enforcement(rule, original):
    spec = rule.meta.get("forbid_ast")
    invalid = forbid_ast_spec_error(spec) if "forbid_ast" in rule.meta else None
    if invalid is None and (not rule.mandatory or "forbid_ast" in rule.meta):
        return []
    unchanged = (isinstance(original, Rule) and original.id == rule.id
                 and (original.type, original.enforcement, original.meta.get("forbid_ast"))
                 == (rule.type, rule.enforcement, spec))
    return [_finding(5, "paper_gate", "gate requires a valid non-empty forbid_ast specification",
                     "warning" if unchanged else "error")]


def _source_shape(sources):
    if type(sources) is not dict or len(sources) > MAX_SOURCE_FILES:
        raise _LintError("source_limit")
    total = 0
    for path, data in sources.items():
        if (type(path) is not str or not path or len(path) > 1024 or type(data) is not bytes
                or path.startswith("/") or any(c in path for c in ("\\", ":", "\x00"))):
            raise _LintError("source_unavailable")
        parts = path.split("/")
        if len(parts) > 128 or any(part in {"", ".", ".."} or len(part) > 255 for part in parts):
            raise _LintError("source_unavailable")
        total += len(data)
        if len(data) > MAX_SOURCE_BYTES or total > MAX_SOURCE_TOTAL:
            raise _LintError("source_limit")


def _extension_summary(extensions):
    # Every label is canonicalized and redacted before either truncation step.
    labels = sorted({display_text(extension or "<none>") for extension in extensions})
    selected = []
    for label in labels:
        if len(", ".join(selected + [label])) > 128:
            selected.append("...")
            break
        selected.append(label)
    return ", ".join(selected)


def _dry_run(rule, sources):
    spec = rule.meta.get("forbid_ast")
    if not spec or forbid_ast_spec_error(spec) is not None:
        return [], None, 0
    if sources is None:
        return [_finding(6, "source_unavailable", "gate dry run not evaluated: no source snapshot", "warning")], None, 0
    findings, count, checked, unevaluated = [], 0, 0, Counter()
    try:
        _source_shape(sources)
        unevaluated = Counter(Path(path).suffix for path in sources if rule.applies_to(path)
                              and Path(path).suffix.lower() not in _SOURCE_EXTENSIONS and not _documentation(path))
        for path, data in sorted(sources.items()):
            if not rule.applies_to(path):
                continue
            suffix = Path(path).suffix.lower()
            if suffix not in _SOURCE_EXTENSIONS:
                continue
            source = decode_python_source(data) if suffix == ".py" else data.decode("utf-8")
            tree = _quiet_parse(extract_normalized_ast, path, code=source)
            if tree is None:
                raise _LintError("source_unavailable")
            hits = evaluate_forbid_ast_structured(tree, spec, rule_id=rule.id, source=source)
            count += len(hits)
            checked += 1
    except _LintError as error:
        findings.append(_finding(6, error.code, "gate dry run not evaluated: source snapshot unavailable or over limit", "warning"))
    except (ASTExtractionError, ASTDriverError, ValueError, UnicodeError, RecursionError, SyntaxError, OSError):
        findings.append(_finding(6, "source_unavailable", "gate dry run not evaluated: source could not be parsed", "warning"))
    incomplete = []
    if unevaluated:
        extensions = _extension_summary(unevaluated)
        incomplete = [_finding(6, "dry_run_incomplete",
                               f"gate dry run incomplete: {sum(unevaluated.values())} unevaluated file(s); extensions: {extensions}", "warning")]
    if findings:
        return findings + incomplete, None, 0
    return [_finding(6, "gate_hits", f"gate dry run: {count} hit(s) across {checked} supported file(s)", "warning")] + incomplete, count, checked


def lint_rule(data, path, *, original=None, command_slots=None, sources=None):
    """Lint exact final bytes/path; ``original`` permits E7's unchanged-gate amendment.

    Callers materialize proposals before calling. ``sources`` is a bounded byte
    snapshot, never paths to open or code to execute. ``command_slots`` contains
    trusted user-scope role mappings, not repository configuration.
    """
    if type(data) is not bytes:
        return _refusal(path, "invalid_input")
    if len(data) > MAX_RULE_BYTES:
        return _refusal(path, "too_large")
    rule = _load(data, path)
    if rule is None:
        return LintResult(display_text(path), (_finding(1, "loader", "final accepted bytes or destination fail the rule loader"),))
    return _lint_loaded(rule, data, path, original, command_slots, sources)


def _lint_loaded(rule, data, path, original, command_slots, sources, source_error=None, simulation="not evaluated: no scan workspace"):
    try:
        commands = command_roles(command_slots, _LintError)
    except _LintError as error:
        return _refusal(path, error.code)
    body = split_frontmatter(data.decode("utf-8-sig"))[2]
    retained, prefix = _guidance(body)
    findings, guidance = _content(rule, body, retained, prefix, commands)
    findings.extend(command_findings(guidance, commands, _finding, _canonical_head))
    findings.extend(_enforcement(rule, original))
    if not rule.target_paths and "forbid_ast" not in rule.meta:
        findings.append(_finding(6, "target_paths", "target_paths is empty without forbid_ast", "warning"))
    dry, hits, checked = ([source_error], None, 0) if source_error else _dry_run(rule, sources)
    findings.extend(dry)
    findings.append(_finding(7, "scan_simulation", simulation, "warning"))
    return LintResult(display_text(path), tuple(findings), hits, checked)


class _LintError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__("lint input refused: " + code)


def _source_refusal(code):
    code = "source_limit" if code in {"source_limit", "too_large"} else "source_unavailable"
    return _finding(6, code, "gate dry run not evaluated: source capture refused", "warning")


def lint_workspace(root, paths=(), *, command_slots=None):
    """Report selected rule files/directories without any writes.

    Codes: unsupported, invalid_path, invalid_input, too_large, unsafe, missing,
    changed, io, loader. Per-file size refusals retain other rule results;
    inventory capture refusals return one fixed finding, not a partial report.
    The runtime inventory owns rule-set snapshot semantics; explicit candidates
    are bounded before inventory and compared to its bytes before parsing.
    """
    if not descriptor_supported():
        return (_refusal("", "unsupported"),)
    if type(paths) not in (list, tuple) or len(paths) > MAX_SELECTIONS:
        return (_refusal("", "invalid_input"),)
    try:
        root = _workspace_root(root, _LintError)
        snapshot, records, oversized, identities, captured = capture_rules(
            root, paths, _LintError, confined_file=confined_file, inventory_rules=inventory_rules,
            load_rules=load_rules, max_entries=MAX_ENTRIES, max_rules=MAX_RULES,
            max_rule_bytes=MAX_RULE_BYTES, max_rule_total=MAX_RULE_TOTAL)
        if any(entry.size > MAX_RULE_BYTES for entry in captured[0].entries):
            simulations = {rule.id: "not evaluated: scan inputs over limit" for rule in records}
        else:
            simulations = (getattr(scan_service, "simulate_rule_selection", None) or (lambda *_: {}))(root, *captured)
        duplicates = {name for name, count in identities.items() if count > 1}
        selected = sorted((rule for rule in records if rule.path in snapshot), key=lambda rule: rule.path)
        gates = [rule for rule in selected if rule.path not in oversized and _accepted(rule, rule.path)
                 and "forbid_ast" in rule.meta and forbid_ast_spec_error(rule.meta["forbid_ast"]) is None]
        sources, source_error = None, None
        if gates:
            try:
                sources = capture_sources(
                    root, gates, _LintError, confined_file=confined_file,
                    iter_confined_files=iter_confined_files, max_entries=MAX_ENTRIES,
                    max_source_files=MAX_SOURCE_FILES, max_source_bytes=MAX_SOURCE_BYTES,
                    max_source_total=MAX_SOURCE_TOTAL)
            except _LintError as error:
                source_error = _source_refusal(error.code)
            except ConfinedFileError as error:
                source_error = _source_refusal(error.reason)
            except (OSError, ValueError, UnicodeError):
                source_error = _source_refusal("source_unavailable")
        results = []
        by_path = {rule.path: rule for rule in selected}
        for path in sorted(snapshot.keys() | oversized):
            rule = by_path.get(path)
            if path in oversized:
                result = _refusal(path, "too_large")
                if rule_path_id(path) in duplicates:
                    result = LintResult(result.path, result.findings + (_duplicate_finding(),))
                results.append(result)
                continue
            if rule is None:
                continue
            if rule.id in duplicates:
                result = LintResult(display_text(rule.path), (_duplicate_finding(),))
            elif not _accepted(rule, rule.path):
                result = LintResult(display_text(rule.path), (_finding(1, "loader", "final accepted bytes or destination fail the rule loader"),))
            else:
                result = _lint_loaded(rule, snapshot[rule.path], rule.path, None, command_slots, sources,
                                      source_error if rule in gates else None,
                                      simulations.get(rule.id, "not evaluated: scan API unavailable"))
            results.append(result)
        return tuple(results)
    except _LintError as error:
        return (_refusal("", error.code),)
    except ConfinedFileError as error:
        code = error.reason if error.reason in {"unsupported", "invalid_path", "too_large", "unsafe", "missing"} else "io"
        return (_refusal("", code),)
    except RuleInventoryError as error:
        code = "unsafe" if error.operation == "validate" else "changed"
        if error.cause is not None:
            code = _io_code(error.cause)
        return (_refusal("", code),)
    except OSError as error:
        return (_refusal("", _io_code(error)),)
    except (ValueError, UnicodeError):
        return (_refusal("", "invalid_path"),)


def _duplicate_finding():
    return _finding(1, "duplicate", "duplicate rule id in captured inventory")


def _io_code(error):
    return {errno.ENOENT: "missing", errno.ELOOP: "unsafe", errno.ENOTDIR: "unsafe"}.get(getattr(error, "errno", None), "io")
