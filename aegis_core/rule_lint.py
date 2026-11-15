"""Read-only mining lint of exact accepted-rule bytes and final destinations.

Checks 1--5 refuse drafts, 6 warns, and 7 is explicitly deferred to
M2C-SCAN-SIM. No proposal, rule, ledger or decision is written. Filesystem
candidates use bounded confined reads; rule sets use the runtime inventory.
Unsupported platforms report a fixed refusal. In-memory lint works on every host.
"""
from __future__ import annotations

from collections import Counter
from bisect import bisect_right
from dataclasses import dataclass, field, replace
import ast
import codecs
import errno
import hashlib
from pathlib import Path
import re
import shlex
from threading import RLock
import unicodedata
import warnings

from aegis_core.ast.detect import NATIVE_SOURCE_EXTENSIONS
from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.policy import ASTExtractionError, evaluate_forbid_ast_structured, extract_normalized_ast
from aegis_core.ast.source import decode_python_source
from aegis_core.packs import MAX_RULE_BYTES, PackPathError, parse_pack_path
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text
from aegis_core.rule_inventory import RuleInventory, RuleInventoryEntry, RuleInventoryError, inventory_rules
from aegis_core.rules import Rule, load_rules, rule_path_id
from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES, SlotRegistry
from aegis_core.storage import ConfinedFileError, confined_file
from aegis_core.storage import confined_descriptor_supported as descriptor_supported
from aegis_core.verification.forbid_ast_spec import forbid_ast_spec_error
from aegis_core.workspace.layout import RULES_RELDIR, WorkspaceLayout
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
_PREFIX = RULES_RELDIR + "/"
_ROLES = ("TEST_RUNNER", "LINTER", "FORMATTER", "TYPE_CHECKER", "BUILD_TOOL")
_SOURCE_EXTENSIONS = NATIVE_SOURCE_EXTENSIONS | {".py"}
_DOCUMENT_EXTENSIONS = {".md", ".markdown", ".rst", ".txt", ".adoc", ".png", ".jpg", ".jpeg",
                        ".gif", ".svg", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".avif", ".heic"}
_REF = re.compile(r"\$\{SLOT\.([A-Za-z0-9_-]+)\}")
_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*)|[ \t]*$)")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_CONTAINER_PREFIX = re.compile(r"^(?:\s+|>\s*|(?:[-+*]|[0-9]+[.)])(?:\s+|$))*")
_ATTRIBUTE = r'''[A-Za-z_:][A-Za-z0-9_.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|"[^"]*"|'[^']*'))?'''
_INLINE_HTML = re.compile(r"<(?:/?[A-Za-z][A-Za-z0-9-]*(?:\s+" + _ATTRIBUTE + r")*\s*/?"
                          r"|[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\x00-\x20<>]*)>")
_PARSE_LOCK = RLock()


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
    """Exclude reserved Evidence sections before selecting the actual Do line."""
    lines, evidence, in_do, do_index = [], False, False, None
    for raw, _, kind, _ in _markdown_lines(body):
        line = raw.rstrip("\r\n")
        if not lines and not line.strip():
            continue
        heading = _HEADING.match(line) if kind == "heading" else None
        if heading and len(heading[1]) <= 2:
            title = (heading[2] or "").strip().rstrip("#").rstrip().casefold()
            evidence = len(heading[1]) == 2 and title == "evidence"
            in_do = len(heading[1]) == 2 and title == "do"
        if evidence:
            continue
        if in_do and do_index is None and _CONTAINER_PREFIX.sub("", line).strip() and kind == "inline":
            do_index = len(lines)
        lines.append(line)
    return lines, do_index


def _content(rule, lines, do_index, commands):
    findings = []
    for field in ("hypothesis", "prediction"):
        value = rule.meta.get(field)
        if not isinstance(value, str) or not value.strip():
            findings.append(_finding(2, "required_content", "hypothesis and prediction must be non-empty text"))
    fields = tuple(str(rule.meta.get(k, "")) for k in ("hypothesis", "prediction")) + ("\n".join(lines),)
    guidance = "\n\n".join(fields)
    known = set(DEFAULT_SLOTS)
    references = list(_REF.finditer(guidance))
    if any(ref[1] not in known for ref in references) or "${SLOT" in _REF.sub("", guidance):
        findings.append(_finding(3, "unknown_slot", "unknown slot or incomplete ${SLOT.*} placeholder"))
    if do_index is None or do_index >= 8:
        findings.append(_finding(2, "do_window", "first Do instruction must fit the rendered 300-character Detail window"))
    else:
        for profile in PLATFORM_SLOT_PROFILES.values():
            registry = SlotRegistry({**DEFAULT_SLOTS, **profile, **commands}).sanitized()
            rendered = [registry.resolve(line.strip(), strict=False) for line in lines[:do_index + 1]]
            if len(" ".join(rendered)) > 300:
                findings.append(_finding(2, "do_window", "first Do instruction must fit the rendered 300-character Detail window"))
                break
    return findings, fields


@dataclass(frozen=True)
class _CommandToken:
    """Shell word or an unquoted control; quoting never manufactures controls."""

    value: str
    control: bool = False
    wrapped: bool = field(default=False, compare=False)


def _code_spans(text):
    runs = {match.start(): match.end() for match in re.finditer(r"\x60+", text)}
    widths = {}
    for start, end in runs.items():
        widths.setdefault(end - start, []).append(start)
    index = 0
    while index < len(text):
        if text[index] not in "<`":
            index += 1
            continue
        back = index - 1
        while back >= 0 and text[back] == "\\":
            back -= 1
        escaped = (index - 1 - back) % 2
        if text[index] == "<" and not escaped:
            literal = _INLINE_HTML.match(text, index)
            if literal:
                index = literal.end()
                continue
        end = runs.get(index)
        if end is None:
            index += 1
            continue
        start = index + escaped  # Only the first tick of an escaped run is literal.
        candidates = widths.get(end - start, [])
        following = bisect_right(candidates, index)
        if following == len(candidates):
            index = end
            continue
        closing = candidates[following]
        value = text[end:closing]
        value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ")
        if value.startswith(" ") and value.endswith(" ") and value.strip(" "):
            value = value[1:-1]
        yield value, start
        index = runs[closing]


def _inline_examples(text):
    return ((value, bool(re.search(r"\b(?:run|execute|invoke)\s+$",
                                  text[max(0, start - 80):start], re.I)))
            for value, start in _code_spans(text))


def _expanded_indent(raw):
    prefix = _CONTAINER_PREFIX.match(raw)[0]
    return prefix.expandtabs(4) + raw[len(prefix):]


def _fence_content(raw, quote_depth, list_indent):
    """Remove only the containers that enclosed the opening fence."""
    line = _expanded_indent(raw)
    for _ in range(quote_depth):
        prefix = re.match(r"^ {0,3}>[ \t]?", line)
        if prefix is None:
            return None
        line = line[prefix.end():]
    if list_indent and line.strip():
        if not line.startswith(" " * list_indent):
            return None
        line = line[list_indent:]
    return line


def _markdown_lines(guidance):
    """One block grammar for section selection and executable-example extraction."""
    fence, shell, quote_depth, list_indent = None, False, 0, 0
    for raw in guidance.splitlines(keepends=True):
        if fence is not None:
            line = _fence_content(raw, quote_depth, list_indent)
            if line is not None:
                marker = _FENCE.match(line.rstrip("\r\n"))
                kind = "shell" if shell else "fenced"
                if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                    fence, shell, kind = None, False, "fence"
                yield raw, line, kind, False
                continue
            fence, shell = None, False
        line = _expanded_indent(raw)
        depth, offset = 0, 0
        while True:
            prefix = re.compile(r" {0,3}>[ \t]?").match(line, offset)
            if prefix is None:
                break
            offset = prefix.end()
            depth += 1
        line = line[offset:]
        item = re.match(r"^ {0,3}(?:[-+*]|[0-9]{1,9}[.)])(?:[ \t]+|(?=\r?$))", line)
        boundary = depth != quote_depth or item is not None
        if depth != quote_depth:
            list_indent = 0
        quote_depth = depth
        if item:
            list_indent = item.end()
            line = line[item.end():]
        elif list_indent and line.strip():
            if line.startswith(" " * list_indent):
                line = line[list_indent:]
            else:
                list_indent = 0
        marker = _FENCE.match(line.rstrip("\r\n"))
        if fence is None and marker and not (marker[1][0] == chr(96) and chr(96) in marker[2]):
            fence = marker[1]
            shell = marker[2].strip().lower() in {"sh", "bash", "shell", "console", "powershell", "zsh"}
            kind = "fence"
        elif not line.strip():
            kind = "blank"
        elif line.startswith(("    ", "\t")):
            kind = "code"
        elif _HEADING.match(line):
            kind = "heading"
        else:
            kind = "inline"
        yield raw, line, kind, boundary


def _markdown_blocks(guidance):
    previous, window = None, []
    for raw, line, kind, boundary in _markdown_lines(guidance):
        boundary |= kind == "inline" and bool(re.search(r"[-+*]|[0-9][.)]", _CONTAINER_PREFIX.match(raw)[0]))
        if boundary or kind != previous:
            yield previous == "shell", "".join(window)
            window = []
        if kind in {"inline", "shell"}:
            window.append(line)
        elif kind == "heading":
            yield False, _HEADING.match(line)[2] or ""
        previous = kind
    yield previous == "shell", "".join(window)


def _examples(blocks):
    for shell, block in blocks:
        if not shell:
            yield from ((text, executable, False) for text, executable in _inline_examples(block))
            continue
        # A continued physical shell line belongs to the same executable example.
        logical = ""
        for line in block.splitlines(keepends=True):
            logical += line
            tail = line.rstrip("\r\n")
            if (len(tail) - len(tail.rstrip("\\"))) % 2:
                continue
            if logical.strip():
                yield logical, True, True
            logical = ""
        if logical.strip():
            yield logical, True, True


def _stripped_blocks(guidance):
    """Read all container levels independently of the Markdown block parser."""
    fence, depth, window = None, 0, []
    for raw in guidance.splitlines() + [""]:
        prefix = _CONTAINER_PREFIX.match(raw)[0]
        line = raw[len(prefix):]
        marker = _FENCE.match(line)
        if marker and marker[1][0] == chr(96) and chr(96) in marker[2]:
            marker = None
        quoted = prefix.count(">")
        closing = fence and marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip()
        if closing or (fence is None and (marker or not line or quoted != depth or re.search(r"[-+*]|[0-9][.)]", prefix))):
            yield fence is not None, "\n".join(window)
            window = []
        if marker and (fence is None or closing):
            fence = marker[1] if fence is None else None
        else:
            window.append(line)
        depth = quoted
    yield fence is not None, "\n".join(window)


def _command_examples(guidance):
    """Union the four block, physical-line and stripped-container readings.

    Supplemental readings can add configured matches, never unmapped warnings.
    """
    examples = {(text, executable): False for text, executable, _ in _examples(_markdown_blocks(guidance))}
    for _, line, kind, _ in _markdown_lines(guidance):
        if kind in {"shell", "fenced"}:
            examples.setdefault((line, True), True)
    for line in guidance.splitlines():
        for example in _inline_examples(line):
            examples.setdefault(example, True)
    for (text, executable), supplemental in examples.items():
        yield text, executable, supplemental
    yield from _examples(_stripped_blocks(guidance))


def _quiet_parse(parser, *args, **kwargs):
    # Compiler diagnostics are not lint reports. Serialize our warning contexts
    # on Python 3.9--3.12, whose warning-filter state is shared across threads.
    with _PARSE_LOCK, warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        return parser(*args, **kwargs)


def _literal_example(text):
    try:
        node = _quiet_parse(ast.parse, text.strip(), mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        return False
    return isinstance(node, (ast.Constant, ast.Call, ast.Subscript, ast.Lambda,
                             ast.List, ast.Tuple, ast.Set, ast.Dict, ast.ListComp,
                             ast.SetComp, ast.DictComp, ast.GeneratorExp))


def _command_lexemes(text):
    """Keep literal path separators and POSIX escapes, quotes and word boundaries."""
    chunk, index, quote, boundary, comment = [], 0, None, True, False
    while index < len(text):
        char = text[index]
        if comment:
            if char not in "\r\n":
                index += 1
                continue
            comment = False
        if char == "\\" and quote != "'" and index + 1 < len(text):
            following = text[index + 1]
            if following.isspace() or following in "\"'#\\$`":
                width = 3 if text[index + 1:index + 3] == "\r\n" else 2
                if following not in "\r\n":
                    literal = '"\'"' if following == "'" else "'" + following + "'"
                    chunk.append((quote or "") + literal + (quote or ""))
                    boundary = False
                index += width
                continue
        if quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
            boundary = False
        elif char == "#" and boundary:
            yield "".join(chunk), False
            chunk = []
            comment = True
            index += 1
            continue
        elif char in ";&|\r\n":
            yield "".join(chunk), False
            chunk = []
            width = 2 if text[index:index + 2] in {"&&", "||", "\r\n"} else 1
            control = text[index:index + width]
            yield "\n" if control in {"\r", "\r\n"} else control, True
            index += width
            boundary = True
            continue
        elif not quote:
            boundary = char.isspace()
        chunk.append(char)
        index += 1
    if not comment:
        yield "".join(chunk), False


def _command_segments(tokens):
    start = 0
    for index, token in enumerate(tokens):
        if token.control:
            if start < index:
                yield start, index
            start = index + 1
    if start < len(tokens):
        yield start, len(tokens)


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


def _command_model(text):
    tokens = []
    try:
        for value, control in _command_lexemes(unicodedata.normalize("NFKC", text)):
            if control:
                tokens.append(_CommandToken(value, True))
            else:
                lexer = shlex.shlex(value, posix=True, punctuation_chars=";&|")
                lexer.whitespace_split, lexer.commenters = True, ""
                lexer.escape = ""  # Selective escapes were encoded above, identically for mappings.
                tokens.extend(_CommandToken(word) for word in lexer)
    except ValueError:
        return None
    # Normalize each head independently without losing original control offsets.
    result, start = [], 0
    for index, token in enumerate(tokens):
        if token.control:
            result.extend(_canonical_head(tokens[start:index]))
            result.append(token)
            start = index + 1
    result.extend(_canonical_head(tokens[start:]))
    return tuple(result)


def _command_roles(commands):
    if commands is None:
        return {}
    if type(commands) is not dict or len(commands) > 64:
        raise _LintError("invalid_input")
    selected = {}
    for key, value in commands.items():
        if key not in _ROLES:
            continue
        if type(value) is not str or len(value) > 4096:
            raise _LintError("too_large" if type(value) is str else "invalid_input")
        selected[key] = value
    return selected


def _command_mappings(commands):
    full = []
    for key in _ROLES:
        for text in {DEFAULT_SLOTS[key], commands.get(key, DEFAULT_SLOTS[key])}:
            tokens = _command_model(text)
            if tokens:
                full.append((tokens, "concrete_command", "$" + "{SLOT." + key + "}"))
    for profile in PLATFORM_SLOT_PROFILES.values():
        for key, text in profile.items():
            tokens = _command_model(text)
            if tokens:
                full.append((tokens, "vendor_name", "$" + "{SLOT." + key + "}"))
    return tuple(dict.fromkeys(full))


def _command_prefixes(full):
    prefixes = []
    for tokens, code, slot in full:
        for begin, end in _command_segments(tokens):
            prefix = tokens[begin:end]
            while prefix and prefix[-1].value in {"-q", "-v", "--quiet", "--verbose"}:
                prefix = prefix[:-1]
            if prefix:
                prefixes.append((prefix, code, slot))
    return tuple(dict.fromkeys(prefixes))


def _matches_at(tokens, begin, pattern):
    return begin + len(pattern) <= len(tokens) and all(
        tokens[begin + offset] == token for offset, token in enumerate(pattern))


def _match_command(tokens, mappings, executable):
    matches, covered, unknown = set(), set(), False
    # Complete compound commands are recognized before segment-prefix fallback.
    for begin, token in enumerate(tokens):
        if token.control or (begin and not tokens[begin - 1].control) or _REF.fullmatch(token.value):
            continue
        for pattern, code, slot in mappings:
            if _matches_at(tokens, begin, pattern):
                matches.add((code, slot))
                covered.update(range(begin, begin + len(pattern)))
    prefixes = _command_prefixes(mappings)
    for begin, end in _command_segments(tokens):
        if _REF.fullmatch(tokens[begin].value) or all(i in covered for i in range(begin, end)):
            continue
        found = {(code, slot) for pattern, code, slot in prefixes
                 if len(pattern) <= end - begin and _matches_at(tokens, begin, pattern)}
        matches.update(found)
        values = [token.value for token in tokens[begin:end]]
        if not found and (executable or tokens[begin].wrapped or (len(values) > 1 and re.fullmatch(r"[A-Za-z0-9_./-]+", values[0])
                                        and values[1] not in {"=", "==", "is", "in"})):
            unknown = True
    return matches, unknown


def _names(fields, commands):
    mappings = _command_mappings(commands)
    slots, unknown = {}, False
    for example, executable, supplemental in (example for text in fields for example in _command_examples(text)):
        if _literal_example(example):
            continue
        tokens = _command_model(example)
        if tokens is None:
            unknown |= not supplemental and (executable or any(c.isspace() for c in example))
            continue
        matches, unmapped = _match_command(tokens, mappings, executable)
        unknown |= unmapped and not supplemental
        for code, slot in matches:
            slots.setdefault(code, set()).add(slot)
    findings = []
    for code, message in (("vendor_name", "replace concrete tool/model name with a capability slot"),
                          ("concrete_command", "replace concrete project command with a role slot")):
        if code in slots:
            findings.append(_finding(4, code, message, suggestions=slots[code]))
    if unknown:
        findings.append(_finding(4, "unmapped_command", "executable example has no explicit command role mapping", "warning"))
    return findings


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


def _documentation(path):
    name = Path(path).name
    return (Path(path).suffix.lower() in _DOCUMENT_EXTENSIONS
            or name.upper().startswith(("README", "LICENSE", "CHANGELOG", "NOTICE")))


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


def _lint_loaded(rule, data, path, original, command_slots, sources, source_error=None):
    try:
        commands = _command_roles(command_slots)
    except _LintError as error:
        return _refusal(path, error.code)
    body = split_frontmatter(data.decode("utf-8-sig"))[2]
    lines, do_index = _guidance(body)
    findings, guidance = _content(rule, lines, do_index, commands)
    findings.extend(_names(guidance, commands))
    findings.extend(_enforcement(rule, original))
    if not rule.target_paths and "forbid_ast" not in rule.meta:
        findings.append(_finding(6, "target_paths", "target_paths is empty without forbid_ast", "warning"))
    dry, hits, checked = ([source_error], None, 0) if source_error else _dry_run(rule, sources)
    findings.extend(dry)
    findings.append(_finding(7, "scan_simulation", "not evaluated: pending M2C-SCAN-SIM", "warning"))
    return LintResult(display_text(path), tuple(findings), hits, checked)


class _LintError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__("lint input refused: " + code)


def _workspace_root(root):
    spelling = str(root) if isinstance(root, Path) else root
    if type(spelling) is not str or len(spelling) > 32768 or "\x00" in spelling:
        raise _LintError("invalid_path")
    path = Path(spelling)
    if not path.is_absolute() or ".." in path.parts:
        raise _LintError("invalid_path")
    spelling.encode("utf-8")
    return path


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(root, parts, limit):
    with confined_file(root, parts) as reader:
        before = _signature(reader.parent_stat())
        data = reader.read_bytes(limit)
        if _signature(reader.parent_stat()) != before:
            raise _LintError("changed")
        return data


def _parts(path, root):
    if type(path) is not str or not path or len(path) > 1024 or any(c in path for c in ("\x00", "\\")):
        raise _LintError("invalid_path")
    if Path(path).is_absolute():
        try:
            path = Path(path).relative_to(root).as_posix()
        except ValueError:
            raise _LintError("invalid_path") from None
    parts = path.split("/")
    layout = WorkspaceLayout(Path(root))
    rules_parts = layout.rules_dir.relative_to(layout.root).parts
    if (tuple(parts[:len(rules_parts)]) != rules_parts or len(parts) > 32
            or any(not part or part in {".", ".."} or len(part) > 255 for part in parts)):
        raise _LintError("invalid_path")
    return parts


def _rule_excluded(path):
    parts = path[len(_PREFIX):].split("/")
    return not path.startswith(_PREFIX) or any(part.startswith(".") for part in parts[:-1])


def _classification_prefix(data):
    """Complete bounded metadata or empty headerless text, with whole-file UTF-8."""
    decoder = codecs.getincrementaldecoder("utf-8-sig")()
    try:
        text = decoder.decode(data[:MAX_RULE_BYTES], final=False)
        end = min(len(data), MAX_RULE_BYTES) - len(decoder.getstate()[0])
        status, _, body = split_frontmatter(text)
        if status == "unterminated":
            return None
        if status == "ok":
            if not body.startswith("\n") and end < len(data):
                return None
            end -= len(body.encode("utf-8")) - int(body.startswith("\n"))
        else:
            end = 0
        for offset in range(MAX_RULE_BYTES, len(data), MAX_RULE_BYTES):
            decoder.decode(data[offset:offset + MAX_RULE_BYTES], final=False)
        decoder.decode(b"", final=True)
    except UnicodeError:
        return None
    return data[:end]


def _rules(root, paths):
    layout = WorkspaceLayout(root)
    selections = [_parts(path, root) for path in paths or [layout.rules_dir.relative_to(layout.root).as_posix()]]
    candidates, requested, oversized = {}, set(), set()
    for parts in selections:
        if parts[-1].lower().endswith(".md"):
            path = "/".join(parts)
            if path not in requested:
                requested.add(path)
                if len(requested) > MAX_RULES:
                    raise _LintError("too_large")
                if _rule_excluded(path):
                    continue
                # Multiple selections are a rule set, captured once by the
                # runtime inventory. Only a single candidate needs this extra
                # bounded read and exact-byte comparison before inventory.
                if len(selections) != 1:
                    continue
                try:
                    data = _read(root, parts, MAX_RULE_BYTES)
                except ConfinedFileError as error:
                    if error.reason != "too_large":
                        raise
                    oversized.add(path)
                    continue
                candidates[path] = data
        else:
            # Validate the selected directory without opening or creating a file.
            with confined_file(root, parts + [".lint-probe"]) as directory:
                directory.parent_stat()
    inventory = inventory_rules(str(root))
    # Post-capture bounds precede parsing. Inventory allocation and ancestor
    # anchoring belong to the shared reader (RF-32), not this consumer.
    if len(inventory.entries) > MAX_ENTRIES:
        raise _LintError("too_large")
    all_paths = {entry.relative_path for entry in inventory.entries}
    entries = tuple(entry for entry in inventory.entries if not _rule_excluded(entry.relative_path))
    if len(entries) > MAX_RULES:
        raise _LintError("too_large")
    found, total, bounded_entries, prefix_paths = {}, 0, [], set()
    prefixes = ["/".join(parts) for parts in selections]
    for entry in entries:
        data, path = entry.content, entry.relative_path
        if path in candidates and data != candidates[path]:
            raise _LintError("changed")
        if path in oversized and len(data) <= MAX_RULE_BYTES:
            raise _LintError("changed")
        bounded = entry
        if len(data) > MAX_RULE_BYTES:
            oversized.add(path)
            prefix = _classification_prefix(data)
            bounded = None if prefix is None else replace(entry, content=prefix, size=len(prefix),
                                                         digest=hashlib.sha256(prefix).hexdigest())
            if bounded is not None:
                prefix_paths.add(path)
        if bounded is not None:
            if total + len(bounded.content) > MAX_RULE_TOTAL:
                raise _LintError("too_large")
            total += len(bounded.content)
            bounded_entries.append(bounded)
        found[path] = data
    if (candidates.keys() | oversized) - found.keys():
        raise _LintError("changed")
    if requested - all_paths:
        raise _LintError("missing")
    # Validate all bounded entries together, including unselected rules.
    # Oversized bodies never reach parsing. Bounded classification prefixes let
    # this same public loader distinguish documentation from error records.
    try:
        bounded = RuleInventory(tuple(bounded_entries), inventory.fingerprint)
        loaded = load_rules(root, inventory=bounded)
    except (ValueError, UnicodeError, RecursionError):
        raise _LintError("loader") from None
    selected = {path: data for path, data in found.items()
                if any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)}
    oversized.difference_update(prefix_paths - {rule.path for rule in loaded.rules})
    identities = Counter(rule_path_id(path) for path in oversized)
    identities.update(rule.id for rule in loaded.rules if rule.path not in oversized)
    return selected, loaded.rules, oversized & selected.keys(), identities


def _sources(root, rules):
    sources, total, count = {}, 0, 0
    # Reuse public enumeration; reads themselves remain descriptor-confined.
    for path, problem in iter_confined_files(root, root, suffix=""):
        relative = path.relative_to(root).as_posix()
        if relative.split("/", 1)[0] == ".git":
            continue
        count += 1
        if count > MAX_ENTRIES:
            raise _LintError("source_limit")
        if problem:
            raise _LintError("source_unavailable")
        if len(relative) > 1024:
            raise _LintError("source_limit")
        if not any(rule.applies_to(relative) for rule in rules):
            continue
        if path.suffix.lower() not in _SOURCE_EXTENSIONS and _documentation(relative):
            continue
        if len(sources) >= MAX_SOURCE_FILES:
            raise _LintError("source_limit")
        data = _read(root, relative.split("/"), min(MAX_SOURCE_BYTES, MAX_SOURCE_TOTAL - total))
        total += len(data)
        sources[relative] = data
    return sources


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
        root = _workspace_root(root)
        snapshot, records, oversized, identities = _rules(root, paths)
        duplicates = {name for name, count in identities.items() if count > 1}
        selected = sorted((rule for rule in records if rule.path in snapshot), key=lambda rule: rule.path)
        gates = [rule for rule in selected if rule.path not in oversized and _accepted(rule, rule.path)
                 and "forbid_ast" in rule.meta and forbid_ast_spec_error(rule.meta["forbid_ast"]) is None]
        sources, source_error = None, None
        if gates:
            try:
                sources = _sources(root, gates)
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
                                      source_error if rule in gates else None)
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
