"""Example and command analysis for read-only rule lint.

This module tokenizes Markdown examples and configured commands. It does not
decide which guidance scan serves. Headings, Evidence spans, withheld fields,
control predicates and the Do window stay on the public scan grammar, and the
reviewed command-head canonicalizer stays in rule_lint.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
import ast
import re
import shlex
from threading import RLock
import unicodedata
import warnings

from aegis_core.skills.slots import DEFAULT_SLOTS, PLATFORM_SLOT_PROFILES

__all__ = [
    "COMMAND_ROLES",
    "CommandToken",
    "SLOT_REF",
    "command_findings",
    "command_roles",
    "quiet_parse",
]

_ROLES = ("TEST_RUNNER", "LINTER", "FORMATTER", "TYPE_CHECKER", "BUILD_TOOL")
_REF = re.compile(r"\$\{SLOT\.([A-Za-z0-9_-]+)\}")
_HEADING = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*)|[ \t]*$)")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_CONTAINER_PREFIX = re.compile(r"^(?:\s+|>\s*|(?:[-+*]|[0-9]+[.)])(?:\s+|$))*")
_ATTRIBUTE = r'''[A-Za-z_:][A-Za-z0-9_.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|"[^"]*"|'[^']*'))?'''
_INLINE_HTML = re.compile(r"<(?:/?[A-Za-z][A-Za-z0-9-]*(?:\s+" + _ATTRIBUTE + r")*\s*/?"
                          r"|[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\x00-\x20<>]*)>")
_PARSE_LOCK = RLock()

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


def quiet_parse(parser, *args, **kwargs):
    # Compiler diagnostics are not lint reports. Serialize our warning contexts
    # on Python 3.9--3.12, whose warning-filter state is shared across threads.
    with _PARSE_LOCK, warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        return parser(*args, **kwargs)


def _literal_example(text):
    try:
        node = quiet_parse(ast.parse, text.strip(), mode="eval").body
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


def _command_model(text, canonical_head):
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
            result.extend(canonical_head(tokens[start:index]))
            result.append(token)
            start = index + 1
    result.extend(canonical_head(tokens[start:]))
    return tuple(result)


def command_roles(commands, refuse):
    if commands is None:
        return {}
    if type(commands) is not dict or len(commands) > 64:
        raise refuse("invalid_input")
    selected = {}
    for key, value in commands.items():
        if key not in _ROLES:
            continue
        if type(value) is not str or len(value) > 4096:
            raise refuse("too_large" if type(value) is str else "invalid_input")
        selected[key] = value
    return selected


def _command_mappings(commands, canonical_head):
    full = []
    for key in _ROLES:
        for text in {DEFAULT_SLOTS[key], commands.get(key, DEFAULT_SLOTS[key])}:
            tokens = _command_model(text, canonical_head)
            if tokens:
                full.append((tokens, "concrete_command", "$" + "{SLOT." + key + "}"))
    for profile in PLATFORM_SLOT_PROFILES.values():
        for key, text in profile.items():
            tokens = _command_model(text, canonical_head)
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


def command_findings(fields, commands, finding, canonical_head):
    mappings = _command_mappings(commands, canonical_head)
    slots, unknown = {}, False
    for example, executable, supplemental in (example for text in fields for example in _command_examples(text)):
        if _literal_example(example):
            continue
        tokens = _command_model(example, canonical_head)
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
            findings.append(finding(4, code, message, suggestions=slots[code]))
    if unknown:
        findings.append(finding(4, "unmapped_command", "executable example has no explicit command role mapping", "warning"))
    return findings

SLOT_REF = _REF
COMMAND_ROLES = _ROLES
CommandToken = _CommandToken
