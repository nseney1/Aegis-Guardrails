"""Zero-dependency AegisYAML parser with DoS and security limits."""
from __future__ import annotations
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

MAX_DOC_BYTES: int = 512 * 1024
MAX_SCALAR_CHARS: int = 4096
MAX_LINES: int = 5000
MAX_DEPTH: int = 20
ZERO_WIDTH_CHARS = ("\ufeff", "\u200b", "\u200c", "\u200d")

class AegisYAMLError(ValueError):
    """Base error raised when AegisYAML validation, parsing, or security limits fail."""

FrontmatterError = AegisYAMLError
_BOOL_TRUE = frozenset(("true", "yes", "on"))
_BOOL_FALSE = frozenset(("false", "no", "off"))
_NULL_VALUES = frozenset(("", "~", "null"))
_INT_RE = re.compile(r"^[-+]?[0-9]+$")
_FLOAT_RE = re.compile(r"^[-+]?(?:[0-9]+\.[0-9]*(?:[eE][-+][0-9]+)?|\.[0-9]+(?:[eE][-+][0-9]+)?)$")
_SEQ_MAPPING_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*:(?:\s|$)")
_MAPPING_COLON_RE = re.compile(r":(?:[ \t]|$)")
_UNSUPPORTED_PREFIXES = ("&", "*", "!", "%", "@", "`")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "'": "'", " ": " "}
_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
_BLOCK_INDICATORS = ("|", "|-", "|+", ">", ">-", ">+")

def _unescape_double(body: str) -> str:
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "0": raise AegisYAMLError("Escape sequence \\0 is not permitted")
            if nxt == "\r" and i + 2 < len(body) and body[i + 2] == "\n": i += 3
            elif nxt == "\n": i += 2
            elif nxt in _ESCAPES: out.append(_ESCAPES[nxt]); i += 2
            elif nxt in ("u", "U") and i + (5 if nxt == "u" else 9) < len(body):
                span = 6 if nxt == "u" else 10
                digits = body[i + 2 : i + span]
                if not _HEX_RE.fullmatch(digits): out.append(nxt); i += 2; continue
                cp = int(digits, 16)
                if cp > 0x10FFFF: raise AegisYAMLError(f"Escape sequence \\{nxt}{digits} is outside the Unicode range (max U+10FFFF)")
                # NUL is refused raw (_prepare_lines) and as \0; refusing every spelling keeps U+0000 out of all parsed text.
                if cp == 0: raise AegisYAMLError(f"Escape sequence \\{nxt}{digits} decodes to NUL, which is not permitted")
                out.append(chr(cp)); i += span
            else: out.append(nxt); i += 2
        else: out.append(ch); i += 1
    return "".join(out)

def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t": i += 1
    return i

def _is_escaped_quote_pair(text: str, i: int, quote: str) -> bool:
    return (quote == '"' and text[i] == "\\" and i + 1 < len(text)) or (quote == "'" and text[i] == "'" and i + 1 < len(text) and text[i + 1] == "'")

def _read_token(text: str, start: int, stops: str) -> Tuple[str, int]:
    i, quote = start, None
    while i < len(text):
        ch = text[i]
        if quote:
            if _is_escaped_quote_pair(text, i, quote): i += 2; continue
            if ch == quote: quote = None
            i += 1
        elif ch in ('"', "'") and i == start: quote, i = ch, i + 1
        elif ch in stops: break
        else: i += 1
    if quote: raise FrontmatterError("unterminated quoted string")
    return text[start:i], i

def _strip_comment(line: str, quote: Optional[str] = None) -> str:
    if "#" not in line: return line
    out, i = [], 0
    while i < len(line):
        ch = line[i]
        if quote:
            if _is_escaped_quote_pair(line, i, quote): out.append(line[i : i + 2]); i += 2; continue
            if ch == quote: quote = None
            out.append(ch)
        elif ch in ('"', "'"): quote = ch; out.append(ch)
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"): break
        else: out.append(ch)
        i += 1
    return "".join(out)

def _find_unclosed_quote(line: str, initial_quote: Optional[str] = None) -> Optional[str]:
    quote, i = initial_quote, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if _is_escaped_quote_pair(line, i, quote): i += 2; continue
            if ch == quote: quote = None
        elif ch in ('"', "'"): quote = ch
        i += 1
    return quote

def _is_quote_closed(text: str, quote_char: str) -> bool:
    if len(text) < 2 or not text.endswith(quote_char): return False
    if quote_char == '"':
        bs_count, k = 0, len(text) - 2
        while k >= 0 and text[k] == "\\": bs_count, k = bs_count + 1, k - 1
        return (bs_count % 2) == 0
    q_count, k = 0, len(text) - 1
    while k >= 0 and text[k] == "'": q_count, k = q_count + 1, k - 1
    return (q_count % 2 == 0) if q_count == len(text) else (q_count % 2 == 1)

def _parse_scalar(raw: str, lineno: int = 1) -> Any:
    text = raw.strip()
    if len(text) > MAX_SCALAR_CHARS: raise AegisYAMLError(f"Scalar length ({len(text)}) exceeds maximum limit ({MAX_SCALAR_CHARS}) at line {lineno}")
    if text[:1] in ('"', "'"):
        if len(text) < 2 or text[-1] != text[0]: raise FrontmatterError(f"unterminated quoted scalar: {text[:24]!r}")
        body = text[1:-1]
        return _unescape_double(body) if text[0] == '"' else body.replace("''", "'")
    if text[:1] in ("[", "{"):
        value, idx = _parse_flow(text, 0, lineno=lineno)
        if text[idx:].strip(): raise FrontmatterError(f"trailing content after flow collection: {text[idx:][:20]!r}")
        return value
    lowered = text.lower()
    if lowered in _NULL_VALUES: return None
    if lowered in _BOOL_TRUE: return True
    if lowered in _BOOL_FALSE: return False
    if _INT_RE.match(text): return int(text)
    if _FLOAT_RE.match(text): return float(text)
    if text[:1] in _UNSUPPORTED_PREFIXES: raise FrontmatterError(f"unsupported YAML construct: {text[:24]!r}")
    return text

def _parse_key(raw_key: str, lineno: int) -> str:
    # Values keep invisible format characters (M5), but a raw one in a key would make two visually
    # identical keys distinct; require the explicit \\u escape inside a double-quoted key instead.
    for ch in raw_key:
        if unicodedata.category(ch) == "Cf": raise AegisYAMLError(f"line {lineno}: invisible format character U+{ord(ch):04X} in key; write it as a \\u escape in a double-quoted key")
    return str(_parse_scalar(raw_key, lineno=lineno))

def _is_compact_mapping(item: str) -> bool:
    # A list item is a "key: value" entry when its first unquoted ':' (whatever the key's shape) is
    # followed by whitespace or ends the item; "C:\0" and URLs stay scalars, flow items are values.
    if item[:1] in ("[", "{"): return False
    try: _, idx = _read_token(item, 0, ":")
    except AegisYAMLError: return False
    return idx < len(item) and item[idx + 1 : idx + 2] in ("", " ", "\t")

def _split_entry(content: str) -> Optional[Tuple[str, str]]:
    try: raw_key, idx = _read_token(content, 0, ":")
    except AegisYAMLError: return None
    return (raw_key, content[idx + 1 :].strip()) if idx < len(content) else None

def _parse_flow(text: str, i: int, lineno: int = 1, depth: int = 0) -> Tuple[Any, int]:
    if depth > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
    i = _skip_ws(text, i)
    if i >= len(text): raise FrontmatterError("unexpected end of flow collection")
    if text[i] == "[": return _parse_flow_seq(text, i, lineno=lineno, depth=depth + 1)
    if text[i] == "{": return _parse_flow_map(text, i, lineno=lineno, depth=depth + 1)
    raw, i = _read_token(text, i, ",]}")
    if not raw.strip(): raise FrontmatterError("empty entry in flow collection")
    return _parse_scalar(raw, lineno=lineno), i

def _parse_flow_seq(text: str, i: int, lineno: int = 1, depth: int = 0) -> Tuple[List[Any], int]:
    if depth > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
    items, i = [], _skip_ws(text, i + 1)
    if i < len(text) and text[i] == "]": return items, i + 1
    while True:
        value, i = _parse_flow(text, i, lineno=lineno, depth=depth)
        items.append(value); i = _skip_ws(text, i)
        if i >= len(text): raise FrontmatterError("unterminated flow sequence")
        if text[i] == "]": return items, i + 1
        if text[i] != ",": raise FrontmatterError(f"expected ',' in flow sequence, got {text[i]!r}")
        i = _skip_ws(text, i + 1)
        if i < len(text) and text[i] == "]": return items, i + 1

def _parse_flow_map(text: str, i: int, lineno: int = 1, depth: int = 0) -> Tuple[Dict[str, Any], int]:
    if depth > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
    mapping, i = {}, _skip_ws(text, i + 1)
    if i < len(text) and text[i] == "}": return mapping, i + 1
    while True:
        raw_key, i = _read_token(text, i, ":")
        if i >= len(text) or text[i] != ":": raise FrontmatterError("expected ':' in flow mapping")
        if not raw_key.strip(): raise FrontmatterError("empty key in flow mapping")
        key = _parse_key(raw_key, lineno)
        if key in mapping: raise AegisYAMLError(f"Duplicate key '{key}' detected at line {lineno}")
        value, i = _parse_flow(text, _skip_ws(text, i + 1), lineno=lineno, depth=depth)
        mapping[key], i = value, _skip_ws(text, i)
        if i >= len(text): raise FrontmatterError("unterminated flow mapping")
        if text[i] == "}": return mapping, i + 1
        if text[i] != ",": raise FrontmatterError(f"expected ',' in flow mapping, got {text[i]!r}")
        i = _skip_ws(text, i + 1)
        if i < len(text) and text[i] == "}": return mapping, i + 1

def _prepare_lines(text: str) -> List[Tuple[int, str, int]]:
    raw_lines = text.splitlines()
    if len(raw_lines) > MAX_LINES: raise AegisYAMLError(f"Document line count ({len(raw_lines)}) exceeds maximum line limit ({MAX_LINES})")
    prepared, in_block_scalar, scalar_indent, in_quote = [], False, 0, None
    for lineno, raw in enumerate(raw_lines, 1):
        for ch in raw:
            if ord(ch) < 32 and ch not in ("\t", "\n", "\r"): raise AegisYAMLError(f"Control character {ord(ch):#04x} is prohibited at line {lineno}")
        if raw.startswith("\t") or (len(raw) - len(raw.lstrip(" ")) > 0 and raw.lstrip(" ").startswith("\t")):
            raise FrontmatterError(f"line {lineno}: tab characters are not allowed for indentation in YAML")
        indent, stripped = len(raw) - len(raw.lstrip(" ")), raw.strip()
        if in_block_scalar:
            if not stripped or indent > scalar_indent:
                prepared.append(((scalar_indent + 1) if not stripped else indent, stripped, lineno)); continue
            in_block_scalar = False
        if in_quote is not None:
            if not stripped: prepared.append((indent, "", lineno)); continue
            line = _strip_comment(raw, quote=in_quote)
            in_quote = _find_unclosed_quote(line, initial_quote=in_quote)
            prepared.append((indent, line.strip(), lineno)); continue
        line = _strip_comment(raw)
        if not line.strip(): continue
        line_indent, line_content = len(line) - len(line.lstrip(" ")), line.strip()
        col, entry, levels = line_indent, line_content, 0
        while entry == "-" or entry.startswith("- "):
            item = entry[1:].lstrip(" ")
            if not (item == "-" or item.startswith("- ") or _is_compact_mapping(item)): break
            # "- key: v" and "- - x" open a mapping / sequence anchored at the item's column (YAML compact
            # form); emitting a bare "-" plus the item lets the block parsers handle the nesting.
            levels += 1
            if levels > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
            prepared.append((col, "-", lineno))
            col, entry = col + len(entry) - len(item), item
        prepared.append((col, entry, lineno))
        if entry == "-" or entry.startswith("- "):
            item = entry[1:].lstrip(" ")
            # Anchored at the dash column, so a sibling item at that column ends the block scalar.
            if item in _BLOCK_INDICATORS: in_block_scalar, scalar_indent = True, col
            elif item[:1] in ('"', "'") and _find_unclosed_quote(item) is not None: in_quote = item[0]
            continue
        split = _split_entry(entry)
        if split is None: continue
        rest = split[1]
        if rest in _BLOCK_INDICATORS: in_block_scalar, scalar_indent = True, col
        elif rest[:1] in ('"', "'") and _find_unclosed_quote(rest) is not None: in_quote = rest[0]
    return prepared

def _parse_collection(lines: List[Tuple[int, str, int]], start: int, indent: int, depth: int = 0) -> Tuple[Any, int]:
    if depth > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
    content = lines[start][1]
    return _parse_block_seq(lines, start, indent, depth=depth) if (content == "-" or content.startswith("- ")) else _parse_block_map(lines, start, indent, depth=depth)

def _parse_block_scalar(lines: List[Tuple[int, str, int]], start: int, parent_indent: int, style: str) -> Tuple[str, int]:
    scalar_lines, base_indent, i = [], None, start
    while i < len(lines) and (not lines[i][1] or lines[i][0] > parent_indent):
        line_indent, content, _ = lines[i]
        if base_indent is None and content: base_indent = line_indent
        rel = line_indent - (base_indent if base_indent is not None else line_indent)
        scalar_lines.append("" if not content else " " * max(0, rel) + content); i += 1
    res = "\n".join(scalar_lines) if style.startswith("|") else " ".join(scalar_lines)
    if style.endswith("-"): return res.rstrip("\n"), i
    if style.endswith("+"): return (res if res.endswith("\n") else res + "\n"), i
    return (res.rstrip("\n") + "\n" if res.rstrip("\n") else ""), i

def _consume_multiline_quote(lines: List[Tuple[int, str, int]], i: int, indent: int, initial: str, err_ctx: str) -> Tuple[str, int]:
    quote_char, j, accum = initial[0], i, initial
    while not _is_quote_closed(accum, quote_char):
        j += 1
        if j >= len(lines): raise FrontmatterError(f"line {lines[i][2]}: unterminated quoted string")
        if lines[j][0] <= indent and lines[j][1]: raise FrontmatterError(f"line {lines[j][2]}: unterminated quoted string before sibling {err_ctx}")
        accum = accum + "\n" + lines[j][1]
    return accum, j + 1

def _parse_block_map(lines: List[Tuple[int, str, int]], start: int, indent: int, depth: int = 0) -> Tuple[Dict[str, Any], int]:
    if depth > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
    mapping, i = {}, start
    while i < len(lines) and lines[i][0] >= indent:
        line_indent, content, lineno = lines[i]
        if line_indent > indent: raise FrontmatterError(f"line {lineno}: unexpected indentation")
        if content == "-" or content.startswith("- "): raise FrontmatterError(f"line {lineno}: unexpected sequence item inside a mapping")
        raw_key, idx = _read_token(content, 0, ":")
        if idx >= len(content) or content[idx] != ":": raise FrontmatterError(f"line {lineno}: expected 'key: value'")
        if not raw_key.strip(): raise FrontmatterError(f"line {lineno}: missing key")
        key = _parse_key(raw_key, lineno)
        if key in mapping: raise AegisYAMLError(f"Duplicate key '{key}' detected at line {lineno}")
        rest = content[idx + 1 :].strip()
        if rest in _BLOCK_INDICATORS: mapping[key], i = _parse_block_scalar(lines, i + 1, indent, rest)
        elif rest:
            if rest[:1] in ('"', "'"):
                accum, i = _consume_multiline_quote(lines, i, indent, rest, "key")
                mapping[key] = _parse_scalar(accum, lineno=lineno)
            elif rest[:1] not in ("[", "{"):
                j = i + 1
                while j < len(lines) and lines[j][0] > indent and not (_SEQ_MAPPING_RE.match(lines[j][1]) or lines[j][1].startswith("- ") or lines[j][1] == "-"):
                    rest, j = rest + " " + lines[j][1], j + 1
                mapping[key], i = _parse_scalar(rest, lineno=lineno), j
            else: mapping[key], i = _parse_scalar(rest, lineno=lineno), i + 1
        elif i + 1 < len(lines) and lines[i + 1][0] == indent and (lines[i + 1][1] == "-" or lines[i + 1][1].startswith("- ")):
            mapping[key], i = _parse_block_seq(lines, i + 1, indent, depth=depth + 1)
        elif i + 1 < len(lines) and lines[i + 1][0] > indent:
            mapping[key], i = _parse_collection(lines, i + 1, lines[i + 1][0], depth=depth + 1)
        else: mapping[key], i = None, i + 1
    return mapping, i

def _parse_block_seq(lines: List[Tuple[int, str, int]], start: int, indent: int, depth: int = 0) -> Tuple[List[Any], int]:
    if depth > MAX_DEPTH: raise AegisYAMLError("Maximum YAML nesting depth exceeded")
    items, i = [], start
    while i < len(lines) and lines[i][0] >= indent:
        line_indent, content, lineno = lines[i]
        if line_indent > indent: raise FrontmatterError(f"line {lineno}: unexpected indentation in sequence")
        if not (content == "-" or content.startswith("- ")): break
        body = content[1:].strip()
        if not body:
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                value, i = _parse_collection(lines, i + 1, lines[i + 1][0], depth=depth + 1); items.append(value)
            else: items.append(None); i += 1
        elif body in _BLOCK_INDICATORS:
            value, i = _parse_block_scalar(lines, i + 1, indent, body); items.append(value)
        elif body[:1] in ('"', "'"):
            accum, i = _consume_multiline_quote(lines, i, indent, body, "item")
            items.append(_parse_scalar(accum, lineno=lineno))
        elif body[:1] not in ("[", "{") and _MAPPING_COLON_RE.search(body):
            # _prepare_lines already turned "key: v" items into mappings; a ': ' left here follows a key
            # that itself contains ':' ("a:b: c"), which this subset cannot read without guessing.
            raise AegisYAMLError(f"line {lineno}: ambiguous sequence item {body[:40]!r}: quote the key or the whole item")
        else: items.append(_parse_scalar(body, lineno=lineno)); i += 1
    return items, i

def parse_yaml_subset(text: str) -> Dict[str, Any]:
    try: raw_bytes = text.encode("utf-8")
    except UnicodeEncodeError as exc: raise AegisYAMLError(f"Document contains a lone surrogate U+{ord(text[exc.start]):04X} at offset {exc.start}; it cannot be encoded as UTF-8") from None
    if len(raw_bytes) > MAX_DOC_BYTES: raise AegisYAMLError(f"Document size ({len(raw_bytes)} bytes) exceeds maximum allowed size ({MAX_DOC_BYTES} bytes)")
    lines = _prepare_lines(text[1:] if text.startswith("\ufeff") else text)
    if not lines: return {}
    value, idx = _parse_collection(lines, 0, lines[0][0], depth=0)
    if idx != len(lines): raise FrontmatterError(f"line {lines[idx][2]}: unparsed content")
    if not isinstance(value, dict): raise FrontmatterError(f"Expected YAML mapping at document root, got {type(value).__name__}")
    return value
