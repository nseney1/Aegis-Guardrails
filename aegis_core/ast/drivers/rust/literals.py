"""Rust scalar decoding; expressions and unsupported scalar kinds stay UNKNOWN."""
from __future__ import annotations

import math
import re
import struct

from aegis_core.ast.driver_errors import ASTDriverError

UNKNOWN = '<expr>'
_INTEGER = re.compile(r'(0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|[0-9][0-9_]*)([A-Za-z][A-Za-z0-9_]*)?\Z')
_FLOAT = re.compile(r'(\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?[\d_]+)?)(f32|f64)?\Z')
_SUFFIXES = {'i8', 'i16', 'i32', 'i64', 'i128', 'isize', 'u8', 'u16', 'u32', 'u64', 'u128', 'usize'}
_SIMPLE = {'n': '\n', 'r': '\r', 't': '\t', '0': '\0', '\\': '\\', '"': '"', "'": "'"}


def invalid(detail, line):
    raise ASTDriverError(f'invalid {detail} at line {line}', reason='syntax')


def decode_string(text, line=1):
    """Decode Rust string/character escapes without executing expressions."""
    raw = text.startswith(('r', 'br', 'cr'))
    start = text.find('"') if raw else next((i for i, ch in enumerate(text) if ch in ('"', "'")), -1)
    if start < 0:
        invalid('string', line)
    quote = text[start]
    end = text.rfind(quote)
    body = text[start + 1:end].replace('\r\n', '\n')
    if raw:
        if text.startswith('br') and not body.isascii():
            invalid('raw byte string', line)
        if text.startswith('cr') and '\0' in body:
            invalid('C string NUL', line)
        return body
    if '\\' not in body:
        if quote == "'" and len(body) != 1:
            invalid('character literal', line)
        if text.startswith('b') and not body.isascii():
            invalid('byte literal', line)
        if text.startswith('c') and '\0' in body:
            invalid('C string NUL', line)
        return body
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        i += 1
        if ch != '\\':
            if text.startswith('b') and ord(ch) > 127:
                invalid('byte literal', line)
            out.append(ch)
            continue
        if i == len(body):
            invalid('escape', line)
        escaped = body[i]
        i += 1
        if escaped in _SIMPLE:
            out.append(_SIMPLE[escaped])
        elif escaped == 'x':
            value = body[i:i + 2]
            if not re.fullmatch('[0-9a-fA-F]{2}', value):
                invalid('escape', line)
            if int(value, 16) > 127 and not text.startswith('b'):
                invalid('ASCII escape', line)
            out.append(chr(int(value, 16)))
            i += 2
        elif escaped == 'u':
            closing = body.find('}', i)
            value = body[i + 1:closing].replace('_', '') if body[i:i + 1] == '{' else ''
            if not re.fullmatch('[0-9a-fA-F]{1,6}', value) or text.startswith('b'):
                invalid('Unicode escape', line)
            number = int(value, 16)
            if number > 0x10ffff or 0xd800 <= number <= 0xdfff:
                invalid('Unicode scalar', line)
            out.append(chr(number))
            i = closing + 1
        elif escaped in '\r\n' and quote == '"':
            while i < len(body) and body[i].isspace():
                i += 1
        else:
            invalid('escape', line)
    value = ''.join(out)
    if quote == "'" and len(value) != 1:
        invalid('character literal', line)
    if text.startswith('b') and any(ord(ch) > 255 for ch in value):
        invalid('byte literal', line)
    if text.startswith('c') and '\0' in value:
        invalid('C string NUL', line)
    return value


def number(text, line=1):
    if len(text) > 512:
        return UNKNOWN  # bounded scalar decoding; very large integers are not evaluated
    if text.startswith(('0x', '0o', '0b')):
        alphabet = {'x': '0123456789abcdefABCDEF_', 'o': '01234567_', 'b': '01_'}[text[1]]
        end = 2
        while end < len(text) and text[end] in alphabet:
            end += 1
        digits, suffix = text[2:end].replace('_', ''), text[end:]
        if not digits or (suffix and (not suffix[0].isalpha())):
            invalid('integer literal', line)
        if suffix and suffix not in _SUFFIXES:
            return UNKNOWN
        return repr(int(digits, {'x': 16, 'o': 8, 'b': 2}[text[1]]))
    match = _FLOAT.fullmatch(text)
    if match and ('.' in text or 'e' in text.lower() or match[2]):
        try:
            value = float(match[1].replace('_', ''))
        except ValueError:
            invalid('float literal', line)
        if not math.isfinite(value):
            return UNKNOWN
        if match[2] == 'f32':
            try:
                if struct.unpack('!f', struct.pack('!f', value))[0] != value:
                    return UNKNOWN
            except OverflowError:
                return UNKNOWN
        return repr(value)
    match = _INTEGER.fullmatch(text)
    if match:
        digits, suffix = match.groups()
        if suffix and suffix not in _SUFFIXES:
            return UNKNOWN
        digits = digits.rstrip('_').replace('_', '')
        base = 0 if digits.startswith(('0x', '0o', '0b')) else 10
        try:
            return repr(int(digits, base))
        except ValueError:
            invalid('integer literal', line)
    if re.fullmatch(r'\d[\d_]*[A-Za-z]\w*', text):
        return UNKNOWN
    invalid('numeric literal', line)


def render(tokens):
    """Render one scalar token (optionally signed); never evaluate compound input."""
    if not tokens:
        return UNKNOWN
    if len(tokens) == 2 and tokens[0].value in ('-', '+') and tokens[1].kind == 'number':
        result = number(tokens[1].value, tokens[1].line)
        return UNKNOWN if result == UNKNOWN else ('-' + result if tokens[0].value == '-' else result)
    if len(tokens) != 1:
        return UNKNOWN
    token = tokens[0]
    if token.kind in ('string', 'char'):
        return repr(decode_string(token.value, token.line))
    if token.kind == 'number':
        return number(token.value, token.line)
    return {'true': 'True', 'false': 'False', 'None': 'None'}.get(token.value, UNKNOWN)
