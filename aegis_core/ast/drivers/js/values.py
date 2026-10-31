"""Decode JavaScript scalar spellings without evaluating source expressions."""
from __future__ import annotations

import json
import math
import re
import unicodedata

UNKNOWN = '<expr>'
_ESCAPE = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f', 'v': '\v', '0': '\0'}
_UNICODE = re.compile(r'\\u(?:\{([0-9a-fA-F]{1,6})\}|([0-9a-fA-F]{4}))')
_IDENTIFIER_VALUES = {'true': 'True', 'false': 'False', 'null': 'None', 'undefined': UNKNOWN,
                      'NaN': UNKNOWN, 'Infinity': UNKNOWN, 'True': UNKNOWN, 'False': UNKNOWN, 'None': UNKNOWN}
_NON_JSON_ESCAPE = re.compile(r'\\(?:[^"\\/bfnrtu]|u(?![0-9a-fA-F]{4}))')
_JSON_CONTROL = re.compile(r'[\x00-\x1f]')


def identifier_value(value):
    return _IDENTIFIER_VALUES.get(value, value)


def identifier_start(ch):
    return ch in '_$' or unicodedata.category(ch) in ('Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nl') or ch in '\u2118\u212e\u309b\u309c'


def identifier_part(ch):
    return identifier_start(ch) or unicodedata.category(ch) in ('Mn', 'Mc', 'Nd', 'Pc') or ch in '\u200c\u200d\u00b7\u0387\u19da' or '\u1369' <= ch <= '\u1371'


def unicode_escape(source, offset):
    match = _UNICODE.match(source, offset)
    if not match:
        raise ValueError('invalid_unicode_escape')
    value = int(match[1] or match[2], 16)
    if value > 0x10ffff:
        raise ValueError('invalid_unicode_escape')
    return chr(value), match.end()


def decode_string(raw):
    """Decode JS escapes and combine equivalent UTF-16 surrogate spellings."""
    body, output, index = raw[1:-1], [], 0
    if '\\' not in body and body.isascii():
        return body
    if raw.startswith('"') and not _NON_JSON_ESCAPE.search(body) and not _JSON_CONTROL.search(body):
        return json.loads(raw)
    while index < len(body):
        ch = body[index]
        if ch != '\\':
            output.append(ch)
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise ValueError('unterminated_string')
        ch = body[index]
        if ch == 'u':
            value, index = unicode_escape(body, index - 1)
            output.append(value)
            continue
        if ch == 'x':
            digits = body[index + 1:index + 3]
            if len(digits) != 2 or any(c not in '0123456789abcdefABCDEF' for c in digits):
                raise ValueError('invalid_string_escape')
            output.append(chr(int(digits, 16)))
            index += 3
            continue
        if ch in '\r\n\u2028\u2029':
            index += 2 if ch == '\r' and body[index:index + 2] == '\r\n' else 1
            continue
        if ch.isdigit() and (ch != '0' or (index + 1 < len(body) and body[index + 1].isdigit())):
            raise ValueError('unsupported_lexical_context:legacy_string_escape')
        output.append(_ESCAPE.get(ch, ch))
        index += 1
    decoded = ''.join(output)
    return decoded if decoded.isascii() else decoded.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')


def number_value(raw):
    if raw.endswith('n'):
        return UNKNOWN
    clean = raw.replace('_', '')
    try:
        if clean.lower().startswith(('0x', '0o', '0b')):
            value = int(clean, 0)
        elif '.' not in clean and 'e' not in clean.lower():
            value = int(clean, 10)
        else:
            value = float(clean)
        if not math.isfinite(float(value)):
            return UNKNOWN
        if type(value) is int and int(float(value)) != value:
            return UNKNOWN
        return repr(value)
    except (ValueError, OverflowError):
        return UNKNOWN


def render(tokens):
    """Render only a scalar or symbolic reference, never an evaluated expression."""
    if not tokens:
        return UNKNOWN
    sign = ''
    if len(tokens) == 2 and tokens[0].value in ('-', '+') and tokens[1].kind == 'number':
        sign, tokens = tokens[0].value, tokens[1:]
    if len(tokens) == 1:
        token = tokens[0]
        if token.kind == 'string':
            return repr(token.value)
        if token.kind == 'number':
            value = number_value(token.value)
            return ('-' + value if sign == '-' and value != UNKNOWN else value)
        if token.kind == 'identifier':
            return identifier_value(token.value)
    if (len(tokens) >= 2 and tokens[0].kind == 'template_start' and tokens[-1].kind == 'template_end'
            and all(t.kind == 'template_text' for t in tokens[1:-1])):
        try:
            return repr(decode_string('`' + ''.join(t.value for t in tokens[1:-1]) + '`'))
        except ValueError:
            return UNKNOWN
    if all(t.kind == 'identifier' if i % 2 == 0 else t.value == '.' for i, t in enumerate(tokens)):
        return ''.join(t.value for t in tokens)
    return UNKNOWN
