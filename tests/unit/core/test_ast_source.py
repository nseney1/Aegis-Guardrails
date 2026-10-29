"""The shared Python-source decoder: cookie positions and the complete legacy-codec corpus.

Moved from test_forbid_ast_hardening so Layer 1 finds tests of the extracted leaf;
policy, security-pack and full Layer 1 encoding behavior stay in their integration suites.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from aegis_core.ast.source import read_python_source


@pytest.mark.parametrize(
    "raw",
    [
        b"# -*- coding: latin-1 -*-\rimport pickle\rS = '\xe9'\r",
        b"#!/usr/bin/env python\r# -*- coding: latin-1 -*-\rimport pickle\rS = '\xe9'\r",
        b"# -*- coding: latin-1 -*-\r\nimport pickle\r\nS = '\xe9'\r\n",
    ],
    ids=["cr-line1", "cr-line2", "crlf-line1"],
)
def test_cookie_on_first_two_cr_lines_is_honoured(tmp_path: Path, raw: bytes):
    target = tmp_path / "legacy.py"
    target.write_bytes(raw)
    assert "S = 'é'" in read_python_source(target)
    assert ast.dump(ast.parse(read_python_source(target))) == ast.dump(ast.parse(raw))


@pytest.mark.parametrize("codec", ["utf-7", "hz", "iso2022_jp", "unicode_escape", "utf-16", "cp037", "idna"])
def test_non_ascii_transparent_cookie_raises_unicode_error(tmp_path: Path, codec: str):
    target = tmp_path / "odd.py"
    target.write_bytes(f"# coding: {codec}\nimport json\n".encode("ascii"))
    with pytest.raises(UnicodeError) as excinfo:
        read_python_source(target)
    assert str(excinfo.value) == f"source encoding {codec!r} does not decode ASCII to itself"


@pytest.mark.parametrize(
    "codec, text",
    [
        ("cp1252", "café €"),
        ("iso-8859-15", "café €"),
        ("koi8-r", "привет"),
        ("shift_jis", "日本語"),
        ("euc-jp", "日本語"),
        ("gbk", "中文"),
        ("big5", "中文"),
        ("euc-kr", "한국어"),
        ("mac-roman", "café"),
    ],
)
def test_ascii_transparent_legacy_codecs_are_parsed(tmp_path: Path, codec: str, text: str):
    target = tmp_path / "legacy.py"
    target.write_bytes(f"# -*- coding: {codec} -*-\nimport pickle\nS = '{text}'\n".encode(codec))
    assert read_python_source(target) == f"# -*- coding: {codec} -*-\nimport pickle\nS = '{text}'\n"
