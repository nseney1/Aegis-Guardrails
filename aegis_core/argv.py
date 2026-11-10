"""Operator command-string decoding (L0, standard library only; no shell or I/O).

Validation, executable lookup and legacy path fallbacks belong to the consumers.
"""
from __future__ import annotations

import os
import shlex
from typing import List

__all__ = ["split_command"]

_WINDOWS_SPACE = " \t\r\n"


def _split_windows(raw: str) -> List[str]:
    """Split a Windows command line the way CommandLineToArgvW reads one.

    Whitespace ends an argument outside a quoted span; a double-quoted span groups
    anywhere in a token (``--flag="a b"`` is the one argument ``--flag=a b``) and its
    quotes are syntax. 2n backslashes before a quote are n backslashes and the quote is
    syntax, 2n+1 are n and a literal quote; other backslashes are literal, so
    ``C:\\tools\\llm.exe`` keeps them. In a run of quotes every third is a literal quote.
    Three departures, kept from the shlex split this replaced: a line break also ends an
    argument, a token that starts with a single quote is read verbatim to the next one
    (POSIX quoting, as shlex.join writes a path), and an unclosed quote is an error
    rather than running to the end of the line.
    """
    args: List[str] = []
    i, n = 0, len(raw)
    while True:
        while i < n and raw[i] in _WINDOWS_SPACE:
            i += 1
        if i >= n:
            return args
        token: List[str] = []
        if raw[i] == "'":
            end = raw.find("'", i + 1)
            if end < 0:
                raise ValueError("No closing quotation")
            token.append(raw[i + 1:end])
            i = end + 1
        in_quotes = False
        backslashes = 0
        while i < n and (in_quotes or raw[i] not in _WINDOWS_SPACE):
            ch = raw[i]
            i += 1
            if ch == "\\":
                backslashes += 1
                continue
            if ch != '"':
                token.append("\\" * backslashes + ch)
                backslashes = 0
                continue
            token.append("\\" * (backslashes // 2))
            if backslashes % 2:
                token.append('"')
            else:
                quotes = 2 if in_quotes else 1
                while i < n and raw[i] == '"':
                    quotes += 1
                    i += 1
                    if quotes == 3:
                        token.append('"')
                        quotes = 0
                in_quotes = quotes == 1
            backslashes = 0
        if in_quotes:
            raise ValueError("No closing quotation")
        token.append("\\" * backslashes)
        args.append("".join(token))


def split_command(raw: str) -> List[str]:
    """Decode argv using the host grammar; raise ValueError for unclosed quotes."""
    # POSIX shlex reads every backslash as an escape, so a native Windows path
    # (C:\tools\llm.exe) lost them: on Windows the command line is split as the C
    # runtime would split it.
    if os.name != "nt":
        return shlex.split(raw)
    return _split_windows(raw)
