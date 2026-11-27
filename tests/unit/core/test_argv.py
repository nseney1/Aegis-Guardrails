"""Command-string grammar, exercised directly without changing the host OS."""
from __future__ import annotations

import os
import subprocess
from types import SimpleNamespace

import pytest

from aegis_core import argv as command_argv


@pytest.fixture
def windows(monkeypatch):
    # Replace the module reference, never os.name: pathlib/pytest keep the host OS.
    monkeypatch.setattr(command_argv, "os", SimpleNamespace(**{**vars(os), "name": "nt"}))


def test_windows_command_keeps_the_backslashes_of_native_paths(windows):
    # POSIX shlex reads '\' as an escape: C:\tools\llm.exe became C:toolsllm.exe.
    decoded = command_argv.split_command(r"C:\Python312\python.exe C:\tools\llm.py -p")
    assert decoded == [r"C:\Python312\python.exe", r"C:\tools\llm.py", "-p"]


def test_windows_command_groups_a_double_quoted_path_with_spaces(windows):
    decoded = command_argv.split_command(r'"C:\Program Files\nodejs\node.exe" D:\tools\llm.js --json')
    assert decoded == [r"C:\Program Files\nodejs\node.exe", r"D:\tools\llm.js", "--json"]


def test_windows_command_accepts_posix_single_quoting(windows):
    # What shlex.join (and docs written for a POSIX shell) produce for these paths.
    decoded = command_argv.split_command(r"'C:\Program Files\llm.exe' 'C:\tools\x.py' ship")
    assert decoded == [r"C:\Program Files\llm.exe", r"C:\tools\x.py", "ship"]


def test_windows_command_with_unbalanced_quotes_is_an_error(windows):
    with pytest.raises(ValueError, match="^No closing quotation$"):
        command_argv.split_command(r'"C:\Program Files\llm.exe -p')


@pytest.mark.parametrize("raw, argv", [
    # A quoted span groups anywhere in a token, as CommandLineToArgvW reads it.
    ('llm --flag="a b" -p', ["llm", "--flag=a b", "-p"]),
    ('llm --title="say \\"hi\\"" x', ["llm", '--title=say "hi"', "x"]),
    ('llm pre"fix mid"post', ["llm", "prefix midpost"]),
    # 2n backslashes before a quote are n and the quote is syntax; 2n+1 escape it.
    (r'llm "C:\dir with space\\" next', ["llm", "C:\\dir with space\\", "next"]),
    (r'llm a\\\"b', ["llm", 'a\\"b']),
    # Backslashes anywhere else are literal; an empty quoted span is an empty argument.
    (r"llm C:\tools\ x", ["llm", "C:\\tools\\", "x"]),
    ('llm "" x', ["llm", "", "x"]),
])
def test_windows_command_splits_as_command_line_to_argv(windows, raw, argv):
    assert command_argv.split_command(raw) == argv


@pytest.mark.parametrize("argv", [
    ["llm", "--flag=a b", "-p"],
    [r"C:\Program Files\node.exe", r"D:\x y\llm.js", 'say "hi"', "trailing\\", "dir with\\", "", "100%"],
    ["codex", "exec", "--skip-git-repo-check", r"\\server\share\x", 'a\\"b'],
])
def test_windows_command_reads_back_what_list2cmdline_writes(windows, argv):
    # subprocess.list2cmdline quotes for the C runtime; the split must undo it exactly.
    assert command_argv.split_command(subprocess.list2cmdline(argv)) == argv


def test_windows_command_with_an_unclosed_mid_token_quote_is_an_error(windows):
    with pytest.raises(ValueError, match="^No closing quotation$"):
        command_argv.split_command('llm --flag="a b')


def test_posix_command_honors_shell_quoting_and_escapes(monkeypatch):
    monkeypatch.setattr(command_argv, "os", SimpleNamespace(**{**vars(os), "name": "posix"}))
    decoded = command_argv.split_command(r"my\ llm -p 'two words'")
    assert decoded == ["my llm", "-p", "two words"]
