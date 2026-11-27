"""CLI helpers preserve display, terminal and installed-import behavior."""
import os
from pathlib import Path
import re
import shlex
import string
import subprocess
import sys
from types import SimpleNamespace

import pytest

import aegis_cli
from aegis_cli import approve, doctor_base, init, init_views, install_hosts
from aegis_cli.hooks import commitmsg, management
from aegis_core import primitives


def test_uncut_display_converts_objects_and_strips_escapes():
    assert aegis_cli.sanitize_display("x" * 5000 + "\x1b[31m", max_len=None) == "x" * 5000
    assert aegis_cli.sanitize_display("abcdef", max_len=3) == "..."
    assert aegis_cli.sanitize_display(ValueError("e\x1b[2Jv"), max_len=None) == "ev"


def test_display_matches_legacy_output_for_supported_escape_corpus():
    def legacy(value, limit):
        text = str(value)
        text = re.sub(r'\x1b(?:\[[0-9;?]*[a-zA-Z]|\].*?(?:\x07|\x1b\\)|P.*?(?:\x1b\\|\x07)|[=><NOM78c])', '', text)
        text = re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', text)
        text = re.sub(r'[\x80-\x9f]', '', text)
        text = text.replace('\n', ' ').replace('\r', '').replace('\t', ' ')
        return text[:limit - 3] + '...' if limit is not None and len(text) > limit else text

    # Every value in the existing helper test, plus the C1/DCS regression values.
    corpus = ["x" * 5000 + "\x1b[31m", "abcdef", ValueError("e\x1b[2Jv"),
              "normal\x9b2Jtext\x90device\x9dwindow", "start\x1bP$qterm\x1b\\end",
              "plain caf\u00e9 \u6f22\u5b57\n\ttext\r", "".join(chr(code) for code in range(160)),
              "", "bad\x1b[31", "bad\x1b?text",
              "start\x1b]title\nmore\x07end", "start\x1bPdata\nmore\x1b\\end",
              "start\x1b]outer\x1bPnested\x1b[31mtext\nend",
              "fix: parser\x1b]): src/auth.py, src/token.py",
              "src/a\x1b]b.py:12: rule: trusted finding"]
    escapes = ["\x1b" + char for char in "=><NOM78c"]
    escapes += ["\x1b[" + params + char for params in ("", "0", "1;?30") for char in string.ascii_letters]
    escapes += ["\x1b" + kind + body + end for kind in ("]", "P")
                for body in ("", "title", "nested\x1b]text\x1bPdata") for end in ("\x07", "\x1b\\")]
    corpus += ["before" + escape + "after" for escape in escapes]
    corpus += ["left" + "".join(escapes) + "right"]
    # Plain text, control boundaries and unterminated strings share legacy output.
    plain = ["", "a", "x" * 1024, "caf\u00e9 \u6f22\u5b57 \u202e \U0001f642"]
    corpus += plain
    corpus += [prefix + chr(code) + "trusted suffix" for prefix in plain
               for code in (*range(32), *range(127, 160))]
    corpus += [prefix + "\x1b" + kind + body + suffix for prefix in plain
               for kind in ("]", "P") for body in ("", "title", "\x1b]\x1bP\x1b[31m")
               for suffix in ("", " trusted suffix", "\ntrusted suffix")]
    for value in corpus:
        for limit in (None, 80, 3, 0, -1, 10000):
            assert aegis_cli.sanitize_display(value, max_len=limit) == legacy(value, limit)


def test_display_preserves_unterminated_control_strings_with_bounded_work():
    # A subprocess deadline bounds a CPU denial of service without a speed ratio assertion.
    # Each input contains 256 KiB of unterminated prefixes; neither may rescan suffixes.
    script = (
        "from aegis_cli import sanitize_display\n"
        "for prefix in ('\\x1b]', '\\x1bP'):\n"
        "    assert sanitize_display('visible' + prefix * 131072, max_len=None) == 'visible' + prefix[1] * 131072\n"
        "    assert sanitize_display(prefix * 131072 + '\\n', max_len=None) == prefix[1] * 131072 + ' '\n"
        "print('bounded')\n"
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=Path(aegis_cli.__file__).resolve().parent.parent,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "bounded\n"


def test_argon_base_messages_keep_trusted_suffixes():
    base = "main^{/|\x1b]0;\x07: aegis-state\x1b]}"
    assert aegis_cli.sanitize_display(f"Governance changed since {base}: rules, tests-deleted", max_len=None) == (
        "Governance changed since main^{/|: aegis-state]}: rules, tests-deleted")
    assert aegis_cli.sanitize_display(
        "HEAD shares no history with missing\x1b]FORGED: fetch with fetch-depth 0", max_len=None
    ) == "HEAD shares no history with missing]FORGED: fetch with fetch-depth 0"


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for key in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(key, str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize("error", [ValueError, OSError, AttributeError])
def test_broken_or_missing_stdin_is_not_a_tty(monkeypatch, error):
    def broken():
        raise error("closed")
    monkeypatch.setattr("sys.stdin", SimpleNamespace(isatty=broken) if error is not AttributeError else object())
    assert aegis_cli.stdin_is_tty() is False
    assert approve._stdin_is_tty() is False and doctor_base._stdin_is_tty() is False


def test_shared_import_root_is_installed_location_and_hook_default():
    root = aegis_cli.aegis_import_root()
    assert primitives.aegis_import_root() == root
    assert (Path(root) / "aegis_core").is_dir() and (Path(root) / "aegis_cli").is_dir()
    assert install_hosts.mcp_command(path="", scripts_dirs=[])[-1] == root
    shown = root.replace("\\", "/") if os.name == "nt" else root
    for script in (management.generate_hook_block(), commitmsg.generate_script()):
        assert "AEGIS_PATH=" + shlex.quote(shown) in script
    assert init.SCAFFOLD_LABEL is init_views.SCAFFOLD_LABEL
