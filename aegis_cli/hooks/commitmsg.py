"""The git ``prepare-commit-msg`` hook: an ``Aegis-Check`` trailer for a verified tree (v4.3 T1).

``Aegis-Check: tree=<staged tree> exit=<n>`` is added only when the ledger holds a passing
``check`` row for exactly the tree the commit is about to record (``git write-tree`` on the
hook's own index, so ``git commit -a`` and partial staging are judged as committed). The trailer
is a claim CI can compare with its own run (``aegis_core.credit.check_ci_divergence``); it is
never trusted on its own. The hook never blocks a commit: every failure leaves the message as is.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import stat
import sys
from typing import BinaryIO, Optional, Sequence, Tuple

__all__ = ["HOOK_NAME", "generate_script", "install", "main", "trailer_for_staged", "uninstall"]

HOOK_NAME = "prepare-commit-msg"
_START = "# >>> aegis prepare-commit-msg >>>"
_END = "# <<< aegis prepare-commit-msg <<<"
_RUNNER = ("import sys; sys.path.insert(0, sys.argv[1]); "
           "from aegis_cli.hooks.commitmsg import main; sys.exit(main(sys.argv[2:]))")
#: A merge or squash message is not a work commit the agent verified.
_SKIPPED_SOURCES = ("merge", "squash")
MAX_MESSAGE_SCAN_BYTES = 4 * 1024 * 1024
_MESSAGE_READ_BYTES = 4096
_MAX_COMMENT_CONFIG_BYTES = 65536
_CUT_SUFFIX = b" ------------------------ >8 ------------------------"
_CUT_LINE = b"#" + _CUT_SUFFIX
_CUT_ENDINGS = (_CUT_SUFFIX, _CUT_SUFFIX + b"\r", _CUT_SUFFIX + b"\n", _CUT_SUFFIX + b"\r\n")
_BELOW_CUT_AUTHORITY = re.compile(
    r"^[ \t]*aegis-(?:approve(?:-insight)?|exempt-test)[ \t]*:|^aegis-manager-approve[ \t]*:",
    re.I | re.M,
)


def _notice(reason: str) -> None:
    """Only fixed internal reasons reach this content-free diagnostic."""
    print(f"aegis prepare-commit-msg: Aegis-Check not added ({reason})", file=sys.stderr)


def _comment_markers_supported(root: Path) -> bool:
    """Prove all comment aliases use # in one bounded, NUL-delimited result."""
    from aegis_core import gitsafe

    try:
        result = gitsafe.run(["config", "--null", "--get-regexp", r"^core\.comment(char|string)$"], root)
    except gitsafe.GitError:
        return False
    if result.returncode == 1:
        return True
    raw = result.stdout
    if result.returncode != 0 or not raw or len(raw) > _MAX_COMMENT_CONFIG_BYTES or not raw.endswith(b"\0"):
        return False
    for entry in raw[:-1].split(b"\0"):
        key, separator, value = entry.partition(b"\n")
        if key not in (b"core.commentchar", b"core.commentstring") or not separator or value != b"#":
            return False
    return True


def _candidate_message(stream: BinaryIO) -> Tuple[bytes, Optional[str], bool]:
    """Bound candidate bytes and scan the entire bounded tail for authority."""
    from aegis_core.approval_shape import MAX_MESSAGE_BYTES

    candidate = bytearray()
    scanned, first, comment = 0, True, False
    cut_padding = False
    tail = b""
    while scanned < MAX_MESSAGE_SCAN_BYTES:
        size = min(_MESSAGE_READ_BYTES, MAX_MESSAGE_SCAN_BYTES - scanned)
        part = stream.readline(size)
        if not part:
            if cut_padding or (not first and not comment and tail.endswith(_CUT_ENDINGS)):
                return b"", "comment character", False
            return bytes(candidate), None, False
        scanned += len(part)
        if first:
            comment = part.startswith(b"#")
            tail = b""
            if part == _CUT_LINE + b"\n":
                remaining = MAX_MESSAGE_SCAN_BYTES - scanned
                if remaining <= 0:
                    return b"", "scan limit", False
                below_cut = stream.read(remaining)
                if len(below_cut) == remaining:
                    return b"", "scan limit", False
                return bytes(candidate), None, _BELOW_CUT_AUTHORITY.search(
                    below_cut.decode("utf-8", "surrogateescape")) is not None
            cut_padding = part.startswith(_CUT_LINE)
        if cut_padding:
            # An editor can trim this into a cut. Track padding across chunks
            # without buffering the comment or trusting an unfinished line.
            padding = part[len(_CUT_LINE):] if first else part
            cut_padding = not padding.strip(b" \t\r\n")
            if cut_padding and (part.endswith(b"\n") or len(part) < size):
                return b"", "comment character", False
        if not comment:
            tail = (tail + part)[-(len(_CUT_SUFFIX) + 2):]
            if (part.endswith(b"\n") or len(part) < size) and tail.endswith(_CUT_ENDINGS):
                return b"", "comment character", False
            if len(candidate) + len(part) > MAX_MESSAGE_BYTES:
                return b"", "message too large", False
            candidate.extend(part)
        first = part.endswith(b"\n")
    return b"", "scan limit", False


def _record_check(root: Path, argument: str, line: str) -> None:
    """Inspect the message Git keeps, then publish through the portable helper."""
    from aegis_core import approval_shape, gitsafe

    try:
        with open(argument, "rb") as stream:
            raw, refusal, authority_after_cut = _candidate_message(stream)
    except (OSError, ValueError):
        _notice("unreadable")
        return
    if authority_after_cut:
        _notice("authority below cut")
        return
    if refusal:
        _notice(refusal)
        return
    if approval_shape.has_authority_line(raw.decode("utf-8", "surrogateescape")):
        return
    if not gitsafe.add_trailer(argument, line):
        _notice("unreadable")


def trailer_for_staged(root: Path) -> Optional[str]:
    """The trailer line for the tree staged in ``root``'s index, or None when no passing check covers it."""
    from aegis_core import credit, gitsafe

    res = gitsafe.run(["write-tree"], root)
    if res.returncode != 0:
        return None  # unmerged entries or a missing object: nothing to bind
    tree = res.stdout.decode("ascii", "replace").strip()
    row = credit.passing_check(credit.read_rows(root), tree)
    return credit.format_trailer(tree, int(row.get("exit") or 0)) if row is not None else None


def main(argv: Sequence[str]) -> int:
    """``prepare-commit-msg MSGFILE [SOURCE [SHA]]``. Always 0."""
    try:
        if not argv or (len(argv) > 1 and argv[1] in _SKIPPED_SOURCES):
            return 0
        # Git invokes this hook at the work-tree root with its index/config environment.
        root = Path.cwd()
        line = trailer_for_staged(root)
        if line is None:
            return 0
        if not _comment_markers_supported(root):
            _notice("comment character")
            return 0
        _record_check(root, argv[0], line)
    except Exception:  # a commit is never blocked by bookkeeping
        _notice("unreadable")
    return 0


def generate_script(python: Optional[str] = None, import_root: Optional[str] = None) -> str:
    """The hook file: the installing interpreter and aegis_cli directory baked in, nothing looked up on PATH."""
    import aegis_cli

    python = python if python is not None else sys.executable
    import_root = import_root if import_root is not None else aegis_cli.aegis_import_root()
    for label, value in (("interpreter", python), ("import root", import_root)):
        if not os.path.isabs(value):
            raise ValueError(f"hook {label} must be an absolute path, got {value!r}")
    shown = (lambda p: p.replace("\\", "/") if os.name == "nt" else p)
    return (f"#!/bin/sh\n{_START}\n# Installed by aegis; adds an Aegis-Check trailer for a verified tree\n"
            f"AEGIS_PYTHON={shlex.quote(shown(python))}\nAEGIS_PATH={shlex.quote(shown(import_root))}\n"
            'if [ -x "$AEGIS_PYTHON" ] && [ -f "$AEGIS_PATH/aegis_cli/__init__.py" ]; then\n'
            f'  "$AEGIS_PYTHON" -I -c {shlex.quote(_RUNNER)} "$AEGIS_PATH" "$@" || true\nfi\nexit 0\n{_END}\n')


def _ours(text: str) -> bool:
    return _START in text and _END in text


def install(hooks_dir: Path, *, dry_run: bool = False) -> str:
    """``installed``, ``unchanged`` or ``foreign`` (a hook that is not ours is left alone)."""
    target = Path(hooks_dir) / HOOK_NAME
    script = generate_script()
    if target.is_symlink():
        return "foreign"
    if target.exists():
        current = target.read_text(encoding="utf-8", errors="replace")
        if not _ours(current):
            return "foreign"
        if current == script:
            return "unchanged"
    if not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(script.encode("utf-8"))
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return "installed"


def uninstall(hooks_dir: Path, *, dry_run: bool = False) -> str:
    """``removed``, ``absent`` or ``foreign``."""
    target = Path(hooks_dir) / HOOK_NAME
    if not target.exists() and not target.is_symlink():
        return "absent"
    if target.is_symlink() or not _ours(target.read_text(encoding="utf-8", errors="replace")):
        return "foreign"
    if not dry_run:
        target.unlink()
    return "removed"

