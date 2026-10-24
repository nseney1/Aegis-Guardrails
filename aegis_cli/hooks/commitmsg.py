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
import shlex
import stat
import sys
from typing import Optional, Sequence

__all__ = ["HOOK_NAME", "generate_script", "install", "main", "trailer_for_staged", "uninstall"]

HOOK_NAME = "prepare-commit-msg"
_START = "# >>> aegis prepare-commit-msg >>>"
_END = "# <<< aegis prepare-commit-msg <<<"
_RUNNER = ("import sys; sys.path.insert(0, sys.argv[1]); "
           "from aegis_cli.hooks.commitmsg import main; sys.exit(main(sys.argv[2:]))")
#: A merge or squash message is not a work commit the agent verified.
_SKIPPED_SOURCES = ("merge", "squash")


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
        from aegis_core import gitsafe

        root = gitsafe.toplevel(Path.cwd())
        line = trailer_for_staged(root) if root is not None else None
        if line is not None:
            gitsafe.add_trailer(argv[0], line)
    except Exception as exc:  # a commit is never blocked by bookkeeping
        print(f"aegis prepare-commit-msg: {exc}", file=sys.stderr)
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

