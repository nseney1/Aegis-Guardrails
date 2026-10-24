"""Lazy ``UserPromptSubmit`` hook entrypoint for human insight capture (v4.3 T8)."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Sequence

from aegis_core.insights import record_hook_prompt

__all__ = ["enable_insight_hook", "main", "run_insight_hook"]


def enable_insight_hook(host: str, *, excerpts: bool = False, home: Optional[Path] = None) -> Dict[str, Any]:
    """Register the UserPromptSubmit insight hook for ``host`` (see registrar.install_insight_hook)."""
    # Imported here: this module is the per-prompt hook, and the registrar pulls in the host plane.
    from aegis_cli.hooks import registrar

    return registrar.install_insight_hook(host, excerpts, home=home, environ=os.environ)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis_cli.hooks.insights", add_help=False)
    parser.add_argument("--host", default="claude-code")
    parser.add_argument("--excerpts", dest="excerpts", action="store_true", default=True)
    parser.add_argument("--no-excerpts", dest="excerpts", action="store_false")
    return parser


def run_insight_hook(argv: Optional[Sequence[str]] = None, stdin: Optional[str] = None, *, home: Optional[Path] = None) -> int:
    """Execute the ``UserPromptSubmit`` insight hook; always returns ``0``."""
    try:
        args, _ = _build_parser().parse_known_args(list(argv) if argv is not None else sys.argv[1:])
        raw = stdin if stdin is not None else ("" if sys.stdin.isatty() else sys.stdin.read())
        record_hook_prompt(args.host, raw, excerpts=bool(args.excerpts), home=home)
    except Exception as exc:
        try:
            sys.stderr.write(f"aegis insight hook error: {exc}\n")
        except Exception:
            pass
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    return run_insight_hook(argv=argv)


if __name__ == "__main__":
    raise SystemExit(main())
