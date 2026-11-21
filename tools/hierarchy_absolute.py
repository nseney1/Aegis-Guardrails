"""Shared lexical absolute-path validation without container or orchestration imports."""
from __future__ import annotations

import os
from pathlib import Path

from hierarchy_mailbox import require, text


def _absolute(value, label):
    # Preserve hierarchy_team.absolute's lexical contract without importing orchestration.
    value = os.fspath(value) if isinstance(value, os.PathLike) else value
    text(value, label)
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts,
            "%s must be an absolute path without ..: %s" % (label, value))
    return path
