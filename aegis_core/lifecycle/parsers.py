"""Rule ids, slugs, file lookup and frontmatter transforms for the lifecycle."""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Optional, Tuple

from aegis_core.fitness import rule_age_days
from aegis_core.yaml_engine.serializer import dump_frontmatter
from aegis_core.yaml_engine.frontmatter import parse_rule_frontmatter
from aegis_core.workspace import literal_workspace
from aegis_core.workspace.base import Workspace
from aegis_core.taxonomy import RULE_TYPE_DIRS, RULE_TYPES

__all__ = [
    "find_rule_file",
    "generate_slug",
    "rule_age_days",
    "sanitize_rule_id",
    "validate_rule_id",
]


def _on_windows() -> bool:
    return os.name == "nt"  # where ":" makes a drive-relative name ("D:x") or a stream


def _escapes(rule_id: str) -> bool:
    return "/" in rule_id or "\\" in rule_id or ".." in rule_id or (_on_windows() and ":" in rule_id)


def sanitize_rule_id(rule_id: str) -> Optional[str]:
    """A rule id with no path separator or "..", without a trailing .md (None if invalid)."""
    if not rule_id or _escapes(rule_id):
        return None
    cleaned = rule_id.strip()
    if cleaned.endswith(".md"):
        cleaned = cleaned[:-3]
    return cleaned if cleaned else None


def validate_rule_id(rule_id: str | None) -> None:
    """Raise ValueError for a rule id that could escape its directory."""
    if not rule_id:
        return
    if _escapes(rule_id):
        raise ValueError(f"Invalid ID_OVERRIDE contains path traversal characters: {rule_id!r}")


def generate_slug(hypothesis: str, id_override: str | None = None) -> str:
    """A file-safe rule id from the hypothesis (or the explicit override)."""
    if id_override:
        validate_rule_id(id_override)
        return id_override

    cleaned = re.sub(r"[^a-zA-Z0-9 ]", "", hypothesis.lower())
    slug = re.sub(r"\s+", "-", cleaned).strip("-")[:50].rstrip("-")
    return slug or "unnamed-rule"


def find_rule_file(workspace: Workspace | Path | str, rule_id: str) -> Tuple[Optional[Path], Optional[str]]:
    """Locate a rule in its type directory, ``.aegis/rules/<type dir>/<id>.md``."""
    clean_id = sanitize_rule_id(rule_id)
    if not clean_id:
        return None, None

    ws = literal_workspace(workspace)
    for type_name, dir_name in RULE_TYPE_DIRS.items():
        candidate = ws.rules_dir / dir_name / f"{clean_id}.md"
        if candidate.is_file():
            return candidate, type_name
    return None, None


def _transform_frontmatter_type(content: str, new_type: str) -> str:
    """Set a rule's type (and the enforcement its new tier needs), keeping the body."""
    try:
        meta, body = parse_rule_frontmatter(content)
    except Exception:
        return content

    meta["type"] = new_type
    if RULE_TYPES[new_type].mandatory:
        meta["enforcement"] = "gate"
    elif new_type == "trap":
        meta.pop("enforcement", None)
        meta.pop("enforcement_artifact", None)

    return dump_frontmatter(meta, body=body)


