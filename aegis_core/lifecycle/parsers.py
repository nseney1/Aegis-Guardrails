"""Rule ids, slugs, file lookup and frontmatter transforms for the lifecycle."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any, Optional, Tuple

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


def rule_age_days(rule: Any, now: Optional[datetime] = None) -> int:
    """Days since the rule's ``created`` date (0 when it has none or it cannot be read)."""
    created = (getattr(rule, "meta", None) or {}).get("created")
    if isinstance(created, datetime):
        created_dt = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    elif isinstance(created, str) and created:
        text = created.strip()
        text = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            created_dt = datetime.fromisoformat(text) if "T" in text else datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return 0
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
    elif hasattr(created, "isoformat"):  # a date
        created_dt = datetime(created.year, created.month, created.day, tzinfo=timezone.utc)
    else:
        return 0
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return max(0, (current - created_dt).days)


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


