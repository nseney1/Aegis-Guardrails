"""Frontmatter extraction helpers and primary AegisYAML gateway interface."""
from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from aegis_core.diagnostic_messages import receipt_value
from aegis_core.rule_inventory import RuleInventoryError, read_rule_file, split_frontmatter
from aegis_core.yaml_engine.document import AegisDocument
from aegis_core.yaml_engine.parser import (
    AegisYAMLError,
    parse_yaml_subset,
)


def _get_body(content: str) -> str:
    """Extract body text after YAML frontmatter delimiters."""
    status, _fm, body = split_frontmatter(content)
    return body.strip() if status == "ok" else body


def parse_frontmatter(content: str) -> Optional[Dict[str, Any]]:
    """Legacy helper: parse frontmatter mapping or return None/empty dict."""
    if not isinstance(content, str):
        return None
    status, fm_text, _body = split_frontmatter(content)
    if status == "none":
        return {}
    if fm_text is None:  # "unterminated": only an "ok" split carries frontmatter text
        return None
    fm_text = fm_text.strip()
    if not fm_text:
        return {}
    try:
        return parse_yaml_subset(fm_text)
    except Exception:
        return None


class RuleReadError(AegisYAMLError):
    """A path could not be read safely; diagnostics never contain supplied text."""

    def __init__(self, message: str, *, code: str = "RULE_FILE_READ_REFUSED"):
        self.code = code
        super().__init__(message)


class RuleFileNotFoundError(FileNotFoundError):
    """A missing rule path, preserving the file parser's FileNotFoundError API."""

    code = "RULE_FILE_NOT_FOUND"


def _read_rule_text(filepath, *, root=None, encoding="utf-8-sig", source=None,
                    canonicalize_parent=True) -> str:
    try:
        raw = read_rule_file(filepath, root=root, source=source, preserve_os_errors=True,
                             canonicalize_parent=canonicalize_parent)
    except RuleInventoryError as exc:
        if exc.code == "RULE_FILE_NOT_FOUND":
            raise RuleFileNotFoundError("Rule file not found") from None
        raise RuleReadError("Rule file read refused") from None
    # Preserve each entry point's original codec and decoding errors, while
    # matching universal newlines only after the bounded byte capture.
    return raw.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")


def _parse_rule_text(content: str) -> Tuple[Dict[str, Any], str]:
    status, fm_text, body = split_frontmatter(content)
    if status == "none":
        raise ValueError("No frontmatter delimiter")
    if fm_text is None:  # "unterminated": only an "ok" split carries frontmatter text
        raise ValueError("Unclosed frontmatter")
    fm_text = fm_text.strip()
    data = {} if not fm_text else parse_yaml_subset(fm_text)
    return data, body.lstrip("\r\n")


def parse_rule_frontmatter(content_or_path: str) -> Tuple[Dict[str, Any], str]:
    """Parse a rule file or markdown string into (frontmatter_dict, body)."""
    content = content_or_path
    if (isinstance(content_or_path, (str, Path)) and len(str(content_or_path)) <= 32768
            and os.path.exists(content_or_path) and os.path.isfile(content_or_path)):
        content = _read_rule_text(content_or_path)
    return _parse_rule_text(content)


def parse_rule_file(filepath: str) -> Tuple[Dict[str, Any], str]:
    """Parse the rule file at ``filepath`` into (frontmatter_dict, body).

    Legacy missing/non-file and parse failures retain their exception types,
    prefixes and ERR_AEGIS code. File content is omitted from parse diagnostics
    and displayed paths are canonicalized, redacted and bounded. Newly refused
    unsafe reads use RULE_FILE_READ_REFUSED. Public through ``aegis_sdk``.
    """
    from aegis_core.errors import RuleNotFoundError, RuleParseError

    if (isinstance(filepath, (str, Path)) and len(str(filepath)) <= 32768
            and "\x00" not in str(filepath) and not os.path.isfile(filepath)):
        raise RuleNotFoundError(f"Rule file not found: {receipt_value(str(filepath), 400, identifier=True)}")
    try:
        return _parse_rule_text(_read_rule_text(filepath))
    except FileNotFoundError:
        raise RuleNotFoundError(f"Rule file not found: {receipt_value(str(filepath), 400, identifier=True)}") from None
    except RuleReadError:
        raise RuleParseError("Rule file read refused", code="RULE_FILE_READ_REFUSED") from None
    except ValueError as exc:
        # Only these source-owned delimiter diagnostics are public verbatim.
        # Parser and decoder errors can contain arbitrary keys, values or bytes;
        # do not format them, even in a chained traceback or before clipping.
        diagnostic = "Invalid YAML frontmatter"
        if type(exc) is ValueError and exc.args in (("No frontmatter delimiter",), ("Unclosed frontmatter",)):
            diagnostic = exc.args[0]
        shown_path = receipt_value(str(filepath), 400, identifier=True)
        raise RuleParseError(f"Error parsing rule {shown_path}: {diagnostic}") from None


def _rule_workspace_root(workspace):
    """Recover an exposed trusted root without resolving its current spelling."""
    from aegis_core.workspace.base import Workspace

    root = getattr(workspace, "root", None)
    if root is None:
        owner = getattr(workspace.confine_path, "__self__", None)
        if isinstance(owner, Workspace):
            root = owner.root
    if root is not None and (not isinstance(root, (str, Path))
            or not 1 <= len(str(root)) <= 32768 or "\x00" in str(root)):
        raise RuleReadError("Rule file read refused")
    return root


class AegisYAML:
    """Primary zero-dependency AegisYAML engine."""

    @staticmethod
    def parse_text(content: str) -> AegisDocument:
        """Parse pure in-memory markdown or yaml string into an AegisDocument. Never touches disk."""
        # Same leading-only strip as the other entry points: removing these characters anywhere in the
        # document silently altered metadata values and the body (review M5).
        status, fm_text, body = split_frontmatter(content)
        if status == "ok" and fm_text is not None:
            fm_text = fm_text.strip()
            metadata = parse_yaml_subset(fm_text) if fm_text else {}
            return AegisDocument(metadata=metadata, body=body.strip())
        working_content = body

        data = parse_yaml_subset(working_content)
        return AegisDocument(metadata=data, body="")

    @staticmethod
    def parse_file(rel_path: str | Path, workspace: Any) -> AegisDocument:
        """Parse a bounded rule, querying the confiner only for the original path.

        An exposed root, including a bound Workspace.confine_path owner, uses
        the anchored no-follow walk over the original descendant components.
        An opaque adapter owns containment and any original symlink resolution:
        read exactly its returned path (or tuple[0]) once, without rebuilding it.
        Its returned final component is never followed. A resolver that provides
        no containment is outside this opaque-adapter trust boundary.
        """
        if not hasattr(workspace, "confine_path"):
            raise AegisYAMLError("Workspace with confine_path() required to parse file")
        if not isinstance(rel_path, (str, Path)) or not 1 <= len(str(rel_path)) <= 32768:
            raise RuleReadError("Rule file read refused")

        ws_root = _rule_workspace_root(workspace)
        if ws_root is not None:
            raw_target = Path(ws_root) / rel_path
            if raw_target.is_symlink():
                raise AegisYAMLError(f"Symlink parsing prohibited for security: {raw_target}")

        # Preserve the full result for legacy metadata checks and diagnostics.
        resolved = workspace.confine_path(rel_path)
        if isinstance(resolved, tuple):
            resolved_abs = resolved[0]
        else:
            resolved_abs = resolved

        source_path = resolved_abs
        if (not isinstance(resolved_abs, (str, Path)) or not 1 <= len(str(resolved_abs)) <= 32768
                or "\x00" in str(resolved_abs)):
            raise RuleReadError("Rule file read refused")
        path_obj = Path(resolved_abs)
        if not path_obj.exists():
            raise FileNotFoundError(f"File does not exist: {resolved_abs}")
        if path_obj.is_symlink():
            raise AegisYAMLError(f"Symlink parsing prohibited for security: {resolved_abs}")
        if path_obj.is_dir():
            if os.name == "nt":
                raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(path_obj))
            raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(path_obj))

        target = Path(ws_root) / rel_path if ws_root is not None else source_path
        try:
            content = _read_rule_text(target, root=ws_root, encoding="utf-8", source=source_path,
                                      canonicalize_parent=False)
        except FileNotFoundError:
            raise FileNotFoundError(f"File does not exist: {resolved_abs}") from None
        except OSError as exc:
            if exc.filename is not None:
                exc.filename = str(path_obj)
            raise
        doc = AegisYAML.parse_text(content)
        doc._source_path = str(source_path)
        return doc

__all__ = [
    "AegisYAML",
    "RuleFileNotFoundError",
    "RuleReadError",
    "_get_body",
    "parse_frontmatter",
    "parse_rule_file",
    "parse_rule_frontmatter",
    "read_rule_file",
    "split_frontmatter",
]
