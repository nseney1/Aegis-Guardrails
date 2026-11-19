"""Confined capture of rule files and gate-dry-run sources.

Bounds are applied before inventory parsing and before each source read.
Readers and limits are the caller's bindings, so a retry sees the same
public rule_lint names the tests replace. Descriptor reads stay inside
confined_file, including when that reader fails closed.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
import hashlib
from pathlib import Path

from aegis_core.ast.detect import NATIVE_SOURCE_EXTENSIONS
from aegis_core.rule_inventory import RuleInventory, classification_prefix
from aegis_core.rules import rule_path_id
from aegis_core.storage import ConfinedFileError
from aegis_core.workspace.layout import RULES_RELDIR, WorkspaceLayout

__all__ = [
    "RULE_PREFIX",
    "SOURCE_EXTENSIONS",
    "capture_rules",
    "capture_sources",
    "documentation",
    "workspace_root",
]

RULE_PREFIX = RULES_RELDIR + "/"
SOURCE_EXTENSIONS = NATIVE_SOURCE_EXTENSIONS | {".py"}
DOCUMENT_EXTENSIONS = {".md", ".markdown", ".rst", ".txt", ".adoc", ".png", ".jpg", ".jpeg",
                       ".gif", ".svg", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".avif", ".heic"}


def documentation(path):
    """True when a path is documentation or a static asset, not a dry-run source."""
    name = Path(path).name
    return (Path(path).suffix.lower() in DOCUMENT_EXTENSIONS
            or name.upper().startswith(("README", "LICENSE", "CHANGELOG", "NOTICE")))


def workspace_root(root, refuse):
    spelling = str(root) if isinstance(root, Path) else root
    if type(spelling) is not str or len(spelling) > 32768 or "\x00" in spelling:
        raise refuse("invalid_path")
    path = Path(spelling)
    if not path.is_absolute() or ".." in path.parts:
        raise refuse("invalid_path")
    spelling.encode("utf-8")
    return path


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read(root, parts, limit, confined_file, refuse):
    with confined_file(root, parts) as reader:
        before = _signature(reader.parent_stat())
        data = reader.read_bytes(limit)
        if _signature(reader.parent_stat()) != before:
            raise refuse("changed")
        return data


def _parts(path, root, refuse):
    if type(path) is not str or not path or len(path) > 1024 or any(c in path for c in ("\x00", "\\")):
        raise refuse("invalid_path")
    if Path(path).is_absolute():
        try:
            path = Path(path).relative_to(root).as_posix()
        except ValueError:
            raise refuse("invalid_path") from None
    parts = path.split("/")
    layout = WorkspaceLayout(Path(root))
    rules_parts = layout.rules_dir.relative_to(layout.root).parts
    if (tuple(parts[:len(rules_parts)]) != rules_parts or len(parts) > 32
            or any(not part or part in {".", ".."} or len(part) > 255 for part in parts)):
        raise refuse("invalid_path")
    return parts


def _rule_excluded(path):
    parts = path[len(RULE_PREFIX):].split("/")
    return not path.startswith(RULE_PREFIX) or any(part.startswith(".") for part in parts[:-1])


def capture_rules(root, paths, refuse, *, confined_file, inventory_rules, load_rules,
                   max_entries, max_rules, max_rule_bytes, max_rule_total):
    layout = WorkspaceLayout(root)
    selections = [_parts(path, root, refuse) for path in paths or [layout.rules_dir.relative_to(layout.root).as_posix()]]
    candidates, requested, oversized = {}, set(), set()
    for parts in selections:
        if parts[-1].lower().endswith(".md"):
            path = "/".join(parts)
            if path not in requested:
                requested.add(path)
                if len(requested) > max_rules:
                    raise refuse("too_large")
                if _rule_excluded(path):
                    continue
                # Multiple selections are a rule set, captured once by the
                # runtime inventory. Only a single candidate needs this extra
                # bounded read and exact-byte comparison before inventory.
                if len(selections) != 1:
                    continue
                try:
                    data = _read(root, parts, max_rule_bytes, confined_file, refuse)
                except ConfinedFileError as error:
                    if error.reason != "too_large":
                        raise
                    oversized.add(path)
                    continue
                candidates[path] = data
        else:
            # Validate the selected directory without opening or creating a file.
            with confined_file(root, parts + [".lint-probe"]) as directory:
                directory.parent_stat()
    inventory = inventory_rules(str(root))
    # Post-capture bounds precede parsing. Inventory allocation and ancestor
    # anchoring belong to the shared reader (RF-32), not this consumer.
    if len(inventory.entries) > max_entries:
        raise refuse("too_large")
    all_paths = {entry.relative_path for entry in inventory.entries}
    entries = tuple(entry for entry in inventory.entries if not _rule_excluded(entry.relative_path))
    if len(entries) > max_rules:
        raise refuse("too_large")
    found, total, bounded_entries, prefix_paths = {}, 0, [], set()
    prefixes = ["/".join(parts) for parts in selections]
    for entry in entries:
        data, path = entry.prefix or entry.content, entry.relative_path
        if path in candidates and data != candidates[path]:
            raise refuse("changed")
        if path in oversized and entry.size <= max_rule_bytes:
            raise refuse("changed")
        bounded = entry
        if entry.size > max_rule_bytes:
            oversized.add(path)
            prefix = classification_prefix(data, max_rule_bytes)
            bounded = None if prefix is None else replace(entry, content=prefix, size=len(prefix),
                                                         digest=hashlib.sha256(prefix).hexdigest())
            if bounded is not None:
                prefix_paths.add(path)
        if bounded is not None:
            if total + len(bounded.content) > max_rule_total:
                raise refuse("too_large")
            total += len(bounded.content)
            bounded_entries.append(bounded)
        found[path] = data
    if (candidates.keys() | oversized) - found.keys():
        raise refuse("changed")
    if requested - all_paths:
        raise refuse("missing")
    # Validate all bounded entries together, including unselected rules.
    # Oversized bodies never reach parsing. Bounded classification prefixes let
    # this same public loader distinguish documentation from error records.
    try:
        bounded = RuleInventory(tuple(bounded_entries), inventory.fingerprint)
        loaded = load_rules(root, inventory=bounded)
    except (ValueError, UnicodeError, RecursionError):
        raise refuse("loader") from None
    selected = {path: data for path, data in found.items()
                if any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)}
    oversized.difference_update(prefix_paths - {rule.path for rule in loaded.rules})
    identities = Counter(rule_path_id(path) for path in oversized)
    identities.update(rule.id for rule in loaded.rules if rule.path not in oversized)
    return selected, loaded.rules, oversized & selected.keys(), identities, (inventory, loaded)


def capture_sources(root, rules, refuse, *, confined_file, iter_confined_files,
                     max_entries, max_source_files, max_source_bytes, max_source_total):
    sources, total, count = {}, 0, 0
    # Reuse public enumeration; reads themselves remain descriptor-confined.
    for path, problem in iter_confined_files(root, root, suffix="", skip_root_git=True):
        relative = path.relative_to(root).as_posix()
        count += 1
        if count > max_entries:
            raise refuse("source_limit")
        if problem:
            raise refuse("source_unavailable")
        if len(relative) > 1024:
            raise refuse("source_limit")
        if not any(rule.applies_to(relative) for rule in rules):
            continue
        if path.suffix.lower() not in SOURCE_EXTENSIONS and documentation(relative):
            continue
        if len(sources) >= max_source_files:
            raise refuse("source_limit")
        data = _read(root, relative.split("/"), min(max_source_bytes, max_source_total - total), confined_file, refuse)
        total += len(data)
        sources[relative] = data
    return sources
