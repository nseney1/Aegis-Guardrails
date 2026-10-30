"""Shared AST availability and forbid-rule evaluation for ordinary and staged sources."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from aegis_core.ast.detect import LANGUAGE_DEFINITIONS
from aegis_core.ast import policy
from aegis_core.ast.schema import canonical_spelling
from aegis_core.verification import ToolEvidence
from aegis_core.workspace.layout import RULES_RELDIR

NO_DRIVER_NOTE_TOOL = 'forbid_ast_no_driver'


def site_key(path: str, line: int, pattern: str) -> tuple[str, int, str]:
    """One ownership identity for equivalent user-rule and security-pack spellings."""
    return path, line, canonical_spelling(pattern)


def source_language(path: str) -> str:
    from pathlib import Path

    ext = Path(path).suffix.lower()
    return next((language for language, config in LANGUAGE_DEFINITIONS.items()
                 if ext in config['extensions']), 'unknown')


def covered_paths(paths: list[str], root: str, discover_rules: Any) -> set[str]:
    """Keep covered non-driver blobs in the staged snapshot, including broken rule sets."""
    try:
        rules, _broken = discover_rules(root)
        return {rel for rel in paths if any(rule.applies_to(rel) for rule, _spec in rules)}
    except Exception:
        return set(paths)  # snapshot evaluation reports the rule-loading failure


def uncovered_extensions(root: Any, configured: set[str]) -> set[str]:
    """Doctor's local coverage hints, including languages outside the packaged set."""
    from aegis_core.ast.detect import iter_project_files
    from aegis_core.rules import RuleCache

    rules = [rule for rule in RuleCache().get(root).rules
             if rule.ok and not rule.expired and 'forbid_ast' in rule.meta]
    return {path.suffix.lower() for path in iter_project_files(root)
            if path.suffix.lower() not in configured | {'.py'}
            and any(rule.applies_to(path.relative_to(root).as_posix()) for rule in rules)}


def driver_availability(ws_root: Path) -> Tuple[Dict[str, str], List[str]]:
    """(the AST driver configured per extension, 'default' for the catch-all slot; the detected
    non-Python source extensions that have none): the one definition the driver check and the
    --fix plan share. A config that cannot be read raises SlotResolutionError."""
    from aegis_core.ast.detect import detect_project_languages
    from aegis_core.skills.slots import SlotRegistry

    langs = detect_project_languages(ws_root)
    drivers: Dict[str, str] = {}
    for registry in (SlotRegistry.load(ws_root), SlotRegistry.load_user(ws_root)):
        for slot_name, slot_val in registry.to_dict().items():
            if slot_name == "ast_driver":
                drivers["default"] = str(slot_val)
            elif slot_name.startswith("ast_driver_"):
                drivers[f".{slot_name[len('ast_driver_'):]}"] = str(slot_val)
    if "default" in drivers:
        return drivers, []
    missing = {ext for lang, info in langs.items() if lang != "python"
               for ext in info.get("extensions", []) if ext not in drivers}
    return drivers, sorted(missing | uncovered_extensions(ws_root, set(drivers)))


def _rule_failure(rule_id: str, rel: str, exc: Exception, failure: Any, language: str) -> ToolEvidence:
    row = failure(f'forbid_ast:{rule_id}', rel, exc)
    if isinstance(exc, policy.ASTExtractionError):
        row.detail = f'forbid_ast: cannot verify {rel}: {exc.reason}'
    row.language = language
    return row


def run_checks(paths: list[tuple[str, str]], root: str, session: Any, *, discover_rules: Any,
               evidence: Any, exempt_notes: Any, failure: Any, reviewed: bool = True,
               too_large: dict[str, str] | None = None) -> tuple[list[ToolEvidence], set]:
    """Evaluate applicable rules once per parsed file; keep unavailable coverage explicit."""
    results: list[ToolEvidence] = []
    try:
        rules, broken = discover_rules(*((root,) if reviewed else (root, False)))
    except Exception as exc:
        rules, broken = [], []
        results.append(ToolEvidence('forbid_ast', RULES_RELDIR, False,
                                   f'forbid_ast: cannot load rules: {type(exc).__name__}: {exc}'))
    for path, reason in broken:
        results.append(ToolEvidence('forbid_ast', path, False, f'forbid_ast: cannot load rule {path}: {reason}'))
    owned: set[tuple[str, int, str]] = set()
    for rel, why in (too_large or {}).items():
        covering = [rule for rule, _spec in rules if rule.applies_to(rel)]
        results.extend(ToolEvidence(f'forbid_ast:{rule.id}', rel, False,
                                    f'forbid_ast: cannot verify {rel}: {why}',
                                    language=source_language(rel)) for rule in covering)
    for rel, path in paths:
        applicable = [(rule, spec) for rule, spec in rules if rule.applies_to(rel)]
        if not applicable:
            continue
        try:
            tree = session.get(path)
        except Exception as exc:
            results.extend(_rule_failure(rule.id, rel, exc, failure, source_language(rel))
                           for rule, _spec in applicable)
            continue
        for rule, spec in applicable:
            if tree is None:
                from pathlib import Path

                ext = Path(rel).suffix.lower()
                results.append(ToolEvidence(NO_DRIVER_NOTE_TOOL, rel, True,
                               f'unverified no_driver:{ext}: {rel} matched forbid_ast:{rule.id}; no AST driver configured',
                               language=source_language(rel)))
                continue
            try:
                findings = policy.evaluate_forbid_ast_structured(tree, spec, rule_id=rule.id)
                owned.update(site_key(rel, f['line'], f['pattern']) for f in findings if not f['unknown'])
                rows = evidence(root, rule.id, rel, findings)
                for row in rows:
                    row.language = tree.language
                results.extend(rows)
            except Exception as exc:
                results.append(_rule_failure(rule.id, rel, exc, failure, tree.language))
    try:
        results.extend(exempt_notes(rules, [rel for rel, _path in paths]))
    except Exception as exc:
        results.append(failure('forbid_ast', RULES_RELDIR, exc))
    return results, owned
