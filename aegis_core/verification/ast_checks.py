"""Shared AST availability and forbid-rule evaluation for ordinary and staged sources."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

from aegis_core.ast import policy
from aegis_core.ast.detect import LANGUAGE_DEFINITIONS
from aegis_core.ast.schema import canonical_spelling
from aegis_core.match import is_test_path
from aegis_core.verification import ToolEvidence
from aegis_core.verification.security_pack import PACK_EXTENSIONS
from aegis_core.workspace.layout import RULES_RELDIR

NO_DRIVER_NOTE_TOOL = 'forbid_ast_no_driver'
AST_SIZE_NOTE_TOOL = 'ast_unverified'


def too_large_note(path: str, language: str = 'unknown') -> ToolEvidence:
    return ToolEvidence(AST_SIZE_NOTE_TOOL, path, True,
        f'unverified too_large: {path} exceeds 2 MiB; use target_paths to exclude generated bundles (aegis doctor)',
        language=language)


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
    from aegis_core.ast.runner import NATIVE_SOURCE_EXTENSIONS, ASTDriverRegistry
    from aegis_core.skills.slots import SlotRegistry

    langs = detect_project_languages(ws_root)
    drivers: Dict[str, str] = {}
    for registry in (SlotRegistry.load(ws_root), SlotRegistry.load_user(ws_root)):
        for slot_name, slot_val in registry.to_dict().items():
            if slot_name == "ast_driver":
                drivers["default"] = str(slot_val)
            elif slot_name.startswith("ast_driver_"):
                drivers[f".{slot_name[len('ast_driver_'):]}"] = str(slot_val)
    native = ASTDriverRegistry()
    for info in langs.values():
        for ext in info.get('extensions', []):
            if ext in NATIVE_SOURCE_EXTENSIONS:
                drivers[ext] = native.resolve_driver(ext)
    if "default" in drivers:
        return drivers, []
    missing = {ext for lang, info in langs.items() if lang != "python"
               for ext in info.get("extensions", []) if ext not in drivers}
    return drivers, sorted(missing | uncovered_extensions(ws_root, set(drivers)))


def _rule_failure(rule_id: str, rel: str, exc: Exception, failure: Any, language: str) -> ToolEvidence:
    row = failure(f'forbid_ast:{rule_id}', rel, exc)
    if isinstance(exc, policy.ASTExtractionError) and row.tool != AST_SIZE_NOTE_TOOL:
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
        if not covering and Path(rel).suffix.lower() in PACK_EXTENSIONS - {'.py'}:
            results.append(too_large_note(rel, source_language(rel)))
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


def run_security_checks(git_root: str, rels: list[str], work_root: str, diff_base: str | None,
                        owned: set[tuple[str, int, str]], contents: dict[str, bytes] | None,
                        present: Any, *, read_base: Any, failure: Any, session: Any = None) -> list[ToolEvidence]:
    """T7 on ``rels``: the language security packs and the Tier A secret scan, each against the file's
    text before the change, so only what it introduces fails (spec T7, D-delta: user forbid_ast rules
    keep whole-file judgment). Test-path hits and undecidable sites are reported on a passing row; an
    ``# aegis: allow`` hit passes unrecorded (no credit for pack rows); an unreadable file and any
    failure to run fail closed. A call a user forbid_ast rule judged at a site, failed or allowed (the
    seeded no-eval rule's eval), is that rule's: the pack neither reports it twice nor second-guesses
    its allow. Another call on the same line (``pickle.loads(eval(s))``) stays the pack's.
    ``contents`` holds the bytes of files not on disk under ``work_root`` (non-Python only), and
    ``present`` says which paths the checked tree holds (_base_sources)."""
    from aegis_core.verification import scanners, security_pack

    try:
        base_sources = read_base(git_root, rels, work_root, diff_base, contents, present)
        typed = [rel for rel in rels if Path(rel).suffix.lower() in PACK_EXTENSIONS]
        pack = security_pack.evaluate_security_pack(work_root, typed, base_sources, session=session) if typed else {}
        secrets = scanners.scan_secrets_delta(work_root, rels, {p: b.decode("utf-8", "replace") for p, b in base_sources.items()}, contents)
    except Exception as exc:
        return [failure("security_pack", "changed files", exc)]
    hits: dict[tuple[str, str], list[dict[str, Any]]] = {}
    notes: dict[str, list[str]] = {}
    advisory = []
    for hit in pack.get("violations", ()):
        if site_key(hit["file"], hit["line"], hit["pattern"]) not in owned:
            hits.setdefault((f"security_pack:{hit['rule_id']}", hit["file"]), []).append(hit)
    for hit in pack.get("unverified_findings", ()):
        if hit.get('reason') == 'too_large':
            advisory.append(too_large_note(hit['file'], source_language(hit['file'])))
        elif hit.get('reason', '').startswith('no_driver:'):
            advisory.append(ToolEvidence(NO_DRIVER_NOTE_TOOL, hit['file'], True,
                f"unverified {hit['reason']}: {hit['file']} has a security pack; no AST driver configured",
                language=source_language(hit['file'])))
        elif hit["kind"] == "file":
            hits.setdefault(("security_pack", hit["file"]), []).append(hit)
        else:
            notes.setdefault(hit["file"], []).append(f"unverified (advisory): {hit['rule_id']} line {hit['line']}")
    for hit in pack.get("exempted_test_findings", ()):
        notes.setdefault(hit["file"], []).append(f"exempted in a test path: {hit['rule_id']} line {hit['line']}")
    for f in secrets:
        if is_test_path(f.path):
            notes.setdefault(f.path, []).append(f"exempted in a test path: {f.rule_id} line {f.line}")
        else:  # named by rule and line only: no repository text, masked or not, reaches the detail
            hits.setdefault((f"secret_scan:{f.rule_id}", f.path), []).append({"line": f.line, "pattern": f.rule_id})
    out = advisory
    for (tool, rel), found in hits.items():
        if tool == "security_pack":
            detail = f"security_pack: cannot verify {rel}: {found[0]['reason']}"
        else:
            # No line number: SARIF fingerprints hash the message, and the lines are in ``lines``.
            detail = "; ".join(dict.fromkeys(f"{h['pattern']} introduced by this change" for h in found))
        out.append(ToolEvidence(tool=tool, target=rel, verdict=False, detail=detail,
                                lines=sorted({h["line"] for h in found if h["line"] > 0}), language=source_language(rel)))
    out.extend(ToolEvidence(tool="security_pack", target=rel, verdict=True, detail="; ".join(items), language=source_language(rel))
               for rel, items in sorted(notes.items()))
    return out
