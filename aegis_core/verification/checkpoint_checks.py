"""Shared, deterministic, read-only checkpoint checks for CLI and MCP."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import List

from aegis_core.taxonomy import RULE_TYPES
from aegis_core.workspace.layout import AEGIS_DIRNAME, LEGACY_SOMA_DIRNAME


HARDCODED_PATH_RE = re.compile(r'''(?:"|')(/home/|/Users/|/tmp/)''')
SKIP_DIRS = {
    "__pycache__", ".git", LEGACY_SOMA_DIRNAME, AEGIS_DIRNAME, "node_modules", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "egg-info",
}


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except (ValueError, OSError):
        return str(path)


def _failure(
    check: str,
    root: Path,
    path: Path,
    operation: str,
    exc: BaseException,
) -> dict:
    rel = _relative(root, path)
    return {
        "check": check,
        "file": rel,
        "message": f"{rel}: {operation} failed: {exc}",
    }


def _is_regular_file(
    check: str,
    root: Path,
    path: Path,
    issues: list[dict],
) -> bool:
    """Validate a checked input without following a symlink."""
    try:
        info = os.stat(path, follow_symlinks=False)
    except FileNotFoundError as exc:
        issues.append(_failure(check, root, path, "stat", exc))
        return False
    except (OSError, UnicodeError) as exc:
        issues.append(_failure(check, root, path, "stat", exc))
        return False
    if stat.S_ISLNK(info.st_mode):
        issues.append({
            "check": check,
            "file": _relative(root, path),
            "message": f"{_relative(root, path)}: symlinked file is not allowed",
        })
        return False
    if not stat.S_ISREG(info.st_mode):
        issues.append({
            "check": check,
            "file": _relative(root, path),
            "message": f"{_relative(root, path)}: expected a regular file",
        })
        return False
    return True


def find_python_files(root: Path, subdir: str) -> list[Path]:
    """Find source files without following symlinked directories."""
    target = root / subdir
    result = []  # type: List[Path]
    try:
        target_info = os.stat(target, follow_symlinks=False)
    except FileNotFoundError:
        return result
    if not stat.S_ISDIR(target_info.st_mode):
        return result

    def walk_error(exc: OSError) -> None:
        raise exc

    for dirpath, dirnames, filenames in os.walk(
        target, topdown=True, followlinks=False, onerror=walk_error
    ):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            if filename.endswith(".py") and not filename.startswith("__"):
                result.append(Path(dirpath) / filename)
    return result


def _source_dirs(root: Path, check: str, issues: list[dict]) -> list[str]:
    try:
        with os.scandir(root) as it:
            candidates = sorted(it, key=lambda e: e.name)
    except (OSError, UnicodeError) as exc:
        issues.append(_failure(check, root, root, "list", exc))
        return []

    names = []
    for entry in candidates:
        name = entry.name
        if name.startswith(".") or name in SKIP_DIRS or name == "tests":
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            issues.append(_failure(check, root, Path(entry.path), "stat", exc))
            continue
        except (OSError, UnicodeError) as exc:
            issues.append(_failure(check, root, Path(entry.path), "stat", exc))
            continue
        candidate = Path(entry.path)
        if stat.S_ISLNK(info.st_mode):
            issues.append({
                "check": check,
                "file": _relative(root, candidate),
                "message": (
                    f"{_relative(root, candidate)}: "
                    "symlinked source directory is not allowed"
                ),
            })
            continue
        if not stat.S_ISDIR(info.st_mode):
            continue
        try:
            if find_python_files(root, name):
                names.append(name)
        except (OSError, UnicodeError) as exc:
            issues.append(_failure(check, root, candidate, "list", exc))
    return names


def _resolve_canonical_test_candidates(root: Path, source_file: Path) -> list[Path]:
    """Resolve deterministic test candidates for a source file in canonical and dynamic layouts."""
    test_dir = root / "tests"
    rel_posix = _relative(root, source_file)
    candidates: list[Path] = []

    # 1. Canonical mirrored directory paths (tests/<clean_pkg>/.../test_<stem>.py and tests/<top_pkg>/.../test_<stem>.py)
    rel_path = Path(rel_posix)
    parts = list(rel_path.parts)
    stem = rel_path.stem
    if len(parts) >= 2:
        top_pkg = parts[0]
        if top_pkg.startswith("aegis_"):
            clean_pkg = top_pkg[6:]
        elif top_pkg.startswith("soma_"):
            clean_pkg = top_pkg[5:]
        else:
            clean_pkg = top_pkg
        subparts = parts[1:-1]
        candidates.append(test_dir.joinpath(clean_pkg, *subparts, f"test_{stem}.py"))
        candidates.append(test_dir.joinpath(top_pkg, *subparts, f"test_{stem}.py"))
        candidates.append(test_dir.joinpath("unit", clean_pkg, *subparts, f"test_{stem}.py"))
        candidates.append(test_dir.joinpath("unit", top_pkg, *subparts, f"test_{stem}.py"))
        candidates.append(test_dir.joinpath("unit", clean_pkg, f"test_{stem}.py"))
        candidates.append(test_dir.joinpath("unit", top_pkg, f"test_{stem}.py"))

    # 2. Subpackage and platform suite candidates
    parent_name = source_file.parent.name
    if parent_name != "tests":
        candidates.append(test_dir / f"test_{parent_name}.py")
        candidates.append(test_dir / f"test_{parent_name}_{stem}.py")
        if len(parts) >= 2:
            clean_pkg = parts[0][6:] if parts[0].startswith("aegis_") else (parts[0][5:] if parts[0].startswith("soma_") else parts[0])
            candidates.append(test_dir / f"test_{clean_pkg}_{parent_name}.py")
            candidates.append(test_dir / f"test_{parent_name}_adapters.py")
            candidates.append(test_dir / f"test_{clean_pkg}_{parent_name}_adapters.py")
            candidates.append(test_dir / f"test_{clean_pkg}_{parent_name}_{stem}.py")

    # 3. Domain and legacy suite mappings, for the Aegis packages only
    candidates.extend(_aegis_suite_candidates(test_dir, parts, stem, parent_name))

    # 4. Flat root candidates
    candidates.append(test_dir / f"test_{stem}.py")
    candidates.append(test_dir / f"test_{stem}_behavioral.py")
    candidates.append(test_dir / "test_verification" / f"test_{stem}.py")
    candidates.append(test_dir / "unit" / "verification" / f"test_{stem}.py")

    expanded: list[Path] = []
    seen = set()
    for c in candidates:
        if c not in seen:
            expanded.append(c)
            seen.add(c)
        if c.parent == test_dir:
            for domain in ("core", "cli", "mcp", "sdk", "verification"):
                cand_domain = test_dir / "unit" / domain / c.name
                if cand_domain not in seen:
                    expanded.append(cand_domain)
                    seen.add(cand_domain)
            for subdir in ("integration", "contract"):
                cand_sub = test_dir / subdir / c.name
                if cand_sub not in seen:
                    expanded.append(cand_sub)
                    seen.add(cand_sub)

    return expanded


def _aegis_suite_candidates(test_dir: Path, parts: List[str], stem: str, parent_name: str) -> List[Path]:
    """Aegis's own suite files for a source file of the Aegis packages (aegis_*, or the legacy
    soma_* brand). The map names this repository's layout, so it is valid only inside those
    packages: anywhere else a suite it names says nothing about the file."""
    candidates: List[Path] = []
    top_dir = parts[0] if parts else ""
    if top_dir in ("aegis_cli", "soma_cli"):
        candidates.append(test_dir / f"test_cli_{stem}.py")
        candidates.append(test_dir / "test_platforms.py")
        candidates.append(test_dir / "test_platform_adapters.py")
    elif top_dir in ("aegis_core", "soma_core"):
        candidates.append(test_dir / f"test_core_{stem}.py")
    elif top_dir in ("aegis_mcp", "soma_mcp"):
        candidates.append(test_dir / f"test_mcp_{stem}.py")
    elif top_dir in ("aegis_sdk", "soma_sdk"):
        candidates.append(test_dir / f"test_sdk_{stem}.py")
    else:
        return candidates

    if "ast" in parts:
        candidates.append(test_dir / f"test_ast_{stem}.py")
        candidates.append(test_dir / "unit" / "core" / f"test_ast_{stem}.py")
    if stem == "detect":
        candidates.append(test_dir / "test_ast_detect.py")
        candidates.append(test_dir / "unit" / "core" / "test_ast_detect.py")
        candidates.append(test_dir / "test_polyglot_detect.py")
        candidates.append(test_dir / "unit" / "core" / "test_polyglot_detect.py")
    if stem == "schema":
        candidates.append(test_dir / "test_ast_schema.py")
        candidates.append(test_dir / "unit" / "core" / "test_ast_schema.py")
        candidates.append(test_dir / "test_normalized_ast_schema.py")
        candidates.append(test_dir / "unit" / "core" / "test_normalized_ast_schema.py")
    if stem == "python":
        candidates.append(test_dir / "test_ast_python.py")
        candidates.append(test_dir / "unit" / "core" / "test_ast_python.py")
        candidates.append(test_dir / "test_ast_driver_runner.py")
        candidates.append(test_dir / "unit" / "core" / "test_ast_driver_runner.py")
    if stem == "rust_ast":
        candidates.append(test_dir / "test_ast_rust.py")
        candidates.append(test_dir / "unit" / "core" / "test_ast_rust.py")
        candidates.append(test_dir / "test_rust_ast_driver.py")
        candidates.append(test_dir / "unit" / "core" / "test_rust_ast_driver.py")
    if stem == "checkpoint_checks":
        candidates.append(test_dir / "test_checkpoint_fail_closed.py")
    if stem in ("call_graph", "persistence_checker", "runner"):
        candidates.append(test_dir / "test_verification" / "test_layer1.py")
        candidates.append(test_dir / "unit" / "verification" / "test_layer1.py")
        candidates.append(test_dir / "unit" / "verification" / "test_call_graph_ast.py")
    if stem == "hooks":
        candidates.append(test_dir / "test_hooks_lifecycle.py")
    if stem == "errors":
        candidates.append(test_dir / "test_domain_errors.py")
    if stem == "frontmatter":
        candidates.append(test_dir / "test_core_lifecycle.py")
    if stem == "rule_inventory":
        candidates.append(test_dir / "test_rule_inventory.py")
    if stem == "adversarial_verify":
        candidates.append(test_dir / "unit" / "verification" / "test_adversarial_verify.py")
    if stem in ("taxonomy", "operations", "layout", "discovery"):
        candidates.append(test_dir / "unit" / "core" / "test_v3_zero_legacy_invariants.py")
        candidates.append(test_dir / "unit" / "core" / "test_storage.py")
        candidates.append(test_dir / "unit" / "core" / "test_workspace.py")
    if stem == "server":
        candidates.append(test_dir / "test_mcp_dispatch.py")
        candidates.append(test_dir / "test_mcp_session_stdio_contract.py")
        candidates.append(test_dir / "test_mcp_protocol_hygiene.py")
    if stem == "tools":
        candidates.append(test_dir / "test_mcp_tools_contract.py")
    if top_dir == "aegis_mcp" and stem == "schemas":
        candidates.append(test_dir / "unit" / "mcp" / "test_mcp_registry.py")
    if parent_name == "skills" or stem in ("slots", "skills"):
        candidates.append(test_dir / "test_skills.py")
    if parent_name == "handlers" or stem in ("registry", "projection"):
        candidates.append(test_dir / "test_mcp_tools_contract.py")
        candidates.append(test_dir / "test_mcp_dispatch.py")
        candidates.append(test_dir / "test_mcp_projection.py")
    if parent_name == "outcomes":
        candidates.append(test_dir / "test_outcome_engine.py")
        candidates.append(test_dir / "test_outcomes.py")
    if parent_name == "hooks":
        candidates.append(test_dir / "test_hooks_lifecycle.py")
    if parent_name == "formatters" or stem in ("base", "report"):
        candidates.append(test_dir / "test_cli.py")
        candidates.append(test_dir / "test_check_sarif.py")
    if parent_name == "yaml_engine" or stem in ("document", "serializer"):
        candidates.append(test_dir / "test_yaml_engine_roundtrip.py")
        candidates.append(test_dir / "test_frontmatter_engine.py")
    if stem in ("doctor_base", "doctor_findings", "doctor_repair", "doctor_render"):
        candidates.append(test_dir / "test_doctor.py")
        candidates.append(test_dir / "test_doctor_fix.py")
    if stem == "commands_table":
        candidates.append(test_dir / "test_cli_removed_commands.py")
    if stem == "init_views":
        candidates.append(test_dir / "test_init.py")
        candidates.append(test_dir / "test_init_card.py")
    if stem == "_version":
        candidates.append(test_dir / "test_version.py")
    if stem == "approve":
        candidates.append(test_dir / "test_human_gate.py")
        candidates.append(test_dir / "test_f_a1_human_gate_acceptance.py")
    if stem == "bootstrap":
        candidates.append(test_dir / "test_hosts_contract.py")
        candidates.append(test_dir / "test_init_hosts.py")
    if stem in ("checkrun", "treeid"):
        candidates.append(test_dir / "test_verified_checks_units.py")
        candidates.append(test_dir / "test_f_a2_verified_checks_acceptance.py")
    if stem == "credit":
        candidates.append(test_dir / "test_f_b2_credit_model_acceptance.py")
    if stem == "hosts":
        candidates.append(test_dir / "test_hosts_contract.py")
        candidates.append(test_dir / "test_init_hosts.py")
    if stem == "scan_compliance":
        candidates.append(test_dir / "test_status_compliance.py")
    if stem == "policy":
        candidates.append(test_dir / "test_forbid_ast_rules.py")
        candidates.append(test_dir / "test_forbid_ast_hardening.py")
    return candidates


def check_test_coverage(root: Path) -> list[dict]:
    issues = []  # type: List[dict]
    source_files = []  # type: List[Path]
    for source_dir in _source_dirs(root, "test_coverage", issues):
        try:
            source_files.extend(find_python_files(root, source_dir))
        except (OSError, UnicodeError) as exc:
            issues.append(_failure(
                "test_coverage", root, root / source_dir, "list", exc
            ))

    for source_file in source_files:
        if not _is_regular_file(
            "test_coverage", root, source_file, issues
        ):
            continue

        candidates = _resolve_canonical_test_candidates(root, source_file)
        matched = False
        for expected in candidates:
            try:
                expected_info = os.stat(expected, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError) as exc:
                issues.append(_failure("test_coverage", root, expected, "stat", exc))
                matched = True
                break
            else:
                if stat.S_ISLNK(expected_info.st_mode) or not stat.S_ISREG(expected_info.st_mode):
                    kind = "symlinked" if stat.S_ISLNK(expected_info.st_mode) else "non-regular"
                    issues.append({
                        "check": "test_coverage",
                        "file": _relative(root, expected),
                        "message": (
                            f"{_relative(root, expected)}: {kind} test file "
                            "does not satisfy coverage"
                        ),
                    })
                matched = True
                break

        if not matched:
            issues.append({
                "check": "test_coverage",
                "file": _relative(root, source_file),
                "message": (
                    f"Missing test file for {source_file.name}: "
                    f"expected tests/test_{source_file.stem}.py"
                ),
            })
    return issues


def check_hardcoded_paths(root: Path) -> list[dict]:
    issues = []  # type: List[dict]
    for source_dir in _source_dirs(root, "hardcoded_paths", issues):
        try:
            files = find_python_files(root, source_dir)
        except (OSError, UnicodeError) as exc:
            issues.append(_failure(
                "hardcoded_paths", root, root / source_dir, "list", exc
            ))
            continue
        for py_file in files:
            if not _is_regular_file(
                "hardcoded_paths", root, py_file, issues
            ):
                continue
            try:
                content = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                issues.append(_failure(
                    "hardcoded_paths", root, py_file, "read", exc
                ))
                continue
            for line_no, line in enumerate(content.splitlines(), 1):
                if HARDCODED_PATH_RE.search(line):
                    issues.append({
                        "check": "hardcoded_paths",
                        "file": _relative(root, py_file),
                        "line": line_no,
                        "message": (
                            f"Hardcoded absolute path found in "
                            f"{py_file.name}:{line_no}"
                        ),
                    })
    return issues


def check_assertion_density(root: Path) -> list[dict]:
    """Every ``test_*`` function under tests/ must assert something and not be a stub.

    Judged per function by AST (#1): text such as "assert " in a comment, a
    docstring or a neighbouring test no longer passes a file.
    """
    from aegis_core.verification.quality_gate import check_assertion_density as density
    from aegis_core.verification.quality_gate import check_no_bare_pass as bare_pass

    issues = []  # type: List[dict]
    try:
        test_files = find_python_files(root, "tests")
    except (OSError, UnicodeError) as exc:
        return [_failure("assertion_density", root, root / "tests", "list", exc)]

    for test_file in test_files:
        if not test_file.name.startswith("test_"):
            continue
        if not _is_regular_file("assertion_density", root, test_file, issues):
            continue
        try:
            found = [density(str(test_file)), bare_pass(str(test_file))]
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            issues.append(_failure("assertion_density", root, test_file, "parse", exc))
            continue
        prefixes = ("Low assertion density in", "Placeholder tests in")
        for prefix, evidence in zip(prefixes, found):
            if not evidence.verdict:
                issues.append({
                    "check": "assertion_density",
                    "file": _relative(root, test_file),
                    "lines": evidence.lines,
                    "message": f"{prefix} {test_file.name}: {evidence.detail[0].lower()}{evidence.detail[1:]}",
                })
    return issues


def check_rule_fitness(root: Path) -> list[dict]:
    """Unreadable ledger rows, and rules the fitness engine (aegis_core.fitness.compute, the
    lifecycle's one decision) decides misfire."""
    from aegis_core.fitness import compute
    from aegis_core.telemetry_engine import ledger

    issues = []  # type: List[dict]
    view = ledger.read(root)
    rel = _relative(root, Path(view.path)) if view.path is not None else "ledger"
    if view.error:
        issues.append({"check": "rule_fitness", "file": rel, "message": f"{rel}: {view.error}"})
    for line in view.skipped_lines:
        issues.append({
            "check": "rule_fitness",
            "file": rel,
            "message": f"{rel}: line {line} is not a JSON object row",
        })
    if view.unusable_rows:
        issues.append({
            "check": "rule_fitness",
            "file": rel,
            "message": f"{rel}: {view.unusable_rows} row(s) lack a rule, a valid outcome or a valid weight",
        })

    for rule_id, counts in sorted(ledger.aggregate_rows(view.rows).items()):
        fit = compute(counts, rule=rule_id)
        if fit.state == "decided" and fit.suggestion in ("demote", "archive"):
            issues.append({
                "check": "rule_fitness",
                "rule": rule_id,
                "message": (
                    f"Rule '{rule_id}' misfires: {fit.fp:g} of {fit.verdicts:g} verdicts are false "
                    f"positives, and the fitness engine decided it (P(precision < 0.7) = {fit.p_below_demote:.2f}); "
                    "aegis sync suggests demoting or archiving it"
                ),
            })
    return issues


def check_rule_conventions(root: Path) -> list[dict]:
    """Every rule file loads (aegis_core.rules) and carries the fields its type needs.

    A rule that cannot be loaded is a ``rule_load`` issue: aegis scan refuses to serve
    the rule set while it exists, so ``aegis check`` blocks on it too.
    """
    from aegis_core.rule_inventory import RuleInventoryError
    from aegis_core.rules import load_rules

    issues = []  # type: List[dict]
    try:
        ruleset = load_rules(root)
    except RuleInventoryError as exc:
        return [_failure("rule_load", root, Path(exc.path), exc.operation, exc)]

    for rule in ruleset.rules:
        if rule.error:
            issues.append({"check": "rule_load", "file": rule.path, "message": f"{rule.path}: {rule.error}"})
            continue
        required = ["id", "domain", "type"]
        if rule.type in ("invariant", "trap"):
            required.append("enforcement")
        for name in required:
            if name not in rule.meta:
                issues.append({
                    "check": "rule_conventions",
                    "file": rule.path,
                    "message": f"{rule.path}: missing required field '{name}'",
                })
    return issues


def check_paper_gates(root: Path) -> list[dict]:
    """A gate or invariant rule must use ``gate`` enforcement: one that does not claims to
    be a gate and enforces nothing. A mandatory-type rule that cannot be loaded cannot be
    shown to be a gate, so it is reported too."""
    from aegis_core.rule_inventory import RuleInventoryError
    from aegis_core.rules import load_rules

    try:
        ruleset = load_rules(root)
    except RuleInventoryError as exc:
        return [_failure("paper_gates", root, Path(exc.path), exc.operation, exc)]
    issues = []
    for rule in ruleset.rules:
        if rule.type is None or not RULE_TYPES[rule.type].mandatory:
            continue
        name = rule.path.rsplit("/", 1)[-1]
        label = f"{rule.type.capitalize()} rule '{name}'"
        if rule.error:
            issues.append({
                "check": "paper_gates",
                "file": rule.path,
                "message": f"{label} cannot be read, so it cannot be shown to use 'gate': {rule.error}",
            })
        elif rule.enforcement != "gate":
            issues.append({
                "check": "paper_gates",
                "file": rule.path,
                "message": (
                    f"{label} enforcement is '{rule.meta.get('enforcement')}', "
                    f"but all {rule.type} rules must use 'gate'."
                ),
            })
    return issues


ALL_CHECKS = [
    check_test_coverage,
    check_hardcoded_paths,
    check_assertion_density,
    check_rule_fitness,
    check_rule_conventions,
    check_paper_gates,
]
CHECK_NAMES = [
    "test_coverage",
    "hardcoded_paths",
    "assertion_density",
    "rule_fitness",
    "rule_conventions",
    "paper_gates",
]


def run_all_checks(root: Path) -> list[dict]:
    """Run every check and convert unexpected check failures into issues."""
    issues = []  # type: List[dict]
    for check_fn in ALL_CHECKS:
        try:
            issues.extend(check_fn(root))
        except Exception as exc:
            check_name = check_fn.__name__.replace("check_", "", 1)
            issues.append(_failure(check_name, root, root, "check", exc))
    return issues

