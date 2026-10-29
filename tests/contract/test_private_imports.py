"""Shrink-only cross-module private coupling, including module aliases."""
import ast
from collections import Counter
from pathlib import Path
import pprint
import sys

import pytest

from tests.contract.test_process_ratchets import module_trees, ScopedNames, import_bindings

REPO = Path(__file__).resolve().parents[2]
PRIVATE_IMPORTS = {'aegis_cli/check.py:aegis_cli.verify._append_step_summary': 1,
 'aegis_cli/check.py:aegis_cli.verify._resolve_git_cwd': 2,
 'aegis_cli/check.py:aegis_cli.verify._wants_json': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._Ctx': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._HookStatus': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._claude_config': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._claude_project_keys': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._clean': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._confirm': 3,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._entry_facts': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._home': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._host_json_path': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._is_home': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._names': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._registration': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._server_entry': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._setup_fix': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_base._stdin_is_tty': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_findings._ast_driver_state': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_findings._diagnose': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_findings._missing_ast_extensions': 2,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._NO_AEGIS_JOB': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._github_plan': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._payload': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_findings': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_github': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_hosts': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_plan': 2,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_results': 2,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_tiers': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._print_trust': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_render._registered_launchers': 1,
 'aegis_cli/doctor.py:aegis_cli.doctor_repair._apply': 2,
 'aegis_cli/doctor.py:aegis_cli.doctor_repair._plan': 2,
 'aegis_cli/doctor_base.py:aegis_cli.commands_table._HOST_HOOK': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._Action': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._Ctx': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._FIX_HINT': 6,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._File': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._Finding': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._HookStatus': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._Instructions': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._LEGACY_ENTRY': 2,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._READS_AGENTS_OVERRIDE': 2,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._REGISTRY_BOUND': 3,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._TRUNCATES_TAIL': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._V3_SHIPPED_RULE_SHA256': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._app': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._claude_config': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._claude_dir': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._claude_user_registered': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._clean': 3,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._desktop_configs': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._host_json_path': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._instruction_files': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._instructions': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._is_home': 2,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._legacy_items': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._legacy_ranges': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._list_location': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._location': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._path_key': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._plane_found': 2,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._registered_roots': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._removed_host_phases': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._setup_command': 1,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._sha256': 7,
 'aegis_cli/doctor_findings.py:aegis_cli.doctor_base._without_lines': 1,
 'aegis_cli/doctor_render.py:aegis_cli.doctor_base._Ctx': 1,
 'aegis_cli/doctor_render.py:aegis_cli.doctor_base._Finding': 1,
 'aegis_cli/doctor_render.py:aegis_cli.doctor_base._clean': 1,
 'aegis_cli/doctor_render.py:aegis_cli.doctor_findings._Diagnosis': 1,
 'aegis_cli/doctor_render.py:aegis_cli.doctor_findings._TIER_TEXT': 1,
 'aegis_cli/doctor_render.py:aegis_cli.doctor_repair._Change': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._Finding': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._aegis_version': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._clean': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._location': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._path_key': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._sha256': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._without_lines': 1,
 'aegis_cli/doctor_repair.py:aegis_cli.doctor_base._write_refusal': 1,
 'aegis_cli/hooks/management.py:aegis_core.command_safety._HEREDOC': 1,
 'aegis_cli/hooks/registrar.py:aegis_cli.install_hosts._dump': 1,
 'aegis_cli/hooks/registrar.py:aegis_cli.install_hosts._load_json_object': 1,
 'aegis_cli/hooks/registrar.py:aegis_cli.install_hosts._preflight': 5,
 'aegis_cli/hooks/registrar.py:aegis_cli.install_hosts._read': 1,
 'aegis_cli/hooks/registrar.py:aegis_cli.install_hosts._replace': 2,
 'aegis_cli/hooks/registrar.py:aegis_cli.install_hosts._writable_dir': 1,
 'aegis_cli/init.py:aegis_cli.hooks._AEGIS_HOOK_START': 1,
 'aegis_cli/init.py:aegis_cli.hooks._SOMA_HOOK_START': 1,
 'aegis_cli/init.py:aegis_cli.hooks.management._replace_hook_block': 2,
 'aegis_cli/init.py:aegis_cli.init_views._home_label': 1,
 'aegis_cli/init.py:aegis_cli.init_views._print_actions': 1,
 'aegis_cli/init.py:aegis_cli.init_views._print_card': 1,
 'aegis_cli/init.py:aegis_cli.init_views._report_ci': 1,
 'aegis_cli/init.py:aegis_cli.init_views._report_hook': 1,
 'aegis_cli/init.py:aegis_core.workspace.hooks._find_git_dirs': 1,
 'aegis_cli/package.py:aegis_cli.skills_sync._packaged_skills': 1,
 'aegis_cli/package.py:aegis_cli.skills_sync._render': 1,
 'aegis_cli/uninstall.py:aegis_core.workspace.binding._resolve': 1,
 'aegis_cli/uninstall.py:aegis_core.workspace.binding._usable': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._SpellingIndex': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._call_target': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._decorator_name': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._decorator_pattern': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._extract_import_tuple': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._extract_python_decorators_from_file': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._extract_python_decorators_from_tree': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._import_aliases': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._normalize_ast_token': 1,
 'aegis_core/ast/policy.py:aegis_core.ast.schema._spellings': 1,
 'aegis_core/baseline.py:aegis_core.ast.detect._SKIP_DIRS': 1,
 'aegis_core/baseline.py:aegis_core.verification.runner._discover_forbid_ast_rules': 1,
 'aegis_core/command_safety/analyzer.py:aegis_core.command_safety.lexer._GIT_SHORT_VALUES': 1,
 'aegis_core/command_safety/analyzer.py:aegis_core.command_safety.lexer._long_option': 1,
 'aegis_core/command_safety/analyzer.py:aegis_core.command_safety.lexer._short_letters': 1,
 'aegis_core/command_safety/analyzer.py:aegis_core.command_safety.lexer._writes_a_device': 1,
 'aegis_core/command_safety/guard.py:aegis_core.command_safety.lexer._GIT_SHORT_VALUES': 1,
 'aegis_core/command_safety/guard.py:aegis_core.command_safety.lexer._long_option': 1,
 'aegis_core/command_safety/guard.py:aegis_core.command_safety.lexer._scan_heredocs': 1,
 'aegis_core/command_safety/guard.py:aegis_core.command_safety.lexer._short_letters': 1,
 'aegis_core/command_safety/guard.py:aegis_core.command_safety.lexer._split_heredocs': 1,
 'aegis_core/command_safety/guard.py:aegis_core.command_safety.lexer._writes_a_device': 1,
 'aegis_core/fitness.py:aegis_core.stats._num': 1,
 'aegis_core/insights/capture.py:aegis_core.insights.keys._append_user_insights': 1,
 'aegis_core/insights/capture.py:aegis_core.insights.keys._ensure_hs': 1,
 'aegis_core/insights/capture.py:aegis_core.insights.keys._ensure_private_dir': 1,
 'aegis_core/insights/capture.py:aegis_core.insights.keys._user_layout': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._confirmed': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._cosine': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._effective_level': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._paths_overlap_rule': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._superseded': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._tfidf_vectors': 1,
 'aegis_core/insights/recurrence.py:aegis_core.insights.review._tokenize': 1,
 'aegis_core/insights/review.py:aegis_core.insights.capture._corroborating_hook': 1,
 'aegis_core/insights/review.py:aegis_core.insights.capture._row_source': 1,
 'aegis_core/insights/review.py:aegis_core.insights.keys._append_user_insights': 1,
 'aegis_core/lifecycle/promotion.py:aegis_core.lifecycle.parsers._transform_frontmatter_type': 1,
 'aegis_core/migrate.py:aegis_core.config._read_json': 1,
 'aegis_core/rule_integrity.py:aegis_core.ast.schema._normalize_ast_token': 2,
 'aegis_core/storage.py:aegis_core.atomicio._O_CLOEXEC': 1,
 'aegis_core/storage.py:aegis_core.atomicio._O_NOFOLLOW': 1,
 'aegis_core/storage.py:aegis_core.atomicio._O_NONBLOCK': 1,
 'aegis_core/storage.py:aegis_core.atomicio._PRIVATE_FILE_MODE': 1,
 'aegis_core/storage.py:aegis_core.atomicio._SHARED_DIR_NAME': 1,
 'aegis_core/storage.py:aegis_core.atomicio._link_error': 1,
 'aegis_core/storage.py:aegis_core.atomicio._make_private': 1,
 'aegis_core/storage.py:aegis_core.atomicio._open_regular': 1,
 'aegis_core/storage.py:aegis_core.atomicio._write_all': 1,
 'aegis_core/verification/security_pack.py:aegis_core.ast.policy._new_findings': 1,
 'aegis_core/workspace/base.py:aegis_core.workspace.hooks._find_git_dirs': 1,
 'aegis_core/yaml_engine/frontmatter.py:aegis_core.yaml_engine.parser._CLOSING_DELIM_RE': 1,
 'aegis_core/yaml_engine/serializer.py:aegis_core.yaml_engine.parser._BOOL_FALSE': 1,
 'aegis_core/yaml_engine/serializer.py:aegis_core.yaml_engine.parser._BOOL_TRUE': 1,
 'aegis_core/yaml_engine/serializer.py:aegis_core.yaml_engine.parser._FLOAT_RE': 1,
 'aegis_core/yaml_engine/serializer.py:aegis_core.yaml_engine.parser._INT_RE': 1,
 'aegis_core/yaml_engine/serializer.py:aegis_core.yaml_engine.parser._NULL_VALUES': 1}


def test_private_import_pin_matches_tree():
    sites = private_imports(REPO)
    assert dict(Counter(sites)) == PRIVATE_IMPORTS, "private imports changed (lower pins after removals): " + repr(private_imports(REPO, locations=True))


def test_private_imports_count_imports_alias_attributes_and_skip_reexports(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "new.py").write_text("from aegis_core.config import _is_within\nfrom aegis_core import config as cfg\ncfg._read_capped('x')\n", encoding="utf-8")
    (package / "__init__.py").write_text("from .new import _helper\n", encoding="utf-8")
    found = private_imports(tmp_path)
    assert found == ["aegis_core/new.py:aegis_core.config._is_within", "aegis_core/new.py:aegis_core.config._read_capped"]


def private_imports(root, locations=False):
    found = []
    for rel, tree in module_trees(root):
        resolver = ScopedNames(tree, rel)
        own = rel.removesuffix(".py").replace("/", ".")
        package = own.rsplit(".", 1)[0]
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [import_bindings(node, rel)[a.asname or a.name] for a in node.names if a.name.startswith("_") and not a.name.startswith("__")]
            elif isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__"):
                names = resolver.resolve(node)
            for name in names:
                if not name.startswith(tuple(p + "." for p in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"))):
                    continue
                if name.rsplit(".", 1)[0] == own:
                    continue
                if rel.endswith("/__init__.py") and name.startswith(package + "."):
                    continue
                found.append(f"{rel}:{node.lineno}:{name}" if locations else f"{rel}:{name}")
    return sorted(found)


def lowered_private(record, current):
    growth = [k for k, v in current.items() if v > record.get(k, 0)]
    if growth:
        raise ValueError("refusing to raise private import records: " + repr(growth))
    return current


def test_private_pin_writer_can_only_shrink():
    with pytest.raises(ValueError, match="refusing to raise private import records"):
        lowered_private({"old": 1}, {"new": 1})
    with pytest.raises(ValueError, match="refusing to raise private import records"):
        lowered_private({"old": 1}, {"old": 2})
    assert lowered_private({"old": 2}, {"old": 1}) == {"old": 1}


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 tests/contract/test_private_imports.py --write")
    current = dict(Counter(private_imports(REPO)))
    try:
        current = lowered_private(PRIVATE_IMPORTS, current)
    except ValueError as exc:
        sys.exit(str(exc))
    path = Path(__file__)
    source = path.read_text(encoding="utf-8")
    assignment = next(n for n in ast.parse(source).body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "PRIVATE_IMPORTS" for t in n.targets))
    lines = source.splitlines(keepends=True)
    lines[assignment.lineno - 1:assignment.end_lineno] = ["PRIVATE_IMPORTS = " + pprint.pformat(current, sort_dicts=True) + "\n"]
    path.write_text("".join(lines), encoding="utf-8")


@pytest.mark.parametrize("reverse", [False, True])
def test_private_aliases_do_not_leak_between_sibling_scopes(tmp_path, reverse):
    package = tmp_path / "aegis_core"
    package.mkdir()
    pieces = ["def inspect():\n    from aegis_core import config as backend\n    backend._read_capped('x')\n",
              "def decode():\n    import json as backend\n    backend._decoder('x')\n"]
    (package / "probe.py").write_text("\n".join(reversed(pieces) if reverse else pieces), encoding="utf-8")
    assert private_imports(tmp_path) == ["aegis_core/probe.py:aegis_core.config._read_capped"]
