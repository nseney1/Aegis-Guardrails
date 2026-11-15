"""Pin process, lookup, conversion and envelope sites by function and count."""
import ast
from collections import Counter, namedtuple
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
RECORD = Path(__file__).with_name("process_ratchet.json")
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")
RAW = {"subprocess." + n for n in ("run", "Popen", "check_output", "call", "check_call", "getoutput", "getstatusoutput")} | {"os.system", "os.popen"}
RAW |= {"os." + n for n in (
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "posix_spawn", "posix_spawnp")}
POPEN_POSITIONAL_APIS = {"subprocess." + name for name in ("Popen", "run", "call", "check_call", "check_output")}

# Coordinator ruling 2026-11-15T04:52:12Z: this reviewed source inventory is
# the completeness gate. Resolver precision does not grant admission to a site.
SELECTOR_SITE_TABLE = (
    ("aegis_cli/doctor.py", "_launcher_problem", "lexer-or-message",
     "Compare the registered isolated Python launcher shape; no launch is performed here."),
    ("aegis_cli/hooks/commitmsg.py", "generate_script", "shell-script",
     "Render the commit-message hook with its isolated Python bootstrap and installation root."),
    ("aegis_cli/hooks/management.py", "generate_hook_block", "shell-script",
     "Render the pre-commit shell hook with its isolated Python bootstrap and installation root."),
    ("aegis_cli/hooks/registrar.py", "install_insight_hook", "resolved-python-program",
     "Construct isolated Python insight-hook launchers from the constant INSIGHT_RUNNER."),
    ("aegis_cli/install_hosts.py", "mcp_command", "resolved-python-program",
     "Construct the isolated MCP launcher from the constant MCP_RUNNER."),
    ("aegis_core/benchmark.py", "measure_hook", "resolved-python-program",
     "Benchmark the constant isolated HOOK_RUNNER through the injected reviewed runner."),
    ("aegis_core/command_safety/analyzer.py", "evaluate_git", "lexer-or-message",
     "Recognize and refuse Git configuration override flags in analyzed commands."),
    ("aegis_core/command_safety/guard.py", "_git_aliases", "lexer-or-message",
     "Read alias definitions from already-tokenized Git configuration flags."),
    ("aegis_core/command_safety/lexer.py", "<module>", "lexer-or-message",
     "Declare option grammars for native tools and shell interpreter command selectors."),
    ("aegis_core/command_safety/lexer.py", "unwrap_command_stage", "lexer-or-message",
     "Recognize shell command selectors while unwrapping commands for analysis."),
    ("aegis_core/gitops_fds.py", "_git_command", "git-config",
     "Skip Git configuration pairs before enforcing the closed effect command grammar."),
    ("aegis_core/gitops_fds.py", "git_effect", "git-config",
     "Insert effect hardening and the descriptor-pinned SSH command as Git configuration data."),
    ("aegis_core/gitops_fds.py", "git_result", "git-config",
     "Skip Git configuration pairs when interpreting a completed effect command."),
    ("aegis_core/gitops_fds.py", "holder_recipe", "resolved-python-program",
     "Run the once-captured co-located holder module with -I; its spawn has a separate module row."),
    ("aegis_core/gitops_holder.py", "main", "reviewed-dynamic",
     "Spawn the effect through the descriptor-pinned executable supplied by the parent's holder recipe."),
    ("aegis_core/gitsafe.py", "export_tree", "git-config",
     "Disable symlink, sparse-checkout and newline conversion for native Git tree export."),
    ("aegis_core/gitsafe.py", "filter_overrides", "git-config",
     "Construct Git configuration pairs that neutralize repository filter drivers."),
    ("aegis_core/gitsafe.py", "merge_tree_conflicted", "git-config",
     "Disable merge renormalization alongside the existing Git filter hardening."),
    ("aegis_core/gitsafe.py", "run", "reviewed-dynamic",
     "Delegate the Git transport with its executable resolver and existing subprocess runner reference."),
    ("aegis_core/gitsafe_run.py", "<module>", "git-config",
     "Declare the fixed native Git hardening and lane configuration option tuples."),
    ("aegis_core/gitsafe_run.py", "LaneRunner.validate", "git-config",
     "Add bounded validated filter-driver configuration overrides to the lane command."),
    ("aegis_core/gitsafe_run.py", "_argv", "git-config",
     "Insert native Git hooks-path and maintenance configuration before command arguments."),
    ("aegis_core/gitsafe_run.py", "_command", "git-config",
     "Validate Git configuration pairs against the fixed configuration and filter grammars."),
    ("aegis_core/human_gate.py", "_signature", "git-config",
     "Select SSH signature verification settings for native Git log."),
    ("aegis_core/human_gate.py", "signed_empty_commit", "git-config",
     "Select the signing key and SSH signing program for the native signed Git commit."),
    ("aegis_core/inference_provider.py", "CommandBackend.generate", "reviewed-dynamic",
     "Run the configured model command with the executable supplied by its start recipe."),
    ("aegis_core/language_runtime.py", "language_runtime_environment", "lexer-or-message",
     "Build language environment metadata using the runtime command's executable; this helper does not spawn."),
    ("aegis_core/language_runtime.py", "prepare_language_runtime", "lexer-or-message",
     "Build Go environment metadata with its resolved executable; the environment constructor does not spawn."),
    ("aegis_core/manager_config.py", "initialize", "resolved-python-program",
     "Register the isolated manager MCP launcher targeting the censused aegis_mcp package."),
    ("aegis_core/manager_config.py", "verify_owner", "git-config",
     "Select pinned signer material and SSH verification settings for native Git log."),
    ("aegis_core/sync.py", "<module>", "git-config",
     "Declare native Git push hardening that disables hooks and unapproved transports."),
    ("aegis_core/sync.py", "_commit", "lexer-or-message",
     "The native Git commit-tree -m option carries the commit title rather than a Python module target."),
    ("aegis_core/testexec.py", "python_module_index", "lexer-or-message",
     "Recognize code selectors in the source-pinned interpreter-option validator."),
    ("aegis_core/testexec.py", "run_pytest_snapshot", "resolved-python-program",
     "Construct the isolated snapshot test launcher from its constant bootstrap."),
    ("aegis_core/treeid.py", "BoundTree.export", "git-config",
     "Disable conversion, symlink and sparse-checkout behavior for native Git checkout-index."),
    ("aegis_core/treeid.py", "_neutralising_flags", "git-config",
     "Construct native Git filter neutralization pairs from observed driver names."),
    ("aegis_core/treeid.py", "_stable_flags", "git-config",
     "Expand the fixed stable native Git configuration settings into option pairs."),
    ("aegis_core/verification/coverage_check.py", "_native_coverage", "reviewed-dynamic",
     "The Go coverage option starts with -c but is native tool data, not Python source."),
    ("aegis_core/verification/language_tests.py", "<module>", "reviewed-dynamic",
     "The native Go test default uses -count=1; the option text starts with the selector prefix."),
    ("aegis_core/verification/regression_commands.py", "run_configured_snapshot", "resolved-python-program",
     "Construct the constant snapshot bootstrap with the unchanged source-pinned option-prefix proof."),
    ("aegis_cli/__main__.py", "<module>", "lexer-or-message",
     "Module documentation describes the python -m aegis_cli entry point."),
    ("aegis_cli/check.py", "CheckCommand.configure_parser", "lexer-or-message",
     "Coverage help text describes Go's native -coverprofile option."),
    ("aegis_cli/hooks/registrar.py", "<module>", "lexer-or-message",
     "Host registration documentation includes the shell -lc launch form."),
    ("aegis_cli/hooks/registrar.py", "_rules_still_used", "lexer-or-message",
     "A scope-specific uninstall diagnostic contains the literal -scope suffix."),
    ("aegis_cli/hooks/safety.py", "<module>", "lexer-or-message",
     "Hook safety command metadata includes the python -m pytest example."),
    ("aegis_cli/package.py", "<module>", "lexer-or-message",
     "CLI documentation describes isolated -c launchers and module-execution risks."),
    ("aegis_cli/pathcheck.py", "build_hint", "lexer-or-message",
     "Render a Python -m pip installation hint."),
    ("aegis_cli/rule.py", "RuleCommand.configure_parser", "lexer-or-message",
     "Parser help explains the -imported suffix for conflicting rule IDs."),
    ("aegis_cli/rule.py", "_run_insight", "lexer-or-message",
     "Render signed Git commit instructions containing -c and -m options."),
    ("aegis_core/ast/batch.py", "BatchDriver._start", "reviewed-dynamic",
     "Start the batch driver with generated platform Popen options."),
    ("aegis_core/ast/gobuild.py", "_build", "native-option",
     "Build the native Go driver with the compiler's -trimpath option."),
    ("aegis_core/ast/gobuild.py", "_run", "reviewed-dynamic",
     "Run the Go driver process with generated platform Popen flags."),
    ("aegis_core/ast/runner.py", "_user_command_plan", "lexer-or-message",
     "Command-plan documentation explains Python -m lookup in neutral directories."),
    ("aegis_core/checkrun.py", "record", "lexer-or-message",
     "The missing-test-command diagnostic includes a Python -m pytest example."),
    ("aegis_core/command_safety/analyzer.py", "evaluate_powershell", "lexer-or-message",
     "Recognize PowerShell -recurse and -force flags in analyzed commands."),
    ("aegis_core/command_safety/guard.py", "_guard_git_alias", "lexer-or-message",
     "Alias-classification documentation describes Git -c overrides."),
    ("aegis_core/command_safety/lexer.py", "_su_command", "lexer-or-message",
     "Document how su handles its -c and command-value options."),
    ("aegis_core/ghcli.py", "default_gh_runner", "reviewed-dynamic",
     "Run the GitHub transport with generated Popen or effect keyword mappings."),
    ("aegis_core/gitsafe.py", "<module>", "lexer-or-message",
     "Module security documentation enumerates native Git -c hardening flags."),
    ("aegis_core/gitsafe_run.py", "capture", "reviewed-dynamic",
     "Launch descriptor-bound Git capture with generated Popen options."),
    ("aegis_core/governance.py", "<module>", "lexer-or-message",
     "Governance documentation includes the Python -m pytest runner example."),
    ("aegis_core/packaging.py", "<module>", "lexer-or-message",
     "Packaging documentation explains the repository import risk of Python -m."),
    ("aegis_core/packaging.py", "_check_mcp", "lexer-or-message",
     "Reject MCP module launchers and explain the isolated -c alternative."),
    ("aegis_core/packaging.py", "build_plugin", "lexer-or-message",
     "Function documentation lists Python -m among rejected package-launcher forms."),
    ("aegis_core/packs.py", "<module>", "lexer-or-message",
     "Rule-conflict metadata uses the -imported identifier suffix."),
    ("aegis_core/skills/slots.py", "<module>", "lexer-or-message",
     "Skill placeholder defaults include Python -m pytest and build commands."),
    ("aegis_core/testexec.py", "<module>", "resolved-python-program",
     "Document and declare the default Python -m pytest test command."),
    ("aegis_core/testexec.py", "plan_command", "reviewed-dynamic",
     "Normalize user-scope Python and pytest commands to interpreter/module argv."),
    ("aegis_core/testexec.py", "run_tests", "reviewed-dynamic",
     "Run test argv with generated process-group and platform keyword options."),
    ("aegis_core/testplans.py", "language_environment", "native-option",
     "Set the native Go -mod=readonly policy in generated environments."),
    ("aegis_core/treeid.py", "_filter_drivers", "lexer-or-message",
     "The filter-driver refusal message explains values Git -c cannot carry."),
    ("aegis_core/unittest_runner.py", "main", "lexer-or-message",
     "Supply the descriptive Python -m unittest argv label to unittest.main."),
    ("aegis_core/verification/coverage_check.py", "_python_coverage", "reviewed-dynamic",
     "Build coverage and pytest module commands from the prepared interpreter and argument tail."),
    ("aegis_core/verification/mutation_tester.py", "_check_tests", "reviewed-dynamic",
     "Launch mutation tests with the computed Popen keyword mapping."),
    ("aegis_core/verification/perf_check.py", "<module>", "resolved-python-program",
     "Declare the fixed pytest module argv for the benchmark runner."),
    ("aegis_core/verification/snapshot_tests.py", "run_snapshot_tests", "lexer-or-message",
     "Build per-language scratch names using the literal -selection suffix."),
    ("aegis_core/verification/test_runner.py", "resolve_pytest_cmd", "resolved-python-program",
     "Construct pytest argv including the sys.executable -m pytest fallback."),
    ("aegis_core/verification/test_runner.py", "run_external_cmd", "reviewed-dynamic",
     "Launch normalized external test argv with forwarded Popen keyword options."),
    ("aegis_mcp/queue_owner.py", "<module>", "lexer-or-message",
     "Module documentation describes the owner-launched Python -m queue MCP command."),
    ("aegis_core/rule_lint.py", "_canonical_head", "lexer-or-message",
     "Report-only rule lint command-example lexer; recognize Python -m, never execute it."),
    ("aegis_core/ast/batch.py", "BatchDriver._terminate_group", "reviewed-dynamic",
     "The Popen type annotation shares a scope with positional process-group cleanup calls."),
    ("aegis_core/benchmark.py", "run_benchmark", "reviewed-dynamic",
     "Forward the default subprocess runner to benchmark helpers using positional arguments."),
    ("aegis_core/team_supervisor_start.py", "_spawn", "reviewed-dynamic",
     "Launch the configured supervisor process and perform startup identity and timeout checks."),
    ("aegis_core/testexec.py", "kill_group", "reviewed-dynamic",
     "Run Windows taskkill directly; positional process-group termination shares the scope."),
    ("aegis_core/verification/test_runner.py", "discover_test_evidence", "reviewed-dynamic",
     "Execute discovered test files with subprocess.run after path and AST discovery."),
    ("aegis_cli/doctor.py", "_probe_claude", "lexer-or-message",
     "Forward observed Claude registration facts as structured report metadata."),
    ("aegis_cli/doctor.py", "_probe_codex", "lexer-or-message",
     "Forward observed Codex registration facts as structured report metadata."),
    ("aegis_cli/doctor.py", "_probe_json_host", "lexer-or-message",
     "Forward JSON-host registration facts as structured report metadata."),
    ("aegis_cli/hooks/registrar.py", "hook_file", "lexer-or-message",
     "Expand the host hook path components while constructing its registration path."),
    ("aegis_core/ghcli.py", "resolve_repo", "reviewed-dynamic",
     "Forward Git transport options while reading the origin URL for repository resolution."),
    ("aegis_core/gitsafe.py", "RefConflict.__init__", "lexer-or-message",
     "Forward structured ref-conflict fields and error metadata to GitError."),
    ("aegis_core/gitsafe.py", "_completed", "reviewed-dynamic",
     "Forward completed-command options to the reviewed Git transport runner."),
    ("aegis_core/gitsafe.py", "_out", "reviewed-dynamic",
     "Forward output-capture options through the Git completed-command wrapper."),
    ("aegis_core/gitsafe.py", "_safe_export_target", "lexer-or-message",
     "Expand path components when checking the destination of a Git tree export."),
    ("aegis_core/gitsafe.py", "_text", "reviewed-dynamic",
     "Forward text-output options through the Git output wrapper."),
    ("aegis_core/gitsafe.py", "_tree_entry", "lexer-or-message",
     "Unpack decoded Git ls-tree metadata into its entry record."),
    ("aegis_core/gitsafe.py", "git_executable", "lexer-or-message",
     "Forward executable lookup settings to the native Git path resolver."),
    ("aegis_core/gitsafe_run.py", "LaneRunner.run_checked", "reviewed-dynamic",
     "Forward checked lane options through the bound run method."),
    ("aegis_core/gitsafe_run.py", "completed", "reviewed-dynamic",
     "Forward command options and the injected runner for completed Git results."),
    ("aegis_core/gitsafe_run.py", "output", "reviewed-dynamic",
     "Forward command options through the completed Git result callback."),
    ("aegis_core/gitsafe_run.py", "text", "reviewed-dynamic",
     "Forward command options through the Git output callback before decoding text."),
)
SELECTOR_KINDS = frozenset({"git-config", "resolved-python-program", "shell-script",
                            "lexer-or-message", "native-option", "reviewed-dynamic"})
BROAD_SELECTOR_PATTERN = re.compile(r"""(?:^|[\s'"=])-[A-Za-z]*[cm][^\s'"]*""")
SELECTOR_WORD_PATTERN = re.compile(r"\S+")

# Coordinator compatibility ruling, 2026-11-15: only this reviewed validator,
# path rebasing and caller prove that the dynamic slice contains options, not code.
# Hash the exact function source (UTF-8, universal newlines, no trailing newline).
OPTION_PREFIX_PINS = {
    ("aegis_core/testexec.py", "python_module_index"): (
        "0de65206435fe87378510c7486acff9703822f86e286b2ec650318638f5050a3",
        "The closed option grammar stops at code, scripts, stdin and unknown flags before accepting -m."),
    ("aegis_core/testplans.py", "rebase_snapshot_arguments"): (
        "fddac660d4e26088480767049daf5da4d9fd52dc42721d3816521f19d3b418fb",
        "Rebasing preserves option words and sequence length; it changes only absolute path values."),
    ("aegis_core/verification/regression_commands.py", "run_configured_snapshot"): (
        "27aea26dd61e3e9e6e9299c9efe75e405cd7fd826bb17378936faba79e1bfe8f",
        "The checked logical slice precedes the constant -c bootstrap after fixed -I -S -B options."),
}
OPTION_PREFIX_CALLER = ("aegis_core/verification/regression_commands.py", "run_configured_snapshot")


def checked_prefix_function(modules, key, pins):
    rel, function = key
    tree = modules.get(rel)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function] if tree else []
    source = getattr(tree, "census_source", None)
    text = ast.get_source_segment(source, nodes[0]) if source is not None and len(nodes) == 1 else None
    if (text is None or nodes[0].decorator_list
            or hashlib.sha256(text.encode("utf-8")).hexdigest() != pins[key][0]):
        raise ValueError("process census: re-review pinned function " + rel + "::" + function)
    return nodes[0]


def test_process_census_matches_reviewed_sites():
    record = json.loads(RECORD.read_text())
    assert census_errors(process_sites(REPO), record) == []
    assert sum(v["count"] for k, v in record.items() if k.startswith("typeerror:")) <= 18
    assert sum(v["count"] for k, v in record.items() if k.startswith("envelope:")) <= 2
    assert all(v["reason"].strip() for v in record.values())


def test_census_detects_aliases_duplicate_calls_and_relocation(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("from subprocess import run as spawn\ndef one():\n    spawn(['tool'])\n", encoding="utf-8")
    sites = process_sites(tmp_path)
    key = "process:aegis_core/probe.py:one:subprocess.run"
    assert sites == {key: [3]}
    record = {key: {"count": 1, "reason": "test boundary"}}
    path.write_text(path.read_text() + "    spawn(['more'])\n", encoding="utf-8")
    assert "1 -> 2" in census_errors(process_sites(tmp_path), record)[0]
    path.write_text("import subprocess as sp\ndef two():\n    sp.run(['tool'])\n", encoding="utf-8")
    assert any("unreviewed" in e and ":two:" in e for e in census_errors(process_sites(tmp_path), record))
    with pytest.raises(ValueError, match="refusing to raise"):
        lowered_census(record, process_sites(tmp_path))
    assert lowered_census(record, {}) == {}


def test_census_covers_conversion_lookup_envelope_and_bad_python(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("from shutil import which as locate\ndef f():\n    locate('thing')\n    try: int(None)\n    except (ValueError, TypeError): pass\n    return {'aegis_version': 1, 'checked_at': 2}\n", encoding="utf-8")
    keys = process_sites(tmp_path)
    assert set(k.split(':')[0] for k in keys) == {"lookup", "typeerror", "envelope"}
    path.write_text("def f(\n", encoding="utf-8")
    with pytest.raises(SyntaxError) as err:
        process_sites(tmp_path)
    assert err.value.filename == "aegis_core/probe.py"


def module_trees(root):
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=rel)
            tree.census_source = source
            yield rel, tree


def import_bindings(node, rel):
    """The bindings introduced by this import, independent of sibling scopes."""
    if isinstance(node, ast.Import):
        return {a.asname or a.name.split(".")[0]: a.name if a.asname else a.name.split(".")[0]
                for a in node.names}
    if isinstance(node, ast.ImportFrom):
        base = node.module or ""
        if node.level:
            package = rel.removesuffix(".py").replace("/", ".").split(".")[:-1]
            base = ".".join(package[:len(package) - node.level + 1] + ([base] if base else []))
        bindings = {a.asname or a.name: base + "." + a.name for a in node.names if a.name != "*"}
        if node.level == 0 and base in {"os", "subprocess"} and any(a.name == "*" for a in node.names):
            bindings.update((name.split(".")[1], name) for name in RAW if name.startswith(base + "."))
        return bindings
    return {}


class _AliasScope:
    def __init__(self, parent=None, kind="module", *, comprehension=False):
        self.parent = parent
        self.kind = kind
        self.comprehension = comprehension
        self.imports = {}
        self.bound = set()
        self.globals = set()
        self.nonlocals = set()

    def resolve(self, name):
        # A scope may import different things along different branches. Keep every
        # possible import there; never let another scope's last import overwrite it.
        if name in self.imports:
            return self.imports[name]
        if name in self.globals and self.parent is not None:
            root = self.parent
            while root.parent is not None:
                root = root.parent
            return root.resolve(name)
        if name in self.nonlocals and self.parent is not None:
            return self.parent.resolve(name)
        if name in self.bound:
            return set()
        return self.parent.resolve(name) if self.parent is not None else set()


def _lexical_parent(scope):
    # Methods, nested classes and comprehensions do not close over class locals.
    while scope.kind == "class":
        scope = scope.parent
    return scope


class ScopedNames:
    """Resolve import aliases lexically, not by a file-wide last assignment.

    This is not control-flow analysis: imports in alternative branches of one
    scope remain plausible. Parameters and local bindings shadow outer imports;
    defaults/decorators are evaluated in the enclosing scope. Assignment aliases
    and dynamic imports are outside this static resolver.
    """
    def __init__(self, tree, rel, *, runtime_only=False):
        self.rel = rel
        self.at = {}
        self.allowed = None
        if runtime_only:
            from tests.contract.test_import_boundary import import_nodes
            self.allowed = {id(n) for n in import_nodes(tree)}
        self._index(tree, _AliasScope())

    def _arguments(self, args, outer, inner):
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg):
            if arg is not None:
                inner.bound.add(arg.arg)
                self.at[id(arg)] = inner
                if arg.annotation is not None:
                    self._index(arg.annotation, outer)
        for value in (*args.defaults, *args.kw_defaults):
            if value is not None:
                self._index(value, outer)

    def _index(self, node, scope):
        if self.allowed is not None and id(node) not in self.allowed:
            return
        self.at[id(node)] = scope
        if isinstance(node, ast.NamedExpr):
            owner = scope
            while owner.comprehension:
                owner = owner.parent
            self._index(node.target, owner)
            self._index(node.value, scope)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                scope.bound.add(node.name)
                for value in node.decorator_list:
                    self._index(value, scope)
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            inner = _AliasScope(_lexical_parent(scope), kind)
            if isinstance(node, ast.ClassDef):
                for value in (*node.bases, *node.keywords):
                    self._index(value, scope)
            else:
                self._arguments(node.args, scope, inner)
                if getattr(node, "returns", None) is not None:
                    self._index(node.returns, scope)
            for value in [node.body] if isinstance(node, ast.Lambda) else node.body:
                self._index(value, inner)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            inner = _AliasScope(_lexical_parent(scope), "function", comprehension=True)
            for index, generator in enumerate(node.generators):
                self._index(generator.iter, scope if index == 0 else inner)
                self._index(generator.target, inner)
                for condition in generator.ifs:
                    self._index(condition, inner)
            for value in (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,):
                self._index(value, inner)
            return
        for local, target in import_bindings(node, self.rel).items():
            scope.bound.add(local)
            scope.imports.setdefault(local, set()).add(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            scope.bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope.bound.add(node.name)
        elif isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        for child in ast.iter_child_nodes(node):
            self._index(child, scope)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            scope = self.at.get(id(node))
            return scope.resolve(node.id) if scope is not None else set()
        if isinstance(node, ast.Attribute):
            return {base + "." + node.attr for base in self.resolve(node.value)}
        return set()


def binding_scope(scope, name):
    if name in scope.globals:
        while scope.parent is not None:
            scope = scope.parent
    elif name in scope.nonlocals:
        scope = scope.parent
        while scope.parent is not None and name not in scope.bound:
            scope = scope.parent
    return scope


def mutable_call_inputs(node, names, bindings, namespaces):
    """Unproven helpers may mutate receivers/arguments; OS launch APIs do not."""
    resolved = names.resolve(node.func)
    if resolved and resolved <= RAW | {"shlex.quote", "pathlib.Path.cwd", "pathlib.Path.home"}:
        return ()
    if isinstance(node.func, ast.Name) and node.func.id in {
            "str", "int", "float", "bytes", "repr", "ascii", "len", "hash", "bool",
            "list", "tuple", "dict", "set", "frozenset", "print", "isinstance", "issubclass",
            "range", "enumerate", "zip", "reversed", "sorted", "any", "all", "sum", "min", "max",
            "getattr", "hasattr"}:
        scope = names.at[id(node.func)]
        while scope is not None and node.func.id not in scope.bound:
            scope = scope.parent
        if scope is None:
            return ()
    receiver = (node.func.value,) if isinstance(node.func, ast.Attribute) else ()
    if receiver:
        symbols = names.resolve(receiver[0])
        if symbols and symbols <= namespaces:
            receiver = ()  # A module function call has no bound mutable receiver.
    if receiver and node.func.attr in {"copy", "count", "index", "get", "keys", "values", "items"}:
        value = receiver[0]
        if isinstance(value, ast.Name):
            scope = names.at[id(value)]
            while scope.parent is not None and value.id not in scope.bound:
                scope = scope.parent
            initializers = bindings.get((binding_scope(scope, value.id), value.id), ())
            if initializers and all(isinstance(n, (ast.List, ast.Tuple, ast.Dict, ast.Set, ast.Constant)) for n in initializers):
                return ()
    return (*receiver, *node.args, *(keyword.value for keyword in node.keywords))


def alias_inputs(node):
    """Object aliases, not scalar inputs to a constructor or copied star expansion."""
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        yield node
        if isinstance(node, ast.Subscript):
            yield from alias_inputs(node.value)
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for item in node.elts:
            if not isinstance(item, ast.Starred):
                yield from alias_inputs(item)
    elif isinstance(node, ast.Dict):
        for item in (*node.keys, *node.values):
            yield from alias_inputs(item)
    elif isinstance(node, ast.IfExp):
        yield from alias_inputs(node.body)
        yield from alias_inputs(node.orelse)
    elif isinstance(node, ast.BinOp):
        yield from alias_inputs(node.left)
        yield from alias_inputs(node.right)


def literal_bindings(tree, rel, namespaces=frozenset(), modules=None):
    """Keep alternatives, but never trust an initializer after an unsupported write."""
    names, bindings = ScopedNames(tree, rel), {}
    changed, aliases, exports, export_aliases = set(), [], set(), []
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def key(target):
        scope = names.at[id(target)]
        if isinstance(target.ctx, ast.Load):
            while scope.parent is not None and target.id not in scope.bound:
                scope = scope.parent
        return binding_scope(scope, target.id), target.id

    def immutable_value(value):
        return (isinstance(value, (ast.Constant, ast.JoinedStr)) or isinstance(value, ast.Call)
                and captured_module(value, names, rel, modules or {}) is not None)

    def invalidate(target, *, mutation=False):
        if isinstance(target, ast.Name):
            values = bindings.get(key(target), ())
            if mutation and values and all(immutable_value(value) for value in values):
                return  # Passing an immutable literal cannot mutate its binding.
            changed.add(key(target))
        elif isinstance(target, ast.Subscript):
            invalidate(target.value, mutation=mutation)
        elif isinstance(target, ast.Attribute):
            if mutation and names.resolve(target) <= {"os.devnull", "sys.executable"} and names.resolve(target):
                return  # Passing an immutable value cannot replace the module attribute.
            exports.update(names.resolve(target))
        elif isinstance(target, (ast.List, ast.Tuple, ast.Set)):
            for item in target.elts:
                invalidate(item, mutation=mutation)
        elif isinstance(target, ast.Dict):
            for item in (*target.keys, *target.values):
                invalidate(item, mutation=mutation)
        elif isinstance(target, ast.Starred):
            invalidate(target.value, mutation=mutation)

    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            bindings.setdefault((names.at[id(node)], node.arg), []).append(None)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            if isinstance(node.target, ast.Name):
                bindings.setdefault(key(node.target), []).append(node)
            else:
                invalidate(node.target)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if not isinstance(parents[id(node)], (ast.Assign, ast.AnnAssign, ast.For, ast.comprehension)):
                invalidate(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)):
            if node.name:
                changed.add((binding_scope(names.at[id(node)], node.name), node.name))
        elif type(node).__name__ in {"MatchAs", "MatchStar", "MatchMapping"}:
            name = getattr(node, "name", None) or getattr(node, "rest", None)
            if name:
                scope = names.at[id(node)]
                scope.bound.add(name)
                changed.add((binding_scope(scope, name), name))
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else [])
        shared = [key(target) for target in targets if isinstance(target, ast.Name)]
        aliases.extend((shared[0], other) for other in shared[1:])
        for target in targets:
            if isinstance(target, ast.Name) and node.value is not None:
                bindings.setdefault(key(target), []).append(node.value)
                for dependency in alias_inputs(node.value):
                    if isinstance(dependency, ast.Attribute):
                        export_aliases.extend((key(target), name) for name in names.resolve(dependency)
                                              if name not in {"sys.executable", "os.devnull"})
                    if not isinstance(dependency, ast.Name) or not isinstance(dependency.ctx, ast.Load):
                        continue
                    source = names.at[id(dependency)]
                    while source.parent is not None and dependency.id not in source.bound:
                        source = source.parent
                    aliases.append((key(target), (binding_scope(source, dependency.id), dependency.id)))
            else:
                invalidate(target)
        if isinstance(node, (ast.AugAssign, ast.NamedExpr)):
            changed.add(key(node.target)) if isinstance(node.target, ast.Name) else invalidate(node.target)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                invalidate(target)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for target in mutable_call_inputs(node, names, bindings, namespaces):
                invalidate(target, mutation=True)
    immutable = {key for key, values in bindings.items() if values and all(immutable_value(value) for value in values)}
    aliases = [(left, right) for left, right in aliases if left not in immutable and right not in immutable]
    while True:
        expanded = changed | {other for a, b in aliases if a in changed or b in changed for other in (a, b)}
        if expanded == changed:
            break
        changed = expanded
    for scope, name in changed:
        bindings.setdefault((scope, name), []).append(None)
        exports.update(scope.imports.get(name, ()))
    exports.update(name for key, name in export_aliases if key in changed)
    return names, bindings, exports


def captured_module(node, names, rel, modules):
    """Prove an import-time UTF-8 read of a co-located, censused module."""
    scope = names.at[id(node)]
    if scope.kind != "module" or "__file__" in scope.bound:
        return None
    if (not isinstance(node, ast.Call) or node.args or not isinstance(node.func, ast.Attribute)
            or node.func.attr != "read_text" or len(node.keywords) != 1):
        return None
    encoding = node.keywords[0]
    if encoding.arg != "encoding" or not isinstance(encoding.value, ast.Constant) or encoding.value.value != "utf-8":
        return None
    anchor = node.func.value
    if (not isinstance(anchor, ast.Call) or not isinstance(anchor.func, ast.Attribute)
            or anchor.func.attr != "with_name" or len(anchor.args) != 1 or anchor.keywords):
        return None
    filename, path = anchor.args[0], anchor.func.value
    if (not isinstance(filename, ast.Constant) or not isinstance(filename.value, str)
            or not filename.value.endswith(".py") or not filename.value[:-3].isidentifier()):
        return None
    if (not isinstance(path, ast.Call) or names.resolve(path.func) != {"pathlib.Path"}
            or len(path.args) != 1 or path.keywords or not isinstance(path.args[0], ast.Name)
            or path.args[0].id != "__file__"):
        return None
    target = str(Path(rel).with_name(filename.value)).replace("\\", "/")
    return ("captured-module", target) if target in modules else None


_Argv = namedtuple("_Argv", "kind items")
_Shell = namedtuple("_Shell", "text holes hidden")
_Quoted = namedtuple("_Quoted", "value")
_Launch = namedtuple("_Launch", "executable argv shell")
_SPLICE, _PYTHON, _OPTION_PREFIX, _USE_HEAD = object(), object(), object(), object()
_MAX_CHOICES, _MAX_WORDS, _MAX_TEXT = 64, 4096, 1048576
_MAX_DEPTH = 64


def append_shell_piece(parts, piece, budget):
    if len(piece) > budget[0]:
        raise ValueError("shell text limit")
    budget[0] -= len(piece)
    parts.append(piece)


def python_word(word):
    if not isinstance(word, str):
        return False
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    if name in {"py", "pyw"}:
        return True
    for prefix in ("pythonw", "python", "pypy"):
        if name.startswith(prefix):
            suffix = name[len(prefix):]
            return not suffix or all(part.isdecimal() for part in suffix.split("."))
    return False


def selector_constant(value):
    if len(value) > _MAX_TEXT:
        raise ValueError("selector text limit")
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    if "-" not in value or not ("c" in value or "m" in value):
        return False
    for index, _ in enumerate(SELECTOR_WORD_PATTERN.finditer(value)):
        if index >= _MAX_WORDS:
            raise ValueError("selector word limit")
    return BROAD_SELECTOR_PATTERN.search(value) is not None


def qualified_nodes(node, scope="<module>", *, include_signature=False):
    """Attribute constants to their nearest named body, not every ancestor."""
    yield node, scope
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        inner = node.name if scope == "<module>" else scope + "." + node.name
        for field, value in ast.iter_fields(node):
            children = value if isinstance(value, list) else (value,)
            for child in children:
                if isinstance(child, ast.AST):
                    yield from qualified_nodes(child, inner if field == "body" or include_signature else scope,
                                               include_signature=include_signature)
    else:
        for child in ast.iter_child_nodes(node):
            yield from qualified_nodes(child, scope, include_signature=include_signature)


def selector_executable_override(node):
    # The coordinator's probe includes transport wrappers and environment
    # constructors. Review the keyword syntax without trusting callee resolution.
    if not isinstance(node, ast.Call):
        return False
    for keyword in node.keywords:
        if keyword.arg != "executable":
            continue
        value = keyword.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
            if len(value.value) > _MAX_TEXT:
                raise ValueError("selector text limit")
            if not python_word(value.value) and not shell_word(value.value):
                continue
        return True
    return False


def selector_argv_items(node, depth=0):
    """Flatten syntax only: unresolved operands remain opaque AST elements."""
    if depth >= _MAX_DEPTH:
        raise ValueError("selector depth limit")
    if isinstance(node, (ast.List, ast.Tuple)):
        yield from node.elts
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        yield from selector_argv_items(node.left, depth + 1)
        yield from selector_argv_items(node.right, depth + 1)
    else:
        yield node


def selector_module_argv(node):
    if not isinstance(node, (ast.List, ast.Tuple)):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
            return False
        if not any(isinstance(child, (ast.List, ast.Tuple)) for child in ast.walk(node)):
            return False  # String concatenation alone is not an argv construction.
    following_selector = False
    for index, item in enumerate(selector_argv_items(node)):
        if index >= _MAX_WORDS:
            raise ValueError("selector word limit")
        if following_selector:
            if not isinstance(item, ast.Constant):
                return True
            if isinstance(item.value, str):
                if len(item.value) > _MAX_TEXT:
                    raise ValueError("selector text limit")
                if item.value.partition(".")[0] in {"aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk", "tools"}:
                    return True
        following_selector = isinstance(item, ast.Constant) and item.value == "-m"
    return False


def selector_expanded_spawn(node, names):
    if (isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in {"os", "subprocess"}
            and any(alias.name == "*" for alias in node.names)):
        return True
    if not isinstance(node, ast.Call):
        return False
    apis = names.resolve(node.func) & RAW
    if not apis:
        return False
    return (any(isinstance(arg, ast.Starred) for arg in node.args)
            or any(keyword.arg is None for keyword in node.keywords)
            or apis & POPEN_POSITIONAL_APIS and len(node.args) > 1)


def selector_sites(modules):
    found = {}
    for rel, tree in modules.items():
        if not rel.startswith(("aegis_core/", "aegis_cli/", "aegis_mcp/")):
            continue
        names = ScopedNames(tree, rel)
        references, expanded, positional = set(), {}, {}
        module_reference = False
        # Clause B is module-wide for expanded calls; callable alias analysis
        # is deliberately unnecessary. Keep the prior same-scope positional
        # rule as well. Defaults/decorators participate in their function.
        for node, scope in qualified_nodes(tree, include_signature=True):
            imported = set(import_bindings(node, rel).values()) & RAW
            if names.resolve(node) & RAW or imported:
                references.add(scope)
                module_reference = True
            if isinstance(node, ast.Call) and (any(isinstance(arg, ast.Starred) for arg in node.args)
                                              or any(keyword.arg is None for keyword in node.keywords)):
                expanded.setdefault(scope, []).append(node.lineno)
            if isinstance(node, ast.Call) and len(node.args) > 1:
                positional.setdefault(scope, []).append(node.lineno)
        if module_reference:
            for scope, lines in expanded.items():
                found.setdefault((rel, scope), []).extend(lines)
        for scope in references & positional.keys():
            found.setdefault((rel, scope), []).extend(positional[scope])
        for node, scope in qualified_nodes(tree, include_signature=True):
            try:
                if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                    selected = selector_constant(node.value)
                else:
                    selected = (selector_expanded_spawn(node, names)
                                or selector_executable_override(node) or selector_module_argv(node))
            except ValueError:
                raise ValueError("selector site limit " + rel + ":" + scope) from None
            if selected:
                found.setdefault((rel, scope), []).append(node.lineno)
    return dict(sorted(found.items()))


def selector_site_errors(current, table):
    reviewed, errors = set(), []
    for rel, scope, kind, reason in table:
        key = rel, scope
        if kind not in SELECTOR_KINDS or not reason.strip() or "\n" in reason or "\r" in reason:
            errors.append("invalid selector row " + rel + ":" + scope)
        if key in reviewed:
            errors.append("duplicate selector site " + rel + ":" + scope)
        reviewed.add(key)
    errors.extend("unreviewed selector site " + rel + ":" + scope for rel, scope in sorted(current.keys() - reviewed))
    errors.extend("stale selector site " + rel + ":" + scope for rel, scope in sorted(reviewed - current.keys()))
    return errors


def python_selector(word):
    """One interpreter-option parser for separate, bundled and attached code."""
    if not isinstance(word, str):
        return "unknown", None
    if word in ("-", "--"):
        return "stop", None
    if word == "--check-hash-based-pycs":
        return "value", None
    if word.startswith("--check-hash-based-pycs="):
        return "option", None
    if not word.startswith("-"):
        return "stop", None
    for position, flag in enumerate(word[1:], 2):
        if flag == "c":
            return "code", word[position:] or None
        if flag == "m":
            return "module", word[position:] or None
        if flag in "WX":
            return ("option" if word[position:] else "value"), None
        if flag not in "bBdEhiIOPqRsSuvVx":
            return "unknown", None
    return "option", None


def selector_hint(text):
    return any(python_selector(word.strip("'\";,()"))[0] in {"code", "module"} for word in text.split())


def value_selector_hint(value):
    text = value.text if isinstance(value, _Shell) else value
    return python_selector(text)[0] in {"code", "module"}


def api_arguments(node, api):
    """Return executable AST, argv AST/variadic tuple, and shell mode by API."""
    if (len(node.args) + len(node.keywords) > _MAX_WORDS
            or any(isinstance(arg, ast.Starred) for arg in node.args)
            or any(keyword.arg is None for keyword in node.keywords)):
        return None
    keywords = {keyword.arg: keyword.value for keyword in node.keywords}
    if len(keywords) != len(node.keywords):
        return None
    shell_apis = {"os.system": "command", "os.popen": "cmd",
                  "subprocess.getoutput": "cmd", "subprocess.getstatusoutput": "cmd"}
    if api in shell_apis:
        key = shell_apis[api]
        if node.args and key in keywords:
            return None
        command = node.args[0] if node.args else keywords.get(key)
        return (None, command, True) if command is not None else None
    if api.startswith("subprocess."):
        if node.args and "args" in keywords or len(node.args) > 2 and "executable" in keywords:
            return None
        command = node.args[0] if node.args else keywords.get("args")
        executable = node.args[2] if len(node.args) > 2 else keywords.get("executable")
        shell = node.args[8] if len(node.args) > 8 else keywords.get("shell")
        if shell is not None and (not isinstance(shell, ast.Constant) or type(shell.value) is not bool):
            return None
        return (executable, command, shell.value if shell is not None else False) if command is not None else None
    offset = 1 if api.startswith("os.spawn") else 0
    if len(node.args) <= offset + 1:
        return None
    executable = node.args[offset]
    suffix = api.rsplit(".", 1)[1]
    if suffix.startswith(("execl", "spawnl")):
        end = -1 if suffix.endswith("e") else len(node.args)
        vector = tuple(node.args[offset + 1:end])
        return (executable, vector, False) if vector else None
    return executable, node.args[offset + 1], False


def shell_word(word):
    if not isinstance(word, str):
        return False
    return word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe") in {
        "sh", "bash", "dash", "ash", "ksh", "zsh", "cmd", "powershell", "pwsh"}


class CommandResolver:
    """Resolve whole command constructions; uncertainty never becomes an initializer.

    Names keep lexical alternatives. Augmented assignments, mutations, unsupported
    writes and cycles contribute an unknown alternative. Shell interpolation is
    rendered as a complete command with typed placeholders for unresolved fields.
    Namespace obfuscation remains outside ScopedNames' honest-author threat model.
    """
    def __init__(self, modules, *, option_pins=None, package_context=None):
        self.modules = modules if package_context is None else {**package_context.modules, **modules}
        namespaces = {rel.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".") for rel in modules}
        namespaces.update(target for rel, tree in modules.items() for node in ast.walk(tree)
                          if isinstance(node, ast.Import) for target in import_bindings(node, rel).values())
        namespaces.add("os.path")
        if package_context is not None:
            namespaces.update(package_context.namespaces)
        self.namespaces = namespaces
        # Package ASTs and their bindings are unchanged. Analyze only the new
        # literal tree, keeping original modules available for its imports.
        self.contexts = {} if package_context is None else dict(package_context.contexts)
        self.contexts.update({rel: literal_bindings(tree, rel, namespaces, self.modules) for rel, tree in modules.items()})
        self.changed_exports = {name for _, _, changes in self.contexts.values() for name in changes}
        pins = OPTION_PREFIX_PINS if option_pins is None else option_pins
        self.option_functions = ({key: checked_prefix_function(modules, key, pins) for key in pins}
                                 if OPTION_PREFIX_CALLER[0] in modules else {})

    def export_changed(self, qualified):
        return any(qualified == name or qualified.startswith(name + ".") or name.startswith(qualified + ".")
                   for name in self.changed_exports)

    def option_prefix(self, node, origin):
        if origin != OPTION_PREFIX_CALLER[0] or not self.option_functions:
            return False
        names, bindings, _ = self.contexts[origin]
        caller = self.option_functions[OPTION_PREFIX_CALLER]
        scope = names.at[id(node)]
        expression = ast.parse(
            "rebase_snapshot_arguments(logical[1:1 + module], workspace, snapshot) if module >= 0 else []",
            mode="eval").body
        if scope is not names.at[id(caller.body[0])] or ast.dump(node) != ast.dump(expression):
            return False
        initializers = bindings.get((scope, "module"), ())
        expected = ast.parse("testexec.python_module_index(logical[1:])", mode="eval").body
        if len(initializers) != 1 or initializers[0] is None or ast.dump(initializers[0]) != ast.dump(expected):
            return False
        rebase, validator = "aegis_core.testplans.rebase_snapshot_arguments", "aegis_core.testexec.python_module_index"
        return (names.resolve(node.body.func) == {rebase} and names.resolve(initializers[0].func) == {validator}
                and not any(self.export_changed(name) for name in (rebase, validator)))

    def text(self, value):
        if isinstance(value, str):
            return value
        if isinstance(value, _Quoted) and isinstance(value.value, str):
            if len(value.value) > (_MAX_TEXT - 2) // 5:
                return None
            return shlex.quote(value.value)
        return None

    def imported(self, qualified, seen):
        if qualified in seen or self.export_changed(qualified) or len(seen) >= _MAX_DEPTH:
            return {None}
        seen = seen | {qualified}
        base, _, attribute = qualified.rpartition(".")
        origin = base.replace(".", "/") + ".py"
        if origin not in self.modules:
            origin = base.replace(".", "/") + "/__init__.py"
        if origin not in self.modules:
            return {None}
        names, bindings, _ = self.contexts[origin]
        scope = names.at[id(self.modules[origin])]
        result = {v for node in bindings.get((scope, attribute), ()) for v in self.values(node, origin, seen)}
        return (result | {v for name in scope.imports.get(attribute, ()) for v in self.imported(name, seen)}) or {None}

    def named(self, node, origin, seen):
        names, bindings, _ = self.contexts[origin]
        result = {v for name in names.resolve(node) for v in self.imported(name, seen)}
        if isinstance(node, ast.Name):
            scope = names.at[id(node)]
            while scope is not None:
                if node.id in scope.globals or node.id in scope.nonlocals:
                    scope = binding_scope(scope, node.id)
                qualified = origin.removesuffix("/__init__.py").removesuffix(".py").replace("/", ".") + "." + node.id
                if scope.kind == "module" and self.export_changed(qualified):
                    return {None}
                values = bindings.get((scope, node.id), ())
                if values or node.id in scope.bound:
                    return (result | {v for item in values for v in self.values(item, origin, seen)}) or {None}
                scope = scope.parent
        return result or {None}

    def sequence(self, node, origin, seen):
        if len(node.elts) > _MAX_WORDS:
            return {None}
        states = {()}
        for item in node.elts:
            starred = isinstance(item, ast.Starred)
            choices = self.values(item.value if starred else item, origin, seen)
            pieces = {v.items if starred and isinstance(v, _Argv) else (
                (_OPTION_PREFIX,) if starred and v is _OPTION_PREFIX else ((_SPLICE,) if starred else (v,))) for v in choices}
            if len(states) * len(pieces) > _MAX_CHOICES:
                return {None}
            if any(len(a) + len(b) > _MAX_WORDS for a in states for b in pieces):
                return {None}
            states = {a + b for a in states for b in pieces}
        return {_Argv("list" if isinstance(node, ast.List) else "tuple", state) for state in states}

    def concatenate(self, node, origin, seen):
        left, right = self.values(node.left, origin, seen), self.values(node.right, origin, seen)
        if len(left) * len(right) > _MAX_CHOICES:
            return {None}
        result = set()
        for a in left:
            for b in right:
                x, y = self.text(a), self.text(b)
                if x is not None and y is not None and len(x) + len(y) <= _MAX_TEXT:
                    result.add(x + y)
                elif isinstance(a, _Argv) and isinstance(b, _Argv) and a.kind == b.kind and len(a.items) + len(b.items) <= _MAX_WORDS:
                    result.add(_Argv(a.kind, a.items + b.items))
                elif not isinstance(a, _Argv) and not isinstance(b, _Argv):
                    parts = []
                    for position, value in enumerate((a, b)):
                        text = self.text(value)
                        if text is not None:
                            parts.append(_Shell(text, frozenset(), False))
                        elif isinstance(value, _Shell):
                            parts.append(value)
                        else:
                            token = "__AEGIS_CENSUS_CONCAT_" + str(id(node)) + "_" + str(position) + "__"
                            parts.append(_Shell(token, frozenset({(token, not isinstance(value, _Quoted))}), False))
                    if len(parts[0].text) + len(parts[1].text) > _MAX_TEXT:
                        result.add(None)
                    else:
                        result.add(_Shell(parts[0].text + parts[1].text, parts[0].holes | parts[1].holes,
                                          parts[0].hidden or parts[1].hidden))
                else:
                    result.add(None)
        return result

    def interpolation(self, node, origin, seen):
        states = {("", frozenset(), False)}
        for part in node.values:
            if isinstance(part, ast.Constant):
                choices = {(part.value, None, False)}
            else:
                choices = set()
                for value in self.values(part.value, origin, seen):
                    text = self.text(value)
                    if part.format_spec is not None or part.conversion not in (-1, 115, 114, 97):
                        text = None
                    elif text is not None and part.conversion in (114, 97):
                        text = (repr(text) if part.conversion == 114 else ascii(text)) if len(text) <= (_MAX_TEXT - 2) // 10 else None
                    hidden = isinstance(value, _Shell) and (value.hidden or selector_hint(value.text))
                    if text is None:
                        token = "__AEGIS_CENSUS_FIELD_" + str(id(part)) + "__"
                        choices.add((token, (token, not isinstance(value, _Quoted)), hidden))
                    else:
                        choices.add((text, None, hidden))
            if len(states) * len(choices) > _MAX_CHOICES:
                return {None}
            if any(len(a) + len(b) > _MAX_TEXT for a, _, _ in states for b, _, _ in choices):
                return {None}
            states = {(a + b, holes | ({hole} if hole else set()), hidden or extra)
                      for a, holes, hidden in states for b, hole, extra in choices}
        return {_Shell(text, holes, hidden) if holes or hidden else text for text, holes, hidden in states}

    def values(self, node, origin, seen=frozenset()):
        if node is None or id(node) in seen or len(seen) >= _MAX_DEPTH:
            return {None}
        seen = seen | {id(node)}
        if isinstance(node, (ast.For, ast.comprehension)):
            return {v for sequence in self.values(node.iter, origin, seen)
                    for v in (sequence.items if isinstance(sequence, _Argv) else (None,))} or {None}
        names, _, _ = self.contexts[origin]
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            if len(node.value) > _MAX_TEXT:
                return {None}
            try:
                return {os.fsdecode(node.value)}
            except UnicodeError:
                return {None}
        if names.resolve(node) == {"sys.executable"} and not self.export_changed("sys.executable"):
            return {_PYTHON}
        if names.resolve(node) == {"os.devnull"} and not self.export_changed("os.devnull"):
            return {os.devnull}
        capture = captured_module(node, names, origin, self.modules)
        if capture is not None and not self.export_changed("pathlib.Path"):
            return {capture}
        if isinstance(node, (ast.List, ast.Tuple)):
            return self.sequence(node, origin, seen)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.concatenate(node, origin, seen)
        if isinstance(node, ast.JoinedStr):
            return self.interpolation(node, origin, seen)
        if isinstance(node, ast.IfExp):
            if self.option_prefix(node, origin):
                return {_OPTION_PREFIX}
            return self.values(node.body, origin, seen) | self.values(node.orelse, origin, seen)
        if (isinstance(node, ast.Call) and names.resolve(node.func) == {"shlex.quote"}
                and len(node.args) == 1 and not node.keywords):
            return {_Quoted(v) for v in self.values(node.args[0], origin, seen)}
        return self.named(node, origin, seen)

    def code(self, value):
        if isinstance(value, tuple) and len(value) == 2 and value[0] == "captured-module":
            return value
        return self.text(value)

    def effective_executables(self, executable, origin):
        """An omitted or explicit None override selects the argv executable."""
        if executable is None or isinstance(executable, ast.Constant) and executable.value is None:
            return {_USE_HEAD}
        return self.values(executable, origin)

    def normalized_launches(self, node, api, origin):
        extracted = api_arguments(node, api)
        if extracted is None:
            yield None
            return
        executable, command, shell = extracted
        if isinstance(command, tuple):
            vectors = self.sequence(ast.Tuple(elts=list(command)), origin, frozenset())
        else:
            vectors = self.values(command, origin)
        executables = self.effective_executables(executable, origin)
        if len(vectors) * len(executables) > _MAX_CHOICES:
            yield None
            return
        for vector in vectors:
            for program in executables:
                if shell:
                    text = self.text(vector)
                    if text is None or program is not _USE_HEAD and not isinstance(program, str) and program is not _PYTHON:
                        yield None
                    elif program is _USE_HEAD:
                        yield _Launch("sh", text, True)
                    else:
                        yield _Launch(program, _Argv("tuple", ("sh", "-c", text)), False)
                    continue
                if isinstance(vector, str) and not any(char.isspace() for char in vector):
                    vector = _Argv("tuple", (vector,))
                if not isinstance(vector, _Argv) or not vector.items:
                    yield None
                    continue
                program = vector.items[0] if program is _USE_HEAD else program
                valid_words = all(isinstance(word, str) or word is _PYTHON or word is _OPTION_PREFIX
                                  or isinstance(word, tuple) and len(word) == 2 and word[0] == "captured-module"
                                  for word in vector.items)
                if not valid_words or not isinstance(program, str) and program is not _PYTHON:
                    yield None
                else:
                    yield _Launch(program, vector, False)

    def launch_programs(self, node, api, origin):
        # Unknown runtime arguments still enroll at the API reference. Inspect
        # partial vectors too: a known selector must not lose its unknown code.
        extracted = api_arguments(node, api)
        if extracted is None:
            return
        executable, command, shell = extracted
        vectors = (self.sequence(ast.Tuple(elts=list(command)), origin, frozenset())
                   if isinstance(command, tuple) else self.values(command, origin))
        executables = self.effective_executables(executable, origin)
        if None in vectors and any(isinstance(vector, _Argv) and vector.items
                                   and any(python_selector(word)[0] == "code" for word in vector.items)
                                   and (vector.items[0] is _PYTHON or python_word(vector.items[0])
                                        or vector.items[0] is None) for vector in vectors):
            yield None  # An untracked write can change a known program vector.
        for vector in vectors:
            for program in executables:
                if shell:
                    text = vector.items[0] if isinstance(vector, _Argv) and vector.items else vector
                    if program is _PYTHON or python_word(program):
                        yield self.code(text)
                    elif isinstance(text, (str, _Shell)):
                        yield from self.shell_programs(text)
                elif isinstance(vector, _Argv):
                    yield from self.argv_programs(vector, executable=program, fragment=False)

    def module_program(self, value):
        if not isinstance(value, str) or not value.startswith(("aegis_core.", "aegis_cli.", "aegis_mcp.", "tools.")):
            return "external-module", value
        base = value.replace(".", "/")
        for target in (base + ".py", base + "/__main__.py"):
            if target in self.modules:
                return "captured-module", target
        return None

    def shell_argv_programs(self, items, executable, depth):
        if executable.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe") in {"cmd", "powershell", "pwsh"}:
            if len(items) > 1:
                yield None
            return
        for index, word in enumerate(items[1:], 1):
            if not isinstance(word, str):
                yield None
                return
            if word == "--" or not word.startswith("-"):
                return
            flags = word[1:]
            if not flags or any(flag not in "cefilnuvxs" for flag in flags):
                yield None
                return
            if "c" in flags:
                source = self.text(items[index + 1]) if index + 1 < len(items) else None
                if source is None:
                    yield None
                else:
                    yield from self.shell_programs(source, depth=depth + 1, strict=True)
                return

    def git_setting(self, value):
        """A configuration data fragment stays data; a Python parent still refuses unknown text."""
        text = value.text if isinstance(value, _Shell) else self.text(value)
        if text is None or "=" not in text:
            return False
        key = text.partition("=")[0]
        return bool(key and key[0].isalpha() and all(char.isalnum() or char in "._-" for char in key))

    def argv_programs(self, value, *, fragment=True, executable=_USE_HEAD, depth=0):
        items = value.items
        if not items:
            return
        if depth >= _MAX_DEPTH:
            yield None
            return
        for nested in items:
            if isinstance(nested, _Argv):
                yield from self.argv_programs(nested, depth=depth + 1)
        if isinstance(items[0], _Argv):
            return
        prefixes = [index for index, word in enumerate(items) if word is _OPTION_PREFIX]
        if prefixes and (prefixes != [4] or items[1:4] != ("-I", "-S", "-B")
                         or len(items) <= 5 or items[5] != "-c"):
            yield None
            return
        head = items[0] if executable is _USE_HEAD else executable
        if shell_word(head):
            yield from self.shell_argv_programs(items, head, depth)
            return
        hint = any(value_selector_hint(word) for word in items)
        interpreter = head is _PYTHON or python_word(head)
        uncertain = head is None or head is _SPLICE or isinstance(head, (_Shell, _Quoted))
        if not hint and not (interpreter and any(word is _SPLICE for word in items)):
            return
        if interpreter:
            index = 1
        elif uncertain:
            index = 0 if value_selector_hint(head) else 1
            if head is _SPLICE or any(word is _SPLICE for word in items[1:index + 1]):
                index = next((i for i, word in enumerate(items) if value_selector_hint(word)), index)
        elif isinstance(head, str) and head.startswith("-") and fragment:
            if head == "-c" and len(items) > 1 and not isinstance(items[1], str) and self.git_setting(items[1]):
                return
            uncertain = True  # An option fragment has no executable yet.
            index = 0
        else:
            if any(word is _PYTHON or python_word(word) for word in items[1:]):
                yield None  # Interpreter/selector present but not consumed at the command position.
                return
            # Native option grammars differ from Python's. Inspect constant
            # programs wherever their selector occurs, without interpreting data.
            for position, word in enumerate(items[1:], 1):
                mode, attached = python_selector(word)
                if mode == "code":
                    source = attached if attached is not None else self.code(items[position + 1]) if position + 1 < len(items) else None
                    if source is not None:
                        yield source
            return
        while index < len(items):
            word = items[index]
            if word is _OPTION_PREFIX:
                index += 1
                continue  # The exact pinned proof permits only options here.
            mode, attached = python_selector(word)
            if mode in {"code", "module"}:
                source = None
                if attached is not None:
                    source = attached
                elif index + 1 < len(items):
                    source = self.code(items[index + 1])
                elif fragment:
                    return
                if mode == "module":
                    yield self.module_program(source)
                elif source is not None or interpreter or uncertain:
                    yield source
                return
            if mode == "stop":
                if (interpreter or uncertain) and hint:
                    yield None
                return
            if mode == "unknown" or word is _SPLICE:
                if interpreter or uncertain:
                    yield None
                return
            if mode == "value":
                if index + 1 >= len(items) or items[index + 1] is _SPLICE:
                    yield None
                    return
                index += 1
            index += 1

    def shell_expansions(self, value):
        text = value.text
        fields, holes, out = dict(value.holes), {}, []
        budget = [_MAX_TEXT]
        index, quote, hidden = 0, None, value.hidden
        while index < len(text):
            char = text[index]
            token = next((key for key in fields if text.startswith(key, index)), None)
            if token is not None:
                holes[token] = fields[token] or quote is not None
                append_shell_piece(out, token, budget)
                index += len(token)
                continue
            if char == "\\" and quote != "'" and index + 1 < len(text):
                if text[index + 1] == "\n":
                    index += 2
                    continue  # POSIX shells remove continuations before tokenization.
                append_shell_piece(out, text[index:index + 2], budget)
                index += 2
                continue
            if char in ("'", '"') and quote in (None, char):
                quote = char if quote is None else None
            if quote != "'" and char in ("$", chr(96)):
                end = index + 1
                if char == chr(96):
                    end = text.find(chr(96), end)
                    if end < 0:
                        raise ValueError("unclosed shell substitution")
                    end += 1
                elif end < len(text) and text[end] in "{(":
                    opening, closing = text[end], "}" if text[end] == "{" else ")"
                    depth, end = 1, end + 1
                    while end < len(text) and depth:
                        depth += (text[end] == opening) - (text[end] == closing)
                        end += 1
                    if depth:
                        raise ValueError("unclosed shell substitution")
                elif end < len(text) and (text[end].isalpha() or text[end] == "_"):
                    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                        end += 1
                elif end < len(text) and text[end] in "@*#?$!-0123456789":
                    end += 1
                else:
                    append_shell_piece(out, char, budget)
                    index += 1
                    continue
                hidden |= selector_hint(text[index:end])
                token = "__AEGIS_CENSUS_EXPANSION_" + str(index) + "__"
                holes[token] = quote != '"'
                append_shell_piece(out, token, budget)
                index = end
                continue
            append_shell_piece(out, char, budget)
            index += 1
        return "".join(out), holes, hidden

    def shell_programs(self, value, *, depth=0, strict=False):
        if depth >= _MAX_DEPTH:
            yield None
            return
        if isinstance(value, str):
            value = _Shell(value, frozenset(), False)
        try:
            text, holes, hidden = self.shell_expansions(value)
            lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()\n")
            lexer.whitespace = " \t\r"
            lexer.whitespace_split = True
            words = []
            for word in lexer:
                if len(words) >= _MAX_WORDS:
                    raise ValueError("shell word limit")
                words.append(word)
        except ValueError:
            if strict or value.hidden or selector_hint(value.text):
                yield None
            return
        if hidden:
            yield None
            return
        segment = []
        could_program = selector_hint(text) or any(python_word(word) or shell_word(word) for word in words)
        for word in (*words, "\n"):
            if word and all(char in ";&|()\n" for char in word):
                yield from self.shell_segment(segment, holes, depth=depth, could_program=could_program)
                segment = []
            else:
                segment.append(word)

    def shell_segment(self, words, holes, *, depth=0, could_program=False):
        while words and (words[0].replace("\\", "/").rsplit("/", 1)[-1] in {"if", "then", "elif", "else", "do", "exec", "command", "env"}
                         or words[0].partition("=")[0].isidentifier() and "=" in words[0]):
            words = words[1:]
        if not words:
            return
        if (words[0] in {"!", "while", "until", "for", "case", "time"}
                or words[0].lstrip("0123456789").startswith(("<", ">", "-"))):
            if could_program or selector_hint(" ".join(words)) or any(python_word(word) or shell_word(word) for word in words):
                yield None
            return
        converted = []
        for word in words:
            matches = [multi for token, multi in holes.items() if token in word]
            converted.append(_SPLICE if any(matches) else (None if matches else word))
        yield from self.argv_programs(_Argv("list", tuple(converted)), fragment=False, depth=depth + 1)

    def bearing(self, node, origin, seen=frozenset()):
        if id(node) in seen or len(seen) >= _MAX_DEPTH:
            return False
        seen = seen | {id(node)}
        names, bindings, _ = self.contexts[origin]
        for child in ast.walk(node):
            if names.resolve(child) == {"sys.executable"}:
                return True
            if isinstance(child, ast.Constant) and isinstance(child.value, str) and value_selector_hint(child.value):
                return True
            if isinstance(child, ast.Name):
                scope = names.at[id(child)]
                while scope is not None:
                    scope = binding_scope(scope, child.id)
                    values = bindings.get((scope, child.id), ())
                    if values or child.id in scope.bound:
                        if any(isinstance(value, (ast.Name, ast.List, ast.Tuple, ast.BinOp, ast.JoinedStr, ast.Constant, ast.IfExp))
                               and self.bearing(value, origin, seen) for value in values):
                            return True
                        break
                    scope = scope.parent
        return False

    def imported_argv_source_words(self, qualified, seen):
        """Follow the same re-export chain as values(), retaining AST operands."""
        if qualified in seen or len(seen) >= _MAX_DEPTH:
            return set()
        seen = seen | {qualified}
        base, _, attribute = qualified.rpartition(".")
        target = base.replace(".", "/") + ".py"
        if target not in self.modules:
            target = base.replace(".", "/") + "/__init__.py"
        if target not in self.modules:
            return set()
        names, bindings, _ = self.contexts[target]
        scope = names.at[id(self.modules[target])]
        result = set()
        choices = (self.argv_source_words(value, target, seen) for value in bindings.get((scope, attribute), ()))
        imports = (self.imported_argv_source_words(name, seen) for name in scope.imports.get(attribute, ()))
        for groups in (choices, imports):
            for extra in groups:
                if len(result) + len(extra) > _MAX_CHOICES:
                    return set()
                result.update(extra)
        return result

    def argv_source_words(self, node, origin, seen=frozenset()):
        """Retain AST operands through flattening; this never resolves a program."""
        if node is None or id(node) in seen or len(seen) >= _MAX_DEPTH:
            return set()
        seen = seen | {id(node)}
        if isinstance(node, (ast.For, ast.comprehension)):
            result = set()
            for words in self.argv_source_words(node.iter, origin, seen):
                for item_origin, item in words:
                    extra = self.argv_source_words(item, item_origin, seen)
                    if len(result) + len(extra) > _MAX_CHOICES:
                        return set()
                    result.update(extra)
            return result
        if isinstance(node, tuple):
            return {tuple((origin, item) for item in node)} if len(node) <= _MAX_WORDS else set()
        if isinstance(node, (ast.List, ast.Tuple)):
            if len(node.elts) > _MAX_WORDS:
                return set()
            states = {()}
            for item in node.elts:
                pieces = self.argv_source_words(item.value, origin, seen) if isinstance(item, ast.Starred) else {((origin, item),)}
                if len(states) * len(pieces) > _MAX_CHOICES:
                    return set()
                if any(len(left) + len(right) > _MAX_WORDS for left in states for right in pieces):
                    return set()
                states = {left + right for left in states for right in pieces}
            return states
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.argv_source_words(node.left, origin, seen)
            right = self.argv_source_words(node.right, origin, seen)
            if len(left) * len(right) > _MAX_CHOICES:
                return set()
            if any(len(a) + len(b) > _MAX_WORDS for a in left for b in right):
                return set()
            return {a + b for a in left for b in right}
        if isinstance(node, ast.IfExp):
            left = self.argv_source_words(node.body, origin, seen)
            right = self.argv_source_words(node.orelse, origin, seen)
            return left | right if len(left) + len(right) <= _MAX_CHOICES else set()
        if isinstance(node, (ast.Name, ast.Attribute)):
            names, bindings, _ = self.contexts[origin]
            result = set()
            for qualified in names.resolve(node):
                extra = self.imported_argv_source_words(qualified, seen)
                if len(result) + len(extra) > _MAX_CHOICES:
                    return set()
                result.update(extra)
            if not isinstance(node, ast.Name):
                return result
            scope = names.at[id(node)]
            while scope is not None:
                scope = binding_scope(scope, node.id)
                values = bindings.get((scope, node.id), ())
                if values or node.id in scope.bound:
                    for value in values:
                        extra = self.argv_source_words(value, origin, seen)
                        if len(result) + len(extra) > _MAX_CHOICES:
                            return set()
                        result.update(extra)
                    return result
                scope = scope.parent
            return result
        return set()

    def program_sources(self, command, program, origin, *, executable=None, fragment=True):
        """Use the selector's source operand as the occurrence, not its wrappers."""
        found = set()
        for words in self.argv_source_words(command, origin):
            if not words:
                continue
            heads = self.effective_executables(executable, origin)
            if _USE_HEAD in heads:
                head_origin, head = words[0]
                heads = (heads - {_USE_HEAD}) | self.values(head, head_origin)
            shell = any(shell_word(value) for value in heads)
            first_only = any(value is _PYTHON or python_word(value) or shell_word(value)
                             or not isinstance(value, str) or value.startswith("-") for value in heads)
            option_argument = False
            for index, (word_origin, word) in enumerate(words):
                if index == 0 and not fragment:
                    continue  # argv[0] is the display name, never an option.
                if option_argument:
                    option_argument = False
                    continue
                selectors = [python_selector(value) for value in self.values(word, word_origin)]
                if shell:
                    selectors.extend(("code", None) for value in self.values(word, word_origin)
                                     if isinstance(value, str) and value.startswith("-") and "c" in value[1:]
                                     and all(flag in "cefilnuvxs" for flag in value[1:]))
                code = [(mode, attached) for mode, attached in selectors if mode == "code"]
                for _, attached in code:
                    operand = (word_origin, word) if attached is not None else words[index + 1] if index + 1 < len(words) else None
                    if attached == program or attached is None and operand is not None and any(
                            self.code(value) == program or isinstance(value, (str, _Shell))
                            and program in self.shell_programs(value) for value in self.values(operand[1], operand[0])):
                        found.add(operand)
                if code and first_only:
                    break
                if first_only and not shell and any(mode == "value" for mode, _ in selectors):
                    option_argument = True
        return found

    def construction_command(self, node, api):
        """Locate argv source for counting, even when other launch options are unknown."""
        if len(node.args) + len(node.keywords) > _MAX_WORDS:
            return None
        extracted = api_arguments(node, api)
        if extracted is not None:
            return extracted[1]
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
        if api.startswith("subprocess."):
            return node.args[0] if node.args else keywords.get("args")
        suffix = api.rsplit(".", 1)[1]
        if suffix in {"system", "popen"}:
            return None
        offset = 1 if suffix.startswith("spawn") else 0
        if suffix.startswith(("execl", "spawnl")):
            end = -1 if suffix.endswith("e") else len(node.args)
            return tuple(node.args[offset + 1:end])
        return node.args[offset + 1] if len(node.args) > offset + 1 else keywords.get("argv")

    def construction_programs(self, value, node, api, origin):
        """A normalized call's execution context also governs its constructions."""
        extracted = api_arguments(node, api)
        if extracted is None:
            yield from self.argv_programs(value)
            return  # Retain existing reviewed uncertainty; do not normalize kwargs.
        executable, _, shell = extracted
        if shell:
            return  # launch_programs already inspects the actual shell command.
        for program in self.effective_executables(executable, origin):
            yield from self.argv_programs(value, executable=program, fragment=program is _USE_HEAD)

    def programs(self, rel, *, with_locations=False):
        # Located events distinguish launch occurrences from argv source data.
        # Consumers remove construction subtrees used by a normalized launch;
        # separate calls remain separate even when they share one argv value.
        tree = self.modules[rel]
        names = self.contexts[rel][0]
        parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        emitted = set()
        events = {}
        event_counts = [0, 0]

        def record(node, program, sources, launch):
            key = node.lineno, node.col_offset, program, launch
            if key in events:
                events[key][2].update(sources)
            else:
                category = int(program is None)
                if event_counts[category] >= _MAX_WORDS:
                    raise ValueError(rel + ": literal occurrence limit")
                event_counts[category] += 1
                events[key] = (node, program, set(sources), launch)

        for node in ast.walk(tree):
            parent = parents.get(id(node))
            if isinstance(node, ast.Call) and names.resolve(node.func) & RAW:
                for api in sorted(names.resolve(node.func) & RAW):
                    extracted = api_arguments(node, api) if with_locations else None
                    for program in self.launch_programs(node, api, rel):
                        sources = set()
                        if with_locations and extracted is not None and isinstance(program, str):
                            executable, command, shell = extracted
                            if not shell:
                                sources = self.program_sources(command, program, rel, executable=executable, fragment=False)
                        key = node.lineno, program
                        if with_locations:
                            record(node, program, sources, True)
                        elif key not in emitted:
                            emitted.add(key)
                            yield key
                    if with_locations:
                        command = self.construction_command(node, api)
                        vectors = (self.sequence(ast.Tuple(elts=list(command)), rel, frozenset())
                                   if isinstance(command, tuple) else self.values(command, rel))
                        if extracted is not None:
                            executable, _, _ = extracted
                            executables = self.effective_executables(executable, rel)
                            complete = bool(vectors) and all(isinstance(vector, _Argv) and vector.items and all(
                                isinstance(word, str) or word is _PYTHON or word is _OPTION_PREFIX
                                or isinstance(word, tuple) and len(word) == 2 and word[0] == "captured-module"
                                for word in vector.items) for vector in vectors)
                            if complete and all(value is _USE_HEAD or value is _PYTHON or isinstance(value, str)
                                                for value in executables):
                                origins = {word for words in self.argv_source_words(command, rel) for word in words}
                                if origins:
                                    record(node, None, origins, True)
                        for vector in vectors:
                            if not isinstance(vector, _Argv):
                                continue
                            for program in self.construction_programs(vector, node, api, rel):
                                sources = (self.program_sources(command, program, rel, executable=extracted[0], fragment=False)
                                           if isinstance(program, str) and extracted is not None else (
                                               self.program_sources(command, program, rel) if isinstance(program, str) else set()))
                                record(node, program, sources, True)
                continue
            candidate = isinstance(node, (ast.List, ast.Tuple)) or (
                isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add))
            if isinstance(parent, ast.Assign) and all(isinstance(target, (ast.Tuple, ast.List)) for target in parent.targets):
                continue  # Unpacking data is not an argv; its bindings remain unknown.
            elif (isinstance(parent, ast.Compare)
                  or not with_locations and isinstance(parent, (ast.Starred, ast.List, ast.Tuple))
                  or not with_locations and isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add)):
                continue
            if not candidate:
                continue
            launch = parent if with_locations else None
            while launch is not None and not (isinstance(launch, ast.Call) and names.resolve(launch.func) & RAW):
                launch = parents.get(id(launch))
            values = self.values(node, rel)
            for value in values:
                if isinstance(value, _Argv):
                    if with_locations and any(isinstance(item, _Argv) for item in value.items):
                        continue  # Nested argv values have distinct source occurrences below this wrapper.
                    programs = (program for api in sorted(names.resolve(launch.func) & RAW)
                                for program in self.construction_programs(value, launch, api, rel)) if launch is not None else self.argv_programs(value)
                elif value is None and self.bearing(node, rel):
                    programs = (None,)
                else:
                    continue
                for program in programs:
                    sources = self.program_sources(node, program, rel) if with_locations and isinstance(program, str) else set()
                    if with_locations:
                        if launch is not None:
                            record(launch, program, sources, True)
                            continue
                    for source_rel, occurrence in sources or {(rel, node)}:
                        if source_rel != rel:
                            continue  # The defining package module inventories its own construction.
                        key = node.lineno, program
                        if with_locations:
                            record(occurrence, program, {(source_rel, occurrence)}, False)
                        elif key not in emitted:
                            emitted.add(key)
                            yield key
        if with_locations:
            yield from events.values()


def literal_programs(tree, rel, modules=None, resolver=None):
    modules = {rel: tree} if modules is None else modules
    yield from (resolver or CommandResolver(modules)).programs(rel)

def refuse_literal_spawns(tree, rel, modules=None, resolver=None):
    if not rel.startswith(("aegis_core/", "aegis_cli/")):
        return
    for _, source in literal_programs(tree, rel, modules, resolver):
        if source is None:
            raise ValueError(f"{rel}: unresolved Python -c program")
        if isinstance(source, tuple) and len(source) == 2 and source[0] in {"captured-module", "external-module"}:
            continue  # Exact co-located module capture, already parsed by this census.
        try:
            program = ast.parse(source)
        except (SyntaxError, ValueError, UnicodeError):
            continue  # Invalid constant Python cannot execute a hidden spawn.
        if any(isinstance(node, ast.ImportFrom) and node.module in {"os", "subprocess"}
               and any(alias.name == "*" for alias in node.names) for node in ast.walk(program)):
            raise ValueError(f"{rel}: unresolved Python -c program")
        names = ScopedNames(program, rel)
        if any(names.resolve(node) & RAW for node in ast.walk(program)):
            raise ValueError(f"{rel}: process spawn inside a literal -c program")


def module_process_sites(modules):
    found = {}
    for rel, tree in modules.items():
        names = ScopedNames(tree, rel)

        def visit(node, scope="<module>"):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope = node.name if scope == "<module>" else scope + "." + node.name
            sites = {("process", name) for name in names.resolve(node) & RAW}
            if isinstance(node, ast.Call) and rel.startswith("aegis_core/"):
                for name in names.resolve(node.func) & {"shutil.which", "aegis_core.pathlookup.which"}:
                    # only_skipped forwards its caller's fence positionally.
                    fenced = any(k.arg == "outside" for k in node.keywords) or (name.endswith("pathlookup.which") and len(node.args) >= 3)
                    if not fenced:
                        sites.add(("lookup", name))
            elif isinstance(node, ast.ExceptHandler) and node.type:
                if any(isinstance(n, ast.Name) and n.id == "TypeError" for n in ast.walk(node.type)):
                    sites.add(("typeerror", "TypeError"))
            elif isinstance(node, ast.Dict):
                keys = {n.value for n in node.keys if isinstance(n, ast.Constant) and isinstance(n.value, str)}
                if {"aegis_version", "checked_at"} <= keys:
                    sites.add(("envelope", "dict"))
            for category, detail in sorted(sites):
                found.setdefault(f"{category}:{rel}:{scope}:{detail}", []).append(node.lineno)
            for child in ast.iter_child_nodes(node):
                visit(child, scope)
        visit(tree)
    return dict(sorted(found.items()))


def literal_fixture_sites(root, *, option_pins=None):
    """Retain round-6 resolver component assertions, independently of site admission."""
    modules = dict(module_trees(root))
    resolver = CommandResolver(modules, option_pins=option_pins)
    for rel, tree in modules.items():
        refuse_literal_spawns(tree, rel, modules, resolver)
    return module_process_sites(modules)


def literal_process_sites(rel, tree, resolver, *, owner=None, origin_line=None, depth=0, context_rel=None,
                          consumed=None, constructors=None, dependencies=frozenset()):
    """Count resolvable program occurrences, retaining their reviewed source owner."""
    found, parsed = [], set()
    consumed = set() if consumed is None else consumed
    constructors = set() if constructors is None else constructors
    scopes = {id(node): scope for node, scope in qualified_nodes(tree, include_signature=True)}
    context_rel = rel if context_rel is None else context_rel
    for node, source, origins, launch in resolver.programs(context_rel, with_locations=True):
        if launch and source is None and origins:
            consumed.update((source_rel, id(source_node)) for source_rel, source_node in origins)
        if not isinstance(source, str):
            continue  # Reviewed uncertainty or an already-censused captured module.
        required = dependencies
        if launch:
            consumed.update((source_rel, id(source_node), source) for source_rel, source_node in origins)
        else:
            construction = context_rel, id(node), source
            if construction in constructors or construction in consumed or construction[:2] in consumed:
                continue
            constructors.add(construction)
            required = dependencies | {construction}
        scope = scopes[id(node)] if owner is None else owner + "." + scopes[id(node)]
        location = node.lineno, node.col_offset
        key = scope, location, source
        if key in parsed:
            continue
        if depth >= _MAX_DEPTH:
            raise ValueError(rel + ": literal program nesting limit")
        if len(source) > _MAX_TEXT:
            raise ValueError(rel + ": literal program text limit")
        parsed.add(key)
        try:
            program = ast.parse(source)
        except (SyntaxError, ValueError, UnicodeError):
            continue
        prefix = scope + f".<literal-c-L{node.lineno}C{node.col_offset}>"
        line = node.lineno if origin_line is None else origin_line
        for child_key, lines in module_process_sites({rel: program}).items():
            category, _, child_scope, api = child_key.split(":", 3)
            if category == "process":
                found.extend((f"process:{rel}:{prefix}.{child_scope}:{api}", line, required) for _ in lines)
        # A virtual sibling preserves relative imports and leaves the original
        # module available to absolute imports from this literal program.
        parent = context_rel.rpartition("/")[0]
        stem = context_rel.rsplit("/", 1)[-1].removesuffix(".py")
        nested_rel = parent + f"/<{stem}__literal_D{depth}_L{node.lineno}_C{node.col_offset}>.py"
        nested = CommandResolver({nested_rel: program}, option_pins={}, package_context=resolver)
        found.extend(literal_process_sites(
            rel, program, nested, owner=prefix, origin_line=line, depth=depth + 1, context_rel=nested_rel,
            consumed=consumed, constructors=constructors, dependencies=required))
    return found


def process_sites(root, *, option_pins=None, selector_table=None):
    modules = dict(module_trees(root))
    # Temporary repositories have no inherited source reviews. The production
    # repository always uses the one static table, including rows for removed files.
    if selector_table is None:
        selector_table = SELECTOR_SITE_TABLE if root.resolve() == REPO else ()
    errors = selector_site_errors(selector_sites(modules), selector_table)
    if errors:
        raise ValueError(errors[0])
    resolver = CommandResolver(modules, option_pins=option_pins)
    found = module_process_sites(modules)
    literals, consumed, constructors = [], set(), set()
    for rel, tree in modules.items():
        literals.extend(literal_process_sites(rel, tree, resolver, consumed=consumed, constructors=constructors))
    for key, line, dependencies in literals:
        if all(dependency not in consumed and dependency[:2] not in consumed for dependency in dependencies):
            found.setdefault(key, []).append(line)
    return dict(sorted(found.items()))


def census_errors(current, record):
    errors = []
    for key, lines in current.items():
        if key not in record:
            errors.append(f"unreviewed {key} at lines {lines}")
        elif len(lines) != record[key]["count"]:
            errors.append(f"{key}: {record[key]['count']} -> {len(lines)} at lines {lines}; lower pins after removals")
    errors.extend(f"{key}: removed; lower the ratchet" for key in record.keys() - current.keys())
    return errors


def lowered_census(record, current):
    growth = [k for k, v in current.items() if k not in record or len(v) > record[k]["count"]]
    if growth:
        raise ValueError("refusing to raise process records: " + repr(growth))
    return {k: {"count": len(v), "reason": record[k]["reason"]} for k, v in current.items()}


def runner_violations(root, program):
    found = []
    for rel, tree in module_trees(root):
        names = ScopedNames(tree, rel)
        comparisons = {id(n) for c in ast.walk(tree) if isinstance(c, ast.Compare) for n in c.comparators}
        transport = {"aegis_core/ghcli.py"} if program == "gh" else {"aegis_core/gitsafe.py", "aegis_core/treeid.py"}
        for node in ast.walk(tree):
            reason = None
            if (isinstance(node, (ast.List, ast.Tuple)) and id(node) not in comparisons and node.elts and
                    isinstance(node.elts[0], ast.Constant) and node.elts[0].value == program and rel not in transport):
                reason = f"{program} argv outside transport"
            elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                if names.resolve(node.func) & {"shutil.which", "aegis_core.pathlookup.which"} and node.args[0].value == program:
                    resolver = "aegis_core/ghcli.py" if program == "gh" else "aegis_core/gitsafe.py"
                    if rel != resolver:
                        reason = f"{program} resolution outside transport"
            if (program == "git" and isinstance(node, ast.Call)
                    and "aegis_core.gitsafe.git_executable" in names.resolve(node.func) and rel not in transport):
                reason = "git executable outside transport"
            if program == "git":
                if any(name.startswith("aegis_core.gitsafe._") for name in names.resolve(node)) and rel != "aegis_core/gitsafe.py":
                    reason = "private gitsafe reach"
                if (isinstance(node, ast.Constant) and node.value == "refs/remotes/origin/HEAD"
                        and rel not in ("aegis_core/gitsafe.py", "aegis_core/gitevidence.py")):
                    reason = "default branch outside git evidence"
            if reason:
                found.append((rel, node.lineno, reason))
    return [f"{rel}:{line}: {reason}" for rel, line, reason in sorted(found)]


if __name__ == "__main__":
    if sys.argv[1:] != ["--write"]:
        sys.exit("usage: python3 tests/contract/test_process_ratchets.py --write")
    try:
        updated = lowered_census(json.loads(RECORD.read_text()), process_sites(REPO))
    except ValueError as exc:
        sys.exit(str(exc))
    RECORD.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.mark.parametrize("reverse", [False, True])
def test_process_aliases_do_not_leak_between_sibling_scopes(tmp_path, reverse):
    package = tmp_path / "aegis_core"
    package.mkdir()
    pieces = ["def launch():\n    import subprocess as backend\n    backend.run(['tool'])\n",
              "def decode():\n    import json as backend\n    backend.loads('{}')\n"]
    (package / "probe.py").write_text("\n".join(reversed(pieces) if reverse else pieces), encoding="utf-8")
    sites = process_sites(tmp_path)
    assert list(sites) == ["process:aegis_core/probe.py:launch:subprocess.run"]
    assert len(next(iter(sites.values()))) == 1


def test_process_aliases_respect_parameters_closures_and_default_expressions(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import subprocess as backend\n"
        "def ignored(backend):\n    backend.run([])\n"
        "def defaults(backend=backend.run):\n    backend([])\n"
        "def outer():\n    import subprocess as nested\n    def inner():\n        nested.run([])\n",
        encoding="utf-8")
    assert set(process_sites(tmp_path)) == {
        "process:aegis_core/probe.py:defaults:subprocess.run",
        "process:aegis_core/probe.py:outer.inner:subprocess.run"}


@pytest.mark.parametrize("body,expected", [
    ("PROG = \"import subprocess; subprocess.run(['tool'])\"\nargv = [sys.executable, '-c', PROG]", "spawn"),
    ("argv = [exe, '-c', unresolved]", "unresolved"),
    ("argv = ('git', '-c', 'core.x=y')", "accepted"),
    ("list(map(subprocess.run, commands))", "enrolled"),
    ("argv = [sys.executable, '-m', 'aegis_core.not_censused']", "unresolved"),
    ("subprocess.run([sys.executable, '-m', 'pytest'])", "enrolled"),
    ("subprocess.run(command)", "enrolled"),
    ("message = 'python -c unknown'\nhelp = f'python -c {unknown}'\nmetadata = {'command': 'python -c unknown'}", "accepted"),
    ("argv = [sys.executable, '-c', 'def broken(']", "accepted"),
    ("commands = {'key': [sys.executable, '-c', \"import subprocess; subprocess.run(['tool'])\"]}", "spawn"),
    ("argv = ['git', '-c', \"import subprocess; subprocess.run(['tool'])\"]", "spawn"),
    ("argv = ['-c', \"x=1; import subprocess; subprocess.run(['tool'])\"]", "spawn"),
    ("argv = ['git', '-C', directory, '-c', \"import subprocess; subprocess.run(['tool'])\"]", "spawn"),
    ("argv = [sys.executable, '-c', \"import subprocess; subprocess.run(['tool'])\"] * 2", "spawn"),
])
def test_rule_m_scope_correction(tmp_path, body, expected):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("import sys, subprocess\n" + body + "\n", encoding="utf-8")
    if expected in {"spawn", "unresolved"}:
        message = ("process spawn inside a literal -c program" if expected == "spawn"
                   else "unresolved Python -c program")
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/probe.py: " + message
    else:
        sites = literal_fixture_sites(tmp_path)
        assert sum(len(lines) for lines in sites.values()) == (1 if expected == "enrolled" else 0)
        if sites:
            assert census_errors(sites, {}) == [
                "unreviewed " + key + " at lines " + repr(lines) for key, lines in sites.items()]


@pytest.mark.parametrize("operation", ["getattr(os, 'O_RDONLY', 0)", "hasattr(os, 'O_RDONLY')",
                                       "helper({'value': os.devnull})"])
def test_readonly_namespace_and_immutable_attribute_inputs(tmp_path, operation):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import os, sys\n" + operation + "\nargv = [sys.executable, '-c', 'core.path=' + os.devnull]\n",
        encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {}


@pytest.mark.parametrize("package", ["aegis_core", "aegis_cli"])
@pytest.mark.parametrize("program", [
    "import subprocess; subprocess.Popen(['tool'])",
    "import subprocess as sp; sp.run(['tool'])",
    "from subprocess import check_output as launch; launch(['tool'])",
    "import os; os.spawnvp(0, 'tool', ['tool'])",
    "from os import execv as launch; launch('/tool', ['tool'])",
    "import os as system; system.posix_spawn('/tool', ['tool'], {})",
])
@pytest.mark.parametrize("binding", ["inline", "module", "local"])
def test_census_refuses_literal_program_spawns(tmp_path, package, program, binding):
    directory = tmp_path / package
    directory.mkdir()
    value = repr(program)
    prefix = ""
    if binding == "module":
        prefix, value = "CODE = " + value + "\n", "CODE"
    elif binding == "local":
        prefix, value = "    CODE = " + value + "\n", "CODE"
    body = "    return [python, '-I', '-c', " + value + "]\n"
    source = ("def launch():\n" + prefix + body if binding == "local" else
              prefix + "def launch():\n" + body)
    path = directory / "probe.py"
    path.write_text(source, encoding="utf-8")
    message = package + "/probe.py: process spawn inside a literal -c program"
    for _ in range(2):  # Refusal is stable on a retry, with no mutable census state.
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == message


def test_literal_program_guard_preserves_scope_and_nonspawning_programs(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "CODE = 'import json; print(json.dumps({}))'\n"
        "def one():\n    CODE = 'import subprocess; subprocess.Popen([])'\n"
        "def two():\n    return [python, '-c', CODE]\n"
        "def three():\n    return ['git', '-c', 'core.fsmonitor=false']\n"
        "def five():\n    return [python, '-c', 'def f(subprocess): subprocess.run([])']\n",
        encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {}


def test_invalid_python_program_refuses_without_echoing_source(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("argv = [python, '-c', 'def broken(']\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {}  # A constant syntax error cannot run a spawn.
    (package / "probe.py").write_text("argv = [python, '-c', unknown]\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


@pytest.mark.parametrize("form", ["import", "attribute", "shell", "shell_inline", "reexport"])
def test_census_refuses_imported_and_shell_literal_programs(tmp_path, form):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "program.py").write_text("CODE = 'import subprocess; subprocess.Popen([])'\n", encoding="utf-8")
    (package / "relay.py").write_text("from aegis_core.program import CODE as SCRIPT\n", encoding="utf-8")
    sources = {
        "import": "from aegis_core.program import CODE as program\nargv = [python, '-c', program]\n",
        "attribute": "import aegis_core.program as program\nargv = [python, '-c', program.CODE]\n",
        "shell": "import shlex\nfrom aegis_core.program import CODE\nprogram = shlex.quote(CODE)\ncommand = f'python -I -c {program} arg'\n",
        "shell_inline": "command = " + repr("python -I -c " + shlex.quote("import subprocess; subprocess.Popen([])")) + "\n",
        "reexport": "from aegis_core.relay import SCRIPT\nargv = [python, '-c', SCRIPT]\n",
    }
    (package / "launch.py").write_text(sources[form], encoding="utf-8")
    if form in {"shell", "shell_inline"}:
        assert literal_fixture_sites(tmp_path) == {}  # Shell text alone is not an argv.
        (package / "launch.py").write_text(
            sources[form] + "import subprocess\nsubprocess.run(command, shell=True)\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/launch.py: process spawn inside a literal -c program"


def test_literal_import_cycles_and_constant_cycles_terminate(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "one.py").write_text("from aegis_core.two import CODE\nargv = [python, '-c', CODE]\n", encoding="utf-8")
    (package / "two.py").write_text("from aegis_core.one import CODE\n", encoding="utf-8")
    (package / "three.py").write_text("CODE = CODE\nargv = [python, '-c', CODE]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unresolved Python -c program"):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("api", ["spawnvp", "execv", "posix_spawn"])
def test_census_enrolls_direct_os_spawns(tmp_path, api):
    package = tmp_path / "aegis_core"
    package.mkdir()
    call = _RULE_M_APIS["os." + api].replace("CODE", repr("pass"))
    (package / "probe.py").write_text("import os, sys\ndef launch():\n    " + call + "\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {"process:aegis_core/probe.py:launch:os." + api: [3]}


_RULE_M_APIS = {
    **{"os.exec" + tail: "os.exec" + tail + "(sys.executable, 'worker', '-c', CODE" +
       (", {})" if tail.endswith('e') else ")") for tail in ("l", "le", "lp", "lpe")},
    **{"os.spawn" + tail: "os.spawn" + tail + "(0, sys.executable, 'worker', '-c', CODE" +
       (", {})" if tail.endswith('e') else ")") for tail in ("l", "le", "lp", "lpe")},
    **{"os.exec" + tail: "os.exec" + tail + "(sys.executable, ['worker', '-c', CODE]" +
       (", {})" if tail.endswith('e') else ")") for tail in ("v", "ve", "vp", "vpe")},
    **{"os.spawn" + tail: "os.spawn" + tail + "(0, sys.executable, ['worker', '-c', CODE]" +
       (", {})" if tail.endswith('e') else ")") for tail in ("v", "ve", "vp", "vpe")},
    **{"os." + name: "os." + name + "(sys.executable, ['worker', '-c', CODE], {})"
       for name in ("posix_spawn", "posix_spawnp")},
    "subprocess.literal_override": "subprocess.run(['worker', '-c', CODE], executable='python3')",
    "subprocess.path_override": "subprocess.run(['worker', '-c', CODE], executable='/trusted/python3.12')",
    "subprocess.marker_override": "subprocess.run(['worker', '-c', CODE], executable=sys.executable)",
    "os.system": "os.system('python3 -c ' + shlex.quote(CODE))",
    "os.popen": "os.popen('python3 -c ' + shlex.quote(CODE))",
    "subprocess.getoutput": "subprocess.getoutput('python3 -c ' + shlex.quote(CODE))",
    "subprocess.getstatusoutput": "subprocess.getstatusoutput('python3 -c ' + shlex.quote(CODE))",
}


@pytest.mark.parametrize("api", list(_RULE_M_APIS))
@pytest.mark.parametrize("spawn", [False, True], ids=["benign", "spawn"])
def test_rule_m_api_normalization(tmp_path, api, spawn):
    package = tmp_path / "aegis_core"
    package.mkdir()
    code = "import subprocess; subprocess.run(['tool'])" if spawn else "print('safe')"
    (package / "probe.py").write_text(
        "import os, sys, subprocess, shlex\nCODE = " + repr(code) + "\n" + _RULE_M_APIS[api] + "\n", encoding="utf-8")
    if spawn:
        for _ in range(2):
            with pytest.raises(ValueError) as error:
                literal_fixture_sites(tmp_path)
            assert str(error.value) in {"aegis_core/probe.py: process spawn inside a literal -c program",
                                       "aegis_core/probe.py: unresolved Python -c program"}
    else:
        assert sum(len(lines) for key, lines in literal_fixture_sites(tmp_path).items() if key.startswith("process:")) == 1


@pytest.mark.parametrize("write", [
    "CODE = 'pass'\n[(CODE := P) for _ in [0]]\nargv = [sys.executable, '-c', CODE]",
    "def launch():\n    CODE = 'pass'\n    [[(CODE := P) for _ in [0]] for _ in [0]]\n    return [sys.executable, '-c', CODE]",
    "FLAGS = ['-I']\nlist.append(FLAGS, '-c')\nargv = [sys.executable, *FLAGS, P]",
    "FLAGS = ['-I']\ndef mutate(flags):\n    flags.append('-c')\nmutate(FLAGS)\nargv = [sys.executable, *FLAGS, P]",
    "FLAGS = ['-I']\nBOX = [FLAGS]\nBOX[0].append('-c')\nargv = [sys.executable, *FLAGS, P]",
    "FLAGS = ['-I']\nBOX = {'flags': FLAGS}\nALIAS = BOX['flags']\nALIAS.append('-c')\nargv = [sys.executable, *FLAGS, P]",
])
def test_rule_m_untracked_writes_refuse(tmp_path, write):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys\nP = \"import subprocess; subprocess.run(['tool'])\"\n" + write + "\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) in {"aegis_core/probe.py: unresolved Python -c program",
                               "aegis_core/probe.py: process spawn inside a literal -c program"}


@pytest.mark.parametrize("body", [
    "list(map(subprocess.run, [[sys.executable, '-c', P]]))",
    "commands = [[sys.executable, '-c', P]]\nlist(map(subprocess.run, commands))",
    "callback = subprocess.run\ncallback([sys.executable, '-c', P])",
    "def launch(callback=subprocess.run):\n    callback([sys.executable, '-c', P])",
])
def test_rule_m_spawn_values_refuse(tmp_path, body):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, subprocess\nP = \"import subprocess; subprocess.run(['tool'])\"\n" + body + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("prefix,suffix", [
    ("! ", ""), ("while ", "; do :; done"), ("until ", "; do :; done"),
    (">/dev/null ", ""), ("env -i ", ""), ("env --ignore-environment ", ""), ("command -p ", ""),
])
def test_rule_m_shell_prefixes_refuse(tmp_path, prefix, suffix):
    package = tmp_path / "aegis_core"
    package.mkdir()
    code = "import subprocess; subprocess.run(['tool'])"
    command = prefix + "python3 -c " + shlex.quote(code) + suffix
    (package / "probe.py").write_text("import subprocess\nsubprocess.run(" + repr(command) + ", shell=True)\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("spawn", [False, True], ids=["benign", "spawn"])
@pytest.mark.parametrize("form", ["nested_shell", "continuation", "nested_continuation"])
def test_rule_m_shell_programs_and_continuations(tmp_path, spawn, form):
    package = tmp_path / "aegis_core"
    package.mkdir()
    code = "import subprocess; subprocess.run(['tool'])" if spawn else "print('safe')"
    command = "python3 " + ("\\\n" if form != "nested_shell" else "") + "-c " + shlex.quote(code)
    expression = repr(command) + ", shell=True" if form == "continuation" else repr(["sh", "-c", command])
    (package / "probe.py").write_text("import subprocess\nsubprocess.run(" + expression + ")\n", encoding="utf-8")
    if spawn:
        with pytest.raises(ValueError):
            literal_fixture_sites(tmp_path)
    else:
        assert len(literal_fixture_sites(tmp_path)) == 1


def test_rule_m_python_module_program_is_censused_or_refused(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "worker.py").write_text("import subprocess\nsubprocess.run(['tool'])\n", encoding="utf-8")
    path = package / "probe.py"
    path.write_text("import sys, subprocess\nsubprocess.run([sys.executable, '-m', 'aegis_core.worker'])\n", encoding="utf-8")
    assert sum(key.startswith("process:") for key in literal_fixture_sites(tmp_path)) == 2
    path.write_text("import sys, subprocess\ndef launch(module):\n    subprocess.run([sys.executable, '-m', module])\n", encoding="utf-8")
    assert sum(key.startswith("process:") for key in literal_fixture_sites(tmp_path)) == 2


@pytest.mark.parametrize("call", [
    "subprocess.run(command)", "subprocess.run(['worker'], executable=program)",
    "subprocess.run(['worker'], shell=mode)", "subprocess.run(['worker'], **options)",
    "os.execl(program, 'worker', '-c', code)", "os.execv(program, argv)",
])
def test_rule_m_unresolved_launches_refuse(tmp_path, call):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, os, subprocess\ndef launch(command, program, mode, options, code, argv):\n    " + call + "\n", encoding="utf-8")
    if "'-c'" in call:
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"
    else:
        assert sum(len(lines) for lines in literal_fixture_sites(tmp_path).values()) == 1


@pytest.mark.parametrize("call", [
    "subprocess.run(['/usr/bin/env', 'python', '-c', P])",
    "subprocess.run(['env', sys.executable, '-c', P])",
    "os.system('env -i python -c ' + shlex.quote(P))",
    "subprocess.run(['pythonw', '-c', P])",
    "subprocess.run(['pythonw.exe', '-c', P])",
    "subprocess.run(['py', '-3', '-c', P])",
    "subprocess.run(['pyw', '-3', '-c', P])",
    "subprocess.run(P, shell=True, executable=sys.executable)",
    "subprocess.run(P, shell=True, executable='python3')",
    "subprocess.run(['python -c ' + shlex.quote(P)], shell=True)",
    "os.spawnlp(os.P_WAIT, 'python', 'python', '-c', P)",
])
def test_rule_m_correctness_exact_launch_forms_refuse(tmp_path, call):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, os, shlex, subprocess\nP = 'import os; os.system(\"id\")'\n" + call + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("code", ["from os import *\nsystem('id')", "from subprocess import *\nPopen(['tool'])",
                                      "from subprocess import *\ngetoutput('tool')"])
def test_rule_m_star_import_program_refuses(tmp_path, code):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, subprocess\nsubprocess.run([sys.executable, '-c', " + repr(code) + "])\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("body", [
    "FLAGS = ['-I']\ndef setup():\n    FLAGS.append('-c')\n    FLAGS.append(P)\ndef run():\n    setup()\n    subprocess.run([sys.executable, *FLAGS])",
    "ARGV = [sys.executable, '-I', '-c', 'pass']\ndef run():\n    ARGV[3] = P\n    subprocess.run(ARGV)",
    "CODE = 'pass'\nimport aegis_core.probe as probe\nprobe.CODE = P\nsubprocess.run([sys.executable, '-c', CODE])",
    "FLAGS = ['-I']\ndef setup():\n    FLAGS.extend(['-c', P])\nsetup()\nsubprocess.run([sys.executable, *FLAGS])",
    "ARGV = [sys.executable, '-I', '-c', 'pass']\ndef setup():\n    ARGV[3] = P\nsetup()\nsubprocess.run(ARGV)",
])
def test_rule_m_argon_module_writes_refuse(tmp_path, body):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, subprocess\nP = \"import subprocess; subprocess.Popen(['/bin/true'])\"\n" + body + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("expression", ["f'-c{code}'", "'-c' + code", "f'-Ic{code}'"])
@pytest.mark.parametrize("standalone", [False, True])
def test_rule_m_argon_unresolved_attached_selector_refuses(tmp_path, expression, standalone):
    package = tmp_path / "aegis_core"
    package.mkdir()
    body = "return [" + expression + "]" if standalone else "subprocess.run([python, '-I', " + expression + "])"
    (package / "probe.py").write_text(
        "import subprocess\ndef launch(python, code):\n    " + body + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("logging", ["f'{argv}'", "[*argv]", "argv * 2"])
def test_rule_m_argon_logged_builder_still_refuses(tmp_path, logging):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, subprocess\nP = \"import subprocess; subprocess.Popen(['/bin/true'])\"\n"
        "def build():\n    argv = [sys.executable, '-I', '-c', P]\n    print(" + logging + ")\n    return argv\n"
        "subprocess.run(args=build(), executable=sys.executable)\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


def test_rule_m_argon_imported_prefix_refuses(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "shared.py").write_text("import sys\nPREFIX = [sys.executable, '-I', '-c']\n", encoding="utf-8")
    (package / "probe.py").write_text(
        "import subprocess\nfrom aegis_core.shared import PREFIX\n"
        "tail = [\"import subprocess; subprocess.Popen(['/bin/true'])\"]\nsubprocess.run(PREFIX + tail)\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


@pytest.mark.parametrize("prefix", ["/usr/bin/env -i ", "2>/dev/null ", "2>&1 ", "time "])
def test_rule_m_shell_prefix_siblings_refuse(tmp_path, prefix):
    package = tmp_path / "aegis_core"
    package.mkdir()
    command = prefix + "python3 -c " + shlex.quote("import os; os.system('id')")
    (package / "probe.py").write_text("import subprocess\nsubprocess.run(" + repr(command) + ", shell=True)\n", encoding="utf-8")
    with pytest.raises(ValueError):
        literal_fixture_sites(tmp_path)


_REVIEW_COMMANDS = {
    "argv_combined": "argv = [sys.executable, '-Ic', CODE]",
    "argv_attached": "argv = [sys.executable, '-c' + CODE]",
    "argv_separate": "argv = [sys.executable, '-I', '-c', CODE]",
    "argv_named_star": "FLAGS = ['-I', '-c']\nargv = [sys.executable, *FLAGS, CODE]",
    "argv_nested_star": "FLAGS = ('-I',)\nSELECTOR = ['-c']\nargv = [sys.executable, *FLAGS, *SELECTOR, CODE]",
    "argv_list_sum": "argv = [sys.executable] + ['-I', '-c'] + [CODE]",
    "argv_tuple_sum": "argv = (sys.executable,) + ('-I', '-c') + (CODE,)",
    "shell_interpolated_combined": "argv = f'python -Ic {CODE}'",
    "shell_interpolated_attached": "argv = f'python -c{CODE}'",
    "shell_interpolated_separate": "argv = f'python -I -c {CODE}'",
    "shell_double_combined": "argv = f'python -Ic \"{CODE}\"'",
    "shell_double_attached": "argv = f'python -c\"{CODE}\"'",
    "shell_double_separate": "argv = f'python -I -c \"{CODE}\"'",
    "shell_single_combined": 'argv = f"python -Ic \'{CODE}\'"',
    "shell_single_attached": 'argv = f"python -c\'{CODE}\'"',
    "shell_single_separate": 'argv = f"python -I -c \'{CODE}\'"',
    "shell_literal_combined": None,
    "shell_literal_attached": None,
    "shell_literal_separate": None,
}


def test_rule_m_shell_name_metadata_is_not_a_launch(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import subprocess\nWORDS = {'cmd', 'powershell', 'pwsh', 'py', 'pyw'}\nsubprocess.run(['worker'])\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {"process:aegis_core/probe.py:<module>:subprocess.run": [3]}


@pytest.mark.parametrize("method", ["cwd", "home"])
def test_rule_m_readonly_path_classmethod_preserves_capture(tmp_path, method):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "worker.py").write_text("import subprocess\nsubprocess.run(['worker'])\n", encoding="utf-8")
    (package / "probe.py").write_text(
        "from pathlib import Path\nimport sys\nHERE = Path." + method + "()\n"
        "CODE = Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n"
        "argv = [sys.executable, '-I', '-c', CODE]\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {"process:aegis_core/worker.py:<module>:subprocess.run": [2]}


@pytest.mark.parametrize("use", ["opaque_argv_user", "reader_replacement"])
def test_rule_m_capture_text_is_immutable_but_reader_must_be_unchanged(tmp_path, use):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "worker.py").write_text("import subprocess\nsubprocess.run(['worker'])\n", encoding="utf-8")
    replacement = "Path.read_text = lambda self, **kw: \"import os; os.system('id')\"\n" if use == "reader_replacement" else ""
    (package / "probe.py").write_text(
        "from pathlib import Path\nimport sys\n" + replacement +
        "CODE = Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n"
        "argv = [sys.executable, '-I', '-c', CODE]\ndef helper(argv):\n    return argv\nhelper(argv)\n", encoding="utf-8")
    if use == "reader_replacement":
        with pytest.raises(ValueError):
            literal_fixture_sites(tmp_path)
    else:
        assert literal_fixture_sites(tmp_path) == {"process:aegis_core/worker.py:<module>:subprocess.run": [2]}


@pytest.mark.parametrize("assembly", list(_REVIEW_COMMANDS))
@pytest.mark.parametrize("spawn", [False, True], ids=["benign", "spawn"])
def test_formal_command_resolution_matrix(tmp_path, assembly, spawn):
    package = tmp_path / "aegis_core"
    package.mkdir()
    code = "import subprocess; subprocess.Popen(['tool'])" if spawn else "print('safe')"
    command = _REVIEW_COMMANDS[assembly]
    if command is None:
        words = {"shell_literal_combined": ["python", "-Ic", code],
                 "shell_literal_attached": ["python", "-c" + code],
                 "shell_literal_separate": ["python", "-I", "-c", code]}[assembly]
        command = "argv = " + repr(shlex.join(words))
    source = "import sys, subprocess\nCODE = " + repr(code) + "\n" + command + "\nsubprocess.run(argv, shell=" + str(assembly.startswith("shell")) + ")\n"
    (package / "probe.py").write_text(source, encoding="utf-8")
    if assembly.startswith("shell_interpolated"):
        # These original unquoted semicolon-containing programs are not valid
        # Python after shell splitting. Keep that input, then exercise real code.
        assert len(literal_fixture_sites(tmp_path)) == 1
        (package / "probe.py").write_text(
            source.replace("CODE = " + repr(code), "CODE = " + repr(shlex.quote(code))), encoding="utf-8")
    if spawn:
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) in {
            "aegis_core/probe.py: process spawn inside a literal -c program",
            "aegis_core/probe.py: unresolved Python -c program"}
    else:
        sites = literal_fixture_sites(tmp_path)
        assert list(sites) == ["process:aegis_core/probe.py:<module>:subprocess.run"]
        assert len(next(iter(sites.values()))) == 1


@pytest.mark.parametrize("assembly", [
    "FLAGS = read_flags()\nargv = [sys.executable, *FLAGS, CODE]",
    "FLAGS = read_flags()\nargv = [sys.executable, '-I', *FLAGS, '-c', CODE]",
    "FLAGS = ['-I']\nFLAGS += read_flags()\nargv = [sys.executable, *FLAGS, CODE]",
    "FLAGS = ['-I']\nFLAGS.append('-c')\nargv = [sys.executable, *FLAGS, CODE]",
    "argv = f'python -c \"{unknown}\"'",
    'argv = f"python -c \'{unknown}\'"',
    "argv = f'python -c \"{CODE}'",
])
def test_formal_unresolved_assembly_refuses(tmp_path, assembly):
    package = tmp_path / "aegis_core"
    package.mkdir()
    source = "import sys, subprocess\nCODE = 'print(1)'\n" + assembly + "\n"
    if "argv = f" in assembly:
        (package / "probe.py").write_text(source, encoding="utf-8")
        assert literal_fixture_sites(tmp_path) == {}
    (package / "probe.py").write_text(
        source + "subprocess.run(argv, shell=" + str("argv = f" in assembly) + ")\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


@pytest.mark.parametrize("api", ["getoutput", "getstatusoutput"])
def test_formal_output_helpers_are_enrolled_and_refused_in_programs(tmp_path, api):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("import subprocess\ndef launch():\n    subprocess." + api + "('tool')\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {"process:aegis_core/probe.py:launch:subprocess." + api: [3]}
    code = "import subprocess; subprocess." + api + "('tool')"
    path.write_text("import sys\nargv = [sys.executable, '-c', " + repr(code) + "]\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("placement", ["module", "local", "imported"])
def test_formal_literal_accumulation_refuses(tmp_path, placement):
    package = tmp_path / "aegis_core"
    package.mkdir()
    definition = "CODE = 'import subprocess;'\nCODE += \"subprocess.run(['tool'])\"\n"
    launch = "argv = [python, '-c', CODE]\n"
    if placement == "local":
        source = "def launch():\n" + "".join("    " + line + "\n" for line in (definition + launch).splitlines())
    elif placement == "imported":
        (package / "program.py").write_text(definition, encoding="utf-8")
        source = "from aegis_core.program import CODE\n" + launch
    else:
        source = definition + launch
    (package / "probe.py").write_text(source, encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


@pytest.mark.parametrize("code", [
    "import subprocess; list(map(subprocess.run, [['tool']]))",
    "import subprocess\ndef launch(spawn=subprocess.Popen):\n    spawn(['tool'])\nlaunch()",
    "from subprocess import run as spawn; callback = spawn",
])
def test_formal_spawn_references_in_programs_refuse(tmp_path, code):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("argv = [python, '-c', " + repr(code) + "]\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("body", [
    "code = ''\npython, code = sys.executable, P\nargv = [python, '-I', '-c', code]\n",
    "def launch(code=None):\n    if code is None: code = 'pass'\n    return [sys.executable, '-I', '-c', code]\nlaunch(P)\n",
    "def launch(code):\n    flags = ['-c', code]\n    return [sys.executable, '-I', *flags]\nlaunch(P)\n",
    "def launch(code):\n    return ['-c', code]\nlaunch(P)\n",
])
def test_argon_binding_and_fragment_cases_refuse(tmp_path, body):
    package = tmp_path / "aegis_core"
    package.mkdir()
    code = "import subprocess; subprocess.Popen(['/bin/true'])"
    (package / "probe.py").write_text("import sys\nP = " + repr(code) + "\n" + body, encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


def test_option_metadata_and_process_result_text_are_not_launches(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, subprocess\n"
        "def launch(flag):\n"
        "    if flag in ('-c', '--exec-path', '--config-env'): pass\n"
        "    options = ('-r', '--recursive', '-f', '--force')\n"
        "    argv = [sys.executable, '-I', '-c', 'print(1)']\n"
        "    proc = subprocess.run(argv)\n"
        "    return f'run exited {proc.returncode}' + (f': {proc.stderr}' if proc.stderr else '')\n",
        encoding="utf-8")
    assert list(literal_fixture_sites(tmp_path)) == ["process:aegis_core/probe.py:launch:subprocess.run"]


def test_git_data_fragments_do_not_exempt_a_python_parent(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    source = "import sys\ndef flags(driver):\n    return ['-c', f'filter.{driver}.required=false']\n"
    path.write_text(source, encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {}
    path.write_text(source + "\ndef launch(value):\n    cfg = ['-c', f'core.option={value}']\n    return [sys.executable, *cfg]\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


def test_native_git_configuration_is_not_an_unresolved_python_program(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("import os\ndef query(program):\n    return (program, '-c', 'core.hooksPath=' + os.devnull, 'rev-parse')\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {}
    path.write_text("import sys\nargv = [sys.executable, '-c', 'core.hooksPath=/trusted/null']\n", encoding="utf-8")
    assert literal_fixture_sites(tmp_path) == {}  # Invalid constant Python is accepted under any head.


@pytest.mark.parametrize("definition", [
    "FLAGS = OTHER = ['-I']\nFLAGS.append('-c')\nargv = [sys.executable, *OTHER, CODE]",
    "FLAGS = ['-I']\nOTHER = FLAGS\nOTHER.extend(['-c'])\nargv = [sys.executable, *FLAGS, CODE]",
    "def launch(code=None):\n    code = 'pass'\n    return [sys.executable, '-c', code]",
])
def test_unsupported_alias_writes_and_parameter_overwrites_refuse(tmp_path, definition):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("import sys\nCODE = 'print(1)'\n" + definition + "\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


@pytest.mark.parametrize("write", [
    "with context() as CODE:\n    pass",
    "try:\n    action()\nexcept Exception as CODE:\n    pass",
    "async def launch():\n    CODE = 'pass'\n    async for CODE in source:\n        return [sys.executable, '-c', CODE]",
    "def CODE():\n    pass",
    "class CODE:\n    pass",
    pytest.param("match value:\n    case CODE:\n        pass", marks=pytest.mark.skipif(
        sys.version_info < (3, 10), reason="pattern bindings require Python 3.10")),
    pytest.param("match value:\n    case [*CODE]:\n        pass", marks=pytest.mark.skipif(
        sys.version_info < (3, 10), reason="pattern bindings require Python 3.10")),
    pytest.param("match value:\n    case {**CODE}:\n        pass", marks=pytest.mark.skipif(
        sys.version_info < (3, 10), reason="pattern bindings require Python 3.10")),
])
def test_implicit_binding_writes_refuse(tmp_path, write):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys\nCODE = 'pass'\n" + write + "\nargv = [sys.executable, '-c', CODE]\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


@pytest.mark.parametrize("case", ["words", "text", "aliases", "null", "unicode"])
def test_resolver_bounds_and_bad_programs_refuse(tmp_path, case):
    package = tmp_path / "aegis_core"
    package.mkdir()
    if case == "words":
        definition = "argv = [sys.executable, " + "'-I', " * (_MAX_WORDS + 1) + "'-c', 'pass']\n"
    elif case == "aliases":
        definition = "C0 = 'pass'\n" + "".join("C" + str(i) + " = C" + str(i - 1) + "\n" for i in range(1, _MAX_DEPTH + 2))
        definition += "argv = [sys.executable, '-c', C" + str(_MAX_DEPTH + 1) + "]\n"
    else:
        code = {"text": "x" * (_MAX_TEXT + 1), "null": "\0", "unicode": "\ud800"}[case]
        definition = "argv = [sys.executable, '-c', " + ascii(code) + "]\n"
    (package / "probe.py").write_text("import sys\n" + definition, encoding="utf-8")
    if case in {"null", "unicode"}:
        assert literal_fixture_sites(tmp_path) == {}
        return  # Invalid constant Python cannot execute a spawn.
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


@pytest.fixture
def option_prefix_tree(tmp_path):
    for rel in ("aegis_core/testexec.py", "aegis_core/testplans.py",
                "aegis_core/verification/regression_commands.py"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text((REPO / rel).read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


def test_source_pinned_option_prefix_resolves_current_source(option_prefix_tree):
    modules = dict(module_trees(option_prefix_tree))
    rel = OPTION_PREFIX_CALLER[0]
    for _ in range(2):
        resolver = CommandResolver(modules)
        programs = list(literal_programs(modules[rel], rel, modules, resolver))
        assert programs and all(source is not None for _, source in programs)
        refuse_literal_spawns(modules[rel], rel, modules, resolver)


@pytest.mark.parametrize("rel,function,statement", [
    ("aegis_core/testexec.py", "python_module_index", "    index = 0"),
    ("aegis_core/testplans.py", "rebase_snapshot_arguments", "    result = []"),
    ("aegis_core/verification/regression_commands.py", "run_configured_snapshot", "    scratch.mkdir(parents=True)"),
])
def test_source_pinned_option_prefix_changed_function_refuses(option_prefix_tree, rel, function, statement):
    path = option_prefix_tree / rel
    source = path.read_text(encoding="utf-8")
    assert source.count(statement + "\n") >= 1
    path.write_text(source.replace(statement + "\n", statement + "  # changed proof\n", 1), encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(option_prefix_tree)
        assert str(error.value) == "process census: re-review pinned function " + rel + "::" + function


@pytest.mark.parametrize("old,new", [
    ("before = rebase_snapshot_arguments(logical[1:1 + module], workspace, snapshot) if module >= 0 else []",
     "before = read_flags()"),
    ("logical[1:1 + module]", "logical[0:1 + module]"),
    ("module = testexec.python_module_index(logical[1:])", "module = testexec.python_module_index(logical)"),
    ('*before, "-c", _BOOTSTRAP', '"-c", *before, _BOOTSTRAP'),
    ('*before, "-c", _BOOTSTRAP', '"-c", _BOOTSTRAP, *before'),
    ('argv[0], "-I", "-S", "-B", *before', 'argv[0], *before, "-I", "-S", "-B"'),
])
def test_source_pinned_option_prefix_other_constructions_refuse(option_prefix_tree, old, new):
    import hashlib

    rel, function = "aegis_core/verification/regression_commands.py", "run_configured_snapshot"
    path = option_prefix_tree / rel
    source = path.read_text(encoding="utf-8")
    assert source.count(old) == 1
    source = source.replace(old, new)
    path.write_text(source, encoding="utf-8")
    # A test-owned policy copy isolates structural/position checks from digest
    # refusal without changing the repository census's shared reviewed pins.
    pins = dict(OPTION_PREFIX_PINS)
    key = (rel, function)
    if key in pins:
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == function)
        digest = hashlib.sha256(ast.get_source_segment(source, node).encode("utf-8")).hexdigest()
        pins[key] = (digest, pins[key][1])
    with pytest.raises(ValueError) as error:
        modules = dict(module_trees(option_prefix_tree))
        refuse_literal_spawns(modules[rel], rel, modules, CommandResolver(modules, option_pins=pins))
    assert str(error.value) == rel + ": unresolved Python -c program"


def test_holder_is_a_censused_isolated_module():
    from aegis_core import gitops_fds

    holder = REPO / "aegis_core/gitops_holder.py"
    tree = ast.parse(holder.read_text(encoding="utf-8"))
    names = ScopedNames(tree, "aegis_core/gitops_holder.py")
    assert all(not name.startswith("aegis_") for node in ast.walk(tree)
               for name in import_bindings(node, "aegis_core/gitops_holder.py").values())
    spawns = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
              and "subprocess.Popen" in names.resolve(node.func)]
    assert len(spawns) == 1
    key = "process:aegis_core/gitops_holder.py:main:subprocess.Popen"
    assert process_sites(REPO)[key] == [spawns[0].lineno]
    source = (REPO / "aegis_core/gitops_fds.py").read_text(encoding="utf-8")
    assert gitops_fds._HOLDER_SOURCE == holder.read_text(encoding="utf-8")
    assert '[sys.executable, "-I", "-c", _HOLDER_SOURCE,' in source


@pytest.mark.parametrize("capture", [
    "Path(__file__).with_name('worker.py').read_text(encoding='utf-8')",
    "Path(__file__).with_name('absent.py').read_text(encoding='utf-8')",
    "Path(__file__).with_name('../worker.py').read_text(encoding='utf-8')",
    "Path(location).read_text(encoding='utf-8')",
    "build_program()", "arguments.code", "input()",
    "Path(__file__).with_name('worker.py').read_text(encoding='utf-8').replace('x', 'y')",
])
def test_census_accepts_only_a_captured_module_program(tmp_path, capture):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "worker.py").write_text("import subprocess\ndef main():\n    subprocess.Popen(['tool'])\n", encoding="utf-8")
    (package / "launch.py").write_text(
        "from pathlib import Path\nimport sys\nCODE = " + capture +
        "\nargv = [sys.executable, '-I', '-c', CODE]\n", encoding="utf-8")
    if capture == "Path(__file__).with_name('worker.py').read_text(encoding='utf-8')":
        assert literal_fixture_sites(tmp_path) == {"process:aegis_core/worker.py:main:subprocess.Popen": [3]}
    else:
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/launch.py: unresolved Python -c program"


@pytest.mark.parametrize("expression", ["code", "build()", "source[0]"])
def test_census_refuses_unresolved_python_and_shell_programs(tmp_path, expression):
    package = tmp_path / "aegis_cli"
    package.mkdir()
    for command in ("[python, '-c', " + expression + "]", "f'python -I -c {" + expression + "}'"):
        (package / "launch.py").write_text("def launch(code, source):\n    return " + command + "\n", encoding="utf-8")
        if command.startswith("f"):
            assert literal_fixture_sites(tmp_path) == {}
            (package / "launch.py").write_text(
                "import subprocess\ndef launch(code, source):\n    return subprocess.run(" + command + ", shell=True)\n",
                encoding="utf-8")
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_cli/launch.py: unresolved Python -c program"


@pytest.mark.parametrize("flag", ["-I", "-S", "-B"])
def test_census_refuses_unresolved_python_option_fragments(tmp_path, flag):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "launch.py").write_text(
        "import sys, subprocess\ndef launch(code):\n    flags = [" + repr(flag) + ", '-c', code]\n"
        "    return subprocess.run([sys.executable, *flags])\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/launch.py: unresolved Python -c program"


@pytest.mark.parametrize("source_case", ["snapshot", "missing", "invalid_utf8"])
def test_holder_uses_captured_checkout_bytes_without_installed_module(tmp_path, source_case):
    import os
    import shutil
    import subprocess
    import venv
    from aegis_core import gitops_fds, team_gitops

    if not gitops_fds.descriptor_supported() or not team_gitops.descriptor_supported():
        pytest.skip("custody holder requires Linux subreaper support")
    git = shutil.which("git")
    if git is None:
        pytest.skip("needs git")
    environment = tmp_path / "isolated-python"
    venv.EnvBuilder(with_pip=False).create(environment)
    python = environment / "bin/python"
    probe = subprocess.run([str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                           capture_output=True, text=True, check=True, timeout=20)
    installed = Path(probe.stdout.strip()) / "aegis_core"
    installed.mkdir()
    (installed / "__init__.py").write_text("# Installed package has no holder.\n", encoding="utf-8")
    absent = subprocess.run([str(python), "-I", "-c", "import importlib.util; assert importlib.util.find_spec('aegis_core.gitops_holder') is None"],
                            capture_output=True, check=True, timeout=20)
    assert absent.stdout == absent.stderr == b""
    checkout = tmp_path / "parent-package"
    shutil.copytree(REPO / "aegis_core", checkout / "aegis_core", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    repo, marker = tmp_path / "repository", tmp_path / "untrusted-import"
    repo.mkdir()
    subprocess.run([git, "init", "-q", str(repo)], capture_output=True, check=True, timeout=20)
    malicious = "from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\nraise RuntimeError('untrusted')\n"
    (repo / "subprocess.py").write_text(malicious, encoding="utf-8")
    (repo / "aegis_core").mkdir()
    (repo / "aegis_core/__init__.py").write_text(malicious, encoding="utf-8")
    script = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
source = Path(sys.argv[1]) / 'aegis_core/gitops_holder.py'
original = source.read_bytes()
if sys.argv[5] == 'missing':
    source.unlink()
elif sys.argv[5] == 'invalid_utf8':
    source.write_bytes(b'\\xff')
from aegis_core import gitops_fds, gitsafe, team_gitops
if sys.argv[5] == 'snapshot':
    assert gitops_fds._HOLDER_SOURCE.encode('utf-8') == source.read_bytes()
    source.write_text(sys.argv[3], encoding='utf-8')
with team_gitops.GitOpsJournal(Path(sys.argv[2]) / '.git').record_intent(
        op='push', lane='lane-1', request_id='request-1', actor='session-1',
        expected_old='a' * 40, expected_new='b' * 40) as receipt:
    for _ in range(2):
        try:
            result = gitsafe.run(['version'], sys.argv[2], effect_fds=receipt.inheritable_fds(),
                                worktree_root=sys.argv[2], timeout=10,
                                _environ={'PATH': os.path.dirname(sys.argv[4])})
        except gitsafe.GitError as error:
            assert sys.argv[5] != 'snapshot'
            assert error.code == 'effect_command_refused' and error.process_started is False
            assert str(error) == 'Git operation effect command refused.'
            source.write_bytes(original)
        else:
            assert sys.argv[5] == 'snapshot'
            assert result.returncode == 0 and result.stdout.startswith(b'git version ')
assert 'aegis_core.gitops_holder' not in sys.modules
print('captured holder succeeded twice')
"""
    result = subprocess.run([str(python), "-I", "-c", script, str(checkout), str(repo), malicious, git, source_case],
                            cwd=repo, env={**os.environ, "PYTHONPATH": str(repo)}, capture_output=True, timeout=40)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout == b"captured holder succeeded twice\n" and result.stderr == b""
    assert not marker.exists()


@pytest.fixture(scope="module")
def installed_holder(tmp_path_factory):
    """Install the tracked module in a test-owned interpreter, never on sys.path."""
    import os
    import shutil
    import subprocess
    import venv
    from aegis_core.gitops_fds import descriptor_supported

    if not descriptor_supported():
        pytest.skip("custody holder requires Linux subreaper support")
    root = tmp_path_factory.mktemp("installed-holder")
    venv.EnvBuilder(with_pip=False).create(root)
    python = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    probe = subprocess.run([str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                           capture_output=True, text=True, check=True, timeout=20)
    package = Path(probe.stdout.strip()) / "aegis_core"
    package.mkdir()
    for name in ("__init__.py", "_version.py", "gitops_holder.py"):
        shutil.copyfile(REPO / "aegis_core" / name, package / name)
    return python


@pytest.mark.parametrize("case,expected", [
    ("success", b"started\nexit:0"), ("124", b"started\nexit:124"),
    ("125", b"started\nexit:125"), ("signal", b"started\nexit:-15"),
    ("timeout", b"started\ntimeout"), ("spawn", b"spawn"),
])
def test_installed_holder_status_protocol_and_import_isolation(installed_holder, tmp_path, case, expected):
    import os
    import subprocess
    from contextlib import ExitStack

    marker = tmp_path / "untrusted-import"
    malicious = "from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\nraise RuntimeError('untrusted')\n"
    (tmp_path / "subprocess.py").write_text(malicious, encoding="utf-8")
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "__init__.py").write_text(malicious, encoding="utf-8")
    scripts = {"success": "pass", "124": "raise SystemExit(124)", "125": "raise SystemExit(125)",
               "signal": "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
               "timeout": "import time; time.sleep(30)", "spawn": "pass"}
    with ExitStack() as stack:
        reader, writer = os.pipe()
        for fd in (reader, writer):
            stack.callback(os.close, fd)
        executable = os.open(sys.executable, os.O_RDONLY)
        stack.callback(os.close, executable)
        argv = [str(installed_holder), "-I", "-m", "aegis_core.gitops_holder", str(writer),
                "0.05" if case == "timeout" else "5", "-1", "-1", "-1",
                "-1" if case == "spawn" else str(executable), "-1",
                sys.executable, "-I", "-c", scripts[case]]
        for _ in range(2):
            result = subprocess.run(argv, cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(tmp_path)},
                                    pass_fds=(writer, executable), capture_output=True, timeout=10)
            assert result.returncode == (125 if case == "spawn" else 0)
            assert result.stdout == result.stderr == b""
            assert os.read(reader, 65) == expected
    assert not marker.exists()


def test_holder_unsupported_probe_refuses_before_spawn(monkeypatch):
    from aegis_core import gitops_fds
    from aegis_core.errors import AegisError

    monkeypatch.setattr("aegis_core.gitops_fds.descriptor_supported", lambda: False)
    with pytest.raises(AegisError) as error:
        gitops_fds.pass_through((-1,))
    assert error.value.code == "unsupported_effect_platform"
    assert str(error.value) == "Git operation effect descriptor platform unavailable."
    assert error.value.process_started is False


@pytest.mark.parametrize("kind,code,message", [
    ("git", "effect_command_refused", "Git operation effect command refused."),
    ("gh", "gh_spawn_failed", "GitHub CLI could not start; no effect process started."),
])
def test_unavailable_holder_source_refuses_before_recipe_resources(monkeypatch, kind, code, message):
    from aegis_core import gitops_fds
    from aegis_core.errors import AegisError

    monkeypatch.setattr("aegis_core.gitops_fds._HOLDER_SOURCE", "")
    with pytest.raises(AegisError) as error:
        with gitops_fds.holder_recipe([], {}, 1, kind=kind, error=AegisError,
                                     timeout_error=TimeoutError, transport=object()):
            pytest.fail("unavailable holder source must refuse before yielding a recipe")
    assert error.value.code == code and str(error.value) == message
    assert error.value.process_started is False and error.value.effect_process_started is False


def test_concurrent_holders_keep_custody_until_both_cancel(installed_holder, tmp_path):
    import fcntl
    import os
    import select
    import signal
    import subprocess
    from contextlib import ExitStack

    with ExitStack() as stack:
        receipt = stack.enter_context((tmp_path / "receipt").open("w+b"))
        contender = stack.enter_context((tmp_path / "receipt").open("r+b"))
        fcntl.flock(receipt, fcntl.LOCK_EX | fcntl.LOCK_NB)
        executable = os.open(sys.executable, os.O_RDONLY)
        stack.callback(os.close, executable)
        holders = []
        try:
            for _ in range(2):
                reader, writer = os.pipe()
                stack.callback(os.close, reader)
                try:
                    command = [str(installed_holder), "-I", "-m", "aegis_core.gitops_holder",
                               str(writer), "20", "-1", "-1", "-1", str(executable), "-1",
                               sys.executable, "-I", "-c", "import time; time.sleep(30)"]
                    process = subprocess.Popen(command, pass_fds=(writer, executable, receipt.fileno()),
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    holders.append((process, reader))
                finally:
                    os.close(writer)
                assert select.select([reader], [], [], 5)[0], "holder did not acknowledge spawn"
                assert os.read(reader, 8) == b"started\n"
            receipt.close()
            for process, reader in holders:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                process.send_signal(signal.SIGUSR1)
                assert process.communicate(timeout=10) == (b"", b"")
                assert process.returncode == 0
                assert os.read(reader, 65) == b"cancelled"
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            for process, _ in holders:
                if process.poll() is None:
                    process.send_signal(signal.SIGUSR1)
                process.communicate(timeout=10)


_FORMAL_0440_CASES = {
    "empty_star": ("", "os.execl(sys.executable, 'worker', '-c', P, *())", "os.execl"),
    "empty_keywords": ("", "subprocess.run(P, shell=True, executable=sys.executable, **{})", "subprocess.run"),
    "named_shell": ("", "mode=True\nsubprocess.run('python3 -c '+shlex.quote(P), shell=mode)", "subprocess.run"),
    "truthy_shell": ("", "subprocess.run('python3 -c '+shlex.quote(P), shell=1)", "subprocess.run"),
    "starred_selector": ("", "os.execl(sys.executable, 'worker', *['-c', P])", "os.execl"),
    "shell_comment": ("", "os.system('printf x#y; python3 -c '+shlex.quote(P))", "os.system"),
    "written_alias": ("", "F=['-I']\nbox=[None]\nbox[0]=F\nbox[0].append('-c')\nsubprocess.run([sys.executable,*F,P])", "subprocess.run"),
    "accessor_alias": ("", "A=[sys.executable,'-c','pass']\nBOX={'argv':A}\nALIAS=BOX.get('argv')\nALIAS[2]=P\nsubprocess.run(A)", "subprocess.run"),
    "override_mutation": ("", "A=['worker','-c','pass']\nA[2]=P\nsubprocess.run(A, executable=sys.executable)", "subprocess.run"),
    "shell_mutation": ("", "A=['sh','-c','true']\nA[2]='python3 -c '+shlex.quote(P)\nsubprocess.run(A)", "subprocess.run"),
    "imported_prefix": ("from aegis_core.shared import PREFIX\n", "subprocess.run(PREFIX + tail)", "subprocess.run"),
    "imported_builder": ("from aegis_core.shared import PREFIX\n", "def build():\n    return [P]\nsubprocess.run(PREFIX + build())", "subprocess.run"),
    "argon_env_shell": ("", "subprocess.run(['env', 'sh', '-c', f'python3 -c {P!r}'])", "subprocess.run"),
    "argon_append_selector": ("", "ARGV=[sys.executable, '-I']\nARGV.append('-c')\nARGV.append(P)\nsubprocess.run(ARGV)", "subprocess.run"),
    "argon_returned_prefix": ("", "def get_prefix():\n    return [sys.executable, '-I', '-c']\nsubprocess.run(get_prefix() + [P])", "subprocess.run"),
    "argon_env_path": ("", "subprocess.run(['/usr/bin/env','sh','-c',f'python3 -c {P!r}'])", "subprocess.run"),
    "argon_nice_shell": ("", "subprocess.run(['nice','sh','-c',f'python3 -c {P!r}'])", "subprocess.run"),
    "argon_shell_plus_e": ("", "subprocess.run(['sh','+e','-c',f'python3 -c {P!r}'])", "subprocess.run"),
    "argon_shell_plus_u": ("", "subprocess.run(['sh','+u','-c',f'python3 -c {P!r}'])", "subprocess.run"),
    "argon_shell_plus_x": ("", "subprocess.run(['sh','+x','-c',f'python3 -c {P!r}'])", "subprocess.run"),
    "argon_call_star": ("", "subprocess.run(*[[sys.executable,'-c',P]])", "subprocess.run"),
    "argon_shell_mode": ("", "subprocess.run(f'python3 -c {P!r}', shell=mode)", "subprocess.run"),
    "argon_shell_keywords": ("", "subprocess.run(f'python3 -c {P!r}', **opts)", "subprocess.run"),
    "argon_keyword_posix_spawn": ("", "os.posix_spawn(path=sys.executable, argv=['worker','-c',code], env={})", "os.posix_spawn"),
    "argon_exec_override": ("", "ARGV=['worker','-I','-c','pass']\nARGV[3]=P\nos.execv(sys.executable,ARGV)", "os.execv"),
    "argon_string_walrus": ("", "CMD='python3 -c pass'\n[(CMD := f'python3 -c {P!r}') for _ in [0]]\nsubprocess.run(CMD,shell=True)", "subprocess.run"),
    "argon_spliced_prefix": ("", "FLAGS=[sys.executable,'-I']\nFLAGS.append('-c')\nFLAGS.append(P)\nsubprocess.run([*FLAGS,'-c','pass'])", "subprocess.run"),
    "argon_spliced_head": ("", "FLAGS=[sys.executable,'-I']\nFLAGS.append('-c')\nFLAGS.append(P)\nsubprocess.run([python,*FLAGS,'-c','pass'])", "subprocess.run"),
    "argon_getter_mutation": ("", "FLAGS=['-I']\nBOX={'flags':FLAGS}\nBOX.get('flags').append('-c')\nsubprocess.run([sys.executable,*FLAGS,P])", "subprocess.run"),
    "argon_unpack_alias": ("", "FLAGS=['-I']\nALIAS,_=FLAGS,None\nALIAS.append('-c')\nsubprocess.run([sys.executable,*FLAGS,P])", "subprocess.run"),
    "argon_loop_alias": ("", "FLAGS=['-I']\nfor ALIAS in [FLAGS]:\n    ALIAS.append('-c')\nsubprocess.run([sys.executable,*FLAGS,P])", "subprocess.run"),
    "argon_bool_alias": ("", "FLAGS=['-I']\nALIAS=FLAGS or []\nALIAS.append('-c')\nsubprocess.run([sys.executable,*FLAGS,P])", "subprocess.run"),
    "argon_walrus_alias": ("", "FLAGS=['-I']\n(ALIAS := FLAGS).append('-c')\nsubprocess.run([sys.executable,*FLAGS,P])", "subprocess.run"),
    "argon_attribute_alias": ("", "import aegis_core.probe as probe\nFLAGS=['-I']\nALIAS=FLAGS\nprobe.ALIAS.append('-c')\nsubprocess.run([sys.executable,*FLAGS,P])", "subprocess.run"),
    "argon_nonlocal_alias": ("", "def outer():\n    CODE='pass'\n    def middle():\n        nonlocal CODE\n        def inner():\n            nonlocal CODE\n            CODE=P\n        inner()\n    middle()\n    return [sys.executable,'-c',CODE]\nsubprocess.run(outer())", "subprocess.run"),
    "argon_git_setting": ("", "def make_flags(code):\n    return ['-c',f'x={code}']\nsubprocess.run(['python3','-I']+make_flags(P))", "subprocess.run"),
    "argon_nested_concatenation": ("", "tail=[]\ntail.append(P)\nlist(map(subprocess.run,[[sys.executable,'-I','-c']+tail]))", "subprocess.run"),
}


@pytest.mark.parametrize("case", list(_FORMAL_0440_CASES))
def test_selector_site_formal_0440_requires_review(tmp_path, case):
    package = tmp_path / "aegis_core"
    package.mkdir()
    prefix, body, api = _FORMAL_0440_CASES[case]
    if prefix:
        (package / "shared.py").write_text("import sys\nPREFIX=[sys.executable,'-I','-c']\n", encoding="utf-8")
    program = "import subprocess; subprocess.Popen(['/bin/true'])" if case.startswith("argon_") else "import os; os.system('id')"
    source = ("import os, sys, subprocess, shlex\nP=" + repr(program) + "\n" + prefix
              + "def launch(tail=None, code=None, mode=None, opts=None):\n"
              + "".join("    " + line + "\n" for line in body.splitlines()))
    (package / "probe.py").write_text(source, encoding="utf-8")
    scope = {"argon_returned_prefix": "launch.get_prefix", "argon_nonlocal_alias": "launch.outer",
             "argon_git_setting": "launch.make_flags"}.get(case, "launch")
    site = ("aegis_core/shared.py", "<module>") if prefix else ("aegis_core/probe.py", scope)
    message = "unreviewed selector site " + ":".join(site)
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == message
    table = ((*site, "reviewed-dynamic", "Test-owned review of this selector construction."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert "process:aegis_core/probe.py:launch:" + api in sites


def test_selector_site_stale_row_refuses(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    row = ("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned selector review.")
    path.write_text("def launch():\n    return ['python3','-c', unknown]\n", encoding="utf-8")
    assert process_sites(tmp_path, selector_table=(row,)) == {}
    path.write_text("def launch():\n    return []\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=(row,))
        assert str(error.value) == "stale selector site aegis_core/probe.py:launch"
    path.unlink()
    with pytest.raises(ValueError, match="^stale selector site aegis_core/probe.py:launch$"):
        process_sites(tmp_path, selector_table=(row,))


@pytest.mark.parametrize("text,expected", [
    ("printf x#y; python3 -c 'pass'", True),
    ("printf x # python3 -c 'pass'", True),
    ("printf '#'; python3 -IEc 'pass'", True),
    ("printf x\\#y; python3 -c 'pass'", True),
    ("# python3 -c 'pass'\nprintf ok", True),
    ('"$PYTHON" -c code', True), ("$PYTHON -c code", True),
    ("/usr/bin/env -i python3 -c code", True),
    ("git -c cannot carry", True),
])
def test_selector_site_shell_comments_and_variables(tmp_path, text, expected):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("MESSAGE=" + repr(text) + "\n", encoding="utf-8")
    if expected:
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site aegis_core/probe.py:<module>"
    else:
        assert process_sites(tmp_path) == {}


@pytest.mark.parametrize("token", ["-c", "-Ic", "-Ec", "-IEc", "-cpass", "-cprint(1)"])
@pytest.mark.parametrize("package_name", ["aegis_core", "aegis_cli", "aegis_mcp"])
def test_selector_site_tokens_cover_all_admitted_packages(tmp_path, token, package_name):
    package = tmp_path / package_name
    package.mkdir()
    (package / "probe.py").write_text("def launch():\n    return [python," + repr(token) + "]\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site " + package_name + "/probe.py:launch"


def test_selector_site_git_argv_and_message_require_rows(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("MESSAGE='git -c cannot carry'\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:<module>"
    assert process_sites(tmp_path, selector_table=((
        "aegis_core/probe.py", "<module>", "lexer-or-message", "Reviewed Git option message."),)) == {}
    path.write_text("argv=['git','-c','core.x=y']\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:<module>"
    assert process_sites(tmp_path, selector_table=((
        "aegis_core/probe.py", "<module>", "git-config", "Fixed Git configuration data."),)) == {}


def test_selector_site_scope_and_resolved_spawn_counting(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import subprocess, sys\nclass Outer:\n    FLAGS=['-Ic']\n    def launch(self):\n"
        "        def inner():\n            return ['python','-cpass']\n"
        "        subprocess.run([sys.executable,'-c',\"import os; os.system('id')\"])\n", encoding="utf-8")
    table = tuple(("aegis_core/probe.py", name, "resolved-python-program", "Test-owned literal program.")
                  for name in ("Outer", "Outer.launch", "Outer.launch.inner"))
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 1
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("case", ["text", "words"])
def test_selector_site_limits_refuse_without_echoing_text(tmp_path, case, monkeypatch):
    from types import SimpleNamespace

    package = tmp_path / "aegis_core"
    package.mkdir()
    text = "x" * (_MAX_TEXT + 1) if case == "text" else "echo " + "word " * _MAX_WORDS + "python3 -c pass"
    (package / "probe.py").write_text("MESSAGE=" + repr(text) + "\n", encoding="utf-8")
    if case == "text":
        def forbidden_lexer(*args, **kwargs):
            pytest.fail("text limit must precede shell lexing")
        monkeypatch.setattr("tests.contract.test_process_ratchets.shlex", SimpleNamespace(shlex=forbidden_lexer))
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "selector site limit aegis_core/probe.py:<module>"


@pytest.mark.parametrize("kind,reason,duplicate,message", [
    ("unknown", "review", False, "invalid selector row"),
    ("reviewed-dynamic", "", False, "invalid selector row"),
    ("reviewed-dynamic", "line1\nline2", False, "invalid selector row"),
    ("reviewed-dynamic", "review", True, "duplicate selector site"),
])
def test_selector_site_table_metadata_refuses(tmp_path, kind, reason, duplicate, message):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("FLAGS=['-c']\n", encoding="utf-8")
    row = ("aegis_core/probe.py", "<module>", kind, reason)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=(row, row) if duplicate else (row,))
    assert str(error.value) == message + " aegis_core/probe.py:<module>"


@pytest.mark.parametrize("body", [
    "subprocess.run(P, shell=True, executable=sys.executable, **{})",
    "subprocess.run([sys.executable, '-m', f'aegis_core.{name}'])",
    "subprocess.run([sys.executable, '-m', 'aegis_sdk.missing'])",
    "subprocess.run([sys.executable, '-m', 'aegis_core'])",
    "subprocess.run([sys.executable, '-m', 'aegis_cli'])",
    "subprocess.run([sys.executable, '-m', 'aegis_core.not_censused'])",
])
def test_selector_site_round8_gaps_require_review(tmp_path, body):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys, subprocess\nP='pass'\ndef launch(name=None):\n    " + body + "\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    table = (("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned review of the extended site."),)
    assert process_sites(tmp_path, selector_table=table)["process:aegis_core/probe.py:launch:subprocess.run"] == [4]


@pytest.mark.parametrize("expression,selected", [
    ("subprocess.run(argv, executable=sys.executable)", True),
    ("subprocess.run(argv, executable='python3.12')", True),
    ("subprocess.run(argv, executable='/trusted/python.exe')", True),
    ("subprocess.run(argv, executable=program)", True),
    ("subprocess.run(argv, executable=None)", True),
    ("subprocess.run(argv, executable='sh')", True),
    ("subprocess.run(argv, executable='/trusted/git')", False),
    ("ordinary(argv, executable=sys.executable)", True),
    ("[sys.executable, '-m', 'pytest']", True),
    ("[sys.executable, '-m', 'coverage']", True),
    ("[sys.executable, '-m', 'pip']", True),
    ("[sys.executable, '-m', 'aegis_core_extra.worker']", True),
    ("[sys.executable, '-m', 'aegis_mcp.server']", True),
    ("(sys.executable, '-m', 'tools.worker')", True),
    ("[sys.executable, '-m'] + [target]", True),
    ("(sys.executable,) + ('-m',) + ('aegis_cli',)", True),
    ("[sys.executable, '-m'] + tail", True),
    ("[sys.executable, '-m'] + ['pytest']", True),
    ("{'flag': '-m', 'target': 'aegis_core'}", True),
])
def test_selector_site_round8_predicate_boundaries(tmp_path, expression, selected):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("import sys, subprocess\ndef launch(argv, program, target, tail):\n    " + expression + "\n", encoding="utf-8")
    if selected:
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    else:
        assert selector_sites(dict(module_trees(tmp_path))) == {}
        process_sites(tmp_path)


_FORMAL_0554_CASES = {
    "interpolated_interpreter": ("", "subprocess.run(f'{sys.executable} -c {shlex.quote(P)}', shell=mode)", "launch", "subprocess.run"),
    "named_keywords": ("", "options={'shell':True,'executable':sys.executable}\nsubprocess.run(P, **options)", "launch", "subprocess.run"),
    "literal_keywords": ("", "subprocess.run(P, **{'shell':True,'executable':sys.executable})", "launch", "subprocess.run"),
    "forwarded_keywords": ("", "def forward(options):\n    subprocess.run(P, **options)\nforward(options)", "launch.forward", "subprocess.run"),
    "bundled_attached": ("", "os.execl(sys.executable, 'worker', *[\"-Icimport os; os.system('id')\"])", "launch", "os.execl"),
    "starred_module": ("", "subprocess.run([sys.executable, *['-m'], target])", "launch", "subprocess.run"),
    "named_module_prefix": ("", "PREFIX=[sys.executable, '-m']\nsubprocess.run([*PREFIX, target])", "launch", "subprocess.run"),
    "imported_module_prefix": ("from aegis_core.shared import PREFIX\n", "subprocess.run([*PREFIX, target])", "<module>", "subprocess.run"),
    "positional_popen": ("", "subprocess.Popen(P, -1, sys.executable, shell=mode)", "launch", "subprocess.Popen"),
    "starred_call": ("", "subprocess.run(*arguments)", "launch", "subprocess.run"),
    "starred_spawn": ("", "os.posix_spawn(*arguments)", "launch", "os.posix_spawn"),
    "security_quoted_interpreter": ("", "subprocess.run(f'\"{sys.executable}\" -c {shlex.quote(P)}', shell=mode)", "launch", "subprocess.run"),
    "security_attached_empty_star": ("", "os.execl(sys.executable, 'worker', '-Icimport os; os.system(\"id\")', *())", "launch", "os.execl"),
    "security_redirected_shell": ("", "os.system('printf x#y; python3>/dev/null -c ' + shlex.quote(P))", "launch", "os.system"),
    "argon_attached_fstring": ("", "subprocess.run(f'python3 -c\"{P}\"', shell=mode)", "launch", "subprocess.run"),
    "argon_attached_concat": ("", "os.system('python3 -c\"' + P + '\"')", "launch", "os.system"),
    "argon_quoted_python": ("", "os.system(f'\"{sys.executable}\" -c {P!r}')", "launch", "os.system"),
    "argon_quoted_path": ("", "os.system(f'cd \"{path}\" && python3 -c {P!r}')", "launch", "os.system"),
    "argon_concat_interpreter": ("", "os.system(sys.executable + ' -c ' + shlex.quote(P))", "launch", "os.system"),
    "argon_hash_shell": ("", "os.system(f'printf x#y; {sys.executable} -c {P!r}')", "launch", "os.system"),
    "argon_default_shell": ("", "def invoke(code=P):\n    os.system(f'{sys.executable} -c {code}')", "launch.invoke", "os.system"),
    "argon_bundled_shell": ("", "subprocess.run(\"python3 -Ic'import subprocess; subprocess.Popen([\\\"/bin/true\\\"])'\", shell=mode)", "launch", "subprocess.run"),
    "argon_mutated_bundle": ("", "ARGV=[sys.executable]\nARGV.append(\"-Icimport subprocess; subprocess.Popen(['/bin/true'])\")\nsubprocess.run(ARGV)", "launch", "subprocess.run"),
    "argon_default_bundle": ("", "def invoke(code=P):\n    subprocess.run([sys.executable, f'-Ic {code}'])", "launch.invoke", "subprocess.run"),
    "argon_shell_flags": ("", "subprocess.run(['sh', '-ecx', P])", "launch", "subprocess.run"),
    "argon_run_positional_expansion": ("", "subprocess.run(P, -1, sys.executable, shell=True, **{})", "launch", "subprocess.run"),
    "argon_run_positional_default": ("", "def invoke(code=P):\n    subprocess.run(code, -1, sys.executable, shell=True)", "launch.invoke", "subprocess.run"),
    "argon_override_mapping": ("", "subprocess.run(P, shell=True, **{'executable': sys.executable})", "launch", "subprocess.run"),
    "argon_bundled_module": ("", "subprocess.run([sys.executable, '-Im', 'aegis_core.not_censused'])", "launch", "subprocess.run"),
    "argon_attached_module": ("", "subprocess.run([sys.executable, '-maegis_core.not_censused'])", "launch", "subprocess.run"),
    "argon_interpolated_module": ("", "subprocess.run([sys.executable, f'-m{name}'])", "launch", "subprocess.run"),
    "argon_shell_module": ("", "subprocess.run('python3 -m aegis_core.not_censused', shell=True)", "launch", "subprocess.run"),
    "argon_variadic_module": ("", "os.execl(sys.executable, 'python3', '-m', 'aegis_core.not_censused')", "launch", "os.execl"),
    "argon_concat_module": ("", "PREFIX=[sys.executable, '-m']\nsubprocess.run(PREFIX + ['aegis_core.not_censused'])", "launch", "subprocess.run"),
    "argon_mutated_module": ("", "ARGV=[sys.executable, '-m']\nARGV.append('aegis_core.not_censused')\nsubprocess.run(ARGV)", "launch", "subprocess.run"),
}


@pytest.mark.parametrize("case", list(_FORMAL_0554_CASES))
def test_selector_site_formal_0554_requires_review(tmp_path, case):
    package = tmp_path / "aegis_core"
    package.mkdir()
    prefix, body, scope, api = _FORMAL_0554_CASES[case]
    if prefix:
        (package / "shared.py").write_text("import sys\nPREFIX=[sys.executable, '-m']\n", encoding="utf-8")
    (package / "probe.py").write_text(
        "import os, sys, subprocess, shlex\nP=\"import os; os.system('id')\"\n" + prefix
        + "def launch(mode=True, options=None, target=None, arguments=None, name=None, path=None):\n"
        + "".join("    " + line + "\n" for line in body.splitlines()), encoding="utf-8")
    rel = "aegis_core/shared.py" if prefix else "aegis_core/probe.py"
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site " + rel + ":" + scope
    table = ((rel, scope, "reviewed-dynamic", "Test-owned broad-site review."),)
    sites = process_sites(tmp_path, selector_table=table)
    caller = "launch" if scope == "<module>" else scope
    assert "process:aegis_core/probe.py:" + caller + ":" + api in sites


@pytest.mark.parametrize("text,selected", [
    (" -c ", True), ("-Icimport os; os.system('id')", True),
    ("message=-mworker", True), ("git -c cannot carry", True),
    ("# python3 -c pass", True), ("'-IEcprint(1)'", True),
    ("-mod=vendor", True), ("-count=1", True), ("-march=native", True),
    ("--command", False), ("--module", False), ("x--cm", False),
    ("prefix-c", False), ("-C", False), ("plain text", False),
])
def test_selector_site_broad_literal_boundaries(tmp_path, text, selected):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("VALUE=" + repr(text) + "\n", encoding="utf-8")
    if selected:
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site aegis_core/probe.py:<module>"
        assert process_sites(tmp_path, selector_table=((
            "aegis_core/probe.py", "<module>", "native-option", "Test-owned option text."),)) == {}
    else:
        assert process_sites(tmp_path) == {}


def test_selector_site_expansion_requires_a_spawn_api(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("def helper(arguments, options):\n    ordinary(*arguments, **options)\n", encoding="utf-8")
    assert process_sites(tmp_path) == {}


def test_literal_spawn_occurrences_keep_function_provenance(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    program = "import os; os.system('id')"
    def source(second):
        return ("import sys,subprocess\ndef a():\n    subprocess.run([sys.executable,'-c',"
                + repr(program) + "])\ndef b():\n    subprocess.run([sys.executable,'-c'," + repr(second) + "])\n")
    table = tuple(("aegis_core/probe.py", name, "resolved-python-program", "Test-owned literal occurrence.")
                  for name in ("a", "b"))
    path.write_text(source("pass"), encoding="utf-8")
    before = process_sites(tmp_path, selector_table=table)
    record = {key: {"count": len(lines), "reason": "Test-owned process inventory."} for key, lines in before.items()}
    path.write_text(source(program), encoding="utf-8")
    after = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in after.items() if key.endswith(":os.system")) == 2
    assert any("unreviewed process:aegis_core/probe.py:b." in error for error in census_errors(after, record))


def test_literal_spawn_occurrences_on_one_line_are_distinct(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "import os; os.system('id')"
    call = "subprocess.run([sys.executable,'-c'," + repr(program) + "])"
    (package / "probe.py").write_text("import sys,subprocess\ndef launch():\n    " + call + "; " + call + "\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Two test-owned literal occurrences."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 2


def test_literal_spawn_count_recurses_into_nested_programs(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    def source(inner):
        program = "import sys,subprocess\nsubprocess.run([sys.executable,'-c'," + repr(inner) + "])"
        return "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n"
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned nested literal programs."),)
    path.write_text(source("pass"), encoding="utf-8")
    before = process_sites(tmp_path, selector_table=table)
    record = {key: {"count": len(lines), "reason": "Test-owned process inventory."} for key, lines in before.items()}
    path.write_text(source("import os; os.system('id')"), encoding="utf-8")
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
    assert any("unreviewed process:" in error and error.endswith(":os.system at lines [3]") for error in census_errors(sites, record))


@pytest.mark.parametrize("api", sorted(RAW))
def test_selector_site_wildcard_import_requires_review_and_counts(tmp_path, api):
    package = tmp_path / "aegis_core"
    package.mkdir()
    module, name = api.split(".")
    (package / "probe.py").write_text(
        "from " + module + " import *\ndef launch(command):\n    " + name + "(command)\n"
        + "def shadowed(" + name + "):\n    " + name + "('data')\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:<module>"
    table = (("aegis_core/probe.py", "<module>", "reviewed-dynamic", "Test-owned wildcard spawn import."),)
    assert process_sites(tmp_path, selector_table=table) == {"process:aegis_core/probe.py:launch:" + api: [3]}


@pytest.mark.parametrize("program,api", [
    ("from subprocess import *; Popen(['/bin/true'])", "subprocess.Popen"),
    ("from os import *; system('id')", "os.system"),
])
def test_literal_spawn_wildcard_import_is_counted(tmp_path, program, api):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n",
        encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned wildcard literal program."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":" + api)) == 1


@pytest.mark.parametrize("source,scope", [
    ("def launch():\n    runner=subprocess.run\n    runner(P, **{'shell': True, 'executable': sys.executable})\n", "launch"),
    ("def launch(runner=subprocess.run):\n    runner(P, **opts)\n", "launch"),
    ("def launch():\n    functools.partial(subprocess.run, **options)(P)\n", "launch"),
    ("runner=subprocess.run\nrunner(P, **opts)\n", "<module>"),
    ("@factory(subprocess.run)\ndef launch():\n    runner(P, **opts)\n", "launch"),
    ("@factory(**options)\ndef launch(runner=subprocess.run):\n    runner(P)\n", "launch"),
    ("from subprocess import run\ndef launch():\n    runner=run\n    runner(P, **opts)\n", "launch"),
    ("class Holder:\n    runner=subprocess.run\n    runner(P, **opts)\n", "Holder"),
    ("def outer():\n    def inner(runner=subprocess.run):\n        runner(P, **opts)\n", "outer.inner"),
    ("def launch():\n    runner=subprocess.run\n    ordinary(*arguments)\n", "launch"),
    ("def launch(code, runner=subprocess.run):\n    return runner(code, **{'shell':True,'executable':sys.executable})\nlaunch(P)\n", "launch"),
    ("def launch(code, runner=subprocess.run):\n    return runner(*[code], **options)\nlaunch(P)\n", "launch"),
    ("def launch(code, runner=subprocess.run):\n    return runner(code, -1, *[sys.executable], shell=True)\nlaunch(P)\n", "launch"),
    ("def launch(code, runner=subprocess.run):\n    return runner(code, -1, sys.executable, shell=True)\nlaunch(P)\n", "launch"),
    ("def launch():\n    spawn=subprocess.Popen\n    spawn(P, -1, sys.executable, shell=True)\n", "launch"),
])
def test_selector_site_formal_0640_alias_free_expansion(tmp_path, source, scope):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess,functools\nP=\"import os; os.system('id')\"\n" + source, encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site aegis_core/probe.py:" + scope
    table = (("aegis_core/probe.py", scope, "reviewed-dynamic", "Test-owned expanded spawn-reference scope."),)
    sites = process_sites(tmp_path, selector_table=table)
    api = "subprocess.Popen" if "subprocess.Popen" in source else "subprocess.run"
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":" + api)) == 1


def test_selector_site_expansions_require_review_across_sibling_scopes(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import subprocess\ndef reference():\n    return subprocess.run\n"
        "def expansion(options):\n    ordinary(**options)\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:expansion"
    table = (("aegis_core/probe.py", "expansion", "reviewed-dynamic", "Test-owned module-wide expansion."),)
    assert process_sites(tmp_path, selector_table=table) == {"process:aegis_core/probe.py:reference:subprocess.run": [3]}


@pytest.mark.parametrize("call", [
    "subprocess.run(['sh','-c',P], executable=sys.executable)",
    "subprocess.Popen(['sh','-c',P], executable=sys.executable)",
    "subprocess.call(['sh','-c',P], executable=sys.executable)",
    "subprocess.check_call(['sh','-c',P], executable=sys.executable)",
    "subprocess.check_output(['sh','-c',P], executable=sys.executable)",
    "os.execv(sys.executable, ['sh','-c',P])",
    "os.execve(sys.executable, ['sh','-c',P], {})",
    "os.execvp(sys.executable, ['sh','-c',P])",
    "os.execvpe(sys.executable, ['sh','-c',P], {})",
    "os.spawnv(os.P_WAIT, sys.executable, ['sh','-c',P])",
    "os.spawnve(os.P_WAIT, sys.executable, ['sh','-c',P], {})",
    "os.spawnvp(os.P_WAIT, sys.executable, ['sh','-c',P])",
    "os.spawnvpe(os.P_WAIT, sys.executable, ['sh','-c',P], {})",
    "os.posix_spawn(sys.executable, ['sh','-c',P], {})",
    "os.posix_spawnp(sys.executable, ['sh','-c',P], {})",
])
@pytest.mark.parametrize("nested", [False, True], ids=["direct", "nested"])
@pytest.mark.parametrize("reverse", [False, True], ids=["python-executable", "shell-executable"])
def test_literal_spawn_formal_0640_effective_executable(tmp_path, call, nested, reverse):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "import os; os.system('id')"
    if reverse:
        program = "python3 -c " + shlex.quote(program)
    call = call.replace("['sh','-c',P]", "[HEAD,'-c',P]").replace("sys.executable", "EXEC")
    bindings = "EXEC='sh'; HEAD=sys.executable\n" if reverse else "EXEC=sys.executable; HEAD='sh'\n"
    body = "import os,sys,subprocess\n" + bindings + "P=" + repr(program) + "\n" + call + "\n"
    source = ("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',"
              + repr(body) + "])\n") if nested else (
                  "import os,sys,subprocess\n" + bindings + "P=" + repr(program) + "\ndef launch():\n    " + call + "\n")
    (package / "probe.py").write_text(source, encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned effective interpreter."),)
    if reverse and not nested:
        table += (("aegis_core/probe.py", "<module>", "resolved-python-program", "Test-owned shell program constant."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
    assert all(":launch." in key for key in sites if key.endswith(":os.system"))


@pytest.mark.parametrize("head", ["sys.executable", "'sh'"])
def test_literal_spawn_launch_and_inline_argv_count_once(tmp_path, head):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([" + head
        + ",'-c',\"import os; os.system('id')\"], executable=sys.executable)\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned single literal occurrence."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("provider", ["shared", "probe", "relative"])
@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_nested_import_keeps_package_context(tmp_path, provider, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / ("probe.py" if provider == "probe" else "shared.py")
    target = ".shared" if provider == "relative" else "aegis_core." + provider
    program = "import sys,subprocess\nfrom " + target + " import CODE\nsubprocess.run([sys.executable,'-c',CODE])\n"
    owners = ("launch", "other")[:copies]
    launch = "import sys,subprocess\n" + "".join(
        "def " + name + "():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n" for name in owners)
    table = tuple(("aegis_core/probe.py", name, "resolved-python-program", "Test-owned nested package constant.")
                  for name in owners)
    def write(code):
        definition = "CODE=" + repr(code) + "\n"
        path.write_text(definition + (launch if provider == "probe" else ""), encoding="utf-8")
        if provider != "probe":
            (package / "probe.py").write_text(launch, encoding="utf-8")
    write("pass")
    before = process_sites(tmp_path, selector_table=table)
    record = {key: {"count":len(lines), "reason":"Test-owned inventory."} for key, lines in before.items()}
    write("import os; os.system('id')")
    after = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in after.items() if key.endswith(":os.system")) == copies
    assert any("unreviewed process:aegis_core/probe.py:launch." in error and ":os.system" in error
               for error in census_errors(after, record))


@pytest.mark.parametrize("body", [
    "subprocess.run([sys.executable, *['-c',P]])",
    "subprocess.run((sys.executable, *('-c',P)))",
    "FRAGMENT=['-c',P]\nsubprocess.run([sys.executable, *FRAGMENT])",
    "FRAGMENT=('-c',P)\nsubprocess.run((sys.executable,) + FRAGMENT)",
    "PREFIX=[sys.executable]\nFRAGMENT=['-c',P]\nsubprocess.run(PREFIX + FRAGMENT)",
    "ARGV=[sys.executable,'-c',P]\nsubprocess.run(ARGV)",
    "ARGV=[sys.executable,'-c',P]\nALIAS=ARGV\nsubprocess.run(ALIAS)",
])
def test_literal_spawn_flattened_fragments_count_once(tmp_path, body):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\nP=\"import os; os.system('id')\"\ndef launch():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()), encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned flattened occurrence."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("imported", [False, True], ids=["local", "imported"])
@pytest.mark.parametrize("same_owner", [False, True], ids=["two-functions", "same-function"])
def test_literal_spawn_shared_argv_keeps_each_launch(tmp_path, imported, same_owner):
    package = tmp_path / "aegis_core"
    package.mkdir()
    definition = "import sys\nARGV=[sys.executable,'-c',\"import os; os.system('id')\"]\n"
    if imported:
        (package / "shared.py").write_text(definition, encoding="utf-8")
    prefix = "from aegis_core.shared import ARGV\n" if imported else definition
    path = package / "probe.py"
    table = (("aegis_core/shared.py" if imported else "aegis_core/probe.py", "<module>",
              "resolved-python-program", "Test-owned shared argv construction."),)
    def write(second):
        source = prefix + "import subprocess\ndef a():\n    subprocess.run(ARGV)\n"
        source += "    " if same_owner else "def b():\n    "
        path.write_text(source + "subprocess.run(" + second + ")\n", encoding="utf-8")
    write("['true']")
    before = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in before.items() if key.endswith(":os.system")) == 1
    record = {key:{"count":len(lines),"reason":"Test-owned process rows."} for key,lines in before.items()}
    write("ARGV")
    after = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in after.items() if key.endswith(":os.system")) == 2
    assert any("unreviewed process:" in error and ":os.system" in error for error in census_errors(after, record))


@pytest.mark.parametrize("tail", ["extra", "[]"])
def test_literal_spawn_constant_prefix_survives_concatenation(tmp_path, tail):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\nP=\"import os; os.system('id')\"\ndef launch(extra):\n"
        + "    subprocess.run([sys.executable,'-I','-c',P] + " + tail + ")\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned constant program prefix."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


def test_literal_spawn_argon_native_head_shell_override(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\nP=\"import os; os.system('id')\"\ndef launch():\n"
        + "    subprocess.run(['worker','-c',f'python3 -c {P!r}'], executable='/bin/sh')\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned shell executable override."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("inner", [
    "subprocess.run(P, **{'shell':True,'executable':sys.executable})",
    "FLAGS=['-I']; FLAGS.append('-c'); subprocess.run([sys.executable,*FLAGS,P])",
])
def test_selector_site_argon_nested_dynamic_program_requires_owner(tmp_path, inner):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "import sys,subprocess\nP=\"import os; os.system('id')\"\n" + inner
    (package / "probe.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n",
        encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    table = (("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned review of the nested dynamic construction."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("source,owners", [
    ("runner=subprocess.run\ndef launch():\n    runner(P, **options)\n", ("launch",)),
    ("def outer():\n    runner=subprocess.run\n    def launch():\n        runner(P, **options)\n", ("outer.launch",)),
    ("def outer(runner=subprocess.run):\n    def launch():\n        runner(P, **options)\n", ("outer.launch",)),
    ("class Holder:\n    runner=staticmethod(subprocess.run)\n    def launch(self):\n        self.runner(P, **options)\n", ("Holder.launch",)),
    ("def launch(callback):\n    callback(P, **options)\nlaunch(callback=subprocess.run)\n", ("launch",)),
    ("from subprocess import run\ndef launch():\n    ordinary(**options)\n", ("launch",)),
    ("from os import system\ndef launch():\n    ordinary(*arguments)\n", ("launch",)),
    ("from subprocess import *\ndef launch():\n    ordinary(**options)\n", ("<module>", "launch")),
    ("runner=subprocess.run\ndef outer():\n    class Inner:\n        ordinary(**options)\n", ("outer.Inner",)),
])
def test_selector_site_formal_0728_module_wide(tmp_path, source, owners):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("import sys,subprocess\nP=\"import os; os.system('id')\"\n" + source, encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site aegis_core/probe.py:" + sorted(owners)[0]
    table = tuple(("aegis_core/probe.py", owner, "reviewed-dynamic", "Test-owned module-wide callback review.")
                  for owner in owners)
    process_sites(tmp_path, selector_table=table)


@pytest.mark.parametrize("prefix", ["import subprocess", "from subprocess import PIPE", "from os import path"])
def test_selector_site_module_without_spawn_reference_accepts_expansion(tmp_path, prefix):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(prefix + "\ndef launch():\n    ordinary(**options)\n", encoding="utf-8")
    assert process_sites(tmp_path) == {}


@pytest.mark.parametrize("call", [
    "subprocess.run([sys.executable,b'-c',P])",
    "subprocess.Popen([sys.executable,b'-c',P])",
    "subprocess.call([sys.executable,b'-c',P])",
    "subprocess.check_call([sys.executable,b'-c',P])",
    "subprocess.check_output([sys.executable,b'-c',P])",
    "os.execv(sys.executable,[b'worker',b'-c',P])",
    "os.execve(sys.executable,[b'worker',b'-c',P],{})",
    "os.execvp(sys.executable,[b'worker',b'-c',P])",
    "os.execvpe(sys.executable,[b'worker',b'-c',P],{})",
    "os.spawnv(os.P_WAIT,sys.executable,[b'worker',b'-c',P])",
    "os.spawnve(os.P_WAIT,sys.executable,[b'worker',b'-c',P],{})",
    "os.spawnvp(os.P_WAIT,sys.executable,[b'worker',b'-c',P])",
    "os.spawnvpe(os.P_WAIT,sys.executable,[b'worker',b'-c',P],{})",
    "os.posix_spawn(sys.executable,[b'worker',b'-c',P],{})",
    "os.posix_spawnp(sys.executable,[b'worker',b'-c',P],{})",
    "os.execl(sys.executable,b'worker',b'-c',P)",
    "os.spawnl(os.P_WAIT,sys.executable,b'worker',b'-c',P)",
    "subprocess.run([sys.executable,*[b'-c',P]])",
    "subprocess.run((sys.executable,) + (b'-c',P))",
])
@pytest.mark.parametrize("bytes_program", [False, True], ids=["str-program", "bytes-program"])
def test_selector_site_formal_0728_bytes_argv_and_programs(tmp_path, call, bytes_program):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "import os; os.system('id')"
    if bytes_program:
        program = program.encode("utf-8")
    (package / "probe.py").write_text(
        "import os,sys,subprocess\nP=" + repr(program) + "\ndef launch():\n    " + call + "\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned byte argv program."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("call", ["os.system(CMD)", "subprocess.getoutput(CMD)", "subprocess.getstatusoutput(CMD)",
                                  "subprocess.run(CMD,shell=True)", "subprocess.Popen(CMD,shell=True)"])
def test_selector_site_formal_0728_byte_shell_commands(tmp_path, call):
    package = tmp_path / "aegis_core"
    package.mkdir()
    command = ('python3 -c "import os; os.system(\'id\')"').encode("ascii")
    (package / "probe.py").write_text(
        "import os,subprocess\ndef launch():\n    CMD=" + repr(command) + "\n    " + call + "\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned byte shell command."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == (2 if call.startswith("os.system") else 1)


def test_literal_spawn_utf8_byte_program_is_counted(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "π=1; import os; os.system('id')".encode("utf-8")
    (package / "probe.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,b'-c',"
                                     + repr(program) + "])\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned UTF-8 byte program."),)
    assert sum(len(lines) for key,lines in process_sites(tmp_path,selector_table=table).items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("call", ["subprocess.run(CMD)", "os.execv(EXEC,CMD)",
                                  "os.spawnv(os.P_WAIT,EXEC,CMD)", "os.posix_spawn(EXEC,CMD,{})"])
@pytest.mark.parametrize("shape", ["shell", "reexport", "loop", "comprehension"])
@pytest.mark.parametrize("nested", [False, True], ids=["direct", "nested"])
def test_literal_spawn_formal_0728_launch_site_dedup(tmp_path, call, shape, nested):
    package = tmp_path / "aegis_core"
    package.mkdir()
    head = "'sh'" if shape == "shell" else "sys.executable"
    definition = "P=\"import os; os.system('id')\"\nEXEC=" + head + "\n"
    imports = "import os,sys,subprocess,shlex\n"
    owners = []
    if shape == "reexport":
        (package / "base.py").write_text(definition.replace("EXEC=sys.executable\n", "") + "FRAGMENT=['-c',P]\n", encoding="utf-8")
        (package / "relay.py").write_text("from .base import FRAGMENT\n", encoding="utf-8")
        imports += "from aegis_core.relay import FRAGMENT\n"
        body = "CMD=[sys.executable,*FRAGMENT]\n" + call
        owners.append(("aegis_core/base.py", "<module>"))
    elif shape == "shell":
        body = "CMD=['sh','-c','python3 -c '+shlex.quote(P)]\n" + call
    else:
        body = "ARGV=[sys.executable,'-c',P]\n"
        body += "for CMD in [ARGV,ARGV]:\n    " + call if shape == "loop" else "[" + call + " for CMD in [ARGV,ARGV]]"
    if nested:
        program = imports + definition + body
        source = "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n"
    else:
        source = imports + definition + "def launch():\n" + "".join("    " + line + "\n" for line in body.splitlines())
    if nested or shape != "reexport" or not call.startswith("subprocess.run"):
        owners.append(("aegis_core/probe.py", "launch"))
    (package / "probe.py").write_text(source, encoding="utf-8")
    table = tuple((rel,owner,"resolved-python-program","Test-owned launch-site deduplication.") for rel,owner in owners)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("selector,script", [
    ("-c", "'python3 -c '+shlex.quote(P)"),
    ("-c", repr('python3 -c "import os; os.system(\'id\')"\n')),
    ("-ecx", "'python3 -c '+shlex.quote(P)"),
])
@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_shell_vector_uses_launch_occurrences(tmp_path, selector, script, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    call = "    subprocess.run(['sh'," + repr(selector) + "," + script + "])\n"
    (package / "probe.py").write_text("import subprocess,shlex\nP=\"import os; os.system('id')\"\ndef launch():\n"
                                     + call * copies, encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned shell launch occurrences."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies


@pytest.mark.parametrize("selector", [b"-c", b"-Ic", b"-IEc"])
def test_literal_spawn_byte_interpreter_and_bundled_selector(tmp_path, selector):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "π=1; import os; os.system('id')".encode("utf-8")
    (package / "probe.py").write_text("import subprocess\ndef launch():\n    subprocess.run([b'python3',"
                                     + repr(selector) + "," + repr(program) + "])\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned byte interpreter options."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("oversized", [False, True], ids=["latin1", "limit"])
def test_selector_site_byte_metadata_and_limit(tmp_path, oversized):
    package = tmp_path / "aegis_core"
    package.mkdir()
    value = b"\xff -c" if not oversized else b"x" * (_MAX_TEXT + 1)
    (package / "probe.py").write_text("MESSAGE=" + repr(value) + "\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    expected = "selector site limit" if oversized else "unreviewed selector site"
    assert str(error.value) == expected + " aegis_core/probe.py:<module>"
    if not oversized:
        table = (("aegis_core/probe.py", "<module>", "lexer-or-message", "Test-owned Latin-1 byte metadata."),)
        assert process_sites(tmp_path, selector_table=table) == {}


def test_literal_spawn_invalid_byte_program_returns_only_outer_site(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,b'-c',b'\\xff'])\n",
                                     encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned invalid byte program."),)
    assert process_sites(tmp_path, selector_table=table) == {"process:aegis_core/probe.py:launch:subprocess.run": [3]}


@pytest.mark.parametrize("staged", [False, True], ids=["inline", "named"])
@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_argon_0728_imported_tail_is_counted(tmp_path, staged, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "shared.py").write_text("P=\"import os; os.system('id')\"\nTAIL=[P]\n", encoding="utf-8")
    body = "ARGV=[sys.executable,'-c',*TAIL]\n" if staged else ""
    command = "ARGV" if staged else "[sys.executable,'-c',*TAIL]"
    body += ("subprocess.run(" + command + ", **opts)\n") * copies
    (package / "probe.py").write_text("import sys,subprocess\nfrom aegis_core.shared import TAIL\ndef launch(opts):\n"
                                     + "".join("    " + line + "\n" for line in body.splitlines()), encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned resolved argv with expanded options."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies


@pytest.mark.parametrize("flag", ["-W", "-X", "--check-hash-based-pycs"])
@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_argon_0728_option_value_is_not_selector(tmp_path, flag, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    call = "    subprocess.run([sys.executable," + repr(flag) + ",'-c','-c',P])\n"
    (package / "probe.py").write_text("import sys,subprocess\nP=\"import os; os.system('id')\"\ndef launch():\n"
                                     + call * copies, encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned interpreter option argument."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies


@pytest.mark.parametrize("source", [
    "def launch(flag='-c',code=P):\n    return [sys.executable,flag,code]\n",
    "def launch(flag=b'-c',code=P):\n    return [sys.executable,flag,code]\n",
    "@factory('-c')\ndef launch():\n    pass\n",
    "def launch(flag:'-c'):\n    pass\n",
    "def launch()->'-c':\n    pass\n",
    "def launch(recipe=factory(executable=sys.executable)):\n    return recipe\n",
])
def test_selector_site_argon_0728_signature_needs_function_row(tmp_path, source):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("import sys\nMESSAGE='python -m pytest'\nP='pass'\n" + source, encoding="utf-8")
    module_row = ("aegis_core/probe.py", "<module>", "lexer-or-message", "Test-owned module help message.")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=(module_row,))
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    function_row = ("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned signature selector.")
    assert process_sites(tmp_path, selector_table=(module_row,function_row)) == {}


@pytest.mark.parametrize("argument", [
    "[sys.executable,'-c',CODE,*args]",
    "[sys.executable,'-c',CODE] + args",
    "[sys.executable,'-c',CODE], **opts",
])
def test_literal_spawn_argon_0728_nested_dynamic_argv_is_site(tmp_path, argument):
    package = tmp_path / "aegis_core"
    package.mkdir()
    code = "import sys,subprocess\nsubprocess.run(sys.argv[1:])\n"
    argument = argument.replace("CODE",repr(code))
    (package / "probe.py").write_text("import sys,subprocess\ndef launch(args,opts):\n    subprocess.run(" + argument + ")\n",
                                     encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned nested program with dynamic child argv."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":subprocess.run")) == 2
    child = [(key,lines) for key,lines in sites.items() if ":launch.<literal-c-" in key]
    assert len(child) == 1 and child[0][1] == [3]


@pytest.mark.parametrize("api", ["run", "Popen", "call", "check_call", "check_output"])
@pytest.mark.parametrize("positional", [False, True], ids=["keyword-none", "positional-none"])
@pytest.mark.parametrize("byte_argv", [False, True], ids=["str-argv", "byte-argv"])
@pytest.mark.parametrize("loop", [False, True], ids=["direct", "loop"])
@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_formal_0821_none_executable_counts_once(tmp_path, api, positional, byte_argv, loop, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    command = "python3 -c " + shlex.quote("import os; os.system('id')")
    argv = ["sh", "-ec", command]
    if byte_argv:
        argv = [part.encode("utf-8") for part in argv]
    call = "subprocess." + api + ("(CMD,-1,None)" if positional else "(CMD,executable=None)")
    body = ("for CMD in [ARGV,ARGV]:\n" + "".join("    " + call + "\n" for _ in range(copies))) if loop else (
        "CMD=ARGV\n" + (call + "\n") * copies)
    (package / "probe.py").write_text("import subprocess\nARGV=" + repr(argv) + "\ndef launch():\n"
                                     + "".join("    " + line + "\n" for line in body.splitlines()), encoding="utf-8")
    table = tuple(("aegis_core/probe.py", owner, "resolved-python-program", "Test-owned explicit default executable.")
                  for owner in ("<module>","launch"))
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies
    assert all(":launch." in key for key in sites if key.endswith(":os.system"))


@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_formal_0821_late_origins_are_merged(tmp_path, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    argv = ["sh","-ec","python3 -c " + shlex.quote("import os; os.system('id')")]
    call = "    subprocess.run([*[*ARGV],*extra],executable='sh')\n"
    (package / "probe.py").write_text("import subprocess\nARGV=" + repr(argv) + "\ndef launch(extra):\n" + call * copies,
                                     encoding="utf-8")
    table = tuple(("aegis_core/probe.py", owner, "resolved-python-program", "Test-owned late construction origins.")
                  for owner in ("<module>","launch"))
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies
    assert all(":launch." in key for key in sites if key.endswith(":os.system"))


@pytest.mark.parametrize("copies", [4, 5])
def test_literal_spawn_occurrence_buffer_limit(tmp_path, monkeypatch, copies):
    monkeypatch.setattr("tests.contract.test_process_ratchets._MAX_WORDS",4)
    package = tmp_path / "aegis_core"
    package.mkdir()
    call = "    subprocess.run([sys.executable,'-c',\"import os; os.system('id')\"])\n"
    (package / "probe.py").write_text("import sys,subprocess\ndef launch():\n" + call * copies, encoding="utf-8")
    table = (("aegis_core/probe.py","launch","resolved-python-program","Test-owned bounded occurrence collection."),)
    if copies == 5:
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == "aegis_core/probe.py: literal occurrence limit"
    else:
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies


@pytest.mark.parametrize("api", ["run", "Popen", "call", "check_call", "check_output"])
@pytest.mark.parametrize("positional", [False, True], ids=["keyword-executable", "positional-executable"])
def test_selector_site_argon_0821_expanded_options_require_review(tmp_path, api, positional):
    package = tmp_path / "aegis_core"
    package.mkdir()
    call = "subprocess." + api + ("(['sh','-c',P],-1,sys.executable,**opts)" if positional else (
        "(['sh','-c',P],executable=sys.executable,**opts)"))
    (package / "probe.py").write_text("import sys,subprocess\nP=\"import os; os.system('id')\"\ndef launch():\n    opts={}\n    "
                                     + call + "\n", encoding="utf-8")
    table = (("aegis_core/probe.py","launch","resolved-python-program","Test-owned explicit executable with expanded options."),)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == "unreviewed selector site aegis_core/probe.py:launch"
    sites = process_sites(tmp_path,selector_table=table)
    assert sites["process:aegis_core/probe.py:launch:subprocess." + api] == [5]


@pytest.mark.parametrize("display", ["-W", "-X", "--check-hash-based-pycs"])
@pytest.mark.parametrize("copies", [1, 2])
def test_literal_spawn_argon_0821_argv_zero_is_not_option(tmp_path, display, copies):
    package = tmp_path / "aegis_core"
    package.mkdir()
    call = "    subprocess.run([" + repr(display) + ",*FRAGMENT],executable=sys.executable)\n"
    (package / "probe.py").write_text("import sys,subprocess\nP=\"import os; os.system('id')\"\nFRAGMENT=['-c',P]\ndef launch():\n"
                                     + call * copies, encoding="utf-8")
    table = tuple(("aegis_core/probe.py",owner,"resolved-python-program","Test-owned argv display name.")
                  for owner in ("<module>","launch"))
    sites = process_sites(tmp_path,selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies


@pytest.mark.parametrize("staged", [False, True], ids=["inline", "named"])
@pytest.mark.parametrize("case", ["shell-executable", "python-executable", "shell-mode", "python-shell-mode"])
def test_literal_spawn_correctness_0821_effective_context_has_no_false_spawn(tmp_path, staged, case):
    package = tmp_path / "aegis_core"
    package.mkdir()
    program = "import os; os.system('id')"
    if case == "python-executable":
        argv = "['sh','-c'," + repr("''' '\npython3 -c \"" + program + "\"\n' '''") + "]"
        options = ",executable=sys.executable"
    else:
        argv = "[sys.executable,'-c'," + repr(program) + "]"
        options = {"shell-executable":",executable='/bin/sh'", "shell-mode":",shell=True",
                   "python-shell-mode":",shell=True,executable=sys.executable"}[case]
    prefix = "ARGV=" + argv + "\n" if staged else ""
    command = "ARGV" if staged else argv
    source = "import sys,subprocess\n" + prefix + "def launch():\n    subprocess.run(" + command + options + ")\n"
    (package / "probe.py").write_text(source,encoding="utf-8")
    owners = (("<module>",) if case == "shell-mode" else ("<module>","launch")) if staged else ("launch",)
    table = tuple(("aegis_core/probe.py",owner,"resolved-python-program","Test-owned effective execution context.") for owner in owners)
    sites = process_sites(tmp_path,selector_table=table)
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == 0


@pytest.mark.parametrize("kind", ["default", "decorator"])
def test_literal_spawn_correctness_0821_signature_owner(tmp_path, kind):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    program = "import os; os.system('id')"
    def write(owner):
        argv = "[sys.executable,'-c'," + repr(program) + "]"
        source = ("def " + owner + "(result=subprocess.run(" + argv + ")):\n    pass\n") if kind == "default" else (
            "@register(" + argv + ")\ndef " + owner + "():\n    pass\n")
        path.write_text("import sys,subprocess\n" + source,encoding="utf-8")
    def reviewed(owner):
        return (("aegis_core/probe.py",owner,"resolved-python-program","Test-owned signature process owner."),)
    write("one")
    before = process_sites(tmp_path,selector_table=reviewed("one"))
    assert sum(len(lines) for key,lines in before.items() if ":one.<literal-c-" in key and key.endswith(":os.system")) == 1
    write("two")
    after = process_sites(tmp_path,selector_table=reviewed("two"))
    assert sum(len(lines) for key,lines in after.items() if ":two.<literal-c-" in key and key.endswith(":os.system")) == 1
    assert not any(":one.<literal-c-" in key for key in after)
