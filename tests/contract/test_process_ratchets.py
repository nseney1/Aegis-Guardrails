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
SPAWN_MODULES = frozenset(api.partition(".")[0] for api in RAW)
POPEN_POSITIONAL_APIS = {"subprocess." + name for name in ("Popen", "run", "call", "check_call", "check_output")}

# Coordinator ruling 2026-11-15T04:52:12Z: this reviewed source inventory is
# the completeness gate. Resolver precision does not grant admission to a site.
SELECTOR_SITE_TABLE = (
    ("aegis_core/ast/runner.py", "_run_driver", "reviewed-dynamic",
     "Review AST driver argv from the validated driver plan; no shell, no stdin, bounded timeout."),
    ("aegis_cli/doctor.py", "_run_host_cli", "reviewed-dynamic",
     "Review doctor's single host-CLI probe argv and _child_env; no shell, no stdin, bounded timeout."),
    ("aegis_cli/hooks/registrar.py", "_probe", "reviewed-dynamic",
     "Review host hook probe argv in an empty temporary directory; no shell, no stdin, bounded timeout."),
    ("aegis_cli/install_hosts.py", "_run_cli", "reviewed-dynamic",
     "Review host CLI registration argv in a neutral temporary cwd; no shell, no stdin, bounded timeout."),
    ("aegis_cli/hooks/__init__.py", "__getattr__", "escape",
     "Review the lazy hook facade's allowlisted projections from management, secret-masking, runtime and safety modules."),
    ("aegis_cli/team_queue.py", "run_queue", "escape",
     "Review dynamic dispatch of the declared release/done verbs through the repository team_queue module."),
    ("aegis_core/storage.py", "__getattr__", "escape",
     "Review the lazy storage facade's three allowlisted projections through the storage_confined module."),
    ("aegis_cli/msg.py", "_write_output", "escape",
     "Review clearing the imported sys.stdout after a failed write so interpreter shutdown cannot retry the failed stream."),
    ("aegis_core/ast/batch.py", "BatchDriver.__init__", "escape",
     "The optional stored-process Popen annotation is type metadata, not a callable forwarding path."),
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
    ("aegis_core/benchmark.py", "measure_hook", "escape",
     "Review the subprocess.run default forwarded to the constant isolated HOOK_RUNNER launcher."),
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
    ("aegis_core/gitsafe.py", "run", "escape",
     "Review subprocess.run and its legacy subprocess namespace passed to Git transport with executable resolution and hardening."),
    ("aegis_core/gitsafe_run.py", "execute", "escape",
     "Review the legacy subprocess namespace used for DEVNULL and TimeoutExpired; launches use the separately supplied runner."),
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
    ("aegis_core/treeid.py", "_spawn", "reviewed-dynamic",
     "Review native Git argv from gitsafe.git_executable and caller flags/arguments when imported command provenance is unresolved."),
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
    ("aegis_core/ast/batch.py", "BatchDriver._terminate_group", "escape",
     "The Popen parameter annotation is type metadata; review also covers process-group cleanup calls."),
    ("aegis_core/benchmark.py", "run_benchmark", "escape",
     "Review the subprocess.run default forwarded positionally only to the reviewed hook benchmark."),
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
                            "lexer-or-message", "native-option", "reviewed-dynamic", "escape"})
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

# Coordinator ruling 2026-11-15T20:13:07Z: waive only imported-module
# stores in these exact UTF-8 program bytes, at these reviewed source owners.
LITERAL_PROGRAM_EXCEPTIONS = {
    ("aegis_core/testexec.py", "run_pytest_snapshot",
     "803eddf9509c06ab8e5e37a94653738489f699425b8a1e3d2cd130f99d452902"):
        "snapshot bootstrap isolates sys.path from the live checkout",
    ("aegis_core/verification/regression_commands.py", "run_configured_snapshot",
     "820cac9a505d774844ddad9f86f0ee041ba49eeb42fd186ca35914b683dca456"):
        "snapshot bootstrap isolates sys.path from the live checkout",
}


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
    assert selector_gate_errors(dict(module_trees(REPO)), SELECTOR_SITE_TABLE) == []
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
    def __init__(self, parent=None, kind="module", *, comprehension=False, namespace=""):
        self.parent = parent
        self.kind = kind
        self.comprehension = comprehension
        self.imports = {}
        self.star_imports = set()
        self.classes = {}
        self.namespace = namespace
        self.bound = set()
        self.globals = set()
        self.nonlocals = set()
        self.writes = set()
        self.definite = set()
        self.conditional = set()
        self.opaque = set()
        self.opaque_views = {}

    def bind(self, name):
        self.bound.add(name)
        self.writes.add(name)

    def resolve(self, name):
        # A scope may import different things along different branches. Keep every
        # possible import there; never let another scope's last import overwrite it.
        values = self.imports.get(name, set())
        if name not in self.bound or name in self.imports:
            values = values | {base + "." + name for base in self.star_imports}
        if values:
            if self.kind == "class" and self.parent is not None:
                values = values | self.parent.resolve(name)
            return values
        if name in self.globals and self.parent is not None:
            root = self.parent
            while root.parent is not None:
                root = root.parent
            return root.resolve(name)
        if name in self.nonlocals and self.parent is not None:
            return self.parent.resolve(name)
        if name in self.classes:
            values = {self.classes[name]}
            if self.kind == "class" and self.parent is not None:
                values |= self.parent.resolve(name)
            return values
        if name in self.bound:
            # Class LOAD_NAME may reach an enclosing import before a class
            # assignment/definition binds the name. Function locals still hide it.
            return self.parent.resolve(name) if self.kind == "class" and self.parent is not None else set()
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
    def __init__(self, tree, rel, *, runtime_only=False, import_graph=None):
        self.rel = rel
        self.at = {}
        self.allowed = None
        self.import_graph = import_graph
        self.class_reads = []
        namespace = rel.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        root = _AliasScope(namespace=namespace)
        self.namespaces = {namespace: [root]}
        if runtime_only:
            from tests.contract.test_import_boundary import import_nodes
            self.allowed = {id(n) for n in import_nodes(tree)}
        self._index(tree, root)
        for node, scope, definite in self.class_reads:
            owner = binding_scope(scope, node.id)
            if owner is not scope:
                self.at[id(node)] = owner
            elif node.id in scope.bound and (not definite or node.id in scope.conditional):
                if node.id not in scope.opaque_views:
                    if len(scope.opaque_views) >= _MAX_WORDS:
                        raise ValueError("selector import resolution limit")
                    view = _AliasScope(scope.parent, "class", namespace=scope.namespace)
                    view.bound.add(node.id)
                    view.opaque.add(node.id)
                    scope.opaque_views[node.id] = view
                self.at[id(node)] = scope.opaque_views[node.id]
        # Imports declared global/nonlocal belong to their Python binding scope.
        # Move them after indexing, when all enclosing bindings are known.
        for scope in set(self.at.values()):
            for local, targets in tuple(scope.imports.items()):
                owner = binding_scope(scope, local)
                if owner is not scope:
                    owner.imports.setdefault(local, set()).update(targets)
                    del scope.imports[local]

    def _arguments(self, args, outer, inner):
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg):
            if arg is not None:
                inner.bind(arg.arg)
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
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and scope.kind == "class":
            if len(self.class_reads) >= _MAX_WORDS:
                raise ValueError("selector import resolution limit")
            self.class_reads.append((node, scope, node.id in scope.definite))
        if isinstance(node, ast.NamedExpr):
            owner = scope
            while owner.comprehension:
                owner = owner.parent
            self._index(node.value, scope)
            self._index(node.target, owner)
            return
        if scope.kind == "class" and isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value is not None:
                self._index(node.value, scope)
            targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
            for target in targets:
                bound = isinstance(target, ast.Name) and target.id in scope.bound
                self._index(target, scope)
                if isinstance(node, ast.AnnAssign) and node.value is None and isinstance(target, ast.Name) and not bound:
                    scope.bound.discard(target.id)  # An annotation alone does not bind a class value.
            if isinstance(node, ast.AnnAssign):
                self._index(node.annotation, scope)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                for value in node.decorator_list:
                    self._index(value, scope)
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            label = node.name if not isinstance(node, ast.Lambda) else "<lambda>"
            suffix = ".<locals>" if kind == "function" else ""
            if len(scope.namespace) + len(label) + len(suffix) + 1 > 1048576:
                raise ValueError("selector import resolution limit")
            namespace = scope.namespace + "." + label + suffix
            inner = _AliasScope(_lexical_parent(scope), kind, namespace=namespace)
            if isinstance(node, ast.ClassDef):
                self.namespaces.setdefault(namespace, []).append(inner)
                for value in (*node.bases, *node.keywords):
                    self._index(value, scope)
            else:
                self._arguments(node.args, scope, inner)
                if getattr(node, "returns", None) is not None:
                    self._index(node.returns, scope)
            for value in [node.body] if isinstance(node, ast.Lambda) else node.body:
                if kind == "class":
                    inner.writes = set()
                self._index(value, inner)
                if kind == "class":
                    if isinstance(value, ast.AnnAssign) and value.value is None:
                        continue
                    if isinstance(value, (ast.Assign, ast.AnnAssign, ast.Import, ast.ImportFrom,
                                          ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        inner.definite.update(inner.writes)
                    else:
                        inner.conditional.update(inner.writes)
                        inner.definite.difference_update(inner.writes)
            if not isinstance(node, ast.Lambda):
                scope.bind(node.name)
                if isinstance(node, ast.ClassDef):
                    scope.classes[node.name] = namespace
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            inner = _AliasScope(_lexical_parent(scope), "function", comprehension=True, namespace=scope.namespace)
            for index, generator in enumerate(node.generators):
                self._index(generator.iter, scope if index == 0 else inner)
                self._index(generator.target, inner)
                for condition in generator.ifs:
                    self._index(condition, inner)
            for value in (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,):
                self._index(value, inner)
            return
        for local, target in import_bindings(node, self.rel).items():
            scope.bind(local)
            scope.imports.setdefault(local, set()).add(target)
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            probe = ast.ImportFrom(module=node.module, level=node.level,
                                   names=[ast.alias(name="__all__", asname=None)])
            base = import_bindings(probe, self.rel)["__all__"].removesuffix(".__all__")
            if base.partition(".")[0] in PACKAGES:
                scope.star_imports.add(base)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            scope.bind(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope.bind(node.name)
        elif type(node).__name__ in {"MatchAs", "MatchStar", "MatchMapping"}:
            local = getattr(node, "name", None) or getattr(node, "rest", None)
            if local:
                scope.bind(local)
        elif isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        for child in ast.iter_child_nodes(node):
            self._index(child, scope)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            scope = self.at.get(id(node))
            if scope is not None and node.id in scope.opaque and self.import_graph is None:
                return set()  # Value proofs cannot choose either side of an ambiguous class read.
            if scope is not None and scope.kind == "class" and not isinstance(node.ctx, ast.Load):
                # STORE_NAME/DELETE_NAME do not read an enclosing class-body
                # fallback; retain only imports already indexed in this scope.
                names = scope.imports.get(node.id, set())
            else:
                names = scope.resolve(node.id) if scope is not None else set()
        elif isinstance(node, ast.Attribute):
            names = {base + "." + node.attr for base in self.resolve(node.value)}
        else:
            names = set()
        if self.import_graph is None:
            return names
        return set().union(*(self.import_graph.resolve(name) for name in names))


class ImportGraph:
    """Follow only import declarations and class namespaces in the parsed tree.

    Import alternatives accumulate. Assignments, callable results and object
    attributes do not add edges; escape review covers those uses separately.
    """
    def __init__(self, modules, *, parent=None):
        added = {rel: ScopedNames(tree, rel) for rel, tree in modules.items()}
        self.names = {} if parent is None else dict(parent.names)
        self.names.update(added)
        self.namespaces = {} if parent is None else dict(parent.namespaces)
        self.cache = {}
        for names in added.values():
            for namespace, scopes in names.namespaces.items():
                self.namespaces[namespace] = [*self.namespaces.get(namespace, ()), *scopes]
            names.import_graph = self
        for rel, names in added.items():
            namespace = names.at[id(modules[rel])].namespace
            if len(namespace) > 1048576 or namespace.count(".") >= 4096:
                raise ValueError("selector import resolution limit")
            while "." in namespace:
                namespace = namespace.rpartition(".")[0]
                self.namespaces.setdefault(namespace, [])
        self.module_names = {namespace for namespace, scopes in self.namespaces.items()
                             if not scopes or any(scope.kind == "module" for scope in scopes)}
        self.repo_module_names = set(self.module_names)
        if parent is None:
            children = {}
            for namespace in self.repo_module_names:
                package, _, child = namespace.rpartition(".")
                children.setdefault(package, set()).add(child)
            shadowed = set()
            for rel, names in added.items():
                if not rel.endswith("/__init__.py"):
                    continue
                owner = names.at[id(modules[rel])]
                candidates = owner.bound & children.get(owner.namespace, set())
                if not candidates:
                    continue
                conflicts = set()
                for node in ast.walk(modules[rel]):
                    if names.at.get(id(node)) is not owner:
                        continue
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        for alias in node.names:
                            if alias.name == "*":
                                continue
                            local = alias.asname or (alias.name.partition(".")[0] if isinstance(node, ast.Import)
                                                     else alias.name)
                            canonical = (isinstance(node, ast.ImportFrom) and node.level == 1
                                         and node.module is None and alias.asname is None)
                            if not canonical:
                                conflicts.add(local)
                    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        conflicts.add(node.id)
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        conflicts.add(node.name)
                    elif isinstance(node, ast.ExceptHandler) and node.name:
                        conflicts.add(node.name)
                shadowed.update(owner.namespace + "." + child for child in candidates & conflicts)
            self.shadowed_children = frozenset(shadowed)
        else:
            self.shadowed_children = parent.shadowed_children
        if parent is not None:
            self.module_names.update(parent.module_names)
        self.module_names.update(target for rel, tree in modules.items() for node in ast.walk(tree)
                                 if isinstance(node, ast.Import) for target in import_bindings(node, rel).values())
        # A literal adds namespaces without re-indexing or mutating its package
        # graph. Its parent scopes keep their original resolution context.
        self.size = len(self.namespaces) + (1 if parent is None else parent.size) + sum(
            len(names.namespaces) + sum(sum(map(len, scope.imports.values()))
                                       + len(scope.classes) + len(scope.star_imports)
                                       for scopes in names.namespaces.values() for scope in scopes)
            for names in added.values())

    def is_shadowed(self, qualified):
        if len(qualified) > 1048576 or qualified.count(".") >= 4096:
            raise ValueError("selector import resolution limit")
        return any(qualified == child or qualified.startswith(child + ".") for child in self.shadowed_children)

    def imported(self, node, rel):
        references = set()
        for target in import_bindings(node, rel).values():
            references.update(self.resolve(target))
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            probe = ast.ImportFrom(module=node.module, level=node.level,
                                   names=[ast.alias(name="__all__", asname=None)])
            base = import_bindings(probe, rel)["__all__"].removesuffix(".__all__")
            remaining, seen = list(self.resolve(base)), set()
            while remaining:
                namespace = remaining.pop()
                if namespace in seen or namespace not in self.namespaces:
                    continue
                seen.add(namespace)
                for scope in self.namespaces[namespace]:
                    for targets in scope.imports.values():
                        for target in targets:
                            references.update(self.resolve(target))
                    for target in scope.star_imports:
                        remaining.extend(self.resolve(target) - seen)
        return references

    def resolve(self, qualified):
        # Bound text and component counts before splitting or concatenating.
        if len(qualified) > 1048576 or qualified.count(".") >= 4096:
            raise ValueError("selector import resolution limit")
        if qualified in self.cache:
            return self.cache[qualified]
        remaining, seen, found = [qualified], {qualified}, set()
        budget = self.size * (qualified.count(".") + 2)
        while remaining:
            name = remaining.pop()
            if len(name) > 1048576 or name.count(".") >= 4096:
                raise ValueError("selector import resolution limit")
            if self.is_shadowed(name):
                found.add(name)  # Preserve the unresolved path; never follow the physical child or alias.
                continue
            if name in RAW:
                found.add(name)
                continue
            if name in self.namespaces:
                found.add(name)
            parts = name.split(".")
            prefix = next((i for i in range(len(parts) - 1, 0, -1)
                           if ".".join(parts[:i]) in self.namespaces), None)
            if prefix is None:
                found.add(name)
                continue
            namespace = ".".join(parts[:prefix])
            targets = set()
            attribute = parts[prefix]
            for scope in self.namespaces[namespace]:
                # Attribute lookup sees exported declarations, not the enclosing
                # fallback used while evaluating expressions in a class body.
                targets.update(scope.imports.get(attribute, ()))
                if attribute in scope.classes:
                    targets.add(scope.classes[attribute])
                targets.update(base + "." + attribute for base in scope.star_imports)
            if not targets:
                found.add(name)
                continue
            suffix = ".".join(parts[prefix + 1:])
            for target in targets:
                if len(target) + len(suffix) + bool(suffix) > 1048576:
                    raise ValueError("selector import resolution limit")
                following = target + "." + suffix if suffix else target
                if following not in seen:
                    if len(seen) >= budget:
                        raise ValueError("selector import resolution limit")
                    seen.add(following)
                    remaining.append(following)
        self.cache[qualified] = found
        return found


def binding_scope(scope, name):
    if name in scope.globals:
        while scope.parent is not None:
            scope = scope.parent
    elif name in scope.nonlocals:
        scope = scope.parent
        while scope.parent is not None and name not in scope.bound:
            scope = scope.parent
    return scope


# Canonical builtin type names are identity proofs only after lexical shadowing
# and export-mutation checks. Keep this closed vocabulary separate from callable
# transforms; reading the live builtins namespace is itself a ratchet escape.
_BUILTIN_BASES = frozenset({
    "bool", "memoryview", "bytearray", "bytes", "classmethod", "complex", "dict", "enumerate", "filter",
    "float", "frozenset", "property", "int", "list", "map", "object", "range", "reversed", "set", "slice",
    "staticmethod", "str", "super", "tuple", "type", "zip", "BaseException", "Exception", "GeneratorExit",
    "KeyboardInterrupt", "SystemExit", "ArithmeticError", "AssertionError", "AttributeError", "BufferError",
    "EOFError", "ImportError", "LookupError", "MemoryError", "NameError", "OSError", "ReferenceError",
    "RuntimeError", "StopAsyncIteration", "StopIteration", "SyntaxError", "SystemError", "TypeError",
    "ValueError", "Warning", "FloatingPointError", "OverflowError", "ZeroDivisionError", "BytesWarning",
    "DeprecationWarning", "FutureWarning", "ImportWarning", "PendingDeprecationWarning", "ResourceWarning",
    "RuntimeWarning", "SyntaxWarning", "UnicodeWarning", "UserWarning", "BlockingIOError", "ChildProcessError",
    "ConnectionError", "FileExistsError", "FileNotFoundError", "InterruptedError", "IsADirectoryError",
    "NotADirectoryError", "PermissionError", "ProcessLookupError", "TimeoutError", "IndentationError",
    "IndexError", "KeyError", "ModuleNotFoundError", "NotImplementedError", "RecursionError", "UnboundLocalError",
    "UnicodeError", "BrokenPipeError", "ConnectionAbortedError", "ConnectionRefusedError", "ConnectionResetError",
    "TabError", "UnicodeDecodeError", "UnicodeEncodeError", "UnicodeTranslateError", "EnvironmentError", "IOError",
})
if sys.version_info >= (3, 10):
    _BUILTIN_BASES |= {"EncodingWarning"}
if sys.version_info >= (3, 11):
    _BUILTIN_BASES |= {"BaseExceptionGroup", "ExceptionGroup"}
if os.name == "nt":
    _BUILTIN_BASES |= {"WindowsError"}


PURE_BUILTINS = frozenset({
    "str", "int", "float", "bytes", "repr", "ascii", "len", "hash", "bool",
    "list", "tuple", "dict", "set", "frozenset", "print", "isinstance", "issubclass",
    "range", "enumerate", "zip", "reversed", "sorted", "any", "all", "sum", "min", "max",
    "getattr", "hasattr",
})


def mutable_call_inputs(node, names, bindings, namespaces, *, callees=None, helper_identity=None,
                        module_identity=None):
    """Unproven helpers may mutate receivers/arguments; OS launch APIs do not."""
    if callees is not None:
        resolved = callees.resolve(node.func)
        if resolved and resolved <= RAW:
            return ()
    if helper_identity is not None and helper_identity(node.func, names.rel) is not None:
        return ()  # The same proven stdlib helpers have no mutable receiver or argument.
    if isinstance(node.func, ast.Attribute) and node.func.attr in _CONTENT_METHODS | _STRING_METHODS:
        return ()  # Content readers and string transforms do not replace their input bindings.
    resolved = names.resolve(node.func)
    readonly = {"shlex.quote", "pathlib.Path.cwd", "pathlib.Path.home"} if helper_identity is None else set()
    if resolved and resolved <= RAW | readonly:
        return ()
    if isinstance(node.func, ast.Name) and node.func.id in PURE_BUILTINS:
        scope = names.at[id(node.func)]
        while scope is not None and node.func.id not in scope.bound:
            scope = scope.parent
        if scope is None:
            return ()
    receiver = (node.func.value,) if isinstance(node.func, ast.Attribute) else ()
    if receiver:
        if module_identity is None:
            symbols = names.resolve(receiver[0])
        else:
            symbols = module_identity(receiver[0], names.rel) or set()
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


def literal_bindings(tree, rel, namespaces=frozenset(), modules=None, *, callees=None, helper_identity=None,
                     module_identity=None, call_inputs=True):
    """Keep alternatives, but never trust an initializer after an unsupported write."""
    # Value traversal must visit intermediate bindings and invalidations rather
    # than following an import-only graph straight to the terminal declaration.
    names, bindings = ScopedNames(tree, rel), {}
    for scope in set(names.at.values()):
        for name in scope.opaque:
            bindings[scope, name] = [_UNRESOLVED_IMPORT]
    changed, aliases, exports, export_aliases = set(), [], set(), []
    declarations, invalidated, parameters, untraced = set(), set(), set(), set()
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

    def key(target):
        scope = names.at[id(target)]
        if isinstance(target.ctx, ast.Load):
            while scope.parent is not None and target.id not in scope.bound:
                scope = scope.parent
        return binding_scope(scope, target.id), target.id

    def immutable_value(value):
        return (isinstance(value, (ast.Constant, ast.JoinedStr)) or isinstance(value, ast.Call)
                and captured_module(value, names, rel, modules or {}, helper_identity=helper_identity) is not None)

    def invalidate(target, *, mutation=False):
        if isinstance(target, ast.Name):
            values = bindings.get(key(target), ())
            if mutation and values and all(immutable_value(value) for value in values):
                return  # Passing an immutable literal cannot mutate its binding.
            if mutation and key(target) in parameters and values == [None]:
                return  # An opaque parameter retains its existing provenance treatment.
            changed.add(key(target))
            invalidated.add(key(target))
            if not mutation:
                untraced.add(key(target))
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

    parameters.update((names.at[id(node)], node.arg) for node in ast.walk(tree) if isinstance(node, ast.arg))
    for node in ast.walk(tree):
        if isinstance(node, ast.arg):
            bindings.setdefault((names.at[id(node)], node.arg), []).append(None)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            if isinstance(node.target, ast.Name):
                bindings.setdefault(key(node.target), []).append(node)
            else:
                invalidate(node.target)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            if isinstance(node.optional_vars, ast.Name):
                bindings.setdefault(key(node.optional_vars), []).append(node.context_expr)
            else:
                invalidate(node.optional_vars)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if not isinstance(parents[id(node)], (ast.Assign, ast.AnnAssign, ast.For, ast.AsyncFor,
                                                  ast.comprehension, ast.withitem)):
                invalidate(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)):
            if node.name:
                declaration = binding_scope(names.at[id(node)], node.name), node.name
                changed.add(declaration)
                if isinstance(node, ast.ExceptHandler):
                    invalidated.add(declaration)
                    untraced.add(declaration)
                else:
                    declarations.add(declaration)
        elif type(node).__name__ in {"MatchAs", "MatchStar", "MatchMapping"}:
            name = getattr(node, "name", None) or getattr(node, "rest", None)
            if name:
                scope = names.at[id(node)]
                scope.bound.add(name)
                changed.add((binding_scope(scope, name), name))
                invalidated.add((binding_scope(scope, name), name))
                untraced.add((binding_scope(scope, name), name))
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
                if isinstance(target, ast.Name) and node.value is None:
                    invalidated.add(key(target))
                if isinstance(target, (ast.Tuple, ast.List)):
                    for item in ast.walk(target):
                        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                            # Keep the source for provenance without resolving unpacked values.
                            bindings.setdefault(key(item), []).append(node)
        if isinstance(node, (ast.AugAssign, ast.NamedExpr)):
            invalidate(node.target)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                invalidate(target)
    if call_inputs:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for target in mutable_call_inputs(node, names, bindings, namespaces, callees=callees,
                                                   helper_identity=helper_identity, module_identity=module_identity):
                    invalidate(target, mutation=True)
    immutable = {key for key, values in bindings.items() if values and all(immutable_value(value) for value in values)}
    aliases = [(left, right) for left, right in aliases if left not in immutable and right not in immutable]
    while True:
        expanded = changed | {other for a, b in aliases if a in changed or b in changed for other in (a, b)}
        unknown = untraced | {other for a, b in aliases if a in untraced or b in untraced for other in (a, b)}
        if expanded == changed and unknown == untraced:
            break
        changed, untraced = expanded, unknown
    for scope, name in changed:
        values = bindings.get((scope, name), ())
        # Opaque call-side mutations keep the earlier source traversal (D-aw).
        # Unsupported writes or absent initializers need an explicit unknown source.
        traced = (scope, name) not in untraced and (
            (scope, name) in declarations and (scope, name) not in invalidated
            or any(isinstance(value, ast.AST) for value in values))
        marker = None if traced else _UNRESOLVED_IMPORT
        bindings.setdefault((scope, name), []).append(marker)
        exports.update(scope.imports.get(name, ()))
        if (scope.kind == "module" and ((scope, name) not in declarations or (scope, name) in invalidated
                                       or any(value is not None for value in bindings[(scope, name)]))):
            exports.add(scope.namespace + "." + name)
    exports.update(name for key, name in export_aliases if key in changed)
    return names, bindings, exports


def captured_module(node, names, rel, modules, *, helper_identity=None):
    """Prove an import-time UTF-8 read of a co-located, censused module."""
    if not isinstance(node, ast.Call):
        return None
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
    if (not isinstance(path, ast.Call) or len(path.args) != 1 or path.keywords or not isinstance(path.args[0], ast.Name)
            or path.args[0].id != "__file__"):
        return None
    identity = helper_identity(path.func, rel) if helper_identity is not None else (
        "pathlib.Path" if names.resolve(path.func) == {"pathlib.Path"} else None)
    if identity != "pathlib.Path":
        return None
    target = str(Path(rel).with_name(filename.value)).replace("\\", "/")
    return ("captured-module", target) if target in modules else None


_Argv = namedtuple("_Argv", "kind items")
_Shell = namedtuple("_Shell", "text holes hidden")
_Quoted = namedtuple("_Quoted", "value")
_Launch = namedtuple("_Launch", "executable argv shell")
_LaunchResolution = namedtuple("_LaunchResolution", "programs reason module")
_SpawnVerdict = namedtuple("_SpawnVerdict", "rel node scope verdict reason programs module")


class _CommandEvidence(namedtuple("_CommandEvidence", "unresolved interpreter selector content module",
                                  defaults=(False,))):
    __slots__ = ()

    @property
    def requires_review(self):
        return self.unresolved and (self.interpreter or self.selector or self.content)


_SPLICE, _PYTHON, _OPTION_PREFIX, _USE_HEAD, _NONE = object(), object(), object(), object(), object()
_UNRESOLVED_IMPORT = object()
_UNRESOLVED_MODULE = object()
_CONTENT_METHODS = frozenset({"read_text", "read_bytes", "open", "read", "readline", "readlines"})
_STRING_METHODS = frozenset({"capitalize", "casefold", "center", "count", "encode", "endswith", "expandtabs",
    "find", "format", "format_map", "index", "isalnum", "isalpha", "isascii", "isdecimal", "isdigit",
    "isidentifier", "islower", "isnumeric", "isprintable", "isspace", "istitle", "isupper", "join",
    "ljust", "lower", "lstrip", "maketrans", "partition", "removeprefix", "removesuffix", "replace",
    "rfind", "rindex", "rjust", "rpartition", "rsplit", "rstrip", "split", "splitlines", "startswith",
    "strip", "swapcase", "title", "translate", "upper", "zfill"})
_MAX_CHOICES, _MAX_WORDS, _MAX_TEXT = 64, 4096, 1048576
_MAX_DEPTH = 64
_FORMAT_FIELD = re.compile(r"\{([A-Za-z_][A-Za-z_0-9]*|[0-9]*)(?:!([sra]))?(?::s?)?\}")


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


def selector_import_escape(node, rel, names, imports):
    """Review noncanonical bindings at their import, before any forwarding."""
    if not isinstance(node, (ast.Import, ast.ImportFrom)):
        return False
    if names.at[id(node)].kind == "class":
        return True
    if isinstance(node, ast.ImportFrom) and set(import_bindings(node, rel).values()) & RAW:
        return True
    if isinstance(node, ast.Import) and any(alias.name in SPAWN_MODULES and alias.asname is not None
                                          for alias in node.names):
        return True
    if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
        probe = ast.ImportFrom(module=node.module, level=node.level,
                               names=[ast.alias(name="__all__", asname=None)])
        base = import_bindings(probe, rel)["__all__"].removesuffix(".__all__")
        return (base in imports.namespaces and base in imports.module_names
                or bool(imports.imported(node, rel) & (RAW | SPAWN_MODULES)))
    return False


def selector_module_escape(node, parents, names, imports=None):
    """Module objects forwarded as values require review at their origin."""
    if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(node.ctx, ast.Load):
        return False
    if isinstance(node, ast.Attribute) and imports is not None:
        for namespace in names.resolve(node.value) & imports.namespaces.keys():
            if imports.is_shadowed(namespace):
                continue
            for scope in imports.namespaces[namespace]:
                if any(imports.resolve(target) & (RAW | SPAWN_MODULES)
                       for target in scope.imports.get(node.attr, ())):
                    return True
    modules = names.resolve(node) & (SPAWN_MODULES | (imports.repo_module_names if imports is not None else set()))
    if not modules:
        return False
    parent = parents.get(id(node))
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return False
    if (isinstance(parent, ast.Call) and parent.args and parent.args[0] is node
            and not parent.keywords and isinstance(parent.func, ast.Name)):
        name = parent.func.id
        scope = names.at[id(parent.func)]
        while scope is not None and name not in scope.bound:
            scope = scope.parent
        if scope is None:
            if name == "hasattr" and len(parent.args) == 2:
                return False
            if (name == "getattr" and len(parent.args) in (2, 3)
                    and isinstance(parent.args[1], ast.Constant) and isinstance(parent.args[1].value, str)
                    and all(module + "." + parent.args[1].value not in RAW for module in modules)):
                return False
    return True


def selector_module_mutation(node, names, imports):
    """Stores rooted at imported module objects require review."""
    target = None
    if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
        target = node
    elif isinstance(node, ast.Call) and node.args:
        resolved = names.resolve(node.func)
        if resolved and resolved <= {"builtins.setattr", "builtins.delattr"}:
            target = node.args[0]
        elif isinstance(node.func, ast.Name) and node.func.id in {"setattr", "delattr"}:
            scope = names.at[id(node.func)]
            while scope is not None and node.func.id not in scope.bound:
                scope = scope.parent
            if scope is None:
                target = node.args[0]
    while isinstance(target, (ast.Attribute, ast.Subscript)):
        target = target.value
    return target is not None and bool(names.resolve(target) & imports.module_names)


def selector_escape_sites(modules):
    """Noncanonical imports and API values outside a direct callee need review."""
    found = {}
    imports = ImportGraph(modules)
    for rel, tree in modules.items():
        if not rel.startswith(tuple(package + "/" for package in PACKAGES)):
            continue
        names = imports.names[rel]
        parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        callees = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for node, scope in qualified_nodes(tree, include_signature=True):
            if (selector_import_escape(node, rel, names, imports)
                    or selector_module_escape(node, parents, names, imports)
                    or selector_module_mutation(node, names, imports)
                    or id(node) not in callees and names.resolve(node) & RAW):
                found.setdefault((rel, scope), []).append(node.lineno)
    return dict(sorted(found.items()))


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


def selector_sites(modules, *, include_escapes=True, table=()):
    found = {}
    resolver = CommandResolver(modules, option_pins={})
    imports = resolver.imports
    verdicts = spawn_totality(modules, table, resolver=resolver)
    for item in verdicts:
        unknown_command = False
        if item.verdict == "reviewed" and not item.programs:
            for api in imports.names[item.rel].resolve(item.node.func) & RAW:
                command = resolver.construction_command(item.node, api)
                expression = ast.Tuple(elts=list(command)) if isinstance(command, tuple) else command
                unknown_command |= any(value is None or value is _UNRESOLVED_IMPORT
                                       for value in resolver.values(expression, item.rel))
        if item.reason is not None or unknown_command:
            found.setdefault((item.rel, item.scope), []).append(item.node.lineno)
    for rel, tree in modules.items():
        if not rel.startswith(tuple(package + "/" for package in PACKAGES)):
            continue
        names = imports.names[rel]
        scopes = {id(node): scope for node, scope in qualified_nodes(tree, include_signature=True)}
        scopes.update((id(item.node), item.scope) for item in verdicts if item.rel == rel)
        for node, source, origins, launch in resolver.programs(rel, with_locations=True):
            module_operand = source == ("external-module", None)
            if launch and module_operand:
                found.setdefault((rel, scopes[id(node)]), []).append(node.lineno)
        references, expanded, positional = set(), {}, {}
        module_reference = False
        # Clause B is module-wide for expanded calls; callable alias analysis
        # is deliberately unnecessary. Keep the prior same-scope positional
        # rule as well. Defaults/decorators participate in their function.
        for node, scope in qualified_nodes(tree, include_signature=True):
            if any(imports.is_shadowed(target) for target in names.resolve(node)):
                found.setdefault((rel, scope), []).append(node.lineno)
            imported = imports.imported(node, rel) & RAW
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
    if include_escapes:
        for key, lines in selector_escape_sites(modules).items():
            found.setdefault(key, []).extend(lines)
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


def selector_gate_errors(modules, table):
    """Review every selector and API escape, including the escape row kind."""
    escapes = selector_escape_sites(modules)
    current = selector_sites(modules, include_escapes=False, table=table)
    for key, lines in escapes.items():
        current.setdefault(key, []).extend(lines)
    errors = selector_site_errors(current, table)
    kinds = {(rel, scope): kind for rel, scope, kind, _ in table}
    errors.extend("selector escape requires escape kind " + rel + ":" + scope
                  for rel, scope in sorted(escapes.keys() & kinds.keys())
                  if kinds[rel, scope] != "escape")
    errors.extend("stale selector escape " + rel + ":" + scope
                  for (rel, scope), kind in sorted(kinds.items())
                  if kind == "escape" and (rel, scope) not in escapes)
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


def api_keywords(node, *, key_resolver=None, opaque_values=None):
    """Expand explicit dictionary keys while keeping unknown mappings separate from evidence."""
    if len(node.keywords) > _MAX_WORDS:
        return None, True
    found, unknown, budget = {}, False, [_MAX_WORDS]

    def mapping(value, depth):
        if not isinstance(value, ast.Dict):
            return {}, True
        if depth >= _MAX_DEPTH or len(value.keys) > budget[0]:
            return None, True
        budget[0] -= len(value.keys)
        fields, opaque = {}, False
        for key, item in zip(value.keys, value.values):
            if key is None:
                extra, uncertain = mapping(item, depth + 1)
                if extra is None:
                    return None, True
                fields.update(extra)  # Within one dict, Python uses the last value for a key.
                opaque |= uncertain
            elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                fields[key.value] = item
            else:
                keys = key_resolver(key) if key_resolver is not None else None
                if keys is not None and len(keys) == 1 and all(isinstance(word, str) for word in keys):
                    name = next(iter(keys))
                    fields[name] = item
                    keep = name in {"args", "argv", "cmd", "command", "executable", "path", "file"}
                else:
                    opaque = True
                    keep = True
                if keep and opaque_values is not None:
                    if len(opaque_values) >= _MAX_WORDS:
                        return None, True
                    opaque_values.append(item)
        return fields, opaque

    for keyword in node.keywords:
        if keyword.arg is not None:
            if budget[0] <= 0:
                return None, True
            budget[0] -= 1
            fields = {keyword.arg: keyword.value}
        else:
            fields, opaque = mapping(keyword.value, 0)
            if fields is None:
                return None, True
            unknown |= opaque
        for key, value in fields.items():
            if key in found:
                return None, True
            found[key] = value
    return found, unknown


def api_executable_fields(node, api):
    """Retain executable evidence even when the complete argument layout is rejected."""
    if len(node.args) + len(node.keywords) > _MAX_WORDS:
        return None
    keywords, _ = api_keywords(node)
    if keywords is None:
        return None
    if api in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}:
        return ()
    index = 2 if api.startswith("subprocess.") else (1 if api.startswith("os.spawn") else 0)
    keys = {"executable"} if api.startswith("subprocess.") else {"path", "file", "executable"}
    fields = [node.args[index]] if len(node.args) > index else []
    for key, value in keywords.items():
        if key in keys:
            if len(fields) >= _MAX_CHOICES:
                return None
            fields.append(value)
    return tuple(fields)


def api_arguments(node, api):
    """Return executable AST, argv AST/variadic tuple, and shell mode by API."""
    if (len(node.args) + len(node.keywords) > _MAX_WORDS
            or any(isinstance(arg, ast.Starred) for arg in node.args)):
        return None
    keywords, unknown = api_keywords(node)
    if keywords is None or unknown:
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
    executable_keys = [key for key in ("file", "path", "executable") if key in keywords]
    if len(executable_keys) > 1 or len(node.args) > offset and executable_keys:
        return None
    executable = node.args[offset] if len(node.args) > offset else keywords.get(executable_keys[0]) if executable_keys else None
    suffix = api.rsplit(".", 1)[1]
    vector_keys = [key for key in ("args", "argv") if key in keywords]
    if len(vector_keys) > 1 or len(node.args) > offset + 1 and vector_keys:
        return None
    if vector_keys:
        return executable, keywords[vector_keys[0]], False
    if len(node.args) <= offset + 1:
        return None
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


# Exact option spellings and operand arities; anything else is UNKNOWN.
_WRAPPER_GRAMMAR = {
    "env": ({"-i", "--ignore-environment"}, {"-u", "--unset", "-C", "--chdir"}),
    "nice": (set(), {"-n", "--adjustment"}),
    "timeout": ({"--foreground", "--preserve-status", "--verbose", "-v"}, {"-s", "--signal", "-k", "--kill-after"}),
    "stdbuf": (set(), {"-i", "-o", "-e", "--input", "--output", "--error"}),
    "xargs": ({"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "--interactive", "-x", "--exit"},
              {"-n", "--max-args", "-L", "--max-lines", "-s", "--max-chars", "-P", "--max-procs", "-d", "--delimiter", "-E", "--eof"}),
    **{name: (set(), set()) for name in ("sudo", "doas", "time", "command", "builtin", "exec", "nohup",
                                       "setsid", "busybox", "ionice")},
}
_UNKNOWN_WRAPPERS = frozenset({"su", "runuser", "sg"})


def command_basename(word):
    if not isinstance(word, str) or len(word) > _MAX_TEXT:
        return None
    return word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")


def closed_wrapper_argv(items):
    """Return the untouched suffix only after a completely proven wrapper prefix."""
    if len(items) > _MAX_WORDS or sum(len(word) for word in items if isinstance(word, str)) > _MAX_TEXT:
        return None
    index = 0
    for _ in range(_MAX_DEPTH):
        if index >= len(items):
            return ()
        wrapper = command_basename(items[index])
        if wrapper in _UNKNOWN_WRAPPERS:
            return None  # A username and shell command do not form an executable suffix.
        if wrapper not in _WRAPPER_GRAMMAR:
            return items[index:]
        switches, operands = _WRAPPER_GRAMMAR[wrapper]
        index += 1
        while index < len(items):
            word = items[index]
            if not isinstance(word, str):
                return None
            if word == "--":
                index += 1
                break
            if word in switches:
                index += 1
            elif word in operands:
                if index + 1 >= len(items) or not isinstance(items[index + 1], str):
                    return None
                operand = items[index + 1]
                if wrapper == "nice" and not re.fullmatch(r"[+-]?[0-9]+", operand):
                    return None
                if (wrapper == "xargs" and word in {"-n", "--max-args", "-L", "--max-lines", "-s", "--max-chars", "-P", "--max-procs"}
                        and not re.fullmatch(r"[0-9]+", operand)):
                    return None
                if wrapper == "stdbuf" and not re.fullmatch(r"L|0|[0-9]+[KMG]?", operand):
                    return None
                if (wrapper == "timeout" and word in {"-k", "--kill-after"}
                        and not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[smhd]?", operand)):
                    return None
                index += 2
            elif wrapper == "stdbuf" and re.fullmatch(r"-[ioe](?:L|0|[0-9]+[KMG]?)", word):
                index += 1
            elif wrapper == "xargs" and re.fullmatch(r"-[nLsP][0-9]+", word):
                index += 1
            elif word.startswith("-"):
                return None
            elif wrapper == "env" and "=" in word:
                name = word.partition("=")[0]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
                    return None
                index += 1
            else:
                break
        if wrapper == "timeout":
            if (index >= len(items) or not isinstance(items[index], str)
                    or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[smhd]?", items[index])):
                return None
            index += 1
    return None


class CommandResolver:
    """Resolve whole command constructions; uncertainty never becomes an initializer.

    Names keep lexical alternatives. Augmented assignments, mutations, unsupported
    writes and cycles contribute an unknown alternative. Shell interpolation is
    rendered as a complete command with typed placeholders for unresolved fields.
    Namespace obfuscation remains outside ScopedNames' honest-author threat model.
    """
    def __init__(self, modules, *, option_pins=None, package_context=None):
        self._constant_checks = set()
        self._launch_cache = {}
        self._return_definitions = {}
        self._method_graph = None
        self._definite_cache = {}
        self.modules = modules if package_context is None else {**package_context.modules, **modules}
        self.imports = ImportGraph(modules, parent=None if package_context is None else package_context.imports)
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
        self.contexts.update({rel: literal_bindings(tree, rel, namespaces, self.modules,
                                                   callees=self.imports.names[rel], call_inputs=False)
                              for rel, tree in modules.items()})
        self.changed_exports = {name for _, _, changes in self.contexts.values() for name in changes}
        # Establish explicit bindings/writes before classifying call effects, so
        # a re-exported stdlib module is not mistaken for a mutable receiver.
        # The full pass retains all other call effects and capture immutability.
        self.contexts.update({rel: literal_bindings(tree, rel, namespaces, self.modules,
                                                   callees=self.imports.names[rel], helper_identity=self.helper_identity,
                                                   module_identity=self.module_identity)
                              for rel, tree in modules.items()})
        self.changed_exports = {name for _, _, changes in self.contexts.values() for name in changes}
        pins = OPTION_PREFIX_PINS if option_pins is None else option_pins
        self.option_functions = ({key: checked_prefix_function(modules, key, pins) for key in pins}
                                 if OPTION_PREFIX_CALLER[0] in modules else {})
        self._proven_cache = {}

    def export_changed(self, qualified, *, descendants=True):
        return any(qualified == name or qualified.startswith(name + ".")
                   or descendants and name.startswith(qualified + ".")
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

    def imported_binding(self, qualified):
        """Locate one module hop without skipping its local writes."""
        if self.imports.is_shadowed(qualified):
            return None
        base, _, attribute = qualified.rpartition(".")
        origin = base.replace(".", "/") + ".py"
        if origin not in self.modules:
            origin = base.replace(".", "/") + "/__init__.py"
        if origin not in self.modules:
            return None
        names, bindings, _ = self.contexts[origin]
        scope = names.at[id(self.modules[origin])]
        sources = set(scope.imports.get(attribute, ()))
        sources.update(base + "." + attribute for base in scope.star_imports)
        return origin, bindings.get((scope, attribute), ()), sources

    def helper_identity(self, node, origin):
        """Prove only the modeled stdlib identities, preserving binding guards."""
        if isinstance(node, ast.Name) and not self.definite_name(node, origin):
            return None
        return self.reference_identity(node, origin, {
            "shlex.quote", "shlex.join", "os.fspath", "pathlib.Path", "pathlib.PurePath",
            "pathlib.Path.cwd", "pathlib.Path.home"})

    def module_identity(self, node, origin):
        """Prove namespace receivers without treating classes as modules."""
        return self.reference_identity(node, origin, self.namespaces, module_receiver=True)

    def reference_identity(self, node, origin, terminals, *, module_receiver=False):
        """Share the bounded alias/import proof and its invalidation guards."""
        cache, expressions, remaining = {}, {}, [_MAX_WORDS]

        def qualified_names(expression, source, seen):
            key = "node", source, id(expression)
            if key in seen or len(seen) >= _MAX_DEPTH or remaining[0] <= 0:
                return set()
            remaining[0] -= 1
            if key in expressions:
                return expressions[key]
            names, bindings, _ = self.contexts[source]
            result = set()
            if isinstance(expression, ast.Name):
                if len(expression.id) > _MAX_TEXT:
                    return set()
                builtin = self.builtin_name(expression, source)
                if builtin is not None and len(builtin) + 9 <= _MAX_TEXT:
                    qualified = "builtins." + builtin
                    if qualified in terminals:
                        expressions[key] = {qualified}
                        return expressions[key]
                scope = names.at[id(expression)]
                while scope is not None:
                    scope = binding_scope(scope, expression.id)
                    values = bindings.get((scope, expression.id), ())
                    if scope.kind == "module":
                        if len(scope.namespace) + len(expression.id) + 1 > _MAX_TEXT:
                            return set()
                        if self.export_changed(scope.namespace + "." + expression.id, descendants=not module_receiver):
                            return set()
                    if values:
                        if ((not module_receiver and len(values) != 1) or expression.id in scope.imports
                                or len(values) > _MAX_CHOICES):
                            return set()
                        for value in values:
                            extra = qualified_names(value, source, seen | {key})
                            if not extra or len(result) + len(extra) > _MAX_CHOICES:
                                return set()
                            result.update(extra)
                        break
                    if expression.id in scope.bound:
                        result = names.resolve(expression)
                        break
                    scope = scope.parent
                else:
                    result = names.resolve(expression)
            elif isinstance(expression, ast.Attribute):
                bases = qualified_names(expression.value, source, seen | {key})
                if any(len(base) + len(expression.attr) + 1 > _MAX_TEXT or base.count(".") + 1 >= 4096
                       for base in bases):
                    return set()
                result = {base + "." + expression.attr for base in bases}
            elif module_receiver and isinstance(expression, ast.IfExp):
                for choice in (expression.body, expression.orelse):
                    extra = qualified_names(choice, source, seen | {key})
                    if not extra or len(result) + len(extra) > _MAX_CHOICES:
                        return set()
                    result.update(extra)
            if len(result) > _MAX_CHOICES:
                return set()
            expressions[key] = result
            return result

        def follow(qualified, seen):
            key = "qualified", qualified
            if key in seen or len(seen) >= _MAX_DEPTH or remaining[0] <= 0:
                return None
            remaining[0] -= 1
            if qualified in cache:
                return cache[qualified]
            result = None
            if (not self.imports.is_shadowed(qualified)
                    and not self.export_changed(qualified, descendants=not module_receiver)):
                if qualified in terminals:
                    result = frozenset({qualified})
                else:
                    binding = self.imported_binding(qualified)
                    prefix, suffix = qualified, ""
                    while binding is None and "." in prefix and remaining[0] > 0:
                        remaining[0] -= 1
                        prefix, _, attribute = prefix.rpartition(".")
                        suffix = attribute + ("." + suffix if suffix else "")
                        binding = self.imported_binding(prefix)
                    if binding is not None:
                        target, choices, sources = binding
                        if choices:
                            if sources or len(choices) > _MAX_CHOICES or not module_receiver and len(choices) != 1:
                                sources = set()
                            else:
                                sources = set()
                                for choice in choices:
                                    extra = qualified_names(choice, target, seen | {key})
                                    if not extra or len(sources) + len(extra) > _MAX_CHOICES:
                                        sources = set()
                                        break
                                    sources.update(extra)
                        if sources and len(sources) <= _MAX_CHOICES:
                            for source in sources:
                                if len(source) + len(suffix) + bool(suffix) > _MAX_TEXT:
                                    result = None
                                    break
                                following = source + "." + suffix if suffix else source
                                identity = follow(following, seen | {key})
                                if identity is None or result is not None and len(result) + len(identity) > _MAX_CHOICES:
                                    result = None
                                    break
                                result = identity if result is None else result | identity
            cache[qualified] = result
            return result

        names = qualified_names(node, origin, frozenset())
        identities = frozenset()
        for name in names:
            extra = follow(name, frozenset())
            if extra is None or len(identities) + len(extra) > _MAX_CHOICES:
                return None
            identities |= extra
        if module_receiver:
            return identities or None
        return next(iter(identities)) if len(identities) == 1 else None

    def imported(self, qualified, seen):
        if qualified in seen or self.export_changed(qualified) or len(seen) >= _MAX_DEPTH:
            return {None}
        seen = seen | {qualified}
        binding = self.imported_binding(qualified)
        if binding is None:
            return {None}
        origin, choices, sources = binding
        if any(isinstance(node, (ast.List, ast.Dict, ast.Set, ast.Call)) for node in choices):
            return {None}
        result = {v for node in choices for v in self.values(node, origin, seen)}
        result |= {v for name in sources for v in self.imported(name, seen)}
        if len(result) > _MAX_CHOICES:
            return {None}
        retained = set()
        for value in result:
            if isinstance(value, _Argv) and value.kind == "tuple":
                if len(value.items) > _MAX_WORDS:
                    return {None}
                # An opaque operand cannot erase the immutable words around it.
                # Nested mutable containers cross only as unknown individual words.
                words = tuple(word if word is None or word is _UNRESOLVED_IMPORT or word is _SPLICE
                              or isinstance(word, str) or word is _PYTHON
                              or isinstance(word, _Quoted) and isinstance(word.value, str)
                              else None for word in value.items)
                retained.add(_Argv("tuple", words))
            elif value is None or value is _UNRESOLVED_IMPORT or isinstance(value, str) or value is _PYTHON or value is _NONE:
                retained.add(value)
            else:
                retained.add(None)  # Mutable containers and call results stay opaque.
        return retained or {None}

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
            return {self.unknown_value(node, origin)}
        states = {()}
        for item in node.elts:
            starred = isinstance(item, ast.Starred)
            choices = self.values(item.value if starred else item, origin, seen)
            if not starred and any(value is None or value is _UNRESOLVED_IMPORT for value in choices):
                constants = self.constant_strings(item, origin, seen)
                if constants is not None:
                    choices = constants
            pieces = {v.items if starred and isinstance(v, _Argv) else (
                (_OPTION_PREFIX,) if starred and v is _OPTION_PREFIX else (
                    (_UNRESOLVED_IMPORT,) if v is _UNRESOLVED_IMPORT else ((_SPLICE,) if starred else (v,)))) for v in choices}
            if len(states) * len(pieces) > _MAX_CHOICES:
                return {self.unknown_value(node, origin)}
            if any(len(a) + len(b) > _MAX_WORDS for a in states for b in pieces):
                return {self.unknown_value(node, origin)}
            states = {a + b for a in states for b in pieces}
        return {_Argv("list" if isinstance(node, ast.List) else "tuple", state) for state in states}

    def constant_strings(self, node, origin, seen=frozenset(), budget=None):
        """Resolve only bounded, string-only constant formatting; never execute user helpers."""
        budget = [_MAX_WORDS] if budget is None else budget
        if not isinstance(node, ast.AST) or id(node) in seen or len(seen) >= _MAX_DEPTH or budget[0] <= 0:
            return None
        budget[0] -= 1
        seen = seen | {id(node)}
        if isinstance(node, ast.Constant):
            return {node.value} if isinstance(node.value, str) and len(node.value) <= _MAX_TEXT else None
        names, bindings, _ = self.contexts[origin]
        if isinstance(node, (ast.Name, ast.Attribute)):
            choices = []
            for qualified in names.resolve(node):
                if self.export_changed(qualified):
                    return None
                binding = self.imported_binding(qualified)
                if binding is None or binding[2] or not binding[1]:
                    return None
                if len(choices) + len(binding[1]) > _MAX_CHOICES:
                    return None
                choices.extend((value, binding[0]) for value in binding[1])
            if isinstance(node, ast.Name):
                scope = names.at[id(node)]
                while scope is not None:
                    scope = binding_scope(scope, node.id)
                    if scope.kind == "module" and self.export_changed(scope.namespace + "." + node.id):
                        return None
                    values = bindings.get((scope, node.id), ())
                    if values or node.id in scope.bound:
                        if len(choices) + len(values) > _MAX_CHOICES:
                            return None
                        choices.extend((value, origin) for value in values)
                        break
                    scope = scope.parent
            if not choices or len(choices) > _MAX_CHOICES:
                return None
            result = set()
            for value, source in choices:
                extra = self.constant_strings(value, source, seen, budget)
                if extra is None or len(result) + len(extra) > _MAX_CHOICES:
                    return None
                result.update(extra)
            return result
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.constant_strings(node.left, origin, seen, budget)
            right = self.constant_strings(node.right, origin, seen, budget)
            if left is None or right is None or len(left) * len(right) > _MAX_CHOICES:
                return None
            if any(len(a) + len(b) > _MAX_TEXT for a in left for b in right):
                return None
            return {a + b for a in left for b in right}
        if isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.FormattedValue) and (
                        part.format_spec is not None or self.constant_strings(part.value, origin, seen, budget) is None):
                    return None
            normal = self.values(node, origin, seen - {id(node)})
            return normal if normal and all(isinstance(value, str) for value in normal) else None
        if isinstance(node, (ast.BoolOp, ast.IfExp)):
            operands = node.values if isinstance(node, ast.BoolOp) else (node.body, node.orelse)
            result = set()
            for operand in operands:
                extra = self.constant_strings(operand, origin, seen, budget)
                if extra is None or len(result) + len(extra) > _MAX_CHOICES:
                    return None
                result.update(extra)
            return result
        percent = isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
        formatted = (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                     and node.func.attr == "format")
        if not percent and not formatted:
            return None
        templates = self.constant_strings(node.left if percent else node.func.value, origin, seen, budget)
        if templates is None:
            return None
        arguments = (node.right.elts if isinstance(node.right, ast.Tuple) else (node.right,)) if percent else node.args
        keywords = () if percent else node.keywords
        if len(arguments) + len(keywords) > _MAX_WORDS or any(keyword.arg is None for keyword in keywords):
            return None
        states = {()}
        for argument in (*arguments, *(keyword.value for keyword in keywords)):
            choices = self.constant_strings(argument, origin, seen, budget)
            if choices is None or len(states) * len(choices) > _MAX_CHOICES:
                return None
            states = {state + (choice,) for state in states for choice in choices}
        if len(states) * len(templates) > _MAX_CHOICES:
            return None
        result = set()
        fields = _FORMAT_FIELD
        for template in templates:
            for values in states:
                output, size, position, automatic, explicit = [], 0, 0, 0, False
                used = 0
                while position < len(template):
                    if len(output) >= _MAX_WORDS:
                        return None
                    char = template[position]
                    if percent and char == "%":
                        if position + 1 >= len(template):
                            return None
                        conversion = template[position + 1]
                        position += 2
                        if conversion == "%":
                            piece = "%"
                        elif conversion in "sra" and used < len(values):
                            piece = values[used]
                            used += 1
                            if conversion != "s":
                                if len(piece) > (_MAX_TEXT - 2) // 10:
                                    return None
                                piece = repr(piece) if conversion == "r" else ascii(piece)
                        else:
                            return None  # Unsupported widths/conversions are never evaluated.
                    elif not percent and char in "{}":
                        if template.startswith(char * 2, position):
                            piece, position = char, position + 2
                        elif char == "{":
                            field = fields.match(template, position)
                            if field is None:
                                return None
                            name, conversion = field.groups()
                            if name and not name.isdigit():
                                keys = [keyword.arg for keyword in keywords]
                                if name not in keys:
                                    return None
                                index = len(arguments) + keys.index(name)
                            elif name:
                                if automatic or len(name) > len(str(_MAX_WORDS)):
                                    return None
                                explicit = True
                                index = int(name)
                                if index >= len(arguments):
                                    return None
                            else:
                                if explicit:
                                    return None
                                index, automatic = automatic, automatic + 1
                                if index >= len(arguments):
                                    return None
                            if index >= len(values):
                                return None
                            piece = values[index]
                            if conversion in ("r", "a"):
                                if len(piece) > (_MAX_TEXT - 2) // 10:
                                    return None
                                piece = repr(piece) if conversion == "r" else ascii(piece)
                            position = field.end()
                        else:
                            return None
                    else:
                        # Copy a bounded literal run, not one allocation per character.
                        end = position + 1
                        special = "%" if percent else "{}"
                        while end < len(template) and template[end] not in special:
                            end += 1
                        piece, position = template[position:end], end
                    if size + len(piece) > _MAX_TEXT:
                        return None
                    size += len(piece)
                    output.append(piece)
                if percent and used != len(values):
                    return None
                result.add("".join(output))
        return result

    def concatenate(self, node, origin, seen):
        left, right = self.values(node.left, origin, seen), self.values(node.right, origin, seen)
        if len(left) * len(right) > _MAX_CHOICES:
            return {None}
        opaque = any(isinstance(a, _Argv) != isinstance(b, _Argv) for a in left for b in right)
        if opaque and len(left) * len(right) == _MAX_CHOICES:
            return {None}  # Reserve the uncertainty alternative before allocating results.
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
                elif isinstance(a, _Argv) and not isinstance(b, _Argv) and len(a.items) < _MAX_WORDS:
                    result.add(_Argv(a.kind, a.items + (_SPLICE,)))  # Preserve the known prefix around an opaque suffix.
                    result.add(None)  # Retain unresolved construction evidence as well as known words.
                elif isinstance(b, _Argv) and not isinstance(a, _Argv) and len(b.items) < _MAX_WORDS:
                    result.add(_Argv(b.kind, (_SPLICE,) + b.items))  # Preserve the known suffix around an opaque prefix.
                    result.add(None)
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
        if node is _UNRESOLVED_IMPORT:
            return {_UNRESOLVED_IMPORT}
        result = self._values(node, origin, seen)
        if any(value is None or value is _UNRESOLVED_IMPORT or isinstance(value, _Shell)
               and (value.holes or value.hidden) for value in result):
            key = origin, id(node)
            if key not in self._constant_checks and len(self._constant_checks) < _MAX_DEPTH:
                self._constant_checks.add(key)
                try:
                    constants = self.constant_strings(node, origin, seen)
                finally:
                    self._constant_checks.remove(key)
                if constants is not None:
                    result = constants
        if None in result:
            marker = self.unknown_value(node, origin)
            if marker is _UNRESOLVED_IMPORT:
                result = (result - {None}) | {marker}
        return result

    def unknown_value(self, node, origin):
        """Type unknown sources without recursively re-entering their provenance check."""
        if not isinstance(node, ast.AST) or getattr(self, "_checking_value_source", False):
            return None
        self._checking_value_source = True
        try:
            return _UNRESOLVED_IMPORT if self.bearing(node, origin, unresolved_only=True) else None
        finally:
            self._checking_value_source = False

    def _values(self, node, origin, seen=frozenset()):
        if node is None or node is _UNRESOLVED_IMPORT or id(node) in seen or len(seen) >= _MAX_DEPTH:
            return {None}
        seen = seen | {id(node)}
        if isinstance(node, (ast.For, ast.comprehension)):
            return {v for sequence in self.values(node.iter, origin, seen)
                    for v in (sequence.items if isinstance(sequence, _Argv) else (None,))} or {None}
        names, _, _ = self.contexts[origin]
        if isinstance(node, ast.Constant) and node.value is None:
            return {_NONE}  # Explicit None selects the argv head; it is not an unresolved value.
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
        capture = captured_module(node, names, origin, self.modules, helper_identity=self.helper_identity)
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
            constants = self.constant_strings(node, origin, seen - {id(node)})
            if constants is not None:
                return constants
            left = self.values(node.body, origin, seen)
            right = self.values(node.orelse, origin, seen)
            if len(left) + len(right) >= _MAX_CHOICES:
                return {_UNRESOLVED_IMPORT}
            return left | right | {_UNRESOLVED_IMPORT}
        if (isinstance(node, ast.Call) and self.helper_identity(node.func, origin) == "shlex.quote"
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
        values = self.values(executable, origin)
        if _NONE in values:
            values = {_USE_HEAD if item is _NONE else item for item in values}
        if None in values or _UNRESOLVED_IMPORT in values:
            constants = self.constant_strings(executable, origin)
            if constants is not None:
                return constants
        return values

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
                positions = {}
                for _ in self.argv_programs(vector, fragment=False, executable=program, source_positions=positions):
                    pass
                module_operand = positions.get("index") if positions.get("mode") == "module" else None
                valid_words = all(index == module_operand or isinstance(word, str)
                                  or word is _PYTHON or word is _OPTION_PREFIX
                                  or isinstance(word, tuple) and len(word) == 2 and word[0] == "captured-module"
                                  for index, word in enumerate(vector.items))
                if not valid_words or not isinstance(program, str) and program is not _PYTHON:
                    yield None
                else:
                    yield _Launch(program, vector, False)

    def opaque_command(self, node, origin, seen=frozenset(), budget=None):
        """Unknown command expressions stay opaque unless an existing model classifies them."""
        if not isinstance(node, ast.AST):
            return node is None or node is _UNRESOLVED_IMPORT
        budget = [0] if budget is None else budget
        if id(node) in seen or len(seen) >= _MAX_DEPTH or budget[0] >= _MAX_WORDS:
            return True
        budget[0] += 1
        seen = seen | {id(node)}
        if isinstance(node, (ast.List, ast.Tuple)):
            return bool(node.elts) and self.opaque_command(node.elts[0], origin, seen, budget)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {"list", "tuple"} and len(node.args) == 1 and not node.keywords):
            return self.opaque_command(node.args[0], origin, seen, budget)
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Call):
            pure = self.helper_identity(node.func, origin) is not None
            if isinstance(node.func, ast.Name) and node.func.id in {"str", "repr", "ascii", "bytes"}:
                scope = self.contexts[origin][0].at[id(node.func)]
                while scope is not None and (node.func.id not in scope.bound or scope.kind == "class"):
                    scope = scope.parent
                pure |= scope is None
            if isinstance(node.func, ast.Attribute) and node.func.attr in _STRING_METHODS:
                pure |= node.func.attr != "format" or self.format_conversion(node, origin)
            return not pure or self.bearing(node, origin, unresolved_only=True)
        if not isinstance(node, ast.Name):
            return True
        names, bindings, _ = self.contexts[origin]
        scope = names.at[id(node)]
        while scope is not None:
            scope = binding_scope(scope, node.id)
            choices = bindings.get((scope, node.id), ())
            if choices or node.id in scope.bound:
                if not choices or len(choices) > _MAX_CHOICES:
                    return True
                return any(self.opaque_command(value, origin, seen, budget) for value in choices)
            scope = scope.parent
        return True

    def launch_resolution(self, node, api, origin):
        """Fill unresolved source/selector outcomes without replacing no-program proofs."""
        key = origin, id(node), api
        if key in self._launch_cache:
            return self._launch_cache[key]
        if len(self._launch_cache) >= _MAX_WORDS:
            return _LaunchResolution((), "spawn verdict limit", False)
        extracted = api_arguments(node, api)
        command = self.construction_command(node, api)
        fields = api_executable_fields(node, api)
        executable = (extracted[0] if extracted is not None else
                      fields[0] if fields else None)
        evidence = self.command_evidence(command, origin, executable=executable)
        opaque_values = []
        resolved_keywords, _ = api_keywords(node, key_resolver=lambda key: self.constant_strings(key, origin),
                                           opaque_values=opaque_values)
        for value in opaque_values:
            extra = self.command_evidence(value, origin)
            evidence = _CommandEvidence(*(left or right for left, right in zip(evidence, extra)))
        for field in fields or ():
            if field is not executable:
                extra = self.command_evidence(command, origin, executable=field)
                evidence = _CommandEvidence(*(left or right for left, right in zip(evidence, extra)))
        reason = "unresolved selector or program source" if evidence.requires_review else None
        if resolved_keywords is None:
            reason = reason or "keyword evidence limit"
        if fields is None:
            reason = "executable evidence limit"
        executables = self.effective_executables(executable, origin)
        native_override = bool(executables) and all(isinstance(item, str)
            and not python_word(item) and not shell_word(item) for item in executables)
        native_program = native_override and all(command_basename(item) not in _WRAPPER_GRAMMAR.keys() | _UNKNOWN_WRAPPERS
                                                 for item in executables)
        last_input = 8 if api.startswith("subprocess.") else 2 if api.startswith("os.spawn") else 1
        if api.rsplit(".", 1)[1].startswith(("execl", "spawnl")):
            last_input = len(node.args) - 1  # Every variadic argv slot can supply a selector or its source.
        if extracted is None and (evidence.interpreter or evidence.selector or evidence.content
                or not native_program and any(isinstance(argument, ast.Starred) and index <= last_input
                       for index, argument in enumerate(node.args))):
            reason = "unresolved launch arguments"
        names = self.contexts[origin][0]
        if any(isinstance(item, ast.Name) and item.id in names.at[id(item)].opaque
               for item in ast.walk(node.func)):
            reason = "unresolved class callee"
        programs = []
        for program in self.launch_programs(node, api, origin):
            if len(programs) >= _MAX_WORDS:
                raise ValueError(origin + ": literal occurrence limit")
            programs.append(program)
            if program is None or program is _UNRESOLVED_MODULE:
                reason = reason or "unresolved program source"
            elif isinstance(program, str):
                if len(program) > _MAX_TEXT:
                    raise ValueError(origin + ": literal program text limit")
        # A whole unknown command has no established head or operand positions.
        # Partial native argv and transparent helper constructions retain the
        # existing parser's no-program classification.
        expression = ast.Tuple(elts=list(command)) if isinstance(command, tuple) else command
        values = self.values(expression, origin)
        if (executable is not None and evidence.requires_review
                and any(item is None or item is _UNRESOLVED_IMPORT for item in executables)):
            reason = reason or "unresolved executable"
        if (evidence.requires_review and any(item is None or item is _UNRESOLVED_IMPORT for item in values)
                and not native_override and self.opaque_command(expression, origin)):
            reason = reason or "unresolved command value"
        result = _LaunchResolution(tuple(programs), reason,
                                   evidence.module or any(item is _UNRESOLVED_MODULE for item in programs))
        self._launch_cache[key] = result
        return result

    def selector_owner(self, node, origin, fallback):
        """Retain a local helper's existing ownership of a Python selector prefix."""
        owners, work = set(), 0
        names = self.contexts[origin][0]
        root = names.at[id(self.modules[origin])].namespace
        for api in self.imports.names[origin].resolve(node.func) & RAW:
            if self.launch_resolution(node, api, origin).reason is None:
                continue
            command = self.construction_command(node, api)
            expression = ast.Tuple(elts=list(command)) if isinstance(command, tuple) else command
            if not isinstance(expression, ast.AST):
                continue
            for child in ast.walk(expression):
                if work >= _MAX_WORDS:
                    return fallback
                work += 1
                if not isinstance(child, ast.Call):
                    continue
                returns = self.called_returns(child.func, origin, call=child)
                if returns is None:
                    return fallback
                for item in returns:
                    value, value_origin = item if isinstance(item, tuple) else (item, origin)
                    if value_origin != origin:
                        return fallback  # Only a local helper can take this source owner's selector row.
                    if work >= _MAX_WORDS:
                        return fallback
                    work += 1
                    for choice in self.values(value, value_origin):
                        if (isinstance(choice, _Argv) and choice.items
                                and (choice.items[0] is _PYTHON or python_word(choice.items[0]))
                                and any(value_selector_hint(word) for word in choice.items[1:])):
                            if len(owners) >= _MAX_CHOICES:
                                return fallback
                            namespace = self.contexts[value_origin][0].at[id(value)].namespace
                            owners.add(namespace.removeprefix(root + ".").replace(".<locals>", ""))
        return next(iter(owners)) if len(owners) == 1 else fallback

    def string_receiver_proven(self, node, origin, seen=frozenset(), budget=None):
        """Prove a modeled string value, rather than trusting a local method spelling."""
        budget = [_MAX_WORDS] if budget is None else budget
        if not isinstance(node, ast.AST) or id(node) in seen or len(seen) >= _MAX_DEPTH or budget[0] <= 0:
            return False
        budget[0] -= 1
        seen = seen | {id(node)}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return (self.string_receiver_proven(node.left, origin, seen, budget)
                    and self.string_receiver_proven(node.right, origin, seen, budget))
        if isinstance(node, ast.IfExp):
            return (self.string_receiver_proven(node.body, origin, seen, budget)
                    and self.string_receiver_proven(node.orelse, origin, seen, budget))
        values = self.values(node, origin)
        if values and len(values) <= _MAX_CHOICES and all(
                isinstance(value, (str, _Quoted)) or value is _PYTHON for value in values):
            return True
        names, bindings, _ = self.contexts[origin]
        if isinstance(node, ast.Call):
            if self.helper_identity(node.func, origin) in {"shlex.quote", "shlex.join", "os.fspath"}:
                return True
            if isinstance(node.func, ast.Name) and node.func.id in {"str", "repr", "ascii", "bytes"}:
                scope = names.at[id(node.func)]
                while scope is not None and node.func.id not in scope.bound:
                    scope = scope.parent
                if scope is None:
                    return True  # These are the unshadowed builtins, not local name patterns.
            if isinstance(node.func, ast.Attribute) and node.func.attr in _STRING_METHODS:
                return self.string_receiver_proven(node.func.value, origin, seen, budget)
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Name):
            scope = names.at[id(node)]
            while scope is not None:
                scope = binding_scope(scope, node.id)
                choices = bindings.get((scope, node.id), ())
                if choices or node.id in scope.bound:
                    if (len(choices) > _MAX_CHOICES or _UNRESOLVED_IMPORT in choices
                            or node.id in scope.imports or scope.star_imports):
                        return False
                    expressions = [value for value in choices if isinstance(value, ast.AST)]
                    return (bool(expressions) and len(expressions) == len(choices)
                            and all(self.string_receiver_proven(value, origin, seen, budget)
                                    for value in expressions))
                scope = scope.parent
        return False

    def definite_bindings(self, origin):
        """Index direct declarations without promoting writes from a conditional body."""
        names = self.contexts[origin][0]
        cached = self._definite_cache.get(origin)
        if cached is None or cached[0] is not names:
            definite, count = set(), 0
            for work, parent in enumerate(ast.walk(self.modules[origin])):
                if work >= _MAX_WORDS * _MAX_DEPTH:
                    self._definite_cache[origin] = names, None
                    return None
                if not isinstance(parent, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if len(parent.body) > _MAX_WORDS:
                    self._definite_cache[origin] = names, None
                    return None
                if not parent.body:
                    continue
                scope = names.at[id(parent)] if isinstance(parent, ast.Module) else names.at[id(parent.body[0])]
                for statement in parent.body:
                    locals_ = ()
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        locals_ = (statement.name,)
                    elif isinstance(statement, (ast.Import, ast.ImportFrom)):
                        locals_ = (("*",) if isinstance(statement, ast.ImportFrom)
                                   and any(alias.name == "*" for alias in statement.names)
                                   else import_bindings(statement, origin))
                    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                        if statement.value is None:
                            continue
                        targets = statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
                        if len(targets) > _MAX_WORDS:
                            self._definite_cache[origin] = names, None
                            return None
                        locals_ = (target.id for target in targets if isinstance(target, ast.Name))
                    for local in locals_:
                        if count >= _MAX_WORDS:
                            self._definite_cache[origin] = names, None
                            return None
                        count += 1
                        if binding_scope(scope, local) is scope:
                            definite.add((scope, local))
            self._definite_cache[origin] = names, definite
            cached = names, definite
        return cached[1]

    def definite_name(self, node, origin):
        """Prove a binding exists without relying on a conditional statement."""
        if not isinstance(node, ast.Name):
            return False
        definite = self.definite_bindings(origin)
        if definite is None:
            return False
        names = self.contexts[origin][0]
        scope = names.at[id(node)]
        while scope is not None:
            scope = binding_scope(scope, node.id)
            if node.id in scope.bound:
                return (scope, node.id) in definite
            if scope.star_imports:
                return (scope, "*") in definite
            scope = scope.parent
        return False

    def builtin_name(self, node, origin):
        if not isinstance(node, ast.Name):
            return None
        scope = self.contexts[origin][0].at[id(node)]
        while scope is not None:
            scope = binding_scope(scope, node.id)
            if node.id in scope.bound or scope.star_imports:
                return None
            scope = scope.parent
        return node.id

    def builtin_base(self, node, origin):
        """Builtin type identities cannot inherit an in-repository class."""
        name = self.builtin_name(node, origin)
        if name in _BUILTIN_BASES:
            return not self.export_changed("builtins." + name)
        terminals = {"builtins." + name for name in _BUILTIN_BASES}
        return self.reference_identity(node, origin, terminals) is not None

    def receiver_binding(self, node, origin):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        names = self.contexts[origin][0]
        scope = binding_scope(names.at[id(node)], node.name)
        arguments = node.args.posonlyargs or node.args.args
        if scope.kind != "class" or not arguments:
            return None
        classmethod = (len(node.decorator_list) == 1 and (
            self.builtin_name(node.decorator_list[0], origin) == "classmethod"
            or self.reference_identity(node.decorator_list[0], origin, {"builtins.classmethod"}) is not None))
        if node.decorator_list and not classmethod:
            return None
        return names.at[id(arguments[0])], arguments[0].arg, scope

    def method_candidates(self, owner, attribute):
        """Union class lookup and subclass overrides; writes or unresolved bases fail closed."""
        if self._method_graph is None:
            records, written, unresolved = {}, {}, False
            receivers, writes = {}, []
            class_bindings, class_rebindings = set(), set()
            count = 0
            for origin, tree in self.modules.items():
                names = self.contexts[origin][0]
                for work, node in enumerate(ast.walk(tree)):
                    if work >= _MAX_WORDS * _MAX_DEPTH:
                        self._method_graph = False
                        return None
                    if isinstance(node, ast.ClassDef):
                        if count >= _MAX_WORDS or len(node.bases) > _MAX_CHOICES:
                            self._method_graph = False
                            return None
                        count += 1
                        outer = names.at[id(node)].namespace
                        if len(outer) + len(node.name) + 1 > _MAX_TEXT:
                            self._method_graph = False
                            return None
                        namespace = outer + "." + node.name
                        if not node.body:
                            self._method_graph = False
                            return None
                        scope = names.at[id(node.body[0])]
                        if scope.kind != "class" or scope.namespace != namespace:
                            self._method_graph = False
                            return None
                        # Alternative ClassDefs share a namespace, never a body scope.
                        records.setdefault(namespace, []).append((origin, node, (scope,), set()))
                        declaration = binding_scope(names.at[id(node)], node.name), node.name
                        class_bindings.add(declaration)
                        if node.decorator_list:
                            class_rebindings.add(declaration)
                    receiver = self.receiver_binding(node, origin)
                    if receiver is not None:
                        if len(receivers) >= _MAX_WORDS:
                            self._method_graph = False
                            return None
                        scope, label, owner_scope = receiver
                        receivers[scope, label] = owner_scope.namespace
                    name, target, mutation = None, None, False
                    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        name, target, mutation = node.attr, node.value, True
                    if isinstance(node, ast.Call):
                        setter = self.builtin_name(node.func, origin) in {"setattr", "delattr"}
                        setter |= bool(names.resolve(node.func) & {"builtins.setattr", "builtins.delattr"})
                        if setter:
                            target = node.args[0] if node.args else None
                            if (len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                                    and isinstance(node.args[1].value, str)):
                                name = node.args[1].value
                            mutation = True
                    if mutation:
                        if name is not None and len(name) > _MAX_TEXT or len(writes) >= _MAX_WORDS:
                            self._method_graph = False
                            return None
                        writes.append((origin, target, name))
            # A setter can mutate a class without rebinding its lexical name.
            # Distinguish that declaration metadata from an actual competing binding.
            for origin, tree in self.modules.items():
                names = self.contexts[origin][0]
                for work, node in enumerate(ast.walk(tree)):
                    if work >= _MAX_WORDS * _MAX_DEPTH:
                        self._method_graph = False
                        return None
                    labels = ()
                    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                        labels = (node.id,)
                    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        labels = (node.name,)
                    elif isinstance(node, ast.arg):
                        labels = (node.arg,)
                    elif isinstance(node, (ast.Import, ast.ImportFrom)):
                        if len(node.names) > _MAX_WORDS:
                            self._method_graph = False
                            return None
                        labels = import_bindings(node, origin)
                    elif isinstance(node, ast.ExceptHandler) and node.name:
                        labels = (node.name,)
                    elif type(node).__name__ in {"MatchAs", "MatchStar", "MatchMapping"}:
                        label = getattr(node, "name", None) or getattr(node, "rest", None)
                        labels = (label,) if label else ()
                    for label in labels:
                        key = binding_scope(names.at[id(node)], label), label
                        if key in class_bindings:
                            class_rebindings.add(key)
            constructor_unsafe_bases, constructor_unsafe_symbols = set(), set()
            for namespace, alternatives in records.items():
                for origin, node, _, bases in alternatives:
                    names = self.contexts[origin][0]
                    if (binding_scope(names.at[id(node)], node.name), node.name) in class_rebindings:
                        constructor_unsafe_symbols.add(namespace)
                    for base in node.bases:
                        if self.builtin_base(base, origin):
                            continue
                        targets = set()
                        for name in names.resolve(base):
                            extra = self.imports.resolve(name)
                            if len(targets) + len(extra) > _MAX_CHOICES:
                                unresolved = True
                                constructor_unsafe_bases.add(id(node))
                                break
                            targets.update(extra)
                        if not targets or not targets <= records.keys() or len(bases) + len(targets) > _MAX_CHOICES:
                            unresolved = True
                            constructor_unsafe_bases.add(id(node))
                        else:
                            bases.update(targets)
            remaining = [_MAX_WORDS]
            constructor_changes, constructor_cache = set(), {}
            constructor_work = [_MAX_WORDS]

            def conventional_constructor(namespace, ancestors=frozenset()):
                if namespace in ancestors or len(ancestors) >= _MAX_DEPTH:
                    return False
                if namespace in constructor_cache:
                    return constructor_cache[namespace]
                if (namespace not in records or namespace in constructor_unsafe_symbols
                        or constructor_work[0] <= 0
                        or None in constructor_changes or namespace in constructor_changes):
                    return False
                constructor_work[0] -= 1
                alternatives = records[namespace]
                if len(alternatives) > _MAX_CHOICES:
                    return False
                following = ancestors | {namespace}
                proven = True
                for origin, declaration, scopes, bases in alternatives:
                    if constructor_work[0] <= 0:
                        proven = False
                        break
                    constructor_work[0] -= 1
                    if (id(declaration) in constructor_unsafe_bases or declaration.decorator_list
                            or len(declaration.keywords) > _MAX_CHOICES
                            or any("__new__" in scope.bound for scope in scopes)):
                        proven = False
                        break
                    for keyword in declaration.keywords:
                        if constructor_work[0] <= 0:
                            proven = False
                            break
                        constructor_work[0] -= 1
                        if (keyword.arg != "metaclass" or self.reference_identity(
                                keyword.value, origin, {"builtins.type"}) != "builtins.type"):
                            proven = False
                            break
                    if not proven or not all(conventional_constructor(base, following) for base in bases):
                        proven = False
                        break
                constructor_cache[namespace] = proven
                return proven

            def owners(node, origin, seen=frozenset(), *, class_only=False, constructors=True):
                if node is None or id(node) in seen or len(seen) >= _MAX_DEPTH or remaining[0] <= 0:
                    return {None}
                remaining[0] -= 1
                names, bindings, _ = self.contexts[origin]
                following = seen | {id(node)}
                if isinstance(node, ast.Call):
                    if class_only:
                        return {None}  # A factory result is not a proven class constructor.
                    type_call = (self.builtin_name(node.func, origin) == "type"
                                 or self.reference_identity(node.func, origin, {"builtins.type"}) is not None)
                    if type_call:
                        if len(node.args) != 1 or node.keywords:
                            return {None}
                        return owners(node.args[0], origin, following, constructors=constructors)
                    if not constructors:
                        return {None}  # Constructor-hook writes cannot assume their receiver's result type.
                    result = owners(node.func, origin, following, class_only=True)
                    if None in result or not all(conventional_constructor(owner) for owner in result):
                        return {None}
                    return result
                if class_only and self.builtin_base(node, origin):
                    return set()  # A builtin instance cannot be an in-repository class's receiver.
                result, unrelated = set(), False
                for qualified in names.resolve(node):
                    targets = self.imports.resolve(qualified)
                    if len(result) + len(targets) > _MAX_CHOICES:
                        return {None}
                    for target in targets:
                        if target in records:
                            result.add(target)
                        elif target in self.imports.module_names:
                            unrelated = True
                if isinstance(node, ast.Name):
                    scope = names.at[id(node)]
                    while scope is not None:
                        scope = binding_scope(scope, node.id)
                        if node.id in scope.bound:
                            declaration = scope, node.id
                            if declaration in class_rebindings:
                                return {None}
                            receiver = receivers.get((scope, node.id))
                            if receiver is not None and not class_only:
                                result.add(receiver)
                            choices = bindings.get((scope, node.id), ())
                            if len(choices) > _MAX_CHOICES:
                                return {None}
                            for value in choices:
                                if value is None and (result or unrelated):
                                    continue  # A known class/receiver's declaration metadata is not another owner.
                                if value is _UNRESOLVED_IMPORT and result and declaration in class_bindings:
                                    continue  # Call-side mutation cannot rebind this proven class declaration.
                                extra = owners(value, origin, following, class_only=class_only,
                                               constructors=constructors)
                                if len(result) + len(extra) > _MAX_CHOICES:
                                    return {None}
                                result.update(extra)
                            break
                        scope = scope.parent
                elif isinstance(node, (ast.Constant, ast.List, ast.Tuple, ast.Dict, ast.Set)):
                    unrelated = True
                return result if result else set() if unrelated else {None}

            # A class hook assigned after its body is just as uncertain as a
            # declared __new__. Resolve these writes without assuming constructors.
            for origin, target, name in writes:
                if name is None or name == "__new__":
                    changed = owners(target, origin, constructors=False)
                    if changed & constructor_unsafe_symbols:
                        changed = {None}  # An unproven class alias can name any constructor's hook.
                    if len(constructor_changes) + len(changed) > _MAX_WORDS:
                        constructor_changes = {None}
                        break
                    constructor_changes.update(changed)
            total = 0
            for origin, target, name in writes:
                for namespace in owners(target, origin):
                    if total >= _MAX_WORDS:
                        self._method_graph = False
                        return None
                    total += 1
                    written.setdefault(namespace, set()).add(name)
            self._method_graph = records, written, unresolved
        if self._method_graph is False:
            return None
        records, written, unresolved = self._method_graph
        if unresolved or owner.namespace not in records:
            return None
        selected = {owner.namespace}
        for _ in range(len(records)):
            extra = {namespace for namespace, alternatives in records.items()
                     if any(bases & selected for _, _, _, bases in alternatives)}
            if extra <= selected:
                break
            selected.update(extra)
        related, pending = set(selected), list(selected)
        while pending:
            namespace = pending.pop()
            for _, _, _, bases in records[namespace]:
                for base in bases:
                    if base not in related:
                        if len(related) >= _MAX_WORDS:
                            return None
                        related.add(base)
                        pending.append(base)
        if any(attribute in written.get(namespace, ()) or None in written.get(namespace, ())
               for namespace in (*related, None)):
            return None
        pending, visited, found, work = list(selected), set(), [], 0
        while pending:
            namespace = pending.pop()
            if namespace in visited:
                continue
            if work >= _MAX_WORDS:
                return None
            work += 1
            visited.add(namespace)
            if len(namespace) + len(attribute) + 1 > _MAX_TEXT:
                return None
            if self.export_changed(namespace + "." + attribute):
                return None
            for origin, tree, scopes, bases in records[namespace]:
                names, bindings, _ = self.contexts[origin]
                local = False
                for scope in scopes:
                    declared = []
                    for node in ast.walk(tree):
                        if work >= _MAX_WORDS:
                            return None
                        work += 1
                        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == attribute
                                and binding_scope(names.at[id(node)], node.name) is scope):
                            if len(declared) >= _MAX_CHOICES:
                                return None
                            declared.append(node)
                    assigned = bindings.get((scope, attribute), ())
                    if len(found) + len(declared) + len(assigned) > _MAX_CHOICES:
                        return None
                    if declared or assigned:
                        definite = self.definite_bindings(origin)
                        if definite is None:
                            return None
                        local |= (scope, attribute) in definite
                        found.extend((value, origin) for value in declared)
                        found.extend((value, origin) for value in assigned if value is not None or not declared)
                if not local:
                    if len(pending) + len(bases) + work > _MAX_WORDS:
                        return None
                    pending.extend(bases)
        return tuple(found) if found else None

    def identity_decorator(self, node, origin):
        """Preserve only proven builtin descriptor identities."""
        if self.reference_identity(node, origin, {"builtins.staticmethod", "builtins.classmethod"}) is not None:
            return True
        if not isinstance(node, ast.Name) or node.id not in {"staticmethod", "classmethod"}:
            return False
        scope = self.contexts[origin][0].at[id(node)]
        while scope is not None:
            scope = binding_scope(scope, node.id)
            if node.id in scope.bound or scope.star_imports:
                return False
            scope = scope.parent
        return True

    def called_returns(self, function, origin, *, call=None, _factory=0, _depth=0,
                       _ancestors=frozenset(), _budget=None, _decorating=False):
        """Union bounded callable candidates' evidence; unsupported selections are unknown."""
        if _depth >= _MAX_DEPTH or id(function) in _ancestors or (_budget is not None and _budget[0] <= 0):
            return None
        names, bindings, _ = self.contexts[origin]
        if origin not in self._return_definitions:
            definitions, receivers, parameters = {}, {}, set()
            count = 0
            for work, node in enumerate(ast.walk(self.modules[origin])):
                if work >= _MAX_WORDS * _MAX_DEPTH:
                    return None
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                    if count >= _MAX_WORDS:
                        return None
                    count += 1
                    if not isinstance(node, ast.Lambda):
                        scope = binding_scope(names.at[id(node)], node.name)
                        definitions.setdefault((scope, node.name), []).append(node)
                        receiver = self.receiver_binding(node, origin)
                        if receiver is not None:
                            parameter_scope, label, owner_scope = receiver
                            receivers[parameter_scope, label] = owner_scope
                    if isinstance(node, ast.ClassDef):
                        continue  # Keep class identity; its body is not function return evidence.
                    args = node.args
                    count_parameters = (len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
                                        + int(args.vararg is not None) + int(args.kwarg is not None))
                    if count_parameters > _MAX_WORDS or len(parameters) + count_parameters > _MAX_WORDS:
                        return None
                    arguments = (*args.posonlyargs, *args.args, *args.kwonlyargs,
                                 *((args.vararg,) if args.vararg is not None else ()),
                                 *((args.kwarg,) if args.kwarg is not None else ()))
                    parameters.update((names.at[id(argument)], argument.arg) for argument in arguments)
            self._return_definitions[origin] = definitions, receivers, parameters
        definitions, receivers, parameters = self._return_definitions[origin]
        budget = [_MAX_WORDS] if _budget is None else _budget

        def receiver_owner(node):
            if not isinstance(node, ast.Name):
                return None, None
            scope = names.at[id(node)]
            while scope is not None:
                scope = binding_scope(scope, node.id)
                if node.id in scope.bound:
                    break
                scope = scope.parent
            return scope, receivers.get((scope, node.id))

        def callable_reference(node, seen=frozenset(), *, container=False):
            if id(node) in seen or len(seen) >= _MAX_DEPTH or budget[0] <= 0:
                return True
            budget[0] -= 1
            following = seen | {id(node)}
            if isinstance(node, ast.Lambda):
                return True
            if isinstance(node, ast.IfExp):
                return (callable_reference(node.body, following, container=container)
                        or callable_reference(node.orelse, following, container=container))
            if isinstance(node, ast.BoolOp):
                return any(callable_reference(value, following, container=container) for value in node.values)
            if isinstance(node, ast.Subscript):
                return callable_reference(node.value, following, container=True)
            if isinstance(node, (ast.List, ast.Tuple, ast.Dict, ast.Set)):
                values = node.values if isinstance(node, ast.Dict) else node.elts
                if len(values) > _MAX_CHOICES:
                    return True
                return any(callable_reference(value, following) for value in values)
            if isinstance(node, ast.Call):
                returns = self.called_returns(node.func, origin, call=node, _depth=_depth + len(following),
                                              _ancestors=_ancestors | following, _budget=budget)
                return (returns is None or any(isinstance(value, tuple)
                        or callable_reference(value, following, container=container) for value in returns))
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                _, owner = receiver_owner(node.value)
                if owner is not None and definitions.get((owner, node.attr)):
                    return True
                return False
            if not isinstance(node, ast.Name):
                return False
            scope = names.at[id(node)]
            while scope is not None:
                scope = binding_scope(scope, node.id)
                if (scope, node.id) in definitions or node.id in scope.imports or scope.star_imports:
                    return True
                if node.id in scope.bound:
                    choices = bindings.get((scope, node.id), ())
                    if len(choices) > _MAX_CHOICES:
                        return True
                    return any(callable_reference(value, following, container=container) for value in choices if value is not None)
                scope = scope.parent
            return False

        def decorated_target(node):
            if isinstance(node, ast.Name) and self.definite_name(node, origin):
                scope = names.at[id(node)]
                while scope is not None:
                    scope = binding_scope(scope, node.id)
                    if node.id in scope.bound:
                        declared = definitions.get((scope, node.id), ())
                        return bool(declared) and all(value.decorator_list for value in declared)
                    scope = scope.parent
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                _, owner = receiver_owner(node.value)
                methods = self.method_candidates(owner, node.attr) if owner is not None else None
                return methods is not None and all(isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef))
                                                   and value.decorator_list for value, _ in methods)
            return False

        def decorator_argument(node):
            if isinstance(node, ast.Lambda):
                return True
            if isinstance(node, ast.Name) and self.definite_name(node, origin):
                scope = names.at[id(node)]
                while scope is not None:
                    scope = binding_scope(scope, node.id)
                    if node.id in scope.bound:
                        return bool(definitions.get((scope, node.id))) or self.helper_identity(node, origin) is not None
                    scope = scope.parent
            return False

        def selection_form(node, decorating, factory):
            if isinstance(node, ast.Name):
                if self.builtin_name(node, origin) in PURE_BUILTINS:
                    return "pure-builtin" if factory == 0 and call is not None else "UNKNOWN"
                return "definite-name" if self.definite_name(node, origin) else "UNKNOWN"
            if isinstance(node, ast.Attribute):
                return "resolved-attribute"
            if isinstance(node, ast.Lambda):
                return "lambda"
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return "resolved-definition"
            if isinstance(node, ast.Call):
                if self.identity_decorator(node.func, origin) and len(node.args) == 1 and not node.keywords:
                    return "descriptor"
                if decorating or decorated_target(node.func):
                    return "decorator-model"
                if len(node.args) == 1 and not node.keywords and decorator_argument(node.args[0]):
                    return "decorator-application"
            return "UNKNOWN"

        def callback_arguments():
            callbacks = []
            if len(call.args) + len(call.keywords) > _MAX_WORDS:
                return None
            for value in call.args:
                if callable_reference(value):
                    if len(callbacks) >= _MAX_WORDS:
                        return None
                    callbacks.append(value)
            fields, unknown = api_keywords(call, key_resolver=lambda value: self.constant_strings(value, origin))
            # Unknown ** mappings can contain key= or a callable under another key.
            if fields is None or unknown:
                return None
            else:
                for name, value in fields.items():
                    key_callback = name == "key" and not (isinstance(value, ast.Constant) and value.value is None)
                    if key_callback or callable_reference(value):
                        if len(callbacks) >= _MAX_WORDS:
                            return None
                        callbacks.append(value)
            return callbacks

        callbacks, inspected_callbacks = (), False
        pending, found, seen, work = [(function, False, _depth, _ancestors, _factory, _decorating)], [], set(), 0
        while pending:
            node, selected, depth, ancestors, factory, decorating = pending.pop()
            if id(node) in ancestors or depth >= _MAX_DEPTH:
                return None
            key = id(node), selected, factory, decorating
            if key in seen:
                continue
            if work >= _MAX_WORDS or budget[0] <= 0:
                return None
            budget[0] -= 1
            seen.add(key)
            work += 1
            if node is None and not selected:
                continue  # Ordinary local declaration metadata adds no callable alternative.
            form = selection_form(node, decorating, factory)
            if form == "UNKNOWN":
                return None
            if form == "pure-builtin" and (not selected or decorating):
                if not inspected_callbacks:
                    callbacks, inspected_callbacks = callback_arguments(), True
                if callbacks is None:
                    return None
                if len(pending) + len(callbacks) + work > _MAX_WORDS:
                    return None
                for value in callbacks:
                    pending.append((value, True, depth + 1, ancestors | {id(node)}, 0, False))
            candidates = ()
            next_factory, next_decorating = factory, decorating
            if isinstance(node, ast.Name):
                scope = names.at[id(node)]
                while scope is not None:
                    scope = binding_scope(scope, node.id)
                    imported = node.id in scope.imports or node.id not in scope.bound and scope.star_imports
                    if imported and self.helper_identity(node, origin) is None:
                        # Helper identity follows imported_binding; declaration placeholders supply no return body.
                        return None
                    if node.id in scope.bound:
                        if (scope, node.id) in parameters:
                            return None  # A caller may replace a callable parameter, whatever its default.
                        declared = definitions.get((scope, node.id), ())
                        assigned = bindings.get((scope, node.id), ())
                        if len(declared) + len(assigned) > _MAX_CHOICES:
                            return None
                        if declared:
                            # None marks an ordinary declaration, not another callable alternative.
                            assigned = tuple(value for value in assigned if value is not None)
                        candidates = (*declared, *assigned)
                        break
                    scope = scope.parent
                if (not candidates and self.helper_identity(node, origin) is None
                        and self.builtin_name(node, origin) not in PURE_BUILTINS):
                    return None  # An opaque callable candidate is not an inspected native helper.
            elif isinstance(node, ast.Call):
                next_decorating = True
                if self.identity_decorator(node.func, origin) and len(node.args) == 1 and not node.keywords:
                    candidates, selected = (node.args[0],), True
                else:
                    candidates, selected, next_factory = (node.func,), True, factory + 1
            elif isinstance(node, ast.Attribute):
                scope, owner = receiver_owner(node.value)
                if owner is not None:
                    initializers = bindings.get((scope, node.value.id), ())
                    if (owner is None or len(initializers) > _MAX_CHOICES
                            or any(value is not None for value in initializers)):
                        return None
                    methods = self.method_candidates(owner, node.attr)
                    if methods is None:
                        return None
                    local = []
                    for candidate, target in methods:
                        if target == origin:
                            local.append(candidate)
                        else:
                            returns = self.called_returns(candidate, target, _factory=factory, _depth=depth + 1,
                                                          _ancestors=ancestors | {id(node)}, _budget=budget)
                            if returns is None or len(found) + len(returns) > _MAX_WORDS:
                                return None
                            found.extend(item if isinstance(item, tuple) else (item, target) for item in returns)
                    candidates = tuple(local)
                elif (self.helper_identity(node, origin) is None
                      and not (node.attr in _STRING_METHODS and self.string_receiver_proven(node.value, origin))):
                    return None  # An unmodeled method may return an interpreter command.
            elif isinstance(node, ast.Lambda):
                if len(found) + len(node.args.defaults) + len(node.args.kw_defaults) + 1 > _MAX_WORDS:
                    return None
                found.extend(value for value in (*node.args.defaults, *node.args.kw_defaults) if value is not None)
                if factory:
                    candidates, next_factory = (node.body,), factory - 1
                else:
                    found.append(node.body)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if len(node.decorator_list) > _MAX_CHOICES or len(node.decorator_list) + work > _MAX_WORDS:
                    return None
                replacement = None
                for decorator in node.decorator_list:
                    work += 1
                    if not self.identity_decorator(decorator, origin):
                        replacement = decorator
                        break
                if replacement is not None:
                    if len(pending) + work + 1 > _MAX_WORDS:
                        return None
                    # The outermost non-descriptor decorator determines the returned callable.
                    pending.append((replacement, True, depth + 1, ancestors | {id(node)}, factory + 1, True))
                    continue
                if (len(node.body) + work > _MAX_WORDS
                        or len(found) + len(node.args.defaults) + len(node.args.kw_defaults) > _MAX_WORDS):
                    return None
                found.extend(value for value in (*node.args.defaults, *node.args.kw_defaults) if value is not None)
                body = list(node.body)
                returned = []
                while body:
                    statement = body.pop()
                    if work >= _MAX_WORDS:
                        return None
                    work += 1
                    if isinstance(statement, (ast.Return, ast.Yield, ast.YieldFrom)):
                        if statement.value is not None:
                            if len(found) + len(returned) >= _MAX_WORDS:
                                return None
                            (returned if factory else found).append(statement.value)
                    elif not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                        for child in ast.iter_child_nodes(statement):
                            if len(body) + work >= _MAX_WORDS:
                                return None
                            body.append(child)
                if factory:
                    candidates, next_factory = returned, factory - 1
            elif selected or node is not None:
                return None  # An unresolved callable alternative is unknown even before selection.
            if len(candidates) > _MAX_CHOICES or len(pending) + len(candidates) + work > _MAX_WORDS:
                return None
            ancestors = ancestors | {id(node)}
            pending.extend((candidate, selected, depth + 1, ancestors, next_factory, next_decorating)
                           for candidate in candidates)
        return tuple(found)

    def command_evidence(self, command, origin, *, executable=None):
        """Keep uncertainty and interpreter evidence when command resolution loses words."""
        expression = ast.Tuple(elts=list(command)) if isinstance(command, tuple) else command
        content = expression is not None and self.bearing(expression, origin, unresolved_only=True)
        pending, visited = [(expression, origin, 0)], set()
        executables = self.effective_executables(executable, origin) or {None}
        if len(executables) > _MAX_CHOICES:
            return _CommandEvidence(True, True, True, True)
        if executable is not None and executables != {_USE_HEAD}:
            pending.append((executable, origin, 0))
        unresolved, interpreter, selector = False, False, False
        module, code = False, False
        work = 0

        def extend(target, items):
            for item in items:
                if len(target) + work >= _MAX_WORDS:
                    return False
                target.append(item)
            return True

        while pending:
            node, source, depth = pending.pop()
            key = source, node if isinstance(node, str) else id(node)
            if key in visited:
                continue
            visited.add(key)
            if depth >= _MAX_DEPTH or work >= _MAX_WORDS:
                return _CommandEvidence(True, True, True, True)
            work += 1
            if isinstance(node, str):
                binding = self.imported_binding(node)
                if binding is None:
                    unresolved = content = True
                    continue
                target, choices, imports = binding
                if any(item is None for item in choices):
                    return _CommandEvidence(True, True, True, True)  # Imported declarations provide no return body.
                extra = []
                if (not extend(extra, ((item, target, depth + 1) for item in choices))
                        or not extend(extra, ((item, None, depth + 1) for item in imports))):
                    return _CommandEvidence(True, True, True, True)
            elif isinstance(node, ast.AST):
                values = self.values(node, source)
                if None in values or _UNRESOLVED_IMPORT in values:
                    constants = self.constant_strings(node, source)
                    if constants is not None:
                        values = constants
                if _UNRESOLVED_IMPORT in values:
                    content |= self.bearing(node, source, unresolved_only=True)
                unknown = False
                words = []
                if not extend(words, values):
                    return _CommandEvidence(True, True, True, True)
                while words:
                    value = words.pop()
                    if value is _PYTHON:
                        interpreter = True
                    elif value is _OPTION_PREFIX:
                        continue  # The exact source-pinned option proof is known.
                    elif isinstance(value, _Argv):
                        if len(value.items) > _MAX_WORDS:
                            return _CommandEvidence(True, True, True, True)
                        allowed, module_operands, tails = None, None, None
                        for actual in executables:
                            positions, captures_for_actual, resolved_code = {}, Counter(), False
                            for program in self.argv_programs(value, fragment=False, executable=actual,
                                                              source_positions=positions):
                                if (positions.get("mode") == "code" and isinstance(program, tuple)
                                        and program[0] == "captured-module"):
                                    captures_for_actual[program] += 1
                                resolved_code |= positions.get("mode") == "code" and isinstance(program, str)
                            suffix = set(range(positions["tail"], len(value.items))) if resolved_code else set()
                            tails = suffix if tails is None else tails & suffix
                            index = positions.get("index") if positions.get("mode") == "module" else None
                            indices = set() if index is None else {index}
                            module_operands = indices if module_operands is None else module_operands & indices
                            allowed = captures_for_actual if allowed is None else allowed & captures_for_actual
                        allowed = allowed or Counter()
                        captures = Counter(word for word in value.items if isinstance(word, tuple)
                                           and len(word) == 2 and word[0] == "captured-module")
                        for index, word in enumerate(value.items):
                            if index in (tails or ()):
                                continue  # Arguments after a resolved -c source cannot change its program.
                            if index in (module_operands or ()):
                                continue  # ROUND-17c: this argument names a module, never inline source.
                            if word in captures and captures[word] <= allowed[word]:
                                continue  # Exactly a modeled, unchanged program operand.
                            if not extend(words, (word,)):
                                return _CommandEvidence(True, True, True, True)
                    elif isinstance(value, _Quoted):
                        text = self.text(value)
                        if not extend(words, (text if text is not None else None,)):
                            return _CommandEvidence(True, True, True, True)
                    elif isinstance(value, (str, _Shell)):
                        text = value.text if isinstance(value, _Shell) else value
                        if len(text) > _MAX_TEXT:
                            return _CommandEvidence(True, True, True, True)
                        tokens = text.split(None, _MAX_WORDS)
                        if len(tokens) > _MAX_WORDS:
                            return _CommandEvidence(True, True, True, True)
                        interpreter |= any(python_word(word.strip("'\";,()")) for word in tokens)
                        selector |= any(value_selector_hint(word) or selector_hint(word) for word in tokens)
                        modes = {python_selector(word.strip("'\";,()"))[0] for word in tokens}
                        module |= "module" in modes
                        code |= "code" in modes
                        unknown |= isinstance(value, _Shell) and bool(value.holes or value.hidden)
                    else:
                        unknown = True
                        if isinstance(value, tuple) and len(value) == 2 and value[0] == "captured-module":
                            content = True  # Captures elsewhere cannot waive launch uncertainty.
                unresolved |= unknown
                if not unknown:
                    continue
                names, bindings, _ = self.contexts[source]
                extra = []
                trusted = isinstance(node, ast.Call) and self.helper_identity(node.func, source) is not None
                children = (child for child in ast.iter_child_nodes(node)
                            if not (trusted and child is node.func))
                if not extend(extra, ((child, source, depth + 1) for child in children)):
                    return _CommandEvidence(True, True, True, True)
                if isinstance(node, ast.Name):
                    scope = names.at[id(node)]
                    while scope is not None:
                        scope = binding_scope(scope, node.id)
                        choices = bindings.get((scope, node.id), ())
                        if choices or node.id in scope.bound:
                            if not extend(extra, ((item, source, depth + 1) for item in choices)):
                                return _CommandEvidence(True, True, True, True)
                            break
                        scope = scope.parent
                if isinstance(node, ast.Call) and not trusted:
                    returns = self.called_returns(node.func, source, call=node)
                    if returns is None:
                        return _CommandEvidence(True, True, True, True)
                    for item in returns:
                        value, target = item if isinstance(item, tuple) else (item, source)
                        if not extend(extra, ((value, target, depth + 1),)):
                            return _CommandEvidence(True, True, True, True)
                if not extend(extra, ((name, None, depth + 1) for name in names.resolve(node))):
                    return _CommandEvidence(True, True, True, True)
            else:
                unresolved = True
                continue
            if len(pending) + len(extra) + work > _MAX_WORDS:
                return _CommandEvidence(True, True, True, True)
            pending.extend(extra)
        return _CommandEvidence(unresolved, interpreter, selector, content, module and not code)

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
        for vector in vectors:
            for program in executables:
                if shell:
                    text = vector.items[0] if isinstance(vector, _Argv) and vector.items else vector
                    if program is _PYTHON or python_word(program):
                        yield self.code(text)
                    elif program is None or program is _UNRESOLVED_IMPORT:
                        yield None  # An explicit unknown executable may select Python rather than a shell.
                    elif isinstance(text, (str, _Shell)):
                        yield from self.shell_programs(text)
                elif isinstance(vector, _Argv):
                    yield from self.argv_programs(vector, executable=program, fragment=False)

    def module_program(self, value):
        if not isinstance(value, str):
            return "external-module", None  # Unknown module operands use the import path (ROUND-17c).
        if not value.startswith(("aegis_core.", "aegis_cli.", "aegis_mcp.", "tools.")):
            return "external-module", value
        base = value.replace(".", "/")
        for target in (base + ".py", base + "/__main__.py"):
            if target in self.modules:
                return "captured-module", target
        return _UNRESOLVED_MODULE

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

    def argv_programs(self, value, *, fragment=True, executable=_USE_HEAD, depth=0,
                      source_positions=None):
        """Extract this argv's own program; the AST census visits nested containers separately."""
        items = value.items
        if not items:
            return
        if depth >= _MAX_DEPTH or len(items) > _MAX_WORDS:
            yield None
            return
        if isinstance(items[0], _Argv):
            return
        prefixes = [index for index, word in enumerate(items) if word is _OPTION_PREFIX]
        if prefixes and (prefixes != [4] or items[1:4] != ("-I", "-S", "-B")
                         or len(items) <= 5 or items[5] != "-c"):
            yield None
            return
        head = items[0] if executable is _USE_HEAD else executable
        if isinstance(head, tuple) and len(head) == 2 and head[0] == "captured-module":
            yield None  # Captured module bytes are never a proven interpreter name.
            return
        if shell_word(head):
            yield from self.shell_argv_programs(items, head, depth)
            return
        wrapper = command_basename(head)
        original_wrapper = command_basename(items[0])
        wrappers = _WRAPPER_GRAMMAR.keys() | _UNKNOWN_WRAPPERS
        if wrapper in wrappers or original_wrapper in wrappers:
            if executable is not _USE_HEAD:
                yield None
                return  # Explicit executable overrides are outside the closed wrapper model.
            suffix = closed_wrapper_argv(items)
            if suffix is None:
                yield None
                return
            if not suffix:
                return
            start = len(items) - len(suffix)
            positions = {}
            for program in self.argv_programs(_Argv(value.kind, suffix), fragment=False,
                                              depth=depth + 1, source_positions=positions):
                yield _UNRESOLVED_MODULE if program == ("external-module", None) else program
            if source_positions is not None and positions:
                source_positions.update(positions)
                for key in ("index", "tail"):
                    if source_positions.get(key) is not None:
                        source_positions[key] += start
            return
        hint = any(value_selector_hint(word) for word in items)
        interpreter = head is _PYTHON or python_word(head)
        uncertain = head is None or head is _UNRESOLVED_IMPORT or head is _SPLICE or isinstance(head, (_Shell, _Quoted))
        if not interpreter and hint:
            for position, word in enumerate(items[1:], 1):
                mode, attached = python_selector(word)
                if mode != "code":
                    continue
                source = attached if attached is not None else self.code(items[position + 1]) if position + 1 < len(items) else None
                if not isinstance(source, str):
                    continue
                if len(source) > _MAX_TEXT:
                    yield None
                    return
                try:
                    ast.parse(source)
                except (SyntaxError, ValueError, UnicodeError, RecursionError):
                    continue  # Only a parsable literal is inspected independently of its head.
                yield source
        if uncertain and not fragment:
            if hint or len(items) > 1:
                yield None  # Its selector may be Python; its source language is unproven.
            return
        if not hint and not (interpreter and any(not isinstance(word, str) and word is not _OPTION_PREFIX
                                                for word in items[1:])):
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
            shell = next((index for index, word in enumerate(items[1:], 1) if shell_word(word)), None)
            if shell is not None:
                yield from self.shell_argv_programs(items[shell:], items[shell], depth)
                return
            if any(word is _PYTHON or python_word(word) for word in items[1:]):
                yield None  # Interpreter/selector present but not consumed at the command position.
                return
            return
        while index < len(items):
            word = items[index]
            if word is _OPTION_PREFIX:
                index += 1
                continue  # The exact pinned proof permits only options here.
            if not isinstance(word, str):
                yield None  # Only resolved strings may occupy an option/selector position.
                return
            mode, attached = python_selector(word)
            if mode in {"code", "module"}:
                source = None
                if attached is not None:
                    source = attached
                elif index + 1 < len(items):
                    source = self.code(items[index + 1])
                elif fragment:
                    return
                if interpreter and source_positions is not None:
                    source_positions.update(mode=mode, index=index + 1 if attached is None
                                            and index + 1 < len(items) else None,
                                            tail=index + (2 if attached is None else 1))
                if mode == "module":
                    yield (_UNRESOLVED_MODULE if attached is None and index + 1 >= len(items)
                           else self.module_program(source))
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

    def format_conversion(self, node, origin):
        """Prove plain string fields; attribute and subscript fields perform operations."""
        templates = self.constant_strings(node.func.value, origin)
        if templates is None:
            return False
        work = 0
        for template in templates:
            position = 0
            for brace in re.finditer(r"[{}]", template):
                if work >= _MAX_WORDS:
                    return False
                work += 1
                if brace.start() < position:
                    continue
                char, position = brace.group(), brace.start()
                if template.startswith(char * 2, position):
                    position += 2
                else:
                    field = _FORMAT_FIELD.match(template, position) if char == "{" else None
                    if field is None:
                        return False
                    position = field.end()
        return True

    def bearing(self, node, origin, seen=frozenset(), *, unresolved_only=False):
        """Walk sources, preserving unknown content through every value wrapper."""
        pending, visited = [(node, origin, False, False)], set()

        def enqueue(value, source, operated, path_operated=False):
            if len(pending) + len(visited) >= _MAX_WORDS:
                return False
            pending.append((value, source, operated, path_operated))
            return True

        while pending:
            value, source, operated, path_operated = pending.pop()
            if value is _UNRESOLVED_IMPORT:
                return True
            if value is None:
                continue  # Parameters and ordinary declarations are opaque, not content sources.
            key = (value, operated, path_operated) if isinstance(value, str) else (source, id(value), operated, path_operated)
            if key in visited or not isinstance(value, str) and id(value) in seen:
                continue
            visited.add(key)
            if isinstance(value, str):
                if self.export_changed(value) or self.imported(value, frozenset()) == {None}:
                    return True
                binding = self.imported_binding(value)
                if binding is None:
                    return True
                target, choices, imports = binding
                for item in choices:
                    if not enqueue(item, target, operated, path_operated):
                        return True
                for qualified in imports:
                    if not enqueue(qualified, None, operated, path_operated):
                        return True
                continue
            if not isinstance(value, ast.AST):
                continue
            names, bindings, _ = self.contexts[source]
            capture = captured_module(value, names, source, self.modules, helper_identity=self.helper_identity)
            if capture is not None and not self.export_changed("pathlib.Path"):
                if operated:
                    return True
                continue  # Only the exact, unchanged captured bytes are known.
            if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
                text = value.value
                if len(text) > _MAX_TEXT:
                    return True
                if isinstance(text, bytes):
                    text = text.decode("latin-1")
                words = text.split(None, _MAX_WORDS)
                if len(words) > _MAX_WORDS or any(
                        value_selector_hint(word) or selector_hint(word) for word in words):
                    return True
                continue
            if isinstance(value, (ast.For, ast.AsyncFor, ast.comprehension)):
                if not enqueue(value.iter, source, True, True):
                    return True
                if isinstance(value, ast.comprehension):
                    for condition in value.ifs:
                        if not enqueue(condition, source, True, True):
                            return True
                continue
            if isinstance(value, ast.Call):
                # These helpers transform inputs without introducing a new source.
                # Their entire proven callee reference is known; every argument remains live.
                identity = self.helper_identity(value.func, source)
                if path_operated and identity in {"pathlib.Path", "pathlib.PurePath", "pathlib.Path.cwd", "pathlib.Path.home"}:
                    return True
                trusted = identity is not None
                conversion = identity == "os.fspath" or identity in {
                    "pathlib.Path", "pathlib.PurePath", "pathlib.Path.cwd", "pathlib.Path.home"}
                if isinstance(value.func, ast.Name) and value.func.id in {"str", "repr", "ascii", "bytes"}:
                    scope = names.at[id(value.func)]
                    while scope is not None and (value.func.id not in scope.bound or scope.kind == "class"):
                        scope = scope.parent
                    conversion = scope is None
                if isinstance(value.func, ast.Attribute):
                    if value.func.attr in _CONTENT_METHODS:
                        return True
                    if not trusted and value.func.attr in _STRING_METHODS:
                        if not enqueue(value.func.value, source, True, True):
                            return True
                        trusted = True
                        conversion = value.func.attr == "format" and self.format_conversion(value, source)
                if not trusted and not enqueue(value.func, source, True, True):
                    return True
                for argument in value.args:
                    if not enqueue(argument, source, True, not conversion):
                        return True
                for keyword in value.keywords:
                    if not enqueue(keyword.value, source, True, not conversion):
                        return True
                continue
            if isinstance(value, (ast.Name, ast.Attribute)):
                if isinstance(value, ast.Name) and value.id == "open":
                    scope = names.at[id(value)]
                    while scope is not None and ("open" not in scope.bound or scope.kind == "class"):
                        scope = scope.parent
                    if scope is None:
                        return True  # Preserve the builtin reader through stored callable aliases too.
                if isinstance(value, ast.Attribute) and value.attr in _CONTENT_METHODS:
                    return True  # A stored reader keeps its source when called via an alias.
                resolved = names.resolve(value)
                if resolved in ({"sys.executable"}, {"os.devnull"}):
                    if resolved == {"sys.executable"} and not unresolved_only:
                        return True
                    continue
                for qualified in resolved:
                    if not enqueue(qualified, None, operated, path_operated):
                        return True
                if isinstance(value, ast.Name):
                    scope = names.at[id(value)]
                    while scope is not None:
                        scope = binding_scope(scope, value.id)
                        choices = bindings.get((scope, value.id), ())
                        if choices or value.id in scope.bound:
                            for item in choices:
                                if not enqueue(item, source, operated, path_operated):
                                    return True
                            break
                        scope = scope.parent
                    continue
            if isinstance(value, ast.FormattedValue):
                if not enqueue(value.value, source, True, False):
                    return True
                if value.format_spec is not None and not enqueue(value.format_spec, source, True, True):
                    return True
                continue
            if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
                templates = self.values(value.left, source)
                if templates and all(isinstance(text, str) for text in templates):
                    if not enqueue(value.left, source, True, False) or not enqueue(value.right, source, True, False):
                        return True
                    continue
            # Transport preserves Path values. String conversion ends Path operations;
            # every transformation of captured program bytes still removes its waiver.
            unchanged = isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.IfExp, ast.BoolOp))
            for child in ast.iter_child_nodes(value):
                if not enqueue(child, source, operated or not unchanged or isinstance(value, ast.BoolOp),
                               path_operated or not unchanged):
                    return True
        return False

    def imported_argv_source_words(self, qualified, seen):
        """Follow the same re-export chain as values(), retaining AST operands."""
        if qualified in seen or self.export_changed(qualified) or len(seen) >= _MAX_DEPTH:
            return {((None, _UNRESOLVED_IMPORT),)}
        if self.imported(qualified, seen) == {None}:
            return {((None, _UNRESOLVED_IMPORT),)}
        seen = seen | {qualified}
        binding = self.imported_binding(qualified)
        if binding is None:
            return {((None, _UNRESOLVED_IMPORT),)}
        target, values, sources = binding
        result = set()
        choices = (self.argv_source_words(value, target, seen) for value in values)
        imports = (self.imported_argv_source_words(name, seen) for name in sources)
        for groups in (choices, imports):
            for extra in groups:
                if len(result) + len(extra) > _MAX_CHOICES:
                    return {((None, _UNRESOLVED_IMPORT),)}
                result.update(extra)
        return result or {((None, _UNRESOLVED_IMPORT),)}

    def argv_source_words(self, node, origin, seen=frozenset()):
        """Retain AST operands through flattening; this never resolves a program."""
        def fallback():
            if isinstance(node, tuple):
                if len(node) > _MAX_WORDS:
                    return {((origin, _UNRESOLVED_IMPORT),)}
                bearing = any(self.bearing(item, origin, unresolved_only=True) for item in node)
            else:
                bearing = isinstance(node, ast.AST) and self.bearing(node, origin, unresolved_only=True)
            return {((origin, _UNRESOLVED_IMPORT),)} if bearing else set()

        if node is _UNRESOLVED_IMPORT:
            return {((origin, node),)}
        if node is None or id(node) in seen or len(seen) >= _MAX_DEPTH:
            return fallback()
        seen = seen | {id(node)}
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return {((origin, node),)}  # A known word is source data, never an unknown marker.
        if isinstance(node, (ast.For, ast.comprehension)):
            result = set()
            for words in self.argv_source_words(node.iter, origin, seen):
                for item_origin, item in words:
                    extra = self.argv_source_words(item, item_origin, seen)
                    if len(result) + len(extra) > _MAX_CHOICES:
                        return fallback()
                    result.update(extra)
            return result or fallback()
        if isinstance(node, tuple):
            return {tuple((origin, item) for item in node)} if len(node) <= _MAX_WORDS else fallback()
        if isinstance(node, (ast.List, ast.Tuple)):
            if len(node.elts) > _MAX_WORDS:
                return fallback()
            states = {()}
            for item in node.elts:
                pieces = self.argv_source_words(item.value, origin, seen) if isinstance(item, ast.Starred) else {((origin, item),)}
                if not pieces and isinstance(item, ast.Starred):
                    pieces = ({((origin, _UNRESOLVED_IMPORT),)} if self.bearing(item, origin, unresolved_only=True)
                              else {((origin, item.value),)})
                if len(states) * len(pieces) > _MAX_CHOICES:
                    return fallback()
                if any(len(left) + len(right) > _MAX_WORDS for left in states for right in pieces):
                    return fallback()
                states = {left + right for left in states for right in pieces}
            return states
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.argv_source_words(node.left, origin, seen) or {((origin, node.left),)}
            right = self.argv_source_words(node.right, origin, seen) or {((origin, node.right),)}
            if len(left) * len(right) > _MAX_CHOICES:
                return fallback()
            if any(len(a) + len(b) > _MAX_WORDS for a in left for b in right):
                return fallback()
            return {a + b for a in left for b in right}
        if isinstance(node, ast.IfExp):
            left = self.argv_source_words(node.body, origin, seen)
            right = self.argv_source_words(node.orelse, origin, seen)
            return left | right if len(left) + len(right) <= _MAX_CHOICES else fallback()
        if isinstance(node, (ast.Name, ast.Attribute)):
            names, bindings, _ = self.contexts[origin]
            if names.resolve(node) in ({"sys.executable"}, {"os.devnull"}):
                return {((origin, node),)}
            result = set()
            for qualified in names.resolve(node):
                extra = self.imported_argv_source_words(qualified, seen)
                if len(result) + len(extra) > _MAX_CHOICES:
                    return fallback()
                result.update(extra)
            if not isinstance(node, ast.Name):
                return result or fallback()
            scope = names.at[id(node)]
            while scope is not None:
                scope = binding_scope(scope, node.id)
                values = bindings.get((scope, node.id), ())
                if values or node.id in scope.bound:
                    for value in values:
                        extra = self.argv_source_words(value, origin, seen)
                        if len(result) + len(extra) > _MAX_CHOICES:
                            return fallback()
                        result.update(extra)
                    return result or fallback()
                scope = scope.parent
            return result or fallback()
        if isinstance(node, ast.AST) and self.bearing(node, origin, seen - {id(node)}, unresolved_only=True):
            return {((origin, _UNRESOLVED_IMPORT),)}
        return fallback()

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
            return _UNRESOLVED_IMPORT
        extracted = api_arguments(node, api)
        if extracted is not None:
            return extracted[1]
        keywords, _ = api_keywords(node)
        if keywords is None:
            return _UNRESOLVED_IMPORT
        shell_keys = {"os.system": "command", "os.popen": "cmd", "subprocess.getoutput": "cmd",
                      "subprocess.getstatusoutput": "cmd"}
        if api in shell_keys:
            return node.args[0] if node.args else keywords.get(shell_keys[api])
        if api.startswith("subprocess."):
            return node.args[0] if node.args else keywords.get("args")
        suffix = api.rsplit(".", 1)[1]
        if suffix in {"system", "popen"}:
            return None
        offset = 1 if suffix.startswith("spawn") else 0
        if suffix.startswith(("execl", "spawnl")):
            if len(node.args) <= offset + 1:
                return keywords.get("argv", keywords.get("args"))
            end = -1 if suffix.endswith("e") else len(node.args)
            return tuple(node.args[offset + 1:end])
        return node.args[offset + 1] if len(node.args) > offset + 1 else keywords.get("argv", keywords.get("args"))

    def _direct_command_launch(self, node, parents, names):
        """The raw call whose command expression is this node, with no intervening call."""
        parent = parents.get(id(node))
        keyword = None
        if isinstance(parent, ast.keyword):
            keyword = parent
            parent = parents.get(id(parent))
        if not (isinstance(parent, ast.Call) and names.resolve(parent.func) & RAW):
            return None
        for api in names.resolve(parent.func) & RAW:
            command = self.construction_command(parent, api)
            target = keyword.value if keyword is not None else node
            if command is target:
                return parent
        return None

    def proven_consumed_ids(self, rel):
        """Node ids whose construction is the same event as a proven raw spawn.

        A binding qualifies only when it is one simple ``name = <literal>``
        inside a function, every load of that name in the function is the
        direct first positional of one raw spawn, and that spawn's argv is
        closed and yields exactly the literal's programs. Module bindings and
        every unlisted shape stay counted at the construction.
        """
        cached = self._proven_cache.get(rel)
        if cached is not None:
            return cached
        proven = self._prove_consumed(rel)
        self._proven_cache[rel] = proven
        return proven

    def _prove_consumed(self, rel):
        tree = self.modules.get(rel)
        names = self.imports.names.get(rel) if tree is not None else None
        if tree is None or names is None:
            return frozenset()
        parents = {id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        proven = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                proven.update(self._proven_binding_ids(node, rel, names, parents))
        return frozenset(proven)

    def _direct_function_nodes(self, function):
        """Nodes in one function, excluding nested function, class, and lambda bodies."""
        nodes, stack = [], list(function.body)
        nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        while stack:
            node = stack.pop()
            if isinstance(node, nested):
                continue
            nodes.append(node)
            stack.extend(ast.iter_child_nodes(node))
        return nodes

    def _closed_program(self, vectors):
        """One fully resolved argv must yield exactly one literal program."""
        if len(vectors) != 1:
            return None
        vector = next(iter(vectors))
        if (not isinstance(vector, _Argv) or not vector.items
                or any(not (isinstance(word, str) or word is _PYTHON) for word in vector.items)):
            return None
        program = None
        for source in self.argv_programs(vector, executable=_USE_HEAD, fragment=False):
            if program is not None or not isinstance(source, str) or not source or len(source) > _MAX_TEXT:
                return None
            program = source
        return program

    def _raw_command_load(self, load, parents, names):
        """True when this name is the direct argv of one raw spawn and nothing else."""
        parent = parents.get(id(load))
        if not isinstance(parent, ast.Call) or len(parent.args) != 1 or parent.args[0] is not load:
            return False
        if any(keyword.arg is None or keyword.arg in {"executable", "shell", "args", "argv", "cmd", "command"}
               for keyword in parent.keywords):
            return False
        apis = names.resolve(parent.func)
        if len(apis) != 1 or not apis <= RAW:
            return False
        extracted = api_arguments(parent, next(iter(apis)))
        if extracted is None:
            return False
        executable, command, shell = extracted
        return executable is None and not shell and command is load

    def _proven_binding_ids(self, function, rel, names, parents):
        direct = self._direct_function_nodes(function)
        direct_ids = {id(node) for node in direct}
        assignments, rejected = {}, set()
        for node in direct:
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                rejected.update(node.names)
            elif isinstance(node, ast.Delete):
                rejected.update(target.id for target in node.targets if isinstance(target, ast.Name))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                parent = parents.get(id(node))
                simple = (isinstance(parent, ast.Assign) and len(parent.targets) == 1
                          and parent.targets[0] is node)
                if not simple:
                    rejected.add(node.id)
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name)):
                name = node.targets[0].id
                if name in assignments:
                    rejected.add(name)
                else:
                    assignments[name] = node
        for node in ast.walk(function):
            if node is function or id(node) in direct_ids:
                continue
            if isinstance(node, ast.Name) and node.id in assignments:
                rejected.add(node.id)  # A nested scope can observe or rebind the name.
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                rejected.update(name for name in node.names if name in assignments)
        proven = set()
        for name, assign in assignments.items():
            if (name in rejected or not isinstance(assign.value, (ast.List, ast.Tuple))
                    or any(not isinstance(item, (ast.Constant, ast.Name, ast.Attribute))
                           for item in assign.value.elts)):
                continue
            loads = [node for node in direct
                     if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == name]
            if not loads or any(not self._raw_command_load(load, parents, names) for load in loads):
                continue
            literal = self._closed_program(self.values(assign.value, rel))
            if literal is None:
                continue
            if any(self._closed_program(self.values(load, rel)) != literal for load in loads):
                continue
            proven.update(id(node) for node in ast.walk(assign.value))
        return proven

    def construction_programs(self, value, node, api, origin):
        """A normalized call's execution context also governs its constructions."""
        extracted = api_arguments(node, api)
        if extracted is None:
            yield from self.argv_programs(value, fragment=False)
            return  # Retain existing reviewed uncertainty; do not normalize kwargs.
        executable, _, shell = extracted
        if shell:
            return  # launch_programs already inspects the actual shell command.
        for program in self.effective_executables(executable, origin):
            yield from self.argv_programs(value, executable=program, fragment=False)

    def programs(self, rel, *, with_locations=False, with_nodes=False, construction_refusals=False):
        # Located events distinguish launch occurrences from argv source data.
        # Constructions stay in the census. proven_consumed_ids drops only a
        # function literal whose every load is a raw spawn of that same program.
        # Every container is visited independently, with source-position
        # deduplication instead of parent-shape or nested-container exclusions.
        tree = self.modules[rel]
        names = self.imports.names[rel]  # The graph resolves spawn callees only.
        parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        emitted = set()
        events = {}
        event_counts = [0, 0]

        def record(node, program, sources, launch):
            key = node.lineno, node.col_offset, program, launch
            if key in events:
                events[key][2].update(sources)
            else:
                category = int(program is None or program is _UNRESOLVED_MODULE)
                if event_counts[category] >= _MAX_WORDS:
                    raise ValueError(rel + ": literal occurrence limit")
                event_counts[category] += 1
                events[key] = (node, program, set(sources), launch)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and names.resolve(node.func) & RAW:
                for api in sorted(names.resolve(node.func) & RAW):
                    command = self.construction_command(node, api)
                    expression = ast.Tuple(elts=list(command)) if isinstance(command, tuple) else command
                    vectors = (self.sequence(expression, rel, frozenset()) if isinstance(command, tuple)
                               else self.values(command, rel))
                    extracted = api_arguments(node, api)
                    resolution = self.launch_resolution(node, api, rel)
                    unresolved = resolution.reason is not None
                    uncertainty = _UNRESOLVED_MODULE if resolution.module else None
                    if unresolved:
                        if with_locations:
                            record(node, uncertainty, {(rel, _UNRESOLVED_IMPORT)}, True)
                        else:
                            key = (id(node) if with_nodes else node.lineno), uncertainty
                            if key not in emitted:
                                emitted.add(key)
                                yield (node if with_nodes else node.lineno), uncertainty
                    for program in resolution.programs:
                        sources = set()
                        if (program is None or program is _UNRESOLVED_MODULE) and unresolved:
                            sources.add((rel, _UNRESOLVED_IMPORT))
                        if with_locations and extracted is not None and isinstance(program, str):
                            executable, command, shell = extracted
                            if not shell:
                                sources = self.program_sources(command, program, rel, executable=executable, fragment=False)
                        key = (id(node) if with_nodes else node.lineno), program
                        if with_locations:
                            record(node, program, sources, True)
                        elif key not in emitted:
                            emitted.add(key)
                            yield (node if with_nodes else node.lineno), program
                    if with_locations:
                        command = self.construction_command(node, api)
                        vectors = (self.sequence(ast.Tuple(elts=list(command)), rel, frozenset())
                                   if isinstance(command, tuple) else self.values(command, rel))
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
            if not candidate:
                continue
            # Only the call's own command expression inherits its executable.
            # A nested list, slice or helper call is a separate construction:
            # re-reading it under the outer executable invents argv fragments.
            launch = self._direct_command_launch(node, parents, names) if with_locations else None
            values = self.values(node, rel)
            for value in values:
                if isinstance(value, _Argv):
                    programs = (program for api in sorted(names.resolve(launch.func) & RAW)
                                for program in self.construction_programs(value, launch, api, rel)) if launch is not None else self.argv_programs(value)
                elif (value is None or value is _UNRESOLVED_IMPORT) and self.bearing(node, rel):
                    programs = (None,)
                else:
                    continue
                for program in programs:
                    if (program is None or program is _UNRESOLVED_MODULE) and (
                            with_locations or not construction_refusals
                            and not self.bearing(node, rel, unresolved_only=True)):
                        continue  # Unknown construction data is judged at its actual spawn call.
                    sources = self.program_sources(node, program, rel) if with_locations and isinstance(program, str) else set()
                    if with_locations:
                        if launch is not None:
                            record(launch, program, sources, True)
                            continue
                    for source_rel, occurrence in sources or {(rel, node)}:
                        if source_rel != rel:
                            continue  # The defining package module inventories its own construction.
                        key = (id(node) if with_nodes else node.lineno), program
                        if with_locations:
                            record(occurrence, program, {(source_rel, occurrence)}, False)
                        elif key not in emitted:
                            emitted.add(key)
                            yield (node if with_nodes else node.lineno), program
        if with_locations:
            yield from events.values()


def spawn_totality(modules, table, *, resolver=None):
    """Enumerate each spawn call once; no resolver return may leave it unclassified."""
    resolver = resolver or CommandResolver(modules)
    reviewed = {row[:2] for row in table}
    expected, found, verdicts = set(), set(), []
    for rel, tree in modules.items():
        names = resolver.imports.names[rel]
        scopes = {id(node): scope for node, scope in qualified_nodes(tree, include_signature=True)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            apis = names.resolve(node.func) & RAW
            if not apis:
                continue
            key = rel, id(node)
            expected.add(key)
            scope = scopes[id(node)]
            reason, programs, module = None, [], False
            for api in sorted(apis):
                resolution = resolver.launch_resolution(node, api, rel)
                reason = reason or resolution.reason
                module |= resolution.module
                if len(programs) + len(resolution.programs) > _MAX_WORDS:
                    raise ValueError("process census: spawn verdict limit")
                programs.extend(resolution.programs)
            if reason is not None:
                scope = resolver.selector_owner(node, rel, scope)
            verdict = ("reviewed" if (rel, scope) in reviewed else
                       "inventoried" if reason is None else "refused")
            if key in found:
                raise ValueError("process census: duplicate spawn verdict")
            if len(verdicts) >= _MAX_WORDS:
                raise ValueError(rel + ": literal occurrence limit")
            found.add(key)
            verdicts.append(_SpawnVerdict(rel, node, scope, verdict, reason, tuple(programs), module))
    if found != expected:
        raise ValueError("process census: incomplete spawn verdicts")
    return verdicts


def literal_programs(tree, rel, modules=None, resolver=None):
    modules = {rel: tree} if modules is None else modules
    yield from (resolver or CommandResolver(modules)).programs(rel)


def literal_context(program, context_rel, resolver, suffix):
    # A virtual sibling preserves relative imports and leaves the original
    # module available to absolute imports from this literal program.
    parent = context_rel.rpartition("/")[0]
    stem = context_rel.rsplit("/", 1)[-1].removesuffix(".py")
    nested_rel = parent + f"/<{stem}__literal_{suffix}>.py"
    nested = CommandResolver({nested_rel: program}, option_pins={}, package_context=resolver)
    return nested_rel, nested


def checked_literal_exceptions(exceptions):
    for reason in exceptions.values():
        if (not isinstance(reason, str) or not reason or reason.isspace()
                or any(char in reason for char in "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")):
            raise ValueError("process census: invalid literal program exception")
    return exceptions


def literal_program_review(source, rel, scope, exceptions):
    key = rel, scope, hashlib.sha256(source.encode("utf-8")).hexdigest()
    return key if key in exceptions else None


def refuse_literal_escapes(program, rel, context_rel, resolver, *, store_review=None, used_reviews=None):
    """Literals cannot carry review rows for import or module-value escapes."""
    names = resolver.imports.names[context_rel]
    parents = {id(child): node for node in ast.walk(program) for child in ast.iter_child_nodes(node)}
    callees = {id(node.func) for node in ast.walk(program) if isinstance(node, ast.Call)}
    for node in ast.walk(program):
        if any(resolver.imports.is_shadowed(target) for target in names.resolve(node)):
            raise ValueError(f"{rel}: unresolved Python -c program")
        module_store = selector_module_mutation(node, names, resolver.imports)
        if module_store and store_review is not None and used_reviews is not None:
            used_reviews.add(store_review)
        if (selector_import_escape(node, context_rel, names, resolver.imports)
                or selector_module_escape(node, parents, names, resolver.imports)
                or module_store and store_review is None
                or id(node) not in callees and names.resolve(node) & RAW):
            if (isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in SPAWN_MODULES
                    and any(alias.name == "*" for alias in node.names)):
                raise ValueError(f"{rel}: unresolved Python -c program")
            raise ValueError(f"{rel}: process spawn inside a literal -c program")


def refuse_literal_spawns(tree, rel, modules=None, resolver=None, *, literal_exceptions=None,
                          construction_refusals=False):
    if not rel.startswith(tuple(package + "/" for package in PACKAGES)):
        return
    exceptions = checked_literal_exceptions(LITERAL_PROGRAM_EXCEPTIONS if literal_exceptions is None else literal_exceptions)
    resolver = resolver or CommandResolver({rel: tree} if modules is None else modules)
    scopes = {id(node): scope for node, scope in qualified_nodes(tree, include_signature=True)}
    for node, source in resolver.programs(rel, with_nodes=True, construction_refusals=construction_refusals):
        if source is _UNRESOLVED_MODULE:
            raise ValueError(f"{rel}: unresolved Python module")
        if source is None:
            raise ValueError(f"{rel}: unresolved Python -c program")
        if isinstance(source, tuple) and len(source) == 2 and source[0] in {"captured-module", "external-module"}:
            continue  # Exact co-located module capture, already parsed by this census.
        if len(source) > _MAX_TEXT:
            raise ValueError(rel + ": literal program text limit")
        try:
            program = ast.parse(source)
        except (SyntaxError, ValueError, UnicodeError, RecursionError):
            continue  # A resolved Python program with invalid syntax has no executable spawns.
        nested_rel, nested = literal_context(program, rel, resolver, f"refusal_L{node.lineno}C{node.col_offset}")
        review = literal_program_review(source, rel, scopes[id(node)], exceptions)
        refuse_literal_escapes(program, rel, nested_rel, nested, store_review=review)
        names = nested.imports.names[nested_rel]
        if any(names.resolve(node) & RAW for node in ast.walk(program)):
            raise ValueError(f"{rel}: process spawn inside a literal -c program")


def module_process_sites(modules, *, imports=None):
    found = {}
    imports = imports or ImportGraph(modules)
    for rel, tree in modules.items():
        names = imports.names[rel]

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
        refuse_literal_spawns(tree, rel, modules, resolver, construction_refusals=True)
    return module_process_sites(modules, imports=resolver.imports)


def literal_process_sites(rel, tree, resolver, *, owner=None, origin_line=None, depth=0, context_rel=None,
                          constructors=None,
                          literal_exceptions=None, used_reviews=None, selector_table=()):
    """Count resolvable program occurrences, retaining their reviewed source owner."""
    found, parsed = [], set()
    constructors = set() if constructors is None else constructors
    exceptions = checked_literal_exceptions({} if literal_exceptions is None else literal_exceptions)
    used_reviews = set() if used_reviews is None else used_reviews
    scopes = {id(node): scope for node, scope in qualified_nodes(tree, include_signature=True)}
    context_rel = rel if context_rel is None else context_rel
    rows = selector_table if not depth else ()
    reviewed = {row[:2] for row in rows}
    proven = resolver.proven_consumed_ids(context_rel)
    for verdict in spawn_totality({context_rel: tree}, rows, resolver=resolver):
        scopes[id(verdict.node)] = verdict.scope
        if verdict.verdict == "refused":
            raise ValueError(rel + (": unresolved Python module" if verdict.module
                                    else ": unresolved Python -c program"))
    for node, source, origins, launch in resolver.programs(context_rel, with_locations=True):
        if source is None or source is _UNRESOLVED_MODULE:
            if (context_rel, scopes[id(node)]) not in reviewed:
                raise ValueError(rel + (": unresolved Python module" if source is _UNRESOLVED_MODULE
                                        else ": unresolved Python -c program"))
            continue  # Explicitly reviewed uncertainty; never an implicit source=None omission.
        if not isinstance(source, str):
            continue  # Reviewed uncertainty or an already-censused captured module.
        if not launch:
            construction = context_rel, id(node), source
            # Only a proven direct binding is the same event as its launch.
            if id(node) in proven or construction in constructors:
                continue
            constructors.add(construction)
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
        except (SyntaxError, ValueError, UnicodeError, RecursionError):
            continue  # Unparsable constants contribute no child spawns.
        prefix = scope + f".<literal-c-L{node.lineno}C{node.col_offset}>"
        line = node.lineno if origin_line is None else origin_line
        nested_rel, nested = literal_context(program, context_rel, resolver,
                                             f"D{depth}_L{node.lineno}_C{node.col_offset}")
        review = literal_program_review(source, rel, scope, exceptions)
        refuse_literal_escapes(program, rel, nested_rel, nested, store_review=review, used_reviews=used_reviews)
        for child_key, lines in module_process_sites({nested_rel: program}, imports=nested.imports).items():
            category, _, child_scope, api = child_key.split(":", 3)
            if category == "process":
                found.extend((f"process:{rel}:{prefix}.{child_scope}:{api}", line) for _ in lines)
        found.extend(literal_process_sites(
            rel, program, nested, owner=prefix, origin_line=line, depth=depth + 1, context_rel=nested_rel,
            constructors=constructors,
            literal_exceptions=exceptions, used_reviews=used_reviews))
    return found


def process_sites(root, *, option_pins=None, selector_table=None, literal_exceptions=None):
    modules = dict(module_trees(root))
    # Temporary repositories have no inherited source reviews. The production
    # repository always uses the one static table, including rows for removed files.
    if selector_table is None:
        selector_table = SELECTOR_SITE_TABLE if root.resolve() == REPO else ()
    if literal_exceptions is None:
        literal_exceptions = LITERAL_PROGRAM_EXCEPTIONS if root.resolve() == REPO else {}
    literal_exceptions = checked_literal_exceptions(literal_exceptions)
    current = selector_sites(modules, include_escapes=False, table=selector_table)
    # Escape review belongs to the selector gate; keep the process/reference
    # inventory independent, including the pinned default-expression fixture.
    applicable = tuple(row for row in selector_table if row[2] != "escape" or row[:2] in current)
    errors = selector_site_errors(current, applicable)
    if errors:
        raise ValueError(errors[0])
    resolver = CommandResolver(modules, option_pins=option_pins)
    found = module_process_sites(modules, imports=resolver.imports)
    literals, constructors, used_reviews = [], set(), set()
    for rel, tree in modules.items():
        literals.extend(literal_process_sites(rel, tree, resolver, constructors=constructors,
                                             literal_exceptions=literal_exceptions, used_reviews=used_reviews,
                                             selector_table=selector_table))
    if literal_exceptions.keys() - used_reviews:
        raise ValueError("process census: stale literal program exception")
    for key, line in literals:
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
        errors = selector_gate_errors(dict(module_trees(REPO)), SELECTOR_SITE_TABLE)
        if errors:
            raise ValueError(errors[0])
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
        if body == "argv = [sys.executable, '-m', 'aegis_core.not_censused']":
            message = "unresolved Python module"  # ROUND-17c authorizes this relabel only.
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
    "imported_prefix": ("from aegis_core.shared import PREFIX\n", "subprocess.run([*PREFIX, *tail])", "subprocess.run"),
    "imported_builder": ("from aegis_core.shared import PREFIX\n", "def build():\n    return [P]\nsubprocess.run([*PREFIX, *build()])", "subprocess.run"),
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
        (package / "shared.py").write_text("import sys\nPREFIX=(sys.executable,'-I','-c')\n", encoding="utf-8")
    program = "import subprocess; subprocess.Popen(['/bin/true'])" if case.startswith("argon_") else "import os; os.system('id')"
    source = ("import os, sys, subprocess, shlex\nP=" + repr(program) + "\n" + prefix
              + "def launch(tail=None, code=None, mode=None, opts=None):\n"
              + "".join("    " + line + "\n" for line in body.splitlines()))
    (package / "probe.py").write_text(source, encoding="utf-8")
    scope = {"argon_returned_prefix": "launch.get_prefix", "argon_nonlocal_alias": "launch.outer",
             "argon_git_setting": "launch.make_flags"}.get(case, "launch")
    original = ("aegis_core/shared.py", "<module>") if prefix else ("aegis_core/probe.py", scope)
    # ROUND-17b: the consuming launch now needs its own review as well.
    site = (("aegis_core/probe.py", "launch") if case in {
        "imported_prefix", "imported_builder", "argon_git_setting"} else original)
    message = "unreviewed selector site " + ":".join(site)
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == message
    table = tuple((*key, "reviewed-dynamic", "Test-owned review of this selector construction.")
                  for key in sorted({original, site}))
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
        (package / "shared.py").write_text("import sys\nPREFIX=(sys.executable, '-m')\n", encoding="utf-8")
    (package / "probe.py").write_text(
        "import os, sys, subprocess, shlex\nP=\"import os; os.system('id')\"\n" + prefix
        + "def launch(mode=True, options=None, target=None, arguments=None, name=None, path=None):\n"
        + "".join("    " + line + "\n" for line in body.splitlines()), encoding="utf-8")
    rel = "aegis_core/shared.py" if prefix else "aegis_core/probe.py"
    site = ("aegis_core/probe.py", "launch") if case == "imported_module_prefix" else (rel, scope)
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == "unreviewed selector site " + ":".join(site)
    table = tuple((*key, "reviewed-dynamic", "Test-owned broad-site review.")
                  for key in sorted({(rel, scope), site}))
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
def test_literal_spawn_wildcard_import_refuses_without_review(tmp_path, program, api):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n",
        encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned wildcard literal program."),)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


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


@pytest.mark.parametrize("body,count", [
    ("subprocess.run([sys.executable, *['-c',P]])", 2),
    ("subprocess.run((sys.executable, *('-c',P)))", 2),
    ("FRAGMENT=['-c',P]\nsubprocess.run([sys.executable, *FRAGMENT])", 2),
    ("FRAGMENT=('-c',P)\nsubprocess.run((sys.executable,) + FRAGMENT)", 2),
    ("PREFIX=[sys.executable]\nFRAGMENT=['-c',P]\nsubprocess.run(PREFIX + FRAGMENT)", 2),
    ("ARGV=[sys.executable,'-c',P]\nsubprocess.run(ARGV)", 1),
    ("ARGV=[sys.executable,'-c',P]\nALIAS=ARGV\nsubprocess.run(ALIAS)", 2),
])
def test_literal_spawn_flattened_fragments_count_once(tmp_path, body, count):
    """A direct function binding counts once; a fragment or alias also keeps its construction."""
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(
        "import sys,subprocess\nP=\"import os; os.system('id')\"\ndef launch():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()), encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "resolved-python-program", "Test-owned flattened occurrence."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == count


@pytest.mark.parametrize("imported", [False, True], ids=["local", "imported"])
@pytest.mark.parametrize("same_owner", [False, True], ids=["two-functions", "same-function"])
def test_literal_spawn_shared_argv_keeps_each_launch(tmp_path, imported, same_owner):
    package = tmp_path / "aegis_core"
    package.mkdir()
    definition = "import sys\nARGV=(sys.executable,'-c',\"import os; os.system('id')\")\n"
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
    assert sum(len(lines) for key, lines in before.items() if key.endswith(":os.system")) == 2
    record = {key:{"count":len(lines),"reason":"Test-owned process rows."} for key,lines in before.items()}
    write("ARGV")
    after = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in after.items() if key.endswith(":os.system")) == 3
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
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 2


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
    if inner.startswith("FLAGS="):
        # ROUND-17b: an outer review cannot waive unresolved mutated argv inside it.
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"
        return
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
    # A starred fragment or tuple concatenation is its own construction.
    nested = call in {
        "subprocess.run([sys.executable,*[b'-c',P]])",
        "subprocess.run((sys.executable,) + (b'-c',P))",
    }
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == (2 if nested else 1)


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
        (package / "base.py").write_text(definition.replace("EXEC=sys.executable\n", "") + "FRAGMENT=('-c',P)\n", encoding="utf-8")
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
    # Fragments, loops and the shell expression using shlex.quote are not a
    # simple closed literal binding, so the construction stays counted.
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == 2


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
    (package / "shared.py").write_text("P=\"import os; os.system('id')\"\nTAIL=(P,)\n", encoding="utf-8")
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
    code = "import subprocess\ndef child(args):\n    subprocess.run(args)\nchild([])\n"
    argument = argument.replace("CODE",repr(code))
    (package / "probe.py").write_text("import sys,subprocess\ndef launch(args,opts):\n    subprocess.run(" + argument + ")\n",
                                     encoding="utf-8")
    table = (("aegis_core/probe.py", "launch", "reviewed-dynamic", "Test-owned nested program with dynamic child argv."),)
    sites = process_sites(tmp_path, selector_table=table)
    # A preserved prefix keeps the launch as well as the list construction.
    concat = "+ args" in argument
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":subprocess.run")) == (3 if concat else 2)
    child = [(key,lines) for key,lines in sites.items() if ":launch.<literal-c-" in key]
    assert len(child) == (2 if concat else 1)
    assert all(lines == [3] for _, lines in child)


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
    system = {key: lines for key, lines in sites.items() if key.endswith(":os.system")}
    owner = lambda key: key.split(":")[2].split(".<literal", 1)[0]
    assert sum(len(lines) for key, lines in system.items() if owner(key) == "launch") == copies
    assert sum(len(lines) for key, lines in system.items() if owner(key) == "<module>") == 1


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
    system = {key: lines for key, lines in sites.items() if key.endswith(":os.system")}
    owner = lambda key: key.split(":")[2].split(".<literal", 1)[0]
    assert sum(len(lines) for key, lines in system.items() if owner(key) == "launch") == copies
    assert sum(len(lines) for key, lines in system.items() if owner(key) == "<module>") == 1


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
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == copies + 1


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
    # A named module argv stays counted. The shell or executable override adds no second program.
    assert sum(len(lines) for key,lines in sites.items() if key.endswith(":os.system")) == (1 if staged else 0)


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


@pytest.mark.parametrize("position,source,scope", [
    ("assignment", "runner = subprocess.Popen\n", "<module>"),
    ("default", "def launch(runner=subprocess.Popen):\n    pass\n", "launch"),
    ("argument", "consume(subprocess.Popen)\n", "<module>"),
    ("map", "map(subprocess.Popen, commands)\n", "<module>"),
    ("partial", "from functools import partial\npartial(subprocess.Popen)\n", "<module>"),
    ("container", "callbacks = [subprocess.Popen]\n", "<module>"),
    ("attribute_store", "holder.callback = subprocess.Popen\n", "<module>"),
    ("return", "def factory():\n    return subprocess.Popen\n", "factory"),
    ("yield", "def callbacks():\n    yield subprocess.Popen\n", "callbacks"),
    ("decorator", "@subprocess.Popen\ndef factory():\n    pass\n", "factory"),
    ("comparison", "same = callback is subprocess.Popen\n", "<module>"),
    ("annotation", "def cleanup(proc: subprocess.Popen):\n    pass\n", "cleanup"),
    ("from_import", "from subprocess import Popen as spawn\nrunner = spawn\n", "<module>"),
])
@pytest.mark.parametrize("package_name", PACKAGES)
def test_spawn_escape_positions_require_review(tmp_path, position, source, scope, package_name):
    package = tmp_path / package_name
    package.mkdir()
    path = package / "probe.py"
    path.write_text("import subprocess\n" + source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    key = package_name + "/probe.py", scope
    for _ in range(2):
        assert set(selector_sites(modules)) == {key}
        assert selector_site_errors(selector_sites(modules), ()) == ["unreviewed selector site " + key[0] + ":" + scope]
    table = ((*key, "escape", "Test-owned spawn API escape review."),)
    assert selector_site_errors(selector_sites(modules), table) == []
    assert selector_gate_errors(modules, table) == []


@pytest.mark.parametrize("api", sorted(RAW))
def test_spawn_escape_uses_the_complete_api_inventory(tmp_path, api):
    package = tmp_path / "aegis_core"
    package.mkdir()
    module, name = api.split(".")
    (package / "probe.py").write_text("import " + module + "\nrunner = " + module + "." + name + "\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_escape_sites(modules) == {("aegis_core/probe.py", "<module>"): [2]}
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site aegis_core/probe.py:<module>"]


@pytest.mark.parametrize("source", [
    "import subprocess\nsubprocess.Popen(['tool'])\n",
    "from subprocess import Popen as spawn\nspawn(['tool'])\n",
    "import subprocess\nvalue = subprocess.PIPE\n",
    "import subprocess as backend\ndef shadowed(backend):\n    return backend.Popen\n",
    "from subprocess import Popen as spawn\ndef shadowed(spawn):\n    return spawn\n",
    "def left():\n    from subprocess import Popen as spawn\n    spawn(['tool'])\ndef right(spawn):\n    return spawn\n",
    "import subprocess\nsubprocess.Popen(['tool']).wait()\n",
])
def test_spawn_direct_calls_and_shadows_add_no_value_escapes(tmp_path, source):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    expected = {}
    if " as " in source:
        scope, line = ("left", 2) if source.startswith("def left") else ("<module>", 1)
        expected[("aegis_core/probe.py", scope)] = [line]
    assert selector_escape_sites(modules) == expected
    table = tuple((*key, "escape", "Review the import; direct calls and shadows add no value escapes.") for key in expected)
    assert selector_gate_errors(modules, table) == []


@pytest.mark.parametrize("case,provider,consumer,scope", [
    ("inheritance", "class Base:\n    callback = staticmethod(subprocess.Popen)\n",
     "from .provider import Base\nclass Child(Base):\n    pass\nChild().callback(code, **options)\n", "Base"),
    ("bound_method", "runner = subprocess.Popen\n",
     "from .provider import runner\nclass Holder:\n    def set(this, callback):\n        this.callback = callback\nholder = Holder()\nsetter = holder.set\nsetter(runner)\nholder.callback(code, **options)\n", "<module>"),
    ("starred_offset", "runner = subprocess.Popen\n",
     "from .provider import runner\ndef third(a, b, c):\n    return c\ncallback = third(*(None, None), runner)\ncallback(code, **options)\n", "<module>"),
    ("container_copy", "runner = subprocess.Popen\n",
     "from .provider import runner\ncallbacks = [runner]\ncopied = callbacks[:].copy()\ncopied[0](code, **options)\n", "<module>"),
    ("dictionary_default", "def factory():\n    return {}.get('runner', subprocess.Popen)\n",
     "from .provider import factory\ncallback = factory()\ncallback(code, **options)\n", "factory"),
    ("generator", "def callbacks():\n    yield subprocess.Popen\n",
     "from .provider import callbacks\nfor callback in callbacks():\n    callback(code, **options)\n", "callbacks"),
    ("decorator", "def inject(target):\n    return lambda: target(subprocess.Popen)\n",
     "from .provider import inject\n@inject\ndef factory(backend):\n    return backend\ncallback = factory()\ncallback(code, **options)\n", "inject"),
])
def test_spawn_escape_reviews_the_origin_of_formal_forwarding_routes(tmp_path, case, provider, consumer, scope):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "provider.py").write_text("import subprocess\n" + provider, encoding="utf-8")
    (package / "consumer.py").write_text(consumer, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    key = "aegis_core/provider.py", scope
    assert set(selector_escape_sites(modules)) == {key}
    for _ in range(2):
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":" + scope]
    table = ((*key, "escape", "Test-owned review of the forwarding origin."),)
    assert selector_gate_errors(modules, table) == []
    assert selector_gate_errors(dict(reversed(list(modules.items()))), table) == []


def test_spawn_escape_requires_its_review_kind_and_rejects_stale_reviews(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("import subprocess\nrunner = subprocess.Popen\nmessage = '-c example'\n", encoding="utf-8")
    key = "aegis_core/probe.py", "<module>"
    wrong = ((*key, "reviewed-dynamic", "This ordinary row cannot review an escape."),)
    table = ((*key, "escape", "Test-owned spawn escape review."),)
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, wrong) == ["selector escape requires escape kind aegis_core/probe.py:<module>"]
    assert selector_gate_errors(modules, table) == []
    path.write_text("message = '-c example'\n", encoding="utf-8")
    assert selector_gate_errors(dict(module_trees(tmp_path)), table) == ["stale selector escape aegis_core/probe.py:<module>"]
    for reason in ("", "first\nsecond", "first\rsecond"):
        row = ((*key, "escape", reason),)
        assert selector_gate_errors(modules, row) == ["invalid selector row aegis_core/probe.py:<module>"]


def test_spawn_escape_review_is_separate_from_process_reference_counts(tmp_path):
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text("import subprocess\nrunner = subprocess.Popen\n", encoding="utf-8")
    table = (("aegis_core/probe.py", "<module>", "escape", "Test-owned API assignment review."),)
    expected = {"process:aegis_core/probe.py:<module>:subprocess.Popen": [2]}
    assert process_sites(tmp_path) == expected
    assert process_sites(tmp_path, selector_table=table) == expected
    assert selector_gate_errors(dict(module_trees(tmp_path)), ()) == ["unreviewed selector site aegis_core/probe.py:<module>"]
    assert selector_gate_errors(dict(module_trees(tmp_path)), table) == []


def test_spawn_escape_concurrent_gate_checks_keep_their_own_state(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    package = tmp_path / "aegis_core"
    package.mkdir()
    path = package / "probe.py"
    path.write_text("from subprocess import Popen as spawn\nrunner = spawn\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    table = (("aegis_core/probe.py", "<module>", "escape", "Test-owned concurrent escape review."),)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: selector_gate_errors(modules, table), range(4), timeout=30))
    assert results == [[], [], [], []]
    path.write_text("value = None\n", encoding="utf-8")
    assert selector_gate_errors(dict(module_trees(tmp_path)), ()) == []
    assert selector_gate_errors(dict(module_trees(tmp_path)), table) == ["stale selector site aegis_core/probe.py:<module>",
                                                                     "stale selector escape aegis_core/probe.py:<module>"]


@pytest.mark.parametrize("route", ["plain", "alias", "namespace", "import_as", "package", "chain", "class_import", "nested_class", "star", "star_chain"])
@pytest.mark.parametrize("shape", ["expanded", "positional", "escape"])
@pytest.mark.parametrize("consumer_package", ["aegis_core", "aegis_sdk"])
def test_import_chain_references_receive_normal_review(tmp_path, route, shape, consumer_package):
    core = tmp_path / "aegis_core"
    core.mkdir()
    provider, prefix, callee = "from subprocess import Popen\n", "from aegis_core.provider import Popen\n", "Popen"
    if route == "alias":
        provider, prefix, callee = "from subprocess import Popen as runner\n", "from aegis_core.provider import runner as invoke\n", "invoke"
    elif route == "namespace":
        provider, prefix, callee = "import subprocess as backend\n", "from aegis_core.provider import backend as driver\n", "driver.Popen"
    elif route == "import_as":
        provider, prefix, callee = "import subprocess\n", "import aegis_core.provider as driver\n", "driver.subprocess.Popen"
    elif route == "package":
        (core / "__init__.py").write_text("from .provider import Popen as spawn\n", encoding="utf-8")
        prefix, callee = "from aegis_core import spawn\n", "spawn"
    elif route == "chain":
        (core / "middle.py").write_text("from .provider import Popen as first\n", encoding="utf-8")
        prefix, callee = "from aegis_core.middle import first as invoke\n", "invoke"
    elif route == "class_import":
        provider = "class Backend:\n    from subprocess import Popen as runner\n"
        prefix, callee = "from aegis_core.provider import Backend\n", "Backend.runner"
    elif route == "nested_class":
        provider = "class Outer:\n    class Inner:\n        from subprocess import Popen\n"
        prefix, callee = "from aegis_core.provider import Outer\n", "Outer.Inner.Popen"
    elif route == "star":
        prefix = "from aegis_core.provider import *\n"
    elif route == "star_chain":
        (core / "middle.py").write_text("from .provider import *\n", encoding="utf-8")
        prefix = "from aegis_core.middle import Popen\n"
    (core / "provider.py").write_text(provider, encoding="utf-8")
    consumer = tmp_path / consumer_package
    consumer.mkdir(exist_ok=True)
    operation = {"expanded": callee + "(command, **options)", "positional": callee + "(command, -1, executable)",
                 "escape": callee}[shape]
    (consumer / "consumer.py").write_text(
        prefix + "def launch(command, options, executable):\n    return " + operation + "\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    key = consumer_package + "/consumer.py", "launch"
    origin = set() if route == "import_as" else {("aegis_core/provider.py", {
        "class_import": "Backend", "nested_class": "Outer.Inner"}.get(route, "<module>"))}
    if route == "star":
        origin.add((consumer_package + "/consumer.py", "<module>"))
    elif route == "star_chain":
        origin.add(("aegis_core/middle.py", "<module>"))
    escaped = shape == "escape" or route in {"import_as", "class_import", "nested_class"}
    assert set(selector_sites(modules)) == origin | {key}
    assert set(selector_escape_sites(modules)) == origin | ({key} if escaped else set())
    for _ in range(2):
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + scope
                                                    for rel, scope in sorted(origin | {key})]
    table = ((*key, "escape" if escaped else "reviewed-dynamic", "Test-owned transitive import review."),)
    table += tuple((*site, "escape", "Test-owned import-origin review.") for site in sorted(origin))
    assert selector_gate_errors(modules, table) == []
    assert selector_gate_errors(dict(reversed(list(modules.items()))), table) == []


@pytest.mark.parametrize("shape,body,scope", [
    ("rhs", "    Popen = Popen\n", "Backend"),
    ("default", "    def Popen(self, spawn=Popen):\n        pass\n", "Backend.Popen"),
    ("decorator", "    @decorate(Popen)\n    def Popen(self):\n        pass\n", "Backend.Popen"),
    ("class_base", "    class Popen(Popen):\n        pass\n", "Backend.Popen"),
    ("class_decorator", "    @decorate(Popen)\n    class Popen:\n        pass\n", "Backend.Popen"),
    ("staticmethod", "    Popen = staticmethod(Popen)\n", "Holder"),
])
def test_class_body_references_reach_enclosing_imports(tmp_path, shape, body, scope):
    core = tmp_path / "aegis_core"
    core.mkdir()
    class_name = "Holder" if shape == "staticmethod" else "Backend"
    (core / "provider.py").write_text("from subprocess import Popen\nclass " + class_name + ":\n" + body, encoding="utf-8")
    (core / "consumer.py").write_text(
        "from .provider import " + class_name + "\ndef launch(command, options):\n    return " + class_name + ".Popen(command, **options)\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    key = "aegis_core/provider.py", scope
    origin = "aegis_core/provider.py", "<module>"
    assert selector_escape_sites(modules).keys() == {key, origin}
    assert len(selector_escape_sites(modules)[key]) == 1
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + owner
                                                for rel, owner in sorted({key, origin})]
    table = tuple((*site, "escape", "Test-owned enclosing import escape review.") for site in (key, origin))
    assert selector_gate_errors(modules, table) == []


@pytest.mark.parametrize("shape", ["parameter", "class_parameter", "nonspawn"])
def test_import_chain_and_class_resolution_keep_nonspawn_shadows(tmp_path, shape):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text("from subprocess import Popen as runner\nfrom subprocess import PIPE\n", encoding="utf-8")
    body = {"parameter": "from .provider import runner\ndef launch(runner):\n    return runner\n",
            "class_parameter": "from .provider import runner\nclass Backend:\n    def launch(runner):\n        return runner\n",
            "nonspawn": "from .provider import PIPE as runner\nvalue = runner\n"}[shape]
    (core / "consumer.py").write_text(body, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_escape_sites(modules) == {("aegis_core/provider.py", "<module>"): [1]}
    table = (("aegis_core/provider.py", "<module>", "escape", "Review only the provider import, not a shadow."),)
    assert selector_gate_errors(modules, table) == []


def test_import_resolution_distinguishes_class_lookup_from_class_body_loads(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text(
        "from subprocess import Popen\nclass Backend:\n    def Popen(self, command, **options):\n        pass\n", encoding="utf-8")
    (core / "consumer.py").write_text(
        "from .provider import Backend\ndef launch(command, options):\n    return Backend.Popen(command, **options)\n", encoding="utf-8")
    table = (("aegis_core/provider.py", "<module>", "escape", "Test-owned provider import review."),)
    assert selector_gate_errors(dict(module_trees(tmp_path)), table) == []


def test_import_resolution_preserves_import_and_class_alternatives(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text(
        "from subprocess import Popen as Backend\nif mode:\n    class Backend:\n        pass\n", encoding="utf-8")
    (core / "consumer.py").write_text("from .provider import Backend\ncallback = Backend\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_escape_sites(modules) == {("aegis_core/consumer.py", "<module>"): [2],
                                              ("aegis_core/provider.py", "<module>"): [1]}


@pytest.mark.parametrize("size_kind", ["text", "parts", "namespace"])
def test_import_resolution_limits_refuse_without_echoing_input(size_kind):
    name = ".".join(["private_marker"] * 4097) if size_kind == "parts" else "private_marker" + "x" * 1048576
    tree = ast.fix_missing_locations(ast.Module(body=[
        ast.Import(names=[ast.alias(name=name, asname="backend")]),
        ast.Assign(targets=[ast.Name(id="callback", ctx=ast.Store())],
                   value=ast.Attribute(value=ast.Name(id="backend", ctx=ast.Load()), attr="Popen", ctx=ast.Load())),
    ], type_ignores=[]))
    if size_kind == "namespace":
        tree = ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(
            name=name, bases=[], keywords=[], body=[ast.Pass()], decorator_list=[]
        )], type_ignores=[]))
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            selector_gate_errors({"aegis_core/probe.py": tree}, ())
        assert str(error.value) == "selector import resolution limit"


def test_import_cycles_and_concurrent_gates_keep_resolution_local(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    core = tmp_path / "aegis_core"
    core.mkdir()
    provider = core / "provider.py"
    provider.write_text("if mode:\n    from .middle import runner\nelse:\n    from subprocess import Popen as runner\n", encoding="utf-8")
    (core / "middle.py").write_text("from .provider import runner\n", encoding="utf-8")
    (core / "consumer.py").write_text("from .middle import runner\ncallback = runner\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    table = tuple((rel, "<module>", "escape", "Test-owned cyclic import escape review.")
                  for rel in ("aegis_core/consumer.py", "aegis_core/provider.py"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: selector_gate_errors(modules, table), range(4), timeout=30))
    assert results == [[], [], [], []]
    provider.write_text("from .middle import runner\n", encoding="utf-8")
    assert selector_gate_errors(dict(module_trees(tmp_path)), ()) == []


@pytest.mark.parametrize("shape", ["api", "module"])
def test_argon_exact_import_chain_inputs_require_review(tmp_path, shape):
    core = tmp_path / "aegis_core"
    core.mkdir()
    provider, prefix, callee = ("from subprocess import Popen as runner\n", "from .provider import runner\n", "runner") if shape == "api" else (
        "import subprocess\n", "from .provider import subprocess\n", "subprocess.Popen")
    (core / "provider.py").write_text(provider, encoding="utf-8")
    (core / "consumer.py").write_text(prefix + "def launch(code, options):\n    return " + callee + "(code, **options)\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    expected = ["unreviewed selector site aegis_core/consumer.py:launch"]
    table = (("aegis_core/consumer.py", "launch", "reviewed-dynamic", "Test-owned exact Argon import-chain review."),)
    if shape == "api":
        expected.append("unreviewed selector site aegis_core/provider.py:<module>")
        table += (("aegis_core/provider.py", "<module>", "escape", "Test-owned exact import-origin review."),)
    assert selector_gate_errors(modules, ()) == expected
    assert selector_gate_errors(modules, table) == []
    sites = process_sites(tmp_path, selector_table=table)
    assert sites == {"process:aegis_core/consumer.py:launch:subprocess.Popen": [3]}


@pytest.mark.parametrize("package_name", PACKAGES)
@pytest.mark.parametrize("shape", ["expanded", "positional", "escape", "wildcard", "literal", "module_wide"])
def test_argon_selector_rules_are_uniform_across_packages(tmp_path, package_name, shape):
    package = tmp_path / package_name
    package.mkdir()
    source, scope, kind = {
        "expanded": ("import subprocess, sys\nP=\"import os; os.system('id')\"\ndef launch():\n    return subprocess.Popen(P, **{'shell': True, 'executable': sys.executable})\n", "launch", "reviewed-dynamic"),
        "positional": ("import subprocess\ndef launch(command, executable):\n    return subprocess.Popen(command, -1, executable)\n", "launch", "reviewed-dynamic"),
        "escape": ("import subprocess\ndef launch():\n    return subprocess.Popen\n", "launch", "escape"),
        "wildcard": ("from subprocess import *\n", "<module>", "escape"),
        "literal": ("message = '-c example'\n", "<module>", "reviewed-dynamic"),
        "module_wide": ("from subprocess import Popen\ndef launch(options):\n    return ordinary(**options)\n", "launch", "reviewed-dynamic"),
    }[shape]
    (package / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    key = package_name + "/probe.py", scope
    keys = {key}
    table = ((*key, kind, "Test-owned uniform package selector review."),)
    if shape == "module_wide":
        keys.add((key[0], "<module>"))
        table += ((key[0], "<module>", "escape", "Test-owned uniform import-origin review."),)
    for _ in range(2):
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + owner
                                                    for rel, owner in sorted(keys)]
    assert selector_gate_errors(modules, table) == []


@pytest.mark.parametrize("star", [False, True])
def test_transitive_import_declarations_keep_module_wide_expansion_review(tmp_path, star):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text("from subprocess import Popen as runner\n", encoding="utf-8")
    (core / "consumer.py").write_text(
        "from .provider import " + ("*" if star else "runner") + "\ndef launch(options):\n    return ordinary(**options)\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    escapes = {("aegis_core/provider.py", "<module>"): [1]}
    if star:
        escapes[("aegis_core/consumer.py", "<module>")] = [1]
    assert selector_escape_sites(modules) == escapes
    keys = escapes.keys() | {("aegis_core/consumer.py", "launch")}
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + scope
                                                for rel, scope in sorted(keys)]


@pytest.mark.parametrize("api", sorted(RAW))
@pytest.mark.parametrize("scope", ["<module>", "launch", "Backend"])
@pytest.mark.parametrize("aliased", [False, True])
def test_spawn_api_import_origin_requires_escape_review(tmp_path, api, scope, aliased):
    module, name = api.split(".")
    statement = "from " + module + " import " + name + (" as runner" if aliased else "") + "\n"
    source = statement if scope == "<module>" else (
        ("def launch():\n" if scope == "launch" else "class Backend:\n") + "    " + statement)
    modules = {"aegis_core/probe.py": ast.parse(source)}
    key = "aegis_core/probe.py", scope
    expected = ["unreviewed selector site " + key[0] + ":" + scope]
    for _ in range(2):
        assert selector_gate_errors(modules, ()) == expected
    assert selector_escape_sites(modules) == {key: [1 if scope == "<module>" else 2]}
    row = (*key, "escape", "Test-owned import-origin review.")
    assert selector_gate_errors(modules, (row,)) == []
    assert selector_gate_errors(modules, ((*key, "reviewed-dynamic", row[3]),)) == [
        "selector escape requires escape kind " + key[0] + ":" + scope]


@pytest.mark.parametrize("module", ["os", "subprocess"])
@pytest.mark.parametrize("scope", ["<module>", "launch", "Backend"])
@pytest.mark.parametrize("aliased", [False, True])
def test_spawn_module_import_origin_respects_canonical_scopes(module, scope, aliased):
    statement = "import " + module + (" as backend" if aliased else "") + "\n"
    source = statement if scope == "<module>" else (
        ("def launch():\n" if scope == "launch" else "class Backend:\n") + "    " + statement)
    modules = {"aegis_sdk/probe.py": ast.parse(source)}
    key = "aegis_sdk/probe.py", scope
    if aliased or scope == "Backend":
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":" + scope]
        assert selector_gate_errors(modules, ((*key, "escape", "Test-owned module import review."),)) == []
    else:
        assert selector_escape_sites(modules) == {}
        assert selector_gate_errors(modules, ()) == []


@pytest.mark.parametrize("shape", ["alternative", "global", "nonlocal"])
def test_formal_1657_class_import_origins_require_review(shape):
    source, scope = {
        "alternative": ("if use_native:\n    from .native import Backend\nelse:\n    class Backend:\n        from subprocess import Popen\ncallback = Backend.Popen\n", "Backend"),
        "global": ("def initialize():\n    global Backend\n    class Backend:\n        from subprocess import Popen\ninitialize()\n", "initialize.Backend"),
        "nonlocal": ("def outer():\n    Backend = None\n    def initialize():\n        nonlocal Backend\n        class Backend:\n            from subprocess import Popen\n    initialize()\n    return Backend\n", "outer.initialize.Backend"),
    }[shape]
    modules = {"aegis_core/provider.py": ast.parse(source),
               "aegis_core/native.py": ast.parse("class Backend:\n    Popen = None\n"),
               "aegis_core/consumer.py": ast.parse("from .provider import Backend\ndef launch(c, o):\n    return Backend.Popen(c, **o)\n")}
    if shape == "alternative":
        del modules["aegis_core/consumer.py"]
    key = "aegis_core/provider.py", scope
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":" + scope]
    row = (*key, "escape", "Review the class import before any forwarded use.")
    assert selector_gate_errors(modules, (row,)) == []


@pytest.mark.parametrize("shape", ["module", "class", "positional"])
def test_formal_1657_star_shadow_routes_require_provider_review(shape):
    source = {
        "module": "from .provider import *\ncallback = runner\ndef runner():\n    pass\n",
        "class": "class Backend:\n    from .provider import *\n    callback = runner\n    def runner():\n        pass\n",
        "positional": "from .provider import *\nif use_native:\n    def runner():\n        pass\ndef launch(command, executable):\n    return runner(command, -1, executable)\n",
    }[shape]
    modules = {"aegis_core/provider.py": ast.parse("from subprocess import Popen as runner\n"),
               "aegis_core/consumer.py": ast.parse(source)}
    key = "aegis_core/provider.py", "<module>"
    keys = {key}
    keys.add(("aegis_core/consumer.py", "Backend" if shape == "class" else "<module>"))
    for _ in range(2):
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + scope
                                                    for rel, scope in sorted(keys)]
    table = tuple((*site, "escape", "Review the star route at its import origin.") for site in sorted(keys))
    assert selector_gate_errors(modules, table) == []


def test_argon_1657_conditional_class_reexport_import_requires_review():
    modules = {
        "aegis_core/provider.py": ast.parse("from subprocess import Popen as runner\n"),
        "aegis_core/consumer.py": ast.parse("import types as Backend\nif mode:\n    class Backend:\n        from .provider import runner\ndef launch(c, exe):\n    return Backend.runner(c, -1, exe)\n"),
    }
    keys = {("aegis_core/provider.py", "<module>"), ("aegis_core/consumer.py", "Backend")}
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + scope
                                                for rel, scope in sorted(keys)]
    table = tuple((*key, "escape", "Test-owned review of the conditional class import origin.") for key in keys)
    assert selector_gate_errors(modules, table) == []


@pytest.mark.parametrize("route", ["plain", "alias", "module", "class", "package"])
@pytest.mark.parametrize("nested", [False, True])
def test_argon_1657_literal_import_graph_counts_and_refuses(tmp_path, route, nested):
    core = tmp_path / "aegis_core"
    core.mkdir()
    provider, prefix, callee = {
        "plain": ("from subprocess import Popen as runner\n", "from aegis_core.provider import runner", "runner"),
        "alias": ("from subprocess import Popen as runner\n", "from aegis_core.middle import invoke", "invoke"),
        "module": ("import subprocess\n", "from aegis_core.provider import subprocess as backend", "backend.Popen"),
        "class": ("class Backend:\n    from subprocess import Popen\n", "from aegis_core.provider import Backend", "Backend.Popen"),
        "package": ("from subprocess import Popen as runner\n", "from aegis_core import invoke", "invoke"),
    }[route]
    (core / "provider.py").write_text(provider, encoding="utf-8")
    (core / "middle.py").write_text("from .provider import runner as invoke\n", encoding="utf-8")
    (core / "__init__.py").write_text("from .provider import runner as invoke\n", encoding="utf-8")
    program = prefix + "; " + callee + "(['/bin/true'])"
    if nested:
        program = "import sys,subprocess; subprocess.run([sys.executable,'-c'," + repr(program) + "])"
    (core / "consumer.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Test-owned imported literal spawn."),)
    if route == "class":
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"
        return
    for _ in range(2):
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.Popen")) == 1
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == (2 if nested else 1)
        assert all(lines == [3] for key, lines in sites.items() if ":launch." in key)
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"


def test_argon_1657_literal_import_graph_retries_and_concurrency(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    core = tmp_path / "aegis_core"
    core.mkdir()
    provider = core / "provider.py"
    provider.write_text("from subprocess import Popen as runner\n", encoding="utf-8")
    (core / "consumer.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',\"from .provider import runner; runner([])\"])\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Test-owned relative literal import."),)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: process_sites(tmp_path, selector_table=table), range(4), timeout=30))
    assert all(any(key.endswith(":subprocess.Popen") for key in sites) for sites in results)
    provider.write_text("def runner(command):\n    pass\n", encoding="utf-8")
    assert process_sites(tmp_path, selector_table=table) == {"process:aegis_core/consumer.py:launch:subprocess.run": [3]}
    assert literal_fixture_sites(tmp_path) == {"process:aegis_core/consumer.py:launch:subprocess.run": [3]}


@pytest.mark.parametrize("form", ["code", "argv", "package_code", "package_argv", "star_code", "star_argv"])
def test_imported_command_values_visit_intermediate_rebindings(tmp_path, form):
    core = tmp_path / "aegis_core"
    core.mkdir()
    vector = form.endswith("argv")
    name = "ARGV" if vector else "CODE"
    initial = "('python3', '-c', 'pass')" if vector else repr("pass")
    changed = "('python3', '-c', \"import os; os.system('id')\")" if vector else repr("import os; os.system('id')")
    (core / "defaults.py").write_text("import sys\n" + name + " = " + initial + "\n", encoding="utf-8")
    if form.startswith("package_"):
        provider = core / "provider" / "__init__.py"
        provider.parent.mkdir()
        prefix = "from ..defaults import "
    else:
        provider = core / "provider.py"
        prefix = "from .defaults import "
    declaration = prefix + ("*" if form.startswith("star_") else name) + "\n"
    provider.write_text("import sys\n" + declaration + name + " = " + changed + "\n", encoding="utf-8")
    argument = name if vector else "[sys.executable, '-c', CODE]"
    (core / "consumer.py").write_text("import sys,subprocess\nfrom .provider import " + name
                                     + "\ndef launch():\n    subprocess.run(" + argument + ")\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Test-owned intermediate value replacement."),)
    if vector:
        table = tuple((path, "<module>", "resolved-python-program", "Test-owned imported argv construction.")
                      for path in ("aegis_core/defaults.py", provider.relative_to(tmp_path).as_posix()))
    for _ in range(2):
        sites = process_sites(tmp_path, selector_table=table)
        children = {key: lines for key, lines in sites.items() if key.endswith(":os.system")}
        if vector:
            # The provider tuple is a module construction and is never consumed.
            provider_rel = provider.relative_to(tmp_path).as_posix()
            launch = {key: lines for key, lines in children.items()
                      if key.startswith("process:aegis_core/consumer.py:launch.")}
            module = {key: lines for key, lines in children.items()
                      if key.startswith("process:" + provider_rel + ":<module>.")}
            assert set(launch) | set(module) == set(children)
            assert list(launch.values()) == [[4]]
            assert list(module.values()) == [[3]]
        else:
            assert len(children) == 1
            assert next(iter(children)).startswith("process:aegis_core/consumer.py:launch.")
            assert next(iter(children.values())) == [4]
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"
    provider.write_text(declaration, encoding="utf-8")
    remaining_table = tuple(row for row in table if row[0] != provider.relative_to(tmp_path).as_posix())
    expected = {"process:aegis_core/consumer.py:launch:subprocess.run": [4]}
    assert process_sites(tmp_path, selector_table=remaining_table) == expected
    assert literal_fixture_sites(tmp_path) == expected


@pytest.mark.parametrize("form", ["code", "argv", "package_code", "package_argv", "star_code", "star_argv"])
@pytest.mark.parametrize("write", ["augment", "delete", "unknown"])
def test_imported_command_values_keep_intermediate_invalidations(tmp_path, form, write):
    core = tmp_path / "aegis_core"
    core.mkdir()
    vector = form.endswith("argv")
    name = "ARGV" if vector else "CODE"
    initial = "[sys.executable, '-c', 'pass']" if vector else repr("pass")
    (core / "defaults.py").write_text("import sys\n" + name + " = " + initial + "\n", encoding="utf-8")
    if form.startswith("package_"):
        provider = core / "provider" / "__init__.py"
        provider.parent.mkdir()
        prefix = "from ..defaults import "
    else:
        provider = core / "provider.py"
        prefix = "from .defaults import "
    replacement = {"augment": name + " += extra\n", "delete": "del " + name + "\n",
                   "unknown": name + " = make_value()\n"}[write]
    provider.write_text(prefix + ("*" if form.startswith("star_") else name) + "\n" + replacement, encoding="utf-8")
    argument = name if vector else "[sys.executable, '-c', CODE]"
    (core / "consumer.py").write_text("import sys,subprocess\nfrom .provider import " + name
                                     + "\ndef launch():\n    subprocess.run(" + argument + ")\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("source", [
    "from subprocess import Popen\n",
    "import subprocess as backend\n",
    "class Backend:\n    import subprocess\n",
    "class Backend:\n    import math\n",
    "def initialize():\n    global Backend\n    class Backend:\n        from subprocess import Popen\ninitialize()\nBackend.Popen(['/bin/true'])\n",
    "if use_native:\n    from types import SimpleNamespace as Backend\nelse:\n    class Backend:\n        from subprocess import Popen\nBackend.Popen(['/bin/true'])\n",
    "def outer():\n    Backend = None\n    def initialize():\n        nonlocal Backend\n        class Backend:\n            from subprocess import Popen\n    initialize()\n    return Backend\nouter().Popen(['/bin/true'])\n",
])
@pytest.mark.parametrize("entry", ["refusal", "inventory"])
@pytest.mark.parametrize("package_name", PACKAGES)
def test_literal_import_origins_refuse_without_review(tmp_path, source, entry, package_name):
    core = tmp_path / package_name
    core.mkdir()
    (core / "consumer.py").write_text(
        "import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c'," + repr(source) + "])\n", encoding="utf-8")
    table = ((package_name + "/consumer.py", "launch", "resolved-python-program", "A parent review cannot admit a literal import escape."),)
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                literal_fixture_sites(tmp_path)
            else:
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == package_name + "/consumer.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("case", ["rebound_value", "literal_import"])
def test_command_resolution_retries_and_concurrent_runs_keep_state_local(tmp_path, case):
    from concurrent.futures import ThreadPoolExecutor

    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("CODE = 'pass'\n", encoding="utf-8")
    provider = core / "provider.py"
    program = "import os; os.system('id')" if case == "rebound_value" else "from subprocess import Popen"
    provider.write_text("from .defaults import CODE\nCODE = " + repr(program) + "\n", encoding="utf-8")
    (core / "consumer.py").write_text(
        "import sys,subprocess\nfrom .provider import CODE\ndef launch():\n    subprocess.run([sys.executable,'-c',CODE])\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Test-owned concurrent command resolution."),)
    expected = "aegis_core/consumer.py: process spawn inside a literal -c program"

    def inspect(_):
        if case == "literal_import":
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=table)
            assert str(error.value) == expected
        else:
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == expected
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(inspect, range(4), timeout=30)) == [True] * 4
    provider.write_text("from .defaults import CODE\n", encoding="utf-8")
    expected_sites = {"process:aegis_core/consumer.py:launch:subprocess.run": [4]}
    assert process_sites(tmp_path, selector_table=table) == expected_sites
    assert literal_fixture_sites(tmp_path) == expected_sites


def test_imported_spawn_callee_preserves_its_local_command_value(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "backend.py").write_text("from subprocess import Popen as spawn\n", encoding="utf-8")
    (core / "consumer.py").write_text(
        "import sys\nfrom .backend import spawn\ndef launch():\n    ARGV = [sys.executable, '-c', 'pass']\n    spawn(ARGV)\n", encoding="utf-8")
    expected = {"process:aegis_core/consumer.py:launch:subprocess.Popen": [5]}
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Test-owned imported spawn callee."),)
    assert literal_fixture_sites(tmp_path) == expected
    assert process_sites(tmp_path, selector_table=table) == expected


@pytest.mark.parametrize("expression", [
    "backend = subprocess\n",
    "def launch(backend=subprocess):\n    pass\n",
    "def launch():\n    return subprocess\n",
    "consume(subprocess)\n",
    "backends = [subprocess]\n",
    "spawn = getattr(subprocess, 'Popen')\n",
    "def launch(hasattr):\n    return hasattr(subprocess, 'Popen')\n",
    "def launch(getattr):\n    return getattr(subprocess, 'PIPE')\n",
])
@pytest.mark.parametrize("entry", ["module", "literal"])
def test_spawn_module_values_require_review_or_literal_refusal(tmp_path, expression, entry):
    source = "import subprocess\n" + expression
    scope = "launch" if expression.startswith("def ") else "<module>"
    if entry == "module":
        modules = {"aegis_core/probe.py": ast.parse(source)}
        key = "aegis_core/probe.py", scope
        assert set(selector_escape_sites(modules)) == {key}
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":" + scope]
        assert selector_gate_errors(modules, ((*key, "escape", "Test-owned module value review."),)) == []
    else:
        core = tmp_path / "aegis_core"
        core.mkdir()
        (core / "probe.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',"
                                       + repr(source) + "])\n", encoding="utf-8")
        table = (("aegis_core/probe.py", "launch", "resolved-python-program", "A literal module escape cannot be reviewed."),)
        for operation in (lambda: process_sites(tmp_path, selector_table=table), lambda: literal_fixture_sites(tmp_path)):
            with pytest.raises(ValueError) as error:
                operation()
            assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("source", [
    "import subprocess\nsubprocess.Popen(['tool'])\n",
    "import os\nhasattr(os, 'posix_spawn')\n",
    "import subprocess\nvalue = getattr(subprocess, 'PIPE', None)\n",
    "import os\nvalue = getattr(os, 'O_NOFOLLOW', 0)\n",
    "import subprocess\ndef launch(subprocess):\n    return subprocess\n",
])
def test_spawn_module_value_capability_guards_and_parameter_shadows_are_not_escapes(source):
    modules = {"aegis_sdk/probe.py": ast.parse(source)}
    assert selector_escape_sites(modules) == {}
    assert selector_gate_errors(modules, ()) == []


@pytest.mark.parametrize("shape", ["expanded", "positional", "capture"])
@pytest.mark.parametrize("route", ["direct", "star_chain", "alias_chain"])
def test_star_imports_of_spawn_modules_require_origin_review(shape, route):
    modules = {"aegis_core/provider.py": ast.parse("import subprocess\n")}
    provider, symbol = "provider", "subprocess"
    keys = {("aegis_core/consumer.py", "<module>")}
    if route != "direct":
        provider = "middle"
        modules["aegis_core/middle.py"] = ast.parse("from .provider import " + (
            "subprocess as runner\n" if route == "alias_chain" else "*\n"))
        if route == "alias_chain":
            symbol = "runner"
        else:
            keys.add(("aegis_core/middle.py", "<module>"))
    operation = {"expanded": symbol + ".Popen(command, **options)",
                 "positional": symbol + ".Popen(command, -1, executable)",
                 "capture": symbol + ".Popen"}[shape]
    modules["aegis_core/consumer.py"] = ast.parse("from ." + provider
        + " import *\nif use_native:\n    " + symbol + " = native\ndef launch(command, options, executable):\n    return " + operation + "\n")
    assert set(selector_escape_sites(modules)) == keys
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + scope
                                                for rel, scope in sorted(keys)]
    table = tuple((*key, "escape", "Review the star import before any forwarding.") for key in keys)
    assert selector_gate_errors(modules, table) == []


@pytest.mark.parametrize("shape", ["conditional", "global", "nonspawn"])
def test_every_class_body_import_requires_origin_review(shape):
    source, scope = {
        "conditional": ("import types as Backend\nif mode:\n    class Backend:\n        from . import provider\ndef launch(c, o):\n    return Backend.provider.subprocess.Popen(c, **o)\n", "Backend"),
        "global": ("def initialize():\n    global Backend\n    class Backend:\n        import aegis_core.provider as p\ninitialize()\nBackend.p.subprocess.Popen(c, **o)\n", "initialize.Backend"),
        "nonspawn": ("class Backend:\n    import math\n", "Backend"),
    }[shape]
    modules = {"aegis_core/provider.py": ast.parse("import subprocess\n"),
               "aegis_core/consumer.py": ast.parse(source)}
    key = "aegis_core/consumer.py", scope
    assert set(selector_escape_sites(modules)) == {key}
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":" + scope]
    assert selector_gate_errors(modules, ((*key, "escape", "Test-owned class import review."),)) == []


@pytest.mark.parametrize("literal", [False, True])
def test_implicit_package_prefixes_preserve_spawn_callees(tmp_path, literal):
    core = tmp_path / "aegis_core"
    (core / "subpkg").mkdir(parents=True)
    (core / "__init__.py").write_text("from .helpers import *\n", encoding="utf-8")
    (core / "helpers.py").write_text("VALUE = 1\n", encoding="utf-8")
    (core / "subpkg" / "provider.py").write_text("import subprocess\n", encoding="utf-8")
    source = "import aegis_core.subpkg.provider\ndef launch(c, o):\n    return aegis_core.subpkg.provider.subprocess.Popen(c, **o)\n"
    if literal:
        program = "import aegis_core.subpkg.provider; aegis_core.subpkg.provider.subprocess.Popen([])"
        source = "import sys,subprocess\ndef launch(c, o):\n    subprocess.run([sys.executable,'-c'," + repr(program) + "])\n"
    (core / "consumer.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Test-owned implicit package spawn route."),)
    table += (("aegis_core/__init__.py", "<module>", "escape", "Review the package star re-export."),)
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site aegis_core/__init__.py:<module>",
                                                "unreviewed selector site aegis_core/consumer.py:launch"]
    if literal:
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"
    else:
        table = tuple((*row[:2], "escape", row[3]) for row in table)
        assert selector_gate_errors(modules, table) == []
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.Popen")) == 1


def test_literal_star_import_origin_cannot_be_reviewed(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text("import subprocess\n", encoding="utf-8")
    program = "from .provider import *\nif use_native:\n    subprocess = native\nsubprocess.Popen([])\n"
    (core / "consumer.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',"
                                     + repr(program) + "])\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "A literal star escape cannot be reviewed."),)
    for operation in (lambda: process_sites(tmp_path, selector_table=table), lambda: literal_fixture_sites(tmp_path)):
        with pytest.raises(ValueError) as error:
            operation()
        assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("route", ["direct", "package", "chain"])
def test_unresolved_module_reexports_require_consuming_site_review(tmp_path, route):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("import sys\nARGV = [sys.executable, '-c', 'pass']\n", encoding="utf-8")
    if route == "package":
        provider = core / "provider" / "__init__.py"
        provider.parent.mkdir()
        declaration = "from .. import defaults as config\n"
    elif route == "chain":
        provider = core / "provider.py"
        (core / "relay.py").write_text("from . import defaults as config\n", encoding="utf-8")
        declaration = "from .relay import config\n"
    else:
        provider = core / "provider.py"
        declaration = "from . import defaults as config\n"
    provider.write_text(declaration + "config.ARGV[2] = \"import os; os.system('id')\"\n", encoding="utf-8")
    (core / "consumer.py").write_text("import subprocess\nfrom .provider import config\nsubprocess.run(config.ARGV)\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    defaults = (("aegis_core/defaults.py", "<module>", "resolved-python-program", "Test-owned original argv."),)
    consumer = "aegis_core/consumer.py", "<module>"
    mutation = provider.relative_to(tmp_path).as_posix(), "<module>"
    for _ in range(2):
        errors = selector_gate_errors(modules, defaults)
        assert "unreviewed selector site " + consumer[0] + ":<module>" in errors
        assert "unreviewed selector site " + mutation[0] + ":<module>" in errors
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=defaults)
        assert str(error.value) == "unreviewed selector site aegis_core/consumer.py:<module>"
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"
    table = defaults + ((*consumer, "reviewed-dynamic", "Review the unknown imported command."),
                        (*mutation, "escape", "Review the cross-module mutation."))
    assert selector_gate_errors(modules, table) == []
    assert process_sites(tmp_path, selector_table=table) == {
        "process:aegis_core/consumer.py:<module>:subprocess.run": [3]}


@pytest.mark.parametrize("statement", [
    "config.ARGV = []\n",
    "config.ARGV[2] = 'new'\n",
    "config.ARGV += extra\n",
    "del config.ARGV\n",
    "setattr(config, 'ARGV', [])\n",
    "delattr(config, 'ARGV')\n",
])
@pytest.mark.parametrize("entry", ["module", "literal"])
def test_imported_module_mutations_require_review_or_literal_refusal(tmp_path, statement, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("ARGV = []\n", encoding="utf-8")
    source = "from . import defaults as config\n" + statement
    if entry == "module":
        (core / "probe.py").write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        key = "aegis_core/probe.py", "<module>"
        assert set(selector_escape_sites(modules)) == {key}
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":<module>"]
        assert selector_gate_errors(modules, ((*key, "escape", "Test-owned imported-module store review."),)) == []
    else:
        (core / "probe.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',"
                                       + repr(source) + "])\n", encoding="utf-8")
        table = (("aegis_core/probe.py", "launch", "resolved-python-program", "A parent row cannot review a literal store."),)
        for operation in (lambda: process_sites(tmp_path, selector_table=table), lambda: literal_fixture_sites(tmp_path)):
            with pytest.raises(ValueError) as error:
                operation()
            assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("provider", ["from . import backend\n", "from . import backend as runner\n"])
def test_every_repository_star_import_requires_review(provider):
    symbol = "runner" if " as " in provider else "backend"
    modules = {"aegis_core/backend.py": ast.parse("import subprocess\n"),
               "aegis_core/provider.py": ast.parse(provider),
               "aegis_core/consumer.py": ast.parse("from .provider import *\nif use_native:\n    " + symbol
                   + " = native\ndef launch(c, o):\n    return " + symbol + ".subprocess.Popen(c, **o)\n")}
    key = "aegis_core/consumer.py", "<module>"
    assert set(selector_escape_sites(modules)) == {key}
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":<module>"]
    assert selector_gate_errors(modules, ((*key, "escape", "Review the repository star import at its origin."),)) == []


def test_repository_star_import_without_spawn_exports_is_still_a_literal_escape(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text("VALUE = 1\n", encoding="utf-8")
    program = "from .provider import *\n"
    (core / "consumer.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',"
                                     + repr(program) + "])\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "A literal cannot review any repository star import."),)
    for operation in (lambda: process_sites(tmp_path, selector_table=table), lambda: literal_fixture_sites(tmp_path)):
        with pytest.raises(ValueError) as error:
            operation()
        assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"


def test_imported_loop_argv_invalidation_remains_bearing(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text(
        "import sys\nfor ARGV in [[sys.executable,'-c','pass']]:\n    ARGV[2] = \"import os; os.system('id')\"\n", encoding="utf-8")
    (core / "consumer.py").write_text("import subprocess\nfrom .defaults import ARGV\nsubprocess.run(ARGV)\n", encoding="utf-8")
    table = (("aegis_core/defaults.py", "<module>", "resolved-python-program", "Test-owned loop argv construction."),)
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == "unreviewed selector site aegis_core/consumer.py:<module>"


def test_unresolved_import_retries_and_concurrent_reviews_keep_state_local(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("import sys\nARGV = [sys.executable, '-c', 'pass']\n", encoding="utf-8")
    provider = core / "provider.py"
    provider.write_text("from . import defaults as config\nconfig.ARGV[2] = 'changed'\n", encoding="utf-8")
    consumer = core / "consumer.py"
    consumer.write_text("import subprocess\nfrom .provider import config\nsubprocess.run(config.ARGV)\n", encoding="utf-8")
    defaults = (("aegis_core/defaults.py", "<module>", "resolved-python-program", "Test-owned original argv."),)
    table = defaults + (("aegis_core/provider.py", "<module>", "escape", "Review the imported-module mutation."),
                        ("aegis_core/consumer.py", "<module>", "reviewed-dynamic", "Review the unresolved imported command."))
    modules = dict(module_trees(tmp_path))
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(lambda _: selector_gate_errors(modules, table), range(4), timeout=30)) == [[], [], [], []]
    (core / "defaults.py").write_text("import sys\nARGV = (sys.executable, '-c', 'pass')\n", encoding="utf-8")
    provider.write_text("from .defaults import ARGV\n", encoding="utf-8")
    consumer.write_text("import subprocess\nfrom .provider import ARGV\nsubprocess.run(ARGV)\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, defaults) == []
    assert process_sites(tmp_path, selector_table=defaults) == {
        "process:aegis_core/consumer.py:<module>:subprocess.run": [3]}
    assert literal_fixture_sites(tmp_path) == {
        "process:aegis_core/consumer.py:<module>:subprocess.run": [3]}
    errors = selector_gate_errors(modules, table)
    assert "stale selector site aegis_core/consumer.py:<module>" in errors
    assert "stale selector escape aegis_core/provider.py:<module>" in errors


def test_imported_class_and_shadowed_module_stores_are_not_module_mutations():
    modules = {"aegis_core/provider.py": ast.parse("class Holder:\n    pass\n"),
               "aegis_core/consumer.py": ast.parse("from .provider import Holder\nHolder.report_path = 'out'\n"
                   "import sys\ndef launch(sys):\n    sys.stdout = None\n")}
    assert selector_escape_sites(modules) == {}
    assert selector_gate_errors(modules, ()) == []


@pytest.mark.parametrize("api", ["os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"])
def test_unresolved_imported_shell_text_requires_consuming_review(tmp_path, api):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("CODE = 'pass'\n", encoding="utf-8")
    (core / "provider.py").write_text("from . import defaults as config\n", encoding="utf-8")
    (core / "consumer.py").write_text("import os,subprocess\nfrom .provider import config\n"
                                     + api + "(config.CODE)\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    expected = "unreviewed selector site aegis_core/consumer.py:<module>"
    assert selector_gate_errors(modules, ()) == [expected]
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path)
    assert str(error.value) == expected
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("body", ["backend = provider\n", "provider.subprocess.Popen(c, **options)\n"])
def test_repository_module_values_and_spawn_exposing_attributes_require_review(body):
    modules = {"aegis_core/provider.py": ast.parse("import subprocess\n"),
               "aegis_core/consumer.py": ast.parse("from . import provider\n" + body)}
    key = "aegis_core/consumer.py", "<module>"
    assert set(selector_escape_sites(modules)) == {key}
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + key[0] + ":<module>"]
    assert selector_gate_errors(modules, ((*key, "escape", "Review the repository namespace origin."),)) == []


def test_ambiguous_package_binding_and_module_file_are_unknown(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text("CODE = 'pass'\n", encoding="utf-8")
    (core / "evil.py").write_text("CODE = \"import os; os.system('id')\"\n", encoding="utf-8")
    (core / "__init__.py").write_text("from . import evil as provider\n", encoding="utf-8")
    (core / "consumer.py").write_text("import sys,subprocess\nfrom . import provider\n"
                                     "subprocess.run([sys.executable,'-c',provider.CODE])\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            literal_fixture_sites(tmp_path)
        assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("definition", ["ARGV = ['python3', '-c', 'pass']\n", "ARGV = list(('python3', '-c', 'pass'))\n"])
def test_mutable_or_call_result_command_values_cannot_cross_modules_as_known(tmp_path, definition):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text(definition, encoding="utf-8")
    (core / "consumer.py").write_text("import subprocess\nfrom .provider import ARGV\nsubprocess.run(ARGV)\n", encoding="utf-8")
    table = (("aegis_core/provider.py", "<module>", "resolved-python-program", "Test-owned original argv."),)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == "unreviewed selector site aegis_core/consumer.py:<module>"
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


def test_noncall_spawn_reference_in_literal_has_no_review_path(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    program = "import subprocess\nrunner = subprocess.Popen\nrunner('tool', **options)\n"
    (core / "consumer.py").write_text("import sys,subprocess\ndef launch():\n    subprocess.run([sys.executable,'-c',"
                                     + repr(program) + "])\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "A literal RAW value cannot carry review."),)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == "aegis_core/consumer.py: process spawn inside a literal -c program"


SNAPSHOT_LITERAL_CASES = (
    ("aegis_core/testexec.py", "run_pytest_snapshot", "_SNAPSHOT_RUNNER",
     "803eddf9509c06ab8e5e37a94653738489f699425b8a1e3d2cd130f99d452902"),
    ("aegis_core/verification/regression_commands.py", "run_configured_snapshot", "_BOOTSTRAP",
     "820cac9a505d774844ddad9f86f0ee041ba49eeb42fd186ca35914b683dca456"),
)


def test_literal_program_exceptions_are_the_two_reviewed_bootstraps():
    assert LITERAL_PROGRAM_EXCEPTIONS == {
        (rel, function, digest): "snapshot bootstrap isolates sys.path from the live checkout"
        for rel, function, _, digest in SNAPSHOT_LITERAL_CASES}


def snapshot_literal_source(rel, binding):
    tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
    return ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                                 and any(isinstance(target, ast.Name) and target.id == binding
                                         for target in node.targets)))


def literal_review_tree(tmp_path, program, rel="aegis_core/probe.py", function="launch"):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("import subprocess, sys\ndef " + function + "():\n"
                    "    subprocess.run([sys.executable, '-c', " + repr(program) + "])\n", encoding="utf-8")
    return ((rel, function, "resolved-python-program", "Test-owned literal program."),)


@pytest.mark.parametrize("rel,function,binding,digest", SNAPSHOT_LITERAL_CASES)
def test_snapshot_literal_exact_source_is_accepted(tmp_path, rel, function, binding, digest):
    program = snapshot_literal_source(rel, binding)
    assert hashlib.sha256(program.encode("utf-8")).hexdigest() == digest
    table = literal_review_tree(tmp_path, program, rel, function)
    modules = dict(module_trees(tmp_path))
    # The existing refusal entry point must accept each real bootstrap too.
    refuse_literal_spawns(modules[rel], rel, modules, CommandResolver(modules, option_pins={}))
    exceptions = {(rel, function, digest): "snapshot bootstrap isolates sys.path from the live checkout"}
    assert process_sites(tmp_path, option_pins={}, selector_table=table, literal_exceptions=exceptions) == {
        "process:" + rel + ":" + function + ":subprocess.run": [3]}


@pytest.mark.parametrize("rel,function,binding,digest", SNAPSHOT_LITERAL_CASES)
def test_snapshot_literal_one_byte_change_refuses(tmp_path, rel, function, binding, digest):
    program = snapshot_literal_source(rel, binding) + " "
    table = literal_review_tree(tmp_path, program, rel, function)
    exceptions = {(rel, function, digest): "snapshot bootstrap isolates sys.path from the live checkout"}
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, option_pins={}, selector_table=table, literal_exceptions=exceptions)
    assert str(error.value) == rel + ": process spawn inside a literal -c program"


@pytest.mark.parametrize("changed", ["file", "function"])
def test_snapshot_literal_exception_is_bound_to_its_owner(tmp_path, changed):
    rel, function, binding, digest = SNAPSHOT_LITERAL_CASES[0]
    program = snapshot_literal_source(rel, binding)
    exceptions = {(rel, function, digest): "snapshot bootstrap isolates sys.path from the live checkout"}
    if changed == "file":
        rel = "aegis_core/other.py"
    else:
        function = "other"
    table = literal_review_tree(tmp_path, program, rel, function)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, option_pins={}, selector_table=table, literal_exceptions=exceptions)
    assert str(error.value) == rel + ": process spawn inside a literal -c program"


def test_unlisted_literal_module_store_has_no_exception(tmp_path):
    table = literal_review_tree(tmp_path, "import sys\nsys.path[:] = []\n")
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


@pytest.mark.parametrize("program", [None, "pass\n"])
def test_literal_program_exception_stale_row_refuses(tmp_path, program):
    rel, function, _, digest = SNAPSHOT_LITERAL_CASES[0]
    table = () if program is None else literal_review_tree(tmp_path, program, rel, function)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, option_pins={}, selector_table=table,
                      literal_exceptions={(rel, function, digest): "Test-owned stale review."})
    assert str(error.value) == "process census: stale literal program exception"


@pytest.mark.parametrize("tail", [
    "import subprocess as backend\n",
    "import subprocess\nrunner = subprocess.Popen\n",
    "import subprocess\nforwarded = subprocess\n",
    "class Backend:\n    import pathlib\n",
])
def test_literal_program_exception_waives_only_module_stores(tmp_path, tail):
    program = "import sys\nsys.path[:] = []\n" + tail
    table = literal_review_tree(tmp_path, program)
    key = "aegis_core/probe.py", "launch", hashlib.sha256(program.encode("utf-8")).hexdigest()
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table,
                      literal_exceptions={key: "Test-owned module-store exception only."})
    assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


def test_literal_program_exception_keeps_nested_spawn_inventory(tmp_path):
    program = "import sys, subprocess\nsys.path[:] = []\nsubprocess.run(['native-tool'])\n"
    table = literal_review_tree(tmp_path, program)
    key = "aegis_core/probe.py", "launch", hashlib.sha256(program.encode("utf-8")).hexdigest()
    exceptions = {key: "Test-owned module-store exception only."}
    sites = process_sites(tmp_path, selector_table=table, literal_exceptions=exceptions)
    assert sites == {
        "process:aegis_core/probe.py:launch:subprocess.run": [3],
        "process:aegis_core/probe.py:launch.<literal-c-L3C4>.<module>:subprocess.run": [3],
    }
    modules = dict(module_trees(tmp_path))
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules["aegis_core/probe.py"], "aegis_core/probe.py", modules,
                              literal_exceptions=exceptions)
    assert str(error.value) == "aegis_core/probe.py: process spawn inside a literal -c program"


def test_literal_program_exception_keeps_unresolved_import_refusal(tmp_path):
    program = ("import sys, subprocess\nsys.path[:] = []\n"
               "from .provider import config\nsubprocess.run(config.ARGV)\n")
    table = literal_review_tree(tmp_path, program)
    (tmp_path / "aegis_core/defaults.py").write_text("ARGV = ('python', '-c', 'pass')\n", encoding="utf-8")
    (tmp_path / "aegis_core/provider.py").write_text("from . import defaults as config\n", encoding="utf-8")
    table += (("aegis_core/defaults.py", "<module>", "resolved-python-program", "Test-owned original argv."),)
    key = "aegis_core/probe.py", "launch", hashlib.sha256(program.encode("utf-8")).hexdigest()
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table,
                      literal_exceptions={key: "Test-owned module-store exception only."})
    assert str(error.value) == "aegis_core/probe.py: unresolved Python -c program"


def package_shadow_tree(tmp_path, declaration, *, form="code", nested=False, package_child=True):
    core = tmp_path / "aegis_core"
    core.mkdir()
    owner = core / "outer" if nested else core
    owner.mkdir(exist_ok=True)
    (owner / "__init__.py").write_text(declaration, encoding="utf-8")
    (owner / "alternate.py").write_text("from . import payload as config\n", encoding="utf-8")
    (owner / "payload.py").write_text("CODE = \"import os; os.system('id')\"\n", encoding="utf-8")
    if package_child:
        child = owner / "provider"
        child.mkdir()
        (child / "__init__.py").write_text("", encoding="utf-8")
        config = child / "config.py"
        expression = "provider.config."
    else:
        config = owner / "provider.py"
        expression = "provider."
    config.write_text("CODE = 'pass'\nARGV = ('python', '-c', 'pass')\n", encoding="utf-8")
    command = "[sys.executable, '-c', " + expression + "CODE]" if form == "code" else expression + "ARGV"
    consumer = owner / "consumer.py"
    consumer.write_text("import sys, subprocess\nfrom . import provider\nsubprocess.run(" + command + ")\n",
                        encoding="utf-8")
    return consumer.relative_to(tmp_path).as_posix(), config.relative_to(tmp_path).as_posix()


@pytest.mark.parametrize("declaration", [
    "from . import alternate as provider\n",
    "from .alternate import config as provider\n",
    "provider = None\n",
    "def provider():\n    pass\n",
    "class provider:\n    pass\n",
    "from . import provider\nprovider = None\n",
])
@pytest.mark.parametrize("form", ["code", "argv"])
def test_shadowed_package_prefix_literal_refusal(tmp_path, declaration, form):
    rel, _ = package_shadow_tree(tmp_path, declaration, form=form)
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("nested,package_child", [(False, True), (True, True), (False, False), (True, False)])
def test_shadowed_package_prefix_inventory_requires_consumer_review(tmp_path, nested, package_child):
    rel, config = package_shadow_tree(tmp_path, "from . import alternate as provider\n", form="argv",
                                     nested=nested, package_child=package_child)
    table = ((config, "<module>", "resolved-python-program", "Test-owned physical argv."),)
    modules = dict(module_trees(tmp_path))
    expected = "unreviewed selector site " + rel + ":<module>"
    assert selector_gate_errors(modules, table) == [expected]
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == expected
    table += ((rel, "<module>", "reviewed-dynamic", "Review an unresolved package command."),)
    assert selector_gate_errors(modules, table) == []
    assert process_sites(tmp_path, selector_table=table) == {"process:" + rel + ":<module>:subprocess.run": [3]}


@pytest.mark.parametrize("declaration", [
    "", "from . import provider\n", "other = None\n",
    "def other():\n    provider = None\n", "class Other:\n    provider = None\n",
])
@pytest.mark.parametrize("form", ["code", "argv"])
def test_unshadowed_nested_package_values_still_resolve(tmp_path, declaration, form):
    rel, config = package_shadow_tree(tmp_path, declaration, form=form, nested=True)
    modules = dict(module_trees(tmp_path))
    resolver = CommandResolver(modules)
    assert list(literal_programs(modules[rel], rel, modules, resolver)) == [(3, "pass")]
    assert literal_fixture_sites(tmp_path) == {"process:" + rel + ":<module>:subprocess.run": [3]}
    table = ((config, "<module>", "resolved-python-program", "Test-owned physical argv."),)
    if form == "code":
        table += ((rel, "<module>", "resolved-python-program", "Test-owned scalar program."),)
    assert selector_gate_errors(modules, table) == []
    assert process_sites(tmp_path, selector_table=table) == {"process:" + rel + ":<module>:subprocess.run": [3]}


def test_shadowed_package_prefix_callee_is_unknown(tmp_path):
    rel, config = package_shadow_tree(tmp_path, "from . import alternate as provider\n")
    (tmp_path / config).write_text("from subprocess import Popen\n", encoding="utf-8")
    (tmp_path / rel).write_text("from . import provider\nprovider.config.Popen(command)\n", encoding="utf-8")
    table = ((config, "<module>", "escape", "Review the physical spawn import."),)
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, table) == ["unreviewed selector site " + rel + ":<module>"]
    table += ((rel, "<module>", "reviewed-dynamic", "Review an unresolved package callee."),)
    assert selector_gate_errors(modules, table) == []
    assert process_sites(tmp_path, selector_table=table) == {}


def test_shadowed_package_prefix_in_literal_callee_refuses(tmp_path):
    rel, config = package_shadow_tree(tmp_path, "from . import alternate as provider\n")
    (tmp_path / config).write_text("from subprocess import Popen\n", encoding="utf-8")
    program = "from . import provider\nprovider.config.Popen(command)\n"
    table = literal_review_tree(tmp_path, program, rel, "launch")
    table += ((config, "<module>", "escape", "Review the physical spawn import."),)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("declaration,expression", [
    ("from .provider.config import CODE\n", "CODE"),
    ("import aegis_core.provider.config as config\n", "config.CODE"),
    ("import aegis_core.provider.config\n", "aegis_core.provider.config.CODE"),
    ("from .relay import CODE\n", "CODE"),
])
def test_shadowed_package_prefix_survives_import_routes(tmp_path, declaration, expression):
    rel, _ = package_shadow_tree(tmp_path, "from . import alternate as provider\n")
    (tmp_path / "aegis_core/relay.py").write_text("from .provider.config import CODE\n", encoding="utf-8")
    (tmp_path / rel).write_text("import sys, subprocess\n" + declaration
                               + "subprocess.run([sys.executable, '-c', " + expression + "])\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == rel + ": unresolved Python -c program"


def test_shadowed_package_prefix_does_not_match_a_sibling_name(tmp_path):
    rel, _ = package_shadow_tree(tmp_path, "from . import alternate as provider\n")
    (tmp_path / "aegis_core/provider_extra.py").write_text("CODE = 'pass'\n", encoding="utf-8")
    (tmp_path / rel).write_text("import sys, subprocess\nfrom . import provider_extra\n"
                               "subprocess.run([sys.executable, '-c', provider_extra.CODE])\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert list(literal_programs(modules[rel], rel, modules, CommandResolver(modules))) == [(3, "pass")]
    assert literal_fixture_sites(tmp_path) == {"process:" + rel + ":<module>:subprocess.run": [3]}


@pytest.mark.parametrize("declaration", [
    "from . import provider, alternate as provider\n",
    "from . import alternate as provider, provider\n",
])
@pytest.mark.parametrize("form", ["code", "argv"])
def test_shadowed_package_prefix_repeated_import_alias_refuses(tmp_path, declaration, form):
    rel, _ = package_shadow_tree(tmp_path, declaration, form=form)
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("wrapper", ["tuple(config.ARGV)", "list(config.ARGV)", "config.ARGV[:]",
                                      "[x for x in config.ARGV]"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_unresolved_import_provenance_survives_local_wrappers(tmp_path, wrapper, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("ARGV = ('python', '-c', 'pass')\n", encoding="utf-8")
    (core / "provider.py").write_text("import sys\nfrom . import defaults as config\n"
                                     "config.ARGV = (sys.executable, '-c', \"import os; os.system('id')\")\n",
                                     encoding="utf-8")
    (core / "consumer.py").write_text("import subprocess\nfrom .provider import config\nargv = " + wrapper
                                     + "\nsubprocess.run(argv)\n", encoding="utf-8")
    rel = "aegis_core/consumer.py"
    modules = dict(module_trees(tmp_path))
    table = (("aegis_core/defaults.py", "<module>", "resolved-python-program", "Test-owned original argv."),
             ("aegis_core/provider.py", "<module>", "escape", "Review the imported-module store."))
    expected = "unreviewed selector site " + rel + ":<module>"
    if entry == "selector":
        assert selector_gate_errors(modules, table) == [expected]
    elif entry == "refusal":
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules, CommandResolver(modules))
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == expected


@pytest.mark.parametrize("wrapper", ["tuple(('native-tool',))", "[str(x) for x in ('native-tool',)]"])
def test_local_wrappers_without_bearing_sources_add_no_review(tmp_path, wrapper):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "consumer.py").write_text("import subprocess\nargv = " + wrapper + "\nsubprocess.run(argv)\n",
                                     encoding="utf-8")
    assert selector_gate_errors(dict(module_trees(tmp_path)), ()) == []
    assert literal_fixture_sites(tmp_path) == {"process:aegis_core/consumer.py:<module>:subprocess.run": [3]}


@pytest.mark.parametrize("route", ["module", "from_import"])
@pytest.mark.parametrize("reviewed", [False, True])
def test_modeled_stdlib_quote_callee_is_not_unresolved(tmp_path, route, reviewed):
    core = tmp_path / "aegis_core"
    core.mkdir()
    declaration, helper = ("import shlex\n", "shlex.quote") if route == "module" else (
        "from shlex import quote as shell_quote\n", "shell_quote")
    metadata = "    message = '-c is printed as shell data'\n" if reviewed else ""
    (core / "consumer.py").write_text("import os\n" + declaration + "def launch(arg):\n" + metadata
                                     + "    os.system('echo ' + " + helper + "(arg))\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "lexer-or-message", "Review the literal option-message metadata."),) if reviewed else ()
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, table) == []
    expected = {"process:aegis_core/consumer.py:launch:os.system": [5 if reviewed else 4]}
    assert process_sites(tmp_path, selector_table=table) == expected
    assert literal_fixture_sites(tmp_path) == expected


@pytest.mark.parametrize("route", ["module", "from_import"])
def test_modeled_stdlib_quote_still_walks_unresolved_arguments(tmp_path, route):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "defaults.py").write_text("CODE = 'plain text'\n", encoding="utf-8")
    (core / "provider.py").write_text("from . import defaults as config\n", encoding="utf-8")
    declaration, helper = ("import shlex\n", "shlex.quote") if route == "module" else (
        "from shlex import quote as shell_quote\n", "shell_quote")
    (core / "consumer.py").write_text("import os\n" + declaration + "from .provider import config\n"
                                     + "os.system('echo ' + " + helper + "(config.CODE))\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


def test_captured_stdlib_path_callee_is_not_unresolved(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "worker.py").write_text("pass\n", encoding="utf-8")
    (core / "consumer.py").write_text("from pathlib import Path\n"
                                     "CODE = Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n",
                                     encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    resolver = CommandResolver(modules)
    expression = modules["aegis_core/consumer.py"].body[1].value
    assert resolver.bearing(expression, "aegis_core/consumer.py", unresolved_only=True) is False
    assert literal_fixture_sites(tmp_path) == {}


@pytest.mark.parametrize("reason", ["", "   ", "one\ntwo", "one\rtwo", "one\r\ntwo", "one\u2028two", None, 7, b"reason"])
@pytest.mark.parametrize("entry", ["refusal", "inventory"])
def test_literal_exception_reason_must_be_one_nonempty_text_line(tmp_path, reason, entry):
    rel, function, program = "aegis_core/probe.py", "launch", "import sys\nsys.path[:] = []\n"
    table = literal_review_tree(tmp_path, program, rel, function)
    exceptions = {(rel, function, hashlib.sha256(program.encode()).hexdigest()): reason}
    with pytest.raises(ValueError) as error:
        if entry == "refusal":
            modules = dict(module_trees(tmp_path))
            refuse_literal_spawns(modules[rel], rel, modules, literal_exceptions=exceptions)
        else:
            process_sites(tmp_path, selector_table=table, literal_exceptions=exceptions)
    assert str(error.value) == "process census: invalid literal program exception"


@pytest.mark.parametrize("reviewed", [False, True])
def test_literal_exception_ownership_uses_statement_nodes_on_shared_lines(reviewed):
    rel, program = "aegis_core/probe.py", "import sys\nsys.path[:] = []\n"
    command = "subprocess.run([sys.executable, '-c', " + repr(program) + "])"
    # AST location metadata can co-locate separate statements. Preserve each
    # statement's actual lexical owner instead of taking the line's last scope.
    if reviewed:
        tree = ast.parse("import sys, subprocess\ndef launch(): " + command + "\npass\n")
        ast.increment_lineno(tree.body[-1], -1)
    else:
        tree = ast.parse("import sys, subprocess\n" + command + "\ndef launch(): pass\n")
        ast.increment_lineno(tree.body[-1], -1)
    exceptions = {(rel, "launch", hashlib.sha256(program.encode()).hexdigest()): "Review only the function's store."}
    if reviewed:
        refuse_literal_spawns(tree, rel, {rel: tree}, literal_exceptions=exceptions)
    else:
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(tree, rel, {rel: tree}, literal_exceptions=exceptions)
        assert str(error.value) == rel + ": process spawn inside a literal -c program"


STDLIB_REEXPORT_ROUTES = ("direct", "plain", "aliased", "package", "transitive", "namespace", "package_transitive",
                         "stdlib_module", "stdlib_module_alias")


def stdlib_reexport_tree(tmp_path, helper, route):
    core = tmp_path / "aegis_core"
    core.mkdir()
    module, name = ("shlex", "quote") if helper == "quote" else ("pathlib", "Path")
    export = "exported" if route == "aliased" else name
    declaration = "from " + module + " import " + name + (" as exported" if route == "aliased" else "") + "\n"
    files = {}
    provider = None
    if route == "direct":
        consumer_import = "from " + module + " import " + name + " as helper\n"
        expression = "helper"
    else:
        provider = "helpers/__init__.py" if route == "package" else "provider.py"
        files[provider] = declaration
        source = "helpers" if route == "package" else "provider"
        if route == "transitive":
            files["relay.py"] = "from .provider import " + name + "\n"
            source, provider = "relay", "relay.py"
        elif route == "package_transitive":
            files = {"helpers/leaf.py": declaration, "helpers/__init__.py": "from .leaf import " + name + "\n"}
            source, provider = "helpers", "helpers/__init__.py"
        consumer_import = "from ." + source + " import " + export + " as helper\n"
        expression = "helper"
        if route == "namespace":
            consumer_import, expression = "from . import provider\n", "provider." + name
        elif route in {"stdlib_module", "stdlib_module_alias"}:
            export = "tools" if route == "stdlib_module_alias" else module
            files[provider] = "import " + module + (" as tools" if route == "stdlib_module_alias" else "") + "\n"
            consumer_import, expression = "from .provider import " + export + " as helper\n", "helper." + name
    for rel, text in files.items():
        path = core / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return consumer_import, expression, core / provider if provider is not None else None, export


@pytest.mark.parametrize("route", STDLIB_REEXPORT_ROUTES)
@pytest.mark.parametrize("command", ["echo", "python"])
def test_trusted_stdlib_reexports_preserve_quote_modeling(tmp_path, route, command):
    declaration, helper, _, _ = stdlib_reexport_tree(tmp_path, "quote", route)
    call = "os.system('echo ' + " + helper + "(arg))" if command == "echo" else (
        "os.system('python -c ' + " + helper + "('pass'))")
    (tmp_path / "aegis_core/consumer.py").write_text("import os\n" + declaration + "def launch(arg):\n"
        "    message = '-c is option-message metadata'\n    " + call + "\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    table = (("aegis_core/consumer.py", "launch", "resolved-python-program", "Review this test-owned shell site."),)
    assert selector_gate_errors(modules, table) == []
    expected = {"process:aegis_core/consumer.py:launch:os.system": [5]}
    assert literal_fixture_sites(tmp_path) == expected
    assert process_sites(tmp_path, selector_table=table) == expected
    if command == "python":
        assert list(literal_programs(modules["aegis_core/consumer.py"], "aegis_core/consumer.py", modules)) == [(5, "pass")]


@pytest.mark.parametrize("route", STDLIB_REEXPORT_ROUTES)
@pytest.mark.parametrize("opaque_user", [False, True])
def test_trusted_stdlib_reexports_preserve_path_capture(tmp_path, route, opaque_user):
    declaration, helper, _, _ = stdlib_reexport_tree(tmp_path, "Path", route)
    (tmp_path / "aegis_core/worker.py").write_text("pass\n", encoding="utf-8")
    source = declaration + "import sys, subprocess\nCODE = " + helper + "(__file__).with_name('worker.py').read_text(encoding='utf-8')\n"
    if opaque_user:
        source += "def inspect(code):\n    pass\ninspect(CODE)\n"
    source += "subprocess.run([sys.executable, '-c', CODE])\n"
    (tmp_path / "aegis_core/consumer.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    resolver = CommandResolver(modules)
    capture = next(node.value for node in modules["aegis_core/consumer.py"].body if isinstance(node, ast.Assign))
    assert resolver.bearing(capture, "aegis_core/consumer.py", unresolved_only=True) is False
    expected = {"process:aegis_core/consumer.py:<module>:subprocess.run": [len(source.splitlines())]}
    table = (("aegis_core/consumer.py", "<module>", "resolved-python-program", "Review the test-owned captured module."),)
    assert selector_gate_errors(modules, table) == []
    assert literal_fixture_sites(tmp_path) == expected
    assert process_sites(tmp_path, selector_table=table) == expected


@pytest.mark.parametrize("route", STDLIB_REEXPORT_ROUTES)
def test_trusted_stdlib_reexports_still_walk_quote_arguments(tmp_path, route):
    declaration, helper, _, _ = stdlib_reexport_tree(tmp_path, "quote", route)
    core = tmp_path / "aegis_core"
    (core / "defaults.py").write_text("CODE = 'plain text'\n", encoding="utf-8")
    (core / "config_source.py").write_text("from . import defaults as config\n", encoding="utf-8")
    (core / "consumer.py").write_text("import os\n" + declaration + "from .config_source import config\n"
        "os.system('echo ' + " + helper + "(config.CODE))\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("route", ["plain", "aliased", "package", "transitive", "stdlib_module", "stdlib_module_alias"])
@pytest.mark.parametrize("helper", ["quote", "Path"])
def test_trusted_stdlib_reexports_refuse_intermediate_rebinding(tmp_path, route, helper):
    declaration, expression, provider, export = stdlib_reexport_tree(tmp_path, helper, route)
    provider.write_text(provider.read_text(encoding="utf-8") + export + " = str\n", encoding="utf-8")
    core = tmp_path / "aegis_core"
    (core / "worker.py").write_text("pass\n", encoding="utf-8")
    call = ("os.system('echo ' + " + expression + "(arg))" if helper == "quote" else
            "subprocess.run([sys.executable, '-c', " + expression + "(__file__).with_name('worker.py').read_text(encoding='utf-8')])")
    (core / "consumer.py").write_text("import os, sys, subprocess\n" + declaration
        + "def launch(arg):\n    " + call + "\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("shape", ["cycle", "depth"])
def test_trusted_stdlib_reexports_bound_import_walks(tmp_path, shape):
    declaration, helper, provider, _ = stdlib_reexport_tree(tmp_path, "quote", "plain")
    core = tmp_path / "aegis_core"
    if shape == "cycle":
        provider.write_text("from .relay import quote\n", encoding="utf-8")
        (core / "relay.py").write_text("from .provider import quote\n", encoding="utf-8")
    else:
        provider.write_text("from .hop0 import quote\n", encoding="utf-8")
        for index in range(_MAX_DEPTH + 1):
            text = "from .hop" + str(index + 1) + " import quote\n" if index < _MAX_DEPTH else "from shlex import quote\n"
            (core / ("hop" + str(index) + ".py")).write_text(text, encoding="utf-8")
    (core / "consumer.py").write_text("import os\n" + declaration + "def launch(arg):\n"
        "    os.system('echo ' + " + helper + "(arg))\n", encoding="utf-8")
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("route", ["direct", "plain", "stdlib_module_alias"])
@pytest.mark.parametrize("method", ["cwd", "home"])
def test_trusted_stdlib_readonly_path_calls_pass(tmp_path, route, method):
    declaration, helper, _, _ = stdlib_reexport_tree(tmp_path, "Path", route)
    (tmp_path / "aegis_core/consumer.py").write_text("import os\n" + declaration + "def launch():\n"
        "    message = '-c is option-message metadata'\n"
        "    os.system('echo ' + str(" + helper + "." + method + "()))\n", encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "lexer-or-message", "Review test-owned option-message metadata."),)
    assert selector_gate_errors(dict(module_trees(tmp_path)), table) == []
    expected = {"process:aegis_core/consumer.py:launch:os.system": [5]}
    assert literal_fixture_sites(tmp_path) == expected
    assert process_sites(tmp_path, selector_table=table) == expected


@pytest.mark.parametrize("route", ["direct", "plain", "package_transitive"])
@pytest.mark.parametrize("scope", ["module", "function"])
def test_trusted_stdlib_local_alias_preserves_quote(tmp_path, route, scope):
    declaration, helper, _, _ = stdlib_reexport_tree(tmp_path, "quote", route)
    source = "import os\n" + declaration
    if scope == "module":
        source += "quote_alias = " + helper + "\n"
    source += "def launch(arg):\n    message = '-c is option-message metadata'\n"
    if scope == "function":
        source += "    quote_alias = " + helper + "\n"
    source += "    os.system('echo ' + quote_alias(arg))\n"
    (tmp_path / "aegis_core/consumer.py").write_text(source, encoding="utf-8")
    table = (("aegis_core/consumer.py", "launch", "lexer-or-message", "Review test-owned option-message metadata."),)
    assert selector_gate_errors(dict(module_trees(tmp_path)), table) == []
    expected = {"process:aegis_core/consumer.py:launch:os.system": [len(source.splitlines())]}
    assert literal_fixture_sites(tmp_path) == expected
    assert process_sites(tmp_path, selector_table=table) == expected


@pytest.mark.parametrize("route", ["direct", "plain"])
@pytest.mark.parametrize("scope", ["module", "function"])
def test_trusted_stdlib_local_alias_rebinding_refuses(tmp_path, route, scope):
    declaration, helper, _, _ = stdlib_reexport_tree(tmp_path, "quote", route)
    core = tmp_path / "aegis_core"
    (core / "foreign.py").write_text("def foreign(value):\n    return value\n", encoding="utf-8")
    source = "import os\n" + declaration + "from .foreign import foreign\n"
    assignment = "quote_alias = " + helper + "\nquote_alias = foreign\n"
    if scope == "module":
        source += assignment
    source += "def launch(arg):\n"
    if scope == "function":
        source += "".join("    " + line + "\n" for line in assignment.splitlines())
    source += "    os.system('echo ' + quote_alias(arg))\n"
    (core / "consumer.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    call = next(n for n in ast.walk(modules["aegis_core/consumer.py"]) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "quote_alias")
    assert CommandResolver(modules).helper_identity(call.func, "aegis_core/consumer.py") is None
    with pytest.raises(ValueError) as error:
        literal_fixture_sites(tmp_path)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("shape", ["cycle", "depth"])
def test_trusted_stdlib_local_alias_walk_is_bounded(tmp_path, shape):
    core = tmp_path / "aegis_core"
    core.mkdir()
    if shape == "cycle":
        source = "first = second\nsecond = first\n"
    else:
        source = "from shlex import quote\nfirst = alias0\n"
        source += "".join("alias" + str(i) + " = " + ("alias" + str(i + 1) if i < _MAX_DEPTH else "quote")
                          + "\n" for i in range(_MAX_DEPTH + 1))
    source += "def launch(arg):\n    return first(arg)\n"
    (core / "consumer.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    call = next(n for n in ast.walk(modules["aegis_core/consumer.py"]) if isinstance(n, ast.Call))
    assert CommandResolver(modules).helper_identity(call.func, "aegis_core/consumer.py") is None


TRUSTED_RECEIVER_FORMS = ("direct", "module", "function", "chain_module", "chain_function", "closure",
                          "nested_closure", "reexport", "reexport_assignment", "reexport_chain")
TRUSTED_RECEIVER_REBINDS = (("direct", "first"), ("module", "first"), ("function", "first"),
    ("chain_module", "first"), ("chain_module", "last"), ("chain_function", "first"), ("chain_function", "last"),
    ("closure", "first"), ("nested_closure", "first"), ("nested_closure", "last"),
    ("reexport", "first"), ("reexport_assignment", "first"), ("reexport_chain", "first"), ("reexport_chain", "last"))


def trusted_receiver_tree(tmp_path, form, api, *, rebind=None, argument=None):
    core = tmp_path / "aegis_core"
    core.mkdir()
    module = "shlex" if api == "quote" else "pathlib"
    lines = ["import os, sys, shlex, pathlib, types"]
    if form.startswith("reexport"):
        (core / "provider.py").write_text("import " + module + " as q\n", encoding="utf-8")
        if form == "reexport_chain":
            (core / "relay.py").write_text("from .provider import q as tools\n", encoding="utf-8")
            lines.append("from .relay import tools as imported")
        else:
            lines.append("from .provider import q as imported")
    if argument == "foreign":
        (core / "defaults.py").write_text("CODE = 'plain text'\n", encoding="utf-8")
        (core / "config_source.py").write_text("from . import defaults as config\n", encoding="utf-8")
        lines.append("from .config_source import config")
    pairs = {
        "direct": [], "module": [("tools", module)], "function": [("tools", module)],
        "chain_module": [("a", module), ("b", "a")], "chain_function": [("a", module), ("b", "a")],
        "closure": [("tools", module)], "nested_closure": [("tools", module), ("selected", "tools")],
        "reexport": [], "reexport_assignment": [("tools", "imported")],
        "reexport_chain": [("a", "imported"), ("b", "a")],
    }[form]
    receiver = pairs[-1][0] if pairs else ("imported" if form == "reexport" else module)
    target = pairs[0 if rebind == "first" else -1][0] if pairs else receiver

    def emit(text, indent=0):
        lines.append("    " * indent + text)

    def assignments(items, indent):
        for name, value in items:
            emit(name + " = " + value, indent)
            if rebind is not None and name == target:
                emit(name + " = types", indent)

    if not pairs and rebind is not None:
        emit(target + " = types")
    if form in {"module", "chain_module", "reexport_assignment"}:
        assignments(pairs, 0)
    indent, scope = 0, "launch"
    if form in {"closure", "nested_closure"}:
        emit("def outer():")
        assignments(pairs[:1], 1)
        indent, scope = 1, "outer.launch"
        if form == "nested_closure":
            emit("def middle():", 1)
            assignments(pairs[1:], 2)
            indent, scope = 2, "outer.middle.launch"
    emit("def launch(arg):", indent)
    emit("message = '-c is option-message metadata'", indent + 1)
    if form in {"function", "chain_function", "reexport_chain"}:
        assignments(pairs, indent + 1)
    helper = receiver + (".quote" if api == "quote" else ".Path" + ("." + api if api in {"cwd", "home"} else ""))
    operand = "config.CODE" if argument == "foreign" else receiver if argument == "receiver" else "arg"
    call = helper + "(" + operand + ")" if api in {"quote", "path"} else helper + "()"
    emit("os.system('echo ' + " + (call if api == "quote" else "str(" + call + ")") + ")", indent + 1)
    path = core / "consumer.py"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    tree = modules["aegis_core/consumer.py"]
    spawn = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == "os" and n.func.attr == "system")
    command = spawn.args[0]
    reference = command.right.func if api == "quote" else command.right.args[0].func
    table = (("aegis_core/consumer.py", scope, "lexer-or-message", "Review the test-owned option-message metadata."),)
    expected = {"process:aegis_core/consumer.py:" + scope + ":os.system": [len(lines)]}
    return modules, CommandResolver(modules), command, reference, table, expected


@pytest.mark.parametrize("form", TRUSTED_RECEIVER_FORMS)
@pytest.mark.parametrize("api", ["quote", "path", "cwd", "home"])
@pytest.mark.parametrize("entry", ["selector", "refusal"])
def test_trusted_receiver_forms_agree_with_helper_identity(tmp_path, form, api, entry):
    modules, resolver, command, reference, table, expected = trusted_receiver_tree(tmp_path, form, api)
    identity = "shlex.quote" if api == "quote" else "pathlib.Path" + ("." + api if api in {"cwd", "home"} else "")
    assert resolver.helper_identity(reference, "aegis_core/consumer.py") == identity
    assert resolver.bearing(command, "aegis_core/consumer.py", unresolved_only=True) is False
    if entry == "selector":
        assert selector_gate_errors(modules, table) == []
        assert process_sites(tmp_path, selector_table=table) == expected
    else:
        refuse_literal_spawns(modules["aegis_core/consumer.py"], "aegis_core/consumer.py", modules, resolver)
        assert literal_fixture_sites(tmp_path) == expected


@pytest.mark.parametrize("form,link", TRUSTED_RECEIVER_REBINDS)
@pytest.mark.parametrize("api", ["quote", "path", "cwd", "home"])
def test_trusted_receiver_rebinding_keeps_refusal(tmp_path, form, link, api):
    modules, resolver, command, reference, _, _ = trusted_receiver_tree(tmp_path, form, api, rebind=link)
    assert resolver.helper_identity(reference, "aegis_core/consumer.py") is None
    assert resolver.bearing(command, "aegis_core/consumer.py", unresolved_only=True) is True
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules["aegis_core/consumer.py"], "aegis_core/consumer.py", modules, resolver)
    assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


@pytest.mark.parametrize("form", ["module", "chain_function", "closure", "reexport_assignment"])
@pytest.mark.parametrize("argument", ["foreign", "receiver"])
@pytest.mark.parametrize("entry", ["selector", "refusal"])
def test_trusted_receiver_exemption_still_walks_arguments(tmp_path, form, argument, entry):
    modules, resolver, command, reference, table, _ = trusted_receiver_tree(tmp_path, form, "quote", argument=argument)
    assert resolver.helper_identity(reference, "aegis_core/consumer.py") == "shlex.quote"
    assert resolver.bearing(command, "aegis_core/consumer.py", unresolved_only=True) is True
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + table[0][0] + ":" + table[0][1]]
        assert any(source is None for _, source in literal_programs(modules["aegis_core/consumer.py"],
                                                                    "aegis_core/consumer.py", modules, resolver))
    else:
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules["aegis_core/consumer.py"], "aegis_core/consumer.py", modules, resolver)
        assert str(error.value) == "aegis_core/consumer.py: unresolved Python -c program"


TRUSTED_CONSTRUCTION_RECEIVERS = {
    "direct": ("direct", "quote"), "assignment": ("function", "quote"),
    "chain": ("chain_function", "quote"), "closure": ("closure", "quote"),
    "reexport": ("reexport", "quote"), "path_cwd": ("function", "cwd"),
    "path_home": ("function", "home"),
}
TRUSTED_COMMAND_CONSTRUCTIONS = ("concatenation", "f_string", "percent", "format", "join", "list_argv",
                                 "list_concat", "tuple_argv", "comprehension_argv", "return_concat")


def trusted_construction_tree(tmp_path, receiver, construction, *, rebound=False, argument=None):
    form, api = TRUSTED_CONSTRUCTION_RECEIVERS[receiver]
    modules, _, command, reference, table, _ = trusted_receiver_tree(
        tmp_path, form, api, rebind="first" if rebound else None, argument=argument)
    spelling = ast.unparse(reference)
    word = ast.unparse(command.right)
    expressions = {
        "concatenation": "'echo ' + " + word,
        "f_string": 'f"echo {' + word + '}"',
        "percent": "'echo %s' % " + word,
        "format": "'echo {}'.format(" + word + ")",
        "join": "' '.join(['echo', " + word + "])",
        "list_argv": "['echo', " + word + "]",
        "list_concat": "['echo', " + word + "] + extra",
        "tuple_argv": "tuple(['echo', " + word + "])",
        "comprehension_argv": "[" + word.replace("(arg)", "(item)") + " for item in arg]",
        "return_concat": "['echo', " + word + "] + extra",
    }
    tree = modules["aegis_core/consumer.py"]
    spawn = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == "os.system")
    path = tmp_path / "aegis_core/consumer.py"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("import os, sys,", "import os, sys, subprocess,", 1)
    if construction in {"list_concat", "return_concat"}:
        lines = [line.replace("def launch(arg):", "def launch(arg, extra=()):") for line in lines]
    process_api = "subprocess.run" if construction in {
        "list_argv", "list_concat", "tuple_argv", "comprehension_argv"} else "os.system"
    statement = ("return " + expressions[construction] if construction == "return_concat" else
                 process_api + "(" + expressions[construction] + ")")
    lines[spawn.lineno - 1] = " " * spawn.col_offset + statement
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    tree = modules["aegis_core/consumer.py"]
    if construction == "return_concat":
        statement = next(node for node in ast.walk(tree) if isinstance(node, ast.Return))
        command, expected = statement.value, {}
    else:
        spawn = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and ast.unparse(node.func) == process_api)
        command = spawn.args[0]
        expected = {"process:aegis_core/consumer.py:" + table[0][1] + ":" + process_api: [spawn.lineno]}
    reference = next(node.func for node in ast.walk(tree) if isinstance(node, ast.Call)
                     and ast.unparse(node.func) == spelling)
    return modules, CommandResolver(modules), command, reference, table, expected


@pytest.mark.parametrize("receiver", TRUSTED_CONSTRUCTION_RECEIVERS)
@pytest.mark.parametrize("construction", TRUSTED_COMMAND_CONSTRUCTIONS)
@pytest.mark.parametrize("entry", ["selector", "refusal"])
@pytest.mark.parametrize("rebound", [False, True])
def test_trusted_receiver_construction_matrix(tmp_path, receiver, construction, entry, rebound):
    modules, resolver, command, reference, table, expected = trusted_construction_tree(
        tmp_path, receiver, construction, rebound=rebound)
    rel = "aegis_core/consumer.py"
    api = TRUSTED_CONSTRUCTION_RECEIVERS[receiver][1]
    identity = "shlex.quote" if api == "quote" else "pathlib.Path." + api
    assert resolver.helper_identity(reference, rel) == (None if rebound else identity)
    if rebound:
        if entry == "selector":
            message = "unreviewed selector site " + rel + ":" + table[0][1]
            assert selector_gate_errors(modules, ()) == [message]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == message
            assert any(source is None for _, source in literal_programs(modules[rel], rel, modules, resolver))
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules, resolver)
            assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        if entry == "selector":
            assert selector_gate_errors(modules, table) == []
            assert process_sites(tmp_path, selector_table=table) == expected
        else:
            refuse_literal_spawns(modules[rel], rel, modules, resolver)
            assert literal_fixture_sites(tmp_path) == expected
        assert list(literal_programs(modules[rel], rel, modules, resolver)) == []
    for unresolved_only in (False, True):
        assert resolver.bearing(command, rel, unresolved_only=unresolved_only) is rebound


@pytest.mark.parametrize("construction", TRUSTED_COMMAND_CONSTRUCTIONS)
@pytest.mark.parametrize("entry", ["selector", "refusal"])
def test_trusted_receiver_constructions_keep_argument_provenance(tmp_path, construction, entry):
    modules, resolver, command, reference, table, _ = trusted_construction_tree(
        tmp_path, "assignment", construction, argument="foreign")
    rel = "aegis_core/consumer.py"
    assert resolver.helper_identity(reference, rel) == "shlex.quote"
    if entry == "selector":
        message = "unreviewed selector site " + rel + ":" + table[0][1]
        assert selector_gate_errors(modules, ()) == [message]
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=())
        assert str(error.value) == message
        assert any(source is None for _, source in literal_programs(modules[rel], rel, modules, resolver))
    else:
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules, resolver)
        assert str(error.value) == rel + ": unresolved Python -c program"
    for unresolved_only in (False, True):
        assert resolver.bearing(command, rel, unresolved_only=unresolved_only) is True


@pytest.mark.parametrize("route", ["direct", "module_alias", "class_alias", "stored_method"])
@pytest.mark.parametrize("method", ["read_text", "open"])
@pytest.mark.parametrize("command", ["argv", "shell"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_untrusted_path_methods_keep_receiver_provenance(tmp_path, route, method, command, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    declarations = {
        "direct": ("", "pathlib.Path." + method),
        "module_alias": ("    paths = pathlib\n", "paths.Path." + method),
        "class_alias": ("    cls = pathlib.Path\n", "cls." + method),
        "stored_method": ("    cls = pathlib.Path\n    reader = cls." + method + "\n", "reader"),
    }
    assignment, reference = declarations[route]
    read = reference + "(p)"
    call = ("subprocess.run([sys.executable, " + read + ", \"import os; os.system('id')\"])") if command == "argv" else (
        "os.system('echo ' + " + read + ")")
    source = "import os, subprocess, sys, pathlib\ndef launch(p):\n" + assignment + "    " + call + "\n"
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            message = "unreviewed selector site " + rel + ":launch"
            assert selector_gate_errors(modules, ()) == [message]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == message
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("receiver", ["assignment", "chain", "closure", "reexport"])
@pytest.mark.parametrize("construction", TRUSTED_COMMAND_CONSTRUCTIONS)
@pytest.mark.parametrize("entry", ["selector", "refusal"])
@pytest.mark.parametrize("mutated", [False, True])
def test_module_alias_calls_preserve_helpers_and_real_mutations(tmp_path, receiver, construction, entry, mutated):
    modules, _, command, reference, table, expected = trusted_construction_tree(tmp_path, receiver, construction)
    rel = "aegis_core/consumer.py"
    alias = ast.unparse(reference.value)
    path = tmp_path / rel
    lines = path.read_text(encoding="utf-8").splitlines()
    position = command.lineno - 1
    indent = " " * (len(lines[position]) - len(lines[position].lstrip()))
    before = ([indent + "setattr(" + alias + ", 'quote', str)"] if mutated else [])
    before.extend([indent + alias + ".split(arg)", indent + "os.system('echo ' + shlex.quote(arg))"])
    lines[position:position] = before
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    other = "aegis_core/other.py"
    (tmp_path / other).write_text("import os, shlex\ndef launch(arg):\n"
        "    message = '-c is option-message metadata'\n    os.system('echo ' + shlex.quote(arg))\n",
        encoding="utf-8")
    table += ((other, "launch", "lexer-or-message", "Review test-owned option-message metadata."),)
    expected = {key: [line + len(before) for line in values] for key, values in expected.items()}
    direct = "process:" + rel + ":" + table[0][1] + ":os.system"
    expected.setdefault(direct, []).insert(0, position + len(before))
    expected["process:" + other + ":launch:os.system"] = [4]
    modules = dict(module_trees(tmp_path))
    resolver = CommandResolver(modules)
    if mutated:
        if entry == "selector":
            message = "unreviewed selector site " + rel + ":" + table[0][1]
            assert selector_gate_errors(modules, table[1:]) == [message]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=table[1:])
            assert str(error.value) == message
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules, resolver)
            assert str(error.value) == rel + ": unresolved Python -c program"
        assert any(source is None for _, source in literal_programs(modules[rel], rel, modules, resolver))
    else:
        if entry == "selector":
            assert selector_gate_errors(modules, table) == []
            assert process_sites(tmp_path, selector_table=table) == expected
        else:
            for source_rel, tree in modules.items():
                refuse_literal_spawns(tree, source_rel, modules, resolver)
            assert literal_fixture_sites(tmp_path) == expected
        for source_rel in (rel, other):
            assert list(literal_programs(modules[source_rel], source_rel, modules, resolver)) == []
            references = [node.func for node in ast.walk(modules[source_rel]) if isinstance(node, ast.Call)
                          and isinstance(node.func, ast.Attribute) and node.func.attr == "quote"]
            assert all(resolver.helper_identity(node, source_rel) == "shlex.quote" for node in references)


SHELL_SELECTOR_TEMPLATES = (
    "os.system('python3 -c %s' % shlex.quote(P))",
    "os.system('python3 -c {}'.format(shlex.quote(P)))",
    "os.system(' '.join(['python3 -c', shlex.quote(P)]))",
    "os.system(('python3 -c ' + shlex.quote(P)).strip())",
    "subprocess.run('python3 -c %s' % tools.quote(P), shell=True)",
    "subprocess.run(tuple(['python3', b'-c', P]))",
)


@pytest.mark.parametrize("command", SHELL_SELECTOR_TEMPLATES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_shell_template_constants_retain_python_selectors(tmp_path, command, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import os, subprocess, shlex\nP = \"import os; os.system('id')\"\n"
              "def launch():\n    tools = shlex\n    " + command + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            message = "unreviewed selector site " + rel + ":launch"
            assert selector_gate_errors(modules, ()) == [message]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == message
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


TRUSTED_RESULT_OPERATIONS = {
    "direct": ("", "", "pathlib.Path(p).read_text()"),
    "stored": ("", "    q = pathlib.Path(p)\n", "q.read_text()"),
    "stored_alias": ("", "    q = pathlib.Path(p)\n    target = q\n", "target.read_text()"),
    "module_alias": ("", "    paths = pathlib\n", "paths.Path(p).read_text()"),
    "class_alias": ("", "    P = pathlib.Path\n", "P(p).read_text()"),
    "open_read": ("", "", "pathlib.Path(p).open().read()"),
    "cwd": ("", "", "(pathlib.Path.cwd() / p).read_text()"),
    "home": ("", "", "(pathlib.Path.home() / p).read_text()"),
    "joinpath": ("", "", "pathlib.Path.cwd().joinpath(p).read_text()"),
    "stored_method": ("", "    reader = pathlib.Path(p).read_text\n", "reader()"),
    "missing_capture": ("CODE = pathlib.Path(__file__).with_name('absent.py').read_text(encoding='utf-8')\n", "", "CODE"),
    "attribute": ("", "", "pathlib.Path(p).name"),
    "subscript": ("", "    q = shlex.quote(p)\n", "q[:2]"),
    "iteration": ("", "", "next(iter(pathlib.Path(p)))"),
    "iteration_binding": ("", "    for opt in shlex.quote(p):\n        pass\n", "opt"),
    "comprehension": ("", "    parts = [c for c in shlex.quote(p)]\n", "''.join(parts)"),
    "unpack": ("", "    opt, *rest = shlex.quote(p)\n", "opt"),
    "unpack_instance": ("", "    q, = [pathlib.Path(p)]\n", "q.read_text()"),
    "f_string_attribute": ("", "", "f'{pathlib.Path(p).name}'"),
    "format_attribute": ("", "    q = pathlib.Path(p)\n", "'{}'.format(q.name)"),
}


@pytest.mark.parametrize("shape", TRUSTED_RESULT_OPERATIONS)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_operations_on_trusted_results_keep_provenance(tmp_path, shape, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    module, local, operand = TRUSTED_RESULT_OPERATIONS[shape]
    source = ("import pathlib, os, subprocess, sys, shlex\n" + module + "def launch(p):\n" + local
              + "    subprocess.run([sys.executable, " + operand + ", \"import os; os.system('id')\"])\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            message = "unreviewed selector site " + rel + ":launch"
            assert selector_gate_errors(modules, ()) == [message]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == message
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("declaration,operand", [
    ("", "str(pathlib.Path(p))"),
    ("    q = pathlib.Path(p)\n", "str(q)"),
    ("    q = pathlib.Path(p)\n    alias = q\n", "str(alias)"),
    ("    q = shlex.quote(p)\n", "q"),
    ("    q = pathlib.Path.cwd()\n", "str(q)"),
    ("    q = pathlib.Path.home()\n", "str(q)"),
])
def test_trusted_results_used_directly_remain_exempt(tmp_path, declaration, operand):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = "import pathlib, os, shlex\ndef launch(p):\n" + declaration + "    os.system('echo ' + " + operand + ")\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, ()) == []
    refuse_literal_spawns(modules[rel], rel, modules)
    assert literal_fixture_sites(tmp_path) == {"process:" + rel + ":launch:os.system": [len(source.splitlines())]}


NAMESPACE_RECEIVER_CASES = ("unpack", "annotation", "handler", "handler_table", "package_unrelated",
    "conditional_import", "conditional_alias", "conditional_reexport", "conditional_assignment", "conditional_expression")


def namespace_receiver_tree(tmp_path, case, rebound):
    core = tmp_path / "aegis_core"
    core.mkdir()
    if case in NAMESPACE_RECEIVER_CASES[:5]:
        changes = {"unpack": "A, B = (1, 2)\n", "annotation": "A: int\n",
            "handler": "try:\n    pass\nexcept Exception as error:\n    pass\n",
            "handler_table": "HANDLERS = (helper,)\n", "package_unrelated": ""}
        provider = (core / "provider/__init__.py") if case == "package_unrelated" else (core / "provider.py")
        provider.parent.mkdir(exist_ok=True)
        provider.write_text("import shlex as q\nCMD = ('git', 'status')\ndef helper(x):\n    return x\n"
                            + changes[case], encoding="utf-8")
        if case == "package_unrelated":
            provider.with_name("unrelated.py").write_text("A, B = (1, 2)\n", encoding="utf-8")
        source = "import os, subprocess\nfrom . import provider\nfrom .provider import q, CMD\n"
        source += ("provider = object()\n" if rebound else "") + "def launch(arg):\n"
        quote = "provider.q.quote" if rebound else "q.quote"
        source += "    provider.helper(arg)\n    os.system('echo ' + " + quote + "(arg))\n    subprocess.run(CMD)\n"
    else:
        imports = ("import os, sys, shlex, ntpath\nif sys.platform == 'win32':\n"
                   "    import ntpath as helper_mod\nelse:\n    import shlex as helper_mod\n")
        receiver = "helper_mod"
        if case == "conditional_reexport":
            (core / "provider.py").write_text(imports, encoding="utf-8")
            source = "import os, shlex\nfrom .provider import helper_mod\n"
        elif case == "conditional_assignment":
            source = ("import os, sys, shlex, ntpath\nif sys.platform == 'win32':\n"
                      "    helper_mod = ntpath\nelse:\n    helper_mod = shlex\n")
        elif case == "conditional_expression":
            source = "import os, sys, shlex, ntpath\nhelper_mod = ntpath if sys.platform == 'win32' else shlex\n"
        else:
            source = imports
        if case == "conditional_alias":
            source += "alias = helper_mod\n"
            receiver = "alias"
        source += (receiver + " = object()\n" if rebound else "") + "def launch(arg):\n"
        quote = receiver + ".quote" if rebound else "shlex.quote"
        source += "    " + receiver + ".split(arg)\n    os.system('echo ' + " + quote + "(arg))\n"
    (core / "consumer.py").write_text(source, encoding="utf-8")
    return source


@pytest.mark.parametrize("case", NAMESPACE_RECEIVER_CASES)
@pytest.mark.parametrize("rebound", [False, True])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_namespace_receiver_changes_do_not_poison_exports(tmp_path, case, rebound, entry):
    source = namespace_receiver_tree(tmp_path, case, rebound)
    rel = "aegis_core/consumer.py"
    if entry == "inventory":
        (tmp_path / rel).write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', "
                                   + repr(source) + "])\n", encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        if rebound:
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=table)
            assert str(error.value) == rel + ": unresolved Python -c program"
        else:
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == (
                2 if case in NAMESPACE_RECEIVER_CASES[:5] else 1)
        return
    modules = dict(module_trees(tmp_path))
    if rebound:
        if entry == "selector":
            message = "unreviewed selector site " + rel + ":launch"
            assert selector_gate_errors(modules, ()) == [message]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == message
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == []
        else:
            refuse_literal_spawns(modules[rel], rel, modules)
        sites = process_sites(tmp_path, selector_table=())
        expected = {"process:" + rel + ":launch:" + api: [index] for index, text in enumerate(source.splitlines(), 1)
                    for api in ("os.system", "subprocess.run") if text.strip().startswith(api + "(")}
        assert sites == expected


CONTENT_SOURCE_CASES = {
    "conditional": ("", "", "(pathlib.Path(p) if p else pathlib.Path(q)).read_text()"),
    "boolean": ("", "", "(pathlib.Path(p) or pathlib.Path(q)).read_bytes()"),
    "list_selection": ("", "", "[pathlib.Path(p), pathlib.Path(q)][0].read_text()"),
    "dict_selection": ("", "", "{'p': pathlib.Path(p)}['p'].read_text()"),
    "comprehension": ("", "    paths = [pathlib.Path(x) for x in (p, q)]\n", "paths[0].read_text()"),
    "comprehension_filter": ("", "", "''.join(x for x in p if pathlib.Path(q).read_text())"),
    "builtin_open": ("", "", "open(pathlib.Path(p)).read()"),
    "with_open": ("", "    with pathlib.Path(p).open() as stream:\n        flag = stream.read()\n", "flag"),
    "async_with": ("", "    async with pathlib.Path(p).open() as stream:\n        flag = stream.readline()\n", "flag"),
    "stream_iteration": ("", "    with open(p) as stream:\n        for flag in stream:\n            pass\n", "flag"),
    "stream_alias_iteration": ("", "    opener = open\n    for flag in opener(p):\n        pass\n", "flag"),
    "stream_lines": ("", "", "''.join(open(p).readlines())"),
    "wrapped_read": ("", "", "f'{pathlib.Path(p).read_text()}'.strip()"),
    "formatted_read": ("", "", "'{}'.format(pathlib.Path(p).read_text()).strip()"),
    "joined_read": ("", "", "''.join([pathlib.Path(p).read_text()]).strip()"),
    "capture_replace": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8').replace('# setup', 'pass')\n", "", "CODE"),
    "capture_strip": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\nFLAG = CODE.strip()\n", "", "FLAG"),
    "capture_slice": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n", "", "CODE[:2]"),
    "capture_concat": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n", "", "CODE + p"),
    "capture_alias": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n", "    alias = CODE\n", "alias.replace('# setup', p)"),
    "capture_iteration": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n", "    for flag in CODE:\n        pass\n", "flag"),
    "invalidated": ("", "    flag: str\n", "flag"),
}


@pytest.mark.parametrize("case", CONTENT_SOURCE_CASES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_content_sources_survive_wrappers_and_binding_targets(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "worker.py").write_text("# setup\npass\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    module, local, operand = CONTENT_SOURCE_CASES[case]
    definition = "async def" if case == "async_with" else "def"
    command = ("os.system('echo ' + " + operand + ")" if case in {"stream_alias_iteration", "comprehension_filter"} else
               "subprocess.run([sys.executable, " + operand + ", \"import os; os.system('id')\"])")
    source = ("import pathlib, subprocess, sys, os\n" + module + definition + " launch(p, q):\n" + local
              + "    " + command + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert "unreviewed selector site " + rel + ":launch" in selector_gate_errors(modules, ())
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("branch", ["assignments", "conditional"])
@pytest.mark.parametrize("template", ["'python3 -c %s'", "b'python3 -c %s'"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_mixed_template_alternatives_retain_selectors(tmp_path, branch, template, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    program = template + " % shlex.quote(P)"
    assignments = ("    command = " + program + "\n    command = 'echo ok'\n" if branch == "assignments"
                   else "    command = " + program + " if cond else 'echo ok'\n")
    source = ("import os, shlex\nP = \"import os; os.system('id')\"\ndef launch(cond):\n"
              + assignments + "    os.system(command)\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("expression", [
    "f'{shlex.quote(p)}'.strip()", "'{}'.format(shlex.quote(p)).strip()",
    "''.join([shlex.quote(p)]).strip()", "shlex.join([shlex.quote(p)])",
    "str(pathlib.PurePath(p))", "os.fspath(pathlib.Path(p))",
])
@pytest.mark.parametrize("content", [False, True])
def test_pure_transforms_keep_only_input_provenance(tmp_path, expression, content):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    argument = "pathlib.Path(p).read_text()" if content else "p"
    source = ("import os, shlex, pathlib\ndef launch(p):\n    os.system('echo ' + "
              + expression.replace("(p)", "(" + argument + ")") + ")\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if content:
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        assert selector_gate_errors(modules, ()) == []
        refuse_literal_spawns(modules[rel], rel, modules)
        assert literal_fixture_sites(tmp_path) == {"process:" + rel + ":launch:os.system": [3]}


@pytest.mark.parametrize("method", ["format", "join", "replace", "strip"])
def test_string_transform_names_do_not_exempt_module_functions(tmp_path, method):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    (core / "probe.py").write_text("import os, foreign\ndef launch(p):\n    tools = foreign\n"
        "    os.system('echo ' + tools." + method + "(p))\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + ": unresolved Python -c program"


POSITIONAL_SOURCE_CASES = {
    "capture_selector": ("FLAG = pathlib.Path(__file__).with_name('opts.py').read_text(encoding='utf-8')\n", "", "subprocess.run(['python3', FLAG, P])"),
    "capture_head": ("FLAG = pathlib.Path(__file__).with_name('interpreter.py').read_text(encoding='utf-8')\n", "", "subprocess.run([FLAG, '-c', P])"),
    "capture_boolean": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n", "", "subprocess.run(['python3', '-c', CODE or p])"),
    "capture_format": ("CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n", "", "subprocess.run(['python3', '-c', '%s' % CODE])"),
    "path_selector": ("", "", "subprocess.run(['python3', pathlib.Path(p).name, P])"),
    "parameter_selector": ("", "", "subprocess.run(['python3', p, P])"),
    "parameter_head": ("", "", "subprocess.run([p, '-c', P])"),
    "override_selector": ("", "", "subprocess.run(['worker', p, P], executable=sys.executable)"),
    "parameter_program": ("", "", "subprocess.run(['python3', '-c', p])"),
    "percent_width": ("", "", "subprocess.run(['python3', '-c', '%1048577s' % P])"),
    "format_width": ("", "", "subprocess.run(['python3', '-c', '{:1048577}'.format(P)])"),
    "nonstring_format": ("", "", "subprocess.run(['python3', '-c', '%s' % b\"import os; os.system('id')\"] )"),
    "missing_positional": ("", "", "subprocess.run(['python3', '-c', '{}'.format(code=P)])"),
    "keyword_as_index": ("", "", "subprocess.run(['python3', '-c', '{1}'.format('pass', code=P)])"),
    "attribute_splice": ("", "    plan = SimpleNamespace(argv=pathlib.Path(p).read_text().split())\n", "subprocess.run(['env', *(plan.argv if cond else [])])"),
    "add_splice": ("", "    parts = [pathlib.Path(p).read_text()] + tail\n", "subprocess.run(['env', *(parts if cond else ())])"),
    "comprehension_splice": ("", "    parts = [x for x in pathlib.Path(p).read_text().split()]\n", "subprocess.run(['env', *(parts if cond else [])])"),
    "alias_store": ("", "    argv = ['env', 'true']\n    alias = argv\n    alias[1] = pathlib.Path(p).read_text()\n", "subprocess.run(argv)"),
    "except_target": ("", "    cmd = 'echo ok'\n    try:\n        pass\n    except Exception as cmd:\n        pass\n", "os.system(cmd)"),
    "match_as": ("", "    cmd = 'echo ok'\n    match pathlib.Path(p).read_text():\n        case str() as cmd:\n            pass\n", "os.system(cmd)"),
    "match_star": ("", "    cmd = 'echo ok'\n    match list(pathlib.Path(p).read_text()):\n        case [*cmd]:\n            pass\n", "os.system(cmd)"),
    "match_mapping": ("", "    cmd = 'echo ok'\n    match {}:\n        case {**cmd}:\n            pass\n", "os.system(cmd)"),
    "path_name": ("", "", "os.system('echo ' + pathlib.Path(p).name)"),
    "path_readlink": ("", "", "os.system(str(pathlib.Path(p).readlink()))"),
    "path_resolve": ("", "", "os.system(str(pathlib.Path(p).resolve()))"),
    "path_glob": ("", "", "subprocess.run(['env', *(pathlib.Path(p).glob('*') if cond else [])])"),
    "path_iterdir": ("", "", "subprocess.run(['env', *(pathlib.Path(p).iterdir() if cond else [])])"),
    "path_walk": ("", "", "subprocess.run(['env', *(pathlib.Path(p).walk() if cond else [])])"),
    "path_division": ("", "", "os.system(str(pathlib.Path.cwd() / p))"),
    "path_subscript": ("", "    path = pathlib.Path(p)\n", "os.system(str(path[0]))"),
    "none_vector": ("", "    cmd = tuple([sys.executable, p, P]) if cond else ('echo', 'ok')\n", "subprocess.run(cmd)"),
    "none_shell": ("", "", "os.system('%s %s %s' % (sys.executable, p, shlex.quote(P)))"),
    "class_open": ("class Session:\n    CMD = next(open('cmd.txt'))\n    def open(self):\n        pass\n    subprocess.run(['env', CMD])\n", "", "os.system('echo')"),
    "overflow_splice": ("", "    parts = [pathlib.Path(p).read_text(), *('a' if cond else 'b'), *('a' if cond else 'b'), *('a' if cond else 'b'), *('a' if cond else 'b'), *('a' if cond else 'b'), *('a' if cond else 'b'), *('a' if cond else 'b')]\n", "subprocess.run(['env', *(parts if cond else [])])"),
}


@pytest.mark.parametrize("case", POSITIONAL_SOURCE_CASES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_positional_sources_and_untraced_values_fail_closed(tmp_path, case, entry):
    if case.startswith("match_") and not hasattr(ast, "Match"):
        pytest.skip("Pattern matching requires Python 3.10 or later")
    core = tmp_path / "aegis_core"
    core.mkdir()
    for name, text in (("opts.py", "-c"), ("interpreter.py", "python3"), ("worker.py", "pass\n")):
        (core / name).write_text(text, encoding="utf-8")
    rel = "aegis_core/probe.py"
    module, local, call = POSITIONAL_SOURCE_CASES[case]
    source = ("import os, sys, pathlib, shlex, subprocess\nfrom types import SimpleNamespace\n"
              "P = \"import os; os.system('id')\"\n" + module + "def launch(p, tail, cond):\n" + local
              + "    " + call + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            errors = selector_gate_errors(modules, ())
            assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == errors[0]
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("operand", ["'%s' % P", "'{}'.format(P)", "'{code}'.format(code=P)", "'{0}'.format(P)", "f'{P}'", "P + ''", "P"])
@pytest.mark.parametrize("head", ["'python3'", "sys.executable"])
def test_constant_program_transforms_are_resolved_and_inventoried(tmp_path, operand, head):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import sys, subprocess\nP = \"import os; os.system('id')\"\n"
              "subprocess.run([" + head + ", '-c', " + operand + "])\n")
    (core / "probe.py").write_text("import sys, subprocess\nsubprocess.run([sys.executable, '-c', "
                                   + repr(source) + "])\n", encoding="utf-8")
    table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("head", ["'python3'", "sys.executable"])
def test_unchanged_capture_is_known_only_in_program_position(tmp_path, head):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "worker.py").write_text("import subprocess\nsubprocess.run(['worker'])\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    (core / "probe.py").write_text("import sys, pathlib, subprocess\n"
        "CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n"
        "subprocess.run([" + head + ", '-c', CODE])\n", encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    refuse_literal_spawns(modules[rel], rel, modules)
    table = ((rel, "<module>", "resolved-python-program", "Review the unchanged captured module program."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sites == {"process:" + rel + ":<module>:subprocess.run": [3],
                     "process:aegis_core/worker.py:<module>:subprocess.run": [2]}


STICKY_ARGV_CASES = {
    wrapper + "_" + head_name + "_" + flag_name: (
        "FLAG = pathlib.Path(__file__).with_name('opts.py').read_text(encoding='utf-8')\n"
        if flag_name == "capture" else "",
        "",
        "subprocess.run([" + repr(wrapper) + ", " + head + ", " + flag + ", P])")
    for wrapper in ("env", "nice", "timeout", "stdbuf", "xargs", "launcher")
    for head_name, head in (("literal", "'python3'"), ("canonical", "sys.executable"))
    for flag_name, flag in (("parameter", "flag"), ("capture", "FLAG"))
}
STICKY_ARGV_CASES.update({
    "construction_" + name + "_" + head_name: ("", "    argv = " + expression.replace("HEAD", head) + "\n",
                                               "os.system(argv)" if name in {"percent", "f_string", "join"}
                                               else "subprocess.run(argv)")
    for head_name, head in (("literal", "'python3'"), ("canonical", "sys.executable"))
    for name, expression in (
        ("tuple", "tuple([HEAD, flag, P])"),
        ("list", "list((HEAD, flag, P))"),
        ("slice", "[HEAD, flag, P][:]"),
        ("add", "[HEAD] + [flag, P]"),
        ("percent", "'%s %s %s' % (HEAD, flag, shlex.quote(P))"),
        ("f_string", 'f"{HEAD} {flag} {shlex.quote(P)}"'),
        ("join", "' '.join([HEAD, flag, shlex.quote(P)])"))
})
STICKY_ARGV_CASES["capture_program_with_unknown_tail"] = (
    "CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n",
    "", "subprocess.run(['python3', '-c', CODE, flag])")


@pytest.mark.parametrize("case", STICKY_ARGV_CASES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_unresolved_argv_evidence_survives_heads_and_constructions(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "opts.py").write_text("-c", encoding="utf-8")
    (core / "worker.py").write_text("pass\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    module, local, call = STICKY_ARGV_CASES[case]
    source = ("import os, sys, pathlib, shlex, subprocess\n"
              "P = \"import os; os.system('id')\"\n" + module
              + "def launch(flag):\n" + local + "    " + call + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == "unreviewed selector site " + rel + ":launch"
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("call", [
    "os.system('echo ' + '{0.name}'.format(pathlib.Path(p)))",
    "os.system('echo ' + '{0[0]}'.format([pathlib.Path(p)]))",
    "subprocess.run(['echo', '{0.name}'.format(pathlib.Path(p))])",
    "subprocess.run(['echo', '{0[0]}'.format([pathlib.Path(p)])])",
    "subprocess.run([sys.executable, '-c', CODE if cond else 'pass'])",
    "subprocess.run([sys.executable, '-c', p if cond else 'pass'])",
], ids=["format_attribute_shell", "format_subscript_shell", "format_attribute_argv",
        "format_subscript_argv", "conditional_capture", "conditional_parameter"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_correctness_0748_formats_and_conditional_programs_refuse(tmp_path, call, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "worker.py").write_text("pass\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    source = ("import os, sys, pathlib, subprocess\n"
              "CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n"
              "def launch(p, cond):\n    " + call + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=())
            assert str(error.value) == "unreviewed selector site " + rel + ":launch"
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("expression", [
    "['python3', '-m', module]",
    "['python3', '-m', 'aegis_core.absent']",
    "['env', 'python3', '-m', module]",
    "tuple(['python3', '-m', module])",
], ids=["parameter", "missing_module", "wrapper", "construction"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_unresolved_module_launches_use_module_refusals(tmp_path, expression, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = "import subprocess\ndef launch(module):\n    subprocess.run(" + expression + ")\n"
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        if expression == "['python3', '-m', module]":
            # ROUND-17c: retain this scenario as an accepted module-operand control.
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2
            return
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python module"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
        else:
            if expression == "['python3', '-m', module]":
                refuse_literal_spawns(modules[rel], rel, modules)
                assert literal_fixture_sites(tmp_path) == {"process:" + rel + ":launch:subprocess.run": [3]}
                return
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python module"


@pytest.mark.parametrize("call", [
    "subprocess.run([sys.executable, '-m', module])",
    "subprocess.run(['python3', '-m', module])",
    "subprocess.run([sys.executable, '-I', '-m', module])",
    "subprocess.run([sys.executable, '-Im', module])",
    "subprocess.run([sys.executable, '-m', CODE])",
    "subprocess.run([sys.executable, '-m', pathlib.Path(module).read_text()])",
    "subprocess.run(['display', '-m', module], executable=sys.executable)",
    "subprocess.run([sys.executable, '-m', module], executable=None)",
], ids=["canonical", "literal", "options", "bundled", "capture", "content", "override", "none_override"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_module_operand_positions_accept_unknown_names(tmp_path, call, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "worker.py").write_text("import subprocess\nsubprocess.run(['worker'])\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    source = ("import sys, pathlib, subprocess\n"
              "CODE = pathlib.Path(__file__).with_name('worker.py').read_text(encoding='utf-8')\n"
              "def launch(module):\n    " + call + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 3
        assert sum(len(lines) for key, lines in sites.items() if key.startswith(
            "process:aegis_core/worker.py:")) == 1
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
            table = ((rel, "launch", "resolved-python-program", "Review the test-owned module launch."),)
            assert selector_gate_errors(modules, table) == []
            sites = process_sites(tmp_path, selector_table=table)
        else:
            refuse_literal_spawns(modules[rel], rel, modules)
            sites = literal_fixture_sites(tmp_path)
        assert sites == {"process:" + rel + ":launch:subprocess.run": [4],
                         "process:aegis_core/worker.py:<module>:subprocess.run": [2]}


@pytest.mark.parametrize("call,message", [
    ("subprocess.run([sys.executable, flag, CODE])", "unresolved Python -c program"),
    ("subprocess.run([sys.executable, '-W', '-m', flag, CODE])", "unresolved Python module"),
], ids=["selector_parameter", "module_text_is_option_data"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_module_operand_waiver_never_covers_selector_parameters(tmp_path, call, message, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import sys, subprocess\nCODE = 'pass'\ndef launch(flag):\n    " + call + "\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": " + message
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": " + message


@pytest.mark.parametrize("case", ["env_capture", "class_later_binding", "nested_class_later_binding",
                                  "conditional_splice", "comprehension_filter"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_argon_0748_selector_sources_keep_uncertainty(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "opts.py").write_text("-c", encoding="utf-8")
    rel = "aegis_core/probe.py"
    prefix = ("import sys, pathlib, subprocess\nP = \"import os; os.system('id')\"\n"
              "FLAG = pathlib.Path(__file__).with_name('opts.py').read_text(encoding='utf-8')\n")
    bodies = {
        "env_capture": ("def launch():\n    subprocess.run(['env', sys.executable, FLAG, P])\n", "launch"),
        "class_later_binding": ("class Spec:\n    subprocess.run([sys.executable, FLAG, P])\n    FLAG = '-I'\n", "Spec"),
        "nested_class_later_binding": ("def launch():\n    class Spec:\n        subprocess.run([sys.executable, FLAG, P])\n        FLAG = '-I'\n", "launch.Spec"),
        "conditional_splice": ("def launch(path):\n    subprocess.run(['env', *([] if pathlib.Path(path).read_text() else [])])\n", "launch"),
        "comprehension_filter": ("def launch(path, items):\n    subprocess.run(['env', *[item for item in items if pathlib.Path(path).read_text()]])\n", "launch"),
    }
    body, scope = bodies[case]
    source = prefix + body
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":" + scope]
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_class_binding_before_the_launch_shadows_enclosing_capture(tmp_path, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "opts.py").write_text("-c", encoding="utf-8")
    rel = "aegis_core/probe.py"
    source = ("import sys, pathlib, subprocess\nP = 'pass'\n"
              "FLAG = pathlib.Path(__file__).with_name('opts.py').read_text(encoding='utf-8')\n"
              "class Spec:\n    FLAG = '-I'\n    subprocess.run([sys.executable, FLAG, P])\n")
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == []
        else:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert process_sites(tmp_path) == {"process:" + rel + ":Spec:subprocess.run": [6]}


@pytest.mark.parametrize("body", [
    "subprocess.run([sys.executable, '-c', '' + ('%s' % P)])",
    "subprocess.run([sys.executable, '-c', ('%s' % P) + ''])",
    "subprocess.run([sys.executable, '-c', f\"{'%s' % P}\"])",
    "subprocess.run([sys.executable, '-c', '{}'.format('%s' % P)])",
    "subprocess.run([sys.executable, '-c' + ('%s' % P)])",
    "ARGV = [sys.executable, '-c', '' + ('%s' % P)]\nsubprocess.run(ARGV)",
    "subprocess.run([sys.executable, f\"-c{'%s' % P}\"])",
], ids=["left_concat", "right_concat", "f_string", "format", "attached", "stored_argv", "attached_f_string"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_argon_0748_constant_program_wrappers_resolve_and_count_once(tmp_path, body, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import sys, subprocess\nP = \"import os; os.system('id')\"\ndef launch():\n"
              + "".join("    " + line + "\n" for line in body.splitlines()))
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
            table = ((rel, "launch", "resolved-python-program", "Review the test-owned resolved program."),)
            sites = process_sites(tmp_path, selector_table=table)
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": process spawn inside a literal -c program"
            return
    stored_argv = body == ("ARGV = [sys.executable, '-c', '' + ('%s' % P)]\n"
                           "subprocess.run(ARGV)")
    # ROUND-3 default-deny retains the stored argv construction and launch.
    expected_count = 2 if stored_argv else 1
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == expected_count


TOTALITY_REFUSAL_CASES = {
    "conditional_class": "class Spec:\n    if sys.platform == 'win32':\n        FLAG = '-I'\n    subprocess.run([sys.executable, FLAG, P])\n",
    "class_loop": "class Spec:\n    for item in range(2):\n        subprocess.run([sys.executable, FLAG, P])\n        FLAG = PROGRAM_FLAG\n",
    "class_try": "class Spec:\n    try:\n        unknown()\n        FLAG = '-I'\n    except Exception:\n        pass\n    subprocess.run([sys.executable, FLAG, P])\n",
    "class_with": "class Spec:\n    with context() as FLAG:\n        pass\n    subprocess.run([sys.executable, FLAG, P])\n",
    "class_before_binding": "class Spec:\n    subprocess.run([sys.executable, FLAG, P])\n    FLAG = PROGRAM_FLAG\n",
    "reexport_program": "from .middle import CODE\ndef launch():\n    subprocess.run([sys.executable, '-c', '%s' % CODE])\n",
    "quote_percent": "def launch():\n    subprocess.run([sys.executable, '-c', '%s' % shlex.quote(P)])\n",
    "quote_format": "def launch():\n    subprocess.run([sys.executable, '-c', '{}'.format(shlex.quote(P))])\n",
    "shell_parameter": "def launch(flag, mode):\n    subprocess.run(['worker', flag, P], executable=sys.executable, shell=mode)\nlaunch('-c', False)\n",
    "shell_resolved_text": "def launch(mode):\n    subprocess.run('python3 -c ' + shlex.quote(P), shell=mode)\nlaunch(True)\n",
}


@pytest.mark.parametrize("case", TOTALITY_REFUSAL_CASES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_totality_requires_a_verdict_for_every_unresolved_launch(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "opts.py").write_text("-c", encoding="utf-8")
    (core / "provider.py").write_text("CODE = \"import os; os.system('id')\"\n", encoding="utf-8")
    (core / "middle.py").write_text("from .provider import CODE\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    flags = ("FLAG = '-I'\nPROGRAM_FLAG" if case in {"class_loop", "class_before_binding"} else "FLAG")
    source = ("import sys, pathlib, subprocess, shlex\nP = \"import os; os.system('id')\"\n"
              + flags + " = pathlib.Path(__file__).with_name('opts.py').read_text(encoding='utf-8')\n"
              + TOTALITY_REFUSAL_CASES[case])
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            errors = selector_gate_errors(modules, ())
            assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


def test_spawn_totality_assigns_exactly_one_verdict_per_call():
    rel = "aegis_core/probe.py"
    modules = {rel: ast.parse("import sys, subprocess\n"
        "subprocess.run(['echo', 'safe'])\n"
        "def opaque(command):\n    subprocess.run(command)\n"
        "def module_launch(name):\n    subprocess.run([sys.executable, '-m', name])\n")}
    verdicts = spawn_totality(modules, ())
    assert [(item.scope, item.verdict) for item in verdicts] == [
        ("<module>", "inventoried"), ("opaque", "inventoried"), ("module_launch", "inventoried")]
    assert len({id(item.node) for item in verdicts}) == 3
    rows = ((rel, "opaque", "reviewed-dynamic", "Review the test-owned opaque command."),)
    reviewed = spawn_totality(modules, rows)
    assert [(item.scope, item.verdict) for item in reviewed] == [
        ("<module>", "inventoried"), ("opaque", "reviewed"), ("module_launch", "inventoried")]


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
@pytest.mark.parametrize("consumed", [False, True])
def test_totality_judges_unknown_argv_only_at_actual_spawn(tmp_path, entry, consumed):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess, sys\n"
              "def candidate(option):\n"
              "    words = [sys.executable, option, 'print(1)']\n"
              + ("    subprocess.run(words)\n" if consumed else "    return words\n"))
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        if consumed:
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=table)
            assert str(error.value) == rel + ": unresolved Python -c program"
        else:
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 1
        return
    path.write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        expected = ["unreviewed selector site " + rel + ":candidate"] if consumed else []
        assert selector_gate_errors(modules, ()) == expected
    elif consumed:
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        refuse_literal_spawns(modules[rel], rel, modules)


@pytest.mark.parametrize("rel, scope", [
    ("aegis_core/ast/runner.py", "_run_driver"),
    ("aegis_cli/doctor.py", "_run_host_cli"),
    ("aegis_cli/hooks/registrar.py", "_probe"),
    ("aegis_cli/install_hosts.py", "_run_cli"),
])
def test_totality_launch_wrappers_have_reviewed_program_sources(rel, scope):
    modules = {rel: ast.parse((REPO / rel).read_text(encoding="utf-8"))}
    verdicts = spawn_totality(modules, SELECTOR_SITE_TABLE)
    assert [(item.scope, item.verdict) for item in verdicts if item.rel == rel and item.scope == scope] == [
        (scope, "reviewed")]


ROUND19_UNRESOLVED_CALLS = {
    "positional_shell": "def launch(mode):\n    subprocess.Popen('python3 -c ' + shlex.quote(P), -1, None, None, None, None, None, True, mode)\nlaunch(True)\n",
    "returned_argv": "def build(flag):\n    return [sys.executable, flag, P]\ndef launch(flag):\n    subprocess.run(build(flag))\nlaunch('-c')\n",
    "expanded_options": "def launch(command, options):\n    subprocess.run(command, **options)\nlaunch('python3 -c ' + shlex.quote(P), {'shell': True})\n",
    "direct_builder": "def build(flag):\n    return [sys.executable, flag, P]\nsubprocess.run(build('-c'))\n",
    "parameter": "def launch(command):\n    subprocess.run(command)\n",
    "subscript": "def launch(commands):\n    subprocess.run(commands[0])\n",
    "attribute": "def launch(config):\n    subprocess.run(config.command)\n",
    "conditional": "def launch(first, second, choice):\n    subprocess.run(first if choice else second)\n",
    "star_args": "def launch(args):\n    subprocess.run(*args)\n",
    "positional_executable": "def launch(executable):\n    subprocess.Popen(['worker'], -1, executable)\n",
}


@pytest.mark.parametrize("case", ROUND19_UNRESOLVED_CALLS)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round19_rejected_layouts_and_whole_commands_refuse(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess, sys, shlex\nP = \"import os; os.system('id')\"\n"
              + ROUND19_UNRESOLVED_CALLS[case])
    path = core / "probe.py"
    if case in {"parameter", "subscript", "attribute", "conditional", "positional_executable", "expanded_options"}:
        if entry == "inventory":
            path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                            encoding="utf-8")
            table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith((":subprocess.run", ":subprocess.Popen"))) == 2
            return
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            # Positional executable/expanded-call syntax retain their structural review rules.
            errors = selector_gate_errors(modules, ())
            if case in {"positional_executable", "expanded_options"}:
                assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
            else:
                assert errors == []
        else:
            refuse_literal_spawns(modules[rel], rel, modules)
        return
    if entry == "inventory":
        unreviewed = {rel: ast.parse(source)}
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(unreviewed[rel], rel, unreviewed)
        assert str(error.value) == rel + ": unresolved Python -c program"
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            errors = selector_gate_errors(modules, ())
            assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            assert str(error.value) == rel + ": unresolved Python -c program"


ARGON1322_CASES = {
    "posix_path": "def launch(flag):\n    os.posix_spawn(path=sys.executable, argv=['worker', flag, P], env={})\nlaunch('-c')\n",
    "exec_file": "def launch(flag):\n    os.execvp(file=sys.executable, args=['worker', flag, P])\nlaunch('-c')\n",
    "partial_argv": "def launch(exe, flag):\n    subprocess.run([exe, flag, P])\n",
    "empty_import_branch": "if sys.platform == 'win32':\n    from .safe import FLAG\nelse:\n    from .provider import FLAG\nsubprocess.run([sys.executable, FLAG, P])\n",
    "bad_python": "subprocess.run([sys.executable, '-c', 'def broken('])\n",
    "shell_program": "subprocess.run(['env', 'sh', '-c', 'python3 -c ' + shlex.quote(P)])\n",
}


@pytest.mark.parametrize("case", ARGON1322_CASES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_argon1322_preserves_unknown_branches_and_source_language(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "safe.py").write_text("FLAG = '-I'\n", encoding="utf-8")
    (core / "provider.py").write_text("import sys\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    source = ("import os, subprocess, sys, shlex\nP = \"import os; os.system('id')\"\n"
              + ARGON1322_CASES[case])
    path = core / "probe.py"
    if entry == "inventory":
        path.write_text("import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n",
                        encoding="utf-8")
        table = ((rel, "<module>", "resolved-python-program", "Review the test-owned outer literal."),)
        if case == "shell_program":
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
        elif case == "bad_python":
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2
        else:
            unreviewed = dict(module_trees(tmp_path))
            unreviewed[rel] = ast.parse(source)
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(unreviewed[rel], rel, unreviewed)
            assert str(error.value) == rel + ": unresolved Python -c program"
            with pytest.raises(ValueError) as error:
                process_sites(tmp_path, selector_table=table)
            assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        path.write_text(source, encoding="utf-8")
        modules = dict(module_trees(tmp_path))
        if entry == "selector":
            errors = selector_gate_errors(modules, ())
            assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
        elif case == "bad_python":
            refuse_literal_spawns(modules[rel], rel, modules)
        else:
            with pytest.raises(ValueError) as error:
                refuse_literal_spawns(modules[rel], rel, modules)
            message = ("process spawn inside a literal -c program" if case == "shell_program"
                       else "unresolved Python -c program")
            assert str(error.value) == rel + ": " + message


@pytest.mark.parametrize("python", [False, True])
@pytest.mark.parametrize("route", ["direct", "alias", "nested"])
def test_round19b_called_return_evidence_controls_unknown_launches(tmp_path, python, route):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    head = "sys.executable" if python else "'echo'"
    source = "import subprocess, sys\ndef build(flag):\n    return [" + head + ", flag, 'pass']\n"
    if route == "alias":
        source += "runner = build\n"
        call = "runner(flag)"
    elif route == "nested":
        source += "def wrapper(flag):\n    return build(flag)\n"
        call = "wrapper(flag)"
    else:
        call = "build(flag)"
    source += "def launch(flag):\n    subprocess.run(" + call + ")\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if python:
        assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        assert selector_gate_errors(modules, ()) == []
        refuse_literal_spawns(modules[rel], rel, modules)
        assert process_sites(tmp_path) == {"process:" + rel + ":launch:subprocess.run": [len(source.splitlines())]}


@pytest.mark.parametrize("program", ["def broken(", "\x00", "\ud800"])
def test_round21_invalid_constants_have_zero_child_spawns(tmp_path, program):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(program) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    table = ((rel, "<module>", "resolved-python-program", "Review the test-owned invalid Python literal."),)
    refuse_literal_spawns(modules[rel], rel, modules)
    assert process_sites(tmp_path, selector_table=table) == {"process:" + rel + ":<module>:subprocess.run": [2]}


@pytest.mark.parametrize("head", ["'git'", "head"])
def test_round20_literal_spawn_programs_refuse_under_any_head(tmp_path, head):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess\ndef launch(head):\n    subprocess.run([" + head
              + ", '-c', \"import os; os.system('id')\"])\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    table = ((rel, "launch", "reviewed-dynamic", "Review the test-owned unresolved executable."),)
    modules = dict(module_trees(tmp_path))
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + (": process spawn inside a literal -c program"
                                     if head == "'git'" else ": unresolved Python -c program")
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1
    assert sites["process:" + rel + ":launch:subprocess.run"] == [3]


@pytest.mark.parametrize("case", ["reviewed_child", "unreviewed_sibling", "escape"])
def test_round21_parent_review_does_not_authorize_unknown_children(tmp_path, case):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    child = ("import subprocess, sys\ndef child(flag):\n"
             "    subprocess.run([sys.executable, flag, 'pass'])\nchild('-I')\n")
    if case == "escape":
        child = "import subprocess as backend\ncallback = backend.run\n"
    source = "import subprocess, sys\ndef reviewed():\n    subprocess.run([sys.executable, '-c', " + repr(child) + "])\n"
    if case == "unreviewed_sibling":
        source += "def sibling(flag):\n    subprocess.run([sys.executable, flag, 'pass'])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    table = ((rel, "reviewed", "resolved-python-program", "Review only this outer literal site."),)
    with pytest.raises(ValueError) as error:
        process_sites(tmp_path, selector_table=table)
    expected = ("unreviewed selector site " + rel + ":sibling" if case == "unreviewed_sibling"
                else rel + ": process spawn inside a literal -c program" if case == "escape"
                else rel + ": unresolved Python -c program")
    assert str(error.value) == expected


@pytest.mark.parametrize("mapping, argv, refuses", [
    ("options", "['worker']", False),
    ("{'executable': sys.executable}", "['worker', flag, 'pass']", True),
    ("{'shell': True, 'executable': sys.executable}", "'import os; os.system(\\'id\\')'", True),
])
def test_round20_expanded_mapping_evidence_uses_explicit_keys(tmp_path, mapping, argv, refuses):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess, sys\ndef launch(flag, options):\n    subprocess.run(" + argv
              + ", **" + mapping + ")\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if refuses:
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + (": process spawn inside a literal -c program"
                                         if "shell" in mapping else ": unresolved Python -c program")
    else:
        refuse_literal_spawns(modules[rel], rel, modules)
        table = ((rel, "launch", "reviewed-dynamic", "Review the expanded mapping syntax without program evidence."),)
        assert process_sites(tmp_path, selector_table=table) == {"process:" + rel + ":launch:subprocess.run": [3]}


ROUND22_CALLABLES = {
    "conditional_alias": "build = python_argv if use_python else native_argv\n    subprocess.run(build(flag))",
    "conditional_callee": "subprocess.run((python_argv if use_python else native_argv)(flag))",
    "bool_or": "build = python_argv or native_argv\n    subprocess.run(build(flag))",
    "bool_and": "build = use_python and python_argv\n    subprocess.run(build(flag))",
    "list_subscript": "build = [native_argv, python_argv][use_python]\n    subprocess.run(build(flag))",
    "tuple_subscript": "subprocess.run((native_argv, python_argv)[use_python](flag))",
    "dict_subscript": "builders = {'native': native_argv, 'python': python_argv}\n    subprocess.run(builders[use_python](flag))",
    "unknown_candidate": "build = native_argv if use_python else unknown\n    subprocess.run(build(flag))",
    "unknown_container": "subprocess.run(unknown[use_python](flag))",
    "unsupported_candidate": "build = native_argv if use_python else choose(flag)\n    subprocess.run(build(flag))",
    "unsupported_method": "build = unknown.format if use_python else native_argv\n    subprocess.run(build(flag))",
}


@pytest.mark.parametrize("case", [*ROUND22_CALLABLES, "method", "default"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round22_callable_selection_preserves_return_evidence(tmp_path, case, entry):
    source = "import subprocess, sys\nP = \"import os; os.system('id')\"\n"
    if case == "method":
        source += ("class Builder:\n    def argv(self, flag):\n        return [sys.executable, flag, P]\n"
                   "    def launch(self, flag):\n        subprocess.run(self.argv(flag))\n")
    elif case == "default":
        source += ("def build(flag, exe=sys.executable):\n    return [exe, flag, P]\n"
                   "def launch(flag):\n    subprocess.run(build(flag))\n")
    else:
        source += ("def python_argv(flag):\n    return [sys.executable, flag, P]\n"
                   "def native_argv(flag):\n    return ['echo', flag]\n"
                   "def launch(flag, use_python, unknown):\n    " + ROUND22_CALLABLES[case] + "\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        errors = selector_gate_errors(modules, ())
        assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the test-owned outer literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("selection", [
    "first if enabled else second", "first or second", "[first, second][enabled]",
    "{'first': first, 'second': second}[enabled]",
])
def test_round22_native_callable_candidates_keep_no_program(tmp_path, selection):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess\ndef first(flag):\n    return ['echo', flag]\n"
              "def second(flag):\n    return ['git', flag]\n"
              "def launch(flag, enabled):\n    build = " + selection + "\n    subprocess.run(build(flag))\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    # ROUND-29: conditional and container selections are outside the closed allowlist.
    assert selector_gate_errors(modules, ()) == ["unreviewed selector site " + rel + ":launch"]
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + ": unresolved Python -c program"


ROUND22_KEYWORDS = {
    "executable": "subprocess.run(['worker', flag, P], **{**{'executable': sys.executable}})",
    "args": "subprocess.run(**{**{'args': [sys.executable, flag, P]}})",
    "shell": "subprocess.run(flag, **{**{'shell': True, 'executable': sys.executable}})",
    "path": "os.posix_spawn(**{**{'path': sys.executable, 'argv': ['worker', flag, P], 'env': {}}})",
    "file": "os.execvp(**{**{'file': sys.executable, 'args': ['worker', flag, P]}})",
    "deep": "subprocess.run(['worker', flag, P], **{**{**{'executable': sys.executable}}})",
    "mixed_unknown": "subprocess.run(['worker', flag, P], **{**options, **{'executable': sys.executable}})",
    "dict_override": "subprocess.run(['worker', flag, P], **{'executable': 'worker', **{'executable': sys.executable}})",
}


@pytest.mark.parametrize("case", ROUND22_KEYWORDS)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round22_nested_literal_keywords_retain_launch_evidence(tmp_path, case, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import os, subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def launch(flag, options):\n    " + ROUND22_KEYWORDS[case] + "\n")
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        errors = selector_gate_errors(modules, ())
        assert errors and all(message.startswith("unreviewed selector site " + rel + ":") for message in errors)
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the test-owned outer literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("case", ["dict_depth", "dict_words", "callable_depth", "callable_choices", "callable_cycle"])
def test_round22_collector_limits_refuse_without_raw_exceptions(tmp_path, case):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = "import subprocess\n"
    if case.startswith("dict_"):
        if case == "dict_depth":
            mapping = "{'executable': 'worker'}"
            for _ in range(_MAX_DEPTH + 1):
                mapping = "{**" + mapping + "}"
        else:
            mapping = "{" + ",".join(repr(str(i)) + ": 'worker'" for i in range(_MAX_WORDS + 1)) + "}"
        source += "subprocess.run(['worker'], **" + mapping + ")\n"
    else:
        source += "def native(flag):\n    return ['echo', flag]\n"
        if case == "callable_depth":
            source += "a0 = native\n"
            source += "".join("a" + str(i + 1) + " = a" + str(i) + "\n" for i in range(_MAX_DEPTH + 1))
            function = "a" + str(_MAX_DEPTH + 1)
        elif case == "callable_choices":
            function = "[" + ",".join(["native"] * (_MAX_CHOICES + 1)) + "][flag]"
        else:
            source += "first = second\nsecond = first\n"
            function = "first"
        source += "def launch(flag):\n    subprocess.run((" + function + ")(flag))\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, ())
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("mapping", [
    "{**{'args': [sys.executable, '-c', P]}}",
    "{**{'executable': sys.executable, 'args': ['worker', '-c', P]}}",
])
def test_round22_resolved_nested_keywords_inventory_the_program(tmp_path, mapping):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "subprocess.run(**" + mapping + ")\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    table = ((rel, "<module>", "resolved-python-program", "Review the test-owned resolved nested mapping."),)
    modules = dict(module_trees(tmp_path))
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + ": process spawn inside a literal -c program"
    sites = process_sites(tmp_path, selector_table=table)
    # The nested args list is a module construction as well as the launch.
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 2


@pytest.mark.parametrize("mapping", [
    "{**options}", "{'executable': sys.executable, **{'executable': 'worker'}}",
])
def test_round22_nested_native_and_unknown_mappings_keep_no_program(tmp_path, mapping):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess, sys\ndef launch(options):\n"
              "    subprocess.run(['worker'], **" + mapping + ")\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    refuse_literal_spawns(modules[rel], rel, modules)
    table = ((rel, "launch", "reviewed-dynamic", "Review expanded kwargs without interpreter evidence."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 1


@pytest.mark.parametrize("call", [
    "os.execvp(file=exe, args=[sys.executable, flag, P])",
    "os.execv(path=exe, argv=[sys.executable, flag, P])",
    "os.execvpe(file=exe, args=[sys.executable, flag, P], env={})",
    "os.spawnv(mode=0, path=exe, args=[sys.executable, flag, P])",
    "os.spawnvp(mode=0, file=exe, args=[sys.executable, flag, P])",
    "os.posix_spawn(path=exe, argv=[sys.executable, flag, P], env={})",
    "os.execl(file=exe, args=[sys.executable, flag, P])",
    "os.execl(file=exe, args=[sys.executable, flag, P], **options)",
    "subprocess.Popen(args=[sys.executable, flag, P], executable=exe)",
    "subprocess.run(P, shell=True, executable=exe)",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round22_argon_keyword_arguments_preserve_program_evidence(tmp_path, call, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import os, subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def launch(exe, flag, options):\n    " + call + "\n")
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("receiver", ["self", "cls"])
@pytest.mark.parametrize("python", [False, True])
@pytest.mark.parametrize("method", ["build", "format"])
def test_round22_argon_methods_enumerate_return_evidence(tmp_path, receiver, python, method):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    decorator = "    @classmethod\n" if receiver == "cls" else ""
    head = "sys.executable" if python else "'echo'"
    source = ("import subprocess, sys\nclass Runner:\n" + decorator + "    def " + method + "(" + receiver
              + ", flag):\n        return [" + head + ", flag, 'pass']\n" + decorator
              + "    def launch(" + receiver + ", flag):\n        subprocess.run(" + receiver + "." + method + "(flag))\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if python:
        assert selector_gate_errors(modules, ())
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        assert selector_gate_errors(modules, ()) == []
        refuse_literal_spawns(modules[rel], rel, modules)
        assert sum(len(lines) for key, lines in process_sites(tmp_path).items() if key.endswith(":subprocess.run")) == 1


@pytest.mark.parametrize("prefix", [
    "'env',", "'nice','-n','2',", "'timeout','5',", "'stdbuf','-oL',", "'xargs','-n','1',",
    "'env','nice','-n','2','timeout','5',",
])
@pytest.mark.parametrize("head", ["sh", "python3"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round22_argon_wrappers_inventory_nested_programs(tmp_path, prefix, head, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = "import subprocess, sys, shlex\nP = \"import os; os.system('id')\"\n"
    command = "'python3 -c ' + shlex.quote(P)" if head == "sh" else "P"
    flag = "-ec" if head == "sh" else "-c"
    source += "subprocess.run([" + prefix + repr(head) + "," + repr(flag) + "," + command + "])\n"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    elif entry == "refusal":
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + ": process spawn inside a literal -c program"
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


@pytest.mark.parametrize("program", ["\"python3 -c '\"", "program"])
def test_round22_argon_uncertain_wrapped_shell_source_refuses(tmp_path, program):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess\ndef launch(program):\n"
              "    subprocess.run(['env', 'sh', '-ec', " + program + "])\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    assert selector_gate_errors(modules, ())
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("head", ["sh", "python3"])
def test_round22_argon_wrapper_tails_preserve_resolved_program(tmp_path, head):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    command = "'python3 -c ' + shlex.quote(P)" if head == "sh" else "P"
    flag = "-ec" if head == "sh" else "-c"
    source = ("import subprocess, shlex\nP = \"import os; os.system('id')\"\n"
              "def launch(args):\n    subprocess.run(['env'," + repr(head) + "," + repr(flag) + ","
              + command + ",*args])\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    table = ((rel, "launch", "reviewed-dynamic", "Review only the dynamic argv after the resolved test program."),)
    sites = process_sites(tmp_path, selector_table=table)
    assert sum(len(lines) for key, lines in sites.items() if key.endswith(":os.system")) == 1


ROUND23_EVIDENCE_CASES = {
    "factory": "def choose(enabled):\n    return python_argv if enabled else native_argv\ndef launch(enabled, flag):\n    subprocess.run(choose(enabled)(flag))\n",
    "factory_alias": "def choose(enabled):\n    return python_argv if enabled else native_argv\ndef launch(enabled, flag):\n    build = choose(enabled)\n    subprocess.run(build(flag))\n",
    "default": "def launch(flag, build=python_argv):\n    subprocess.run(build(flag))\n",
    "keyword_default": "def launch(flag, *, build=python_argv):\n    subprocess.run(build(flag))\n",
    "default_alias": "def launch(flag, build=python_argv):\n    callback = build\n    subprocess.run(callback(flag))\n",
    "parameter": "def launch(command):\n    subprocess.run(command)\n",
    "attribute": "def launch(config):\n    subprocess.run(config.command)\n",
    "comprehension": "def launch(commands):\n    subprocess.run([item for item in commands])\n",
}


@pytest.mark.parametrize("case", ROUND23_EVIDENCE_CASES)
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round23_unproven_evidence_defaults_to_unknown(tmp_path, case, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def python_argv(flag):\n    return [sys.executable, flag, P]\n"
              "def native_argv(flag):\n    return ['echo', flag]\n" + ROUND23_EVIDENCE_CASES[case])
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if case in {"parameter", "attribute", "comprehension"}:
        # ROUND-23b withdraws blanket UNKNOWN; retain the existing NoProgram controls.
        if entry == "selector":
            assert selector_gate_errors(modules, ()) == []
        elif entry == "refusal":
            refuse_literal_spawns(modules[rel], rel, modules)
        else:
            table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
            sites = process_sites(tmp_path, selector_table=table)
            assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2
        return
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("method", ["format", "join", "replace", "split"])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round23_method_names_never_prove_transforms(tmp_path, method, alias, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "class Builder:\n    def " + method + "(self, flag):\n        return [sys.executable, flag, P]\n")
    if alias:
        source += "    def launch(self, flag):\n        receiver = self\n        subprocess.run(receiver." + method + "(flag))\n"
    else:
        source += "def launch(builder, flag):\n    subprocess.run(builder." + method + "(flag))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("call", [
    "subprocess.run(['xargs', '-I{}', sys.executable, '-c', '{}'], input=shlex.quote(P)+'\\n', text=True)",
    "subprocess.run(['xargs', '-I', '{}', sys.executable, '-c', '{}'])",
    "subprocess.run(['xargs', '-i', sys.executable, '-c', '{}'])",
    "subprocess.run(['xargs', '--replace={}', sys.executable, '-c', '{}'])",
    "subprocess.run(['env', '-S', 'python3 -c {}'])",
    "subprocess.run(['env', '--split-string=python3 -c {}'])",
    "subprocess.run(['display', 'sh', '-ec', 'python3 -c '+shlex.quote(P)], executable='/usr/bin/env')",
    "os.execv('/usr/bin/env', ['display', 'sh', '-ec', 'python3 -c '+shlex.quote(P)])",
    "os.spawnv(0, '/usr/bin/env', ['display', 'sh', '-ec', 'python3 -c '+shlex.quote(P)])",
    "subprocess.run(['env', '--future-option', 'python3', '-c', '{}'])",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round23_wrapper_options_and_overrides_are_unknown(tmp_path, call, entry):
    source = "import os, subprocess, sys, shlex\nP = \"import os; os.system('id')\"\n" + call + "\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("route", ["direct", "alias", "default", "keyword_default", "default_alias", "lambda_default"])
@pytest.mark.parametrize("python", [False, True])
def test_round23b_factory_and_default_candidates_keep_return_evidence(tmp_path, route, python):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    head = "sys.executable" if python else "'echo'"
    source = ("import subprocess, sys\ndef build(flag):\n    return [" + head + ", flag, 'pass']\n"
              "def choose(enabled):\n    return build if enabled else build\n")
    if route == "direct":
        source += "def launch(enabled, flag):\n    subprocess.run(choose(enabled)(flag))\n"
    elif route == "alias":
        source += "def launch(enabled, flag):\n    callback = choose(enabled)\n    subprocess.run(callback(flag))\n"
    elif route == "lambda_default":
        source += "launch = lambda flag, callback=build: subprocess.run(callback(flag))\n"
    else:
        signature = "flag, *, callback=build" if route == "keyword_default" else "flag, callback=build"
        source += "def launch(" + signature + "):\n"
        source += ("    alias = callback\n    subprocess.run(alias(flag))\n" if route == "default_alias"
                   else "    subprocess.run(callback(flag))\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    # ROUND-27b covers parameters; ROUND-29 also makes generic factory selections UNKNOWN.
    assert selector_gate_errors(modules, ())
    with pytest.raises(ValueError) as error:
        refuse_literal_spawns(modules[rel], rel, modules)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("api,key", [
    ("os.system", "command"), ("os.popen", "cmd"),
    ("subprocess.getoutput", "cmd"), ("subprocess.getstatusoutput", "cmd"),
])
@pytest.mark.parametrize("bound", ["depth", "words"])
@pytest.mark.parametrize("entry", ["refusal", "inventory", "literal_inventory"])
def test_round24_keyword_expansion_bounds_refuse(tmp_path, api, key, bound, entry):
    mapping = "{" + repr(key) + ": 'python3 -c ' + shlex.quote(P)}"
    if bound == "depth":
        mapping = "{**" * (_MAX_DEPTH + 1) + mapping + "}" * (_MAX_DEPTH + 1)
    else:
        mapping = "{" + ",".join(repr("padding" + str(index)) + ": 0" for index in range(_MAX_WORDS)) + ",**" + mapping + "}"
    source = "import os, subprocess, shlex\nP = \"import os; os.system('id')\"\n" + api + "(**" + mapping + ")\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry != "refusal":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    with pytest.raises(ValueError) as error:
        if entry == "refusal":
            refuse_literal_spawns(modules[rel], rel, modules)
        elif entry == "inventory":
            table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
            process_sites(tmp_path, selector_table=table)
        else:
            table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
            literal_process_sites(rel, modules[rel], CommandResolver(modules), selector_table=table)
    expected = ("selector site limit " + rel + ":<module>" if entry == "inventory" and bound == "words"
                else rel + ": unresolved Python -c program")
    assert str(error.value) == expected


@pytest.mark.parametrize("call", [
    "os.execv(exe, *argv)", "os.execve(exe, *argv, {})",
    "os.execvp(exe, *argv)", "os.execvpe(exe, *argv, {})",
    "os.spawnv(0, exe, *argv)", "os.spawnve(0, exe, *argv, {})",
    "os.spawnvp(0, exe, *argv)", "os.spawnvpe(0, exe, *argv, {})",
    "os.execl(exe, *argv)", "os.execle(exe, *argv, {})",
    "os.spawnl(0, exe, *argv)", "os.spawnle(0, exe, *argv, {})",
    "os.execl(exe, 'display', *argv)", "os.execle(exe, 'display', *argv, {})",
    "os.execlp(exe, 'display', *argv)", "os.execlpe(exe, 'display', *argv, {})",
    "os.spawnl(0, exe, 'display', *argv)", "os.spawnle(0, exe, 'display', *argv, {})",
    "os.spawnlp(0, exe, 'display', *argv)", "os.spawnlpe(0, exe, 'display', *argv, {})",
    "subprocess.Popen(*argv, executable=exe)", "subprocess.run(*argv, executable=exe)",
])
@pytest.mark.parametrize("entry", ["refusal", "inventory"])
def test_round24_starred_argv_slots_refuse(tmp_path, call, entry):
    source = "import os, subprocess\ndef launch(exe, argv):\n    " + call + "\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    with pytest.raises(ValueError) as error:
        if entry == "refusal":
            refuse_literal_spawns(modules[rel], rel, modules)
        else:
            table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
            process_sites(tmp_path, selector_table=table)
    assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("call", [
    "os.execv('echo', *argv)", "os.spawnv(0, 'echo', *argv)",
    "os.execl('echo', *argv)", "os.spawnl(0, 'echo', *argv)",
    "os.execl('echo', 'display', *argv)", "os.spawnl(0, 'echo', 'display', *argv)",
    "subprocess.Popen(*argv, executable='echo')",
    "subprocess.run(['python3', '-c', 'pass', *argv])",
    "os.execv(sys.executable, ['worker', '-c', 'pass', *argv])",
    "os.spawnv(0, sys.executable, ['worker', '-c', 'pass', *argv])",
    "subprocess.getoutput(**options)",
    "subprocess.getoutput(**{**{'cmd': 'echo ok'}})",
])
@pytest.mark.parametrize("entry", ["refusal", "inventory"])
def test_round24_known_native_tails_and_unknown_mappings_keep_controls(tmp_path, call, entry):
    source = "import os, subprocess, sys\ndef launch(argv, options):\n    " + call + "\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.startswith("process:")) == 2


@pytest.mark.parametrize("method", ["format", "join", "replace", "split"])
@pytest.mark.parametrize("route", ["parameter", "default", "method_alias", "class_alternative"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round25_string_receiver_needs_every_binding_proven(tmp_path, method, route, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "class Builder:\n    def " + method + "(self, flag):\n        return [sys.executable, flag, P]\n")
    if route == "class_alternative":
        source += "def launch(flag, enabled):\n    builder = Builder() if enabled else 'echo'\n"
    else:
        signature = "flag, builder=None" if route == "default" else "builder, flag"
        source += "def launch(" + signature + "):\n    if builder is None:\n        builder = 'echo'\n"
    source += ("    method = builder." + method + "\n    subprocess.run(method(flag))\n" if route == "method_alias"
               else "    subprocess.run(builder." + method + "(flag))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("route", ["direct", "import_alias", "assignment_alias", "reexport", "keyword", "lambda"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round25_imported_callable_defaults_keep_unknown_evidence(tmp_path, route, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    (core / "provider.py").write_text(
        "import sys\nP = \"import os; os.system('id')\"\ndef build(flag):\n    return [sys.executable, flag, P]\n",
        encoding="utf-8")
    if route == "reexport":
        (core / "exports.py").write_text("from .provider import build\n", encoding="utf-8")
    source = "import subprocess\nfrom aegis_core." + ("exports" if route == "reexport" else "provider") + " import build"
    source += " as imported\nbuild = imported\n" if route == "import_alias" else "\n"
    if route == "assignment_alias":
        source += "callback = build\n"
    callback = "callback" if route == "assignment_alias" else "build"
    if route == "lambda":
        source += "launch = lambda flag, callback=" + callback + ": subprocess.run(callback(flag))\n"
    else:
        source += "def launch(flag, " + ("*, " if route == "keyword" else "") + "callback=" + callback + "):\n    subprocess.run(callback(flag))\n"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("arguments", [
    "['worker', '-c', CMD]", "['worker', '--command', CMD]", "['worker', '--command='+CMD]",
    "['worker', '--session-command', CMD]", "['worker', '--session-command='+CMD]",
    "['--', 'worker', '-c', CMD]",
])
@pytest.mark.parametrize("prefix", ["['su']", "['env', 'su']", "['busybox', 'su']"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round25_su_username_is_never_a_transparent_executable(tmp_path, arguments, prefix, entry):
    source = ("import subprocess, shlex\nP = \"import os; os.system('id')\"\n"
              "CMD = 'python3 -c ' + shlex.quote(P)\nsubprocess.run(" + prefix + " + " + arguments + ")\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("route", ["strings", "string_alias", "helper_default"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round25_proven_receivers_and_helper_defaults_keep_no_program(tmp_path, route, entry):
    source = "import subprocess\nfrom shlex import quote\n"
    if route == "helper_default":
        source += "def launch(value, build=quote):\n    subprocess.run(build(value))\n"
    else:
        source += "def launch(value, condition):\n    builder = 'echo'\n    if condition:\n        builder = 'text'\n"
        source += ("    method = builder.format\n    subprocess.run(method(value))\n" if route == "string_alias"
                   else "    subprocess.run(builder.format(value))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    # ROUND-27b supersedes the callable-parameter acceptance in this control.
    if route == "helper_default":
        if entry == "selector":
            assert selector_gate_errors(modules, ())
        else:
            with pytest.raises(ValueError) as error:
                if entry == "refusal":
                    refuse_literal_spawns(modules[rel], rel, modules)
                else:
                    table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                    process_sites(tmp_path, selector_table=table)
            assert str(error.value) == rel + ": unresolved Python -c program"
        return
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == []
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("builtin", ["str", "repr", "ascii", "bytes"])
@pytest.mark.parametrize("route", ["direct", "module_alias", "chained_alias", "closure_alias"])
@pytest.mark.parametrize("signature", ["positional", "keyword", "lambda"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round26_unshadowed_builtin_defaults_keep_no_program(tmp_path, builtin, route, signature, entry):
    source = "import subprocess\n"
    default, indent = builtin, ""
    if route == "module_alias":
        source += "transform = " + builtin + "\n"
        default = "transform"
    elif route == "chained_alias":
        source += "first = " + builtin + "\ntransform = first\n"
        default = "transform"
    elif route == "closure_alias":
        source += "def factory():\n    transform = " + builtin + "\n"
        default, indent = "transform", "    "
    if signature == "lambda":
        source += indent + "launch = lambda value, callback=" + default + ": subprocess.run(['echo', callback(value)])\n"
    else:
        source += indent + "def launch(value, " + ("*, " if signature == "keyword" else "") + "callback=" + default + "):\n"
        source += indent + "    subprocess.run(['echo', callback(value)])\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    # ROUND-27b supersedes this historical builtin-default NoProgram control.
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("route", ["function", "alias", "import", "opaque", "rebound_alias", "mixed_alias", "callback_reassignment"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round26_shadowed_builtin_defaults_stay_unknown(tmp_path, route, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def build(flag):\n    return [sys.executable, flag, P]\n")
    default, indent = "str", ""
    if route == "function":
        source += "def str(flag):\n    return build(flag)\n"
    elif route == "alias":
        source += "str = build\n"
    elif route == "import":
        source += "from aegis_core.provider import build as str\n"
    elif route == "opaque":
        source += "def factory(str):\n"
        indent = "    "
    elif route == "callback_reassignment":
        source += "from aegis_core.provider import build as imported\n"
    else:
        source += "transform = str\n"
        source += "transform = build\n" if route == "rebound_alias" else "if enabled:\n    transform = build\n"
        default = "transform"
    source += indent + "def launch(flag, callback=" + default + "):\n"
    if route == "callback_reassignment":
        source += "    if enabled:\n        callback = imported\n"
    source += indent + "    subprocess.run(callback(flag))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text("import sys\ndef build(flag):\n    return [sys.executable, flag, 'pass']\n", encoding="utf-8")
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("builtin", ["str", "repr", "ascii", "bytes"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round26_builtin_defaults_walk_content_arguments(tmp_path, builtin, entry):
    source = ("import subprocess\nfrom pathlib import Path\ndef launch(path, callback=" + builtin + "):\n"
              "    subprocess.run(['echo', callback(Path(path).read_text())])\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("head,arguments", [
    ("runuser", "['worker', '-c', CMD]"),
    ("runuser", "['worker', '--command', CMD]"),
    ("runuser", "['worker', '--command='+CMD]"),
    ("runuser", "['worker', '--session-command', CMD]"),
    ("runuser", "['worker', '--session-command='+CMD]"),
    ("runuser", "['--', 'worker', '-c', CMD]"),
    ("sg", "['group', '-c', CMD]"),
])
@pytest.mark.parametrize("prefix", [[], ["sudo"]])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round26_user_group_wrappers_remain_unknown_after_peeling(tmp_path, head, arguments, prefix, entry):
    source = ("import subprocess, shlex\nP = \"import os; os.system('id')\"\n"
              "CMD = 'python3 -c ' + shlex.quote(P)\nsubprocess.run(" + repr(prefix + [head]) + " + " + arguments + ")\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("route", ["lambda_default", "local_helper", "callable_alias", "reexport"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round26_argon_imported_helpers_never_have_empty_evidence(tmp_path, route, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text(
        "import sys\nP = \"import os; os.system('id')\"\ndef build(flag):\n    return [sys.executable, flag, P]\n",
        encoding="utf-8")
    if route == "reexport":
        (core / "exports.py").write_text("from .provider import build\n", encoding="utf-8")
    source = "import subprocess\nfrom aegis_core." + ("exports" if route == "reexport" else "provider") + " import build\n"
    if route == "local_helper":
        source += "def wrapper(flag):\n    return build(flag)\ndef launch(flag):\n    subprocess.run(wrapper(flag))\n"
    else:
        if route == "callable_alias":
            source += "runner = build\n"
        source += ("def launch(flag, callback=lambda flag: " + ("runner" if route == "callable_alias" else "build")
                   + "(flag)):\n    subprocess.run(callback(flag))\n")
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("route", ["direct", "method_alias", "local_import", "method_default"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round26_argon_imported_receiver_alternatives_need_proof(tmp_path, route, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "provider.py").write_text(
        "import sys\nP = \"import os; os.system('id')\"\nclass Builder:\n    def format(self, flag):\n"
        "        return [sys.executable, flag, P]\nbuilder = Builder()\n", encoding="utf-8")
    source = "import subprocess\n"
    if route == "local_import":
        source += "def launch(flag):\n    from aegis_core.provider import builder\n    if False:\n        builder = 'echo'\n"
    else:
        source += ("from aegis_core.provider import builder\nif False:\n    builder = 'echo'\ndef launch(flag"
                   + (", method=builder.format" if route == "method_default" else "") + "):\n")
    if route == "method_alias":
        source += "    method = builder.format\n    subprocess.run(method(flag))\n"
    else:
        source += "    subprocess.run(" + ("method(flag)" if route == "method_default" else "builder.format(flag)") + ")\n"
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("builtin", ["str", "repr", "ascii", "bytes", "list", "tuple"])
@pytest.mark.parametrize("form", ["positional", "keyword", "lambda", "assignment_alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round27b_callable_default_overrides_need_review(tmp_path, builtin, form, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def build(flag):\n    return [sys.executable, flag, P]\n")
    default = builtin
    if form == "assignment_alias":
        source += "transform = " + builtin + "\n"
        default = "transform"
    if form == "lambda":
        source += "launch = lambda value, callback=" + default + ": subprocess.run(callback(value))\n"
    else:
        source += "def launch(value, " + ("*, " if form == "keyword" else "") + "callback=" + default + "):\n    subprocess.run(callback(value))\n"
    source += "def main(flag):\n    launch(flag, callback=build)\nmain(sys.argv[1])\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("case", ["default_str", "default_tuple", "no_default", "parameter_alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round27b_callable_parameters_are_unknown(tmp_path, case, entry):
    source = "import subprocess\n"
    if case == "default_str":
        source += "def launch(value, callback=str):\n    subprocess.run(['echo', callback(value)])\n"
    elif case == "default_tuple":
        source += "def launch(convert=tuple):\n    subprocess.run(convert(['echo', 'ok']))\n"
    else:
        source += "def launch(value, callback):\n"
        source += ("    operation = callback\n    subprocess.run(operation(value))\n" if case == "parameter_alias"
                   else "    subprocess.run(callback(value))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("command", [
    "tuple(['echo', 'ok'])", "list(['echo', 'ok'])", "['echo', str(value)]",
    "['echo', repr(value)]", "['echo', ascii(value)]", "['echo', bytes(value)]", "value",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round27b_direct_builtins_and_plain_parameters_keep_models(tmp_path, command, entry):
    source = "import subprocess\ndef launch(value):\n    subprocess.run(" + command + ")\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == []
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("case", [
    "factory", "lambda_factory", "quote_default", "class_loop", "class_deleted",
    "imported_placeholder", "stream_return",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round27_argon_callable_alternatives_require_review(tmp_path, case, entry):
    source = "import subprocess\nfrom .provider import build\n"
    if case in {"factory", "lambda_factory", "quote_default"}:
        if case == "lambda_factory":
            source += "choose = lambda callback=str: callback\n"
        else:
            default = "shlex.quote" if case == "quote_default" else "str"
            source += "import shlex\ndef choose(callback=" + default + "):\n    return callback\n"
        source += "def launch(flag):\n    subprocess.run(choose(build)(flag))\n"
    elif case in {"class_loop", "class_deleted"}:
        if case == "class_deleted":
            source += "class Base:\n    callback = staticmethod(build)\n"
        source += "class Spec" + ("(Base)" if case == "class_deleted" else "") + ":\n"
        source += "    def callback(self, flag):\n        return ['echo', flag]\n"
        source += ("    del callback\n" if case == "class_deleted"
                   else "    for callback in (build,):\n        pass\n")
        source += "    def launch(self, flag):\n        subprocess.run(self.callback(flag))\n"
    elif case == "imported_placeholder":
        source += ("class Spec:\n    def callback(self, flag=build):\n        return ['echo', 'ok']\n"
                   "    def launch(self):\n        subprocess.run(self.callback())\n")
    else:
        source = ("import os\ndef read_cmd(p):\n    return next(open(p))\n"
                  "def launch(p):\n    os.system(read_cmd(p))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    provider = ("import sys\nP = \"import os; os.system('id')\"\n"
                "def build(flag):\n    return [sys.executable, flag, P]\n")
    (core / "provider.py").write_text(provider, encoding="utf-8")
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("case", [
    "function", "method", "factory", "async", "called_decorator", "stacked", "shadowed", "opaque",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round28_decorated_callables_require_review(tmp_path, case, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def python_argv(source):\n    def wrapped(flag):\n"
              "        return [sys.executable, flag, source(flag)]\n    return wrapped\n")
    if case == "method":
        source += ("def method_argv(source):\n    def wrapped(self, flag):\n"
                   "        return [sys.executable, flag, source(self, flag)]\n    return wrapped\n"
                   "class Runner:\n    @method_argv\n    def build(self, flag):\n        return P\n"
                   "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    elif case == "factory":
        source += ("def python_factory(source):\n    def replacement():\n        def wrapped(flag):\n"
                   "            return [sys.executable, flag, source()(flag)]\n"
                   "        return wrapped\n    return replacement\n"
                   "@python_factory\ndef factory():\n    def build(flag):\n        return P\n    return build\n"
                   "def launch(flag):\n    subprocess.run(factory()(flag))\n")
    elif case == "async":
        source += ("def async_argv(source):\n    def wrapped(flag):\n"
                   "        return [sys.executable, flag, P]\n    return wrapped\n"
                   "@async_argv\nasync def build(flag):\n    return 'echo'\n"
                   "def launch(flag):\n    subprocess.run(build(flag))\n")
    elif case == "stacked":
        source += ("class Runner:\n    @staticmethod\n    @python_argv\n    def build(flag):\n        return P\n"
                   "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    else:
        decorator = "python_argv"
        if case == "called_decorator":
            source += "def make_decorator():\n    return python_argv\n"
            decorator = "make_decorator()"
        elif case == "shadowed":
            source += "staticmethod = python_argv\n"
            decorator = "staticmethod"
        elif case == "opaque":
            source += "from functools import lru_cache as decorate\n"
            decorator = "decorate"
        source += "@" + decorator + "\ndef build(flag):\n    return P\n"
        source += "def launch(flag):\n    subprocess.run(build(flag))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("factory", [False, True])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round28_enumerable_decorators_replace_original_return_evidence(tmp_path, factory, entry):
    source = "import subprocess, sys\nP = \"import os; os.system('id')\"\n"
    if factory:
        source += ("def decorate(source):\n    def replacement():\n        def wrapped(flag):\n"
                   "            return ['echo', flag]\n        return wrapped\n    return replacement\n"
                   "@decorate\ndef factory():\n    def build(flag):\n"
                   "        return [sys.executable, flag, P]\n    return build\n"
                   "def launch(flag):\n    subprocess.run(factory()(flag))\n")
    else:
        source += ("def decorate(source):\n    def wrapped(flag):\n        return ['echo', flag]\n    return wrapped\n"
                   "@decorate\ndef build(flag):\n    return [sys.executable, flag, P]\n"
                   "def launch(flag):\n    subprocess.run(build(flag))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == []
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("descriptor", ["staticmethod", "classmethod"])
@pytest.mark.parametrize("style", ["bare", "imported", "module"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round28_proven_descriptors_keep_native_calls(tmp_path, descriptor, style, entry):
    source = "import subprocess\n"
    decorator = descriptor
    if style == "imported":
        source += "from builtins import " + descriptor + " as descriptor\n"
        decorator = "descriptor"
    elif style == "module":
        source += "import builtins\n"
        decorator = "builtins." + descriptor
    arguments = "cls, flag" if descriptor == "classmethod" else "flag"
    source += ("class Runner:\n    @" + decorator + "\n    def build(" + arguments + "):\n"
               "        return ['echo', flag]\n    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == []
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round28_decorator_choice_bound_requires_review(tmp_path, entry):
    source = ("import subprocess\n" + "@staticmethod\n" * (_MAX_CHOICES + 1)
              + "def build(flag):\n    return ['echo', flag]\n"
              "def launch(flag):\n    subprocess.run(build(flag))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("case", [
    "instance_store", "instance_delete", "class_store", "subclass", "static_self", "unknown_base",
    "map", "filter", "sorted_key", "min_key", "reduce", "builtin_argument", "argument_alias",
    "builtin_conditional", "builtin_boolean", "builtin_subscript", "builtin_factory", "builtin_method",
    "string_add", "string_branch", "keyword_executable", "keyword_args", "keyword_unknown",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round28_correctness_addendum_requires_review(tmp_path, case, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def build(flag):\n    return [sys.executable, flag, P]\n")
    if case in {"instance_store", "instance_delete", "class_store", "subclass", "static_self", "unknown_base"}:
        source += "class Runner:\n    def callback(self, flag):\n        return ['echo', flag]\n"
        if case in {"instance_store", "instance_delete"}:
            source += "    def __init__(self, callback):\n        self.callback = callback\n"
            if case == "instance_delete":
                source += "        del self.callback\n"
        if case == "static_self":
            source += "    @staticmethod\n"
        source += "    def launch(self, flag):\n        subprocess.run(self.callback(flag))\n"
        if case == "class_store":
            source += "Runner.callback = build\n"
        elif case == "subclass":
            source += "class PythonRunner(Runner):\n    callback = staticmethod(build)\n"
        elif case == "unknown_base":
            source += "def derive(base):\n    class PythonRunner(base):\n        callback = staticmethod(build)\n    return PythonRunner\n"
    elif case == "builtin_method":
        source += ("class Runner:\n    def callback(self, flag):\n        return [sys.executable, flag, P]\n"
                   "    def launch(self):\n        subprocess.run(str(self.callback))\n")
    elif case in {"map", "filter", "sorted_key", "min_key", "reduce", "builtin_argument", "argument_alias",
                  "builtin_conditional", "builtin_boolean", "builtin_subscript", "builtin_factory"}:
        calls = {"map": "next(map(build, [flag]))", "filter": "next(filter(build, [flag]))",
                 "sorted_key": "sorted([flag], key=build)", "min_key": "min([flag], key=build)",
                 "reduce": "functools.reduce(lambda a, item: build(item), [flag], None)",
                 "builtin_argument": "str(build)", "argument_alias": "str(callback)",
                 "builtin_conditional": "str(build if flag else build)", "builtin_boolean": "str(build or build)",
                 "builtin_subscript": "str([build][0])", "builtin_factory": "str(callback_factory())"}
        source += ("import functools\ncallback = build\ndef callback_factory():\n    return build\n"
                   "def launch(flag):\n    subprocess.run(" + calls[case] + ")\n")
    elif case in {"string_add", "string_branch"}:
        source += ("class Builder:\n    def __add__(self, other):\n        return self\n"
                   "    def format(self, flag):\n        return [sys.executable, flag, P]\n")
        expression = "builder + suffix" if case == "string_add" else "builder if enabled else 'echo'"
        source += "def launch(builder, suffix, enabled, flag):\n    subprocess.run((" + expression + ").format(flag))\n"
    else:
        key = "'args'" if case == "keyword_args" else "'executable'"
        source += "KEY = " + key + "\ndef launch(flag, unknown_key):\n"
        if case == "keyword_args":
            call = "subprocess.run(**{KEY: [sys.executable, flag, P]})"
        else:
            word = "unknown_key" if case == "keyword_unknown" else "KEY"
            call = "subprocess.run(['worker', flag, P], **{" + word + ": sys.executable})"
        source += "    " + call + "\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("python", [False, True])
@pytest.mark.parametrize("entry", ["selector", "refusal"])
def test_round28_cross_module_subclass_return_evidence(tmp_path, python, entry):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    source = ("import subprocess\nclass Base:\n    def callback(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.callback(flag))\n"
              "from .provider import Child\n")
    head = "sys.executable" if python else "'echo'"
    provider = ("import sys\nfrom .probe import Base\nclass Child(Base):\n"
                "    def callback(self, flag):\n        return [" + head + ", flag, 'pass']\n")
    (core / "probe.py").write_text(source, encoding="utf-8")
    (core / "provider.py").write_text(provider, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert bool(selector_gate_errors(modules, ())) is python
    elif python:
        with pytest.raises(ValueError) as error:
            refuse_literal_spawns(modules[rel], rel, modules)
        assert str(error.value) == rel + ": unresolved Python -c program"
    else:
        refuse_literal_spawns(modules[rel], rel, modules)


@pytest.mark.parametrize("entry", ["refusal", "inventory"])
def test_round28_dynamic_keyword_collision_preserves_module_label(tmp_path, entry):
    source = ("import subprocess, sys\nKEY = 'executable'\ndef launch(module):\n"
              "    subprocess.run([sys.executable, '-m', module], **{KEY: None}, **{KEY: None})\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    with pytest.raises(ValueError) as error:
        if entry == "refusal":
            refuse_literal_spawns(modules[rel], rel, modules)
        else:
            table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
            process_sites(tmp_path, selector_table=table)
    assert str(error.value) == rel + ": unresolved Python module"


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round28_classmethod_binding_does_not_depend_on_parameter_spelling(tmp_path, entry):
    source = ("import subprocess\nclass Runner:\n    @classmethod\n    def callback(cls, flag):\n"
              "        return ['echo', flag]\n    @classmethod\n    def launch(self, flag):\n"
              "        subprocess.run(self.callback(flag))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == []
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("shape", ["if_def", "if_assign", "try", "for", "while", "with"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_conditional_override_keeps_inherited_evidence(tmp_path, shape, entry):
    source = ("import subprocess, sys, contextlib\nP = \"import os; os.system('id')\"\n"
              "class Base:\n    def callback(self, flag):\n        return [sys.executable, flag, P]\n"
              "class Runner(Base):\n")
    native = "def callback(self, flag):\n            return ['echo', flag]\n"
    if shape == "if_def":
        source += "    if sys.platform == 'win32':\n        " + native
    elif shape == "if_assign":
        source += "    if sys.platform == 'win32':\n        callback = lambda self, flag: ['echo', flag]\n"
    elif shape == "try":
        source += ("    try:\n        if sys.platform != 'win32':\n            raise RuntimeError()\n"
                   "        " + native + "    except RuntimeError:\n        pass\n")
    elif shape == "for":
        source += "    for item in ([0] if sys.platform == 'win32' else []):\n        " + native
    elif shape == "while":
        source += "    while sys.platform == 'win32':\n        " + native + "        break\n"
    else:
        source += ("    with contextlib.suppress(RuntimeError):\n        if sys.platform != 'win32':\n"
                   "            raise RuntimeError()\n        " + native)
    source += "    def launch(self, flag):\n        subprocess.run(self.callback(flag))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("selection", [
    "list([build])[0]", "tuple([build])[0]", "sorted([build])[0]",
    "dict([('builder', build)])['builder']", "[build][0]", "(build,)[0]", "{'builder': build}['builder']",
])
@pytest.mark.parametrize("alias", ["direct", "container", "callable", "constructor"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_container_callable_selections_are_unknown(tmp_path, selection, alias, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def build(flag):\n    return [sys.executable, flag, P]\n")
    if alias == "callable":
        source += "callback = " + selection + "\n"
        selection = "callback"
    elif alias == "container":
        container, _, index = selection.rpartition("[")
        source += "callbacks = " + container + "\n"
        selection = "callbacks[" + index
    elif alias == "constructor":
        if selection.startswith(("list(", "tuple(", "sorted(", "dict(")):
            constructor, _, arguments = selection.partition("(")
            source += "make = " + constructor + "\n"
            selection = "make(" + arguments
        else:
            source += "callback = " + selection + "\n"
            selection = "callback"
    source += "def launch(flag):\n    subprocess.run(" + selection + "(flag))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("builtin", ["min", "max", "sorted"])
@pytest.mark.parametrize("expansion", ["literal", "nested", "opaque", "other_key", "alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_expanded_builtin_callbacks_require_review(tmp_path, builtin, expansion, entry):
    mapping = {"literal": "{'key': build}", "nested": "{**{'key': build}}", "opaque": "options",
               "other_key": "{'callback': build}", "alias": "{'key': build}"}[expansion]
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def build(flag):\n    return [sys.executable, flag, P]\n")
    if expansion == "alias":
        source += "choose = " + builtin + "\n"
        builtin = "choose"
    source += "def launch(candidates, options):\n    subprocess.run(" + builtin + "(candidates, **" + mapping + "))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("unrelated", ["write", "dynamic_write", "class_write", "exception", "builtin_alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_unrelated_owners_do_not_invalidate_native_methods(tmp_path, unrelated, entry):
    source = ("import subprocess\nclass Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    if unrelated == "write":
        source += "class Other:\n    def __init__(self):\n        self.build = None\n"
    elif unrelated == "dynamic_write":
        source += "class Other:\n    def __init__(self, name):\n        setattr(self, name, None)\n"
    elif unrelated == "class_write":
        source += "class Other:\n    pass\nOther.build = None\n"
    elif unrelated == "exception":
        source += "class Problem(Exception):\n    pass\n"
    else:
        source += "from builtins import Exception as Error\nclass Problem(Error):\n    pass\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ()) == []
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_recursive_callback_arguments_require_review(tmp_path, entry):
    source = "import subprocess\ndef launch():\n    value = str(value)\n    subprocess.run(str(value))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("argument", ["[build]", "(build,)", "{'callback': build}", "{build}"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_builtin_container_arguments_are_callable_bearing(tmp_path, argument, entry):
    source = ("import subprocess, sys\ndef build(flag):\n    return [sys.executable, flag, 'pass']\n"
              "def launch():\n    subprocess.run(str(" + argument + "))\n")
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


@pytest.mark.parametrize("statement", [
    "if enabled:\n    def build(flag):\n        return ['echo', flag]\n",
    "if enabled:\n    build = lambda flag: ['echo', flag]\n",
    "try:\n    def build(flag):\n        return ['echo', flag]\nexcept Exception:\n    pass\n",
    "for item in options:\n    def build(flag):\n        return ['echo', flag]\n",
    "while enabled:\n    def build(flag):\n        return ['echo', flag]\n    break\n",
    "with manager:\n    def build(flag):\n        return ['echo', flag]\n",
])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round29_conditional_module_binding_is_not_definite(tmp_path, statement, entry):
    source = "import subprocess\n" + statement + "def launch(flag):\n    subprocess.run(build(flag))\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        assert selector_gate_errors(modules, ())
    else:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"


def round30_indent(source):
    return "".join("    " + line + "\n" for line in source.splitlines())


def round30_launch_outcome(tmp_path, source, entry, *, review):
    core = tmp_path / "aegis_core"
    core.mkdir()
    rel = "aegis_core/probe.py"
    if entry == "inventory":
        source = "import subprocess, sys\nsubprocess.run([sys.executable, '-c', " + repr(source) + "])\n"
    (core / "probe.py").write_text(source, encoding="utf-8")
    modules = dict(module_trees(tmp_path))
    if entry == "selector":
        errors = selector_gate_errors(modules, ())
        if review:
            assert errors
        else:
            assert errors == []
    elif review:
        with pytest.raises(ValueError) as error:
            if entry == "refusal":
                refuse_literal_spawns(modules[rel], rel, modules)
            else:
                table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
                process_sites(tmp_path, selector_table=table)
        assert str(error.value) == rel + ": unresolved Python -c program"
    elif entry == "refusal":
        refuse_literal_spawns(modules[rel], rel, modules)
    else:
        table = ((rel, "<module>", "resolved-python-program", "Review only the outer test literal."),)
        sites = process_sites(tmp_path, selector_table=table)
        assert sum(len(lines) for key, lines in sites.items() if key.endswith(":subprocess.run")) == 2


@pytest.mark.parametrize("base", ["list", "tuple", "callable"])
@pytest.mark.parametrize("binding", ["module", "local", "nested", "attribute_alias", "callable_alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_class_calls_are_not_function_evidence(tmp_path, base, binding, entry):
    source = "import subprocess, sys\nP = \"import os; os.system('id')\"\n"
    if base == "list":
        builder = ("class Build(list):\n    def __init__(self, flag):\n"
                   "        super().__init__([sys.executable, flag, P])\n")
        call = "Build(flag)"
    elif base == "tuple":
        builder = ("class Build(tuple):\n    def __new__(cls, flag):\n"
                   "        return super().__new__(cls, [sys.executable, flag, P])\n")
        call = "Build(flag)"
    else:
        builder = "class Build:\n    def __call__(self, flag):\n        return [sys.executable, flag, P]\n"
        call = "Build()(flag)"
    if binding == "module":
        source += builder + "def launch(flag):\n    subprocess.run(" + call + ")\n"
    elif binding == "local":
        source += "def launch(flag):\n" + round30_indent(builder)
        source += "    subprocess.run(" + call + ")\n"
    else:
        if binding == "attribute_alias":
            source += builder + "class Runner:\n    Build = Build\n"
        else:
            source += "class Runner:\n" + round30_indent(builder)
        source += "    def launch(self, flag):\n"
        if binding == "callable_alias":
            source += "        build = self.Build\n        subprocess.run(" + call.replace("Build", "build") + ")\n"
        else:
            source += "        subprocess.run(" + call.replace("Build", "self.Build") + ")\n"
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("shape", ["if", "try", "for", "while", "with"])
@pytest.mark.parametrize("scope", ["module", "class"])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_class_alternatives_keep_each_fallback(tmp_path, shape, scope, alias, entry):
    source = ("import contextlib, subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "class Base:\n    def callback(self, flag):\n        return [sys.executable, flag, P]\n")
    launch = "    def launch(self, flag):\n        subprocess.run(self.callback(flag))\n"
    fallback = "class Runner(Base):\n" + launch
    native = "class Runner(Base):\n    def callback(self, flag):\n        return ['echo', flag]\n" + launch
    if alias:
        source += "class Native(Base):\n    def callback(self, flag):\n        return ['echo', flag]\n" + launch
        source += "class Fallback(Base):\n" + launch
        native, fallback = "Runner = Native\n", "Runner = Fallback\n"
    if shape == "if":
        alternatives = ("if sys.platform == 'win32':\n" + round30_indent(native)
                        + "else:\n" + round30_indent(fallback))
    elif shape == "try":
        alternatives = ("try:\n    if sys.platform != 'win32':\n        raise RuntimeError()\n"
                        + round30_indent(native) + "except RuntimeError:\n" + round30_indent(fallback))
    else:
        header = {"for": "for item in ([0] if sys.platform == 'win32' else []):\n",
                  "while": "while sys.platform == 'win32':\n",
                  "with": "with contextlib.suppress(RuntimeError):\n"}[shape]
        body = native + ("break\n" if shape == "while" else "")
        if shape == "with":
            body = "if sys.platform != 'win32':\n    raise RuntimeError()\n" + body
        alternatives = fallback + header + round30_indent(body)
    source += "class Group:\n" + round30_indent(alternatives) if scope == "class" else alternatives
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("receiver", [
    "self", "this", "cls", "klass", "class", "type_self", "module_instance", "local_instance",
    "instance_alias", "unresolved",
])
@pytest.mark.parametrize("mutation", ["assign", "delete", "setattr", "delattr"])
@pytest.mark.parametrize("owner", ["Runner", "Other"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_receiver_spelling_retains_write_owner(tmp_path, receiver, mutation, owner, entry):
    source = ("import subprocess\nclass Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    if owner == "Other":
        source += "class Other:\n    pass\n"
    target = owner
    prefix = ""
    if receiver in {"self", "this", "cls", "klass", "type_self"}:
        # Reopen via a subclass to keep the mutation in the owner's hierarchy.
        source += "class Mutator(" + owner + "):\n"
        argument = "self" if receiver == "type_self" else receiver
        if receiver in {"cls", "klass"}:
            source += "    @classmethod\n"
        source += "    def configure(" + argument + "):\n"
        prefix = "        "
        target = "type(self)" if receiver == "type_self" else argument
    elif receiver == "module_instance":
        source += "instance = " + owner + "()\n"
        target = "instance"
    elif receiver == "instance_alias":
        source += "instance = " + owner + "()\nalias = instance\n"
        target = "alias"
    elif receiver == "local_instance":
        source += "def configure():\n    instance = " + owner + "()\n"
        prefix, target = "    ", "instance"
    elif receiver == "unresolved":
        source += "def configure(instance):\n"
        prefix, target = "    ", "instance"
    statement = {"assign": target + ".build = None", "delete": "del " + target + ".build",
                 "setattr": "setattr(" + target + ", 'build', None)",
                 "delattr": "delattr(" + target + ", 'build')"}[mutation]
    source += prefix + statement + "\n"
    round30_launch_outcome(tmp_path, source, entry, review=owner == "Runner" or receiver == "unresolved")


@pytest.mark.parametrize("base", ["Exception", "object", "list"])
@pytest.mark.parametrize("route", ["direct", "chain", "local"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_builtin_base_aliases_remain_unrelated(tmp_path, base, route, entry):
    source = ("import subprocess\nclass Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    alias = "Error = " + base + "\n"
    if route == "chain":
        alias += "Again = Error\n"
    declaration = "class Problem(" + ("Again" if route == "chain" else "Error") + "):\n    pass\n"
    source += "def configure():\n" + round30_indent(alias + declaration) if route == "local" else alias + declaration
    round30_launch_outcome(tmp_path, source, entry, review=False)


@pytest.mark.parametrize("route", ["parameter", "conditional", "rebound"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_builtin_base_aliases_require_identity_proof(tmp_path, route, entry):
    source = ("import subprocess\nclass Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    if route == "parameter":
        source += "def configure(Error):\n    class Problem(Error):\n        pass\n"
    elif route == "conditional":
        source += "Error = Exception if enabled else opaque\nclass Problem(Error):\n    pass\n"
    else:
        source += "Error = Exception\nError = opaque\nclass Problem(Error):\n    pass\n"
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("descriptor", ["instance", "classmethod"])
@pytest.mark.parametrize("label", ["this", "klass", "builder"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_receiver_identity_uses_its_parameter_scope(tmp_path, descriptor, label, entry):
    decorator = "    @classmethod\n" if descriptor == "classmethod" else ""
    source = ("import subprocess\nclass Runner:\n" + decorator + "    def build(" + label
              + ", flag):\n        return ['echo', flag]\n" + decorator + "    def launch(" + label
              + ", flag):\n        subprocess.run(" + label + ".build(flag))\n")
    round30_launch_outcome(tmp_path, source, entry, review=False)


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_other_receiver_label_does_not_capture_string_helpers(tmp_path, entry):
    source = ("import subprocess\nclass Other:\n    def configure(builder):\n        pass\n"
              "def launch(flag):\n    builder = 'echo'\n    subprocess.run(builder.format(flag))\n")
    round30_launch_outcome(tmp_path, source, entry, review=False)


@pytest.mark.parametrize("replacement", ["function", "assignment", "parameter", "decorator"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round30_rebound_class_constructor_has_unknown_owner(tmp_path, replacement, entry):
    source = ("import subprocess\nclass Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    if replacement == "decorator":
        source += "@opaque\nclass Other:\n    pass\n"
    else:
        source += "class Other:\n    pass\n"
    if replacement == "function":
        source += "def Other():\n    return Runner()\n"
    elif replacement == "assignment":
        source += "Other = opaque\n"
    elif replacement == "parameter":
        source += "def configure(Other):\n    setattr(Other(), 'build', None)\n"
    if replacement != "parameter":
        source += "setattr(Other(), 'build', None)\n"
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("construction", [
    "new", "inherited_new", "deep_new", "diamond_new", "metaclass", "inherited_metaclass",
    "metaclass_default", "conditional_meta", "new_alias", "new_assignment", "new_setattr", "dynamic_hook",
])
@pytest.mark.parametrize("route", ["call", "module", "local", "alias", "chain", "constructor_alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round31_unproven_constructor_results_have_unknown_owners(tmp_path, construction, route, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def python_argv(flag):\n    return [sys.executable, flag, P]\n"
              "class Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\nrunner = Runner()\n")
    new = "    def __new__(cls):\n        return runner\n"
    if construction == "new":
        source += "class Factory:\n" + new
    elif construction in {"inherited_new", "deep_new", "diamond_new"}:
        source += "class Parent:\n" + new
        if construction == "deep_new":
            source += "class Middle(Parent):\n    pass\nclass Factory(Middle):\n    pass\n"
        elif construction == "diamond_new":
            source += "class Plain:\n    pass\nclass Factory(Plain, Parent):\n    pass\n"
        else:
            source += "class Factory(Parent):\n    pass\n"
    elif construction in {"metaclass", "inherited_metaclass", "metaclass_default", "conditional_meta"}:
        source += "class Meta(type):\n"
        source += ("    pass\n" if construction == "metaclass_default"
                   else "    def __call__(cls):\n        return runner\n")
        if construction == "inherited_metaclass":
            source += "class Parent(metaclass=Meta):\n    pass\nclass Factory(Parent):\n    pass\n"
        elif construction == "conditional_meta":
            source += "Choice = type if enabled else Meta\nclass Factory(metaclass=Choice):\n    pass\n"
        else:
            source += "class Factory(metaclass=Meta):\n    pass\n"
    else:
        source += "def factory_new(cls):\n    return runner\nclass Factory:\n"
        source += "    __new__ = factory_new\n" if construction == "new_alias" else "    pass\n"
        if construction == "new_assignment":
            source += "Factory.__new__ = factory_new\n"
        elif construction == "new_setattr":
            source += "setattr(Factory, '__new__', factory_new)\n"
        elif construction == "dynamic_hook":
            source += ("def configure_hook(name):\n    setattr(Factory, name, factory_new)\n"
                       "configure_hook('__new__')\n")
    if route == "call":
        source += "Factory().build = python_argv\n"
    elif route == "local":
        source += "def configure():\n    instance = Factory()\n    instance.build = python_argv\nconfigure()\n"
    else:
        source += "Constructor = Factory\n" if route == "constructor_alias" else ""
        source += "instance = " + ("Constructor" if route == "constructor_alias" else "Factory") + "()\n"
        target = "instance"
        if route in {"alias", "chain"}:
            source += "alias = instance\n"
            target = "alias"
        if route == "chain":
            source += "again = alias\n"
            target = "again"
        source += target + ".build = python_argv\n"
    source += "runner.launch(sys.argv[1])\n"
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("construction", [
    "plain", "inherited", "explicit_type", "type_alias", "builtin_base", "custom_init",
    "unrelated_hook", "ordinary_class_mutation",
])
@pytest.mark.parametrize("route", ["module", "local", "alias"])
@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round31_proven_constructors_keep_unrelated_owners(tmp_path, construction, route, entry):
    source = ("import subprocess\nclass Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n")
    if construction == "inherited":
        source += "class Parent:\n    pass\nclass Other(Parent):\n    pass\n"
    elif construction == "explicit_type":
        source += "class Other(metaclass=type):\n    pass\n"
    elif construction == "type_alias":
        source += "Meta = type\nclass Other(metaclass=Meta):\n    pass\n"
    elif construction == "builtin_base":
        source += "class Other(list):\n    pass\n"
    elif construction == "custom_init":
        source += "class Other:\n    def __init__(self):\n        self.marker = None\n"
    else:
        source += "class Other:\n    pass\n"
    if construction == "unrelated_hook":
        source += "class Factory:\n    def __new__(cls):\n        return Runner()\n"
    elif construction == "ordinary_class_mutation":
        source += "setattr(Other, 'marker', None)\n"
    if route == "local":
        source += "def configure():\n    instance = Other()\n    instance.build = None\nconfigure()\n"
    elif route == "alias":
        source += "instance = Other()\nalias = instance\nalias.build = None\n"
    else:
        source += "instance = Other()\ninstance.build = None\n"
    round30_launch_outcome(tmp_path, source, entry, review=False)


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round31_new_can_return_a_fresh_runner(tmp_path, entry):
    source = ("import subprocess, sys\nP = \"import os; os.system('id')\"\n"
              "def python_argv(flag):\n    return [sys.executable, flag, P]\n"
              "class Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n"
              "class Factory:\n    def __new__(cls):\n        return Runner()\n"
              "obj = Factory()\nobj.build = python_argv\nobj.launch(sys.argv[1])\n")
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round31_constructor_proof_bound_requires_review(tmp_path, entry):
    source = ("import subprocess, sys\ndef python_argv(flag):\n    return [sys.executable, flag, 'pass']\n"
              "class Runner:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n"
              "class Base0:\n    pass\n")
    for index in range(1, _MAX_DEPTH + 1):
        source += "class Base" + str(index) + "(Base" + str(index - 1) + "):\n    pass\n"
    source += "instance = Base" + str(_MAX_DEPTH) + "()\ninstance.build = python_argv\n"
    round30_launch_outcome(tmp_path, source, entry, review=True)


@pytest.mark.parametrize("entry", ["selector", "refusal", "inventory"])
def test_round31_hook_write_through_unproven_class_alias_is_unknown(tmp_path, entry):
    source = ("import subprocess, sys\ndef python_argv(flag):\n    return [sys.executable, flag, 'pass']\n"
              "class Victim:\n    def build(self, flag):\n        return ['echo', flag]\n"
              "    def launch(self, flag):\n        subprocess.run(self.build(flag))\n"
              "class Runner:\n    pass\ndef redirect(cls):\n    return Runner\n"
              "class Holder:\n    @redirect\n    class Factory:\n        pass\n"
              "def factory_new(cls):\n    return Victim()\n"
              "Holder.Factory.__new__ = factory_new\nobj = Runner()\nobj.build = python_argv\n"
              "obj.launch(sys.argv[1])\n")
    round30_launch_outcome(tmp_path, source, entry, review=True)


# Exact nested-spawn counts. One normalized argv is the only command reading.
# A construction is omitted only for one simple function binding whose every
# load is a raw spawn of that same closed program. Every other shape stays
# counted, so module bindings and fragments can add an occurrence.
# Explicit None selects the argv head and is distinct from an unresolved name.
_EXACT_PROGRAM = "import os; os.system('id')"
_EXACT_SHELL = "python3 -c " + repr(_EXACT_PROGRAM)


def _exact_source(template):
    return template.replace("__PROGRAM__", repr(_EXACT_PROGRAM)).replace("__SHELL__", repr(_EXACT_SHELL))


def _exact_sites(tmp_path, files, rows):
    """Retry the census; a second read of the same tree must match the first."""
    package = tmp_path / "aegis_core"
    package.mkdir(exist_ok=True)
    for name, template in files.items():
        (package / name).write_text(_exact_source(template), encoding="utf-8")
    table = tuple((rel, owner, "resolved-python-program", "Test-owned exact nested spawn count.")
                  for rel, owner in rows)
    first = process_sites(tmp_path, selector_table=table)
    second = process_sites(tmp_path, selector_table=table)
    assert first == second
    return first


def _exact_system(sites):
    return {key: lines for key, lines in sites.items() if key.endswith(":os.system")}


def _exact_owners(sites):
    return {key.split(":")[1] + ":" + key.split(":")[2].split(".<literal", 1)[0]
            for key in _exact_system(sites)}


_FRAGMENT_CALLS = (
    ("run", "subprocess.run", "subprocess.run(__FRAG__, executable=sys.executable)"),
    ("popen", "subprocess.Popen", "subprocess.Popen(__FRAG__, executable=sys.executable)"),
    ("call", "subprocess.call", "subprocess.call(__FRAG__, executable=sys.executable)"),
    ("check-call", "subprocess.check_call", "subprocess.check_call(__FRAG__, executable=sys.executable)"),
    ("check-output", "subprocess.check_output", "subprocess.check_output(__FRAG__, executable=sys.executable)"),
    ("execv", "os.execv", "os.execv(sys.executable, __FRAG__)"),
    ("execve", "os.execve", "os.execve(sys.executable, __FRAG__, {})"),
    ("spawnv", "os.spawnv", "os.spawnv(os.P_WAIT, sys.executable, __FRAG__)"),
    ("spawnve", "os.spawnve", "os.spawnve(os.P_WAIT, sys.executable, __FRAG__, {})"),
    ("spawnvp", "os.spawnvp", "os.spawnvp(os.P_WAIT, sys.executable, __FRAG__)"),
    ("spawnvpe", "os.spawnvpe", "os.spawnvpe(os.P_WAIT, sys.executable, __FRAG__, {})"),
    ("posix-spawn", "os.posix_spawn", "os.posix_spawn(sys.executable, __FRAG__, None, None)"),
    ("posix-spawnp", "os.posix_spawnp", "os.posix_spawnp(sys.executable, __FRAG__, None, None)"),
    ("execv-path", "os.execv", "os.execv(path=sys.executable, argv=__FRAG__)"),
    ("spawnv-path", "os.spawnv", "os.spawnv(mode=os.P_WAIT, path=sys.executable, argv=__FRAG__)"),
    ("posix-path", "os.posix_spawn", "os.posix_spawn(path=sys.executable, argv=__FRAG__, file_actions=None, attr=None)"),
    ("run-args", "subprocess.run", "subprocess.run(args=__FRAG__, executable=sys.executable)"),
)


@pytest.mark.parametrize("label,api,call", _FRAGMENT_CALLS, ids=[item[0] for item in _FRAGMENT_CALLS])
def test_literal_spawn_fragment_after_program_is_not_counted(tmp_path, label, api, call):
    """A normalized argv is the only command; words after the program are not a new spawn."""
    fragment = "[sys.executable, '-c', 'pass'] + ['sh', '-c', __PROGRAM__]"
    source = "import os, sys, subprocess\ndef launch():\n    " + call.replace("__FRAG__", fragment) + "\n"
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _exact_system(sites) == {}, label
    assert sites["process:aegis_core/probe.py:launch:" + api] == [3]


_PRECISION_SHAPES = {
    "shlex-shell": {
        "files": {"probe.py": "import subprocess, sys, shlex\ndef launch():\n    subprocess.run(shlex.join([sys.executable, '-c', __PROGRAM__]), shell=True)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:launch"},
    },
    "execv-shlex": {
        "files": {"probe.py": "import os, sys, shlex\ndef launch():\n    os.execv('/bin/sh', ['sh', '-c', shlex.join([sys.executable, '-c', __PROGRAM__])])\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:launch"},
    },
    "rhs-sublist": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    subprocess.run(['worker', 'script.py'] + ['arg1', '-c', __PROGRAM__], executable=sys.executable)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:launch"},
        "outer": ("aegis_core/probe.py", "launch", "subprocess.run"),
    },
    "quoted-executable": {
        "files": {"probe.py": "import subprocess, sys, shlex\nargv = [sys.executable, '-c', __PROGRAM__, shlex.quote('x')]\ndef launch():\n    subprocess.run(argv, executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "quoted-shell": {
        "files": {"probe.py": "import subprocess, sys, shlex\nargv = [sys.executable, '-c', __PROGRAM__, shlex.quote('x')]\ndef launch():\n    subprocess.run(argv, shell=True)\n"},
        "rows": (("aegis_core/probe.py", "<module>"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "escape-list": {
        "files": {"probe.py": "import subprocess, sys\nargv = [sys.executable, '-c', __PROGRAM__]\ndef launch():\n    subprocess.run(argv, executable='/bin/sh')\n    subprocess.run(list(argv))\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "builder-return": {
        "files": {"probe.py": "import subprocess, sys\nARGV = [sys.executable, '-c', __PROGRAM__]\ndef probe():\n    subprocess.run(ARGV, executable='/bin/sh')\ndef build():\n    return ARGV\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "probe")),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "builder-annotation": {
        "files": {"probe.py": "import subprocess, sys\nARGV: list = [sys.executable, '-c', __PROGRAM__]\ndef probe():\n    subprocess.run(ARGV, executable='/bin/sh')\ndef build():\n    return ARGV\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "probe")),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "return-and-run": {
        "files": {"probe.py": "import subprocess, sys\nARGV = [sys.executable, '-c', __PROGRAM__]\ndef build():\n    return ARGV\ndef launch():\n    subprocess.run(ARGV)\n"},
        "rows": (("aegis_core/probe.py", "<module>"),),
        "count": 2,
        "owners": {"aegis_core/probe.py:<module>", "aegis_core/probe.py:launch"},
    },
    "none-name": {
        "files": {"probe.py": "import subprocess\nEXEC = None\ndef launch():\n    subprocess.run(['sh', '-ec', __SHELL__], executable=EXEC)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:launch"},
    },
    "none-conditional": {
        "files": {"probe.py": "import subprocess\ndef launch(cond):\n    EXEC = None if cond else 'sh'\n    subprocess.run(['sh', '-c', __SHELL__], executable=EXEC)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:launch"},
    },
    "none-staged": {
        "files": {"probe.py": "import subprocess\nEXEC = None\nARGV = ['sh', '-ec', __SHELL__]\ndef a():\n    subprocess.run(ARGV, executable=EXEC)\ndef b():\n    subprocess.run(ARGV, executable=EXEC)\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "a"), ("aegis_core/probe.py", "b")),
        "count": 3,
        "owners": {"aegis_core/probe.py:<module>", "aegis_core/probe.py:a", "aegis_core/probe.py:b"},
    },
    "star-under-shell": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    subprocess.run([sys.executable, *['-I', '-c', __SHELL__]], executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 0,
        "owners": set(),
    },
    "plus-under-shell": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    subprocess.run([sys.executable] + ['-I', '-c', __SHELL__], executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 0,
        "owners": set(),
    },
    "star-under-python": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    subprocess.run(['/bin/sh', '-e', *['-I', '-c', __PROGRAM__]], executable=sys.executable)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:launch"},
    },
    "tail-under-shell": {
        "files": {"probe.py": "import subprocess, sys\nARGV = [sys.executable, '-c', __PROGRAM__]\ndef launch(extra):\n    subprocess.run([*ARGV, extra], executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "tail-plus-under-shell": {
        "files": {"probe.py": "import subprocess, sys\nARGV = [sys.executable, '-c', __PROGRAM__]\ndef launch(extra):\n    subprocess.run(ARGV + [extra], executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "tail-shell-mode": {
        "files": {"probe.py": "import subprocess, sys\nARGV = [sys.executable, '-c', __PROGRAM__]\ndef launch(extra):\n    subprocess.run([*ARGV, extra], shell=True)\n"},
        "rows": (("aegis_core/probe.py", "<module>"),),
        "count": 1,
        "owners": {"aegis_core/probe.py:<module>"},
    },
    "tail-under-python": {
        "files": {"probe.py": "import subprocess, sys\nARGV = [sys.executable, '-c', __PROGRAM__]\ndef launch(extra):\n    subprocess.run([*ARGV, extra], executable=sys.executable)\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 2,
        "owners": {"aegis_core/probe.py:<module>", "aegis_core/probe.py:launch"},
    },
    "constant-prefix": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    subprocess.run([sys.executable, '-c', __PROGRAM__] + ['extra'])\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "count": 2,
        "owners": {"aegis_core/probe.py:launch"},
    },
    "cross-return": {
        "files": {
            "shared.py": "import sys\nARGV = (sys.executable, '-c', __PROGRAM__)\ndef build():\n    return ARGV\n",
            "probe.py": "import subprocess\nfrom aegis_core.shared import ARGV\ndef launch():\n    subprocess.run(ARGV, executable='/bin/sh')\n",
        },
        "rows": (("aegis_core/shared.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 1,
        "owners": {"aegis_core/shared.py:<module>"},
    },
    "cross-consumed": {
        "files": {
            "shared.py": "import sys\nARGV = (sys.executable, '-c', __PROGRAM__)\n",
            "probe.py": "import subprocess\nfrom aegis_core.shared import ARGV\ndef launch():\n    subprocess.run(ARGV, executable='/bin/sh')\n",
        },
        "rows": (("aegis_core/shared.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "count": 1,
        "owners": {"aegis_core/shared.py:<module>"},
        "outer": ("aegis_core/probe.py", "launch", "subprocess.run"),
    },
}


@pytest.mark.parametrize("label", sorted(_PRECISION_SHAPES))
def test_literal_spawn_count_precision_shapes(tmp_path, label):
    """Unproven constructions stay counted; a shell override does not erase them."""
    case = _PRECISION_SHAPES[label]
    sites = _exact_sites(tmp_path, case["files"], case["rows"])
    found = _exact_system(sites)
    assert sum(len(lines) for lines in found.values()) == case["count"]
    assert _exact_owners(sites) == case["owners"]
    outer = case.get("outer")
    if outer is not None:
        rel, scope, api = outer
        assert sites["process:" + rel + ":" + scope + ":" + api]


@pytest.mark.parametrize("body,reviewed_count", [
    ("def launch(flag):\n    subprocess.run([sys.executable, flag, '-c', __PROGRAM__])\n", 0),
    ("def launch(executable):\n    subprocess.run(['sh', '-ec', __SHELL__], executable=executable)\n    subprocess.run(['sh', '-ec', __SHELL__], executable=executable)\n", 0),
])
def test_literal_spawn_count_precision_unresolved_refuses(tmp_path, body, reviewed_count):
    """An unresolved option or executable is refused and does not invent a nested spawn."""
    source = "import subprocess, sys\n" + body
    package = tmp_path / "aegis_core"
    package.mkdir()
    (package / "probe.py").write_text(_exact_source(source), encoding="utf-8")
    expected = "unreviewed selector site aegis_core/probe.py:launch"
    for _ in range(2):
        with pytest.raises(ValueError) as error:
            process_sites(tmp_path)
        assert str(error.value) == expected
        assert _EXACT_PROGRAM not in str(error.value)
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert sum(len(lines) for lines in _exact_system(sites).values()) == reviewed_count
    assert len(sites["process:aegis_core/probe.py:launch:subprocess.run"]) == body.count("subprocess.run")


def test_literal_spawn_count_precision_concurrent_resolvers_match(tmp_path):
    """Each census builds its own resolver, so concurrent reads agree."""
    import threading
    case = _PRECISION_SHAPES["none-staged"]
    package = tmp_path / "aegis_core"
    package.mkdir()
    for name, template in case["files"].items():
        (package / name).write_text(_exact_source(template), encoding="utf-8")
    table = tuple((rel, owner, "resolved-python-program", "Test-owned exact nested spawn count.")
                  for rel, owner in case["rows"])
    results, errors = [], []

    def run():
        try:
            results.append(process_sites(tmp_path, selector_table=table))
        except Exception as exc:  # The thread must return the census refusal, not drop it.
            errors.append(exc)

    threads = [threading.Thread(target=run, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == 2 and results[0] == results[1]
    assert sum(len(lines) for lines in _exact_system(results[0]).values()) == 3
    assert _exact_owners(results[0]) == case["owners"]


# Formal 1121: a construction stays counted unless every load is a raw spawn
# of that same closed program. These shapes were erased by escape recognition.
def _deny_count(sites):
    return sum(len(lines) for lines in _exact_system(sites).values())


_DENY_CASES = {
    "starred-call": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    A = (sys.executable, '-c', __PROGRAM__)\n    subprocess.run(A, executable='/bin/sh')\n    subprocess.run(*[A])\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "list-forward": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    A = (sys.executable, '-c', __PROGRAM__)\n    B = A\n    subprocess.run(A, executable='/bin/sh')\n    subprocess.run(list(B))\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "assign-forward": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    A = (sys.executable, '-c', __PROGRAM__)\n    B = A\n    subprocess.run(B, executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "chained-assign": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    A = B = (sys.executable, '-c', __PROGRAM__)\n    subprocess.run(A, executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "cross-module": {
        "files": {
            "shared.py": "import sys\nARGV = (sys.executable, '-c', __PROGRAM__)\n",
            "probe.py": "import subprocess\nfrom aegis_core.shared import ARGV\ndef build():\n    return ARGV\ndef launch():\n    subprocess.run(ARGV, executable='/bin/sh')\n",
        },
        "rows": (("aegis_core/shared.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "minimum": 1,
        "owners": ("aegis_core/shared.py:<module>",),
    },
    "slice-copy": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    ARGV = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(ARGV, executable='/bin/sh')\n    subprocess.run(ARGV[:])\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "unpack-rebuild": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    ARGV = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(ARGV, executable='/bin/sh')\n    head, flag, code = ARGV\n    subprocess.run([head, flag, code])\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "ifexp-return": {
        "files": {"probe.py": "import subprocess, sys\ndef launch(cond):\n    ARGV = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(ARGV, executable='/bin/sh')\n    return ARGV if cond else []\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "lambda-load": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    ARGV = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(ARGV, executable='/bin/sh')\n    fn = lambda: ARGV\n    return fn\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "default-argument": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    ARGV = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(ARGV, executable='/bin/sh')\n    def inner(argv=ARGV):\n        return argv\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "executable-override": {
        "files": {"probe.py": "import subprocess, sys\ndef launch():\n    A = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(A, executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
    "opaque-prefix": {
        "files": {"probe.py": "import subprocess, sys\ndef launch(extra=()):\n    A = (sys.executable, '-c', __PROGRAM__)\n    subprocess.run(A + extra)\n    subprocess.run(A + extra)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 2,
    },
    "opaque-suffix": {
        "files": {"probe.py": "import subprocess, sys\ndef launch(extra=()):\n    A = (sys.executable, '-c', __PROGRAM__)\n    subprocess.run(extra + A)\n    subprocess.run(extra + A)\n"},
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 2,
    },
    "module-binding": {
        "files": {"probe.py": "import subprocess, sys\nA = (sys.executable, '-c', __PROGRAM__)\ndef launch():\n    subprocess.run(A, executable='/bin/sh')\n"},
        "rows": (("aegis_core/probe.py", "<module>"), ("aegis_core/probe.py", "launch")),
        "minimum": 1,
    },
    "imported-none": {
        "files": {
            "shared.py": "EXEC = None\n",
            "probe.py": "import subprocess\nfrom aegis_core.shared import EXEC\ndef launch():\n    subprocess.run(['sh', '-ec', __SHELL__], executable=EXEC)\n",
        },
        "rows": (("aegis_core/probe.py", "launch"),),
        "minimum": 1,
    },
}


@pytest.mark.parametrize("label", sorted(_DENY_CASES))
def test_literal_spawn_unproven_construction_stays_counted(tmp_path, label):
    """Shapes that are not a single direct raw spawn keep the nested program."""
    case = _DENY_CASES[label]
    sites = _exact_sites(tmp_path, case["files"], case["rows"])
    assert _deny_count(sites) >= case["minimum"], label
    for owner in case.get("owners", ()):
        assert owner in _exact_owners(sites), label


def test_literal_spawn_direct_function_binding_counts_once(tmp_path):
    """One function assignment used only as a raw spawn counts at the launch."""
    source = "import subprocess, sys\ndef launch():\n    argv = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(argv)\n"
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _deny_count(sites) == 1
    assert _exact_owners(sites) == {"aegis_core/probe.py:launch"}


def test_literal_spawn_direct_function_binding_keeps_each_launch(tmp_path):
    """Two raw launches of one proven binding stay two occurrences."""
    source = "import subprocess, sys\ndef launch():\n    argv = [sys.executable, '-c', __PROGRAM__]\n    subprocess.run(argv)\n    subprocess.run(argv)\n"
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _deny_count(sites) == 2
    assert _exact_owners(sites) == {"aegis_core/probe.py:launch"}


@pytest.mark.parametrize("assignment", [
    "argv = [sys.executable, '-c', __PROGRAM__, extra]",
    "argv = [sys.executable, '-c', __PROGRAM__] + []",
    "argv = [sys.executable, *['-c', __PROGRAM__]]",
    "argv: list = [sys.executable, '-c', __PROGRAM__]",
    "argv = [sys.executable, '-c', __PROGRAM__]\n    argv += []",
    "global argv\n    argv = [sys.executable, '-c', __PROGRAM__]",
])
def test_literal_spawn_consumption_requires_simple_closed_literal(tmp_path, assignment):
    source = ("import subprocess, sys\ndef launch(extra):\n    " + assignment
              + "\n    subprocess.run(argv)\n")
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _deny_count(sites) >= 2  # The construction and the launch both remain.


def test_literal_spawn_opaque_concat_keeps_partial_prefix(tmp_path):
    source = ("import subprocess, sys\ndef launch(extra, tail):\n"
              "    argv = [sys.executable, '-c', __PROGRAM__, extra]\n"
              "    subprocess.run(argv + tail)\n    subprocess.run(argv + tail)\n")
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _deny_count(sites) >= 3  # One construction and both launches.


def test_literal_spawn_ambiguous_raw_callee_keeps_construction(tmp_path):
    source = ("import sys\ndef launch(cond):\n"
              "    if cond:\n        import subprocess as runner\n"
              "    else:\n        import builtins as runner\n"
              "    argv = [sys.executable, '-c', __PROGRAM__]\n"
              "    runner.run(argv)\n")
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _deny_count(sites) == 2


@pytest.mark.parametrize("scope", ["module", "function"])
@pytest.mark.parametrize("literal", ["tuple", "list"])
@pytest.mark.parametrize("target,command", [
    ("head, flag, code", "[head, flag, code]"),
    ("[head, flag, code]", "[head, flag, code]"),
    ("head, flag, *code", "[head, flag, *code]"),
    ("[head, flag, *code]", "[head, flag, *code]"),
    ("(head, flag, code) = [other_head, other_flag, other_code]", "[head, flag, code]"),
    ("(head, flag, *code) = [other_head, other_flag, *other_code]", "[head, flag, *code]"),
], ids=["tuple-target", "list-target", "starred-tuple", "starred-list", "chained-unpack", "chained-starred"])
def test_literal_spawn_census_retains_direct_destructuring(tmp_path, scope, literal, target, command):
    """ROUND-3d: target shape cannot remove a literal before the consumption proof."""
    words = "sys.executable, '-c', __PROGRAM__"
    value = "(" + words + ")" if literal == "tuple" else "[" + words + "]"
    body = target + " = " + value + "\nsubprocess.run(" + command + ")\n"
    owner = "<module>" if scope == "module" else "launch"
    if scope == "function":
        body = "def launch():\n" + "".join("    " + line + "\n" for line in body.splitlines())
    source = "import subprocess, sys\n" + body
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", owner),))
    assert _deny_count(sites) == 1
    assert _exact_owners(sites) == {"aegis_core/probe.py:" + owner}
    assert len(sites["process:aegis_core/probe.py:" + owner + ":subprocess.run"]) == 1


@pytest.mark.parametrize("scope", ["module", "function"])
@pytest.mark.parametrize("literal", ["tuple", "list"])
def test_literal_spawn_census_retains_comparison_construction(tmp_path, scope, literal):
    """A comparison cannot bypass the only construction-removal gate either."""
    words = "sys.executable, '-c', __PROGRAM__"
    value = "(" + words + ")" if literal == "tuple" else "[" + words + "]"
    body = "same = " + value + " == expected\n"
    owner = "<module>" if scope == "module" else "launch"
    if scope == "function":
        body = "def launch(expected):\n    " + body
    source = "import sys\n" + body
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", owner),))
    assert _deny_count(sites) == 1
    assert _exact_owners(sites) == {"aegis_core/probe.py:" + owner}


@pytest.mark.parametrize("launches", [1, 2])
@pytest.mark.parametrize("route", ["direct", "reexport"])
@pytest.mark.parametrize("expression", [
    "(sys.executable, '-c', __PROGRAM__) + tuple(sys.argv[1:])",
    "tuple(sys.argv[1:]) + (sys.executable, '-c', __PROGRAM__)",
    "(sys.executable, '-c', __PROGRAM__) + tuple(sys.argv[1:]) + ('tail',)",
    "(sys.executable, '-c', __PROGRAM__, sys.argv[1]) + tuple(sys.argv[1:])",
], ids=["known-prefix", "known-suffix", "both-sides", "opaque-word"])
def test_literal_spawn_census_imported_opaque_concat_keeps_each_launch(tmp_path, launches, route, expression):
    """Partial immutable argv survives imports with its uncertainty and known words."""
    files = {"shared.py": "import sys\nARGV = " + expression + "\n"}
    provider = "shared"
    if route == "reexport":
        files["bridge.py"] = "from aegis_core.shared import ARGV\n"
        provider = "bridge"
    files["probe.py"] = ("import subprocess\nfrom aegis_core." + provider + " import ARGV\n"
                         "def launch():\n" + "    subprocess.run(ARGV)\n" * launches)
    rows = (("aegis_core/shared.py", "<module>"), ("aegis_core/probe.py", "launch"))
    sites = _exact_sites(tmp_path, files, rows)
    assert _deny_count(sites) == 1 + launches
    assert _exact_owners(sites) == {"aegis_core/shared.py:<module>", "aegis_core/probe.py:launch"}
    assert len(sites["process:aegis_core/probe.py:launch:subprocess.run"]) == launches


@pytest.mark.parametrize("route", ["local", "imported"])
@pytest.mark.parametrize("scope", ["module", "function"])
@pytest.mark.parametrize("target", ["plain", "tuple", "list", "starred", "chained"])
@pytest.mark.parametrize("rhs", ["tuple", "list"])
@pytest.mark.parametrize("shape", ["flat", "nested-empty", "nested-populated", "quoted-tail"])
def test_census_literal_construction_property(tmp_path, shape, rhs, target, scope, route):
    """Every generated program operand has exactly one construction event before consumption."""
    nested_program = _EXACT_PROGRAM + "; pass"
    nested_words = "sys.executable, '-c', " + repr(nested_program)
    tails = {"flat": ("'tail'",), "nested-empty": ("()", "[]"),
             "nested-populated": ("(" + nested_words + ")", "[" + nested_words + "]"),
             "quoted-tail": ("shlex.quote('tail')",)}[shape]
    targets = {"plain": "ARGV", "tuple": "(head, flag, code, tail)",
               "list": "[head, flag, code, tail]", "starred": "(head, flag, code, *tail)",
               "chained": "(head, flag, code, tail) = [other_head, other_flag, other_code, other_tail]"}
    command = "ARGV" if target == "plain" else "[head, flag, code]"
    for index, tail in enumerate(tails):
        root = tmp_path / ("variant_" + str(index))
        root.mkdir()
        words = "sys.executable, '-c', __PROGRAM__, " + tail
        literal = "(" + words + ")" if rhs == "tuple" else "[" + words + "]"
        assignment = targets[target] + " = " + literal + "\n"
        imports = "import subprocess, sys, shlex\n"
        provider = "probe.py" if route == "local" else "shared.py"
        owner = "<module>"
        if scope == "function":
            owner = "launch" if route == "local" else "build"
            body = assignment + ("subprocess.run(" + command + ")\n" if route == "local"
                                 else "return " + command + "\n")
            source = imports + "def " + owner + "():\n" + "".join("    " + line + "\n" for line in body.splitlines())
        else:
            source = imports + assignment
            if route == "local":
                source += "subprocess.run(" + command + ")\n"
        files, rows = {provider: source}, [("aegis_core/" + provider, owner)]
        if route == "imported":
            exports = "build" if scope == "function" else "ARGV" if target == "plain" else "head, flag, code"
            consumer = "build()" if scope == "function" else command
            files["probe.py"] = ("import subprocess\nfrom aegis_core.shared import " + exports
                                 + "\ndef launch():\n    subprocess.run(" + consumer + ")\n")
            if not (scope == "module" and target == "plain" and rhs == "tuple"):
                rows.append(("aegis_core/probe.py", "launch"))
        package = root / "aegis_core"
        package.mkdir()
        for name, text in files.items():
            (package / name).write_text(_exact_source(text), encoding="utf-8")
        modules = dict(module_trees(root))
        # The oracle comes from the generated syntax, independently of extraction:
        # each literal argv has its own third operand, even when nested in another argv.
        expected = Counter((rel, node.elts[2].lineno, node.elts[2].col_offset, node.elts[2].value)
                           for rel, tree in modules.items() for node in ast.walk(tree)
                           if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) >= 3
                           and isinstance(node.elts[1], ast.Constant) and node.elts[1].value == "-c"
                           and isinstance(node.elts[2], ast.Constant)
                           and node.elts[2].value in {_EXACT_PROGRAM, nested_program})
        assert sum(expected.values()) == (2 if shape == "nested-populated" else 1)
        resolver = CommandResolver(modules)
        actual = Counter((rel, node.lineno, node.col_offset, program)
                         for rel in modules
                         for node, program, origins, launch in resolver.programs(rel, with_locations=True)
                         if not launch and isinstance(program, str))
        assert actual == expected
        sites = _exact_sites(root, files, rows)
        launched = int(target == "plain" and (route == "local" or scope == "module" and rhs == "tuple"))
        consumed = int(route == "local" and scope == "function" and target == "plain" and shape == "flat")
        assert _deny_count(sites) == sum(expected.values()) + launched - consumed


def test_census_formal_1531_destructured_empty_metadata(tmp_path):
    source = ("import subprocess, sys\ndef launch():\n"
              "    head, flag, code, unused = (sys.executable, '-c', __PROGRAM__, ())\n"
              "    subprocess.run([head, flag, code])\n")
    sites = _exact_sites(tmp_path, {"probe.py": source}, (("aegis_core/probe.py", "launch"),))
    assert _deny_count(sites) == 1


@pytest.mark.parametrize("route", ["direct", "reexport", "attribute"])
@pytest.mark.parametrize("opaque", [False, True])
@pytest.mark.parametrize("launches", [1, 2])
def test_census_formal_1531_imported_quoted_tail(tmp_path, route, opaque, launches):
    expression = "(sys.executable, '-c', __PROGRAM__, shlex.quote('x'))"
    if opaque:
        expression += " + tuple(sys.argv[1:])"
    files = {"shared.py": "import sys, shlex\nARGV = " + expression + "\n"}
    if route == "attribute":
        declaration, command = "from aegis_core import shared", "shared.ARGV"
    else:
        provider = "shared"
        if route == "reexport":
            files["bridge.py"] = "from aegis_core.shared import ARGV\n"
            provider = "bridge"
        declaration, command = "from aegis_core." + provider + " import ARGV", "ARGV"
    files["probe.py"] = ("import subprocess\n" + declaration + "\ndef launch():\n"
                         + ("    subprocess.run(" + command + ")\n") * launches)
    rows = [("aegis_core/shared.py", "<module>")]
    if opaque:
        rows.append(("aegis_core/probe.py", "launch"))
    sites = _exact_sites(tmp_path, files, rows)
    assert _deny_count(sites) == 1 + launches
    assert _exact_owners(sites) == {"aegis_core/shared.py:<module>", "aegis_core/probe.py:launch"}
