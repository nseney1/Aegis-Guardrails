"""The import boundary (ADR 0005 AD-3, D9): a layered core and thin adapters.

Every import in the four packages is read from the source (AST: module level, inside
functions, under TYPE_CHECKING, and constant-string ``__import__``/``import_module``
calls) and checked against the table below:

- **aegis_core** imports nothing from aegis_cli, aegis_mcp or aegis_sdk. Inside it each
  module belongs to one layer and imports only its own layer or a lower one:
  - L0 primitives: storage (atomic I/O, the lock), gitsafe, config, the workspace and
    its layout, and the leaf tables (errors, taxonomy, _version), which import no
    aegis module at all;
  - L1 domain: the rule schema and loader (rules, rule_inventory, yaml_engine), the
    matcher, the ledger (telemetry_engine), fitness, the AST layer and its tool
    slots, command safety;
  - L2 services: scan, sync, lifecycle, migrate, metrics, outcomes, verification and
    its Layer-2 command backend.
- **aegis_cli** and **aegis_mcp** are adapters: they import aegis_core and themselves,
  never each other and never aegis_sdk.
- **aegis_sdk** is the external facade: it imports aegis_core and itself only.
- Everything else imported is the standard library (zero runtime dependencies).

A new aegis_core module fails here until it is given a layer in CORE_LAYERS.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

import pytest

from aegis_core.verification.import_guard import is_stdlib

REPO = Path(__file__).resolve().parents[2]
PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk")

# Module (or package prefix) -> layer. The longest matching prefix wins. The package's
# own __init__ (version only) is L0; it is not a prefix, so a new module has no layer.
CORE_LAYERS: Dict[str, int] = {
    "aegis_core._version": 0,
    "aegis_core.errors": 0,
    "aegis_core.taxonomy": 0,
    # Pure data, no aegis imports: the host table and the bootstrap text.
    "aegis_core.hosts": 0,
    "aegis_core.bootstrap": 0,
    "aegis_core.storage": 0,
    "aegis_core.gitsafe": 0,
    "aegis_core.atomicio": 0,
    # Read-only repository facts keyed by full object ids; imports gitsafe and errors only.
    "aegis_core.gitevidence": 0,
    # The one PATH lookup of a program Aegis runs or registers (stdlib only).
    "aegis_core.pathlookup": 0,
    # GitHub CLI transport over gitsafe and pathlookup, with no trust-policy dependency.
    "aegis_core.ghcli": 0,
    # Path containment, strict JSON and UTC timestamps (stdlib only).
    "aegis_core.primitives": 0,
    "aegis_core.config": 0,
    # The events log (prune metrics): storage and gitsafe only, so any layer may record.
    "aegis_core.events": 0,
    "aegis_core.stats": 0,
    "aegis_core.workspace": 0,
    "aegis_core.rules": 1,
    "aegis_core.rule_inventory": 1,
    "aegis_core.yaml_engine": 1,
    "aegis_core.match": 1,
    "aegis_core.telemetry_engine": 1,
    "aegis_core.fitness": 1,
    "aegis_core.ast": 1,
    "aegis_core.skills": 1,
    "aegis_core.command_safety": 1,
    # Team leases and team.json: gitsafe, config, events and the matcher.
    "aegis_core.team": 1,
    # Host hook payload normalization (stdlib only).
    "aegis_core.hook_events": 1,
    # The post-lane gate (aegis check --lane): team, the matcher, gitsafe and events.
    "aegis_core.lane_ast": 0,
    "aegis_core.lane_gate": 1,
    "aegis_core.scaffolding": 1,
    # The governance file set, CODEOWNERS coverage, and trust tiers / approvals over them.
    "aegis_core.governance": 1,
    "aegis_core.codeowners": 1,
    "aegis_core.human_gate": 1,
    # v4.3 verified checks: the tree identity (gitsafe, pathlookup), the credit state machine over the ledger
    # (ghcli, storage, gitsafe) and the hermetic run, which also runs Layer 1 (baseline).
    "aegis_core.treeid": 1,
    "aegis_core.credit": 1,
    "aegis_core.checkrun": 2,
    "aegis_core.testexec": 1,
    # GitHub ruleset administration uses the transport and trust-policy constants.
    "aegis_core.github_ruleset": 2,
    # v4.3 T3: rank 2+ rules served from the reviewed BASE (the loader, the inventory, gitsafe), under scan.
    "aegis_core.adjudication": 1,
    "aegis_core.rule_integrity": 1,
    # v4.3 T2: `aegis doctor --release` (gitsafe, pathlookup, human_gate's tier); credit no longer verifies attestations.
    "aegis_core.release_verify": 1,
    # v4.3 T8: human insights closed loop (user-scope JSONL, redaction, cue detector, TF-IDF review, recurrence).
    "aegis_core.insights": 2,
    # v4.3 T5: fail-to-pass regression check (gitsafe, testexec's snapshot pytest runner, human_gate exemptions).
    "aegis_core.regression": 2,
    "aegis_core.scan": 2,
    "aegis_core.scan_compliance": 2,
    "aegis_core.sync": 2,
    "aegis_core.lifecycle": 2,
    "aegis_core.migrate": 2,
    "aegis_core.metrics": 2,
    "aegis_core.outcomes": 2,
    "aegis_core.verification": 2,
    "aegis_core.inference_provider": 2,
    # The v4.2 check modes: the ratchet baseline, the day-0 card and the partition report.
    "aegis_core.baseline": 2,
    "aegis_core.card": 3,
    "aegis_core.partition": 3,
    # Rule packs (rule export/import): the loader, migrate's stripper, the lifecycle's id checks and events.
    "aegis_core.packs": 2,
    # The benchmark: scan, Layer 1 and events over a fixture corpus it ships as package data.
    "aegis_core.benchmark": 2,
    # The Claude Code plugin dir (aegis package): pure builders plus an atomic writer over storage.
    "aegis_core.packaging": 1,
}
# Leaf tables: importable from anywhere because they import no aegis module.
CORE_LEAVES = ("aegis_core._version", "aegis_core.errors", "aegis_core.taxonomy")
# Which first-party packages each package may import (besides itself).
ALLOWED_PACKAGES: Dict[str, Sequence[str]] = {
    "aegis_core": (),
    "aegis_cli": ("aegis_core",),
    "aegis_mcp": ("aegis_core",),
    "aegis_sdk": ("aegis_core",),
}


class Edge(NamedTuple):
    source: str  # importing module
    target: str  # imported module (a submodule when `from pkg import submodule`)
    where: str  # path:line

    def __str__(self) -> str:
        return f"{self.where}: {self.source} -> {self.target}"


def _module_files(root: Path = REPO) -> Dict[str, Path]:
    modules: Dict[str, Path] = {}
    for package in PACKAGES:
        for path in sorted((root / package).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            parts = list(path.relative_to(root).with_suffix("").parts)
            is_package = parts[-1] == "__init__"
            if is_package:
                parts.pop()
            modules[".".join(parts)] = path
    return modules


def _string_import(node: ast.Call) -> Optional[str]:
    """The module of ``__import__("x")`` or ``importlib.import_module("x")``."""
    func = node.func
    named = (isinstance(func, ast.Name) and func.id == "__import__") or (
        isinstance(func, ast.Attribute) and func.attr == "import_module"
    )
    if named and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def import_edges(root: Path = REPO) -> List[Edge]:
    modules = _module_files(root)
    edges: List[Edge] = []
    for module, path in modules.items():
        is_package = path.name == "__init__.py"
        rel = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            targets: List[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = module.split(".") if is_package else module.split(".")[:-1]
                    base = base[: len(base) - (node.level - 1)]
                    package = ".".join(base + ([node.module] if node.module else []))
                else:
                    package = node.module or ""
                for alias in node.names:
                    submodule = f"{package}.{alias.name}"
                    targets.append(submodule if submodule in modules else package)
            elif isinstance(node, ast.Call):
                name = _string_import(node)
                targets = [name] if name else []
            edges.extend(Edge(module, target, f"{rel}:{node.lineno}") for target in targets)
    return edges


def core_layer(module: str) -> Optional[int]:
    if module == "aegis_core":
        return 0
    best = None
    for prefix, layer in CORE_LAYERS.items():
        if (module == prefix or module.startswith(prefix + ".")) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, layer)
    return None if best is None else best[1]


def _top(module: str) -> str:
    return module.split(".")[0]


def boundary_violations(edges: Sequence[Edge]) -> List[str]:
    found: List[str] = []
    for edge in edges:
        source_pkg, target_pkg = _top(edge.source), _top(edge.target)
        if target_pkg not in PACKAGES:
            continue
        if target_pkg != source_pkg and target_pkg not in ALLOWED_PACKAGES[source_pkg]:
            found.append(f"{edge}: {source_pkg} may not import {target_pkg}")
        elif source_pkg == target_pkg == "aegis_core":
            source_layer, target_layer = core_layer(edge.source), core_layer(edge.target)
            if source_layer is not None and target_layer is not None and target_layer > source_layer:
                found.append(f"{edge}: L{source_layer} imports L{target_layer}")
            if any(edge.source == leaf or edge.source.startswith(leaf + ".") for leaf in CORE_LEAVES):
                found.append(f"{edge}: {edge.source} is a leaf table and imports no aegis module")
    return found


def third_party_imports(edges: Sequence[Edge]) -> List[str]:
    return [
        f"{edge}: not the standard library"
        for edge in edges
        if _top(edge.target) not in PACKAGES and not is_stdlib(_top(edge.target))
    ]


@pytest.fixture(scope="module")
def edges() -> List[Edge]:
    return import_edges()


def test_the_graph_sees_lazy_relative_and_string_imports(edges):
    """Guard against a parser that silently sees nothing."""
    pairs = {(edge.source, edge.target) for edge in edges}
    assert ("aegis_mcp.server", "aegis_mcp.registry") in pairs  # relative import
    assert ("aegis_core.workspace.hooks", "aegis_core.gitsafe") in pairs  # lazy, `from pkg import module`
    assert ("aegis_cli.cli", "aegis_core.workspace.layout") in pairs


def test_every_core_module_has_a_layer():
    unplaced = sorted(m for m in _module_files() if _top(m) == "aegis_core" and core_layer(m) is None)
    assert unplaced == [], f"give these modules a layer in CORE_LAYERS: {unplaced}"


def test_the_layer_table_names_only_existing_modules():
    modules = set(_module_files())
    stale = sorted(p for p in CORE_LAYERS if not any(m == p or m.startswith(p + ".") for m in modules))
    assert stale == [], f"CORE_LAYERS names modules that no longer exist: {stale}"


def test_imports_respect_the_package_and_layer_boundaries(edges):
    violations = boundary_violations(edges)
    assert violations == [], "import boundary violations (ADR 0005 AD-3):\n" + "\n".join(violations)


def test_checkrun_does_not_import_regression(edges):
    """R-evidence-30: T5's snapshot runner is testexec.run_pytest_snapshot; checkrun never imports regression."""
    assert [e for e in edges if e.source == "aegis_core.checkrun" and e.target == "aegis_core.regression"] == []


def test_runtime_imports_only_the_standard_library(edges):
    offenders = third_party_imports(edges)
    assert offenders == [], "runtime dependencies are not allowed:\n" + "\n".join(offenders)


# The checker itself, on edges that would break each rule.
@pytest.mark.parametrize(
    "source,target",
    [
        ("aegis_core.scan", "aegis_cli.cli"),
        ("aegis_core.rules", "aegis_sdk"),
        ("aegis_core.config", "aegis_mcp.server"),
        ("aegis_cli.init", "aegis_mcp.server"),
        ("aegis_mcp.tools", "aegis_cli.rule"),
        ("aegis_cli.status", "aegis_sdk.governance"),
        ("aegis_mcp.server", "aegis_sdk"),
        ("aegis_sdk.governance", "aegis_cli.registry"),
        ("aegis_core.storage", "aegis_core.rules"),  # L0 -> L1
        ("aegis_core.workspace.base", "aegis_core.rules"),  # L0 -> L1
        ("aegis_core.rules", "aegis_core.migrate"),  # L1 -> L2
        ("aegis_core.match", "aegis_core.scan"),  # L1 -> L2
        ("aegis_core.taxonomy", "aegis_core.errors"),  # a leaf imports nothing
    ],
)
def test_the_checker_rejects(source, target):
    assert boundary_violations([Edge(source, target, "x.py:1")]) != []


@pytest.mark.parametrize(
    "source,target",
    [
        ("aegis_cli.rule", "aegis_core.lifecycle.promotion"),
        ("aegis_mcp.handlers.core", "aegis_core.scan"),
        ("aegis_sdk.governance", "aegis_core.metrics"),
        ("aegis_core.scan", "aegis_core.sync"),  # L2 -> L2
        ("aegis_core.rules", "aegis_core.taxonomy"),  # L1 -> L0
        ("aegis_core.storage", "aegis_core.workspace.layout"),  # L0 -> L0
        ("aegis_cli.cli", "argparse"),
    ],
)
def test_the_checker_accepts(source, target):
    assert boundary_violations([Edge(source, target, "x.py:1")]) == []


def test_the_checker_flags_third_party_imports():
    assert third_party_imports([Edge("aegis_core.rules", "yaml", "x.py:1")]) != []
    assert third_party_imports([Edge("aegis_core.rules", "json", "x.py:1")]) == []
