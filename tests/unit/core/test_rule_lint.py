"""One table-driven lint over every shipped and workspace rule (defense #41).

It runs the production parser (the one ``aegis_sdk.parse_rule_file`` uses), not
a test-local regex. Shipped rules (rules/, rules/.oracles/) are loaded by host
rule loaders, so they carry the host contract; workspace rules
(.aegis/rules/<type>/) are served by aegis_scan, so they carry the type schema.
"""
from __future__ import annotations

import ast
import functools
import glob
import os
import re
from pathlib import Path

import pytest

from aegis_cli.init import install_rules
from aegis_core.lifecycle.constants import PROTECTED_RULES
from aegis_core.yaml_engine.frontmatter import parse_rule_frontmatter
from aegis_core.match import matching_files

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11, where pytest itself depends on tomli
    import tomli as tomllib

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())
SKIP = {"META.md", "README.md"}
DOMAINS = {"architecture", "correctness", "documentation", "efficiency", "governance",
           "portability", "security", "style", "testing"}
# type dir -> (type, required non-empty fields)
WORKSPACE = {"traps": ("trap", ("hypothesis", "target_paths")),
             "invariants": ("invariant", ("hypothesis",)),
             "boundaries": ("boundary", ("hypothesis",)),
             "personas": ("persona", ("hypothesis",)),
             "contracts": ("contract", ("hypothesis", "target_paths"))}
# D16: the author's own process rules govern this repository, not adopters'.
# shipped name -> workspace type (workspace ids carry the type prefix).
DOGFOOD = {"gitflow-review-gate": "invariant", "ci-green-before-release": "invariant",
           "core-change-protocol": "invariant", "no-pre-existing-excuse": "invariant",
           "optional-import-guard": "trap"}
# Ids that no installed rule may name: the dogfood rules plus desktop-automation,
# which is no longer shipped at all (D16).
UNSHIPPED = set(DOGFOOD) | {"desktop-automation"}
WALK_PRUNE = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".pytest_cache", "build", "dist"}


def _md(base: Path, pattern: str) -> list[Path]:
    return sorted(p for p in base.glob(pattern) if p.name not in SKIP)


CORE = _md(ROOT / "rules", "*.md") + _md(ROOT / "rules" / ".oracles", "*.md")
# Rules under a hidden directory (.archive) are out of service, as the loader treats them.
WS = [p for p in _md(ROOT / ".aegis" / "rules", "**/*.md")
      if not any(part.startswith(".") for part in p.relative_to(ROOT / ".aegis" / "rules").parts[:-1])]
ALL = CORE + WS
META = ROOT / "rules" / "META.md"


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def _parse(p: Path) -> tuple[dict, str]:
    try:
        fm, body = parse_rule_frontmatter(str(p))
    except Exception as exc:  # missing, unclosed or malformed frontmatter
        pytest.fail(f"{rel(p)}: unparseable frontmatter: {exc}")
    assert fm, f"{rel(p)}: empty frontmatter"
    return fm, body


def _fm_or_empty(p: Path) -> dict:
    try:
        return parse_rule_frontmatter(str(p))[0] or {}
    except Exception:
        return {}  # reported by the per-file tests, not as a collection error


@pytest.mark.parametrize("p", ALL, ids=rel)
def test_rule_id_matches_filename_domain_is_known_and_body_is_real(p):
    fm, body = _parse(p)
    assert fm.get("id") == p.stem, f"{rel(p)}: id {fm.get('id')!r} != filename stem"
    assert fm.get("domain") in DOMAINS, f"{rel(p)}: domain {fm.get('domain')!r} not allowed"
    assert len(body.strip()) > 50, f"{rel(p)}: body too short to be actionable"


def test_rule_ids_are_unique_across_shipped_and_workspace_rules():
    seen: dict[str, Path] = {}
    for p in ALL:
        rid = _parse(p)[0].get("id")
        assert rid not in seen, f"duplicate id {rid!r}: {rel(seen[rid])} and {rel(p)}"
        seen[rid] = p


@pytest.mark.parametrize("p", CORE + [META], ids=rel)
def test_shipped_rule_host_contract(p):
    fm, _ = _parse(p)
    assert fm.get("trigger") in ("always_on", "model_decision"), f"{rel(p)}: bad trigger"
    assert len(str(fm.get("description", "")).strip()) > 10, f"{rel(p)}: description too short"
    if p.parent.name == "rules" and p != META:
        assert "enforcement" in fm, f"{rel(p)}: missing enforcement"


def test_meta_bootstrap_stays_always_on():
    assert _parse(META)[0].get("trigger") == "always_on"


@pytest.mark.parametrize("p", WS, ids=rel)
def test_workspace_rule_type_schema(p):
    assert p.parent.name in WORKSPACE, f"{rel(p)}: not under a canonical type dir {sorted(WORKSPACE)}"
    rtype, required = WORKSPACE[p.parent.name]
    fm, _ = _parse(p)
    assert fm.get("type") == rtype, f"{rel(p)}: type {fm.get('type')!r}, expected {rtype!r}"
    for field in required:
        assert fm.get(field), f"{rel(p)}: missing or empty {field!r}"
    if rtype == "trap":
        assert "expiry_sessions" in fm or "expiry_days" in fm, f"{rel(p)}: trap has no expiry"
    if rtype == "invariant":
        assert fm.get("enforcement") == "gate", f"{rel(p)}: invariant must be gate"


# A served rule without target_paths applies to no file: scan and check never serve it.
# The set must shrink, never grow (invariant-test-canonical-colocality was retired to .archive/).
KNOWN_UNTARGETED: set = set()


def test_every_served_workspace_rule_applies_to_some_file():
    from aegis_core.rules import load_rules

    untargeted = {r.id for r in load_rules(ROOT).served if not r.target_paths}
    assert untargeted == KNOWN_UNTARGETED, "served rules without target_paths match no file; give them patterns"


_PATHS = [(p, t) for p in WS for t in (_fm_or_empty(p).get("target_paths") or []) if isinstance(t, str)]


@functools.lru_cache(maxsize=None)
def _repo_files() -> tuple[str, ...]:
    found = []
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in WALK_PRUNE and not x.endswith(".egg-info")]
        found.extend(Path(d, f).relative_to(ROOT).as_posix() for f in files)
    return tuple(found)


# A rule file outside the lane that moved its target is a strict xfail logged for the
# rules owner: retargeting the rule turns the xfail into a failure that removes the entry.
# The set must shrink, never grow.
KNOWN_DEAD_TARGETS: set = set()
_DEAD = pytest.mark.xfail(
    strict=True, reason="the docs wave moved this target; the rule file is outside lane f2 (retarget it)"
)


@pytest.mark.parametrize(
    "p,target",
    [pytest.param(p, t, marks=[_DEAD] if (p.name, t) in KNOWN_DEAD_TARGETS else []) for p, t in _PATHS],
    ids=[f"{p.name}:{t}" for p, t in _PATHS],
)
def test_target_paths_resolve(p, target):
    """Resolve with the one matcher every rule site uses (aegis_core.match), not glob:
    a pattern that matches no file is dead, and one that relied on the removed
    substring glob (a bare `src`) matches nothing now."""
    files = _repo_files()
    matched = set(matching_files([target], files))
    assert matched, f"{rel(p)}: {target!r} matches no file through aegis_core.match"
    named = {Path(x).relative_to(ROOT).as_posix() for x in glob.glob(str(ROOT / target), recursive=True)}
    missed = sorted((named & set(files)) - matched)
    assert not missed, f"{rel(p)}: {target!r} reads as a glob for {missed[:5]} but the scan matcher skips them"


@pytest.mark.parametrize("preset", ["minimal", "standard", "full"])
def test_installed_rules_name_no_unshipped_rule(preset, tmp_path):
    installed = install_rules(tmp_path, preset=preset)
    assert installed and not set(installed) & UNSHIPPED
    texts = {p.name: p.read_text(encoding="utf-8") for p in tmp_path.glob("*.md")}
    texts["META.md"] = META.read_text(encoding="utf-8")  # host loaders read META from the package
    hits = sorted(f"{name}: {rid}" for name, text in texts.items() for rid in UNSHIPPED if rid in text)
    assert hits == [], f"{preset} preset installs text naming rules it does not ship"


def test_unshipped_ids_agree_with_wheel_smoke():
    tree = ast.parse((ROOT / ".github" / "scripts" / "wheel_smoke.py").read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(getattr(t, "id", None) == "UNSHIPPED_RULES" for t in n.targets))
    assert set(ast.literal_eval(node.value)) == UNSHIPPED


def test_protected_rules_are_shipped_rules():
    assert PROTECTED_RULES <= {p.stem for p in CORE}


def test_dogfood_rules_are_workspace_rules_not_shipped():
    assert {f"{rtype}-{name}" for name, rtype in DOGFOOD.items()} <= {p.stem for p in WS}
    assert not set(DOGFOOD) & {p.stem for p in CORE}


def _table(text: str, header: str) -> set[str]:
    """Package names in the markdown table under ``## <header>`` ("`yaml` (pyyaml)" -> pyyaml)."""
    section = re.search(rf"^## {re.escape(header)}[^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    rows = [r for r in (section.group(1) if section else "").splitlines() if r.startswith("|") and "---" not in r]
    cells = [r.split("|")[1].strip() for r in rows[1:]]  # rows[0] is the header row
    return {(re.search(r"\((\w+)\)", c) or re.match(r"`?([\w-]+)", c)).group(1).lower() for c in cells}


def test_optional_import_guard_tables_match_pyproject():
    found = [p for p in ALL if p.stem == "trap-optional-import-guard"]
    assert len(found) == 1, f"expected one optional-import-guard rule, found {found}"
    oracle = found[0].read_text(encoding="utf-8")
    with open(ROOT / "pyproject.toml", "rb") as f:
        deps = {re.split(r"[><=!~\[ ;]", d)[0].lower() for d in tomllib.load(f)["project"]["dependencies"]}
    assert deps == set(), "Aegis has zero runtime dependencies"
    assert _table(oracle, "Required Dependencies") <= deps
    assert not _table(oracle, "Known Optional Dependencies") & deps
