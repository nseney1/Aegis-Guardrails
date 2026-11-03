"""What the wheel and sdist ship for `aegis init` names only files that exist, and only
under Aegis's own package names.

The starter rules moved from ``aegis_cli/starter_rules/`` to the repository's ``rules/``
(defense #20, one rule-source locator). v4.0.0 then shipped ``rules/`` and ``skills/`` as
top-level packages named ``rules`` and ``skills``: pip overwrote another distribution's
``rules`` package with them, and a repository's own ``rules/`` shadowed them (release
review, packaging). The repository keeps both directories as the sources, and
``[tool.setuptools.package-dir]`` maps them into ``aegis_core/_data/`` in the wheel.
The package-data table is parsed as TOML so multiline glob arrays are checked.
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11, where pytest itself depends on tomli
    import tomli as tomllib

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
AEGIS_PACKAGES = ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk")


def _pyproject() -> str:
    return (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _table(name: str) -> str:
    section = re.search(rf"(?ms)^\[{re.escape(name)}\]\n(.*?)(?=^\[|\Z)", _pyproject())
    assert section, f"pyproject.toml has no [{name}] table"
    return section.group(1)


def _strings(text: str) -> list:
    return re.findall(r'"([^"]+)"', text)


def _package_data() -> dict:
    return tomllib.loads(_pyproject())["tool"]["setuptools"]["package-data"]


def _package_dir() -> dict:
    return dict(re.findall(r'(?m)^"?([A-Za-z0-9_.]+)"?\s*=\s*"([^"]+)"', _table("tool.setuptools.package-dir")))


def _packages() -> list:
    block = re.search(r"(?ms)^packages\s*=\s*\[(.*?)\]", _table("tool.setuptools"))
    assert block, "[tool.setuptools] lists no packages"
    return _strings(block.group(1))


def _source(package: str) -> Path:
    """Where a package's files are in the checkout, through package-dir."""
    mapped = _package_dir().get(package)
    return REPO_ROOT / mapped if mapped else REPO_ROOT.joinpath(*package.split("."))


def test_every_package_data_glob_matches_a_file():
    entries = _package_data()
    assert entries, "no package-data entries parsed"
    for package, globs in entries.items():
        for pattern in globs:
            assert any(p.is_file() for p in _source(package).glob(pattern)), f"{package}: {pattern!r} matches no file"


def test_the_wheel_installs_only_aegis_named_top_level_packages():
    tops = {name.split(".")[0] for name in _packages()}
    assert tops == set(AEGIS_PACKAGES)
    assert "packages.find" not in _pyproject()


def test_the_shipped_rules_and_skills_map_into_aegis_core_from_the_repository_root():
    assert _package_dir() == {"aegis_core._data.rules": "rules", "aegis_core._data.skills": "skills"}
    assert _package_data()["aegis_core._data.rules"] == ["*.md", ".oracles/*.md"]
    assert _package_data()["aegis_core._data.skills"] == ["*/SKILL.md"]
    # The checkout has no aegis_core/_data: a stale copy there would shadow the sources.
    assert not (REPO_ROOT / "aegis_core" / "_data").exists()


def test_the_package_list_names_every_python_package_in_the_checkout():
    """The list is explicit (package-dir needs it); a new subpackage left off it would be
    missing from the wheel while every test that imports from the checkout still passes."""
    found = set()
    for top in AEGIS_PACKAGES:
        for init in (REPO_ROOT / top).rglob("__init__.py"):
            if "__pycache__" not in init.parts:
                found.add(".".join(init.parent.relative_to(REPO_ROOT).parts))
    listed = set(_packages())
    assert listed - found == {"aegis_core._data.rules", "aegis_core._data.skills"}
    assert found - listed == set()


def test_every_manifest_include_names_an_existing_directory():
    lines = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    for line in lines:
        words = line.split()
        if words and words[0] in ("recursive-include", "graft"):
            assert (REPO_ROOT / words[1]).is_dir(), line


def test_the_sdist_carries_the_rules_and_skills_sources():
    lines = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    # package-dir maps the wheel's aegis_core/_data/ from these, so a wheel built from the
    # sdist needs them.
    assert "recursive-include rules *" in lines and "recursive-include skills *" in lines


def test_the_retired_starter_rules_directory_is_named_nowhere_in_packaging():
    for name in ("pyproject.toml", "MANIFEST.in"):
        assert "starter_rules" not in (REPO_ROOT / name).read_text(encoding="utf-8"), name
