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

import fnmatch
from importlib import resources
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile

import pytest

from tests.conftest import symlink_or_skip

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11, where pytest itself depends on tomli
    import tomli as tomllib

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").is_file())
AEGIS_PACKAGES = ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk")
TEMPLATE_PACKAGE = "aegis_core.team_templates"
TEMPLATE_PATH = "aegis_core/team_templates"
TEMPLATE_FIXTURES = {
    ".root-template.md",
    "roles/.nested-template.md",
    ".profiles/layer/nested-template.md",
    ".profiles/.layer/.deep-template.md",
    "roles/layer/ordinary-template.md",
    ".pyc/builder.md",
    "roles/.pyo/.hidden/.builder.md",
    ".profiles/.pyd/nested-template.md",
}


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


def test_team_templates_are_a_registered_resource_package():
    package = "aegis_core.team_templates"
    assert package in _packages()
    root = resources.files(package)
    assert root.joinpath("__init__.py").is_file()
    assert resources.files(package).joinpath("__init__.py").read_bytes() == (
        REPO_ROOT / "aegis_core/team_templates/__init__.py").read_bytes()


def _anchored_assets(root, patterns):
    return {path.relative_to(root).as_posix() for pattern in patterns
            for path in root.glob(pattern) if not path.is_symlink() and path.is_file()}


def test_team_template_packaging_covers_root_and_nested_assets(tmp_path):
    patterns = _package_data().get("aegis_core.team_templates", [])
    # TA-4 owns the real template move. Check representative destinations without
    # copying its leased bytes or relying on git history/build dependencies.
    names = {"manifest.json", "lane-brief.md", "native-probe-attempt.py",
             "roles/builder.md", "hosts/assistants-builder.json"} | TEMPLATE_FIXTURES
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("template\n", encoding="utf-8")
    assert _anchored_assets(tmp_path, patterns) == names
    assert _anchored_assets(tmp_path, ["*"]) == {name for name in names if "/" not in name}
    assert tomllib.loads(_pyproject())["tool"]["setuptools"]["include-package-data"] is True
    lines = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    assert "recursive-include aegis_core *" in lines
    assert not any(line.split()[:2] == ["recursive-include", "tools"] for line in lines)
    assert not any(name == "tools" or name.startswith("tools.") for name in _packages())


def test_team_template_exclusions_cover_bytecode_and_keep_nested_templates(tmp_path):
    package = "aegis_core.team_templates"
    table = tomllib.loads(_pyproject())["tool"]["setuptools"]
    src_dir = tmp_path / "checkout" / "aegis_core" / "team_templates"
    patterns = [str(src_dir / pattern)
                for pattern in table.get("exclude-package-data", {}).get(package, [])]
    caches = {"planted.pyc", "planted.pyo", "planted.pyd", "roles/planted.pyc",
              "roles/planted.pyo", "roles/planted.pyd", "__pycache__/planted.pyc",
              "roles/__pycache__/planted.pyo", "__pycache__/unexpected.json",
              "roles/__pycache__/unexpected.md"}
    templates = {"manifest.json", "native-probe-attempt.py", "roles/builder.md"}
    for name in caches | templates:
        path = src_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture\n")
    # setuptools matches source-directory-joined names and patterns with fnmatch.
    excluded = {name for name in caches | templates
                if any(fnmatch.fnmatch(str(src_dir / name), pattern) for pattern in patterns)}
    assert excluded == caches


@pytest.mark.parametrize("kind", ["file", "directory", "broken_file", "broken_directory", "root"])
def test_reviewed_template_inventory_refuses_links(tmp_path, kind):
    shutil.copyfile(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    shutil.copyfile(REPO_ROOT / "MANIFEST.in", tmp_path / "MANIFEST.in")
    root = tmp_path / "aegis_core" / "team_templates"
    root.parent.mkdir()
    target = tmp_path / "target"
    directory = kind in {"directory", "broken_directory", "root"}
    if kind in {"directory", "root"}:
        target.mkdir()
        (target / "builder.md").write_bytes(b"other directory\n")
    elif kind == "file":
        target.write_bytes(b"other file\n")
    if kind == "root":
        link = root
    else:
        root.mkdir()
        link = root / ".linked.md"
    symlink_or_skip(target, link, target_is_directory=directory)
    with pytest.raises(ValueError, match=rf"^linked template path: {re.escape(str(link))}$"):
        _packaged_team_template_members(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX FIFO")
def test_reviewed_template_inventory_refuses_special_files(tmp_path):
    shutil.copyfile(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    shutil.copyfile(REPO_ROOT / "MANIFEST.in", tmp_path / "MANIFEST.in")
    fifo = tmp_path / "aegis_core" / "team_templates" / "stream.pyc"
    fifo.parent.mkdir(parents=True)
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match=rf"^unsupported template entry: {re.escape(str(fifo))}$"):
        _packaged_team_template_members(tmp_path)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="requires POSIX permission checks")
def test_reviewed_template_inventory_refuses_unreadable_files(tmp_path):
    shutil.copyfile(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    shutil.copyfile(REPO_ROOT / "MANIFEST.in", tmp_path / "MANIFEST.in")
    path = tmp_path / TEMPLATE_PATH / ".private.md"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"unreadable template\n")
    path.chmod(0o000)
    try:
        with pytest.raises(ValueError, match=rf"^cannot read template file: {re.escape(str(path))}$"):
            _packaged_team_template_members(tmp_path)
    finally:
        path.chmod(0o600)


def test_recipe_refuses_an_unsupported_source_walk(tmp_path):
    guide = (REPO_ROOT / "docs" / "teams-absorption.md").read_text(encoding="utf-8")
    snippets = guide.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)
    checker = tmp_path / "check_templates.py"
    checker.write_text(snippets[0], encoding="utf-8")
    walk = runpy.run_path(str(checker))["walk_templates"]
    with pytest.raises(SystemExit, match=r"^template source scan requires descriptor-relative no-follow support$"):
        walk(tmp_path, (), None, str, supports=lambda: False)


def _wheel_builder():
    # Build dependencies are already declared in pyproject.toml. Use an available
    # installed backend, never install into or modify the CI environment.
    for executable in dict.fromkeys((sys.executable, getattr(sys, "_base_executable", sys.executable))):
        probe = subprocess.run([executable, "-I", "-c", "import setuptools, wheel; "
                                "assert int(setuptools.__version__.split('.')[0]) >= 68"],
                               capture_output=True, timeout=30)
        if probe.returncode == 0:
            return executable
    pytest.skip("wheel build needs the declared setuptools>=68 and wheel build dependencies")


def _ignore_build_cache(directory, names):
    return {name for name in names if name == "__pycache__"
            or (fnmatch.fnmatch(name, "*.py[cod]") and (Path(directory) / name).is_file())}


def _copy_build_sources(checkout, source):
    def ignore(directory, names):
        ignored = _ignore_build_cache(directory, names)
        if Path(directory) == checkout / "aegis_core":
            ignored.add("team_templates")
        return ignored

    source.mkdir()
    for name in (*AEGIS_PACKAGES, "rules", "skills"):
        shutil.copytree(checkout / name, source / name, ignore=ignore)
    for name in ("pyproject.toml", "MANIFEST.in", "README.md", "LICENSE", "NOTICE", "Makefile"):
        shutil.copyfile(checkout / name, source / name)


def test_dirty_checkout_wheel_excludes_bytecode_and_keeps_nested_templates(tmp_path):
    executable = _wheel_builder()
    source = tmp_path / "checkout"
    _copy_build_sources(REPO_ROOT, source)
    root = source / TEMPLATE_PATH
    assets = {"__init__.py", "manifest.json", "roles/builder.md", "hosts/assistants-builder.json"}
    for name in assets | {"__pycache__/planted.pyc", "roles/__pycache__/planted.pyo", "planted.pyd",
                          "__pycache__/unexpected.json", "roles/__pycache__/unexpected.md"}:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# synthetic resource\r\n")
    done = subprocess.run([executable, "-I", "-c",
                           "from setuptools.build_meta import build_wheel; build_wheel('dist')"],
                          cwd=source, capture_output=True, text=True, timeout=90)
    assert done.returncode == 0, done.stderr[-2000:]
    wheel, = (source / "dist").glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        assert {f"{TEMPLATE_PATH}/{name}" for name in assets} <= names
        assert not any("__pycache__" in name or name.endswith((".pyc", ".pyo", ".pyd")) for name in names)


def _template_mode(path):
    try:
        info = path.lstat()
    except OSError:
        raise ValueError(f"cannot inspect template path: {path}") from None
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"linked template path: {path}")
    return info.st_mode


def _packaged_team_template_members(checkout, *, apply_exclusions=True):
    """Snapshot the regular files selected by the recursive manifest and package-data rules."""
    table = tomllib.loads((checkout / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["setuptools"]
    manifest = (checkout / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    assert table["include-package-data"] and "recursive-include aegis_core *" in manifest
    excludes = table.get("exclude-package-data", {}).get(TEMPLATE_PACKAGE, []) if apply_exclusions else None
    root = checkout / TEMPLATE_PATH
    for directory in (root.parent, root):
        if not stat.S_ISDIR(_template_mode(directory)):
            raise ValueError(f"unsupported template entry: {directory}")
    snapshot = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            raise ValueError(f"cannot read template directory: {directory}") from None
        for path in entries:
            mode = _template_mode(path)
            if stat.S_ISDIR(mode):
                if excludes is None or path.name != "__pycache__":
                    pending.append(path)
                continue
            if not stat.S_ISREG(mode):
                raise ValueError(f"unsupported template entry: {path}")
            relative = path.relative_to(root).as_posix()
            if excludes is not None and (path.name == "__pycache__" or any(
                    fnmatch.fnmatch(relative, pattern) for pattern in excludes)):
                continue
            try:
                snapshot[f"{TEMPLATE_PATH}/{relative}"] = path.read_bytes()
            except OSError:
                raise ValueError(f"cannot read template file: {path}") from None
    return snapshot


def _assert_staged_templates(source, expected):
    staged = _packaged_team_template_members(source, apply_exclusions=False)
    if staged.keys() != expected.keys():
        raise AssertionError(f"staged template inventory differs from source: {sorted(staged.keys() ^ expected.keys())}")
    for name, payload in expected.items():
        if staged[name] != payload:
            raise AssertionError(f"staged template bytes differ from source: {name}")


@pytest.mark.parametrize("fault", ["missing", "line_endings"])
def test_staging_detects_changes_to_reviewed_templates(tmp_path, fault):
    reviewed = tmp_path / "reviewed"
    name = f"{TEMPLATE_PATH}/.pyc/roles/.nested-template.md"
    path = reviewed / name
    path.parent.mkdir(parents=True)
    payload = b"original review\r\n"
    path.write_bytes(payload)
    for config in ("pyproject.toml", "MANIFEST.in"):
        shutil.copyfile(REPO_ROOT / config, reviewed / config)
    expected = _packaged_team_template_members(reviewed)
    assert expected == {name: payload}
    staged = tmp_path / "staged"
    shutil.copytree(reviewed, staged, ignore=_ignore_build_cache)
    _assert_staged_templates(staged, expected)
    if fault == "missing":
        shutil.rmtree(staged / TEMPLATE_PATH / ".pyc")
        pattern = rf"^staged template inventory differs from source: {re.escape(str([name]))}$"
    else:
        (staged / name).write_bytes(payload.replace(b"\r\n", b"\n"))
        pattern = rf"^staged template bytes differ from source: {re.escape(name)}$"
    with pytest.raises(AssertionError, match=pattern):
        _assert_staged_templates(staged, expected)


def test_verify_dist_record_matches_the_built_team_templates(tmp_path):
    """Both built archives must pass verification and preserve the selected source bytes."""
    expected = _packaged_team_template_members(REPO_ROOT)
    assert expected
    executable = _wheel_builder()
    source = tmp_path / "checkout"
    _copy_build_sources(REPO_ROOT, source)
    shutil.copytree(REPO_ROOT / TEMPLATE_PATH, source / TEMPLATE_PATH, symlinks=True, ignore=_ignore_build_cache)
    _assert_staged_templates(source, expected)
    script = "from setuptools.build_meta import build_sdist, build_wheel\nbuild_wheel('dist')\nbuild_sdist('dist')\n"
    done = subprocess.run([executable, "-I", "-c", script], cwd=source, capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stderr[-2000:]
    dist = source / "dist"
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    assert len(wheels) == 1 and len(sdists) == 1
    verify = REPO_ROOT / ".github" / "scripts" / "verify_dist.py"
    proc = subprocess.run([executable, str(verify), "record", str(dist)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        digest, separator, filename = line.partition("  ")
        assert separator == "  " and len(digest) == 64 and digest.islower()
        assert all(char in "0123456789abcdef" for char in digest)
        assert filename == wheels[0].name or filename == sdists[0].name
    sums = (dist / "SHA256SUMS").read_bytes()
    assert b"\r" not in sums
    checked = subprocess.run([executable, str(verify), "verify", str(dist)],
                             capture_output=True, text=True, timeout=60)
    assert checked.returncode == 0, checked.stderr
    assert len([line for line in checked.stdout.splitlines() if line.strip()]) == 2

    with zipfile.ZipFile(wheels[0]) as wheel, tarfile.open(sdists[0], "r:gz") as sdist:
        wheel_members = {item.filename for item in wheel.infolist()
                         if not item.is_dir() and item.filename.startswith(f"{TEMPLATE_PATH}/")}
        assert wheel_members == expected.keys()

        first_member = sdist.next()
        assert first_member is not None
        sdist_root = first_member.name.split("/", 1)[0]
        sdist_members = {item.name.partition("/")[2] for item in sdist.getmembers()
                         if item.isfile() and item.name.startswith(f"{sdist_root}/{TEMPLATE_PATH}/")}
        assert sdist_members == expected.keys()

        for name, payload in expected.items():
            with wheel.open(name) as member:
                wheel_matches = member.read(len(payload) + 1) == payload
            assert wheel_matches, f"wheel bytes differ from source: {name}"
            member = sdist.extractfile(f"{sdist_root}/{name}")
            assert member is not None, f"sdist member is not a file: {name}"
            with member:
                sdist_matches = member.read(len(payload) + 1) == payload
            assert sdist_matches, f"sdist bytes differ from source: {name}"
