"""TDD tests for import_guard.py — dependency guard checker.

Behavioral contract: scan Python files for import statements, identify
third-party imports that aren't guarded (try/except or pytest.importorskip),
and flag them as risks when they aren't in the project's dependency manifest.
"""
import os
import sys
import textwrap
from collections import Counter
from types import SimpleNamespace

import pytest
from pathlib import Path

REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import ToolEvidence


class TestImportExtraction:
    """Contract: extract_imports finds all import statements in a file."""

    def test_finds_bare_imports(self, tmp_path):
        """Must find `import foo` statements."""
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text("import os\nimport yaml\nimport json\n")

        imports = extract_imports(str(src))
        modules = {i.module for i in imports}
        assert "os" in modules
        assert "yaml" in modules
        assert "json" in modules

    def test_finds_from_imports(self, tmp_path):
        """Must find `from foo import bar` statements."""
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text("from pathlib import Path\nfrom yaml import safe_load\n")

        imports = extract_imports(str(src))
        modules = {i.module for i in imports}
        assert "pathlib" in modules
        assert "yaml" in modules

    def test_extracts_line_numbers(self, tmp_path):
        """Must capture the line number of each import."""
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text("import os\n\nimport yaml\n")

        imports = extract_imports(str(src))
        yaml_import = [i for i in imports if i.module == "yaml"][0]
        assert yaml_import.lineno == 3

    def test_detects_guarded_try_except(self, tmp_path):
        """Imports inside try/except blocks must be marked as guarded."""
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text(textwrap.dedent("""\
            try:
                import yaml
            except ImportError:
                yaml = None
        """))

        imports = extract_imports(str(src))
        yaml_import = [i for i in imports if i.module == "yaml"][0]
        assert yaml_import.guarded is True

    def test_detects_importorskip(self, tmp_path):
        """pytest.importorskip must be detected as guarded."""
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text('import pytest\nyaml = pytest.importorskip("yaml")\n')

        imports = extract_imports(str(src))
        # importorskip counts as a guarded import of yaml
        yaml_imports = [i for i in imports if i.module == "yaml"]
        assert len(yaml_imports) == 1
        assert yaml_imports[0].guarded is True

    def test_bare_import_is_unguarded(self, tmp_path):
        """Top-level imports outside try/except must be marked unguarded."""
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text("import yaml\n")

        imports = extract_imports(str(src))
        yaml_import = [i for i in imports if i.module == "yaml"][0]
        assert yaml_import.guarded is False

    @pytest.mark.parametrize("statement", ["import pkg{n}", "from pkg{n} import value"],
                             ids=["import", "from"])
    def test_membership_work_is_linear(self, tmp_path, monkeypatch, statement):
        """Counting record reads catches a growing scan without timing assertions."""
        import aegis_core.verification.import_guard as ig

        inspections = 0

        class CountedImportInfo(ig.ImportInfo):
            def __getattribute__(self, name):
                nonlocal inspections
                if name == "module":
                    inspections += 1
                return super().__getattribute__(name)

        monkeypatch.setattr(ig, "ImportInfo", CountedImportInfo)
        count = 256
        src = tmp_path / "many_imports.py"
        src.write_text("\n".join(statement.format(n=n) for n in range(count)),
                       encoding="utf-8")

        imports = ig.extract_imports(str(src))

        assert inspections <= count
        assert [(i.module, i.lineno, i.guarded) for i in imports] == [
            (f"pkg{n}", n + 1, False) for n in range(count)
        ]

    @pytest.mark.parametrize(("source", "expected"), [
        pytest.param(
            "try:\n    import nested\nexcept ImportError:\n    pass\n"
            "import first, second.child\nfrom third.child import value\n",
            [("first", 5, False), ("second", 5, False), ("third", 6, False),
             ("nested", 2, True)],
            id="breadth-first-order",
        ),
        pytest.param(
            'import pkg\nfrom pkg.child import value\n'
            'pytest.importorskip("pkg")\npytest.importorskip("pkg")\n',
            [("pkg", 3, True), ("pkg", 4, True)],
            id="importorskip-prepass-retains-duplicates",
        ),
        pytest.param(
            "import pkg.one\nfrom pkg.two import value\n"
            "try:\n    import pkg\n    from pkg import other\n"
            "except ImportError:\n    pass\n",
            [("pkg", 1, False), ("pkg", 2, False), ("pkg", 4, True)],
            id="unguarded-duplicates-before-guard",
        ),
        pytest.param(
            "try:\n    import pkg.child\nexcept ImportError:\n    pass\n"
            "def later():\n    import pkg\n    from pkg import value\n",
            [("pkg", 2, True)],
            id="guarded-import-suppresses-later-both-forms",
        ),
        pytest.param(
            "try:\n    from pkg.child import value\nexcept ImportError:\n    pass\n"
            "def later():\n    from pkg import other\n    import pkg\n",
            [("pkg", 2, True)],
            id="guarded-from-suppresses-later-both-forms",
        ),
        pytest.param(
            'pytest.importorskip("pkg")\ndef broken(\n',
            [("pkg", 1, True)],
            id="malformed-source-retains-prepass",
        ),
        pytest.param("def broken(\n", [], id="malformed-source-without-prepass"),
    ])
    def test_preserves_order_and_guard_suppression(self, tmp_path, source, expected):
        from aegis_core.verification.import_guard import extract_imports

        src = tmp_path / "mod.py"
        src.write_text(source, encoding="utf-8")

        assert [(i.module, i.lineno, i.guarded) for i in extract_imports(str(src))] == expected

    def test_missing_file_raises(self, tmp_path):
        from aegis_core.verification.import_guard import extract_imports

        missing = tmp_path / "missing.py"
        with pytest.raises(FileNotFoundError) as exc:
            extract_imports(str(missing))
        assert exc.value.filename == str(missing)


@pytest.mark.parametrize("broken", [False, True], ids=["valid", "syntax-error"])
def test_importorskip_line_scanning_is_linear(monkeypatch, broken):
    from aegis_core.verification import import_guard

    slices = []
    scanned = []

    class CountedSource(str):
        def __getitem__(self, key):
            if isinstance(key, slice):
                slices.append(key)
            return super().__getitem__(key)

        def count(self, sub, start=0, end=None):
            end = len(self) if end is None else end
            scanned.append(end - start)
            return super().count(sub, start, end)

    block = ('# pytest.importorskip("comment")\n'
             'text = \'importorskip("string")\'\n'
             'pytest.importorskip(\n  "multiline"\n)\n'
             'importorskip("after")\n')
    source = CountedSource(block * 64 + ("def broken(\n" if broken else ""))
    monkeypatch.setattr(import_guard, "read_python_source", lambda path: source)

    imports = import_guard.extract_imports("virtual.py")

    assert [(i.module, i.lineno, i.guarded) for i in imports] == [
        (module, n * 6 + line, True) for n in range(64)
        for module, line in [("comment", 1), ("string", 2), ("multiline", 3), ("after", 6)]
    ]
    assert slices == []
    assert scanned
    assert sum(scanned) <= len(source)


@pytest.fixture
def discovery_fs(monkeypatch):
    """Replace only import_guard's OS reference, leaving pytest's OS intact."""
    from aegis_core.verification import import_guard

    calls = Counter()
    denied = set()

    def listdir(path):
        calls[("listdir", os.fspath(path))] += 1
        if os.fspath(path) in denied:
            raise PermissionError("discovery denied")
        return os.listdir(path)

    def probe(name):
        def counted(path):
            calls[(name, os.fspath(path))] += 1
            return getattr(os.path, name)(path)
        return counted

    path = SimpleNamespace(**{name: getattr(os.path, name) for name in
                              ("join", "dirname", "abspath", "basename")},
                           isdir=probe("isdir"), exists=probe("exists"))
    monkeypatch.setattr(import_guard, "os", SimpleNamespace(path=path, listdir=listdir))
    return calls, denied


def _run_import_checks(root, sources, not_in_commit=None):
    from aegis_core.verification import structural_checks

    def failure(tool, rel, exc):
        return ToolEvidence(tool, rel, False, f"{type(exc).__name__}: {exc}")

    results = structural_checks.run_checks(
        [(source.name, str(source)) for source in sources], str(root), None,
        fast_mode=True, failure=failure, not_in_commit=not_in_commit,
    )
    return [result for result in results if result.tool == "import_guard"]


def test_discovery_filesystem_work_is_once_per_run(tmp_path, discovery_fs):
    calls, _ = discovery_fs
    package = tmp_path / "localpkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "barehelper.py").write_text("", encoding="utf-8")
    namespace = tmp_path / "namespace"
    namespace.mkdir()
    (namespace / "nested").mkdir()
    (namespace / "nested" / "__init__.py").write_text("", encoding="utf-8")
    sources = [tmp_path / f"app{n}.py" for n in range(8)]
    for source in sources:
        source.write_text("import localpkg\nimport barehelper\nimport namespace\nimport missingdep\n",
                          encoding="utf-8")

    single = _run_import_checks(tmp_path, sources[:1])
    single_calls = calls.copy()
    calls.clear()
    batch = _run_import_checks(tmp_path, sources)

    assert batch == [ToolEvidence("import_guard", source.name, False,
                                 "Unguarded third-party imports: missingdep", [4])
                     for source in sources]
    assert single == batch[:1]
    assert calls == single_calls


def test_discovery_inventories_expire_between_runs(tmp_path, discovery_fs):
    root = tmp_path / "project"
    root.mkdir()
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    source = snapshot / "app.py"
    source.write_text("import freshpkg\nimport freshsibling\n", encoding="utf-8")

    before = _run_import_checks(root, [source])[0]
    package = root / "freshpkg"
    package.mkdir()
    init = package / "__init__.py"
    init.write_text("", encoding="utf-8")
    sibling = snapshot / "freshsibling.py"
    sibling.write_text("", encoding="utf-8")
    during = _run_import_checks(root, [source])[0]
    init.unlink()
    sibling.unlink()
    after = _run_import_checks(root, [source])[0]

    assert before == after == ToolEvidence("import_guard", "app.py", False,
                                          "Unguarded third-party imports: freshpkg, freshsibling", [1, 2])
    assert during.verdict is True


def test_snapshot_sibling_inventory_stays_separate(tmp_path, discovery_fs):
    root = tmp_path / "project"
    root.mkdir()
    sources = []
    for name in ("first", "second"):
        directory = tmp_path / name
        directory.mkdir()
        source = directory / f"{name}.py"
        source.write_text("import snapshot_helper\n", encoding="utf-8")
        sources.append(source)
    (sources[0].parent / "snapshot_helper.py").write_text("", encoding="utf-8")

    results = _run_import_checks(root, sources, lambda *args: ["snapshot_helper"])

    assert results == [
        ToolEvidence("import_guard", "first.py", True, "All imports are stdlib, allowed, or guarded"),
        ToolEvidence("import_guard", "second.py", False,
                     "Unguarded third-party imports: snapshot_helper; snapshot_helper is not staged or "
                     "tracked, so the commit would not include it", [1]),
    ]


@pytest.mark.parametrize("denied_site", ["root", "package", "namespace", "siblings"])
def test_discovery_permission_behavior(tmp_path, discovery_fs, denied_site):
    calls, denied = discovery_fs
    root = tmp_path / "project"
    root.mkdir()
    for name in ("package", "namespace"):
        directory = root / name
        directory.mkdir()
        (directory / "barehelper.py").write_text("", encoding="utf-8")
    (root / "package" / "__init__.py").write_text("", encoding="utf-8")
    siblings = tmp_path / "snapshot"
    siblings.mkdir()
    (siblings / "sibling.py").write_text("", encoding="utf-8")
    sources = [siblings / f"app{n}.py" for n in range(2)]
    for source in sources:
        source.write_text("import package\nimport namespace\nimport sibling\n", encoding="utf-8")
    denied.add(str({"root": root, "package": root / "package",
                    "namespace": root / "namespace", "siblings": siblings}[denied_site]))

    results = _run_import_checks(root, sources)

    if denied_site == "root":
        assert all(result.detail == "PermissionError: discovery denied" and not result.verdict
                   for result in results)
    elif denied_site == "package":
        assert all(result.verdict for result in results)
    else:
        module, line = ("namespace", 2) if denied_site == "namespace" else ("sibling", 3)
        assert all(result.detail == f"Unguarded third-party imports: {module}"
                   and result.lines == [line] and not result.verdict for result in results)
    assert all(calls[("listdir", path)] == 1 for path in denied)


class TestStdlibClassification:
    """Contract: correctly classify stdlib vs third-party modules."""

    def test_os_is_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("os") is True

    def test_sys_is_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("sys") is True

    def test_pathlib_is_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("pathlib") is True

    def test_json_is_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("json") is True

    def test_yaml_is_not_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("yaml") is False

    def test_pytest_is_not_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("pytest") is False

    def test_requests_is_not_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("requests") is False

    def test_msvcrt_is_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("msvcrt") is True

    def test_future_is_stdlib(self):
        from aegis_core.verification.import_guard import is_stdlib
        assert is_stdlib("__future__") is True

    def test_python39_fallback_simulation(self, monkeypatch):
        import sys
        import aegis_core.verification.import_guard as ig
        monkeypatch.delattr(sys, "stdlib_module_names", raising=False)
        monkeypatch.setattr(ig, "_STDLIB_MODULES", None)
        modules = ig._get_stdlib_modules()
        assert "os" in modules
        assert "argparse" in modules
        assert "json" in modules
        assert "msvcrt" in modules
        assert "__future__" in modules



class TestDependencyCheck:
    """Contract: check() returns ToolEvidence with unguarded third-party imports."""

    def test_clean_file_passes(self, tmp_path):
        """File with only stdlib imports should pass."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "clean.py"
        src.write_text("import os\nimport sys\nimport json\n")

        result = check(str(src))
        assert isinstance(result, ToolEvidence)
        assert result.tool == "import_guard"
        assert result.verdict is True
        assert result.lines == []

    def test_unguarded_third_party_fails(self, tmp_path):
        """Unguarded third-party import should fail."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "bad.py"
        src.write_text("import os\nimport yaml\n")

        result = check(str(src))
        assert result.verdict is False
        assert 2 in result.lines  # yaml is on line 2
        assert "yaml" in result.detail

    def test_guarded_third_party_passes(self, tmp_path):
        """Guarded third-party import should pass."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "guarded.py"
        src.write_text(textwrap.dedent("""\
            import os
            try:
                import yaml
            except ImportError:
                yaml = None
        """))

        result = check(str(src))
        assert result.verdict is True

    def test_allowed_deps_not_flagged(self, tmp_path):
        """Imports listed in allowed_deps should not be flagged even if unguarded."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "with_dep.py"
        src.write_text("import pytest\nimport yaml\n")

        result = check(str(src), allowed_deps={"pytest", "yaml"})
        assert result.verdict is True

    def test_reports_multiple_violations(self, tmp_path):
        """Multiple unguarded third-party imports should all be reported."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "multi.py"
        src.write_text("import yaml\nimport requests\nimport numpy\n")

        result = check(str(src))
        assert result.verdict is False
        assert len(result.lines) == 3
        assert "yaml" in result.detail
        assert "requests" in result.detail

    def test_local_project_imports_not_flagged(self, tmp_path):
        """Imports of local project packages should not be flagged."""
        from aegis_core.verification.import_guard import check

        # Create a fake project structure
        project = tmp_path / "myproject"
        project.mkdir()
        pkg = project / "aegis_core"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")

        src = project / "app.py"
        src.write_text("from aegis_core.verification import something\n")

        result = check(str(src), project_root=str(project))
        assert result.verdict is True


class TestRealFiles:
    """Validate against actual project files that triggered the CI failure."""

    def test_catches_original_decay_integration_bug(self, tmp_path):
        """Simulate the exact file that broke CI — bare `import yaml`."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "test_decay.py"
        src.write_text(textwrap.dedent("""\
            import os
            import sys
            import subprocess
            import yaml

            import pytest
        """))

        result = check(str(src), allowed_deps={"pytest"})
        assert result.verdict is False
        assert 4 in result.lines
        assert "yaml" in result.detail

    def test_fixed_version_passes(self, tmp_path):
        """The fixed version with importorskip should pass."""
        from aegis_core.verification.import_guard import check

        src = tmp_path / "test_decay_fixed.py"
        src.write_text(textwrap.dedent("""\
            import os
            import sys
            import subprocess
            import pytest

            yaml = pytest.importorskip("yaml")
        """))

        result = check(str(src), allowed_deps={"pytest"})
        assert result.verdict is True
