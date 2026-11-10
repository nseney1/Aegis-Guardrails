"""TDD tests for import_guard.py — dependency guard checker.

Behavioral contract: scan Python files for import statements, identify
third-party imports that aren't guarded (try/except or pytest.importorskip),
and flag them as risks when they aren't in the project's dependency manifest.
"""
import os
import sys
import textwrap

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
