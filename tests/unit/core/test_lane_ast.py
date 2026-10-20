"""Unit tests for ``aegis_core.lane_ast`` AST test-integrity scanners and config parsers."""
from __future__ import annotations

from typing import Dict

import pytest

from aegis_core import lane_ast


def _forms(source: str) -> Dict[tuple, int]:
    return lane_ast.skip_forms(source.encode("utf-8"))


def _canonical_forms(source: str) -> Dict[tuple, int]:
    counts: Dict[tuple, int] = {}
    for (scope, form), n in _forms(source).items():
        key = (scope, form if form.startswith(("pytestmark", "__test__")) else form.partition(": ")[0])
        counts[key] = counts.get(key, 0) + n
    return counts


class TestExportsAndConstants:
    def test_exported_constants(self):
        assert "python" in lane_ast.COVERED
        assert "addopts" in lane_ast.COLLECTION_KEYS
        assert "norecursedirs" in lane_ast.COLLECTION_KEYS
        assert "pyproject.toml" in lane_ast.PYTEST_CONFIG_FILES
        assert "pytest.ini" in lane_ast.PYTEST_CONFIG_FILES
        assert len(lane_ast.LIMITS) >= 10


class TestCollectedIds:
    def test_default_discovery_and_nesting(self):
        source = (
            b"import unittest\n"
            b"def test_top(): pass\n"
            b"async def test_async(): pass\n"
            b"def helper(): pass\n"
            b"class TestSuite:\n"
            b"    def test_method(self): pass\n"
            b"    class TestNested:\n"
            b"        def test_inner(self): pass\n"
            b"class WithInit:\n"
            b"    def __init__(self): pass\n"
            b"    def test_ignored(self): pass\n"
            b"class WithNew:\n"
            b"    def __new__(cls): pass\n"
            b"    def test_ignored(self): pass\n"
        )
        assert lane_ast.collected_ids(source) == {
            "test_top": True,
            "test_async": True,
            "TestSuite::test_method": True,
            "TestSuite::TestNested::test_inner": True,
        }

    def test_excludes_fixtures_and_aliases(self):
        source = (
            b"import pytest\n"
            b"from pytest import fixture as fx\n"
            b"custom_fx = pytest.fixture(scope='module')\n"
            b"@pytest.fixture\ndef test_not_a_test(): pass\n"
            b"@fx\ndef test_aliased_fixture(): pass\n"
            b"@custom_fx\ndef test_factory_fixture(): pass\n"
            b"def test_real(): pass\n"
        )
        assert lane_ast.collected_ids(source) == {"test_real": True}

    def test_conditional_definitions_and_unbinds(self):
        source = (
            b"import sys\n"
            b"def test_kept(): pass\n"
            b"def test_deleted(): pass\n"
            b"def test_cond_del(): pass\n"
            b"del test_deleted\n"
            b"if sys.platform == 'linux':\n"
            b"    def test_linux_only(): pass\n"
            b"    del test_cond_del\n"
        )
        assert lane_ast.collected_ids(source) == {
            "test_kept": True,
            "test_cond_del": False,
            "test_linux_only": False,
        }

    def test_syntax_error_raises(self):
        with pytest.raises(SyntaxError):
            lane_ast.collected_ids(b"def test_broken(:\n")


class TestSkipForms:
    @pytest.mark.parametrize("source, expected_key", [
        ("import pytest\n@pytest.mark.skip\ndef test_a(): pass\n", ("test_a", "pytest.mark.skip")),
        ("import pytest\n@pytest.mark.skipif(True, reason='r')\ndef test_a(): pass\n", ("test_a", "pytest.mark.skipif")),
        ("import pytest\n@pytest.mark.xfail\ndef test_a(): pass\n", ("test_a", "pytest.mark.xfail")),
        ("import unittest\n@unittest.skip('r')\ndef test_a(): pass\n", ("test_a", "unittest.skip")),
        ("import unittest\n@unittest.skipIf(True, 'r')\ndef test_a(): pass\n", ("test_a", "unittest.skipIf")),
        ("import unittest\n@unittest.skipUnless(False, 'r')\ndef test_a(): pass\n", ("test_a", "unittest.skipUnless")),
        ("import unittest\n@unittest.expectedFailure\ndef test_a(): pass\n", ("test_a", "unittest.expectedFailure")),
        ("import pytest\ndef test_a():\n    pytest.skip('no')\n", ("test_a", "pytest.skip")),
        ("import pytest\ndef test_a():\n    pytest.xfail('no')\n", ("test_a", "pytest.xfail")),
        ("import pytest\npytest.importorskip('numpy')\n", ("<module>", "pytest.importorskip")),
        ("import pytest\ndef test_a():\n    pytest.exit('stop')\n", ("test_a", "pytest.exit")),
        ("import os\ndef test_a():\n    os._exit(0)\n", ("test_a", "os._exit")),
        ("class T:\n    def test_a(self):\n        self.skipTest('x')\n", ("T::test_a", "skipTest")),
        ("import unittest\ndef test_a():\n    raise unittest.SkipTest('x')\n", ("test_a", "unittest.SkipTest")),
        ("__test__ = False\n", ("<module>", "__test__ = False")),
        ("import pytest\npytestmark = pytest.mark.skip\n", ("<module>", "pytestmark = pytest.mark.skip")),
    ])
    def test_detects_standard_skip_forms(self, source: str, expected_key: tuple):
        assert _canonical_forms(source).get(expected_key) == 1

    def test_resolves_aliases_and_chained_assignments(self):
        source = (
            "import pytest as pt\n"
            "from unittest import skip as u_skip\n"
            "marks = pt.mark\n"
            "needs_net = marks.skipif(True, reason='offline')\n"
            "@needs_net\n"
            "def test_a(): pass\n"
            "@u_skip('later')\n"
            "def test_b(): pass\n"
        )
        forms = _canonical_forms(source)
        assert forms[("test_a", "pytest.mark.skipif")] == 1
        assert forms[("test_b", "unittest.skip")] == 1

    def test_tracks_enclosing_guards(self):
        source = "import pytest\ndef test_a():\n    if COND:\n        pytest.skip('guarded')\n"
        assert _forms(source) == {("test_a", "pytest.skip: pytest.skip('guarded') under if COND"): 1}

    def test_syntax_error_raises(self):
        with pytest.raises(SyntaxError):
            lane_ast.skip_forms(b"def broken(:\n")


class TestCollectionHooks:
    def test_conftest_watches_collection_variables_and_hooks(self):
        source = (
            b"collect_ignore = ['legacy.py']\n"
            b"collect_ignore.append('second.py')\n"
            b"collect_ignore_glob = ['*_old.py']\n"
            b"pytest_plugins = ['my_plugin']\n"
            b"def pytest_collection_modifyitems(config, items):\n"
            b"    items[:] = []\n"
            b"def regular_helper():\n"
            b"    return 42\n"
        )
        hooks = lane_ast.collection_hooks(source)
        assert set(hooks) == {
            "collect_ignore",
            "collect_ignore_glob",
            "pytest_plugins",
            "pytest_collection_modifyitems",
        }
        assert len(hooks["collect_ignore"]) == 2
        assert hooks["collect_ignore"] == tuple(sorted(hooks["collect_ignore"]))
        assert all("collect_ignore" in d for d in hooks["collect_ignore"])
        assert len(hooks["pytest_collection_modifyitems"]) == 1
        assert "FunctionDef" in hooks["pytest_collection_modifyitems"][0]

    def test_hooks_only_ignores_variables_and_non_hook_functions(self):
        source = (
            b"import pytest_Thing\n"
            b"collect_ignore = ['a.py']\n"
            b"def helper():\n"
            b"    return False\n"
            b"def pytest_ignore_collect(collection_path):\n"
            b"    return True\n"
        )
        hooks = lane_ast.collection_hooks(source, hooks_only=True)
        assert set(hooks) == {"pytest_ignore_collect"}
        assert len(hooks["pytest_ignore_collect"]) == 1
        assert "pytest_ignore_collect" in hooks["pytest_ignore_collect"][0]

    def test_syntax_error_raises(self):
        with pytest.raises(SyntaxError):
            lane_ast.collection_hooks(b"def broken(:\n")


class TestPytestSettings:
    def test_ini_and_cfg_parsing(self):
        ini_data = b"[pytest]\naddopts = -q\n  --tb=short\ntestpaths = tests\n"
        assert lane_ast.pytest_settings("pytest.ini", ini_data) == {
            "[pytest] addopts": "-q\n--tb=short",
            "[pytest] testpaths": "tests",
        }
        assert lane_ast.pytest_settings("pytest.ini", b"") == {}
        assert lane_ast.pytest_settings("tox.ini", b"[tox]\nenvlist = py311\n") is None
        assert lane_ast.pytest_settings(
            "setup.cfg", b"[tool:pytest]\nnorecursedirs = dist build\n"
        ) == {"[tool:pytest] norecursedirs": "dist build"}

    def test_pyproject_and_pytest_toml_parsing(self):
        pyproject = (
            b'[tool.pytest.ini_options]\n'
            b'addopts = "-q" # comment\n'
            b'testpaths = [\n  "tests",\n  "integration"\n]\n'
        )
        assert lane_ast.pytest_settings("pyproject.toml", pyproject) == {
            "[tool.pytest.ini_options] addopts": '"-q"',
            "[tool.pytest.ini_options] testpaths": '["tests","integration"]',
        }
        assert lane_ast.pytest_settings("pyproject.toml", b'[project]\nname = "demo"\n') is None
        assert lane_ast.pytest_settings("pytest.toml", b"") == {}

    @pytest.mark.parametrize("filename, bad_data", [
        ("unknown.cfg", b"[pytest]\naddopts = -q\n"),
        ("pytest.ini", b"[pytest]\naddopts = -q\naddopts = -x\n"),
        ("pyproject.toml", b'[tool.pytest.ini_options]\naddopts = "unterminated\n'),
        ("pyproject.toml", b'[tool.pytest.ini_options]\ntestpaths = ["a"\n'),
        ("pyproject.toml", b'[tool.pytest.ini_options\naddopts = "-q"\n'),
        ("pyproject.toml", b'[tool.pytest.ini_options]\naddopts = \n'),
        ("setup.cfg", b"\xff"),
    ])
    def test_invalid_config_raises_value_error(self, filename: str, bad_data: bytes):
        with pytest.raises(ValueError):
            lane_ast.pytest_settings(filename, bad_data)


class TestPytestConfigView:
    """Given a pyproject.toml, setup.cfg or tox.ini, When check --ci compares two versions of it,
    Then only what pytest reads counts: every key of its sections, not formatting or other tables."""

    PYPROJECT = (
        b'[project]\nname = "demo"\nversion = "1.0.0"\n\n'
        b'[tool.pytest.ini_options]\naddopts = "-q" # quiet\nrequired_plugins = ["a"]\n'
    )

    def test_whitespace_comments_and_other_tables_do_not_count(self):
        view = lane_ast.pytest_config_view("pyproject.toml", self.PYPROJECT)
        reformatted = self.PYPROJECT.replace(b'version = "1.0.0"', b'version = "2.0.0"').replace(
            b'addopts = "-q" # quiet', b'addopts   =   "-q"')
        assert view == lane_ast.pytest_config_view("pyproject.toml", reformatted)
        assert view == {"tool.pytest.ini_options.addopts": '"-q"',
                        "tool.pytest.ini_options.required_plugins": '["a"]',
                        "[tool.pytest.ini_options]": ""}

    @pytest.mark.parametrize("filename,data,key", [
        ("pyproject.toml", b'[tool.pytest.ini_options]\npythonpath = ["src"]\n', "tool.pytest.ini_options.pythonpath"),
        ("pyproject.toml", b'[tool.pytest]\nminversion = "8"\n', "tool.pytest.minversion"),
        ("pyproject.toml", b'[tool]\npytest = {ini_options = {addopts = "-x"}}\n', "tool.pytest"),
        ("setup.cfg", b"[metadata]\nname = x\n[tool:pytest]\nrequired_plugins = evil\n", "required_plugins"),
        ("tox.ini", b"[tox]\nenvlist = py\n[pytest]\npythonpath = src\n", "pythonpath"),
    ], ids=["pythonpath", "native", "inline", "setup", "tox"])
    def test_keys_outside_the_collection_keys_count(self, filename, data, key):
        assert key not in lane_ast.COLLECTION_KEYS
        assert key in (lane_ast.pytest_config_view(filename, data) or {})

    @pytest.mark.parametrize("filename,data", [
        ("pyproject.toml", b'[project]\nname = "demo"\n'),
        ("setup.cfg", b"[metadata]\nname = x\n"),
        ("tox.ini", b"[tox]\nenvlist = py\n"),
    ], ids=["pyproject", "setup", "tox"])
    def test_a_file_without_a_pytest_section_has_no_view(self, filename, data):
        assert lane_ast.pytest_config_view(filename, data) is None

    @pytest.mark.parametrize("filename,data", [
        ("pyproject.toml", b'[tool.pytest.ini_options\naddopts = "-q"\n'),
        ("setup.cfg", b"\xff"),
        ("tox.ini", b"[pytest]\naddopts = -q\naddopts = -x\n"),
        ("pytest.ini", b"[pytest]\naddopts = -q\n"),
    ], ids=["toml", "bytes", "dupkey", "notcompared"])
    def test_an_unreadable_file_raises_value_error(self, filename, data):
        with pytest.raises(ValueError):
            lane_ast.pytest_config_view(filename, data)

    # TOML spells a key with escapes too: each of these is tool.pytest.ini_options.addopts to pytest.
    SPELLED = [
        b'tool = { "py\\u0074est" = { ini_options = { addopts = "-k nothing_matches" } } }\n[project]\nname = "x"\n',
        b'[tool."py\\U00000074est".ini_options]\naddopts = "-k nothing_matches"\n',
        b'[tool]\n"py\\u0074est".ini_options.addopts = "-k nothing_matches"\n',
        b'"t\\u006fol".pytest.ini_options.addopts = "-k nothing_matches"\n',
        b'"tool"."pytest".ini_options.addopts = "-k nothing_matches"\n',
        b'tool."pytest" = { ini_options = { addopts = "-k nothing_matches" } }\n',
    ]
    SPELLED_IDS = ["escaped-inline", "escaped-header", "escaped-dotted", "escaped-tool", "quoted", "quoted-inline"]

    @pytest.mark.parametrize("data", SPELLED, ids=SPELLED_IDS)
    def test_a_key_spelled_with_quotes_or_escapes_counts(self, data):
        """Given a pyproject.toml whose only pytest configuration is reached through a quoted or escaped
        key, When its view is taken, Then it is not None (an escape may decode to any name, so it counts)."""
        assert lane_ast.pytest_config_view("pyproject.toml", data) is not None
        assert lane_ast.pytest_config_view("pyproject.toml", data) != lane_ast.pytest_config_view(
            "pyproject.toml", data.replace(b"nothing_matches", b"other"))

    def test_any_root_inline_tool_table_counts(self):
        """Fail closed: a root ``tool = {...}`` can hold pytest's table however its keys are spelled."""
        data = b'tool = { ruff = { line-length = 100 } }\n'
        assert lane_ast.pytest_config_view("pyproject.toml", data) is not None

    @pytest.mark.parametrize("before,after", [
        (b'[tool.ruff]\nline-length = 100\n', b'[tool.ruff]\nline-length = 120\n'),
        (b'[tool.ruff]\nline-length = 100\n[tool.pytest.ini_options]\naddopts = "-q"\n',
         b'[tool.ruff]\nline-length = 120\n[tool.pytest.ini_options]\naddopts = "-q"\n'),
        (b'[tool]\nruff.line-length = 100\n', b'[tool]\nruff.line-length = 120\n'),
        (b'[tool."ruff"]\nline-length = 100\n', b'[tool."ruff"]\nline-length = 120\n'),
    ], ids=["ruff", "ruff-beside-pytest", "dotted", "quoted"])
    def test_an_unrelated_tool_table_edit_leaves_the_view_alone(self, before, after):
        assert lane_ast.pytest_config_view("pyproject.toml", before) == lane_ast.pytest_config_view(
            "pyproject.toml", after)

    @pytest.mark.parametrize("data", SPELLED, ids=SPELLED_IDS)
    def test_pytest_settings_sees_the_same_spellings(self, data):
        assert lane_ast.pytest_settings("pyproject.toml", data) is not None

    def test_pytest_settings_reads_an_escaped_header_as_the_ini_options_table(self):
        data = b'[tool."py\\U00000074est".ini_options]\naddopts = "-x"\n'
        assert lane_ast.pytest_settings("pyproject.toml", data) == {"[tool.pytest.ini_options] addopts": '"-x"'}

    def test_it_parses_without_tomllib(self, monkeypatch):
        import sys

        monkeypatch.setitem(sys.modules, "tomllib", None)
        assert lane_ast.pytest_config_view("pyproject.toml", self.PYPROJECT)
