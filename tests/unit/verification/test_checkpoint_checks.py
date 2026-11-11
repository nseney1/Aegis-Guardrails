"""checkpoint_checks.check_assertion_density judges each test function by AST (#1).

The v3 check passed a whole file as soon as the text "assert " appeared anywhere
in it, so stubs sitting next to one real test went unreported.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis_core.verification import quality_gate
from aegis_core.verification.checkpoint_checks import check_assertion_density


def _test_file(root: Path, name: str, body: str) -> Path:
    path = root / "tests" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _messages(root: Path) -> list[str]:
    return [issue["message"] for issue in check_assertion_density(root)]


def test_each_assertion_less_test_and_stub_is_named(tmp_path):
    _test_file(tmp_path, "test_probe.py", """\
        def test_real():
            assert 1 + 1 == 2

        def test_stub_a():
            pass

        def test_stub_b():
            ...

        def test_no_assert():
            value = 1 + 1
    """)
    assert _messages(tmp_path) == [
        "Low assertion density in test_probe.py: tests lacking assertions: test_stub_a, test_stub_b, test_no_assert",
        "Placeholder tests in test_probe.py: bare pass/ellipsis stubs: test_stub_a, test_stub_b",
    ]
    issue = check_assertion_density(tmp_path)[0]
    assert (issue["check"], issue["file"], issue["lines"]) == ("assertion_density", "tests/test_probe.py", [4, 7, 10])


def test_assert_text_in_a_string_or_comment_does_not_count(tmp_path):
    _test_file(tmp_path, "test_text.py", '''\
        def test_only_mentions_assert():
            """we should assert something here"""
            value = "assert value"  # assert later
    ''')
    assert _messages(tmp_path) == [
        "Low assertion density in test_text.py: tests lacking assertions: test_only_mentions_assert",
    ]


def test_fixtures_named_like_tests_are_not_tests(tmp_path):
    _test_file(tmp_path, "test_fixtures.py", """\
        import pytest
        from pytest import fixture

        @pytest.fixture
        def test_workspace(tmp_path):
            return tmp_path

        @pytest.fixture(scope="module")
        def test_env():
            pass

        @fixture
        def test_db():
            ...

        def test_uses_them(test_workspace):
            assert test_workspace
    """)
    assert _messages(tmp_path) == []


def test_assertion_helpers_and_explicit_failures_count(tmp_path):
    _test_file(tmp_path, "test_helpers.py", """\
        import unittest
        import pytest

        def test_custom_helper():
            assert_identical(1, 1)

        def test_private_helper():
            _assert_only_aegis_added("a", "b")

        def test_mock_assertion(mock):
            mock.assert_called_once_with(1)

        def test_raises():
            with pytest.raises(ValueError):
                int("x")

        def test_warns():
            with pytest.warns(UserWarning):
                warn()

        def test_explicit_fail():
            pytest.fail("unreachable")

        class TestCase(unittest.TestCase):
            def test_unittest_assert(self):
                self.assertEqual(1, 1)

            def test_unittest_fail(self):
                self.fail("unreachable")
    """)
    assert _messages(tmp_path) == []


def test_a_skip_or_xfail_alone_is_not_an_assertion(tmp_path):
    _test_file(tmp_path, "test_skips.py", """\
        import unittest
        import pytest

        def test_skip_only():
            pytest.skip("optional dependency missing")

        def test_xfail_only():
            pytest.xfail("later")

        class TestCase(unittest.TestCase):
            def test_skip(self):
                self.skipTest("platform")
    """)
    assert _messages(tmp_path) == [
        "Low assertion density in test_skips.py: tests lacking assertions: test_skip_only, test_xfail_only, test_skip",
    ]


def test_only_test_modules_are_inspected(tmp_path):
    _test_file(tmp_path, "helpers.py", "def test_like_helper():\n    pass\n")
    _test_file(tmp_path, "conftest.py", "def test_hook():\n    pass\n")
    assert _messages(tmp_path) == []


def test_unparseable_test_file_is_reported_not_skipped(tmp_path):
    _test_file(tmp_path, "test_broken.py", "def test_x(:\n    assert True\n")
    issues = check_assertion_density(tmp_path)
    assert len(issues) == 1
    assert issues[0]["check"] == "assertion_density"
    assert issues[0]["message"].startswith("tests/test_broken.py: parse failed: ")


def test_legacy_encoded_test_file_is_parsed(tmp_path):
    path = tmp_path / "tests" / "test_legacy.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(
        "# -*- coding: latin-1 -*-\ndef test_cafe():\n    assert 'café'\n".encode("latin-1")
    )
    assert _messages(tmp_path) == []


def _quality_fixture(root):
    paths = [
        _test_file(root, "test_missing.py", "def test_missing():\n    value = 1\n"),
        _test_file(root, "test_stub.py", "def test_stub():\n    pass\n"),
        _test_file(root, "test_environment.py", """\
            if HAVE_ENV:
                def test_environment():
                    assert True
            else:
                def test_environment():
                    pytest.skip("environment unavailable")
        """),
        _test_file(root, "test_syntax.py", "def test_broken(:\n    pass\n"),
    ]
    _test_file(root, "helpers.py", "def ignored(:\n")
    return sorted(str(path) for path in paths)


def test_quality_checks_read_and_parse_once_per_file_per_run(tmp_path, monkeypatch):
    expected = _quality_fixture(tmp_path)
    reads, parses = [], []
    read_source, parse = quality_gate.read_python_source, quality_gate.ast.parse

    def counted_read(path):
        reads.append(path)
        return read_source(path)

    def counted_parse(source, filename):
        parses.append(filename)
        return parse(source, filename=filename)

    monkeypatch.setattr(quality_gate, "read_python_source", counted_read)
    # Replace this module's reference, leaving the process-wide ast module alone.
    monkeypatch.setattr(quality_gate, "ast", SimpleNamespace(
        **dict(vars(quality_gate.ast), parse=counted_parse)
    ))
    first = check_assertion_density(tmp_path)
    assert (reads, parses) == (expected, expected)
    reads.clear()
    parses.clear()
    assert check_assertion_density(tmp_path) == first
    assert (reads, parses) == (expected, expected)


def test_quality_check_issues_preserve_order_messages_and_parse_failure(tmp_path):
    _quality_fixture(tmp_path)
    broken = tmp_path / "tests" / "test_syntax.py"
    with pytest.raises(SyntaxError) as error:
        quality_gate.ast.parse("def test_broken(:\n    pass\n", filename=str(broken))
    assert check_assertion_density(tmp_path) == [
        {"check": "assertion_density", "file": "tests/test_missing.py", "lines": [1],
         "message": "Low assertion density in test_missing.py: tests lacking assertions: test_missing"},
        {"check": "assertion_density", "file": "tests/test_stub.py", "lines": [1],
         "message": "Low assertion density in test_stub.py: tests lacking assertions: test_stub"},
        {"check": "assertion_density", "file": "tests/test_stub.py", "lines": [1],
         "message": "Placeholder tests in test_stub.py: bare pass/ellipsis stubs: test_stub"},
        {"check": "assertion_density", "file": "tests/test_syntax.py",
         "message": f"tests/test_syntax.py: parse failed: {error.value}"},
    ]


def test_quality_check_read_failure_is_one_parse_issue(tmp_path, monkeypatch):
    path = _test_file(tmp_path, "test_unreadable.py", "def test_ok():\n    assert True\n")
    reads = []

    def refuse_read(filename):
        reads.append(filename)
        raise PermissionError("fixture read refused")

    monkeypatch.setattr(quality_gate, "read_python_source", refuse_read)
    assert check_assertion_density(tmp_path) == [
        {"check": "assertion_density", "file": "tests/test_unreadable.py",
         "message": "tests/test_unreadable.py: parse failed: fixture read refused"},
    ]
    assert reads == [str(path)]


def _rule(root: Path, rule_dir: str, rule_id: str, fields: str) -> None:
    path = root / ".aegis" / "rules" / rule_dir / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"---\nid: {rule_id}\n{fields}---\nBody\n", encoding="utf-8")


def test_each_missing_required_rule_field_is_an_issue(tmp_path):
    from aegis_core.verification.checkpoint_checks import check_rule_conventions

    _rule(tmp_path, "invariants", "inv-bare", "type: invariant\n")
    _rule(tmp_path, "traps", "trap-ok", "type: trap\ndomain: io\nenforcement: advisory\n")
    _rule(tmp_path, "personas", "persona-ok", "type: persona\ndomain: style\n")  # needs no enforcement

    issues = check_rule_conventions(tmp_path)

    assert issues == [
        {"check": "rule_conventions", "file": ".aegis/rules/invariants/inv-bare.md",
         "message": f".aegis/rules/invariants/inv-bare.md: missing required field '{name}'"}
        for name in ("domain", "enforcement")
    ]


def test_an_unreadable_ledger_is_a_rule_fitness_issue(tmp_path):
    from aegis_core.verification.checkpoint_checks import check_rule_fitness

    (tmp_path / ".aegis" / "state" / "ledger.jsonl").mkdir(parents=True)  # not a regular file

    issues = check_rule_fitness(tmp_path)

    assert [(i["check"], i["file"]) for i in issues] == [("rule_fitness", ".aegis/state/ledger.jsonl")]
    assert issues[0]["message"].startswith(".aegis/state/ledger.jsonl: cannot read ")
    assert issues[0]["message"].endswith("it is not a regular file")
