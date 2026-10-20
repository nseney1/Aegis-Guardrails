"""check_test_coverage: Aegis's own suite map applies only inside the Aegis packages (R-checks-54).

Given a source tree and a tests/ tree under tmp_path, When check_test_coverage runs, Then a
source file counts as covered only by a test named after it (or its package path) or, for
aegis_*/soma_* sources, by a suite the Aegis map names.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

import pytest

from aegis_core.verification.checkpoint_checks import check_test_coverage


def _tree(root: Path, files: Iterable[str]) -> None:
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n" if not rel.startswith("tests/") else "def test_x():\n    assert True\n",
                        encoding="utf-8")


def _messages(root: Path) -> List[str]:
    return [issue["message"] for issue in check_test_coverage(root)]


@pytest.mark.parametrize("source,suite", [
    ("mylib/report.py", "tests/test_cli.py"),
    ("mylib/base.py", "tests/test_check_sarif.py"),
    ("mylib/server.py", "tests/test_mcp_dispatch.py"),
    ("mylib/tools.py", "tests/test_mcp_tools_contract.py"),
    ("mylib/errors.py", "tests/test_domain_errors.py"),
    ("mylib/hooks/pre.py", "tests/test_hooks_lifecycle.py"),
    ("mylib/policy.py", "tests/test_forbid_ast_rules.py"),
    ("mylib/serializer.py", "tests/test_yaml_engine_roundtrip.py"),
    ("mylib/runner.py", "tests/unit/verification/test_layer1.py"),
    ("mylib/credit.py", "tests/test_f_b2_credit_model_acceptance.py"),
], ids=["report", "base", "server", "tools", "errors", "hooks", "policy", "serializer", "runner", "credit"])
def test_another_repository_is_not_covered_by_an_aegis_suite(tmp_path, source, suite):
    _tree(tmp_path, [source, suite])
    stem = Path(source).stem
    assert _messages(tmp_path) == [f"Missing test file for {stem}.py: expected tests/test_{stem}.py"]


@pytest.mark.parametrize("source,suite", [
    ("aegis_cli/formatters/report.py", "tests/unit/cli/test_cli.py"),
    ("aegis_mcp/server.py", "tests/unit/mcp/test_mcp_dispatch.py"),
    ("aegis_core/verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("soma_core/credit.py", "tests/test_f_b2_credit_model_acceptance.py"),
], ids=["cli-report", "mcp-server", "runner", "legacy-brand"])
def test_the_aegis_layout_is_still_covered_by_its_mapped_suites(tmp_path, source, suite):
    _tree(tmp_path, [source, suite])
    assert _messages(tmp_path) == []


@pytest.mark.parametrize("source,test", [
    ("mylib/report.py", "tests/test_report.py"),
    ("mylib/pkg/base.py", "tests/mylib/pkg/test_base.py"),
], ids=["flat", "mirrored"])
def test_a_test_named_after_the_file_covers_it_in_any_repository(tmp_path, source, test):
    _tree(tmp_path, [source, test])
    assert _messages(tmp_path) == []
