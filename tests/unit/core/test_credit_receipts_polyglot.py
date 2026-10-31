"""Incomplete structured test receipts never award confirmed rule credit."""
from __future__ import annotations

import pytest

from aegis_core import credit


def _derive(tests):
    commit = "c" * 40
    rows = [
        {"event": "check", "id": "checked", "tree": "a" * 40,
         "passed": True, "tests": tests},
        {"event": "report", "check": "checked", "rule": "trap-sample", "result": "tp"},
        {"event": "ci", "commit": commit, "ci_conclusion": "success"},
    ]
    result, = credit.derive(rows, landed=lambda tree: commit, verified_ci={commit: "success"})
    return result


@pytest.mark.parametrize("complete", [False, None, "true", 1])
def test_a_partial_or_malformed_receipt_cannot_count_as_confirmed_credit(complete):
    result = _derive({"exit": 0, "passed": 2, "failed": 0, "complete": complete})
    assert (result.state, result.counts, result.reason) == ("confirmed", False, "no_tests")


@pytest.mark.parametrize("failed", [1, True, "0", -1])
def test_a_failed_or_malformed_result_cannot_be_laundered_by_exit_zero(failed):
    result = _derive({"exit": 0, "passed": 2, "failed": failed, "complete": True})
    assert (result.state, result.counts, result.reason) == ("confirmed", False, "no_tests")


@pytest.mark.parametrize("fields", [{}, {"complete": True, "failed": 0}])
def test_valid_receipts_preserve_historical_missing_optional_fields(fields):
    result = _derive({"exit": 0, "passed": 2, **fields})
    assert (result.state, result.counts, result.result, result.reason) == ("confirmed", True, "tp", "")
