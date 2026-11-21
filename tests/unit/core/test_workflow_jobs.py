"""Workflow parsing keeps literal check names and the reasons jobs cannot count."""
import pytest

from aegis_core import workflow_jobs


@pytest.mark.parametrize("keys,reason", [
    ("", None),
    ("    if: false\n",
     "the Aegis job gate has a condition (if: false) and may be skipped, which GitHub reports as a passing check"),
    ("    continue-on-error: true\n",
     "the Aegis job gate sets continue-on-error, so it passes even when aegis check fails"),
    ("    needs: [lint]\n",
     "the Aegis job gate needs other jobs without if: always(), so a failed or skipped job it needs skips it"),
    ("    needs: [lint]\n    if: always()\n", None),
], ids=["direct", "conditional", "continue-on-error", "needs", "aggregate"])
def test_job_names_and_refusal_reasons(keys, reason):
    text = "jobs:\n  gate:\n" + keys + "    steps:\n      - run: aegis check --ci\n"
    assert workflow_jobs.aegis_job_verdicts(text) == {"gate": reason}
    assert workflow_jobs.aegis_check_jobs(text) == (["gate"] if reason is None else [])


@pytest.mark.parametrize("text", [
    "",
    "jobs: {gate: invalid}\n",
    "jobs:\n  gate:\n    steps:\n      - run: aegis check\n",
    "jobs:\n  gate:\n    name: '${{ matrix.os }}'\n    steps:\n      - run: aegis check --ci\n",
    "jobs:\n  gate:\n    strategy:\n      matrix:\n        os: [ubuntu-latest]\n    steps:\n      - run: aegis check --ci\n",
], ids=["empty", "unreadable-layout", "no-ci", "templated-name", "matrix"])
def test_workflows_without_a_literal_ci_check_have_no_verdict(text):
    assert workflow_jobs.aegis_job_verdicts(text) == {}
    assert workflow_jobs.aegis_check_jobs(text) == []
