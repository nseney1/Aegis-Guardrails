"""Ruleset JSON and administration through the gh transport boundary."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core import ghcli, human_gate
from aegis_core import github_ruleset
from tests import helpers_humangate as hg


@pytest.mark.parametrize("tier", ["A", "B"])
def test_the_ruleset_pins_every_required_check_to_github_actions(tier):
    ruleset = github_ruleset.build_ruleset(tier, ["aegis-check", "Unit tests"])
    (checks,) = [r["parameters"]["required_status_checks"] for r in ruleset["rules"] if r["type"] == "required_status_checks"]
    assert checks == [{"context": "aegis-check", "integration_id": 15368}, {"context": "Unit tests", "integration_id": 15368}]
    assert human_gate.GITHUB_ACTIONS_APP_ID == 15368



def test_ruleset_variants_differ_in_reviews_only():
    a, b = github_ruleset.build_ruleset("A", ["validate", "test-windows"]), github_ruleset.build_ruleset("B", ["validate"])
    by_type = lambda ruleset: {r["type"]: r.get("parameters", {}) for r in ruleset["rules"]}  # noqa: E731
    assert by_type(a)["pull_request"]["required_approving_review_count"] == 1
    assert by_type(a)["pull_request"]["require_code_owner_review"] is True
    assert by_type(a)["pull_request"]["require_last_push_approval"] is True  # the review approval needs it
    assert by_type(b)["pull_request"]["required_approving_review_count"] == 0
    assert [c["context"] for c in by_type(a)["required_status_checks"]["required_status_checks"]] == [
        "validate", "test-windows"]
    for ruleset in (a, b):
        assert ruleset["bypass_actors"] == [] and ruleset["enforcement"] == "active"
        assert ruleset["name"] == github_ruleset.RULESET_NAME
        assert {"non_fast_forward", "deletion"} <= {r["type"] for r in ruleset["rules"]}
    with pytest.raises(ValueError):
        github_ruleset.build_ruleset("C", ["x"])



GOLDEN_RULESETS = {'A': '{"bypass_actors":[],"conditions":{"ref_name":{"exclude":[],"include":["~DEFAULT_BRANCH"]}},"enforcement":"active","name":"aegis-human-gate","rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"parameters":{"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true,"require_last_push_approval":true,"required_approving_review_count":1,"required_review_thread_resolution":false},"type":"pull_request"},{"parameters":{"required_status_checks":[{"context":"aegis-check","integration_id":15368},{"context":"Unit '
      'tests","integration_id":15368}],"strict_required_status_checks_policy":false},"type":"required_status_checks"}],"target":"branch"}',
 'B': '{"bypass_actors":[],"conditions":{"ref_name":{"exclude":[],"include":["~DEFAULT_BRANCH"]}},"enforcement":"active","name":"aegis-human-gate","rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"parameters":{"dismiss_stale_reviews_on_push":true,"require_code_owner_review":false,"require_last_push_approval":false,"required_approving_review_count":0,"required_review_thread_resolution":false},"type":"pull_request"},{"parameters":{"required_status_checks":[{"context":"aegis-check","integration_id":15368},{"context":"Unit '
      'tests","integration_id":15368}],"strict_required_status_checks_policy":false},"type":"required_status_checks"}],"target":"branch"}'}


@pytest.mark.parametrize("tier", ["A", "B"])
def test_ruleset_json_matches_pre_extraction_golden(tier):
    ruleset = github_ruleset.build_ruleset(tier, ["aegis-check", "Unit tests"])
    assert json.dumps(ruleset, sort_keys=True, separators=(",", ":")) == GOLDEN_RULESETS[tier]


def test_ruleset_admin_keeps_get_and_post_payloads(tmp_path):
    gh = hg.FakeGh(rulesets=[{"name": "other"}])
    assert github_ruleset.ruleset_exists(tmp_path, gh=gh) is False
    gh.rulesets.append({"name": "aegis-human-gate"})
    assert github_ruleset.ruleset_exists(tmp_path, gh=gh) is True
    body = github_ruleset.build_ruleset("A", ["aegis-check"])
    assert github_ruleset.create_ruleset(tmp_path, body, gh=gh) == {"id": 7, "name": "aegis-human-gate"}
    assert gh.calls == [
        (("api", "--method", "GET", "repos/{owner}/{repo}/rulesets"), None),
        (("api", "--method", "GET", "repos/{owner}/{repo}/rulesets"), None),
        (("api", "--method", "POST", "repos/{owner}/{repo}/rulesets", "--input", "-"), json.dumps(body).encode("utf-8")),
    ]


@pytest.mark.parametrize("operation", ["ruleset_exists", "create_ruleset"])
def test_ruleset_admin_missing_gh_keeps_the_public_error(tmp_path, operation):
    gh = hg.FakeGh()
    gh.missing = True
    args = (tmp_path,) if operation == "ruleset_exists" else (tmp_path, {})
    with pytest.raises(human_gate.HumanGateError, match="^gh is not installed$"):
        getattr(github_ruleset, operation)(*args, gh=gh)


@pytest.mark.parametrize("stdout, expected", [("invalid", {}), ("[]", {}), ('{"id":7}', {"id": 7})])
def test_ruleset_creation_keeps_its_response_contract(tmp_path, stdout, expected):
    def gh(argv, stdin=None, cwd=None):
        assert cwd == Path(tmp_path)
        return ghcli.GhResult(0, stdout, "")

    assert github_ruleset.create_ruleset(tmp_path, {}, gh=gh) == expected
