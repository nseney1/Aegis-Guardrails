"""This repository adopts the owner's approval map (Git model ADR AC1)."""
import json
from pathlib import Path

import pytest

from aegis_core import approval_policy

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def repo_config():
    return json.loads((REPO / ".aegis" / "config.json").read_text(encoding="utf-8"))


def test_repo_approval_map_matches_owner_decision(repo_config):
    assert repo_config["v"] == 1
    assert repo_config.get("approvals") == {
        "main": "signature",
        "develop": "review",
        "*": "none",
    }


@pytest.mark.parametrize("target, expected", [
    ("main", "signature"),
    ("develop", "review"),
    ("feature/manager-workspace-prototype", "none"),
    ("feature/teams-t2a-gm-2", "none"),
    ("release/next", "none"),
    ("main-extra", "none"),
    ("develop-extra", "none"),
    (None, "signature"),
])
def test_repo_approval_modes_use_public_policy(repo_config, target, expected):
    policy = approval_policy.parse_policy(repo_config)
    assert policy is not None
    assert approval_policy.mode_for(policy, target) == expected
