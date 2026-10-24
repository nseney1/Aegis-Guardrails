"""GitHub ruleset construction and administration through the gh transport (L2)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from aegis_core import ghcli
from aegis_core.human_gate import GITHUB_ACTIONS_APP_ID, HumanGateError

__all__ = ["RULESET_NAME", "build_ruleset", "create_ruleset", "ruleset_exists"]

RULESET_NAME = "aegis-human-gate"


def build_ruleset(tier: str, contexts: Iterable[str]) -> Dict[str, Any]:
    if tier not in ("A", "B"):
        raise ValueError(f"tier must be 'A' or 'B', got {tier!r}")
    reviewed = tier == "A"
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1 if reviewed else 0,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": reviewed,
                    "require_last_push_approval": reviewed,
                    "required_review_thread_resolution": False,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": False,
                    "required_status_checks": [{"context": c, "integration_id": GITHUB_ACTIONS_APP_ID} for c in contexts],
                },
            },
        ],
    }


def ruleset_exists(root: Any, gh: Optional[ghcli.GhRunner] = None) -> bool:
    runner: ghcli.GhRunner = gh if gh is not None else ghcli.default_gh_runner
    listing, why = ghcli.gh_json(runner, "repos/{owner}/{repo}/rulesets", Path(root))
    if why is not None or not isinstance(listing, list):
        raise HumanGateError(why or "gh api rulesets did not return a list")
    return any(isinstance(r, dict) and r.get("name") == RULESET_NAME for r in listing)


def create_ruleset(root: Any, ruleset: Mapping[str, Any], gh: Optional[ghcli.GhRunner] = None) -> Dict[str, Any]:
    runner: ghcli.GhRunner = gh if gh is not None else ghcli.default_gh_runner
    result = runner(
        ["api", "--method", "POST", "repos/{owner}/{repo}/rulesets", "--input", "-"],
        json.dumps(ruleset).encode("utf-8"),
        Path(root),
    )
    if result is None:
        raise HumanGateError("gh is not installed")
    if result.returncode != 0:
        raise HumanGateError(f"gh could not create the ruleset: {' '.join(result.stderr.split())[:300]}")
    try:
        created = json.loads(result.stdout)
    except ValueError:
        created = {}
    return created if isinstance(created, dict) else {}
