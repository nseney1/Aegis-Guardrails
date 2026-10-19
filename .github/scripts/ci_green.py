#!/usr/bin/env python3
"""Pre-tag check: the required workflow is green on the exact commit about to be tagged.

    python3 .github/scripts/ci_green.py <full-sha> [--workflow validate.yml]

Run it before `git tag`. It cannot be a step inside validate.yml: a job never sees its own
run's conclusion (the workflow's final `verdict` job attests the result for
`aegis doctor --release`, which is the check that does not trust this script's host).

It asks the GitHub REST API (`gh api`), never `gh run list`, and applies the v4.3 T1 rules to
`GET /repos/{owner}/{repo}/actions/runs?head_sha=<sha>&per_page=100` (one page: the API lists
the newest-created runs first, and only a commit with 100 or more runs could push a later re-run off it):

- only runs whose workflow `path` is `.github/workflows/<workflow>` (a run's name is not an
  identity), whose `head_sha` is the commit, whose head repository is the repository itself
  (a fork cannot make a commit green), and whose event is push, workflow_dispatch or release;
- cancelled runs are ignored; of the rest the newest run (its latest attempt) decides, and it
  must be completed with conclusion "success". A run still queued or in progress is not green.

Exit 0 only then; 1 when CI is not green (failed, still running, or never ran); 2 for a usage
error or when gh is missing or fails. Standard library plus the gh CLI.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_WORKFLOW = "validate.yml"
EVENTS = frozenset({"push", "workflow_dispatch", "release"})


class GhError(Exception):
    """gh is missing, failed, or printed something that is not a run list."""


def _api(endpoint: str) -> Dict[str, Any]:
    argv = ["gh", "api", "-H", "Accept: application/vnd.github+json", endpoint]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        raise GhError("gh (GitHub CLI) not found on PATH; install it and run `gh auth login`")
    except subprocess.TimeoutExpired:
        raise GhError("gh api did not answer within 120s")
    if proc.returncode != 0:
        raise GhError(f"gh api failed (exit {proc.returncode}): {proc.stderr.strip()}")
    try:
        body = json.loads(proc.stdout)
    except ValueError:
        raise GhError(f"could not parse gh output as JSON: {proc.stdout[:200]!r}")
    if not isinstance(body, dict) or not isinstance(body.get("workflow_runs"), list):
        raise GhError(f"could not parse gh output as a list of workflow runs: {proc.stdout[:200]!r}")
    return body


def _runs_for(sha: str) -> List[Dict[str, Any]]:
    # gh fills {owner}/{repo} from the repository of the current directory.
    body = _api(f"repos/{{owner}}/{{repo}}/actions/runs?head_sha={sha}&per_page=100")
    return [r for r in body["workflow_runs"] if isinstance(r, dict)]


def _full_name(run: Dict[str, Any], key: str) -> Optional[str]:
    value = run.get(key)
    name = value.get("full_name") if isinstance(value, dict) else None
    return name.lower() if isinstance(name, str) else None


def counted_runs(runs: List[Dict[str, Any]], sha: str, workflow: str) -> List[Dict[str, Any]]:
    """The runs that may decide: the required workflow, this commit, this repository, a trusted event, not cancelled."""
    wanted = f".github/workflows/{workflow}"
    kept = []
    for run in runs:
        path = run.get("path")
        head, repository = _full_name(run, "head_repository"), _full_name(run, "repository")
        run_id = run.get("id")
        if (run.get("head_sha") == sha and isinstance(path, str) and path.split("@", 1)[0] == wanted
                and run.get("event") in EVENTS and run.get("conclusion") != "cancelled"
                and head is not None and head == repository
                and isinstance(run_id, int) and not isinstance(run_id, bool)):
            kept.append(run)
    return kept


def newest(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The run that decides: the latest start (a re-run restarts its run), then the highest id."""
    return max(runs, key=lambda r: (str(r.get("run_started_at") or r.get("created_at") or ""), r["id"]))


def _fail(code: int, message: str) -> int:
    print(f"ci_green: {message}", file=sys.stderr)
    return code


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Exit 0 only if the required workflow is green on the exact commit.")
    parser.add_argument("sha", help="full 40-character commit SHA")
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW,
                        help=f"the required workflow file name under .github/workflows (default {DEFAULT_WORKFLOW})")
    args = parser.parse_args(argv)

    if not FULL_SHA.match(args.sha):
        return _fail(2, f"expected a full 40-character commit SHA in lowercase hex, got {args.sha!r}")
    try:
        runs = _runs_for(args.sha)
    except GhError as exc:
        return _fail(2, str(exc))

    counted = counted_runs(runs, args.sha, args.workflow)
    if not counted:
        return _fail(1, f"no CI run of {args.workflow} found for {args.sha}")
    decisive = newest(counted)
    if decisive.get("status") != "completed" or decisive.get("conclusion") != "success":
        state = decisive.get("conclusion") or decisive.get("status") or "unknown"
        return _fail(1, f"CI is not green on {args.sha} ({args.workflow} run {decisive.get('id')}: {state})")
    print(f"CI is green on {args.sha} ({args.workflow} run {decisive.get('id')}, attempt {decisive.get('run_attempt', 1)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
