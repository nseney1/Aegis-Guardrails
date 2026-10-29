"""Match rules to changed files (git working tree or explicit list)."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from aegis_core import gitsafe
from aegis_core.match import workspace_files
from aegis_core.rules import Rule, RuleSet, load_rules
from aegis_core.workspace.base import Workspace
from aegis_core.workspace import literal_workspace

__all__ = ["match_rules_to_changes", "matched_rules"]


def get_changed_files(workspace: str) -> list[str]:
    """What the session changed: the last commit plus uncommitted edits (``git diff HEAD~1``);
    in a repository with one commit, the uncommitted and untracked files (``git status``)."""
    uncommitted = gitsafe.changed_files(workspace, "working") or []
    if gitsafe.resolve_commit(workspace, "HEAD~1"):
        files = list(dict.fromkeys((gitsafe.changed_files(workspace, "head") or []) + uncommitted))
        if files:
            return files
    untracked = gitsafe.list_files(workspace, tracked=False) or []
    return list(dict.fromkeys(uncommitted + untracked))


def matched_rules(
    workspace: Workspace | Path | str, changed_files: List[str], ruleset: Optional[RuleSet] = None,
) -> List[Tuple[Rule, List[str]]]:
    """Each served rule that applies to some of ``changed_files`` (``Rule.applies_to``),
    with those files (workspace-relative, each once). One loader, one matcher
    (aegis_core.rules, aegis_core.match), the same inputs aegis scan matches.

    Rules that cannot be loaded are not served, so they match nothing here; a caller
    that serves rules (the SDK scan) refuses ``ruleset.errors`` first.
    """
    ws = literal_workspace(workspace)
    rules = ruleset if ruleset is not None else load_rules(ws)
    files = workspace_files(ws.root, changed_files)
    out = []
    for rule in rules.served:
        matched = rule.matching_files(files)
        if matched:
            out.append((rule, matched))
    return out


def match_rules_to_changes(
    workspace: Workspace | Path | str, changed_files: List[str], ruleset: Optional[RuleSet] = None,
) -> List[dict]:
    """``matched_rules`` as ``Rule.as_dict()`` plus ``_matched_files``."""
    out = []
    for rule, matched in matched_rules(workspace, changed_files, ruleset):
        data = rule.as_dict()
        data["_matched_files"] = matched
        out.append(data)
    return out
