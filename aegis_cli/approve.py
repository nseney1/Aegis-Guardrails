"""aegis approve: sign a human approval of the governance files a branch changed (v4.3 §2.2).

Makes one signed, empty commit whose message carries ``Aegis-Approve: <governance tree hash>``
(``aegis_core.human_gate``). The hash covers the governance files as committed at HEAD and the
tests deleted since the base branch, so the approval names exactly the state the person saw, and
any later governance change (another deleted test included) voids it. CI checks it against
``allowed_signers`` on the base branch.

What it will not do:

- sign when nothing governance-related changed since the base branch (nothing to approve), or
  while governance files have uncommitted changes, or while anything is staged (the commit stays
  empty);
- run without a terminal and a typed ``y``: an approval is something a person looks at;
- use a signing program, key or format from the repository's config: they come from the
  user-level git config, which a clone cannot set;
- create a key or sign with one itself: git and ssh-keygen sign, Aegis only runs them. Aegis reads
  at most the first 64 KiB of a key file to classify its protection (plain, passphrase, hardware);
  it never copies, prints or stores it.

A signing key that is a plain, readable file with no passphrase is allowed to sign but flagged:
an agent running as you can use it too, so such an approval does not show a human was there.
Exit codes: 0 approved, 1 refused or declined, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core import gitsafe, governance, human_gate

__all__ = ["ApproveCommand", "run_approve"]

SCHEMA = "aegis.approve/v1"
SOURCE = "aegis approve"


def _stdin_is_tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _envelope(root: Path, status: str, **fields: Any) -> Dict[str, Any]:
    from aegis_core import baseline

    return {"schema": SCHEMA, **baseline.envelope(SOURCE, {"machine": "local", "workspace": str(root)}),
            "status": status, **fields}


class _Refused(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _staged(top: Path) -> bool:
    res = gitsafe.run(["diff-index", "--cached", "--quiet", "HEAD"], top)
    return res.returncode != 0


def _uncommitted_governance(top: Path) -> List[str]:
    changed = gitsafe.changed_files(top, "working", untracked=True)
    if changed is None:
        raise _Refused("git_failed", "git could not list the working tree's changes")
    gone = gitsafe.run(["diff-index", "-z", "--name-only", "--diff-filter=D", "HEAD"], top)
    deleted = [os.fsdecode(p) for p in gone.stdout.split(b"\0") if p] if gone.returncode == 0 else []
    return governance.touches_governance(changed, deleted)


def _preflight(root: Path, base: Optional[str]) -> Tuple[Path, str, str]:
    """(top, base ref, merge-base) that both flows sign against, or the refusal both share."""
    top = gitsafe.toplevel(root)
    if top is None:
        raise _Refused("not_git", f"{root} is not inside a git work tree")
    if not gitsafe.head_commit(top):
        raise _Refused("no_head", "the repository has no commit yet")
    base_ref = base or gitsafe.resolve_base_ref(top)
    if not base_ref:
        raise _Refused("no_base", "no base branch found (origin/$GITHUB_BASE_REF, the branch origin/HEAD "
                                     "names, main, develop or master); pass --base")
    merge_base = gitsafe.merge_base(top, base_ref, "HEAD")
    if not merge_base:
        raise _Refused("no_base", f"HEAD shares no history with {base_ref}: fetch with fetch-depth 0")
    return top, base_ref, merge_base


def _clean(top: Path) -> None:
    """The approval commit stays empty and a person approves only what is committed."""
    if _staged(top):
        raise _Refused("staged", "changes are staged: an approval commit stays empty, so commit or unstage them first")
    dirty = _uncommitted_governance(top)
    if dirty:
        raise _Refused("uncommitted", "governance files have uncommitted changes "
                       f"({', '.join(dirty)}): commit them first, then approve the committed state")


def _sign(top: Path, use_json: bool, summary: List[str], what: str, message: str,
          verify: Callable[[str], human_gate.Approval], fields: Dict[str, Any]) -> Dict[str, Any]:
    """The one way to sign: a key at user scope, a terminal, the summary, a typed y, the signed empty
    commit, then its verification against the base."""
    custody = human_gate.check_key_custody(top)
    if custody.status in ("none", "unsupported"):
        raise _Refused("no_key", f"{custody.detail}. Set it up with: git config --global gpg.format ssh; "
                       "git config --global user.signingkey <your key>")
    warnings = [custody.detail] if custody.status in ("plain_file", "agent", "unknown") else []
    if not _stdin_is_tty():
        raise _Refused("no_terminal", "an approval needs a terminal and a typed y: a person has to look at what is "
                       "approved, so this does not run from a script or an agent's shell")
    if not use_json:
        for line in [*summary, *(f"  warning: {warning}" for warning in warnings)]:
            print(line)
    question = f"Sign {what} on top of {(gitsafe.head_commit(top) or '')[:12]}? [y/N] "
    if use_json:  # stdout carries only the JSON document
        print(question, end="", file=sys.stderr, flush=True)
        question = ""
    try:
        answer = input(question)
    except EOFError:
        answer = ""
    if answer.strip().lower() not in ("y", "yes"):
        raise _Refused("declined", "No approval made.")
    try:
        commit = human_gate.signed_empty_commit(top, message, interactive=True)
    except human_gate.HumanGateError as exc:
        raise _Refused("sign_failed", str(exc)) from exc
    verdict = verify(commit)
    return {"commit": commit, **fields, "verified": verdict.valid,
            "verification": {"code": verdict.code, "reason": verdict.reason},
            "key_custody": custody.status, "warnings": warnings}


def _approve(root: Path, base: Optional[str], use_json: bool) -> Dict[str, Any]:
    top, base_ref, merge_base = _preflight(root, base)
    _clean(top)
    try:
        digest = human_gate.governance_tree_hash(top, "HEAD", base=merge_base)
        before = human_gate.governance_tree_hash(top, merge_base)
        entries = gitsafe.diff_entries(top, merge_base, "HEAD")
    except (human_gate.HumanGateError, gitsafe.GitError) as exc:
        raise _Refused("git_failed", str(exc)) from exc
    if digest == before:
        raise _Refused("nothing", f"nothing governance-related changed since {base_ref}: there is nothing to approve")
    categories = governance.touches_governance([p for _s, _o, _n, p in entries],
                                               [p for s, _o, _n, p in entries if s == "D"])
    summary = [f"Governance changed since {base_ref}: {', '.join(categories)}", f"Governance tree hash: {digest}"]
    return _sign(top, use_json, summary, f"an approval of governance state {digest[:12]}",
                 human_gate.approval_message(digest),
                 lambda commit: human_gate.verify_approval(top, commit, digest, base_ref),
                 {"governance_tree_hash": digest, "base": base_ref, "categories": categories})


def _approve_test_exemption(root: Path, base: Optional[str], exempt_commit: str, reason: str, use_json: bool) -> Dict[str, Any]:
    top, base_ref, _merge_base = _preflight(root, base)
    fix_commit = gitsafe.resolve_commit(top, exempt_commit.strip())
    if not fix_commit:
        raise _Refused("unresolved", f"cannot resolve {exempt_commit!r} to a commit in {top}")
    _clean(top)
    clean_reason = reason.strip()
    return _sign(top, use_json, [f"Exempting fix commit: {fix_commit}", f"Reason: {clean_reason}"],
                 f"a test exemption for {fix_commit[:12]}", human_gate.exemption_message(fix_commit, clean_reason),
                 lambda commit: human_gate.verify_test_exemption(top, commit, fix_commit, base_ref),
                 {"exempt_commit": fix_commit, "reason": clean_reason, "base": base_ref})


@gitsafe.scrubbed()
def run_approve(args: argparse.Namespace) -> int:
    root = Path(getattr(args, "workspace", None) or getattr(args, "_project_root", None) or Path.cwd())
    use_json = bool(getattr(args, "json", False))
    exempt_test = getattr(args, "exempt_test", None)
    reason = getattr(args, "reason", None)
    if exempt_test is not None and (not str(exempt_test).strip() or not isinstance(reason, str) or not reason.strip()):
        print("aegis approve: --exempt-test requires a non-empty --reason", file=sys.stderr)
        return 2
    try:
        if exempt_test is not None:
            result = _approve_test_exemption(root, getattr(args, "base", None), str(exempt_test), str(reason), use_json)
        else:
            result = _approve(root, getattr(args, "base", None), use_json)
    except _Refused as exc:
        if use_json:
            print(json.dumps(_envelope(root, "declined" if exc.code == "declined" else "refused",
                                       code=exc.code, reason=str(exc)), indent=2))
        else:
            print(f"aegis approve: {exc}" if exc.code != "declined" else str(exc),
                  file=sys.stdout if exc.code == "declined" else sys.stderr)
        return 1
    if use_json:
        print(json.dumps(_envelope(root, "approved", **result), indent=2))
        return 0
    if "exempt_commit" in result:
        print(f"Approved test exemption for {result['exempt_commit']} in commit {result['commit']}.")
    else:
        print(f"Approved governance state {result['governance_tree_hash']} in commit {result['commit']}.")
    if not result["verified"]:
        print(f"  warning: it does not verify against {human_gate.ALLOWED_SIGNERS} on {result['base']} yet "
              f"({result['verification']['code']}): CI will not accept it until your key is listed there.")
    print("  Push it with the branch; CI checks the signature against the base branch's keys.")
    return 0


class ApproveCommand(AegisCommand):
    """Sign a human approval of the governance files a branch changed."""

    name = "approve"
    category = CommandCategory.WORKFLOW
    help = "Sign a human approval of this branch's governance changes"
    description = (
        "Makes one signed, empty commit 'Aegis-Approve: <governance tree hash>' naming the governance "
        "files as committed at HEAD. Refuses when nothing governance-related changed since the base "
        "branch, when anything is staged or uncommitted, and without a terminal. The signing key, "
        "format and program come from your user-level git config (gpg.format ssh); no key is created."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--base", metavar="REF", default=None,
                            help="The base branch to measure governance changes against (default: origin/main, "
                                 "main, origin/develop, develop)")
        parser.add_argument("--exempt-test", metavar="COMMIT", default=None,
                            help="Sign a test exemption (Aegis-Exempt-Test) for a specific fix commit")
        parser.add_argument("--reason", metavar="TEXT", default=None,
                            help="Explanation for --exempt-test (signed into the commit)")

    def execute(self, args: argparse.Namespace) -> int:
        return run_approve(args)
