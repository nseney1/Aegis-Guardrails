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
Test-exemption reasons must be printable single-line text of at most 4096 Unicode
characters. Leading and trailing spaces are trimmed before both review and signing.
Explicit base selectors must also be printable single-line text of at most 4096
Unicode characters. Both reviews name the resolved base commit and its sanitized
subject; base commits larger than 1 MiB are refused before reading that subject.
Review fields retain printable Unicode and visibly escape other Unicode characters
after the shared ANSI/control filtering, so formatting cannot reorder trusted text.
Both flows list governance paths changed from the comparison base to HEAD as review
context; exemption signing still names only the selected fix commit and reason.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_cli import stdin_is_tty as _stdin_is_tty
from aegis_cli import sanitize_display
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core import approval_policy, gitsafe, governance, human_gate

__all__ = ["ApproveCommand", "run_approve"]

SCHEMA = "aegis.approve/v1"
SOURCE = "aegis approve"
_MAX_REASON_CHARS = 4096
_MAX_BASE_CHARS = 4096
_MAX_BASE_COMMIT_BYTES = 1024 * 1024


def _approval_payload(root: Path, status: str, **fields: Any) -> Dict[str, Any]:
    from aegis_core import primitives

    return {**primitives.envelope(SOURCE, {"machine": "local", "workspace": str(root)}, schema=SCHEMA),
            "status": status, **fields}


class _Refused(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _review_text(value: object) -> str:
    """Apply shared terminal filtering, then escape every remaining non-printable character."""
    text = sanitize_display(value, max_len=None)
    return ''.join(char if char.isprintable() else ascii(char)[1:-1] for char in text)


def _base_label(value: str) -> str:
    """Canonicalize, redact, then bound the selector used only for display."""
    from aegis_core.redaction import redact_insight_text

    if len(value) > _MAX_BASE_CHARS:
        return "[diagnostic omitted: too_large]"
    text = sanitize_display(value, max_len=None)
    return redact_insight_text(text, max_len=max(len(text), _MAX_BASE_CHARS))[:_MAX_BASE_CHARS]


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


def _base_review(top: Path, base_ref: str, commit: str, merge_base: str) -> str:
    """Describe the pinned base, bounding the commit before reading its subject."""
    error = "git could not read the base commit for review"
    try:
        kind = gitsafe.run(["cat-file", "-t", commit], top)
        if kind.returncode != 0 or kind.stdout not in (b"commit", b"commit\n"):
            raise _Refused("git_failed", error)
        sized = gitsafe.run(["cat-file", "-s", commit], top)
        if sized.returncode != 0 or len(sized.stdout) > 21:
            raise _Refused("git_failed", error)
        size = sized.stdout.removesuffix(b"\n")
        if len(size) > 20 or not size.isdigit():
            raise _Refused("git_failed", error)
        if int(size) > _MAX_BASE_COMMIT_BYTES:
            raise _Refused("git_failed", f"base commit is too large to review (limit {_MAX_BASE_COMMIT_BYTES} bytes)")
        shown = gitsafe.run(["log", "-1", "--no-show-signature", "--format=%s", "--encoding=UTF-8", commit, "--"], top)
    except gitsafe.GitError as exc:
        raise _Refused("git_failed", error) from exc
    if shown.returncode != 0:
        raise _Refused("git_failed", error)
    subject = _review_text(shown.stdout.decode("utf-8", "replace").rstrip("\n"))
    label = f"{_review_text(base_ref)} (= {_review_text(commit)} {subject})"
    if merge_base != commit:
        label += f"; comparison starts at {_review_text(merge_base)}"
    return label


def _preflight(root: Path, base: Optional[str]) -> Tuple[Path, str, str, str, str, Optional[str]]:
    """(top, base ref, pinned base, merge-base, review label, target), or a refusal."""
    top = gitsafe.toplevel(root)
    if top is None:
        raise _Refused("not_git", f"{root} is not inside a git work tree")
    head = gitsafe.head_commit(top)
    if not head:
        raise _Refused("no_head", "the repository has no commit yet")
    if base == "":
        base = None
    base_ref = base if base is not None else gitsafe.resolve_base_ref(top)
    if base_ref is None:
        raise _Refused("no_base", "no base branch found (origin/$GITHUB_BASE_REF, the branch origin/HEAD "
                                     "names, main, develop or master); pass --base")
    try:
        resolved = approval_policy.resolve_comparison(top, base_ref, discovered=base is None)
    except approval_policy.PolicyUnavailable as exc:
        raise _Refused("invalid_approval_policy", approval_policy.POLICY_UNAVAILABLE_DETAIL) from exc
    base_commit = resolved.commit
    label = _base_label(base_ref)
    if not base_commit:
        origin = "fetch origin; " if base_ref.startswith(("origin/", "refs/remotes/origin/")) else ""
        raise _Refused("no_base", f"cannot resolve the base {label!r}; {origin}fetch it or pass the full commit id")
    merge_base = gitsafe.merge_base(top, base_commit, head)
    if not merge_base:
        raise _Refused("no_common_history", "the resolved base and HEAD share no history; pass a base from HEAD's history")
    return top, label, base_commit, merge_base, _base_review(top, label, base_commit, merge_base), resolved.target


def _clean(top: Path) -> None:
    """The approval commit stays empty and a person approves only what is committed."""
    if _staged(top):
        raise _Refused("staged", "changes are staged: an approval commit stays empty, so commit or unstage them first")
    dirty = _uncommitted_governance(top)
    if dirty:
        raise _Refused("uncommitted", "governance files have uncommitted changes "
                       f"({', '.join(dirty)}): commit them first, then approve the committed state")


def _render_review(summary: List[str], warnings: List[str], use_json: bool) -> None:
    """Keep the full human review visible without adding text to JSON stdout."""
    stream = sys.stderr if use_json else sys.stdout
    for line in summary:
        print(_review_text(line), file=stream, flush=True)
    for warning in warnings:
        print(f"  warning: {_review_text(warning)}", file=stream, flush=True)


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
    _render_review(summary, warnings, use_json)
    head = _review_text((gitsafe.head_commit(top) or '')[:12])
    question = f"Sign {_review_text(what)} on top of {head}? [y/N] "
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
    top, base_ref, base_commit, merge_base, base_review, target = _preflight(root, base)
    try:
        policy = approval_policy.resolve_policy(top, base_commit, gitsafe.head_commit(top), target)
    except approval_policy.InvalidApprovalPolicy as exc:
        detail = (approval_policy.POLICY_UNAVAILABLE_DETAIL if isinstance(exc, approval_policy.PolicyUnavailable)
                  else approval_policy.INVALID_DETAIL)
        raise _Refused("invalid_approval_policy", detail) from exc
    if policy.mode in ("none", "review"):
        raise _Refused("not_required", "this target does not require a signed governance approval; "
                       "next_action: review and merge through the target branch's owner policy")
    if policy.error:
        print(policy.error, file=sys.stderr)
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
    paths = [_review_text(path) for status, _old, _new, path in entries
             if governance.category_of(path, deleted=status == "D") is not None]
    summary = [f"Governance changed since {base_review}: {', '.join(_review_text(item) for item in categories)}",
               f"Governance tree hash: {_review_text(digest)}",
               f"Governance paths changed: {', '.join(paths) or 'none'}"]
    return _sign(top, use_json, summary, f"an approval of governance state {digest[:12]}",
                 human_gate.approval_message(digest),
                 lambda commit: human_gate.verify_approval(top, commit, digest, base_commit),
                 {"governance_tree_hash": digest, "base": base_ref, "categories": categories})


def _approve_test_exemption(root: Path, base: Optional[str], exempt_commit: str, reason: str, use_json: bool) -> Dict[str, Any]:
    top, base_ref, base_commit, merge_base, base_review, _target = _preflight(root, base)
    fix_commit = gitsafe.resolve_commit(top, exempt_commit.strip())
    if not fix_commit:
        raise _Refused("unresolved", f"cannot resolve {exempt_commit!r} to a commit in {top}")
    _clean(top)
    clean_reason = reason.strip()
    try:
        entries = gitsafe.diff_entries(top, merge_base, "HEAD")
    except gitsafe.GitError as exc:
        raise _Refused("git_failed", "git could not list governance paths for review") from exc
    paths = [_review_text(path) for status, _old, _new, path in entries
             if governance.category_of(path, deleted=status == "D") is not None]
    return _sign(top, use_json, [f"Base: {base_review}", f"Exempting fix commit: {_review_text(fix_commit)}",
                               f"Reason: {_review_text(clean_reason)}",
                               f"Governance paths changed: {', '.join(paths) or 'none'}"],
                 f"a test exemption for {fix_commit[:12]}", human_gate.exemption_message(fix_commit, clean_reason),
                 lambda commit: human_gate.verify_test_exemption(top, commit, fix_commit, base_commit),
                 {"exempt_commit": fix_commit, "reason": clean_reason, "base": base_ref})


@gitsafe.scrubbed()
def run_approve(args: argparse.Namespace) -> int:
    root = Path(getattr(args, "workspace", None) or getattr(args, "_project_root", None) or Path.cwd())
    use_json = bool(getattr(args, "json", False))
    exempt_test = getattr(args, "exempt_test", None)
    reason = getattr(args, "reason", None)
    base = getattr(args, "base", None)
    if base is not None:
        error = None
        if not isinstance(base, str):
            error = "--base must be one line of printable text"
        elif len(base) > _MAX_BASE_CHARS:
            error = f"--base must be at most {_MAX_BASE_CHARS} characters"
        elif any(not char.isprintable() for char in base):
            error = "--base must be one line of printable text"
        if error:
            print(f"aegis approve: {error}", file=sys.stderr)
            return 2
    if exempt_test is not None:
        error = None
        if not isinstance(reason, str):
            error = "--exempt-test requires a non-empty --reason"
        elif len(reason) > _MAX_REASON_CHARS:
            error = f"--reason must be at most {_MAX_REASON_CHARS} characters"
        elif any(not char.isprintable() for char in reason):
            error = "--reason must be one line of printable text"
        elif not str(exempt_test).strip() or not reason.strip():
            error = "--exempt-test requires a non-empty --reason"
        if error:
            print(f"aegis approve: {error}", file=sys.stderr)
            return 2
    try:
        if exempt_test is not None:
            result = _approve_test_exemption(root, base, str(exempt_test), str(reason), use_json)
        else:
            result = _approve(root, base, use_json)
    except _Refused as exc:
        if use_json:
            print(json.dumps(_approval_payload(root, "declined" if exc.code == "declined" else "refused",
                                       code=exc.code, reason=str(exc)), indent=2))
        else:
            message = f"aegis approve: {exc}" if exc.code != "declined" else str(exc)
            print(_review_text(message),
                  file=sys.stdout if exc.code == "declined" else sys.stderr)
        return 1
    if use_json:
        print(json.dumps(_approval_payload(root, "approved", **result), indent=2))
        return 0
    if "exempt_commit" in result:
        print(f"Approved test exemption for {_review_text(result['exempt_commit'])} in commit {_review_text(result['commit'])}.")
    else:
        print(f"Approved governance state {_review_text(result['governance_tree_hash'])} in commit {_review_text(result['commit'])}.")
    if not result["verified"]:
        warning = (f"  warning: it does not verify against {_review_text(human_gate.ALLOWED_SIGNERS)} "
                   f"on {_review_text(result['base'])} yet ({_review_text(result['verification']['code'])}): "
                   "CI will not accept it until your key is listed there.")
        print(_review_text(warning))
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
