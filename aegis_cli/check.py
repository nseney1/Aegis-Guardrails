"""aegis check — the verification gate for AI coding agent changes.

  aegis check [FILES...]              Layer 1: workspace checkpoint plus call_graph,
                                      import_guard and forbid_ast on FILES (default: files
                                      changed against HEAD, staged, or the branch base)
  aegis check --strict                also fail on checkpoint warnings
  aegis check --hook                  git pre-commit mode: Layer 1 only, never a model call
  aegis check --full --plan TEXT      add Layer 2: adversarial review by --llm-cmd
  aegis check --lane LANE [--base REF] [--paths GLOB...] [--base-policy]
                                      post-lane gate: containment and Python test
                                      integrity of the lane's commits (aegis_core.lane_gate)
  aegis check [--base REF]            with a baseline (.aegis/baseline.json), fail only on
                                      findings it does not hold; --base reads it from REF
  aegis check --write-baseline        record the current findings (aegis_core.baseline)
  aegis check --prune-baseline        drop the baseline entries whose findings are fixed
  aegis check --record [--tests] [--base REF] [--json]
                                      bind the work tree to a git tree, run Layer 1 (and the user-scope
                                      tests.command) on a snapshot of it, write one ledger check row
  aegis check --card [--json]         the day-0 card (aegis_core.card); changes nothing
  aegis check --partition --split NAME=GLOB[,GLOB...] --split NAME=...
                                      cross-lane call, def and import edges between planned
                                      lanes (aegis_core.partition); changes nothing
  aegis check --ci [--base REF] [--head REF] [--no-exec] [--format text|json|github]
                                      the CI weakening check (aegis_core.rule_integrity): the
                                      rules that bind lose nothing between merge-base(REF, HEAD)
                                      and HEAD without a signed human approval; --no-exec reads
                                      git objects only and runs none of the repository's code

--lane, --partition, --card, --write-baseline, --prune-baseline, --record and --ci are modes of
their own: one at a time, and none takes FILES, --full or a plan.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from aegis_cli.base import AegisCommand, CommandCategory
from aegis_cli.verify import run_verify

__all__ = ["CheckCommand", "run_check"]


# Every other mode and the options a --record run would silently ignore.
_NOT_WITH_RECORD = (
    ("--lane", "lane", None), ("--partition", "partition", False), ("--card", "card", False),
    ("--write-baseline", "write_baseline", False), ("--prune-baseline", "prune_baseline", False),
    ("--hook", "hook", False), ("--full", "full", False), ("--strict", "strict", False),
    ("--dry-run", "dry_run", False), ("--plan", "plan", None), ("--plan-file", "plan_file", None),
    ("--llm-cmd", "llm_cmd", None), ("--paths", "paths", None), ("--base-policy", "base_policy", False),
    ("--split", "split", None), ("--ci", "ci", False), ("--head", "head", None), ("FILES", "files", None),
)


def _record_conflict(args: argparse.Namespace) -> str:
    for flag, attr, idle in _NOT_WITH_RECORD:
        value = getattr(args, attr, idle)
        if value not in (idle, [], ()) and value is not idle:
            return flag
    return ""


def _run_record(args: argparse.Namespace) -> int:
    """`aegis check --record [--tests]`: 0 recorded and passed, 1 failed or could not run, 2 usage."""
    from aegis_cli import sanitize_display
    from aegis_cli.verify import _resolve_git_cwd, _wants_json
    from aegis_core import baseline, checkrun

    clash = _record_conflict(args)
    if clash:
        print(f"Error: --record does not combine with {clash}: it checks the whole tree and records one row",
              file=sys.stderr)
        return 2
    root = _resolve_git_cwd(args)
    use_json = _wants_json(args)
    if not os.path.isdir(root):
        print(f"Error: workspace does not exist: {sanitize_display(root, max_len=len(root))}", file=sys.stderr)
        return 1
    outcome = checkrun.record(root, tests=bool(getattr(args, "tests", False)), base=getattr(args, "base", None))
    row = outcome.row or {}
    if use_json:
        document = baseline.envelope("aegis check --record", {"workspace": str(root), "tree": row.get("tree"),
                                                              "base": row.get("base")})
        document.update(status=outcome.status, witness=row.get("witness"), reason=outcome.reason, check=row or None,
                        tree=outcome.binding.as_dict() if outcome.binding else None)
        print(json.dumps(document, indent=2))
    elif outcome.status == "recorded":
        tests = row.get("tests")
        detail = f", tests {tests['passed']} passed, {tests['failed']} failed" if tests else ", Layer 1 only"
        print(f"recorded: tree {row['tree'][:12]} {'passed' if row['passed'] else 'FAILED'}{detail}"
              + ("; protected paths changed: no credit until approved" if row["protected_changed"] else ""))
        if outcome.hint:
            print(f"hint: {outcome.hint}")
    else:
        print(f"{outcome.status}: {sanitize_display(outcome.reason, max_len=300)}", file=sys.stderr)
    if outcome.status != "recorded":
        return 1
    return 0 if row.get("passed") else 1


def run_check(args: argparse.Namespace) -> int:
    """Execute `aegis check`."""
    if getattr(args, "no_exec", False) and not getattr(args, "ci", False):
        print("Error: --no-exec only applies with --ci", file=sys.stderr)
        return 2
    if getattr(args, "tests", False) and not getattr(args, "record", False):
        print("Error: --tests only applies with --record", file=sys.stderr)
        return 2
    fmt = str(getattr(args, "format", None) or "text").lower()
    if fmt == "github" and not getattr(args, "ci", False):
        print("Error: --format github only applies with --ci", file=sys.stderr)
        return 2
    if fmt == "sarif" and not getattr(args, "ci", False):
        print("Error: argument --format: invalid choice: 'sarif' (only applies with --ci)", file=sys.stderr)
        return 2
    if getattr(args, "record", False):
        return _run_record(args)
    if getattr(args, "ci", False):
        return _run_ci(args)
    if getattr(args, "head", None) is not None:
        print("Error: --head only applies with --ci", file=sys.stderr)
        return 2
    return run_verify(args)


# ── --ci: the rule weakening check ───────────────────────────────────────────

_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}")
_FULL_SHA = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")


def _event_pull() -> dict:
    """The ``pull_request`` object of the event file GitHub Actions names in $GITHUB_EVENT_PATH; {} anywhere else."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            pull = json.load(handle).get("pull_request") or {}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}
    return pull if isinstance(pull, dict) else {}


def _event_shas() -> tuple[str | None, str | None]:
    """(base, head) commit ids of the pull request this CI job runs for; (None, None) anywhere else."""
    try:
        pull = _event_pull()
        return pull["base"]["sha"], pull["head"]["sha"]
    except (KeyError, TypeError):
        return None, None


def _event_pull_request():
    """The pull request of a ``pull_request`` run, for tier A's review approval: its number, author and
    full head commit id, each checked; None for any other event or any value in doubt (no gh call then)."""
    from aegis_core import human_gate

    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return None
    try:
        pull = _event_pull()
        number, login, sha = pull["number"], pull["user"]["login"], pull["head"]["sha"]
    except (KeyError, TypeError):
        return None
    if type(number) is not int or number < 1 or not isinstance(login, str) or not _LOGIN.fullmatch(login) \
            or not isinstance(sha, str) or not _FULL_SHA.fullmatch(sha):
        return None
    return human_gate.PullRequest(number, login, sha.lower())


def _escape_annotation(text: str, prop: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if prop else text


# What --no-exec leaves out: both rerun the pull request's code (snapshot tests, fix-commit tests).
_NOT_EXECUTED = ("regression", "trailer_checks")


def _build_ci_document(report, root: str, reg_report=None, cov_report=None, perf_report=None, trailer_checks=None,
                       skipped=()) -> dict:
    reg_blocking = bool(reg_report is not None and reg_report.blocking)
    cov_blocking = bool(cov_report is not None and not cov_report.get("passed", True))
    perf_blocking = bool(perf_report is not None and not perf_report.get("passed", True))
    trailer_blocking = bool(trailer_checks and any(t.get("failed") for t in trailer_checks))
    document = report.as_dict(root)
    if reg_report is not None:
        document["regression"] = reg_report.as_dict(root)
    if cov_report is not None:
        document["coverage"] = cov_report
    if perf_report is not None:
        document["perf"] = perf_report
    if trailer_checks:
        document["trailer_checks"] = trailer_checks
    if skipped:
        document["skipped"] = list(skipped)
    if reg_blocking or cov_blocking or perf_blocking or trailer_blocking:
        document["status"] = "fail"
    return document


def _write_step_summary_if_configured(document: dict, root: str) -> None:
    from pathlib import Path
    from aegis_cli.formatters.report import format_github_step_summary
    from aegis_core.config import env_github_step_summary
    from aegis_core.storage import atomic_write_text

    summary_path = env_github_step_summary()
    if not summary_path:
        return
    try:
        target = Path(summary_path)
        existing = target.read_text(encoding="utf-8") if target.exists() else ""
        md = format_github_step_summary(document, workspace_root=root)
        atomic_write_text(target, existing + md)
    except OSError:
        pass


def _print_ci(report, fmt: str, root: str, reg_report=None, cov_report=None, perf_report=None, trailer_checks=None,
              skipped=()) -> None:
    from aegis_cli import sanitize_display
    from aegis_cli.formatters.report import format_sarif_report

    reg_blocking = bool(reg_report is not None and reg_report.blocking)
    trailer_blocking = bool(trailer_checks and any(t.get("failed") for t in trailer_checks))
    document = _build_ci_document(report, root, reg_report, cov_report, perf_report, trailer_checks=trailer_checks,
                                  skipped=skipped)
    _write_step_summary_if_configured(document, root)

    if fmt == "sarif":
        print(str(format_sarif_report(document, workspace_root=root)))
        return
    if fmt == "json":
        print(json.dumps(document, indent=2))
        return
    approved = bool(report.weakenings) and report.passed
    gated = report.governance_gated
    cats = ", ".join(report.governance_categories)
    note = (f"governance files changed ({cats}) but the base lists no key in allowed_signers, "
            "so no approval can be required (tier C: detection only)") if cats and not gated else ""
    if fmt == "github":
        level, title = ("notice", "weakening approved") if approved else ("error", "weakening without approval")
        for item in report.weakenings:
            print(f"::{level} file={_escape_annotation(item.path, True)},title={_escape_annotation(title, True)}"
                  f"::{_escape_annotation(f'{item.code}: {item.rule}: {item.message}')}")
        level, title = ("notice", "governance change approved") if report.passed else ("error", "governance change without approval")
        for path, category in report.governance_paths if gated else ():
            print(f"::{level} file={_escape_annotation(path, True)},title={_escape_annotation(title, True)}"
                  f"::{_escape_annotation(f'governance:{category}: {path} changed; it passes only with a signed approval (aegis approve)')}")
        if note:
            print(f"::warning title={_escape_annotation('governance change not enforced', True)}::{_escape_annotation(note)}")
        if reg_report is not None:
            reg_level = "error" if reg_report.tier == "gate" else "warning"
            reg_title = "regression check failed" if reg_report.tier == "gate" else "regression check warning"
            for finding in reg_report.findings:
                print(
                    f"::{reg_level} file={_escape_annotation(finding.path, True)},"
                    f"title={_escape_annotation(reg_title, True)}"
                    f"::{_escape_annotation(f'{finding.code}: {finding.message}')}"
                )
    short = lambda sha: sha[:10]  # noqa: E731
    span = f"{short(report.merge_base)}..{short(report.head)}"
    if not report.weakenings and not gated:
        if reg_blocking:
            print(f"aegis check --ci: FAILED: regression check failed ({len(reg_report.findings)} finding(s), {span})")
        elif trailer_blocking:
            print(f"aegis check --ci: FAILED: Aegis-Check trailer divergence ({span})")
        elif report.merge_base == report.head:  # a push to the base branch, a dispatch run, a stale branch
            print(f"aegis check --ci: note: base and head are the same commit; nothing was compared ({span})")
        else:
            print(f"aegis check --ci: PASSED, no rule weakened ({report.rules_checked} binding rule(s) at the merge base, {span})")
    else:
        count, paths = len(report.weakenings), len(report.governance_paths)
        if not gated:
            what, counted, done = "weakening", f"{count} finding{'' if count == 1 else 's'}", f"{count} weakening(s)"
        elif not count:
            what, counted, done = "governance change", f"{paths} path(s) in {cats}", f"{paths} governance path(s)"
        else:
            what, counted = "weakening and governance change", f"{count} finding(s), {paths} path(s) in {cats}"
            done = f"{count} weakening(s) and {paths} governance path(s)"
        if not report.passed:
            print(f"aegis check --ci: FAILED: {what} without approval ({counted}, {span})")
        elif reg_blocking:  # approved, but another check fails: say which, not "without approval"
            print(f"aegis check --ci: FAILED: regression check failed ({len(reg_report.findings)} finding(s), {span})")
        elif trailer_blocking:
            print(f"aegis check --ci: FAILED: Aegis-Check trailer divergence ({span})")
        else:
            approval = report.approval
            signer = (f"review of {approval.signer}" if approval.source == "review"
                      else approval.signer or "a key in the base allowed_signers")
            print(f"aegis check --ci: PASSED, {done} approved by {sanitize_display(signer, 120)} ({span})")
        for item in report.weakenings:
            print(sanitize_display(f"  [{item.code}] {item.rule} ({item.path}): {item.message}", 400))
        for path, category in report.governance_paths if gated else ():
            print(sanitize_display(f"  [governance:{category}] {path}", 400))
        if not report.passed:
            print(f"  A {what} passes only with a signed approval: aegis approve (a key listed in allowed_signers on the base "
                  "branch), or at tier A with an approving review of the head commit by someone other than its author.")
    if note:
        print(sanitize_display(f"  note: {note}", 400))
    if reg_report is not None:
        if reg_report.findings and reg_report.tier != "gate":
            print('  regression tier: warning (advisory; blocking at gate tier via --strict or regression.tier="gate")')
        for finding in reg_report.findings:
            tag = "FAIL" if reg_report.tier == "gate" else "WARN"
            print(sanitize_display(f"  [{tag}:regression/{finding.code}] ({finding.path}): {finding.message}", 400))
        if reg_report.total_fix_commits > 0 and reg_report.exempted_count > 0:
            rate_pct = f"{reg_report.exemption_rate * 100:.1f}%"
            prune_note = " (exceeds 25% prune-box threshold)" if reg_report.prune_box_exceeded else ""
            print(
                sanitize_display(
                    f"  regression exemptions: {reg_report.exempted_count}/{reg_report.total_fix_commits} "
                    f"({rate_pct}){prune_note}",
                    400,
                )
            )
        for untested in reg_report.untested_changes:
            files_str = ", ".join(untested.source_files[:5])
            print(
                sanitize_display(
                    f"  [untested-change] {untested.commit[:10]} ({untested.subject}): {files_str}",
                    400,
                )
            )
    for t_chk in trailer_checks or ():
        if t_chk.get("failed"):
            print(sanitize_display(f"  [FAIL:trailer-divergence] {t_chk['commit'][:10]}: {t_chk.get('reason', '')}", 400))
    if skipped:
        print("  note: --no-exec: the regression and Aegis-Check trailer checks were not run")


def _run_ci(args: argparse.Namespace) -> int:
    """`aegis check --ci`: 0 nothing weakened or every weakening approved, 1 otherwise, 2 usage."""
    from aegis_cli import sanitize_display
    from aegis_core import checkrun, credit, gitsafe, regression, rule_integrity

    stray = [flag for flag, given in (
        ("FILES", bool(getattr(args, "files", None))), ("--full", bool(getattr(args, "full", False))),
        ("--plan", getattr(args, "plan", None) is not None), ("--plan-file", getattr(args, "plan_file", None) is not None),
        ("--hook", bool(getattr(args, "hook", False))),
        ("--dry-run", bool(getattr(args, "dry_run", False))), ("--llm-cmd", getattr(args, "llm_cmd", None) is not None),
        ("--paths", getattr(args, "paths", None) is not None), ("--base-policy", bool(getattr(args, "base_policy", False))),
        ("--split", bool(getattr(args, "split", None))),
    ) if given]
    if stray:
        print(f"Error: --ci does not combine with {', '.join(stray)}: it compares the committed rules of two commits",
              file=sys.stderr)
        return 2
    no_exec = bool(getattr(args, "no_exec", False))
    runs_code = [flag for flag, attr in (("--coverage", "coverage"), ("--perf", "perf"), ("--strict", "strict"),
                                         ("--require-regression", "require_regression")) if getattr(args, attr, False)]
    if no_exec and runs_code:
        print(f"Error: --no-exec does not combine with {', '.join(runs_code)}: they run the repository's code",
              file=sys.stderr)
        return 2
    fmt = "json" if getattr(args, "json", False) else str(getattr(args, "format", None) or "text").lower()
    root = str(getattr(args, "workspace", None) or getattr(args, "repo_root", None)
               or getattr(args, "_project_root", None) or getattr(args, "_root", None) or os.getcwd())
    event_base, event_head = _event_shas()
    base = getattr(args, "base", None) or event_base or gitsafe.resolve_base_ref(root)
    head = getattr(args, "head", None) or event_head or "HEAD"
    if not base:
        print("Error: --ci needs a base to compare with: pass --base REF (a pull request job has it in the event file)",
              file=sys.stderr)
        return 1
    force_gate = bool(getattr(args, "strict", False) or getattr(args, "require_regression", False))
    reg_tier = "gate" if force_gate else None
    try:
        report = rule_integrity.check_ci(root, base, head, pull_request=_event_pull_request())
        reg_report = None if no_exec else regression.check_ci_regressions(root, base, head, tier=reg_tier)
        trailer_checks = [] if no_exec else checkrun.verify_commit_trailers(root, base, head)
    except (rule_integrity.IntegrityError, regression.RegressionError, gitsafe.GitError) as exc:
        print(f"Error: {sanitize_display(str(exc), 400)}", file=sys.stderr)
        return 1

    cov_report = None
    if getattr(args, "coverage", False):
        from aegis_core.verification.coverage_check import run_diff_coverage
        cov_report = run_diff_coverage(root, base_ref=base)

    perf_report = None
    if getattr(args, "perf", False):
        from aegis_core.verification.perf_check import run_perf_check
        perf_report = run_perf_check(root, base_ref=base)
        if hasattr(perf_report, "as_dict"):
            perf_report = perf_report.as_dict()
        elif isinstance(perf_report, dict) and "passed" not in perf_report:
            perf_report["passed"] = perf_report.get("status") != "fail"

    _print_ci(report, fmt, root, reg_report, cov_report=cov_report, perf_report=perf_report, trailer_checks=trailer_checks,
              skipped=_NOT_EXECUTED if no_exec else ())
    cov_ok = True if cov_report is None else bool(cov_report.get("passed", True))
    perf_ok = True if perf_report is None else bool(perf_report.get("passed", True))
    trailer_ok = not any(t.get("failed") for t in trailer_checks)
    reg_ok = reg_report is None or not reg_report.blocking
    overall_passed = report.passed and reg_ok and cov_ok and perf_ok and trailer_ok
    return 0 if overall_passed else 1


class CheckCommand(AegisCommand):
    """Unified verification gate for AI coding agent changes."""

    name = "check"
    category = CommandCategory.WORKFLOW
    help = "Verify changes: Layer 1 checks, plus a Layer 2 model review with --full"

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "files",
            nargs="*",
            default=None,  # keeps the contract snapshot identical across argparse versions
            metavar="FILES",
            help="Files to check (default: changed against HEAD, staged, or against the branch base)",
        )
        parser.add_argument(
            "--hook",
            action="store_true",
            help="Git pre-commit mode: Layer 1 only, never a model call",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Fail on checkpoint warnings too (missing tests, hardcoded paths, stub tests...)",
        )
        parser.add_argument(
            "--full",
            action="store_true",
            help="Add Layer 2: adversarial review of the change by the --llm-cmd model",
        )
        plan = parser.add_mutually_exclusive_group()
        plan.add_argument("--plan", metavar="TEXT", default=None, help="Task plan for Layer 2 (implies --full)")
        plan.add_argument(
            "--plan-file", metavar="PATH", default=None, help="File holding the task plan (implies --full)"
        )
        parser.add_argument(
            "--llm-cmd",
            metavar="CMD",
            default=None,
            help="Layer 2 model command, e.g. 'claude -p': gets the prompt on stdin, prints the reply. "
            "It runs in an empty temporary directory, never the repository, so give scripts absolute "
            "paths (default: $AEGIS_LLM_CMD; never read from repository files)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be checked without running anything",
        )
        parser.add_argument(
            "--record",
            action="store_true",
            help="Bind the work tree to a git tree, run Layer 1 on an exported snapshot of it and write one "
            "ledger check row (witness: aegis). A label, not proof: only CI on the landing commit confirms it. "
            "A tree git cannot see completely (assume-unchanged or skip-worktree files) or that holds symbolic "
            "links is unbindable and writes no row; exit 0 only when the run passed",
        )
        parser.add_argument(
            "--tests",
            action="store_true",
            help="With --record: also run the test command from the user-scope config (tests.command in "
            "~/.aegis/config.json, default python -m pytest, never the repository's) in the snapshot with a "
            "fixed environment; exit 5 or zero passed tests is never evidence",
        )
        parser.add_argument("--format", choices=("text", "json", "github", "sarif"), default="text",
                            help="Output format (github, with --ci only: workflow-command annotations)")
        # One mode at a time. run_verify refuses every option a mode would otherwise ignore.
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument(
            "--lane",
            metavar="LANE",
            default=None,
            help="Post-lane gate: check the lane's commits since merge-base(--base, HEAD) for containment "
            "(every changed path, deletions and both sides of a move included, inside the lane's globs) and "
            "Python test integrity (removed tests, added skips or xfails, pytest collection changes; assert "
            "weakening is not detected). Any finding fails. Self-attested from the live lease or --paths; "
            "witnessed with --base-policy. As a CI job it is advisory in v4.1, and a witness is only as strong "
            "as the protection on .github/** and on the base branch",
        )
        mode.add_argument(
            "--partition",
            action="store_true",
            help="Report the cross-lane call, def and import edges between lanes planned with --split (at least "
            "two), and the [FROZEN_SIGNATURES] of the functions that cross a lane boundary. Python, and Rust when "
            "its driver is enabled. A report: it changes nothing and exits 0 even when it finds edges",
        )
        mode.add_argument(
            "--card",
            action="store_true",
            help="Print the day-0 card: languages, AST drivers, rules by type, the Layer 1 pass rate on the "
            "files and the 5 files with the most findings (above 2000 files it samples, and says so). "
            "Changes nothing and never reads baseline.json; --json for the machine-readable form",
        )
        mode.add_argument(
            "--write-baseline",
            action="store_true",
            help="Record every current Layer 1 finding in .aegis/baseline.json, so that aegis check then fails "
            "only on new ones. Findings are fingerprinted by rule, path, matched line and its occurrence, not "
            "by line number. A failure that is not about a line (a rule that cannot load, a file that cannot "
            "be parsed) is listed and is never recorded",
        )
        mode.add_argument(
            "--prune-baseline",
            action="store_true",
            help="Drop the entries of .aegis/baseline.json whose findings are fixed (or whose file is gone). "
            "It never adds a finding, and it refuses to run while a check cannot run",
        )
        mode.add_argument(
            "--ci",
            action="store_true",
            help="The CI weakening check: compare the rules that bind (gates, invariants, enforcement: gate) at "
            "merge-base(--base, --head) with those at --head, and flag every way one binds less (a deletion or "
            "archive, a rank decrease, a target_paths pattern no longer kept or a file moved out of reach, a "
            "forbid_ast pattern or call entry no longer covered, "
            "a new or unknown key, any applies_to change, or a mandatory rule widened or added past the scan's "
            "slot cap), or a change to the governance set (when the base lists a signing key). A "
            "flagged change passes only with a signed Aegis-Approve commit (aegis approve) by a key in the base "
            "branch's allowed_signers or, at tier A on a pull_request run, a non-author's approving review of the "
            "head commit (read with gh; GH_TOKEN with pull-requests: read). Also runs T5 fix-commit regression checks (advisory at default warning tier; "
            'blocking at gate tier via --strict or user config regression.tier="gate"). Exit 0 pass, 1 fail',
        )
        parser.add_argument(
            "--head",
            metavar="REF",
            default=None,
            help="With --ci: the commit under review (default: the pull request head in $GITHUB_EVENT_PATH, else HEAD)",
        )
        parser.add_argument(
            "--split",
            action="append",
            metavar="NAME=GLOB[,GLOB...]",
            default=None,
            help="With --partition: one planned lane and the globs of its files; give at least two. They match "
            "as rule target_paths do: a glob without '/' matches at any depth",
        )
        parser.add_argument(
            "--base",
            metavar="REF",
            default=None,
            help="With --ci: the pull request's base (default: its base.sha in $GITHUB_EVENT_PATH, else as below). "
            "With --lane: the base branch (default: origin/$GITHUB_BASE_REF, $GITHUB_BASE_REF, origin/main, "
            "main, origin/develop or develop). A shallow clone fails: fetch with fetch-depth 0. Without --lane: "
            "read .aegis/baseline.json from REF (label baseline: base@<sha>; absent there means empty: baseline: "
            "absent at base) and check what changed since REF; the working tree's baseline is then not consulted, "
            "and a REF that does not resolve is an error. Without --base the working tree's baseline is used and "
            "labelled self-attested: a candidate can edit its own. There is no CI detection",
        )
        parser.add_argument(
            "--paths",
            nargs="+",
            metavar="GLOB",
            default=None,
            help="With --lane: the lane's globs instead of its live lease (self-attested). They match as rule "
            "target_paths do: a glob without '/' matches at any depth, so CHANGELOG.md also admits "
            "docs/CHANGELOG.md. They never allow .aegis/** or .github/workflows/**",
        )
        parser.add_argument(
            "--base-policy",
            action="store_true",
            help="With --lane: take lanes.<lane> and shared from .aegis/team.json at the base tip, never the "
            "candidate; refuses --paths. Only then is the result 'witnessed: base policy', and only then may "
            ".aegis/** and .github/workflows/** change",
        )
        parser.add_argument(
            "--no-exec",
            action="store_true",
            help="With --ci: read git objects only and run none of the repository's code: the T5 regression "
            "and Aegis-Check trailer reruns are skipped and said so, and the ledger is never read or written. "
            "Refuses --coverage, --perf and --strict",
        )
        parser.add_argument(
            "--coverage",
            action="store_true",
            help="With --ci: run pytest with diff coverage over changed lines",
        )
        parser.add_argument(
            "--perf",
            action="store_true",
            help="With --ci: run performance regression check",
        )

    def execute(self, args: argparse.Namespace) -> int:
        return run_check(args)


if __name__ == "__main__":  # pragma: no cover
    from aegis_cli.cli import main
    sys.exit(main(["check"] + sys.argv[1:]))
