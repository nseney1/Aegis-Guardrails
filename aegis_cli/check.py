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
  aegis check --calibration [--json]  the calibration of the logged Layer 2 predictions per backend and
                                      observable kind (.aegis/state/arbiter_predictions.jsonl); log-only
  aegis check --partition --split NAME=GLOB[,GLOB...] --split NAME=...
                                      cross-lane call, def and import edges between planned
                                      lanes (aegis_core.partition); changes nothing
  aegis check --ci [--base REF] [--head REF] [--no-exec] [--format text|json|github|sarif] [--coverage] [--perf]
                                      the CI weakening check (aegis_core.rule_integrity): the
                                      rules that bind lose nothing between merge-base(REF, HEAD)
                                      and HEAD without a signed human approval; --no-exec reads
                                      git objects only and runs none of the repository's code; --coverage
                                      reports diff coverage, --perf benchmarks the merge base against HEAD

--lane, --partition, --card, --write-baseline, --prune-baseline, --calibration, --record and --ci are
modes of their own: one at a time, and none takes FILES, --full or a plan.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from aegis_core import primitives
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
    ("--coverage", "coverage", False), ("--perf", "perf", False), ("--calibration", "calibration", False),
)


# What a --ci run would silently ignore: it compares the committed rules of two commits.
_NOT_WITH_CI = (
    ("FILES", "files", None), ("--full", "full", False), ("--plan", "plan", None), ("--plan-file", "plan_file", None),
    ("--hook", "hook", False), ("--dry-run", "dry_run", False), ("--llm-cmd", "llm_cmd", None),
    ("--paths", "paths", None), ("--base-policy", "base_policy", False), ("--split", "split", None),
    ("--strict", "strict", False),
)


def _given(args: argparse.Namespace, table) -> list:
    """The flags of ``table`` (flag, attribute, idle value) that ``args`` sets."""
    return [flag for flag, attr, idle in table
            if getattr(args, attr, idle) not in (idle, [], ()) and getattr(args, attr, idle) is not idle]


def _record_conflict(args: argparse.Namespace) -> str:
    return next(iter(_given(args, _NOT_WITH_RECORD)), "")


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
        print(f"Error: workspace does not exist: {sanitize_display(root, max_len=None)}", file=sys.stderr)
        return 1
    outcome = checkrun.record(root, tests=bool(getattr(args, "tests", False)), base=getattr(args, "base", None))
    row = outcome.row or {}
    if use_json:
        document = primitives.envelope("aegis check --record", {"workspace": str(root), "tree": row.get("tree"),
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


def _format_refusal(args: argparse.Namespace) -> str:
    """Why ``--format`` cannot apply to this run, or "": the one rule for every mode. github and sarif
    report a --ci run or a plain Layer 1 check; a mode of its own has a report of its own."""
    fmt = str(getattr(args, "format", None) or "text").lower()
    if fmt not in ("github", "sarif"):
        return ""
    if getattr(args, "json", False):
        return f"--json does not combine with --format {fmt}: stdout holds one report"
    own = _given(args, (("--record", "record", False), ("--lane", "lane", None), ("--partition", "partition", False),
                        ("--card", "card", False), ("--write-baseline", "write_baseline", False),
                        ("--prune-baseline", "prune_baseline", False), ("--calibration", "calibration", False)))
    return f"--format {fmt} reports --ci or a plain Layer 1 check, not {own[0]}" if own and not getattr(args, "ci", False) else ""


def run_check(args: argparse.Namespace) -> int:
    """Execute `aegis check`."""
    if getattr(args, "no_exec", False) and not getattr(args, "ci", False):
        print("Error: --no-exec only applies with --ci", file=sys.stderr)
        return 2
    if getattr(args, "tests", False) and not getattr(args, "record", False):
        print("Error: --tests only applies with --record", file=sys.stderr)
        return 2
    for flag, attr in (("--coverage", "coverage"), ("--perf", "perf")):
        if getattr(args, attr, False) and not getattr(args, "ci", False):
            print(f"Error: {flag} only applies with --ci", file=sys.stderr)
            return 2
    refusal = _format_refusal(args)
    if refusal:
        print(f"Error: {refusal}", file=sys.stderr)
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
    """The pull request of a ``pull_request`` or ``pull_request_target`` run (the base-sourced governance
    job), for tier A's review approval: its number, author, full head commit id and base branch, each
    checked; None for any other event or any value in doubt (no gh call then)."""
    from aegis_core import human_gate

    if os.environ.get("GITHUB_EVENT_NAME") not in ("pull_request", "pull_request_target"):
        return None
    try:
        pull = _event_pull()
        number, login, sha, ref = pull["number"], pull["user"]["login"], pull["head"]["sha"], pull["base"]["ref"]
    except (KeyError, TypeError):
        return None
    if type(number) is not int or number < 1 or not isinstance(login, str) or not _LOGIN.fullmatch(login) \
            or not isinstance(sha, str) or not _FULL_SHA.fullmatch(sha) or not human_gate.is_branch_name(ref):
        return None
    return human_gate.PullRequest(number, login, sha.lower(), ref)


# What --no-exec leaves out: both rerun the pull request's code (snapshot tests, fix-commit tests).
_NOT_EXECUTED = ("regression", "trailer_checks")


def _weakening_terms(report) -> tuple[str, str, str]:
    """(what, counted, done) naming a run's weakenings and governance paths in the verdict line."""
    count, paths, cats = len(report.weakenings), len(report.governance_paths), ", ".join(report.governance_categories)
    if not report.governance_gated:
        return "weakening", f"{count} finding{'' if count == 1 else 's'}", f"{count} weakening(s)"
    if not count:
        return "governance change", f"{paths} path(s) in {cats}", f"{paths} governance path(s)"
    return ("weakening and governance change", f"{count} finding(s), {paths} path(s) in {cats}",
            f"{count} weakening(s) and {paths} governance path(s)")


def _ci_blocking(report, reg_report=None, perf_report=None, trailer_checks=None, scanner_results=None) -> list:
    """The one blocking predicate of ``check --ci``: every cause, in priority order, that makes the run fail.
    An unverified perf or scanner result and diff coverage (a report) never block (--strict is refused)."""
    span = f"{report.merge_base[:10]}..{report.head[:10]}"
    causes = []
    if not report.passed:
        what, counted, _done = _weakening_terms(report)
        causes.append(f"{what} without approval ({counted}, {span})")
    if reg_report is not None and reg_report.blocking:
        causes.append(f"regression check failed ({len(reg_report.findings)} finding(s), {span})")
    if any(t.get("failed") for t in trailer_checks or ()):
        causes.append(f"Aegis-Check trailer divergence ({span})")
    new = sum(len(r["findings"]) for r in scanner_results or () if r["status"] == "fail")
    if new:
        causes.append(f"scanner finding ({new} new, {span})")
    if perf_report is not None and perf_report.get("status") == "fail":
        causes.append(f"performance regression ({span})")
    return causes


def _build_ci_document(report, root: str, reg_report=None, cov_report=None, perf_report=None, trailer_checks=None,
                       skipped=(), scanner_results=None) -> dict:
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
    if scanner_results:  # findings without their fingerprint: it hashes the unmasked line
        document["scanners"] = [{**r, "findings": [{k: v for k, v in f.as_dict().items() if k != "fingerprint"}
                                                   for f in r["findings"]]} for r in scanner_results]
    document["blocking"] = _ci_blocking(report, reg_report, perf_report, trailer_checks, scanner_results)
    if document["blocking"]:
        document["status"] = "fail"
    return document


def _print_ci(report, fmt: str, root: str, reg_report=None, cov_report=None, perf_report=None, trailer_checks=None,
              skipped=(), scanner_results=None) -> list:
    """Print the ``check --ci`` result in ``fmt`` and append the step summary; return the blocking causes."""
    from aegis_cli import sanitize_display
    from aegis_cli.formatters.report import format_sarif_report, github_annotation_lines, governance_note, perf_line
    from aegis_cli.verify import _append_step_summary
    from aegis_core import regression

    document = _build_ci_document(report, root, reg_report, cov_report, perf_report, trailer_checks=trailer_checks,
                                  skipped=skipped, scanner_results=scanner_results)
    blocking = document["blocking"]
    _append_step_summary(document, root)

    if fmt == "sarif":
        print(format_sarif_report(document, workspace_root=root))
        return blocking
    if fmt == "json":
        print(json.dumps(document, indent=2))
        return blocking
    gated = report.governance_gated
    note = governance_note(document)
    if fmt == "github":
        for line in github_annotation_lines(document):
            print(line)
    span = f"{report.merge_base[:10]}..{report.head[:10]}"
    if not report.weakenings and not gated:
        if blocking:
            print(f"aegis check --ci: FAILED: {blocking[0]}")
        elif report.merge_base == report.head:  # a push to the base branch, a dispatch run, a stale branch
            print(f"aegis check --ci: note: base and head are the same commit; nothing was compared ({span})")
        else:
            print(f"aegis check --ci: PASSED, no rule weakened ({report.rules_checked} binding rule(s) at the merge base, {span})")
    else:
        what, _counted, done = _weakening_terms(report)
        if blocking:  # an approved change and another blocker: say which, not "without approval"
            print(f"aegis check --ci: FAILED: {blocking[0]}" + (f"; {done} approved" if report.passed else ""))
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
            print("  regression tier: warning (advisory in 4.4.0; no setting makes it block)")
        for finding in reg_report.findings:
            tag = ("UNVERIFIED" if finding.code in regression.UNVERIFIED_CODES
                   else "FAIL" if reg_report.tier == "gate" else "WARN")
            print(sanitize_display(f"  [{tag}:regression/{finding.code}] ({finding.path}): {finding.message}", 400))
        if reg_report.exempted_count > 0:
            print(f"  regression exemptions: {reg_report.exempted_count}/{reg_report.total_fix_commits} "
                  f"({reg_report.exemption_rate * 100:.1f}%)")
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
    if scanner_results is not None and not scanner_results:
        print("scanners: none configured")
    for result in scanner_results or ():
        tag = f"{result['status'].upper()}:scanner/{result['name']}"
        if result["status"] == "unverified":
            print(sanitize_display(f"  [{tag}] {result['reason']}", 400))
        elif result["status"] == "pass":
            print(f"  [{tag}] no new finding ({result['subtracted']} at the merge base)")
        for f in result["findings"]:
            print(sanitize_display(f"  [{tag}] {f.path}:{f.line} {f.rule_id}: {f.message}", 400))
    if scanner_results:
        supp = scanner_results[0]["suppressions"]
        since = "no merge-base count" if supp["delta"] is None else f"{supp['delta']:+d} since the merge base"
        print(f"scanners: {supp['count']} security suppression(s) in tracked files ({since})")
    if perf_report is not None:
        print(sanitize_display(perf_line(perf_report), 400))
    if cov_report is not None and cov_report.get("status") == "reported":
        ratio = cov_report.get("ratio")
        print(sanitize_display(f"  coverage (report only): {'n/a' if ratio is None else f'{ratio * 100:.1f}%'} of "
                               f"{cov_report.get('executable_lines', 0)} changed executable lines "
                               f"({len(cov_report.get('unmeasured') or ())} file(s) not measured)", 400))
    elif cov_report is not None:
        print(sanitize_display(f"  coverage: UNVERIFIED ({cov_report.get('reason', '')})", 400))
    if skipped:
        print("  note: --no-exec: the regression and Aegis-Check trailer checks were not run")
    return blocking


def _ci_error(message: str, fmt: str) -> int:
    """A run that could not be judged: exit 1 with the reason, and in SARIF a valid log that says the run
    did not complete, so an upload step that always runs never meets an empty or invalid file."""
    from aegis_cli.formatters.report import format_sarif_report

    print(f"Error: {message}", file=sys.stderr)
    if fmt == "sarif":
        print(format_sarif_report({}, error=message))
    return 1


def _run_ci(args: argparse.Namespace) -> int:
    """`aegis check --ci`: 0 nothing weakened or every weakening approved, 1 otherwise, 2 usage."""
    from aegis_cli import sanitize_display
    from aegis_core import checkrun, gitsafe, regression, rule_integrity

    from aegis_cli.verify import _resolve_git_cwd

    stray = _given(args, _NOT_WITH_CI)
    no_exec = bool(getattr(args, "no_exec", False))
    runs_code = [flag for flag, attr in (("--coverage", "coverage"), ("--perf", "perf")) if getattr(args, attr, False)]
    # --no-exec's own refusals are checked first so that their messages name it; --strict runs nothing
    # and gets --ci's refusal below.
    if no_exec and runs_code:
        print(f"Error: --no-exec does not combine with {', '.join(runs_code)}: they run the repository's code",
              file=sys.stderr)
        return 2
    # No flag sets require_regression (ignored otherwise); a hand-built Namespace asking for the regression
    # reruns that --no-exec skips is still refused.
    if no_exec and getattr(args, "require_regression", False):
        print("Error: --no-exec does not combine with --require-regression: --no-exec skips the regression reruns",
              file=sys.stderr)
        return 2
    if stray:
        print(f"Error: --ci does not combine with {', '.join(stray)}: it compares the committed rules of two commits",
              file=sys.stderr)
        return 2
    fmt = "json" if getattr(args, "json", False) else str(getattr(args, "format", None) or "text").lower()
    root = _resolve_git_cwd(args)
    event_base, event_head = _event_shas()
    with gitsafe.scrubbed():  # the default base is evidence about root, as check_ci's own git is
        base = getattr(args, "base", None) or event_base or gitsafe.resolve_base_ref(root)
    head = getattr(args, "head", None) or event_head or "HEAD"
    if not base:
        return _ci_error("--ci needs a base to compare with: pass --base REF (a pull request job has it in the event file)",
                         fmt)
    try:
        report = rule_integrity.check_ci(root, base, head, pull_request=_event_pull_request())
        # The reruns can take long; progress goes to stderr so the json and github stdout stay unchanged.
        progress = lambda line: print(f"aegis check --ci: {sanitize_display(line, 300)}", file=sys.stderr, flush=True)  # noqa: E731
        reg_report = None if no_exec else regression.check_ci_regressions(root, base, head, progress=progress)
        trailer_checks = [] if no_exec else checkrun.verify_commit_trailers(root, base, head, progress=progress)
    except (rule_integrity.IntegrityError, regression.RegressionError, gitsafe.GitError) as exc:
        return _ci_error(sanitize_display(str(exc), 400), fmt)

    cov_report = None
    if getattr(args, "coverage", False):
        from aegis_core.verification.coverage_check import run_diff_coverage
        cov_report = run_diff_coverage(root, base, head)

    perf_report = None
    if getattr(args, "perf", False):
        from aegis_core.verification import perf_check
        checkout, named = gitsafe.head_commit(root), getattr(args, "head", None)
        asked = gitsafe.resolve_commit(root, named) if named else checkout
        if asked != checkout:  # perf measures the work tree, as coverage does
            perf_report = {"status": "unverified", "regressed": False, "noisy": False, "passed": True,
                           "reason": f"the checkout is not {(asked or str(named))[:12]}; check out the pull request head"}
        else:
            try:
                perf_report = perf_check.run_perf_check(root, base_ref=base)
            except Exception as exc:  # the type only: str(exc) can embed paths
                perf_report = {"status": "unverified", "reason": f"perf check could not run ({type(exc).__name__})",
                               "regressed": False, "noisy": False, "passed": True}

    from aegis_core.config import user_scanners
    from aegis_core.verification import scanners
    scanner_results = []
    for name in user_scanners(root):
        try:
            scanner_results.append(scanners.run_preset(name, root, report.merge_base))
        except Exception as exc:  # the type only: a message can embed paths
            scanner_results.append({"name": name, "status": "unverified", "findings": [], "subtracted": 0,
                                    "reason": f"{name} could not run ({type(exc).__name__})"})
    suppressions = scanners.suppression_count(root, report.merge_base) if scanner_results else None
    for result in scanner_results:  # one in-repository count, shown with each scanner's result
        result["suppressions"] = suppressions

    blocking = _print_ci(report, fmt, root, reg_report, cov_report=cov_report, perf_report=perf_report,
                         trailer_checks=trailer_checks, skipped=_NOT_EXECUTED if no_exec else (),
                         scanner_results=scanner_results)
    return 1 if blocking else 0


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
                            help="Output format. github|sarif: workflow-command annotations or SARIF 2.1.0 for --ci or "
                            "a plain Layer 1 check (also appended to $GITHUB_STEP_SUMMARY); neither combines with --json")
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
            "--calibration",
            action="store_true",
            help="Report how well the logged Layer 2 predictions (.aegis/state/arbiter_predictions.jsonl, one row "
            "per prediction of aegis check --full, no model text) came true, per backend and observable kind: "
            "the resolved count, hits, a Wilson interval and, from 100 resolved, a Brier skill score. Read-only "
            "and log-only: no verdict or exit code depends on it",
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
            "branch's allowed_signers or, at tier A on a pull_request or pull_request_target run, a non-author's "
            "approving review of the "
            "head commit (read with gh; GH_TOKEN with pull-requests: read). Also runs the T5 fix-commit regression check, "
            "a report at warning tier that never changes the exit code (no setting makes it block). Exit 0 pass, 1 fail",
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
            "With --lane: the base branch (default: origin/$GITHUB_BASE_REF, then the branch origin/HEAD names, "
            "then main, develop or master, each as origin/<name> before <name>). A shallow clone fails: fetch with fetch-depth 0. Without --lane: "
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
            "Refuses --coverage and --perf",
        )
        parser.add_argument(
            "--coverage",
            action="store_true",
            help="With --ci only: report-only diff coverage, the share of the executable lines changed since "
            "merge-base(--base, --head) that the user-scope tests.command (pytest-based) runs. It never changes "
            "the exit code, and a run that cannot be measured says UNVERIFIED with the reason",
        )
        parser.add_argument(
            "--perf",
            action="store_true",
            help="With --ci only: a paired, interleaved benchmark of the merge-base export against the checked-out "
            "tree (the user-scope perf.command, or pytest-benchmark when it is installed). A regression fails the "
            "run; a run that measured nothing says UNVERIFIED and does not block",
        )

    def execute(self, args: argparse.Namespace) -> int:
        return run_check(args)


if __name__ == "__main__":  # pragma: no cover
    from aegis_cli.cli import main
    sys.exit(main(["check"] + sys.argv[1:]))
