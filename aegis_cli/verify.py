"""The engine behind `aegis check`: target files, Layer 1 and the opt-in Layer 2.

Layer 1 is the workspace checkpoint (aegis_cli.checkpoint) plus call_graph,
import_guard and forbid_ast on the target files. With --hook (the git pre-commit
hook) and no FILES, the targets are the staged files and Layer 1 reads their
staged content: what the commit records, whatever the working tree holds. Layer 2 (--full, or a plan)
adds the adversarial Spec/Code agent pair and the deterministic Arbiter, run
by one model command (--llm-cmd or AEGIS_LLM_CMD).

With --lane, `aegis check` is the post-lane gate instead (aegis_core.lane_gate): the
lane's commits since its merge base with the base branch, checked for containment and
Python test integrity.

The v4.2 modes work on the whole workspace and take no FILES: --card (aegis_core.card),
--write-baseline and --prune-baseline (aegis_core.baseline) and --partition
(aegis_core.partition). A plain check with a baseline fails only on the findings the
baseline does not hold (aegis_core.baseline); --base names where the baseline is read from.

Exit codes: 0 pass, 1 findings or a failed run, 2 usage error. Layer 2 is advisory: the
exit status is Layer 1's, and a model command that cannot run is a failed run.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from aegis_cli.checkpoint import is_blocking, run_checkpoint
from aegis_cli.formatters.report import (
    format_layer1_json_payload,
    format_layer2_json,
    format_layer2_summary,
)
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = [
    "discover_test_evidence",
    "resolve_target_files",
    "resolve_task_plan",
    "run_verify",
]


def _resolve_git_cwd(args: argparse.Namespace) -> str:
    if getattr(args, "ws", None) is not None:
        return str(args.ws.root)
    return str(
        getattr(args, "workspace", None)
        or getattr(args, "repo_root", None)
        or getattr(args, "_project_root", None)
        or getattr(args, "_root", None)
        or os.getcwd()
    )


def _files_under(directory: str, git_cwd: str) -> list[str] | None:
    """Tracked and untracked, not ignored, files under *directory*; None outside a git work tree."""
    from aegis_core import gitsafe

    listed = gitsafe.list_files(git_cwd, [directory])
    if listed is None:
        return None
    # A tracked file deleted from the working tree is listed too; there is nothing to check.
    return [f for f in listed if os.path.isfile(os.path.join(git_cwd, f))]


def _workspace_relative(paths: list[str], git_cwd: str) -> list[str]:
    """``paths`` as git diff names them (from the top of the work tree) made relative to
    the workspace at ``git_cwd``; a path outside the workspace is not its to check."""
    from aegis_core import gitsafe

    top = gitsafe.toplevel(git_cwd)
    if top is None:
        return paths
    try:
        prefix = Path(os.path.relpath(os.path.realpath(git_cwd), os.path.realpath(str(top)))).as_posix()
    except ValueError:  # another drive on Windows
        return paths
    if prefix == "." or prefix.startswith(".."):
        return paths
    lead = prefix + "/"
    return [p[len(lead):] for p in paths if p.startswith(lead)]


def resolve_target_files(args: argparse.Namespace) -> list[str]:
    """Resolve target files from FILES (a directory means the files under it) or git changes.

    With ``--hook`` and no FILES the targets are the staged files, what the commit records;
    ``args._staged_unreadable`` is set when git cannot list them. Otherwise, without FILES,
    sets ``args._diff_base`` to the base ref the changes came from, or
    ``args._no_diff_base`` when nothing changed and no base ref could be diffed against
    (a shallow clone, a repository with no main branch), so a clean tree is not assumed.
    With ``--base REF`` the targets are the uncommitted changes plus those since the merge
    base of REF and HEAD; ``args._base_unreadable`` is set when git cannot give them.
    """
    git_cwd = _resolve_git_cwd(args)
    explicit = getattr(args, "files", None)
    if explicit:
        from aegis_cli import sanitize_display

        repo_root = os.path.realpath(git_cwd)
        safe_files = []
        for f in explicit:
            resolved = os.path.realpath(os.path.join(repo_root, f))
            if not resolved.startswith(repo_root + os.sep) and resolved != repo_root:
                print(f"Warning: skipping out-of-tree file: {sanitize_display(f)}", file=sys.stderr)
                continue
            if os.path.isdir(resolved):
                listed = _files_under(f, git_cwd)
                if listed is None:
                    # Fail closed: a named target that cannot be expanded is not checked.
                    print(
                        f"Error: cannot list the files under {sanitize_display(f)}: not a git work tree; "
                        "name the files instead",
                        file=sys.stderr,
                    )
                    return []
                if not listed:
                    print(f"Warning: no files to check under {sanitize_display(f)}", file=sys.stderr)
                for g in listed:
                    real = os.path.realpath(os.path.join(repo_root, g))
                    if real.startswith(repo_root + os.sep):
                        safe_files.append(g)
                    else:
                        print(f"Warning: skipping out-of-tree file: {sanitize_display(g)}", file=sys.stderr)
                continue
            safe_files.append(f)
        if not safe_files:
            print("Error: none of the specified files can be checked (outside the repository or empty)",
                  file=sys.stderr)
        return list(dict.fromkeys(safe_files))

    from aegis_core import gitsafe

    if getattr(args, "hook", False):
        staged = gitsafe.changed_files(git_cwd, "staged")
        if staged is None:
            setattr(args, "_staged_unreadable", True)
            return []
        return _workspace_relative(staged, git_cwd)

    # `git diff HEAD` plus `git diff --cached`: what a commit of the working tree would add.
    files = _workspace_relative(gitsafe.changed_files(git_cwd, "working") or [], git_cwd)
    explicit_base = getattr(args, "base", None)
    if explicit_base:
        # --base names the commit the baseline is read from, so the files checked are everything
        # this candidate changed since it: committed since the merge base, and uncommitted.
        ranged = gitsafe.changed_files(git_cwd, "range", base=explicit_base)
        if ranged is None:
            setattr(args, "_base_unreadable", True)
            return []
        setattr(args, "_diff_base", f"{explicit_base}...HEAD")
        return list(dict.fromkeys(files + _workspace_relative(ranged, git_cwd)))
    if not files:
        # Nothing uncommitted: check what this branch adds to its base, else the last commit.
        diffed = False
        base = gitsafe.resolve_base_ref(git_cwd)
        candidates = [("range", base)] if base else []
        if gitsafe.resolve_commit(git_cwd, "HEAD~1"):  # a root commit has no parent to diff against
            candidates.append(("head", "HEAD~1"))
        for mode, ref in candidates:
            found = gitsafe.changed_files(git_cwd, mode, base=ref if mode == "range" else None)
            if found is None:
                continue
            diffed = True
            if found:
                files = _workspace_relative(found, git_cwd)
                setattr(args, "_diff_base", f"{ref}...HEAD" if mode == "range" else ref)
                break
        if not diffed:
            setattr(args, "_no_diff_base", True)
    return files


def discover_test_evidence(target_files: list[str], repo_root: str) -> tuple[list[str], str]:
    """Discover matching test files, parse test names via AST, and execute tests."""
    from aegis_core.verification.test_runner import discover_test_evidence as _core_discover
    return _core_discover(target_files, repo_root)


def resolve_task_plan(args: argparse.Namespace, repo_root: str) -> str | None:
    """Resolve task plan from --plan, --plan-file, or standard plan conventions.

    An explicit --plan is returned as given (stripped), even when empty: the caller
    rejects an empty plan rather than falling back to a plan file nobody named.
    """
    if getattr(args, "plan", None) is not None:
        return args.plan.strip()

    plan_file = getattr(args, "plan_file", None)
    if plan_file:
        plan_path = plan_file if os.path.isabs(plan_file) else os.path.join(repo_root, plan_file)
        if not os.path.isfile(plan_path):
            print(f"Error: plan file not found: {plan_file}", file=sys.stderr)
            return None
        try:
            with open(plan_path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError as e:
            print(f"Error: could not read plan file {plan_file}: {e}", file=sys.stderr)
            return None

    real_root = os.path.realpath(repo_root)
    for default_name in ("docs/plan.md", f"{AEGIS_DIRNAME}/plan.md", "PLAN.md"):
        cand = os.path.join(repo_root, default_name)
        if not os.path.lexists(cand):
            continue
        # Nobody named this file, and its text goes to the model: a branch must not be
        # able to route a secret from outside the repository into the prompt.
        if os.path.islink(cand) or not os.path.realpath(cand).startswith(real_root + os.sep):
            print(f"Warning: ignoring {default_name}: it is a symlink or leaves the repository", file=sys.stderr)
            continue
        if os.path.isfile(cand):
            try:
                with open(cand, encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        return content
            except OSError:
                pass
    return None


def _vendor_warning(repo_root: str) -> str:
    """The cross-vendor advisory for the user's declared ``arbiter_vendor`` (user scope only: a
    repository cannot set it) against ``AEGIS_CLIENT``. An advisory input never fails Layer 2, so
    an unusable user config reads as nothing declared."""
    from aegis_core.config import UserConfig, env_client
    from aegis_core.errors import AegisError
    from aegis_core.verification.arbiter import vendor_warning

    try:
        declared = UserConfig.load(repo_root).arbiter_vendor
    except (AegisError, OSError):
        declared = None
    return vendor_warning(declared, env_client())


def _append_step_summary(document: dict, root: str) -> None:
    """Append the Markdown summary of ``document`` to $GITHUB_STEP_SUMMARY when it is set: appended, as
    every step of the job does, never read back; one stderr note when it cannot be written."""
    from aegis_cli.formatters.report import format_github_step_summary
    from aegis_core.config import env_github_step_summary

    summary_path = env_github_step_summary()
    if not summary_path:
        return
    md = format_github_step_summary(document, workspace_root=root)
    try:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(md)
    except OSError as exc:
        print(f"note: the step summary could not be written ({type(exc).__name__})", file=sys.stderr)


def _emit_report(fmt: str, passed: bool, owned: list, issues: list, strict: bool, root: str) -> None:
    """``--format github|sarif`` for Layer 1: one report on stdout, and the step summary."""
    from aegis_cli.formatters.report import format_sarif_report, github_annotation_lines, layer1_report_document

    document = layer1_report_document(passed, owned, issues, strict)
    print(format_sarif_report(document, workspace_root=root) if fmt == "sarif" else "\n".join(github_annotation_lines(document)))
    _append_step_summary(document, root)


def _usage_error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 2


def _print_checkpoint(issues: list[dict], strict: bool) -> None:
    if not issues:
        print("checkpoint: all checks passed")
    for issue in issues:
        label = "[FAIL]" if is_blocking(issue, strict) else "[WARN]"
        print(f"{label} {issue['message']}")


_MODE_FLAGS = (
    ("--lane", "lane"),
    ("--partition", "partition"),
    ("--card", "card"),
    ("--write-baseline", "write_baseline"),
    ("--prune-baseline", "prune_baseline"),
    ("--calibration", "calibration"),
)


def _given_modes(args: argparse.Namespace) -> list[str]:
    """The mode flags set on *args*, in the grammar's order. A namespace built by hand
    (older SDK callers) lacks the v4.2 attributes: those count as not given."""
    return [flag for flag, attr in _MODE_FLAGS
            if (getattr(args, attr, None) is not None if attr == "lane" else bool(getattr(args, attr, False)))]


def _other_options(args: argparse.Namespace) -> list[str]:
    """The options a mode would ignore, as the user wrote them."""
    return [flag for flag, given in (
        ("FILES", bool(getattr(args, "files", None))),
        ("--full", bool(getattr(args, "full", False))),
        ("--plan", getattr(args, "plan", None) is not None),
        ("--plan-file", getattr(args, "plan_file", None) is not None),
        ("--hook", bool(getattr(args, "hook", False))),
        ("--strict", bool(getattr(args, "strict", False))),
        ("--dry-run", bool(getattr(args, "dry_run", False))),
        ("--llm-cmd", getattr(args, "llm_cmd", None) is not None),
    ) if given]


def _wants_json(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json", False) or str(getattr(args, "format", None) or "text").lower() == "json")


def _run_lane_gate(args: argparse.Namespace) -> int:
    """`aegis check --lane`: the post-lane gate (aegis_core.lane_gate). 0 pass, 1 findings
    or a gate that could not run, 2 usage."""
    from aegis_cli import sanitize_display
    from aegis_core import gitsafe, lane_gate, team

    use_json = _wants_json(args)
    root = _resolve_git_cwd(args)

    def fail(message: str, code: int) -> int:
        if use_json:
            print(json.dumps(lane_gate.error_report(root, args.lane, message), indent=2))
        else:
            print(f"Error: {sanitize_display(message, max_len=len(message))}", file=sys.stderr)
        return code

    others = _other_options(args)
    if others:
        return fail(f"--lane does not combine with {', '.join(others)}: it checks the lane's committed range", 2)
    try:
        result = lane_gate.check_lane(root, args.lane, base=getattr(args, "base", None),
                                      paths=getattr(args, "paths", None),
                                      base_policy=bool(getattr(args, "base_policy", False)))
    except (lane_gate.LaneGateUsage, team.TeamUsageError, team.TeamFileError) as exc:
        return fail(str(exc), 2)
    except (lane_gate.LaneGateError, gitsafe.GitError) as exc:
        return fail(str(exc), 1)
    if use_json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        for line in result.text_lines():  # warnings included, as "warning: ..." lines
            print(sanitize_display(line, max_len=len(line)))
    if not result.integrity_passed:
        _void_lane_tree(root, result.head)
    return 0 if result.passed else 1


def _void_lane_tree(root: str, head: str) -> None:
    """A failed integrity gate voids the credit of the lane head's tree; bookkeeping never changes
    the gate's exit code, so a failure is one stderr note."""
    from aegis_core import credit, gitsafe
    from aegis_core.errors import AegisError

    try:
        res = gitsafe.run(["rev-parse", "--verify", "--quiet", f"{head}^{{tree}}"], root)
        tree = res.stdout.decode("ascii", "replace").strip() if res.returncode == 0 else ""
        if not tree:
            raise gitsafe.GitError(f"cannot read the tree of {head[:12]}")
        credit.void_tree(root, tree, "lane_integrity")
    except (AegisError, OSError) as exc:
        print(f"note: could not void the credit of the lane's tree: {exc}", file=sys.stderr)


# ── The v4.2 modes: whole-workspace reports, no FILES ───────────────────────

_MODE_WHY = {
    "--partition": "it reads the whole workspace's lanes",
    "--card": "it reports on the whole workspace",
    "--write-baseline": "it records the whole workspace's findings",
    "--prune-baseline": "it re-checks the whole workspace against the baseline",
    "--calibration": "it reports on the whole prediction log",
}


def _event_warning(root: str, kind: str, result: str, detail: dict) -> list[str]:
    """Append an event; a log that cannot be written is a warning, never a failure."""
    from aegis_core import events
    from aegis_core.errors import AegisError

    try:
        events.append(root, kind, result, detail)
    except (ValueError, TypeError, OSError, AegisError) as exc:
        return [f"event not recorded: {exc}"]
    return []


def _shown(text: str, limit: int = 200) -> str:
    from aegis_cli import sanitize_display

    return sanitize_display(text, max_len=limit)


def _run_mode(flag: str, args: argparse.Namespace) -> int:
    """`aegis check --card | --write-baseline | --prune-baseline | --partition`. 0 done,
    1 could not run, 2 usage. Every option the mode would ignore is refused."""
    from aegis_cli import sanitize_display
    from aegis_core import baseline

    use_json = _wants_json(args)
    root = _resolve_git_cwd(args)
    source = f"aegis check {flag}"

    def fail(message: str, code: int) -> int:
        if use_json:
            document = baseline.envelope(source, {"workspace": str(root)})
            document.update(status="error", error=message)
            print(json.dumps(document, indent=2))
        else:
            print(f"Error: {sanitize_display(message, max_len=len(message))}", file=sys.stderr)
        return code

    for lane_option, given in (("--paths", getattr(args, "paths", None) is not None),
                               ("--base-policy", bool(getattr(args, "base_policy", False)))):
        if given:
            return fail(f"{lane_option} only applies with --lane", 2)
    others = _other_options(args) + (["--base"] if getattr(args, "base", None) is not None else [])
    if others:
        return fail(f"{flag} does not combine with {', '.join(others)}: {_MODE_WHY[flag]}", 2)
    if not os.path.isdir(root):
        return fail(f"workspace does not exist: {root}", 1)
    runner_for = {
        "--card": _run_card,
        "--write-baseline": _run_write_baseline,
        "--prune-baseline": _run_prune_baseline,
        "--partition": _run_partition,
        "--calibration": _run_calibration,
    }[flag]
    return runner_for(args, str(root), use_json, source, fail)


def _unbaselinable_lines(blocked: Any) -> list[str]:
    lines = [f"    - {_shown(e.tool, 80)}: {_shown(e.target, 120)}: {_shown(e.detail)}" for e in list(blocked)[:20]]
    if len(blocked) > 20:
        lines.append(f"    ... and {len(blocked) - 20} more")
    return lines


def _unbaselinable_rows(blocked: Any) -> list[dict]:
    return [{"tool": e.tool, "target": e.target, "detail": e.detail} for e in blocked]


def _layer1_everywhere(root: str) -> tuple[list, Any, list[str]]:
    """Layer 1 on every file of the workspace it has something to say about: the pairs,
    their sources and the files checked."""
    from aegis_core import baseline

    files, _origin = baseline.list_files(root)
    targets = baseline.checkable(root, files)
    pairs, sources = baseline.run_fast(root, targets)
    return pairs, sources, targets


def _run_write_baseline(args: argparse.Namespace, root: str, use_json: bool, source: str, fail: Any) -> int:
    from aegis_core import baseline

    try:
        pairs, sources, targets = _layer1_everywhere(root)
    except Exception as exc:
        return fail(f"Layer 1 could not run: {exc}", 1)
    collected = baseline.collect(pairs, sources)
    entries = {f.entry for f in collected.findings}
    previous: frozenset = frozenset()
    note = ""
    try:
        previous = baseline.load(root).entries
    except baseline.BaselineError as exc:  # replaced below; a symlink is refused by write
        note = f"the previous baseline was not valid ({exc})"
    had_one = os.path.lexists(os.path.join(root, baseline.BASELINE_FILE))
    try:
        baseline.write(root, entries)
    except (baseline.BaselineError, OSError) as exc:
        return fail(str(exc), 1)
    added, removed = len(entries - previous), len(previous - entries)
    warnings = _event_warning(root, "baseline_written", "written", {
        "mode": "write", "entries": len(entries), "added": added, "removed": removed,
        "files_checked": len(targets), "unbaselinable": len(collected.blocked)})
    if use_json:
        document = baseline.envelope(source, {"workspace": root})
        document.update(status="written", path=baseline.BASELINE_FILE, entries=len(entries), added=added,
                        removed=removed, files_checked=len(targets),
                        unbaselinable=_unbaselinable_rows(collected.blocked), warnings=warnings,
                        notes=[note] if note else [])
        print(json.dumps(document, indent=2))
        return 0
    delta = f" ({added} added, {removed} removed since the last baseline)" if had_one and not note else ""
    print(f"aegis check --write-baseline: wrote {baseline.BASELINE_FILE}: {len(entries)} finding(s) "
          f"from {len(targets)} file(s) checked{delta}")
    if note:
        print(f"  {note}")
    if collected.blocked:
        print(f"  {len(collected.blocked)} failure(s) cannot be baselined and keep failing aegis check:")
        for line in _unbaselinable_lines(collected.blocked):
            print(line)
    print(f"  Commit {baseline.BASELINE_FILE}. aegis check then fails only on findings it does not hold.")
    print("  In CI run aegis check --base <ref>: the baseline is then read from the base branch, not the candidate.")
    for warning in warnings:
        print(f"warning: {_shown(warning, 300)}")
    return 0


def _run_prune_baseline(args: argparse.Namespace, root: str, use_json: bool, source: str, fail: Any) -> int:
    from aegis_core import baseline

    try:
        held = baseline.load(root)
    except baseline.BaselineError as exc:
        return fail(str(exc), 1)
    if not held.active:
        return fail(f"no baseline to prune: {baseline.BASELINE_FILE} does not exist", 1)
    try:
        pairs, sources, targets = _layer1_everywhere(root)
    except Exception as exc:
        return fail(f"Layer 1 could not run: {exc}", 1)
    collected = baseline.collect(pairs, sources)
    unjudged = set()
    for (path, evidence), found in zip(pairs, collected.by_evidence):
        if evidence.verdict or found is not None:
            continue
        if path is None:  # a check that covers no one file, such as a rule that cannot load
            return fail(f"cannot prune: a check could not run ({_shown(evidence.tool, 80)}: "
                        f"{_shown(evidence.detail)}); fix it first, then prune", 1)
        unjudged.add(path)
    current = {f.entry for f in collected.findings}
    checked = set(targets)
    kept, dropped = [], []
    for entry in sorted(held.entries):
        file_exists = os.path.isfile(os.path.join(root, *entry.path.split("/")))
        judged = file_exists and entry.path in checked and entry.path not in unjudged
        (dropped if entry not in current and (not file_exists or judged) else kept).append(entry)
    not_added = len(current - held.entries)
    warnings: list[str] = []
    if dropped:
        try:
            baseline.write(root, kept)
        except (baseline.BaselineError, OSError) as exc:
            return fail(str(exc), 1)
        warnings = _event_warning(root, "baseline_written", "pruned", {
            "mode": "prune", "entries": len(kept), "added": 0, "removed": len(dropped),
            "files_checked": len(targets), "unbaselinable": len(collected.blocked)})
    if use_json:
        document = baseline.envelope(source, {"workspace": root})
        document.update(status="pruned" if dropped else "unchanged", path=baseline.BASELINE_FILE,
                        entries=len(kept), removed=len(dropped), kept=len(kept), not_added=not_added,
                        files_checked=len(targets), warnings=warnings)
        print(json.dumps(document, indent=2))
        return 0
    if dropped:
        print(f"aegis check --prune-baseline: pruned {baseline.BASELINE_FILE}: dropped {len(dropped)} fixed "
              f"finding(s), {len(kept)} kept")
    else:
        print("aegis check --prune-baseline: nothing to prune: every entry still matches a finding")
    if not_added:
        print(f"  {not_added} current finding(s) are not in the baseline and were not added: aegis check fails on "
              "them; --write-baseline records them")
    for warning in warnings:
        print(f"warning: {_shown(warning, 300)}")
    return 0


def _print_lines(lines: list[str]) -> None:
    """Report lines carry repository-chosen text (paths, rule ids, matched code): no terminal controls."""
    for line in lines:
        print(_shown(line, max(len(line), 80)))


def _run_card(args: argparse.Namespace, root: str, use_json: bool, source: str, fail: Any) -> int:
    """`aegis check --card`: the day-0 card (aegis_core.card). Read-only."""
    from aegis_core import card

    try:
        built = card.build(root)
    except Exception as exc:
        return fail(f"the card could not be built: {type(exc).__name__}: {exc}", 1)
    if use_json:
        print(json.dumps(built.as_dict(), indent=2))
    else:
        _print_lines(built.text_lines())
    return 0


def _run_partition(args: argparse.Namespace, root: str, use_json: bool, source: str, fail: Any) -> int:
    """`aegis check --partition --split ...`: the cross-lane edge report (aegis_core.partition).
    A report: exit 0 even when it finds edges."""
    from aegis_core import partition

    try:
        lanes = partition.parse_splits(getattr(args, "split", None))
    except partition.PartitionUsage as exc:
        return fail(str(exc), 2)
    try:
        report = partition.check(root, lanes)
    except Exception as exc:
        return fail(f"the partition report could not be built: {type(exc).__name__}: {exc}", 1)
    if use_json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        _print_lines(report.text_lines())
    return 0


def _run_calibration(args: argparse.Namespace, root: str, use_json: bool, source: str, fail: Any) -> int:
    """`aegis check --calibration`: the calibration of the logged Layer 2 predictions per backend and
    observable kind. Read-only; T6 is log-only, so nothing depends on it."""
    import time

    from aegis_core.storage import read_jsonl
    from aegis_core.verification import records
    from aegis_core.verification.arbiter import calibration
    from aegis_core.workspace.layout import WorkspaceLayout

    log = read_jsonl(WorkspaceLayout(Path(root)).predictions_log)
    if log.error:
        return fail(f"cannot read the prediction log: {log.error}", 1)
    try:  # dispositions and outcomes come from git, on read; nothing is written back
        groups = calibration(records.resolve_rows(root, log.rows, time.time()))
    except (ValueError, TypeError) as exc:
        return fail(f"the prediction log holds a row that cannot be scored: {exc}", 1)
    n = sum(group["n"] for group in groups.values())
    status = f"insufficient (n={n}/25)" if n < 25 else "ok"
    if use_json:
        print(json.dumps({"logged": len(log.rows), "n": n, "status": status, "groups": groups}, indent=2))
        return 0
    shown = "; ".join(f"{key}: {g['status']}, n={g['n']}, hits={g['hits']}" for key, g in groups.items())
    print(_shown(f"{len(log.rows)} logged | {shown or status}", 2000))
    return 0


def _log_predictions(root: str, predictions: Any, backend: Any, files: list[str]) -> list[str]:
    """Append one stamped row per Layer 2 prediction to .aegis/state/arbiter_predictions.jsonl, without
    the model's text (risk, mechanism and the function name can quote the diff). Only in an Aegis
    workspace; a failure is a warning: logging never changes the verdict or the exit code."""
    import time

    from aegis_core import storage, treeid
    from aegis_core.verification.adversarial_verify import extract_signatures
    from aegis_core.verification.arbiter import stamp
    from aegis_core.workspace.layout import WorkspaceLayout

    if not predictions or not os.path.isdir(os.path.join(root, AEGIS_DIRNAME)):
        return []
    try:
        try:
            with treeid.bind(root) as bound:
                tree = bound.binding.tree or ""
        except treeid.TreeError:
            tree = ""
        defined: dict[str, str] = {}  # function name -> the first changed file that defines it
        for rel in files:
            if rel.endswith(".py") and os.path.isfile(os.path.join(root, rel)):
                for sig in extract_signatures(os.path.join(root, rel)):
                    defined.setdefault(sig[4:].split("(", 1)[0], rel.replace(os.sep, "/"))
        rows = []
        for p in stamp(list(predictions), tree=tree, backend=os.path.basename(backend.argv[0]), ts=time.time()):
            row = {k: v for k, v in p.to_dict().items() if k not in ("risk", "mechanism", "affected_function")}
            row["scope"] = {"path": defined.get(p.scope["symbol"], ""), "symbol": p.scope["symbol"]}
            rows.append(row)
        storage.state_dir(root)  # refuses a linked .aegis or state directory
        storage.append_jsonl(WorkspaceLayout(Path(root)).predictions_log, rows)
    except Exception as exc:
        return [f"predictions not logged: {type(exc).__name__}: {exc}"]
    return []


def run_verify(args: argparse.Namespace) -> int:
    """Run `aegis check` for *args*. Returns 0, 1 or 2 (see the module docstring)."""
    from aegis_core import baseline
    from aegis_core.inference_provider import MISSING_BACKEND, LLMCommandError, resolve_backend
    from aegis_core.verification.pipeline import VerificationPipeline
    from aegis_core.verification import runner
    from aegis_core.workspace.base import Workspace

    modes = _given_modes(args)
    if len(modes) > 1:
        return _usage_error(f"{modes[0]} and {modes[1]} are modes of their own: give one")
    if getattr(args, "split", None) and modes != ["--partition"]:
        return _usage_error("--split only applies with --partition")
    if modes == ["--lane"]:
        return _run_lane_gate(args)
    if modes:
        return _run_mode(modes[0], args)
    stray = [flag for flag, given in (
        ("--paths", getattr(args, "paths", None) is not None),
        ("--base-policy", bool(getattr(args, "base_policy", False))),
    ) if given]
    if stray:
        return _usage_error(f"{stray[0]} only applies with --lane")

    hook = bool(getattr(args, "hook", False))
    plan = getattr(args, "plan", None)
    plan_file = getattr(args, "plan_file", None)
    # Presence, not truthiness: `--plan "$PLAN"` with PLAN unset still asked for Layer 2.
    layer2 = bool(getattr(args, "full", False)) or plan is not None or plan_file is not None
    if hook and layer2:
        return _usage_error("--hook runs Layer 1 only; drop --full, --plan and --plan-file")
    fmt = str(getattr(args, "format", None) or "text").lower()
    report_fmt = fmt if fmt in ("github", "sarif") else ""
    if report_fmt and (layer2 or getattr(args, "dry_run", False)):
        named = "--dry-run" if getattr(args, "dry_run", False) else next(
            flag for flag, given in (("--full", getattr(args, "full", False)), ("--plan", plan is not None),
                                     ("--plan-file", plan_file is not None)) if given)
        return _usage_error(f"--format {report_fmt} reports a Layer 1 check; it does not combine with {named}")
    if plan is not None and not plan.strip():
        return _usage_error("Layer 2 needs a task plan: --plan is empty")
    if plan_file is not None and not plan_file.strip():
        return _usage_error("Layer 2 needs a task plan: --plan-file is empty")

    backend = None
    if layer2:
        # Fail before any work: a Layer 2 run without a model must never pass as Layer 1 only.
        try:
            backend = resolve_backend(getattr(args, "llm_cmd", None))
        except LLMCommandError as exc:
            return _usage_error(str(exc))
        if backend is None:
            return _usage_error(MISSING_BACKEND)

    raw_ws = (
        getattr(args, "workspace", None)
        or getattr(args, "repo_root", None)
        or getattr(args, "_project_root", None)
        or getattr(args, "_root", None)
    )
    if getattr(args, "ws", None) is None and raw_ws and not os.path.isdir(str(raw_ws)):
        # Workspace.resolve walks up to an existing parent; checking that instead fails open.
        print(f"Error: workspace does not exist: {raw_ws}", file=sys.stderr)
        return 1
    ws_obj = getattr(args, "ws", None) or Workspace.resolve(raw_ws)
    repo_root = str(ws_obj.root)
    if not os.path.isdir(repo_root):
        print(f"Error: repo root does not exist: {repo_root}", file=sys.stderr)
        return 1

    held = baseline.Baseline(frozenset(), None, "none")
    if not getattr(args, "dry_run", False):
        try:
            held = baseline.load(repo_root, getattr(args, "base", None))
        except baseline.BaselineUsage as exc:
            return _usage_error(_shown(str(exc), 300))
        except baseline.BaselineError as exc:
            print(f"Error: {_shown(str(exc), 300)}", file=sys.stderr)
            return 1

    task_plan = None
    if layer2:
        task_plan = resolve_task_plan(args, repo_root)
        if plan_file and task_plan is None:
            return 1
        if not task_plan:
            return _usage_error("Layer 2 needs a task plan: pass --plan or --plan-file (or add docs/plan.md)")

    use_json = bool(getattr(args, "json", False) or fmt == "json")
    machine = use_json or bool(report_fmt)  # stdout holds exactly one report
    strict = bool(getattr(args, "strict", False))
    mode = "Layer 1 + Layer 2" if layer2 else "Layer 1"

    target_files = resolve_target_files(args)
    if getattr(args, "files", None) and not target_files:
        return 1
    if getattr(args, "_base_unreadable", False):
        print(f"Error: cannot list what changed since {_shown(str(args.base), 120)}: needs history: fetch with "
              "fetch-depth 0 (no merge base with HEAD)", file=sys.stderr)
        return 1
    staged = hook and not getattr(args, "files", None)
    if staged and getattr(args, "_staged_unreadable", False):
        # Fail closed: a commit whose content cannot be listed is not checked.
        print("Error: cannot read the staged changes (not a git work tree, or git failed); nothing was checked",
              file=sys.stderr)
        return 1
    no_diff_base = not target_files and bool(getattr(args, "_no_diff_base", False))
    if layer2 and no_diff_base:
        return _usage_error(
            "Layer 2 has nothing to review: no changed files, and no base commit found to diff "
            "against (a shallow clone?); pass the files to review"
        )
    if getattr(args, "files", None) and not getattr(args, "dry_run", False):
        missing = [f for f in target_files if not os.path.exists(os.path.join(repo_root, f))]
        if missing:
            for f in missing:
                print(f"Error: file not found: {f}", file=sys.stderr)
            return 1

    if getattr(args, "dry_run", False):
        if use_json:
            print(json.dumps({"dry_run": True, "mode": mode, "repo_root": repo_root, "files": target_files}, indent=2))
            return 0
        print(f"Dry run — {mode}\nRepo root: {repo_root}\nFiles to verify ({len(target_files)}):")
        for f in target_files:
            print(f"  {f}")
        return 0

    # ── Layer 1: workspace checkpoint, then the per-file tools ────────────
    issues, blocking = run_checkpoint(Path(repo_root), strict=strict)
    if not machine:
        _print_checkpoint(issues, strict)

    if not target_files:
        if staged:
            summary = "Layer 1: 0 files staged (nothing to check)"
        elif no_diff_base:
            summary = "Layer 1: 0 files changed (no base commit found to diff against; pass the files to check)"
        else:
            summary = "Layer 1: 0 files changed (clean repository)"
        # Say so: a Layer 2 run that reviewed nothing must not read like a Layer 1-only pass.
        layer2_summary = "Layer 2: no changed files to review"
        if report_fmt:
            _emit_report(report_fmt, not blocking, [], issues, strict, repo_root)
        elif use_json:
            payload = format_layer1_json_payload(not blocking, [], [], summary)
            payload["checkpoint_issues"] = issues
            if held.active:
                payload["baseline"] = {**held.as_dict(), "grandfathered": 0, "new": [], "blocked": []}
            if layer2:
                payload["layer2"] = {"verdict": None, "summary": layer2_summary}
            print(json.dumps(payload, indent=2))
        else:
            print(summary)
            if held.active:
                print(f"{held.label}: 0 finding(s) grandfathered, 0 new")
            if layer2:
                print(layer2_summary)
        return 1 if blocking else 0

    try:
        if staged:
            # What `git commit` records is the index, not the working tree.
            pairs = baseline.run_grouped(
                lambda group: runner.run_layer1_on_index(group, repo_root), target_files, root=repo_root)
        else:
            # Mutation testing is slow; it runs only behind --full (fast_mode otherwise).
            pairs = baseline.run_grouped(
                lambda group: runner.run_layer1(
                    changed_files=group,
                    repo_root=repo_root,
                    fast_mode=not layer2,
                    diff_base=getattr(args, "_diff_base", None),
                ),
                target_files, root=repo_root)
    except Exception as exc:
        print(f"Error: Layer 1 could not run: {exc}", file=sys.stderr)
        return 1
    results = [evidence for _path, evidence in pairs]
    applied = None
    if held.active:
        # The baseline decides which failed checks count. Evidence it does not hold stays failing.
        try:
            applied = baseline.apply(pairs, baseline.Sources(repo_root, staged=staged), held)
        except Exception as exc:  # fail closed: a baseline that cannot be applied excuses nothing
            print(f"Error: the baseline could not be applied: {_shown(str(exc), 300)}", file=sys.stderr)
            return 1
        results = list(applied.effective)

    tools_pass = runner.gate_verdict(results)
    layer1_pass = tools_pass and not blocking
    if results:
        summary = runner.format_summary(results)
    else:
        n = len(target_files)
        summary = f"Layer 1: no check applies to the {n} target file{'' if n == 1 else 's'} (0 checks run, PASSED)"
    if not machine:
        for r in results:
            if not r.verdict:
                print(f"🔴 {r.tool}: {r.target} — {r.detail}")
            elif r.tool in runner.NOTE_TOOLS:  # advisory: what was not read, decided or checked
                print(f"note: {r.detail}")
        print(summary)
        if applied is not None:
            print(f"{held.label}: {len(applied.grandfathered)} finding(s) grandfathered, {len(applied.new)} new")
            for f in applied.new:
                print(_shown(f"new: {f.path}:{f.line} {f.rule}  {f.text}", 300))

    def _record_baseline(passed: bool) -> None:
        if applied is None:
            return
        for warning in _event_warning(repo_root, "baseline_check", "pass" if passed else "fail", {
            "label": held.label, "source": held.source, "commit": held.commit,
            "entries": len(held.entries), "files": len(target_files),
            "grandfathered": len(applied.grandfathered), "new": len(applied.new), "blocked": len(applied.blocked),
        }):
            print(f"warning: {_shown(warning, 300)}", file=sys.stderr)

    def _record_telemetry(passed: bool, verdict: Any) -> None:
        # Advisory rule-trigger telemetry: it must never change the verdict.
        try:
            from aegis_core.outcomes.telemetry import record_verification_telemetry
            record_verification_telemetry(
                workspace=repo_root,
                target_files=target_files,
                passed=passed,
                verdict=verdict,
                layer1_evidence=results,
                source="session",
            )
        except Exception:
            pass

    def _emit_json(passed: bool, layer2_result: Any = None, vendor: str = "") -> None:
        payload = format_layer1_json_payload(passed, target_files, results, summary)
        payload["checkpoint_issues"] = issues
        if applied is not None:
            payload["baseline"] = {
                **held.as_dict(),
                "grandfathered": len(applied.grandfathered),
                "new": [f.as_dict() for f in applied.new],
                "blocked": _unbaselinable_rows(applied.blocked),
            }
        if layer2_result is not None:
            payload["layer2"] = format_layer2_json(layer2_result.arbitration_result, layer2_result.verdict, vendor)
        print(json.dumps(payload, indent=2))

    if not layer2:
        _record_telemetry(tools_pass, "PASS" if tools_pass else "FAIL")
        _record_baseline(layer1_pass)
        if report_fmt:  # baseline.apply keeps one item per pair, in order
            _emit_report(report_fmt, layer1_pass, [(path, e) for (path, _), e in zip(pairs, results)], issues, strict,
                         repo_root)
        elif use_json:
            _emit_json(layer1_pass)
        return 0 if layer1_pass else 1

    # ── Layer 2: adversarial pair + Arbiter ───────────────────────────────
    try:
        test_names, test_results = discover_test_evidence(target_files, repo_root)
    except Exception as e:
        # A command that cannot run is not evidence about the rules: nothing is recorded.
        print(f"Error: Test discovery and execution failed: {_shown(str(e), 300)}", file=sys.stderr)
        return 1

    try:
        pipeline_res = VerificationPipeline().run(
            changed_files=target_files,
            workspace=ws_obj,
            task_plan=task_plan,
            backend=backend,
            test_names=test_names,
            test_results=test_results,
            layer1_evidence=results,
        )
    except Exception as e:
        print(f"Error: Layer 2 failed: {_shown(str(e), 300)}", file=sys.stderr)  # model stderr is untrusted
        return 1

    # T6 is log-only: the Layer 2 verdict is meta text, never the exit status or a rule outcome.
    passed = layer1_pass
    arb = pipeline_res.arbitration_result
    for warning in _log_predictions(repo_root, getattr(arb, "llm_predictions", ()), backend, target_files):
        print(f"warning: {_shown(warning, 300)}", file=sys.stderr)
    # arbitrate() still names a verdict (SHIP over a passing Layer 1) for a review that never completed;
    # the ledger says UNVERIFIED, as the text and JSON output do.
    unverified = arb is not None and getattr(arb, "infra_status", "ok") != "ok"
    _record_telemetry(tools_pass, "UNVERIFIED" if unverified else pipeline_res.verdict)
    _record_baseline(passed)
    vendor = _vendor_warning(repo_root)
    if use_json:
        _emit_json(passed, pipeline_res, vendor)
    elif pipeline_res.arbitration_result:
        print(format_layer2_summary(pipeline_res.arbitration_result, vendor))
    return 0 if passed else 1
