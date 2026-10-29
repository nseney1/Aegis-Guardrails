"""aegis status — show active rules and stats."""
from __future__ import annotations

import argparse
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from aegis_cli import resolve_root, sanitize_display
from aegis_cli.base import CommandCategory, AegisCommand
from aegis_core.taxonomy import (
    CHARS_PER_TOKEN_ESTIMATE,
    JIT_DEFAULT_MAX_TOKENS,
    RULE_TYPES,
)

__all__ = ["run_status", "run_compliance", "StatusCommand"]

from aegis_core.yaml_engine.frontmatter import parse_rule_file


def _repo_root(args: argparse.Namespace) -> Path:
    """The workspace, or else the directory aegis_cli is installed in."""
    return resolve_root(args, default=Path(__file__).resolve().parent.parent)


def _same_dir(a: Path, b: Path) -> bool:
    try:
        return a.is_dir() and b.is_dir() and a.resolve() == b.resolve()
    except OSError:
        return False


def _project_root(args: argparse.Namespace) -> Path:
    """The workspace the command acts on."""
    return resolve_root(args)


def _parse_frontmatter(filepath: str) -> dict:
    """Extract YAML frontmatter from a cell file using the canonical parser.

    Falls back to empty dict on any error.
    """
    try:
        fm, _body = parse_rule_file(filepath)
        return fm
    except Exception:
        return {}


def _parse_created_date(created_val) -> date | None:
    """Parse a created date from frontmatter."""
    if created_val is None:
        return None
    if isinstance(created_val, datetime):
        return created_val.date()
    if isinstance(created_val, date):
        return created_val
    if isinstance(created_val, (int, float)):
        try:
            return datetime.fromtimestamp(created_val).date()
        except Exception:
            return None
    if isinstance(created_val, str):
        s = created_val.strip().rstrip("Z")
        try:
            return date.fromisoformat(s[:10])
        except Exception:
            pass
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            pass
    return None


def _format_adaptive_expiry(created_val, expiry_days_val) -> str:
    """Calculate remaining days for an adaptive rule."""
    if expiry_days_val is None or created_val is None:
        return "—"
    try:
        expiry_days = int(expiry_days_val)
    except (ValueError, TypeError):
        return "—"

    created_date = _parse_created_date(created_val)
    if created_date is None:
        return "—"

    days_elapsed = (date.today() - created_date).days
    remaining_days = expiry_days - days_elapsed
    if remaining_days < 0:
        return "expired"
    return f"{remaining_days}d"


def blocked_commands_summary(workspace: Path | str) -> dict:
    """Count hook-observed blocked commands per host from guard_match events."""
    from aegis_core import events

    by_host: dict[str, int] = {}
    ev_read = events.read(workspace, kinds="guard_match")
    for row in ev_read.rows:
        if row.get("result") == "block":
            host = str(row.get("host") or "unknown")
            by_host[host] = by_host.get(host, 0) + 1
    total = sum(by_host.values())
    return {
        "total": total,
        "by_host": by_host,
        "source": "hook-observed",
        "label": "hook-observed",
    }


class _StatusModel(NamedTuple):
    """What both views of ``aegis status`` show, gathered once (one ledger read)."""

    core_files: List[Path]
    ruleset: Any
    inventory_error: Optional[str]
    view: Any
    claimed: Dict[str, Any]
    proj_credits: Any
    blocked_cmds: Dict[str, Any]
    loaded: List[Any]
    fits: Dict[str, Any]
    derived: Optional[Dict[str, Any]]
    stale: List[Dict[str, Any]]
    insights: Dict[str, Any]


def run_status(args: argparse.Namespace) -> int:
    """Show active rules and stats."""
    root = _repo_root(args)
    proj = _project_root(args)
    model = _gather_status(root, proj)

    # 4. Process all rules and calculate character overhead
    # Host-installed instruction rules ("core") list first, then the rule types in table order.
    _type_order = {"core": 0, **{name: spec.display_order for name, spec in RULE_TYPES.items()}}

    core_rules, core_chars = _core_entries(model.core_files, model.view, model.proj_credits)
    adaptive_rules, adaptive_chars = _adaptive_entries(model.loaded, model.fits)
    all_rules = core_rules + adaptive_rules
    total_chars = core_chars + adaptive_chars
    problems = _status_problems(model.ruleset, model.stale)
    ledger_health = model.view.health()
    rc = 1 if (problems["rule_errors"] or model.inventory_error) else 0

    # Context load: total characters / 4
    estimated_tokens = total_chars // CHARS_PER_TOKEN_ESTIMATE

    # Sort rules grouped by modern type, then triggers descending, fitness descending, name
    all_rules.sort(
        key=lambda r: (
            _type_order.get(r["type"], 99),
            -r["triggers"],
            -(float(r["score"]) if isinstance(r.get("score"), (int, float)) else -1.0),
            r["name"],
        )
    )

    if getattr(args, "json", False):
        import json
        print(json.dumps(_status_payload(model, all_rules, estimated_tokens, ledger_health, problems), indent=2))
        return rc

    return _print_status(args, proj, model, all_rules, estimated_tokens, problems, rc)


def _gather_status(root: Path, proj: Path) -> _StatusModel:
    """Read what both views show; every per-rule number comes from the one ledger read."""
    # 1. Core rules: the shipped rules, listed only in the Aegis checkout they ship from.
    #    v4 installs no rule files into host directories (host-matrix spec §3.2), and a
    #    workspace's own rules/ is its project's, never Aegis's.
    from aegis_cli.init import packaged_dir, packaged_rules

    core_files: list[Path] = []
    if _same_dir(root / "rules", packaged_dir("rules")):
        core_files = list(packaged_rules().values())

    # 2. Workspace rules, through the one loader; fitness from the ledger.
    from aegis_core.fitness import for_rules
    from aegis_core.rule_inventory import RuleInventoryError
    from aegis_core.rules import RuleSet, load_rules
    from aegis_core.sync import read_derived, stale_rules

    inventory_error = None
    try:
        ruleset = load_rules(proj)
    except RuleInventoryError as exc:
        inventory_error = str(exc)
        ruleset = RuleSet(())
    from aegis_core.telemetry_engine import ledger

    # One ledger read for every per-rule number below; what it could not use is shown.
    view = ledger.read(proj)
    from aegis_core.credit import claimed_summary, project_credits

    # aegis_report_outcome calls with no check row for their tree: counted apart, never per rule.
    claimed = claimed_summary(proj, view=view)
    proj_credits = project_credits(proj, view=view)
    blocked_cmds = blocked_commands_summary(proj)
    loaded = [r for r in ruleset.rules if r.ok]
    fits = for_rules(proj, loaded, view=view)
    derived = read_derived(proj)
    stale = stale_rules(ruleset, derived)
    from aegis_core.insights import insight_status

    # The user-scope insights log, read once and offline; nothing when there is none.
    insights = insight_status(proj)
    return _StatusModel(core_files, ruleset, inventory_error, view, claimed, proj_credits, blocked_cmds, loaded,
                        fits, derived, stale, insights)


def _core_fitness(totals: Dict[str, Any], proj_credits: Any, *names: str) -> Tuple[int, Optional[float]]:
    from aegis_core.fitness import compute

    entry = next((totals[n] for n in names if n in totals), {})
    fit = compute(entry, evidence_available=proj_credits.available, evidence_error=proj_credits.error)
    return fit.triggers, fit.reported_score


def _core_entries(core_files: List[Path], view: Any, proj_credits: Any) -> Tuple[List[dict], int]:
    """The core rules' table entries, and their characters for the context load."""
    # 3. Ledger totals of the host-installed rules (they have no rule file here)
    from aegis_core.fitness import combined_totals

    totals = combined_totals(view, proj_credits)
    total_chars = 0
    all_rules: list[dict] = []

    for f in core_files:
        try:
            content = f.read_text(encoding="utf-8-sig")
        except Exception:
            content = ""
        total_chars += len(content)
        fm = _parse_frontmatter(str(f))
        rule_name = sanitize_display(str(fm.get("id") or f.stem))
        triggers, score = _core_fitness(totals, proj_credits, rule_name, f.stem)
        all_rules.append({
            "name": rule_name,
            "type": "core",
            "score": score,
            "triggers": triggers,
            "expiry": "∞ (core)",
            "is_core": True,
        })
    return all_rules, total_chars


def _adaptive_entries(loaded: List[Any], fits: Dict[str, Any]) -> Tuple[List[dict], int]:
    """The workspace rules' table entries, and their characters for the context load."""
    total_chars = 0
    all_rules: list[dict] = []
    for rule in loaded:
        total_chars += len(rule.raw.decode("utf-8-sig", "replace"))
        fit = fits[rule.id]
        all_rules.append({
            "name": sanitize_display(rule.id),
            "type": rule.type,
            "score": fit.reported_score,
            "state": fit.state,
            "status_label": fit.status_label,
            "evidence_available": fit.evidence_available,
            "evidence_error": fit.evidence_error,
            "contested": fit.contested,
            "override_rate": fit.override_rate,
            "flagged_for_review": fit.flagged_for_review,
            "triggers": fit.triggers,
            "expiry": "expired" if rule.expired else _format_adaptive_expiry(
                rule.meta.get("created"), rule.meta.get("expiry_days")),
            "is_core": False,
        })
    return all_rules, total_chars


def _status_problems(ruleset: Any, stale: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "rule_errors": [{"path": r.path, "error": r.error} for r in ruleset.errors],
        "ignored": [{"path": i.path, "reason": i.reason} for i in ruleset.ignored],
        "stale_rules": stale,
        "needs_migrate": [{"path": r.path, "keys": list(r.legacy_keys)} for r in ruleset.needs_migrate],
        "untargeted": [{"id": r.id, "path": r.path} for r in sorted(ruleset.served, key=lambda r: r.id)
                       if not r.target_paths],
    }


def _status_payload(model: _StatusModel, all_rules: List[dict], estimated_tokens: int, ledger_health: Dict[str, Any],
                    problems: Dict[str, Any]) -> Dict[str, Any]:
    """The JSON document, its keys in the order the view has always written them."""
    return {
        "core_rules": len(model.core_files),
        "adaptive_rules": len(model.loaded),
        "estimated_tokens": estimated_tokens,
        "rules": all_rules,
        "last_sync": model.derived.get("synced_at") if model.derived else None,
        "inventory_error": model.inventory_error,
        "ledger": ledger_health,
        "claimed": model.claimed,
        "blocked_commands": model.blocked_cmds,
        "insights": model.insights,
        **problems,
    }


def _print_status(args: argparse.Namespace, proj: Path, model: _StatusModel, all_rules: List[dict],
                  estimated_tokens: int, problems: Dict[str, Any], rc: int) -> int:
    """The text view: only it reads the token budget and the terminal's output settings."""
    core_files, loaded, derived, insights = model.core_files, model.loaded, model.derived, model.insights
    blocked_cmds, claimed, inventory_error, view = model.blocked_cmds, model.claimed, model.inventory_error, model.view
    from aegis_cli.ui.table import Table
    from aegis_cli.ui.theme import OutputContext
    from aegis_core.insights import insight_status_lines

    existing_ui = getattr(args, "ui", None)
    ui = existing_ui if isinstance(existing_ui, OutputContext) else OutputContext.from_env_and_args(args)
    from aegis_core.config import jit_max_tokens

    max_budget = jit_max_tokens(proj, JIT_DEFAULT_MAX_TOKENS)

    header_title = "🛡️ Aegis Workspace Status" if ui.emoji_enabled else "Aegis Workspace Status"
    print(f"{ui.style(header_title, 'bold', 'cyan')}\n")
    print(f"  {'Core rules:':<16}{len(core_files)} active")
    print(f"  {'Adaptive rules:':<16}{len(loaded)} (traps/patterns)")
    print(f"  {'Context load:':<16}~{estimated_tokens:,} tokens (pre-JIT max)")
    print(f"  {'Token budget:':<16}{ui.format_budget_bar(estimated_tokens, max_budget)}")
    print(f"  {'Last sync:':<16}{derived.get('synced_at') if derived else 'never (run aegis sync)'}\n")
    insight_lines = insight_status_lines(insights)
    for line in insight_lines:
        print(f"  {sanitize_display(line, 300)}")
    if insight_lines:
        print()
    if blocked_cmds["total"]:
        by_host_str = ", ".join(f"{sanitize_display(h)}: {n}" for h, n in sorted(blocked_cmds["by_host"].items()))
        print(f"  {'Blocked cmds:':<16}{blocked_cmds['total']} ({blocked_cmds['label']}: {by_host_str})\n")
    if claimed["claimed"]:
        print(f"  {claimed['label']}: {claimed['claimed']} report(s) from {claimed['sessions']} session(s), "
              "no rule's evidence\n")
    _print_problems(inventory_error, problems, view.incomplete)

    if not all_rules:
        print("  No rules found. Run 'aegis init' to set up governance rules.")
        return rc

    tbl = Table(ctx=ui)
    tbl.add_column("Rule", no_wrap=True)
    tbl.add_column("Triggers", no_wrap=True)
    tbl.add_column("Type", no_wrap=True)
    tbl.add_column("Fitness", no_wrap=True)
    tbl.add_column("Expiry", no_wrap=True)

    last_type: str | None = None
    for r in all_rules:
        r_type = str(r.get("type", "trap"))
        if last_type is not None and r_type != last_type:
            tbl.add_section()
        last_type = r_type

        score_val = r.get("score")
        status_label = r.get("status_label")
        if isinstance(score_val, (int, float)):
            score_str = ui.color_fitness(float(score_val))
        elif status_label:
            score_str = str(status_label)
        else:
            score_str = "—"
        type_str = ui.color_rule_type(r_type)
        tbl.add_row(
            str(r["name"]),
            str(r["triggers"]),
            type_str,
            score_str,
            str(r["expiry"]),
        )

    for line in tbl.render(ui).splitlines():
        print(f"  {line}")

    return rc


def _print_problems(inventory_error: str | None, problems: dict, ledger_missing: str | None = None) -> None:
    """What the scan would refuse, skip or flag, so nothing is excluded unseen."""
    from aegis_cli.sync import LEDGER_WARNING

    if inventory_error:
        print(f"  ❌ The rules directory cannot be read safely: {sanitize_display(inventory_error)}")
    if ledger_missing:
        print(f"  {LEDGER_WARNING.format(sanitize_display(ledger_missing, 300))}")
    if problems["rule_errors"]:
        print(f"  ❌ {len(problems['rule_errors'])} rule file(s) cannot be loaded; aegis scan fails until they are fixed:")
        for item in problems["rule_errors"]:
            print(f"     {sanitize_display(item['path'])}: {sanitize_display(item['error'])}")
    if problems["stale_rules"]:
        print(f"  ✏️  {len(problems['stale_rules'])} rule(s) changed since the last aegis sync:")
        for item in problems["stale_rules"]:
            print(f"     {sanitize_display(str(item['id']))} ({item['change']})")
    if problems["needs_migrate"]:
        print(f"  ⚠️  {len(problems['needs_migrate'])} rule file(s) still carry derived counters or retired v3 keys "
              "(ignored; run aegis migrate --apply to strip them):")
        for item in problems["needs_migrate"]:
            print(f"     {sanitize_display(item['path'])}: {', '.join(item['keys'])}")
    if problems["ignored"]:
        print(f"  ℹ️  {len(problems['ignored'])} file(s) under .aegis/rules are not rules:")
        for item in problems["ignored"]:
            print(f"     {sanitize_display(item['path'])}: {item['reason']}")
    if problems["untargeted"]:
        print(f"  ⚠️  {len(problems['untargeted'])} rule(s) apply to no file (no target_paths), "
              "so scan and check never serve them:")
        for item in problems["untargeted"]:
            print(f"     {sanitize_display(str(item['id']))}: {sanitize_display(item['path'])}")
    if any(problems.values()) or inventory_error or ledger_missing:
        print()


# ── aegis status --compliance (ADR 0005 AD-9) ───────────────────────────────

COMPLIANCE_HELP = (
    "Show the per-host scan-before-edit rate from the MCP activity log "
    "(.aegis/state/activity.jsonl), per session and per host. Edits are the files a session "
    "named in aegis_report_outcome 'files' plus the files of commits inside exactly one "
    "session's window (first to last event, plus 15 minutes). Limits: an edit time is an upper "
    "bound (report or commit time), so the rate can overstate compliance; uncommitted edits "
    "that were never reported are not seen; commits in overlapping sessions count as "
    "ambiguous, not as misses; a session with no observed edit is unknown, never 0. A host "
    "rate is an aggregate over sessions, not a per-attempt verdict. Reads only."
)


def _rate_text(row: dict) -> str:
    return f"{round(row['rate'] * 100)}%" if row.get("rate") is not None else "unknown"


def run_compliance(args: argparse.Namespace) -> int:
    """``aegis status --compliance [--json]``: read-only; writes, syncs and fetches nothing."""
    import json
    import sys

    from aegis_core._version import __version__
    from aegis_core.scan_compliance import report
    from aegis_core.workspace.layout import is_aegis_workspace

    root = Path(_project_root(args)).resolve()
    if not is_aegis_workspace(root):
        print(f"Error: not an Aegis workspace (no .aegis/ in {root}); run aegis init", file=sys.stderr)
        return 1
    data = report(root)
    data = {"schema": data.pop("schema"), "source": data.pop("source"), "aegis_version": __version__, **data}
    if args.json:  # AegisParser.parse_args always sets it
        print(json.dumps(data, indent=2))
        return 0

    print("Scan-before-edit compliance (aegis status --compliance)\n")
    if not data["hosts"]:
        print("  No MCP activity recorded yet: the rate is unknown.")
    else:
        print(f"  {'Host':<16}{'Sessions':>9}{'Measured':>10}{'Edits':>7}{'Scanned first':>15}{'Rate':>9}")
        for row in data["hosts"]:
            scanned = "—" if row["scanned_before_edit"] is None else str(row["scanned_before_edit"])
            print(f"  {sanitize_display(row['host'], 16):<16}{row['sessions']:>9}{row['sessions_measured']:>10}"
                  f"{row['edits_observed']:>7}{scanned:>15}{_rate_text(row):>9}")
        print("\n  Host rates are aggregates over sessions, not a per-attempt verdict; "
              "--json lists every session.")
    if data["git"]["status"] != "used":
        print("  Commits were not read (no git repository or git unavailable): only reported edits count.")
    elif data["git"]["ambiguous_edits"]:
        print(f"  {data['git']['ambiguous_edits']} committed file(s) fell in overlapping sessions and were not attributed.")
    if data["activity"]["skipped"]:
        print(f"  {data['activity']['skipped']} activity row(s) could not be used.")
    print(f"\n  How it is measured: {data['heuristic']['edits']}")
    return 0


class StatusCommand(AegisCommand):
    """Command to show active rules, rule inventory, and health stats."""

    name = "status"
    category = CommandCategory.WORKFLOW
    help = "Show active rules and stats"

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        """status takes the global flags and --compliance."""
        parser.add_argument("--compliance", action="store_true", help=COMPLIANCE_HELP)

    def execute(self, args: argparse.Namespace) -> int:
        if getattr(args, "compliance", False):
            return run_compliance(args)
        return run_status(args)

