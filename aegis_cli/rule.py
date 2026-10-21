"""aegis rule — Unified rule lifecycle management.

Subcommands:
  aegis rule list                 List active workspace rules and fitness scores
  aegis rule create               Create a rule (--hypothesis, optional --body-file)
  aegis rule promote <rule_id>    Promote a rule up lifecycle tiers
  aegis rule demote <rule_id>     Demote a rule down lifecycle tiers
  aegis rule archive [--dry-run]  Archive rules that misfire (applies unless --dry-run)
  aegis rule export OUT           Write rules to an unsigned pack file (aegis_core.packs)
  aegis rule import PACK          Add the rules of a pack file (--rename, --dry-run)
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from aegis_cli import sanitize_display
from aegis_cli.base import CommandCategory, AegisCommand
from aegis_core.errors import WorkspaceNotFoundError
from aegis_core.lifecycle.creation import MAX_RULE_BODY_BYTES, validate_rule_body
from aegis_core.taxonomy import CANONICAL_RULE_TYPES
from aegis_core.workspace.base import Workspace
from aegis_core.workspace.binding import bounded_walk_up, home_message
from aegis_core.workspace.layout import WorkspaceLayout
from aegis_core.lifecycle.promotion import (
    promote_rule,
    demote_rule,
    evaluate_promotions,
    evaluate_demotions,
    evaluate_rule_tiers,
)
from aegis_core.lifecycle.selection import evidence_line, prune_rules, transition_candidates
from aegis_core.workspace.layout import is_aegis_workspace

__all__ = [
    "run_rule", "RuleCommand", "run_promote", "run_demote", "_force_promote",
    "_force_demote", "collect_workspace_rules",
]


def run_rule(args: argparse.Namespace) -> int:
    """Entrypoint for aegis rule subcommands."""
    action = getattr(args, "rule_action", None) or "list"
    handlers = {
        "list": _run_list, "create": _run_create, "promote": _run_promote,
        "demote": _run_demote, "archive": _run_archive, "export": _run_export,
        "import": _run_import, "insight": _run_insight, "adjudicate": _run_adjudicate,
    }
    if action not in handlers:
        print(f"Unknown rule subcommand: {action}", file=sys.stderr)
        return 1
    try:
        return handlers[action](args)
    except WorkspaceNotFoundError as exc:
        return _emit_error(args, str(exc))


def _emit_error(args: argparse.Namespace, msg: str) -> int:
    if getattr(args, "json", False):
        print(json.dumps({"status": "error", "error": msg}))
    else:
        print(f"Error: {msg}", file=sys.stderr)
    return 1


class _WorkspaceArg(argparse.Action):
    """Keep the operator's ``--workspace`` verbatim.

    ``cli.main`` replaces ``args.workspace`` with its own walked-up resolution
    before dispatch, which is how ``rule create`` once landed in ``$HOME``.
    """

    def __call__(self, parser, namespace, values, option_string=None):  # type: ignore[override]
        setattr(namespace, self.dest, values)
        setattr(namespace, "_rule_workspace_arg", values)


def _home() -> Path | None:
    try:
        return Path.home().resolve()
    except (RuntimeError, KeyError, OSError):
        return None


def _not_a_workspace(directory: Path) -> WorkspaceNotFoundError:
    return WorkspaceNotFoundError(f"not an Aegis workspace (no .aegis/ in {directory}); run aegis init")


def _walk_up_to_workspace(start: Path) -> Path:
    """The workspace an explicit --workspace names: AD-4's bounded walk-up from ``start``
    (never above its git toplevel, never ``$HOME`` or the filesystem root), else ``start``.

    It ignores AEGIS_WORKSPACE: an explicit --workspace beats the environment, as it
    already does for create.
    """
    return bounded_walk_up(start) or start


def _resolve_workspace_root(args: argparse.Namespace, require_aegis: bool = False) -> Path:
    """Resolve the rule workspace. Never ``$HOME``, never above the git toplevel (H8, AD-4).

    An explicit ``--workspace DIR`` is the start point, whichever position it
    was given in (``_workspace_arg`` is the raw global flag, when ``cli.main``
    keeps it). ``rule create`` (``require_aegis``) uses exactly DIR; the other
    actions take the bounded walk-up from DIR, and DIR must then resolve to a
    workspace. Without DIR the root comes from ``cli.main``'s discovery, which is
    bounded the same way.
    """
    explicit = getattr(args, "_rule_workspace_arg", None) or getattr(args, "_workspace_arg", None)
    if explicit:
        try:
            start = Path(explicit).expanduser().resolve()
        except (OSError, RuntimeError, ValueError) as exc:  # a NUL byte, a link loop before 3.13
            raise WorkspaceNotFoundError(f"--workspace {explicit} cannot be resolved: {exc}") from exc
        root = start if require_aegis else _walk_up_to_workspace(start)
    else:
        ws_obj = getattr(args, "ws", None)
        raw = getattr(args, "workspace", None) or getattr(args, "_project_root", None) or getattr(args, "_root", None)
        if ws_obj is None and raw:
            root = start = Path(raw).resolve()
        else:
            root = Path(ws_obj.root if ws_obj is not None else Workspace.resolve().root).resolve()
            start = Path.cwd().resolve()

    home = _home()
    if home is not None and root == home:
        if start == home:
            raise WorkspaceNotFoundError(home_message(home))
        raise _not_a_workspace(start)

    if (explicit or require_aegis) and not is_aegis_workspace(root):
        raise _not_a_workspace(root)
    return root


def collect_workspace_rules(
    root: Path,
    rule_type_filter: str | None = None,
    min_fitness: float | None = None,
) -> list[dict[str, Any]]:
    """The workspace's rules (one loader) with their ledger fitness, filtered.

    A rule file that cannot be loaded is listed with its ``error``; it has no fitness.
    A rule edited or added since the last ``aegis sync`` carries ``stale`` (``edited``
    or ``new``); it is listed like any other.
    """
    from aegis_core.fitness import for_rules
    from aegis_core.rules import load_rules
    from aegis_core.sync import read_derived, stale_rules

    ruleset = load_rules(root)
    selected = [r for r in ruleset.rules if not rule_type_filter or r.type == rule_type_filter]
    fits = for_rules(root, [r for r in selected if r.ok])
    stale = {s["id"]: s["change"] for s in stale_rules(ruleset, read_derived(root))}
    rules: list[dict[str, Any]] = []
    for rule in selected:
        fit = fits.get(rule.id) if rule.ok else None
        score = fit.score if fit is not None else None
        if min_fitness is not None and (score is None or score < min_fitness):
            continue
        entry: dict[str, Any] = {
            "id": rule.id,
            "type": rule.type,
            "domain": rule.meta.get("domain", "general"),
            "enforcement": rule.enforcement,
            "score": score,
            "reported_score": fit.reported_score if fit is not None else None,
            "triggers": fit.triggers if fit is not None else 0,
            "path": rule.path,
        }
        if rule.error:
            entry["error"] = rule.error
        if rule.expired:
            entry["expired"] = True
        if rule.id in stale and rule.ok:
            entry["stale"] = stale[rule.id]
        rules.append(entry)
    return rules


def _run_list(args: argparse.Namespace) -> int:
    """List active rules and fitness metrics."""
    root = _resolve_workspace_root(args)
    rules_dir = WorkspaceLayout(root).rules_dir
    if not rules_dir.is_dir():
        print(json.dumps([]) if getattr(args, "json", False) else "No rules directory found.")
        return 0

    from aegis_core.rule_inventory import RuleInventoryError

    try:
        rules = collect_workspace_rules(root, getattr(args, "type", None), getattr(args, "min_fitness", None))
    except RuleInventoryError as exc:
        return _emit_error(args, str(exc))
    if getattr(args, "json", False):
        print(json.dumps(rules, indent=2))
        return 0
    if not rules:
        print("No matching rules found.")
        return 0

    from aegis_cli.ui.table import Table
    from aegis_cli.ui.theme import OutputContext

    existing_ui = getattr(args, "ui", None)
    ui = existing_ui if isinstance(existing_ui, OutputContext) else OutputContext.from_env_and_args(args)
    tbl = Table(ctx=ui)
    for col in ("Rule ID", "Type", "Enforcement"):
        tbl.add_column(col, no_wrap=True)
    tbl.add_column("Fitness", justify="right", no_wrap=True)
    for r in rules:
        score_str = ui.color_fitness(float(r["reported_score"])) if isinstance(r.get("reported_score"), (int, float)) else "—"
        if r.get("error"):
            score_str = "error"
        tbl.add_row(sanitize_display(str(r["id"])), ui.color_rule_type(str(r["type"])), str(r["enforcement"]), score_str)

    print(f"Active Rules ({len(rules)} found):")
    for line in tbl.render(ui).splitlines():
        print(f"  {line}")
    stale = [f"{sanitize_display(str(r['id']))} ({r['stale']})" for r in rules if r.get("stale")]
    if stale:
        print(f"  {len(stale)} rule(s) changed since the last aegis sync: {', '.join(stale)}")
    return 0


def _emit_status(use_json: bool, payload: dict[str, Any], text: str, rc: int) -> int:
    print(json.dumps(payload) if use_json else text)
    return rc


def _resolve_rule_id(args: argparse.Namespace) -> str | None:
    return getattr(args, "rule_id", None)


def _run_promote(args: argparse.Namespace) -> int:
    """Promote a rule up lifecycle tiers or evaluate promotion candidates."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    root = _resolve_workspace_root(args)
    rule_id = _resolve_rule_id(args)
    dry_run = getattr(args, "dry_run", False)
    use_json = getattr(args, "json", False)

    if getattr(args, "tier_check", False):
        res = evaluate_rule_tiers(root, execute=not dry_run)
        if use_json:
            print(json.dumps(res, indent=2))
        else:
            changes = res.get("changes", [])
            print(f"  Evaluated {res.get('evaluated', 0)} rules across enforcement tiers.")
            if not changes:
                print("  No tier changes required.")
            for c in changes:
                print(f"    {c['rule']}: {c['old_tier']} → {c['new_tier']} ({c['reason']})")
            if res.get("refused"):
                print(f"  ❌ {res['refused']}")
        return 1 if res.get("refused") else 0

    if not rule_id:
        candidates = evaluate_promotions(str(root))
        if use_json:
            print(json.dumps({"candidates": candidates}, indent=2, default=str))
        elif not candidates:
            print("  No promotion candidates found.")
        else:
            print(f"  Promotion Candidates ({len(candidates)}):\n")
            for c in candidates:
                print(f"    {c['rule_id']}: {c['from_type']} → {c['to_type']}\n      triggers={c['triggers']} fitness={c['fitness']:.2f} age={c['age_days']}d")
            print()
        return 0

    res = promote_rule(root, rule_id, force=True, dry_run=dry_run)
    status = res.get("status")
    if status == "not_found":
        msg = f"Rule '{rule_id}' not found in workspace"
        return _emit_status(use_json, {"error": msg}, f"  ❌ {msg}", 1)
    if status == "already_terminal":
        msg = f"Rule '{rule_id}' is already at terminal tier ('{res.get('current_type')}')"
        return _emit_status(use_json, {"info": msg}, f"  ℹ️  {msg}", 0)
    if status not in ("promoted", "dry_run"):
        msg = res.get("message") or f"Promotion of '{rule_id}' failed ({status})"
        return _emit_status(use_json, {"error": msg}, f"  ❌ {msg}", 1)

    from_t, to_t = res.get("from_type"), res.get("to_type")
    if dry_run:
        return _emit_status(use_json, {"action": "promote", "rule_id": rule_id, "from": from_t, "to": to_t, "dry_run": True}, f"  🔍 Would promote: {rule_id}: {from_t} → {to_t}", 0)
    return _emit_status(use_json, {"action": "promote", "rule_id": rule_id, "from": from_t, "to": to_t, "success": True}, f"  ✅ Promoted: {rule_id}: {from_t} → {to_t}", 0)


def _run_demote(args: argparse.Namespace) -> int:
    """Demote a rule down lifecycle tiers or evaluate demotion candidates."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    root = _resolve_workspace_root(args)
    rule_id = _resolve_rule_id(args)
    dry_run = getattr(args, "dry_run", False)
    use_json = getattr(args, "json", False)

    if not rule_id:
        candidates, unavailable = transition_candidates(str(root), "demote")
        if use_json:
            print(json.dumps({"candidates": candidates}, indent=2, default=str))
            return 0
        if unavailable:
            print(f"  ⚠️  {evidence_line(unavailable)}")
        if not candidates:
            print("  No demotion candidates found.")
        else:
            print(f"  ⚠️  Demotion Candidates ({len(candidates)}):\n")
            for c in candidates:
                print(f"    {c['rule_id']}: {c['from_type']} → {c['to_type']} (misfiring)\n      "
                      f"triggers={c['triggers']} tp={c['tp']:g} fp={c['fp']:g} misfire bound={c['misfire']:.2f}")
            print()
        return 0

    try:
        res = demote_rule(root, rule_id, dry_run=dry_run)
    except ValueError:
        msg = f"Cannot demote core rule: {rule_id}."
        return _emit_status(use_json, {"error": msg}, f"  ❌ {msg}", 1)
    except Exception as exc:
        msg = f"Demotion error: {exc}"
        return _emit_status(use_json, {"error": msg}, f"  ❌ {msg}", 1)

    status = res.get("status")
    if status == "not_found":
        msg = f"Rule '{rule_id}' not found in workspace"
        return _emit_status(use_json, {"error": msg}, f"  ❌ {msg}", 1)
    if status == "already_base":
        msg = f"Rule '{rule_id}' is already at base tier ('{res.get('current_type')}')"
        return _emit_status(use_json, {"error": msg}, f"  ⚠️  {msg}", 1)
    if status not in ("demoted", "dry_run"):
        msg = res.get("message") or f"Demotion of '{rule_id}' failed ({status})"
        return _emit_status(use_json, {"error": msg}, f"  ❌ {msg}", 1)

    from_t, to_t = res.get("from_type"), res.get("to_type")
    if dry_run:
        return _emit_status(use_json, {"action": "demote", "rule_id": rule_id, "from": from_t, "to": to_t, "dry_run": True}, f"  🔍 Would demote: {rule_id}: {from_t} → {to_t}", 0)
    return _emit_status(use_json, {"action": "demote", "rule_id": rule_id, "from": from_t, "to": to_t, "success": True}, f"  ✅ Demoted: {rule_id}: {from_t} → {to_t}", 0)


def _force_promote(project_root: Path, rule_id: str, dry_run: bool = False, use_json: bool = False) -> int:
    return _run_promote(argparse.Namespace(_project_root=project_root, rule_id=rule_id, dry_run=dry_run, json=use_json, force=True))


def _force_demote(project_root: Path, rule_id: str, dry_run: bool = False, use_json: bool = False) -> int:
    return _run_demote(argparse.Namespace(_project_root=project_root, rule_id=rule_id, dry_run=dry_run, json=use_json, force=True))


run_promote = _run_promote
run_demote = _run_demote


def _run_archive(args: argparse.Namespace) -> int:
    """Archive extinct rules; --dry-run only reports what would move."""
    root = _resolve_workspace_root(args)
    execute = not getattr(args, "dry_run", False)
    return prune_rules(workspace=root, execute=execute)


def _split_csv_arg(raw: Any) -> list[str] | None:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw.strip():
        return [item.strip() for item in raw.split(",") if item.strip()]
    return None


class _BodyFileError(Exception):
    pass


def _read_body_file(raw: str) -> str:
    """Read a rule body from PATH or stdin (``-``), never more than the size cap + 1 byte."""
    label = "<stdin>" if raw == "-" else raw
    limit = MAX_RULE_BODY_BYTES + 1
    try:
        if raw == "-":
            stream = getattr(sys.stdin, "buffer", None)
            data = stream.read(limit) if stream is not None else sys.stdin.read(limit).encode("utf-8")
        else:
            with open(raw, "rb") as fh:
                data = fh.read(limit)
    except OSError as exc:
        raise _BodyFileError(f"--body-file {label}: cannot read file ({exc.strerror or exc})") from exc
    if len(data) > MAX_RULE_BODY_BYTES:
        raise _BodyFileError(f"--body-file {label}: rule body exceeds 64 KiB ({MAX_RULE_BODY_BYTES} bytes)")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _BodyFileError(f"--body-file {label}: rule body is not valid UTF-8") from exc
    try:
        return validate_rule_body(text)
    except ValueError as exc:
        raise _BodyFileError(f"--body-file {label}: {exc}") from exc


def _run_create(args: argparse.Namespace) -> int:
    """Create a new governance rule in the workspace."""
    from aegis_core.lifecycle.creation import create_rule
    rule_type = getattr(args, "type", None) or "trap"
    hypothesis = getattr(args, "hypothesis", "")
    if not hypothesis:
        print("Error: --hypothesis is required to create a rule.", file=sys.stderr)
        return 1
    root = _resolve_workspace_root(args, require_aegis=True)
    body = None
    body_file = getattr(args, "body_file", None)
    if body_file is not None:
        try:
            body = _read_body_file(body_file)
        except _BodyFileError as exc:
            return _emit_error(args, str(exc))
    rule_id = getattr(args, "id", None) or None
    target_paths = _split_csv_arg(getattr(args, "target_paths", None))
    try:
        created = create_rule(
            rule_type=rule_type, hypothesis=hypothesis, prediction=getattr(args, "prediction", "") or "",
            falsification=getattr(args, "falsification", "") or "",
            tags=_split_csv_arg(getattr(args, "tags", None)), id_override=rule_id,
            target_paths=target_paths, domain=getattr(args, "domain", "correctness") or "correctness",
            workspace=root, enforcement=getattr(args, "enforcement", None), body=body,
        )
    except Exception as exc:
        return _emit_error(args, str(exc))
    warnings = []
    if not any(isinstance(p, str) and p.strip() for p in target_paths or []):
        # Created as asked, but a rule without target_paths applies to no file (aegis_core.match).
        warnings.append(
            f"rule {created.stem!r} has no target_paths, so it matches no file: aegis scan never shows it "
            "and aegis check records nothing for it. Pass --target-paths (for example 'src/**/*.py')."
        )
    if getattr(args, "json", False):
        print(json.dumps({"status": "created", "path": str(created), "id": created.stem, "warnings": warnings}, indent=2))
    else:
        print(f"Created rule: {created}")
        for warning in warnings:
            print(f"Warning: {warning}", file=sys.stderr)
    return 0


# ── Rule packs: export and import (v4.2 #3, aegis_core.packs) ───────────────

_SHOWN_PROBLEMS = 10
_UNSIGNED = "The pack is unsigned: its sha256 ({short}) shows it was not altered after export, not who made it."


def _show(value: object) -> str:
    """Pack content and rule files are repository or network content: no terminal controls."""
    text = str(value)
    return sanitize_display(text, max_len=len(text))


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _pack_envelope(action: str, root: Optional[Path], scope: Dict[str, Any]) -> Dict[str, Any]:
    from aegis_core._version import __version__

    return {
        "source": f"aegis rule {action}",
        "aegis_version": __version__,
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {"workspace": str(root) if root is not None else None, **scope},
    }


def _pack_fail(args: argparse.Namespace, action: str, root: Optional[Path], scope: Dict[str, Any],
               message: str, problems: Sequence[str] = (), status: str = "error", header: str = "") -> int:
    """A refusal or failure that wrote nothing: an enveloped document with --json, else stderr.
    With problems, the text lists the first ten under ``header``."""
    if getattr(args, "json", False):
        doc = _pack_envelope(action, root, scope)
        doc.update({"status": status, "error": message})
        if problems:
            doc["problems"] = list(problems)
        print(json.dumps(doc, indent=2))
    elif problems and header:
        print(f"Error: {header}", file=sys.stderr)
        for problem in problems[:_SHOWN_PROBLEMS]:
            print(f"  {_show(problem)}", file=sys.stderr)
        if len(problems) > _SHOWN_PROBLEMS:
            print(f"  ... and {len(problems) - _SHOWN_PROBLEMS} more problems", file=sys.stderr)
    else:
        print(f"Error: {_show(message)}", file=sys.stderr)
    return 1


def _out_problem(out: str) -> Optional[str]:
    """Why ``out`` cannot be written as a pack file, or None. A link is refused (the write
    would land wherever it points); an existing regular file is replaced."""
    if os.path.islink(out):
        return f"{out} is a symlink"
    if os.path.isdir(out):
        return f"{out} is a directory"
    if os.path.lexists(out) and not os.path.isfile(out):
        return f"{out} is not a regular file"
    parent = os.path.dirname(out)
    if not os.path.isdir(parent):
        return f"the directory {parent} does not exist"
    return None


def _run_export(args: argparse.Namespace) -> int:
    """Write the workspace's rules to a pack file; nothing in the workspace changes."""
    from aegis_core import packs
    from aegis_core.storage import atomic_write_bytes

    types = list(getattr(args, "types", None) or [])
    min_fitness = getattr(args, "min_fitness", None)
    scope: Dict[str, Any] = {"types": types, "min_fitness": min_fitness}
    try:
        root = _resolve_workspace_root(args)
    except WorkspaceNotFoundError as exc:
        return _pack_fail(args, "export", None, scope, str(exc))
    out = os.path.abspath(os.path.expanduser(args.out))
    problem = _out_problem(out)
    if problem:
        return _pack_fail(args, "export", root, scope, f"cannot write the pack: {problem}")
    try:
        selection = packs.select_rules(root, types=types or None, min_fitness=min_fitness)
        pack = packs.build_pack(selection.rules)
    except packs.PackError as exc:
        many = len(exc.problems) > 1
        message = f"the export was refused: {len(exc.problems)} problems" if many else exc.problems[0]
        return _pack_fail(args, "export", root, scope, message, exc.problems, "refused",
                          header="the export was refused:" if many else "")
    try:
        atomic_write_bytes(out, packs.dump_pack(pack))
    except OSError as exc:
        return _pack_fail(args, "export", root, scope, f"cannot write the pack: {exc.strerror or exc}")

    entries = []
    for entry in pack["rules"]:
        parsed = packs.parse_pack_path(entry["path"])
        entries.append({"path": entry["path"], "id": parsed.id, "type": parsed.type, "sha256": entry["sha256"]})
    skipped = [{"id": rule_id, "reason": reason} for rule_id, reason in selection.skipped]
    if getattr(args, "json", False):
        doc = _pack_envelope("export", root, scope)
        doc.update({"status": "exported", "out": out, "signed": False, "sha256": pack["sha256"],
                    "rules": entries, "skipped": skipped})
        print(json.dumps(doc, indent=2))
        return 0
    print(f"Exported {_plural(len(entries), 'rule')} to {_show(out)}")
    for entry in entries:
        print(f"  {entry['path']}")
    if skipped:
        print("Skipped: " + ", ".join(f"{_show(s['id'])} ({s['reason']})" for s in skipped))
    print(_UNSIGNED.format(short=pack["sha256"][:12]))
    return 0


class _PackFileError(Exception):
    pass


def _read_pack_file(path: str, limit: int) -> bytes:
    """The pack file's bytes, at most ``limit`` + 1 of them; a file that is not a regular file
    is never opened (a FIFO would block)."""
    if not os.path.lexists(path):
        raise _PackFileError(f"{path} does not exist")
    if not os.path.isfile(path):
        raise _PackFileError(f"{path} is not a regular file")
    try:
        with open(path, "rb") as handle:
            return handle.read(limit + 1)
    except OSError as exc:
        raise _PackFileError(f"{path}: {exc.strerror or exc}") from None


def _run_import(args: argparse.Namespace) -> int:
    """Add the rules of a pack file to the workspace, all or none."""
    from aegis_core import packs

    pack_path = os.path.abspath(os.path.expanduser(args.pack))
    rename = bool(getattr(args, "rename", False))
    dry_run = bool(getattr(args, "dry_run", False))
    scope: Dict[str, Any] = {"pack": pack_path, "rename": rename, "dry_run": dry_run}
    try:
        root = _resolve_workspace_root(args, require_aegis=True)
    except WorkspaceNotFoundError as exc:
        return _pack_fail(args, "import", None, scope, str(exc))
    try:
        data = _read_pack_file(pack_path, packs.MAX_PACK_BYTES)
    except _PackFileError as exc:
        return _pack_fail(args, "import", root, scope, f"cannot read the pack: {exc}")
    try:
        pack = packs.load_pack(data)
        result = packs.import_pack(root, pack, rename=rename, dry_run=dry_run)
    except packs.PackError as exc:
        count = _plural(len(exc.problems), "problem")
        return _pack_fail(args, "import", root, scope, f"the pack was not imported: {count}", exc.problems,
                          "refused", header="the pack was not imported:")
    except Exception as exc:  # a lock timeout, an unconfined state dir...: nothing was imported
        return _pack_fail(args, "import", root, scope, f"the pack was not imported: {exc}")

    rules = [{"path": r.path, "id": r.id, "type": r.type, "renamed_from": r.renamed_from, "sha256": r.sha256}
             for r in result.rules]
    if getattr(args, "json", False):
        doc = _pack_envelope("import", root, scope)
        doc.update({"status": "dry_run" if result.dry_run else "imported", "signed": False,
                    "pack_sha256": result.pack_sha256, "rules": rules, "warnings": list(result.warnings)})
        print(json.dumps(doc, indent=2))
        return 0
    short = result.pack_sha256[:12]
    count = _plural(len(rules), "rule")
    verb = f"Dry run: would import {count}" if result.dry_run else f"Imported {count}"
    print(f"{verb} from {_show(pack_path)} (sha256 {short}):")
    for rule in rules:
        renamed = f" (renamed from {rule['renamed_from']!r})" if rule["renamed_from"] else ""
        print(f"  {rule['path']}{renamed}")
    for warning in result.warnings:
        print(f"Warning: {_show(warning)}", file=sys.stderr)
    if result.dry_run:
        print("Nothing was written.")
    else:
        print("The pack is unsigned: review the imported rules (git diff) before you rely on them, "
              "then run aegis sync.")
    return 0


class RuleCommand(AegisCommand):
    """Unified rule lifecycle management."""

    name = "rule"
    aliases = ()
    category = CommandCategory.LIFECYCLE
    help = "Manage rule lifecycle (list, create, promote, demote, archive) and share rules as unsigned packs"

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        common = argparse.ArgumentParser(add_help=False)
        for flag in ("--plain", "--json"):
            common.add_argument(flag, action="store_true", default=argparse.SUPPRESS)
        common.add_argument("--workspace", type=str, default=argparse.SUPPRESS, action=_WorkspaceArg)
        sub = parser.add_subparsers(dest="rule_action", metavar="ACTION")

        p_list = sub.add_parser("list", parents=[common], help="List active rules and fitness metrics")
        p_list.add_argument("--type", choices=list(CANONICAL_RULE_TYPES), help="Filter by rule type")
        p_list.add_argument("--min-fitness", type=float, help="Filter by minimum fitness score")

        p_create = sub.add_parser("create", parents=[common], help="Create a new governance rule")
        p_create.add_argument("-t", "--type", dest="type", default="trap", help=f"Rule type ({', '.join(CANONICAL_RULE_TYPES)})")
        p_create.add_argument("--hypothesis", default="", help="Testable rule hypothesis")
        p_create.add_argument("-p", "--prediction", default="", help="Expected outcome when hypothesis holds")
        p_create.add_argument("-f", "--falsification", default="", help="Criteria that falsify the rule")
        p_create.add_argument("-d", "--domain", default="correctness", help="Governance domain")
        p_create.add_argument("-e", "--enforcement", default=None, help="Enforcement tier (gate, advisory)")
        p_create.add_argument("-n", "--name", "--id", dest="id", default=None, help="Explicit rule ID stem")
        p_create.add_argument("--target-paths", dest="target_paths", default="", help="Comma-separated target path globs")
        p_create.add_argument("--tags", default="", help="Comma-separated tags")
        p_create.add_argument("--body-file", dest="body_file", default=None, metavar="PATH",
                              help="Rule body (markdown after the frontmatter) from PATH, or '-' for stdin; max 64 KiB")

        p_prom = sub.add_parser("promote", parents=[common], help="Promote a rule up lifecycle tiers (no RULE_ID: list candidates)")
        p_prom.add_argument("rule_id", nargs="?", default=None, metavar="RULE_ID", help="Rule identifier to promote")
        p_prom.add_argument("--tier-check", action="store_true", help="Evaluate enforcement tier transitions")
        p_prom.add_argument("--dry-run", action="store_true", help="Preview promotion without moving files")

        p_dem = sub.add_parser("demote", parents=[common], help="Demote a rule down lifecycle tiers (no RULE_ID: list candidates)")
        p_dem.add_argument("rule_id", nargs="?", default=None, metavar="RULE_ID", help="Rule identifier to demote")
        p_dem.add_argument("--dry-run", action="store_true", help="Preview demotion without moving files")

        p_arch = sub.add_parser("archive", parents=[common], help="Archive rules whose ledger evidence says they misfire")
        p_arch.add_argument("--dry-run", action="store_true", help="Report the rules that would be archived; move nothing")

        p_exp = sub.add_parser(
            "export", parents=[common], help="Write the workspace's rules to an unsigned pack file",
            description=("Write the workspace's rules to OUT as a pack: their text and digests, no ledger rows. "
                         "The pack is unsigned: its sha256 shows it was not altered after export, not who made "
                         "it. A rule that cannot be loaded, or that still has derived or retired keys (run "
                         "aegis migrate --apply), stops the export; an expired rule is skipped and reported. "
                         "An existing regular file at OUT is replaced; a link is refused."))
        p_exp.add_argument("out", metavar="OUT", help="The pack file to write")
        p_exp.add_argument("--type", dest="types", action="append", choices=list(CANONICAL_RULE_TYPES),
                           metavar="TYPE", help=f"Export only rules of this type (repeatable): {', '.join(CANONICAL_RULE_TYPES)}")
        p_exp.add_argument("--min-fitness", dest="min_fitness", type=float, default=None, metavar="X",
                           help="Export only rules whose fitness in this repository's ledger is at least X")

        p_imp = sub.add_parser(
            "import", parents=[common], help="Add the rules of an unsigned pack file to the workspace",
            description=("Add the rules of PACK to the workspace's .aegis/rules. The pack is unsigned: its digests "
                         "show it was not altered after export, not who made it, so every entry is checked "
                         "(its path must be exactly <type dir>/<id>.md, and the rule loader must accept it) and "
                         "the pack is imported whole or not at all. An id the workspace already has refuses the "
                         "pack unless --rename gives the incoming rule a free id. With --workspace DIR, DIR "
                         "itself must hold .aegis (there is no walk-up from it). Review the imported rules "
                         "before you rely on them."))
        p_imp.add_argument("pack", metavar="PACK", help="The pack file to read")
        p_imp.add_argument("--rename", action="store_true",
                           help="Give a rule whose id is taken a free id (<id>-imported, -imported-2, ...) instead of refusing")
        p_imp.add_argument("--dry-run", dest="dry_run", action="store_true",
                           help="Check the pack and report what would be added; write nothing")

        p_ins = sub.add_parser(
            "insight", parents=[common],
            help="Capture, review, and enable human correction insights (add, review, enable)",
        )
        ins_sub = p_ins.add_subparsers(dest="insight_action", metavar="INSIGHT_ACTION")

        p_ins_add = ins_sub.add_parser("add", parents=[common], help="Record an explicit human correction insight")
        p_ins_add.add_argument("text", metavar="TEXT", help="Correction insight text (redacted and capped at 300 chars)")
        p_ins_add.add_argument("--paths", nargs="*", default=None, help="Target file paths (default: git dirty set)")
        p_ins_add.add_argument("--kind", default=None, help="Optional insight category or kind")
        p_ins_add.add_argument("--commit", default=None, help="Optional signed commit SHA carrying Aegis-Approve-Insight")
        p_ins_add.add_argument("--base-ref", dest="base_ref", default=None, help="Optional base branch reference for --commit")

        p_ins_rev = ins_sub.add_parser("review", parents=[common], help="Cluster and review insights or record a decision")
        p_ins_rev.add_argument("--decision", choices=["propose", "reject", "snooze", "merge-into-rule", "noise"],
                               default=None, help="Record a review decision for a cluster")
        p_ins_rev.add_argument("--cluster", dest="cluster_id", default=None, help="Cluster ID for --decision")
        p_ins_rev.add_argument("--proposal-id", dest="proposal_id", default=None, help="Proposal ID when --decision propose")
        p_ins_rev.add_argument("--category", default="correctness", help="Proposal category when --decision propose")
        p_ins_rev.add_argument("--summary", default=None, help="Closed-template summary bullet when --decision propose")
        p_ins_rev.add_argument("--rule", dest="rule_id", default=None, help="Target rule ID for merge-into-rule or recurrence check")
        p_ins_rev.add_argument("--reason", default=None, help="Optional reason for the decision")

        p_ins_en = ins_sub.add_parser("enable", parents=[common], help="Opt-in enable UserPromptSubmit insight capture for a host")
        p_ins_en.add_argument("--host", required=True, choices=["claude-code", "codex-cli"],
                              help="Host to configure (claude-code or codex-cli)")
        p_ins_en.add_argument("--excerpts", action="store_true", default=False,
                              help="Also store redacted <=300 char excerpts on correction cues (default: counters/heartbeats only)")

        p_adj = sub.add_parser("adjudicate", parents=[common], help=_ADJUDICATE_HELP, description=_ADJUDICATE_DESCRIPTION)
        p_adj.add_argument("rule_id", metavar="RULE_ID", help="Rule identifier to adjudicate")
        p_adj.add_argument("verdict", choices=["tp", "fp"], metavar="VERDICT", help="Adjudication verdict (tp or fp)")
        p_adj.add_argument("--ref", default=None, help="Optional commit SHA, PR number, or issue reference")
        p_adj.add_argument("--summary", default=None, help="Optional one-line summary of the adjudicated example")
        p_adj.add_argument("--file", default=None, help="Optional file path where the rule applied")
        p_adj.add_argument("--line", type=int, default=None, help="Optional line number in --file")
        p_adj.add_argument("--session", default=None, help="Optional session identifier")
        p_adj.add_argument("--repo", default=None, help="Optional repository identifier")

    def execute(self, args: argparse.Namespace) -> int:
        return run_rule(args)


_ADJUDICATE_HELP = "Record an adjudication label (tp or fp) in .aegis/adjudications/; it counts after it is merged to the base branch"
_ADJUDICATE_DESCRIPTION = ("Append a tp or fp label for a rule to .aegis/adjudications/<rule-id>.jsonl. The label counts "
                           "toward the rule's fitness only after a reviewed pull request merges it to the base branch.")


def _run_adjudicate(args: argparse.Namespace) -> int:
    import hashlib

    from aegis_core.adjudication import ADJUDICATIONS_DIR, RULE_ID
    from aegis_core.errors import AegisError
    from aegis_core.storage import append_jsonl

    rule_id = str(args.rule_id)
    if not RULE_ID.fullmatch(rule_id):
        return _emit_error(args, f"invalid rule id {sanitize_display(rule_id, 80)!r}: use letters, digits, '.', '_' or '-' (at most 128)")
    root = _resolve_workspace_root(args)
    directory = root.joinpath(*ADJUDICATIONS_DIR.split("/"))
    if directory.is_symlink() or directory.parent.is_symlink():
        return _emit_error(args, f"{ADJUDICATIONS_DIR} is a symlink; refusing to write a label through it")
    ref, file, line, summary = (getattr(args, k, None) for k in ("ref", "file", "line", "summary"))
    example = ref or hashlib.sha256(f"{rule_id}|{file or ''}|{'' if line is None else line}|{summary or ''}".encode("utf-8")).hexdigest()[:16]
    row: Dict[str, Any] = {"example_id": str(example), "verdict": str(args.verdict),
                           "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    for key in ("ref", "summary", "file", "session", "repo"):
        if getattr(args, key, None) is not None:
            row[key] = str(getattr(args, key))
    if line is not None:
        row["line"] = int(line)
    rel = f"{ADJUDICATIONS_DIR}/{rule_id}.jsonl"
    try:
        append_jsonl(directory / f"{rule_id}.jsonl", [row])
    except (OSError, AegisError) as exc:
        return _emit_error(args, f"cannot write {rel}: {exc}")
    if getattr(args, "json", False):
        print(json.dumps({"status": "recorded", "rule": rule_id, "path": rel, "label": row}, indent=2))
    else:
        print(f"Recorded a {row['verdict']} label for {sanitize_display(rule_id)} in {rel}; "
              "it counts after it is merged to the base branch")
    return 0


def _run_insight(args: argparse.Namespace) -> int:
    from aegis_core.insights import (
        add_insight, measure_recurrence, record_decision, review_insights, write_proposal,
    )
    sub_action = getattr(args, "insight_action", None)
    use_json = bool(getattr(args, "json", False))
    if sub_action == "enable":
        from aegis_cli.hooks.insights import enable_insight_hook
        from aegis_cli.hooks.registrar import CODEX_TRUST_STEP

        host, excerpts = getattr(args, "host", None), bool(getattr(args, "excerpts", False))
        try:
            res = enable_insight_hook(host, excerpts=excerpts)
        except Exception as exc:
            return _emit_error(args, str(exc))
        if use_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Enabled insight capture for {host} ({'excerpts + heartbeats' if excerpts else 'heartbeats only'}) in {res['config_path']}")
            if res.get("backup_dir"):
                print(f"   backup: {res['backup_dir']}")
        if host == "codex-cli":
            print(f"   Next: {CODEX_TRUST_STEP}", file=sys.stderr if use_json else sys.stdout)
        return 0

    if sub_action == "add":
        root = _resolve_workspace_root(args)
        try:
            row = add_insight(
                root, getattr(args, "text", ""), paths=getattr(args, "paths", None),
                kind=getattr(args, "kind", None), commit=getattr(args, "commit", None),
                base_ref=getattr(args, "base_ref", None),
            )
        except Exception as exc:
            return _emit_error(args, str(exc))
        print(json.dumps(row, indent=2) if use_json else f"Recorded insight {row['id']} (level={row['level']}, psrc={row['psrc']})")
        return 0

    if sub_action == "review":
        root = _resolve_workspace_root(args)
        decision = getattr(args, "decision", None)
        rev = review_insights(root)
        if decision:
            cid = getattr(args, "cluster_id", None)
            target_cluster = next((c for c in rev["clusters"] if c["cluster_id"] == cid), None) if cid else (rev["clusters"][0] if rev["clusters"] else None)
            cid = cid or (target_cluster["cluster_id"] if target_cluster else None)
            if not cid:
                return _emit_error(args, "no cluster available to record decision; pass --cluster")
            ins_ids = target_cluster["insight_ids"] if target_cluster else []
            try:
                dec_row = record_decision(
                    root, cluster_id=cid, decision=decision, insight_ids=ins_ids,
                    reason=getattr(args, "reason", None), rule_id=getattr(args, "rule_id", None),
                )
                if decision == "propose":
                    prop_id = getattr(args, "proposal_id", None) or f"trap-{cid.replace('cluster-', '')}"
                    summary = getattr(args, "summary", None) or f"Address recurring correction cluster {cid}."
                    paths = (target_cluster.get("paths") if target_cluster else None) or ["**"]
                    dec_row["proposal_path"] = str(write_proposal(
                        root, proposal_id=prop_id, target_paths=paths,
                        category=getattr(args, "category", "correctness") or "correctness",
                        summary_bullets=[summary], insight_ids=ins_ids,
                    ))
            except Exception as exc:
                return _emit_error(args, str(exc))
            print(json.dumps(dec_row, indent=2) if use_json else f"Recorded decision '{decision}' for {cid}")
            return 0

        if rule_id := getattr(args, "rule_id", None):
            try:
                rev["recurrence"] = measure_recurrence(root, rule_id)
            except Exception as exc:
                return _emit_error(args, str(exc))
        if use_json:
            print(json.dumps(rev, indent=2))
        else:
            clusters, suggestions = rev.get("clusters", []), rev.get("suggestions", [])
            print(f"Insight Review: {len(clusters)} cluster(s), {len(suggestions)} unconfirmed agent suggestion(s)")
            for c in clusters:
                print(f"  [{c['cluster_id']}] count={c['count']} status={c['match_status']} rule={c.get('matched_rule') or 'none'}")
        return 0

    return _emit_error(args, "Specify an insight action: add, review, or enable")


if __name__ == "__main__":  # pragma: no cover
    from aegis_cli.cli import main
    sys.exit(main(["rule"] + sys.argv[1:]))
