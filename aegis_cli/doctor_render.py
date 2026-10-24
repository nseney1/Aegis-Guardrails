"""Output formatting, JSON payload assembly, GitHub ruleset display, and release verification UI for ``aegis doctor``."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple

from aegis_core import human_gate
from aegis_core.primitives import utc_stamp

if TYPE_CHECKING:
    from aegis_cli.doctor import Registered, _Ctx
    from aegis_cli.doctor_findings import _Finding
    from aegis_cli.doctor_repair import _Change, _Diagnosis


# ── Enforcement tiers (AD-8) ────────────────────────────────────────────────

def _floor_status(root: Path) -> Tuple[str, Optional[str]]:
    """The local floor's status, and why an installed, current hook never runs. The floor
    is active only for a hook that is installed, current and reached by git (hook_status
    ``reachable``; a status without the key predates it and counts as reachable)."""
    from aegis_cli import doctor as _doc
    from aegis_cli.hooks import management

    try:
        st = management.hook_status(root)
    except Exception:
        return "unknown", None
    if st.get("status") == "no_git_repository":
        return "unavailable", None
    if not st.get("managed_by_aegis"):
        return "inactive", None
    if st.get("status") != "installed":
        return "outdated", None
    gone = [p for p in (st.get("interpreter"), st.get("aegis_path")) if p and not p.get("exists")]
    if gone:
        return "outdated", None
    if st.get("reachable", True) is False:
        return "inactive", _doc._clean(st.get("unreachable_reason") or "git does not reach the Aegis block", 1024)
    return "active", None


_TIER_TEXT = {
    "advisory": ("Advisory", "AGENTS.md bootstrap, MCP instructions, JIT rules"),
    "best_effort": ("Best-effort", "per-host pre-tool hooks"),
    "local_floor": ("Local floor", "git pre-commit runs aegis check --hook (--no-verify bypasses it)"),
    "authoritative": ("Authoritative", "CI runs aegis check on the exact SHA; a human merges"),
}


def _tiers(rows: List[Dict[str, Any]], floor: str, governed: bool, unreached: Optional[str] = None,
           setup: str = "aegis init") -> List[Dict[str, Any]]:
    ids = [r["id"] for r in rows]
    reached = [r["id"] for r in rows if r["advisory"] is True]
    unsure = [r["id"] for r in rows if r["advisory"] is None]
    if ids and len(reached) == len(ids):
        advisory = "active"
    else:
        advisory = "partial" if reached else ("unknown" if unsure else "inactive")
    reach = f"reaches {', '.join(reached) or 'no selected host'}"
    if unsure:
        reach += f"; unknown for {', '.join(unsure)}"
    floor_detail = {
        "active": "the Aegis pre-commit hook is installed and current",
        "inactive": "no Aegis pre-commit hook: run aegis hook install",
        "outdated": "the Aegis pre-commit hook is outdated: run aegis hook install",
        "unavailable": "not a git repository",
        "unknown": "the git hooks directory could not be read",
    }[floor]
    if unreached:
        floor_detail = f"the Aegis pre-commit hook is installed but never runs: {unreached}; see aegis hook status"
    if not governed and floor != "unavailable":
        # A hook here, installed or not, has no rules to check: the floor is not in force.
        floor, floor_detail = "inactive", f"no .aegis/ here, so a pre-commit hook has nothing to enforce: run {setup}"
    return [
        {"tier": "advisory", "mechanism": _TIER_TEXT["advisory"][1], "hosts": ids, "status": advisory,
         "detail": reach},
        _best_effort(rows, governed, setup),
        {"tier": "local_floor", "mechanism": _TIER_TEXT["local_floor"][1], "hosts": ids, "status": floor,
         "detail": floor_detail},
        {"tier": "authoritative", "mechanism": _TIER_TEXT["authoritative"][1], "hosts": [], "status": "unavailable",
         "detail": "not checked: aegis doctor does not read CI runs; the trust tier says what GitHub enforces"},
    ]


def _hook_tier_text(host_id: str, hooks: Dict[str, Any]) -> str:
    text = f"{host_id}: {hooks['tier']} [{hooks['evidence']}]"
    return text + (f", {hooks['trust']}" if hooks["trust"] else "")


def _best_effort(rows: List[Dict[str, Any]], governed: bool, setup: str) -> Dict[str, Any]:
    """The per-host hook tier. Doctor reads files only, so a registered hook makes the tier
    ``unknown``, never active: whether a host runs it is out of doctor's sight."""
    tier = {"tier": "best_effort", "mechanism": _TIER_TEXT["best_effort"][1], "hosts": []}
    hooks = {row["id"]: row["hooks"] for row in rows}
    capable = [h for h, v in hooks.items() if v["status"] not in ("unavailable", "none")]
    hooked = [h for h in capable if hooks[h]["status"] in ("registered", "duplicate")]
    if not capable:
        reasons = "; ".join(v["detail"] for v in hooks.values() if v["detail"]) or "no selected host has Aegis hooks"
        return dict(tier, status="unavailable", detail=reasons)
    if not governed:
        return dict(tier, status="inactive",
                    detail=f"no .aegis/ here, so a registered hook passes every call: run {setup}")
    if hooked:
        said = "; ".join(_hook_tier_text(h, hooks[h]) for h in hooked)
        return dict(tier, hosts=hooked, status="unknown",
                    detail=f"registered for {said}. Doctor reads the host files only and cannot confirm that a host "
                           "runs them; each fails open when Aegis errors")
    unreadable = [h for h in capable if hooks[h]["status"] == "unknown"]
    if unreadable:
        return dict(tier, status="unknown",
                    detail=f"cannot tell for {', '.join(unreadable)}: a hook file cannot be read (see the warnings)")
    modified = [h for h in capable if hooks[h]["status"] == "modified"]
    if modified:
        return dict(tier, status="unknown",
                    detail=f"cannot tell for {', '.join(modified)}: its Aegis hook entry is not the one aegis hook "
                           "install writes (see the warnings)")
    absent = [h for h in capable if hooks[h]["status"] == "absent"]
    broken = [h for h in capable if hooks[h]["status"] == "broken"]
    parts = [f"no Aegis PreToolUse hook registered for {', '.join(absent)}"] if absent else []
    if broken:
        parts.append(f"the Aegis hook of {', '.join(broken)} runs a missing aegis")
    return dict(tier, status="inactive", detail="; ".join(parts) + ": run aegis hook install --host <host>")


# ── Output ──────────────────────────────────────────────────────────────────

_CHECKS: Tuple[Tuple[str, bool], ...] = (
    # (id, failing it fails the run); advisory checks only warn.
    ("python_version", True), ("zero_dependencies", True), ("rules", True), ("state_dir", True),
    ("cli_on_path", True), ("precommit_hook", True), ("ast_drivers", False), ("mcp_launcher", False),
)


def _registered_launchers(rows: List[Dict[str, Any]]) -> List[Registered]:
    """The command each host has registered, where doctor could read it."""
    return [(row["id"], row["registration"]["command"]) for row in rows
            if row["registration"]["status"] == "registered" and row["registration"]["command"]]


def _run_checks(root: Path, fix_ast: bool, only: Optional[Sequence[str]] = None,
                registered: Sequence[Registered] = ()) -> List[Dict[str, Any]]:
    from aegis_cli import doctor as _doc

    calls: Dict[str, Callable[[], Optional[bool]]] = {
        "python_version": _doc._check_python_version,
        "zero_dependencies": _doc._check_zero_dependencies,
        "rules": lambda: _doc._check_rules(root),
        "state_dir": lambda: _doc._check_state_dir(root),
        "cli_on_path": lambda: _doc._check_cli_resolvable(root),
        "precommit_hook": lambda: _doc._check_precommit_hook(root),
        "ast_drivers": lambda: _doc._check_ast_drivers(root, fix=fix_ast),
        "mcp_launcher": lambda: _doc._check_mcp_launcher(workspace=root, registered=registered),
    }
    out = []
    for check_id, blocking in _CHECKS:
        if only is not None and check_id not in only:
            continue
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok = calls[check_id]()
        status = "skip" if ok is None else ("pass" if ok else ("fail" if blocking else "warn"))
        # The lines quote rule file names, loader errors and paths a repository chooses:
        # cleaned here, at the one place every check's output passes.
        text = "".join(_doc._clean(line, 4096) + "\n" for line in buf.getvalue().splitlines())
        out.append({"id": check_id, "status": status, "text": text,
                    "detail": [line.strip() for line in text.splitlines() if line.strip()]})
    return out


def _summary(checks: List[Dict[str, Any]], findings: List[_Finding]) -> Dict[str, int]:
    counted = [c for c in checks if c["status"] != "skip"]
    warn_checks = sum(c["status"] == "warn" for c in counted)
    return {"passed": sum(c["status"] == "pass" for c in counted),
            "warnings": warn_checks + sum(f.severity == "warning" for f in findings),
            "failed": sum(c["status"] == "fail" for c in counted), "total": len(counted)}


def _payload(diag: _Diagnosis, checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    from aegis_cli import doctor as _doc

    ctx = diag.ctx
    summary = _summary(checks, diag.findings)
    unknown = [f"{r['id']}.{field}" for r in diag.rows for field in r["unknown"]]
    hosts = [{k: v for k, v in row.items() if k != "advisory"} for row in diag.rows]
    return {
        "schema": _doc.SCHEMA,
        "source": _doc.SOURCE,
        "aegis_version": _doc._aegis_version(),
        "checked_at": utc_stamp(),
        "scope": {"machine": "local", "workspace": str(ctx.root), "workspace_governed": ctx.governed,
                  "hosts": [s.id for s in ctx.selected], "host_selection": ctx.selection},
        "stale": False,
        "unknown": unknown,
        # Only the checks: a run whose hosts are all unregistered can pass them. The hosts'
        # verdicts are their own ``state`` and ``enforcement_level``.
        "checks_ok": summary["failed"] == 0,
        "summary": summary,
        "checks": [{k: v for k, v in c.items() if k != "text"} for c in checks],
        "hosts": hosts,
        "enforcement_tiers": diag.tiers,
        "human_gate": diag.trust.as_dict() if diag.trust is not None else None,
        "state_modes": diag.modes.as_dict() if diag.modes is not None else None,
        "findings": [f.as_dict() for f in diag.findings],
    }


_ICON = {"ok": "✅", "missing_binary": "➖", "unregistered": "❌", "auth_unknown": "❔", "policy_gap": "⚠️ "}


def _print_hosts(diag: _Diagnosis) -> None:
    from aegis_cli import doctor as _doc

    ctx = diag.ctx
    how = "from .aegis/config.json" if ctx.selection == "config" else "every supported host; aegis init --host picks yours"
    print(f"\nHosts ({how}):")
    for row in diag.rows:
        reg, boot, budget = row["registration"], row["bootstrap"], row["budget"]
        label = " [experimental]" if row["experimental"] else ""
        print(f"  {_ICON[row['state']]} {row['display_name']} ({row['id']}){label}: {row['state']}")
        if row["experimental"]:
            print("      experimental documented by the vendor, not yet checked on a real install "
                  "(verified after 3 clean runs)")
        if row["surfaces"]:
            print(f"      surfaces     {', '.join(row['surfaces'])}")
        binary = row["binary"]
        where = binary["path"] or ("found only where doctor runs nothing (see below)" if binary["ignored"]
                                   else "not on PATH")
        print(f"      binary       {where}")
        if row["app"]:
            print(f"      app          {_doc._clean(ctx.label(Path(row['app'])), 4096)}")
        registered = {"registered": f"yes, {reg['scope']} scope", "absent": "no", "unknown": "unknown",
                      "unavailable": "not checked"}[reg["status"]]
        print(f"      registered   {registered} ({_doc._clean(reg['source'], 4096)})")
        if reg["command"]:
            exists = {True: "exists", False: "MISSING", None: "unknown"}[reg["command_exists"]]
            print(f"      command      {reg['command'][0]} ({exists})")
        ident = row["identity"]
        if reg["status"] == "registered":
            print(f"      identity     {ident['status']}" + (f" (AEGIS_CLIENT={ident['aegis_client']})"
                                                             if ident["aegis_client"] else ""))
        ws = {True: "registered", False: "not registered", None: "unknown"}[row["workspace_registered"]]
        print(f"      workspace    {ws} in ~/.aegis/workspaces.json")
        print(f"      bootstrap    {boot['file']}: {boot['status']}")
        if budget["bytes"] is not None:
            limit = (f"of {budget['budget_bytes']} bytes" if budget["budget_bytes"] is not None
                     else "bytes (no documented limit)")
            print(f"      budget       {budget['file']} {budget['bytes']} {limit}")
        print(f"      hooks        {_doc._clean(_hooks_line(row, ctx), 4096)}")
        print(f"      enforcement  {row['enforcement_level'].replace('_', ' ')}")
        for reason in row["reasons"]:
            if reason["code"] != "missing_binary":
                print(f"      → {reason['message']}")


def _hooks_line(row: Dict[str, Any], ctx: _Ctx) -> str:
    hooks, status = row["hooks"], row["hooks"]["status"]
    entries = hooks["entries"]
    if status == "registered":
        e = entries[0]
        text = (f"registered ({e['scope']} scope, {ctx.label(Path(e['path']))}); if {row['display_name']} runs it: "
                f"{hooks['tier']} [{hooks['evidence']}]")
        return text + (f"; {hooks['trust']}" if hooks["trust"] else "")
    if status == "absent":
        return f"not registered: aegis hook install --host {row['id']}"
    if status == "duplicate":
        return f"{len(entries)} Aegis entries ({', '.join(e['scope'] for e in entries)}): keep one"
    if status == "broken":
        return f"registered, but {entries[0]['aegis']} is missing or not executable (fails open)"
    if status == "modified":
        e = entries[0]
        return (f"registered but modified ({e['scope']} scope, {ctx.label(Path(e['path']))}): not the entry aegis "
                "hook install writes, so no tier is claimed")
    if status in ("unknown", "unavailable"):
        return f"{status}: {hooks['detail']}"
    return "none"


def _print_tiers(diag: _Diagnosis) -> None:
    from aegis_cli.hooks import registrar

    print("\nEnforcement tiers (AD-8):")
    for tier in diag.tiers:
        name, mechanism = _TIER_TEXT[tier["tier"]]
        hosts = ", ".join(tier["hosts"]) or "-"
        print(f"  {name:<14} {tier['status']:<12} {mechanism}")
        print(f"  {'':<14} {'':<12} hosts: {hosts}; {tier['detail']}")
        if tier["tier"] == "best_effort":
            print(f"  {'':<14} {'':<12} known gaps (guardrails, not a security boundary):")
            for gap in registrar.KNOWN_GAPS:
                print(f"  {'':<14} {'':<12}   - {gap}")


def _print_trust(diag: _Diagnosis) -> None:
    from aegis_cli import doctor as _doc

    from aegis_core import gitsafe

    print("")
    for line in diag.trust.text_lines():
        print(_doc._clean(line, 4096))
    if gitsafe.toplevel(diag.ctx.root) is not None:
        for line in _ci_workflow_lines(_ci_workflow(diag.ctx.root)):
            print("  " + _doc._clean(line, 4096))
    modes = diag.modes
    if modes is not None and modes.supported and modes.looser:
        print(f"  Shared state: {modes.looser} of {modes.checked} entries are looser than 0700/0600 "
              "(aegis migrate --apply tightens them).")


def _print_findings(findings: List[_Finding]) -> None:
    if not findings:
        return
    print("\nWarnings:")
    for finding in findings:
        icon = "ℹ️ " if finding.severity == "info" else "⚠️ "
        print(f"  {icon} {finding.message}")


def _print_plan(plan: List[_Change], home: Optional[Path]) -> None:
    from aegis_cli import doctor as _doc
    from aegis_core.workspace.layout import UserLayout

    where = f"{UserLayout(home).backups_dir}{os.sep}<UTC stamp>" if home else "the Aegis backups directory"
    print(f"\nPlanned changes (each file is backed up to {_doc._clean(where, 4096)} first):")
    for index, change in enumerate(plan, 1):
        print(f"  {index}. {_doc._clean(change.path, 4096)}: {_doc._clean('; '.join(change.describe), 4096)}")


def _print_results(results: List[Dict[str, Any]], backup: Optional[Path]) -> None:
    from aegis_cli import doctor as _doc

    print("")
    for item in results:
        icon = {"applied": "✅", "skipped": "⚠️ ", "failed": "❌"}[item["status"]]
        line = f"  {icon} {_doc._clean(item['path'], 4096)}: {_doc._clean('; '.join(item['changes']), 4096)}"
        if item["reason"]:
            line += f" ({item['status']}: {item['reason']})"
        print(line)
    if backup is not None:
        print(f"\nBackups: {_doc._clean(backup, 4096)}")


# ── --github: what the trust tiers need, and --apply ────────────────────────

_PLACEHOLDER_CHECK = "aegis"
# GitHub names a check after the job's name:, expanded, so only a literal name can be required.
_NO_AEGIS_JOB = ("no job in .github/workflows runs aegis check --ci under a literal name outside a matrix "
                 "(a templated name: or a matrix has no fixed check name to require)")


def _aegis_jobs(root: Path) -> List[str]:
    """The Aegis jobs of the working tree's workflows: what a ruleset written now should require."""
    found: List[str] = []
    for path in sorted(p for p in (root / ".github" / "workflows").glob("*") if p.suffix in (".yml", ".yaml")):
        with contextlib.suppress(OSError):
            text = path.read_text(encoding="utf-8", errors="replace")
            found += [job for job in human_gate.aegis_check_jobs(text) if job not in found]
    return found


def _ci_workflow(root: Path) -> Dict[str, Any]:
    """The workflow credit confirmation reads (user ``ci.workflow`` or the default) and whether it
    exists at HEAD. Local only: no network."""
    from aegis_core import config, credit, gitsafe

    named = config.user_ci_workflow(root)
    name = named or credit.DEFAULT_WORKFLOW
    top = gitsafe.toplevel(root)
    present = False
    if top is not None:
        with contextlib.suppress(gitsafe.GitError):
            present = gitsafe.read_blob(top, "HEAD", f".github/workflows/{name}") is not None
    return {"name": name, "source": "user-config" if named else "default", "present": present}


def _ci_workflow_lines(info: Dict[str, Any]) -> List[str]:
    where = f".github/workflows/{info['name']}"
    how = ("(ci.workflow)" if info["source"] == "user-config"
           else "(default; set ci.workflow in ~/.aegis/config.json to use another workflow)")
    lines = [f"CI credit: credit looks for runs of {where} {how}"]
    if not info["present"]:
        lines.append(f"⚠️  {where} is missing at HEAD, so no credit can be confirmed")
    return lines


def _github_plan(root: Path, report: Any) -> Dict[str, Any]:
    found = _aegis_jobs(root)
    contexts = found or [_PLACEHOLDER_CHECK]
    repo = report.evidence.get("repo") or {}
    owner = repo.get("full_name") or ""
    org = (repo.get("owner") or {}).get("type") == "Organization"
    handle = "@OWNER-OR-@org/team" if org else ("@" + owner.split("/")[0] if "/" in owner else "@OWNER")
    return {
        "required_checks": contexts,
        "required_checks_from_workflows": bool(found),
        "ruleset": {"A": human_gate.build_ruleset("A", contexts), "B": human_gate.build_ruleset("B", contexts)},
        "codeowners": human_gate.codeowners_lines(handle),
        "codeowners_note": ("an organization owns this repository, and GitHub ignores a bare @org owner: "
                            "name a team (@org/team) or people") if org else None,
        "signing_setup": human_gate.signers_setup(),
        "ci_workflow": _ci_workflow(root),
    }


def _print_github(plan: Dict[str, Any], report: Any) -> None:
    from aegis_cli import doctor as _doc

    print("aegis doctor --github: what the trust tiers need (read-only; nothing below has been applied)\n")
    for line in report.text_lines():
        print(_doc._clean(line, 4096))
    for line in _ci_workflow_lines(plan["ci_workflow"]):
        print(_doc._clean(line, 4096))
    checks = ", ".join(plan["required_checks"])
    if plan["required_checks_from_workflows"]:
        print(f"\nRequired status checks (the jobs in .github/workflows that run aegis check --ci): {checks}")
    else:
        print(f"\nRequired status checks: none found ({_NO_AEGIS_JOB}); the rulesets below name a placeholder "
              f"check {checks!r}, and --apply refuses until such a job exists.")
    print(f"Each check's source is pinned to GitHub Actions (integration_id {human_gate.GITHUB_ACTIONS_APP_ID}): a status "
          "posted by any other app or token does not satisfy it.")
    for tier, title in (("B", "solo, signed: pull request + required checks, approvals are `aegis approve` signatures"),
                        ("A", "separation of duties: one approving review + code-owner review + required checks")):
        print(f"\nRuleset, tier {tier} ({title}):")
        print(json.dumps(plan["ruleset"][tier], indent=2))
    print("\nCODEOWNERS lines (commit to the default branch; replace the owner with your reviewer):")
    if plan["codeowners_note"]:
        print(f"  ({plan['codeowners_note']})")
    for line in plan["codeowners"]:
        print(f"  {line}")
    print("\nSigning setup for tier B (nothing here is run for you):")
    for line in plan["signing_setup"]:
        print(f"  {line}")
    print("\nCreate the ruleset: aegis doctor --github --apply --tier A|B (asks at a terminal first).")


def _run_github(root: Path, use_json: bool, apply: bool, tier: Optional[str]) -> int:
    from aegis_cli import doctor as _doc

    report = human_gate.detect_tier(root)
    plan = _github_plan(root, report)
    status = "printed"
    result: Optional[Dict[str, Any]] = None
    if apply:
        if not _doc._stdin_is_tty():
            print("aegis doctor: --apply changes repository settings, so it only runs at a terminal with an "
                  "interactive y/N answer (--yes does not apply); nothing was changed.", file=sys.stderr)
            return 1
        if not plan["required_checks_from_workflows"]:
            print(f"aegis doctor: {_NO_AEGIS_JOB}; add the Aegis workflow (aegis init --ci) first. Nothing was changed.",
                  file=sys.stderr)
            return 1
        try:
            exists = human_gate.ruleset_exists(root)
        except human_gate.HumanGateError as exc:
            print(f"aegis doctor: cannot read the repository's rulesets: {_doc._clean(exc, 1000)}. Nothing was changed.",
                  file=sys.stderr)
            return 1
        if exists:
            print(f"aegis doctor: a ruleset named {human_gate.RULESET_NAME!r} already exists; edit it on GitHub "
                  "(--apply only ever creates). Nothing was changed.", file=sys.stderr)
            return 1
        body = plan["ruleset"][tier]
        print(json.dumps(body, indent=2))
        if not _doc._confirm(f"Create this ruleset on the default branch (tier {tier})? [y/N] "):
            print("No changes made.")
            return 1
        try:
            result = human_gate.create_ruleset(root, body)
        except human_gate.HumanGateError as exc:
            print(f"aegis doctor: {_doc._clean(exc, 1000)}", file=sys.stderr)
            return 1
        status = "applied"
        print(f"Created ruleset {human_gate.RULESET_NAME!r}. Re-run aegis doctor to see the tier.")
    if use_json:
        print(json.dumps({
            "schema": _doc.SCHEMA, "source": _doc.SOURCE, "aegis_version": _doc._aegis_version(),
            "checked_at": utc_stamp(), "scope": {"machine": "local", "workspace": str(root), "mode": "github"},
            "stale": False, "unknown": [], "status": status, "human_gate": report.as_dict(), "github": plan,
            "created": result,
        }, indent=2))
    elif not apply:
        _print_github(plan, report)
    return 0


# ── --release: was this commit green, by a signed attestation ───────────────

def _run_release(root: Path, sha: str, use_json: bool) -> int:
    from aegis_cli import doctor as _doc
    from aegis_core import release_verify

    report = release_verify.verify_release(root, sha)
    if use_json:
        print(json.dumps(report.as_dict(root), indent=2))
    else:
        for line in report.text_lines():
            print(_doc._clean(line, 4096))
    return 0 if report.verified else 1


def _run_drivers_only(root: Path, use_json: bool, fix: bool, yes: bool) -> int:
    from aegis_cli import doctor as _doc
    from aegis_cli.doctor_repair import _apply, _missing_ast_extensions, _plan

    results: List[Dict[str, Any]] = []
    backup: Optional[Path] = None
    declined = False
    text = io.StringIO()
    with contextlib.redirect_stdout(text) if use_json else contextlib.nullcontext():
        if not use_json:
            print(f"aegis doctor — AST driver health check ({_doc._clean(root, 4096)}):\n")
            print("Trust tier: not read in this mode (run aegis doctor)")  # --drivers stays local, no gh
        plan = _plan([], _missing_ast_extensions(root), root) if fix else []
        if plan:
            _print_plan(plan, _doc._home())
            if yes or _doc._confirm(f"Apply these {len(plan)} changes? [y/N] "):
                results, backup = _apply(plan, _doc._home(), root)
                _print_results(results, backup)
            else:
                declined = True
                print("No changes made.")
        (check,) = [c for c in _run_checks(root, fix_ast=False, only=("ast_drivers",))]
        if not use_json:
            print(check["text"], end="")
    failed = check["status"] != "pass" or declined or any(r["status"] != "applied" for r in results)
    if use_json:
        payload = {"schema": _doc.SCHEMA, "source": _doc.SOURCE, "aegis_version": _doc._aegis_version(),
                   "checked_at": utc_stamp(),
                   "scope": {"machine": "local", "workspace": str(root), "checks": ["ast_drivers"]},
                   "stale": False, "unknown": [], "checks_ok": check["status"] == "pass",
                   "checks": [{k: v for k, v in check.items() if k != "text"}]}
        if fix:
            payload["fixes"] = results
            payload["backup_dir"] = str(backup) if backup else None
        print(json.dumps(payload, indent=2))
    return 1 if failed else 0
