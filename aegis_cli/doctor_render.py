"""Output for ``aegis doctor``: the text report, the ``--json`` payload and the ``--github`` plan
(the ruleset JSON, CODEOWNERS lines and signing setup the trust tiers need). It prints what the
diagnosis found; it decides nothing and changes nothing."""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from aegis_cli.doctor_base import SCHEMA, SOURCE, Registered, _Ctx, _Finding, _clean
from aegis_cli.doctor_findings import _TIER_TEXT
from aegis_core import primitives
from aegis_core import codeowners, github_ruleset, human_gate

if TYPE_CHECKING:
    from aegis_cli.doctor_findings import _Diagnosis
    from aegis_cli.doctor_repair import _Change


# ── Output ──────────────────────────────────────────────────────────────────

def _registered_launchers(rows: List[Dict[str, Any]]) -> List[Registered]:
    """The command each host has registered, where doctor could read it."""
    return [(row["id"], row["registration"]["command"]) for row in rows
            if row["registration"]["status"] == "registered" and row["registration"]["command"]]


def _summary(checks: List[Dict[str, Any]], findings: List[_Finding]) -> Dict[str, int]:
    counted = [c for c in checks if c["status"] != "skip"]
    warn_checks = sum(c["status"] == "warn" for c in counted)
    return {"passed": sum(c["status"] == "pass" for c in counted),
            "warnings": warn_checks + sum(f.severity == "warning" for f in findings),
            "failed": sum(c["status"] == "fail" for c in counted), "total": len(counted)}


def _payload(diag: _Diagnosis, checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    ctx = diag.ctx
    summary = _summary(checks, diag.findings)
    unknown = [f"{r['id']}.{field}" for r in diag.rows for field in r["unknown"]]
    hosts = [{k: v for k, v in row.items() if k != "advisory"} for row in diag.rows]
    return {
        **primitives.envelope(SOURCE, {"machine": "local", "workspace": str(ctx.root), "workspace_governed": ctx.governed,
                  "hosts": [s.id for s in ctx.selected], "host_selection": ctx.selection}, schema=SCHEMA),
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
            print(f"      app          {_clean(ctx.label(Path(row['app'])), 4096)}")
        registered = {"registered": f"yes, {reg['scope']} scope", "absent": "no", "unknown": "unknown",
                      "unavailable": "not checked"}[reg["status"]]
        print(f"      registered   {registered} ({_clean(reg['source'], 4096)})")
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
        print(f"      hooks        {_clean(_hooks_line(row, ctx), 4096)}")
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
    from aegis_core import gitsafe

    print("")
    for line in diag.trust.text_lines():
        print(_clean(line, 4096))
    if gitsafe.toplevel(diag.ctx.root) is not None:
        for line in _ci_workflow_lines(_ci_workflow(diag.ctx.root)):
            print("  " + _clean(line, 4096))
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
    from aegis_core.workspace.layout import UserLayout

    where = f"{UserLayout(home).backups_dir}{os.sep}<UTC stamp>" if home else "the Aegis backups directory"
    print(f"\nPlanned changes (each file is backed up to {_clean(where, 4096)} first):")
    for index, change in enumerate(plan, 1):
        print(f"  {index}. {_clean(change.path, 4096)}: {_clean('; '.join(change.describe), 4096)}")


def _print_results(results: List[Dict[str, Any]], backup: Optional[Path]) -> None:
    print("")
    for item in results:
        icon = {"applied": "✅", "skipped": "⚠️ ", "failed": "❌"}[item["status"]]
        line = f"  {icon} {_clean(item['path'], 4096)}: {_clean('; '.join(item['changes']), 4096)}"
        if item["reason"]:
            line += f" ({item['status']}: {item['reason']})"
        print(line)
    if backup is not None:
        print(f"\nBackups: {_clean(backup, 4096)}")


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
        "ruleset": {"A": github_ruleset.build_ruleset("A", contexts), "B": github_ruleset.build_ruleset("B", contexts)},
        "codeowners": codeowners.codeowners_lines(handle),
        "codeowners_note": ("an organization owns this repository, and GitHub ignores a bare @org owner: "
                            "name a team (@org/team) or people") if org else None,
        "signing_setup": human_gate.signers_setup(),
        "ci_workflow": _ci_workflow(root),
    }


def _print_github(plan: Dict[str, Any], report: Any) -> None:
    print("aegis doctor --github: what the trust tiers need (read-only; nothing below has been applied)\n")
    for line in report.text_lines():
        print(_clean(line, 4096))
    for line in _ci_workflow_lines(plan["ci_workflow"]):
        print(_clean(line, 4096))
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
