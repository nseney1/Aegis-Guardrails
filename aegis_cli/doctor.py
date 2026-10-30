"""aegis doctor — workspace health, the host matrix and backed-up cleanup (host-matrix §3.9-3.10).

A read run changes nothing: it reads files, runs ``codex mcp get aegis --json`` (the only
host CLI it starts: Codex keeps its registrations in TOML, which stdlib-only Aegis does not
parse), and never syncs, checks or initializes. Its default report makes the trust tier's
read-only ``gh api`` GETs through the user's own ``gh`` (no ``gh`` means tier C).
``--github --apply`` can create a ruleset after confirmation; ``--release`` reads the default
branch, pull requests and reviews and runs ``gh attestation verify``. Other GitHub callers
are ``aegis sync`` and ``aegis rule promote|demote|archive`` for evidence, ``aegis sync --pr``
to open a pull request, and ``aegis check --ci`` for tier-A approval reviews on pull-request
events. Claude Code is read from ``~/.claude.json`` instead of ``claude mcp list``, which
starts every configured server.

Each host gets one state, the first of these that applies:

- ``missing_binary``: none of its binaries is in an absolute PATH entry outside the
  workspace (one found only inside it, or only through an empty or relative entry, is
  listed in ``binary.ignored`` with the reason ``binary_in_workspace`` or
  ``binary_on_relative_path``, and makes the host's installation unknown), and none of
  its desktop apps is installed (``app``: an IDE or desktop app puts nothing on PATH);
- ``unregistered``: its config has no ``aegis`` server, or the registered command is gone;
- ``auth_unknown``: doctor cannot confirm the host will load ``aegis`` or read its
  bootstrap (its CLI failed or timed out, its config cannot be parsed, the registration
  waits on an approval doctor cannot see, the registered command is a relative path or is
  found only where doctor does not look, a host that sends no workspace depends on an
  unreadable registry, or a CLAUDE.md-family file above the workspace, which doctor does
  not read, decides whether Claude Code reads AGENTS.md; the user's own
  ``~/.claude/CLAUDE.md``, which Claude Code loads as user memory, never does);
- ``policy_gap``: ``aegis`` loads, but this repository's policy does not fully reach the
  host (no or broken bootstrap, a CLAUDE.md, CLAUDE.local.md, .claude/CLAUDE.md or
  AGENTS.override.md shadowing AGENTS.md, a file the host truncates, an unregistered
  workspace for a host without roots, a disabled entry or one Claude Code turns off for
  the project in ``disabledMcpServers``, another host's identity, or an unsafe
  registration: a command that is not absolute, or that runs ``-m`` or ``-c`` without
  ``-I`` and so imports from the project directory the host starts it in);
- ``ok``: none of the above.

``--json`` prints one ``aegis.doctor/v1`` document: ``schema``, ``source``, ``aegis_version``,
``checked_at`` (UTC), ``scope``, ``stale`` and ``unknown`` (fields doctor could not
determine), ``checks_ok`` (no blocking check failed; it says nothing about the hosts),
``checks``, ``hosts`` (each with ``state``, ``reasons``, the matrix facts,
``enforcement_level`` and ``trust_tier``, the repository's human_gate tier), ``enforcement_tiers``,
``human_gate`` (the tier, the evidence it rests on and why it is not higher), ``state_modes``
(how many entries of the shared state are looser than 0700/0600; a count, never names),
``findings``, and with ``--fix`` the ``fixes`` it applied and its ``backup_dir``.

The trust tier (``aegis_core.human_gate``, v4.3 §2.2) is printed on every full report: A,
separation of duties; B, solo with signed approvals; C, self-attested; ``--drivers`` and
``--release`` print what they ran (``--drivers`` reads no tier, ``--release`` prints the tier it
read, or why it could not). ``--github`` prints what A and B
need: the exact ruleset JSON, the CODEOWNERS lines and the signing setup. ``--github --apply
--tier A|B`` creates that ruleset through ``gh api``, and only after an interactive y/N at a
terminal: ``--yes`` and ``--json`` never apply, and a ruleset of the same name is never
touched. ``--release SHA`` (aegis_core.release_verify) asks ``gh attestation verify`` whether the
CI verdict job attested that exact commit, pinning repository, workflow, digest and ref; a gh
that is missing or older than 2.93.0 prints ``UNVERIFIED (gh >= 2.93.0 required)`` and exits
non-zero, and at tiers B and C the report says the workflow is agent-editable and exits non-zero too
(the release claim needs tier A).

Each row lists the ``surfaces`` its config plane covers (CLI, IDE extension, desktop app).
A row whose host table entry is unverified (``verified_row`` false: Cursor, Copilot, Kiro,
Windsurf) is also ``experimental``, and the text names it so: its registration file is the
one the vendor documents, not yet checked on a real install.
Without ``hosts`` in .aegis/config.json the matrix is every verified host plus each
experimental one found on this machine (by binary, config path or app). A host found
here whose agent reads AGENTS.md, while AGENTS.md carries the bootstrap and the host has
no ``aegis`` registration, is the ``bootstrap_without_tools`` warning: the bootstrap
tells that agent to call tools it does not have (fix: ``aegis init --host <id>``).

``enforcement_level`` is the strongest tier known to be in force for the host here:
``local_floor``, ``advisory``, ``none`` (an ungoverned workspace, a host not installed,
or no route by which aegis or its bootstrap reaches the agent) or ``unknown`` (a fact
that decides it cannot be read, such as a host binary found only inside the workspace).
The home directory is never a governed workspace: its ``.aegis/`` is the user plane, so
run from there doctor checks no project rules, state or AST drivers.

Each host row also has ``hooks`` (v4.1 §2): the Aegis PreToolUse entries in the files the
host reads hooks from (user, project and, for Claude Code, local settings), whether each
runs an executable ``aegis``, and the tier such an entry gives with its evidence label
(Claude Code and Codex blocking are documented, DOC; Antigravity's exit-1 block is LIVE).
Presence never claims enforcement: no entry changes ``state`` or ``enforcement_level``, and
the best-effort tier is ``unknown`` while any is registered, since doctor cannot see a host
run it (nor Codex's /hooks approval). An entry that is not the one ``aegis hook install``
writes (matcher, type, command form with its host, or timeout) is ``modified`` and claims no
tier. Duplicates, modified entries, host files that do not parse, entries
whose ``aegis`` is gone and v3 leftovers (``soma hook ...`` or a removed ``aegis hook``
phase, in any hook file or the stale v3 Antigravity plugin) are findings; ``--fix`` removes
the leftovers with the ``remove_list_items`` action (or deletes a plugin file that holds
nothing else).
Strings taken from files or host output are printed without control sequences, and
doctor starts only host CLIs found in absolute PATH entries outside the workspace
(aegis_core.pathlookup). It never starts the MCP server or a registered command: the MCP
launcher check compares what each host registered with what ``aegis init --host`` would
register from this install.

``--fix`` changes only what a finding reported as fixable, after confirmation (``--yes``
skips it). Configuration files are first copied to ``~/.aegis/backups/<UTC stamp>/`` with a manifest;
writes are atomic; a symlink, a hard link or a file that changed since the check is never
written. Generated Go driver cache entries are rebuilt, without a binary backup.
It never edits shell rc files (D17) and never writes TOML.
"""
from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone  # noqa: F401 - names the 4.3.3 public-names pin holds
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aegis_cli import doctor_base as _base
from aegis_cli import doctor_findings as _findings
from aegis_cli import doctor_render as _render
from aegis_cli import doctor_repair as _repair
from aegis_cli.base import AegisCommand, CommandCategory
from aegis_cli.formatters.text import render_release
from aegis_cli.doctor_base import (
    SCHEMA, SERVER, SOURCE, Registered, _Ctx, _HookStatus, _claude_config, _claude_project_keys, _clean,
    _entry_facts, _home, _host_json_path, _is_home, _names, _registration, _server_entry, _setup_fix,
)
from aegis_core import github_ruleset, human_gate, primitives
from aegis_core.pathlookup import INSIDE_FENCE, Hit
from aegis_core.primitives import is_within

__all__ = ["run_doctor", "DoctorCommand", "probe_mcp_launcher", "SCHEMA"]

EXIT_USAGE = 2


def _check_python_version() -> bool:
    """Check Python >= 3.9."""
    ok = sys.version_info >= (3, 9)
    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if ok:
        print(f"  ✅ Python {ver} (≥ 3.9)")
    else:
        print(f"  ❌ Python {ver} (requires ≥ 3.9)")
    return ok


def _check_zero_dependencies() -> bool:
    """Verify that the frontmatter engine is operational with zero dependencies."""
    from aegis_core.yaml_engine.frontmatter import parse_frontmatter

    test_fm = "---\nid: test\ntype: invariant\n---\n"
    ok = parse_frontmatter(test_fm) == {"id": "test", "type": "invariant"}
    if ok:
        print("  ✅ zero-dependency runtime operational (pure standard library)")
    else:
        print("  ❌ frontmatter engine validation failed")
    return ok


def _check_rules(project_root: Path) -> bool:
    """The workspace serves at least one rule and every rule file loads."""
    from aegis_core.rules import load_rules
    from aegis_core.workspace.layout import UserLayout, WorkspaceLayout

    if _is_home(project_root):
        print(f"  ❌ Rules: {project_root} is your home directory, never a workspace: "
              f"{UserLayout(Path(project_root)).rules_dir} is your user rule layer, which every workspace adds to its own")
        print("    Fix: run aegis doctor inside a repository.")
        return False
    rules_dir = WorkspaceLayout(Path(project_root)).rules_dir
    if not rules_dir.is_dir():
        print(f"  ❌ No rules directory ({rules_dir})")
        print("    " + _setup_fix(project_root, "install starter rules"))
        return False
    try:
        ruleset = load_rules(project_root)
    except Exception as exc:  # an unreadable tree fails closed, here as in scan
        print(f"  ❌ Rules cannot be loaded from {rules_dir}: {exc}")
        return False
    if ruleset.errors:
        first = ruleset.errors[0]
        print(f"  ❌ {len(ruleset.errors)} rule file(s) cannot be served, e.g. {first.path}: {first.error}")
        print("    Fix: correct them; 'aegis check' fails closed until they load.")
        return False
    if not ruleset.served:
        print(f"  ❌ No rules are served from {rules_dir}")
        print("    " + _setup_fix(project_root, "install starter rules"))
        return False
    print(f"  ✅ Rules: {len(ruleset.served)} served from {rules_dir}")
    return True


def _check_state_dir(project_root: Path) -> Optional[bool]:
    """Check .aegis/state/ (ledger, lock) exists and is writable, or can be created (read-only check)."""
    from aegis_core.workspace.layout import WorkspaceLayout

    root = Path(project_root).resolve()
    if _is_home(root):
        print(f"  ℹ️  State directory: not checked: {root} is your home directory, whose .aegis/ is your "
              "user layer; a workspace keeps its state in its own .aegis/state")
        return None
    state = WorkspaceLayout(root).state_dir
    if state.is_dir():
        if os.access(str(state), os.W_OK):
            print(f"  ✅ State directory writable ({state})")
            return True
        print(f"  ❌ State directory not writable ({state})")
        print(f"    Fix: Verify write permissions on {state}.")
        return False
    parent = state.parent
    if parent.is_dir() and os.access(str(parent), os.W_OK):
        print(f"  ✅ State directory can be created ({state})")
        return True
    print(f"  ❌ State directory does not exist ({state})")
    print("    " + _setup_fix(root, "create workspace directories"))
    return False


def _check_cli_resolvable(project_root: Path) -> bool:
    """Check that the 'aegis' CLI the bootstrap sends agents to is on PATH.

    Only absolute PATH entries count (aegis_core.pathlookup): an empty or relative entry
    resolves against the directory a shell starts in, where a cloned repository can plant
    an ``aegis``. Doctor runs nothing here, so an absolute entry inside the workspace (a
    project virtualenv the user put on PATH) counts, and the line says where it is.
    """
    root = Path(project_root).resolve()
    path = _base.which("aegis")
    if path:
        inside = _base.which("aegis", outside=root) != path
        print(f"  ✅ aegis CLI resolvable ({path}{', inside the workspace' if inside else ''})")
        return True
    print("  ❌ aegis CLI not found on PATH")
    for hit in _base.only_skipped("aegis", base=root):
        print(f"    {hit.path} is reached only through the relative PATH entry {hit.entry!r}, which "
              "resolves against the current directory: not counted")
    from aegis_cli.pathcheck import build_hint
    hint = build_hint()
    if hint:
        print("\n".join("    " + line for line in hint.splitlines()))
    return False


# ── Programs doctor starts ───────────────────────────────────────────────────

def _child_env() -> Dict[str, str]:
    """The environment of a program doctor starts.

    On Windows a ``.cmd`` or ``.bat`` shim (npm's ``codex.cmd``) runs under cmd.exe,
    which looks for the programs it calls (``node``) in the current directory first:
    the repository, for the codex probe. This variable turns that search off.
    """
    env = dict(os.environ)
    if sys.platform == "win32":
        env["NoDefaultCurrentDirectoryInExePath"] = "1"
    return env


# ── MCP launcher ─────────────────────────────────────────────────────────────

def _same_command(a: Sequence[str], b: Sequence[str]) -> bool:
    if len(a) != len(b) or not a:
        return False
    return os.path.normcase(a[0]) == os.path.normcase(b[0]) and list(a[1:]) == list(b[1:])


def _launcher_problem(argv: Sequence[str], current: Sequence[str]) -> Optional[str]:
    """Why a registered launcher is wrong, or None. Nothing is run."""
    from aegis_cli.install_hosts import MCP_RUNNER, display_command, launch_risk

    shown = display_command(argv) if argv else "an empty command"
    risk = launch_risk(argv)
    if risk:
        return f"starts `{shown}`, an unsafe registration: {risk}"
    if not (os.path.isfile(argv[0]) and (os.name == "nt" or os.access(argv[0], os.X_OK))):
        return f"starts {argv[0]}, which does not exist"
    if len(argv) == 5 and argv[1:4] == ["-I", "-c", MCP_RUNNER] \
            and not os.path.isfile(os.path.join(argv[4], "aegis_mcp", "server.py")):
        return f"starts {argv[0]} with no aegis_mcp in {argv[4]}: that install is gone"
    if not _same_command(argv, current):
        return f"starts {shown}, not this install's {display_command(current)}"
    return None


def probe_mcp_launcher(path_env: Optional[str] = None, registered: Sequence[Registered] = (),
                       scripts_dirs: Optional[Sequence[str]] = None) -> Tuple[List[str], List[Tuple[str, str]]]:
    """The command `aegis init --host` registers from this install (install_hosts.mcp_command
    under ``path_env``), and each ``registered`` host whose command is unsafe (launch_risk),
    gone, or another install's, with the reason.

    Doctor runs neither: the registered argv comes from a host's config file, and
    starting the server would prove nothing a host does not do at its next session.
    """
    from aegis_cli.install_hosts import mcp_command

    # None reaches mcp_command as it does from init: $PATH, or the OS default path when unset.
    current = mcp_command(path_env, scripts_dirs)
    problems = []
    for host_id, argv in registered:
        why = _launcher_problem(list(argv), current)
        if why:
            problems.append((host_id, why))
    return current, problems


def _where(hit: Hit, fence: Any) -> str:
    """Where a program ``only_skipped`` passed over is, and why it was passed over;
    ``fence`` names what it was inside."""
    if hit.reason == INSIDE_FENCE:
        return f"{hit.path}, inside {fence}"
    return f"{hit.path}, through the relative PATH entry {hit.entry!r}"


def _check_mcp_launcher(path_env: Optional[str] = None, workspace: Optional[Path] = None,
                        registered: Sequence[Registered] = (),
                        scripts_dirs: Optional[Sequence[str]] = None) -> bool:
    """Advisory: the MCP launcher this install registers, and whether each host's matches."""
    from aegis_cli.install_hosts import MCP_SCRIPT, display_command

    current, problems = probe_mcp_launcher(path_env, registered, scripts_dirs)
    where = ""
    if len(current) == 1 and workspace is not None:
        # The script's directory, not the script: a version manager's link resolves elsewhere.
        if is_within(Path(current[0]).parent, workspace, unresolvable=True):  # the cautious label
            where = ", inside the workspace"
    if len(current) == 1:
        print(f"  {'⚠️ ' if problems else '✅'} MCP launcher: {current[0]}{where} (what aegis init --host registers)")
    else:
        print(f"  {'⚠️ ' if problems else '✅'} MCP launcher: no {MCP_SCRIPT} script found, so aegis init --host "
              f"registers this interpreter in isolated mode: {display_command(current)}")
    for host_id, why in problems:
        print(f"      {host_id} {why}. Fix: re-run aegis init --host {host_id}")
    ok_hosts = [h for h, _ in registered if h not in {p for p, _ in problems}]
    if ok_hosts:
        print(f"      registered for {', '.join(ok_hosts)}")
    return not problems


def _check_ast_drivers(project_root: Path) -> Optional[bool]:
    """Check the AST drivers this workspace uses and that their executables resolve.

    A repository opts in to a packaged driver in .aegis/config.json; driver commands
    come only from ~/.aegis/config.json (D10). The check only reports: ``--fix``
    provisions the missing packaged drivers through its backed-up plan.
    """
    import shlex
    from aegis_core.ast.runner import ASTDriverRunner, resolve_driver_executable
    from aegis_core.skills.slots import SlotResolutionError

    ws_root = Path(project_root)
    if _is_home(ws_root):
        # Never walk the home directory for sources: its .aegis/ is the user scope.
        print(f"  ℹ️  AST drivers: not checked: {ws_root} is your home directory, whose .aegis/ is your user layer")
        return None
    try:
        ast_drivers, missing = _findings._ast_driver_state(ws_root)
    except SlotResolutionError as exc:
        print(f"  ❌ AST drivers: {exc}")
        return False
    if missing:
        reasons = ', '.join(f'no_driver:{ext}' for ext in missing)
        print(f"  ⚠️  AST drivers: unconfigured driver for detected source extension(s): {', '.join(missing)}. "
              f"Run 'aegis doctor --fix' to provision packaged drivers; other languages need a user-scope driver ({reasons}).")
        return False

    if not ast_drivers:
        print("  ✅ AST drivers: native Python stdlib (in-process)")
        return True

    all_resolvable = True
    registry = ASTDriverRunner().registry
    for ext, cmd in sorted(ast_drivers.items()):
        try:
            plan = registry.plan_driver(ext, workspace_root=ws_root)
        except Exception as exc:  # like the card, keep a failed plan visible in the diagnostic
            print(f"  ⚠️  AST driver ({ext}): {type(exc).__name__}: {exc}")
            all_resolvable = False
            continue
        if plan is not None and (plan.in_process_js or plan.in_process_rust):
            print(f"  ✅ AST driver ({ext}): {plan.label}")
            continue
        if plan is not None and plan.packaged_go:
            from aegis_core.ast.gobuild import GoDriverUnavailableError, inspect_go_driver

            try:
                status = inspect_go_driver(ws_root)
                if status.cache_hit:
                    print(f"  ✅ AST driver ({ext}): {status.goversion} ({status.compiler}); cache hit ({status.binary})")
                else:
                    print(f"  ⚠️  AST driver ({ext}): {status.goversion}; Go driver cache is cold; "
                          "run aegis doctor --drivers --fix")
                    all_resolvable = False
            except GoDriverUnavailableError as exc:
                print(f"  ⚠️  AST driver ({ext}): {exc}")
                all_resolvable = False
            continue
        try:
            parts = (
                shlex.split(cmd)
                if os.name != "nt"
                else [p.strip('"') for p in shlex.split(cmd, posix=False)]
            )
        except ValueError:
            if plan is None or not plan.unavailable:
                raise
            print(f"  ⚠️  AST driver ({ext}): {plan.unavailable}")
            all_resolvable = False
            continue
        if not parts:
            continue
        bin_name = parts[0]
        # As the driver runs: absolute PATH entries outside the workspace, a relative path
        # joined to the workspace root (aegis_core.ast.runner).
        found = resolve_driver_executable(bin_name, workspace=ws_root)
        hits = [] if found else _base.only_skipped(bin_name, outside=ws_root, base=ws_root)
        if found and plan is not None and plan.unavailable:
            print(f"  ⚠️  AST driver ({ext}): {plan.unavailable}")
            all_resolvable = False
        elif found:
            print(f"  ✅ AST driver ({ext}): {bin_name} resolvable ({found})")
        elif hits:
            print(f"  ⚠️  AST driver ({ext}): executable '{bin_name}' is found only at "
                  f"{_where(hits[0], 'the workspace')}, where aegis never runs it")
            all_resolvable = False
        else:
            print(f"  ⚠️  AST driver ({ext}): executable '{bin_name}' not found on PATH")
            all_resolvable = False

    return all_resolvable


# ── Pre-commit hook ──────────────────────────────────────────────────────────

def _hook_status(root: Path) -> _HookStatus:
    """The run's one hook_status reading: (status, None), or (None, the exception it raised).
    The local floor reports a reading that raised as unknown; the pre-commit check raises it."""
    from aegis_cli.hooks import management

    try:
        return management.hook_status(root), None
    except Exception as exc:
        return None, exc


def _check_precommit_hook(project_root: Path, hook: Optional[_HookStatus] = None) -> bool | None:
    """True for a current, runnable hook block; False for an older one or one whose
    pinned interpreter or aegis path is gone; None if absent. ``hook`` is the run's
    reading (_hook_status), taken here when none is given.

    Blocks before the current format resolved aegis through PATH, $VIRTUAL_ENV
    or the repository's .venv, so repository code could run on commit.
    """
    st, error = _hook_status(project_root) if hook is None else hook
    if error is not None:
        raise error
    if not st["managed_by_aegis"]:
        return None
    if st["status"] == "installed":
        gone = [p["path"] for p in (st["interpreter"], st["aegis_path"]) if p and not p["exists"]]
        if gone:
            print(f"  ❌ Pre-commit hook ({st['hook_file']}) pins {gone[0]}, which no longer exists,\n"
                  "      so every commit fails closed. Re-run `aegis hook install` to re-pin it.")
            return False
        if st.get("reachable", True) is False:
            print(f"  ❌ Pre-commit hook ({st['hook_file']}) is installed but never runs: "
                  f"{st.get('unreachable_reason') or 'git does not reach the Aegis block'}.\n"
                  "      Run `aegis hook status` for the fix.")
            return False
        print(f"  ✅ Pre-commit hook is current ({st['hook_file']})")
        return True
    print(f"  ❌ Pre-commit hook uses an old block (format {st['format_version']}, {st['hook_file']}).\n"
          "      It can run an aegis found on PATH or in the repository instead of\n"
          "      the one you installed. Re-run `aegis hook install` to refresh it.")
    return False


# ── Host plane: registration probes ─────────────────────────────────────────

# Codex's own answer when no server has that name. Any other failure leaves the
# registration unknown: a CLI that crashed has not said "absent".
_CODEX_ABSENT = re.compile(r"no mcp server named\s+['\"]?aegis['\"]?\s+found", re.IGNORECASE)
_PROBE_TIMEOUT = 10.0


def _run_host_cli(argv: Sequence[str], cwd: str, timeout: float) -> "subprocess.CompletedProcess[str]":
    """The one place doctor starts a host CLI: an argv (no shell), no stdin, bounded in time."""
    return subprocess.run(list(argv), cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, errors="replace", timeout=timeout, env=_child_env())


def _probe_codex(spec: Any, binary: Optional[str], ctx: _Ctx) -> Dict[str, Any]:
    source = "codex mcp get aegis --json"
    if binary is None:
        detail = ("the only codex on PATH is inside the workspace or behind a relative PATH entry, "
                  "and doctor does not run it" if ctx.passed_over("codex") else "codex is not on PATH")
        return _registration("unavailable", source, detail=detail)
    try:
        # From the workspace: Codex answers with the config it would use here (user
        # config plus a trusted project's own).
        proc = _run_host_cli([binary, "mcp", "get", SERVER, "--json"], cwd=str(ctx.root), timeout=_PROBE_TIMEOUT)
    except subprocess.TimeoutExpired:
        return _registration("unknown", source, detail=f"codex did not answer within {_PROBE_TIMEOUT:g}s")
    except OSError as exc:
        return _registration("unknown", source, detail=f"codex could not be started ({exc.strerror or exc})")
    if proc.returncode != 0:
        said = ((proc.stderr or "") + (proc.stdout or "")).strip()
        if _CODEX_ABSENT.search(said):
            return _registration("absent", source)
        first = _clean(said.splitlines()[0], 200) if said else "no output"
        return _registration("unknown", source, detail=f"codex exited {proc.returncode}: {first}")
    try:
        data = json.loads(proc.stdout)
    except (ValueError, RecursionError):  # RecursionError: nested past the parser's depth
        return _registration("unknown", source, detail="codex printed no JSON")
    if not isinstance(data, dict) or data.get("name") != SERVER:
        return _registration("unknown", source, detail="codex answered about another server")
    transport = data.get("transport") if isinstance(data.get("transport"), dict) else {}
    facts = _entry_facts(transport, ctx)
    if isinstance(data.get("enabled"), bool):
        facts["enabled"] = data["enabled"]
    return _registration("registered", source, scope="effective", **facts)


def _probe_claude(spec: Any, binary: Optional[str], ctx: _Ctx) -> Dict[str, Any]:
    path = _claude_config(ctx)
    if path is None:
        return _registration("unknown", "~/.claude.json", detail="no home directory")
    source = ctx.label(path)
    cfg = ctx.file(path, as_json=True)
    if cfg.error:
        return _registration("unknown", source, detail=f"{source} {cfg.error}")
    data = cfg.data or {}
    projects = data.get("projects") if isinstance(data.get("projects"), dict) else {}
    key = next((k for k in _claude_project_keys(ctx) if isinstance(projects.get(k), dict)), None)
    project = projects[key] if key is not None else {}

    def facts_of(entry: Any) -> Dict[str, Any]:
        facts = _entry_facts(entry, ctx)
        # Claude Code turns off any server this project lists, whatever its scope
        # (user, local or .mcp.json): "turned off; turn it on in /mcp".
        if SERVER in _names(project.get("disabledMcpServers")):
            facts["enabled"] = False
            facts["detail"] = (f"Claude Code turns aegis off in this project: {source} lists it in "
                               f"projects[{key}].disabledMcpServers; turn it on in Claude Code's /mcp")
        return facts

    local = _server_entry(project)
    user = _server_entry(data)
    if local is not None:
        return _registration("registered", source, scope="local", **facts_of(local))
    if user is not None:
        return _registration("registered", source, scope="user", **facts_of(user))
    dot_mcp = ctx.file(ctx.root / ".mcp.json", as_json=True)
    shared = _server_entry(dot_mcp.data) if not dot_mcp.error else None
    if shared is not None:
        # A project .mcp.json server runs only after the user approves it; that answer
        # lives in settings files doctor does not read, unless .claude.json records it.
        approved = _names(project.get("enabledMcpjsonServers"))
        denied = _names(project.get("disabledMcpjsonServers"))
        approval = ("approved" if SERVER in approved or project.get("enableAllProjectMcpServers") is True
                    else "denied" if SERVER in denied else "unknown")
        facts = facts_of(shared)
        if approval == "denied":
            facts["enabled"] = False
        return _registration("registered", ctx.label(ctx.root / ".mcp.json"), scope="project",
                             approval=approval, **facts)
    return _registration("absent", source)


def _probe_json_host(spec: Any, binary: Optional[str], ctx: _Ctx) -> Dict[str, Any]:
    path = _host_json_path(spec, ctx)
    if path is None:
        return _registration("unknown", spec.registration.path, detail="no home directory")
    source = ctx.label(path)
    cfg = ctx.file(path, as_json=True)
    if cfg.error:
        return _registration("unknown", source, detail=f"{source} {cfg.error}")
    servers = (cfg.data or {}).get(spec.registration.key)
    entry = servers.get(SERVER) if isinstance(servers, dict) else None
    if entry is None:
        return _registration("absent", source)
    return _registration("registered", source, scope="user", **_entry_facts(entry, ctx))


_PROBES: Dict[str, Callable[[Any, Optional[str], _Ctx], Dict[str, Any]]] = {
    "codex-cli": _probe_codex,
    "claude-code": _probe_claude,
}


def _probe(spec: Any, binary: Optional[str], ctx: _Ctx) -> Dict[str, Any]:
    if spec.id in _PROBES:
        return _PROBES[spec.id](spec, binary, ctx)
    if spec.registration is not None and spec.registration.kind == "json_file":
        return _probe_json_host(spec, binary, ctx)
    return _registration("unavailable", "-", detail=f"doctor has no check for {spec.display_name}")


# ── Checks and modes ────────────────────────────────────────────────────────

_CHECKS: Tuple[Tuple[str, bool], ...] = (
    # (id, failing it fails the run); advisory checks only warn.
    ("python_version", True), ("zero_dependencies", True), ("rules", True), ("state_dir", True),
    ("cli_on_path", True), ("precommit_hook", True), ("ast_drivers", False), ("mcp_launcher", False),
)


def _run_checks(root: Path, only: Optional[Sequence[str]] = None, registered: Sequence[Registered] = (),
                hook: Optional[_HookStatus] = None) -> List[Dict[str, Any]]:
    calls: Dict[str, Callable[[], Optional[bool]]] = {
        "python_version": _check_python_version,
        "zero_dependencies": _check_zero_dependencies,
        "rules": lambda: _check_rules(root),
        "state_dir": lambda: _check_state_dir(root),
        "cli_on_path": lambda: _check_cli_resolvable(root),
        "precommit_hook": lambda: _check_precommit_hook(root, hook),
        "ast_drivers": lambda: _check_ast_drivers(root),
        "mcp_launcher": lambda: _check_mcp_launcher(workspace=root, registered=registered),
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
        text = "".join(_clean(line, 4096) + "\n" for line in buf.getvalue().splitlines())
        out.append({"id": check_id, "status": status, "text": text,
                    "detail": [line.strip() for line in text.splitlines() if line.strip()]})
    return out


def _run_github(root: Path, use_json: bool, apply: bool, tier: Optional[str]) -> int:
    report = human_gate.detect_tier(root)
    plan = _render._github_plan(root, report)
    if apply:
        if not _base._stdin_is_tty():
            print("aegis doctor: --apply changes repository settings, so it only runs at a terminal with an "
                  "interactive y/N answer (--yes does not apply); nothing was changed.", file=sys.stderr)
            return 1
        if not plan["required_checks_from_workflows"]:
            print(f"aegis doctor: {_render._NO_AEGIS_JOB}; add the Aegis workflow (aegis init --ci) first. Nothing was changed.",
                  file=sys.stderr)
            return 1
        try:
            exists = github_ruleset.ruleset_exists(root)
        except human_gate.HumanGateError as exc:
            print(f"aegis doctor: cannot read the repository's rulesets: {_clean(exc, 1000)}. Nothing was changed.",
                  file=sys.stderr)
            return 1
        if exists:
            print(f"aegis doctor: a ruleset named {github_ruleset.RULESET_NAME!r} already exists; edit it on GitHub "
                  "(--apply only ever creates). Nothing was changed.", file=sys.stderr)
            return 1
        body = plan["ruleset"][tier]
        print(json.dumps(body, indent=2))
        if not _base._confirm(f"Create this ruleset on the default branch (tier {tier})? [y/N] "):
            print("No changes made.")
            return 1
        try:
            github_ruleset.create_ruleset(root, body)
        except human_gate.HumanGateError as exc:
            print(f"aegis doctor: {_clean(exc, 1000)}", file=sys.stderr)
            return 1
        print(f"Created ruleset {github_ruleset.RULESET_NAME!r}. Re-run aegis doctor to see the tier.")
    if use_json:  # run_doctor refuses --apply with --json, so this document only prints the plan
        print(json.dumps({
            **primitives.envelope(SOURCE, {"machine": "local", "workspace": str(root), "mode": "github"}, schema=SCHEMA),
            "stale": False, "unknown": [], "status": "printed", "human_gate": report.as_dict(), "github": plan,
            "created": None,
        }, indent=2))
    elif not apply:
        _render._print_github(plan, report)
    return 0


# ── --release: was this commit green, by a signed attestation ───────────────

def _run_release(root: Path, sha: str, use_json: bool) -> int:
    from aegis_core import release_verify

    report = release_verify.verify_release(root, sha)
    if use_json:
        print(json.dumps(report.as_dict(root), indent=2))
    else:
        for line in render_release(report.as_dict(root)):
            print(_clean(line, 4096))
    return 0 if report.verified else 1


def _run_drivers_only(root: Path, use_json: bool, fix: bool, yes: bool) -> int:
    results: List[Dict[str, Any]] = []
    backup: Optional[Path] = None
    declined = False
    text = io.StringIO()
    with contextlib.redirect_stdout(text) if use_json else contextlib.nullcontext():
        if not use_json:
            print(f"aegis doctor — AST driver health check ({_clean(root, 4096)}):\n")
            print("Trust tier: not read in this mode (run aegis doctor)")  # --drivers stays local, no gh
        plan = _repair._plan([], _findings._missing_ast_extensions(root), root) if fix else []
        if plan:
            _render._print_plan(plan, _home())
            if yes or _base._confirm(f"Apply these {len(plan)} changes? [y/N] "):
                results, backup = _repair._apply(plan, _home(), root)
                _render._print_results(results, backup)
            else:
                declined = True
                print("No changes made.")
        (check,) = [c for c in _run_checks(root, only=("ast_drivers",))]
        if not use_json:
            print(check["text"], end="")
    failed = check["status"] != "pass" or declined or any(r["status"] != "applied" for r in results)
    if use_json:
        payload = {**primitives.envelope(SOURCE, {"machine": "local", "workspace": str(root), "checks": ["ast_drivers"]}, schema=SCHEMA),
                   "stale": False, "unknown": [], "checks_ok": check["status"] == "pass",
                   "checks": [{k: v for k, v in check.items() if k != "text"}]}
        if fix:
            payload["fixes"] = results
            payload["backup_dir"] = str(backup) if backup else None
        print(json.dumps(payload, indent=2))
    return 1 if failed else 0


# ── Entry point ─────────────────────────────────────────────────────────────

def _usage_error(message: str) -> int:
    print(f"aegis doctor: {message}", file=sys.stderr)
    return EXIT_USAGE


def _resolve_root(args: argparse.Namespace) -> Path:
    from aegis_core.workspace.base import Workspace

    ws = getattr(args, "ws", None)
    if ws is not None:
        return Path(ws.root)
    raw = getattr(args, "workspace", None) or getattr(args, "_project_root", None)
    return Path(Workspace.resolve(raw).root)


def run_doctor(args: argparse.Namespace) -> int:
    """Run the health checks and the host matrix; with --fix, repair what they reported.

    Exit 0 when no blocking check failed (and every planned fix was applied), 1 otherwise,
    2 for a usage error.
    """
    use_json = bool(getattr(args, "json", False))
    fix = bool(getattr(args, "fix", False))
    yes = bool(getattr(args, "yes", False))
    if yes and bool(getattr(args, "apply", False)):
        return _usage_error("--yes does not apply to --github --apply: changing repository settings always asks "
                            "at a terminal")
    if yes and not fix:
        return _usage_error("--yes only applies to --fix")
    if use_json and fix and not yes:
        return _usage_error("--json --fix needs --yes (there is no prompt in JSON mode)")
    github = bool(getattr(args, "github", False))
    apply = bool(getattr(args, "apply", False))
    tier = getattr(args, "tier", None)
    if apply and not github:
        return _usage_error("--apply only applies to --github")
    if tier and not apply:
        return _usage_error("--tier only applies to --github --apply")
    if github and (fix or getattr(args, "drivers", False)):
        return _usage_error("--github cannot be combined with --fix or --drivers")
    if apply and use_json:
        return _usage_error("--github --apply asks at a terminal, so it cannot run with --json")
    if apply and tier not in ("A", "B"):
        return _usage_error("--github --apply needs --tier A or --tier B")
    release = getattr(args, "release", None)
    if release is not None:
        others = [flag for flag, given in (("--fix", fix), ("--yes", yes), ("--github", github),
                                           ("--drivers", bool(getattr(args, "drivers", False)))) if given]
        if others:
            return _usage_error(f"--release does not combine with {', '.join(others)}: it only reads")
        if not str(release).strip():
            return _usage_error("--release needs a commit")
    root = _resolve_root(args)

    if release is not None:
        return _run_release(root, str(release).strip(), use_json)

    if github:
        return _run_github(root, use_json, apply, tier)

    if getattr(args, "drivers", False):
        return _run_drivers_only(root, use_json, fix, yes)

    hook = _hook_status(root)
    diag = _findings._diagnose(root, _probe, hook)
    plan = _repair._plan(diag.findings, _findings._missing_ast_extensions(root), root) if fix else []
    results: List[Dict[str, Any]] = []
    backup: Optional[Path] = None
    declined = False
    text = io.StringIO()
    with contextlib.redirect_stdout(text) if use_json else contextlib.nullcontext():
        if not use_json:
            print(f"aegis doctor — running health checks ({_clean(root, 4096)}):\n")
        checks = _run_checks(root, registered=_render._registered_launchers(diag.rows), hook=hook)
        if not use_json:
            for check in checks:
                print(check["text"], end="")
            _render._print_hosts(diag)
            _render._print_tiers(diag)
            _render._print_trust(diag)
            from aegis_core.sync import base_fetch

            fetched = base_fetch(root)[0]  # Aegis never fetches; this says how old BASE may be
            if fetched:
                print(f"  {fetched}")
            _render._print_findings(diag.findings)
        if fix:
            if not plan:
                print("\nNothing to fix.")
            else:
                _render._print_plan(plan, diag.ctx.home)
                if yes or _base._confirm(f"Apply these {len(plan)} changes? [y/N] "):
                    results, backup = _repair._apply(plan, diag.ctx.home, root)
                    _render._print_results(results, backup)
                else:
                    declined = True
                    print("No changes made.")

    payload = _render._payload(diag, checks)
    failed = payload["summary"]["failed"] > 0 or declined or any(r["status"] != "applied" for r in results)
    if use_json:
        if fix:
            payload["fixes"] = results
            payload["backup_dir"] = str(backup) if backup else None
        print(json.dumps(payload, indent=2))
        return 1 if failed else 0

    s = payload["summary"]
    warn_label = "warning" if s["warnings"] == 1 else "warnings"
    print(f"\n{s['passed']}/{s['total']} checks passed ({s['passed']} passed, {s['warnings']} {warn_label}, "
          f"{s['failed']} failed).")
    return 1 if failed else 0


class DoctorCommand(AegisCommand):
    """Command for system health and governance audit."""

    name = "doctor"
    category = CommandCategory.SETUP
    help = "System health and governance audit"
    description = (
        "Read-only health checks, the host matrix (binary, registration, identity, workspace, "
        "bootstrap, budget per host) and the enforcement tiers in force here. --fix changes only "
        "what doctor reported (stale v3 and misplaced MCP entries, v3 hook entries, legacy rule "
        "blocks, unedited v3 rule copies, missing packaged AST drivers and Go cache entries), after confirmation. "
        "Configuration files are backed up to ~/.aegis/backups/<UTC stamp>/ first; generated cache entries are rebuilt."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--fix",
            action="store_true",
            help="Repair after confirmation; configuration files are backed up and generated Go caches are rebuilt",
        )
        parser.add_argument(
            "--yes",
            action="store_true",
            help="With --fix: apply without asking (required with --json or without a terminal)",
        )
        parser.add_argument(
            "--drivers",
            action="store_true",
            help="Run only AST driver and language detection health check",
        )
        parser.add_argument(
            "--github",
            action="store_true",
            help="Print what trust tiers A and B need: the ruleset JSON, CODEOWNERS lines and signing setup",
        )
        parser.add_argument(
            "--apply",
            action="store_true",
            help="With --github --tier: create the ruleset through gh, only after a y/N at a terminal",
        )
        parser.add_argument(
            "--release",
            metavar="SHA",
            default=None,
            help="Verify that the CI verdict job attested this commit (gh attestation verify, gh >= 2.93.0; "
            "otherwise UNVERIFIED and a non-zero exit)",
        )
        parser.add_argument(
            "--tier",
            choices=("A", "B"),
            help="With --github --apply: which ruleset to create (A: reviews; B: solo, signed approvals)",
        )

    def execute(self, args: argparse.Namespace) -> int:
        return run_doctor(args)
