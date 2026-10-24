"""aegis doctor — workspace health, the host matrix and backed-up cleanup (host-matrix §3.9-3.10).

A read run changes nothing: it reads files, runs ``codex mcp get aegis --json`` (the only
host CLI it starts: Codex keeps its registrations in TOML, which stdlib-only Aegis does not
parse), and never syncs, checks or initializes. The one network access is the trust tier's
read-only ``gh api`` GETs through the user's own ``gh`` (no ``gh`` means tier C). Claude Code
is read from ``~/.claude.json`` instead of ``claude mcp list``, which starts every configured
server.

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
skips it). Every file is first copied to ``~/.aegis/backups/<UTC stamp>/`` with a manifest;
writes are atomic; a symlink, a hard link or a file that changed since the check is never
written. It never edits shell rc files (D17) and never writes TOML.
"""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core.pathlookup import INSIDE_FENCE, Hit, only_skipped, which
from aegis_core.primitives import is_within, real_key

__all__ = ["run_doctor", "DoctorCommand", "probe_mcp_launcher", "SCHEMA", "V3_SHIPPED_RULE_SHA256"]

SCHEMA = "aegis.doctor/v1"
SOURCE = "aegis doctor"
SERVER = "aegis"
# The v3 server name; v4 registers only "aegis" and doctor --fix removes this one.
LEGACY_SERVER = "soma"
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


def _is_home(root: Path) -> bool:
    """Whether ``root`` is the home directory, whose ``.aegis/`` is the user plane."""
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout.current()
    key = real_key(root)
    return layout is not None and key is not None and key == real_key(layout.home)


def _setup_command(root: Path) -> str:
    """What sets governance up here: ``aegis migrate`` while an unmigrated v3 workspace is
    here (``aegis init`` would leave its rules unserved, and the check would then pass on
    none of them), else ``aegis init``."""
    from aegis_core.errors import WorkspaceError
    from aegis_core.workspace.discovery import refuse_unmigrated_v3

    try:
        refuse_unmigrated_v3(root)
    except WorkspaceError:
        return "aegis migrate"
    return "aegis init"


def _setup_fix(root: Path, purpose: str) -> str:
    if _setup_command(root) == "aegis migrate":
        return "Fix: Run 'aegis migrate' to see how this v3 workspace converts, then 'aegis migrate --apply'."
    return f"Fix: Run 'aegis init' to {purpose}."


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


def _check_state_dir(project_root: Path | None = None) -> Optional[bool]:
    """Check .aegis/state/ (ledger, lock) exists and is writable, or can be created (read-only check)."""
    from aegis_core.workspace.layout import WorkspaceLayout

    root = Path(project_root or Path.cwd()).resolve()
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


def _check_cli_resolvable(project_root: Optional[Path] = None) -> bool:
    """Check that the 'aegis' CLI the bootstrap sends agents to is on PATH.

    Only absolute PATH entries count (aegis_core.pathlookup): an empty or relative entry
    resolves against the directory a shell starts in, where a cloned repository can plant
    an ``aegis``. Doctor runs nothing here, so an absolute entry inside the workspace (a
    project virtualenv the user put on PATH) counts, and the line says where it is.
    """
    root = Path(project_root or Path.cwd()).resolve()
    path = which("aegis")
    if path:
        inside = which("aegis", outside=root) != path
        print(f"  ✅ aegis CLI resolvable ({path}{', inside the workspace' if inside else ''})")
        return True
    print("  ❌ aegis CLI not found on PATH")
    for hit in only_skipped("aegis", base=root):
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


def _clean(text: Any, limit: int = 512) -> str:
    """A string from a file or a host's output, safe to print: no escape or control sequences."""
    from aegis_cli import sanitize_display

    return sanitize_display(str(text), max_len=limit)


# ── MCP launcher ─────────────────────────────────────────────────────────────

# A registered command, as doctor compares it: (host id, argv as the host config holds it).
Registered = Tuple[str, Sequence[str]]


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


def _check_ast_drivers(project_root: Path | None = None, fix: bool = False) -> Optional[bool]:
    """Check the AST drivers this workspace uses and that their executables resolve.

    A repository opts in to a packaged driver in .aegis/config.json; driver commands
    come only from ~/.aegis/config.json (D10).
    """
    import shlex
    from aegis_core.ast.detect import detect_project_languages, provision_ast_driver_slots
    from aegis_core.ast.runner import resolve_driver_executable
    from aegis_core.errors import PathTraversalError
    from aegis_core.skills.slots import SlotRegistry, SlotResolutionError

    ws_root = Path(project_root or Path.cwd())
    if _is_home(ws_root):
        # Never walk the home directory for sources, nor write a repository's driver
        # opt-in into ~/.aegis/config.json, which is the user scope.
        print(f"  ℹ️  AST drivers: not checked: {ws_root} is your home directory, whose .aegis/ is your user layer")
        return None
    detected_langs = detect_project_languages(ws_root)
    non_py_langs = {k: v for k, v in detected_langs.items() if k != "python"}

    def _configured() -> dict[str, str]:
        drivers: dict[str, str] = {}
        for registry in (SlotRegistry.load(ws_root), SlotRegistry.load_user(ws_root)):
            for slot_name, slot_val in registry.to_dict().items():
                if slot_name == "ast_driver":
                    drivers["default"] = str(slot_val)
                elif slot_name.startswith("ast_driver_"):
                    drivers[f".{slot_name[len('ast_driver_'):]}"] = str(slot_val)
        return drivers

    try:
        ast_drivers = _configured()
    except SlotResolutionError as exc:
        print(f"  ❌ AST drivers: {exc}")
        return False

    missing = sorted({
        ext
        for l_info in non_py_langs.values()
        for ext in l_info.get("extensions", [])
        if ext not in ast_drivers and "default" not in ast_drivers
    })
    if missing:
        if fix:
            try:
                _slots, written = provision_ast_driver_slots(ws_root, detected_langs)
            except PathTraversalError as exc:
                print(f"  ❌ AST drivers: {exc}")
                return False
            if written:
                print(f"  ✅ Fixed: enabled the packaged AST drivers in .aegis/config.json for {', '.join(missing)}")
                ast_drivers = _configured()
        else:
            print(f"  ⚠️  AST drivers: unconfigured driver for detected source extension(s): {', '.join(missing)}. Run 'aegis doctor --fix' to provision.")
            return False

    if not ast_drivers:
        print("  ✅ AST drivers: native Python stdlib (in-process)")
        return True

    all_resolvable = True
    for ext, cmd in sorted(ast_drivers.items()):
        parts = (
            shlex.split(cmd)
            if os.name != "nt"
            else [p.strip('"') for p in shlex.split(cmd, posix=False)]
        )
        if not parts:
            continue
        bin_name = parts[0]
        # As the driver runs: absolute PATH entries outside the workspace, a relative path
        # joined to the workspace root (aegis_core.ast.runner).
        found = resolve_driver_executable(bin_name, workspace=ws_root)
        hits = [] if found else only_skipped(bin_name, outside=ws_root, base=ws_root)
        if found:
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

def _check_precommit_hook(project_root: Path | None = None) -> bool | None:
    """True for a current, runnable hook block; False for an older one or one whose
    pinned interpreter or aegis path is gone; None if absent.

    Blocks before the current format resolved aegis through PATH, $VIRTUAL_ENV
    or the repository's .venv, so repository code could run on commit.
    """
    from aegis_cli.hooks.management import hook_status

    st = hook_status(project_root)
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


# ── Host plane: context ──────────────────────────────────────────────────────

# Codex's own answer when no server has that name. Any other failure leaves the
# registration unknown: a CLI that crashed has not said "absent".
_CODEX_ABSENT = re.compile(r"no mcp server named\s+['\"]?aegis['\"]?\s+found", re.IGNORECASE)
_PROBE_TIMEOUT = 10.0
# Hosts that silently keep only the start of an over-budget instruction file: Codex at
# its 32 KiB project_doc_max_bytes, Antigravity at 24,000 bytes per file (host-matrix
# §1-§2, verified 2026-10-15). A block that ends within the budget still arrives; for
# the other hosts the budget is advice.
_TRUNCATES_TAIL = frozenset({"codex-cli", "antigravity"})
# Hosts that send no MCP roots and attest no workspace: the registry is how the server
# finds the repository (host-matrix §2, §3.6).
_REGISTRY_BOUND = frozenset({"antigravity"})
# Hosts that read AGENTS.override.md instead of AGENTS.md at the same level.
_READS_AGENTS_OVERRIDE = frozenset({"codex-cli"})
_FIX_HINT = "aegis doctor --fix"
_LEGACY_ENTRY = f"stale v3 '{LEGACY_SERVER}' MCP server"


def _run_host_cli(argv: Sequence[str], cwd: str, timeout: float) -> "subprocess.CompletedProcess[str]":
    """The one place doctor starts a host CLI: an argv (no shell), no stdin, bounded in time."""
    return subprocess.run(list(argv), cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, errors="replace", timeout=timeout, env=_child_env())


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _aegis_version() -> str:
    from aegis_core._version import __version__
    return __version__


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class _Ctx:
    """What one doctor run looks at; files are read once."""

    root: Path
    governed: bool
    home: Optional[Path]
    environ: Mapping[str, str]
    selected: Tuple[Any, ...]
    selection: str
    is_home: bool = False
    # What sets this workspace up: aegis migrate while an unmigrated v3 workspace is here.
    setup: str = "aegis init"
    _cache: Dict[Tuple[str, bool], Any] = field(default_factory=dict)

    @property
    def path_env(self) -> str:
        return self.environ.get("PATH", "")

    def which(self, name: str) -> Optional[str]:
        return which(name, self.path_env, outside=self.root)

    def passed_over(self, name: str) -> List[Hit]:
        """Where ``name`` is when ``which`` refused every place: a relative or empty PATH
        entry (resolved against the workspace, where a host would start) or an absolute
        entry inside it. Never run."""
        return only_skipped(name, self.path_env, outside=self.root, base=self.root)

    def file(self, path: Path, as_json: bool = False) -> Any:
        key = (os.path.abspath(str(path)), as_json)
        if key not in self._cache:
            entry = _read_file(Path(path))
            self._cache[key] = _parse_json(entry) if as_json else entry
        return self._cache[key]

    def label(self, path: Path) -> str:
        """``~/x`` for a file under the home directory (as the docs name them), else the path."""
        if self.home is not None:
            try:
                return "~/" + Path(path).relative_to(self.home).as_posix()
            except ValueError:
                pass
        return str(path)


def _platform() -> str:
    """``sys.platform``, read in one place so a test can emulate another OS's app folders."""
    return sys.platform


def _app(spec: Any, ctx: _Ctx) -> Optional[str]:
    """The installed desktop app of ``spec`` (an app bundle is a directory), or None."""
    from aegis_core import hosts

    if ctx.home is None:
        return None
    return next((app for app in hosts.app_paths(spec, ctx.home, ctx.environ, _platform()) if os.path.isdir(app)),
                None)


def _plane_found(spec: Any, ctx: _Ctx) -> Optional[str]:
    """What shows ``spec``'s config plane is on this machine, for people: a binary doctor
    would run, a config path in the home directory or a desktop app; None when nothing does."""
    for name in spec.binaries:
        found = ctx.which(name)
        if found:
            return ctx.label(Path(found))
    if ctx.home is not None:
        for spec_path in spec.config_paths:
            rel = spec_path[2:] if spec_path.startswith("~/") else spec_path
            if os.path.exists(ctx.home.joinpath(*rel.split("/"))):
                return spec_path
    app = _app(spec, ctx)
    return ctx.label(Path(app)) if app else None


# ── Host plane: registration probes ─────────────────────────────────────────

def _registration(status: str, source: str, **facts: Any) -> Dict[str, Any]:
    reg = {"status": status, "source": source, "scope": None, "command": None, "command_exists": None,
           "enabled": None, "approval": None, "detail": None, "aegis_client": None}
    reg.update(facts)
    return reg


def _entry_facts(entry: Any, ctx: _Ctx) -> Dict[str, Any]:
    """Command, AEGIS_CLIENT and enabled flag of one MCP server entry.

    The strings come from files a repository can write (a project .mcp.json), so the
    command is reported without control sequences; the existence check uses it as
    written, and AEGIS_CLIENT stays raw for the identity decision (``_identity`` cleans
    what it reports), since the server sees the raw value.
    """
    facts: Dict[str, Any] = {}
    if not isinstance(entry, dict):
        return facts
    command = entry.get("command")
    if isinstance(command, str) and command:
        args = entry.get("args") if isinstance(entry.get("args"), list) else []
        facts["command"] = [_clean(command)] + [_clean(a) for a in args]
        facts["command_exists"] = _command_exists(command, ctx)
    env = entry.get("env")
    if isinstance(env, dict) and isinstance(env.get("AEGIS_CLIENT"), str):
        facts["aegis_client"] = env["AEGIS_CLIENT"]
    if isinstance(entry.get("disabled"), bool):
        facts["enabled"] = not entry["disabled"]
    if isinstance(entry.get("enabled"), bool):
        facts["enabled"] = entry["enabled"]
    return facts


def _command_exists(command: str, ctx: _Ctx) -> Optional[bool]:
    """Whether the registered command exists; None when doctor cannot tell.

    A relative path with a directory part resolves against the directory the host starts
    the server in, which doctor does not know. A bare name found only through an empty or
    relative PATH entry, or in an absolute entry inside the workspace, is one the host
    may run but doctor does not count.
    """
    if os.path.isabs(command):
        return os.path.isfile(command) and (os.name == "nt" or os.access(command, os.X_OK))
    if os.sep in command or (os.altsep and os.altsep in command):
        return None
    if ctx.which(command) is not None:
        return True
    return None if ctx.passed_over(command) else False


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


def _present(path: Path) -> bool:
    """Whether a file is there, without reading it; True when that cannot be told, so an
    unreadable parent directory never lets doctor claim the bootstrap through."""
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, ValueError):
        return True


#: sha256 of every rules/*.md and rules/.oracles/*.md file shipped in the v3.0.0-v3.3.0
#: wheels, which v3's Gemini and Kiro adapters copied byte for byte into
#: ~/.gemini/config/rules and ~/.kiro/steering. Computed from the release tags with
#: ``git show vX:rules/<file> | sha256sum``. A copy is removed only on an exact match;
#: names and content are never compared (defense #39).
V3_SHIPPED_RULE_SHA256 = frozenset({
    "acab95f21fc4eb254337fc84fe87dbcd8b059173fb56fe520f385224e27825a2",  # .oracles/architectural-tenets
    "af94c7153052c7488e0e67d86e780a74fdf106caf45da65244cc9fb9643130ba",  # .oracles/atomic-workstream-protocol
    "3d605fdfe36b2fbef771776c43c079dffbda2a593e71cb5f04175e23807fe9a2",  # .oracles/documentation
    "03a9e189a1c72f6178d9c1c5eb139fca008db810cd14eddc56400b014b9ce4db",  # .oracles/feature-specs
    "e5bc5f348d4e2cdf93457471c60b239ab6d64f2420e349f368e4995396c2afc5",  # .oracles/git-workflow
    "ca215d78f371e0f7aa4ad562a22be47db42e639d0cb28797dc7971157db0ddd8",  # .oracles/optional-import-guard (3.0)
    "63a857db70e56ceabda0fd07412f8924b128e227ec94b63d839497ef73b7152b",  # .oracles/optional-import-guard (3.1+)
    "ded22d86c5f47a0a13f64f9da99d543d276ddf830017b6a63f1c5a6e78b5c021",  # .oracles/polyglot-standards
    "337cee795219e24354a7850acebb9d79e6266e595ca7d31e4598d0d21b9e82f4",  # .oracles/tdd-protocol (3.0)
    "d33b2a6ebd2dc7c81ac3b98c060e52c38bb80baaf6362a3aea22900463af74c8",  # .oracles/tdd-protocol (3.1+)
    "863c28d335a31e48a1aef27c83b32dcab881029b3eb07a955e0b8eadd5d198e8",  # .oracles/testing
    "12d8813c7b251bc310e8122305c6ee7778fe01483dd4103691b26000a3369354",  # META (3.0)
    "4879bfb58b4a5bd3344e0278c815ce33b90ae746f694f6b82b52e87e80938582",  # META (3.1+)
    "f7ec0a8f721b64f8d37b5f259e64c86470d98a00dd3e535e68b4ab33813d486c",  # ci-green-before-release
    "20b2f3294ef1e9ceb23c4714c3d1ed95cd89f6828dd57230099da9e62fd43ecc",  # core-change-protocol (3.0)
    "8b85634178a5e121581ca98687c490c55c37a0dae4a36950866631fa215f2dcd",  # core-change-protocol (3.1+)
    "4b1656771eab2a652e0b41f221be1f5712565493506295edd3de06be44978e0c",  # cost-optimization (3.0)
    "db76ddf60f833f0b0070e0a811cdcd101e02ccc204956d6c62609e929ae13955",  # cost-optimization (3.1+)
    "25600eecc61dbd447e67ae9d43255425efbcf94195930b8c8ca11c771d26add5",  # desktop-automation
    "91fdf925befe794b662d882a069fe7035c5acf731e413d961b9e1c83d6432447",  # destructive-ops
    "2473444c146b5d36d0edefd74347e0175e76a355536ab5d5df51514b69ba7ed1",  # gitflow-review-gate (3.0)
    "18357403da55489f326c15dad044ded615badaea7b77f37aeb7757f163bdbb3a",  # gitflow-review-gate (3.1+)
    "2be52fdd2f290e1cbd81600e35d8198bc6766b5c827c0d1b240ce060470984fc",  # no-pre-existing-excuse (3.0)
    "5187404be379aca6b0cb0ec62436054ebfcad320c264a34ef95e271a42c95767",  # no-pre-existing-excuse (3.1+)
    "27b596123c2a88dea15b82a846e07215774e0b1dfdc2c3b67f2336b89d3fad3b",  # providence (3.0)
    "6417ece31939ece9e3f6fec52413d4f8c329fbf38be8c104b01b2f28ee0a5fe6",  # providence (3.1+)
    "04946d5d7b525f24284ae51f2d958f8b5fcc4d3ed891e391ceec71f5dd5ddd0f",  # subagent-delegation (3.0)
    "5d54ce9b04be9572698749908558800cbf2d8acdffc15e7b7a651fbf6f39488f",  # subagent-delegation (3.1+)
})


def _stdin_is_tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _confirm(prompt: str) -> bool:
    """Ask on the terminal; anything but y/yes is no. Without a terminal the answer is no."""
    if not _stdin_is_tty():
        print("stdin is not a terminal, so nothing was applied: re-run with --yes to apply these changes.")
        return False
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


from aegis_cli.doctor_findings import (  # noqa: E402
    ListItem, _Action, _BLOCK_BEGIN, _BLOCK_END, _BOM, _CLAUDE_FAMILY, _CODE_SPAN, _COMMAND_STARTERS,
    _ClaudeFile, _FENCE, _Finding, _HEX12, _HOOK_SCOPE_FILES, _IMPORTS_AGENTS, _IMPORTS_PARENT_AGENTS,
    _INDENTED_CODE, _Instructions, _LEGACY_MARKER, _TIER_TEXT, _V3_PLUGIN, _advisory, _all, _any,
    _best_effort, _bootstrap_reaches, _bootstrap_state, _bootstrap_tool_findings, _budget, _budget_findings,
    _claude_import_advice, _claude_names, _claude_reads_agents, _fence_step, _floor_status,
    _home_rules_finding, _hook_files, _hook_findings, _hook_row, _hook_tier_text, _host_row, _identity,
    _instruction_files, _instructions, _is_legacy_handler, _key_finding, _legacy_block_findings,
    _legacy_hook_findings, _legacy_items, _legacy_ranges, _level, _list_location, _location, _mcp_findings,
    _mcp_loads, _path_key, _program_name, _prose, _registered_roots, _removed_host_phases,
    _runnable, _selection, _tiers, _upgrade_findings, _v3_copy_findings, _workspace_findings,
    _worktree_ledger_findings,
)
from aegis_cli.doctor_render import (  # noqa: E402
    _CHECKS, _ICON, _PLACEHOLDER_CHECK, _github_plan, _hooks_line, _payload, _print_findings,
    _print_github, _print_hosts, _print_plan, _print_results, _print_tiers, _print_trust,
    _registered_launchers, _run_checks, _run_drivers_only, _run_github, _run_release, _summary,
)
from aegis_cli.doctor_repair import (  # noqa: E402
    _Change, _Diagnosis, _File, _Refused, _apply, _backup_root, _claude_config, _claude_dir,
    _claude_project_keys, _claude_user_registered, _current_bytes, _desktop_configs, _diagnose,
    _dump_like, _host_json_path, _missing_ast_extensions, _names, _parse_json, _plan, _probe_claude,
    _probe_json_host, _read_file, _reject_constant, _server_entry, _state_modes, _strict_pairs,
    _without_keys, _without_lines, _without_list_items, _write_manifest, _write_refusal,
)

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


def _home() -> Optional[Path]:
    from aegis_core.workspace.layout import UserLayout

    layout = UserLayout.current()
    return layout.home if layout else None


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

    diag = _diagnose(root)
    plan = _plan(diag.findings, _missing_ast_extensions(root), root) if fix else []
    results: List[Dict[str, Any]] = []
    backup: Optional[Path] = None
    declined = False
    text = io.StringIO()
    with contextlib.redirect_stdout(text) if use_json else contextlib.nullcontext():
        if not use_json:
            print(f"aegis doctor — running health checks ({_clean(root, 4096)}):\n")
        checks = _run_checks(root, fix_ast=False, registered=_registered_launchers(diag.rows))
        if not use_json:
            for check in checks:
                print(check["text"], end="")
            _print_hosts(diag)
            _print_tiers(diag)
            _print_trust(diag)
            from aegis_core.sync import base_fetch

            fetched = base_fetch(root)[0]  # Aegis never fetches; this says how old BASE may be
            if fetched:
                print(f"  {fetched}")
            _print_findings(diag.findings)
        if fix:
            if not plan:
                print("\nNothing to fix.")
            else:
                _print_plan(plan, diag.ctx.home)
                if yes or _confirm(f"Apply these {len(plan)} changes? [y/N] "):
                    results, backup = _apply(plan, diag.ctx.home, root)
                    _print_results(results, backup)
                else:
                    declined = True
                    print("No changes made.")

    payload = _payload(diag, checks)
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
        "blocks, unedited v3 rule copies, missing packaged AST drivers), after confirmation, backing each file up "
        "to ~/.aegis/backups/<UTC stamp>/ first."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--fix",
            action="store_true",
            help="Repair what doctor reported, after confirmation; every file is backed up first",
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
