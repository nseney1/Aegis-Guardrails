"""Smoke-test an installed Aegis distribution with the source checkout hidden.

Run with an interpreter that has the built wheel (or sdist) installed, from a
directory OUTSIDE the repository, in isolated mode so neither PYTHONPATH nor
the current directory can shadow site-packages:

    cd "$(mktemp -d)" && python -I /path/to/wheel_smoke.py

Fails (non-zero exit) if any Aegis module resolves from outside site-packages,
or if the CLI, the MCP server, or Governance SDK do not work.
"""
import importlib
import importlib.util
import json
import os
import site
import subprocess
import sys
import sysconfig
import tempfile

PACKAGES = ("aegis_cli", "aegis_sdk", "aegis_core", "aegis_mcp")
# Shipped rule floor (D16): rules/ has 4 guidance rules, the active starter and META.md, and
# rules/.oracles/ has 8; init's rule locator and the full preset see the 12 guidance rules
# (not META.md, not the active starter, which init seeds as an invariant: v4.1 d5).
FULL_PRESET_RULES = 12
ACTIVE_STARTERS = ("no-eval",)
# The author's dogfood rules live in the repository's .aegis/rules (D16), and
# desktop-automation is not shipped; none of them may reach the wheel.
UNSHIPPED_RULES = ("gitflow-review-gate", "ci-green-before-release", "core-change-protocol",
                   "no-pre-existing-excuse", "optional-import-guard", "desktop-automation")


def _ensure_site_packages():
    """Return (valid_site_roots, subprocess_isolation_flag).

    Under ``python -I``, user site-packages (``~/.local/lib/pythonX.Y/site-packages``)
    is omitted from ``sys.path``. When ``pip install`` defaulted to ``--user`` on a
    non-venv POSIX host, re-attach user site-packages. Children then run with ``-P``
    (Python 3.11+) or ``-E`` (older Pythons have no ``-P``); every child starts in a
    fresh temporary directory, so the current directory holds nothing to import.
    """
    roots = {os.path.realpath(sysconfig.get_paths()[k]) for k in ("purelib", "platlib")}
    user_site = getattr(site, "USER_SITE", None) or os.path.expanduser(
        f"~/.local/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    )
    if user_site and os.path.isdir(user_site):
        real_user_site = os.path.realpath(user_site)
        roots.add(real_user_site)
        if importlib.util.find_spec("aegis_cli") is None:
            site.addsitedir(real_user_site)
            return roots, "-P" if sys.version_info >= (3, 11) else "-E"
    return roots, "-I"


_SITE_ROOTS, _SUBPROC_FLAG = _ensure_site_packages()


def _home_env(home, drop=()):
    """os.environ without ``drop``, with HOME and USERPROFILE moved to ``home``. A user-site install
    (the fallback above) finds its site directory through HOME, so its base stays pinned to this
    process's, read before the child's HOME changes."""
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env.update(HOME=home, USERPROFILE=home)
    if _SUBPROC_FLAG != "-I":
        env["PYTHONUSERBASE"] = site.getuserbase()
    return env


def fail(msg):
    print(f"wheel smoke FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def check_module_origins(names=PACKAGES):
    for name in names:
        mod = importlib.import_module(name)
        origin = os.path.realpath(getattr(mod, "__file__", "") or "")
        if not any(origin.startswith(r + os.sep) for r in _SITE_ROOTS):
            fail(f"{name} imported from {origin!r}, not from site-packages {sorted(_SITE_ROOTS)}")
        print(f"ok  {name:14s} {origin}")


def make_workspace():
    ws = tempfile.mkdtemp(prefix="aegis-smoke-")
    rules = os.path.join(ws, ".aegis", "rules", "traps")
    os.makedirs(rules)
    with open(os.path.join(rules, "trap-smoke.md"), "w", encoding="utf-8") as f:
        f.write("---\nid: trap-smoke\ntype: trap\nhypothesis: smoke\n"
                "prediction: smoke\ntarget_paths: ['*.py']\n---\n# Smoke\n")
    return ws


def check_native_ast(ws):
    """Parse installed native languages directly with no toolchain or user configuration."""
    from aegis_core.ast.policy import evaluate_forbid_ast_structured
    from aegis_core.ast.runner import ASTDriverRunner

    javascript = ("import {exec as run} from 'node:child_process';\n"
                  "export function native_smoke(){run('smoke');}\n")
    rust = 'use std::process::Command as Cmd;\npub fn native_smoke(){Cmd::new("smoke");}\n'
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="aegis-smoke-native-home-") as home:
        env = _home_env(home, drop=("PYTHONPATH", "AEGIS_WORKSPACE", "CLAUDE_CONFIG_DIR", "CODEX_HOME"))
        env.update(PATH=home, XDG_CONFIG_HOME=os.path.join(home, ".config"))
        try:
            os.environ.clear()
            os.environ.update(env)
            for extension in (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs", ".rs"):
                source = rust if extension == ".rs" else javascript
                path = os.path.join(ws, "native_smoke" + extension)
                with open(path, "w", encoding="utf-8") as stream:
                    stream.write(source)
                tree = ASTDriverRunner().parse_file(path, workspace_root=ws)
                language = ("rust" if extension == ".rs" else "javascript"
                            if extension in (".js", ".jsx", ".mjs", ".cjs") else "typescript")
                target = "Cmd::new" if extension == ".rs" else "run"
                pattern = "std::process::Command::new" if extension == ".rs" else "child_process.exec"
                if (tree.language != language or [d.name for d in tree.definitions] != ["native_smoke"] or
                        [call.target for call in tree.call_sites] != [target]):
                    fail(f"native {extension} extraction witness failed")
                findings = evaluate_forbid_ast_structured(
                    tree, {"calls": [{"name": pattern, "where": {"#0": "smoke"}}]}, source=source)
                if len(findings) != 1 or findings[0]["unknown"] or findings[0]["pattern"] != pattern:
                    fail(f"native {extension} qualified-call witness failed: {findings!r}")
                print(f"ok  native {extension} {language}: definition, call and qualified argument")
            check_module_origins(("aegis_core.ast.drivers.js", "aegis_core.ast.drivers.rust"))
        finally:
            os.environ.clear()
            os.environ.update(previous)


def check_cli(ws):
    proc = subprocess.run([sys.executable, _SUBPROC_FLAG, "-m", "aegis_cli.cli", "--help"],
                          capture_output=True, text=True, timeout=60, cwd=ws)
    if proc.returncode != 0:
        fail(f"aegis --help exited {proc.returncode}: {proc.stderr[-500:]}")
    print("ok  aegis --help")


def check_doctor(ws):
    """`aegis doctor --json` imports the whole doctor family from the wheel; a fresh HOME and an empty
    PATH keep the machine's hosts, git and gh out of it. A failed check (exit 1) is fine, a crash is not."""
    home = tempfile.mkdtemp(prefix="aegis-smoke-home-")
    env = _home_env(home, drop=("PYTHONPATH", "CLAUDE_CONFIG_DIR", "CODEX_HOME"))
    env["PATH"] = home
    # -E would ignore the pinned PYTHONUSERBASE; the child runs in the fresh workspace with
    # PYTHONPATH dropped, so nothing there can shadow site-packages.
    flags = [] if _SUBPROC_FLAG == "-E" else [_SUBPROC_FLAG]
    proc = subprocess.run([sys.executable, *flags, "-m", "aegis_cli.cli", "doctor", "--json", "--workspace", ws],
                          capture_output=True, text=True, timeout=120, cwd=ws, env=env)
    if proc.returncode not in (0, 1):
        fail(f"aegis doctor --json exited {proc.returncode}: {proc.stderr[-500:]}")
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        fail(f"aegis doctor --json printed no JSON (exit {proc.returncode}): {proc.stderr[-500:]}")
    if payload.get("schema") != "aegis.doctor/v1" or not isinstance(payload.get("hosts"), list):
        fail(f"aegis doctor --json returned {proc.stdout[:500]!r}")
    print("ok  aegis doctor --json (hermetic HOME)")


def check_mcp(ws):
    requests = "".join(json.dumps(r) + "\n" for r in (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "aegis_list_rules", "arguments": {}}},
    ))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["AEGIS_WORKSPACE"] = ws
    proc = subprocess.run([sys.executable, _SUBPROC_FLAG, "-m", "aegis_mcp"], input=requests,
                          capture_output=True, text=True, timeout=60, cwd=ws, env=env)
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 3:
        fail(f"MCP returned {len(lines)} responses: {proc.stdout[-500:]} {proc.stderr[-500:]}")
    tools = lines[1]["result"]["tools"]
    if len(tools) != 5:
        fail(f"MCP tools/list expected the 5 v4 tools, got {len(tools)}")
    payload = json.loads(lines[2]["result"]["content"][0]["text"])
    rules = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(rules, list):
        fail(f"MCP aegis_list_rules returned no rules list: {payload!r}")
    if "trap-smoke" not in {c.get("_name") for c in rules if isinstance(c, dict)}:
        fail(f"MCP aegis_list_rules did not see the workspace rule: {rules!r}")
    print("ok  aegis_mcp initialize / tools/list (5 tools) / aegis_list_rules")


def check_governance_fitness(ws):
    from aegis_sdk.governance import Governance
    result = Governance(project_root=ws).fitness_landscape()
    if isinstance(result, dict) and "error" in result:
        fail(f"governance fitness_landscape failed: {result}")
    print("ok  governance (Governance.fitness_landscape)")


def check_full_rule_preset(ws):
    """Prove the wheel contains the full rules, not only starter rules."""
    from pathlib import Path
    from aegis_cli.init import install_rules

    target = Path(ws) / "full-rules"
    installed = install_rules(target, preset="full")
    files = sorted(target.glob("*.md"))
    if len(installed) < FULL_PRESET_RULES or len(files) != len(installed):
        fail(f"full rule preset is incomplete: installed={installed!r}, files={files!r}")
    leaked = sorted(set(installed) & set(UNSHIPPED_RULES))
    if leaked:
        fail(f"full rule preset ships rules that must stay unshipped: {leaked!r}")
    print(f"ok  packaged full rule preset ({len(installed)} rules)")


def check_packaged_rules_and_skills(ws):
    """Prove the wheel packages rules/ and skills/ inside aegis_core/_data (seen through
    init's one locator), and installs no top-level package other than the aegis_* ones."""
    import importlib.metadata
    import importlib.resources
    from pathlib import Path
    from aegis_cli.init import packaged_active_rules, packaged_dir, packaged_rules
    from aegis_mcp.registry import TOOL_DEFINITIONS

    if len(TOOL_DEFINITIONS) != 5:
        fail(f"TOOL_DEFINITIONS expected the 5 v4 tools, got {len(TOOL_DEFINITIONS)}")
    dist = importlib.metadata.distribution("aegis-guardrails")
    top_level = sorted((dist.read_text("top_level.txt") or "").split())
    if top_level != sorted(PACKAGES):
        fail(f"the wheel installs top-level packages {top_level!r}, expected only {sorted(PACKAGES)!r}")
    # RECORD paths: the packages, the .dist-info, and console scripts outside site-packages ("..").
    tops = {f.parts[0] for f in dist.files or () if f.parts}
    foreign = sorted(t for t in tops if t not in PACKAGES and t != ".." and not t.endswith(".dist-info"))
    if foreign:
        fail(f"the wheel installs files outside the aegis_* packages: {foreign!r}")
    data = Path(str(importlib.resources.files("aegis_core"))) / "_data"
    for name in ("rules", "skills"):
        if packaged_dir(name) != data / name:
            fail(f"packaged_dir({name!r}) is {packaged_dir(name)}, not the wheel's {data / name}")
    rules = packaged_rules()
    if len(rules) < FULL_PRESET_RULES:
        fail(f"packaged_rules() found only {len(rules)} rules in the wheel: {sorted(rules)!r}")
    active = packaged_active_rules()
    if sorted(active) != sorted(ACTIVE_STARTERS) or any(p.parent != data / "rules" for p in active.values()):
        fail(f"the wheel's active starter rules are {active!r}, expected {ACTIVE_STARTERS!r} in {data / 'rules'}")
    skills = sorted(d.name for d in (data / "skills").iterdir() if (d / "SKILL.md").is_file())
    if len(skills) < 15:
        fail(f"the wheel packages only {len(skills)} skills: {skills!r}")
    print(f"ok  packaged rules and skills in aegis_core/_data ({len(rules)} rules, {len(skills)} skills, "
          f"5 MCP tools; top level {', '.join(top_level)})")


def _planted_repo(packages, modules=()):
    """A directory holding packages and top-level modules a cloned repository could plant,
    each of which writes a marker when imported, and a rules/pricing.md."""
    repo = tempfile.mkdtemp(prefix="aegis-smoke-planted-")
    marker = os.path.join(repo, "PLANTED_RAN")
    for package in packages + ("rules",):
        os.makedirs(os.path.join(repo, package))
        for module in ("__init__.py", "__main__.py"):
            with open(os.path.join(repo, package, module), "w", encoding="utf-8") as f:
                f.write(f"open({marker!r}, 'a').write({package!r} + chr(10))\n")
    for module in modules:
        with open(os.path.join(repo, module + ".py"), "w", encoding="utf-8") as f:
            f.write(f"open({marker!r}, 'a').write({module!r} + chr(10))\n")
    with open(os.path.join(repo, "rules", "pricing.md"), "w", encoding="utf-8") as f:
        f.write("---\nid: pricing\n---\n# repository text\n")
    return repo, marker


def check_mcp_launcher():
    """The commands `aegis init --host` registers start the wheel's server from a directory
    that plants aegis_mcp, aegis_core and a json module, and import none of them (release
    review: v4.0.0 registered `python -m aegis_mcp` when aegis-mcp was not on PATH)."""
    from aegis_cli.install_hosts import launch_risk, mcp_command

    requests = "".join(json.dumps(r) + "\n" for r in (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ))
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "AEGIS_WORKSPACE")}
    commands = {"registered": mcp_command(), "fallback": mcp_command(path="", scripts_dirs=[])}
    if commands["fallback"][:3] != [sys.executable, "-I", "-c"]:
        fail(f"the fallback MCP launcher is {commands['fallback']!r}, not this interpreter in isolated mode")
    for kind, command in commands.items():
        risk = launch_risk(command)
        if risk:
            fail(f"the {kind} MCP launcher {command!r} is unsafe: {risk}")
        # json: a standard-library module the server imports, which only -I (or a console
        # script, whose own directory leads sys.path) keeps the start directory from shadowing.
        repo, marker = _planted_repo(("aegis_mcp", "aegis_core"), modules=("json",))
        proc = subprocess.run(command, input=requests, capture_output=True, text=True, timeout=60,
                              cwd=repo, env=env)
        if os.path.exists(marker):
            fail(f"the {kind} MCP launcher {command!r} imported planted code from its start directory")
        lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        if len(lines) != 2 or len(lines[1].get("result", {}).get("tools", [])) != 5:
            fail(f"the {kind} MCP launcher {command!r} did not serve 5 tools: {proc.stdout[-300:]} {proc.stderr[-300:]}")
        print(f"ok  {kind} MCP launcher ignores planted packages: {command[0]}")


def check_init_ignores_a_repository_rules_package():
    """`python -m aegis_cli init --rules full` run inside a repository with its own
    rules/__init__.py and rules/pricing.md (the case that put the repository first on
    sys.path) seeds the wheel's rules and never imports or copies the repository's."""
    import shutil

    if shutil.which("git") is None:
        print("skip init in a repository with its own rules/ (git not found)")
        return
    repo, marker = _planted_repo(("skills",))
    home = tempfile.mkdtemp(prefix="aegis-smoke-home-")
    env = _home_env(home, drop=("PYTHONPATH", "AEGIS_WORKSPACE"))
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
    # Not isolated on purpose: the current directory is first on sys.path, as it was for
    # the README's old `python3 -m aegis_cli` advice.
    proc = subprocess.run([sys.executable, "-m", "aegis_cli.cli", "init", "--yes", "--no-hooks", "--rules", "full"],
                          capture_output=True, text=True, timeout=120, cwd=repo, env=env)
    if proc.returncode != 0:
        fail(f"aegis init in a repository with its own rules/ exited {proc.returncode}: {proc.stderr[-500:]}")
    seeded = sorted(os.listdir(os.path.join(repo, ".aegis", "rules", "personas")))
    if os.path.exists(marker) or "pricing.md" in seeded or len(seeded) != FULL_PRESET_RULES:
        fail(f"aegis init read the repository's own rules/: seeded {seeded!r}, "
             f"planted code ran: {os.path.exists(marker)}")
    active = sorted(os.listdir(os.path.join(repo, ".aegis", "rules", "invariants")))
    if active != [f"{name}.md" for name in sorted(ACTIVE_STARTERS)]:
        fail(f"aegis init seeded the active starters {active!r}, expected {ACTIVE_STARTERS!r}")
    print(f"ok  aegis init in a repository with its own rules/ seeds the wheel's {len(seeded)} rules "
          f"and {len(active)} active one")


def check_init_dry_run(ws):
    """`aegis init --dry-run --json` plans from the wheel and writes nothing."""
    repo = tempfile.mkdtemp(prefix="aegis-smoke-init-")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run([sys.executable, _SUBPROC_FLAG, "-m", "aegis_cli.cli", "--json", "init",
                           "--workspace", repo, "--dry-run", "--rules", "full"],
                          capture_output=True, text=True, timeout=60, cwd=ws, env=env)
    if proc.returncode != 0:
        fail(f"aegis init --dry-run exited {proc.returncode}: {proc.stderr[-500:]}")
    payload = json.loads(proc.stdout)
    if payload.get("source") != "aegis init" or payload.get("status") != "ok" or not payload.get("dry_run"):
        fail(f"aegis init --dry-run --json returned {payload!r}")
    if not {"aegis_version", "checked_at", "scope", "actions"} <= set(payload):
        fail(f"aegis init --json lacks provenance keys: {sorted(payload)!r}")
    if os.listdir(repo):
        fail(f"aegis init --dry-run wrote {os.listdir(repo)!r}")
    print("ok  aegis init --dry-run --json (writes nothing)")


def main():
    if os.environ.get("PYTHONPATH"):
        fail("PYTHONPATH must be unset for a source-hidden smoke test")
    if not sys.flags.isolated:
        fail("run with python -I so the current directory cannot shadow site-packages")
    check_module_origins()
    ws = make_workspace()
    check_native_ast(ws)
    check_cli(ws)
    check_doctor(ws)
    check_mcp(ws)
    check_mcp_launcher()
    check_governance_fitness(ws)
    check_full_rule_preset(ws)
    check_packaged_rules_and_skills(ws)
    check_init_ignores_a_repository_rules_package()
    check_init_dry_run(ws)
    print("wheel smoke passed")


if __name__ == "__main__":
    main()

