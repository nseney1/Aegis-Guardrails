"""Smoke-test an installed Aegis distribution with the source checkout hidden.

Run with an interpreter that has the built wheel (or sdist) installed, from a
directory OUTSIDE the repository, in isolated mode so neither PYTHONPATH nor
the current directory can shadow site-packages:

    cd "$(mktemp -d)" && python -I /path/to/wheel_smoke.py

Fails (non-zero exit) if any Aegis module resolves from outside site-packages,
or if the CLI, the MCP server, or Governance SDK do not work.
"""
from collections import Counter
import hashlib
import importlib
import importlib.util
import json
import os
import re
import site
import subprocess
from subprocess import CalledProcessError, TimeoutExpired
import sys
import sysconfig
import tempfile

PACKAGES = ("aegis_cli", "aegis_sdk", "aegis_core", "aegis_mcp")
# Keep this independent of the installed package under test. The repository's
# release tests compare it with the shipped registry before an artifact is built.
EXPECTED_MCP_TOOLS = (
    "aegis_capture_insight",
    "aegis_create_rule",
    "aegis_list_rules",
    "aegis_msg_read",
    "aegis_msg_write",
    "aegis_report_outcome",
    "aegis_scan",
    "aegis_team_config",
    "aegis_team_model",
    "aegis_team_queue",
)
MAX_MCP_STDOUT = 1024 * 1024
MAX_MCP_TOOLS = 1024
MAX_MCP_NAME = 128
FACT_CHANNELS = frozenset((
    "stdout", "stderr", "error", "timeout-stdout", "timeout-stderr", "command", "origin", "site-roots",
    "findings", "rules", "result", "installed", "files", "packages", "foreign", "path", "active",
    "skills", "seeded", "entries", "name", "provenance", "hosts", "dry-run", "risk", "tools", "module",
))
EXPECTED_FACT_KEYS = tuple(sorted(set(EXPECTED_MCP_TOOLS) | {
    "result", "error", "tools", "name", "content", "text", "rules", "_name", "schema", "lanes", "check",
    "status", "tip", "hosts", "source", "dry_run", "aegis_version", "checked_at", "scope", "actions",
    "rule", "type", "triggers", "tp", "fp", "score",
}))
EXPECTED_IDENTIFIERS = frozenset(EXPECTED_MCP_TOOLS + (
    "trap-smoke", "aegis.team.claim/v1", "aegis.team.status/v1", "aegis.doctor/v1", "aegis init", "ok", "pass", "workspace-tip",
))
EXPECTED_MODULES = PACKAGES + ("aegis_core.ast.drivers.js", "aegis_core.ast.drivers.rust", "aegis_core.team_status")
SAFE_EXCEPTION_CLASSES = {
    OSError: "OSError", FileNotFoundError: "FileNotFoundError", PermissionError: "PermissionError",
    ValueError: "ValueError", TypeError: "TypeError", RecursionError: "RecursionError",
    RuntimeError: "RuntimeError", UnicodeDecodeError: "UnicodeDecodeError", UnicodeEncodeError: "UnicodeEncodeError",
    ImportError: "ImportError", ModuleNotFoundError: "ModuleNotFoundError",
}
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


def _data_type(value):
    for kind, label in ((str, "str"), (bytes, "bytes"), (bool, "boolean"), (int, "int"),
                        (float, "float"), (dict, "dict"), (list, "list"), (tuple, "tuple")):
        if type(value) is kind:
            return label
    return "null" if value is None else "unsupported"


def _raw_data(data):
    """Strings use UTF-8/surrogatepass; decoded objects use bounded canonical JSON."""
    if type(data) in (str, bytes):
        return data
    remaining = MAX_MCP_STDOUT

    def bound(value, depth=0):
        nonlocal remaining
        size = 12 * len(value) + 4 if type(value) is str else 32
        if type(value) in (dict, list, tuple):
            size += 4 * len(value)
        elif type(value) is int:
            size += value.bit_length()
        if depth > 32 or size > remaining:
            fail("diagnostic data exceeds limits")
        remaining -= size
        if type(value) is dict:
            for key, field in value.items():
                bound(key, depth + 1)
                bound(field, depth + 1)
        elif type(value) in (list, tuple):
            for field in value:
                bound(field, depth + 1)
        elif value is not None and type(value) not in (str, bool, int, float):
            fail("diagnostic data unsupported")

    bound(data)
    try:
        return json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (ValueError, TypeError, RecursionError):
        fail("diagnostic data unsupported")


def _fingerprint(data):
    raw = _raw_data(data)
    digest = hashlib.sha256()
    length = 0
    if type(raw) is bytes:
        digest.update(raw)
        length = len(raw)
        lines = raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))
    else:
        # Count bytes and hash before allocating an encoded field or parsing it.
        for offset in range(0, len(raw), 4096):
            chunk = raw[offset:offset + 4096].encode("utf-8", "surrogatepass")
            length += len(chunk)
            digest.update(chunk)
        lines = raw.count("\n") + int(bool(raw) and not raw.endswith("\n"))
    return raw, length, lines, digest.hexdigest()[:12]


def _facts(channel, data):
    """Only constants, counts and a raw-byte fingerprint may reach a diagnostic."""
    if channel not in FACT_CHANNELS:
        fail("invalid diagnostic channel")
    raw, length, lines, digest = _fingerprint(data)
    result = f"{channel} bytes={length} lines={lines} sha256={digest}"
    if length > MAX_MCP_STDOUT:
        return result + " json=unparsed"
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return result + " json=invalid"
    json_type = {str: "string", dict: "object", list: "array", bool: "boolean",
                 int: "number", float: "number", type(None): "null"}[type(value)]
    result += f" json={json_type}"
    if type(value) is dict:
        # Select from script constants, never from the child's key strings.
        known = [key for key in EXPECTED_FACT_KEYS if key in value]
        result += f" keys={len(value)} known-keys=[{','.join(known)}] other-keys={len(value) - len(known)}"
    return result


def _exception_class(exc):
    # Even a subclass may have a hostile class name. Non-builtin/unknown classes
    # are omitted; their messages, repr and class metadata are never inspected.
    return SAFE_EXCEPTION_CLASSES.get(type(exc), "omitted")


def _first_difference(value, expected):
    if type(value) is not str:
        return "none"
    for index, (actual, wanted) in enumerate(zip(value, expected)):
        if actual != wanted:
            return index
    return min(len(value), len(expected))


def _identifier_facts(value, expected, expected_label=None, schema=False):
    label = expected if expected_label is None else expected_label
    if label not in EXPECTED_IDENTIFIERS:
        fail("invalid expected identifier")
    raw, length, _, digest = _fingerprint(value)
    actual_length = len(value) if type(value) is str else length
    result = (f"expected={label!r} actual-type={_data_type(value)} length={actual_length} "
              f"sha256={digest} first-difference={_first_difference(value, expected)}")
    if (schema and type(value) is str and len(value) <= MAX_MCP_NAME
            and re.fullmatch(r"aegis(\.[a-z]{1,24}){1,4}/v[0-9]{1,3}", value)):
        result += f" actual-schema={value}"
    return result


def _closest_tool(value):
    return max(EXPECTED_MCP_TOOLS, key=lambda name: _first_difference(value, name)) if type(value) is str else EXPECTED_MCP_TOOLS[0]


def _identifier_list(values, expected=None):
    if len(values) > MAX_MCP_TOOLS:
        fail("diagnostic entries exceeds 1024")
    return f"count={len(values)} [" + "; ".join(
        _identifier_facts(value, expected if expected is not None else _closest_tool(value)) for value in values) + "]"


def _name_list(values):
    if len(values) > MAX_MCP_TOOLS:
        fail("diagnostic entries exceeds 1024")
    return f"count={len(values)} [" + "; ".join(_facts("name", value) for value in values) + "]"


def _directory_names(path):
    names = []
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if len(names) >= MAX_MCP_TOOLS:
                    fail("directory entries exceeds 1024")
                names.append(entry.name)
    except OSError as exc:
        fail(f"directory entries unavailable: exception={_exception_class(exc)}")
    return sorted(names)


def _expect_identifier(value, expected, context, expected_label=None):
    if value != expected:
        fail(f"{context} mismatch: {_identifier_facts(value, expected, expected_label, context.endswith('schema'))}")


def _run(command, **kwargs):
    """Capture raw bytes and keep process failures on the refusal path."""
    kwargs["text"] = False
    kwargs.pop("encoding", None)
    kwargs.pop("errors", None)
    kwargs.pop("universal_newlines", None)
    if type(kwargs.get("input")) is str:
        kwargs["input"] = kwargs["input"].encode("utf-8")
    try:
        return subprocess.run(command, **kwargs)
    except TimeoutExpired as exc:
        fail(f"command {_facts('command', command)} timed out after {kwargs.get('timeout')} seconds; "
             f"{_facts('timeout-stdout', exc.output or b'')}; {_facts('timeout-stderr', exc.stderr or b'')}")
    except CalledProcessError as exc:
        fail(f"command {_facts('command', command)} exited {exc.returncode}; "
             f"{_facts('stdout', exc.output)}; {_facts('stderr', exc.stderr)}")
    except (OSError, UnicodeError) as exc:
        fail(f"command {_facts('command', command)} could not run: exception={_exception_class(exc)}")


def _stdout_limit_unit(data):
    if type(data) is str and len(data) > MAX_MCP_STDOUT:
        return "characters"
    return "bytes" if _fingerprint(data)[1] > MAX_MCP_STDOUT else None


def _json_output(proc):
    context = f"command {_facts('command', proc.args)}"
    unit = _stdout_limit_unit(proc.stdout)
    if unit:
        fail(f"{context} stdout exceeds {MAX_MCP_STDOUT} {unit}; {_facts('stdout', proc.stdout)}; {_facts('stderr', proc.stderr)}")
    try:
        value = json.loads(proc.stdout)
    except (ValueError, RecursionError) as exc:
        fail(f"{context} returned invalid JSON; exception={_exception_class(exc)}; {_facts('stdout', proc.stdout)}; {_facts('stderr', proc.stderr)}")
    if not isinstance(value, dict):
        fail(f"{context} returned a non-object JSON response; {_facts('stdout', proc.stdout)}; {_facts('stderr', proc.stderr)}")
    return value


def _mcp_responses(proc, count, context):
    unit = _stdout_limit_unit(proc.stdout)
    if unit:
        fail(f"{context} stdout exceeds {MAX_MCP_STDOUT} {unit}; {_facts('stdout', proc.stdout)}; {_facts('stderr', proc.stderr)}")
    try:
        lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    except (ValueError, RecursionError) as exc:
        fail(f"{context} returned invalid JSON: exception={_exception_class(exc)}; {_facts('stdout', proc.stdout)}; {_facts('stderr', proc.stderr)}")
    if len(lines) != count:
        fail(f"{context} did not return {count} responses: {_facts('stdout', proc.stdout)}; {_facts('stderr', proc.stderr)}")
    for index, line in enumerate(lines):
        if not isinstance(line, dict):
            fail(f"{context} invalid response at index {index}; {_facts('stderr', proc.stderr)}")
    return lines


def _mcp_result(response, context, stderr):
    result = response.get("result")
    if not isinstance(result, dict):
        fail(f"{context} returned no result: {_facts('error', response.get('error'))}; {_facts('stderr', stderr)}")
    return result


def check_mcp_tools(tools, context):
    if not isinstance(tools, list):
        fail(f"{context} tools must be a list")
    if len(tools) > MAX_MCP_TOOLS:
        fail(f"{context} tools exceeds {MAX_MCP_TOOLS} entries")
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            fail(f"{context} invalid tool entry at index {index}: expected a dict with a string name")
        if len(tool["name"]) > MAX_MCP_NAME or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", tool["name"]):
            fail(f"{context} invalid tool name at index {index}: expected [A-Za-z0-9_.-]{{1,128}}; "
                 f"{_identifier_facts(tool['name'], _closest_tool(tool['name']))}")
    names = tuple(sorted(tool["name"] for tool in tools))
    if names != EXPECTED_MCP_TOOLS:
        missing = sorted(set(EXPECTED_MCP_TOOLS) - set(names))
        unexpected = sorted(set(names) - set(EXPECTED_MCP_TOOLS))
        duplicates = [name for name, count in sorted(Counter(names).items()) if count > 1]
        fail(f"{context} tools mismatch: missing={missing!r}, unexpected={_identifier_list(unexpected)}, duplicates={_identifier_list(duplicates)}")


def check_module_origins(names=PACKAGES):
    for name in names:
        if name not in EXPECTED_MODULES:
            fail(f"unexpected module: {_facts('module', name)}")
        mod = importlib.import_module(name)
        origin = os.path.realpath(getattr(mod, "__file__", "") or "")
        if not any(origin.startswith(r + os.sep) for r in _SITE_ROOTS):
            fail(f"{name} imported from {_facts('origin', origin)}, not from site-packages {_facts('site-roots', sorted(_SITE_ROOTS))}")
        print(f"ok  {name:14s} {_facts('origin', origin)}")


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
                    fail(f"native {extension} qualified-call witness failed: {_facts('findings', findings)}")
                print(f"ok  native {extension} {language}: definition, call and qualified argument")
            check_module_origins(("aegis_core.ast.drivers.js", "aegis_core.ast.drivers.rust"))
        finally:
            os.environ.clear()
            os.environ.update(previous)


def check_cli(ws):
    proc = _run([sys.executable, _SUBPROC_FLAG, "-m", "aegis_cli.cli", "--help"],
                          capture_output=True, text=True, timeout=60, cwd=ws)
    if proc.returncode != 0:
        fail(f"aegis --help exited {proc.returncode}: {_facts('stderr', proc.stderr)}")
    print("ok  aegis --help")


def check_team_status():
    """The installed CLI observes a captured lane tip without changing refs or events."""
    from pathlib import Path
    from aegis_core import events, gitsafe

    with tempfile.TemporaryDirectory(prefix="aegis-smoke-team-") as temporary:
        root = Path(temporary)
        repo, home = root / "repo", root / "home"
        (repo / ".aegis").mkdir(parents=True)
        home.mkdir()
        env = _home_env(str(home), drop=("PYTHONPATH", "AEGIS_WORKSPACE", "CLAUDE_CONFIG_DIR", "CODEX_HOME"))
        for args in (("init", "-q", "-b", "main"),
                     ("-c", "user.name=Smoke", "-c", "user.email=smoke@example.test", "-c", "commit.gpgsign=false",
                      "commit", "--allow-empty", "-qm", "base")):
            _run([gitsafe.git_executable(), *args], cwd=repo, env=env, check=True,
                           capture_output=True, timeout=30)
        cli = [sys.executable, _SUBPROC_FLAG, "-m", "aegis_cli.cli", "team"]
        claim = _run([*cli, "claim", "docs", "--paths", "docs/**", "--branch", "main", "--json"],
                               cwd=repo, env=env, capture_output=True, text=True, timeout=60)
        if claim.returncode != 0:
            fail(f"installed team claim failed: {_facts('stdout', claim.stdout)}; {_facts('stderr', claim.stderr)}")
        _expect_identifier(_json_output(claim).get("schema"), "aegis.team.claim/v1", "installed team claim schema")
        before = (gitsafe.list_refs(repo, "refs/aegis/lanes"), events.read(repo).rows)
        report = _run([*cli, "status", "--check", "--json"], cwd=repo, env=env,
                                capture_output=True, text=True, timeout=60)
        if report.returncode != 0:
            fail(f"installed team status failed: {_facts('stdout', report.stdout)}; {_facts('stderr', report.stderr)}")
        value = _json_output(report)
        lanes = value.get("lanes")
        _expect_identifier(value.get("schema"), "aegis.team.status/v1", "installed team status schema")
        if (not isinstance(lanes, list) or len(lanes) != 1 or not isinstance(lanes[0], dict)
                or not isinstance(lanes[0].get("check"), dict)):
            fail(f"installed team status invalid lanes/check shape: {_facts('result', lanes)}")
        _expect_identifier(lanes[0]["check"].get("status"), "pass", "installed team status check.status")
        _expect_identifier(lanes[0].get("tip"), gitsafe.head_commit(repo), "installed team status tip", expected_label="workspace-tip")
        if before != (gitsafe.list_refs(repo, "refs/aegis/lanes"), events.read(repo).rows):
            fail("installed team status changed refs or events")
    check_module_origins(("aegis_core.team_status",))
    print("ok  installed team status --check --json (read-only lane observation)")


def check_doctor(ws):
    """`aegis doctor --json` imports the whole doctor family from the wheel; a fresh HOME and an empty
    PATH keep the machine's hosts, git and gh out of it. A failed check (exit 1) is fine, a crash is not."""
    home = tempfile.mkdtemp(prefix="aegis-smoke-home-")
    env = _home_env(home, drop=("PYTHONPATH", "CLAUDE_CONFIG_DIR", "CODEX_HOME"))
    env["PATH"] = home
    # -E would ignore the pinned PYTHONUSERBASE; the child runs in the fresh workspace with
    # PYTHONPATH dropped, so nothing there can shadow site-packages.
    flags = [] if _SUBPROC_FLAG == "-E" else [_SUBPROC_FLAG]
    proc = _run([sys.executable, *flags, "-m", "aegis_cli.cli", "doctor", "--json", "--workspace", ws],
                          capture_output=True, text=True, timeout=120, cwd=ws, env=env)
    if proc.returncode not in (0, 1):
        fail(f"aegis doctor --json exited {proc.returncode}: {_facts('stderr', proc.stderr)}")
    payload = _json_output(proc)
    _expect_identifier(payload.get("schema"), "aegis.doctor/v1", "aegis doctor --json schema")
    if not isinstance(payload.get("hosts"), list):
        fail(f"aegis doctor --json hosts must be a list: {_facts('hosts', payload.get('hosts'))}")
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
    proc = _run([sys.executable, _SUBPROC_FLAG, "-m", "aegis_mcp"], input=requests,
                          capture_output=True, text=True, timeout=60, cwd=ws, env=env)
    lines = _mcp_responses(proc, 3, "MCP")
    tools = _mcp_result(lines[1], "MCP tools/list", proc.stderr).get("tools")
    check_mcp_tools(tools, "MCP tools/list")
    content = _mcp_result(lines[2], "MCP aegis_list_rules", proc.stderr).get("content")
    if (not isinstance(content, list) or not content or not isinstance(content[0], dict)
            or not isinstance(content[0].get("text"), str)):
        fail(f"MCP aegis_list_rules returned invalid content; {_facts('stderr', proc.stderr)}")
    try:
        payload = json.loads(content[0]["text"])
    except (ValueError, RecursionError) as exc:
        fail(f"MCP aegis_list_rules returned invalid JSON; exception={_exception_class(exc)}; {_facts('stderr', proc.stderr)}")
    rules = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(rules, list):
        fail(f"MCP aegis_list_rules returned no rules list: {_facts('rules', payload)}")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or not isinstance(rule.get("_name"), str):
            fail(f"MCP aegis_list_rules invalid rule entry at index {index}: expected a dict with a string _name")
        if len(rule["_name"]) > MAX_MCP_NAME or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", rule["_name"]):
            fail(f"MCP aegis_list_rules invalid rule name at index {index}: expected [A-Za-z0-9_.-]{{1,128}}; "
                 f"{_identifier_facts(rule['_name'], 'trap-smoke')}")
    if "trap-smoke" not in {rule["_name"] for rule in rules}:
        fail(f"MCP aegis_list_rules did not see the workspace rule: {_identifier_list([rule['_name'] for rule in rules], 'trap-smoke')}")
    print(f"ok  aegis_mcp initialize / tools/list ({len(EXPECTED_MCP_TOOLS)} tools) / aegis_list_rules")


def check_governance_fitness(ws):
    from aegis_sdk.governance import Governance
    try:
        result = Governance(project_root=ws).fitness_landscape()
    except (OSError, ValueError, RuntimeError) as exc:
        fail(f"governance fitness_landscape failed: exception={_exception_class(exc)}")
    expected = {"rule": "trap-smoke", "type": "trap", "triggers": 0, "tp": 0, "fp": 0, "score": 0.0}
    if (not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict)
            or any(result[0].get(key) != value for key, value in expected.items())):
        fail(f"governance fitness_landscape invalid workspace fitness: {_facts('result', result)}")
    print("ok  governance (Governance.fitness_landscape)")


def check_full_rule_preset(ws):
    """Prove the wheel contains the full rules, not only starter rules."""
    from pathlib import Path
    from aegis_cli.init import install_rules

    target = Path(ws) / "full-rules"
    installed = install_rules(target, preset="full")
    files = sorted(target.glob("*.md"))
    if len(installed) < FULL_PRESET_RULES or len(files) != len(installed):
        fail(f"full rule preset is incomplete: {_facts('installed', installed)}, {_facts('files', [os.fspath(path) for path in files])}")
    leaked = sorted(set(installed) & set(UNSHIPPED_RULES))
    if leaked:
        fail(f"full rule preset ships rules that must stay unshipped: {_facts('rules', leaked)}")
    print(f"ok  packaged full rule preset ({len(installed)} rules)")


def check_packaged_rules_and_skills(ws):
    """Prove the wheel packages rules/ and skills/ inside aegis_core/_data (seen through
    init's one locator), and installs no top-level package other than the aegis_* ones."""
    import importlib.metadata
    import importlib.resources
    from pathlib import Path
    from aegis_cli.init import packaged_active_rules, packaged_dir, packaged_rules
    from aegis_mcp.registry import TOOL_DEFINITIONS

    check_mcp_tools(TOOL_DEFINITIONS, "TOOL_DEFINITIONS")
    dist = importlib.metadata.distribution("aegis-guardrails")
    top_level = sorted((dist.read_text("top_level.txt") or "").split())
    if top_level != sorted(PACKAGES):
        fail(f"the wheel installs top-level packages {_facts('packages', top_level)}, expected only {sorted(PACKAGES)!r}")
    # RECORD paths: the packages, the .dist-info, and console scripts outside site-packages ("..").
    tops = {f.parts[0] for f in dist.files or () if f.parts}
    foreign = sorted(t for t in tops if t not in PACKAGES and t != ".." and not t.endswith(".dist-info"))
    if foreign:
        fail(f"the wheel installs files outside the aegis_* packages: {_facts('foreign', foreign)}")
    data = Path(str(importlib.resources.files("aegis_core"))) / "_data"
    for name in ("rules", "skills"):
        if packaged_dir(name) != data / name:
            fail(f"packaged_dir({name!r}) is {_facts('path', os.fspath(packaged_dir(name)))}, not the wheel's {_facts('path', os.fspath(data / name))}")
    rules = packaged_rules()
    if len(rules) < FULL_PRESET_RULES:
        fail(f"packaged_rules() found only {len(rules)} rules in the wheel: {_facts('rules', sorted(rules))}")
    active = packaged_active_rules()
    if sorted(active) != sorted(ACTIVE_STARTERS) or any(p.parent != data / "rules" for p in active.values()):
        fail(f"the wheel's active starter rules are {_facts('active', {key: os.fspath(value) for key, value in active.items()})}, "
             f"expected {ACTIVE_STARTERS!r} in {_facts('path', os.fspath(data / 'rules'))}")
    skills = sorted(d.name for d in (data / "skills").iterdir() if (d / "SKILL.md").is_file())
    if len(skills) < 15:
        fail(f"the wheel packages only {len(skills)} skills: {_facts('skills', skills)}")
    print(f"ok  packaged rules and skills in aegis_core/_data ({len(rules)} rules, {len(skills)} skills, "
          f"{len(EXPECTED_MCP_TOOLS)} MCP tools; top level {', '.join(sorted(PACKAGES))})")


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
        fail(f"the fallback MCP launcher is {_facts('command', commands['fallback'])}, not this interpreter in isolated mode")
    for kind, command in commands.items():
        context = f"the {kind} MCP launcher {_facts('command', command)}"
        risk = launch_risk(command)
        if risk:
            fail(f"{context} is unsafe: {_facts('risk', risk)}")
        # json: a standard-library module the server imports, which only -I (or a console
        # script, whose own directory leads sys.path) keeps the start directory from shadowing.
        repo, marker = _planted_repo(("aegis_mcp", "aegis_core"), modules=("json",))
        proc = _run(command, input=requests, capture_output=True, text=True, timeout=60,
                              cwd=repo, env=env)
        if os.path.exists(marker):
            fail(f"{context} imported planted code from its start directory")
        lines = _mcp_responses(proc, 2, context)
        tools = _mcp_result(lines[1], f"{context} tools/list", proc.stderr).get("tools")
        check_mcp_tools(tools, context)
        print(f"ok  {kind} MCP launcher ignores planted packages: {_facts('command', command)}")


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
    _run(["git", "init", "-q"], cwd=repo, check=True, env=env, timeout=30, capture_output=True)
    # Not isolated on purpose: the current directory is first on sys.path, as it was for
    # the README's old `python3 -m aegis_cli` advice.
    proc = _run([sys.executable, "-m", "aegis_cli.cli", "init", "--yes", "--no-hooks", "--rules", "full"],
                          capture_output=True, text=True, timeout=120, cwd=repo, env=env)
    if proc.returncode != 0:
        fail(f"aegis init in a repository with its own rules/ exited {proc.returncode}: {_facts('stderr', proc.stderr)}")
    seeded = _directory_names(os.path.join(repo, ".aegis", "rules", "personas"))
    if os.path.exists(marker) or "pricing.md" in seeded or len(seeded) != FULL_PRESET_RULES:
        fail(f"aegis init read the repository's own rules/: seeded {_name_list(seeded)}, "
             f"planted code ran: {os.path.exists(marker)}")
    active = _directory_names(os.path.join(repo, ".aegis", "rules", "invariants"))
    if active != [f"{name}.md" for name in sorted(ACTIVE_STARTERS)]:
        fail(f"aegis init seeded the active starters {_name_list(active)}, expected {ACTIVE_STARTERS!r}")
    print(f"ok  aegis init in a repository with its own rules/ seeds the wheel's {len(seeded)} rules "
          f"and {len(active)} active one")


def check_init_dry_run(ws):
    """`aegis init --dry-run --json` plans from the wheel and writes nothing."""
    repo = tempfile.mkdtemp(prefix="aegis-smoke-init-")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = _run([sys.executable, _SUBPROC_FLAG, "-m", "aegis_cli.cli", "--json", "init",
                           "--workspace", repo, "--dry-run", "--rules", "full"],
                          capture_output=True, text=True, timeout=60, cwd=ws, env=env)
    if proc.returncode != 0:
        fail(f"aegis init --dry-run exited {proc.returncode}: {_facts('stderr', proc.stderr)}")
    payload = _json_output(proc)
    _expect_identifier(payload.get("source"), "aegis init", "aegis init --dry-run source")
    _expect_identifier(payload.get("status"), "ok", "aegis init --dry-run status")
    if not payload.get("dry_run"):
        fail(f"aegis init --dry-run dry_run must be true: {_facts('dry-run', payload.get('dry_run'))}")
    if not {"aegis_version", "checked_at", "scope", "actions"} <= set(payload):
        fail(f"aegis init --json lacks provenance keys: {_facts('provenance', proc.stdout)}")
    entries = _directory_names(repo)
    if entries:
        fail(f"aegis init --dry-run wrote {_name_list(entries)}")
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
    check_team_status()
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
    try:
        main()
    except Exception as exc:
        fail(f"smoke check raised exception={_exception_class(exc)}")

