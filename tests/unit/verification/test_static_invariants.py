"""Static regression tests — one per audited finding that can be proven
without running an install. Each test names the finding it guards.

These are cheap and require no third-party packages, so they can gate every
commit.
"""
import json
import os
import re
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, iter_source_files, read, run

# ── AEGIS-C03 / cross-OS: Bash 4 constructs break macOS Bash 3.2 ──────────

BASH4_PATTERNS = {
    "${var^} / ${var^^} case conversion": re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*\^\^?\}'),
    "${var,,} case conversion": re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*,,?\}'),
    "declare -A associative array": re.compile(r'\bdeclare\s+-A\b'),
    "typeset -A associative array": re.compile(r'\btypeset\s+-A\b'),
    "mapfile": re.compile(r'\bmapfile\b'),
    "readarray": re.compile(r'\breadarray\b'),
    "local -n nameref": re.compile(r'\blocal\s+-n\b'),
    "&>> append redirect": re.compile(r'&>>'),
}


def _shell_sources():
    """(name, text) of every shell script Aegis ships or writes: the repo-root
    `aegis` wrapper and the git pre-commit block `aegis hook install` writes."""
    from aegis_cli.hooks.management import generate_hook_block

    sources = [
        ("aegis", read(os.path.join(REPO_ROOT, "aegis"))),
        ("pre-commit hook block", generate_hook_block("/usr/bin/python3", import_root="/opt/site")),
    ]
    assert all(text.strip() for _, text in sources)
    return sources


@pytest.mark.parametrize("label,pattern", sorted(BASH4_PATTERNS.items()))
def test_no_bash4_only_constructs(label, pattern):
    """AEGIS-C03: macOS ships Bash 3.2; these constructs raise 'bad substitution'
    at expansion time, which `bash -n` cannot detect."""
    offenders = []
    for name, text in _shell_sources():
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if pattern.search(line):
                offenders.append(f"{name}:{lineno}: {line.strip()}")
    assert not offenders, f"Bash 4+ construct ({label}) found:\n" + "\n".join(offenders)


# ── AEGIS-C02: escaped quotes inside command substitution ────────────────

def test_no_escaped_quotes_in_command_substitution():
    """AEGIS-C02: `cd \\"$(dirname ...)\\"` passes literal quote characters, so the
    script dies at line 4 before sourcing anything. Killed the PreToolUse gate."""
    offenders = []
    for name, text in _shell_sources():
        for lineno, line in enumerate(text.splitlines(), 1):
            # Only flag the specific pattern that broke BASH_SOURCE resolution.
            # Legitimate uses like sed 's/"/\\"/g' inside $() are fine.
            if 'BASH_SOURCE' in line and '\\"' in line and "$(" in line:
                offenders.append(f"{name}:{lineno}: {line.strip()}")
    assert not offenders, (
        "Escaped quotes inside command substitution:\n" + "\n".join(offenders)
    )


# ── AEGIS-H04: unencoded file I/O corrupts on non-UTF-8 locales ──────────

OPEN_CALL = re.compile(r'(?<!\.)\bopen\s*\(')
BINARY_MODE = re.compile(r'''['"][rwxa+t]*b[rwxa+t]*['"]''')


def test_all_text_open_calls_specify_encoding():
    """AEGIS-H04: requires-python >=3.9 means PEP 686 does not apply, so Windows
    uses the locale codepage. Rule files contain characters cp1252 cannot encode."""
    offenders = []
    for sub in ("aegis_mcp", "aegis_sdk", "aegis_mcp", "aegis_sdk"):
        root = os.path.join(REPO_ROOT, sub)
        if not os.path.isdir(root):
            continue
        for path in iter_source_files(root, (".py",)):
            for lineno, line in enumerate(read(path).splitlines(), 1):
                if not OPEN_CALL.search(line):
                    continue
                if "encoding=" in line or BINARY_MODE.search(line):
                    continue
                if "makedirs" in line or line.lstrip().startswith("#"):
                    continue
                rel = os.path.relpath(path, REPO_ROOT)
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "open() without encoding= (add encoding=\"utf-8\"):\n" + "\n".join(offenders)
    )


# ── AEGIS-M01: JSON must not contain Infinity ────────────────────────────

def test_no_infinity_emitted_in_json_payloads():
    """AEGIS-M01: json.dumps(float('inf')) emits bare `Infinity`, which RFC 8259
    forbids; strict non-Python MCP clients reject the frame."""
    offenders = []
    for sub in ("aegis_mcp", "aegis_sdk", "aegis_mcp", "aegis_sdk"):
        root = os.path.join(REPO_ROOT, sub)
        if not os.path.isdir(root):
            continue
        for path in iter_source_files(root, (".py",)):
            for lineno, line in enumerate(read(path).splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if re.search(r"float\(\s*['\"]inf['\"]\s*\)", line):
                    rel = os.path.relpath(path, REPO_ROOT)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "float('inf') reaches JSON payloads:\n" + "\n".join(offenders)
    )


# ── AEGIS-C01: the MCP server must start without third-party packages ─────
# (no runtime import outside the standard library: tests/contract/test_import_boundary.py)

def test_mcp_server_answers_jsonrpc_without_pyyaml(tmp_path):
    """AEGIS-C01 end to end: initialize + tools/list must return valid JSON on a
    bare interpreter. Regression: ModuleNotFoundError, exit 1, 0 bytes stdout."""
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    requests = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
    )
    env = {"PYTHONPATH": REPO_ROOT}
    mcp_pkg = "aegis_mcp" if os.path.exists(os.path.join(REPO_ROOT, "aegis_mcp")) else "aegis_mcp"
    proc = subprocess.run(
        [sys.executable, "-m", mcp_pkg],
        cwd=str(tmp_path), input=requests, capture_output=True, text=True,
        timeout=120, env={**os.environ, **env},
    )
    assert proc.returncode == 0, f"server exited {proc.returncode}: {proc.stderr[:600]}"
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, f"server produced no stdout. stderr: {proc.stderr[:600]}"
    for ln in lines:
        json.loads(ln)  # every framed response must be valid JSON
    first = json.loads(lines[0])
    assert first["result"]["serverInfo"]["name"] in ("aegis-mcp", "aegis-mcp")
    tools = json.loads(lines[1])["result"]["tools"]
    assert len(tools) >= 1


# ── AEGIS-M03: failure paths must exit nonzero ───────────────────────────

def test_cli_exits_nonzero_on_unknown_command():
    """AEGIS-M03: main() returned None on the unknown-command path, so the
    console script produced exit 0 while printing an error."""
    proc = run([sys.executable, '-m', 'aegis_cli.cli',
                'definitely-not-a-command'])
    assert proc.returncode != 0, (
        f"CLI reported an unknown command but exited 0:\n{proc.stdout}{proc.stderr}"
    )


# ── Static Import & Documentation Integrity ─────────────────────────────

def test_no_undefined_names_in_python_code():
    """Verify zero F821 undefined names across aegis_core, aegis_cli, aegis_sdk."""
    import shutil
    ruff_bin = shutil.which("ruff") or os.path.expanduser("~/.local/bin/ruff")
    if not os.path.exists(ruff_bin):
        pytest.skip("ruff binary not found")
    targets = [
        d for d in ("aegis_core", "aegis_cli", "aegis_sdk", "aegis_mcp", "aegis_core", "aegis_cli", "aegis_sdk", "aegis_mcp")
        if os.path.isdir(os.path.join(REPO_ROOT, d))
    ]
    proc = subprocess.run(
        [ruff_bin, "check", "--select", "F821", *targets],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"Found undefined names (F821):\n{proc.stdout}"


def test_no_dangling_aegis_imports():
    """Every `from aegis_x import name` resolves, including lazy imports inside functions.

    A cut (v4 D14 removed inference_provider.resolve_provider) leaves function-level
    imports that only fail when that code path runs, or that an `except ImportError`
    quietly turns into a fallback. ruff F821 cannot see either.
    """
    import ast
    import importlib

    dangling = []
    for pkg in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in sorted(iter_source_files(os.path.join(REPO_ROOT, pkg), (".py",))):
            rel = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
            tree = ast.parse(read(path), filename=rel)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.ImportFrom) and node.level == 0 and node.module):
                    continue
                if not node.module.split(".")[0].startswith("aegis_"):
                    continue
                module = importlib.import_module(node.module)
                for alias in node.names:
                    if alias.name == "*" or hasattr(module, alias.name):
                        continue
                    try:
                        importlib.import_module(f"{node.module}.{alias.name}")
                    except ModuleNotFoundError:
                        dangling.append(f"{rel}:{node.lineno} {node.module}.{alias.name}")
    assert dangling == []
