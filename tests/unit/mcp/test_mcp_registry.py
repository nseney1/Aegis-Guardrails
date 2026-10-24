"""MCP schemas and governance: the rule inventory the MCP handlers list, and the rule-creation prompt."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from aegis_core import sync
from aegis_core._version import __version__
from aegis_core.workspace.base import Workspace
from aegis_mcp.handlers.governance import build_rule_create_prompt, list_rules


def _rule(root: Path, folder: str, rule_id: str, rule_type: str, extra: str = "", body: str = "body\n") -> Path:
    path = root / ".aegis" / "rules" / folder / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    # write_bytes, not write_text: the server quotes raw bytes, and text mode would write CRLF on Windows
    path.write_bytes(f"---\nid: {rule_id}\ntype: {rule_type}\nhypothesis: h\n{extra}---\n{body}".encode("utf-8"))
    return path


def _ids(records: list) -> list:
    return sorted(record["id"] for record in records)


def test_a_type_filter_narrows_both_the_rules_and_the_stale_rules(tmp_path: Path):
    edited = [
        _rule(tmp_path, "traps", "trap-a", "trap"),
        _rule(tmp_path, "invariants", "inv-a", "invariant", "enforcement: gate\n"),
    ]
    sync.sync(tmp_path)
    for path in edited:  # both now differ from what sync recorded
        path.write_text(path.read_text(encoding="utf-8") + "more\n", encoding="utf-8")
    ws = Workspace.confine(tmp_path)

    every = list_rules(ws)
    assert (_ids(every["rules"]), _ids(every["stale_rules"])) == (["inv-a", "trap-a"], ["inv-a", "trap-a"])
    invariants = list_rules(ws, rule_type="invariant")
    assert (_ids(invariants["rules"]), _ids(invariants["stale_rules"])) == (["inv-a"], ["inv-a"])


def test_an_expired_rule_is_still_listed_and_marked_expired(tmp_path: Path):
    _rule(tmp_path, "traps", "retired", "trap", "expired_at: 2026-01-01T00:00:00Z\n")
    _rule(tmp_path, "traps", "live", "trap")

    records = {record["id"]: record for record in list_rules(Workspace.confine(tmp_path))["rules"]}

    assert records["retired"]["_expired"] is True
    assert "_expired" not in records["live"]


def test_the_creation_prompt_quotes_at_most_three_rules_cut_at_500_characters(tmp_path: Path):
    texts = [
        _rule(tmp_path, "traps", f"rule-{letter}", "trap", body=letter * 600 + "\n").read_text(encoding="utf-8")
        for letter in "abcd"
    ]

    prompt = build_rule_create_prompt("Flag unpinned dependencies", args={"workspace": str(tmp_path)})

    assert sum(text[:500] in prompt for text in texts) == 3
    assert not any(text[:501] in prompt for text in texts)


def test_stdio_initialize_tools_list_and_unknown_tool_preserve_wire_bytes(tmp_path: Path):
    """Golden guard for the schema/handler move, including the protocol error path."""
    repo = Path(__file__).resolve().parents[3]
    home = tmp_path / "home"
    home.mkdir()
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("AEGIS_") and key != "CLAUDE_PROJECT_DIR"}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               PYTHONPATH=str(repo) + os.pathsep + env.get("PYTHONPATH", ""))
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "not-an-aegis-tool", "arguments": {}}},
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "aegis_mcp"], cwd=home, env=env,
        input=b"".join((json.dumps(request) + "\n").encode("utf-8") for request in requests),
        capture_output=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", errors="replace")
    expected = [
        {"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": "aegis-mcp", "version": __version__},
            "instructions": (
                "Aegis serves this repository's coding rules just in time. Before editing files, call "
                "aegis_scan with the paths you plan to change and follow the rules it returns. After "
                "verifying a change with tests or checks, call aegis_report_outcome with the rules you "
                "used and the outcome. Rules live in .aegis/rules/; aegis check enforces the deterministic "
                "ones before commit and in CI."
            ),
        }},
        {"jsonrpc": "2.0", "id": 2, "result": json.loads(
            (repo / "tests/contract/mcp_tools.json").read_text(encoding="utf-8"))},
        {"jsonrpc": "2.0", "id": 3, "error": {
            "code": -32602, "message": "Unknown tool: not-an-aegis-tool",
        }},
    ]
    # A native Windows stdout uses CRLF; every JSON frame's bytes remain exact.
    assert proc.stdout.splitlines() == [json.dumps(frame).encode("utf-8") for frame in expected]
    assert not list(home.iterdir())


def test_the_server_imports_resolve_for_layer1():
    from aegis_core.verification import import_guard

    repo = Path(__file__).resolve().parents[3]
    result = import_guard.check(str(repo / "aegis_mcp/server.py"), project_root=str(repo))
    assert result.verdict, result.detail


def test_mcp_schema_coverage_routes_to_its_wire_guard_only_inside_aegis(tmp_path: Path):
    from aegis_core.verification.checkpoint_checks import check_test_coverage

    for package, expected in (
        ("aegis_mcp", []),
        ("mylib", ["Missing test file for schemas.py: expected tests/test_schemas.py"]),
    ):
        root = tmp_path / package
        source = root / package / "schemas.py"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"TOOL_DEFINITIONS = []\n")
        test = root / "tests/unit/mcp/test_mcp_registry.py"
        test.parent.mkdir(parents=True)
        test.write_bytes(b"def test_wire_bytes():\n    pass\n")

        assert [issue["message"] for issue in check_test_coverage(root)] == expected
