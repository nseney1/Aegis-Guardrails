"""Integration regressions for the consumers of the one rule loader (SDK, MCP list, create prompt)."""
import json
import os

import pytest


CELL_TEMPLATE = (
    "---\n"
    "id: {cell_id}\n"
    "type: invariant\n"
    "hypothesis: {hypothesis}\n"
    "target_paths:\n"
    "  - src/*.py\n"
    "---\n"
    "Body for {cell_id}.\n"
)


def _write_cell(workspace, cell_id="alpha", hypothesis="first"):
    path = workspace / ".aegis" / "rules" / "invariants" / f"{cell_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        CELL_TEMPLATE.format(cell_id=cell_id, hypothesis=hypothesis),
        encoding="utf-8",
    )
    return path


def _symlinked_cell_directory(tmp_path):
    workspace = tmp_path / "workspace"
    cells_dir = workspace / ".aegis" / "rules"
    cells_dir.mkdir(parents=True)
    outside = tmp_path / "outside"
    _write_cell(outside, "outside", "must not escape")
    link = cells_dir / "invariants"
    try:
        link.symlink_to(outside / ".aegis" / "rules" / "invariants", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    return workspace


def test_sdk_and_mcp_direct_list_reject_symlinked_directory(tmp_path, monkeypatch):
    from aegis_sdk.governance import Governance
    import aegis_mcp.tools as tools

    workspace = _symlinked_cell_directory(tmp_path)

    with pytest.raises(RuntimeError, match="rule inventory.*symlink"):
        Governance(project_root=workspace).list_rules()

    monkeypatch.chdir(workspace)
    result = tools.execute_tool("aegis_list_rules", {})
    assert result["status"] == "FAIL"
    assert "symlink" in result["error"]


def test_mcp_transport_marks_inventory_failure_as_error(tmp_path, monkeypatch):
    import aegis_mcp.server as server

    workspace = _symlinked_cell_directory(tmp_path)
    monkeypatch.setattr(server, "_session_id", "inventory-test")
    monkeypatch.setattr(server, "_canonical_workspace", str(workspace))

    response = server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "aegis_list_rules", "arguments": {}},
    })

    assert response["result"]["isError"] is True
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["status"] == "FAIL"
    assert "symlink" in payload["error"]


def test_same_size_restored_mtime_edit_is_visible_to_sdk_and_mcp(tmp_path, monkeypatch):
    from aegis_sdk.governance import Governance
    import aegis_mcp.tools as tools

    cell_path = _write_cell(tmp_path, "alpha", "first")
    governance = Governance(project_root=tmp_path)
    assert governance.list_rules()[0]["id"] == "alpha"

    monkeypatch.chdir(tmp_path)
    assert tools.execute_tool("aegis_list_rules", {})["rules"][0]["id"] == "alpha"

    original_stat = cell_path.stat()
    original = cell_path.read_text(encoding="utf-8")
    changed = original.replace("alpha", "bravo")
    assert len(changed.encode("utf-8")) == len(original.encode("utf-8"))
    cell_path.write_text(changed, encoding="utf-8")
    os.utime(cell_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    assert governance.list_rules()[0]["id"] == "bravo"
    assert tools.execute_tool("aegis_list_rules", {})["rules"][0]["id"] == "bravo"


def test_invalid_utf8_is_exposed_as_diagnostic_by_sdk_and_mcp(tmp_path, monkeypatch):
    from aegis_sdk.governance import Governance
    import aegis_mcp.tools as tools

    bad_path = tmp_path / ".aegis" / "rules" / "invariants" / "bad.md"
    bad_path.parent.mkdir(parents=True)
    bad_path.write_bytes(b"---\nid: bad\n---\n\xff\n")

    sdk_records = Governance(project_root=tmp_path).list_rules()
    assert len(sdk_records) == 1
    assert sdk_records[0]["_name"] == "bad"
    assert sdk_records[0]["_path"] == ".aegis/rules/invariants/bad.md"
    assert "UTF-8" in sdk_records[0]["_error"]

    monkeypatch.chdir(tmp_path)
    mcp_records = tools.execute_tool("aegis_list_rules", {})["rules"]
    assert len(mcp_records) == 1
    assert mcp_records[0]["_name"] == "bad"
    assert mcp_records[0]["_path"] == ".aegis/rules/invariants/bad.md"
    assert "UTF-8" in mcp_records[0]["_error"]


def test_create_prompt_uses_inventory_bytes_without_reopen(tmp_path, monkeypatch):
    from aegis_core.rule_inventory import inventory_rules
    import aegis_core.rules as rules
    import aegis_mcp.handlers.governance as governance

    cell_path = _write_cell(tmp_path, "snapshot", "captured hypothesis")
    snapshot = inventory_rules(str(tmp_path))
    cell_path.write_text(
        CELL_TEMPLATE.format(cell_id="mutatedx", hypothesis="changed hypothesis"),
        encoding="utf-8",
    )
    monkeypatch.setattr(rules, "inventory_rules", lambda workspace: snapshot)

    prompt = governance.build_rule_create_prompt(
        "new concern", args={"workspace": str(tmp_path)}
    )

    assert "captured hypothesis" in prompt
    assert "changed hypothesis" not in prompt


def test_create_prompt_rejects_outside_symlinked_example(tmp_path):
    from aegis_core.rule_inventory import RuleInventoryError
    from aegis_mcp.handlers.governance import build_rule_create_prompt

    workspace = _symlinked_cell_directory(tmp_path)
    with pytest.raises(RuleInventoryError, match="symlink"):
        build_rule_create_prompt("new concern", args={"workspace": str(workspace)})


def test_mcp_list_parses_inventory_with_the_stdlib_parser(tmp_path, monkeypatch):
    import aegis_mcp.tools as tools

    _write_cell(tmp_path, "fallback", "stdlib parser")
    monkeypatch.chdir(tmp_path)

    rules = tools.execute_tool("aegis_list_rules", {})["rules"]
    assert rules[0]["id"] == "fallback"
    assert rules[0]["target_paths"] == ["src/*.py"]
    assert rules[0]["_path"] == ".aegis/rules/invariants/fallback.md"
