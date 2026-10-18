"""docs/reference.md is generated from the contract snapshots and must match them (D18, AD-6).

The chain is: the live parser and tools/list -> cli_tree.json and mcp_tools.json (checked by
test_cli_contract and test_mcp_contract) -> docs/reference.md (checked here). After an
intended surface change, regenerate both snapshots, then:

    PYTHONPATH=. python3 tests/contract/gen_reference.py --write
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

import pytest

CONTRACT = Path(__file__).resolve().parent
REFERENCE = CONTRACT.parents[1] / "docs" / "reference.md"
COMMON = {"-h", "--help", "--json", "--plain", "--workspace"}


def _load_generator():
    spec = importlib.util.spec_from_file_location("aegis_gen_reference", CONTRACT / "gen_reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    return _load_generator()


@pytest.fixture(scope="module")
def snapshots() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    cli = json.loads((CONTRACT / "cli_tree.json").read_text(encoding="utf-8"))
    mcp = json.loads((CONTRACT / "mcp_tools.json").read_text(encoding="utf-8"))
    return cli, mcp


def _commands(node: Dict[str, Any], path: List[str]) -> Iterator[Tuple[List[str], Dict[str, Any]]]:
    for name, child in node.get("commands", {}).items():
        yield path + [name], child
        yield from _commands(child, path + [name])


def _section(text: str, heading: str) -> str:
    start = text.index(heading + "\n")
    following = text.find("\n### ", start + len(heading))
    return text[start: following if following != -1 else len(text)]


def test_the_reference_is_up_to_date(gen, snapshots):
    assert REFERENCE.is_file(), "docs/reference.md is missing: run tests/contract/gen_reference.py --write"
    assert REFERENCE.read_text(encoding="utf-8") == gen.render(*snapshots), (
        "docs/reference.md is stale; regenerate it with\n"
        "    PYTHONPATH=. python3 tests/contract/gen_reference.py --write"
    )


def test_every_command_flag_default_and_help_is_documented(gen, snapshots):
    cli, _ = snapshots
    text = gen.render(*snapshots)
    paths = list(_commands(cli["parser"], []))
    assert paths, "the CLI snapshot has no commands"
    for path, node in paths:
        section = _section(text, f"### `aegis {' '.join(path)}`")
        assert node["help"] and node["help"] in section, path
        for arg in node["arguments"]:
            if set(arg["flags"]) & COMMON or arg["kind"] == "parsers" or arg["help"] == "==SUPPRESS==":
                continue  # hidden flags only exist to name their v4 replacement
            name = ", ".join(f"`{f}`" for f in arg["flags"]) or f"`{arg['dest']}`"
            row = next((line for line in section.splitlines() if line.startswith(f"| {name} |")), None)
            assert row is not None, (path, name)
            assert arg["help"].replace("|", "\\|") in row, (path, name)
            if arg["default"] not in (None, False, "==SUPPRESS=="):
                assert f"`{json.dumps(arg['default'])}`" in row, (path, name)
            for choice in arg.get("choices") or []:
                assert f"`{choice}`" in row, (path, name, choice)


def test_every_global_option_and_removed_command_is_documented(gen, snapshots):
    cli, _ = snapshots
    text = gen.render(*snapshots)
    for arg in cli["parser"]["arguments"]:
        for flag in arg["flags"]:
            assert f"`{flag}`" in _section(text, "### Global options"), flag
    for name, pointer in cli["removed_commands"].items():
        assert f"| `aegis {name}` | {pointer} |" in text, name


def test_every_mcp_tool_and_schema_is_documented(gen, snapshots):
    _, mcp = snapshots
    text = gen.render(*snapshots)
    assert mcp["tools"], "the MCP snapshot has no tools"
    for tool in mcp["tools"]:
        section = _section(text, f"### `{tool['name']}`")
        assert tool["description"] in section
        assert tool["annotations"]["title"] in section
        for prop, schema in tool["inputSchema"].get("properties", {}).items():
            assert f"| `{prop}` |" in section, (tool["name"], prop)
            assert schema.get("description", "") in section, (tool["name"], prop)
        # The full schema, exactly as tools/list sends it.
        assert json.dumps(tool["inputSchema"], indent=2, ensure_ascii=False) in section
        assert json.dumps(tool["outputSchema"], indent=2, ensure_ascii=False) in section


def test_render_escapes_table_cells(gen):
    cli = {
        "parser": {"arguments": [], "description": "d", "commands": {
            "x": {"help": "a | b", "description": None, "aliases": [], "arguments": [
                {"kind": "store", "flags": ["--y"], "dest": "y", "default": None, "nargs": None,
                 "required": False, "help": "one | two\nthree", "metavar": None},
            ]},
        }},
        "registry": [{"name": "x", "aliases": [], "category": "Workflow", "help": "a | b"}],
        "removed_commands": {},
    }
    text = gen.render(cli, {"tools": []})
    assert "| `--y` | `Y` |  | one \\| two three |" in text
