"""Render docs/reference.md from the contract snapshots (ADR 0005 D18, AD-6).

The reference is a pure function of tests/contract/cli_tree.json and
tests/contract/mcp_tools.json, which the contract tests keep equal to the live parser
and tools/list. Nothing here imports Aegis, so the page cannot describe a surface the
snapshots do not pin. From the repository root:

    PYTHONPATH=. python3 tests/contract/gen_reference.py --write   # regenerate
    PYTHONPATH=. python3 tests/contract/gen_reference.py --check   # exit 1 when stale
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

CONTRACT = Path(__file__).resolve().parent
REFERENCE = CONTRACT.parents[1] / "docs" / "reference.md"
SUPPRESS = "==SUPPRESS=="
# Options every command inherits from the top-level parser (documented once).
COMMON_FLAGS = frozenset({"-h", "--help", "--json", "--plain", "--workspace"})
FLAG_KINDS = frozenset({"store_true", "store_false", "store_const", "append_const", "count", "help", "version"})
# aegis_cli.base.CommandCategory, in the order `aegis --help` lists them; others sort last.
CATEGORY_ORDER = ("Setup & Environment", "Daily Workflow & Verification", "Rule Evolution & Intelligence", "Plumbing")

HEADER = """\
# Aegis reference

Every `aegis` command and option, and every tool the `aegis-mcp` server offers, with
its input schema. This page is generated from the contract snapshots
(`tests/contract/cli_tree.json` and `tests/contract/mcp_tools.json`) by
`tests/contract/gen_reference.py`, and a test fails when it drifts from them. Do not
edit it by hand: change the code, then regenerate the snapshots and this page:

```
PYTHONPATH=. python3 tests/contract/test_cli_contract.py --write
PYTHONPATH=. python3 tests/contract/test_mcp_contract.py --write
PYTHONPATH=. python3 tests/contract/gen_reference.py --write
```
"""


def _cell(text: Any) -> str:
    """Text for one markdown table cell: one line, with `|` escaped."""
    if text is None or text == SUPPRESS:
        return ""
    return " ".join(str(text).split()).replace("|", "\\|")


def _code(value: Any) -> str:
    return f"`{value}`"


def _value_column(arg: Dict[str, Any]) -> str:
    if arg["kind"] in FLAG_KINDS:
        return ""
    choices = arg.get("choices")
    if choices:
        return "one of " + ", ".join(_code(c) for c in choices)
    metavar = arg.get("metavar")
    name = metavar if isinstance(metavar, str) and metavar != SUPPRESS else arg["dest"].upper()
    shape = {"?": "[{0}]", "*": "[{0} ...]", "+": "{0} [{0} ...]"}.get(arg.get("nargs"), "{0}")
    return _code(shape.format(name))


def _default_column(arg: Dict[str, Any]) -> str:
    default = arg.get("default")
    if default in (None, SUPPRESS) or (default is False and arg["kind"] in FLAG_KINDS):
        return ""
    return _code(json.dumps(default, ensure_ascii=False))


def _argument_row(arg: Dict[str, Any]) -> str:
    name = ", ".join(_code(f) for f in arg["flags"]) or _code(arg["dest"])
    help_text = _cell(arg.get("help"))
    if not arg["flags"] and arg.get("required"):
        help_text = f"{help_text} (required)".strip()
    return f"| {name} | {_value_column(arg)} | {_default_column(arg)} | {help_text} |"


def _arguments_table(arguments: List[Dict[str, Any]], skip_common: bool) -> List[str]:
    rows = [
        _argument_row(arg)
        for arg in arguments
        if arg["kind"] != "parsers" and arg["help"] != SUPPRESS
        and not (skip_common and set(arg["flags"]) & COMMON_FLAGS)
    ]
    if not rows:
        return []
    return ["| Argument | Value | Default | Description |", "| --- | --- | --- | --- |", *rows, ""]


def _command(path: List[str], node: Dict[str, Any], registry: Dict[str, Dict[str, Any]]) -> List[str]:
    lines = [f"### `aegis {' '.join(path)}`", "", _cell(node.get("help")) or "(no help text)", ""]
    description = node.get("description")
    if description and description != SUPPRESS and description != node.get("help"):
        lines += [_cell(description), ""]
    facts = []
    entry = registry.get(path[0]) if len(path) == 1 else None
    if entry is not None:
        facts.append(f"Category: {entry['category']}.")
    if node.get("aliases"):
        facts.append("Aliases: " + ", ".join(_code(a) for a in node["aliases"]) + ".")
    subcommands = list(node.get("commands", {}))
    if subcommands:
        facts.append("Subcommands: " + ", ".join(_code(s) for s in subcommands) + ".")
    if facts:
        lines += [" ".join(facts), ""]
    lines += _arguments_table(node["arguments"], skip_common=True)
    for name, child in node.get("commands", {}).items():
        lines += _command(path + [name], child, registry)
    return lines


def _schema_type(schema: Dict[str, Any]) -> str:
    kind = schema.get("type", "any")
    if kind == "array":
        kind = f"array of {_schema_type(schema.get('items', {}))}"
    if "enum" in schema:
        kind += ": one of " + ", ".join(_code(json.dumps(v)) for v in schema["enum"])
    return kind


def _tool(tool: Dict[str, Any]) -> List[str]:
    annotations = tool.get("annotations", {})
    traits = [
        label
        for key, label in (
            ("readOnlyHint", "read-only"),
            ("destructiveHint", "destructive"),
            ("idempotentHint", "idempotent"),
            ("openWorldHint", "open-world"),
        )
        if annotations.get(key)
    ]
    title = annotations.get("title", tool["name"])
    lines = [
        f"### `{tool['name']}`",
        "",
        f"**{title}**" + (f" ({', '.join(traits)})" if traits else ""),
        "",
        _cell(tool.get("description")),
        "",
    ]
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    if properties:
        lines += ["| Parameter | Type | Required | Description |", "| --- | --- | --- | --- |"]
        for name, prop in properties.items():
            lines.append(
                f"| {_code(name)} | {_cell(_schema_type(prop))} | {'yes' if name in required else 'no'} "
                f"| {_cell(prop.get('description'))} |"
            )
        lines.append("")
    else:
        lines += ["It takes no parameters.", ""]
    lines += ["Input schema:", "", "```json", json.dumps(schema, indent=2, ensure_ascii=False), "```", ""]
    if "outputSchema" in tool:
        lines += [
            "Output schema:",
            "",
            "```json",
            json.dumps(tool["outputSchema"], indent=2, ensure_ascii=False),
            "```",
            "",
        ]
    return lines


def render(cli: Dict[str, Any], mcp: Dict[str, Any]) -> str:
    parser = cli["parser"]
    registry = {entry["name"]: entry for entry in cli.get("registry", [])}
    lines = [HEADER, "## Command line: `aegis`", ""]
    if parser.get("description"):
        lines += [_cell(parser["description"]), ""]
    lines += [
        "### Global options",
        "",
        "Every command also accepts `-h/--help`, `--json`, `--plain` and `--workspace`.",
        "",
        *_arguments_table(parser["arguments"], skip_common=False),
        "### Commands",
        "",
        "| Command | Category | Description |",
        "| --- | --- | --- |",
    ]
    commands = parser.get("commands", {})

    def order(name: str) -> tuple:
        category = registry.get(name, {}).get("category", "")
        rank = CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER else len(CATEGORY_ORDER)
        return rank, name

    for name in sorted(commands, key=order):
        category = registry.get(name, {}).get("category", "")
        lines.append(f"| `aegis {name}` | {category} | {_cell(commands[name].get('help'))} |")
    lines.append("")
    for name in sorted(commands, key=order):
        lines += _command([name], commands[name], registry)
    removed = cli.get("removed_commands") or {}
    if removed:
        lines += [
            "### Removed commands",
            "",
            "Each of these exits with status 2 and prints where to go instead.",
            "",
            "| Command | Instead |",
            "| --- | --- |",
            *[f"| `aegis {name}` | {_cell(pointer)} |" for name, pointer in removed.items()],
            "",
        ]
    lines += ["## MCP server: `aegis-mcp`", ""]
    tools = mcp.get("tools", [])
    if tools:
        lines += [
            "The server speaks MCP over stdio. Its tools, as `tools/list` returns them. A write tool "
            "declares only `readOnlyHint: false`, so the MCP defaults apply to its other hints:",
            "",
            "| Tool | Title |",
            "| --- | --- |",
            *[f"| `{t['name']}` | {_cell(t.get('annotations', {}).get('title'))} |" for t in tools],
            "",
        ]
    for tool in tools:
        lines += _tool(tool)
    return "\n".join(lines).rstrip("\n") + "\n"


def _snapshots() -> tuple:
    cli = json.loads((CONTRACT / "cli_tree.json").read_text(encoding="utf-8"))
    mcp = json.loads((CONTRACT / "mcp_tools.json").read_text(encoding="utf-8"))
    return cli, mcp


def main(argv: Optional[List[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args not in (["--write"], ["--check"]):
        print("usage: PYTHONPATH=. python3 tests/contract/gen_reference.py --write|--check", file=sys.stderr)
        return 2
    text = render(*_snapshots())
    if args == ["--check"]:
        current = REFERENCE.read_text(encoding="utf-8") if REFERENCE.is_file() else None
        if current != text:
            print(f"{REFERENCE} is stale: run with --write", file=sys.stderr)
            return 1
        return 0
    with open(REFERENCE, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(f"wrote {REFERENCE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
