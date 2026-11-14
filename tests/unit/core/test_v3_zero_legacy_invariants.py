"""v3.0.0 zero-legacy invariants that are not vocabulary counts.

1. All `.aegis/rules/` files use pure Aegis prefixes and types.
2. The MCP tools are registered strictly under the `aegis_*` namespace.
3. Every CLI command in `CommandRegistry` supports `OutputContext` (`--plain`,
   `NO_COLOR`, `--json`) without leaking ANSI escape sequences.

Zero `soma_*` imports, zero `Soma*` classes or aliases and zero organelle rule-type
literals are rows of the legacy-vocabulary ratchet (tests/contract/test_legacy_ratchet.py).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from aegis_cli.cli import main as cli_main
from aegis_cli.registry import get_default_registry
from aegis_cli.ui.theme import OutputContext
from aegis_core.yaml_engine.frontmatter import parse_rule_frontmatter
from aegis_mcp.registry import TOOL_DEFINITIONS
from aegis_mcp.tools import _TOOL_HANDLERS

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestV3RuleAndToolNamespaces:
    """Repository rules and MCP tools use the Aegis names."""

    def test_repository_rules_use_pure_aegis_prefixes_and_types(self) -> None:
        rules_dir = REPO_ROOT / ".aegis" / "rules"
        valid_prefixes = ("invariant-", "boundary-", "trap-", "persona-", "contract-", "gate-")
        valid_types = {"invariant", "boundary", "trap", "persona", "contract", "gate"}
        offenders: list[str] = []

        for md_file in sorted(rules_dir.rglob("*.md")):
            if md_file.name == "README.md":
                continue
            rel = md_file.relative_to(REPO_ROOT)
            if not md_file.name.startswith(valid_prefixes):
                offenders.append(f"{rel}: filename does not start with {valid_prefixes}")
            meta, _ = parse_rule_frontmatter(str(md_file))
            rule_id = str(meta.get("id", ""))
            rule_type = str(meta.get("type", ""))
            if not rule_id.startswith(valid_prefixes):
                offenders.append(f"{rel}: frontmatter id '{rule_id}' invalid prefix")
            if rule_type not in valid_types:
                offenders.append(f"{rel}: frontmatter type '{rule_type}' not in {valid_types}")

        assert not offenders, "Repository rules violated pure Aegis naming:\n" + "\n".join(offenders)

    def test_mcp_tools_registered_strictly_under_aegis_namespace(self) -> None:
        tool_names = [t["name"] for t in TOOL_DEFINITIONS]
        contract = json.loads((REPO_ROOT / "tests" / "contract" / "mcp_tools.json").read_text(encoding="utf-8"))
        assert sorted(tool_names) == sorted(tool["name"] for tool in contract["tools"])
        assert all(name.startswith("aegis_") for name in tool_names), tool_names
        assert set(_TOOL_HANDLERS.keys()) == set(tool_names)


class TestV3CLIOutputContextAndANSIHygiene:
    """Verify every CLI command in CommandRegistry supports OutputContext without leaking ANSI."""

    def test_every_registered_command_supports_output_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        registry = get_default_registry()
        commands = list(registry._commands.values())
        assert len(commands) >= 9

        for cmd in commands:
            ns_plain = argparse.Namespace(plain=True, json=False)
            ui_plain = cmd.get_ui(ns_plain)
            assert isinstance(ui_plain, OutputContext)
            assert ui_plain.color_enabled is False
            assert ui_plain.emoji_enabled is False

            ns_json = argparse.Namespace(plain=False, json=True)
            ui_json = cmd.get_ui(ns_json)
            assert ui_json.json_mode is True
            assert ui_json.color_enabled is False
            assert ui_json.emoji_enabled is False

            monkeypatch.setenv("NO_COLOR", "1")
            ns_env = argparse.Namespace(plain=False, json=False)
            ui_env = cmd.get_ui(ns_env)
            assert ui_env.color_enabled is False
            monkeypatch.delenv("NO_COLOR", raising=False)

    @pytest.mark.parametrize(
        "argv",
        [
            ["status", "--plain"],
            ["doctor", "--plain"],
            ["doctor", "--json"],
            ["rule", "list", "--plain"],
            ["hook", "status", "--plain"],
        ],
    )
    def test_cli_commands_emit_zero_ansi_when_plain_or_no_color(
        self,
        argv: list[str],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from aegis_cli import doctor

        def no_host_cli(cli_argv, cwd, timeout):  # doctor asks codex; never a real host in tests
            raise OSError("host CLIs are not run in tests")

        monkeypatch.setattr(doctor, "_run_host_cli", no_host_cli)
        monkeypatch.setenv("NO_COLOR", "1")
        cli_main(argv)
        captured = capsys.readouterr()
        # A removed command prints only a pointer, which would pass vacuously.
        assert captured.out.strip(), f"{argv} printed nothing on stdout: {captured.err!r}"
        assert "\x1b[" not in captured.out, f"ANSI escape leaked to stdout for {argv}: {captured.out!r}"
        assert "\x1b[" not in captured.err, f"ANSI escape leaked to stderr for {argv}: {captured.err!r}"
