"""Registry of aegis CLI commands with categorization and alias resolution."""
from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional, Union

from aegis_cli.base import CommandCategory, AegisCommand

__all__ = ["CommandRegistry", "create_default_registry", "get_default_registry"]


class CommandRegistry:
    """Registry of active commands, their aliases, and categorized help."""

    def __init__(self) -> None:
        self._commands: Dict[str, AegisCommand] = {}
        self._alias_map: Dict[str, AegisCommand] = {}

    def register(self, command: Union[AegisCommand, type[AegisCommand]]) -> None:
        """Register a command instance or class into the registry."""
        inst = command() if isinstance(command, type) else command
        self._commands[inst.name] = inst
        self._alias_map[inst.name] = inst
        for alias in inst.aliases:
            self._alias_map[alias] = inst

    def get(self, name_or_alias: str) -> Optional[AegisCommand]:
        """Resolve a command by its primary name or alias."""
        return self._alias_map.get(name_or_alias)

    def list_commands(self) -> List[AegisCommand]:
        """Return all unique registered primary commands."""
        return list(self._commands.values())

    def get_by_category(self, category: CommandCategory) -> List[AegisCommand]:
        """Return all registered commands belonging to a specific category."""
        return [c for c in self._commands.values() if c.category == category]

    def populate_subparsers(
        self,
        subparsers: Any,
        common_parser: Optional[argparse.ArgumentParser] = None,
    ) -> Dict[str, argparse.ArgumentParser]:
        """Configure subparsers for all registered commands."""
        parsers: Dict[str, argparse.ArgumentParser] = {}
        parents = [common_parser] if common_parser else []

        for cmd in self._commands.values():
            kwargs: Dict[str, Any] = {
                "help": cmd.help,
                "parents": parents,
            }
            if cmd.aliases:
                kwargs["aliases"] = list(cmd.aliases)
            if cmd.description:
                kwargs["description"] = cmd.description

            sub_p = subparsers.add_parser(cmd.name, **kwargs)
            cmd.configure_parser(sub_p)
            parsers[cmd.name] = sub_p

        return parsers

    def format_categorized_help(
        self,
        prog: str = "aegis",
        ctx: Optional[Any] = None,
    ) -> str:
        """Render standard grouped help message showing commands by logical category."""
        from aegis_cli.ui.table import Grid
        from aegis_cli.ui.theme import OutputContext

        ui = ctx if isinstance(ctx, OutputContext) else OutputContext()
        title_line = ui.style(
            "Aegis Governance — make AI coding agents trustworthy",
            "bold",
            "cyan",
        )
        lines = [
            title_line,
            "",
            f"usage: {prog} <command> [options]",
            "",
        ]

        categories = [
            CommandCategory.SETUP,
            CommandCategory.WORKFLOW,
            CommandCategory.LIFECYCLE,
            CommandCategory.PLUMBING,
        ]

        max_name_len = max((len(c.name) for c in self._commands.values()), default=12)
        col_width = max(max_name_len + 2, 14)

        for cat in categories:
            cmds = self.get_by_category(cat)
            if not cmds:
                continue

            lines.append(ui.style(f"{cat.value}:", "bold"))
            grid = Grid(ctx=ui, padding=2)
            grid.add_column(style="green")
            grid.add_column()
            for cmd in sorted(cmds, key=lambda c: c.name):
                alias_str = f" (aliases: {', '.join(cmd.aliases)})" if cmd.aliases else ""
                padded_name = f"  {cmd.name:<{col_width - 2}}"
                grid.add_row(padded_name, f"{cmd.help}{alias_str}")
            lines.append(grid.render(ui))
            lines.append("")

        lines.extend([
            ui.style("Common Options:", "bold"),
            "  --workspace PATH   Target workspace directory (default: current directory)",
            "  --json             Output results as machine-readable JSON",
            "  --plain            Disable emoji and rich styling",
            "  -h, --help         Show this help message and exit",
            "",
            f"Run '{prog} <command> --help' for details on a specific command.",
        ])

        return "\n".join(lines)


_DEFAULT_REGISTRY: Optional[CommandRegistry] = None


def create_default_registry() -> CommandRegistry:
    """Create a CommandRegistry holding the v4 command set."""
    reg = CommandRegistry()

    from aegis_cli.approve import ApproveCommand
    from aegis_cli.benchmark import BenchmarkCommand
    from aegis_cli.check import CheckCommand
    from aegis_cli.doctor import DoctorCommand
    from aegis_cli.hooks import HookCommand
    from aegis_cli.init import InitCommand
    from aegis_cli.migrate import MigrateCommand
    from aegis_cli.package import PackageCommand
    from aegis_cli.rule import RuleCommand
    from aegis_cli.scan import ScanCommand
    from aegis_cli.skills_sync import SkillsCommand
    from aegis_cli.status import StatusCommand
    from aegis_cli.sync import SyncCommand
    from aegis_cli.team import TeamCommand
    from aegis_cli.uninstall import UninstallCommand

    for cmd_cls in (
        InitCommand,
        UninstallCommand,
        MigrateCommand,
        DoctorCommand,
        CheckCommand,
        ApproveCommand,
        ScanCommand,
        StatusCommand,
        RuleCommand,
        SyncCommand,
        HookCommand,
        TeamCommand,
        SkillsCommand,
        BenchmarkCommand,
        PackageCommand,
    ):
        reg.register(cmd_cls)

    return reg


def get_default_registry() -> CommandRegistry:
    """Return the cached default CommandRegistry singleton."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = create_default_registry()
    return _DEFAULT_REGISTRY
