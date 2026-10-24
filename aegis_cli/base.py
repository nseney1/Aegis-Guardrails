"""Declarative CLI Command Protocol and Category Definitions."""
from __future__ import annotations

from abc import ABC, abstractmethod
import argparse
from enum import Enum
import os
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from aegis_cli.ui.theme import OutputContext

__all__ = ["CommandCategory", "AegisCommand", "host_option", "unwritable"]


def host_option(value: str):
    """Parse a host selection, reporting bad values as command-line usage errors."""
    from aegis_cli.install_hosts import parse_hosts

    try:
        return parse_hosts(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def unwritable(directory: Path) -> Optional[str]:
    """Why no file can be created in ``directory`` (made with its parents when missing,
    so the nearest directory that exists decides); None when one can."""
    existing = Path(directory)
    while not os.path.lexists(existing) and existing.parent != existing:
        existing = existing.parent
    if existing.is_dir() and os.access(existing, os.W_OK | os.X_OK):
        return None
    return f"{existing} is not a writable directory"


class CommandCategory(str, Enum):
    """Categorical grouping for Aegis commands in help screens and documentation."""
    SETUP = "Setup & Environment"
    WORKFLOW = "Daily Workflow & Verification"
    LIFECYCLE = "Rule Evolution & Intelligence"
    PLUMBING = "Plumbing"


class AegisCommand(ABC):
    """Abstract Base Class defining the lifecycle contract for all Aegis CLI subcommands."""

    name: str
    aliases: Tuple[str, ...] = ()
    category: CommandCategory
    help: str
    description: Optional[str] = None

    def get_names(self) -> Tuple[str, ...]:
        """Return the primary command name and all registered aliases."""
        return (self.name, *self.aliases)

    def get_ui(self, args: Optional[argparse.Namespace] = None) -> "OutputContext":
        """Resolve or create the OutputContext for this command invocation."""
        from aegis_cli.ui.theme import OutputContext
        existing = getattr(args, "ui", None) if args is not None else None
        if isinstance(existing, OutputContext):
            return existing
        return OutputContext.from_env_and_args(args)

    @abstractmethod
    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        """Register command-specific flags and arguments onto its subparser."""
        ...

    @abstractmethod
    def execute(self, args: argparse.Namespace) -> int:
        """Execute command logic. Common options are pre-handled by the dispatcher."""
        ...
