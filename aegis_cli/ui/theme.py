"""Zero-dependency terminal color, badge, and OutputContext primitives for Aegis CLI."""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import sys
from typing import Any, Mapping, Optional

from aegis_core.taxonomy import RULE_TYPES
from aegis_cli import sanitize_display
from aegis_core.redaction import TOKEN_REDACTIONS, redact_command_secrets

__all__ = ["ANSI_ESCAPE_RE", "OutputContext", "strip_ansi", "diagnostic_text"]

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

_ANSI_CODES: dict[str, str] = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "white": "\x1b[37m",
}

# "core" is the status label of host-installed instruction rules, not a rule type.
_RULE_TYPE_STYLES: dict[str, tuple[str, ...]] = {
    **{name: spec.style for name, spec in RULE_TYPES.items()},
    "core": ("bold", "green"),
}


def strip_ansi(text: str) -> str:
    """Remove all ANSI SGR escape sequences from text."""
    return ANSI_ESCAPE_RE.sub("", text)


def diagnostic_text(text: str, limit: int = 80) -> str:
    """Bound input, canonicalize, redact credentials, then truncate for display."""
    if len(text) > 65536:
        return "[diagnostic omitted: too_large]"
    canonical = sanitize_display(text, max_len=None)
    for pattern, replacement in TOKEN_REDACTIONS:
        canonical = pattern.sub(replacement, canonical)
    return sanitize_display(redact_command_secrets(canonical), max_len=limit)


@dataclass(frozen=True)
class OutputContext:
    """Immutable rendering configuration resolved from CLI flags and terminal environment."""

    color_enabled: bool = False
    emoji_enabled: bool = False
    json_mode: bool = False
    plain: bool = False

    @classmethod
    def from_env_and_args(
        cls,
        args: Any = None,
        environ: Optional[Mapping[str, str]] = None,
        isatty: Optional[bool] = None,
    ) -> "OutputContext":
        env = environ if environ is not None else os.environ
        tty = isatty if isatty is not None else bool(getattr(sys.stdout, "isatty", lambda: False)())

        plain = bool(getattr(args, "plain", False))
        json_mode = bool(getattr(args, "json", False))

        no_color_env = bool(env.get("NO_COLOR", ""))
        term_dumb = env.get("TERM", "").lower() == "dumb"
        force_color_env = bool(env.get("FORCE_COLOR", ""))

        if json_mode or plain or no_color_env or term_dumb:
            color_enabled = False
        elif force_color_env:
            color_enabled = True
        else:
            color_enabled = tty

        emoji_enabled = bool(tty and not plain and not json_mode and not term_dumb)

        return cls(
            color_enabled=color_enabled,
            emoji_enabled=emoji_enabled,
            json_mode=json_mode,
            plain=plain or not tty,
        )

    def style(self, text: str, *styles: str) -> str:
        """Wrap text in ANSI style codes when color_enabled is True."""
        if not self.color_enabled or not text or not styles:
            return str(text)
        prefix = "".join(_ANSI_CODES.get(s, "") for s in styles)
        if not prefix:
            return str(text)
        return f"{prefix}{text}{_ANSI_CODES['reset']}"

    def badge_pass(self, label: str = "PASS") -> str:
        if self.emoji_enabled:
            return self.style(f"✔ {label}", "green")
        return self.style(f"[{label}]", "green")

    def badge_warn(self, label: str = "WARN") -> str:
        if self.emoji_enabled:
            return self.style(f"⚠ {label}", "yellow")
        return self.style(f"[{label}]", "yellow")

    def badge_fail(self, label: str = "FAIL") -> str:
        if self.emoji_enabled:
            return self.style(f"✖ {label}", "bold", "red")
        return self.style(f"[{label}]", "bold", "red")

    def badge_info(self, label: str = "INFO") -> str:
        if self.emoji_enabled:
            return self.style(f"ℹ {label}", "cyan")
        return self.style(f"[{label}]", "cyan")

    def diagnostic_badge(self, icon: str, label: str) -> str:
        """Select an application-authored icon without transforming diagnostic content."""
        return icon if self.emoji_enabled else f"[{label}]"

    def color_fitness(self, score: float) -> str:
        formatted = f"{score:.2f}"
        if score >= 0.80:
            return self.style(formatted, "green")
        if score >= 0.50:
            return self.style(formatted, "yellow")
        return self.style(formatted, "red")

    def color_rule_type(self, rule_type: str) -> str:
        styles = _RULE_TYPE_STYLES.get(rule_type.lower(), ("dim",))
        return self.style(rule_type, *styles)

    def format_budget_bar(self, used: int, budget: int, width: int = 20) -> str:
        safe_budget = max(budget, 1)
        ratio = min(max(used / safe_budget, 0.0), 1.0)
        pct = int(round((used / safe_budget) * 100))
        filled = int(round(ratio * width))
        empty = max(width - filled, 0)

        if self.emoji_enabled:
            bar_raw = ("█" * filled) + ("░" * empty)
        else:
            bar_raw = "[" + ("#" * filled) + ("-" * empty) + "]"

        if ratio > 0.90:
            bar_colored = self.style(bar_raw, "red")
        elif ratio >= 0.70:
            bar_colored = self.style(bar_raw, "yellow")
        else:
            bar_colored = self.style(bar_raw, "green")

        return f"{bar_colored} {used:,}/{safe_budget:,} ({pct}%)"
