"""Behavioral tests for aegis_cli.ui.theme (OutputContext, ANSI palette, and badges)."""
from __future__ import annotations

import argparse
import re

from aegis_cli.ui.theme import (
    ANSI_ESCAPE_RE,
    OutputContext,
     strip_ansi,
)


def _make_ns(**kwargs) -> argparse.Namespace:
    defaults = {
        "plain": False,
        "no_emoji": False,
        "format": "text",
        "json": False,
        "quiet": False,
        "verbose": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_output_context_enables_color_and_emoji_on_interactive_tty():
    ctx = OutputContext.from_env_and_args(
        _make_ns(),
        environ={},
        isatty=True,
    )
    assert ctx.color_enabled is True
    assert ctx.emoji_enabled is True
    assert ctx.json_mode is False

    badge = ctx.badge_pass("PASSED")
    assert "\x1b[" in badge
    assert "PASSED" in strip_ansi(badge)


def test_output_context_disables_color_when_no_color_env_set():
    ctx = OutputContext.from_env_and_args(
        _make_ns(),
        environ={"NO_COLOR": "1"},
        isatty=True,
    )
    assert ctx.color_enabled is False
    assert "\x1b[" not in ctx.badge_pass()
    assert "\x1b[" not in ctx.badge_warn()
    assert "\x1b[" not in ctx.badge_fail()
    assert "\x1b[" not in ctx.color_fitness(0.95)


def test_output_context_disables_color_and_emoji_when_plain_or_piped():
    piped_ctx = OutputContext.from_env_and_args(
        _make_ns(),
        environ={},
        isatty=False,
    )
    assert piped_ctx.color_enabled is False
    assert piped_ctx.emoji_enabled is False
    assert piped_ctx.badge_pass() == "[PASS]"
    assert piped_ctx.badge_warn() == "[WARN]"
    assert piped_ctx.badge_fail() == "[FAIL]"
    assert piped_ctx.badge_info() == "[INFO]"

    plain_ctx = OutputContext.from_env_and_args(
        _make_ns(plain=True),
        environ={"FORCE_COLOR": "1"},
        isatty=True,
    )
    assert plain_ctx.color_enabled is False
    assert plain_ctx.emoji_enabled is False
    assert plain_ctx.badge_pass() == "[PASS]"


def test_output_context_respects_force_color_when_not_plain_or_json():
    ctx = OutputContext.from_env_and_args(
        _make_ns(),
        environ={"FORCE_COLOR": "1"},
        isatty=False,
    )
    assert ctx.color_enabled is True
    assert "\x1b[" in ctx.style("hello", "green")


def test_output_context_json_mode_forces_zero_color_and_zero_emoji():
    ctx = OutputContext.from_env_and_args(
        _make_ns(json=True),
        environ={"FORCE_COLOR": "1"},
        isatty=True,
    )
    assert ctx.json_mode is True
    assert ctx.color_enabled is False
    assert ctx.emoji_enabled is False
    assert not ANSI_ESCAPE_RE.search(ctx.badge_fail("FAIL"))


def test_color_fitness_applies_threshold_semantics():
    tty_ctx = OutputContext.from_env_and_args(_make_ns(), environ={}, isatty=True)
    high = tty_ctx.color_fitness(0.91)
    mid = tty_ctx.color_fitness(0.65)
    low = tty_ctx.color_fitness(0.32)

    assert "\x1b[32m" in high  # Green for >= 0.80
    assert "\x1b[33m" in mid   # Yellow for 0.50..0.79
    assert "\x1b[31m" in low   # Red for < 0.50
    assert strip_ansi(high) == "0.91"
    assert strip_ansi(mid) == "0.65"
    assert strip_ansi(low) == "0.32"


def test_format_budget_bar_renders_proportion_and_respects_plain_mode():
    plain_ctx = OutputContext.from_env_and_args(_make_ns(plain=True), environ={}, isatty=False)
    bar = plain_ctx.format_budget_bar(used=1500, budget=3000, width=10)
    assert "50%" in bar
    assert "1,500/3,000" in bar
    assert "\x1b[" not in bar

    tty_ctx = OutputContext.from_env_and_args(_make_ns(), environ={}, isatty=True)
    over_bar = tty_ctx.format_budget_bar(used=2900, budget=3000, width=10)
    assert "\x1b[31m" in over_bar  # >90% triggers red warning color


def test_without_args_an_interactive_tty_gets_color_and_emoji_not_json():
    """Callers that have no parsed flags (args=None, or a namespace without them) are text mode."""
    for args in (None, argparse.Namespace()):
        ctx = OutputContext.from_env_and_args(args, environ={}, isatty=True)
        assert (ctx.json_mode, ctx.plain, ctx.color_enabled, ctx.emoji_enabled) == (False, False, True, True)


def test_diagnostic_badge_selects_only_the_authored_icon():
    plain = OutputContext(plain=True)
    rich = OutputContext(emoji_enabled=True)
    for icon, label in (("✅", "PASS"), ("⚠️ ", "WARN"), ("❌", "FAIL"), ("ℹ️ ", "INFO")):
        assert plain.diagnostic_badge(icon, label) == f"[{label}]"
        assert rich.diagnostic_badge(icon, label) == icon


def test_diagnostic_text_canonicalizes_and_redacts_before_truncating():
    from aegis_cli.ui.theme import diagnostic_text

    token = "ghp_" + "A" * 20 + "\x1b[31m" + "B" * 16
    shown = diagnostic_text("⚠️  caller " + token, 35)
    assert "⚠️  caller" in shown
    assert "REDACTED" in shown and "A" * 10 not in shown
    assert "\x1b" not in shown and len(shown) <= 35
    assert diagnostic_text("x" * 65537, 80) == "[diagnostic omitted: too_large]"
