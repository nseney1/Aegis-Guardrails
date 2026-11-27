"""Git pre-commit hook management, the agent-host hook runtime (`aegis hook run`,
in aegis_cli.hooks.pretool) and the isolated command safety gate."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis_cli.hooks.management import (
        AEGIS_HOOK_FORMAT,
        CURRENT_HOOK_FORMAT_VERSION,
        _AEGIS_HOOK_END,
        _AEGIS_HOOK_START,
        _replace_hook_block,
        generate_hook_block,
        hook_status,
        install_hook,
        run_hook_install,
        run_hook_status,
        run_hook_uninstall,
        uninstall_hook,
    )
    from aegis_cli.hooks.redaction import (
        SECRET_REPLACEMENTS,
        redact_secrets,
    )
    from aegis_cli.hooks.runtime import (
        HookCommand,
        run_hook,
    )
    from aegis_cli.hooks.safety import (
        DANGEROUS_FLAGS,
        METACHARACTERS,
        SAFE_COMMAND_PREFIXES,
        log_gate_event,
        run_safety_gate,
    )

__all__ = [
    "SAFE_COMMAND_PREFIXES",
    "METACHARACTERS",
    "DANGEROUS_FLAGS",
    "SECRET_REPLACEMENTS",
    "redact_secrets",
    "log_gate_event",
    "run_safety_gate",
    "_AEGIS_HOOK_START",
    "_AEGIS_HOOK_END",
    "AEGIS_HOOK_FORMAT",
    "CURRENT_HOOK_FORMAT_VERSION",
    "generate_hook_block",
    "_replace_hook_block",
    "install_hook",
    "uninstall_hook",
    "hook_status",
    "run_hook_install",
    "run_hook_uninstall",
    "run_hook_status",
    "run_hook",
    "HookCommand",
]

_REDACTION_NAMES = frozenset({"SECRET_REPLACEMENTS", "redact_secrets"})
_RUNTIME_NAMES = frozenset({"HookCommand", "run_hook"})
_SAFETY_NAMES = frozenset({
    "DANGEROUS_FLAGS",
    "METACHARACTERS",
    "SAFE_COMMAND_PREFIXES",
    "log_gate_event",
    "run_safety_gate",
})
_MANAGEMENT_NAMES = frozenset(__all__) - _REDACTION_NAMES - _RUNTIME_NAMES - _SAFETY_NAMES


def __getattr__(name: str) -> Any:
    if name in _MANAGEMENT_NAMES:
        from aegis_cli.hooks import management

        return getattr(management, name)
    if name in _REDACTION_NAMES:
        from aegis_cli.hooks import redaction

        return getattr(redaction, name)
    if name in _RUNTIME_NAMES:
        from aegis_cli.hooks import runtime

        return getattr(runtime, name)
    if name in _SAFETY_NAMES:
        from aegis_cli.hooks import safety

        return getattr(safety, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
