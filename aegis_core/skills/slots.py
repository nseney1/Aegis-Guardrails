"""Fail-closed slot resolution binding abstract skill parameters to host and user values.

Shipped rule and skill text names capabilities, never one host's tools: ``${SLOT.TOOL_EDIT}``,
``${SLOT.MODEL_FAST}`` (build-sheet D16). They are rendered for the host that asks, by the
``slot_profile`` of its row in :mod:`aegis_core.hosts`; a host Aegis does not know gets the
neutral ``generic`` profile, never another vendor's.

Trust model (H5, D10): the repo's .aegis/config.json is untrusted input. It can only
opt in to the AST drivers that ship inside aegis (``ast.packaged_drivers``); it
cannot name a command or set a slot, and such keys are reported in ``warnings``.
Driver commands and slot overrides (TOOL_*/MODEL_* included) come only from code or
the user-scope ~/.aegis/config.json outside the workspace (aegis_core.config).
"""
from __future__ import annotations

from pathlib import Path
import re
import unicodedata
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core import hosts
from aegis_core.ast.detect import NATIVE_JS_EXTENSIONS
from aegis_core.errors import AegisValidationError
from aegis_core.hosts import GENERIC

__all__ = [
    "SlotResolutionError",
    "SlotRegistry",
    "SLOT_REF_PATTERN",
    "PLATFORM_SLOT_PROFILES",
    "DEFAULT_SLOTS",
    "profile_id",
    "render_for_host",
    "render_scan_result",
    "sanitize_slot_value",
    "MAX_SLOT_VALUE_LEN",
]

SLOT_REF_PATTERN = re.compile(r"\$\{(?:SLOT|RULE)\.([A-Za-z0-9_\-]+)\}|\$\{([A-Za-z0-9_\-]+)\}")

# One profile per host slot_profile id (aegis_core.hosts). Values are single tool or
# model names, so they pass sanitize_slot_value and render inside backticks.
_ANTIGRAVITY_PROFILE: dict[str, str] = {
    "TOOL_READ": "view_file",
    "TOOL_EDIT": "replace_file_content",
    "TOOL_WRITE": "write_to_file",
    "TOOL_SEARCH": "grep_search",
    "TOOL_RUN": "run_command",
    "TOOL_SUBAGENT": "invoke_subagent",
    "MODEL_FAST": "flash",
    "MODEL_STANDARD": "inherit",
    "MODEL_HEAVY": "pro",
}

_CLAUDE_PROFILE: dict[str, str] = {
    "TOOL_READ": "Read",
    "TOOL_EDIT": "Edit",
    "TOOL_WRITE": "Write",
    "TOOL_SEARCH": "Grep",
    "TOOL_RUN": "Bash",
    "TOOL_SUBAGENT": "Task",
    "MODEL_FAST": "haiku",
    "MODEL_STANDARD": "sonnet",
    "MODEL_HEAVY": "opus",
}

# Codex has no read or search tool: it reads and greps through exec_command (codex-cli
# 0.162.1). Its model slugs differ per account and plan and none is on record, so the
# tiers stay generic; ~/.aegis/config.json "slots" can name them.
_CODEX_PROFILE: dict[str, str] = {
    "TOOL_READ": "exec_command",
    "TOOL_EDIT": "apply_patch",
    "TOOL_WRITE": "apply_patch",
    "TOOL_SEARCH": "exec_command",
    "TOOL_RUN": "exec_command",
    "TOOL_SUBAGENT": "spawn_agent",
    "MODEL_FAST": "fast",
    "MODEL_STANDARD": "standard",
    "MODEL_HEAVY": "heavy",
}

# Neutral names for a host Aegis does not know: a tool kind, never one vendor's name. A
# model tier is a bare adjective, as rules say "use the `${SLOT.MODEL_FAST}` tier".
_GENERIC_PROFILE: dict[str, str] = {
    "TOOL_READ": "read_file",
    "TOOL_EDIT": "edit_file",
    "TOOL_WRITE": "write_file",
    "TOOL_SEARCH": "grep",
    "TOOL_RUN": "shell",
    "TOOL_SUBAGENT": "subagent",
    "MODEL_FAST": "fast",
    "MODEL_STANDARD": "standard",
    "MODEL_HEAVY": "heavy",
}

# Gemini CLI is retired (aegis_core.hosts), but identify() still names its client when it
# connects, so it renders its documented tool names; the subagent tool and the model tiers
# stay generic, as no real install ever confirmed them.
_GEMINI_CLI_PROFILE: dict[str, str] = {
    **_GENERIC_PROFILE,
    "TOOL_READ": "read_file",
    "TOOL_EDIT": "replace",
    "TOOL_WRITE": "write_file",
    "TOOL_SEARCH": "grep_search",
    "TOOL_RUN": "run_shell_command",
}

PLATFORM_SLOT_PROFILES: dict[str, dict[str, str]] = {
    "codex-cli": dict(_CODEX_PROFILE),
    "claude-code": dict(_CLAUDE_PROFILE),
    "antigravity": dict(_ANTIGRAVITY_PROFILE),
    "gemini-cli": dict(_GEMINI_CLI_PROFILE),
    GENERIC: dict(_GENERIC_PROFILE),
}

# Transitional: until wave C's runtime lane lands, the MCP server on this base still
# names its client by the v3 platform labels below. Nothing else may add one (H1).
_V3_PLATFORM_PROFILES: dict[str, str] = {"claude": "claude-code", "gemini": "antigravity"}

DEFAULT_SLOTS: dict[str, str] = {
    "TEST_RUNNER": "python3 -m pytest -q",
    "LINTER": "ruff check",
    "FORMATTER": "ruff format",
    "TYPE_CHECKER": "mypy",
    "BUILD_TOOL": "python3 -m build",
    **_GENERIC_PROFILE,
}


MAX_SLOT_VALUE_LEN = 80
_CAPABILITY_PREFIXES = ("TOOL_", "MODEL_")
_CAPABILITY_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+\-]*")
_KNOWN_CAPABILITY_KEYS = frozenset(_GENERIC_PROFILE)
_MAX_LISTED_KEYS = 5
# Cc: C0/C1 controls incl. newlines; Cf: bidi overrides, zero-width chars; Zl/Zp: U+2028/U+2029.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def sanitize_slot_value(key: str, value: str) -> Optional[str]:
    """Return ``value`` made safe to inline into agent-facing text, or None to leave it unresolved.

    Control and format characters become spaces, whitespace collapses to one line and
    the result is capped at MAX_SLOT_VALUE_LEN. TOOL_*/MODEL_* values must be a plain
    tool or model name, otherwise None.
    """
    text = "".join(" " if unicodedata.category(ch) in _UNSAFE_CATEGORIES else ch for ch in str(value))
    text = " ".join(text.split())
    if str(key).startswith(_CAPABILITY_PREFIXES):
        if len(text) <= MAX_SLOT_VALUE_LEN and _CAPABILITY_VALUE.fullmatch(text):
            return text
        return None
    return text[:MAX_SLOT_VALUE_LEN] or None


def _keys_summary(keys: Sequence[str]) -> str:
    """'N slot(s) (names)' for a warning; only slot names aegis defines are listed."""
    listed = [k for k in keys if k in _KNOWN_CAPABILITY_KEYS][:_MAX_LISTED_KEYS]
    names = ", ".join(repr(k) for k in listed)
    rest = len(keys) - len(listed)
    if rest:
        names = f"{names} and {rest} more" if names else "names not shown"
    return f"{len(keys)} {'slot' if len(keys) == 1 else 'slots'} ({names})"


def profile_id(host: Optional[str]) -> str:
    """The slot profile for a host id (or a profile id); anything unknown is ``generic``.

    A host whose table row names another profile gets that one (Claude Desktop is
    identity only and gets ``generic``). It never falls back to a vendor's profile.
    """
    key = str(host or "").strip()
    key = _V3_PLATFORM_PROFILES.get(key, key)
    try:
        return hosts.get(key).slot_profile
    except KeyError:
        return key if key in PLATFORM_SLOT_PROFILES else GENERIC


class SlotResolutionError(AegisValidationError):
    """Raised when a required skill slot cannot be resolved fail-closed."""


class SlotRegistry:
    """Slot bindings: host profile, ~/.aegis/config.json (user) and .aegis/config.json opt-ins (repo)."""

    def __init__(
        self,
        slots: Optional[Mapping[str, Any]] = None,
        warnings: Optional[Sequence[str]] = None,
    ) -> None:
        self._slots: Dict[str, str] = {
            str(k): str(v) for k, v in (slots or {}).items() if v is not None and not (
                str(k).lower().startswith('ast_driver_')
                and '.' + str(k)[len('ast_driver_'):].lstrip('.').lower() in NATIVE_JS_EXTENSIONS)
        }
        self._warnings: List[str] = list(warnings or [])

    @property
    def warnings(self) -> List[str]:
        """Why slot keys were ignored, for callers to surface (doctor, scan)."""
        return list(self._warnings)

    @classmethod
    def load(cls, workspace_root: Path | str) -> SlotRegistry:
        """The repo's packaged-driver opt-ins (``ast_driver_<ext>`` slots) from .aegis/config.json.

        The slot value names the packaged driver and is never run (aegis_core.ast.runner).
        Ignored config keys go to ``warnings``. Raises SlotResolutionError if the file
        exists but cannot be read or parsed.
        """
        from aegis_core.ast.detect import packaged_driver_for_extension
        from aegis_core.config import ConfigError, RepoConfig

        try:
            repo = RepoConfig.load(workspace_root)
        except ConfigError as exc:
            raise SlotResolutionError(str(exc)) from exc
        slots = {}
        warnings = list(repo.warnings)
        unknown = 0
        for ext in repo.packaged_drivers:
            if '.' + ext.lstrip('.').lower() in NATIVE_JS_EXTENSIONS:
                continue  # obsolete opt-in; the built-in parser already handles this extension
            config = packaged_driver_for_extension(ext)
            if config is not None:
                slots[f"ast_driver_{ext}"] = config["default_command"]
            else:
                unknown += 1
        if unknown:
            warnings.append(
                f"ignored {unknown} 'ast.packaged_drivers' entr{'y' if unknown == 1 else 'ies'} in "
                ".aegis/config.json: only extensions with a driver that ships inside aegis can be enabled"
            )
        return cls(slots, warnings=warnings)

    @classmethod
    def load_user(cls, workspace_root: Path | str | None = None) -> SlotRegistry:
        """The trusted user-scope ~/.aegis/config.json: driver commands and slot overrides.

        A user file inside the workspace is ignored with a warning. Raises
        SlotResolutionError if the file exists but cannot be read or parsed.
        """
        from aegis_core.config import ConfigError, UserConfig

        try:
            user = UserConfig.load(workspace_root)
        except ConfigError as exc:
            raise SlotResolutionError(str(exc)) from exc
        slots = dict(user.slots)
        slots.update({f"ast_driver_{ext}": command for ext, command in user.drivers.items()})
        return cls(slots, warnings=user.warnings)

    @classmethod
    def for_platform(cls, platform: str, workspace: str | Path | None = None) -> SlotRegistry:
        """The host's capability slots (``platform`` is a host or profile id, see profile_id),
        then user-scope overrides, then the repo's driver opt-ins."""
        merged: Dict[str, str] = dict(DEFAULT_SLOTS)
        profile = PLATFORM_SLOT_PROFILES[profile_id(platform)]
        merged.update(profile)
        user_reg = cls.load_user(workspace)
        warnings = user_reg.warnings
        invalid: List[str] = []
        for key, value in user_reg.to_dict().items():
            if key.startswith(_CAPABILITY_PREFIXES):
                clean = sanitize_slot_value(key, value)
                if clean is None:
                    invalid.append(key)
                    continue
                value = clean
            merged[key] = value
        if invalid:
            warnings.append(
                f"ignored {_keys_summary(invalid)} in ~/.aegis/config.json: tool/model names "
                f"may use only letters, digits and _.:/@+- (max {MAX_SLOT_VALUE_LEN})"
            )
        if workspace is not None:
            ws_reg = cls.load(workspace)
            warnings.extend(ws_reg.warnings)
            merged.update(ws_reg.to_dict())
        return cls(merged, warnings=warnings)

    def sanitized(self) -> SlotRegistry:
        """Copy whose values are safe to inline into agent-facing text (see sanitize_slot_value)."""
        safe = {}
        for key, value in self._slots.items():
            clean = sanitize_slot_value(key, value)
            if clean is not None:
                safe[key] = clean
        return SlotRegistry(safe, warnings=self._warnings)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self._slots.get(key, default)

    def resolve(self, template: str, strict: bool = True) -> str:
        """Interpolate ${SLOT.key} or ${key} references.

        If strict=True and a slot is missing, raises SlotResolutionError (fail-closed).
        """
        def _replacer(m: re.Match) -> str:
            key = m.group(1) or m.group(2)
            if key in self._slots:
                return self._slots[key]
            if strict:
                raise SlotResolutionError(f"Unresolved required slot: '{key}'")
            return m.group(0)

        return SLOT_REF_PATTERN.sub(_replacer, template)

    def to_dict(self) -> Dict[str, str]:
        return dict(self._slots)

    def get_ast_driver(self, extension: str) -> Optional[str]:
        """Resolve external commands; native Python and JS/TS need no command slot."""
        clean_ext = extension.lstrip(".").lower()
        if clean_ext == "py" or f'.{clean_ext}' in NATIVE_JS_EXTENSIONS:
            return None
        return self.get(f"ast_driver_{clean_ext}") or self.get("ast_driver")

    def get_configured_extensions(self) -> set[str]:
        """Return native source extensions and configured external-driver extensions."""
        exts = {".py"} | NATIVE_JS_EXTENSIONS
        for key in self._slots:
            if key.startswith("ast_driver_"):
                ext = key[len("ast_driver_"):].strip().lower()
                if ext:
                    exts.add(f".{ext}" if not ext.startswith(".") else ext)
        return exts


_CONFIG_UNREADABLE = "{files} could not be read or parsed; built-in slot values were used"


def render_for_host(text: str, host: Optional[str], workspace: str | Path | None = None) -> Tuple[str, List[str]]:
    """``(text, warnings)``: ``text`` with its ${SLOT.*} references rendered for ``host``.

    Values are sanitized before they are inlined (the reader is an agent); a reference
    with no value stays as written so the gap is visible. A user config that cannot be
    read never costs the text: the host's built-in values are used and a fixed warning
    (no file content) says so.
    """
    try:
        registry = SlotRegistry.for_platform(host or GENERIC, workspace=workspace)
        warnings = registry.warnings
    except (SlotResolutionError, OSError):
        merged = dict(DEFAULT_SLOTS)
        merged.update(PLATFORM_SLOT_PROFILES[profile_id(host)])
        from aegis_core.workspace.layout import AEGIS_DIRNAME

        files = f"~/{AEGIS_DIRNAME}/config.json" + (f" or {AEGIS_DIRNAME}/config.json" if workspace is not None else "")
        registry, warnings = SlotRegistry(merged), [_CONFIG_UNREADABLE.format(files=files)]
    return registry.sanitized().resolve(text, strict=False), warnings


_SCAN_CONFIG_UNREADABLE = (
    "config files (.aegis/config.json or ~/.aegis/config.json) could not be read or parsed; "
    "${SLOT.*} placeholders were left unresolved"
)
# The scan fields an agent reads that may quote rule text: the guidance, and the
# hypothesis/prediction (and a body, where one is carried) of each listed rule.
_SCAN_LISTS = ("relevant_rules", "invariant_warnings")
_SCAN_RULE_FIELDS = ("body", "hypothesis", "prediction")


def _add_warnings(result: Dict[str, Any], warnings: Sequence[str]) -> None:
    existing = result.get("warnings")
    merged = list(existing) if isinstance(existing, list) else []
    merged.extend(w for w in warnings if w not in merged)
    if merged:
        result["warnings"] = merged


def render_scan_result(result: Dict[str, Any], host: Optional[str],
                       workspace: str | Path | None = None) -> Dict[str, Any]:
    """A scan result (aegis_core.scan) with its ${SLOT.*} references rendered for ``host``.

    One renderer for the MCP aegis_scan (the identified host's profile) and the CLI
    ``aegis scan`` (no host: the generic profile). The agent reads this output, so
    values are sanitized before they are inlined, and ignored keys or a config file
    that cannot be parsed are reported in ``result["warnings"]`` (H5). Slot loading
    never costs the agent its guidance: on such an error the placeholders stay as
    written and a fixed warning, quoting no file content or path, says so.
    """
    try:
        loaded = SlotRegistry.for_platform(host or GENERIC, workspace=str(workspace) if workspace is not None else None)
    except (SlotResolutionError, OSError, RuntimeError):
        _add_warnings(result, [_SCAN_CONFIG_UNREADABLE])
        return result
    _add_warnings(result, loaded.warnings)
    registry = loaded.sanitized()

    guidance = result.get("guidance")
    if isinstance(guidance, str) and "${SLOT." in guidance:
        result["guidance"] = registry.resolve(guidance, strict=False)
    seen = set()
    for key in _SCAN_LISTS:
        items = result.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or id(item) in seen:
                continue
            seen.add(id(item))
            for name in _SCAN_RULE_FIELDS:
                value = item.get(name)
                if isinstance(value, str) and "${SLOT." in value:
                    item[name] = registry.resolve(value, strict=False)
    return result
