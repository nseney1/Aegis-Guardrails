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
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core import hosts
from aegis_core.ast.detect import NATIVE_SOURCE_EXTENSIONS
from aegis_core.errors import AegisValidationError
from aegis_core.guidance_projection import (
    GuidanceProjectionError, MAX_GUIDANCE_CHARS, SLOT_REF_PATTERN, contains_control_characters,
    assembled_text, normalize_layout, project_error_name, project_field, redact_clean_text,
)
from aegis_core.guidance_projection import GuidanceResult as _GuidanceResult
from aegis_core.hosts import GENERIC
from aegis_core.guidance_grammar import clip_redacted

__all__ = [
    "SlotResolutionError",
    "SlotRegistry",
    "SLOT_REF_PATTERN",
    "PLATFORM_SLOT_PROFILES",
    "DEFAULT_SLOTS",
    "profile_id",
    "render_for_host",
    "render_scan_result",
    "scan_registry",
    "sanitize_slot_value",
    "MAX_SLOT_VALUE_LEN",
]

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


def sanitize_slot_value(key: str, value: str) -> Optional[str]:
    """Refuse non-layout controls; collapse layout, redact once, then cap."""
    value = str(value)
    if len(value) > MAX_GUIDANCE_CHARS:
        return None
    try:
        text = normalize_layout(value, single_line=True)
    except GuidanceProjectionError:
        return None
    capability = str(key).startswith(_CAPABILITY_PREFIXES)
    if capability and (len(text) > MAX_SLOT_VALUE_LEN or not _CAPABILITY_VALUE.fullmatch(text)):
        return None
    try:
        text = clip_redacted(redact_clean_text(text), MAX_SLOT_VALUE_LEN)
    except GuidanceProjectionError:
        return None
    if capability and not _CAPABILITY_VALUE.fullmatch(text):
        return None
    return text or None


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
                and '.' + str(k)[len('ast_driver_'):].lstrip('.').lower() in NATIVE_SOURCE_EXTENSIONS)
        }
        self._warnings: List[str] = list(warnings or [])
        self._warning_source = self._warnings
        self._control_refusals: set[str] = set()

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
            if '.' + ext.lstrip('.').lower() in NATIVE_SOURCE_EXTENSIONS:
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
        control_refusals: set[str] = set()
        for key, value in user_reg.to_dict().items():
            if key.startswith(_CAPABILITY_PREFIXES):
                clean = sanitize_slot_value(key, value)
                if clean is None:
                    invalid.append(key)
                    if contains_control_characters(value):
                        control_refusals.add(key)
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
        registry = cls(merged, warnings=warnings)
        registry._control_refusals = control_refusals
        return registry

    def sanitized(self) -> SlotRegistry:
        """Copy safe values; remember only names of overrides refused for controls."""
        safe = {}
        refused = set(self._control_refusals)
        for key, value in self._slots.items():
            clean = sanitize_slot_value(key, value)
            if clean is not None:
                safe[key] = clean
            elif contains_control_characters(value):
                refused.add(key)
        registry = SlotRegistry(safe)
        registry._control_refusals = refused
        # Raw warning text is a complete field. Refused-slot notices below are
        # assembled from separately projected keys owned by this producer.
        warnings = project_field(self._warning_source)
        for key in sorted(refused):
            try:
                name = project_error_name(key)
            except GuidanceProjectionError as exc:
                name = exc.code
            if len(name) > 80:
                name = clip_redacted(name, 77) + "..."
            warning = assembled_text(f"ignored slot {name}: value withheld (control characters)")
            if warning not in warnings:
                warnings.append(warning)
        registry._warnings = warnings
        registry._warning_source = self._warning_source
        return registry

    def control_refused(self, key: str) -> bool:
        """Whether substitution must withhold the instruction for a refused override."""
        return key in self._control_refusals

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
        """Resolve external commands; native Python, JS/TS and Rust need no command slot."""
        clean_ext = extension.lstrip(".").lower()
        if clean_ext == "py" or f'.{clean_ext}' in NATIVE_SOURCE_EXTENSIONS:
            return None
        return self.get(f"ast_driver_{clean_ext}") or self.get("ast_driver")

    def get_configured_extensions(self) -> set[str]:
        """Return native source extensions and configured external-driver extensions."""
        exts = {".py"} | NATIVE_SOURCE_EXTENSIONS
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

    Completed text shares scan's Evidence/control/redaction projection. An
    unclassifiable body is withheld; a resource/type refusal returns that same
    fixed withholding text and its fixed projection code in warnings.
    """
    try:
        registry = SlotRegistry.for_platform(host or GENERIC, workspace=workspace)
        warnings = []
    except (SlotResolutionError, OSError):
        merged = dict(DEFAULT_SLOTS)
        merged.update(PLATFORM_SLOT_PROFILES[profile_id(host)])
        from aegis_core.workspace.layout import AEGIS_DIRNAME

        files = f"~/{AEGIS_DIRNAME}/config.json" + (f" or {AEGIS_DIRNAME}/config.json" if workspace is not None else "")
        registry, warnings = SlotRegistry(merged), [_CONFIG_UNREADABLE.format(files=files)]
    from aegis_core.guidance_projection import GuidanceProjectionError, WITHHELD_GUIDANCE, field_text, project_field

    try:
        registry = registry.sanitized()
        warnings.extend(w for w in registry.warnings if w not in warnings)
        return field_text(project_field(text, registry)), warnings
    except GuidanceProjectionError as exc:
        return WITHHELD_GUIDANCE, warnings + [exc.code]


_SCAN_CONFIG_UNREADABLE = (
    "config files (.aegis/config.json or ~/.aegis/config.json) could not be read or parsed; "
    "${SLOT.*} placeholders were left unresolved"
)
# Compatibility rule collections use the shared shape/projection predicate.
_SCAN_LISTS = ("relevant_rules", "invariant_warnings")


def _add_warnings(result: Dict[str, Any], warnings: Sequence[str]) -> None:
    existing = result.get("warnings")
    merged = list(existing) if isinstance(existing, list) else []
    merged.extend(w for w in warnings if w not in merged)
    if merged:
        result["warnings"] = merged


def scan_registry(host: Optional[str], workspace: str | Path | None = None) -> SlotRegistry:
    """Load one sanitized request registry, with fixed warnings on config failure.

    An empty fallback leaves placeholders unresolved while Evidence projection
    and token accounting still run. No config content or exception is echoed.
    """
    try:
        loaded = SlotRegistry.for_platform(host or GENERIC, workspace=str(workspace) if workspace is not None else None)
    except (SlotResolutionError, OSError, RuntimeError):
        return SlotRegistry(warnings=[_SCAN_CONFIG_UNREADABLE])
    return loaded.sanitized()


def render_scan_result(result: Dict[str, Any], host: Optional[str],
                       workspace: str | Path | None = None) -> Dict[str, Any]:
    """A scan result (aegis_core.scan) with its ${SLOT.*} references rendered for ``host``.

    Real scan results retain private source/fitness snapshots. Reproject that
    snapshot with one request registry, so complete slots are rendered before
    truncation, selection and budgeting even when called after a raw scan.
    Ordinary dictionaries are projected from a bounded private copy and receive
    final token accounting. Opaque overflow refuses as guidance_projection_budget.
    Checked projection refusals retain their fixed code and diagnostic locations
    independently of the guidance token budget, including plain/JSON copies.
    The agent reads this output, so
    values are sanitized before they are inlined, and ignored keys or a config file
    that cannot be parsed are reported in ``result["warnings"]`` (H5). Slot loading
    never costs the agent its guidance: on such an error the placeholders stay as
    written and a fixed warning, quoting no file content or path, says so.
    """
    from aegis_core.guidance_projection import GuidanceResult

    registry = scan_registry(host, workspace)
    if isinstance(result, _PlainScanResult):
        return result.with_registry(registry)
    if isinstance(result, GuidanceResult):
        return _render_bound_result(result, registry)
    return _render_plain_result(result, registry)


class _PlainScanResult(_GuidanceResult):
    def __init__(self, payload: Dict[str, Any], source: Dict[str, Any] | _GuidanceResult, *,
                 identities: tuple[str, ...] = (), mandatory_count: Optional[int] = None) -> None:
        super().__init__(payload)
        self._source = source
        self._canonical_rule_ids = identities
        self._mandatory_count = mandatory_count

    def with_registry(self, registry: SlotRegistry) -> Dict[str, Any]:
        if isinstance(self._source, _GuidanceResult):
            return _render_bound_result(self._source, registry)
        return _render_plain_result(self._source, registry)

    def exposure_rule_ids(self) -> tuple[str, ...]:
        return self._canonical_rule_ids

    def staged_mandatory_count(self) -> int:
        if self._mandatory_count is not None:
            return self._mandatory_count
        return super().staged_mandatory_count()


def _render_bound_result(source: _GuidanceResult, registry: SlotRegistry) -> Dict[str, Any]:
    # Bind the captured structured source once, then treat every resulting
    # assembled field as text. None prevents expansion of literal slot values.
    bound = source.with_registry(registry)
    identities = bound.exposure_rule_ids() if isinstance(bound, _GuidanceResult) else ()
    mandatory_count = bound.staged_mandatory_count() if isinstance(bound, _GuidanceResult) else None
    return _render_plain_result(dict(bound), None, replay_source=source,
                                identities=identities, staged_mandatory_count=mandatory_count)


def _render_plain_result(source: Dict[str, Any], registry: Optional[SlotRegistry], *,
                         replay_source: Optional[_GuidanceResult] = None,
                         identities: tuple[str, ...] = (),
                         staged_mandatory_count: Optional[int] = None) -> Dict[str, Any]:
    from copy import deepcopy
    from aegis_core.guidance_projection import (
        GuidanceProjectionError, checked_result_copy, finish_payload, projection_refusal, projection_refusal_copy,
    )

    try:
        refusal = projection_refusal_copy(source)
        if refusal is not None:
            return _PlainScanResult(deepcopy(refusal), replay_source if replay_source is not None else refusal,
                                    identities=(), mandatory_count=0)
        snapshot = checked_result_copy(source, registry)
        result = deepcopy(snapshot)
        if registry is not None:
            _add_warnings(result, registry.warnings)
        result = _project_scan_fields(result, registry)
        payload = finish_payload(result, preserve_omissions=replay_source is not None,
                                 reserve_warning=replay_source is None,
                                 staged_mandatory_count=staged_mandatory_count)
        # Finalization either retains all entries or discards the selection.
        # Replay remains the original source; telemetry describes this result.
        if payload.get("status") == "FAIL" or len(payload.get("relevant_rules", [])) != len(result.get("relevant_rules", [])):
            identities, staged_mandatory_count = (), 0
        return _PlainScanResult(payload, replay_source if replay_source is not None else snapshot,
                                identities=identities, mandatory_count=staged_mandatory_count)
    except GuidanceProjectionError as exc:
        return projection_refusal(exc.code)


def _project_scan_fields(result: Dict[str, Any], registry: Optional[SlotRegistry]) -> Dict[str, Any]:
    """Project compatibility fields using the same pure functions as scan."""
    from aegis_core.guidance_projection import field_text, project_field, project_envelope_fields, project_rule_entries

    guidance = result.get("guidance")
    if "guidance" in result:
        result["guidance"] = field_text(project_field(guidance, registry))
    for key in _SCAN_LISTS:
        if key in result:
            result[key] = project_rule_entries(result[key], registry)
    project_envelope_fields(result, registry)
    return result
