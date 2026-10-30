"""Unit tests for SlotRegistry in aegis_core.skills.slots."""
from __future__ import annotations

import json

import pytest

from aegis_core.skills.slots import (
    SlotRegistry,
    SlotResolutionError,
    profile_id,
)


def test_slot_registry_init_and_get():
    reg = SlotRegistry({"key1": "val1", "key2": None})
    assert reg.get("key1") == "val1"
    assert reg.get("key2") is None
    assert reg.get("missing", "default") == "default"
    assert reg.to_dict() == {"key1": "val1"}


def test_slot_registry_load_nonexistent(tmp_path):
    reg = SlotRegistry.load(tmp_path)
    assert reg.to_dict() == {}


def test_slot_registry_load_reads_packaged_driver_opt_ins(tmp_path):
    (tmp_path / ".aegis").mkdir()
    (tmp_path / ".aegis" / "config.json").write_text(
        json.dumps({"v": 1, "ast": {"packaged_drivers": ["rs"]}}), encoding="utf-8"
    )

    reg = SlotRegistry.load(tmp_path)
    assert reg.to_dict() == {"ast_driver_rs": "{python} .aegis/drivers/rust_ast.py"}


def test_an_extension_without_a_packaged_driver_is_ignored_with_a_warning(tmp_path):
    (tmp_path / ".aegis").mkdir()
    (tmp_path / ".aegis" / "config.json").write_text(
        json.dumps({"v": 1, "ast": {"packaged_drivers": ["md", "rs"]}}), encoding="utf-8"
    )

    reg = SlotRegistry.load(tmp_path)
    assert reg.to_dict() == {"ast_driver_rs": "{python} .aegis/drivers/rust_ast.py"}
    assert reg.warnings == [
        "ignored 1 'ast.packaged_drivers' entry in .aegis/config.json: "
        "only extensions with a driver that ships inside aegis can be enabled"
    ]


def test_slot_registry_load_invalid_json(tmp_path):
    (tmp_path / ".aegis").mkdir()
    (tmp_path / ".aegis" / "config.json").write_text(": : invalid", encoding="utf-8")

    with pytest.raises(SlotResolutionError, match="not valid JSON"):
        SlotRegistry.load(tmp_path)


def test_slot_registry_load_user_reads_drivers_and_slots(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True)
    (home / ".aegis" / "config.json").write_text(
        json.dumps({"v": 1, "drivers": {"md": "md-ast"}, "slots": {"tool": "/usr/bin/tool"}}), encoding="utf-8"
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    reg = SlotRegistry.load_user(tmp_path / "ws")
    assert reg.to_dict() == {"tool": "/usr/bin/tool", "ast_driver_md": "md-ast"}


def test_slot_registry_resolve_strict():
    reg = SlotRegistry({"compiler": "rustc"})
    # Valid interpolation
    assert reg.resolve("Run ${compiler} --version") == "Run rustc --version"
    assert reg.resolve("Run ${SLOT.compiler} --version") == "Run rustc --version"

    # Missing slot in strict mode raises error
    with pytest.raises(SlotResolutionError, match="Unresolved required slot: 'linker'"):
        reg.resolve("Run ${linker}", strict=True)

    # Missing slot in non-strict mode preserves reference
    assert reg.resolve("Run ${linker}", strict=False) == "Run ${linker}"


def test_slot_registry_get_ast_driver():
    reg = SlotRegistry({
        "ast_driver": "default_driver",
        "ast_driver_rs": "cargo_driver",
    })
    # Python is always None
    assert reg.get_ast_driver("py") is None
    assert reg.get_ast_driver(".py") is None

    # Specific extension resolves ast_driver_<ext>
    assert reg.get_ast_driver("rs") == "cargo_driver"
    assert reg.get_ast_driver(".rs") == "cargo_driver"

    # Fallback to ast_driver for an extension without a native parser
    assert reg.get_ast_driver("kt") == "default_driver"

    # Native JS/TS never takes a command slot, even when one is configured
    assert SlotRegistry({"ast_driver": "d", "ast_driver_ts": "node ts.js"}).get_ast_driver("ts") is None
    assert reg.get_ast_driver(".mjs") is None


def test_slot_registry_get_configured_extensions():
    from aegis_core.ast.runner import NATIVE_JS_EXTENSIONS

    native = {".py", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
    assert NATIVE_JS_EXTENSIONS | {".py"} == native
    # Empty registry always includes the in-process languages
    empty_reg = SlotRegistry({})
    assert empty_reg.get_configured_extensions() == native

    # Configured slots add extensions
    reg = SlotRegistry({
        "ast_driver_rs": "python3 rust.py",
        "ast_driver_.go": "go run go.go",
        "ast_driver_ts": "node ts.js",
        "unrelated_slot": "some_value",
    })
    exts = reg.get_configured_extensions()
    assert exts == native | {".rs", ".go"}


@pytest.mark.parametrize("host, profile", [
    ("claude-code", "claude-code"),
    ("  codex-cli\n", "codex-cli"),  # surrounding whitespace is not part of the id
    ("antigravity", "antigravity"),
    ("claude-desktop", "generic"),  # identity only: its host row names the generic profile
    ("claude", "claude-code"),  # v3 platform names keep the profile they had
    ("gemini", "antigravity"),
    ("generic", "generic"),
    ("no-such-host", "generic"),  # an unknown host never borrows a vendor's profile
    ("", "generic"),
    (None, "generic"),
])
def test_profile_id_names_the_slot_profile_a_host_renders_with(host, profile):
    assert profile_id(host) == profile
