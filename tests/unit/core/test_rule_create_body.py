"""create_rule body input and legacy call forms (aegis_core.lifecycle.creation)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.lifecycle.creation import create_rule
from aegis_core.yaml_engine.frontmatter import _get_body, parse_frontmatter

MAX_BODY = 64 * 1024


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    return tmp_path


def _rule_files(ws: Path) -> list[Path]:
    return sorted((ws / ".aegis" / "rules").rglob("*.md"))


def test_body_replaces_generated_body_and_keeps_frontmatter(ws: Path) -> None:
    body = "## Why\n\nNever call `subprocess.run` with `shell=True`.\n\n- see SECURITY.md\n"

    path = create_rule("trap", "No shell=True", id_override="no-shell", workspace=ws, body=body)

    text = path.read_text(encoding="utf-8")
    meta = parse_frontmatter(text) or {}
    assert meta["id"] == "no-shell"
    assert meta["type"] == "trap"
    assert meta["hypothesis"] == "No shell=True"
    assert _get_body(text).strip() == body.strip()
    assert "### Prediction" not in text
    assert text.endswith("\n")


@pytest.mark.parametrize("body", ["", "   \n\t\n"], ids=["empty", "whitespace"])
def test_empty_body_is_rejected_and_nothing_written(ws: Path, body: str) -> None:
    with pytest.raises(ValueError, match=r"^rule body is empty$"):
        create_rule("trap", "Empty body", id_override="empty-body", workspace=ws, body=body)
    assert _rule_files(ws) == []


def test_body_over_64_kib_is_rejected_and_nothing_written(ws: Path) -> None:
    with pytest.raises(ValueError, match=r"^rule body exceeds 64 KiB \(65536 bytes\)$"):
        create_rule("trap", "Huge body", id_override="huge", workspace=ws, body="x" * (MAX_BODY + 1))
    assert _rule_files(ws) == []


def test_body_limit_counts_utf8_bytes_not_characters(ws: Path) -> None:
    # 32,769 two-byte characters = 65,538 bytes.
    with pytest.raises(ValueError, match="exceeds 64 KiB"):
        create_rule("trap", "Wide body", id_override="wide", workspace=ws, body="é" * (MAX_BODY // 2 + 1))


def test_body_of_exactly_64_kib_is_accepted(ws: Path) -> None:
    path = create_rule("trap", "Max body", id_override="max-body", workspace=ws, body="y" * MAX_BODY)
    assert _get_body(path.read_text(encoding="utf-8")).strip() == "y" * MAX_BODY


def test_legacy_positional_form_generates_default_body(ws: Path) -> None:
    path = create_rule("trap", "Legacy positional", "pred", "fals", workspace=ws)
    text = path.read_text(encoding="utf-8")
    assert "### Prediction\npred" in text
    assert "### Falsification Criteria\nfals" in text


def test_legacy_keyword_form_generates_default_body(ws: Path) -> None:
    path = create_rule(
        rule_type="invariant", hypothesis="Legacy keyword", prediction="", falsification="",
        weight=1.0, tags=["a"], expiry_sessions=15, expiry_days=60, minimum_mode="",
        id_override="legacy-kw", target_paths=["*.py"],
        domain="correctness", workspace=ws, enforcement=None,
    )
    meta = parse_frontmatter(path.read_text(encoding="utf-8")) or {}
    assert meta["enforcement"] == "gate"
    assert "### Prediction" in path.read_text(encoding="utf-8")


# Every separator str.splitlines() honours; the frontmatter parser splits on all of them.
_LINE_BREAKS = ["\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


@pytest.mark.parametrize("sep", _LINE_BREAKS, ids=lambda s: f"U+{ord(s[-1]):04X}" if len(s) == 1 else "CRLF")
@pytest.mark.parametrize("field", ["domain", "minimum_mode"])
def test_multiline_unquoted_frontmatter_values_are_rejected(ws: Path, field: str, sep: str) -> None:
    """A line break in an unquoted scalar would inject frontmatter keys."""
    with pytest.raises(ValueError, match=rf"^Invalid {field} .*: must be a single line\.$"):
        create_rule("trap", "Injected", id_override="injected", workspace=ws, **{field: f"x{sep}activation: dormant"})
    assert _rule_files(ws) == []


@pytest.mark.parametrize(
    "field", ["weight", "expiry_sessions", "expiry_days"],
)
def test_numeric_frontmatter_values_must_be_numbers(ws: Path, field: str) -> None:
    """These are interpolated unquoted too; a string carrying a line break would inject keys."""
    with pytest.raises(ValueError, match=rf"^Invalid {field} 'x\\nactivation: dormant': must be a number\.$"):
        create_rule("trap", "Injected", id_override="injected", workspace=ws, **{field: "x\nactivation: dormant"})
    assert _rule_files(ws) == []


def test_numeric_frontmatter_values_are_written_as_numbers(ws: Path) -> None:
    path = create_rule(
        "trap", "Numbers", id_override="numbers", workspace=ws, weight=2, expiry_sessions=None, expiry_days=30,
    )

    meta = parse_frontmatter(path.read_text(encoding="utf-8")) or {}
    assert meta["impact_weight"] == 2.0
    assert meta["expiry_sessions"] is None
    assert meta["expiry_days"] == 30


def test_none_domain_and_minimum_mode_fall_back_to_defaults(ws: Path) -> None:
    """Programmatic callers pass None for "not given"; that must not crash the newline guard."""
    path = create_rule("trap", "Defaults", id_override="defaults", workspace=ws, domain=None, minimum_mode=None)

    meta = parse_frontmatter(path.read_text(encoding="utf-8")) or {}
    assert meta["domain"] == "correctness"
    assert "minimum_mode" not in meta
