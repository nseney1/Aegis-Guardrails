"""The CHANGELOG's v4.0.0 breaking-change list must match what the parser does.

Every removed command and flag the entry names must be rejected with exit status 2.
Removed commands, and the removed ``init`` and ``uninstall`` flags, print one line
naming the replacement; the other removed flags get the argument parser's usage
error, so the entry's list is the only place that names their replacements.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegis_cli.cli import REMOVED_COMMANDS, main

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


def _v4_entry() -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(r"^## \[4\.0\.0\].*?(?=^## \[|\Z)", text, re.M | re.S)
    assert match, "CHANGELOG.md has no '## [4.0.0]' entry"
    return match.group(0)


def _run(argv, capsys):
    try:
        rc = main(argv)
    except SystemExit as exc:
        rc = exc.code
    return rc, capsys.readouterr().err


# (argv, the flag as the 4.0.0 entry writes it, whether a one-line pointer is printed)
REMOVED_FLAGS = [
    (["--plumbing", "status"], "--plumbing", False),
    (["--internal", "status"], "--internal", False),
    (["-q", "status"], "-q", False),
    (["-v", "status"], "-v", False),
    (["--no-emoji", "status"], "--no-emoji", False),
    (["init", "--platform", "claude"], "--platform", True),
    (["init", "--mcp"], "--mcp", True),
    (["init", "--local"], "--local", True),
    (["uninstall", "--platform", "claude"], "--platform", True),
    (["uninstall", "-p", "claude"], "-p", True),
    (["uninstall", "--local"], "--local", True),
    (["uninstall", "--purge"], "--purge", True),
    (["check", "--release"], "--release", False),
    (["check", "--release-gate"], "--release-gate", False),
    (["check", "--require-arbitration"], "--require-arbitration", False),
    (["check", "--provider", "x"], "--provider", False),
    (["check", "--in-band"], "--in-band", False),
    (["check", "--no-layer2"], "--no-layer2", False),
    (["check", "--all"], "--all", False),
    (["check", "--files", "a.py"], "--files", False),
    (["check", "--pre-commit"], "--pre-commit", False),
    (["check", "--checkpoint-only"], "--checkpoint-only", False),
    (["check", "--layer1-only"], "--layer1-only", False),
    (["check", "--deep"], "--deep", False),
    (["rule", "create", "--from-description", "x"], "--from-description", False),
    (["rule", "create", "--weight", "1"], "--weight", False),
    (["rule", "create", "--expiry-sessions", "1"], "--expiry-sessions", False),
    (["rule", "create", "--expiry-days", "1"], "--expiry-days", False),
    (["rule", "create", "--minimum-mode", "x"], "--minimum-mode", False),
    (["rule", "create", "--effector", "x"], "--effector", False),
    (["rule", "create", "--memory", "x"], "--memory", False),
    (["rule", "promote", "x", "--rule", "y"], "--rule", False),
    (["rule", "promote", "x", "--reason", "y"], "--reason", False),
    (["rule", "demote", "x", "--force"], "--force", False),
    (["rule", "archive", "--apply"], "--apply", False),
    (["status", "--all"], "status --all", False),
    (["doctor", "--fix-path"], "doctor --fix-path", False),
]


@pytest.mark.parametrize(
    "argv, written, pointer", REMOVED_FLAGS, ids=[" ".join(argv) for argv, _, _ in REMOVED_FLAGS]
)
def test_each_removed_flag_in_the_entry_exits_2(argv, written, pointer, tmp_path, monkeypatch, capsys):
    assert f"`{written}`" in _v4_entry() or f"`aegis {written}`" in _v4_entry(), (
        f"the 4.0.0 entry does not name {written!r}"
    )
    monkeypatch.chdir(tmp_path)
    rc, err = _run(argv, capsys)
    assert rc == 2
    lines = err.strip().splitlines()
    if pointer:
        assert len(lines) == 1 and " was removed in v4: " in lines[0], err
    else:
        assert "was removed in v4" not in err
        assert "unrecognized arguments" in lines[-1] or "invalid choice" in lines[-1], err


def _named_in(name: str, entry: str) -> bool:
    words = name.split()
    forms = {f"`{name}`", f"`aegis {name}`"}
    if len(words) == 2 and words[0] in REMOVED_COMMANDS:
        forms.add(f"`{words[0]}`")  # 'system doctor' is removed with 'system'
    if len(words) == 2 and words[0] == "hook":
        forms.add(f"`{words[1]}`")  # the entry lists the hook phases by name
    return any(form in entry for form in forms)


def test_every_removed_command_is_named_in_the_entry():
    entry = _v4_entry()
    assert sorted(name for name in REMOVED_COMMANDS if not _named_in(name, entry)) == []


def test_the_lead_paragraph_promises_pointers_only_where_the_parser_prints_them():
    lead = _v4_entry().split("### ", 1)[0]
    assert not re.search(r"[Ee]very removed command and flag[^.]*prints", lead), lead
    assert re.search(r"removed `init` and `uninstall` flags, print one line", lead), lead


# --- the 4.1.0 entry -------------------------------------------------------------------

def _entry(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(rf"^## \[{re.escape(version)}\].*?(?=^## \[|\Z)", text, re.M | re.S)
    assert match, f"CHANGELOG.md has no '## [{version}]' entry"
    return match.group(0)


def _subsection(entry: str, title: str) -> str:
    match = re.search(rf"^### {re.escape(title)}\n(.*?)(?=^### |\Z)", entry, re.M | re.S)
    assert match, f"no '### {title}' in the entry"
    return " ".join(match.group(1).split())


def test_the_4_1_0_entry_is_dated_and_sits_above_4_0_0():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## \[(.*?)\] - (.*)$", text, re.M)
    versions = [v for v, _ in headings]
    assert versions.index("4.1.0") < versions.index("4.0.0")
    assert dict(headings)["4.1.0"] == "2026-10-16"


def test_the_4_1_0_entry_names_every_command_4_1_added():
    """Each new command and flag, as the parser spells it."""
    added = _subsection(_entry("4.1.0"), "Added")
    for name in ("aegis team claim", "renew", "transfer", "release", "gc", "list", "metrics",
                 "aegis check --lane", "--base-policy", "aegis hook install --host", "aegis hook uninstall --host",
                 "aegis hook run pre-tool --host", "aegis skills sync", "aegis init --skills",
                 "jit.scan_window_s"):
        assert f"`{name}`" in added or f"`{name} " in added or f" {name}`" in added, name
    rc = None
    for argv in (["team", "--help"], ["skills", "sync", "--help"], ["hook", "run", "--help"]):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
        assert rc == 0, argv


def test_the_4_1_0_known_limitations_are_the_ones_doctor_prints():
    from aegis_cli.hooks import registrar

    limits = _subsection(_entry("4.1.0"), "Known limitations")
    for gap in registrar.KNOWN_GAPS:
        assert " ".join(gap.split()) in limits, gap
    assert "advisory" in limits and "check --lane" in limits


def test_the_4_1_0_entry_records_the_staged_ast_driver_fix():
    fixed = _subsection(_entry("4.1.0"), "Fixed")
    assert "escapes workspace" in fixed and "Rust" in fixed and "index snapshot" in fixed


def test_the_4_1_0_entry_has_a_security_section():
    security = _subsection(_entry("4.1.0"), "Security")
    for phrase in ("guardrails, not a security boundary", "--scope project", "/hooks", "not an identity"):
        assert phrase in security, phrase


def test_changelog_top_entry_matches_current_version_and_is_strictly_descending():
    """The top CHANGELOG release heading must match aegis_core._version.__version__, and all
    release headings must appear in strictly descending semantic version order with ISO dates."""
    from aegis_core import _version

    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$", text, re.M)
    assert headings, "CHANGELOG.md has no dated release headings"
    assert headings[0][0] == _version.__version__, (
        f"top CHANGELOG entry is {headings[0][0]!r}, expected current version {_version.__version__!r}"
    )
    tuples = [tuple(int(part) for part in ver.split(".")) for ver, _ in headings]
    for prev_ver, next_ver in zip(tuples, tuples[1:]):
        assert prev_ver > next_ver, f"CHANGELOG versions out of descending order: {prev_ver} <= {next_ver}"


def test_changelog_names_every_registered_cli_command_and_mcp_tool():
    """Every CLI command and MCP tool in the contract snapshots must be documented in CHANGELOG.md."""
    import json

    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    cli_tree = json.loads((ROOT / "tests" / "contract" / "cli_tree.json").read_text(encoding="utf-8"))
    mcp_tools = json.loads((ROOT / "tests" / "contract" / "mcp_tools.json").read_text(encoding="utf-8"))
    for entry in cli_tree["registry"]:
        name = entry["name"]
        assert f"`aegis {name}" in text or f"`{name}`" in text, f"CLI command {name!r} missing from CHANGELOG.md"
    for tool in mcp_tools["tools"]:
        name = tool["name"]
        assert f"`{name}`" in text or f"`{name}(" in text, f"MCP tool {name!r} missing from CHANGELOG.md"
