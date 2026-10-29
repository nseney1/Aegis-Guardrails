"""Docs contracts: validate examples against the parser and paths against their owners.

Commands are inspected, never executed. Only the explicitly marked future roadmap in
why-aegis is excluded; its version guard runs independently of command validation.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ("README.md", "SECURITY.md", "PRIVACY.md", "CONTRIBUTING.md")
PLANNED = "## Planned, not shipped"


def shipped_text(text: str, name: str) -> str:
    """Replace only the authorized roadmap body with blank lines, preserving line numbers."""
    planned = False
    lines = []
    for line in text.splitlines():
        if line.startswith("## "):
            planned = name == "docs/why-aegis.md" and line == PLANNED
        lines.append("" if planned else line)
    return "\n".join(lines)


def roadmap_problems(text: str, current: tuple[int, int]) -> list[str]:
    planned = False
    versions = []
    errors = []
    for line in text.splitlines():
        if line.startswith("## "):
            planned = line == PLANNED
        if planned:
            for match in re.finditer(r"\b(?:v)?(\d+)\.(\d+)(?:\.(\d+))?\b", line):
                version = tuple(int(group or 0) for group in match.groups())
                versions.append(version)
                if version[:2] <= current:
                    errors.append(f"shipped version {'.'.join(map(str, version))} in planned section")
    if PLANNED in text.splitlines() and not versions:
        errors.append("planned section names no future release")
    return errors


def _examples(text: str):
    """Inline command examples and shell commands at line starts, including continuations."""
    text = text.replace("\\\n", " ")
    for number, line in enumerate(text.splitlines(), 1):
        for match in re.finditer(r"`(aegis(?:\s+[^`]+)?)`", line):
            yield number, match.group(1)
        match = re.match(r"\s*(?:\$ )?(aegis\s+[^#]+)", line)
        if match:
            yield number, match.group(1).rstrip()


def command_problems(text: str, parser: dict, name: str = "doc.md") -> list[str]:
    problems = []
    for line, example in _examples(shipped_text(text, name)):
        # Optional syntax and placeholders are documentation notation, not commands to run.
        cleaned = re.sub(r"<[^>]*>", "ARG", example).replace("[", "").replace("]", "")
        try:
            words = shlex.split(cleaned)
        except ValueError as exc:
            problems.append(f"{name}:{line}: malformed command: {exc}")
            continue
        branches = [([parser], 0)]
        for word in words[1:]:
            following = []
            for nodes, skip in branches:
                if skip:
                    following.append((nodes, skip - 1))
                    continue
                if word in ("...", "…", "ARG"):
                    following.append((nodes, 0))
                    continue
                options = {flag: arg for node in nodes for arg in node["arguments"] for flag in arg["flags"]}
                if word.startswith("-"):
                    flag = word.split("=", 1)[0].rstrip(",.;:")
                    if flag not in options:
                        problems.append(f"{name}:{line}: unknown flag {flag}: {example}")
                    else:
                        skip = int("=" not in word and options[flag].get("nargs") != 0)
                        following.append((nodes, skip))
                    continue
                choices = nodes[-1].get("commands", {})
                if choices:
                    for alternative in word.split("|"):
                        if alternative not in choices:
                            problems.append(f"{name}:{line}: unknown command {alternative}: {example}")
                        else:
                            following.append(([*nodes, choices[alternative]], 0))
                elif any(not arg["flags"] for arg in nodes[-1]["arguments"]):
                    following.append((nodes, 0))
                else:
                    problems.append(f"{name}:{line}: unknown command {word}: {example}")
            branches = following
    return problems


def _docs():
    return {name: (ROOT / name).read_text(encoding="utf-8") for name in DOCS} | {
        p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8") for p in (ROOT / "docs").glob("*.md")}


def current_examples(text: str, name: str, removed: dict) -> str:
    """The generated reference documents removed commands too; validate that table separately."""
    retired_table = False
    lines = []
    for line in text.splitlines():
        if re.match(r"#{1,3} ", line):
            retired_table = name == "docs/reference.md" and line == "### Removed commands"
        match = re.match(r"\| `(aegis ([^`]+))` \|", line) if retired_table else None
        if match and match.group(2) in removed:
            line = line.replace(f"`{match.group(1)}`", "retired command", 1)
        lines.append(line)
    return "\n".join(lines)


def test_documented_commands_and_flags_exist():
    contract = json.loads((ROOT / "tests/contract/cli_tree.json").read_text(encoding="utf-8"))
    problems = [problem for name, text in _docs().items()
                for problem in command_problems(current_examples(text, name, contract["removed_commands"]),
                                                contract["parser"], name)]
    assert problems == []


@pytest.mark.parametrize("example, message", [
    ("`aegis nonexistent`", "unknown command nonexistent"),
    ("`aegis check --nonexistent`", "unknown flag --nonexistent"),
    ("aegis rule nonexistent", "unknown command nonexistent"),
    ("`aegis check --format <format> --nonexistent`", "unknown flag --nonexistent"),
])
def test_command_guard_rejects_unknown_examples(example, message):
    parser = json.loads((ROOT / "tests/contract/cli_tree.json").read_text(encoding="utf-8"))["parser"]
    assert message in command_problems(example, parser)[0]


@pytest.mark.parametrize("example, message", [
    ("aegis hook install|status --force", "unknown flag --force"),
    ("aegis hook status|install --force", "unknown flag --force"),
    ("aegis rule|hook insight add", "unknown command insight"),
    ("aegis hook|rule insight add", "unknown command insight"),
    ("aegis rule|status insight add", "unknown command insight"),
    ("aegis status|rule insight add", "unknown command insight"),
])
def test_command_alternatives_must_all_accept_the_remaining_example(example, message):
    parser = json.loads((ROOT / "tests/contract/cli_tree.json").read_text(encoding="utf-8"))["parser"]
    problems = command_problems(f"`{example}`", parser)
    assert any(message in problem for problem in problems), problems


@pytest.mark.parametrize("commands", ["install|uninstall", "uninstall|install"])
def test_command_alternatives_accept_shared_flags_and_values(commands):
    parser = json.loads((ROOT / "tests/contract/cli_tree.json").read_text(encoding="utf-8"))["parser"]
    assert command_problems(f"`aegis hook {commands} --host <host> --force`", parser) == []


def test_roadmap_exemption_is_narrow_and_ends_at_the_next_section():
    parser = json.loads((ROOT / "tests/contract/cli_tree.json").read_text(encoding="utf-8"))["parser"]
    text = PLANNED + "\n### 4.8.0\n`aegis claims check FILE`\n## Shipped\n`aegis check --nonexistent`\n"
    problems = command_problems(text, parser, "docs/why-aegis.md")
    assert len(problems) == 1 and "unknown flag --nonexistent" in problems[0]
    assert any("unknown command claims" in p for p in command_problems(text, parser, "README.md"))
    assert command_problems(text.replace(PLANNED, "## Planned"), parser, "docs/why-aegis.md")
    assert roadmap_problems(text, (4, 4)) == []
    assert roadmap_problems(text.replace("4.8.0", "4.4.0"), (4, 4)) == [
        "shipped version 4.4.0 in planned section"]
    assert roadmap_problems(text.replace("4.8.0", "v4.3"), (4, 4)) == [
        "shipped version 4.3.0 in planned section"]
    assert roadmap_problems(PLANNED + "\n`aegis claims check FILE`", (4, 4)) == [
        "planned section names no future release"]


def test_removed_command_table_does_not_hide_unknown_or_current_examples():
    text = "### Removed commands\n| `aegis agent` | retired |\n| `aegis missing` | retired |\n## Current\n`aegis agent`"
    result = current_examples(text, "docs/reference.md", {"agent": "use scan"})
    assert result.count("`aegis agent`") == 1 and "`aegis missing`" in result
    assert current_examples(text, "README.md", {"agent": "use scan"}) == text


def test_plain_strict_and_calibration_are_registered_examples():
    parser = json.loads((ROOT / "tests/contract/cli_tree.json").read_text(encoding="utf-8"))["parser"]
    assert command_problems("`aegis check --strict` and `aegis check --calibration`", parser) == []


def test_planned_releases_are_future_versions():
    from aegis_core._version import __version__

    why = _docs()["docs/why-aegis.md"]
    assert PLANNED in why.splitlines()
    assert roadmap_problems(why, tuple(map(int, __version__.split(".")[:2]))) == []


# Historical passages stay in CHANGELOG; present-tense policy must not repeat them.
FALSE_CLAIMS = (
    "holds no keys", "only witnessed passes earn rule credit", "Credit comes from signals the agent cannot write",
    "until labels become the only promotion path", "unowned governance/workflow files in `CODEOWNERS`",
    "leaving a governance/workflow file unowned in `CODEOWNERS` fails `aegis check --ci`",
    "the rules that apply to the files about to change (read-only)",
    "an unknown age does not itself block promotion",
)


def stale_claims(text: str) -> list[str]:
    return [claim for claim in FALSE_CLAIMS if claim.lower() in text.lower()]


def test_present_policy_does_not_repeat_corrected_claims():
    assert {name: stale_claims(text) for name, text in _docs().items() if stale_claims(text)} == {}


@pytest.mark.parametrize("claim", FALSE_CLAIMS)
def test_policy_guard_detects_each_retracted_claim(claim):
    assert stale_claims(claim.upper()) == [claim]


def test_docs_name_real_rule_directories_and_shared_ledger_paths(tmp_path, monkeypatch):
    from aegis_core.storage import ledger_site
    from aegis_core.taxonomy import RULE_TYPE_DIRS
    from tests import helpers_humangate as hg

    home = hg.Home(tmp_path / "home")
    for key, value in home.env.items():
        monkeypatch.setenv(key, value)
    docs = _docs()
    for directory in RULE_TYPE_DIRS.values():
        assert f"`{directory}/`" in docs["docs/how-it-works.md"]
        assert f"`{directory}/`" in docs["CONTRIBUTING.md"]
    non_git = tmp_path / "outside"
    non_git.mkdir()
    assert ledger_site(non_git, create=False).path.relative_to(non_git).as_posix() == ".aegis/state/ledger.jsonl"
    repo = hg.Repo(tmp_path / "repo", home)
    site = ledger_site(repo.root, create=False)
    assert site.shared
    shared = site.path.relative_to(repo.root / ".git").as_posix().replace(site.path.parent.name, "<ws-id>")
    local = ledger_site(non_git, create=False).path.relative_to(non_git).as_posix()
    for name in ("SECURITY.md", "PRIVACY.md", "docs/how-it-works.md"):
        directory, relative = shared.split("/", 1)
        assert f"<git common dir>/{shared}" in docs[name] or (
            f"<git common dir>/{directory}/" in docs[name] and f"`{relative}`" in docs[name])
        assert local in docs[name]
    assert ".aegis/rules/<type>/" not in docs["CONTRIBUTING.md"]


def test_release_docs_name_recovery_and_attestation_scope():
    docs = _docs()
    release = docs["CONTRIBUTING.md"].split("## Releases\n", 1)[1].split("\n## ", 1)[0]
    assert "Layer 2" not in release and "cross-vendor" not in release
    for text in ("ci_green.py", "Re-run failed jobs", "pypi.org", "doctor --release", "patch version"):
        assert text in release
    for name in ("SECURITY.md", "docs/how-it-works.md"):
        assert any(all(word in line for word in ("default branch", "attestation", "push", "verdict"))
                   for line in docs[name].splitlines()), name
    assert "warning tier" in docs["docs/why-aegis.md"]
    assert "~/.aegis/link.key" in docs["SECURITY.md"]


def test_no_tracked_or_linked_internal_adrs():
    if not (ROOT / ".git").exists():
        pytest.skip("source distribution without git metadata")
    proc = subprocess.run(["git", "ls-files", "docs/adr"], cwd=ROOT, capture_output=True, text=True,
                          check=True, timeout=10)
    assert proc.stdout == ""
    assert [name for name, text in _docs().items() if re.search(r"\]\([^)]*(?:docs/adr/|\badr/)", text)] == []
