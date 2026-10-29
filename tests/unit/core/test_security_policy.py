"""SECURITY.md must exist, cover the required sections and name a private reporting channel."""
import re
from pathlib import Path

import pytest

from conftest import REPO_ROOT, read

ROOT = Path(REPO_ROOT)
SECURITY = ROOT / "SECURITY.md"


def _security_text():
    assert SECURITY.is_file(), "SECURITY.md is missing from the repository root"
    return read(str(SECURITY))


def _section(text, title):
    match = re.search(rf"^##\s+{re.escape(title)}\s*$(.*?)(?=^##\s|\Z)", text, re.M | re.S)
    assert match, f"SECURITY.md has no '## {title}' section"
    return match.group(1)


def test_security_policy_has_required_sections():
    text = _security_text()
    for title in ("Supported Versions", "Reporting a Vulnerability", "Scope"):
        assert _section(text, title).strip(), f"'## {title}' section is empty"


def test_reporting_uses_private_channel_not_public_issues():
    reporting = _section(_security_text(), "Reporting a Vulnerability")
    assert "Report a vulnerability" in reporting
    assert "private" in reporting.lower()


def test_readme_links_to_security_policy():
    readme = read(str(ROOT / "README.md"))
    # The README is also the PyPI page, where only an absolute link resolves.
    assert re.search(r"\]\((\./|https://github\.com/nseney1/Aegis-Guardrails/blob/main/)?SECURITY\.md\)", readme), \
        "README.md does not link to SECURITY.md"


def test_supported_versions_cover_the_current_major_line():
    from aegis_core._version import __version__

    major = __version__.split(".", 1)[0]
    table = _section(_security_text(), "Supported Versions")
    rows = [line for line in table.splitlines() if line.lstrip().startswith(f"| {major}.")]
    assert rows, f"the Supported Versions table has no {major}.x row"
    assert "✅" in rows[0], f"the {major}.x row is not marked supported: {rows[0]!r}"


# Claims the code does not back (ADR 0005 §5): each was in a policy document and was cut or
# never implemented. Matching is case-insensitive.
POLICY_DOCS = ("SECURITY.md", "PRIVACY.md", "CONTRIBUTING.md", "NOTICE")
RETRACTED = (
    "Ed25519",                # never implemented; the v3 manifest was HMAC-SHA256 and is gone (D3)
    "aegis_request_receipt",  # receipts were cut (D2)
    "17 MCP tools",           # the server has 4 tools (D4)
    "air-gapped",             # Layer 2 sends a diff to the --llm-cmd command when asked
    "count_tokens",           # the Gemini token measurement was cut with the metrics census (D7)
    "check --release",        # Release Gate 4.5 was cut (D6)
    "aegis system",           # a removed command (D5)
    "DirectSDKBackend",       # the vendor SDK backends were cut (D14)
    "Git subprocesses strip inherited repository",  # selector scrubbing is scoped, not the default
    "your PATH, always through `gitsafe`",  # treeid has its own runner and private index
    "an executable resolved outside the repository",  # git accepts absolute PATH entries inside it
)


def retracted_claims_in(text):
    lowered = text.lower()
    return [phrase for phrase in RETRACTED if phrase.lower() in lowered]


def test_policy_documents_make_no_retracted_claim():
    found = {name: retracted_claims_in(read(str(ROOT / name))) for name in POLICY_DOCS}
    assert {name: hits for name, hits in found.items() if hits} == {}


def test_retracted_claim_guard_is_case_insensitive():
    assert retracted_claims_in("Keys are ED25519 and the server is Air-Gapped.") == ["Ed25519", "air-gapped"]
    assert retracted_claims_in("GIT SUBPROCESSES STRIP INHERITED REPOSITORY selectors.") == [
        "Git subprocesses strip inherited repository"]
    assert retracted_claims_in("your PATH, always through `gitsafe`") == [
        "your PATH, always through `gitsafe`"]
    assert retracted_claims_in("AN EXECUTABLE RESOLVED OUTSIDE THE REPOSITORY") == [
        "an executable resolved outside the repository"]


def test_git_environment_claim_names_the_evidence_scope_and_hook_exception():
    trust = _section(_security_text(), "Repository trust")
    paragraphs = [paragraph for paragraph in trust.split("\n\n") if "`gitsafe.scrubbed()`" in paragraph]
    assert len(paragraphs) == 1, "scope the selector-scrubbing claim to gitsafe.scrubbed()"
    for detail in ("evidence", "Ordinary git calls retain", "hooks", "alternate `GIT_INDEX_FILE`",
                   "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
        assert detail in paragraphs[0], detail


# Names of v3 components and v3 biology vocabulary that v4 dropped. A policy document
# that still names one points the reader at something the repository no longer has.
RETIRED_NAMES = ("Breeze", "Tempest", "Spores", "Mulch", "genome", "enzyme", "phylogeny", "evolutionary")


def test_policy_documents_use_no_retired_v3_names():
    found = {}
    for name in POLICY_DOCS:
        lowered = read(str(ROOT / name)).lower()
        hits = [word for word in RETIRED_NAMES if word.lower() in lowered]
        if hits:
            found[name] = hits
    assert found == {}


# Every module that starts a program, and the Repository trust rows that name what it
# starts. SECURITY.md says that table lists everything Aegis runs: a new spawn site must
# be added here and to the table.
SPAWN_SITES = {
    "aegis_core/gitsafe.py": ("`git`",),
    "aegis_cli/install_hosts.py": ("`codex`, `claude`",),
    # Doctor's MCP launcher check compares commands and starts nothing (no `python3`).
    "aegis_cli/doctor.py": ("`codex`, `claude`",),
    "aegis_core/ast/runner.py": ("AST drivers",),
    "aegis_core/verification/test_runner.py": ("`pytest`",),
    "aegis_core/verification/mutation_tester.py": ("`pytest`",),
    "aegis_core/inference_provider.py": ("your model command",),
    # Install runs the aegis it is about to register once, on an empty payload, in an empty directory.
    "aegis_cli/hooks/registrar.py": ("`aegis`, the hook handler",),
    # `aegis benchmark` starts the same handler under this Python (-I -c) on a fixture payload, in a temp workspace.
    "aegis_core/benchmark.py": ("`aegis`, the hook handler",),
    # The trust tier (`aegis doctor`) reads GitHub settings with `gh api` GETs, and `doctor --github --apply` makes
    # one POST after a typed y/N at a terminal; git signs and verifies approvals through ssh-keygen, which only
    # gitsafe-run git starts.
    "aegis_core/ghcli.py": ("`gh`",),
    # `aegis check --record` computes the tree git would commit with `git` under a scrubbed environment and a
    # private index, and runs the test command from the user-scope config (never the repository's) in a snapshot.
    "aegis_core/treeid.py": ("`git`",),
    "aegis_core/testexec.py": ("your test command",),
    # `aegis doctor --release` asks `gh --version`, one read-only `gh api` GET of the repository for its
    # default branch, the tier GETs, then `gh attestation verify` (read-only).
    "aegis_core/release_verify.py": ("`gh`",),
}
_SPAWN_MODULES = {"subprocess", "pty", "multiprocessing"}
_OS_SPAWN = re.compile(r"^(system|popen|startfile|exec\w*|spawn\w*|posix_spawn\w*)$")


def _starts_programs(tree) -> bool:
    import ast

    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] in _SPAWN_MODULES for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _SPAWN_MODULES:
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "os" and any(
                _OS_SPAWN.match(a.name) for a in node.names):
            return True
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os"
                and _OS_SPAWN.match(node.attr)):
            return True
        if isinstance(node, ast.Attribute) and node.attr.startswith("create_subprocess_"):
            return True
    return False


def _spawning_modules():
    import ast

    found = set()
    for package in ("aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"):
        for path in sorted((ROOT / package).rglob("*.py")):
            if _starts_programs(ast.parse(path.read_text(encoding="utf-8"))):
                found.add(path.relative_to(ROOT).as_posix())
    return found


def test_every_module_that_starts_a_program_is_in_the_inventory():
    assert sorted(_spawning_modules() - set(SPAWN_SITES)) == []


def test_the_repository_trust_table_names_what_each_spawn_site_starts():
    table = _section(_security_text(), "Repository trust")
    rows = [line for line in table.splitlines() if line.startswith("| ") and not line.startswith("|---")]
    first_cells = [row.split(" | ", 1)[0] for row in rows]
    missing = sorted({term for terms in SPAWN_SITES.values() for term in terms
                      if not any(term in cell for cell in first_cells)})
    assert missing == [], "the Repository trust table has no row for these programs"


def test_spawn_detection_sees_imports_os_calls_and_ignores_plain_modules():
    import ast

    assert _starts_programs(ast.parse("def f():\n    import subprocess\n"))
    assert _starts_programs(ast.parse("from subprocess import run\n"))
    assert _starts_programs(ast.parse("import os\nos.execvp('x', ['x'])\n"))
    assert _starts_programs(ast.parse("from os import system\n"))
    assert _starts_programs(ast.parse("import asyncio\nasyncio.create_subprocess_exec('x')\n"))
    assert not _starts_programs(ast.parse("import os\nos.path.join('a', 'b')\nimport shutil\n"))


# v4.1 writes host hook registrations and git refs; the policy says what each one is.
def test_security_names_every_hook_registration_file_and_what_it_is_not(tmp_path):
    from aegis_cli.hooks import registrar

    text = " ".join(_security_text().split())
    home, repo = Path("~"), Path("<repo>")
    for host in registrar.HOOK_HOSTS:
        for scope, base in (("user", home), ("project", repo)):
            path = registrar.hook_file(host, scope, home=home, root=repo, environ={}).as_posix()
            assert f"`{path}`" in text, (host, scope, path)
    assert f"`{registrar.codex_rules_file(home, {}).as_posix()}`" in text
    for phrase in ("guardrails, not a security boundary", "teammates", "/hooks", "exit 75",
                   "not an identity", "refs/aegis/lanes"):
        assert phrase in text, phrase


# R-trust-12: at tier B the required checks run the pull request's own workflow and aegis, so a
# tier B tick is only as strong as a check the pull request can edit. Given the "Trust tiers"
# table, Then column B ticks none of the first three claims the way column A does.

def _tier_table():
    section = _section(_security_text(), "Trust tiers")
    rows = [line for line in section.splitlines() if line.startswith("| ") and not line.startswith("|---")]
    header, *body = [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in rows]
    assert header == ["Claim", "Tier A", "Tier B", "Tier C"]
    return [dict(zip(header, cells)) for cells in body]


def test_the_tier_b_column_claims_no_more_than_a_pull_request_editable_check_supports():
    weakening, credited, release = _tier_table()[:3]
    assert "rule weakening" in weakening["Claim"] and "credited" in credited["Claim"] and "release" in release["Claim"]
    for row in (weakening, credited, release):
        assert row["Tier A"] == "✔", row
    assert weakening["Tier B"] != "✔" and ".github/workflows" in weakening["Tier B"], weakening
    assert "approved by a human" not in weakening["Tier B"]
    assert credited["Tier B"] == credited["Tier C"] and release["Tier B"] == release["Tier C"]


def test_readme_names_the_root_allowed_signers_file():
    readme = read(str(ROOT / "README.md"))
    assert "allowed_signers" in readme and ".aegis/allowed_signers" not in readme
