"""The host table and bootstrap text are the shared contract for the host plane."""
import os
from pathlib import Path

import pytest

from aegis_core import bootstrap, hosts


@pytest.mark.parametrize(
    "client_name, expected",
    [
        ("codex-mcp-client", "codex-cli"),
        ("claude-code", "claude-code"),
        ("local-agent-mode-3f9a", "claude-desktop"),
        ("antigravity-client", "antigravity"),
        ("gemini-cli-mcp-client", "gemini-cli"),
        ("kiro", "kiro"),  # SECONDARY: a Kiro IDE 0.11 log; the Kiro CLI's name is unknown
        ("Q DEV CLI", "generic"),  # the Kiro CLI's predecessor: a hint, never a match
        ("cursor-vscode", "generic"),
        ("Claude-Code", "generic"),  # exact match only: no case folding guesses
        ("", "generic"),
        (None, "generic"),
    ],
)
def test_identify_maps_client_names_exactly_and_never_guesses_a_vendor(client_name, expected):
    assert hosts.identify(client_name) == expected


def test_unknown_host_id_names_the_known_ones():
    with pytest.raises(KeyError) as exc:
        hosts.get("gemini")
    assert "codex-cli" in str(exc.value) and "antigravity" in str(exc.value)


def test_every_row_is_well_formed():
    ids = [h.id for h in hosts.HOSTS]
    assert len(ids) == len(set(ids))
    for h in hosts.HOSTS:
        assert h.instructions in hosts.INSTRUCTION_MODES, h.id
        if h.registration is None:
            continue
        if h.registration.kind == "native_cli":
            assert "{command}" in h.registration.argv, h.id
            assert "aegis" in h.registration.argv, h.id
            assert f"AEGIS_CLIENT={h.id}" in h.registration.argv, h.id
        else:
            assert h.registration.kind == "json_file", h.id
            assert h.registration.path.startswith("~/"), h.id


def test_phase_one_hosts_are_the_three_the_author_runs_desktop_identity_and_the_experimental_rows():
    assert {h.id for h in hosts.all_hosts(phase=1)} == {
        "codex-cli", "claude-code", "claude-desktop", "antigravity", "kiro", "cursor", "copilot", "windsurf"}
    assert hosts.get("claude-desktop").registration is None


RETIRED_GEMINI_CLI = ("gemini-cli is not supported: Google retired Gemini CLI for individual Code Assist "
                      "accounts; use --host antigravity.")


def test_without_a_phase_every_host_is_listed_in_table_order():
    assert hosts.all_hosts() == hosts.HOSTS
    assert {h.id for h in hosts.all_hosts(phase=1)} < {h.id for h in hosts.all_hosts()}


def test_gemini_cli_is_retired_and_kept_only_to_name_the_client():
    # Google no longer serves Gemini CLI to individual Code Assist accounts; Antigravity is
    # the Gemini-family host. The row stays so identify() can name the client if it connects,
    # and that client keeps its own ${SLOT.*} profile.
    row = hosts.get("gemini-cli")
    assert row.retired == RETIRED_GEMINI_CLI
    assert row.registration is None
    assert row.verified is False
    assert row.slot_profile == "gemini-cli"
    assert row.phase == 2
    assert row.notes == (
        "Retired: Google no longer serves Gemini CLI to individual Code Assist accounts; "
        "Antigravity is the Gemini-family host. Identity only.",
    )
    assert hosts.identify("gemini-cli-mcp-client") == "gemini-cli"


def test_identity_and_unverified_hook_notes_describe_current_support():
    assert hosts.get("claude-desktop").notes == ("Identity only: Aegis does not register here.",)
    assert "No Aegis hooks: Kiro's hook semantics for blocking are not verified." in hosts.get("kiro").notes


def test_only_gemini_cli_is_retired_and_a_retired_row_never_registers():
    assert [h.id for h in hosts.HOSTS if h.retired] == ["gemini-cli"]
    assert hosts.get("claude-desktop").retired == ""
    for h in hosts.HOSTS:
        if h.retired:
            assert h.registration is None, h.id


def test_skills_dirs_are_the_documented_project_directories_and_none_is_verified():
    # v4.1 §3: skills project to .claude/skills (Claude Code, DOC) and the shared
    # .agents/skills (Antigravity DOC, Codex UNVERIFIED). Nothing was probed on a real
    # install, so no skills_verified is True; it is separate from the row's verified.
    assert {h.id: (h.skills_dir, h.skills_verified) for h in hosts.HOSTS} == {
        "codex-cli": (".agents/skills", False),
        "claude-code": (".claude/skills", False),
        "claude-desktop": (None, False),
        "antigravity": (".agents/skills", False),
        "gemini-cli": (None, False),
        "kiro": (None, False),
        "cursor": (None, False),
        "copilot": (None, False),
        "windsurf": (None, False),
    }
    assert hosts.get("claude-code").verified is True  # the row's own flag is untouched


def test_a_skills_dir_is_a_workspace_relative_posix_directory():
    for h in hosts.HOSTS:
        if h.skills_dir is None:
            continue
        assert not h.skills_dir.startswith(("/", "~", ".\\")) and "\\" not in h.skills_dir, h.id
        assert ".." not in h.skills_dir.split("/") and not h.skills_dir.endswith("/"), h.id
        assert h.registration is not None and not h.retired, h.id


def test_new_host_fields_default_to_no_skills():
    row = hosts.HostSpec(id="x", display_name="X", vendor="V")
    assert row.skills_dir is None and row.skills_verified is False


def test_bootstrap_fits_every_host_budget_and_carries_no_rule_bodies():
    text = bootstrap.bootstrap_text()
    size = len(text.encode("utf-8"))
    assert size <= 700
    for h in hosts.HOSTS:
        if h.budget_bytes:
            assert size < h.budget_bytes
    assert "aegis_scan" in text and "aegis_report_outcome" in text and "aegis scan" in text
    assert "---" not in text  # no frontmatter, so no rule file was pasted in


def test_instructions_first_512_characters_stand_alone():
    head = bootstrap.instructions_text()[:512]
    assert "aegis_scan" in head and "aegis_report_outcome" in head


def test_the_hook_notes_state_the_planned_v41_tiers_as_adr_0005_ad8_does():
    """AD-8 as amended on 2026-10-16: Claude Code blocks with exit 2; Codex blocks once the
    hook is trusted in /hooks; every hook fails open on an Aegis error."""
    assert "PreToolUse hooks can block with exit 2." in hosts.get("claude-code").notes
    assert "Hooks need trust in /hooks and fail open on errors." in hosts.get("codex-cli").notes
    for row in hosts.HOSTS:
        assert not any("strongest host" in n or "need user approval" in n for n in row.notes), row.id


# ── surfaces, aliases and app detection (v4.1 rev 3.1, d4-host-surfaces) ────────────

def test_a_host_is_a_config_plane_and_lists_the_surfaces_that_share_it():
    """The CLI, IDE extension and desktop app of one family read one config plane, so they
    are one host; ``surfaces`` names them so users see their app or IDE is covered."""
    assert {h.id: h.surfaces for h in hosts.HOSTS} == {
        "codex-cli": ("Codex CLI", "Codex IDE extension", "ChatGPT desktop app (Codex mode)"),
        "claude-code": ("Claude Code CLI", "Claude Code IDE extensions", "Claude desktop app (Code tab)"),
        "claude-desktop": ("Claude desktop app (chat)", "Claude desktop app (Cowork)"),
        "antigravity": ("Antigravity app", "Antigravity IDE", "agy CLI"),
        "gemini-cli": (),
        "kiro": ("Kiro IDE", "Kiro CLI"),
        "cursor": ("Cursor IDE", "Cursor CLI (cursor-agent)"),
        "copilot": ("GitHub Copilot in VS Code (agent mode)", "GitHub Copilot CLI"),
        "windsurf": ("Windsurf IDE",),
    }


@pytest.mark.parametrize("name, plane", [
    ("codex-cli", "codex-cli"), ("codex", "codex-cli"), ("codex-ide", "codex-cli"), ("codex-app", "codex-cli"),
    ("chatgpt-desktop", "codex-cli"), ("claude-code", "claude-code"), ("claude-desktop-code", "claude-code"),
    ("antigravity-app", "antigravity"), ("antigravity-ide", "antigravity"), ("kiro-ide", "kiro"),
    ("kiro-cli", "kiro"), ("kiro", "kiro"), ("claude-desktop", "claude-desktop"), ("gemini-cli", "gemini-cli"),
    ("cursor", "cursor"), ("cursor-ide", "cursor"), ("copilot", "copilot"), ("copilot-cli", "copilot"),
    ("windsurf", "windsurf"), ("windsurf-ide", "windsurf"),
])
def test_resolve_maps_a_surface_alias_to_its_plane_id(name, plane):
    assert hosts.resolve(name) == plane


@pytest.mark.parametrize("name", ["gemini", "Codex-App", "cursor-vscode", "", " codex"])
def test_resolve_refuses_anything_else_and_names_the_ids_and_aliases(name):
    with pytest.raises(KeyError) as exc:
        hosts.resolve(name)
    assert "codex-cli" in str(exc.value) and "codex-app" in str(exc.value)


def test_aliases_are_unique_and_never_shadow_a_plane_id():
    ids = {h.id for h in hosts.HOSTS}
    aliases = [a for h in hosts.HOSTS for a in h.aliases]
    assert len(aliases) == len(set(aliases))
    assert not ids & set(aliases)
    # A retired or identity-only row takes no alias: an alias exists to reach a plane Aegis registers.
    assert all(not h.aliases for h in hosts.HOSTS if h.registration is None)


def test_kiro_is_an_experimental_json_file_host_that_reads_agents_md():
    """Kiro IDE and Kiro CLI share ~/.kiro (DOC): MCP in settings/mcp.json under mcpServers,
    AGENTS.md always included. No hooks and no project skills in v4.1; the row stays
    unverified until it is checked on a real install."""
    row = hosts.get("kiro")
    assert row.registration == hosts.Registration(kind="json_file", path="~/.kiro/settings/mcp.json",
                                                  key="mcpServers")
    assert row.instructions == "agents_md"
    assert row.binaries == ("kiro-cli",)
    assert row.config_paths == ("~/.kiro",)
    assert row.client_names == ("kiro",)
    assert (row.phase, row.verified, row.retired, row.skills_dir) == (1, False, "", None)
    assert row.slot_profile == hosts.GENERIC


def test_claude_desktop_stays_identity_only_and_points_the_code_tab_at_claude_code():
    row = hosts.get("claude-desktop")
    assert row.registration is None and row.instructions == "none"
    assert "--host claude-code" in row.redirect


def test_config_paths_cover_claude_codes_user_config_file():
    assert hosts.get("claude-code").config_paths == ("~/.claude", "~/.claude.json")
    assert hosts.get("antigravity").config_paths == ("~/.gemini/config", "~/.gemini/antigravity")


def test_app_paths_follow_the_platform_and_resolve_home_and_environment(tmp_path):
    home = tmp_path / "home"
    local = tmp_path / "local"
    kiro, codex = hosts.get("kiro"), hosts.get("codex-cli")
    assert hosts.app_paths(kiro, home, {}, "darwin") == [
        os.path.join("/Applications", "Kiro.app"), os.path.join(str(home), "Applications", "Kiro.app")]
    assert hosts.app_paths(codex, home, {}, "darwin") == [
        os.path.join("/Applications", "Codex.app"), os.path.join(str(home), "Applications", "Codex.app")]
    assert hosts.app_paths(kiro, home, {"LOCALAPPDATA": str(local)}, "win32") == [
        os.path.join(str(local), "Programs", "Kiro")]
    # An unset or relative variable names no place: nothing is guessed.
    assert hosts.app_paths(kiro, home, {}, "win32") == []
    assert hosts.app_paths(kiro, home, {"LOCALAPPDATA": "rel"}, "win32") == []
    assert hosts.app_paths(kiro, home, {}, "linux") == []
    assert hosts.app_paths(hosts.get("claude-code"), home, {}, "darwin") == []


# ── experimental rows: cursor, copilot, kiro, windsurf (v4.2 #6) ──────────────

EXPERIMENTAL = ("kiro", "cursor", "copilot", "windsurf")  # table order


def test_the_experimental_rows_are_exactly_the_unverified_ones_that_aegis_registers():
    """A row flips to verified only after the ADR 0007 section 4 bar of 3 clean runs on a real install,
    and nobody flips it by accident: the verified rows are these, every other row is unverified."""
    assert [h.id for h in hosts.HOSTS if not h.verified and h.registration is not None] == list(EXPERIMENTAL)
    assert [h.id for h in hosts.HOSTS if h.verified] == ["codex-cli", "claude-code", "claude-desktop", "antigravity"]
    assert [h.id for h in hosts.HOSTS if not h.verified and h.registration is None] == ["gemini-cli"]


@pytest.mark.parametrize("host_id, path, key", [
    ("cursor", "~/.cursor/mcp.json", "mcpServers"),
    ("copilot", "~/.copilot/mcp-config.json", "mcpServers"),
    ("kiro", "~/.kiro/settings/mcp.json", "mcpServers"),
    ("windsurf", "~/.codeium/windsurf/mcp_config.json", "mcpServers"),
])
def test_each_experimental_row_registers_in_the_file_its_vendor_documents(host_id: str, path: str, key: str):
    row = hosts.get(host_id)
    assert row.registration == hosts.Registration(kind="json_file", path=path, key=key)
    assert (row.verified, row.retired, row.phase, row.skills_dir, row.skills_verified) == (False, "", 1, None, False)
    assert row.slot_profile == hosts.GENERIC
    assert row.instructions == "agents_md" and row.redirect == ""
    assert row.surfaces and row.binaries and row.config_paths


@pytest.mark.parametrize("host_id", EXPERIMENTAL)
def test_each_experimental_row_cites_its_vendor_documentation_in_a_comment(host_id: str):
    source = Path(hosts.__file__).read_text(encoding="utf-8")
    block = source.split(f'id="{host_id}"', 1)[1].split("HostSpec(", 1)[0]
    comments = [line for line in block.splitlines() if line.strip().startswith("#")]
    assert any("https://" in line for line in comments), host_id


@pytest.mark.parametrize("host_id", EXPERIMENTAL)
def test_an_experimental_row_says_it_is_unchecked_and_what_flips_it(host_id: str):
    row = hosts.get(host_id)
    assert row.notes[0] == "Its row follows the vendor's documentation and is not yet checked on a real install."
    assert any("3 clean runs" in note for note in row.notes), row.notes


def test_the_flip_to_verified_is_documented_and_not_automated():
    doc = hosts.__doc__
    assert "3 clean runs" in doc and "ADR 0007" in doc
    assert "by hand" in doc or "no automation" in doc


def test_the_new_experimental_rows_are_identified_by_aegis_client_alone():
    # Their MCP clientInfo names are not documented, so none is guessed (kiro's is a log line).
    for host_id in ("cursor", "copilot", "windsurf"):
        assert hosts.get(host_id).client_names == (), host_id
    assert hosts.identify("kiro") == "kiro"


def test_the_experimental_rows_are_found_by_their_binaries_and_config_directories():
    assert hosts.get("cursor").config_paths == ("~/.cursor",)
    assert hosts.get("cursor").binaries == ("cursor-agent", "cursor")
    assert hosts.get("copilot").config_paths == ("~/.copilot",)
    assert hosts.get("copilot").binaries == ("copilot",)
    assert hosts.get("windsurf").config_paths == ("~/.codeium/windsurf",)
    assert hosts.get("windsurf").binaries == ("windsurf",)


def test_the_experimental_rows_name_their_surfaces_and_take_surface_aliases():
    assert hosts.resolve("cursor-ide") == hosts.resolve("cursor-cli") == "cursor"
    assert hosts.resolve("github-copilot") == hosts.resolve("copilot-cli") == "copilot"
    assert hosts.resolve("windsurf-ide") == "windsurf"
    assert hosts.get("windsurf").surfaces == ("Windsurf IDE",)
    assert "GitHub Copilot in VS Code (agent mode)" in hosts.get("copilot").surfaces
    assert "Cursor IDE" in hosts.get("cursor").surfaces


def test_app_paths_find_the_new_desktop_apps(tmp_path, monkeypatch):
    apps = tmp_path / "Applications"
    monkeypatch.setattr(hosts, "APP_DIRS", {"darwin": (str(apps),), "win32": ("%LOCALAPPDATA%/Programs",)})
    assert hosts.app_paths(hosts.get("cursor"), tmp_path, {}, "darwin") == [str(apps / "Cursor.app")]
    assert hosts.app_paths(hosts.get("windsurf"), tmp_path, {}, "darwin") == [str(apps / "Windsurf.app")]
    local = {"LOCALAPPDATA": str(tmp_path / "local")}
    programs = os.path.join(str(tmp_path / "local"), "Programs")
    assert hosts.app_paths(hosts.get("cursor"), tmp_path, local, "win32") == [os.path.join(programs, "cursor")]
    assert hosts.app_paths(hosts.get("windsurf"), tmp_path, local, "win32") == [os.path.join(programs, "Windsurf")]
    assert hosts.app_paths(hosts.get("copilot"), tmp_path, local, "win32") == []
