"""What a Claude team role reads of its contract and brief, and proof that no Codex role reads anything new.

Claude roles in team runs use print mode (Teams T2(a) host-binding ADR, sections 2, 4 and 6; owner decisions 3 and 4):
each turn is one `claude --print` process with `--restricted` file tools, the mailbox (and board) tools and no
command tool. `hierarchy_launcher.host_view` is the only renderer of the `host:claude` and `host:codex` passages.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "tools" / "hierarchy_templates"
ROLES = TEMPLATES / "roles"
# A lane brief is never rendered: the orchestrator fills a template in and publishes it, and the lane reads the
# published bytes (`brief_text` from mailbox_inbox). So each host family has its own template, and one host serves
# every role below ROOT (owner decision 2).
LANE_BRIEF = TEMPLATES / "lane-brief.md"
LANE_BRIEF_CLAUDE = TEMPLATES / "lane-brief-claude.md"
sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_launcher  # noqa: E402
import hierarchy_roles  # noqa: E402

# PR #283, the base of Teams T2(a). Every Codex rendering of a role contract, and the Codex lane brief, must stay
# exactly what it was there. Re-pin BASE and the hashes below only in a reviewed change to a Codex rendering or to
# lane-brief.md, never to make a failing test pass. Pinned by Teams T2(a) PR6b.
BASE = "ac484527ddc7e44f2d6e156b993def70a9075e95"
# sha256 of each contract's Codex rendering at BASE, for clones that lack BASE (CI's Windows checkout is shallow).
# Where git has BASE, test_codex_rendering_equals_the_base_commits_rendering compares the text itself.
CODEX_AT_BASE = {
    "builder.md": "c6ceedc14737a8e8c321afc2a7e2091c349c0b848190ccc838e0dc7141d9d6be",
    "decider.md": "3b13289fc79ea4aa0468b16f9390becb5252c347422f4dde5cc071e4a07a0792",
    "front-door.md": "2b1ce153b7e5d1aa1114d48774b8d04432b955d9031e4a33990cff1e1e9c3e0a",
    "integrator.md": "109712940ea2eddb8b2ba11577e497c9bf4915b045f15e60fca803470e5129e8",
    "lane.md": "f342a1ecaa9373a8cd148ea79fdca1a16e0ee1fe3e42b3056c437626e8d97304",
    "operator.md": "6202ad3bd2f27512b824a8970ca610d3453779ee186c2cc526d0ae71c2e36a76",
    "orchestrator.md": "f564da14c1b087681ebc8efe9a911d42acb605ae86235bb5b0d647dac45bc88a",
    "reviewer.md": "c930b0680bcf2f5fd58095b6b5c448556c94d4d5c5efefa67c72422d6848fefb",
    "root.md": "b292aa2bfe39969790453f6193698a6e010171a3b713cee7873b2a782cc0e455",
    "router.md": "2adcf6163b37aafc8312d41f6a02856c77edf6636d255cfc92c557ec05469a70",
}
# sha256 of lane-brief.md's text at BASE: what a Codex lane's brief is filled in from.
LANE_BRIEF_AT_BASE = "6e02ee4ae5f5e34e4f3ef4dac16d5c6efe1c80f5d5651da6cd32f0b1b3f1cf1f"
CONTRACTS = sorted(CODEX_AT_BASE)
# The archived operator reference quotes the dogfood ROOT's launch rules verbatim, outside any host block, and
# test_hierarchy_templates pins that quote. No role is started with it.
ARCHIVED = "operator.md"
ROLE_CONTRACTS = [name for name in CONTRACTS if name != ARCHIVED]

# Instructions for the interactive and background Claude sessions of the 2026-11-02 dogfood, none of which a
# print-mode team role has.
RETIRED = ["SendMessage", "claude stop", "CLAUDE_JOB_DIR", "sleep", "Bash", ".claude/worktrees"]
# `EnterWorktree` may appear only where a contract says it is not available or never called. The last two are the
# orchestrator's rules that every host shares.
ENTER_WORKTREE_UNAVAILABLE = ("**No `EnterWorktree`, T38, T48 and T139.** No lane calls `EnterWorktree`, whatever its "
                              "kind: it is not available in a team run")
ENTER_WORKTREE_ALLOWED = [ENTER_WORKTREE_UNAVAILABLE, "never calling `EnterWorktree`", "Never call `EnterWorktree`"]
# Recipes the contracts name for a Claude writer's checks; each must exist in root's recipe template.
NAMED_RECIPES = ["commit-exact", "targeted-tests", "full-suite", "lint", "aegis-check"]

PRINT_MODE = ["Each turn is one `claude --print` process",
              "Your start turn carries this contract and has no MCP tools"]
LANE_KIND = PRINT_MODE + [
    "Report only through the mailbox (`ack`, `result`, `info`)",
    "New mail for you starts your next turn",
    "You have no command tool",
    "Rules here or in your brief that name a command",
    "Never attempt a shell-like workaround",
    "ask your orchestrator for it only when one of root's recipes provides it",
    "the boundary is the worktree and the path lease, enforced by permission rules plus independent review and CI",
    '"permission rules, not OS-enforced"',
    "If Edit or Write is refused",
    "report the exact text and stop",
    "the one `mailbox_self` returns",
    ENTER_WORKTREE_UNAVAILABLE,
]
WRITER = ["Writing lanes: work only in the worktree your brief names",
          "Leave your edits uncommitted in the worktree",
          "`commit-exact` for the exact paths you changed",
          "`targeted-tests` on that commit"]
SCAN_GATE = ["You cannot run `aegis scan`",
             "Before your first Edit or Write, hold the scan result for every path you will edit, delivered in your "
             "brief or dispatch from a `scan` job your orchestrator filed",
             "If any path lacks one, edit nothing: report a blocker naming those paths"]
END_OF_TURN = "there is no self-stop and no stop command"
# What the Claude lane contract and the Claude lane brief both tell a lane.
SHARED_WITH_THE_BRIEF = ["Report only through the mailbox",
                         "A result that lists open items for your manager still ends your turn",
                         "an \"accept\" message or a fix-round dispatch starts your next one"]
DECIDER_NEVER = "Never `approve` on evidence you could not re-hash"


def words(text):
    return " ".join(text.split())


def view(name, family):
    path = ROLES / name
    return hierarchy_launcher.host_view(path.read_text(encoding="utf-8"), family, path)


def claude_blocks(name):
    """Only the text inside a contract's `host:claude` blocks."""
    kept, inside = [], False
    for line in (ROLES / name).read_text(encoding="utf-8").splitlines():
        if line.strip() == "<!-- host:claude -->":
            inside = True
        elif inside and line.strip() == "<!-- /host -->":
            inside = False
        elif inside:
            kept.append(line)
    return words("\n".join(kept))


def started(role):
    """A Claude role's start contract, composed as hierarchy_launcher.start_prompt composes a Codex one: a reviewer or
    integrator reads lane.md first, without the sections its own file restates (and a reviewer without the writing
    rules)."""
    names = ([hierarchy_launcher.SHARED_LANE_RULES] if role in hierarchy_launcher.SHARED_FOR else [])
    parts = [view(name, "claude") for name in names + [hierarchy_launcher.CONTRACTS[role]]]
    if len(parts) > 1:
        headings = hierarchy_launcher.KIND_SECTIONS + (("## Writing rules",) if role == "reviewer" else ())
        parts[0] = hierarchy_launcher.without_sections(parts[0], headings)
    return words("\n\n".join(parts))


def missing(text, phrases):
    return [phrase for phrase in phrases if phrase not in text]


def at_base(relative):
    """The file's text at BASE, or None when this checkout has no BASE (a shallow clone, or no git)."""
    try:
        found = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", BASE + "^{commit}"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return None
    if found.returncode != 0:
        return None
    shown = subprocess.run(["git", "-C", str(ROOT), "show", "%s:%s" % (BASE, relative)],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return shown.stdout.decode("utf-8")


def test_every_role_contract_is_covered():
    assert sorted(path.name for path in ROLES.glob("*.md")) == CONTRACTS
    assert view(ARCHIVED, "claude").splitlines()[0].startswith("# Archived operator reference")


@pytest.mark.parametrize("family", ["claude", "codex"])
@pytest.mark.parametrize("name", CONTRACTS)
def test_host_view_renders_every_contract_for_both_families(name, family):
    assert view(name, family).strip()


@pytest.mark.parametrize("name", CONTRACTS)
def test_codex_rendering_matches_the_pinned_base_hash(name):
    assert hashlib.sha256(view(name, "codex").encode("utf-8")).hexdigest() == CODEX_AT_BASE[name]


@pytest.mark.parametrize("name", CONTRACTS)
def test_codex_rendering_equals_the_base_commits_rendering(name):
    text = at_base("tools/hierarchy_templates/roles/" + name)
    if text is None:
        pytest.skip("this checkout does not have %s; the pinned hash test still covers it" % BASE)
    assert view(name, "codex") == hierarchy_launcher.host_view(text, "codex", name)


def test_the_codex_lane_brief_matches_the_pinned_base_hash():
    assert hashlib.sha256(LANE_BRIEF.read_text(encoding="utf-8").encode("utf-8")).hexdigest() == LANE_BRIEF_AT_BASE


def test_the_codex_lane_brief_equals_the_base_commits_brief():
    text = at_base("tools/hierarchy_templates/lane-brief.md")
    if text is None:
        pytest.skip("this checkout does not have %s; the pinned hash test still covers it" % BASE)
    assert LANE_BRIEF.read_text(encoding="utf-8") == text


@pytest.mark.parametrize("name", ROLE_CONTRACTS)
def test_claude_rendering_carries_no_retired_instruction(name):
    text = words(view(name, "claude"))
    assert missing(text, RETIRED) == RETIRED
    for allowed in ENTER_WORKTREE_ALLOWED:
        text = text.replace(allowed, "")
    assert "EnterWorktree" not in text


@pytest.mark.parametrize("role", ["implementer", "reviewer", "integrator"])
def test_every_lane_kind_reads_the_print_mode_facts(role):
    assert missing(started(role), LANE_KIND) == []


@pytest.mark.parametrize("role", ["implementer", "integrator"])
def test_writers_leave_commits_and_checks_to_the_orchestrators_jobs(role):
    assert missing(started(role), WRITER) == []


@pytest.mark.parametrize("role", ["implementer", "integrator"])
def test_a_claude_writer_holds_every_paths_scan_result_before_its_first_edit(role):
    """ADR section 6: a `scan` job the orchestrator files stands in for the pre-edit scan a Claude writer cannot run.
    The gate sits in the writing rules, ahead of the shared scan rule and the checks rule."""
    text = started(role)
    assert missing(text, SCAN_GATE) == []
    gate = text.index(SCAN_GATE[1])
    assert text.index("## Writing rules") < gate < text.index("**Checks and commits through jobs.**")
    assert gate < text.index("**Scan, T50, T76 and T109.** Scan each path you will edit on its own")


@pytest.mark.parametrize("role", ["implementer", "integrator"])
def test_writers_ask_only_for_jobs_that_roots_recipes_provide(role):
    recipes = json.loads((TEMPLATES / "job-recipes.json").read_text(encoding="utf-8"))["recipes"]
    assert [name for name in NAMED_RECIPES if name not in recipes] == []
    text = started(role)
    assert missing(text, ["`%s`" % name for name in NAMED_RECIPES]) == []
    assert missing(text, ["is recorded `not_run` with that reason, under owner decision 4's weaker boundary",
                          "do not ask for a job that no recipe provides"]) == []
    assert "each rule in this section that names one" not in text


def test_a_reviewer_reads_pinned_commits_through_source_views_and_gets_no_writer_rules():
    text = started("reviewer")
    assert missing(text, ["make the pinned commit-id reads with `source_show` and `source_grep`",
                          "Anything you cannot read or re-hash with these tools is a check you could not verify"]) == []
    assert missing(text, WRITER + SCAN_GATE) == WRITER + SCAN_GATE


def test_a_claude_orchestrator_scans_before_dispatch_and_files_its_lanes_checks_as_jobs():
    text = words(view("orchestrator.md", "claude"))
    assert missing(text, PRINT_MODE + [
        "Reach every role through the mailbox only",
        "Fill their briefs from `tools/hierarchy_templates/lane-brief-claude.md`, not `lane-brief.md`",
        "Before you dispatch a writer, file a `scan` job for every path it will edit and put each result in its brief",
        "If that job is refused, report the blocker to root and the front door and do not dispatch the writer",
        "file those that root's recipes provide",
        "Its `source_revision` and `source_tree` are its brief's base, not a tested candidate, so do not read them as "
        "\"no change\"",
        "(`dirty_content_sha256`, `expected_tree`) is a blocker"]) == []


def test_a_claude_orchestrator_is_told_the_tools_the_registry_gives_it():
    entry = hierarchy_roles.registry()["roles"]["orchestrator"]
    named = list(hierarchy_roles.file_tools(entry)) + list(hierarchy_roles.workspace_tools(entry))
    text = words(view("orchestrator.md", "claude"))
    assert missing(text, named + ["`source_show` and `source_grep` when your connection offers them"]) == []


@pytest.mark.parametrize("name", ["lane.md", "reviewer.md", "orchestrator.md"])
def test_a_claude_role_ends_its_turn_with_its_reply_and_stops_no_session(name):
    last = view(name, "claude").splitlines()[-1]
    assert END_OF_TURN in last and "never stop another session" in last


def test_a_claude_decider_escalates_on_evidence_it_cannot_rehash():
    assert missing(words(view("decider.md", "claude")), [
        "you cannot re-hash a file yourself", "Read each evidence file with your file tools",
        "only where a tool's output gives you that file's hash",
        "otherwise record `escalate`, naming each file in `reason` as not re-hashed (`not_run`)"]) == []


def test_the_claude_decider_block_never_allows_approve_on_unverified_evidence():
    block = claude_blocks("decider.md")
    assert DECIDER_NEVER in block
    assert "approve" not in block.replace(DECIDER_NEVER, "")


def test_the_claude_lane_brief_is_plain_text_because_lanes_read_it_verbatim():
    text = LANE_BRIEF_CLAUDE.read_text(encoding="utf-8")
    assert [line for line in text.splitlines() if hierarchy_launcher.HOST_LIKE.search(line)] == []
    assert missing(text, RETIRED + ["self-stop"]) == RETIRED + ["self-stop"]
    assert "only that `ack` is the acceptance" in words(text)


def test_both_lane_briefs_ask_for_the_same_fields():
    """Everything up to the readiness section is shared, so the two templates cannot drift on what a brief records."""
    def fields(path):
        return path.read_text(encoding="utf-8").split("## Readiness and verification")[0]
    assert fields(LANE_BRIEF_CLAUDE) == fields(LANE_BRIEF)


def test_the_claude_lane_brief_carries_scan_results_ahead_of_the_edit_gate():
    text = words(LANE_BRIEF_CLAUDE.read_text(encoding="utf-8"))
    field = "Scan results (from the orchestrator's `scan` job, one per path you will edit"
    gate = ("Before your first edit, hold a scan result above for every path you will edit; if any path lacks one, "
            "edit nothing and report a blocker")
    assert missing(text, [field, gate, "Write the behavior regression first"]) == []
    assert text.index(field) < text.index(gate) < text.index("Write the behavior regression first")


@pytest.mark.parametrize("source", ["contract", "brief"])
def test_the_claude_lane_brief_agrees_with_the_claude_lane_contract(source):
    text = LANE_BRIEF_CLAUDE.read_text(encoding="utf-8") if source == "brief" else view("lane.md", "claude")
    assert missing(words(text), SHARED_WITH_THE_BRIEF) == []
