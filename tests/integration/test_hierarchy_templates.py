"""Templates must work with the tools they describe, so the docs cannot drift from the code.

Assistant definitions are checked as data only. Whether a host enforces them is a separate
live probe that this file does not perform.
"""
import hashlib
import json
import os
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke, message
from tests.integration.test_hierarchy_workspace import Workspace


TEMPLATES = ROOT / "tools" / "hierarchy_templates"
ASSISTANTS = {"front-door": {"inbox-digest"}, "orchestrator": {"brief-checker", "log-reader"},
              "builder": {"code-locator", "failure-reader"}, "reviewer": {"usage-tracer", "coverage-mapper"}}


def template(name):
    return json.loads((TEMPLATES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("role", ["front-door", "orchestrator", "root", "builder", "integrator", "reviewer", "lane"])
def test_every_role_has_a_template(role):
    assert (TEMPLATES / "roles" / (role + ".md")).read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("name, limit", [("roles/root.md", 90), ("roles/front-door.md", 60), ("roles/orchestrator.md", 60),
                                         ("roles/lane.md", 60), ("lane-brief.md", 60)])
def test_templates_state_the_owners_rotation_limit(name, limit):
    words = " ".join((TEMPLATES / name).read_text(encoding="utf-8").split())
    assert "after %d minutes" % limit in words and "45 minutes" not in words


SELF_STOP = 'claude stop "${CLAUDE_CODE_SESSION_ID:0:8}" </dev/null'


def words(name):
    return " ".join((TEMPLATES / name).read_text(encoding="utf-8").split())


def missing(name, phrases):
    text = words(name)
    return [phrase for phrase in phrases if phrase not in text]


def test_lanes_stop_on_a_refusal_and_never_touch_shared_worktree_admin():
    assert missing("roles/lane.md", ["If Edit or Write is refused", "report the exact text and stop",
                                     "Never call `EnterWorktree`", "`git worktree repair`", "`git worktree prune`"]) == []


def test_lanes_read_their_diff_before_each_commit():
    assert missing("roles/lane.md", ["Before each commit, read `git diff <base> -- <file>`"]) == []


def test_lanes_scan_each_path_on_its_own_because_a_combined_scan_can_drop_rules():
    assert missing("roles/lane.md", ["Scan each path you will edit on its own", "union of the rule ids",
                                     "a per-path scan still lists omitted rules, follow those ids too",
                                     "the CLI scan prints \"No changed files detected\""]) == []


def test_lanes_put_evidence_too_long_for_a_field_in_a_cited_file():
    assert missing("roles/lane.md", ["4096 characters", "absolute path, its sha256 and the rule ids"]) == []


@pytest.mark.parametrize("name", ["roles/lane.md", "roles/reviewer.md", "roles/orchestrator.md"])
def test_lane_kinds_end_with_the_self_stop_line(name):
    last = (TEMPLATES / name).read_text(encoding="utf-8").rstrip().splitlines()[-1]
    assert SELF_STOP in last


@pytest.mark.parametrize("name", ["roles/lane.md", "roles/orchestrator.md"])
def test_a_self_stop_never_stops_another_session(name):
    assert missing(name, ["never stop another session"]) == []


def test_only_writers_cd_into_their_worktree_and_read_only_roles_never_use_a_bare_cd():
    assert missing("roles/lane.md", ["Writing lanes:", "the first-step `cd` is into your own worktree only",
                                     "read-only roles never use a bare `cd`"]) == []


def test_orchestrators_read_a_dialog_from_waiting_for_not_from_blocked_alone():
    assert missing("roles/orchestrator.md", ["`waitingFor`", "whatever `state` says", "`state: blocked`",
                                             "A present `waitingFor` is a dialog whatever `status` says"]) == []


def test_orchestrators_bind_by_kind_and_list_governance_paths_without_a_fixed_writer_count():
    assert missing("roles/orchestrator.md", ["Bind by kind", "never bind the wrong kind",
                                             "governance-classified paths", "`set-limits`",
                                             "`writer_limit` also caps that hierarchy's accepted writer dispatches"]) == []
    assert "three concurrent writers" not in words("roles/orchestrator.md")


def test_root_changes_limits_and_stops_earlier_roots_lanes_only_under_owner_decisions():
    assert missing("roles/root.md", ["only from an owner decision, with `set-limits`",
                                     "a finished, orchestrator-verified lane that an earlier ROOT launched",
                                     "approve that specific stop", "never work around the refusal"]) == []


def test_root_launch_prompts_copy_the_briefs_deadline_and_the_exact_self_stop_line():
    assert missing("roles/root.md", ["copy the brief's deadline", "the brief wins over a default", SELF_STOP]) == []


def test_root_stops_the_outgoing_session_and_checks_its_pid():
    assert missing("roles/root.md", ["stop the outgoing session", "verify its PID is gone"]) == []


def test_root_releases_a_live_lanes_grant_only_on_all_four_conditions():
    assert missing("roles/root.md", ["only when all four hold", "it reported done", "verified the report against git",
                                     "no `waitingFor`", "no claimed job and no open accepted dispatch",
                                     "with the session id and the verified tip and tree",
                                     "Nobody messages a released lane", "only its verified tip merges"]) == []


def test_reviewers_fall_back_to_exact_commits_without_a_prepared_copy():
    assert missing("roles/reviewer.md", ['git show "${rev}:path"', "never read the working tree"]) == []


def test_the_lane_brief_asks_for_binding_kind_worktree_and_owner_decisions():
    assert missing("lane-brief.md", ["launch prompt's endpoint and generation win", "Endpoint kind",
                                     "ABSOLUTE_WORKTREE_PATH", "route policy", "Build-cache directory",
                                     "`aegis check --lane`", "Push exception", "`tests-deleted`",
                                     "hosted `aegis check --ci` governance result",
                                     "unless the push-exception field names an owner decision"]) == []


def test_the_manifest_template_gives_each_hierarchy_a_root_routed_only_to_its_orchestrator(tmp_path):
    root = tmp_path / "mailbox"
    manifest = template("manifest.json")
    invoke(root, "init", manifest)
    for endpoint in manifest["endpoints"]:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    assert invoke(root, "publish", message("a/orchestrator", "a/root"))["path"]
    refused = invoke(root, "publish", message("a/root", "a/lane/f2", identifier="diagonal"), ok=False)
    assert refused["error"] == "route is not vertical or an explicit counterpart"


def test_the_checkpoint_template_uses_the_digest_form(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "counterparts": [], "writer_limit": 3,
                          "endpoints": {"a/front-door": {}, "a/orchestrator": {}}})
    invoke(root, "bind", {"endpoint": "a/front-door", "host": "h", "session": "old", "expected_generation": 0})
    brief = tmp_path / "brief.md"
    brief.write_bytes(b"Intent.\n")
    checkpoint = template("checkpoint.json")
    source = checkpoint["sources"][0]
    assert "dirty_state" not in source
    source.update(source_revision="a" * 40, source_tree="b" * 40, dirty_state_sha256="c" * 64)
    checkpoint.update(briefs=[{"path": str(brief), "sha256": hashlib.sha256(b"Intent.\n").hexdigest()}],
                      pending_message_ids=[])
    result = invoke(root, "bind", {"endpoint": "a/front-door", "host": "h", "session": "new", "expected_generation": 1,
                                   "checkpoint": checkpoint})
    assert result["generation"] == 2


@pytest.mark.skipif(os.name == "nt", reason="wake tool process groups are POSIX only")
def test_the_wake_profile_template_is_accepted_after_substitution(tmp_path):
    root = tmp_path / "mailbox"
    session = "bound-session-for-template-test"
    endpoints = {"a/front-door": {}, "a/orchestrator": {}}
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [],
                          "writer_limit": 3})
    invoke(root, "bind", {"endpoint": "a/front-door", "host": "host-one", "session": "a/front-door", "expected_generation": 0})
    invoke(root, "bind", {"endpoint": "a/orchestrator", "host": "claude-code", "session": session, "expected_generation": 0})
    invoke(root, "publish", message("a/front-door", "a/orchestrator"))
    raw = (TEMPLATES / "wake-profile.json").read_text(encoding="utf-8").replace("REPLACE_WITH_BOUND_SESSION", session)
    profile = {**json.loads(raw), "cwd": str(tmp_path)}
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(ROOT / "tools/hierarchy_wake.py"), "--root", str(root),
                             "--delivery-dir", str(tmp_path / "delivery"), "--endpoint", "a/orchestrator",
                             "--profile", str(path), "--dry-run"], capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["state"] == "dry_run"


def test_the_handoff_spec_template_passes_spec_validation(tmp_path):
    spec = template("handoff-spec.json")
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(ROOT / "tools/hierarchy_handoff.py"), "--spec", str(path)],
                            capture_output=True, text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    data = json.loads(result.stdout)
    assert result.returncode == 3 and data["ok"] is False
    assert [row["endpoint"] for row in data["entries"]] == ["a/front-door", "b/front-door"]
    assert all("unexpected fields" not in row["error"] for row in data["entries"])


def test_the_initiative_template_registers(tmp_path):
    workspace = Workspace(tmp_path)
    workspace.run("init", {"writer_limit": 3, "heavy_limit": 1})
    assert workspace.run("register", template("initiative.json"))["initiative"]["id"] == "aegis-p1"


@pytest.mark.parametrize("role,expected", sorted(ASSISTANTS.items()))
def test_assistant_lists_match_the_approved_roles_and_stay_read_only(role, expected):
    catalog = template("claude-agents/assistants-%s.json" % role)
    assert set(catalog) == expected
    for definition in catalog.values():
        assert set(definition) == {"description", "tools", "maxTurns", "prompt"}
        assert [tool.strip() for tool in definition["tools"].split(",")] == ["Read", "Grep", "Glob"]
        assert 0 < definition["maxTurns"] <= 12
        assert "read-only" in definition["prompt"] and "untrusted" in definition["prompt"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the job runner reads /proc")
def test_the_job_recipe_template_needs_local_values_then_passes_its_own_check(tmp_path):
    recipes = template("job-recipes.json")
    source = tmp_path / "recipes.json"

    def check():
        source.write_text(json.dumps(recipes), encoding="utf-8")
        return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "hierarchy_jobs.py"), "--store", str(tmp_path / "store"),
                               "--recipes", str(source), "check-recipes"], capture_output=True, text=True, timeout=20,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    assert check().returncode == 2, "the placeholder paths must not pass as real ones"
    recipes.update(python=sys.executable, hide=[str(tmp_path)])
    result = check()
    assert result.returncode == 0, result.stdout
    assert set(json.loads(result.stdout)["recipes"]) == {"targeted-tests", "full-suite", "lint", "aegis-check", "commit-exact"}
    assert not any(word == "push" for recipe in recipes["recipes"].values() for step in recipe.get("steps", []) for word in step)
    assert all(recipe["sandbox"] == "bwrap" for recipe in recipes["recipes"].values())


def test_root_has_no_assistant_list():
    assert not (TEMPLATES / "claude-agents" / "assistants-root.json").exists()
