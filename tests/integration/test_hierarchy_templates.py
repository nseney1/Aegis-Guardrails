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


def test_root_has_no_assistant_list():
    assert not (TEMPLATES / "claude-agents" / "assistants-root.json").exists()
