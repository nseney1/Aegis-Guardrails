"""Shell-less commit packets bind the runner's admit-time source to the exact commit."""
import hashlib
import json
import os
import subprocess
import tempfile

import pytest

from tests.integration.test_hierarchy_jobs import (commit_request, first_job, needs_bubblewrap, shop,  # noqa: F401
                                                   recorded, source_digest, verified_evidence)
from tests.integration.test_hierarchy_jobs import pytestmark as pytestmark
from tests.integration.test_hierarchy_mailbox import git
from tests.integration.test_hierarchy_workspace import write_lease


PATHS = ["src/app.py", "tests/test_app.py"]


def host_plan(shop, **changes):
    plan = {"schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "pilot", "root": "codex-cli",
            "team": "claude-code", "stand_ins": {}, "config_sha256": "a" * 64, **changes}
    path = shop.base / "host-plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def edit_source(shop):
    (shop.checkout / "src" / "app.py").write_text("value = 2\n")
    (shop.checkout / "tests" / "test_app.py").write_text("def test_app():\n    assert True\n")
    (shop.checkout / "src" / "other.py").write_text("outside the requested paths\n")


def staged_tree(shop):
    with tempfile.TemporaryDirectory(dir=shop.tmp) as folder:
        env = {**os.environ, "GIT_INDEX_FILE": folder + "/index", "GIT_LITERAL_PATHSPECS": "1",
               "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        for args in (("read-tree", "HEAD"), ("add", "--", *PATHS), ("write-tree",)):
            result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
                                    cwd=shop.checkout, env=env, capture_output=True, text=True, check=True, timeout=10)
        return result.stdout.strip()


def request_derive(shop, **changes):
    return shop.request_job("job-1", "commit-exact", derive="runner", paths=PATHS,
                            message="fix: shell-less source", **changes)


@pytest.fixture
def claude_shop(shop):
    host_plan(shop)
    shop.recipes["recipes"]["commit-exact"] = shop.recipes["recipes"]["commit"]
    shop.save_recipes()
    return shop


@pytest.mark.parametrize("sandbox", ["none", pytest.param("bwrap", marks=needs_bubblewrap)])
def test_derive_commits_exact_paths_and_records_the_runner_values(claude_shop, sandbox):
    shop = claude_shop
    shop.recipes["recipes"]["commit-exact"]["sandbox"] = sandbox
    shop.save_recipes()
    edit_source(shop)
    before = shop.head()
    digest, tree = source_digest(shop)["dirty_content_sha256"], staged_tree(shop)
    plan = shop.base / "host-plan.json"
    request_derive(shop)
    assert shop.run_open()["rows"][0]["state"] == "completed"
    result = recorded(shop)
    evidence = verified_evidence(shop.receipts("job-1")[-1])
    assert json.loads(evidence["result.json"].read_text()) == result
    assert result["derived_by"] == "runner"
    assert result["dirty_content_sha256"] == result["before"]["dirty_content_sha256"] == digest
    assert result["expected_tree"] == result["after"]["source_tree"] == tree
    assert result["host_plan"] == {"path": str(plan), "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                                    "team": "claude-code"}
    assert json.loads(evidence["derivation.json"].read_text()) == {
        key: result[key] for key in ("derived_by", "dirty_content_sha256", "expected_tree", "host_plan")}
    assert git(shop.checkout, "rev-parse", "HEAD^") == before["commit"]
    assert git(shop.checkout, "rev-parse", "HEAD^{tree}") == tree
    assert sorted(git(shop.checkout, "show", "--format=", "--name-only", "HEAD").splitlines()) == PATHS
    assert git(shop.checkout, "status", "--porcelain=v1") == "?? src/other.py"


def test_an_edit_between_admit_and_run_refuses_without_moving_head_or_index(claude_shop):
    shop = claude_shop
    edit_source(shop)
    git(shop.checkout, "add", "--", "tests/test_app.py")
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    digest, tree = source_digest(shop)["dirty_content_sha256"], staged_tree(shop)
    first_job(shop, "import pathlib, sys; pathlib.Path(sys.argv[1], 'src/app.py').write_text('value = 3\\n')",
              dirty_content_sha256=digest)
    request_derive(shop)
    row = next(row for row in shop.run_open()["rows"] if row["job"] == "pilot/job-1")
    assert row["state"] == "refused" and "it changed while the job waited" in row["reason"], row
    result = recorded(shop)
    assert result["steps"] == [] and result["derived_by"] == "runner"
    assert result["dirty_content_sha256"] == digest and result["expected_tree"] == tree
    evidence = json.loads((shop.workspace.store / "jobs" / "pilot" / "job-1" / "derivation.json").read_text())
    assert evidence["dirty_content_sha256"] == digest and evidence["expected_tree"] == tree
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


def test_a_derived_no_op_is_refused(claude_shop):
    shop = claude_shop
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "this commit would make no change")
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


@pytest.mark.parametrize("kind", ["command", "merge"])
def test_derive_is_refused_on_other_recipe_kinds(claude_shop, kind):
    shop = claude_shop
    shop.recipes["recipes"]["other"] = (shop.command(["$python", "-c", "print('must not run')"]) if kind == "command"
                                         else {"kind": "merge", "sandbox": "none", "timeout_seconds": 30})
    shop.save_recipes()
    shop.request_job("job-1", "other", derive="runner")
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "only a commit recipe takes derive")


@pytest.mark.parametrize("value", ["lane", "", None, True, {}, ["runner"]])
def test_bad_derive_values_are_refused(claude_shop, value):
    shop = claude_shop
    packet = {"schema": "aegis.hierarchy-job-packet/v1", "recipe": "commit-exact", **shop.head(), "paths": PATHS,
              "message": "fix: bad derive", "derive": value}
    shop.request_job("job-1", "commit-exact", raw=json.dumps(packet))
    row = shop.run_open()["rows"][0]
    assert (row["state"], row["reason"]) == ("refused", "derive must be runner")


def test_a_packet_with_explicit_fields_keeps_the_existing_contract(shop):
    tree = commit_request(shop)
    digest = source_digest(shop)["dirty_content_sha256"]
    assert shop.run_open()["rows"][0]["state"] == "completed"
    result = recorded(shop)
    assert result["before"]["dirty_content_sha256"] == digest
    assert result["after"]["source_tree"] == tree
    assert "derived_by" not in result and "host_plan" not in result


def test_missing_expected_tree_without_derive_keeps_the_existing_refusal(shop):
    commit_request(shop, expected_tree=None)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "commit recipe needs expected_tree and message" in row["reason"]


@pytest.mark.parametrize("changes", [{"team": "codex-cli"}, {"team": "codex"}, {"hierarchy": "other"},
                                    {"schema": "other"}, None, "malformed"])
def test_derive_requires_the_initiatives_claude_team_plan(claude_shop, changes):
    shop = claude_shop
    if changes is None:
        (shop.base / "host-plan.json").unlink()
    elif changes == "malformed":
        (shop.base / "host-plan.json").write_text("{")
    else:
        host_plan(shop, **changes)
    edit_source(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "derive is for shell-less teams" in row["reason"], row
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


def test_derive_still_refuses_paths_owned_by_another_lease(claude_shop):
    shop = claude_shop
    edit_source(shop)
    write_lease(shop.checkout, "someone-else", ["tests/test_app.py"])
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop)
    row = shop.run_open()["rows"][0]
    assert row["state"] == "refused" and "paths overlap another lease" in row["reason"], row
    assert "someone-else" in row["reason"]
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index


@pytest.mark.parametrize("field, value, reason", [("dirty_content_sha256", "0" * 64, "source does not match the packet"),
                                                ("expected_tree", "0" * 40, "tree")])
def test_derive_does_not_discard_explicit_bindings(claude_shop, field, value, reason):
    shop = claude_shop
    edit_source(shop)
    head, index = shop.head()["commit"], (shop.checkout / ".git" / "index").read_bytes()
    request_derive(shop, **{field: value})
    row = shop.run_open()["rows"][0]
    assert row["state"] in ("refused", "failed") and reason in row["reason"], row
    assert git(shop.checkout, "rev-parse", "HEAD") == head
    assert (shop.checkout / ".git" / "index").read_bytes() == index
