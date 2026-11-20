"""Team up carries the launcher's fixed failure reason to the operator's CLI."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tests.conftest import symlink_or_skip
from tests.integration.hierarchy_fake_wrapper import shell_exec
from tests.integration.test_hierarchy_launcher import assert_launch_record_added
from tests.integration.test_hierarchy_mailbox import ROOT, git
from tests.integration.test_hierarchy_provision import copy_source, worker_source_seed
from tools.hierarchy_team import API_KEYS


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="team up reads /proc and the launcher requires POSIX process groups")


def team_child_environment(parent, **settings):
    # Keep only OS bootstrap variables; outcome controls come from this fixture's settings.
    env = {name: parent[name] for name in ("SystemRoot", "WINDIR") if name in parent}
    env.update(settings)
    # Share the guard's key inventory; the existing team fixture removes these same keys.
    for name in API_KEYS:
        env.pop(name, None)
    return env


@pytest.mark.parametrize("mode,state", [("no-thread", "failed_to_start"),
                                        ("fail-after-thread", "start_incomplete")])
def test_team_up_reports_the_launcher_failure_and_retains_it_on_retry(tmp_path, tmp_path_factory, request, mode, state):
    source = tmp_path / "source"
    copy_source(worker_source_seed(tmp_path_factory, request), source)
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("value = 1\n", encoding="utf-8")
    git(project, "init", "-q", "-b", "develop")
    git(project, "add", "app.py")
    git(project, "commit", "-qm", "synthetic project base")
    binary = tmp_path / "fake-bin"
    binary.mkdir()
    for name in ("git", "ps"):
        found = shutil.which(name)
        assert found, name + " is required by team up"
        symlink_or_skip(found, binary / name)
    fake = Path(__file__).with_name("hierarchy_fake_codex.py")
    codex = binary / "codex"
    codex.write_text("#!/bin/sh\n%s \"$@\"\n" % shell_exec("codex", fake, tmp_path), encoding="utf-8")
    codex.chmod(0o700)
    # Init requires bwrap on PATH; this fixture's sandbox-none recipe must never invoke it.
    bwrap = binary / "bwrap"
    bwrap.write_text("#!/bin/sh\necho 'unexpected bwrap invocation' >&2\nexit 1\n", encoding="utf-8")
    bwrap.chmod(0o700)
    template = tmp_path / "recipes-template.json"
    template.write_text(json.dumps({
        "schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable,
        "path": [str(binary)], "identity": {"name": "Test owner", "email": "owner@example.invalid"},
        "recipes": {"lint": {"kind": "command", "heavy": False, "sandbox": "none", "timeout_seconds": 60,
                             "steps": [["$python", "-c", "print('lint ok')"]]}}}), encoding="utf-8")
    run = tmp_path / "run"
    config = tmp_path / "team-run.json"
    config.write_text(json.dumps({
        "schema": "aegis.team-run/v1", "run": str(run), "source": str(source), "project": str(project),
        "base": git(project, "rev-parse", "HEAD"), "branch": "feature/pilot",
        "initiative": {"id": "pilot", "project": "aegis", "repository": "aegis", "priority": 5,
                       "target_branch": "develop"},
        "roles": ["router"], "lanes": [{"id": "review", "kind": "reviewer"}],
        "recipes": {"keep": ["lint"], "python": sys.executable, "template": str(template),
                    "commit_identity": {"name": "Test owner", "email": "owner@example.invalid"}},
        "limits": {"writer_limit": 3, "heavy_limit": 3, "heavy_tests_limit": 1},
        "preflight": {"recipes": ["lint"], "expect": {"lint": {"state": "completed"}}},
        "min_free_gb": 1, "loop": {"interval": 5},
        "team": {"model": "gpt-6.1-sol", "reasoning": "high",
                 "reasoning_by_kind": {"orchestrator": "medium"}}}), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    process_tmp = tmp_path / "process-tmp"
    process_tmp.mkdir()
    parent = {**os.environ, **dict.fromkeys(API_KEYS, "fixture-parent-billing")}
    env = team_child_environment(parent, PATH=str(binary), HOME=str(home), CODEX_HOME=str(run / "codex-home"),
                                 CLAUDE_CONFIG_DIR=str(tmp_path / "claude-home"), PYTHONDONTWRITEBYTECODE="1",
                                 FAKE_CODEX_MODE=mode, FAKE_CODEX_THREAD="fixture-session",
                                 TMPDIR=str(process_tmp), TMP=str(process_tmp), TEMP=str(process_tmp),
                                 LANG="C.UTF-8", LC_ALL="C.UTF-8")
    assert all(parent[name] and name not in env for name in API_KEYS)

    def team(*words, expect=0):
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools" / "hierarchy_team.py"),
                                 "--config", str(config), *words], env=env, capture_output=True,
                                text=True, timeout=120, stdin=subprocess.DEVNULL)
        assert result.returncode == expect, result.stdout + result.stderr
        assert result.stderr == ""
        return json.loads(result.stdout.splitlines()[-1])

    assert team("init")["init"] == "complete"
    folder = run / "initiatives" / "pilot" / "launches" / "pilot%2Frouter"
    saved = {}
    for _ in range(2):
        answer = team("up", "--no-loop", expect=3)
        assert answer["error"] == ("pilot/router did not start: the start process exited unsuccessfully "
                                   "(launcher exit 3, state %s)" % state)
        assert answer["record"]["state"] == state
        assert answer["record"]["error"] == "the start process exited unsuccessfully"
        saved = assert_launch_record_added(folder, saved, answer["record"])
        assert not (folder / ".start.lock").exists() and not (run / "loop.pid").exists()
