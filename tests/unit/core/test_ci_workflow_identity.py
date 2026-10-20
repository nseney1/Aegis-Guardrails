"""Which workflow confirms credit (R-trust-a1): the user-scope ``ci.workflow``, else ``validate.yml``.

The name comes only from ``~/.aegis/config.json``: the repository's config, a user config inside
the workspace and a ledger ``ci`` row never choose it. A repository set up with ``aegis init --ci``
(``.github/workflows/aegis.yml``) confirms once the user names that workflow.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core import config, credit, human_gate
from aegis_core.telemetry_engine import ledger
from tests import helpers_humangate as hg
from tests import helpers_verified as hv

needs_git = pytest.mark.skipif(not hg.git_ok(), reason="needs git")


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GIT_CONFIG_GLOBAL", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)


class _Gh(hg.FakeGh):
    """GitHub as gh answers it: the repository, and the workflow runs of a commit."""

    def __init__(self, runs):
        super().__init__()
        self.runs = runs

    def __call__(self, argv, stdin=None, cwd=None):
        path = argv[-1]
        if "/actions/runs?head_sha=" in path:
            self.calls.append((tuple(argv), stdin))
            sha = path.split("head_sha=", 1)[1].split("&", 1)[0]
            return human_gate.GhResult(0, json.dumps({"workflow_runs": [r for r in self.runs if r["head_sha"] == sha]}), "")
        return super().__call__(argv, stdin, cwd)


@pytest.mark.parametrize("value", ["aegis.yml", "ci.yaml", "Build_1-x.yml"])
def test_a_bare_workflow_file_name_is_accepted(value):
    assert config.ci_workflow_name(value) == value


@pytest.mark.parametrize("value", ["../x.yml", "a/b.yml", "a\\b.yml", "x", "", 7, None, ".hidden.yml", "x.yml.txt",
                                   "a..b.yml"])
def test_anything_else_is_not_a_workflow_name(value):
    assert config.ci_workflow_name(value) is None


def test_a_workflow_name_holds_at_most_100_characters():
    assert config.ci_workflow_name("y" * 96 + ".yml") == "y" * 96 + ".yml"
    assert config.ci_workflow_name("y" * 97 + ".yml") is None


def test_the_user_config_reports_an_unusable_ci_workflow():
    parsed = config.UserConfig.parse({"ci": {"workflow": "../x.yml"}})
    assert parsed.ci_workflow is None
    assert parsed.warnings == ("ignored 'ci.workflow' in ~/.aegis/config.json: it must be a bare .yml or .yaml file name",)
    assert config.UserConfig.parse({"ci": {"workflow": "aegis.yml"}}) == config.UserConfig(ci_workflow="aegis.yml")


def _landed_check(tmp_path):
    """A credited check whose change landed on main as ``commit``, with a ledger ``ci`` row naming ``aegis.yml``."""
    repo = hv.make_project(tmp_path)
    hv.use_stub_runner(repo.home.path)
    repo.write("src/app.py", "def app():\n    return 2\n")
    assert hv.mcp_call("aegis_scan", repo.root, files=["src/app.py"]).get("status") != "FAIL"
    from aegis_core import checkrun

    assert checkrun.record(repo.root, tests=True).row["passed"] is True
    assert hv.mcp_call("aegis_report_outcome", repo.root, outcome="success", rules_used=["trap-sample"],
                       idempotency_key="k1")["status"] == "recorded"
    commit = repo.commit("work")
    repo.git("branch", "-f", "main", commit)
    ledger.append_rows(repo.root, [{"v": ledger.LEDGER_VERSION, "ts": "2026-10-20T00:00:00Z", "event": "ci",
                                    "commit": commit, "workflow": "aegis.yml", "ci_conclusion": "success",
                                    "run_id": 1, "ci_run_attempt": 1}])
    return repo, commit


def _project(repo, commit, monkeypatch):
    gh = _Gh([hv.ci_run(commit, workflow="aegis.yml")])
    monkeypatch.setattr(human_gate, "default_gh_runner", gh)
    credit_, = credit.project_credits(repo.root, verify_ci=True).credits
    return credit_.state, credit_.reason


def _user_ci(repo, workflow) -> None:
    hv.write_user_config(repo.home.path, tests={"command": "python run_checks.py"}, ci={"workflow": workflow})


@needs_git
def test_the_user_named_workflow_confirms_credit(tmp_path, monkeypatch):
    repo, commit = _landed_check(tmp_path)
    _user_ci(repo, "aegis.yml")
    assert credit.required_workflow(repo.root) == "aegis.yml"
    assert _project(repo, commit, monkeypatch) == ("confirmed", "")


@needs_git
def test_without_the_key_the_default_workflow_finds_no_run(tmp_path, monkeypatch):
    repo, commit = _landed_check(tmp_path)  # the ledger ci row names aegis.yml: display only
    assert credit.required_workflow(repo.root) == "validate.yml"
    assert _project(repo, commit, monkeypatch) == ("landed", "unverified_ci")


@needs_git
@pytest.mark.parametrize("value", ["../x.yml", "a/b.yml", "x", "", 7])
def test_an_unusable_user_value_falls_back_to_the_default(tmp_path, monkeypatch, value):
    repo, commit = _landed_check(tmp_path)
    _user_ci(repo, value)
    assert credit.required_workflow(repo.root) == "validate.yml"
    assert _project(repo, commit, monkeypatch) == ("landed", "unverified_ci")


@needs_git
def test_the_repository_config_never_names_the_workflow(tmp_path, monkeypatch):
    repo, commit = _landed_check(tmp_path)
    repo.write(".aegis/config.json", json.dumps({"v": 1, "ci": {"workflow": "aegis.yml"}}))
    assert credit.required_workflow(repo.root) == "validate.yml"
    assert _project(repo, commit, monkeypatch) == ("landed", "unverified_ci")


@needs_git
def test_a_user_config_inside_the_workspace_is_ignored(tmp_path, monkeypatch):
    repo, commit = _landed_check(tmp_path)
    inner = repo.root / "inner-home"
    hv.write_user_config(inner, ci={"workflow": "aegis.yml"})
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(inner))
    assert credit.required_workflow(repo.root) == "validate.yml"


@needs_git
def test_an_explicit_workflow_argument_still_wins(tmp_path):
    repo, commit = _landed_check(tmp_path)
    _user_ci(repo, "aegis.yml")
    summary = credit.confirm(repo.root, client=hv.FakeCI([hv.ci_run(commit)]), workflow=hv.CI_WORKFLOW,
                             landed=credit.landed_lookup(repo.root))
    assert summary["confirmed"] == 1


# ── what doctor and init say ─────────────────────────────────────────────────

def _doctor_github(repo, monkeypatch, capsys, *extra):
    from aegis_cli.cli import main

    monkeypatch.setattr(human_gate, "default_gh_runner", hg.FakeGh())
    monkeypatch.chdir(repo.root)
    capsys.readouterr()
    assert main(["doctor", "--github", *extra]) == 0
    return capsys.readouterr().out


@needs_git
def test_doctor_github_names_the_workflow_and_warns_when_it_is_missing(tmp_path, monkeypatch, capsys):
    repo = hv.make_project(tmp_path)
    out = _doctor_github(repo, monkeypatch, capsys)
    assert "credit looks for runs of .github/workflows/validate.yml (default; set ci.workflow" in out
    assert ".github/workflows/validate.yml is missing at HEAD" in out
    _user_ci(repo, "aegis.yml")
    repo.write(".github/workflows/aegis.yml", "name: Aegis\n")
    repo.commit("workflow")
    out = _doctor_github(repo, monkeypatch, capsys)
    assert "credit looks for runs of .github/workflows/aegis.yml (ci.workflow)" in out and "missing at HEAD" not in out
    payload = json.loads(_doctor_github(repo, monkeypatch, capsys, "--json"))
    assert payload["github"]["ci_workflow"] == {"name": "aegis.yml", "source": "user-config", "present": True}


def test_init_ci_says_how_to_let_credit_read_the_workflow(tmp_path, monkeypatch, capsys):
    from aegis_cli.cli import _build_parser
    from aegis_cli.init import run_init

    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    args = _build_parser().parse_args(["init", "--workspace", str(project), "--yes", "--no-hooks", "--rules",
                                       "minimal", "--ci"])
    assert run_init(args) == 0
    assert '"ci": {"workflow": "aegis.yml"} in ~/.aegis/config.json' in capsys.readouterr().out
