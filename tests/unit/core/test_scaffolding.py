"""Unit tests for ``aegis_core.scaffolding``: rule locator, preset resolution, frontmatter
type projection, and CI workflow generation/inspection."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core import __version__
from aegis_core.scaffolding import (
    ACTIVE_STARTERS,
    CI_WORKFLOW_PATH,
    DEFAULT_RULE_PRESET,
    RULE_PRESETS,
    _RUNS_AEGIS_CHECK,
    _declare_type,
    _runs_aegis_check,
    _workflow_files,
    ci_workflow,
    install_rules,
    packaged_active_rules,
    packaged_dir,
    packaged_rules,
    preset_rules,
)

REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


class TestPackagedDirAndRules:
    def test_packaged_dir_resolves_wheel_and_checkout(self, tmp_path: Path) -> None:
        assert packaged_dir("rules") == REPO_ROOT / "rules"

        site = tmp_path / "site" / "aegis_core"
        (site / "_data" / "rules").mkdir(parents=True)
        assert packaged_dir("rules", base=site) == site / "_data" / "rules"

        checkout = tmp_path / "checkout"
        (checkout / "aegis_core").mkdir(parents=True)
        (checkout / "rules").mkdir()
        # Without pyproject.toml, falls back to installed (_data/rules)
        assert packaged_dir("rules", base=checkout / "aegis_core") == checkout / "aegis_core" / "_data" / "rules"

        (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        assert packaged_dir("rules", base=checkout / "aegis_core") == checkout / "rules"
        # Missing named directory even with pyproject.toml falls back to installed (_data/missing)
        assert packaged_dir("missing", base=checkout / "aegis_core") == checkout / "aegis_core" / "_data" / "missing"

    def test_packaged_rules_excludes_active_starters(self) -> None:
        guidance = packaged_rules()
        active = packaged_active_rules()
        assert set(active) == set(ACTIVE_STARTERS) == {"no-eval"}
        assert "no-eval" not in guidance
        assert {"providence", "destructive-ops", "testing"} <= set(guidance)

    def test_packaged_active_rules_raises_when_missing(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found; reinstall aegis-guardrails"):
            packaged_active_rules(locator=lambda name: tmp_path / "missing" / name)

    def test_preset_rules_resolves_presets_and_rejects_unknown(self) -> None:
        assert DEFAULT_RULE_PRESET == "standard"
        minimal = {p.stem for p in preset_rules("minimal")}
        standard = {p.stem for p in preset_rules("standard")}
        full = {p.stem for p in preset_rules("full")}
        assert minimal == set(RULE_PRESETS["minimal"] or ())
        assert standard == set(RULE_PRESETS["standard"] or ())
        assert minimal < standard < full
        with pytest.raises(ValueError, match="unknown rule preset"):
            preset_rules("nonexistent")


class TestDeclareTypeAndInstallRules:
    def test_declare_type_inserts_or_replaces_type_and_target_paths(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "sample.md"
        rule_file.write_bytes(b"---\nid: sample\ndomain: governance\n---\n# Title\n")
        projected = _declare_type(rule_file, "persona")
        assert projected == (
            b"---\nid: sample\ntype: persona\ntarget_paths: []\ndomain: governance\n---\n# Title\n"
        )

        typed_file = tmp_path / "typed.md"
        typed_file.write_bytes(b"---\r\nid: typed\r\ntype: trap\r\ntarget_paths: [\"*.py\"]\r\n---\r\n# Body\r\n")
        replaced = _declare_type(typed_file, "persona")
        assert replaced == b"---\r\nid: typed\r\ntype: persona\r\ntarget_paths: [\"*.py\"]\r\n---\r\n# Body\r\n"

    def test_declare_type_rejects_missing_frontmatter(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.md"
        bad.write_text("# No frontmatter\n", encoding="utf-8")
        with pytest.raises(ValueError, match="has no frontmatter"):
            _declare_type(bad, "persona")

    def test_install_rules_respects_skip_force_and_dry_run(self, tmp_path: Path) -> None:
        dry_dest = tmp_path / "dry"
        names = install_rules(dry_dest, preset="minimal", dry_run=True)
        assert set(names) == {"providence", "destructive-ops"}
        assert not dry_dest.exists()

        dest = tmp_path / "dest"
        installed = install_rules(dest, preset="minimal", skip=("destructive-ops",), rule_type="persona")
        assert installed == ["providence"]
        assert (dest / "providence.md").is_file()
        assert not (dest / "destructive-ops.md").exists()

        (dest / "providence.md").write_text("custom", encoding="utf-8")
        install_rules(dest, preset="minimal", skip=("destructive-ops",), force=False)
        assert (dest / "providence.md").read_text(encoding="utf-8") == "custom"
        install_rules(dest, preset="minimal", skip=("destructive-ops",), force=True)
        assert (dest / "providence.md").read_text(encoding="utf-8") != "custom"


class TestCiWorkflowHelpers:
    def test_ci_workflow_pins_version_and_runs_aegis_check(self, tmp_path: Path) -> None:
        assert CI_WORKFLOW_PATH == ".github/workflows/aegis.yml"
        wf = ci_workflow()
        assert f"pip install aegis-guardrails=={__version__}" in wf
        wf_file = tmp_path / ".github" / "workflows" / "aegis.yml"
        wf_file.parent.mkdir(parents=True)
        wf_file.write_text(wf, encoding="utf-8")
        other_file = wf_file.parent / "other.yaml"
        other_file.write_text("name: Test\non: push\njobs: {}\n", encoding="utf-8")

        assert _workflow_files(tmp_path) == [wf_file, other_file]
        assert _runs_aegis_check(wf_file) is True
        assert _runs_aegis_check(other_file) is False
        assert _runs_aegis_check(tmp_path / "missing.yml") is False


class TestCiWorkflowSarifUpload:
    """R-checks-41: the generated workflow uploads the SARIF log only where code scanning can take it,
    from a job of its own that holds the write permission and runs none of the pull request's code."""

    @staticmethod
    def _doc():
        yaml = pytest.importorskip("yaml")
        return yaml.safe_load(ci_workflow())

    def test_the_gate_is_unchanged_and_only_the_upload_job_may_write_security_events(self):
        doc = self._doc()
        gate, sarif = doc["jobs"]["aegis-check"], doc["jobs"]["aegis-sarif"]
        runs = [step.get("run", "") for step in gate["steps"]]
        assert runs[-2:] == ["aegis check", "aegis check --ci"] and _RUNS_AEGIS_CHECK.search(ci_workflow())
        assert "security-events" not in gate["permissions"] and "security-events" not in doc.get("permissions", {})
        assert sarif["permissions"] == {"contents": "read", "security-events": "write"}
        (upload,) = [step for step in sarif["steps"] if "upload-sarif" in step.get("uses", "")]
        assert "head.repo.full_name == github.repository" in upload["if"]
        assert "!github.event.repository.private" in upload["if"] and "always()" in upload["if"]

    def test_the_sarif_step_cannot_fail_the_run_and_runs_no_ci_check_with_a_token(self):
        steps = self._doc()["jobs"]["aegis-sarif"]["steps"]
        runs = [step.get("run", "") for step in steps]
        sarif = runs.index("aegis check --format sarif > aegis.sarif")
        assert steps[sarif]["continue-on-error"] is True
        assert sarif < [i for i, step in enumerate(steps) if "upload-sarif" in step.get("uses", "")][0]
        assert not [r for r in runs if "--ci" in r] and not [step for step in steps if "env" in step]

    def test_the_rendered_expressions_are_github_expressions(self):
        text = ci_workflow()
        assert "${{ always() && hashFiles('aegis.sarif') != ''" in text
        assert "${ always()" not in text.replace("${{ always()", "")


class TestInitWorkflowRecognition:
    """Init reports commands that run a check, including installed Python module entrypoints."""

    @pytest.fixture
    def project(self, tmp_path, monkeypatch):
        from aegis_core import hosts

        home = tmp_path / "home"
        home.mkdir()
        for key in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(key, str(home))
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
        for key in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setattr(hosts, "APP_DIRS", {})
        root = tmp_path / "ws"
        root.mkdir()
        return root

    @staticmethod
    def init_action(root, capsys):
        import json
        from aegis_cli.cli import main

        assert main(["init", "--workspace", str(root), "--yes", "--dry-run", "--no-hooks",
                     "--rules", "none-active", "--host", "claude-code", "--json"]) == 0
        doc = json.loads(capsys.readouterr().out)
        action, = [a for a in doc["actions"] if a["target"] == CI_WORKFLOW_PATH]
        return action

    @pytest.mark.parametrize("run", [
        "python3 -m aegis_cli check", "python3 -m aegis_cli.cli check --ci",
        "python3 -I -m aegis_cli check", "python3 -I -m aegis_cli.cli check --ci",
        "python -m aegis_cli.cli check", "'python3 -I -m aegis_cli.cli check --ci'",
        "pip install aegis-guardrails && aegis check", "echo ready; python3 -m aegis_cli check",
        "|\n          python3 -I -m aegis_cli.cli check --ci",
    ], ids=["module", "cli-module", "isolated", "isolated-cli", "python", "yaml-quoted", "and", "semicolon", "block"])
    def test_init_names_a_workflow_running_check(self, project, capsys, run):
        workflow = project / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(("jobs:\n  test:\n    steps:\n      - run: " + run + "\n").encode())
        action = self.init_action(project, capsys)
        assert action["result"] == "present"
        assert action["detail"] == ".github/workflows/ci.yml runs aegis check"

    @pytest.mark.parametrize("run", [
        "python3 -m aegis_cli_extra check", "python3 -m aegis_cli.cli.extra check",
        "python3 -m aegis_cli check-other", "echo python3 -m aegis_cli check",
        "echo 'aegis check'", "echo 'ready && aegis check'", "# aegis check",
        "echo ';' aegis check", "echo '&&' python3 -m aegis_cli check",
        r"echo \; aegis check", r"echo \&\& python3 -m aegis_cli check",
        "|\n          # python3 -I -m aegis_cli.cli check --ci\n          echo ready",
    ], ids=["module-near", "submodule-near", "command-near", "echo-module", "echo-bare", "quoted-shell", "comment", "quoted-semicolon", "quoted-and", "escaped-semicolon", "escaped-and", "block-comment"])
    def test_init_suggests_ci_for_mentions_that_do_not_run_check(self, project, capsys, run):
        workflow = project / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(("jobs:\n  test:\n    steps:\n      - run: " + run + "\n").encode())
        action = self.init_action(project, capsys)
        assert action["result"] == "suggested"
        assert action["detail"] == "no GitHub Actions workflow runs aegis check; aegis init --ci writes one"

    def test_an_unreadable_workflow_is_not_reported_as_running_check(self, project, capsys, monkeypatch):
        import builtins

        workflow = project / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(b"jobs:\n  test:\n    steps:\n      - run: aegis check\n")
        real_open = builtins.open

        def unreadable(path, *args, **kwargs):
            if Path(path) == workflow:
                raise PermissionError("workflow unreadable")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", unreadable)
        assert self.init_action(project, capsys)["result"] == "suggested"
