"""Tests for aegis_cli/verify.py, the engine behind `aegis check`.

The command-line behavior of `aegis check` is tested in test_cli_check.py. This
module covers the helpers and the direct run_verify(args) entry point:
- run_verify on parsed `check` arguments and on the bare namespaces older callers build
- resolve_target_files: explicit files, out-of-tree refusal, git and branch fallbacks
- resolve_task_plan: --plan, --plan-file, docs/plan.md
- telemetry on Layer 1 and Layer 2 runs
"""
import argparse
import subprocess
import sys
import textwrap
from pathlib import Path


# Ensure repo root is on sys.path
REPO_ROOT = str(next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists()))
sys.path.insert(0, REPO_ROOT)

from aegis_core.verification import Verdict
from aegis_cli.cli import _build_parser


class TestVerifyExitCodes:
    """run_verify returns 0 when Layer 1 passes and 1 when it fails."""

    def test_run_verify_returns_zero_on_ship_verdict(self, tmp_path):
        """Direct call to run_verify returning SHIP verdict yields exit code 0."""
        from aegis_cli.verify import run_verify

        clean_file = tmp_path / "healthy.py"
        clean_file.write_text(textwrap.dedent("""\
            def healthy_work():
                return 1

            def main():
                return healthy_work()
        """))

        parser = _build_parser()
        args = parser.parse_args(["check", "--workspace", str(tmp_path), "healthy.py"])
        exit_code = run_verify(args)
        assert exit_code == 0

    def test_run_verify_returns_one_on_block_verdict(self, tmp_path):
        """Direct call to run_verify encountering BLOCK verdict yields exit code 1."""
        from aegis_cli.verify import run_verify

        bad_file = tmp_path / "blocked.py"
        bad_file.write_text(textwrap.dedent("""\
            import unauthorized_external_dep_xyz
        """))

        parser = _build_parser()
        args = parser.parse_args(["check", "--workspace", str(tmp_path), "blocked.py"])
        exit_code = run_verify(args)
        assert exit_code == 1


class TestResolveTargetFiles:
    """Positional FILES pass through; without them git supplies the changed files."""

    def test_resolve_target_files_uses_explicit_files(self):
        """resolve_target_files returns the explicit files when FILES are given."""
        from aegis_cli.verify import resolve_target_files

        parser = _build_parser()
        args = parser.parse_args(["check", "src/foo.py", "src/bar.py"])
        resolved = resolve_target_files(args)
        assert resolved == ["src/foo.py", "src/bar.py"]

    def test_resolve_target_files_defaults_to_git_changes_when_no_files_flag(self):
        """Without FILES, resolve_target_files queries git staged/changed files."""
        from aegis_cli.verify import resolve_target_files

        parser = _build_parser()
        args = parser.parse_args(["check"])
        resolved = resolve_target_files(args)
        assert isinstance(resolved, list), "resolve_target_files must return a list of file paths"

    def test_resolve_rejects_out_of_tree_paths(self, tmp_path):
        """Files outside repo_root should be skipped with warning."""
        from aegis_cli.verify import resolve_target_files

        # Create a repo structure
        repo = tmp_path / "myrepo"
        repo.mkdir()

        parser = _build_parser()
        args = parser.parse_args(["check", "--workspace", str(repo), "../../etc/passwd", "good.py"])
        resolved = resolve_target_files(args)
        # The traversal path should be filtered out
        assert "../../etc/passwd" not in resolved
        # The in-tree file should remain
        assert "good.py" in resolved

class TestVerifyPlanResolution:
    """Test plan resolution logic in aegis_cli.verify."""

    def test_resolve_task_plan_from_argument(self, tmp_path):
        """Explicit --plan string takes highest precedence."""
        from aegis_cli.verify import resolve_task_plan
        args = argparse.Namespace(plan="Implement caching", plan_file=None)
        plan = resolve_task_plan(args, str(tmp_path))
        assert plan == "Implement caching"

    def test_resolve_task_plan_from_file(self, tmp_path):
        """--plan-file reads the plan file from disk."""
        from aegis_cli.verify import resolve_task_plan
        plan_doc = tmp_path / "task_spec.md"
        plan_doc.write_text("Build persistent ledger")
        args = argparse.Namespace(plan=None, plan_file="task_spec.md")
        plan = resolve_task_plan(args, str(tmp_path))
        assert plan == "Build persistent ledger"

    def test_resolve_task_plan_missing_file_returns_none(self, tmp_path, capsys):
        """Missing --plan-file prints error and returns None."""
        from aegis_cli.verify import resolve_task_plan
        args = argparse.Namespace(plan=None, plan_file="nonexistent_spec.md")
        plan = resolve_task_plan(args, str(tmp_path))
        assert plan is None
        captured = capsys.readouterr()
        assert "plan file not found" in captured.err.lower()

    def test_resolve_task_plan_falls_back_to_docs_plan_md(self, tmp_path):
        """Without --plan/--plan-file, a non-empty docs/plan.md is the plan."""
        from aegis_cli.verify import resolve_task_plan
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "plan.md").write_text("  Ship the ledger  \n", encoding="utf-8")
        args = argparse.Namespace(plan=None, plan_file=None)
        assert resolve_task_plan(args, str(tmp_path)) == "Ship the ledger"


class TestRunVerifyNamespaces:
    """run_verify accepts the bare namespaces older callers build."""

    def test_namespace_without_full_runs_layer1_only(self, tmp_path, monkeypatch):
        """No --full and no plan: the model command is never consulted, even if configured."""
        from aegis_cli.verify import run_verify

        marker = tmp_path / "llm-ran"
        monkeypatch.setenv("AEGIS_LLM_CMD", f"{sys.executable} -c \"open({str(marker)!r}, 'w')\"")
        (tmp_path / "core.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        args = argparse.Namespace(
            files=["core.py"], layer1_only=True, dry_run=False, repo_root=str(tmp_path),
            workspace=str(tmp_path), plan=None, plan_file=None,
        )
        assert run_verify(args) == 0
        assert not marker.exists()

    def test_namespace_without_files_checks_the_git_changes(self, tmp_path):
        """A caller that sets no `files` attribute gets the default target discovery
        (with hook=True: the staged files, none here)."""
        from aegis_cli.verify import run_verify

        subprocess.run(["git", "init", "-q"], cwd=str(tmp_path), check=True)
        assert run_verify(argparse.Namespace(hook=True, workspace=str(tmp_path))) == 0

    def test_layer1_run_records_telemetry(self, tmp_path, monkeypatch):
        from aegis_cli.verify import run_verify

        calls = []
        monkeypatch.setattr("aegis_core.outcomes.telemetry.record_verification_telemetry", lambda **kw: calls.append(kw))
        (tmp_path / "core.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        args = argparse.Namespace(files=["core.py"], workspace=str(tmp_path), dry_run=False)
        assert run_verify(args) == 0
        assert [(c["target_files"], c["passed"], c["verdict"]) for c in calls] == [(["core.py"], True, "PASS")]


class TestVerifyLayer2Execution:
    """Layer 2 telemetry; the CLI Layer 2 behavior is tested in test_cli_check.py."""

    def test_run_verify_records_telemetry_on_layer2(self, tmp_path, monkeypatch):
        """run_verify records telemetry on Layer 2 completion."""
        from aegis_cli.verify import run_verify

        telemetry_calls = []
        def mock_record(**kwargs):
            telemetry_calls.append(kwargs)
        monkeypatch.setattr("aegis_core.outcomes.telemetry.record_verification_telemetry", mock_record)

        fake_llm = tmp_path / "fake_llm.py"
        fake_llm.write_text("import sys\nsys.stdin.read()\nprint('[]')\n", encoding="utf-8")

        target = tmp_path / "worker.py"
        target.write_text("def compute(x: int) -> int:\n    return x\n\ndef main():\n    return compute(1)\n")

        args = argparse.Namespace(
            files=["worker.py"],
            repo_root=str(tmp_path),
            workspace=str(tmp_path),
            plan="Implement worker",
            llm_cmd=f"{sys.executable} {fake_llm}",
            layer1_only=False,
            dry_run=False,
            plain=False,
            no_emoji=False,
            strict=False,
        )

        exit_code = run_verify(args)
        assert exit_code == 0
        assert len(telemetry_calls) >= 1
        assert telemetry_calls[-1]["passed"] is True
        assert telemetry_calls[-1]["verdict"] == Verdict.SHIP

    @staticmethod
    def _layer2_args(tmp_path: Path, llm_source: str) -> argparse.Namespace:
        fake_llm = tmp_path / "fake_llm.py"
        fake_llm.write_text(llm_source, encoding="utf-8")
        (tmp_path / "worker.py").write_text(
            "def compute(x: int) -> int:\n    return x\n\ndef main():\n    return compute(1)\n", encoding="utf-8")
        return argparse.Namespace(
            files=["worker.py"], repo_root=str(tmp_path), workspace=str(tmp_path), plan="Implement worker",
            llm_cmd=f"{sys.executable} {fake_llm}", dry_run=False, strict=False,
        )

    def test_a_layer2_block_records_the_layer1_pass(self, tmp_path, monkeypatch):
        """The Layer 2 verdict is meta text: rule outcomes follow Layer 1 only (R-checks-43)."""
        from aegis_cli.verify import run_verify

        calls = []
        monkeypatch.setattr("aegis_core.outcomes.telemetry.record_verification_telemetry", lambda **kw: calls.append(kw))
        critical_for_spec_only = (
            "import json, sys\n"
            "prompt = sys.stdin.read()\n"
            "if 'Spec Agent' in prompt:\n"
            "    print(json.dumps([{'category': 'code_injection', 'severity': 'critical', 'risk': 'eval',"
            " 'mechanism': 'exec', 'affected_function': 'compute'}]))\n"
            "else:\n"
            "    print('[]')\n"
        )
        assert run_verify(self._layer2_args(tmp_path, critical_for_spec_only)) == 0
        assert [(c["passed"], c["verdict"]) for c in calls] == [(True, Verdict.BLOCK)]

    def test_a_model_command_that_cannot_run_fails_without_fp_rows(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.verify import run_verify

        calls = []
        monkeypatch.setattr("aegis_core.outcomes.telemetry.record_verification_telemetry", lambda **kw: calls.append(kw))
        failing = "import sys\nsys.stdin.read()\nsys.stderr.write('quota exceeded\\n')\nsys.exit(7)\n"
        assert run_verify(self._layer2_args(tmp_path, failing)) == 1
        assert "Layer 2 failed" in capsys.readouterr().err
        assert calls == []

    def test_failed_test_discovery_fails_without_fp_rows(self, tmp_path, monkeypatch, capsys):
        from aegis_cli import verify

        calls = []
        monkeypatch.setattr("aegis_core.outcomes.telemetry.record_verification_telemetry", lambda **kw: calls.append(kw))

        def boom(*_args, **_kwargs):
            raise RuntimeError("discovery\x1b[2K broke")  # test output is repository content

        monkeypatch.setattr(verify, "discover_test_evidence", boom)
        assert verify.run_verify(self._layer2_args(tmp_path, "import sys\nsys.stdin.read()\nprint('[]')\n")) == 1
        err = capsys.readouterr().err
        assert "Test discovery and execution failed: discovery broke" in err
        assert "\x1b" not in err
        assert calls == []

class TestResolveTargetFilesFallbacks:
    """resolve_target_files falls back from the working tree to branch diffs (real git, via gitsafe)."""

    @staticmethod
    def _git(repo, *args):
        import subprocess

        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                       cwd=str(repo), check=True, capture_output=True)

    def _repo(self, tmp_path, base="main"):
        repo = tmp_path / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", base)
        (repo / "base.py").write_text("x = 1\n", encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "base")
        return repo

    def _branch_commit(self, repo, name, path):
        self._git(repo, "checkout", "-q", "-b", name)
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("y = 1\n", encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", name)

    def test_resolve_target_files_github_base_ref(self, tmp_path, monkeypatch):
        """A clean tree on a PR branch checks what the branch adds to GITHUB_BASE_REF."""
        from aegis_cli.verify import resolve_target_files

        repo = self._repo(tmp_path)
        self._branch_commit(repo, "topic", "aegis_core/mod.py")
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        args = argparse.Namespace(files=None, workspace=str(repo))
        assert resolve_target_files(args) == ["aegis_core/mod.py"]
        assert args._diff_base == "main...HEAD"

    def test_resolve_target_files_preserves_existing_files_when_github_base_ref_set(self, tmp_path, monkeypatch):
        """Uncommitted changes win: the branch diff is not consulted."""
        from aegis_cli.verify import resolve_target_files

        repo = self._repo(tmp_path)
        self._branch_commit(repo, "topic", "ci_file.py")
        (repo / "staged_file.py").write_text("s = 1\n", encoding="utf-8")
        self._git(repo, "add", "staged_file.py")
        monkeypatch.setenv("GITHUB_BASE_REF", "main")

        args = argparse.Namespace(files=None, workspace=str(repo))
        assert resolve_target_files(args) == ["staged_file.py"]
        assert not hasattr(args, "_diff_base")

    def test_resolve_target_files_without_git(self, tmp_path, monkeypatch):
        """git missing: nothing is known and no base was diffed, so a clean tree is not assumed."""
        from aegis_cli.verify import resolve_target_files

        (tmp_path / "no-git").mkdir()
        monkeypatch.setenv("PATH", str(tmp_path / "no-git"))
        args = argparse.Namespace(files=None, workspace=str(tmp_path))
        assert resolve_target_files(args) == []
        assert args._no_diff_base is True

    def test_resolve_target_files_clean_tree_branch_diff_fallback(self, tmp_path, monkeypatch):
        """Without GITHUB_BASE_REF the base is origin/main, main, origin/develop or develop."""
        from aegis_cli.verify import resolve_target_files

        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        repo = self._repo(tmp_path)
        self._branch_commit(repo, "feature", "core/branch_file.py")
        self._git(repo, "update-ref", "refs/remotes/origin/main", "main")

        args = argparse.Namespace(files=None, workspace=str(repo))
        assert resolve_target_files(args) == ["core/branch_file.py"]
        assert args._diff_base == "origin/main...HEAD"

    def test_resolve_target_files_head_parent_fallback(self, tmp_path, monkeypatch):
        """On the base branch itself (empty branch diff) the last commit is checked."""
        from aegis_cli.verify import resolve_target_files

        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        repo = self._repo(tmp_path)
        (repo / "core").mkdir()
        (repo / "core" / "last_commit_file.py").write_text("z\n", encoding="utf-8")
        self._git(repo, "add", "-A")
        self._git(repo, "commit", "-q", "-m", "second")

        args = argparse.Namespace(files=None, workspace=str(repo))
        assert resolve_target_files(args) == ["core/last_commit_file.py"]
        assert args._diff_base == "HEAD~1"

    def test_resolve_target_files_single_commit_clean_tree_has_no_diff_base(self, tmp_path, monkeypatch):
        from aegis_cli.verify import resolve_target_files

        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        repo = self._repo(tmp_path, base="trunk")
        args = argparse.Namespace(files=None, workspace=str(repo))
        assert resolve_target_files(args) == []
        assert args._no_diff_base is True

    def test_resolve_target_files_custom_github_base_ref_prefers_origin(self, tmp_path, monkeypatch):
        """GITHUB_BASE_REF names the base; its origin/ remote-tracking ref is preferred."""
        from aegis_cli.verify import resolve_target_files

        repo = self._repo(tmp_path)
        self._git(repo, "branch", "release-1.0")
        self._git(repo, "update-ref", "refs/remotes/origin/release-1.0", "release-1.0")
        self._branch_commit(repo, "pr", "core/pr_feature.py")
        self._git(repo, "branch", "-f", "release-1.0", "pr")  # the local branch moved on; origin did not
        monkeypatch.setenv("GITHUB_BASE_REF", "release-1.0")

        args = argparse.Namespace(files=None, workspace=str(repo))
        assert resolve_target_files(args) == ["core/pr_feature.py"]
        assert args._diff_base == "origin/release-1.0...HEAD"


    # Through `aegis check`: what resolve_target_files found decides what the run says.

    def test_a_clean_tree_whose_base_diffs_are_empty_is_a_clean_repository(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.cli import main

        monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
        repo = self._repo(tmp_path)
        (repo / ".aegis" / "rules").mkdir(parents=True)
        self._git(repo, "commit", "-q", "--allow-empty", "-m", "nothing changed")
        assert main(["check", "--workspace", str(repo)]) == 0
        out = capsys.readouterr().out
        assert "Layer 1: 0 files changed (clean repository)" in out
        assert "no base commit" not in out

    def test_hook_without_git_fails_closed(self, tmp_path, monkeypatch, capsys):
        from aegis_cli.cli import main

        ws = tmp_path / "ws"
        (ws / ".aegis" / "rules").mkdir(parents=True)
        (tmp_path / "no-git").mkdir()
        monkeypatch.setenv("PATH", str(tmp_path / "no-git"))
        assert main(["check", "--hook", "--workspace", str(ws)]) == 1
        captured = capsys.readouterr()
        assert "cannot read the staged changes" in captured.err
        assert "PASSED" not in captured.out
