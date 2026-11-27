"""Tests for centralized test runner discovery in aegis_core/verification/test_runner.py."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis_core.errors import NoTestRunnerFoundError
from aegis_core.verification.test_runner import resolve_pytest_cmd
from aegis_core.workspace.base import Workspace


def _pytest_program(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    program = directory / ("pytest.exe" if os.name == "nt" else "pytest")
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o755)
    return program


def _empty(tmp_path: Path) -> str:
    (tmp_path / "empty-bin").mkdir(exist_ok=True)
    return str(tmp_path / "empty-bin")


class TestPytestResolution:
    """Test resolution of pytest runner across environments."""

    def test_prefers_active_virtual_env(self, tmp_path: Path):
        fake_venv = tmp_path / "active_venv"
        fake_bin = fake_venv / ("Scripts" if os.name == "nt" else "bin")
        fake_bin.mkdir(parents=True)
        fake_pytest = fake_bin / ("pytest.exe" if os.name == "nt" else "pytest")
        fake_pytest.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        if os.name != "nt":
            fake_pytest.chmod(0o755)

        with patch.dict(os.environ, {"VIRTUAL_ENV": str(fake_venv)}):
            cmd = resolve_pytest_cmd()
            assert cmd == [str(fake_pytest)]

    def test_falls_back_to_local_workspace_venv(self, tmp_path: Path):
        ws_dir = tmp_path / "my_project"
        ws_dir.mkdir()
        fake_local_venv = ws_dir / ".venv"
        fake_bin = fake_local_venv / ("Scripts" if os.name == "nt" else "bin")
        fake_bin.mkdir(parents=True)
        fake_pytest = fake_bin / ("pytest.exe" if os.name == "nt" else "pytest")
        fake_pytest.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        if os.name != "nt":
            fake_pytest.chmod(0o755)

        with patch.dict(os.environ, {"VIRTUAL_ENV": ""}):
            cmd = resolve_pytest_cmd(workspace=ws_dir)
            assert cmd == [str(fake_pytest)]

            # Also works with Workspace value object
            ws = Workspace(ws_dir)
            cmd_ws = resolve_pytest_cmd(workspace=ws)
            assert cmd_ws == [str(fake_pytest)]

    def test_falls_back_to_system_which(self, tmp_path: Path):
        program = _pytest_program(tmp_path / "bin")
        with patch.dict(os.environ, {"VIRTUAL_ENV": "", "PATH": str(program.parent)}):
            cmd = resolve_pytest_cmd(workspace=tmp_path)
            assert cmd == [str(program)]

    @pytest.mark.parametrize("entry", ["", ".", "bin"])
    def test_a_pytest_behind_a_relative_path_entry_is_never_chosen(self, tmp_path: Path, monkeypatch, entry):
        # Absolute PATH entries only (aegis_core.pathlookup): an empty or relative entry
        # names the cwd, where the repository under verification can plant a program.
        cwd = tmp_path / "cwd"
        _pytest_program(cwd)
        _pytest_program(cwd / "bin")
        real = _pytest_program(tmp_path / "real-bin")
        monkeypatch.chdir(cwd)
        with patch.dict(os.environ, {"VIRTUAL_ENV": "", "PATH": os.pathsep.join([entry, str(real.parent)])}):
            assert resolve_pytest_cmd(workspace=tmp_path / "ws") == [str(real)]

    def test_falls_back_to_sys_executable(self, tmp_path: Path):
        with patch.dict(os.environ, {"VIRTUAL_ENV": "", "PATH": _empty(tmp_path)}):
            with patch("importlib.util.find_spec", return_value=object()):
                cmd = resolve_pytest_cmd(workspace=tmp_path)
                assert cmd == [sys.executable, "-m", "pytest"]

    def test_returns_empty_when_no_runner_and_not_required(self, tmp_path: Path):
        with patch.dict(os.environ, {"VIRTUAL_ENV": "", "PATH": _empty(tmp_path)}):
            with patch("importlib.util.find_spec", return_value=None):
                cmd = resolve_pytest_cmd(workspace=tmp_path, required=False)
                assert cmd == []

    def test_raises_when_no_runner_and_required(self, tmp_path: Path):
        with patch.dict(os.environ, {"VIRTUAL_ENV": "", "PATH": _empty(tmp_path)}):
            with patch("importlib.util.find_spec", return_value=None):
                with pytest.raises(NoTestRunnerFoundError) as exc:
                    resolve_pytest_cmd(workspace=tmp_path, required=True)
                assert "No pytest runner found" in str(exc.value)


class TestDiscoverTestEvidence:
    """Behavioral tests for discover_test_evidence."""

    def test_no_test_files_returns_empty(self, tmp_path):
        from aegis_core.verification.test_runner import discover_test_evidence
        names, results = discover_test_evidence(["nonexistent.py"], str(tmp_path))
        assert names == []
        assert results == ""

    def test_direct_test_file_discovered_and_run(self, tmp_path):
        from aegis_core.verification.test_runner import discover_test_evidence
        import subprocess

        test_file = tmp_path / "test_module.py"
        test_file.write_text("def test_one(): pass\nasync def test_two(): pass\ndef helper(): pass\n")

        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(["pytest"], 0, stdout="1 passed\n", stderr="")
                names, results = discover_test_evidence([str(test_file)], str(tmp_path))
                assert "test_one" in names
                assert "test_two" in names
                assert "helper" not in names
                assert "[test_module.py]" in results
                assert "1 passed" in results

    def test_source_file_finds_candidate_and_handles_error(self, tmp_path):
        from aegis_core.verification.test_runner import discover_test_evidence

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir(parents=True)
        t_file = tests_dir / "test_worker_unit.py"
        t_file.write_text("def test_worker(): assert 1 == 1\n")

        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            with patch("subprocess.run", side_effect=OSError("process spawn failure")):
                names, results = discover_test_evidence(["worker.py"], str(tmp_path))
                assert "test_worker" in names
                assert "error: process spawn failure" in results

    def test_no_runner_found_raises_error(self, tmp_path):
        from aegis_core.verification.test_runner import discover_test_evidence
        from aegis_core.errors import NoTestRunnerFoundError

        test_file = tmp_path / "test_foo.py"
        test_file.write_text("def test_a(): pass\n")

        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=[]):
            with pytest.raises(NoTestRunnerFoundError):
                discover_test_evidence([str(test_file)], str(tmp_path))

    def test_discover_test_evidence_handles_listdir_and_ast_errors(self, tmp_path):
        from aegis_core.verification.test_runner import discover_test_evidence
        import subprocess

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir(parents=True)
        # Corrupted python test file that triggers AST parse exception
        bad_file = tests_dir / "test_broken.py"
        bad_file.write_text("def bad_syntax(:\n")

        with patch("os.listdir", side_effect=OSError("dir read error")):
            names, results = discover_test_evidence(["foo.py"], str(tmp_path))
            assert names == []

        with patch("aegis_core.verification.test_runner.resolve_pytest_cmd", return_value=["pytest"]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(["pytest"], 0, stdout="", stderr="")
                names, results = discover_test_evidence([str(bad_file)], str(tmp_path))
                assert names == []
