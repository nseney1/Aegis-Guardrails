"""Unit tests for aegis init proactive PATH guidance integration."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from aegis_cli.init import run_init


class TestInitPathGuidance:
    def test_init_displays_path_hint_when_aegis_missing_from_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ):
        target = tmp_path / "project"
        target.mkdir()

        # Monkeypatch build_hint in aegis_cli.pathcheck to return a simulated diagnostic
        monkeypatch.setattr(
            "aegis_cli.pathcheck.build_hint",
            lambda **kwargs: "ℹ️  'aegis' was installed to ~/.local/bin, which is not on your zsh PATH.\n      export PATH=\"$HOME/.local/bin:$PATH\"",
        )

        args = argparse.Namespace(
            project=str(target),
            rules="minimal",
            force=True,
            yes=True,
            dry_run=False,
            _project_root=str(target),
        )

        ret = run_init(args)
        assert ret == 0

        captured = capsys.readouterr().out
        assert "ℹ️  'aegis' was installed to ~/.local/bin, which is not on your zsh PATH." in captured
        assert "export PATH=\"$HOME/.local/bin:$PATH\"" in captured

    def test_init_silent_when_aegis_already_on_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ):
        target = tmp_path / "project2"
        target.mkdir()

        # Monkeypatch build_hint to return None (meaning aegis is already on PATH)
        monkeypatch.setattr("aegis_cli.pathcheck.build_hint", lambda **kwargs: None)

        args = argparse.Namespace(
            project=str(target),
            rules="minimal",
            force=True,
            yes=True,
            dry_run=False,
            _project_root=str(target),
        )

        ret = run_init(args)
        assert ret == 0

        captured = capsys.readouterr().out
        assert "which is not on your" not in captured

    def test_build_hint_aegis_cmd_name_and_resolution(self, tmp_path: Path):
        from aegis_cli.pathcheck import build_hint, scripts_dir

        bindir = tmp_path / "bin"
        bindir.mkdir()
        (bindir / "aegis").write_text("#!/bin/sh\n", encoding="utf-8")
        assert scripts_dir([str(bindir)]) == str(bindir)

        # Resolves None when 'aegis' is found by which()
        assert (
            build_hint(
                env={"PATH": str(bindir)},
                candidates=[str(bindir)],
                which=lambda cmd, **_kw: str(bindir / "aegis") if cmd == "aegis" else None,
                cmd_name="aegis",
            )
            is None
        )

        # Reports aegis-guardrails when not installed
        hint_missing = build_hint(
            env={"PATH": "/usr/bin"},
            candidates=[str(tmp_path / "empty")],
            which=lambda *_a, **_kw: None,
            cmd_name="aegis",
            os_name="posix",
        )
        assert hint_missing is not None
        assert "The 'aegis' command is not installed" in hint_missing
        assert "pip install aegis-guardrails" in hint_missing
