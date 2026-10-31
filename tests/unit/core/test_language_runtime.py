"""Shared runtime preparation through its public API and real process boundary."""
from pathlib import Path
import os
import subprocess
import sys

import pytest

from tests.unit.core import test_language_tests

project = test_language_tests.project


def test_go_runtime_prepares_without_test_identities_and_preserves_offline_policy(project):
    from aegis_core.language_runtime import (
        language_runtime_environment,
        prepare_language_runtime,
    )

    runtime = prepare_language_runtime(project["workspace"], "go", ["go", "test"],
                                       scratch=project["scratch"] / "runtime")
    env = language_runtime_environment(runtime, project["scratch"] / "execute")
    assert Path(runtime.command[0]).is_absolute()
    assert runtime.command[1:] == ("test",)
    assert {name: env[name] for name in ("GOTOOLCHAIN", "GOFLAGS", "GOPROXY", "GOWORK", "GOENV")} == {
        "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOWORK": "off", "GOENV": "off"}
    assert env["GOMODCACHE"] == str(project["tools"] / "go-modules")
    assert env["HOME"] == str(project["scratch"] / "execute" / "home")
    assert len(project["calls"]) == 1 and project["calls"][0][0][1:] == ["env", "GOCACHE", "GOMODCACHE"]
    assert Path(project["calls"][0][1]["cwd"]).name == "neutral"


def test_rust_runtime_ignores_repository_pin_and_uses_installed_default(project):
    from aegis_core.language_runtime import (
        language_runtime_environment,
        prepare_language_runtime,
    )

    (project["workspace"] / "rust-toolchain.toml").write_text('[toolchain]\nchannel="missing-fetch-me"')
    runtime = prepare_language_runtime(project["workspace"], "rust", ["cargo", "test"],
                                       scratch=project["scratch"] / "runtime")
    env = language_runtime_environment(runtime, project["scratch"] / "execute")
    assert env["RUSTUP_TOOLCHAIN"] == "stable-fixture"
    assert env["RUSTUP_AUTO_INSTALL"] == "0" and env["CARGO_NET_OFFLINE"] == "true"
    assert not Path(env["CARGO_TARGET_DIR"]).is_relative_to(project["workspace"])
    assert len(project["calls"]) == 1 and project["calls"][0][0][1:] == ["toolchain", "list"]


def test_runtime_refuses_metadata_scratch_inside_workspace(project):
    from aegis_core.language_runtime import RuntimeUnavailable, prepare_language_runtime

    with pytest.raises(RuntimeUnavailable) as error:
        prepare_language_runtime(project["workspace"], "go", ["go", "test"],
                                 scratch=project["workspace"] / "scratch")
    assert error.value.reason == "deps_unavailable"
    assert error.value.detail == "scratch must be outside the workspace"
    assert project["calls"] == []


@pytest.mark.parametrize('replacement', ['regular', 'hardlink', *(['fifo'] if hasattr(os, 'mkfifo') else [])])
def test_report_reader_refuses_open_boundary_replacement(tmp_path, replacement):
    # A process timeout bounds a real FIFO open; it does not assert execution speed.
    script = '''import os,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aegis_core.language_runtime import read_runtime_report, RuntimeUnavailable
report=Path(sys.argv[2]); report.write_text('original')
original_open=os.open
def raced_open(path, flags, *args, **kwargs):
    if Path(path)==report:
        old=report.with_suffix('.old'); report.rename(old)
        if sys.argv[3]=='fifo': os.mkfifo(report)
        elif sys.argv[3]=='hardlink': os.link(old,report)
        else: report.write_text('replacement')
    return original_open(path,flags,*args,**kwargs)
os.open=raced_open
try:
    read_runtime_report(report)
except RuntimeUnavailable as error:
    print(error.reason)
else:
    raise AssertionError('changed report accepted')
'''
    run = subprocess.run([sys.executable, '-I', '-c', script, str(Path(__file__).resolve().parents[3]),
                          str(tmp_path / 'report'), replacement], capture_output=True, text=True, timeout=5)
    assert (run.returncode, run.stdout.strip()) == (0, 'report_unsafe'), run.stderr
