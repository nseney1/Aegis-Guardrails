"""The launcher starts, resumes and stops Codex roles and records every outcome.

Codex is the fake on PATH: a start prints the events a real start begins with, and a resume runs the fake host,
which reads the mailbox through the real adapter. These tests show the tools work together, not that a real
Codex session behaves this way.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import is_dataclass, replace
from types import SimpleNamespace
import uuid

import pytest

# The shared fake wrapper supplies only this integration folder, not the checkout.
# Standalone captured entries load trusted test helpers before executing their target.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.integration.hierarchy_fake_wrapper import shell_exec
from tests.conftest import symlink_or_skip
from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke
from tests.integration.test_hierarchy_provision import Setup, provision, worker_source_seed
from tools import hierarchy_launcher as bootstrap_launcher
import tests.integration.test_hierarchy_launcher as handshake_tests


pytestmark = pytest.mark.skipif(os.name == "nt", reason="the launcher supports POSIX process groups only")
LINUX_HOST_PROGRAMS = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="host program names require Linux; framework Python may replace argv[0]",
)
LAUNCHER = ROOT / "tools" / "hierarchy_launcher.py"
FAKE_CODEX = Path(__file__).with_name("hierarchy_fake_codex.py")
REVIEW = "pilot/lane/review"
START_HEADER = ("The Aegis launcher started this session for %s as %s. This turn comes from the operator who launched "
                "you; it is your role contract.")
START_FOOTER = "Reply READY. Act only when woken."
ROOT_SESSION = "01a19a8e-3073-7af2-b5c0-d0c41fe82ada"
# Bounded outer wait for the complete stop operation, including durable checkpoints and grace.
R2_STOP_TIMEOUT_SECONDS = 60
# Hung-child ceiling only. A live handshake returns on report-pipe readiness or process exit.
R2_HANDSHAKE_CEILING_SECONDS = 60.0
# One control line, checked before json.loads. Emitters already cap a line at 4096 bytes.
# A frame of exactly this many bytes with no newline is still waiting; one byte more is a refusal.
# One pump or discard reads at most this many bytes, so a hostile writer cannot grow memory or
# outrun the handshake ceiling inside a single read.
R2_CONTROL_LINE_LIMIT = 65536
# Complete lines parsed before pump returns to the caller's deadline check.
R2_CONTROL_LINES_PER_PUMP = 64
# Flat control objects stay under this nesting depth. Deeper frames are refused before parsing.
R2_CONTROL_MAX_DEPTH = 8
# The native-probe broker admits 128 actors (ModelledProbeProcesses.MAX_ACTORS).
# Each needs up to five lifecycle frames: intent, created, hello, running, terminal.
# Budget eight 4096-byte emitter frames per actor, including headroom. Both caps
# cover the whole custody lifetime; the next frame past either is still UNKNOWN.
R2_CONTROL_LEDGER_MESSAGES = 128 * 8
R2_CONTROL_LEDGER_BYTES = R2_CONTROL_LEDGER_MESSAGES * 4096

MR1D_PIN_ERROR = "runtime source pin differs from governing provision; use the governing base or reprovision"
MR1D_CHECK_ERROR = "governing source pin check failed; use the governing base or reprovision"

# Captured verbatim from the integration-tip bootstrap at 0d4808f9. The tests run this
# boundary, not Git history, to obtain the old diagnostics on their own interpreter/OS.
MR1D_R2_LEGACY_BOOTSTRAP = '''import argparse
import json
from pathlib import Path
import sys

# Provisioned CLI actions must enter through the retained verifier before importing any peer module.
# A process-local marker prevents recursion; an environment variable cannot bypass verification.
if __name__ == "__main__" and getattr(sys, "_aegis_verified_runtime_entry", None) != str(Path(__file__).resolve()):
    import runpy
    early = argparse.ArgumentParser(add_help=False)
    guarded = False
    try:
        early.add_argument("--base")
        early.add_argument("command", nargs="?")
        parsed, _ = early.parse_known_args()
        if parsed.command in ("start", "resume", "_resume-wake") and parsed.base:
            base = Path(parsed.base)
            guarded = True
        if guarded:
            provision = base / "provision.json"
            setup = json.loads(provision.read_text(encoding="utf-8"))
            verifier = base / "runtime-source.py"
            if not verifier.is_file():
                raise ValueError("runtime source verifier is missing; reprovision into a new base through the existing handoff flow")
            loaded = runpy.run_path(str(verifier))
            loaded["run"](provision, Path(setup["source"]) / "tools" / Path(__file__).name, sys.argv[1:])
            sys.exit(0)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        sys.exit(2)
'''

MR1D_R2_UNSUPPORTED_ENTRY = '''import importlib.util
import json
import sys

entry, arguments, probe = sys.argv[1:]
spec = importlib.util.spec_from_file_location("mr1d_r2_entry", entry)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
# This child owns its module; no global OS/builtins function is patched.
if probe == "unsupported":
    module.bootstrap_descriptor_capable = lambda: False
elif probe == "probe-error":
    class MetadataRefusalPath(type(module.Path())):
        def lstat(self, *args, **kwargs):
            if self.name == "host-plan.json":
                raise PermissionError("metadata probe refused")
            return super().lstat(*args, **kwargs)
    module.Path = MetadataRefusalPath
try:
    assert module.bootstrap_runtime(json.loads(arguments))
except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
    print(json.dumps({"error": str(exc)}, sort_keys=True))
    sys.exit(2)
'''

MR1D_R3_LOOKUP_ENTRY = '''import errno
import importlib.util
import json
import sys

entry, arguments, folder, failure = sys.argv[1:]
spec = importlib.util.spec_from_file_location("mr1d_r3_entry", entry)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
target = module.Path(json.loads(folder)) / "host-plan.json"
failures = {
    "permission": PermissionError(errno.EACCES, "secret\\ninput"),
    "eio": OSError(errno.EIO, "secret\\ninput"),
    "eloop": OSError(errno.ELOOP, "secret\\ninput"),
    "long": OSError(errno.ENAMETOOLONG, "secret\\ninput"),
    "value": ValueError("secret\\ninput"),
    "type": TypeError("secret\\ninput"),
    "runtime": RuntimeError("secret\\ninput"),
    "unexpected": LookupError("secret\\ninput"),
    "missing": FileNotFoundError(errno.ENOENT, "secret\\ninput"),
    "not-directory": NotADirectoryError(errno.ENOTDIR, "secret\\ninput"),
}
# Replace only the owned launcher's Path reference; pytest/stdlib keep their own paths.
class LookupPath(type(module.Path())):
    def lstat(self, *args, **kwargs):
        if self == target and failure != "native":
            raise failures[failure]
        return super().lstat(*args, **kwargs)
module.Path = LookupPath
try:
    assert module.bootstrap_runtime(json.loads(arguments))
except (ValueError, OSError, KeyError, TypeError, UnicodeError) as exc:
    print(json.dumps({"error": str(exc)}, sort_keys=True))
    sys.exit(2)
'''

MR1D_R3_DISPATCH_SPY = '''from pathlib import Path
import runpy

Path(__file__).with_name("verifier-called").write_text("called", encoding="utf-8")
def run(provision, entry, arguments):
    Path(__file__).with_name("launcher-called").write_text("called", encoding="utf-8")
    runpy.run_path(str(entry), run_name="__main__")
'''

MR1D_R3_LEGACY_ENTRY = '''import json
import runpy
import sys

entry, arguments = sys.argv[1:]
sys.argv = [entry, *json.loads(arguments)]
runpy.run_path(entry, run_name="__main__")
'''


@pytest.fixture
def bootstrap_base(tmp_path):
    # A clean permissive old runtime, built without looking up any repository history.
    source = tmp_path / "old-source"
    tools = source / "tools"
    tools.mkdir(parents=True)
    (tools / "hierarchy_launcher.py").write_text(
        'print(\'{"accepted_effort": "ultra"}\')\n', encoding="utf-8")
    shutil.copyfile(ROOT / "tools/hierarchy_runtime_source.py", tools / "hierarchy_runtime_source.py")
    git(source, "init", "-q", "-b", "develop")
    git(source, "add", ".")
    git(source, "commit", "-qm", "synthetic permissive older runtime")
    base, home = tmp_path / "copied", tmp_path / "governing"
    base.mkdir()
    home.mkdir()
    record = {"schema": "aegis.hierarchy-provision/v1", "initiative": "pilot",
              "mailbox_root": str(home / "mailbox"), "source": str(source),
              "source_commit": git(source, "rev-parse", "HEAD"),
              "source_tree": git(source, "rev-parse", "HEAD^{tree}")}
    for directory in (base, home):
        (directory / "provision.json").write_text(json.dumps(record), encoding="utf-8")
    shutil.copyfile(tools / "hierarchy_runtime_source.py", base / "runtime-source.py")
    request = tmp_path / "start.json"
    request.write_text(json.dumps({"endpoint": REVIEW, "effort": "ultra"}), encoding="utf-8")
    return SimpleNamespace(base=base, home=home, record=record, request=request)


def bootstrap_words(built, command):
    return ["--base", str(built.base), command, *(
        ["--request", str(built.request)] if command == "start" else ["--endpoint", REVIEW])]


def bootstrap_call(built, command, expect):
    result = subprocess.run([sys.executable, "-I", str(LAUNCHER), *bootstrap_words(built, command)],
                            capture_output=True, text=True, timeout=R2_STOP_TIMEOUT_SECONDS)
    assert result.stderr == ""
    assert result.returncode == expect, result.stdout
    if expect == 0:
        assert result.stdout == '{"accepted_effort": "ultra"}\n'
    return json.loads(result.stdout)


def bootstrap_legacy(tmp_path, words):
    legacy = tmp_path / "integration-tip" / "hierarchy_launcher.py"
    legacy.parent.mkdir(exist_ok=True)
    legacy.write_text(MR1D_R2_LEGACY_BOOTSTRAP, encoding="utf-8")
    # JSON transport also permits testing the API's NUL-path refusal before OS argv encoding.
    return subprocess.run([sys.executable, "-I", "-c", MR1D_R3_LEGACY_ENTRY, str(legacy), json.dumps(words)],
                          capture_output=True, text=True, timeout=R2_STOP_TIMEOUT_SECONDS)


def bootstrap_lookup_call(built, command, folder, failure):
    return subprocess.run([sys.executable, "-I", "-c", MR1D_R3_LOOKUP_ENTRY,
                           str(LAUNCHER), json.dumps(bootstrap_words(built, command)), json.dumps(str(folder)), failure],
                          capture_output=True, text=True, timeout=R2_STOP_TIMEOUT_SECONDS)


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
@pytest.mark.parametrize("site", ["base", "home"])
@pytest.mark.parametrize("failure", ["permission", "eio", "eloop", "long", "value", "type", "runtime", "unexpected"])
def test_mr1d_r3_indeterminate_lookup_refuses_before_dispatch(bootstrap_base, command, site, failure):
    built = bootstrap_base
    folder = {"base": built.base, "home": built.home}[site]
    (folder / "host-plan.json").write_text("{}", encoding="utf-8")
    (built.home / "provision.json").write_text(
        json.dumps({**built.record, "source_commit": "a" * 40}), encoding="utf-8")
    (built.base / "runtime-source.py").write_text(MR1D_R3_DISPATCH_SPY, encoding="utf-8")
    for _ in range(2):
        current = bootstrap_lookup_call(built, command, folder, failure)
        assert (current.returncode, current.stdout, current.stderr) == (
            2, json.dumps({"error": MR1D_CHECK_ERROR}, sort_keys=True) + "\n", "")
        assert not (built.base / "verifier-called").exists()
        assert not (built.base / "launcher-called").exists()
    # A fresh lookup after recovery must enforce the governing pin too.
    assert bootstrap_call(built, command, 2) == {"error": MR1D_PIN_ERROR}
    assert not (built.base / "verifier-called").exists()
    assert not (built.base / "launcher-called").exists()


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
@pytest.mark.parametrize("site", ["base", "home"])
@pytest.mark.parametrize("failure", ["missing", "not-directory", "native-nul"])
def test_mr1d_r3_absent_lookup_matches_integration_tip(bootstrap_base, tmp_path, command, site, failure):
    built = bootstrap_base
    folder = {"base": built.base, "home": built.home}[site]
    if failure == "native-nul":
        folder = Path(str(folder) + "\0")
        if site == "base":
            built.base = folder
        else:
            (built.base / "provision.json").write_text(
                json.dumps({**built.record, "mailbox_root": str(folder / "mailbox")}), encoding="utf-8")
    baseline = bootstrap_legacy(tmp_path, bootstrap_words(built, command))
    assert baseline.returncode == (2 if failure == "native-nul" and site == "base" else 0)
    for _ in range(2):
        current = bootstrap_lookup_call(built, command, folder, "native" if failure == "native-nul" else failure)
        assert (current.returncode, current.stdout, current.stderr) == (
            baseline.returncode, baseline.stdout, baseline.stderr)


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
@pytest.mark.parametrize("failure", ["permission", "eio"])
@pytest.mark.parametrize("record", ["missing", "malformed", "unsearchable-base"])
def test_mr1d_r3_legacy_read_failure_precedes_indeterminate_lookup(
        bootstrap_base, tmp_path, command, failure, record):
    built = bootstrap_base
    if record == "missing":
        (built.base / "provision.json").unlink()
    elif record == "malformed":
        (built.base / "provision.json").write_text("{", encoding="utf-8")
    elif not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("unsearchable directory requires POSIX modes and a non-root user")
    mode = built.base.stat().st_mode
    try:
        if record == "unsearchable-base":
            built.base.chmod(0)
        baseline = bootstrap_legacy(tmp_path, bootstrap_words(built, command))
        assert baseline.returncode == 2
        current = bootstrap_lookup_call(built, command, built.base, failure)
        assert (current.returncode, current.stdout, current.stderr) == (
            baseline.returncode, baseline.stdout, baseline.stderr)
    finally:
        built.base.chmod(mode)


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
@pytest.mark.parametrize("case", ["missing", "malformed", "unsupported", "probe-error", "duplicate", "oversize",
                                 "base-symlink", "missing-home"])
def test_mr1d_r2_no_plan_matches_integration_tip(bootstrap_base, tmp_path, command, case):
    built = bootstrap_base
    path = built.base / "provision.json"
    if case == "missing":
        path.unlink()
    elif case == "malformed":
        path.write_text("{", encoding="utf-8")
    elif case == "duplicate":
        raw = json.dumps(built.record)
        path.write_text(raw[:-1] + ', "source_commit": ' + json.dumps(built.record["source_commit"]) + '}',
                        encoding="utf-8")
    elif case == "oversize":
        path.write_text(json.dumps({**built.record, "padding": "x" * 262145}), encoding="utf-8")
    elif case == "base-symlink":
        linked = built.base.with_name("linked-base")
        symlink_or_skip(built.base, linked, target_is_directory=True)
        built.base = linked
    elif case == "missing-home":
        (built.home / "provision.json").unlink()
        built.home.rmdir()
    words = bootstrap_words(built, command)
    baseline = bootstrap_legacy(tmp_path, words)
    assert baseline.returncode == (2 if case in ("missing", "malformed") else 0), baseline
    argv = ([sys.executable, "-I", "-c", MR1D_R2_UNSUPPORTED_ENTRY, str(LAUNCHER), json.dumps(words), case]
            if case in ("unsupported", "probe-error") else [sys.executable, "-I", str(LAUNCHER), *words])
    for _ in range(2):
        current = subprocess.run(argv, capture_output=True, text=True, timeout=R2_STOP_TIMEOUT_SECONDS)
        if case == "probe-error":
            # Round 3 explicitly changes this legacy success to a fail-closed refusal.
            assert (current.returncode, current.stdout, current.stderr) == (
                2, json.dumps({"error": MR1D_CHECK_ERROR}, sort_keys=True) + "\n", "")
        else:
            assert (current.returncode, current.stdout, current.stderr) == (
                baseline.returncode, baseline.stdout, baseline.stderr)


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
def test_mr1d_r2_planned_malformed_governing_record_still_refuses(bootstrap_base, command):
    built = bootstrap_base
    plan = built.home / "host-plan.json"
    plan.write_text("{}", encoding="utf-8")
    (built.home / "provision.json").write_text("{", encoding="utf-8")
    assert bootstrap_call(built, command, 2) == {"error": MR1D_CHECK_ERROR}
    # A retry discovers the current plan state instead of caching the prior refusal.
    plan.unlink()
    assert bootstrap_call(built, command, 0) == {"accepted_effort": "ultra"}


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
@pytest.mark.parametrize("component", ["source_commit", "source_tree"])
def test_mr1d_bootstrap_refuses_an_older_pin_before_dispatch(bootstrap_base, command, component):
    built = bootstrap_base
    (built.home / "host-plan.json").write_text("{}", encoding="utf-8")
    governing = {**built.record, component: "a" * 40}
    (built.home / "provision.json").write_text(json.dumps(governing), encoding="utf-8")
    # Retrying the rejected ultra request must never reach the permissive old launcher.
    for _ in range(2):
        assert bootstrap_call(built, command, 2) == {"error": MR1D_PIN_ERROR}


@pytest.mark.parametrize("command", ["start", "resume", "_resume-wake"])
@pytest.mark.parametrize("plan", ["base", "home", None])
def test_mr1d_equal_pin_and_no_plan_keep_retained_dispatch(bootstrap_base, command, plan):
    built = bootstrap_base
    if plan is not None:
        folder = {"base": built.base, "home": built.home}[plan]
        (folder / "host-plan.json").write_text("{}", encoding="utf-8")
    else:
        # No plan: a different governing record has no effect on the old runtime's exact output.
        (built.home / "provision.json").write_text("{}", encoding="utf-8")
    assert bootstrap_call(built, command, 0) == {"accepted_effort": "ultra"}


@pytest.mark.parametrize("case,error", [
    ("missing", MR1D_CHECK_ERROR), ("malformed", MR1D_CHECK_ERROR),
    ("oversize", MR1D_CHECK_ERROR), ("duplicate", MR1D_CHECK_ERROR),
    ("deep", MR1D_CHECK_ERROR), ("integer", MR1D_CHECK_ERROR),
    ("nonfinite", MR1D_CHECK_ERROR), ("utf8", MR1D_CHECK_ERROR),
    ("list", "governing provision record does not match this run; reprovision the base"),
    ("initiative", "governing provision record does not match this run; reprovision the base"),
    ("multiline-pin", "governing provision record has an invalid source pin; reprovision the base"),
])
def test_mr1d_governing_record_failures_refuse_without_echoing(bootstrap_base, case, error):
    built = bootstrap_base
    (built.home / "host-plan.json").write_text("{}", encoding="utf-8")
    path = built.home / "provision.json"
    payloads = {"malformed": b'{"secret\\ninput":', "oversize": b"!" * 262145,
                "duplicate": b'{"secret\\ninput":1,"secret\\ninput":2}',
                "deep": b"[" * 10000 + b"]" * 10000, "integer": b"1" * 129,
                "nonfinite": b"1e9999", "utf8": b"\xff", "list": b"[]",
                "initiative": json.dumps({**built.record, "initiative": "secret\ninput"}).encode(),
                "multiline-pin": json.dumps({**built.record, "source_commit": "a" * 40 + "\n"}).encode()}
    if case == "missing":
        path.unlink()
    else:
        path.write_bytes(payloads[case])
    assert bootstrap_call(built, "start", 2) == {"error": error}
    path.write_text(json.dumps({**built.record, "source_commit": "a" * 40}), encoding="utf-8")
    assert bootstrap_call(built, "start", 2) == {"error": MR1D_PIN_ERROR}


def test_mr1d_unsupported_bootstrap_probe_opens_nothing(bootstrap_base, monkeypatch):
    module = bootstrap_launcher
    (bootstrap_base.home / "host-plan.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(bootstrap_launcher, "bootstrap_descriptor_capable", lambda: False)
    def forbidden(*args, **kwargs):
        pytest.fail("unsupported bootstrap opened a descriptor")
    monkeypatch.setattr(bootstrap_launcher, "os", R2Facade(module.os, open=forbidden))
    with pytest.raises(ValueError) as refusal:
        module.bootstrap_runtime(bootstrap_words(bootstrap_base, "start"))
    assert str(refusal.value) == MR1D_CHECK_ERROR


@pytest.mark.parametrize("case", ["leaf-symlink", "parent-symlink", "fifo"])
def test_mr1d_bootstrap_does_not_follow_untrusted_paths(bootstrap_base, case):
    built = bootstrap_base
    (built.home / "host-plan.json").write_text("{}", encoding="utf-8")
    if case == "leaf-symlink":
        target = built.home / "retained.json"
        (built.home / "provision.json").rename(target)
        symlink_or_skip(target, built.home / "provision.json")
    elif case == "parent-symlink":
        target = built.home.with_name("retained-home")
        built.home.rename(target)
        symlink_or_skip(target, built.home, target_is_directory=True)
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO requires POSIX")
        (built.home / "provision.json").unlink()
        os.mkfifo(built.home / "provision.json")
    assert bootstrap_call(built, "resume", 2) == {"error": MR1D_CHECK_ERROR}


@pytest.mark.parametrize("case", ["parent-rename", "leaf-rename", "leaf-overwrite", "read-error", "oversize"])
def test_mr1d_bootstrap_races_and_read_failures_close_every_descriptor(bootstrap_base, monkeypatch, case):
    built, module = bootstrap_base, bootstrap_launcher
    if not module.bootstrap_descriptor_capable():
        pytest.skip("bootstrap requires directory descriptors")
    (built.home / "host-plan.json").write_text("{}", encoding="utf-8")
    if case == "oversize":
        (built.home / "provision.json").write_bytes(b"!" * 262145)
    real_os = module.os
    home_info = real_os.stat(built.home)
    home_identity = home_info.st_dev, home_info.st_ino
    opened, closed, governing, triggered = [], [], set(), []

    def opening(name, flags, *args, **kwargs):
        fd = real_os.open(name, flags, *args, **kwargs)
        opened.append(fd)
        parent = kwargs.get("dir_fd")
        if name == "provision.json" and parent is not None:
            info = real_os.fstat(parent)
            if (info.st_dev, info.st_ino) == home_identity:
                governing.add(fd)
        return fd

    def reading(fd, count):
        if fd in governing and not triggered:
            triggered.append(True)
            if case == "oversize":
                pytest.fail("oversize record reached read before refusal")
            if case == "read-error":
                raise OSError("secret\ninput")
            if case == "parent-rename":
                built.home.rename(built.home.with_name("moved-home"))
                built.home.mkdir()
            elif case == "leaf-rename":
                (built.home / "provision.json").rename(built.home / "moved.json")
            (built.home / "provision.json").write_text(
                json.dumps({**built.record, "source_commit": "a" * 40}), encoding="utf-8")
        return real_os.read(fd, count)

    def closing(fd):
        governing.discard(fd)
        closed.append(fd)
        return real_os.close(fd)

    monkeypatch.setattr(bootstrap_launcher, "os", R2Facade(real_os, open=opening, read=reading, close=closing))
    with pytest.raises(ValueError) as refusal:
        module.bootstrap_runtime(bootstrap_words(built, "resume"))
    assert str(refusal.value) == MR1D_CHECK_ERROR
    assert sorted(opened) == sorted(closed)
    assert bool(triggered) == (case != "oversize")
    # Restore the owned namespace, then retry through the actual CLI rather than retaining a stale decision.
    if case == "parent-rename":
        (built.home / "provision.json").unlink()
        built.home.rmdir()
        built.home.with_name("moved-home").rename(built.home)
    (built.home / "provision.json").write_text(
        json.dumps({**built.record, "source_commit": "a" * 40}), encoding="utf-8")
    assert bootstrap_call(built, "resume", 2) == {"error": MR1D_PIN_ERROR}


class Launch(Setup):
    def __init__(self, tmp_path, *, source_seed=None):
        super().__init__(tmp_path, source_seed=source_seed)
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        codex = self.bin / "codex"
        codex.write_text('#!/bin/sh\n%s "$@"\n' % shell_exec("codex", FAKE_CODEX, self.tmp), encoding="utf-8")
        codex.chmod(codex.stat().st_mode | stat.S_IXUSR)
        self.codex_log = tmp_path / "fake-codex.log"
        self.host_log = tmp_path / "fake-host.log"
        self.plan = tmp_path / "fake-host-plan.json"
        self.plan.write_text("{}", encoding="utf-8")

    def env(self, **extra):
        return {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1",
                "CODEX_HOME": str(self.tmp / "codex-home"), "FAKE_CODEX_LOG": str(self.codex_log),
                "FAKE_HOST_LOG": str(self.host_log), "FAKE_HOST_PLAN": str(self.plan), **extra}

    def argv(self, *words):
        projection = getattr(self, "stop_projection", None)
        if words and words[0] == "stop" and projection is not None:
            raise RuntimeError("R2 fixture: stop runners require physical custody; use the managed runner")
        return [sys.executable, "-I", str(LAUNCHER), "--base", str(self.base), *words]

    def run(self, *words, expect=0, timeout=R2_STOP_TIMEOUT_SECONDS, **extra):
        context = getattr(self, "stop_case", None)
        if words and words[0] == "stop" and context is not None:
            process, _ = context.runner(stop_words=words, timeout=timeout)
            out, err = process.communicate(timeout=timeout)
            result = subprocess.CompletedProcess(words, process.returncode, out, err)
        else:
            result = subprocess.run(self.argv(*words), capture_output=True, text=True, timeout=timeout, env=self.env(**extra))
        if words and words[0] == "resume" and result.returncode != expect:
            self.report_resume_child_errors()
        assert not result.stderr, result.stderr
        assert result.returncode == expect, result.stdout
        return json.loads(result.stdout)

    def report_resume_child_errors(self):
        # Keep the original assertions/outcome. A disposable container must not discard the real child's
        # import error when pytest prints only the launcher's summary. Read only this fixture's own logs.
        folder = self.base / "delivery" / "wake-logs"
        if self.tmp not in folder.parents:
            raise RuntimeError("test wake log folder escapes its owned fixture")
        current = folder
        while current != self.tmp:
            if current.is_symlink():
                raise RuntimeError("test wake log folder contains a symlink")
            current = current.parent
        for path in sorted(folder.rglob("*.stderr"))[:8]:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise RuntimeError("test wake log is not an owned regular file")
            with path.open("rb") as stream:
                size = stream.seek(0, os.SEEK_END)
                stream.seek(max(0, size - 8192))
                tail = stream.read(8192).decode("utf-8", "replace")
            print("owned wake child stderr (%s):\n%s" % (path.relative_to(self.tmp), tail), file=sys.stderr)

    def start_request(self, **request):
        path = self.tmp / ("start-%s.json" % uuid.uuid4().hex)
        path.write_text(json.dumps({"endpoint": REVIEW, **request}), encoding="utf-8")
        return path

    def start(self, expect=0, mode="", thread=None, environment=None, **request):
        return self.run("start", "--request", str(self.start_request(**request)), expect=expect, FAKE_CODEX_MODE=mode,
                        FAKE_CODEX_THREAD=thread or "019a" + uuid.uuid4().hex[:28], **(environment or {}))

    def started(self, mode="", thread=None, environment=None, **request):
        """A start left running, for tests that act on the launcher while it waits."""
        env = self.env(FAKE_CODEX_MODE=mode, FAKE_CODEX_THREAD=thread or "019a" + uuid.uuid4().hex[:28], **(environment or {}))
        return subprocess.Popen(self.argv("start", "--request", str(self.start_request(**request))), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)

    def records(self, endpoint=REVIEW):
        folder = self.base / "launches" / endpoint.replace("/", "%2F")
        return [json.loads(path.read_text()) for path in sorted(folder.glob("*.json"))] if folder.exists() else []

    def binding(self, endpoint=REVIEW):
        return invoke(self.root, "status")["bindings"].get(endpoint)

    def publish_to(self, endpoint, identifier):
        sender = self.add_role("pilot/orchestrator", cwd=str(self.tmp))
        return invoke(self.root, "publish", {"message_id": identifier, "from": "pilot/orchestrator", "to": endpoint,
                                             "host": sender["host"], "session": sender["session"],
                                             "binding_generation": sender["generation"], "type": "info", "body": "UNTRUSTED-BODY"})


@pytest.fixture
def launch(tmp_path, tmp_path_factory, request):
    built = Launch(tmp_path, source_seed=worker_source_seed(tmp_path_factory, request))
    built.init()
    return built


@pytest.fixture
def team(tmp_path, tmp_path_factory, request):
    """Every endpoint role the launcher starts, Router and Decider included."""
    built = Launch(tmp_path, source_seed=worker_source_seed(tmp_path_factory, request))
    provision("init", built.init_request(roles=["router", "decider"]))
    return built


def contract_path(launch, name):
    return launch.source / "tools" / "hierarchy_templates" / "roles" / name


def for_codex(text):
    """A contract as a Codex role reads it: every block marked for another host and every marker line left out."""
    kept, skipping = [], False
    for line in text.splitlines():
        if line.strip().startswith("<!-- host:"):
            skipping = line.strip() != "<!-- host:codex -->"
        elif line.strip() == "<!-- /host -->":
            skipping = False
        elif not skipping:
            kept.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()


def lane_rules(text, role):
    """lane.md without its Assignments and Protocol checklist, which each lane kind's own file restates."""
    kept, skipping = [], False
    for line in text.splitlines():
        if line.startswith(("# ", "## ")):
            skipping = line in (("## Assignments", "## Protocol checklist") +
                                (("## Writing rules",) if role == "reviewer" else ()))
        if not skipping:
            kept.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip()


# The files each started role's contract is made of, in order; the last is the role's own.
CONTRACT_FILES = {"orchestrator": ["orchestrator.md"], "router": ["router.md"], "decider": ["decider.md"],
                  "front-door": ["front-door.md"], "implementer": ["lane.md"], "reviewer": ["lane.md", "reviewer.md"],
                  "integrator": ["lane.md", "integrator.md"]}


def start_prompt(launch, endpoint, role):
    """The exact start turn: the header, the role's contract from the pinned source as a Codex role reads it (lane.md's
    shared rules first for a reviewer or an integrator), then the instruction to wait."""
    names = CONTRACT_FILES[role]
    parts = [for_codex(contract_path(launch, name).read_text(encoding="utf-8")) for name in names]
    if len(names) > 1:
        parts[0] = lane_rules(parts[0], role)
    return "\n\n".join([START_HEADER % (endpoint, role), *parts, START_FOOTER])


def references(launch, role):
    return [{"path": str(contract_path(launch, name)),
             "sha256": hashlib.sha256(contract_path(launch, name).read_bytes()).hexdigest()}
            for name in CONTRACT_FILES[role]]


def census(session, projection=None):
    if projection is not None:
        module = launcher_module(projection)
        return [row.pid for row in module.process_census(session)
                if not row.state.startswith("Z") and module.names_session(row, session)]
    rows = subprocess.run(["ps", "-ax", "-ww", "-o", "pid=,stat=,args="], capture_output=True, text=True, timeout=R2_STOP_TIMEOUT_SECONDS).stdout
    return [int(line.split()[0]) for line in rows.splitlines()
            if session in line.split()[2:] and not line.split()[1].startswith("Z")]


def alive(pid):
    shown = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=R2_STOP_TIMEOUT_SECONDS).stdout.strip()
    return bool(shown) and not shown.startswith("Z")


def _r2_wait_descriptors(seconds, descriptors=()):
    """Notifications are hints only; callers re-check their own readiness/exit proof."""
    watched = [fd for fd in descriptors if isinstance(fd, int) and fd >= 0]
    if hasattr(select, "poll"):
        poller = select.poll()
        for fd in watched:
            poller.register(fd, select.POLLIN)
        return bool(poller.poll(max(0, int(seconds * 1000))))
    return bool(select.select(watched, [], [], seconds)[0])


def _r2_child_events_capable():
    return sys.platform.startswith("linux") and callable(getattr(os, "pidfd_open", None))


def _r2_wait_child_event(seconds):
    """Wake on a current child's exit; sample non-pollable predicates on a short slice.

    These ephemeral pidfds are notification sources, never custody or exit proof.
    Other POSIX hosts and kernels without pidfds retain bounded predicate sampling.
    """
    handles, source = [], None
    try:
        if _r2_child_events_capable():
            source = os.open("/proc/thread-self/children", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            raw = os.read(source, 4097)
            if len(raw) > 4096:
                raise RuntimeError("R2 fixture: child notification list exceeds bound")
            for word in raw.split():
                if len(handles) >= 128:
                    raise RuntimeError("R2 fixture: too many child notification handles")
                try:
                    fd = os.pidfd_open(int(word), 0)
                except OSError:
                    continue  # Exiting children need no notification handle.
                handles.append(fd)
            # Already-signalled zombies must not turn an unrelated predicate into a busy loop.
            live = [fd for fd in handles if not _r2_wait_descriptors(0, [fd])]
        else:
            live = []
        _r2_wait_descriptors(max(0, min(seconds, .05)), live)
    except OSError:
        # Proc/pidfd access is an optional notification capability, never exit authority.
        _r2_wait_descriptors(max(0, min(seconds, .05)))
    finally:
        _close_fds(source, *handles)


def _r2_check_ceiling(seconds):
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 < seconds <= 600:
        raise RuntimeError("R2 fixture: invalid handshake ceiling")


def wait_until(condition, seconds=R2_HANDSHAKE_CEILING_SECONDS, *, clock=None, block=None):
    """The ceiling detects a hung fixture; scheduling delays are not failures."""
    _r2_check_ceiling(seconds)
    clock = time.monotonic if clock is None else clock
    block = _r2_wait_child_event if block is None else block
    deadline = clock() + seconds
    while True:
        if condition():
            return
        remaining = deadline - clock()
        if remaining <= 0:
            if not condition():
                raise AssertionError("condition not met within %.1f s" % seconds)
            return
        block(remaining)


def test_start_runs_the_start_argv_once_binds_the_session_and_records_it(launch):
    thread = "019a6c3e-1111-7222-8333-444455556666"
    answer = launch.start(thread=thread, cwd=str(launch.source))
    assert answer["schema"] == "aegis.hierarchy-launch/v1" and answer["action"] == "start"
    assert answer["state"] == "bound" and answer["host"] == "codex-cli"
    assert answer["session"] == thread and answer["generation"] == 1
    assert answer["exit_code"] == 0 and answer["timed_out"] is False
    assert launch.binding()["session"] == thread and launch.binding()["host"] == "codex-cli"
    profile = json.loads(Path(answer["wake_profile"]).read_text())
    assert profile["session"] == thread and profile["argv"][-2:] == ["resume", thread]
    assert Path(answer["connection"]).is_file()
    started = [json.loads(line) for line in launch.codex_log.read_text().splitlines()]
    assert len(started) == 1 and started[0]["argv"][-1] == start_prompt(launch, REVIEW, "reviewer")
    assert "resume" not in started[0]["argv"]
    assert started[0]["cwd"] == str(launch.source)
    assert '"thread.started"' in Path(answer["log"]["stdout"]).read_text()
    [record] = launch.records()
    assert record == {key: value for key, value in answer.items() if key != "log"}
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    [path] = folder.glob("*.json")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(folder.stat().st_mode) == 0o700
    # No temporary record name and no start lock outlive the start.
    assert sorted(entry.name for entry in folder.iterdir()) == sorted([path.name, "logs"])
    assert stat.S_IMODE((launch.base / "launches").stat().st_mode) == 0o700


@pytest.mark.parametrize("endpoint,role,name", [
    ("pilot/orchestrator", "orchestrator", "orchestrator.md"),
    ("pilot/router", "router", "router.md"),
    ("pilot/decider", "decider", "decider.md"),
    ("pilot/front-door", "front-door", "front-door.md"),
    ("pilot/lane/f2", "implementer", "lane.md"),
    ("pilot/lane/review", "reviewer", "reviewer.md"),
    ("pilot/lane/integration", "integrator", "integrator.md"),
])
def test_each_launched_role_starts_with_its_contract_inline(team, endpoint, role, name):
    answer = team.start(endpoint=endpoint)
    assert answer["state"] == "bound", answer
    [started] = [json.loads(line) for line in team.codex_log.read_text().splitlines()]
    prompt = started["argv"][-1]
    assert prompt == start_prompt(team, endpoint, role)
    assert prompt.startswith(START_HEADER % (endpoint, role) + "\n\n") and prompt.endswith("\n\n" + START_FOOTER)
    assert "take no other action" not in prompt
    raw = contract_path(team, name).read_bytes()
    assert answer["contract"] == {"path": str(contract_path(team, name)), "sha256": hashlib.sha256(raw).hexdigest()}
    assert answer["contracts"] == references(team, role) and answer["contracts"][-1] == answer["contract"]
    assert team.records(endpoint)[-1]["argv"][-1] == prompt


# Instructions only a Claude host can follow: its self-stop, its messaging tool and its environment variables.
CLAUDE_ONLY = ("claude stop", "SendMessage", "CLAUDE_")


@pytest.mark.parametrize("endpoint", ["pilot/orchestrator", "pilot/router", "pilot/decider", "pilot/front-door",
                                      "pilot/lane/f2", "pilot/lane/review", "pilot/lane/integration"])
def test_a_codex_role_is_sent_no_claude_only_instruction_and_no_host_marker(team, endpoint):
    assert team.start(endpoint=endpoint)["state"] == "bound"
    [started] = [json.loads(line) for line in team.codex_log.read_text().splitlines()]
    argv = "\n".join(started["argv"])
    assert [phrase for phrase in CLAUDE_ONLY if phrase in argv] == []
    assert "<!-- host:" not in argv and "<!-- /host -->" not in argv
    if endpoint.startswith("pilot/lane/") or endpoint == "pilot/orchestrator":
        # In their place a Codex lane or orchestrator is told how its turn ends.
        assert "Never run a command to stop a session" in started["argv"][-1]


@pytest.mark.parametrize("endpoint,own,checklist", [
    ("pilot/lane/review", "# Reviewer role", "A bare `ack`"),
    ("pilot/lane/integration", "# Integrator role", "An Integrator writes, so add `readiness`"),
])
def test_a_reviewer_or_integrator_gets_the_shared_lane_rules_but_only_its_own_checklist(team, endpoint, own, checklist):
    answer = team.start(endpoint=endpoint)
    prompt = answer["argv"][-1]
    for shared in ("# Shared lane rules", "Execute exactly one hash-bound assignment", "**Hashes and times, T92.**",
                   "**Deadline, T111 (3), T117 and T126 (1).**"):
        assert prompt.index(shared) < prompt.index(own), shared
    assert checklist in prompt
    assert "A writing lane adds `readiness` with exactly these 11 fields" not in prompt
    assert prompt.count("## Assignments") == 1 and prompt.count("## Protocol checklist") == 1
    assert prompt.index("## Protocol checklist") > prompt.index(own)
    lane, kind = answer["contracts"]
    assert lane["path"].endswith("/roles/lane.md") and kind == answer["contract"]


def commit_contract(built, name, text):
    """A pinned source whose role contract reads `text`."""
    contract_path(built, name).write_text(text, encoding="utf-8")
    git(built.source, "add", str(contract_path(built, name)))
    git(built.source, "commit", "-qm", "a pinned source with an edited %s" % name)


@pytest.mark.parametrize("change,error", [
    (lambda text, lines: text + "\n<!-- host:claude -->\nClaude only.\n",
     lambda path, lines: "unbalanced host markers in %s: the block opened at line %d is not closed" % (path, lines + 2)),
    (lambda text, lines: "<!-- /host -->\n" + text,
     lambda path, lines: "unbalanced host markers in %s: line 1 closes a block that is not open" % path),
    (lambda text, lines: "<!-- host:claude -->\n<!-- host:codex -->\nx\n<!-- /host -->\n<!-- /host -->\n" + text,
     lambda path, lines: "unbalanced host markers in %s: line 2 opens a block inside the one opened at line 1" % path),
    (lambda text, lines: "<!-- host:gemini -->\nx\n<!-- /host -->\n" + text,
     lambda path, lines: "invalid host marker in %s: line 1 names an unknown host: gemini" % path),
    (lambda text, lines: "Read this <!-- host:claude --> inline.\n" + text,
     lambda path, lines: "invalid host marker in %s: line 1: a host marker must stand alone on its line" % path),
])
def test_a_contract_with_unbalanced_or_invalid_host_markers_refuses_the_start(tmp_path, change, error):
    built = Launch(tmp_path)
    original = contract_path(built, "decider.md").read_text(encoding="utf-8")
    commit_contract(built, "decider.md", change(original, len(original.splitlines())))
    provision("init", built.init_request(roles=["decider"]))
    refused = built.start(expect=2, endpoint="pilot/decider")
    assert refused["error"] == error(contract_path(built, "decider.md"), len(original.splitlines()))
    assert refused["state"] == "refused" and refused["session"] is None
    assert not built.codex_log.exists() and built.binding("pilot/decider") is None


def test_a_reviewer_is_refused_when_the_shared_lane_rules_are_unbalanced(tmp_path):
    built = Launch(tmp_path)
    commit_contract(built, "lane.md", "<!-- host:codex -->\n" + contract_path(built, "lane.md").read_text(encoding="utf-8"))
    built.init()
    refused = built.start(expect=2)
    assert refused["error"].startswith("unbalanced host markers in %s: " % contract_path(built, "lane.md"))
    assert not built.codex_log.exists() and built.binding() is None


@pytest.mark.parametrize("marker", ["<!--host:claude-->", "<!-- HOST:claude -->", "<!-- / host -->"])
def test_misspelled_host_markers_refuse_before_start(tmp_path, marker):
    built = Launch(tmp_path)
    commit_contract(built, "decider.md", marker + "\nClaude-only instructions.\n")
    provision("init", built.init_request(roles=["decider"]))
    refused = built.start(expect=2, endpoint="pilot/decider")
    assert refused["error"] == ("invalid host marker in %s: line 1: a host marker must stand alone on its line"
                                 % contract_path(built, "decider.md"))
    assert not built.codex_log.exists() and built.binding("pilot/decider") is None


@pytest.mark.parametrize("fence", ["```markdown", "~~~~markdown"])
def test_fenced_marker_examples_are_literal_contract_text(tmp_path, fence):
    built = Launch(tmp_path)
    example = fence + "\n<!-- host:claude -->\nexample\n<!-- /host -->\n" + fence[:4 if fence[0] == "~" else 3]
    commit_contract(built, "decider.md", example + "\n<!-- host:claude -->\nprivate instructions\n<!-- /host -->\n")
    provision("init", built.init_request(roles=["decider"]))
    prompt = built.start(endpoint="pilot/decider")["argv"][-1]
    assert example in prompt
    assert "private instructions" not in prompt


def test_reviewer_start_omits_writer_operations_but_preserves_shared_evidence_rules(team):
    prompt = team.start(endpoint=REVIEW)["argv"][-1]
    for instruction in ("Before each commit", "Scan each path you will edit", "Remove build caches",
                        "run `pwd` before your first Write", "Run `pwd` before the first Write", "**Lint and size"):
        assert instruction not in prompt
    assert "**Hashes and times, T92.**" in prompt
    assert "**Deadline, T111 (3), T117 and T126 (1).**" in prompt


def test_orchestrator_start_routes_physical_work_to_the_operator(team):
    prompt = team.start(endpoint="pilot/orchestrator")["argv"][-1]
    assert "Create writing worktrees manually" not in prompt
    assert "Claim leases serially" not in prompt
    assert "Only this role reads and updates GitHub" not in prompt
    assert "`after_message_id`" in prompt


@pytest.mark.parametrize("endpoint,role,name", [
    ("pilot/decider", "decider", "decider.md"),
    ("pilot/lane/f2", "implementer", "lane.md"),
])
def test_a_role_whose_contract_file_is_missing_is_refused_before_anything_runs(tmp_path, endpoint, role, name):
    built = Launch(tmp_path)
    missing = contract_path(built, name)
    if missing.exists():
        git(built.source, "rm", "-q", str(missing))
        git(built.source, "commit", "-qm", "a pinned source without the %s contract" % role)
    provision("init", built.init_request(roles=["decider"]))
    refused = built.start(expect=2, endpoint=endpoint)
    assert refused["error"] == "no role contract for %s: %s" % (role, missing)
    assert refused["state"] == "refused" and refused["session"] is None
    assert [row["state"] for row in built.records(endpoint)] == ["refused"]
    assert not built.codex_log.exists() and built.binding(endpoint) is None


def test_a_bound_endpoint_is_refused_and_the_refusal_is_recorded(launch):
    launch.start()
    refused = launch.start(expect=2)
    assert refused["error"] == "endpoint is already bound; resume it or hand it off"
    assert refused["state"] == "refused" and refused["session"] is None
    assert [row["state"] for row in launch.records()] == ["bound", "refused"]
    assert len(launch.codex_log.read_text().splitlines()) == 1


@pytest.mark.parametrize("request_change,error", [
    ({"base": "/elsewhere"}, "unexpected fields: base"),
    ({"session": "chosen"}, "unexpected fields: session"),
    ({"start_timeout_seconds": 0}, "invalid start_timeout_seconds"),
    ({"start_timeout_seconds": 3601}, "invalid start_timeout_seconds"),
    ({"start_timeout_seconds": "5"}, "invalid start_timeout_seconds"),
])
def test_malformed_start_requests_are_refused_before_anything_runs(launch, request_change, error):
    refused = launch.start(expect=2, **request_change)
    assert refused["error"] == error and refused["state"] == "refused"
    assert [row["error"] for row in launch.records()] == [error]
    assert not launch.codex_log.exists() and launch.binding() is None


def test_an_unknown_endpoint_is_refused_without_a_record(launch):
    refused = launch.start(expect=2, endpoint="pilot/lane/absent")
    assert refused == {"error": "unknown endpoint: pilot/lane/absent"}
    assert not (launch.base / "launches").exists()


def test_a_start_without_a_thread_is_recorded_as_failed_to_start(launch):
    answer = launch.start(expect=3, mode="no-thread")
    assert answer["state"] == "failed_to_start" and answer["session"] is None
    assert answer["exit_code"] == 1 and answer["timed_out"] is False
    assert launch.binding() is None and [row["state"] for row in launch.records()] == ["failed_to_start"]


@pytest.mark.parametrize("reported,exit_code,reason", [
    (None, 0, "the start exited without reporting a session"),
    (None, 1, "the start process exited unsuccessfully"),
    ("fixture-session", 1, "the start process exited unsuccessfully"),
    ("invalid session\nprivate-input", 0, "the start reported an invalid session"),
])
def test_snapshot4e_launcher_failure_always_records_a_fixed_reason(launch, reported, exit_code, reason):
    # Port the transferred cases to this checkout's public launcher harness, without Git history.
    assert not (launch.base / "host-plan.json").exists()
    script = launch.tmp / "start-failure.py"
    script.write_text("import json\n"
                      "def main():\n"
                      "    reported = %r\n"
                      "    if reported is not None:\n"
                      "        print(json.dumps({'type': 'thread.started', 'thread_id': reported}), flush=True)\n"
                      "    raise SystemExit(%d)\n"
                      "main()\n" % (reported, exit_code), encoding="utf-8")
    codex = launch.bin / "codex"
    original = codex.read_text(encoding="utf-8")
    codex.write_text('#!/bin/sh\n%s "$@"\n' % shell_exec("codex", script, launch.tmp), encoding="utf-8")
    answer = launch.start(expect=3)
    assert answer["exit_code"] == exit_code and answer["timed_out"] is False
    assert answer["state"] == ("start_incomplete" if reported == "fixture-session" else "failed_to_start")
    assert answer.get("error") == reason
    [saved] = launch.records()
    assert saved["error"] == reason and launch.binding() is None
    # A refusal releases the start lock, and a later successful start keeps the failure evidence.
    codex.write_text(original, encoding="utf-8")
    assert launch.start()["state"] == "bound"
    assert launch.records()[0] == saved


@pytest.mark.parametrize("reported", [None, "fixture-session"])
def test_snapshot4e_launcher_timeout_records_a_fixed_reason(launch, reported):
    assert not (launch.base / "host-plan.json").exists()
    mode = "silent-hang" if reported is None else "hang"
    answer = launch.start(expect=3, mode=mode, thread=reported, start_timeout_seconds=3)
    assert answer["timed_out"] is True
    assert answer["state"] == ("failed_to_start" if reported is None else "start_incomplete")
    assert answer.get("error") == "the start timed out"
    [saved] = launch.records()
    assert saved["error"] == "the start timed out" and launch.binding() is None
    assert launch.start()["state"] == "bound"
    assert saved in launch.records()


@pytest.mark.parametrize("reported", [None, "fixture-session"])
def test_a_concurrent_start_preserves_the_running_starts_lock_and_reason(launch, reported):
    mode = "silent-hang" if reported is None else "hang"
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    lock = folder / ".start.lock"
    # The normal timeout is a hung-fixture ceiling, not a window for the second start.
    with launch.started(mode=mode, thread=reported) as running:
        assert_concurrent_start_preserves_lock_and_reason(launch, reported, folder, lock, running)


def wait_for_start_record(path, *, pending=None, accepts=lambda record: True):
    ready = []

    def complete():
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        for line in raw.splitlines(keepends=True):
            if line.endswith("\n"):
                record = json.loads(line)
                if accepts(record):
                    ready.append(record)
                    return True
        if pending is not None:
            pending()
        return False

    wait_until(complete)
    return ready[0]


@pytest.mark.parametrize("initial", ["", '{"pid":', '{"pid": 7}'])
def test_start_record_readiness_returns_the_record_it_observed(tmp_path, initial):
    path = tmp_path / "start.log"
    path.write_text(initial, encoding="utf-8")

    def finish():
        path.write_text('{"pid": 7}\n', encoding="utf-8")

    def accept(record):
        # Change the file after parsing: callers must receive the observed unit, not re-read it.
        path.write_text('{"pid": 8}\n', encoding="utf-8")
        return True

    assert wait_for_start_record(path, pending=finish, accepts=accept) == {"pid": 7}
    assert json.loads(path.read_text(encoding="utf-8")) == {"pid": 8}


def test_start_record_readiness_rejects_a_malformed_complete_line(tmp_path):
    path = tmp_path / "start.log"
    path.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError, match=r"^Expecting value: line 1 column 1 \(char 0\)$"):
        wait_for_start_record(path)


def test_start_record_readiness_waits_for_a_complete_json_line(launch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    release = launch.tmp / "release-log"
    script = launch.tmp / "paused-log.py"
    script.write_text("import os, select, sys, time\n"
                      "from pathlib import Path\n"
                      "sys.path.insert(0, %r)\n"
                      "import hierarchy_fake_codex as fake\n"
                      "original = fake.log_call\n"
                      "def paused_log_call(argv, **extra):\n"
                      "    Path(os.environ['FAKE_CODEX_LOG']).touch()\n"
                      "    deadline = time.monotonic() + 60\n"
                      "    while not Path(os.environ['RELEASE_LOG']).exists():\n"
                      "        if time.monotonic() >= deadline:\n"
                      "            raise RuntimeError('paused log fixture was not released')\n"
                      "        select.select([], [], [], 0.05)\n"
                      "    original(argv, **extra)\n"
                      "fake.log_call = paused_log_call\n"
                      "fake.main()\n" % str(FAKE_CODEX.parent), encoding="utf-8")
    (launch.bin / "codex").write_text('#!/bin/sh\n%s "$@"\n' % shell_exec("codex", script, launch.tmp),
                                    encoding="utf-8")
    pending = Event()
    with launch.started(mode="silent-hang", environment={"RELEASE_LOG": str(release)}) as running:
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(wait_for_start_record, launch.codex_log, pending=pending.set)
                try:
                    assert pending.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
                    assert not future.done()
                finally:
                    # An empty marker is solely a release signal; no content is read from it.
                    release.touch()
                started = future.result(timeout=R2_HANDSHAKE_CEILING_SECONDS)
                assert isinstance(started["pid"], int) and started["pid"] > 0
                assert started["argv"] and started["cwd"] == str(launch.source)
            running.send_signal(signal.SIGTERM)
            out, err = running.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
            assert running.returncode == 3 and err == "", out + err
            assert json.loads(out)["state"] == "failed_to_start"
            assert not alive(started["pid"])
        finally:
            release.touch()
            if running.poll() is None:
                running.send_signal(signal.SIGTERM)
                running.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)


def assert_concurrent_start_preserves_lock_and_reason(launch, reported, folder, lock, running):
    try:
        started = wait_for_start_record(launch.codex_log)
        if reported is not None:
            [stdout] = (folder / "logs").glob("*.stdout")
            event = wait_for_start_record(stdout, accepts=lambda record: record.get("type") == "thread.started")
            assert event["thread_id"] == reported
        held = lock.read_bytes()
        refused = launch.start(expect=2)
        assert refused["state"] == "refused"
        assert refused["error"] == "stop custody endpoint is busy: " + REVIEW
        assert lock.read_bytes() == held and running.poll() is None
        assert launch.records() == [refused] and launch.binding() is None
        # Stop the launcher only after the competing start has finished its refusal.
        running.send_signal(signal.SIGTERM)
        out, err = running.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == ("failed_to_start" if reported is None else "start_incomplete")
        assert answer["error"] == "the launcher was interrupted" and answer["timed_out"] is False
        assert answer["session"] == reported
        assert not alive(started["pid"]) and not lock.exists() and launch.binding() is None
        saved = launch.records()
        # Records sort by start identifier, not by completion order.
        assert saved == [{key: value for key, value in answer.items() if key != "log"}, refused]
        assert launch.start()["state"] == "bound"
        assert launch.records()[:2] == saved
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=R2_STOP_TIMEOUT_SECONDS)


def test_a_hung_start_is_stopped_at_its_timeout_and_left_unbound(launch):
    thread = "hung-" + uuid.uuid4().hex
    began = time.monotonic()
    answer = launch.start(expect=3, mode="hang", thread=thread, start_timeout_seconds=1)
    assert time.monotonic() - began < 5
    assert answer["state"] == "start_incomplete" and answer["session"] == thread and answer["timed_out"] is True
    assert launch.binding() is None and census(thread) == []


def test_a_start_that_fails_after_its_thread_is_not_bound(launch):
    thread = "failed-" + uuid.uuid4().hex
    answer = launch.start(expect=3, mode="fail-after-thread", thread=thread)
    assert answer["state"] == "start_incomplete" and answer["session"] == thread
    assert answer["exit_code"] == 4 and answer["timed_out"] is False
    assert launch.binding() is None


@pytest.mark.parametrize("endpoint,change,error", [
    ("pilot/lane/f2", {"source_repo": "SOURCE"},
     "the implementer role has no source views: they are for roles that read source and write none"),
    (REVIEW, {"timeout_seconds": 0}, "invalid timeout_seconds"),
])
def test_a_refused_binding_is_recorded_with_the_session_that_started(launch, endpoint, change, error):
    change = {key: str(launch.source) if value == "SOURCE" else value for key, value in change.items()}
    thread = "unbound-" + uuid.uuid4().hex
    answer = launch.start(expect=3, thread=thread, endpoint=endpoint, **change)
    assert answer["state"] == "bind_refused" and answer["session"] == thread and answer["error"] == error
    assert launch.binding(endpoint) is None and launch.records(endpoint)[-1]["state"] == "bind_refused"


def test_the_record_limit_refuses_before_starting(launch):
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    folder.mkdir(parents=True)
    for number in range(10000):
        (folder / ("%05d.json" % number)).write_text("{}")
    refused = launch.start(expect=2)
    assert refused == {"error": "launch record limit reached for pilot/lane/review"}
    assert len(list(folder.glob("*.json"))) == 10000 and not launch.codex_log.exists()


def test_resume_runs_the_wake_with_the_bound_profile_and_records_it(launch):
    started = launch.start()
    launch.publish_to(REVIEW, "for-review")
    answer = launch.run("resume", "--endpoint", REVIEW)
    assert answer["action"] == "resume" and answer["state"] == "resumed"
    assert answer["session"] == started["session"] and answer["generation"] == 1
    assert answer["wake"]["state"] == "read" and answer["wake"]["exit_code"] == 0
    assert answer["wake"]["wake_id"].startswith("wake-") and answer["wake"]["timed_out"] is False
    assert answer["wake_exit_code"] == 0
    hosted = [json.loads(line) for line in launch.host_log.read_text().splitlines()]
    assert [row["endpoint"] for row in hosted] == [REVIEW] and hosted[0]["argv"][-2] == started["session"]
    assert [row["state"] for row in launch.records()] == ["bound", "resumed"]


def test_unexpected_resume_failure_reports_the_owned_wake_child_stderr(launch, capsys):
    launch.start()
    launch.publish_to(REVIEW, "for-review")
    # MODELLED failed launcher, not a running session host. Preserve the actual wake child's exit/stderr.
    (launch.bin / "codex").write_text("#!/bin/sh\nprintf 'modelled wake import error\\n' >&2\nexit 7\n")
    with pytest.raises(AssertionError, match="resumed_unread"):
        launch.run("resume", "--endpoint", REVIEW)
    captured = capsys.readouterr()
    assert "owned wake child stderr" in captured.err
    assert "modelled wake import error" in captured.err
    assert launch.records()[-1]["wake"]["exit_code"] == 7


def test_resume_dry_run_launches_nothing(launch):
    launch.start()
    launch.publish_to(REVIEW, "for-review")
    answer = launch.run("resume", "--endpoint", REVIEW, "--dry-run")
    assert answer["state"] == "resumed" and answer["dry_run"] is True
    assert answer["wake"] == {"exit_code": None, "state": "dry_run", "timed_out": None, "wake_id": None}
    assert answer["wake_exit_code"] == 0
    assert not launch.host_log.exists()


def test_resume_refuses_an_unbound_endpoint_and_records_it(launch):
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    assert refused["error"] == "endpoint has no binding" and refused["host"] is None
    assert [row["state"] for row in launch.records()] == ["refused"]


def test_resume_refuses_a_native_thread(launch):
    launch.add_role(REVIEW, "codex", session="native-review")
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    assert refused["error"] == "a native thread is resumed by its own app, not the launcher"
    assert refused["host"] == "codex" and refused["session"] == "native-review"


def test_resume_refuses_without_the_bindings_wake_profile(launch):
    Path(launch.start()["wake_profile"]).unlink()
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    path = launch.base / "profiles" / "pilot%2Flane%2Freview-g1.wake.json"
    assert refused["error"] == "no wake profile for the current binding: " + str(path)


def test_resume_mirrors_a_wake_refusal(launch):
    launch.start()
    (launch.root / ".wake-pilot%2Flane%2Freview.lock").write_text("{}")
    launch.publish_to(REVIEW, "for-review")
    refused = launch.run("resume", "--endpoint", REVIEW, expect=2)
    assert refused["state"] == "refused" and "a wake is already in progress" in refused["error"]
    assert refused["wake_exit_code"] == 2 and refused["wake"]["state"] is None


@LINUX_HOST_PROGRAMS
def test_stop_ends_the_process_group_of_a_hung_session(launch):
    session = launch.start()["session"]
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    context = R2Case(launch)
    family = context.spawn_group(["codex", "exec", "--json", "resume", session])
    hung = family["H"]
    try:
        wait_until(lambda: owned_pids(session, projection=context.projection) == [hung.pid])
        children = [int(pid) for pid in subprocess.run(["pgrep", "-g", str(hung.pid)], capture_output=True, text=True,
                                                       timeout=R2_STOP_TIMEOUT_SECONDS).stdout.split() if int(pid) != hung.pid]
        answer = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "2")
        assert answer["action"] == "stop" and answer["state"] == "stopped" and answer["pids"] == sorted([hung.pid, *children])
        assert answer["wake_marker_present"] is False
        assert hung.wait(timeout=R2_STOP_TIMEOUT_SECONDS) < 0
        wait_until(lambda: not any(alive(pid) for pid in children))
        assert [row["state"] for row in launch.records()] == ["bound", "stopped"]
    finally:
        context.close()


def test_stop_with_nothing_running_reports_not_running_and_keeps_the_wake_marker(launch):
    launch.start()
    marker = launch.root / ".wake-pilot%2Flane%2Freview.lock"
    marker.write_text("{}")
    answer = launch.run("stop", "--endpoint", REVIEW)
    assert answer["state"] == "not_running" and answer["wake_marker_present"] is True and marker.exists()


def test_stop_refuses_a_background_claude_session_and_bad_grace(launch):
    launch.add_role("pilot/orchestrator", cwd=str(launch.tmp), background=True)
    refused = launch.run("stop", "--endpoint", "pilot/orchestrator", expect=2)
    assert refused["error"] == "a background claude session stops through claude stop; use the wake tool's control"
    assert launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "61", expect=2)["error"] == "invalid grace_seconds"
    assert launch.run("stop", "--endpoint", REVIEW, expect=2)["error"] == "endpoint has no binding"


def test_status_reads_back_bindings_and_records(launch):
    session = launch.start()["session"]
    launch.start(expect=2)
    shown = launch.run("status", "--endpoint", REVIEW)
    assert shown["schema"] == "aegis.hierarchy-launch-status/v1"
    row = shown["endpoints"][REVIEW]
    assert row["binding"] == {"host": "codex-cli", "session": session, "generation": 1}
    assert row["records"] == 2 and row["last"]["state"] == "refused"
    assert list(launch.run("status")["endpoints"]) == [REVIEW]
    empty = launch.run("status", "--endpoint", "pilot/lane/f2")["endpoints"]["pilot/lane/f2"]
    assert empty == {"binding": None, "last": None, "records": 0}


def test_start_refuses_root_and_records_it(launch):
    refused = launch.start(expect=2, endpoint="pilot/root")
    assert refused["error"] == "ROOT is the owner's session; bind it with add-role" and refused["state"] == "refused"
    assert [row["state"] for row in launch.records("pilot/root")] == ["refused"]
    assert not launch.codex_log.exists() and launch.binding("pilot/root") is None


def test_a_held_start_lock_refuses_a_second_start_and_a_start_releases_its_lock(launch):
    lock = launch.base / "launches" / "pilot%2Flane%2Freview" / ".start.lock"
    lock.parent.mkdir(parents=True)
    lock.write_text('{"pid": 1}')
    refused = launch.start(expect=2)
    assert refused["error"] == "a start is already running for pilot/lane/review; inspect %s if none is" % lock
    assert refused["state"] == "refused" and refused["host"] == "codex-cli"
    assert lock.read_text() == '{"pid": 1}' and not launch.codex_log.exists()
    lock.unlink()
    assert launch.start()["state"] == "bound" and not lock.exists()
    assert [row["state"] for row in launch.records()] == ["refused", "bound"]


def test_a_start_that_cannot_spawn_is_recorded_as_failed_to_start(launch):
    (launch.bin / "codex").unlink()
    # Only git on PATH, so a real codex elsewhere on PATH is never reached.
    (launch.bin / "git").symlink_to(shutil.which("git"))
    answer = launch.start(expect=3, environment={"PATH": str(launch.bin)})
    assert answer["state"] == "failed_to_start" and answer["session"] is None
    assert answer["error"] == "[Errno 2] No such file or directory: 'codex'"
    assert answer["exit_code"] is None and answer["timed_out"] is False
    assert Path(answer["log"]["stderr"]).is_file()
    assert [row["state"] for row in launch.records()] == ["failed_to_start"] and launch.binding() is None


def test_a_descendant_that_leaves_the_group_cannot_hold_the_start(launch):
    child = launch.tmp / "escaped.pid"
    began = time.monotonic()
    try:
        answer = launch.start(mode="escape", environment={"FAKE_CODEX_CHILD": str(child)})
        assert time.monotonic() - began < 10
        assert answer["state"] == "bound" and alive(int(child.read_text()))
    finally:
        if child.exists():
            os.kill(int(child.read_text()), signal.SIGKILL)


def test_a_child_left_in_the_starts_group_is_stopped_after_a_clean_start(launch):
    child = launch.tmp / "left.pid"
    answer = launch.start(mode="leave-child", environment={"FAKE_CODEX_CHILD": str(child)})
    assert answer["state"] == "bound" and answer["exit_code"] == 0
    wait_until(lambda: not alive(int(child.read_text())))


@pytest.mark.parametrize("mode,timeout,timed_out", [("", 300, False), ("hang", 1, True)])
def test_an_invalid_reported_session_is_a_failed_start_without_a_session(launch, mode, timeout, timed_out):
    answer = launch.start(expect=3, mode=mode, thread="bad/../id", start_timeout_seconds=timeout)
    assert answer["state"] == "failed_to_start" and answer["error"] == "the start reported an invalid session"
    assert answer["session"] is None and answer["timed_out"] is timed_out
    assert launch.binding() is None


@pytest.mark.parametrize("mode,number,state", [("hang", "SIGTERM", "start_incomplete"),
                                               ("hang", "SIGHUP", "start_incomplete"),
                                               ("silent-hang", "SIGINT", "failed_to_start")])
def test_an_interrupted_launcher_stops_its_start_and_records_it(launch, mode, number, state):
    number = getattr(signal, number)
    thread = "interrupted-" + uuid.uuid4().hex
    logs = launch.base / "launches" / "pilot%2Flane%2Freview" / "logs"
    running = launch.started(mode=mode, thread=thread)
    try:
        if mode == "hang":
            wait_until(lambda: any('"thread.started"' in path.read_text() for path in logs.glob("*.stdout")))
        else:
            wait_until(launch.codex_log.exists)
        [started] = [json.loads(line) for line in launch.codex_log.read_text().splitlines()]
        running.send_signal(number)
        out, err = running.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == state and answer["error"] == "the launcher was interrupted"
        assert answer["session"] == (thread if state == "start_incomplete" else None)
        assert not alive(started["pid"]) and launch.binding() is None
        assert [row["state"] for row in launch.records()] == [state]
        assert not (logs.parent / ".start.lock").exists()
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=R2_STOP_TIMEOUT_SECONDS)


def test_a_busy_mailbox_writer_is_waited_for_before_binding(launch):
    lock = launch.root / ".write.lock"
    running = launch.started(environment={"FAKE_CODEX_TOUCH": str(lock)})
    try:
        wait_until(lock.exists)
        time.sleep(1)
        lock.unlink()
        out, err = running.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
        assert running.returncode == 0 and err == "", out + err
        assert json.loads(out)["state"] == "bound" and launch.binding() is not None
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=R2_STOP_TIMEOUT_SECONDS)


def test_a_writer_busy_past_the_wait_is_recorded_as_bind_busy_and_can_be_bound(launch):
    lock = launch.root / ".write.lock"
    thread = "019a6c3e-2222-7222-8333-444455556666"
    answer = launch.start(expect=3, thread=thread, environment={"FAKE_CODEX_TOUCH": str(lock)})
    assert answer["state"] == "bind_busy" and answer["session"] == thread
    assert answer["error"] == "mailbox writer is busy; inspect an abandoned lock before retrying"
    assert launch.binding() is None
    lock.unlink()
    launch.add_role(REVIEW, "codex-cli", session=thread)
    assert launch.binding()["session"] == thread


def test_status_reports_an_unreadable_newest_record_and_still_lists_every_endpoint(launch):
    launch.start()
    launch.run("stop", "--endpoint", "pilot/lane/f2", expect=2)
    torn = launch.base / "launches" / "pilot%2Flane%2Freview" / "99999999T000000000000Z-torn.json"
    torn.write_text("")
    row = launch.run("status", "--endpoint", REVIEW)["endpoints"][REVIEW]
    assert row["last"] is None and row["unreadable"] == str(torn) and row["records"] == 2
    listed = launch.run("status")["endpoints"]
    assert listed[REVIEW]["unreadable"] == str(torn) and listed["pilot/lane/f2"]["last"]["state"] == "refused"
    assert "unreadable" not in listed["pilot/lane/f2"]


def test_stop_refuses_root_and_a_native_thread_and_signals_nothing(launch):
    launch.add_role("pilot/root", "codex", session=ROOT_SESSION)
    launch.add_role(REVIEW, "codex", session="native-review")
    named = [subprocess.Popen(["sh", "-c", "sleep 30; :", session], start_new_session=True)
             for session in (ROOT_SESSION, "native-review")]
    try:
        wait_until(lambda: census(ROOT_SESSION) and census("native-review"))
        root = launch.run("stop", "--endpoint", "pilot/root", expect=2)
        assert root["error"] == "ROOT is the owner's session; the launcher does not stop it"
        assert root["state"] == "refused" and root["session"] == ROOT_SESSION
        native = launch.run("stop", "--endpoint", REVIEW, expect=2)
        assert native["error"] == "a native thread is stopped by its own app, not the launcher"
        assert native["state"] == "refused" and native["host"] == "codex"
        assert [row["state"] for row in launch.records("pilot/root") + launch.records()] == ["refused", "refused"]
        assert all(process.poll() is None for process in named)
    finally:
        for process in named:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=R2_STOP_TIMEOUT_SECONDS)


def hold(launch, session, script, *words, **popen):
    """A process naming the session, kept running the way a hung codex turn is."""
    return subprocess.Popen(["codex", "-c", script, *(["resume", *words] if words else [])], executable="sh",
                            env=launch.env(FAKE_CODEX_MODE="hang", FAKE_CODEX_THREAD=session,
                            HELD_SESSION=session), stdout=subprocess.DEVNULL, **popen)


def group(pid):
    return [int(member) for member in subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True,
                                                     timeout=R2_STOP_TIMEOUT_SECONDS).stdout.split()]


def owned_pids(session, host="codex-cli", projection=None):
    return sorted(pid for pid, _ in launcher_module(projection).session_processes(session, set(), host))


@LINUX_HOST_PROGRAMS
@pytest.mark.parametrize("observe_after_stop", [False, True], ids=["concurrent", "completed"])
def test_stop_spares_a_caller_that_names_the_session(launch, observe_after_stop):
    session = launch.start()["session"]
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    context = R2Case(launch)
    try:
        hung = context.spawn(["codex", "exec", "--json", "resume", session])
        wait_until(lambda: owned_pids(session, projection=context.projection) == [hung.pid])

        def before_stop(caller, runner):
            assert owned_pids(session, projection=context.projection) == sorted([hung.pid, caller.pid])

        caller, _ = context.runner(session=session, echo_exit=True, before_stop=before_stop,
                                   stop_words=("stop", "--endpoint", REVIEW, "--grace-seconds", "2"))
        if observe_after_stop:
            # Exercise a scheduler that completes stop before the test observes its result.
            # Reap our own child while the runner independently proves its physical exit.
            def completed():
                hung.poll()
                return caller.poll() is not None
            wait_until(completed, seconds=R2_STOP_TIMEOUT_SECONDS)
        out, err = caller.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
        assert caller.returncode == 0 and err == "", out + err
        answer, last = out.splitlines()
        assert last == "exit=0"
        answer = json.loads(answer)
        assert answer["state"] == "stopped" and answer["pids"] == [hung.pid] and caller.pid not in answer["pids"]
        assert hung.wait(timeout=R2_STOP_TIMEOUT_SECONDS) < 0
    finally:
        context.close()


@LINUX_HOST_PROGRAMS
def test_stop_spares_a_group_whose_leader_does_not_name_the_session(launch, capsys):
    session = launch.start()["session"]
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    context = R2Case(launch)
    family = context.spawn_group(None, named_child=["codex", "exec", "--json", "resume", session], siblings=True)
    leader = family["H"]
    try:
        wait_until(lambda: len(owned_pids(session, projection=context.projection)) == 1 and len(group(leader.pid)) == 3)
        [named] = census(session, projection=context.projection)
        others = [pid for pid in group(leader.pid) if pid not in (leader.pid, named)]
        code, answer = context.stop(context.module(False), capsys, 0)
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [named]
        assert set(answer["unresolved_pids"]) == {leader.pid, *others}
        assert leader.poll() is None and all(alive(pid) for pid in others)
    finally:
        context.close()


@pytest.mark.parametrize("grace", ["0", "1"])
@LINUX_HOST_PROGRAMS
def test_stop_kills_a_session_that_ignores_sigterm_after_the_grace(launch, grace):
    session = launch.start()["session"]
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    context = R2Case(launch)
    family = context.spawn_group(["codex", "exec", "resume", session], stubborn=True)
    stubborn = family["H"]
    try:
        # The private RUNNING handshake follows both actors installing their actual SIGTERM dispositions.
        wait_until(lambda: stubborn.pid in owned_pids(session, projection=context.projection) and len(group(stubborn.pid)) == 2)
        members = sorted(group(stubborn.pid))
        answer = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", grace)
        assert answer["state"] == "stopped" and answer["pids"] == members and answer["grace_seconds"] == int(grace)
        assert stubborn.wait(timeout=R2_STOP_TIMEOUT_SECONDS) == -signal.SIGKILL
    finally:
        context.close()


@pytest.mark.parametrize("stage", ["census", "ancestors"])
def test_stop_records_a_failed_process_census(launch, monkeypatch, capsys, stage):
    launch.start()
    module, is_dir = launcher_module(), Path.is_dir
    if stage == "census":
        monkeypatch.setattr(module, "ancestors", lambda: set())
    monkeypatch.setattr(Path, "is_dir", lambda path: False if str(path) == "/proc" else is_dir(path))
    monkeypatch.setenv("PATH", str(launch.bin))
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 2
    refused = json.loads(capsys.readouterr().out)
    assert refused["error"] == "[Errno 2] No such file or directory: 'ps'" and refused["state"] == "refused"
    assert [row["state"] for row in launch.records()] == ["bound", "refused"]


def test_endpoint_namespace_unsupported_probe_refuses_before_opening(tmp_path, monkeypatch):
    module = launcher_module()
    opened = []
    monkeypatch.setattr(module, "launch_descriptor_capable", lambda: False)
    opening = module.os.open
    def open_path(*args, **kwargs):
        opened.append(True)
        return opening(*args, **kwargs)
    monkeypatch.setattr(module, "os", R2Facade(module.os, open=open_path))
    with pytest.raises(ValueError, match="^endpoint namespace descriptors unsupported on this platform$"):
        with module.stop_endpoint_lock(tmp_path, "pilot/lane/review", create=True):
            pytest.fail("unsupported endpoint namespace admitted an effect")
    assert not opened


@pytest.mark.parametrize("failure", ["probe", "descriptors"])
def test_r31_unavailable_pid_namespace_probe_refuses_without_opening(monkeypatch, failure):
    module = launcher_module()
    opened = []
    def forbidden(*args, **kwargs):
        opened.append(True)
        raise AssertionError("unavailable namespace must not open a descriptor")
    if failure == "probe":
        monkeypatch.setattr(module, "pid_namespace_probe", lambda: None)
    else:
        monkeypatch.setattr(module, "launch_descriptor_capable", lambda: False)
    monkeypatch.setattr(module, "os", R2Facade(module.os, open=forbidden))
    with pytest.raises(ValueError) as refusal:
        module.require_pid_namespace()
    assert str(refusal.value) == module.PID_NAMESPACE_REFUSAL and not opened


def launcher_module(projection=None):
    name = "hierarchy_launcher_under_test_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if projection is not None:
        projection.install(module)
    return module


def r2_indirect_exit_capability():
    """Report usable pidfds and existing subreaper status independently.

    Reading PR_GET_CHILD_SUBREAPER does not change ownership in the pytest worker.
    Only dedicated child scopes establish it with PR_SET_CHILD_SUBREAPER.
    Subreaper status cannot supply an indirect signal handle or a parent's wait.
    """
    capability = {"pidfd": False, "subreaper": False}
    if not sys.platform.startswith("linux"):
        return capability
    descriptor, usable = None, False
    try:
        opening = getattr(os, "pidfd_open", None)
        if callable(opening):
            descriptor = opening(os.getpid())
            if type(descriptor) is int and descriptor >= 0:
                watcher = select.poll()
                watcher.register(descriptor, select.POLLIN)
                usable = not watcher.poll(0)  # Our original instance is still alive.
                if usable:
                    signal.pidfd_send_signal(descriptor, 0)  # Qualify indirect delivery without a signal.
    except (AttributeError, OSError, TypeError, ValueError):
        usable = False
    finally:
        if type(descriptor) is int and descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                usable = False
    capability["pidfd"] = usable
    try:
        import ctypes
        state = ctypes.c_int()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(37, ctypes.byref(state), 0, 0, 0) == 0 and state.value == 1:
            capability["subreaper"] = True
    except (AttributeError, OSError, TypeError):
        pass
    return capability


def require_r2_indirect_exit(*, pidfd=False):
    capability = r2_indirect_exit_capability()
    if isinstance(capability, dict) and (capability.get("pidfd") is True or
                                       (not pidfd and capability.get("subreaper") is True)):
        return capability
    needed = "usable pidfd required" if pidfd else "usable pidfd or native subreaper ownership required"
    pytest.skip("R2 fixture: indirect exit evidence unavailable; " + needed)


class R2IdentityConflict(RuntimeError):
    """Two physical observations contradicted one another; absence cannot repair this."""


def r2_kernel_process(pid):
    """Independent Linux identity capture; no production matcher or host binary is involved."""
    folder = Path("/proc") / str(pid)
    before = (folder / "stat").read_bytes().rpartition(b")")[2].split()
    status = (folder / "status").read_bytes()
    raw = (folder / "cmdline").read_bytes()
    after = (folder / "stat").read_bytes().rpartition(b")")[2].split()
    if len(before) < 20 or len(after) < 20:
        raise RuntimeError("R2 fixture: unavailable physical birth evidence")
    if before[19] != after[19]:
        raise R2IdentityConflict("R2 fixture: unstable physical birth evidence")
    uid = next((line.split()[1:] for line in status.splitlines() if line.startswith(b"Uid:")), [])
    if len(uid) < 2 or not all(word.isdigit() for word in uid[:2]):
        raise RuntimeError("R2 fixture: unavailable physical UID evidence")
    return {"pid": pid, "birth": before[19].decode("ascii"), "raw": raw,
            "digest": hashlib.sha256(raw).hexdigest(), "uid": int(uid[0]), "euid": int(uid[1]),
            "ppid": int(before[1]), "pgid": int(before[2]), "state": before[0].decode("ascii")}


class R2Facade:
    """An instance-local module view: replacing one attribute never patches the real module."""

    def __init__(self, original, **overrides):
        self.original = original
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self.original, name)


class R2CleanupError(RuntimeError):
    def __init__(self, report):
        self.report = report
        super().__init__("R2 physical cleanup " + report["state"] + ": " + json.dumps(report["errors"]))


class R2CleanupUnknown(R2CleanupError):
    pass


class WitnessedPopen(subprocess.Popen):
    """Keep the actual waitpid PID/status; CPython's cached/ECHILD fallback is not evidence."""

    def __init__(self, *args, **kwargs):
        import threading

        self.native_wait_evidence, self.native_wait_unavailable = None, False
        self.native_wait_lock = threading.RLock()
        self.native_birth, self.native_handle = None, None
        super().__init__(*args, **kwargs)
        physical = r2_kernel_process(self.pid)
        self.native_birth = physical["birth"]
        if hasattr(os, "pidfd_open"):
            try:
                self.native_handle = os.pidfd_open(self.pid)
            except OSError:
                pass

    def record_wait(self, pid, status):
        if pid != self.pid or not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            raise RuntimeError("R2 fixture: wait status is not for the original child")
        self.native_wait_evidence = {"wait_pid": pid, "wait_status": status}
        self.native_wait_unavailable = False
        self.returncode = os.waitstatus_to_exitcode(status)
        self.capture_event("native_wait", pid=pid, status=status)
        self.close_native_handle()
        return self.returncode

    def capture_event(self, event, **details):
        path = getattr(self, "capture_trace_path", None)
        if path is not None:
            events = getattr(self, "capture_events", [])
            events.append(dict(event=event, at_ns=time.monotonic_ns(), **details))
            self.capture_events = events
            path.write_text(json.dumps(events) + "\n")

    def communicate(self, *args, **kwargs):
        self.capture_event("communicate_enter")
        try:
            if hasattr(self, "pipe_capture"):
                out, err = self.captured_communicate(*args, **kwargs)
            else:
                out, err = super().communicate(*args, **kwargs)
            self.capture_event("communicate_return", stdout_size=len(out or ""), stderr_size=len(err or ""))
            return out, err
        except BaseException as exc:
            self.capture_event("communicate_error", kind=type(exc).__name__)
            raise

    def start_capture(self):
        """Drain both runner pipes before staging observations can block their writer. No signal authority."""
        import threading

        if hasattr(self, "pipe_capture"):
            raise RuntimeError("R2 fixture: runner capture already started")
        self.pipe_capture = []
        for stream in (self.stdout, self.stderr):
            if stream is None:
                raise RuntimeError("R2 fixture: runner capture requires both pipes")
            state = dict(stream=stream, chunks=[], size=0, error=None, done=threading.Event())
            self.pipe_capture.append(state)

            def drain(state=state):
                try:
                    while True:
                        raw = os.read(state["stream"].fileno(), 65536)
                        if not raw:
                            break
                        state["size"] += len(raw)
                        if state["size"] <= 16 * 1024 * 1024:
                            state["chunks"].append(raw)
                        else:
                            # Keep draining to avoid pipe deadlock, but never return truncated output as success.
                            state["error"] = RuntimeError("R2 fixture: runner capture exceeds 16 MiB")
                except BaseException as exc:
                    state["error"] = exc
                finally:
                    state["done"].set()

            threading.Thread(target=drain, daemon=True).start()

    def captured_communicate(self, input=None, timeout=None):
        if input is not None:
            raise RuntimeError("R2 fixture: captured runner has no input protocol")
        timeout = R2_HANDSHAKE_CEILING_SECONDS if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while self.poll() is None or not all(row["done"].is_set() for row in self.pipe_capture):
            observer = getattr(self, "wait_observer", None)
            if observer is not None:
                observer()
            exited = self.poll() is not None
            pending = next((row for row in self.pipe_capture if not row["done"].is_set()), None)
            if exited and pending is None:
                break
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout,
                                                *(b"".join(row["chunks"]) for row in self.pipe_capture))
            remaining = R2_HANDSHAKE_CEILING_SECONDS if deadline is None else max(0, deadline - time.monotonic())
            blocker = getattr(self, "wait_blocker", None)
            if exited:
                pending["done"].wait(min(remaining, .05))
            elif blocker is not None:
                blocker(min(remaining, .05))
            elif self.native_handle is not None:
                _r2_wait_descriptors(min(remaining, .05), [self.native_handle])
            else:
                if pending is not None:
                    pending["done"].wait(min(remaining, .05))
                else:
                    _r2_wait_descriptors(min(remaining, .05))
        values = []
        for row in self.pipe_capture:
            if row["error"] is not None:
                raise row["error"]
            raw, stream = b"".join(row["chunks"]), row["stream"]
            values.append(self._translate_newlines(raw, stream.encoding, stream.errors) if self.text_mode else raw)
            stream.close()
        return tuple(values)

    def close_native_handle(self):
        if self.native_handle is not None:
            os.close(self.native_handle)
            self.native_handle = None

    def poll(self):
        with self.native_wait_lock:
            if self.native_wait_evidence is not None:
                return os.waitstatus_to_exitcode(self.native_wait_evidence["wait_status"])
            if self.native_wait_unavailable:
                return None
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self.native_wait_unavailable = True
                return None
            return self.record_wait(pid, status) if pid else None

    def wait(self, timeout=None):
        timeout = R2_HANDSHAKE_CEILING_SECONDS if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            code = self.poll()
            if code is not None:
                return code
            if self.native_wait_unavailable:
                raise ChildProcessError("R2 fixture: native wait status unavailable")
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            remaining = R2_HANDSHAKE_CEILING_SECONDS if deadline is None else max(0, deadline - time.monotonic())
            _r2_wait_descriptors(min(remaining, .05), [self.native_handle])

    def send_signal(self, number):
        if self.poll() is not None:
            return
        physical = r2_kernel_process(self.pid)
        if (physical["birth"] != self.native_birth or physical["uid"] != os.geteuid() or
                physical["euid"] != os.geteuid()):
            raise RuntimeError("R2 fixture: signal target changed")
        if self.native_handle is not None and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(self.native_handle, number)
        else:
            os.kill(self.pid, number)


def native_wait_fields(process):
    proof = getattr(process, "native_wait_evidence", None)
    if proof is None or proof.get("wait_pid") != process.pid:
        return None
    return {**proof, "returncode": os.waitstatus_to_exitcode(proof["wait_status"])}


class R2OwnedChild:
    """An indirect child has exit evidence, not an invented native return code."""

    def __init__(self, custody, slot):
        self.custody, self.slot = custody, slot
        self.pid = custody.entries[slot]["pid"]

    def poll(self):
        return "CONFIRMED_EXIT" if self.custody.observe(self.slot) is not None else None


def _r2_control_nesting(text):
    """Bracket depth of one control line. Quoted braces are not structure."""
    depth = 0
    maximum = 0
    in_string = False
    escape = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch in "{[":
            depth += 1
            if depth > maximum:
                maximum = depth
        elif ch in "}]" and depth:
            depth -= 1
    return maximum


def r2_identity_transition(entry, event, *, fd=None, verified=False, source=None):
    """The sole writer of an entry's proof state and owned descriptor.

    Pending includes a verified numeric identity without an original-instance
    handle. Capture commits only after the caller's physical/lineage checks.
    Native ownership is retained separately when optional pidfds are unavailable.
    Lost is terminal, including after a previously proven exit.
    """
    refusal = "R2 fixture: illegal identity proof transition"
    if event == "register":
        if "proof_state" in entry or any(name in entry for name in ("fd", "verified", "verified_fd", "lost", "exit")):
            raise RuntimeError(refusal)
        entry.update(fd=None, verified=False, verified_fd=False, lost=False, exit=None, proof_state="pending")
        return None
    state = entry.get("proof_state", "pending")
    if state not in ("pending", "captured", "lost", "exited"):
        raise RuntimeError(refusal)
    if event in ("lost", "release"):
        previous = entry.get("fd")
        if event == "lost":
            entry.update(fd=None, verified=False, verified_fd=False, lost=True, exit=None, proof_state="lost")
        else:
            state = state if state in ("lost", "exited") else "pending"
            entry.update(fd=None, verified_fd=False, proof_state=state)
        if isinstance(previous, int):
            try:
                os.close(previous)
            except OSError:
                entry["descriptor_close_unavailable"] = True
        return entry.get("exit")
    if event == "capture":
        if (state not in ("pending", "captured") or entry.get("lost") or verified is not True or
                (fd is not None and (type(fd) is not int or fd < 0)) or
                not entry.get("birth") or (entry.get("fd") is not None and entry["fd"] != fd)):
            raise RuntimeError(refusal)
        entry.update(fd=fd, verified=True, verified_fd=isinstance(fd, int), lost=False, exit=None,
                     proof_state="captured" if isinstance(fd, int) else "pending")
        return None
    if event not in ("native_exit", "pidfd_exit", "adopt_exit") or entry.get("lost"):
        raise RuntimeError(refusal)
    if event == "adopt_exit":
        if (not isinstance(source, dict) or source.get("lost") or not source.get("verified") or
                source.get("proof_state") != "exited" or source.get("pid") != entry["pid"] or
                source.get("birth") != entry["birth"] or
                (source.get("exit") or {}).get("proof") not in ("native_waitpid", "original_pidfd_exit")):
            raise RuntimeError(refusal)
        proof = dict(source["exit"])
    else:
        if not entry.get("verified"):
            raise RuntimeError(refusal)
        if state == "exited":
            return entry["exit"]
        if event == "pidfd_exit":
            if entry.get("process") is not None:
                return r2_identity_transition(entry, "native_exit")
            if not isinstance(entry.get("fd"), int) or not entry.get("verified_fd"):
                raise RuntimeError(refusal)
            watcher = select.poll()
            watcher.register(entry["fd"], select.POLLIN)
            if not watcher.poll(0):
                return None
            proof = {"proof": "original_pidfd_exit"}
        else:
            owner = entry.get("process") or entry.get("native_owner")
            if owner is not None and getattr(owner, "pid", None) != entry["pid"]:
                raise RuntimeError(refusal)
            try:
                if owner is None:
                    # A child-local subreaper can acquire native ownership after
                    # an ancestor exits. Validate the retained original instance
                    # while its wait relationship still prevents PID reuse.
                    try:
                        physical = r2_kernel_process(entry["pid"])
                    except (R2IdentityConflict, PermissionError):
                        r2_identity_transition(entry, "lost")
                        raise
                    if (physical["birth"] != entry["birth"] or physical["ppid"] != os.getpid() or
                            physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid()):
                        r2_identity_transition(entry, "lost")
                        raise RuntimeError(refusal)
                    pid, status = os.waitpid(entry["pid"], os.WNOHANG)
                    if not pid:
                        return None
                    fields = {"wait_pid": pid, "wait_status": status,
                              "returncode": os.waitstatus_to_exitcode(status)}
                elif hasattr(owner, "native_wait_evidence"):
                    owner.poll()
                    fields = native_wait_fields(owner)
                    if fields is None:
                        if owner.native_wait_unavailable:
                            entry["wait_status"] = "unavailable"
                        return None
                else:
                    if entry.get("wait_status") == "unavailable":
                        return None
                    pid, status = os.waitpid(entry["pid"], os.WNOHANG)
                    if not pid:
                        return None
                    fields = {"wait_pid": pid, "wait_status": status,
                              "returncode": os.waitstatus_to_exitcode(status)}
                    owner.returncode = fields["returncode"]
            except ChildProcessError:
                entry["wait_status"] = "unavailable"
                return None
            except OSError:
                entry["wait_status"] = "unavailable"
                entry["wait_error"] = True
                return None
            proof = {"proof": "native_waitpid", **fields}
    entry.pop("wait_status", None)
    entry.update(exit=proof, lost=False, verified=True, proof_state="exited")
    return proof


def r2_entry_record(entry):
    """Publish terminal loss before considering any saved proof."""
    return {"pid": entry["pid"], "birth": entry["birth"], "lost": bool(entry.get("lost")),
            "exit": entry.get("exit") if not entry.get("lost") and entry.get("verified") and
            entry.get("proof_state") == "exited" else None,
            **({"wait_status": "unavailable"} if entry.get("wait_status") == "unavailable" else {})}


def r2_pending_test_entry(pid, birth, process=None):
    """Actorless negative models start without a committed handle or exit proof."""
    entry = dict(pid=pid, birth=birth, process=process, native_owner=process)
    r2_identity_transition(entry, "register")
    return entry


def r2_exited_test_entry():
    """Closed bookkeeping models use a real owned native wait, never an invented exit."""
    child = WitnessedPopen([sys.executable, "-I", "-c", "import os; os.read(0,1)"], stdin=subprocess.PIPE)
    try:
        physical = r2_kernel_process(child.pid)
        assert physical["ppid"] == os.getpid() and physical["uid"] == physical["euid"] == os.geteuid()
        entry = dict(pid=child.pid, birth=physical["birth"], process=child, native_owner=child)
        r2_identity_transition(entry, "register")
        r2_identity_transition(entry, "capture", verified=True)
        child.stdin.close()
        assert child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 0
        r2_identity_transition(entry, "native_exit")
        return entry
    finally:
        if not child.stdin.closed:
            child.stdin.close()
        child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        child.close_native_handle()


class R2Custody:
    """Physical fixture custody exists before projection staging and never depends on READY.

    Every possible creation has a reserved slot. A private EOF pipe reaches all actors; only the fixture owns
    its writer. Children announce themselves while gated, before they may fork or execute the stop runner.
    Missing original-instance/slot closure is UNKNOWN, retained, and blocks subsequent actor admission.
    """
    LIMIT = 3.0  # Active cleanup escalation budget; readiness/native waits have the generous ceiling.
    quarantine_report = None

    def __init__(self, folder, quarantine):
        self.folder, self.quarantine = Path(folder), Path(quarantine)
        if R2Custody.quarantine_report is not None or self.quarantine.exists():
            raise R2CleanupUnknown(R2Custody.quarantine_report or json.loads(self.quarantine.read_text()))
        self.folder.mkdir(mode=0o700)
        self.nonce = uuid.uuid4().hex
        opened = []
        self.folder_fd = None
        self.control_directory = None
        try:
            self.folder_fd = self._open_folder_fd()
            opened.append(self.folder_fd)
            self.safety_read, self.safety_write = os.pipe()
            opened.extend((self.safety_read, self.safety_write))
            self.report_read, self.report_write = os.pipe()
            opened.extend((self.report_read, self.report_write))
            os.set_blocking(self.report_read, False)
        except BaseException:
            for fd in opened:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self.folder_fd = None
            raise
        self.slots, self.entries, self.gates = {}, {}, {}
        self.launched_roots = {}
        self.slot_provenance = {}
        self.stderr_paths = {}
        self.buffer, self.messages, self.errors = b"", [], []
        self.retained_bytes = 0
        self._lines_this_pump = 0
        self.closed, self.report, self.cleanup_hook = False, None, None
        self.control_unknown = False
        self.report_eof = False
        self.report_eof_reads, self.report_eof_at = 0, None
        self.report_writer_retired = False
        self.report_rejected = False
        self.visited = []

    def admit_check(self):
        if self.closed or R2Custody.quarantine_report is not None or self.quarantine.exists():
            raise RuntimeError("R2 fixture: physical actor admission is closed")

    def plan(self, nodes, *, fixture_only=()):
        self.admit_check()
        if any(slot not in nodes for slot in fixture_only):
            raise RuntimeError("R2 fixture: invalid synthetic slot reservation")
        for slot, data in nodes.items():
            if (set(data) != {"kind", "parent", "child"} or data["kind"] not in ("H", "M", "W", "C", "R") or
                    (data["parent"] is not None and data["parent"] not in nodes and
                     data["parent"] not in self.entries) or
                    (data["child"] is not None and
                     (data["child"] not in nodes or nodes[data["child"]]["parent"] != slot))):
                raise RuntimeError("R2 fixture: invalid bounded creation plan")
        for slot, data in nodes.items():
            if slot in self.slots:
                raise RuntimeError("R2 fixture: duplicate creation slot")
            self.gates[slot] = os.pipe()
            self.slots[slot] = {**data, "permitted": False, "hello": False,
                                "running": False, "released": False}
            self.slot_provenance[slot] = {
                "fixture_created": True, "fixture_only": slot in fixture_only,
                "handed_to_actor": data["parent"] in self.entries,
            }
        self._expose_reservations(name for name, row in self.slots.items()
                                  if row.get("starting") or name in self.entries)

    def _expose_reservations(self, actors):
        """An actor may fill every reservation beneath it, including omitted descendants."""
        exposed = {name for name in actors if name in self.slots}
        while True:
            descendants = {name for name, row in self.slots.items()
                           if row["parent"] is not None and row["parent"] in exposed}
            added = descendants - exposed
            if not added:
                break
            exposed.update(added)
        for name in exposed:
            self.slot_provenance[name]["handed_to_actor"] = True

    def config(self, nodes, script, path, **extra):
        if "exit_file" in extra:
            exit_file = Path(extra["exit_file"])
            if exit_file.parent != self.folder.parent or not _r2_safe_name(exit_file.name):
                raise RuntimeError("R2 fixture: exit marker path refused")
            if self.control_directory is None:
                # The first config is written before any actor exists. Reuse this anchor thereafter.
                self.control_directory = self._open_folder_fd(self.folder.parent)
            extra["exit_directory"] = self.control_directory
            extra["exit_name"] = exit_file.name
        data = {"nonce": self.nonce, "safety_read": self.safety_read, "report_write": self.report_write,
                "nodes": {slot: {**row, "gate": self.gates[slot][0],
                                  "started": str(self.folder / (slot + ".started"))}
                          for slot, row in nodes.items()},
                "slot_directory": self.folder_fd,
                "inherited": [self.safety_read, self.report_write, self.folder_fd,
                              *([self.control_directory] if self.control_directory is not None else []),
                              *(self.gates[s][0] for s in nodes)],
                "script": str(script), "config": str(path), "trusted_root": str(ROOT),
                "helper": str(Path(__file__).resolve()), **extra}
        path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def capture(self, slot, pid, process=None, birth=None):
        # A trusted Popen must be retained before fallible reads. A report's
        # candidate stays private until validated and cannot mutate genuine custody.
        original = self.entries.get(slot)
        parent = self.slots[slot]["parent"]
        if parent is None and original is None and process is None:
            # A same-parent sibling is not one of our launches. A protocol frame
            # cannot supply the trusted Popen that establishes a root's ownership.
            raise R2IdentityConflict("R2 fixture: root has no retained fixture launch")
        entry = original if original is not None else {
            "pid": pid, "process": process, "native_owner": process, "birth": birth}
        if original is None:
            r2_identity_transition(entry, "register")
        elif "proof_state" not in entry:
            # Legacy actorless models enter unverified; their flags cannot grant proof.
            r2_identity_transition(entry, "register")
        if original is None and process is not None:
            self.entries[slot] = entry
        if entry.get("lost"):
            raise R2IdentityConflict("R2 fixture: no physical authority after identity loss")
        if entry["pid"] != pid or (birth is not None and entry["birth"] not in (None, birth)):
            raise RuntimeError("R2 fixture: conflicting physical creation identity")
        retained_lineage = (original is not None and entry["process"] is None and
                            isinstance(entry["fd"], int) and entry["verified_fd"] and entry.get("lineage"))
        if entry.get("birth") is not None and self._retained_wait(entry):
            # Already captured, and waitpid has reaped it. /proc is gone; the saved
            # identity and wait evidence are the record.
            if process is not None:
                return process
            if entry.get("process") is not None:
                return entry["process"]
            return R2OwnedChild(self, slot)
        candidate = None
        try:
            if entry["fd"] is None and hasattr(os, "pidfd_open"):
                try:
                    candidate = os.pidfd_open(pid)
                except OSError:
                    pass  # Native ownership can still prove an owned direct child's exit.
            physical = r2_kernel_process(pid)
            expected_parent = os.getpid() if parent is None else self.entries[parent]["pid"]
            if entry["birth"] is not None and physical["birth"] != entry["birth"]:
                raise R2IdentityConflict("R2 fixture: physical birth/UID/parent mismatch")
            if entry["lost"] or physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid():
                raise R2IdentityConflict("R2 fixture: physical birth/UID/parent mismatch")
            if retained_lineage:
                # A live original instance may now be adopted by another parent.
                # Its pinned identity and captured ancestry survive that adoption;
                # neither a new PPID nor an already-reaped ancestor replaces them.
                return R2OwnedChild(self, slot)
            if physical["ppid"] != expected_parent:
                raise R2IdentityConflict("R2 fixture: physical birth/UID/parent mismatch")
            if parent is None:
                launched = getattr(self, "launched_roots", {}).get(slot)
                if launched is not None:
                    if (entry["process"] is not launched or launched.pid != pid or
                            launched.native_birth != physical["birth"]):
                        raise R2IdentityConflict("R2 fixture: physical birth/UID/parent mismatch")
                    entry["lineage"] = ((slot, pid, physical["birth"]),)
                else:
                    # An independent observer may retain an explicitly supplied
                    # Popen for exit evidence. It acquires no signal authority.
                    entry["lineage"] = None
            else:
                ancestor = self.entries[parent]
                if R2Custody._retained_wait(self, ancestor):
                    raise R2IdentityConflict("R2 fixture: captured parent has exited")
                try:
                    physical_parent = r2_kernel_process(ancestor["pid"])
                    if (ancestor["lost"] or physical_parent["birth"] != ancestor["birth"] or
                            physical_parent["uid"] != os.geteuid() or physical_parent["euid"] != os.geteuid()):
                        raise R2IdentityConflict("R2 fixture: physical birth/UID/parent mismatch")
                except (R2IdentityConflict, PermissionError):
                    r2_identity_transition(ancestor, "lost")
                    self.control_unknown = True
                    raise
                lineage = ancestor.get("lineage")
                entry["lineage"] = (*lineage, (slot, pid, physical["birth"])) if lineage else None
            entry["birth"] = physical["birth"]
            r2_identity_transition(entry, "capture", fd=entry["fd"] if entry["fd"] is not None else candidate,
                                   verified=True)
            candidate = None
        except BaseException as exc:
            if isinstance(candidate, int):
                try:
                    os.close(candidate)
                except OSError:
                    pass
            if ((original is not None or process is not None) and
                    (not entry.get("verified_fd") or isinstance(exc, (R2IdentityConflict, PermissionError)))):
                r2_identity_transition(entry, "lost")
                self.control_unknown = True
            raise
        self.entries[slot] = entry
        return process if process is not None else R2OwnedChild(self, slot)

    def _retained_wait(self, entry):
        """True when this slot already has original-instance exit evidence."""
        if entry.get("lost") or not entry.get("verified"):
            return False
        process = entry.get("process")
        if process is not None:
            return R2Custody._native_exit(entry) is not None
        if entry.get("exit") is not None:
            return True
        if isinstance(entry.get("fd"), int) and entry.get("verified_fd"):
            return r2_identity_transition(entry, "pidfd_exit") is not None
        return False

    @staticmethod
    def _native_exit(entry):
        """Reap a retained direct child; protocol status and cached returncode are not evidence."""
        if entry.get("lost"):
            return None
        if not entry.get("verified"):
            entry["wait_status"] = "unavailable"
            return None
        return r2_identity_transition(entry, "native_exit")

    def _grant(self, slot):
        # Exemption is revoked before the actor may fill this reservation.
        self.slot_provenance[slot]["handed_to_actor"] = True
        self.slots[slot]["permitted"] = True

    def _unaccounted_reservations(self):
        """Reconcile exposure before each verdict, including grants made by consumer fixtures."""
        self._expose_reservations(name for name, row in self.slots.items()
                                  if row.get("starting") or name in self.entries)
        unresolved = set()
        uncreated = []
        for slot, row in self.slots.items():
            origin = self.slot_provenance[slot]
            if row["permitted"]:
                origin["handed_to_actor"] = True
            if slot in self.entries:
                continue
            if (origin["fixture_created"] and origin["fixture_only"] and not origin["handed_to_actor"]):
                uncreated.append(slot)
            else:
                unresolved.add(slot)
        return unresolved, uncreated

    def launch(self, config, slot, env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, extra=(),
               argv=None, cwd=None, stdin=subprocess.DEVNULL, new_session=True):
        self.admit_check()
        if self.slots[slot]["parent"] is not None or slot in self.launched_roots:
            raise RuntimeError("R2 fixture: root launch requires an unused root slot")
        self.slots[slot]["starting"] = True
        self._grant(slot)
        handed = {slot, *config.get("nodes", {})}
        for row in config.get("nodes", {}).values():
            handed.update((row.get("parent"), row.get("child")))
        self._expose_reservations(handed)
        command = ([sys.executable, "-I", "-B", config["script"], config["config"], slot, *extra]
                   if argv is None else list(argv))
        captured_stderr = None
        if stderr == subprocess.DEVNULL:
            self.stderr_paths[slot] = self.folder / (slot + ".stderr")
            captured_stderr = self.stderr_paths[slot].open("wb")
            stderr = captured_stderr
        try:
            process = WitnessedPopen(command,
                                       env=dict(env), cwd=str(self.folder if cwd is None else cwd), stdin=stdin,
                                       stdout=stdout, stderr=stderr, text=True, start_new_session=new_session,
                                       pass_fds=tuple(config["inherited"]))
        finally:
            if captured_stderr is not None:
                captured_stderr.close()
        self.launched_roots[slot] = process
        return self.capture(slot, process.pid, process)

    def stderr_tail(self):
        if not isinstance(getattr(self, "folder_fd", None), int):
            return "[stderr omitted: closed]"
        return "\n".join("%s:\n%s" % (_r2_untrusted_text(path.name, 256), self._bounded_stderr(slot, tail=True))
                         for slot, path in self.stderr_paths.items())

    def _open_folder_fd(self, directory=None):
        """Anchor the custody directory before any child exists.

        Later stderr reads use this descriptor so a rename or symlink on the
        path cannot redirect them.
        """
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return os.open(os.fspath(self.folder if directory is None else directory), flags)

    def _close_folder_fd(self):
        folder, control = getattr(self, "folder_fd", None), getattr(self, "control_directory", None)
        self.folder_fd = self.control_directory = None
        for fd in (folder, control):
            if isinstance(fd, int):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _discard_pending_report(self):
        """Drop a bounded amount of unread report bytes. Does not retain them."""
        discarded = 0
        while discarded < R2_CONTROL_LINE_LIMIT:
            try:
                part = os.read(self.report_read, 4096)
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            if not part:
                self._note_report_eof()
                return
            discarded += len(part)
        try:
            extra = os.read(self.report_read, 1)
        except BlockingIOError:
            return
        except InterruptedError:
            extra = b"\x00"
        if not extra:
            self._note_report_eof()
            return
        # The writer is still producing past the discard budget. Keep no bytes.
        self.report_rejected = True
        self.control_unknown = True
        if "R2 fixture: control message exceeds its bound" not in self.errors:
            self.errors.append("R2 fixture: control message exceeds its bound")

    def _note_report_eof(self):
        self.report_eof = True
        self.report_eof_reads += 1
        self.report_eof_at = time.monotonic()

    def _retire_report_writer(self):
        """Remove the fixture's writer while keeping its descriptor number owned.

        dup2 replaces the pipe atomically. A late capture cannot reuse the number
        as a pidfd and have teardown close that unrelated descriptor later.
        """
        if self.report_writer_retired:
            return True
        placeholder = None
        try:
            placeholder = os.open(os.devnull, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            if placeholder == self.report_write:
                self.control_unknown = True
                self.errors.append("R2 fixture: report writer ownership was lost")
            else:
                os.dup2(placeholder, self.report_write, inheritable=False)
            self.report_writer_retired = True
            return True
        except OSError:
            self.control_unknown = True
            self.errors.append("R2 fixture: report writer retirement failed")
            return False
        finally:
            if isinstance(placeholder, int) and placeholder != self.report_write:
                os.close(placeholder)

    def _reject_report(self, reason):
        """Latch a fixed refusal. The caller's bytes are not copied into the error."""
        self._latch_refusal(RuntimeError(reason))
        raise RuntimeError(reason) from None

    def _take_lines(self):
        """Parse complete lines until this pump's line budget is spent.

        The budget is reset by pump(), not by this method. A second read in the
        same pump cannot start the count over.
        """
        while b"\n" in self.buffer and self._lines_this_pump < R2_CONTROL_LINES_PER_PUMP:
            line, self.buffer = self.buffer.split(b"\n", 1)
            self._lines_this_pump += 1
            self._intake_frame(line)
        if b"\n" not in self.buffer and len(self.buffer) > R2_CONTROL_LINE_LIMIT:
            self._reject_report("R2 fixture: control message exceeds its bound")
        return self._lines_this_pump >= R2_CONTROL_LINES_PER_PUMP

    def pump(self):
        """Read at most one line-limit, then return.

        True means the budget stopped the read while the peer may still be writing,
        so the caller must not treat this pump as the end of the stream.
        A rejected report is discarded, never decoded.
        """
        if self.report_rejected:
            self.buffer = b""
            self._discard_pending_report()
            raise RuntimeError(self._open_refusal()) from None
        self._lines_this_pump = 0
        read = 0
        while read < R2_CONTROL_LINE_LIMIT:
            if self._take_lines():
                return True
            try:
                part = os.read(self.report_read, 4096)
            except BlockingIOError:
                return False
            except InterruptedError:
                continue
            if not part:
                self._note_report_eof()
                self._take_lines()
                if self.buffer and b"\n" not in self.buffer:
                    self._reject_report("R2 fixture: control message refused")
                return False
            if (len(self.buffer) + len(part) > R2_CONTROL_LINE_LIMIT and b"\n" not in self.buffer
                    and b"\n" not in part):
                self._reject_report("R2 fixture: control message exceeds its bound")
            self.buffer += part
            read += len(part)
        self._take_lines()
        return True

    def _intake_frame(self, line):
        """Only reader of a control frame. Every failure latches UNKNOWN first."""
        if self.report_rejected or self.control_unknown:
            self._reject_report(self._open_refusal())
        try:
            self._accept_frame(line)
        except BaseException as exc:
            self._latch_refusal(exc)
            raise RuntimeError(self._refusal_text(exc)) from None

    def _open_refusal(self):
        for item in reversed(self.errors):
            if isinstance(item, str) and item.startswith("R2 fixture:"):
                return item.split("\n", 1)[0]
        return "R2 fixture: control message refused"

    def _refusal_text(self, exc):
        # Only diagnostics authored here may cross the intake boundary. An OS,
        # decoder or capture exception can contain arbitrary input, even with our prefix.
        refusals = (
            "R2 fixture: control message refused", "R2 fixture: control message exceeds its bound",
            "R2 fixture: control ledger exceeded", "R2 fixture: control drain exceeded",
            "R2 fixture: unplanned control message", "R2 fixture: child appeared without its creation permit",
            "R2 fixture: invalid reserved child creation intent", "R2 fixture: unexpected child creation",
            "R2 fixture: actor ran before physical admission", "R2 fixture: conflicting native child wait",
            "R2 fixture: conflicting unavailable wait", "R2 fixture: invalid control event",
            "R2 fixture: conflicting physical creation identity", "R2 fixture: physical birth/UID/parent mismatch",
        )
        if isinstance(exc, RuntimeError) and str(exc) in refusals:
            return str(exc)
        return "R2 fixture: control message refused"

    def _latch_refusal(self, exc):
        self.report_rejected = True
        self.control_unknown = True
        self.buffer = b""
        reason = self._refusal_text(exc)
        if reason not in self.errors:
            self.errors.append(reason)
        try:
            self._discard_pending_report()
        except OSError:
            pass  # The refusal is already latched; a drain error cannot replace it.

    def _ledger_room(self, line):
        incoming = len(line) + 1
        if (len(self.messages) >= R2_CONTROL_LEDGER_MESSAGES or
                self.retained_bytes + incoming > R2_CONTROL_LEDGER_BYTES):
            raise RuntimeError("R2 fixture: control ledger exceeded")
        return incoming

    def _accept_frame(self, line):
        if len(line) > R2_CONTROL_LINE_LIMIT:
            raise RuntimeError("R2 fixture: control message exceeds its bound")
        incoming = self._ledger_room(line)
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            raise RuntimeError("R2 fixture: control message refused") from None
        if _r2_control_nesting(text) > R2_CONTROL_MAX_DEPTH:
            raise RuntimeError("R2 fixture: control message refused")
        try:
            message = json.loads(text)
        except RecursionError:
            raise RuntimeError("R2 fixture: control message refused") from None
        except json.JSONDecodeError:
            raise RuntimeError("R2 fixture: control message refused") from None
        if not isinstance(message, dict):
            raise RuntimeError("R2 fixture: control message refused")
        slot = message.get("slot")
        nonce = message.get("nonce")
        event = message.get("event")
        if not isinstance(slot, str) or not isinstance(nonce, str) or not isinstance(event, str):
            raise RuntimeError("R2 fixture: control message refused")
        if nonce != self.nonce or slot not in self.slots:
            raise RuntimeError("R2 fixture: unplanned control message")
        # Validate every event's fields before capture or any protocol state mutation.
        identities = {"hello": (("pid", "birth"),), "created": (("child_pid", "child_birth"),),
                      "reaped": (("child_pid", "child_birth"),),
                      "wait_unavailable": (("child_pid", "child_birth"),)}
        for pid_key, birth_key in identities.get(event, ()):
            pid, birth = message.get(pid_key), message.get(birth_key)
            if (type(pid) is not int or pid <= 0 or not isinstance(birth, str) or
                    re.fullmatch(r"[0-9]{1,32}", birth) is None):
                raise RuntimeError("R2 fixture: control message refused")
        if event in ("creation_intent", "created", "reaped", "wait_unavailable"):
            if not isinstance(message.get("child"), str):
                raise RuntimeError("R2 fixture: control message refused")
        if event == "reaped" and (type(message.get("wait_pid")) is not int or
                                   message["wait_pid"] <= 0 or
                                   type(message.get("wait_status")) is not int or
                                   not 0 <= message["wait_status"] <= 0xffffffff or
                                   type(message.get("returncode")) is not int):
            raise RuntimeError("R2 fixture: control message refused")
        if event == "hello":
            if not self.slots[slot]["permitted"]:
                raise RuntimeError("R2 fixture: child appeared without its creation permit")
            if self.slots[slot]["hello"]:
                raise RuntimeError("R2 fixture: conflicting physical creation identity")
            self.capture(slot, message["pid"], birth=message["birth"])
            self.slots[slot]["hello"] = True
        elif event == "creation_intent":
            child = message["child"]
            if (slot not in self.entries or not self.slots[slot]["released"] or child not in self.slots or
                    self.slots[child]["parent"] != slot or self.slots[child]["permitted"]):
                raise RuntimeError("R2 fixture: invalid reserved child creation intent")
            self._grant(child)
        elif event == "created":
            child = message["child"]
            if child not in self.slots or self.slots[child]["parent"] != slot or not self.slots[child]["permitted"]:
                raise RuntimeError("R2 fixture: unexpected child creation")
            if self.slots[child].get("created"):
                raise RuntimeError("R2 fixture: conflicting physical creation identity")
            self.capture(child, message["child_pid"], birth=message["child_birth"])
            self.slots[child]["created"] = True
        elif event == "running":
            if not self.slots[slot]["released"]:
                raise RuntimeError("R2 fixture: actor ran before physical admission")
            self.slots[slot]["running"] = True
        elif event == "reaped":
            child = message["child"]
            entry = self.entries.get(child)
            if (entry is None or self.slots[child]["parent"] != slot or entry["pid"] != message["child_pid"] or
                    entry["birth"] != message["child_birth"] or message.get("wait_pid") != entry["pid"] or
                    not isinstance(message.get("wait_status"), int) or
                    os.waitstatus_to_exitcode(message["wait_status"]) != message["returncode"]):
                raise RuntimeError("R2 fixture: conflicting native child wait")
            # Retained below in the bounded message ledger as a claim. Only an
            # original-instance kernel observation may set this entry's exit.
        elif event == "wait_unavailable":
            child = message["child"]
            entry = self.entries.get(child)
            if (entry is None or self.slots[child]["parent"] != slot or entry["pid"] != message["child_pid"] or
                    entry["birth"] != message["child_birth"]):
                raise RuntimeError("R2 fixture: conflicting unavailable wait")
            # A protocol claim cannot suppress our retained Popen's native wait.
        elif event == "timeout":
            self.closed = True  # The known runner still requires independent closure; no new actors.
        else:
            raise RuntimeError("R2 fixture: invalid control event")
        self.messages.append(message)
        self.retained_bytes += incoming

    def await_event(self, slot, field, ceiling=None, clock=None, before_terminal=None):
        """Block on the report pipe, its EOF, or the child's exit.

        ceiling bounds only a child that never writes and never exits. Callers
        omit it and get R2_HANDSHAKE_CEILING_SECONDS. clock and before_terminal
        are test seams: clock replaces time.monotonic, and before_terminal runs
        once after an empty drain and before the exit decision.
        """
        if slot not in self.slots or field not in self.slots[slot]:
            raise RuntimeError("R2 fixture: invalid handshake wait")
        if ceiling is None:
            ceiling = R2_HANDSHAKE_CEILING_SECONDS
        if isinstance(ceiling, bool) or not isinstance(ceiling, (int, float)) or not 0 < ceiling <= 600:
            raise RuntimeError("R2 fixture: invalid handshake ceiling")
        if clock is None:
            clock = time.monotonic
        deadline = clock() + ceiling
        while not self.slots[slot][field]:
            saturated = self.pump()
            if self.slots[slot][field]:
                return
            if before_terminal is not None:
                before_terminal(self)
                before_terminal = None
            terminal = self._handshake_terminal(slot)
            if terminal is not None:
                # Queued frames can outrun one pump. Keep draining while the
                # budget says more may remain. Stop at the field, EOF, or the
                # lifetime ledger. The ceiling only bounds a blocking read.
                while not self.slots[slot][field]:
                    more = self.pump()
                    if self.slots[slot][field]:
                        return
                    if not more and b"\n" not in self.buffer:
                        break
                if self.slots[slot][field]:
                    return
                self._refuse_handshake(slot, field, self._handshake_terminal(slot) or terminal)
            if saturated:
                continue
            if clock() >= deadline:
                # Readiness wins a deadline race: first consume buffered or
                # newly readable bytes without waiting. Continued traffic is
                # bounded by the same lifetime ledger as every other intake.
                more = self.pump()
                if self.slots[slot][field]:
                    return
                if more or b"\n" in self.buffer:
                    continue
                self._refuse_handshake(slot, field, self._handshake_terminal(slot) or "ceiling")
            remaining = deadline - clock()
            if remaining <= 0:
                continue
            self._block_for_handshake(slot, remaining)

    def _pidfd_for(self, slot):
        """Return a live notification source; retain terminal handles as custody evidence."""
        entry = self.entries.get(slot)
        if entry is None or not entry.get("verified") or entry.get("lost"):
            return None
        self._refresh_exit_code(slot)
        if entry.get("proof_state") == "exited" or entry.get("lost") or entry.get("wait_status") == "unavailable":
            return None
        fd = entry.get("fd")
        if isinstance(fd, int) and entry.get("verified_fd") and entry.get("verified") and not entry.get("lost"):
            return fd
        process = entry.get("process")
        handle = getattr(process, "native_handle", None)
        return handle if isinstance(handle, int) and entry.get("verified") and not entry.get("lost") else None

    def _notification_fds(self, slots):
        """A newly reconciled terminal state wakes the caller once, even without a pidfd."""
        handles = []
        for slot in slots:
            entry = self.entries.get(slot) or {}
            before = (entry.get("proof_state"), entry.get("lost"), entry.get("wait_status"))
            fd = self._pidfd_for(slot)
            entry = self.entries.get(slot) or {}
            after = (entry.get("proof_state"), entry.get("lost"), entry.get("wait_status"))
            if before != after:
                return handles, True
            if isinstance(fd, int):
                handles.append(fd)
        return handles, False

    def _slot_exited(self, slot):
        entry = self.entries.get(slot)
        if entry is None:
            return False
        if entry.get("lost"):
            self.control_unknown = True
            return False
        if entry.get("proof_state") == "exited" and entry.get("verified"):
            return True
        if entry.get("process") is not None:
            # A direct child is confirmed through its retained native owner,
            # including when its pidfd becomes readable before waitpid is ready.
            proof = R2Custody._native_exit(entry)
            if entry.get("wait_status") == "unavailable":
                self.control_unknown = True
            return proof is not None
        try:
            proof = self.observe(slot)
        except (OSError, RuntimeError, ValueError):
            proof = None
        if entry.get("lost"):
            self.control_unknown = True
        return proof is not None

    def _handshake_terminal(self, slot):
        entry = self.entries.get(slot) or {}
        if entry.get("lost"):
            self.control_unknown = True
            return "identity lost"
        exited = self._slot_exited(slot)
        if entry.get("lost"):
            self.control_unknown = True
            return "identity lost"
        if entry.get("wait_status") == "unavailable":
            self.control_unknown = True
            return "wait unavailable"
        if exited:
            return "child exited"
        if self.report_eof:
            return "report pipe closed"
        return None

    def _refresh_exit_code(self, slot):
        """Refresh status through the same proof transition as ordinary observation."""
        entry = self.entries.get(slot)
        if entry is None or entry.get("lost"):
            return
        try:
            if entry.get("process") is not None:
                R2Custody._native_exit(entry)
            elif entry.get("exit") is None:
                self.observe(slot)
        except (OSError, RuntimeError, ValueError):
            entry["wait_status"] = "unavailable"
            self.control_unknown = True
        if entry.get("wait_status") == "unavailable":
            self.control_unknown = True

    def _block_for_handshake(self, slot, remaining):
        if self._handshake_terminal(slot) is not None:
            return
        poller = select.poll()
        try:
            poller.register(self.report_read, select.POLLIN)
        except (OSError, ValueError):
            self.report_eof = True
            return
        handles, transitioned = self._notification_fds((slot,))
        if transitioned:
            return
        watching_exit = False
        for fd in handles:
            try:
                poller.register(fd, select.POLLIN)
                watching_exit = True
            except (OSError, ValueError):
                pass
        # Without a process-exit descriptor the child can exit without closing
        # the report pipe (the fixture still holds the writer). The slice only
        # rechecks waitpid. It is not the handshake deadline.
        limit = remaining if watching_exit else min(remaining, 0.2)
        timeout_ms = int(limit * 1000)
        if timeout_ms < 1:
            timeout_ms = 1
        if self._handshake_terminal(slot) is not None:
            return
        try:
            poller.poll(timeout_ms)
        except OSError:
            return

    def _pending_reap(self, slots):
        """Reconcile a snapshot using retained original-instance evidence, without sampling."""
        return [slot for slot in slots if slot not in self.entries or
                r2_entry_record(self.entries[slot])["exit"] is None]

    def _block_for_reap(self, slots, remaining):
        """A completed outstanding child returns control to cleanup immediately."""
        slots = list(slots)
        if self._pending_reap(slots) != slots:
            return
        self._block_for_notifications(slots, remaining, outstanding=slots)

    def _block_for_notifications(self, slots, remaining, *, outstanding=()):
        """Wait for report or live-child notifications, excluding stable terminal actors.

        Slots with no pidfd are rechecked on a short slice. The slice is not
        the cleanup deadline; the caller passes the time left on the ceiling.
        """
        if remaining <= 0:
            return
        poller = select.poll()
        try:
            poller.register(self.report_read, select.POLLIN)
        except (OSError, ValueError):
            return
        handles, transitioned = self._notification_fds(slots)
        if transitioned:
            return
        watching = False
        for fd in handles:
            try:
                poller.register(fd, select.POLLIN)
                watching = True
            except (OSError, ValueError):
                pass
        limit = remaining if watching or not slots else min(remaining, 0.2)
        timeout_ms = int(limit * 1000)
        if timeout_ms < 1:
            timeout_ms = 1
        # Selection, a peer hook, or a signal recheck can have completed a
        # cleanup snapshot. Never spend its ceiling on the fixture-owned pipe.
        if self._pending_reap(outstanding) != list(outstanding):
            return
        try:
            poller.poll(timeout_ms)
        except OSError:
            return

    def _bounded_stderr(self, slot, *, tail=False):
        path = self.stderr_paths.get(slot)
        directory = getattr(self, "folder_fd", None)
        if not isinstance(directory, int):
            return "[stderr omitted: closed]"
        if path is None or not _r2_slot_read_capable():
            return ""
        name = path.name
        if not _r2_safe_name(name):
            return ""
        source = None
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK
            source = os.open(name, flags, dir_fd=directory)
            info = os.fstat(source)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
                return "[stderr omitted: unsafe]"
            if info.st_size > R2_CONTROL_LINE_LIMIT:
                return "[stderr omitted: too_large]"
            remaining = info.st_size
            chunks = []
            while remaining > 0:
                part = os.read(source, remaining if remaining < R2_CONTROL_LINE_LIMIT else R2_CONTROL_LINE_LIMIT)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            raw = b"".join(chunks)
        except (OSError, NotImplementedError):
            return ""
        finally:
            if isinstance(source, int):
                try:
                    os.close(source)
                except OSError:
                    pass
        return _r2_untrusted_text(raw.decode("utf-8", "replace"), 4096 if tail else 1024, tail=tail)

    def _refuse_handshake(self, slot, field, reason):
        self._refresh_exit_code(slot)
        entry = self.entries.get(slot) or {}
        process = entry.get("process")
        returncode = getattr(process, "returncode", None) if process is not None else None
        exit_row = entry.get("exit") if isinstance(entry.get("exit"), dict) else None
        if returncode is None and exit_row is not None:
            returncode = exit_row.get("returncode")
        evidence = {"slot": slot, "field": field, "reason": reason, "returncode": returncode,
                    "stderr": self._bounded_stderr(slot)}
        if exit_row is not None and exit_row.get("proof"):
            evidence["exit_proof"] = exit_row["proof"]
        elif entry.get("wait_status") == "unavailable":
            evidence["wait_status"] = "unavailable"
        raise RuntimeError("R2 fixture: %s handshake refused: %s\n%s" % (
            field, reason, json.dumps(evidence, sort_keys=True)))

    def release(self, slot):
        self.admit_check()
        if not self.slots[slot]["hello"] or slot not in self.entries or self.entries[slot]["lost"]:
            raise RuntimeError("R2 fixture: physical admission is incomplete")
        child = self.slots[slot].get("child")
        if child is not None:
            self._grant(child)
        self.slots[slot]["released"] = True
        os.write(self.gates[slot][1], b"G")

    def observe(self, slot):
        entry = self.entries[slot]
        if entry.get("lost"):
            # Identity loss is UNKNOWN. It is not "still running" and not a later exit proof.
            self.control_unknown = True
            return None
        process = entry["process"]
        if process is not None:
            proof = R2Custody._native_exit(entry)
            if entry.get("wait_error"):
                self.control_unknown = True
            return proof
        if entry["exit"] is not None and entry.get("proof_state") == "exited":
            return entry["exit"]
        if isinstance(entry.get("fd"), int) and entry.get("verified_fd") and entry.get("verified"):
            proof = r2_identity_transition(entry, "pidfd_exit")
            if proof is not None:
                return proof
        try:
            physical = r2_kernel_process(entry["pid"])
        except (R2IdentityConflict, PermissionError):
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
            return None
        except FileNotFoundError:
            if isinstance(entry.get("fd"), int) and entry.get("verified_fd") and entry.get("verified"):
                return r2_identity_transition(entry, "pidfd_exit")
            if entry.get("native_owner") is not None:
                proof = R2Custody._native_exit(entry)
                if entry.get("wait_error"):
                    self.control_unknown = True
                return proof
            try:
                os.kill(entry["pid"], 0)
            except ProcessLookupError:
                entry["wait_status"] = "unavailable"
                self.control_unknown = True
                return None
            except PermissionError:
                r2_identity_transition(entry, "lost")
                self.control_unknown = True
                return None
            except OSError:
                return None  # The read failed open. Retry; this is not a new identity.
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
            return None
        except (OSError, ValueError, RuntimeError):
            # A transient mid-exit read error means evidence is pending.
            # The retained identity stays. Do not latch lost and do not hide a later zombie.
            if isinstance(entry.get("fd"), int) and entry.get("verified_fd") and entry.get("verified"):
                return r2_identity_transition(entry, "pidfd_exit")
            return None
        if (entry["birth"] != physical["birth"] or physical["uid"] != os.geteuid() or
                physical["euid"] != os.geteuid()):
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
        elif physical["state"].startswith("Z"):
            if isinstance(entry.get("fd"), int) and entry.get("verified_fd") and entry.get("verified"):
                # A zombie leader can precede exit of its whole thread group.
                # Its original verified handle stays pending until readable.
                return r2_identity_transition(entry, "pidfd_exit")
            if entry.get("native_owner") is not None:
                proof = R2Custody._native_exit(entry)
            elif entry.get("verified") and physical["ppid"] == os.getpid():
                proof = r2_identity_transition(entry, "native_exit")
            else:
                entry["wait_status"] = "unavailable"
                self.control_unknown = True
                return None
            if entry.get("lost") or entry.get("wait_error"):
                self.control_unknown = True
            return proof
        return None

    def _owns_lineage(self, slot):
        """Original ancestry survives reparenting and reaping; protocol claims cannot create it."""
        entry = self.entries[slot]
        lineage = entry.get("lineage")
        if not lineage or lineage[-1] != (slot, entry["pid"], entry["birth"]):
            return False
        root_slot, root_pid, root_birth = lineage[0]
        launched = self.launched_roots.get(root_slot)
        if launched is None or launched.pid != root_pid or launched.native_birth != root_birth:
            return False
        for index, (name, pid, birth) in enumerate(lineage):
            retained = self.entries.get(name)
            if (retained is None or (index == len(lineage) - 1 and retained["lost"]) or
                    retained["pid"] != pid or retained["birth"] != birth or
                    retained.get("lineage") != lineage[:index + 1] or
                    self.slots[name]["parent"] != (lineage[index - 1][0] if index else None)):
                return False
        return self.entries[root_slot]["process"] is launched

    def kill_owned(self, slot):
        entry = self.entries[slot]
        if self.observe(slot) is not None:
            return
        try:
            physical = r2_kernel_process(entry["pid"])
        except (R2IdentityConflict, PermissionError):
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
            raise
        if (entry["lost"] or entry["birth"] != physical["birth"] or
                physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid()):
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
            raise RuntimeError("R2 fixture: no physical authority after identity loss")
        if not self._owns_lineage(slot):
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
            raise R2IdentityConflict("R2 fixture: no retained fixture launch ancestry")
        try:
            if entry["fd"] is not None and entry["verified_fd"] and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(entry["fd"], signal.SIGKILL)
            else:
                process = entry["process"]
                if process is None or not hasattr(process, "native_wait_lock"):
                    self.control_unknown = True
                    raise RuntimeError("R2 fixture: original-instance signal handle unavailable")
                # An unreaped direct child cannot have its PID reused. Keep the
                # fixture's native wait and numeric delivery in one critical section.
                with process.native_wait_lock:
                    if self._native_exit(entry) is not None:
                        return
                    if process.native_wait_unavailable:
                        self.control_unknown = True
                        raise RuntimeError("R2 fixture: original-instance signal handle unavailable")
                    os.kill(entry["pid"], signal.SIGKILL)
        except PermissionError:
            r2_identity_transition(entry, "lost")
            self.control_unknown = True
            raise

    def await_slot_file(self, name, slot, *, before=None, ceiling=R2_HANDSHAKE_CEILING_SECONDS):
        """Only a safe file in the captured directory can complete a marker handshake."""
        _r2_check_ceiling(ceiling)
        if not _r2_safe_name(name) or len(name) > 255:
            raise RuntimeError("R2 fixture: slot file refused")
        with R2SlotEvents(self.folder_fd) as events:
            def ready():
                if before is not None:
                    before()
                if _r2_slot_ready(self.folder_fd, name):
                    return True
                terminal = self._handshake_terminal(slot)
                if terminal is not None:
                    # Re-check after the exit observation, as with report handshakes.
                    if _r2_slot_ready(self.folder_fd, name):
                        return True
                    self._refuse_handshake(slot, "slot_file", terminal)
                return False

            def block(remaining):
                handles, transitioned = self._notification_fds(self.entries)
                if transitioned or self._handshake_terminal(slot) is not None:
                    return
                events.wait(min(remaining, .05), [self.report_read, *handles])

            try:
                wait_until(ready, seconds=ceiling, block=block)
            except AssertionError as error:
                if str(error) != "condition not met within %.1f s" % ceiling:
                    raise
                self._refuse_handshake(slot, "slot_file", "ceiling")

    def wait_native(self, slot, seconds=R2_HANDSHAKE_CEILING_SECONDS):
        entry = self.entries[slot]
        process = entry["process"]
        if (process is None or isinstance(seconds, bool) or not isinstance(seconds, (int, float))
                or not 0 < seconds <= 600):
            raise RuntimeError("R2 fixture: invalid direct native wait")
        if isinstance(process, WitnessedPopen):
            code = process.wait(timeout=seconds)
            r2_identity_transition(entry, "native_exit")
            return code
        deadline = time.monotonic() + seconds
        while True:
            proof = r2_identity_transition(entry, "native_exit")
            if proof is not None:
                return proof["returncode"]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proof = r2_identity_transition(entry, "native_exit")
                if proof is not None:
                    return proof["returncode"]
                raise RuntimeError("R2 fixture: native wait deadline exceeded")
            self._block_for_handshake(slot, min(remaining, .05))

    def close(self):
        try:
            return self._finish_close()
        finally:
            self._close_folder_fd()

    def _finish_close(self):
        if self.report is not None:
            unresolved, uncreated = self._unaccounted_reservations()
            for slot, entry in self.entries.items():
                if entry.get("lost"):
                    self.control_unknown = True
                    unresolved.add(slot)
                    self.report["entries"][slot] = r2_entry_record(entry)
            if unresolved:
                self.control_unknown = True
                self.report["state"] = "UNKNOWN"
                self.report["unresolved_slots"] = sorted(set(self.report["unresolved_slots"]) | unresolved)
                self.report["uncreated_slots"] = uncreated
                self.report["slot_provenance"] = {slot: dict(row) for slot, row in self.slot_provenance.items()}
                R2Custody.quarantine_report = self.report
            if self.report["state"] == "UNKNOWN":
                # A later proof loss can invalidate a formerly CLOSED cached
                # report. Retain that UNKNOWN before the caller can admit again.
                R2Custody.quarantine_report = self.report
                try:
                    self.quarantine.write_text(json.dumps(self.report, indent=2) + "\n")
                    (self.folder / "closure.json").write_text(json.dumps(self.report, indent=2) + "\n")
                except OSError:
                    self.errors.append("R2 fixture: UNKNOWN retention write failed")
                raise R2CleanupUnknown(self.report)
            return self.report
        self.closed = True
        # A permitted slot that has no process yet can only announce on the report pipe.
        # LIMIT caps that appearance and the reap below. Exit wakes the poll immediately.
        appear = time.monotonic() + self.LIMIT
        while (not self.report_rejected and
               any(row["permitted"] and slot not in self.entries for slot, row in self.slots.items())):
            saturated = False
            try:
                saturated = bool(self.pump())
            except BaseException as exc:
                self.buffer = b""
                self.control_unknown = True
                saturated = False
                if not self.report_rejected:
                    self.errors.append("control drain: " + str(exc))
                    break
            if not any(row["permitted"] and slot not in self.entries for slot, row in self.slots.items()):
                break
            if time.monotonic() >= appear:
                break
            if saturated:
                continue
            self._block_for_notifications([], appear - time.monotonic())
        try:
            os.close(self.safety_write)  # ONLY the fixture owns this writer. All actors independently see EOF.
        except OSError as exc:
            self.errors.append("safety EOF: " + str(exc))
        for slot, entry in list(self.entries.items()):
            self.visited.append(slot)
            try:
                if self.cleanup_hook is not None:
                    self.cleanup_hook(slot)
            except BaseException as exc:
                self.errors.append("cleanup hook " + slot + ": " + str(exc))
        kill_tried = set()
        # EOF is the graceful stop. SIGKILL follows if the child is still alive.
        # LIMIT is the cleanup cap (tests set it below a second to prove UNKNOWN).
        # A child that exits wakes the pidfd wait immediately; LIMIT is not a sleep.
        # The handshake ceiling is not used here: a slot aimed at the live test
        # process, with kill_owned stubbed, would otherwise block for that ceiling.
        cooperative = time.monotonic() + 0.3
        deadline = time.monotonic() + self.LIMIT
        post_exit = None
        drain_complete = False
        drain_evidence = None
        drain_unavailable = False
        left = list(self.entries)
        while True:
            left = self._pending_reap(left)
            if time.monotonic() >= deadline:
                self._latch_refusal(RuntimeError("R2 fixture: control drain exceeded"))
                break
            saturated = False
            if not drain_unavailable:
                try:
                    saturated = bool(self.pump())
                except BaseException as exc:
                    self.buffer = b""
                    self.control_unknown = True
                    if not self.report_rejected:
                        self.errors.append("control closure: " + str(exc))
                        drain_unavailable = True
            # The exit snapshot predates this pump. Only a fresh EOF, observed
            # before the deadline and with no new captured instance, completes it.
            instances = frozenset((slot, row["pid"], row["birth"]) for slot, row in self.entries.items())
            if (post_exit is not None and post_exit["entries"] == instances and
                    self.report_eof_reads > post_exit["eof_reads"] and
                    self.report_eof_at <= deadline):
                drain_complete = True
                drain_evidence = {"eof_reads": self.report_eof_reads, "eof_at": self.report_eof_at}
                if self.buffer:
                    self._latch_refusal(RuntimeError("R2 fixture: control message refused"))
                break
            left = []
            for slot in list(self.entries):
                if slot not in self.visited:
                    self.visited.append(slot)
                    try:
                        if self.cleanup_hook is not None:
                            self.cleanup_hook(slot)
                    except BaseException as exc:
                        self.errors.append("cleanup hook " + slot + ": " + str(exc))
                try:
                    if self.observe(slot) is None:
                        left.append(slot)
                        if time.monotonic() >= cooperative and slot not in kill_tried:
                            kill_tried.add(slot)
                            self.kill_owned(slot)
                except BaseException as exc:
                    left.append(slot)
                    self.errors.append("observe/cleanup " + slot + ": " + str(exc))
            left = self._pending_reap(left)
            # Absence of buffered bytes is never a completed drain. Even an
            # empty pump must yield UNKNOWN if the exit observation spent the deadline.
            if time.monotonic() >= deadline:
                self._latch_refusal(RuntimeError("R2 fixture: control drain exceeded"))
                break
            if not left:
                if drain_unavailable:
                    break
                exited = instances
                if post_exit is None or post_exit["entries"] != exited:
                    post_exit = {"entries": exited, "eof_reads": self.report_eof_reads}
                    if not self._retire_report_writer():
                        break
                    continue
            else:
                post_exit = None
            if saturated:
                continue
            # Do not sleep through the SIGKILL point. After the signal, the pidfd
            # wakes this wait as soon as the child actually exits.
            remaining = deadline - time.monotonic()
            if any(slot not in kill_tried for slot in left):
                remaining = min(remaining, max(0.0, cooperative - time.monotonic()))
            self._block_for_reap(left, remaining)
        if self.report_rejected:
            try:
                self._discard_pending_report()
            except OSError:
                pass
            self.buffer = b""
        if self.report_rejected:
            self.control_unknown = True
            self.buffer = b""
        missing = [slot for slot, row in self.slots.items() if row["permitted"] and slot not in self.entries]
        reservations, uncreated = self._unaccounted_reservations()
        unresolved = set(left + missing) | reservations
        if self.report_rejected:
            # Discarded frames may have created a reserved slot. Do not call it uncreated.
            for slot in uncreated:
                if slot not in self.entries:
                    unresolved.add(slot)
            uncreated = []
        state = "UNKNOWN" if left or missing or unresolved or self.buffer or self.control_unknown or not drain_complete else "CLOSED_WITH_ERRORS" if self.errors else "CLOSED"
        self.report = {"state": state, "errors": self.errors, "unresolved_slots": sorted(unresolved),
                       "visited": self.visited, "entries": {slot: r2_entry_record(entry)
                        for slot, entry in self.entries.items()},
                       "uncreated_slots": uncreated,
                       "slot_provenance": {slot: dict(row) for slot, row in self.slot_provenance.items()},
                       "post_exit_drain": {"complete": drain_complete,
                                           "eof_reads": drain_evidence["eof_reads"] if drain_evidence else None,
                                           "eof_at": drain_evidence["eof_at"] if drain_evidence else None,
                                           "deadline": deadline}}
        if state == "UNKNOWN":
            R2Custody.quarantine_report = self.report  # Latch BEFORE fallible evidence writes.
            try:
                self.quarantine.write_text(json.dumps(self.report, indent=2) + "\n")
                (self.folder / "closure.json").write_text(json.dumps(self.report, indent=2) + "\n")
            except OSError as exc:
                self.errors.append("UNKNOWN retention write: " + str(exc))
            raise R2CleanupUnknown(self.report)
        for entry in self.entries.values():
            r2_identity_transition(entry, "release")
            if entry.get("descriptor_close_unavailable"):
                self.errors.append("R2 fixture: pidfd close unavailable")
            process = entry["process"]
            if process is not None:
                if isinstance(process, WitnessedPopen):
                    process.close_native_handle()
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError as exc:
                            self.errors.append("Popen stream close: " + str(exc))
        for fd in (self.safety_read, self.report_read, self.report_write, *(f for pair in self.gates.values() for f in pair)):
            if not isinstance(fd, int):
                continue
            try:
                os.close(fd)
            except OSError as exc:
                self.errors.append("control descriptor close: " + str(exc))
        if self.errors:
            self.report["state"] = "CLOSED_WITH_ERRORS"
        try:
            (self.folder / "closure.json").write_text(json.dumps(self.report, indent=2) + "\n")
        except OSError as exc:
            self.errors.append("closure retention write: " + str(exc))
            self.report["state"] = "CLOSED_WITH_ERRORS"
        if self.errors:
            raise R2CleanupError(self.report)
        return self.report


def r2_map_present(observation, transform):
    """Project the OS boundary, supporting the baseline snapshot and R2 typed observations.

    The future typed reader's PRESENT contains a snapshot; UNAVAILABLE/CONFIRMED_ABSENT pass through.
    A fixture/protocol incompatibility raises loudly and is never semantic RED evidence.
    """
    if observation is None:
        return None
    if hasattr(observation, "argv"):
        return transform(observation)
    if getattr(observation, "kind", None) in ("UNAVAILABLE", "CONFIRMED_ABSENT"):
        return observation
    if getattr(observation, "kind", None) != "PRESENT" or not hasattr(observation, "snapshot"):
        raise RuntimeError("R2 fixture: incompatible typed process observation")
    snapshot = transform(observation.snapshot)
    return (replace(observation, snapshot=snapshot) if is_dataclass(observation)
            else observation._replace(snapshot=snapshot))


class R2Processes:
    """MODELLED process cohort and complete argv, real identity/ancestry and individual signals.

    This fixture is explicit and opt-in. Shared fake wrappers and production CLI/environment stay unchanged.
    Receipts are test inputs, never grants. Only known Popen instances can enter the signal allow-list.
    """

    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(mode=0o700)
        self.path = self.folder / "receipts.json"
        self.nonce = uuid.uuid4().hex
        self.receipts, self.handles, self.events, self.opens = {}, {}, [], []
        # Negative-only OS cohort, independent of mutable projection receipts. Remembering a PID
        # never authorizes a signal, and deleting a receipt must not hide its physical actor.
        self.census_births = {}
        self.before_read, self.after_present, self.after_signal = [], [], []
        self.read_counts = {}
        self.processes, self.group_reaping = {}, True
        self.save()

    def save(self):
        if any(part.is_symlink() for part in (self.folder, *self.folder.parents)) or self.path.is_symlink():
            raise RuntimeError("R2 fixture: receipt paths must not be symlinks")
        temporary = self.folder / ("receipt-%s.tmp" % uuid.uuid4().hex)
        with temporary.open("x", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump({"schema": "modelled-r2-processes/v1", "nonce": self.nonce,
                       "receipts": self.receipts}, stream)
        os.replace(temporary, self.path)

    @classmethod
    def load(cls, path, nonce):
        path = Path(path)
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise RuntimeError("R2 fixture: linked receipt input")
        info = path.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError("R2 fixture: receipt input owner/mode mismatch")
        data = json.loads(path.read_text(encoding="utf-8"))
        if set(data) != {"schema", "nonce", "receipts"} or data["schema"] != "modelled-r2-processes/v1" or data["nonce"] != nonce:
            raise RuntimeError("R2 fixture: receipt input identity mismatch")
        made = cls.__new__(cls)
        made.folder, made.path, made.nonce = path.parent, path, nonce
        made.receipts, made.handles, made.events, made.opens = data["receipts"], {}, [], []
        made.census_births = ({pid: row.get("birth") for pid, row in made.receipts.items() if isinstance(row, dict)}
                             if isinstance(made.receipts, dict) else {})
        made.before_read, made.after_present, made.after_signal, made.read_counts = [], [], [], {}
        made.processes, made.group_reaping = {}, True
        return made

    def pending(self, process, *, sample=None):
        if str(process.pid) in self.receipts:
            raise RuntimeError("R2 fixture: an existing receipt cannot be renewed")
        self.processes[process.pid] = process
        physical = (r2_kernel_process if sample is None else sample)(process.pid)
        if physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid():
            raise R2IdentityConflict("R2 fixture: child is not ours")
        self.receipts[str(process.pid)] = {"state": "PENDING", "birth": physical["birth"],
                                          "digest": None, "argv": None}
        self.census_births[str(process.pid)] = physical["birth"]
        self.save()

    def ready(self, process, argv=None, *, sample=None):
        receipt = self.receipts.get(str(process.pid))
        if receipt is None or receipt["state"] != "PENDING":
            raise RuntimeError("R2 fixture: READY requires a known pending Popen")
        physical = (r2_kernel_process if sample is None else sample)(process.pid)
        if (physical["birth"] != receipt["birth"] or physical["uid"] != os.geteuid() or
                physical["euid"] != os.geteuid()):
            raise R2IdentityConflict("R2 fixture: child changed before READY")
        status = process.poll()
        # An owned indirect poll can discover identity loss and return no exit proof.
        if isinstance(process, R2OwnedChild) and process.custody.entries[process.slot].get("lost"):
            raise R2IdentityConflict("R2 fixture: child changed before READY")
        if status is not None or physical["state"].startswith("Z"):
            raise RuntimeError("R2 fixture: child changed before READY")
        if argv is not None and (not isinstance(argv, (list, tuple)) or not argv or
                                 not all(isinstance(word, str) and "\0" not in word for word in argv)):
            raise RuntimeError("R2 fixture: logical argv must be an explicit complete array")
        receipt.update(state="READY", digest=physical["digest"], argv=list(argv) if argv is not None else None)
        self.save()

    def command(self, *words):
        if len(words) < 3 or words[0] != "--base" or words[2] != "stop":
            raise RuntimeError("R2 fixture: the test runner only invokes public stop")
        self.check_ready()
        # Structured request only, never an unregistered executable argv. R2Case admits its runner physically.
        return {"receipt": str(self.path), "nonce": self.nonce, "words": list(words)}

    def check_ready(self):
        if not isinstance(self.receipts, dict):
            raise RuntimeError("R2 fixture: malformed receipt set")
        for pid, row in self.receipts.items():
            if (not isinstance(pid, str) or not pid.isdigit() or int(pid) <= 0 or not isinstance(row, dict) or
                    set(row) != {"state", "birth", "digest", "argv"}):
                raise RuntimeError("R2 fixture: malformed receipt record")
            if row["state"] != "READY":
                raise RuntimeError("R2 fixture: unregistered/pending fake must not fall back to native argv")
            if (not isinstance(row["birth"], str) or not row["birth"].isdigit() or
                    not isinstance(row["digest"], str) or re.fullmatch(r"[0-9a-f]{64}", row["digest"]) is None):
                raise RuntimeError("R2 fixture: malformed physical receipt evidence")
            argv = row["argv"]
            if argv is not None and (not isinstance(argv, list) or not argv or
                                     not all(isinstance(word, str) and "\0" not in word for word in argv)):
                raise RuntimeError("R2 fixture: malformed complete argv receipt")

    def authorize(self, pid):
        receipt = self.receipts.get(str(pid))
        if receipt is None or receipt["state"] != "READY":
            raise RuntimeError("R2 fixture: attempted signal outside the owned receipt set")
        physical = r2_kernel_process(pid)
        if (physical["birth"] != receipt["birth"] or
                (not physical["state"].startswith("Z") and physical["digest"] != receipt["digest"]) or
                physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid()):
            raise RuntimeError("R2 fixture: physical signal target no longer matches its receipt")

    def install(self, module):
        self.check_ready()
        reading, real_os, real_signal = module.read_process, module.os, module.signal
        physical_path = module.Path
        cohort = self.census_births
        projection = self

        class CensusPath(type(physical_path())):
            def iterdir(path):
                if str(path) == "/proc":
                    # File/RPC readers can transport new, unchanged READY receipts after install.
                    # Adding an observation never renews an existing birth or grants signal authority.
                    for pid, receipt in list(projection.receipts.items()):
                        cohort.setdefault(pid, receipt.get("birth") if isinstance(receipt, dict) else None)
                for child in physical_path(path).iterdir():
                    if str(path) != "/proc" or child.name in cohort:
                        yield child

        # MODELLED declared process population, with actual metadata and lifetime. Other tests'
        # transient helpers cannot contribute an unrelated unavailable row to this case's census.
        module.Path = CensusPath
        # A verified receipt belongs to this loaded OS-reader view, never to another module or runner.
        verified_receipts = {}

        def fingerprint(receipt):
            if (not isinstance(receipt, dict) or set(receipt) != {"state", "birth", "digest", "argv"} or
                    receipt["state"] != "READY" or not isinstance(receipt["birth"], str) or
                    not receipt["birth"].isdigit() or not isinstance(receipt["digest"], str) or
                    re.fullmatch(r"[0-9a-f]{64}", receipt["digest"]) is None):
                raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
            argv = receipt["argv"]
            if argv is not None and (not isinstance(argv, list) or not argv or
                                     not all(isinstance(word, str) and "\0" not in word for word in argv)):
                raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
            return receipt["state"], receipt["birth"], receipt["digest"], None if argv is None else tuple(argv)

        def projected(pid, *args, **kwargs):
            count = self.read_counts[pid] = self.read_counts.get(pid, 0) + 1
            for hook in self.before_read:
                hook(pid, count)
            observation = reading(pid, *args, **kwargs)
            if kwargs.get("argv_boundaries", args[0] if args else "proven") == "unproven":
                # A test-owned ps string is still LOSSY_PS. A receipt never upgrades its boundaries.
                return observation

            def present(row):
                receipt = self.receipts.get(str(pid))
                if receipt is not None:
                    if isinstance(receipt, dict) and row.start_time == receipt.get("birth") and row.state.startswith("Z"):
                        return row  # A matching physical zombie is exit evidence, not a stale live receipt.
                    current = fingerprint(receipt)
                    if pid in verified_receipts and verified_receipts[pid] != current:
                        raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
                    if row.start_time != receipt["birth"]:
                        raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
                    if row.cmdline == b"" and row.argv == ():
                        if receipt["argv"] is None:
                            return row  # Native empty data stays negative; no logical argv is projected.
                        if verified_receipts.get(pid) != current:
                            raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
                        # The same original process may expose an empty command line while exiting. This is
                        # negative evidence only: preserve every physical field and never restore logical argv.
                        return row
                    if hashlib.sha256(row.cmdline).hexdigest() != receipt["digest"]:
                        raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
                    verified_receipts.setdefault(pid, current)
                    if receipt["argv"] is not None:
                        row = row._replace(argv=tuple(receipt["argv"]))
                elif str(pid) in cohort or pid in verified_receipts:
                    if row.start_time == cohort.get(str(pid)) and row.state.startswith("Z"):
                        return row  # A physically retired pending actor may have no remaining receipt.
                    raise RuntimeError("R2 fixture: stale/unknown projection receipt; no native fallback")
                for hook in self.after_present:
                    row = hook(pid, count, row)
                return row
            return r2_map_present(observation, present)

        def killed(pid, number):
            if number:
                self.authorize(pid)
                self.events.append((pid, number))
            answer = real_os.kill(pid, number)
            if number:
                for hook in self.after_signal:
                    hook(pid, number)
            return answer

        def opened(pid, *args, **kwargs):
            self.authorize(pid)
            fd = real_os.pidfd_open(pid, *args, **kwargs)
            self.handles[fd] = pid
            self.opens.append((pid, fd))
            return fd

        def sent(fd, number, *args):
            if fd not in self.handles:
                raise RuntimeError("R2 fixture: unknown pidfd")
            pid = self.handles[fd]
            if number:
                self.authorize(pid)
                self.events.append((pid, number))
            answer = real_signal.pidfd_send_signal(fd, number, *args)
            if number:
                for hook in self.after_signal:
                    hook(pid, number)
            return answer

        def no_group_signal(group, number):
            if number != 0:
                raise RuntimeError("R2 fixture: a receipt never authorizes a process group")
            if self.group_reaping:
                for process in self.processes.values():
                    process.poll()  # A normal test parent reaps its own real children; no fabricated ESRCH.
                observer = getattr(self, "group_observer", None)
                if observer is not None:
                    observer()
            return real_os.killpg(group, 0)  # Actual kernel evidence, never a projected empty group.

        def closed(fd):
            self.handles.pop(fd, None)
            return real_os.close(fd)

        module.read_process = projected
        module.os = R2Facade(real_os, kill=killed, killpg=no_group_signal, close=closed)
        module.signal = R2Facade(real_signal)
        module.subprocess = R2Facade(module.subprocess)
        def bounded_subprocess(command, **options):
            # Stop's only Linux helper is its ancestry census. Supply actual kernel PPID without forking an
            # unregistered helper. Other subprocess creation is a fixture protocol failure before Popen.
            if len(command) == 5 and command[:4] == ["ps", "-o", "ppid=", "-p"] and str(command[4]).isdigit():
                parent = r2_kernel_process(int(command[4]))["ppid"]
                return subprocess.CompletedProcess(command, 0, str(parent) + "\n", "")
            raise RuntimeError("R2 fixture: unregistered subprocess requested by stop")

        def no_unregistered_popen(*args, **kwargs):
            raise RuntimeError("R2 fixture: unregistered Popen requested by stop")

        module.subprocess.run = bounded_subprocess
        module.subprocess.Popen = no_unregistered_popen
        if hasattr(real_os, "pidfd_open"):
            module.os.pidfd_open = opened
        if hasattr(real_signal, "pidfd_send_signal"):
            module.signal.pidfd_send_signal = sent

    def path_view(self, module, read=None, proc_available=True):
        """Explicit MODELLED OS faults, confined to this loaded launcher's Path name."""
        original = module.Path

        class LocalPath(type(Path())):
            def read_bytes(self):
                physical = original(self).read_bytes()
                return read(self, physical) if read is not None else physical

            def is_dir(self):
                return False if str(self) == "/proc" and not proc_available else original(self).is_dir()

            def iterdir(self):
                return original(self).iterdir()

        module.Path = LocalPath


def r2_stop_main(arguments):
    """Test-only runner entry: import the trusted control checkout, never a provisioned/drifted source."""
    path, nonce, *words = arguments
    projection = R2Processes.load(path, nonce)
    if len(words) < 3 or words[0] != "--base" or words[2] != "stop":
        raise RuntimeError("R2 fixture: non-stop runner request")
    module = launcher_module(projection)
    # Passive, bounded diagnostics: mmap updates add no fsync/pipe write to the measured path. They never
    # affect identity, projection, signal authorization or the production API's decisions.
    import mmap
    import stat
    trace = Path(path).parent / ("stop-timing-%d-evidence.json" % os.getpid())
    fd = os.open(trace, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.ftruncate(fd, 65536)
    region = mmap.mmap(fd, 65536)
    os.close(fd)
    region[:] = b" " * 65536
    events, phase = [], ["main"]

    def event(name, **details):
        if len(events) < 256:
            events.append(dict(event=name, at_ns=time.monotonic_ns(), phase=phase[0], **details))
            raw = json.dumps(events).encode()
            if len(raw) > len(region):
                raise RuntimeError("R2 fixture: timing evidence exceeds its bound")
            region[:len(raw)] = raw

    syncing, saving = module.os.fsync, module.StopCustody.save

    def fsync(descriptor):
        kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
        event("fsync_enter", kind=kind)
        try:
            return syncing(descriptor)
        finally:
            event("fsync_return", kind=kind)

    def save(custody, observed, attempted, active=True):
        previous, phase[0] = phase[0], "checkpoint" if active else "terminal_clear"
        event("save_enter")
        try:
            return saving(custody, observed, attempted, active)
        finally:
            event("save_return")
            phase[0] = previous

    module.os.fsync, module.StopCustody.save = fsync, save
    try:
        event("main_enter")
        code = module.main(words)
        event("main_return", code=code)
        return code
    finally:
        region.close()


def r2_legacy_child_gate(config, slot):
    """Private fixture protocol for a legacy Python actor, before its test body can run or fork."""
    import threading

    def watchdog():
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline:
                readable, _, _ = select.select([config["safety_read"]], [], [], 0.1)
                if readable and os.read(config["safety_read"], 1) == b"":
                    os._exit(0)
        except BaseException:
            os._exit(76)
        os._exit(75)  # A deadline is never a substitute for observing this instance's exit.

    def emit(event, **values):
        raw = (json.dumps({"nonce": config["nonce"], "slot": slot, "event": event, **values}) + "\n").encode()
        if len(raw) > 4096 or os.write(config["report_write"], raw) != len(raw):
            raise RuntimeError("R2 fixture: incomplete legacy actor control report")

    threading.Thread(target=watchdog, daemon=True).start()
    physical = r2_kernel_process(os.getpid())
    emit("hello", pid=os.getpid(), birth=physical["birth"])
    gate = config["nodes"][slot]["gate"]
    while True:
        readable, _, _ = select.select([gate], [], [], 0.1)
        if readable:
            if os.read(gate, 1) != b"G":
                raise RuntimeError("R2 fixture: legacy actor gate closed before admission")
            break
    Path(config["nodes"][slot]["started"]).write_text("RUNNING", encoding="utf-8")
    emit("running")


def r2_captured_entry(arguments):
    """Test-owned entry, with a closed list of native subprocess requests and genuine creation reports."""
    import builtins

    target, entry, *words = arguments
    control = Path(os.environ["R2_CAPTURE_CONFIG"])
    if any(part.is_symlink() for part in (control, *control.parents)):
        raise RuntimeError("R2 fixture: linked captured-exec control")
    config = json.loads(control.read_text())
    supplied = config["capture_target"]
    path = Path(target)
    if (str(path) != supplied["path"] or path.is_symlink() or
            hashlib.sha256(path.read_bytes()).hexdigest() != supplied["sha256"] or entry != supplied["entry"]):
        raise RuntimeError("R2 fixture: captured target source mismatch")
    available = list(config["capture_specs"])
    children = {}

    def emit(event, **values):
        raw = (json.dumps({"nonce": config["nonce"], "slot": config["exec_slot"], "event": event, **values}) + "\n").encode()
        if len(raw) > 4096 or os.write(config["report_write"], raw) != len(raw):
            raise RuntimeError("R2 fixture: incomplete captured process report")

    class Child:
        def __init__(self, process, slot, birth):
            self.process, self.slot, self.birth, self.reported = process, slot, birth, False
            try:
                self.fd = os.pidfd_open(process.pid) if hasattr(os, "pidfd_open") else None
            except OSError:
                self.fd = None

        def __getattr__(self, name):
            return getattr(self.process, name)

        def report(self):
            proof = native_wait_fields(self.process)
            if not self.reported and (proof is not None or self.process.native_wait_unavailable):
                emit("reaped" if proof is not None else "wait_unavailable",
                     child=self.slot, child_pid=self.pid, child_birth=self.birth, **(proof or {}))
                self.reported = True
                if self.fd is not None:
                    os.close(self.fd)
                    self.fd = None

        def communicate(self, *args, **kwargs):
            try:
                return self.process.communicate(*args, **kwargs)
            finally:
                self.report()

        def wait(self, *args, **kwargs):
            try:
                return self.process.wait(*args, **kwargs)
            finally:
                self.report()

        def poll(self):
            result = self.process.poll()
            self.report()
            return result

        def send_signal(self, number):
            if self.poll() is not None:
                return
            physical = r2_kernel_process(self.pid)
            if physical["birth"] != self.birth or physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid():
                raise RuntimeError("R2 fixture: captured child physical identity changed")
            if self.fd is not None and hasattr(signal, "pidfd_send_signal"):
                signal.pidfd_send_signal(self.fd, number)
            else:
                os.kill(self.pid, number)

        def kill(self):
            self.send_signal(signal.SIGKILL)

        def terminate(self):
            self.send_signal(signal.SIGTERM)

    def popen(argv, *args, **options):
        if args or options.get("shell") or not available:
            raise RuntimeError("R2 fixture: undeclared captured Popen")
        slot = available[0]
        if list(argv) != config["capture_specs"][slot]["argv"]:
            raise RuntimeError("R2 fixture: captured subprocess argv mismatch")
        available.pop(0)
        emit("creation_intent", child=slot)
        command = [sys.executable, "-I", "-B", config["script"], config["config"], slot]
        process = WitnessedPopen(command, **{**options, "pass_fds": tuple(config["inherited"])})
        physical = r2_kernel_process(process.pid)
        emit("created", child=slot, child_pid=process.pid, child_birth=physical["birth"])
        child = Child(process, slot, physical["birth"])
        children[child.pid] = child
        return child

    def run(argv, input=None, capture_output=False, timeout=None, check=False, **options):
        if capture_output:
            if "stdout" in options or "stderr" in options:
                raise ValueError("stdout and stderr arguments may not be used with capture_output.")
            options.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if input is not None:
            if "stdin" in options:
                raise ValueError("stdin and input arguments may not both be used.")
            options["stdin"] = subprocess.PIPE
        process = popen(argv, **options)
        try:
            out, err = process.communicate(input, timeout=R2_HANDSHAKE_CEILING_SECONDS if timeout is None else timeout)
        except BaseException:
            process.kill()
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
            raise
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if check and process.returncode:
            raise subprocess.CalledProcessError(process.returncode, argv, output=out, stderr=err)
        return subprocess.CompletedProcess(argv, process.returncode, out, err)

    def leaf_group(pid, number):
        child = children.get(pid)
        if child is None:
            raise RuntimeError("R2 fixture: unregistered captured child group")
        child.send_signal(number)  # The declared native child is a leaf; never signal a whole group.

    importing = builtins.__import__
    process_view = R2Facade(subprocess, Popen=popen, run=run)
    os_view = R2Facade(os, killpg=leaf_group)

    def isolated(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in ("subprocess", "os"):
            return process_view if name == "subprocess" else os_view
        return importing(name, globals, locals, fromlist, level)

    sys.argv = [str(path), *words]
    namespace = {"__file__": str(path), "__name__": "__r2_captured_fake__", "__package__": "",
                 "__builtins__": {**vars(builtins), "__import__": isolated}}
    exec(compile(path.read_bytes(), str(path), "exec"), namespace)
    if entry == "script":
        return 0
    if entry == "main":
        return namespace["main"]()
    if entry == "rollout_main":
        return namespace["rollout_main"](words)
    raise RuntimeError("R2 fixture: unknown captured target entry")


R2_ACTOR_BOOTSTRAP = '''import json, os, runpy, select, sys, threading, time
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
slot = sys.argv[2]
def watchdog():
    deadline = time.monotonic() + 60
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([config["safety_read"]], [], [], 0.1)
            if readable and os.read(config["safety_read"], 1) == b"":
                if config["nodes"][slot]["kind"] == "R":
                    import faulthandler
                    with Path(config["config"]).with_name(slot + ".eof-stack.txt").open("x") as stack:
                        os.fchmod(stack.fileno(), 0o600)
                        faulthandler.dump_traceback(file=stack, all_threads=True)
                os._exit(0)
    except BaseException:
        os._exit(76)  # A broken safety reader must not silently leave a live actor behind.
    os._exit(75)  # Emergency deadline is NOT closure proof; the fixture must observe original-instance exit.
threading.Thread(target=watchdog, daemon=True).start()
birth = (Path("/proc/self/stat").read_bytes().rpartition(b")")[2].split()[19]).decode()
message = {"nonce": config["nonce"], "event": "hello", "slot": slot, "pid": os.getpid(), "birth": birth}
os.write(config["report_write"], (json.dumps(message) + "\\n").encode())
gate = config["nodes"][slot]["gate"]
while True:
    readable, _, _ = select.select([gate], [], [], 0.1)
    if readable:
        if os.read(gate, 1) != b"G":
            sys.exit(70)
        break
sys.path.insert(0, config["trusted_root"])
scope = runpy.run_path(config["helper"])
sys.exit(scope["r2_actor_main"](config, slot))
'''


def _r2_safe_name(name):
    """A single custody-directory component. Rejects traversal and separators."""
    if not isinstance(name, str) or not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name or "\x00" in name:
        return False
    return True


def _r2_slot_read_capable():
    return os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_NONBLOCK")



def _r2_slot_ready(directory, name):
    """A marker is an owned, unlinked regular inode opened from the retained directory."""
    if not _r2_slot_read_capable():
        raise RuntimeError("R2 fixture: slot file support unavailable")
    if not isinstance(directory, int) or not _r2_safe_name(name) or len(name) > 255:
        raise RuntimeError("R2 fixture: slot file refused")
    source = None
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                         dir_fd=directory)
        info = os.fstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise RuntimeError("R2 fixture: slot file refused")
        return True
    except FileNotFoundError:
        return False
    except (OSError, NotImplementedError):
        raise RuntimeError("R2 fixture: slot file refused") from None
    finally:
        if source is not None:
            os.close(source)


def _r2_slot_events_capable():
    return sys.platform.startswith("linux") and _r2_slot_read_capable() and hasattr(select, "poll")


class R2SlotEvents:
    """Inotify watches the retained directory inode. Event names carry no authority."""

    def __init__(self, directory, *, notify=None):
        self.fd = None
        if not _r2_slot_events_capable():
            raise RuntimeError("R2 fixture: slot event support unavailable")
        if not isinstance(directory, int) or isinstance(directory, bool) or directory < 0:
            raise RuntimeError("R2 fixture: slot event watch refused")
        try:
            if notify is None:
                import ctypes
                notify = ctypes.CDLL(None, use_errno=True)
            libc = notify
            fd = libc.inotify_init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
            if fd < 0:
                raise RuntimeError("R2 fixture: slot event support unavailable")
            self.fd = fd
            # /proc/self/fd is the kernel's descriptor view, not an untrusted path component.
            if libc.inotify_add_watch(fd, os.fsencode("/proc/self/fd/%d" % directory), 0x188) < 0:
                raise RuntimeError("R2 fixture: slot event watch refused")
        except (OSError, AttributeError, ValueError, TypeError):
            self.close()
            raise RuntimeError("R2 fixture: slot event support unavailable") from None
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def wait(self, remaining, descriptors=()):
        if self.fd is None:
            raise RuntimeError("R2 fixture: slot event watch closed")
        ready = _r2_wait_descriptors(remaining, [self.fd, *descriptors])
        try:
            os.read(self.fd, 65536)  # Bounded notification drain; readiness always reopens the marker.
        except BlockingIOError:
            pass
        return ready


def _r2_untrusted_text(text, limit, *, tail=False):
    """Canonicalize, then redact, then truncate. Newlines stay; they are not joined."""
    import unicodedata
    from aegis_core.redaction import TOKEN_REDACTIONS, redact_command_secrets

    canonical = unicodedata.normalize("NFKC", text)
    canonical = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", canonical)
    canonical = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", canonical)
    redacted = redact_command_secrets(canonical)
    for pattern, replacement in TOKEN_REDACTIONS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > limit:
        redacted = redacted[-limit:] if tail else redacted[:limit]
    return redacted


def r2_wait_child_ready(child, ready, ceiling, clock=None, sleeper=None):
    """Wait until ready() is true or the child exits.

    The caller supplies a readiness/exit notification blocker for slot files.
    Non-pollable predicates retain a short sampling slice, not a failure bound.
    ceiling is the only failure bound and applies only while the child is still alive.
    A signal that becomes true as the child exits is still success.
    sleeper replaces time.sleep for tests that have to show the wait blocked.
    """
    if isinstance(ceiling, bool) or not isinstance(ceiling, (int, float)) or not 0 < ceiling <= 600:
        raise RuntimeError("R2 fixture: invalid handshake ceiling")
    if clock is None:
        clock = time.monotonic
    if sleeper is None:
        sleeper = lambda remaining: _r2_wait_descriptors(remaining, [getattr(child, "native_handle", None)])
    deadline = clock() + ceiling
    while True:
        if ready():
            return True
        exited = child.poll() is not None
        if ready():
            return True
        if exited:
            return False
        if clock() >= deadline:
            return False
        remaining = deadline - clock()
        if remaining <= 0:
            return True if ready() else False
        sleeper(min(0.05, remaining))



def r2_wait_marker(directory, relative, *, ceiling=R2_HANDSHAKE_CEILING_SECONDS, clock=None):
    """Wait on an owned marker below an inherited root, never a pathname-following probe."""
    _r2_check_ceiling(ceiling)
    if not _r2_slot_read_capable():
        raise RuntimeError("R2 fixture: slot file support unavailable")
    if (not isinstance(directory, int) or isinstance(directory, bool) or directory < 0 or
            not isinstance(relative, str) or len(relative) > 4096 or relative.count("/") > 63):
        raise RuntimeError("R2 fixture: marker path refused")
    parts = relative.split("/")
    if any(not _r2_safe_name(part) or len(part) > 255 for part in parts):
        raise RuntimeError("R2 fixture: marker path refused")
    opened = []
    try:
        current = os.dup(directory)
        opened.append(current)
        for part in parts[:-1]:
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              getattr(os, "O_CLOEXEC", 0), dir_fd=current)
            opened.append(current)
        with R2SlotEvents(current) as events:
            try:
                wait_until(lambda: _r2_slot_ready(current, parts[-1]), seconds=ceiling,
                           clock=clock, block=events.wait)
            except AssertionError as error:
                if str(error) != "condition not met within %.1f s" % ceiling:
                    raise
                raise RuntimeError("R2 fixture: marker handshake refused: ceiling") from None
    except (OSError, NotImplementedError):
        raise RuntimeError("R2 fixture: marker path refused") from None
    finally:
        close_failed = False
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                close_failed = True
        if close_failed:
            raise RuntimeError("R2 fixture: marker path refused") from None


def r2_actor_main(config, slot):
    """Private test-only actor protocol. This process has already been captured and admitted through its gate."""
    node = config["nodes"][slot]
    fork_gap = config.get("fork_gap")
    if fork_gap and slot == fork_gap["root"]:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # Child-local Linux subreaper, never the pytest process.
            raise OSError(ctypes.get_errno(), "fork-gap reaper unavailable")

    def emit(event, **extra):
        data = {"nonce": config["nonce"], "slot": slot, "event": event, **extra}
        raw = (json.dumps(data) + "\n").encode()
        if len(raw) > 4096 or os.write(config["report_write"], raw) != len(raw):
            raise RuntimeError("R2 fixture: incomplete atomic control report")

    if config.get("ignore") or (config.get("tree") and node["kind"] in ("H", "W")):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    else:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
    child_slot, child = node.get("child"), None
    sidecars = config.get("sidecars", {}).get(slot, [])
    if sidecars and (node["kind"] != "H" or not isinstance(sidecars, list) or len(sidecars) != 1 or
                     sidecars[0] == child_slot or sidecars[0] not in config["nodes"] or
                     config["nodes"][sidecars[0]]["parent"] != slot or
                     config["nodes"][sidecars[0]]["child"] is not None):
        raise RuntimeError("R2 fixture: invalid reserved sibling")
    for requested in ([child_slot] if child_slot is not None else []) + sidecars:
        # The fixture reserved this slot before releasing our gate. The child has its OWN unreleased gate,
        # inherits only the EOF reader (never the writer), and cannot fork/execute the runner before capture.
        created = WitnessedPopen([sys.executable, "-I", "-B", config["script"], config["config"], requested],
                                   env=dict(os.environ), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, pass_fds=tuple(config["inherited"]),
                                   start_new_session=bool(fork_gap and slot == fork_gap["root"]))
        birth = r2_kernel_process(created.pid)["birth"]
        emit("created", child=requested, child_pid=created.pid, child_birth=birth)
        if config["nodes"][requested]["kind"] == "R":
            created.start_capture()
        if requested == child_slot:
            child, child_birth = created, birth
    Path(node["started"]).write_text("RUNNING", encoding="utf-8")
    emit("running")
    if fork_gap and slot == fork_gap["forker"]:
        if os.read(fork_gap["release_read"], 1) != b"X":
            raise RuntimeError("fork-gap exit was not released")
        return 0
    if fork_gap and slot == fork_gap["root"]:
        child.wait(timeout=R2_STOP_TIMEOUT_SECONDS)
        proof = native_wait_fields(child)
        if proof is None:
            raise RuntimeError("fork-gap parent has no native wait proof")
        emit("reaped", child=child_slot, child_pid=child.pid, child_birth=child_birth, **proof)
        os.write(fork_gap["reaped_write"], b"C")
        adopted, status = os.waitpid(-1, 0)
        os.write(fork_gap["reaped_write"], (json.dumps(dict(pid=adopted, status=status)) + "\n").encode())
    command = config.get("exec_children", {}).get(slot, config.get("exec_argv") if node["kind"] == "H" else None)
    if command is not None:
        if (child_slot is not None or sidecars or not isinstance(command, list) or
                not command or not all(isinstance(word, str) and "\0" not in word for word in command)):
            raise RuntimeError("R2 fixture: invalid actual-exec request")
        # The fixture captured this instance and its pidfd before releasing its gate. Exec changes raw argv;
        # the pending receipt gets no positive logical projection until the caller's exact exec handshake.
        os.execvpe(command[0], command, dict(os.environ))
    if node["kind"] == "C":
        started = child_slot + ".started"
        with R2SlotEvents(config["slot_directory"]) as events:
            if not r2_wait_child_ready(
                    child, lambda: _r2_slot_ready(config["slot_directory"], started),
                    R2_HANDSHAKE_CEILING_SECONDS,
                    sleeper=lambda remaining: events.wait(remaining, [child.native_handle])):
                emit("timeout")
                return 124
        try:
            out, err = child.communicate(timeout=config.get("runner_timeout", R2_STOP_TIMEOUT_SECONDS))
        except subprocess.TimeoutExpired:
            emit("timeout")
            return 124  # The fixture still owns the gated/registered runner; caller exit is never its closure.
        proof = native_wait_fields(child)
        emit("reaped" if proof is not None else "wait_unavailable",
             child=child_slot, child_pid=child.pid, child_birth=child_birth, **(proof or {}))
        sys.stdout.write(out)
        sys.stderr.write(err)
        if config.get("runner_action") == "burst":
            sys.stdout.flush()
            sys.stderr.flush()
            Path(node["started"]).with_suffix(".capture-ready").touch()
        if config.get("echo_exit"):
            print("exit=%d" % child.returncode)
        return child.returncode
    if node["kind"] == "R" and config.get("runner_action") != "hang":
        if config.get("runner_action") == "burst":
            # Test-only transport pressure; whitespace preserves the real public stop JSON verbatim.
            sys.stdout.write(" " * (2 * 1024 * 1024))
            sys.stdout.flush()
            sys.stderr.write("E" * (2 * 1024 * 1024))
            sys.stderr.flush()
        request = config["runner_request"]
        code = r2_stop_main([request["receipt"], request["nonce"], *request["words"]])
        if config.get("runner_action") == "burst":
            sys.stdout.flush()
            sys.stderr.flush()
            Path(node["started"]).with_suffix(".capture-ready").touch()
        return code
    with R2SlotEvents(config["exit_directory"]) as events:
        wait_until(lambda: _r2_slot_ready(config["exit_directory"], config["exit_name"]), block=events.wait)
    return 0


def test_resume_records_a_wake_tool_that_cannot_run(launch, monkeypatch, capsys):
    launch.start()
    module = launcher_module()

    run = module.subprocess.run

    def unrunnable(argv, **options):
        if any(str(word).endswith("hierarchy_wake.py") for word in argv):
            raise OSError(8, "Exec format error")
        return run(argv, **options)
    monkeypatch.setattr(module.subprocess, "run", unrunnable)
    assert module.main(["--base", str(launch.base), "resume", "--endpoint", REVIEW]) == 2
    monkeypatch.undo()
    answer = json.loads(capsys.readouterr().out)
    assert answer["error"] == "[Errno 8] Exec format error" and answer["state"] == "refused"
    assert [row["state"] for row in launch.records()] == ["bound", "refused"]


def test_a_record_write_that_fails_part_way_leaves_no_torn_record(launch, monkeypatch, capsys):
    module = launcher_module()

    def failing(fd):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(module.os, "fsync", failing)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 2
    monkeypatch.undo()
    assert json.loads(capsys.readouterr().out) == {"error": "[Errno 28] No space left on device"}
    folder = launch.base / "launches" / "pilot%2Flane%2Freview"
    assert list(folder.iterdir()) == []
    assert launch.run("status", "--endpoint", REVIEW)["endpoints"][REVIEW] == {"binding": None, "last": None, "records": 0}


def test_an_interrupt_during_the_bind_wait_is_recorded_and_releases_the_start_lock(launch):
    lock = launch.root / ".write.lock"
    thread = "019a6c3e-3333-7222-8333-444455556666"
    logs = launch.base / "launches" / "pilot%2Flane%2Freview" / "logs"
    running = launch.started(thread=thread, environment={"FAKE_CODEX_TOUCH": str(lock)})
    try:
        wait_until(lambda: lock.exists() and launch.codex_log.exists())
        [started] = [json.loads(line) for line in launch.codex_log.read_text().splitlines()]
        # The turn has ended and the launcher is waiting out the busy writer before it binds.
        wait_until(lambda: not alive(started["pid"]))
        time.sleep(0.5)
        running.send_signal(signal.SIGTERM)
        out, err = running.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == "start_incomplete" and answer["error"] == "the launcher was interrupted"
        assert answer["session"] == thread and answer["exit_code"] == 0
        assert [row["state"] for row in launch.records()] == ["start_incomplete"]
        assert not (logs.parent / ".start.lock").exists() and launch.binding() is None
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=R2_STOP_TIMEOUT_SECONDS)
    lock.unlink()
    launch.add_role(REVIEW, "codex-cli", session=thread)
    assert launch.binding()["session"] == thread


@LINUX_HOST_PROGRAMS
def test_a_census_that_fails_after_signals_were_sent_is_recorded_as_stop_failed(launch, monkeypatch, capsys):
    session = launch.start()["session"]
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case

    context = R2Case(launch)
    hung = context.spawn(["codex", "exec", "--json", "resume", session])
    try:
        wait_until(lambda: owned_pids(session, projection=context.projection) == [hung.pid])
        # MODELLED pidfd unavailability selects the start-time path so the post-signal read is exercised;
        # the real instance, signal, exit and record assertions below retain their original meaning.
        module = context.module(pidfds=False)
        real, calls = module.read_process, []

        def failing_after_the_first(*args):
            if args[0] == hung.pid:
                calls.append(args)
                if (hung.pid, signal.SIGTERM) in context.projection.events:
                    raise OSError(2, "No such file or directory: 'ps'")
            return real(*args)
        monkeypatch.setattr(module, "read_process", failing_after_the_first)
        assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
        monkeypatch.undo()
        answer = json.loads(capsys.readouterr().out)
        assert answer["state"] == "stop_failed" and answer["pids"] == [hung.pid]
        assert answer["error"] == "[Errno 2] No such file or directory: 'ps'"
        assert hung.wait(timeout=R2_STOP_TIMEOUT_SECONDS) < 0
        assert [row["state"] for row in launch.records()] == ["bound", "stop_failed"]
    finally:
        context.close()


# The child blocks on a latch. It does not sleep. The fixture must return on the report
# pipe, pipe EOF, or process exit. A three-second poll is the defect under test.
R2_HANDSHAKE_CHILD = """import json, os, select, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
slot, mode, field = sys.argv[2], sys.argv[3], sys.argv[4]

def emit(event, **values):
    raw = (json.dumps({"nonce": config["nonce"], "slot": slot, "event": event, **values}) + "\\n").encode()
    if os.write(config["report_write"], raw) != len(raw):
        sys.exit(71)

def hello():
    birth = Path("/proc/self/stat").read_bytes().rpartition(b")")[2].split()[19].decode()
    emit("hello", pid=os.getpid(), birth=birth)

def wait_fd(fd):
    while True:
        readable, _, _ = select.select([fd], [], [], None)
        if readable:
            return os.read(fd, 1)

def wait_gate():
    if wait_fd(config["nodes"][slot]["gate"]) != b"G":
        sys.exit(70)

def hold():
    wait_fd(config["safety_read"])
    sys.exit(0)

sys.stderr.write("\\x1b[31mtoken=supersecretvalue\\nr2-handshake-marker\\n")
sys.stderr.flush()
try:
    os.fsync(sys.stderr.fileno())
except OSError:
    pass
if mode == "exit" and field == "running":
    hello()
    wait_gate()
    sys.exit(7)
if mode == "exit":
    wait_fd(config["delay_read"])
    sys.exit(7)
if mode == "close" and field == "running":
    hello()
    wait_gate()
    wait_fd(config["delay_read"])
    os.close(config["report_write"])
    hold()
if mode == "close":
    wait_fd(config["delay_read"])
    os.close(config["report_write"])
    hold()
def ack():
    os.write(config["ack_write"], b"A")

if mode == "hang" and field == "running":
    hello()
    wait_gate()
    ack()
    hold()
if mode == "hang":
    ack()
    hold()
if mode == "slow" and field == "running":
    hello()
    wait_gate()
    wait_fd(config["delay_read"])
    emit("running")
    hold()
if mode == "slow":
    wait_fd(config["delay_read"])
    hello()
    wait_gate()
    emit("running")
    hold()
if mode == "partial":
    birth = Path("/proc/self/stat").read_bytes().rpartition(b")")[2].split()[19].decode()
    raw = (json.dumps({"nonce": config["nonce"], "slot": slot, "event": "hello", "pid": os.getpid(), "birth": birth}) + "\\n").encode()
    os.write(config["report_write"], raw[:3])
    ack()
    wait_fd(config["delay_read"])
    os.write(config["report_write"], raw[3:])
    wait_gate()
    emit("running")
    hold()
if mode == "garbage":
    os.write(config["report_write"], b"not-json supersecretvalue\\n")
    hold()
if mode == "flood":
    budget = config["flood_bytes"]
    if not isinstance(budget, int) or isinstance(budget, bool) or not 0 < budget <= 1048576:
        sys.exit(71)
    pending = budget
    report = config["report_write"]
    safety = config["safety_read"]
    os.set_blocking(report, False)
    while pending > 0:
        readable, writable, _ = select.select([safety], [report], [])
        if safety in readable:
            sys.exit(0)
        if report not in writable:
            continue
        try:
            wrote = os.write(report, b"Q" * min(4096, pending))
        except BlockingIOError:
            continue
        if wrote <= 0:
            sys.exit(71)
        pending -= wrote
    hold()
hello()
wait_gate()
emit("running")
hold()
"""


def _retire_parent_report_writer(custody):
    """Drop the fixture's report-pipe writer and keep its fd number occupied.

    The child still holds its own writer. Closing the number and leaving it free would let
    custody.close() close whatever was opened next. A /dev/null occupant preserves the number.
    """
    number = custody.report_write
    os.close(number)
    replacement = os.open(os.devnull, os.O_RDONLY)
    if replacement != number:
        os.dup2(replacement, number)
        os.close(replacement)


def _handshake_evidence(caught):
    message, payload = str(caught.value).split("\n", 1)
    return message, json.loads(payload)


def _read_ack(fd):
    """Block until the child says its bytes are in the pipe. The ceiling only bounds a hung child."""
    readable, _, _ = select.select([fd], [], [], R2_HANDSHAKE_CEILING_SECONDS)
    assert readable, "child did not acknowledge the handshake wait"
    assert os.read(fd, 1) == b"A"


def _expired_clock():
    """A clock that stays at zero until the handshake hook jumps it past the ceiling."""
    state = {"now": 0.0}

    def clock():
        return state["now"]

    def jump(_custody):
        state["now"] = 10 ** 9

    return clock, jump


def _start_handshake_child(custody, folder, slot, mode, field, latch_read, ack_write=None):
    script = folder / "handshake-child.py"
    if not script.exists():
        script.write_text(R2_HANDSHAKE_CHILD, encoding="utf-8")
    path = folder / ("handshake-%s.json" % slot)
    nodes = {slot: {"kind": "H", "parent": None, "child": None}}
    if slot not in custody.slots:
        custody.plan(nodes)
    extras = {"delay_read": latch_read, "flood_bytes": R2_CONTROL_LINE_LIMIT + 1}
    if ack_write is not None:
        extras["ack_write"] = ack_write
    data = custody.config(nodes, script, path, **extras)
    data["inherited"].append(latch_read)
    if ack_write is not None:
        data["inherited"].append(ack_write)
    path.write_text(json.dumps(data), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return custody.launch(data, slot, env, extra=(mode, field))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("field", ["hello", "running"])
@pytest.mark.parametrize("mode", ["prompt", "slow", "exit", "close", "hang"])
def test_r2_handshake_follows_the_child_signal(tmp_path, field, mode):
    """A live child that announces on its latch must pass.

    A child that exits or closes the report pipe fails with that evidence.
    A child that never announces fails when the ceiling clock expires, after it has
    acknowledged that its stderr is already written.
    """
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        process = _start_handshake_child(custody, tmp_path, "actor", mode, field, latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        if mode == "close":
            _retire_parent_report_writer(custody)
        if field == "running" and mode in ("prompt", "slow", "exit", "close", "hang"):
            custody.await_event("actor", "hello")
            custody.release("actor")
            if mode == "exit":
                _wait_unreaped(process, custody.entries["actor"].get("fd"))
        assert R2_HANDSHAKE_CEILING_SECONDS >= 60
        if mode == "slow":
            # The old defect returned at a 3s poll. Release only after this wait blocks,
            # and only once a controlled clock is past that bound and still under the ceiling.
            waited = {"blocked": 0, "now": 0.0, "released": False}

            def clock():
                return waited["now"]

            real_block = R2Custody._block_for_handshake

            def blocking(slot, remaining):
                assert custody.slots["actor"][field] is False
                waited["blocked"] += 1
                waited["now"] = 4.0
                if not waited["released"]:
                    os.write(latch_write, b"X")
                    waited["released"] = True
                return real_block(custody, slot, remaining)

            custody._block_for_handshake = blocking
            custody.await_event("actor", field, clock=clock)
            assert waited["blocked"] >= 1 and waited["released"] is True
            assert waited["now"] > 3.0
            assert custody.slots["actor"][field] is True
            return
        if mode == "prompt":
            custody.await_event("actor", field)
            assert custody.slots["actor"][field] is True
            return
        if mode == "hang":
            _read_ack(ack_read)
            clock, jump = _expired_clock()
            with pytest.raises(RuntimeError) as caught:
                custody.await_event("actor", field, clock=clock, before_terminal=jump)
            message, evidence = _handshake_evidence(caught)
            assert message == "R2 fixture: %s handshake refused: ceiling" % field
            assert evidence["reason"] == "ceiling" and evidence["returncode"] is None
            assert "supersecretvalue" not in evidence["stderr"] and "\x1b" not in evidence["stderr"]
            assert "r2-handshake-marker" in evidence["stderr"]
            assert "\n" in evidence["stderr"]
            return
        if mode == "exit" and field == "hello":
            os.write(latch_write, b"X")
        if mode == "close":
            os.write(latch_write, b"X")
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", field)
        message, evidence = _handshake_evidence(caught)
        assert "bounded" not in message
        assert "timeout" not in message.lower()
        assert evidence["slot"] == "actor" and evidence["field"] == field
        assert "supersecretvalue" not in message and "supersecretvalue" not in evidence["stderr"]
        assert "r2-handshake-marker" in evidence["stderr"]
        assert "\n" in evidence["stderr"]
        assert "\x1b" not in evidence["stderr"]
        if mode == "exit":
            assert message == "R2 fixture: %s handshake refused: child exited" % field
            assert evidence["reason"] == "child exited" and evidence["returncode"] == 7
        else:
            assert message == "R2 fixture: %s handshake refused: report pipe closed" % field
            assert evidence["reason"] == "report pipe closed" and evidence["returncode"] is None
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        try:
            if custody.report is None:
                custody.close()
        except R2CleanupError:
            _clear_r2_quarantine()
            raise
        _clear_r2_quarantine()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_child_ready_wait_accepts_a_late_signal_and_fails_fast():
    """The started-file wait uses the same ceiling: a later signal, an exit, a jumped clock."""

    class ReadyChild:
        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

    waited = {"now": 0.0, "slept": 0, "ready": False}

    def clock():
        return waited["now"]

    def sleeper(seconds):
        assert waited["ready"] is False
        waited["slept"] += 1
        waited["now"] = 4.0
        waited["ready"] = True

    assert r2_wait_child_ready(
        ReadyChild(), lambda: waited["ready"], R2_HANDSHAKE_CEILING_SECONDS, clock=clock, sleeper=sleeper,
    ) is True
    assert waited["slept"] >= 1 and waited["now"] > 3.0

    dead = ReadyChild()
    dead.returncode = 9
    assert r2_wait_child_ready(dead, lambda: False, R2_HANDSHAKE_CEILING_SECONDS) is False

    reads = {"n": 0}

    def advancing():
        reads["n"] += 1
        if reads["n"] > 2:
            return 10 ** 9
        return 0

    assert r2_wait_child_ready(ReadyChild(), lambda: False, 60, clock=advancing) is False
    assert reads["n"] > 2


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_handshake_partial_line_waits_for_the_rest(tmp_path):
    """A split hello is not an announcement. The wait resumes when the newline arrives."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        _start_handshake_child(custody, tmp_path, "actor", "partial", "hello", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        _read_ack(ack_read)
        assert custody.pump() is False
        assert custody.slots["actor"]["hello"] is False
        assert b"\n" not in custody.buffer and custody.buffer
        os.write(latch_write, b"X")
        custody.await_event("actor", "hello")
        assert custody.slots["actor"]["hello"] is True
        assert custody.slots["actor"]["running"] is False
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        custody.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_handshake_two_children_share_the_report_pipe(tmp_path):
    """One child's hello does not satisfy the other child's wait."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    try:
        custody.plan({"north": {"kind": "H", "parent": None, "child": None},
                      "south": {"kind": "H", "parent": None, "child": None}})
        _start_handshake_child(custody, tmp_path, "north", "prompt", "hello", latch_read)
        _start_handshake_child(custody, tmp_path, "south", "prompt", "hello", latch_read)
        custody.await_event("north", "hello")
        custody.await_event("south", "hello")
        assert custody.slots["north"]["running"] is False and custody.slots["south"]["running"] is False
        custody.release("north")
        custody.await_event("north", "running")
        assert custody.slots["south"]["running"] is False
        custody.release("south")
        custody.await_event("south", "running")
        assert custody.slots["north"]["running"] is True and custody.slots["south"]["running"] is True
    finally:
        for fd in (latch_read, latch_write):
            try:
                os.close(fd)
            except OSError:
                pass
        custody.close()


def _close_fds(*fds):
    for fd in fds:
        if isinstance(fd, int) and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("mode", ["garbage", "flood"])
def test_r2_handshake_refuses_a_hostile_report_without_echoing_it(tmp_path, mode):
    """A hostile report is a fixed refusal. The bytes are not part of the error.

    Flood delivers one byte past the line limit, waiting for the pipe to drain.
    Closure stays UNKNOWN and does not keep the payload.
    """
    reason = {"garbage": "R2 fixture: control message refused",
              "flood": "R2 fixture: control message exceeds its bound"}[mode]
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    try:
        _start_handshake_child(custody, tmp_path, "actor", mode, "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        stored = json.loads((tmp_path / "handshake-actor.json").read_text(encoding="utf-8"))
        assert stored["flood_bytes"] == R2_CONTROL_LINE_LIMIT + 1
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        message = str(caught.value)
        assert message == reason
        assert "supersecretvalue" not in message
        assert "QQQQ" not in message
        assert custody.control_unknown is True
        assert custody.buffer == b""
        with pytest.raises(R2CleanupUnknown) as closed:
            custody.close()
        report = closed.value.report
        assert report["state"] == "UNKNOWN"
        assert reason in report["errors"]
        _assert_exit_proofs(report)
        blob = json.dumps(report)
        assert "supersecretvalue" not in blob and "QQQQ" not in blob
    finally:
        _close_fds(latch_read, latch_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("case,kind", [("silent-never", "W"), ("silent-before", "W"), ("silent-after", "W"),
                                      ("forged-identity", "W"), ("actor-only", "M"), ("retirement-failure", "W")]
                         + [(event, kind) for event in ("reaped", "wait_unavailable") for kind in "HMWCR"])
def test_r2_closure_requires_independent_evidence_for_exposed_workers(tmp_path, monkeypatch, case, kind):
    require_r2_indirect_exit(pidfd=case in ("reaped", "wait_unavailable"))
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    actor_read, actor_write = os.pipe()
    stop_read, stop_write = os.pipe()
    receipt_read, receipt_write = os.pipe()
    witness = None
    real_os, candidate_fds = handshake_tests.os, []

    def candidate_pidfd(pid, *args):
        fd = real_os.pidfd_open(pid, *args)
        candidate_fds.append(fd)
        return fd

    try:
        before = case in ("silent-before", "actor-only")
        nodes = {"actor": {"kind": "H", "parent": None, "child": "worker" if before else None},
                 "worker": {"kind": kind, "parent": "actor", "child": None}}
        custody.plan(nodes, fixture_only=tuple(nodes))
        script, path = tmp_path / "worker.py", tmp_path / "worker.json"
        script.write_text(R2_UNREPORTED_WORKER)
        handed_nodes = {"actor": {"kind": "H", "parent": None, "child": None}} if case == "actor-only" else nodes
        config = custody.config(handed_nodes, script, path, actor_exit=actor_read, worker_stop=stop_read,
                                 worker_receipt=receipt_write, silent=case != "actor-only", ungranted=not before)
        config["inherited"].extend((actor_read, stop_read, receipt_write))
        path.write_text(json.dumps(config))
        actor = custody.launch(config, "actor", os.environ)
        _close_fds(actor_read, stop_read, receipt_write)
        actor_read = stop_read = receipt_write = -1
        custody.await_event("actor", "hello")
        if case == "actor-only":
            assert custody.slot_provenance["worker"]["handed_to_actor"] is True
        if before:
            custody.release("actor")
        worker_pid = _r2_read_worker_receipt(receipt_read)
        witness = _r2_independent_worker_witness(custody, "worker", worker_pid)
        if before:
            assert custody.slot_provenance["worker"]["handed_to_actor"] is True
        if case in ("silent-after", "forged-identity"):
            custody.release("actor")
            intent = (json.dumps(dict(nonce=custody.nonce, slot="actor", event="creation_intent",
                                      child="worker")) + "\n").encode()
            assert os.write(custody.report_write, intent) == len(intent)
            custody.pump()
        if case == "forged-identity":
            if hasattr(real_os, "pidfd_open"):
                monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=candidate_pidfd))
            raw = (json.dumps(dict(nonce=custody.nonce, slot="actor", event="created", child="worker",
                                   child_pid=1, child_birth="9")) + "\n").encode()
            assert os.write(custody.report_write, raw) == len(raw)
            with pytest.raises(RuntimeError):
                custody.pump()
            assert "worker" not in custody.entries
            for fd in candidate_fds:
                with pytest.raises(OSError):
                    real_os.fstat(fd)
            monkeypatch.setattr(handshake_tests, "os", real_os)
        if case in ("reaped", "wait_unavailable"):
            custody.capture("worker", worker_pid, birth=witness.entries["worker"]["birth"])
            claim = dict(nonce=custody.nonce, slot="actor", event=case, child="worker",
                         child_pid=worker_pid, child_birth=witness.entries["worker"]["birth"])
            if case == "reaped":
                claim.update(wait_pid=worker_pid, wait_status=0, returncode=0)
            raw = (json.dumps(claim) + "\n").encode()
            assert os.write(custody.report_write, raw) == len(raw)
            custody.pump()
            assert custody.entries["worker"]["exit"] is None
            assert custody.entries["worker"].get("wait_status") is None
            assert custody.observe("worker") is None
            assert custody.messages[-1]["event"] == case
        os.write(actor_write, b"X")
        assert actor.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
        if case == "retirement-failure":
            def refuse_retirement(*args, **kwargs):
                raise OSError("modelled report-writer retirement failure")
            monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, dup2=refuse_retirement))
        if case.startswith("silent-") or case in ("forged-identity", "actor-only", "retirement-failure"):
            custody.LIMIT = 0.1  # A genuinely unaccounted slot must return UNKNOWN, not wait forever.
            with pytest.raises(R2CleanupUnknown) as caught:
                custody.close()
            assert "worker" in caught.value.report["unresolved_slots"]
            assert caught.value.report["uncreated_slots"] == []
            if case == "retirement-failure":
                assert "R2 fixture: report writer retirement failed" in caught.value.report["errors"]
                assert caught.value.report["post_exit_drain"]["complete"] is False
            assert R2Custody.observe(witness, "worker") is None
            _clear_r2_quarantine(custody, expected_unknown=True)
            assert R2Custody.quarantine_report is caught.value.report
            with pytest.raises(R2CleanupUnknown):
                R2Custody(tmp_path / "blocked", tmp_path / "blocked.json")
        else:
            report = custody.close()
            assert report["state"] == "CLOSED"
            assert report["entries"]["worker"]["exit"]["proof"] in (
                "original_pidfd_exit", "native_waitpid")
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        _close_fds(actor_read, actor_write, stop_read, stop_write, receipt_read, receipt_write)
        if witness is not None:
            proof = _r2_wait_worker_exit(witness, "worker")
            entry = custody.entries.get("worker")
            if entry is not None:
                r2_identity_transition(entry, "adopt_exit", source=witness.entries["worker"])
            if custody.report is not None:
                _retain_r2_independent_exit(custody, "worker", witness)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        if witness is not None:
            _retain_r2_independent_exit(custody, "worker", witness)
            r2_identity_transition(witness.entries["worker"], "release")
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("grant", ["release", "intent"])
def test_r2_permission_grants_revoke_synthetic_exemptions(tmp_path, monkeypatch, grant):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": "worker" if grant == "release" else None},
                 "worker": {"kind": "W", "parent": "actor", "child": None}}
        custody.plan(nodes, fixture_only=tuple(nodes))
        custody.slots["actor"].update(hello=True, permitted=True)
        custody.entries["actor"] = r2_pending_test_entry(os.getpid(), "1", process=None)
        assert custody.slot_provenance["worker"]["handed_to_actor"] is False
        custody.release("actor")
        if grant == "intent":
            raw = (json.dumps(dict(nonce=custody.nonce, slot="actor", event="creation_intent",
                                   child="worker")) + "\n").encode()
            assert os.write(custody.report_write, raw) == len(raw)
            custody.pump()
        assert custody.slot_provenance["worker"]["handed_to_actor"] is True
        custody.LIMIT = 0.01
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is caught.value.report
    finally:
        # No actor was spawned; only this actorless negative model's state is restored.
        _release_r2_test_descriptors(custody)


@pytest.mark.parametrize("kind", list("HMWCR"))
def test_r2_protocol_proof_never_retires_quarantine(kind):
    report = {"entries": {"worker": {"pid": 7, "birth": "1", "kind": kind,
                "exit": {"proof": "parent_Popen_wait", "wait_pid": 7, "wait_status": 0, "returncode": 0}}},
              "slot_provenance": {"worker": {"fixture_created": True, "fixture_only": False,
                                               "handed_to_actor": True}},
              "unresolved_slots": [], "uncreated_slots": []}
    assert _captured_exit_proven(report) is False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("case", ["permission", "uid-zombie", "euid-zombie", "capture-uid", "capture-euid"])
def test_r2_argon_metadata_conflicts_cannot_be_repaired_by_absence(tmp_path, monkeypatch, case):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    real_os, real_kernel = handshake_tests.os, handshake_tests.r2_kernel_process
    physical = real_kernel(os.getpid())
    reads, kills = [], []

    def metadata(pid):
        reads.append(pid)
        if len(reads) == 1 and case != "permission":
            changed = dict(physical, ppid=os.getpid(), state="Z")
            field = "euid" if "euid" in case else "uid"
            changed[field] += 1
            return changed
        raise FileNotFoundError("modelled unavailable proc metadata")

    def numeric(pid, number):
        assert number == 0  # The actorless model never grants signal authority over this test process.
        kills.append(pid)
        if case == "permission" and len(kills) == 1:
            raise PermissionError("modelled denied identity probe")
        raise ProcessLookupError("modelled later numeric absence")

    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}})
        custody.slots["actor"]["permitted"] = True
        custody.entries["actor"] = r2_pending_test_entry(os.getpid(), physical["birth"], process=None)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", metadata)
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, kill=numeric))
        if case.startswith("capture-"):
            raw = (json.dumps(dict(nonce=custody.nonce, slot="actor", event="hello",
                                   pid=os.getpid(), birth=physical["birth"])) + "\n").encode()
            assert os.write(custody.report_write, raw) == len(raw)
            with pytest.raises(RuntimeError, match="^R2 fixture: physical birth/UID/parent mismatch$"):
                custody.pump()
        else:
            assert custody.observe("actor") is None
        assert custody.observe("actor") is None
        assert custody.entries["actor"]["lost"] and custody.control_unknown
        assert len(reads) == 1
        custody.kill_owned = lambda slot: None
        custody.LIMIT = 0.01
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["entries"]["actor"]["exit"] is None
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is caught.value.report
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_direct_exit_before_intake_is_reaped_through_retained_popen(tmp_path):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    process = None
    try:
        process = _start_handshake_child(custody, tmp_path, "actor", "exit", "running", latch_read)
        assert os.write(custody.gates["actor"][1], b"G") == 1
        _wait_unreaped(process, custody.entries["actor"]["fd"])
        assert process.native_wait_evidence is None
        custody.await_event("actor", "hello")
        assert process.native_wait_evidence is not None
        assert process.native_wait_evidence["wait_pid"] == process.pid
        assert process.returncode == 7
        report = custody.close()
        assert report["entries"]["actor"]["exit"]["proof"] == "native_waitpid"
        assert report["entries"]["actor"]["exit"]["returncode"] == 7
    finally:
        _close_fds(latch_read, latch_write)
        if process is not None:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_handshake_refusal_ignores_a_replaced_stderr(tmp_path):
    """Stderr is opened from the custody directory fd. A swapped symlink is not read."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    try:
        _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        stderr_path = tmp_path / "custody" / "actor.stderr"
        stderr_path.unlink()
        planted = tmp_path / "planted-stderr"
        planted.write_bytes(b"linked-only-marker\ntoken=supersecretvalue\n")
        symlink_or_skip(planted, stderr_path)
        os.write(latch_write, b"X")
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        message, evidence = _handshake_evidence(caught)
        assert message == "R2 fixture: hello handshake refused: child exited"
        assert evidence["returncode"] == 7
        assert "linked-only-marker" not in message and "linked-only-marker" not in evidence["stderr"]
        assert "supersecretvalue" not in message and "supersecretvalue" not in evidence["stderr"]
        assert b"linked-only-marker" in planted.read_bytes()
    finally:
        _close_fds(latch_read, latch_write)
        custody.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_handshake_refusal_bounds_stderr_before_reading_it(tmp_path):
    """A captured stderr larger than the cap is omitted, not parsed or echoed."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    source = None
    try:
        _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        stderr_path = tmp_path / "custody" / "actor.stderr"
        source = os.open(os.fspath(stderr_path), os.O_WRONLY | os.O_CLOEXEC)
        blob = b"token=supersecretvalue\n" + (b"Q" * 70000)
        view = memoryview(blob)
        while view:
            wrote = os.write(source, view)
            if wrote <= 0:
                break
            view = view[wrote:]
        os.close(source)
        source = None
        os.write(latch_write, b"X")
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        message, evidence = _handshake_evidence(caught)
        assert message == "R2 fixture: hello handshake refused: child exited"
        assert evidence["stderr"] == "[stderr omitted: too_large]"
        assert "supersecretvalue" not in message
        assert "QQQQ" not in message
    finally:
        if isinstance(source, int):
            os.close(source)
        _close_fds(latch_read, latch_write)
        custody.close()


@pytest.mark.skipif(os.name != "posix", reason="custody stderr requires directory descriptors")
@pytest.mark.parametrize("kind", ["regular", "symlink", "fifo", "missing", "large"])
def test_r2_stderr_tail_reads_only_bounded_regular_slot_files(tmp_path, kind):
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        pytest.skip("custody stderr requires no-follow directory descriptors")
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    path = custody.folder / "actor.stderr"
    custody.stderr_paths["actor"] = path
    try:
        if kind == "regular":
            path.write_text("head-marker\n" + "Q" * 5000 + "\nｔｏｋｅｎ=supersecretvalue\ntail-marker\n")
        elif kind == "symlink":
            outside = tmp_path / "outside"
            outside.write_text("outside-marker\n")
            symlink_or_skip(outside, path)
        elif kind == "fifo":
            os.mkfifo(path)
        elif kind == "large":
            path.write_bytes(b"Q" * (R2_CONTROL_LINE_LIMIT + 1))
        for _ in range(2):
            tail = custody.stderr_tail()
            assert "outside-marker" not in tail and "supersecretvalue" not in tail
            if kind == "regular":
                assert tail.startswith("actor.stderr:\n") and tail.endswith("tail-marker\n")
                assert "head-marker" not in tail and len(tail.split(":\n", 1)[1]) <= 4096
            else:
                expected = {"fifo": "[stderr omitted: unsafe]", "large": "[stderr omitted: too_large]"}
                assert tail == "actor.stderr:\n" + expected.get(kind, "")
    finally:
        custody.close()


@pytest.mark.skipif(os.name != "posix", reason="custody stderr requires directory descriptors")
@pytest.mark.parametrize("race", ["directory", "leaf", "read-error"])
def test_r2_stderr_tail_keeps_its_anchor_and_closes_reads(tmp_path, monkeypatch, race):
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        pytest.skip("custody stderr requires no-follow directory descriptors")
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    path = custody.folder / "actor.stderr"
    path.write_text("real-marker\n")
    custody.stderr_paths["actor"] = path
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / path.name).write_text("outside-marker\n")
    real_os, opened = handshake_tests.os, []

    def opening(name, flags, **kwargs):
        assert name == "actor.stderr" and kwargs == {"dir_fd": custody.folder_fd}
        assert flags & real_os.O_NOFOLLOW and flags & real_os.O_NONBLOCK
        fd = real_os.open(name, flags, **kwargs)
        opened.append(fd)
        return fd

    def reading(*args):
        if race == "read-error":
            raise OSError("token=supersecretvalue")
        if race == "leaf":
            path.unlink()
            symlink_or_skip(outside / path.name, path)
        return real_os.read(*args)

    try:
        if race == "directory":
            custody.folder.rename(tmp_path / "moved")
            symlink_or_skip(outside, custody.folder)
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, open=opening, read=reading))
        assert custody.stderr_tail() == "actor.stderr:\n" + ("" if race == "read-error" else "real-marker\n")
        for fd in opened:
            with pytest.raises(OSError):
                real_os.fstat(fd)
        assert custody.stderr_tail() == "actor.stderr:\n" + ("real-marker\n" if race == "directory" else "")
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        custody.close()


def test_r2_stderr_tail_omits_content_without_descriptor_support(tmp_path, monkeypatch):
    from types import SimpleNamespace

    path = tmp_path / "actor.stderr"
    path.write_text("outside-marker\n")
    custody = SimpleNamespace(folder_fd=123, stderr_paths={"actor": path})
    custody._bounded_stderr = lambda *args, **kwargs: R2Custody._bounded_stderr(custody, *args, **kwargs)
    monkeypatch.setattr(handshake_tests, "_r2_slot_read_capable", lambda: False)
    assert R2Custody.stderr_tail(custody) == "actor.stderr:\n"


def _captured_exit_proven(report):
    """Every slot has exit evidence or a positive, unexposed fixture-only origin."""
    entries = report.get("entries") if isinstance(report, dict) else None
    provenance = report.get("slot_provenance") if isinstance(report, dict) else None
    if not isinstance(entries, dict) or not isinstance(provenance, dict):
        return False
    for row in entries.values():
        if not isinstance(row, dict) or row.get("lost"):
            return False
        exit_row = row.get("exit")
        if not isinstance(exit_row, dict) or exit_row.get("proof") not in (
                "native_waitpid", "original_pidfd_exit"):
            return False
        if exit_row["proof"] == "native_waitpid":
            status = exit_row.get("wait_status")
            if (exit_row.get("wait_pid") != row.get("pid") or type(status) is not int or
                    not 0 <= status <= 0xffffffff or not (os.WIFEXITED(status) or os.WIFSIGNALED(status)) or
                    exit_row.get("returncode") != os.waitstatus_to_exitcode(status)):
                return False
    slots = set(provenance) | set(report.get("unresolved_slots", ())) | set(report.get("uncreated_slots", ()))
    for slot in slots - set(entries):
        origin = provenance.get(slot, {})
        if not (origin.get("fixture_created") is True and origin.get("fixture_only") is True and
                origin.get("handed_to_actor") is False):
            return False
    return True


def _clear_r2_quarantine(custody=None, expected_unknown=False):
    """Retire expected uncertainty only after every slot is independently accounted for.

    A cleanup that cannot prove an actor's exit keeps the quarantine. The next
    constructor then refuses to admit anyone.
    """
    report = R2Custody.quarantine_report
    if report is not None:
        if custody is not None and report is custody.report:
            custody._unaccounted_reservations()
            report["slot_provenance"] = {slot: dict(row) for slot, row in custody.slot_provenance.items()}
            for slot, entry in custody.entries.items():
                report["entries"][slot] = r2_entry_record(entry)
        if (not expected_unknown or custody is None or report is not custody.report or
                not _captured_exit_proven(report)):
            return
        _release_r2_test_descriptors(custody)
    R2Custody.quarantine_report = None


def _release_r2_test_descriptors(custody):
    """Release a retired test scope's handles; close() already closed safety_write.

    The quarantine decision stays with the caller. This also serves explicitly
    actorless negative models, which never owned a real child.
    """
    released = getattr(custody, "_hook_released_fds", set())
    custody._hook_released_fds = released
    for entry in custody.entries.values():
        fd = entry.get("fd")
        r2_identity_transition(entry, "release")
        if isinstance(fd, int):
            released.add(fd)
        process = entry.get("process")
        if isinstance(process, WitnessedPopen):
            process.close_native_handle()
        for stream in (getattr(process, "stdin", None), getattr(process, "stdout", None),
                       getattr(process, "stderr", None)):
            if stream is not None:
                stream.close()
    fds = [custody.safety_read, custody.report_read, custody.report_write,
           *(fd for pair in custody.gates.values() for fd in pair)]
    if custody.report is None:
        fds.append(custody.safety_write)
    for fd in fds:
        if isinstance(fd, int) and fd not in released:
            released.add(fd)
            _close_fds(fd)
    custody._close_folder_fd()


def _assert_exit_proofs(report):
    assert _captured_exit_proven(report)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_rejected_report_keeps_the_reserved_child_unknown(tmp_path):
    """A bad frame followed by a reserved child's lines must not close as CLOSED.

    The later lines are not trusted. The unrelated fixture-only slot stays
    unresolved in the refused stream; live descendant tests cover actual forks.
    """
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    try:
        _plan_reserved_sibling(custody)
        _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        intent = json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "creation_intent",
                              "child": "worker"})
        created = json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "created",
                               "child": "worker", "child_pid": 1, "child_birth": "9"})
        os.write(custody.report_write, ("[]\n%s\n%s\n" % (intent, created)).encode())
        os.write(latch_write, b"X")
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        assert str(caught.value) == "R2 fixture: control message refused"
        assert "[]" not in str(caught.value)
        assert "child_birth" not in str(caught.value)
        with pytest.raises(R2CleanupUnknown) as closed:
            custody.close()
        report = closed.value.report
        assert report["state"] == "UNKNOWN"
        assert "worker" in report["unresolved_slots"]
        assert "worker" not in report["uncreated_slots"]
        assert report["errors"] == ["R2 fixture: control message refused"]
        _assert_exit_proofs(report)
        assert "[]" not in "".join(report["errors"])
        assert "child_birth" not in json.dumps(report)
        assert R2Custody.quarantine_report is report
    finally:
        _close_fds(latch_read, latch_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_report_stream_stops_at_the_byte_bound(tmp_path):
    """Exactly one line-limit of bytes is still waiting. One more byte is a refusal."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}}, fixture_only=("actor",))
        view = memoryview(b"Q" * R2_CONTROL_LINE_LIMIT)
        while view:
            wrote = os.write(custody.report_write, view[:4096])
            assert wrote > 0
            view = view[wrote:]
            custody.pump()
        assert custody.buffer == b"Q" * R2_CONTROL_LINE_LIMIT
        assert custody.report_rejected is False
        os.write(custody.report_write, b"Q")
        with pytest.raises(RuntimeError) as one_past:
            custody.pump()
        assert str(one_past.value) == "R2 fixture: control message exceeds its bound"
        assert "Q" not in str(one_past.value)
        assert custody.control_unknown is True
        assert custody.buffer == b""
    finally:
        try:
            custody.close()
        except R2CleanupUnknown:
            pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_newline_does_not_unlock_the_read_budget(tmp_path):
    """A leading newline must not let one pump swallow an unbounded hostile stream."""
    import fcntl

    custody = R2Custody(tmp_path / "stream", tmp_path / "stream-quarantine.json")
    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}}, fixture_only=("actor",))
        set_size = getattr(fcntl, "F_SETPIPE_SZ", 1031)
        try:
            fcntl.fcntl(custody.report_write, set_size, R2_CONTROL_LINE_LIMIT * 4)
        except OSError:
            pytest.skip("report pipe capacity cannot be raised")
        payload = b"\n" + (b"Q" * (R2_CONTROL_LINE_LIMIT * 2))
        view = memoryview(payload)
        while view:
            wrote = os.write(custody.report_write, view[:65536])
            assert wrote > 0
            view = view[wrote:]
        with pytest.raises(RuntimeError) as caught:
            custody.pump()
        assert str(caught.value) == "R2 fixture: control message refused"
        assert "QQQQ" not in str(caught.value)
        assert custody.control_unknown is True
        os.set_blocking(custody.report_read, False)
        try:
            leftover = os.read(custody.report_read, 65536)
        except BlockingIOError:
            leftover = b""
        assert len(leftover) > 0
    finally:
        try:
            custody.close()
        except R2CleanupUnknown:
            pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_child_ready_rechecks_the_signal_after_exit():
    """Exit observed between the predicate and poll must not hide a signal that landed."""

    class ReadyChild:
        def __init__(self):
            self.returncode = None

        def poll(self):
            return self.returncode

    flag = {"ready": False}

    class AnnounceOnExit(ReadyChild):
        def poll(self):
            flag["ready"] = True
            self.returncode = 4
            return 4

    assert r2_wait_child_ready(AnnounceOnExit(), lambda: flag["ready"], R2_HANDSHAKE_CEILING_SECONDS) is True

    dead = ReadyChild()
    dead.returncode = 9
    assert r2_wait_child_ready(dead, lambda: False, R2_HANDSHAKE_CEILING_SECONDS) is False

    # The deadline is sampled once. Advancing the clock on later reads is the ceiling.
    reads = {"n": 0}

    def advancing():
        reads["n"] += 1
        if reads["n"] > 2:
            return 10 ** 9
        return 0

    alive = ReadyChild()
    assert r2_wait_child_ready(alive, lambda: False, 60, clock=advancing) is False


def _wait_unreaped(process, extra_fd=None):
    """Wait until the original child is dead without consuming its wait status."""
    fds = []
    handle = getattr(process, "native_handle", None)
    if isinstance(handle, int):
        fds.append(handle)
    if isinstance(extra_fd, int) and extra_fd not in fds:
        fds.append(extra_fd)
    if fds:
        poller = select.poll()
        for fd in fds:
            poller.register(fd, select.POLLIN)
        assert poller.poll(int(R2_HANDSHAKE_CEILING_SECONDS * 1000)), "child did not exit"
        return
    if hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
        deadline = time.monotonic() + R2_HANDSHAKE_CEILING_SECONDS
        while True:
            info = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if info is not None:
                return
            if time.monotonic() >= deadline:
                raise AssertionError("child did not exit")
            time.sleep(0.01)
        return
    deadline = time.monotonic() + R2_HANDSHAKE_CEILING_SECONDS
    while True:
        info = r2_kernel_process(process.pid)
        if info["state"].startswith("Z"):
            return
        if time.monotonic() >= deadline:
            raise AssertionError("child did not exit")
        time.sleep(0.01)


def _drop_indirect_handles(custody, slot, process):
    """Hide the direct process and its pidfds so exit detection has to observe."""
    entry = custody.entries[slot]
    closed = []
    retained_fd = entry.get("fd")
    r2_identity_transition(entry, "release")
    for fd in (getattr(process, "native_handle", None),):
        if fd == retained_fd:
            continue
        if isinstance(fd, int) and fd not in closed:
            try:
                os.close(fd)
            except OSError:
                pass
            closed.append(fd)
    entry["process"] = None
    process.native_handle = None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_queued_announcement_survives_the_child_exit(tmp_path):
    """A running line written as the child exits is the announcement, not an exit refusal."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        process = _start_handshake_child(
            custody, tmp_path, "actor", "hang", "running", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        custody.await_event("actor", "hello")
        custody.release("actor")
        _read_ack(ack_read)

        def queue_then_exit(active):
            raw = (json.dumps({"nonce": active.nonce, "slot": "actor", "event": "running"}) + "\n").encode()
            assert os.write(active.report_write, raw) == len(raw)
            process.send_signal(signal.SIGKILL)
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)

        custody.await_event("actor", "running", before_terminal=queue_then_exit)
        assert custody.slots["actor"]["running"] is True
        report = custody.close()
        assert report["state"] == "CLOSED"
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_exit_status_is_reported_after_the_pidfd_wakes(tmp_path):
    """pidfd can show the exit before the first waitpid stores the status."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    calls = {"n": 0}
    try:
        process = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        os.write(latch_write, b"X")
        _wait_unreaped(process, custody.entries["actor"].get("fd"))
        assert r2_kernel_process(process.pid)["state"].startswith("Z")
        real = process.poll

        def wrapped():
            calls["n"] += 1
            if calls["n"] == 1:
                return None
            return real()

        process.poll = wrapped
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        message, evidence = _handshake_evidence(caught)
        assert message == "R2 fixture: hello handshake refused: child exited"
        assert evidence["reason"] == "child exited"
        assert evidence["returncode"] == 7
        assert calls["n"] >= 2
        report = custody.close()
        assert report["state"] == "CLOSED"
    finally:
        _close_fds(latch_read, latch_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_indirect_exit_without_pidfd_is_not_a_ceiling(tmp_path):
    """An indirect child with no pidfd still reports the exit it can see.

    The status is the observed proof. It is not an invented return code and not the ceiling.
    """
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    try:
        process = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        os.write(latch_write, b"X")
        _wait_unreaped(process, custody.entries["actor"].get("fd"))
        assert r2_kernel_process(process.pid)["state"].startswith("Z")
        _drop_indirect_handles(custody, "actor", process)
        clock, jump = _expired_clock()
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello", clock=clock, before_terminal=jump)
        message, evidence = _handshake_evidence(caught)
        assert message == "R2 fixture: hello handshake refused: child exited"
        assert evidence["reason"] == "child exited"
        assert evidence["returncode"] == 7
        assert evidence["exit_proof"] == "native_waitpid"
        assert "ceiling" not in message
        report = custody.close()
        assert report["state"] == "CLOSED"
    finally:
        _close_fds(latch_read, latch_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine()


def _plan_reserved_sibling(custody):
    """An unrelated fixture-only root stays unexposed to the one-actor script.

    Actual descendant regressions reserve their real parent links explicitly;
    launch revokes every exemption below those actors, even for omitted slots.
    """
    custody.plan({"actor": {"kind": "H", "parent": None, "child": None},
                  "worker": {"kind": "M", "parent": None, "child": None}},
                 fixture_only=("actor", "worker"))


def _assert_refused_sibling(custody, reason):
    assert custody.control_unknown is True
    with pytest.raises(R2CleanupUnknown) as closed:
        custody.close()
    report = closed.value.report
    assert report["state"] == "UNKNOWN"
    assert reason in report["errors"]
    assert "worker" in report["unresolved_slots"]
    assert "worker" not in report["uncreated_slots"]
    blob = json.dumps(report)
    assert "supersecretvalue" not in blob and "QQQQ" not in blob
    _assert_exit_proofs(report)
    return report


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("kind", ["encoding", "nesting", "missing", "type", "protocol", "empty"])
def test_r2_every_intake_refusal_keeps_custody_unknown(tmp_path, kind, monkeypatch):
    """Every decoder, schema, and protocol failure leaves the reserved sibling unresolved."""

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        _plan_reserved_sibling(custody)
        secret = "supersecretvalue"
        parsed_deep = []
        if kind == "encoding":
            frame = b"\xff\xfe" + secret.encode() + b"\n"
            reason = "R2 fixture: control message refused"
        elif kind == "nesting":
            depth = R2_CONTROL_MAX_DEPTH + 1
            frame = (b"[" * depth) + (b"]" * depth) + b"\n"
            reason = "R2 fixture: control message refused"

            real_loads, real_dumps, real_error = json.loads, json.dumps, json.JSONDecodeError

            def refuse_parse(text, *args, **kwargs):
                if isinstance(text, str) and text.count("[") > R2_CONTROL_MAX_DEPTH:
                    parsed_deep.append(True)
                    raise RecursionError("parsed a frame past the depth cap")
                return real_loads(text, *args, **kwargs)

            monkeypatch.setattr(handshake_tests, "json", type("GuardJSON", (), {
                "loads": staticmethod(refuse_parse),
                "dumps": staticmethod(real_dumps),
                "JSONDecodeError": real_error,
            })())
        elif kind == "missing":
            frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "pad": secret}) + "\n").encode()
            reason = "R2 fixture: control message refused"
        elif kind == "empty":
            frame = b"{}\n"
            reason = "R2 fixture: control message refused"
        elif kind == "type":
            frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": 1, "pad": secret}) + "\n").encode()
            reason = "R2 fixture: control message refused"
        else:
            frame = (json.dumps({"nonce": "not-the-nonce", "slot": "actor", "event": "timeout",
                                 "pad": secret}) + "\n").encode()
            reason = "R2 fixture: unplanned control message"
        os.write(custody.report_write, frame)
        with pytest.raises(RuntimeError) as caught:
            custody.pump()
        assert str(caught.value) == reason
        assert secret not in str(caught.value)
        assert parsed_deep == []
        _assert_refused_sibling(custody, reason)
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_report_ledger_bounds_retained_traffic(tmp_path, monkeypatch):
    """Duplicate timeout frames with a large field stop at the lifetime ledger.

    The actor handshake is still pending. Traffic after the cap is refused.
    """
    # Exercise byte exhaustion independently of the larger cohort message cap.
    monkeypatch.setattr(handshake_tests, "R2_CONTROL_LEDGER_BYTES", R2_CONTROL_LINE_LIMIT)
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        _plan_reserved_sibling(custody)
        _start_handshake_child(custody, tmp_path, "actor", "hang", "hello", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        _read_ack(ack_read)
        assert custody.slots["actor"]["hello"] is False
        pad = "Q" * 4000
        frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "timeout",
                             "pad": pad}) + "\n").encode()
        assert R2_CONTROL_LINE_LIMIT > len(frame) > 0
        assert len(frame) < R2_CONTROL_LEDGER_BYTES
        fitting = R2_CONTROL_LEDGER_BYTES // len(frame)
        assert 1 <= fitting < R2_CONTROL_LEDGER_MESSAGES
        for _ in range(fitting):
            os.write(custody.report_write, frame)
            assert custody.pump() in (True, False)
        assert custody.report_rejected is False
        assert custody.slots["actor"]["hello"] is False
        assert len(custody.messages) == fitting
        os.write(custody.report_write, frame)
        with pytest.raises(RuntimeError) as caught:
            custody.pump()
        assert str(caught.value) == "R2 fixture: control ledger exceeded"
        assert "QQQQ" not in str(caught.value)
        hello = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "hello",
                             "pid": 1, "birth": "1"}) + "\n").encode()
        os.write(custody.report_write, hello)
        with pytest.raises(RuntimeError):
            custody.pump()
        assert custody.slots["actor"]["hello"] is False
        _assert_refused_sibling(custody, "R2 fixture: control ledger exceeded")
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_report_ledger_bounds_duplicate_messages(tmp_path):
    """A pending handshake stops accepting duplicate events at the message cap."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        _plan_reserved_sibling(custody)
        _start_handshake_child(custody, tmp_path, "actor", "hang", "hello", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        _read_ack(ack_read)
        frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "timeout"}) + "\n").encode()
        assert len(frame) * (R2_CONTROL_LEDGER_MESSAGES + 1) < R2_CONTROL_LEDGER_BYTES
        for _ in range(R2_CONTROL_LEDGER_MESSAGES):
            os.write(custody.report_write, frame)
            custody.pump()
        assert len(custody.messages) == R2_CONTROL_LEDGER_MESSAGES
        assert all(item["event"] == "timeout" for item in custody.messages)
        assert custody.slots["actor"]["hello"] is False
        os.write(custody.report_write, frame)
        with pytest.raises(RuntimeError) as caught:
            custody.pump()
        assert str(caught.value) == "R2 fixture: control ledger exceeded"
        assert custody.slots["actor"]["hello"] is False
        _assert_refused_sibling(custody, "R2 fixture: control ledger exceeded")
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_reaped_sibling_hello_uses_retained_identity(tmp_path, monkeypatch):
    """A captured sibling can say hello after it is reaped. The wait uses the saved identity."""

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    calls = {"n": 0}
    real_kernel = handshake_tests.r2_kernel_process

    def counting(pid):
        calls["n"] += 1
        return real_kernel(pid)

    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None},
                      "worker": {"kind": "H", "parent": None, "child": None}}, fixture_only=("actor",))
        process = _start_handshake_child(
            custody, tmp_path, "worker", "hang", "hello", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        _read_ack(ack_read)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", counting)
        seen = {"n": calls["n"]}

        def queue_hello_then_exit(active):
            entry = active.entries["worker"]
            raw = (json.dumps({"nonce": active.nonce, "slot": "worker", "event": "hello",
                               "pid": entry["pid"], "birth": entry["birth"]}) + "\n").encode()
            assert os.write(active.report_write, raw) == len(raw)
            # os.kill, not process.kill: send_signal re-reads /proc and would hide the recapture bug.
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)

        custody.await_event("worker", "hello", before_terminal=queue_hello_then_exit)
        assert custody.slots["worker"]["hello"] is True
        assert calls["n"] == seen["n"]
        assert custody.entries["worker"]["birth"]
        report = custody.close()
        assert report["state"] == "CLOSED"
    finally:
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("exited", [False, True], ids=["live", "exited"])
def test_r2_buffered_hello_wins_after_ceiling_jump(tmp_path, exited):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    clock = {"now": 0.0}

    def jump(control):
        assert b"\n" in control.buffer  # A complete frame remains after the saturated first pump.
        clock["now"] = 2.0

    try:
        _enlarge_report_pipe(custody)
        process = _start_handshake_child(custody, tmp_path, "actor", "hang", "hello",
                                         latch_read, ack_write=ack_write)
        _read_ack(ack_read)
        entry = custody.entries["actor"]
        if exited:
            custody.kill_owned("actor")
            assert custody.wait_native("actor") == -signal.SIGKILL
        timeout = _exact_timeout(custody, 157)  # Avoid an exact OS read boundary at line saturation.
        count = R2_CONTROL_LINES_PER_PUMP * (2 if exited else 1)
        hello = (json.dumps(dict(nonce=custody.nonce, slot="actor", event="hello",
                                 pid=process.pid, birth=entry["birth"])) + "\n").encode()
        _write_all(custody.report_write, timeout * count + hello)
        custody.await_event("actor", "hello", ceiling=1.0, clock=lambda: clock["now"], before_terminal=jump)
        assert clock["now"] == 2.0
        assert custody.slots["actor"]["hello"] is True
        assert len(custody.messages) == count + 1
        assert not custody.report_rejected and not custody.control_unknown
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


def _enlarge_report_pipe(custody):
    """Give the report pipe room for a multi-pump stream. Skip when the host cannot."""
    import fcntl

    try:
        fcntl.fcntl(custody.report_write, getattr(fcntl, "F_SETPIPE_SZ", 1031), 1 << 20)
    except OSError:
        pytest.skip("report pipe capacity cannot be raised")


def _write_all(fd, blob):
    view = memoryview(blob)
    while view:
        wrote = os.write(fd, view[:65536])
        assert wrote > 0
        view = view[wrote:]


def _exact_timeout(custody, size):
    empty = {"nonce": custody.nonce, "slot": "actor", "event": "timeout", "pad": ""}
    overhead = len((json.dumps(empty) + "\n").encode())
    pad = size - overhead
    assert pad >= 0
    frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "timeout",
                         "pad": "Q" * pad}) + "\n").encode()
    assert len(frame) == size
    return frame


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_rejected_report_does_not_parse_the_rest(tmp_path, monkeypatch):
    """After a refusal, later frames in the same stream are never decoded."""

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    real_json = json
    try:
        _plan_reserved_sibling(custody)
        _enlarge_report_pipe(custody)
        secret = "token=supersecretvalue"
        intent = json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "creation_intent",
                              "child": "worker"})
        created = json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "created",
                               "child": "worker", "child_pid": 1, "child_birth": secret})
        blob = b"[]\n" + (b" " * 70000) + (intent + "\n").encode() + (created + "\n").encode()
        real_loads, real_dumps, real_error = json.loads, json.dumps, json.JSONDecodeError
        calls = {"n": 0}

        def counting(text, *args, **kwargs):
            calls["n"] += 1
            return real_loads(text, *args, **kwargs)

        monkeypatch.setattr(handshake_tests, "json", type("GuardJSON", (), {
            "loads": staticmethod(counting),
            "dumps": staticmethod(real_dumps),
            "JSONDecodeError": real_error,
        })())
        _write_all(custody.report_write, blob)
        with pytest.raises(RuntimeError) as caught:
            custody.pump()
        assert str(caught.value) == "R2 fixture: control message refused"
        assert calls["n"] == 1
        assert "worker" not in custody.entries
        report = _assert_refused_sibling(custody, "R2 fixture: control message refused")
        assert calls["n"] == 1
        assert secret not in json.dumps(report)
    finally:
        monkeypatch.setattr(handshake_tests, "json", real_json)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_close_drains_a_saturated_report(tmp_path, monkeypatch):
    """Unread frames after a full pump are not a CLOSED report."""
    monkeypatch.setattr(handshake_tests, "R2_CONTROL_LEDGER_BYTES", R2_CONTROL_LINE_LIMIT)
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        _plan_reserved_sibling(custody)
        process = _start_handshake_child(
            custody, tmp_path, "actor", "hang", "hello", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        _read_ack(ack_read)
        _enlarge_report_pipe(custody)
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        frame = _exact_timeout(custody, 4096)
        assert len(frame) * 16 == R2_CONTROL_LEDGER_BYTES
        secret = "token=supersecretvalue"
        intent = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "creation_intent",
                               "child": "worker"}) + "\n").encode()
        created = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "created",
                                "child": "worker", "child_pid": 1, "child_birth": secret}) + "\n").encode()
        _write_all(custody.report_write, frame * 16 + intent + created)
        with pytest.raises(R2CleanupUnknown) as closed:
            custody.close()
        report = closed.value.report
        assert report["state"] == "UNKNOWN"
        assert "worker" in report["unresolved_slots"]
        assert "worker" not in report["uncreated_slots"]
        assert "worker" not in report["entries"]
        assert secret not in json.dumps(report)
        assert len(custody.messages) == 16
        _assert_exit_proofs(report)
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("copies", [16, 32])
@pytest.mark.parametrize("roomy_ledger", [False, True])
def test_r2_queued_running_past_one_pump_is_not_a_false_exit(tmp_path, copies, roomy_ledger, monkeypatch):
    """Bytes past one pump are drained. The result is the announcement or UNKNOWN, not a false exit."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        if roomy_ledger:
            monkeypatch.setattr(handshake_tests, "R2_CONTROL_LEDGER_BYTES", 262144)
            monkeypatch.setattr(handshake_tests, "R2_CONTROL_LEDGER_MESSAGES", 128)
        else:
            monkeypatch.setattr(handshake_tests, "R2_CONTROL_LEDGER_BYTES", R2_CONTROL_LINE_LIMIT)
        process = _start_handshake_child(
            custody, tmp_path, "actor", "hang", "running", latch_read, ack_write=ack_write)
        os.close(latch_read)
        os.close(ack_write)
        latch_read = ack_write = -1
        custody.await_event("actor", "hello")
        custody.release("actor")
        _read_ack(ack_read)
        _enlarge_report_pipe(custody)
        frame = _exact_timeout(custody, 4096)
        running = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "running"}) + "\n").encode()

        def dump_then_exit(active):
            _write_all(active.report_write, frame * copies + running)
            os.kill(process.pid, signal.SIGKILL)
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)

        try:
            custody.await_event("actor", "running", before_terminal=dump_then_exit)
        except RuntimeError as exc:
            assert not roomy_ledger, "a queued announcement inside the ledger must succeed"
            text = str(exc)
            assert "child exited" not in text
            assert "ceiling" not in text
            assert custody.control_unknown is True
        else:
            assert custody.slots["actor"]["running"] is True
    finally:
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("error", [ProcessLookupError, RuntimeError])
def test_r2_mid_exit_read_error_retries_the_retained_identity(tmp_path, monkeypatch, error):
    """ESRCH while reading /proc is pending evidence. The next read can still prove the exit."""
    import errno

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    calls = {"n": 0}
    real_kernel = handshake_tests.r2_kernel_process

    def flaky(pid):
        calls["n"] += 1
        if calls["n"] == 1:
            raise error(errno.ESRCH, "mid-exit read")
        return real_kernel(pid)

    try:
        process = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        os.close(latch_read)
        latch_read = -1
        os.write(latch_write, b"X")
        _wait_unreaped(process, custody.entries["actor"].get("fd"))
        assert real_kernel(process.pid)["state"].startswith("Z")
        _drop_indirect_handles(custody, "actor", process)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", flaky)
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        message, evidence = _handshake_evidence(caught)
        assert message == "R2 fixture: hello handshake refused: child exited"
        assert "ceiling" not in message
        assert evidence["exit_proof"] == "native_waitpid"
        assert custody.entries["actor"]["lost"] is False
        assert calls["n"] >= 2
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        report = custody.close()
        assert report["state"] == "CLOSED"
    finally:
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        _close_fds(latch_read, latch_write)
        try:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        except (NameError, ChildProcessError, subprocess.TimeoutExpired, OSError):
            pass
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        _clear_r2_quarantine()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_unproven_exit_keeps_the_quarantine(tmp_path, monkeypatch):
    """UNKNOWN without an exit proof stays latched. The next custody cannot admit actors."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}})
        custody.slots["actor"].update(permitted=True, hello=True, released=True, running=True)
        custody.entries["actor"] = r2_pending_test_entry(os.getpid(), "1", process=None)
        custody.LIMIT = 0.5

        def refuse(slot):
            raise RuntimeError("modelled closure refuses to signal")

        custody.observe = lambda slot: None
        custody.kill_owned = refuse
        with pytest.raises(R2CleanupUnknown):
            custody.close()
        assert R2Custody.quarantine_report is not None
        assert R2Custody.quarantine_report["state"] == "UNKNOWN"
        assert _captured_exit_proven(R2Custody.quarantine_report) is False
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is custody.report
        with pytest.raises(R2CleanupUnknown):
            R2Custody(tmp_path / "next", tmp_path / "next-quarantine.json")
    finally:
        # Actorless negative model: the entry describes this test process and
        # kill_owned is refused. Restore only this model's latch via monkeypatch.
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("values", [
    {"event": "hello", "pid": True, "birth": "1"},
    {"event": "hello", "pid": 1, "birth": "token=supersecretvalue"},
    {"event": "hello", "pid": 1, "birth": None},
    {"event": "hello", "pid": 1},
    {"event": "created", "child": "worker", "child_pid": "supersecretvalue", "child_birth": "1"},
    {"event": "creation_intent", "child": []},
    {"event": "reaped", "child": "worker", "child_pid": 1, "child_birth": "1",
     "wait_pid": 1, "wait_status": True, "returncode": False},
    {"event": "wait_unavailable", "child": "worker", "child_pid": 1, "child_birth": False},
], ids=["bool-pid", "invalid-birth", "null-birth", "missing-birth", "string-pid",
        "list-child", "bool-wait", "bool-birth"])
def test_r2_intake_validates_event_fields_before_protocol(tmp_path, values):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        _plan_reserved_sibling(custody)
        frame = {"nonce": custody.nonce, "slot": "actor", **values}
        os.write(custody.report_write, (json.dumps(frame) + "\n").encode())
        with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
            custody.pump()
        assert custody.entries == {} and custody.messages == []
        _assert_refused_sibling(custody, "R2 fixture: control message refused")
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("failure", ["decode", "capture"])
@pytest.mark.parametrize("error", [ValueError, RecursionError, RuntimeError, SystemExit])
def test_r2_intake_does_not_echo_boundary_exceptions(tmp_path, monkeypatch, failure, error):

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    real_json, capture = json, R2Custody.capture
    latch_read, latch_write = os.pipe()
    try:
        _plan_reserved_sibling(custody)

        def failed(*args, **kwargs):
            raise error("R2 fixture: token=supersecretvalue\nsecond line")

        if failure == "decode":
            monkeypatch.setattr(handshake_tests, "json", SimpleNamespace(
                loads=failed, dumps=real_json.dumps, JSONDecodeError=real_json.JSONDecodeError))
            event = {"event": "timeout"}
        else:
            process = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
            monkeypatch.setattr(handshake_tests.R2Custody, "capture", failed)
            event = {"event": "hello", "pid": process.pid, "birth": custody.entries["actor"]["birth"]}
        frame = {"nonce": custody.nonce, "slot": "actor", **event}
        os.write(custody.report_write, (json.dumps(frame) + "\n").encode())
        with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
            custody.pump()
        _assert_refused_sibling(custody, "R2 fixture: control message refused")
    finally:
        _close_fds(latch_read, latch_write)
        monkeypatch.setattr(handshake_tests, "json", real_json)
        monkeypatch.setattr(handshake_tests.R2Custody, "capture", capture)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_unavailable_wait_does_not_clear_quarantine(tmp_path, monkeypatch):
    # Actorless report: ECHILD does not establish an original-instance exit.
    report = {"state": "UNKNOWN", "errors": [],
              "entries": {"actor": {"exit": None, "wait_status": "unavailable"}}}
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", report)
    _clear_r2_quarantine()
    assert R2Custody.quarantine_report is report
    with pytest.raises(R2CleanupUnknown):
        R2Custody(tmp_path / "next", tmp_path / "quarantine.json")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("event,reason", [
    ("hello", "child appeared without its creation permit"),
    ("creation_intent", "invalid reserved child creation intent"),
    ("created", "unexpected child creation"),
    ("running", "actor ran before physical admission"),
    ("reaped", "conflicting native child wait"),
    ("wait_unavailable", "conflicting unavailable wait"),
    ("unknown", "invalid control event"),
])
def test_r2_protocol_refusals_latch_unknown(tmp_path, event, reason):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        _plan_reserved_sibling(custody)
        frame = {"nonce": custody.nonce, "slot": "actor", "event": event,
                 "pid": 1, "birth": "1", "child": "worker", "child_pid": 1,
                 "child_birth": "1", "wait_pid": 1, "wait_status": 0, "returncode": 0}
        os.write(custody.report_write, (json.dumps(frame) + "\n").encode())
        reason = "R2 fixture: " + reason
        with pytest.raises(RuntimeError) as caught:
            custody.pump()
        assert str(caught.value) == reason
        _assert_refused_sibling(custody, reason)
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("cross_deadline", [False, True])
def test_r2_close_drains_reports_queued_during_exit_observation(tmp_path, monkeypatch, cross_deadline):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    real_time = time
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    try:
        process = _start_handshake_child(
            custody, tmp_path, "actor", "hang", "hello", latch_read, ack_write=ack_write)
        _read_ack(ack_read)
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        observe = custody.observe
        queued = []
        clock = {"now": 0.0}
        custody.LIMIT = 1.0
        monkeypatch.setattr(handshake_tests, "time", R2Facade(real_time, monotonic=lambda: clock["now"]))

        def exit_then_queue(slot):
            proof = observe(slot)
            if not queued:
                assert proof is not None
                os.write(custody.report_write, b"[]\n")
                queued.append(True)
                if cross_deadline:
                    clock["now"] = 2.0
            return proof

        custody.observe = exit_then_queue
        with pytest.raises(R2CleanupUnknown) as closed:
            custody.close()
        assert queued and closed.value.report["state"] == "UNKNOWN"
        _assert_exit_proofs(closed.value.report)
    finally:
        monkeypatch.setattr(handshake_tests, "time", real_time)
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("handles", ["pidfd", "native-only"])
def test_r2_close_reconciles_exit_during_handle_selection(tmp_path, monkeypatch, handles):
    """A newly observed exit must wake cleanup before its modelled deadline."""
    real_os, real_select, real_time = os, select, time
    trace = {"now": 0.0, "observed_live": False, "injected": False,
             "native_wait": False, "report_waits": 0}
    latch_read, latch_write = os.pipe()
    process = None

    def clock():
        return real_time.monotonic() if trace["native_wait"] else trace["now"]

    class ExitDuringSelection(R2Custody):
        def observe(self, slot):
            proof = super().observe(slot)
            if self.closed and proof is None and not trace["injected"]:
                assert process.poll() is None
                trace["observed_live"] = True
            return proof

        def _pidfd_for(self, slot):
            if self.closed and trace["observed_live"] and not trace["injected"]:
                assert process.poll() is None
                trace["injected"] = True
                trace["now"] = 0.95
                assert real_os.write(latch_write, b"X") == 1
                # Only the real child's wait uses a real hung-fixture ceiling.
                # The cleanup clock stays just before its deadline.
                trace["native_wait"] = True
                try:
                    assert process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
                finally:
                    trace["native_wait"] = False
            return super()._pidfd_for(slot)

    class DeadlinePoll:
        def __init__(self):
            self.poller = real_select.poll()
            self.watched = set()

        def register(self, fd, event):
            self.watched.add(fd)
            self.poller.register(fd, event)

        def poll(self, milliseconds):
            if milliseconds > 0 and self.watched == {custody.report_read} and not custody.report_writer_retired:
                trace["report_waits"] += 1
                trace["now"] = 2.0
                return []  # The fixture's retained writer prevents EOF here.
            return self.poller.poll(milliseconds)

    def unavailable(*args, **kwargs):
        import errno
        raise OSError(errno.ENOSYS, "modelled unavailable pidfd notification")

    custody = None
    try:
        if handles == "native-only":
            monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=unavailable))
        custody = ExitDuringSelection(tmp_path / "custody", tmp_path / "quarantine.json")
        process = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        if handles == "pidfd" and custody._pidfd_for("actor") is None:
            pytest.skip("this case requires an available pidfd notification")
        assert custody.observe("actor") is None
        custody.LIMIT = 1.0
        monkeypatch.setattr(handshake_tests, "time", R2Facade(real_time, monotonic=clock))
        monkeypatch.setattr(handshake_tests, "select", R2Facade(real_select, poll=DeadlinePoll))
        report = custody.close()
        assert trace["observed_live"] and trace["injected"]
        assert trace["report_waits"] == 0
        assert report["state"] == "CLOSED" and report["unresolved_slots"] == []
        assert report["entries"]["actor"]["exit"]["returncode"] == 7
        assert report["post_exit_drain"]["complete"] is True
        assert report["post_exit_drain"]["eof_at"] < report["post_exit_drain"]["deadline"]
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "time", real_time)
        monkeypatch.setattr(handshake_tests, "select", real_select)
        _close_fds(latch_read, latch_write)
        if process is not None:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        if custody is not None:
            custody.LIMIT = R2Custody.LIMIT
            if custody.report is None:
                try:
                    custody.close()
                except R2CleanupUnknown:
                    pass
            _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("recognition", ["pidfd-observe", "native-lock", "peer-hook"])
def test_r2_close_reconciles_retained_exit_before_wait(tmp_path, monkeypatch, recognition):
    """Every producer of exit evidence invalidates cleanup's outstanding snapshot."""
    real_os, real_select, real_time, sample = os, select, time, r2_kernel_process
    trace = {"now": 0.0, "native_wait": False, "live_sample": False, "injected": False,
             "in_kill": False, "kill_observed_live": False, "recognized": None, "report_waits": 0}
    latch_read, latch_write = os.pipe()
    peer_read, peer_write = None, None
    custody, process, peer, deferred_peer = None, None, None, None

    def clock():
        return real_time.monotonic() if trace["native_wait"] else trace["now"]

    def release(child, writer):
        assert child.poll() is None
        assert real_os.write(writer, b"X") == 1
        trace["native_wait"] = True
        try:
            assert child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
        finally:
            trace["native_wait"] = False

    class ExitBeforeWait(R2Custody):
        def observe(self, slot):
            proof = super().observe(slot)
            if self.closed and slot == "actor":
                if trace["in_kill"]:
                    trace["kill_observed_live"] = proof is None
                    if proof is not None:
                        trace["recognized"] = "pidfd-observe"
                elif proof is None and not trace["injected"]:
                    assert process.poll() is None
                    trace["live_sample"] = True
                    trace["now"] = .31 if recognition == "peer-hook" else .35
                    if recognition == "pidfd-observe":
                        release(process, latch_write)
                        trace["injected"], trace["now"] = True, .95
            return proof

        def kill_owned(self, slot):
            if recognition == "peer-hook":
                # Hold signal delivery until the peer hook witnesses the real exit.
                assert process.poll() is None
                return
            trace["in_kill"] = True
            try:
                return super().kill_owned(slot)
            finally:
                trace["in_kill"] = False

        def _native_exit(self, entry):
            proof = super()._native_exit(entry)
            if trace["in_kill"] and proof is not None:
                trace["recognized"] = "native-lock"
            return proof

    def sample_then_exit(pid):
        physical = sample(pid)
        if (recognition == "native-lock" and trace["in_kill"] and
                trace["kill_observed_live"] and not trace["injected"]):
            release(process, latch_write)
            trace["injected"], trace["now"] = True, .95
        return physical

    def cleanup_hook(slot):
        if slot == "actor":
            # Model delayed publication of an already retained original peer.
            # It joins cleanup after the initial hook snapshot was taken.
            custody.entries["peer"] = deferred_peer
            custody.slots["peer"]["permitted"] = True
        elif slot == "peer":
            assert trace["live_sample"] and not trace["injected"]
            release(process, latch_write)
            release(peer, peer_write)
            trace["injected"], trace["now"] = True, .35
            assert custody.observe("actor") is not None
            trace["recognized"] = "peer-hook"

    class DeadlinePoll:
        def __init__(self):
            self.poller, self.watched = real_select.poll(), set()

        def register(self, fd, event):
            self.watched.add(fd)
            self.poller.register(fd, event)

        def poll(self, milliseconds):
            if milliseconds > 0 and self.watched == {custody.report_read} and not custody.report_writer_retired:
                trace["report_waits"] += 1
                trace["now"] = .5 if recognition == "peer-hook" else 2.0
                return []
            return self.poller.poll(milliseconds)

    def unavailable(*args, **kwargs):
        import errno
        raise OSError(errno.ENOSYS, "modelled unavailable pidfd notification")

    try:
        if recognition == "pidfd-observe":
            require_r2_indirect_exit(pidfd=True)
        if recognition == "peer-hook":
            peer_read, peer_write = real_os.pipe()
        if recognition == "native-lock":
            monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=unavailable))
        custody = ExitBeforeWait(tmp_path / "custody", tmp_path / "quarantine.json")
        process = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", latch_read)
        if recognition == "pidfd-observe":
            fd = custody._pidfd_for("actor")
            if fd is None or not hasattr(signal, "pidfd_send_signal"):
                pytest.skip("this case requires a signal-capable pidfd")
            signal.pidfd_send_signal(fd, 0)
        if recognition == "peer-hook":
            peer = _start_handshake_child(custody, tmp_path, "peer", "exit", "hello", peer_read)
            deferred_peer = custody.entries.pop("peer")
            custody.slots["peer"]["permitted"] = False
            custody.cleanup_hook = cleanup_hook
        assert custody.observe("actor") is None
        custody.LIMIT = .4 if recognition == "peer-hook" else 1.0
        monkeypatch.setattr(handshake_tests, "time", R2Facade(real_time, monotonic=clock))
        monkeypatch.setattr(handshake_tests, "select", R2Facade(real_select, poll=DeadlinePoll))
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", sample_then_exit)
        report = custody.close()
        assert trace["live_sample"] and trace["injected"] and trace["recognized"] == recognition
        assert trace["report_waits"] == 0
        assert report["state"] == "CLOSED" and report["unresolved_slots"] == []
        assert report["entries"]["actor"]["exit"]["returncode"] == 7
        assert report["post_exit_drain"]["complete"] is True
        assert report["post_exit_drain"]["eof_at"] < report["post_exit_drain"]["deadline"]
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "time", real_time)
        monkeypatch.setattr(handshake_tests, "select", real_select)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", sample)
        _close_fds(latch_read, latch_write, peer_read, peer_write)
        for child in (process, peer):
            if child is not None:
                child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        if custody is not None:
            if deferred_peer is not None:
                custody.entries["peer"] = deferred_peer
                custody.slots["peer"]["permitted"] = True
            custody.cleanup_hook, custody.LIMIT = None, R2Custody.LIMIT
            if custody.report is None:
                try:
                    custody.close()
                except R2CleanupUnknown:
                    pass
            _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_line_budget_is_shared_by_reads_in_one_pump(tmp_path, monkeypatch):

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    real_os, line_limit = os, R2_CONTROL_LINES_PER_PUMP
    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}}, fixture_only=("actor",))
        frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "timeout"}) + "\n").encode()
        os.write(custody.report_write, frame * 6)
        reading = os.read
        monkeypatch.setattr(handshake_tests, "R2_CONTROL_LINES_PER_PUMP", 3)
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, read=lambda fd, size: reading(fd, min(size, len(frame)))))
        assert custody.pump() is True
        assert len(custody.messages) == 3
        assert custody.pump() is True
        assert len(custody.messages) == 6
        assert custody.pump() is False
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "R2_CONTROL_LINES_PER_PUMP", line_limit)
        assert custody.close()["state"] == "CLOSED"
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "R2_CONTROL_LINES_PER_PUMP", line_limit)
        if custody.report is None:
            custody.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_expected_refusal_releases_handles_after_exit_proofs(tmp_path):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        _plan_reserved_sibling(custody)
        descriptors = [custody.safety_read, custody.report_read, custody.report_write, custody.folder_fd,
                       *(fd for pair in custody.gates.values() for fd in pair)]
        os.write(custody.report_write, b"[]\n")
        with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
            custody.pump()
        _assert_refused_sibling(custody, "R2 fixture: control message refused")
        _clear_r2_quarantine(custody)
        assert R2Custody.quarantine_report is custody.report
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is None
        for fd in descriptors:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("failure", ["open", "pipe", "blocking", "nonce"])
def test_r2_constructor_failure_releases_its_descriptors(tmp_path, monkeypatch, failure):

    descriptors, pipes = [], []
    real_os = os
    real_uuid = uuid

    def opened(*args, **kwargs):
        if failure == "open":
            raise OSError("modelled custody setup failure")
        fd = real_os.open(*args, **kwargs)
        descriptors.append(fd)
        return fd

    def piped():
        if failure == "pipe" and pipes:
            raise OSError("modelled custody setup failure")
        pair = real_os.pipe()
        pipes.append(pair)
        descriptors.extend(pair)
        return pair

    def blocking(*args):
        if failure == "blocking":
            raise OSError("modelled custody setup failure")
        return real_os.set_blocking(*args)

    def nonce():
        if failure == "nonce":
            raise OSError("modelled custody setup failure")
        return real_uuid.uuid4()

    try:
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, open=opened, pipe=piped, set_blocking=blocking))
        monkeypatch.setattr(handshake_tests, "uuid", R2Facade(real_uuid, uuid4=nonce))
        with pytest.raises(OSError, match="^modelled custody setup failure$"):
            R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
        for fd in descriptors:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        _close_fds(*descriptors)


R2_UNREPORTED_WORKER = r'''import json, os, select, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
def wait(fd):
    if not select.select([fd], [], [], 60)[0]:
        os._exit(75)
    return os.read(fd, 1)
birth = Path("/proc/self/stat").read_bytes().rpartition(b")")[2].split()[19].decode()
hello = {"nonce": config["nonce"], "slot": "actor", "event": "hello", "pid": os.getpid(), "birth": birth}
os.write(config["report_write"], (json.dumps(hello) + "\n").encode())
if not config.get("ungranted", False):
    if wait(config["nodes"]["actor"]["gate"]) != b"G":
        os._exit(70)
worker = os.fork()
if worker == 0:
    # A real unreported worker can outlive the actor even after closing its report writer.
    os.close(config["report_write"])
    os.close(config["worker_receipt"])
    wait(config["worker_stop"])
    os._exit(0)
os.write(config["worker_receipt"], (json.dumps({"pid": worker}) + "\n").encode())
wait(config["actor_exit"])
if not config.get("silent", False):
    os.write(config["report_write"], b"[]\n")
os._exit(7)
'''


def _r2_read_worker_receipt(fd):
    pending = b""
    deadline = time.monotonic() + R2_HANDSHAKE_CEILING_SECONDS
    while b"\n" not in pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(pending) >= 4096:
            raise RuntimeError("R2 fixture: independent worker receipt refused")
        try:
            if not select.select([fd], [], [], remaining)[0]:
                raise RuntimeError("R2 fixture: independent worker receipt refused")
            part = os.read(fd, 4096 - len(pending))
        except (OSError, ValueError):
            raise RuntimeError("R2 fixture: independent worker receipt refused") from None
        if not part:
            raise RuntimeError("R2 fixture: independent worker receipt refused")
        pending += part
    try:
        text = pending.decode("utf-8")
        if _r2_control_nesting(text) > R2_CONTROL_MAX_DEPTH:
            raise RuntimeError("R2 fixture: independent worker receipt refused")
        receipt = json.loads(text)
    except (ValueError, UnicodeError, RecursionError):
        raise RuntimeError("R2 fixture: independent worker receipt refused") from None
    if (not isinstance(receipt, dict) or set(receipt) != {"pid"} or
            type(receipt["pid"]) is not int or not 0 < receipt["pid"] <= 0x7fffffff):
        raise RuntimeError("R2 fixture: independent worker receipt refused")
    return receipt["pid"]


def _r2_independent_worker_witness(custody, slot, pid, process=None):
    """Retain a worker's real original identity outside the control-report custody."""
    parent = custody.slots[slot]["parent"]
    parent_entry = custody.entries[parent] if parent is not None else r2_kernel_process(os.getpid())
    assert r2_kernel_process(parent_entry["pid"])["birth"] == parent_entry["birth"]
    witness = SimpleNamespace(entries={parent: parent_entry} if parent is not None else {},
                              slots={slot: {"parent": parent}},
                              original_parent=(parent, parent_entry["pid"], parent_entry["birth"]))
    try:
        R2Custody.capture(witness, slot, pid, process=process)
    except BaseException:
        _close_fds(witness.entries.get(slot, {}).get("fd"))
        raise
    return witness


def _r2_wait_worker_exit(witness, slot):
    deadline = time.monotonic() + R2_HANDSHAKE_CEILING_SECONDS
    while True:
        proof = R2Custody.observe(witness, slot)
        if proof is not None:
            return proof
        remaining = deadline - time.monotonic()
        assert remaining > 0, "independent worker exit was not observed"
        fd = witness.entries[slot].get("fd")
        if isinstance(fd, int):
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            poller.poll(max(1, int(min(remaining, 0.05) * 1000)))
        else:
            time.sleep(min(remaining, 0.05))


def _retain_r2_independent_exit(custody, slot, witness):
    """Add an independently captured original-instance exit to an UNKNOWN report.

    The original UNKNOWN verdict is retained. No unresolved slot is removed;
    quarantine retirement must check this additional exit evidence itself.
    """
    parent = custody.slots[slot]["parent"]
    actor = custody.entries[parent] if parent is not None else r2_kernel_process(os.getpid())
    assert witness.original_parent == (parent, actor["pid"], actor["birth"])
    entry = witness.entries[slot]
    assert entry["verified"] and not entry["lost"]
    proof = R2Custody.observe(witness, slot)
    assert proof is not None, "independent exit evidence is still pending"
    original = custody.entries.get(slot)
    if original is not None and original.get("lost"):
        # Independent recovery may end the physical scope, but never repairs its
        # terminal proof state or retires the UNKNOWN quarantine.
        return
    # Import only an already-closed original instance into the same state
    # ledger, without borrowing the observer's descriptors or process object.
    if original is None:
        original = {"pid": entry["pid"], "birth": entry["birth"], "process": None}
        r2_identity_transition(original, "register")
        custody.entries[slot] = original
    r2_identity_transition(original, "adopt_exit", source=entry)
    custody.slots[slot]["permitted"] = True
    if custody.report is not None:
        custody.report["entries"][slot] = r2_entry_record(original)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_launch_exposes_transitive_reservations_before_process_creation(tmp_path, monkeypatch):
    """Actorless failed-launch model: descendants lose exemption, unrelated roots keep it."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)

    def refused(*args, **kwargs):
        raise OSError("modelled process creation refusal")

    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": None},
                 "worker": {"kind": "M", "parent": "actor", "child": None},
                 "grandchild": {"kind": "W", "parent": "worker", "child": None},
                 "unrelated": {"kind": "W", "parent": None, "child": None}}
        custody.plan(nodes, fixture_only=tuple(nodes))
        config = custody.config({"actor": nodes["actor"]}, tmp_path / "unused.py", tmp_path / "actor.json")
        monkeypatch.setattr(handshake_tests, "WitnessedPopen", refused)
        with pytest.raises(OSError, match="^modelled process creation refusal$"):
            custody.launch(config, "actor", os.environ)
        assert all(custody.slot_provenance[slot]["handed_to_actor"]
                   for slot in ("actor", "worker", "grandchild"))
        assert custody.slot_provenance["unrelated"]["handed_to_actor"] is False
        custody.LIMIT = 0.01
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["unresolved_slots"] == ["actor", "grandchild", "worker"]
        assert caught.value.report["uncreated_slots"] == ["unrelated"]
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is caught.value.report
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("silent", [True, False], ids=["silent", "rejected"])
def test_r2_omitted_ungranted_descendant_keeps_quarantine(tmp_path, silent):
    require_r2_indirect_exit()
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    actor_read, actor_write = os.pipe()
    stop_read, stop_write = os.pipe()
    receipt_read, receipt_write = os.pipe()
    witness = None
    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": None},
                 "worker": {"kind": "W", "parent": "actor", "child": None}}
        custody.plan(nodes, fixture_only=tuple(nodes))
        script, path = tmp_path / "ungranted.py", tmp_path / "ungranted.json"
        script.write_text(R2_UNREPORTED_WORKER)
        config = custody.config({"actor": nodes["actor"]}, script, path, actor_exit=actor_read,
                                 worker_stop=stop_read, worker_receipt=receipt_write,
                                 ungranted=True, silent=silent)
        config["inherited"].extend((actor_read, stop_read, receipt_write))
        path.write_text(json.dumps(config))
        actor = custody.launch(config, "actor", os.environ)
        _close_fds(actor_read, stop_read, receipt_write)
        actor_read = stop_read = receipt_write = -1
        custody.await_event("actor", "hello")
        worker_pid = _r2_read_worker_receipt(receipt_read)
        witness = _r2_independent_worker_witness(custody, "worker", worker_pid)
        assert custody.slots["worker"]["permitted"] is False
        os.write(actor_write, b"X")
        assert actor.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        report = caught.value.report
        assert report["entries"]["actor"]["exit"]["proof"] == "native_waitpid"
        assert "worker" in report["unresolved_slots"] and "worker" not in report["uncreated_slots"]
        assert R2Custody.observe(witness, "worker") is None
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is report
        assert report["slot_provenance"]["worker"]["handed_to_actor"] is True
        with pytest.raises(R2CleanupUnknown):
            R2Custody(tmp_path / "blocked", tmp_path / "blocked.json")
    finally:
        _close_fds(actor_read, actor_write, stop_read, stop_write, receipt_read, receipt_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        if witness is not None:
            try:
                _r2_wait_worker_exit(witness, "worker")
                _retain_r2_independent_exit(custody, "worker", witness)
            finally:
                r2_identity_transition(witness.entries["worker"], "release")
        _clear_r2_quarantine(custody, expected_unknown=True)


R2_REPARENTED_HELLO_WORKER = r'''import json, os, select, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
def wait(fd):
    assert select.select([fd], [], [], 60)[0]
    return os.read(fd, 1)
def birth(pid):
    return Path("/proc/%d/stat" % pid).read_bytes().rpartition(b")")[2].split()[19].decode()
def emit(slot, event, **fields):
    raw = (json.dumps(dict(nonce=config["nonce"], slot=slot, event=event, **fields)) + "\n").encode()
    assert os.write(config["report_write"], raw) == len(raw)
emit("actor", "hello", pid=os.getpid(), birth=birth(os.getpid()))
assert wait(config["nodes"]["actor"]["gate"]) == b"G"
worker = os.fork()
if worker == 0:
    os.close(config["worker_receipt"])
    assert wait(config["hello_read"]) == b"H"
    emit("worker", "hello", pid=os.getpid(), birth=birth(os.getpid()))
    os.write(config["ack_write"], b"A")
    os.close(config["report_write"])
    wait(config["worker_stop"])
    os._exit(0)
emit("actor", "created", child="worker", child_pid=worker, child_birth=birth(worker))
os.write(config["worker_receipt"], (json.dumps(dict(pid=worker)) + "\n").encode())
wait(config["actor_exit"])
os._exit(7)
'''


def _r2_read_scope_file(path, limit, reason):
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError:
        raise AssertionError(reason) from None
    if len(raw) > limit:
        raise AssertionError(reason)
    return raw


def _r2_run_identity_scope(tmp_path, node):
    """A real permanent-loss regression owns a child scope and retains its quarantine."""
    if os.environ.get("R2_IDENTITY_SCOPE_NODE") == node:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            pytest.skip("R2 fixture: identity subreaper ownership unavailable")
        return False
    folder = tmp_path / "identity-scope"
    folder.mkdir()
    outcome = folder / "outcome.xml"
    command = [sys.executable, "-m", "pytest", "-n", "0", "-q", "--tb=short",
               "--basetemp=" + str(folder / "pytest"), "--junitxml=" + str(outcome), node]
    result = subprocess.run(command, env={**os.environ, "R2_IDENTITY_SCOPE_NODE": node,
                            "R2_IDENTITY_SCOPE_FOLDER": str(folder)}, cwd=str(ROOT),
                            text=True, capture_output=True, timeout=180)
    stdout = _r2_untrusted_text(result.stdout, 65536)
    stderr = _r2_untrusted_text(result.stderr, 65536)
    (folder / "pytest.log").write_text("stdout:\n" + stdout + "\nstderr:\n" + stderr)
    failure = "R2 fixture: identity scope child failed"
    if result.returncode != 0:
        raise AssertionError(failure + "\nstdout:\n" + _r2_untrusted_text(result.stdout, 4096) +
                             "\nstderr:\n" + _r2_untrusted_text(result.stderr, 4096))
    from xml.etree import ElementTree
    unavailable = "R2 fixture: identity scope child outcome unavailable"
    raw = _r2_read_scope_file(outcome, 65536, unavailable)
    try:
        cases = ElementTree.fromstring(raw).findall(".//testcase")
    except ElementTree.ParseError:
        raise AssertionError(unavailable) from None
    if len(cases) != 1:
        raise AssertionError(unavailable)
    case = cases[0]
    if case.find("failure") is not None or case.find("error") is not None:
        raise AssertionError(failure)
    skipped = case.find("skipped")
    if skipped is not None:
        reason = skipped.get("message") or skipped.text or "R2 fixture: identity scope child skipped"
        pytest.skip(_r2_untrusted_text(reason, 1024))
    raw = _r2_read_scope_file(folder / "proof.json", 1 << 20,
                              "R2 fixture: identity scope child passed without closure proof")
    try:
        proof = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise AssertionError("R2 fixture: identity scope child proof unavailable") from None
    try:
        worker = proof["report"]["entries"]["worker"]
        valid = (proof["report"]["state"] == "UNKNOWN" and worker["lost"] is True and
                 worker["exit"] is None and proof["scope_exit"]["proof"] == "subreaper_native_ECHILD" and
                 any(row["wait_pid"] == worker["pid"] for row in proof["scope_exit"]["reaped"]))
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise AssertionError("R2 fixture: identity scope child proof unavailable")
    return True


def _r2_finish_identity_scope(custody):
    reaped = []
    deadline = time.monotonic() + R2_HANDSHAKE_CEILING_SECONDS
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid:
            reaped.append(dict(wait_pid=pid, wait_status=status))
        else:
            assert time.monotonic() < deadline, "R2 fixture: identity scope exit unproven"
            _r2_wait_child_event(min(.05, deadline - time.monotonic()))
    assert R2Custody.quarantine_report is custody.report and custody.report["state"] == "UNKNOWN"
    data = {"report": custody.report, "scope_exit": {"proof": "subreaper_native_ECHILD", "reaped": reaped}}
    (Path(os.environ["R2_IDENTITY_SCOPE_FOLDER"]) / "proof.json").write_text(json.dumps(data, indent=2))


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open") or
                    not hasattr(signal, "pidfd_send_signal"), reason="original-instance signals require Linux pidfds")
@pytest.mark.parametrize("changed_birth", [False, True], ids=["reparented", "birth-conflict"])
def test_r2_live_recapture_keeps_original_ancestry(tmp_path, monkeypatch, request, changed_birth):
    require_r2_indirect_exit(pidfd=True)
    if changed_birth and _r2_run_identity_scope(tmp_path, request.node.nodeid):
        return
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    actor_read, actor_write = os.pipe()
    stop_read, stop_write = os.pipe()
    receipt_read, receipt_write = os.pipe()
    hello_read, hello_write = os.pipe()
    ack_read, ack_write = os.pipe()
    real_kernel, real_signal = handshake_tests.r2_kernel_process, handshake_tests.signal
    witness = None
    signals = []

    def sent(fd, number, *args):
        signals.append((fd, number))
        return real_signal.pidfd_send_signal(fd, number, *args)

    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": "worker"},
                 "worker": {"kind": "W", "parent": "actor", "child": None}}
        custody.plan(nodes)
        script, path = tmp_path / "reparent.py", tmp_path / "reparent.json"
        script.write_text(R2_REPARENTED_HELLO_WORKER)
        config = custody.config(nodes, script, path, actor_exit=actor_read, worker_stop=stop_read,
                                 worker_receipt=receipt_write, hello_read=hello_read, ack_write=ack_write)
        config["inherited"].extend((actor_read, stop_read, receipt_write, hello_read, ack_write))
        path.write_text(json.dumps(config))
        actor = custody.launch(config, "actor", os.environ)
        _close_fds(actor_read, stop_read, receipt_write, hello_read, ack_write)
        actor_read = stop_read = receipt_write = hello_read = ack_write = -1
        custody.await_event("actor", "hello")
        custody.release("actor")
        worker_pid = _r2_read_worker_receipt(receipt_read)  # created was written before this receipt.
        custody.pump()
        entry = custody.entries["worker"]
        assert custody.slots["worker"]["hello"] is False
        witness = _r2_independent_worker_witness(custody, "worker", worker_pid)
        retained_fd, retained_lineage = entry["fd"], entry["lineage"]
        assert isinstance(retained_fd, int) and entry["verified_fd"]
        os.write(hello_write, b"H")
        _read_ack(ack_read)  # hello is queued, but has not been parsed.
        os.write(actor_write, b"X")
        assert actor.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
        assert real_kernel(worker_pid)["ppid"] != actor.pid
        monkeypatch.setattr(handshake_tests, "signal", R2Facade(real_signal, pidfd_send_signal=sent))
        if changed_birth:
            def replacement(pid):
                physical = real_kernel(pid)
                return {**physical, "birth": str(int(physical["birth"]) + 1)} if pid == worker_pid else physical
            monkeypatch.setattr(handshake_tests, "r2_kernel_process", replacement)
            with pytest.raises(RuntimeError, match="^R2 fixture: physical birth/UID/parent mismatch$"):
                custody.pump()
            assert entry["lost"] and custody.control_unknown
            with pytest.raises(RuntimeError, match="^R2 fixture: no physical authority after identity loss$"):
                custody.kill_owned("worker")
            assert signals == []
            with pytest.raises(R2CleanupUnknown) as caught:
                custody.close()
            assert caught.value.report["entries"]["worker"]["lost"] is True
            assert caught.value.report["entries"]["worker"]["exit"] is None
            assert not _captured_exit_proven(caught.value.report)
            _clear_r2_quarantine(custody, expected_unknown=True)
            with pytest.raises(R2CleanupUnknown):
                R2Custody(tmp_path / "blocked", tmp_path / "blocked.json")
        else:
            custody.await_event("worker", "hello")
            assert not entry["lost"] and not custody.control_unknown
            assert entry["fd"] == retained_fd and entry["lineage"] == retained_lineage
            custody.kill_owned("worker")
            assert signals == [(retained_fd, signal.SIGKILL)]
            _r2_wait_worker_exit(witness, "worker")
            assert custody.close()["state"] == "CLOSED"
    finally:
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        monkeypatch.setattr(handshake_tests, "signal", real_signal)
        _close_fds(actor_read, actor_write, stop_read, stop_write, receipt_read, receipt_write,
                   hello_read, hello_write, ack_read, ack_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        if witness is not None:
            try:
                _r2_wait_worker_exit(witness, "worker")
                _retain_r2_independent_exit(custody, "worker", witness)
            finally:
                r2_identity_transition(witness.entries["worker"], "release")
        _clear_r2_quarantine(custody, expected_unknown=True)
        if changed_birth:
            _r2_finish_identity_scope(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("boundary", ["observe", "capture"])
def test_r2_indirect_metadata_permission_loss_is_permanent(tmp_path, monkeypatch, boundary):
    """Actorless negative model: no real actor is ever admitted or signalled."""
    import errno

    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    real_os = handshake_tests.os
    physical = r2_kernel_process(os.getpid())
    reads, probes = [], []

    def metadata(pid):
        reads.append(pid)
        if len(reads) == 1:
            raise PermissionError("modelled denied identity metadata")
        raise FileNotFoundError("modelled later metadata absence")

    def absent(pid, number):
        assert pid == os.getpid() and number == 0
        probes.append(pid)
        raise ProcessLookupError("modelled later numeric absence")

    def unavailable(*args):
        raise OSError(errno.ENOSYS, "modelled unavailable pidfd")

    try:
        custody.plan({"actor": {"kind": "W", "parent": None, "child": None}})
        custody.slots["actor"]["permitted"] = True
        custody.entries["actor"] = r2_pending_test_entry(os.getpid(), physical["birth"], process=None)
        custody.kill_owned = lambda slot: None  # This model never acquires signal authority over pytest.
        custody.LIMIT = 0.01
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, kill=absent, pidfd_open=unavailable))
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", metadata)
        if boundary == "capture":
            raw = (json.dumps(dict(nonce=custody.nonce, slot="actor", event="hello",
                                   pid=os.getpid(), birth=physical["birth"])) + "\n").encode()
            assert os.write(custody.report_write, raw) == len(raw)
            with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
                custody.pump()
        else:
            assert custody.observe("actor") is None
        assert custody.observe("actor") is None
        assert custody.entries["actor"]["lost"] and custody.control_unknown
        assert custody.entries["actor"]["exit"] is None
        assert reads == [os.getpid()] and probes == []
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["entries"]["actor"]["exit"] is None
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is caught.value.report
        with pytest.raises(R2CleanupUnknown):
            R2Custody(tmp_path / "blocked", tmp_path / "blocked.json")
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        if custody.report is None or custody.report["state"] == "UNKNOWN":
            _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("fixture_only", [False, True])
def test_r2_unreported_worker_keeps_quarantine_until_independent_exit(tmp_path, fixture_only):
    require_r2_indirect_exit()
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    actor_read, actor_write = os.pipe()
    stop_read, stop_write = os.pipe()
    receipt_read, receipt_write = os.pipe()
    witness = None
    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": "worker"},
                 "worker": {"kind": "M", "parent": "actor", "child": None}}
        custody.plan(nodes, fixture_only=tuple(nodes) if fixture_only else ())
        script, path = tmp_path / "unreported-worker.py", tmp_path / "unreported-worker.json"
        script.write_text(R2_UNREPORTED_WORKER)
        config = custody.config(nodes, script, path, actor_exit=actor_read,
                                 worker_stop=stop_read, worker_receipt=receipt_write)
        config["inherited"].extend((actor_read, stop_read, receipt_write))
        path.write_text(json.dumps(config))
        actor = custody.launch(config, "actor", os.environ)
        _close_fds(actor_read, stop_read, receipt_write)
        actor_read = stop_read = receipt_write = -1
        custody.await_event("actor", "hello")
        custody.release("actor")
        worker_pid = _r2_read_worker_receipt(receipt_read)
        witness = _r2_independent_worker_witness(custody, "worker", worker_pid)
        os.write(actor_write, b"X")
        assert actor.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        report = caught.value.report
        assert report["slot_provenance"]["worker"]["fixture_only"] is fixture_only
        assert report["slot_provenance"]["worker"]["handed_to_actor"] is True
        assert "worker" in report["unresolved_slots"] and "worker" not in report["entries"]
        assert report["entries"]["actor"]["exit"]["proof"]
        assert R2Custody.observe(witness, "worker") is None
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is report
        with pytest.raises(R2CleanupUnknown):
            R2Custody(tmp_path / "blocked", tmp_path / "blocked.json")
        _close_fds(stop_write)
        stop_write = -1
        _r2_wait_worker_exit(witness, "worker")
        _retain_r2_independent_exit(custody, "worker", witness)
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is None
        next_scope = R2Custody(tmp_path / "next", tmp_path / "next.json")
        assert next_scope.close()["state"] == "CLOSED"
    finally:
        _close_fds(actor_read, actor_write, stop_read, stop_write, receipt_read, receipt_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        if witness is not None:
            try:
                _r2_wait_worker_exit(witness, "worker")
                _retain_r2_independent_exit(custody, "worker", witness)
            finally:
                r2_identity_transition(witness.entries["worker"], "release")
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("deadline_position", ["before_exit", "during_exit", "before_eof", "after_drain"])
@pytest.mark.parametrize("pump_state", ["empty", "partial", "saturated"])
@pytest.mark.parametrize("worker_state", ["none", "reported", "unreported", "exited"])
def test_r2_close_requires_post_exit_eof_matrix(tmp_path, monkeypatch, deadline_position, pump_state, worker_state):
    """Real process exits and pipe EOF; only deadline placement is modelled.

    The worker is a second owned root here, isolating drain/EOF behavior from
    ancestry. The separate forked-worker regression covers a real descendant.
    """
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    real_os, real_time = os, time
    actor_read, actor_write = os.pipe()
    worker_read, worker_write = os.pipe()
    witness = None
    worker = None
    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": None}}
        if worker_state != "none":
            nodes["worker"] = {"kind": "H", "parent": None, "child": None}
        custody.plan(nodes)
        actor = _start_handshake_child(custody, tmp_path, "actor", "exit", "hello", actor_read)
        if worker_state == "reported":
            worker = _start_handshake_child(custody, tmp_path, "worker", "prompt", "hello", worker_read)
            custody.await_event("worker", "hello")
            custody.kill_owned("worker")
            worker.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        elif worker_state in ("unreported", "exited"):
            worker = WitnessedPopen(
                [sys.executable, "-c", "import os,sys; os.read(int(sys.argv[1]), 1)", str(worker_read)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(worker_read, custody.report_write))
            witness = _r2_independent_worker_witness(custody, "worker", worker.pid, process=worker)
            if worker_state == "exited":
                _close_fds(worker_write)
                worker_write = -1
                worker.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
                _retain_r2_independent_exit(custody, "worker", witness)
        _close_fds(actor_read, worker_read)
        actor_read = worker_read = -1
        os.write(actor_write, b"X")
        assert actor.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 7
        if pump_state == "partial":
            os.write(custody.report_write, b'{"nonce":')
        elif pump_state == "saturated":
            frame = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "timeout"}) + "\n").encode()
            os.write(custody.report_write, frame * 2)
            monkeypatch.setattr(handshake_tests, "R2_CONTROL_LINES_PER_PUMP", 1)
        trace = {"now": 0.0, "exit_seen": False, "eof_returned": False, "eof_clock_sampled": False}

        def clock():
            if deadline_position == "after_drain" and trace["eof_returned"]:
                if not trace["eof_clock_sampled"]:
                    trace["eof_clock_sampled"] = True
                    return 0.0
                return 2.0
            return trace["now"]

        observing = custody.observe

        def observed(slot):
            proof = observing(slot)
            if proof is not None:
                trace["exit_seen"] = True
                if deadline_position == "during_exit":
                    trace["now"] = 2.0
            return proof

        def reading(fd, size):
            try:
                part = real_os.read(fd, size)
            except BlockingIOError:
                if fd == custody.report_read:
                    if deadline_position == "before_exit" and not trace["exit_seen"]:
                        trace["now"] = 2.0
                    elif trace["exit_seen"] and custody.report_writer_retired and worker_state == "unreported":
                        # This live, unreported writer cannot produce EOF. Spend
                        # the ceiling instead of waiting forever for a model clock.
                        trace["now"] = 2.0
                raise
            if fd == custody.report_read:
                if deadline_position == "before_exit" and not trace["exit_seen"]:
                    trace["now"] = 2.0
                if not part:
                    trace["eof_returned"] = True
                    if deadline_position == "before_eof":
                        trace["now"] = 2.0
            return part

        custody.observe = observed
        custody.LIMIT = 1.0
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, read=reading))
        monkeypatch.setattr(handshake_tests, "time", R2Facade(real_time, monotonic=clock))
        expected_closed = (deadline_position == "after_drain" and pump_state != "partial" and
                           worker_state != "unreported")
        if expected_closed:
            report = custody.close()
            assert report["state"] == "CLOSED"
            assert report["post_exit_drain"]["complete"] is True
            assert report["post_exit_drain"]["eof_at"] <= report["post_exit_drain"]["deadline"]
            assert trace["exit_seen"] and trace["eof_returned"]
            assert clock() > report["post_exit_drain"]["deadline"]
        else:
            with pytest.raises(R2CleanupUnknown) as caught:
                custody.close()
            assert caught.value.report["state"] == "UNKNOWN"
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "time", real_time)
        _close_fds(actor_read, actor_write, worker_read, worker_write)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        if witness is not None:
            try:
                worker.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
                if custody.report["state"] == "UNKNOWN":
                    _r2_wait_worker_exit(witness, "worker")
                    _retain_r2_independent_exit(custody, "worker", witness)
            finally:
                r2_identity_transition(witness.entries["worker"], "release")
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("fixture_only", [False, True])
def test_r2_quarantine_requires_positive_synthetic_slot_proof(tmp_path, monkeypatch, fixture_only):
    """Actorless proof model: an unexposed ordinary reservation is not synthetic."""
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}},
                     fixture_only=("actor",) if fixture_only else ())
        os.write(custody.report_write, b"[]\n")
        with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
            custody.pump()
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert _captured_exit_proven(caught.value.report) is fixture_only
        _clear_r2_quarantine(custody, expected_unknown=True)
        if fixture_only:
            assert R2Custody.quarantine_report is None
            next_scope = R2Custody(tmp_path / "next", tmp_path / "next.json")
            assert next_scope.close()["state"] == "CLOSED"
        else:
            assert R2Custody.quarantine_report is caught.value.report
            with pytest.raises(R2CleanupUnknown):
                R2Custody(tmp_path / "blocked", tmp_path / "blocked.json")
    finally:
        # No actor was created or given a slot. Restore this negative model's
        # global state via monkeypatch, after proving the constructor refusal.
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_report_writer_retirement_closes_its_temporary_descriptor(tmp_path, monkeypatch):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    real_os = os
    opened = []

    def opening(*args, **kwargs):
        fd = real_os.open(*args, **kwargs)
        if args[0] == real_os.devnull:
            opened.append(fd)
        return fd

    def failed(*args, **kwargs):
        raise OSError("token=supersecretvalue")

    try:
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, open=opening, dup2=failed))
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["post_exit_drain"]["complete"] is False
        assert caught.value.report["errors"] == ["R2 fixture: report writer retirement failed"]
        assert opened
        for fd in opened:
            with pytest.raises(OSError):
                real_os.fstat(fd)
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("frame", [b"\xff\n", b"[]\n", b'{"pid":"token=supersecretvalue"}\n',
                                  b'{"pid":9223372036854775808}\n', b"Q" * 4096,
                                  b"[" * 9 + b"]" * 9 + b"\n"],
                         ids=["encoding", "schema", "type", "pid-range", "size", "depth"])
def test_r2_independent_worker_receipt_refuses_invalid_frames(frame):
    read_fd, write_fd = os.pipe()
    try:
        assert os.write(write_fd, frame) == len(frame)
        with pytest.raises(RuntimeError, match="^R2 fixture: independent worker receipt refused$"):
            _r2_read_worker_receipt(read_fd)
    finally:
        _close_fds(read_fd, write_fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("boundary", ["observe", "intake", "kill"])
def test_r2_conflicting_birth_read_cannot_be_retried_into_absence(tmp_path, monkeypatch, boundary):
    """A real two-read birth conflict remains lost when the numeric PID later disappears."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    real_path, real_kernel, real_os = handshake_tests.Path, handshake_tests.r2_kernel_process, handshake_tests.os
    reads = {"stat": 0, "kernel": 0}

    class UnstablePath:
        def __init__(self, path):
            self.path = real_path(path)

        def __truediv__(self, name):
            return UnstablePath(self.path / name)

        def read_bytes(self):
            raw = self.path.read_bytes()
            if self.path.name == "stat":
                reads["stat"] += 1
                if reads["stat"] == 2:
                    prefix, closing, tail = raw.rpartition(b")")
                    fields = tail.split()
                    fields[19] = str(int(fields[19]) + 1).encode("ascii")
                    return prefix + closing + b" " + b" ".join(fields)
            return raw

    def gone(pid, number):
        assert pid == os.getpid() and number == 0
        raise ProcessLookupError("modelled replacement disappeared")

    try:
        physical = real_kernel(os.getpid())
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}})
        custody.slots["actor"]["permitted"] = True
        custody.entries["actor"] = r2_pending_test_entry(os.getpid(), physical["birth"], process=None)
        monkeypatch.setattr(handshake_tests, "Path", UnstablePath)
        with pytest.raises(RuntimeError, match="^R2 fixture: unstable physical birth evidence$") as conflict:
            real_kernel(os.getpid())
        monkeypatch.setattr(handshake_tests, "Path", real_path)

        def unstable_then_missing(pid):
            reads["kernel"] += 1
            if boundary == "kill" and reads["kernel"] == 1:
                return physical
            if reads["kernel"] == (2 if boundary == "kill" else 1):
                raise conflict.value
            raise FileNotFoundError("modelled numeric absence")

        monkeypatch.setattr(handshake_tests, "r2_kernel_process", unstable_then_missing)
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, kill=gone))
        if boundary == "intake":
            raw = (json.dumps({"nonce": custody.nonce, "slot": "actor", "event": "hello",
                               "pid": os.getpid(), "birth": physical["birth"]}) + "\n").encode()
            assert os.write(custody.report_write, raw) == len(raw)
            with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
                custody.pump()
        elif boundary == "kill":
            with pytest.raises(R2IdentityConflict, match="^R2 fixture: unstable physical birth evidence$"):
                custody.kill_owned("actor")
        else:
            assert custody.observe("actor") is None
        assert custody.observe("actor") is None
        assert custody.entries["actor"]["lost"] is True
        assert custody.control_unknown is True
        assert reads["kernel"] == (2 if boundary == "kill" else 1)
        custody.kill_owned = lambda slot: None  # Actorless model never grants authority over this test process.
        custody.LIMIT = 0.01
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["entries"]["actor"]["exit"] is None
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is caught.value.report
    finally:
        monkeypatch.setattr(handshake_tests, "Path", real_path)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        monkeypatch.setattr(handshake_tests, "os", real_os)
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
@pytest.mark.parametrize("target", ["actor", "worker", "duplicate"])
def test_r2_forged_identity_never_weakens_genuine_custody(tmp_path, monkeypatch, target):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    latch_read, latch_write = os.pipe()
    ack_read, ack_write = os.pipe()
    process = None
    retained = None
    real_os, candidate_fds = handshake_tests.os, []

    def candidate_pidfd(pid, *args):
        fd = real_os.pidfd_open(pid, *args)
        candidate_fds.append(fd)
        return fd

    try:
        _plan_reserved_sibling(custody)
        script = tmp_path / "handshake-child.py"
        # This real actor ignores safety EOF. Cleanup must keep its original kill authority.
        script.write_text(R2_HANDSHAKE_CHILD.replace('if mode == "exit" and field == "running":',
            'if mode == "stubborn":\n    if field == "announce":\n        hello()\n'
            '    ack_fd = config["ack_write"]\n'
            '    os.write(ack_fd, b"A")\n    select.select([], [], [], None)\n'
            'if mode == "exit" and field == "running":'), encoding="utf-8")
        process = _start_handshake_child(custody, tmp_path, "actor", "stubborn",
                                         "announce" if target == "duplicate" else "hello",
                                         latch_read, ack_write=ack_write)
        _read_ack(ack_read)
        if target == "duplicate":
            custody.await_event("actor", "hello")
        else:
            assert custody.slots["actor"]["hello"] is False
        retained = dict(custody.entries["actor"])
        # The unpermitted sibling is refused before capture. The real exposed-worker
        # regression separately exercises a forged candidate after an actual grant.
        if hasattr(real_os, "pidfd_open"):
            monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=candidate_pidfd))
        raw = (json.dumps({"nonce": custody.nonce, "slot": "actor" if target == "duplicate" else target,
                           "event": "hello", "pid": retained["pid"] if target == "duplicate" else 1,
                           "birth": retained["birth"] if target == "duplicate" else "9"}) + "\n").encode()
        assert os.write(custody.report_write, raw) == len(raw)
        with pytest.raises(RuntimeError):
            custody.pump()
        assert custody.report_rejected and custody.control_unknown
        assert custody.entries["actor"] == retained
        assert "worker" not in custody.entries
        for fd in candidate_fds:
            with pytest.raises(OSError):
                real_os.fstat(fd)
        monkeypatch.setattr(handshake_tests, "os", real_os)
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["entries"]["actor"]["exit"]["returncode"] == -signal.SIGKILL
        assert process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == -signal.SIGKILL
        _assert_exit_proofs(caught.value.report)
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        _close_fds(latch_read, latch_write, ack_read, ack_write)
        if process is not None:
            if process.poll() is None:
                process.kill()  # Independent original-instance owner recovery, including the RED baseline.
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
            if retained is not None and custody.report is None:
                # Restore only the independently retained genuine identity before retiring this scope.
                candidate = custody.entries.get("worker")
                if candidate is not None and isinstance(candidate.get("fd"), int):
                    _close_fds(candidate["fd"])
                custody.entries = {"actor": retained}
                r2_identity_transition(retained, "native_exit")
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="handshake custody reads Linux /proc")
def test_r2_unterminated_frame_at_eof_is_rejected_and_keeps_reserved_slots(tmp_path):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    try:
        _plan_reserved_sibling(custody)  # Actorless model; neither synthetic slot is handed to an actor.
        assert os.write(custody.report_write, b"{}") == 2
        assert custody._retire_report_writer()
        with pytest.raises(RuntimeError, match="^R2 fixture: control message refused$"):
            custody.pump()
        assert custody.report_rejected and custody.control_unknown
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["unresolved_slots"] == ["actor", "worker"]
        assert caught.value.report["uncreated_slots"] == []
    finally:
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupUnknown:
                pass
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"),
                    reason="indirect custody requires Linux pidfds")
def test_r2_reaped_indirect_worker_hello_uses_retained_pidfd(tmp_path, monkeypatch):
    require_r2_indirect_exit(pidfd=True)
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    hello_read, hello_write = os.pipe()
    ack_read, ack_write = os.pipe()
    real_kernel = handshake_tests.r2_kernel_process
    process = None
    try:
        nodes = {"actor": {"kind": "H", "parent": None, "child": "worker"},
                 "worker": {"kind": "W", "parent": "actor", "child": None}}
        custody.plan(nodes)
        script = tmp_path / "indirect-reap.py"
        script.write_text('''import json, os, select, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
def emit(slot, event, **fields):
    raw = (json.dumps(dict(nonce=config["nonce"], slot=slot, event=event, **fields)) + "\\n").encode()
    assert os.write(config["report_write"], raw) == len(raw)
def birth():
    return Path("/proc/self/stat").read_bytes().rpartition(b")")[2].split()[19].decode()
def wait(fd):
    assert select.select([fd], [], [], 60)[0]
    return os.read(fd, 1)
emit("actor", "hello", pid=os.getpid(), birth=birth())
assert wait(config["nodes"]["actor"]["gate"]) == b"G"
pid = os.fork()
if pid == 0:
    assert wait(config["hello_read"]) == b"H"
    emit("worker", "hello", pid=os.getpid(), birth=birth())
    os._exit(7)
worker_birth = Path("/proc") / str(pid) / "stat"
emit("actor", "created", child="worker", child_pid=pid,
     child_birth=worker_birth.read_bytes().rpartition(b")")[2].split()[19].decode())
os.write(config["ack_write"], b"A")
assert os.waitpid(pid, 0)[0] == pid
os.write(config["ack_write"], b"A")
wait(config["safety_read"])
''', encoding="utf-8")
        config_path = tmp_path / "indirect.json"
        config = custody.config(nodes, script, config_path, hello_read=hello_read, ack_write=ack_write)
        config["inherited"].extend((hello_read, ack_write))
        config_path.write_text(json.dumps(config), encoding="utf-8")
        process = custody.launch(config, "actor", os.environ)
        custody.await_event("actor", "hello")
        custody.release("actor")
        _read_ack(ack_read)
        custody.pump()
        worker = custody.entries["worker"]
        assert isinstance(worker["fd"], int) and worker["verified_fd"], "qualified worker pidfd unavailable"
        assert worker["process"] is None and worker["exit"] is None
        os.write(hello_write, b"H")
        _read_ack(ack_read)  # Parent has actually reaped the worker; hello remains queued.
        assert not (Path("/proc") / str(worker["pid"])).exists()
        reads = []

        def kernel_without_reaped_worker(pid):
            if pid == worker["pid"]:
                reads.append(pid)
                raise FileNotFoundError("reaped worker has no proc metadata")
            return real_kernel(pid)

        monkeypatch.setattr(handshake_tests, "r2_kernel_process", kernel_without_reaped_worker)
        custody.await_event("worker", "hello")
        assert reads == []
        assert worker["exit"] == {"proof": "original_pidfd_exit"}
        assert worker["lost"] is False
        assert custody.close()["state"] == "CLOSED"
    finally:
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        _close_fds(hello_read, hello_write, ack_read, ack_write)
        entry = custody.entries.get("worker")
        if entry is not None and entry["verified_fd"] and isinstance(entry["fd"], int):
            poller = select.poll()
            poller.register(entry["fd"], select.POLLIN)
            if poller.poll(0):
                # Independent retained-pidfd recovery also retires the failing RED baseline safely.
                if not entry["lost"]:
                    r2_identity_transition(entry, "pidfd_exit")
        if custody.report is None:
            try:
                custody.close()
            except R2CleanupError:
                pass
        if process is not None:
            process.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        _clear_r2_quarantine(custody, expected_unknown=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="proof custody reads Linux /proc")
@pytest.mark.parametrize("failure", [FileNotFoundError, PermissionError, R2IdentityConflict, KeyboardInterrupt])
def test_r2_candidate_handle_is_never_committed_before_identity(tmp_path, monkeypatch, failure):
    """Actorless recycled-PID model: a readable candidate is not the original child's proof."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    real_os, real_kernel = handshake_tests.os, handshake_tests.r2_kernel_process
    read_fd, write_fd = os.pipe()
    os.close(write_fd)  # A candidate which exits before metadata is available is immediately readable.
    candidates = []
    physical = r2_kernel_process(os.getpid())

    def opening(pid):
        candidate = real_os.dup(read_fd)
        candidates.append(candidate)
        return candidate

    def refused(pid):
        raise failure("modelled candidate identity unavailable")

    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None},
                      "worker": {"kind": "W", "parent": "actor", "child": None}})
        custody.entries["actor"] = r2_pending_test_entry(os.getpid(), physical["birth"], process=None)
        custody.entries["worker"] = r2_pending_test_entry(os.getpid(), physical["birth"], process=None)
        r2_identity_transition(custody.entries["worker"], "capture", verified=True)
        custody.kill_owned = lambda slot: None  # This model never owns the pytest process.
        custody.LIMIT = 0.01
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=opening))
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", refused)
        with pytest.raises(failure, match="^modelled candidate identity unavailable$"):
            custody.capture("worker", os.getpid())
        assert len(candidates) == 1
        with pytest.raises(OSError):
            real_os.fstat(candidates[0])
        candidates.clear()
        entry = custody.entries["worker"]
        assert entry["fd"] is None and entry["verified_fd"] is False
        assert custody.observe("worker") is None
        assert entry["exit"] is None
        with pytest.raises(R2CleanupUnknown) as caught:
            custody.close()
        assert caught.value.report["entries"]["worker"]["exit"] is None
        _clear_r2_quarantine(custody, expected_unknown=True)
        assert R2Custody.quarantine_report is caught.value.report
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        _close_fds(read_fd, *candidates)
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="proof custody reads Linux /proc")
@pytest.mark.parametrize("failure", ["lost", "poll-error"])
def test_r2_handshake_never_calls_unproven_identity_an_exit(tmp_path, monkeypatch, failure):
    """Actorless diagnostic model; no process or descriptor acquires signal authority."""
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    physical = r2_kernel_process(os.getpid())

    calls = []

    def unavailable():
        calls.append(True)
        raise OSError("modelled native wait unavailable")

    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}})
        entry = r2_pending_test_entry(os.getpid(), physical["birth"])
        if failure == "poll-error":
            entry["process"] = SimpleNamespace(pid=os.getpid(), poll=unavailable, returncode=None,
                                               native_wait_evidence=None, native_wait_unavailable=False)
            entry["native_owner"] = entry["process"]
            r2_identity_transition(entry, "capture", verified=True)
        else:
            r2_identity_transition(entry, "lost")
        custody.entries["actor"] = entry
        with pytest.raises(RuntimeError) as caught:
            custody.await_event("actor", "hello")
        _, evidence = _handshake_evidence(caught)
        assert evidence["reason"] == ("identity lost" if failure == "lost" else "wait unavailable")
        assert "exit_proof" not in evidence and evidence["returncode"] is None
        assert custody.control_unknown
        if failure == "poll-error":
            assert calls and entry["wait_status"] == "unavailable" and entry["wait_error"]
    finally:
        _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="proof custody reads Linux /proc")
@pytest.mark.parametrize("state", ["pending", "captured", "lost", "exited"])
@pytest.mark.parametrize("event", ["register", "capture", "lost", "native_exit", "pidfd_exit", "adopt_exit", "release", "invalid"])
def test_r2_identity_transition_table(state, event):
    """Every state/event pair is defined; no unverified handle or terminal loss proves exit."""
    if not hasattr(os, "pidfd_open"):
        pytest.skip("state table requires Linux pidfds")
    child = WitnessedPopen([sys.executable, "-I", "-c", "import os; os.read(0,1)"], stdin=subprocess.PIPE)
    entry = dict(pid=child.pid, birth=child.native_birth, process=child, native_owner=child)
    candidate = None
    try:
        try:
            candidate = os.pidfd_open(child.pid)
        except OSError:
            pytest.skip("kernel refused the state-table pidfd")
        handshake_tests.r2_identity_transition(entry, "register")
        if state != "pending":
            handshake_tests.r2_identity_transition(entry, "capture", fd=candidate, verified=True)
            candidate = None
        if state == "lost":
            handshake_tests.r2_identity_transition(entry, "lost")
        elif state == "exited":
            child.stdin.close()
            assert child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 0
            handshake_tests.r2_identity_transition(entry, "native_exit")
        source = entry
        if event == "adopt_exit":
            if not child.stdin.closed:
                child.stdin.close()
            assert child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS) == 0
            source = dict(pid=child.pid, birth=child.native_birth, process=child, native_owner=child)
            handshake_tests.r2_identity_transition(source, "register")
            handshake_tests.r2_identity_transition(source, "capture", verified=True)
            handshake_tests.r2_identity_transition(source, "native_exit")
        illegal = event in ("invalid", "register") or (state in ("lost", "exited") and event == "capture") or (
            state in ("pending", "lost") and event in ("native_exit", "pidfd_exit")) or (
            event == "adopt_exit" and state == "lost")
        if illegal:
            with pytest.raises(RuntimeError, match="^R2 fixture: illegal identity proof transition$"):
                handshake_tests.r2_identity_transition(entry, event, source=source)
        else:
            handle = candidate if candidate is not None else entry.get("fd")
            handshake_tests.r2_identity_transition(entry, event, fd=handle, verified=True, source=source)
            if event == "capture":
                candidate = None
            expected = "lost" if event == "lost" else "captured" if event == "capture" else (
                "exited" if event == "adopt_exit" else "pending" if event == "release" and
                state == "captured" else state)
            assert entry["proof_state"] == expected
        assert entry["verified_fd"] is isinstance(entry["fd"], int)
        if entry["proof_state"] == "captured":
            assert isinstance(entry["fd"], int)
        assert not (entry["lost"] and entry["exit"] is not None)
    finally:
        _close_fds(candidate)
        if "proof_state" in entry:
            r2_identity_transition(entry, "release")
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        child.wait(timeout=R2_HANDSHAKE_CEILING_SECONDS)
        child.close_native_handle()


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"),
                    reason="pending original-instance evidence requires Linux pidfds")
@pytest.mark.parametrize("observation", ["zombie", "missing", "read-error"])
def test_r2_verified_handle_pending_exit_does_not_poison_intake(tmp_path, monkeypatch, observation):
    """Actorless OS-boundary model of leader exit before the original handle becomes readable."""
    try:
        candidate = os.pidfd_open(os.getpid())
    except OSError:
        pytest.skip("kernel pidfd capability unavailable")
    custody = None
    real_os, real_kernel = handshake_tests.os, handshake_tests.r2_kernel_process
    physical = None
    probes = []

    def metadata(pid):
        assert pid == os.getpid()
        if observation == "missing":
            raise FileNotFoundError("modelled metadata gone before pidfd readiness")
        if observation == "read-error":
            raise ProcessLookupError("modelled exit during metadata read")
        return {**physical, "state": "Z"}

    def numeric(pid, number):
        probes.append((pid, number))
        raise ProcessLookupError("modelled numeric absence")

    try:
        physical = real_kernel(os.getpid())
        custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
        custody.plan({"actor": {"kind": "W", "parent": None, "child": None}})
        entry = r2_pending_test_entry(os.getpid(), physical["birth"])
        r2_identity_transition(entry, "capture", fd=candidate, verified=True)
        candidate = None
        custody.entries["actor"] = entry
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", metadata)
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, kill=numeric))
        assert custody.observe("actor") is None
        assert not custody.control_unknown
        assert not entry["lost"] and entry["exit"] is None
        assert entry.get("wait_status") is None and probes == []
    finally:
        monkeypatch.setattr(handshake_tests, "r2_kernel_process", real_kernel)
        monkeypatch.setattr(handshake_tests, "os", real_os)
        _close_fds(candidate)
        if custody is not None:
            _release_r2_test_descriptors(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="indirect custody reads Linux /proc")
@pytest.mark.parametrize("consumer", ["independent", "omitted", "unreported", "reaped", "identity-scope"])
def test_r2_indirect_tests_refuse_unavailable_capability_before_spawn(tmp_path, monkeypatch, consumer):
    spawned = []

    def forbidden(*args, **kwargs):
        spawned.append(True)
        raise AssertionError("capability refusal must precede actor creation")

    monkeypatch.setattr(handshake_tests, "r2_indirect_exit_capability", lambda: {"pidfd": False, "subreaper": False})
    monkeypatch.setattr(handshake_tests, "WitnessedPopen", forbidden)
    with pytest.raises(pytest.skip.Exception, match="indirect exit evidence unavailable"):
        if consumer == "independent":
            test_r2_closure_requires_independent_evidence_for_exposed_workers(
                tmp_path, monkeypatch, "silent-never", "W")
        elif consumer == "omitted":
            test_r2_omitted_ungranted_descendant_keeps_quarantine(tmp_path, True)
        elif consumer == "unreported":
            test_r2_unreported_worker_keeps_quarantine_until_independent_exit(tmp_path, False)
        elif consumer == "reaped":
            test_r2_reaped_indirect_worker_hello_uses_retained_pidfd(tmp_path, monkeypatch)
        else:
            request = SimpleNamespace(node=SimpleNamespace(nodeid="unused-child-scope"))
            test_r2_live_recapture_keeps_original_ancestry(tmp_path, monkeypatch, request, True)
    assert spawned == []
    assert not (tmp_path / "identity-scope").exists()
    assert not (tmp_path / "custody").exists()
    assert R2Custody.quarantine_report is None


@pytest.mark.parametrize("outcome", ["skipped", "passed-without-proof", "missing-outcome", "failed",
                                     "reported-failure", "invalid-outcome", "oversize-outcome", "invalid-proof"])
def test_r2_identity_scope_distinguishes_child_outcomes(tmp_path, monkeypatch, outcome):
    """Model only the external child boundary; no actor or exit proof is manufactured."""
    real_subprocess = handshake_tests.subprocess

    def child(command, **kwargs):
        folder = tmp_path / "identity-scope"
        if outcome != "missing-outcome":
            from xml.etree import ElementTree
            suite = ElementTree.Element("testsuite")
            case = ElementTree.SubElement(suite, "testcase", name="identity-child")
            if outcome == "skipped":
                ElementTree.SubElement(case, "skipped", message="kernel denied indirect exit evidence")
            elif outcome in ("failed", "reported-failure"):
                ElementTree.SubElement(case, "failure", message="child assertion failed")
            ElementTree.ElementTree(suite).write(folder / "outcome.xml", encoding="utf-8")
            if outcome == "invalid-outcome":
                (folder / "outcome.xml").write_bytes(b"invalid XML")
            elif outcome == "oversize-outcome":
                (folder / "outcome.xml").write_bytes(b"X" * 65537)
            elif outcome == "invalid-proof":
                (folder / "proof.json").write_text("[]")
        return real_subprocess.CompletedProcess(command, 1 if outcome == "failed" else 0, "", "")

    monkeypatch.setattr(handshake_tests, "subprocess", R2Facade(real_subprocess, run=child))
    if outcome == "skipped":
        with pytest.raises(pytest.skip.Exception, match="^kernel denied indirect exit evidence$"):
            _r2_run_identity_scope(tmp_path, "identity-child")
    else:
        expected = {"passed-without-proof": "R2 fixture: identity scope child passed without closure proof",
                    "missing-outcome": "R2 fixture: identity scope child outcome unavailable",
                    "failed": "R2 fixture: identity scope child failed",
                    "reported-failure": "R2 fixture: identity scope child failed",
                    "invalid-outcome": "R2 fixture: identity scope child outcome unavailable",
                    "oversize-outcome": "R2 fixture: identity scope child outcome unavailable",
                    "invalid-proof": "R2 fixture: identity scope child proof unavailable"}[outcome]
        with pytest.raises(AssertionError, match="^" + re.escape(expected)):
            _r2_run_identity_scope(tmp_path, "identity-child")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native subreaper probes require Linux")
@pytest.mark.parametrize("opening,native,expected", [
    ("absent", False, {"pidfd": False, "subreaper": False}),
    ("denied", False, {"pidfd": False, "subreaper": False}),
    ("denied", True, {"pidfd": False, "subreaper": True}),
    ("usable", False, {"pidfd": True, "subreaper": False}),
    ("usable", True, {"pidfd": True, "subreaper": True}),
])
def test_r2_indirect_capability_uses_only_existing_native_ownership(opening, native, expected):
    """Any native ownership change belongs to this empty child scope, never the pytest worker."""
    if opening == "usable":
        require_r2_indirect_exit(pidfd=True)
    program = '''import ctypes, errno, json, os, sys
sys.path.insert(0, sys.argv[1])
from tests.integration import test_hierarchy_launcher as helper
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, int(sys.argv[3]), 0, 0, 0) != 0:
    sys.exit(77)
def denied(pid):
    raise OSError(errno.ENOSYS, "modelled denied pidfd")
if sys.argv[2] != "usable":
    helper.os = helper.R2Facade(os, pidfd_open=None if sys.argv[2] == "absent" else denied)
print(json.dumps(helper.r2_indirect_exit_capability()))
'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(ROOT), opening, str(int(native))],
                            text=True, capture_output=True, timeout=R2_HANDSHAKE_CEILING_SECONDS)
    if result.returncode == 77:
        pytest.skip("native subreaper capability unavailable")
    assert result.returncode == 0, _r2_untrusted_text(result.stderr, 4096)
    assert json.loads(result.stdout) == expected


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"),
                    reason="pidfd descriptor probes require Linux pidfds")
@pytest.mark.parametrize("reject_poll", [False, True], ids=["usable", "poll-denied"])
def test_r2_indirect_capability_closes_its_probe_descriptor(monkeypatch, reject_poll):
    if not reject_poll:
        require_r2_indirect_exit(pidfd=True)
    real_os, real_select = handshake_tests.os, handshake_tests.select
    original, opened = None, []

    def opening(pid):
        assert pid == os.getpid()
        descriptor = real_os.dup(original)
        opened.append(descriptor)
        return descriptor

    class Rejected:
        def register(self, *args):
            raise OSError("modelled pidfd polling unavailable")

    try:
        try:
            original = real_os.pidfd_open(os.getpid())
        except OSError:
            pytest.skip("kernel pidfd capability unavailable")
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=opening))
        if reject_poll:
            monkeypatch.setattr(handshake_tests, "select", R2Facade(real_select, poll=Rejected))
        capability = r2_indirect_exit_capability()
        assert capability["pidfd"] is (not reject_poll)
        assert len(opened) == 1
        with pytest.raises(OSError):
            real_os.fstat(opened[0])
        opened.clear()
        real_os.fstat(original)
    finally:
        _close_fds(original, *opened)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"),
                    reason="signal authority probes require Linux pidfds")
@pytest.mark.parametrize("unavailable", ["absent", "denied"])
def test_r2_indirect_capability_requires_signal_authority(monkeypatch, unavailable):
    real_os, real_signal = handshake_tests.os, handshake_tests.signal
    original, opened = None, []

    def opening(pid):
        assert pid == os.getpid()
        descriptor = real_os.dup(original)
        opened.append(descriptor)
        return descriptor

    def denied(*args):
        raise OSError("modelled pidfd signal permission denied")

    try:
        try:
            original = real_os.pidfd_open(os.getpid())
        except OSError:
            pytest.skip("kernel pidfd capability unavailable")
        monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=opening))
        monkeypatch.setattr(handshake_tests, "signal", R2Facade(
            real_signal, pidfd_send_signal=None if unavailable == "absent" else denied))
        assert r2_indirect_exit_capability()["pidfd"] is False
        with pytest.raises(pytest.skip.Exception, match="usable pidfd required"):
            require_r2_indirect_exit(pidfd=True)
        assert len(opened) == 2
        for descriptor in opened:
            with pytest.raises(OSError):
                real_os.fstat(descriptor)
        opened.clear()
        real_os.fstat(original)
    finally:
        _close_fds(original, *opened)


@pytest.mark.parametrize("native", [False, True], ids=["unavailable", "subreaper-only"])
@pytest.mark.parametrize("consumer", ["tree", "group", "captured", "caller"])
def test_r2_indirect_case_skips_before_reservation_or_spawn(launch, monkeypatch, consumer, native):
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case, _teardown_r2_case
    spawned = []

    def forbidden(*args, **kwargs):
        spawned.append(True)
        raise AssertionError("unavailable indirect evidence must precede spawn")

    monkeypatch.setattr(handshake_tests.R2Custody, "quarantine_report", None)
    monkeypatch.setattr(handshake_tests, "r2_indirect_exit_capability", lambda: {"pidfd": False, "subreaper": native})
    monkeypatch.setattr(handshake_tests, "WitnessedPopen", forbidden)
    context = R2Case(launch)
    monkeypatch.setattr(handshake_tests.R2Custody, "plan", forbidden)
    try:
        with pytest.raises(pytest.skip.Exception, match="indirect exit evidence unavailable"):
            if consumer == "tree":
                context.spawn(tree=True)
            elif consumer == "group":
                context.spawn_group(None)
            elif consumer == "captured":
                context.spawn_exec([sys.executable], None, [sys.executable],
                                   captured=[{"argv": [], "expected_argv": [], "logical_argv": None}])
            else:
                context.runner(session="modelled-caller")
        assert spawned == [] and context.configs == [] and context.custody.slots == {}
        assert context.close()["state"] == "CLOSED"
        _teardown_r2_case(context)
    finally:
        # The Popen boundary is forbidden throughout this actorless negative model.
        try:
            context.close()
        except R2CleanupError:
            pass
        if context.custody.report is None or context.custody.report["state"] == "UNKNOWN":
            _release_r2_test_descriptors(context.custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="indirect custody reads Linux /proc")
@pytest.mark.parametrize("case", ["reaped", "wait_unavailable"])
@pytest.mark.parametrize("kind", list("HMWCR"))
def test_r2_indirect_signal_cases_refuse_subreaper_without_pidfd(tmp_path, monkeypatch, case, kind):
    admitted = []

    def forbidden(*args, **kwargs):
        admitted.append(True)
        raise AssertionError("indirect signalling requires a pidfd before custody admission")

    monkeypatch.setattr(handshake_tests, "r2_indirect_exit_capability", lambda: {"pidfd": False, "subreaper": True})
    monkeypatch.setattr(handshake_tests.R2Custody, "__init__", forbidden)
    monkeypatch.setattr(handshake_tests, "WitnessedPopen", forbidden)
    with pytest.raises(pytest.skip.Exception, match="usable pidfd required"):
        test_r2_closure_requires_independent_evidence_for_exposed_workers(tmp_path, monkeypatch, case, kind)
    assert admitted == [] and not (tmp_path / "custody").exists()
    assert R2Custody.quarantine_report is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native custody reads Linux /proc")
def test_r2_direct_case_without_pidfd_uses_owned_native_wait(launch, monkeypatch):
    from tests.integration.test_hierarchy_launcher_stop_ownership import R2Case, _teardown_r2_case
    import errno
    real_os = handshake_tests.os

    def denied(*args):
        raise OSError(errno.ENOSYS, "modelled pidfd unavailable")

    monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, pidfd_open=denied))
    monkeypatch.setattr(handshake_tests, "r2_indirect_exit_capability", lambda: {"pidfd": False, "subreaper": True})
    require_r2_indirect_exit()
    context = R2Case(launch)
    try:
        child = context.spawn()
        entry = next(row for row in context.custody.entries.values() if row["process"] is child)
        assert entry["fd"] is None and child.native_handle is None
        report = context.close()
        assert report["state"] == "CLOSED"
        proof = next(row["exit"] for row in report["entries"].values() if row["pid"] == child.pid)
        assert proof["proof"] == "native_waitpid" and proof["wait_pid"] == child.pid
        assert proof["wait_status"] == child.native_wait_evidence["wait_status"]
        (launch.tmp / "native-only-proof.json").write_text(json.dumps({"report": report,
                                                                    "native_wait": child.native_wait_evidence}))
        assert R2Custody.quarantine_report is None
        _teardown_r2_case(context)
    finally:
        context.close()


@pytest.mark.skipif(os.name != "posix", reason="slot files require no-follow directory descriptors")
@pytest.mark.parametrize("kind", ["hardlink", "foreign-owner", "closed"])
def test_r2_stderr_tail_refuses_unowned_linked_or_closed_slots(tmp_path, monkeypatch, kind):
    if not _r2_slot_read_capable() or os.open not in os.supports_dir_fd:
        pytest.skip("slot files require no-follow directory descriptors")
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    path = custody.folder / "actor.stderr"
    custody.stderr_paths["actor"] = path
    outside = tmp_path / "outside"
    outside.write_text("outside-marker")
    real_os, opened = handshake_tests.os, []

    def opening(*args, **kwargs):
        fd = real_os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def metadata(fd):
        info = real_os.fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                               st_uid=info.st_uid + 1, st_size=info.st_size)

    def forbidden_read(*args):
        raise AssertionError("unsafe stderr must be refused before reading")

    try:
        if kind == "hardlink":
            os.link(outside, path)
        else:
            path.write_text("outside-marker")
        if kind == "closed":
            custody.close()
        monkeypatch.setattr(handshake_tests, "os", R2Facade(
            real_os, open=opening, read=forbidden_read,
            fstat=metadata if kind == "foreign-owner" else real_os.fstat))
        expected = "[stderr omitted: closed]" if kind == "closed" else "actor.stderr:\n[stderr omitted: unsafe]"
        for _ in range(2):
            assert custody.stderr_tail() == expected
        for fd in opened:
            with pytest.raises(OSError):
                real_os.fstat(fd)
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        custody.close()


def test_r2_wait_until_accepts_readiness_after_five_seconds():
    clock = {"now": 0.0}
    waits = []

    def block(seconds):
        waits.append(seconds)
        clock["now"] += min(seconds, 1.0)

    wait_until(lambda: clock["now"] >= 6.0, clock=lambda: clock["now"], block=block)
    assert waits and 6.0 <= clock["now"] < R2_HANDSHAKE_CEILING_SECONDS


@pytest.mark.skipif(os.name != "posix", reason="slot files require no-follow directory descriptors")
@pytest.mark.parametrize("kind", ["regular", "missing", "symlink", "fifo", "hardlink", "foreign-owner"])
def test_r2_slot_ready_refuses_unsafe_files_before_reading(tmp_path, monkeypatch, kind):
    if not _r2_slot_read_capable() or os.open not in os.supports_dir_fd:
        pytest.skip("slot files require no-follow directory descriptors")
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    path, outside = tmp_path / "actor.started", tmp_path / "outside"
    outside.write_text("outside-marker")
    real_os, opened = handshake_tests.os, []

    def opening(*args, **kwargs):
        assert kwargs == {"dir_fd": directory}
        assert args[1] & real_os.O_NOFOLLOW and args[1] & real_os.O_NONBLOCK
        fd = real_os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def metadata(fd):
        info = real_os.fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                               st_uid=info.st_uid + 1 if kind == "foreign-owner" else info.st_uid)

    def forbidden_read(*args):
        raise AssertionError("readiness never reads slot contents")

    try:
        if kind in ("regular", "foreign-owner"):
            path.touch()
        elif kind == "symlink":
            symlink_or_skip(outside, path)
        elif kind == "fifo":
            os.mkfifo(path)
        elif kind == "hardlink":
            os.link(outside, path)
        monkeypatch.setattr(handshake_tests, "os", R2Facade(
            real_os, open=opening, fstat=metadata, read=forbidden_read))
        for _ in range(2):
            if kind in ("regular", "missing"):
                assert _r2_slot_ready(directory, path.name) is (kind == "regular")
            else:
                with pytest.raises(RuntimeError, match="^R2 fixture: slot file refused$"):
                    _r2_slot_ready(directory, path.name)
        for fd in opened:
            with pytest.raises(OSError):
                real_os.fstat(fd)
    finally:
        monkeypatch.setattr(handshake_tests, "os", real_os)
        os.close(directory)


@pytest.mark.skipif(os.name != "posix", reason="slot files require no-follow directory descriptors")
def test_r2_slot_ready_keeps_the_directory_anchor_across_rename(tmp_path):
    if not _r2_slot_read_capable() or os.open not in os.supports_dir_fd:
        pytest.skip("slot files require no-follow directory descriptors")
    root, outside = tmp_path / "slot", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "actor.started").touch()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        root.rename(tmp_path / "moved")
        symlink_or_skip(outside, root)
        assert _r2_slot_ready(fd, "actor.started") is True
        (tmp_path / "moved" / "actor.started").unlink()
        symlink_or_skip(outside, tmp_path / "moved" / "actor.started")
        with pytest.raises(RuntimeError, match="^R2 fixture: slot file refused$"):
            _r2_slot_ready(fd, "actor.started")
    finally:
        os.close(fd)


def test_r2_slot_probe_unsupported_platform_is_a_fixed_refusal(monkeypatch):
    monkeypatch.setattr(handshake_tests, "_r2_slot_read_capable", lambda: False)
    with pytest.raises(RuntimeError, match="^R2 fixture: slot file support unavailable$"):
        _r2_slot_ready(123, "actor.started")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="slot events require Linux inotify")
def test_r2_slot_events_wake_for_a_write_after_directory_rename(tmp_path):
    folder, outside = tmp_path / "slot", tmp_path / "outside"
    folder.mkdir()
    outside.mkdir()
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with R2SlotEvents(fd) as events:
            folder.rename(tmp_path / "moved")
            symlink_or_skip(outside, folder)
            (tmp_path / "moved" / "actor.started").touch()
            assert events.wait(R2_HANDSHAKE_CEILING_SECONDS) is True
            assert _r2_slot_ready(fd, "actor.started") is True
            watched = events.fd
        with pytest.raises(OSError):
            os.fstat(watched)
    finally:
        os.close(fd)


def test_r2_slot_events_unsupported_platform_is_a_fixed_refusal(monkeypatch):
    monkeypatch.setattr(handshake_tests, "_r2_slot_events_capable", lambda: False)
    with pytest.raises(RuntimeError, match="^R2 fixture: slot event support unavailable$"):
        R2SlotEvents(123)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="slot events require Linux inotify")
@pytest.mark.parametrize("failure", ["watch", "missing-abi"])
def test_r2_slot_event_setup_failure_closes_its_descriptor(tmp_path, failure):
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    candidate = os.dup(directory)

    class Notify:
        def inotify_init1(self, flags):
            return candidate

        def inotify_add_watch(self, *args):
            if failure == "missing-abi":
                raise AttributeError("untrusted-marker")
            return -1

    try:
        expected = "watch refused" if failure == "watch" else "support unavailable"
        with pytest.raises(RuntimeError, match="^R2 fixture: slot event " + expected + "$"):
            R2SlotEvents(directory, notify=Notify())
        with pytest.raises(OSError):
            os.fstat(candidate)
        os.fstat(directory)  # The caller's anchor is still owned by the caller.
    finally:
        os.close(directory)


def test_r2_wait_until_rechecks_readiness_at_the_ceiling_and_refuses_a_hang():
    state = {"now": 0, "ready": False}

    def block(remaining):
        state.update(now=61, ready=True)

    wait_until(lambda: state["ready"], clock=lambda: state["now"], block=block)
    state.update(now=0, ready=False, reads=0)

    def crossing():
        state["reads"] += 1
        if state["reads"] == 2:
            state.update(now=61, ready=True)
        return state["now"]

    wait_until(lambda: state["ready"], clock=crossing)
    state.update(now=0, ready=False)
    with pytest.raises(AssertionError, match="^condition not met within 60.0 s$"):
        wait_until(lambda: False, clock=lambda: state["now"],
                   block=lambda remaining: state.update(now=61))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="slot events require Linux inotify")
def test_r2_slot_wait_requires_the_marker_even_after_another_handshake_succeeds(tmp_path):
    custody = R2Custody(tmp_path / "custody", tmp_path / "quarantine.json")
    calls = []

    def announced():
        calls.append(True)
        if len(calls) == 2:
            (custody.folder / "actor.started").touch()
        return True  # A successful service call is not the marker's readiness.

    try:
        custody.plan({"actor": {"kind": "H", "parent": None, "child": None}}, fixture_only=("actor",))
        custody.await_slot_file("actor.started", "actor", before=announced)
        assert len(calls) == 2
    finally:
        custody.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="actor control descriptors require Linux")
def test_r2_exit_marker_reuses_its_anchor_and_closes_it(tmp_path):
    folder = tmp_path / "control"
    folder.mkdir()
    custody = R2Custody(folder / "custody", tmp_path / "quarantine.json")
    nodes = {"actor": {"kind": "H", "parent": None, "child": None}}
    custody.plan(nodes, fixture_only=("actor",))
    try:
        first = custody.config(nodes, folder / "actor.py", folder / "actor.json",
                               exit_file=str(folder / "actor.exit"))
        fd = first["exit_directory"]
        assert fd in first["inherited"] and first["slot_directory"] == custody.folder_fd
        folder.rename(tmp_path / "moved-control")
        folder.mkdir()
        (folder / "actor.exit").touch()
        assert _r2_slot_ready(fd, first["exit_name"]) is False
        (tmp_path / "moved-control" / "actor.exit").touch()
        assert _r2_slot_ready(fd, first["exit_name"]) is True
        # Restore the separate retention path before asking close() to write its report.
        (folder / "actor.exit").unlink()
        folder.rmdir()
        (tmp_path / "moved-control").rename(folder)
        custody.close()
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        custody.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="marker events require Linux inotify")
@pytest.mark.parametrize("kind", ["regular", "parent-link", "leaf-link", "missing"])
def test_r2_nested_marker_wait_anchors_components_and_has_a_fixed_ceiling(tmp_path, kind):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "ready").touch()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if kind == "parent-link":
            symlink_or_skip(outside, root / "inner")
        else:
            (root / "inner").mkdir()
            if kind == "regular":
                (root / "inner" / "ready").touch()
                root.rename(tmp_path / "moved")
                symlink_or_skip(outside, root)
            elif kind == "leaf-link":
                symlink_or_skip(outside / "ready", root / "inner" / "ready")
        if kind == "regular":
            r2_wait_marker(fd, "inner/ready")
        elif kind == "missing":
            ticks = iter([0, 61])
            with pytest.raises(RuntimeError, match="^R2 fixture: marker handshake refused: ceiling$"):
                r2_wait_marker(fd, "inner/ready", clock=lambda: next(ticks))
        else:
            message = "marker path refused" if kind == "parent-link" else "slot file refused"
            with pytest.raises(RuntimeError, match="^R2 fixture: " + message + "$"):
                r2_wait_marker(fd, "inner/ready")
        os.fstat(fd)
    finally:
        os.close(fd)


def test_r2_nested_marker_wait_refuses_unsupported_platform(monkeypatch):
    monkeypatch.setattr(handshake_tests, "_r2_slot_read_capable", lambda: False)
    with pytest.raises(RuntimeError, match="^R2 fixture: slot file support unavailable$"):
        r2_wait_marker(123, "inner/ready")


def test_r2_child_ready_event_fallback_does_not_open_descriptors(monkeypatch):
    real_os = handshake_tests.os

    def forbidden(*args, **kwargs):
        raise AssertionError("unsupported notification path must not allocate a descriptor")

    monkeypatch.setattr(handshake_tests, "_r2_child_events_capable", lambda: False)
    monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, open=forbidden))
    _r2_wait_child_event(0)


@pytest.mark.parametrize("surface", ["nested", "slot"])
@pytest.mark.parametrize("ceiling", [True, -1, 601, float("nan")])
def test_r2_marker_wait_limits_precede_descriptor_allocation(monkeypatch, surface, ceiling):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid wait limits must not allocate descriptors")

    monkeypatch.setattr(handshake_tests, "R2SlotEvents", forbidden)
    real_os = handshake_tests.os
    monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, dup=forbidden))
    with pytest.raises(RuntimeError, match="^R2 fixture: invalid handshake ceiling$"):
        if surface == "nested":
            r2_wait_marker(123, "inner/ready", ceiling=ceiling)
        else:
            R2Custody.await_slot_file(SimpleNamespace(folder_fd=123), "ready", "actor", ceiling=ceiling)


@pytest.mark.parametrize("name", ["Q" * 256, "nested/ready", "../ready"])
def test_r2_slot_wait_names_precede_notification_allocation(monkeypatch, name):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid slot names must not allocate descriptors")

    monkeypatch.setattr(handshake_tests, "R2SlotEvents", forbidden)
    with pytest.raises(RuntimeError, match="^R2 fixture: slot file refused$"):
        R2Custody.await_slot_file(SimpleNamespace(folder_fd=123), name, "actor")


def test_r2_child_ready_event_proc_refusal_uses_the_portable_fallback(monkeypatch):
    real_os = handshake_tests.os

    def refused(*args, **kwargs):
        raise PermissionError("token=supersecretvalue")

    monkeypatch.setattr(handshake_tests, "_r2_child_events_capable", lambda: True)
    monkeypatch.setattr(handshake_tests, "os", R2Facade(real_os, open=refused))
    _r2_wait_child_event(0)
