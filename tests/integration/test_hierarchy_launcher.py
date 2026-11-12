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
                            capture_output=True, text=True, timeout=30)
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
                          capture_output=True, text=True, timeout=30)


def bootstrap_lookup_call(built, command, folder, failure):
    return subprocess.run([sys.executable, "-I", "-c", MR1D_R3_LOOKUP_ENTRY,
                           str(LAUNCHER), json.dumps(bootstrap_words(built, command)), json.dumps(str(folder)), failure],
                          capture_output=True, text=True, timeout=30)


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
        current = subprocess.run(argv, capture_output=True, text=True, timeout=30)
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
    rows = subprocess.run(["ps", "-ax", "-ww", "-o", "pid=,stat=,args="], capture_output=True, text=True, timeout=10).stdout
    return [int(line.split()[0]) for line in rows.splitlines()
            if session in line.split()[2:] and not line.split()[1].startswith("Z")]


def alive(pid):
    shown = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, timeout=10).stdout.strip()
    return bool(shown) and not shown.startswith("Z")


def wait_until(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "condition not met within %.1f s" % seconds
        time.sleep(0.05)


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
    running = launch.started(mode=mode, thread=reported, start_timeout_seconds=3)
    logs = launch.base / "launches" / "pilot%2Flane%2Freview" / "logs"
    try:
        wait_until(lambda: any(reported is None or '"thread.started"' in path.read_text()
                               for path in logs.glob("*.stdout")))
        # A concurrent refusal must not steal the first start's lock or replace its reason.
        refused = launch.start(expect=2)
        assert refused["state"] == "refused"
        assert refused["error"] == "stop custody endpoint is busy: " + REVIEW
        out, err = running.communicate(timeout=20)
        assert running.returncode == 3 and not err, out + err
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)
    answer = json.loads(out)
    assert answer["timed_out"] is True
    assert answer["state"] == ("failed_to_start" if reported is None else "start_incomplete")
    assert answer.get("error") == "the start timed out"
    [saved] = [row for row in launch.records() if row["state"] != "refused"]
    assert saved["error"] == "the start timed out" and launch.binding() is None
    assert launch.start()["state"] == "bound"
    assert saved in launch.records()


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
                                                       timeout=10).stdout.split() if int(pid) != hung.pid]
        answer = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "2")
        assert answer["action"] == "stop" and answer["state"] == "stopped" and answer["pids"] == sorted([hung.pid, *children])
        assert answer["wake_marker_present"] is False
        assert hung.wait(timeout=5) < 0
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
        out, err = running.communicate(timeout=20)
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
            running.wait(timeout=5)


def test_a_busy_mailbox_writer_is_waited_for_before_binding(launch):
    lock = launch.root / ".write.lock"
    running = launch.started(environment={"FAKE_CODEX_TOUCH": str(lock)})
    try:
        wait_until(lock.exists)
        time.sleep(1)
        lock.unlink()
        out, err = running.communicate(timeout=30)
        assert running.returncode == 0 and err == "", out + err
        assert json.loads(out)["state"] == "bound" and launch.binding() is not None
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)


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
            process.wait(timeout=5)


def hold(launch, session, script, *words, **popen):
    """A process naming the session, kept running the way a hung codex turn is."""
    return subprocess.Popen(["codex", "-c", script, *(["resume", *words] if words else [])], executable="sh",
                            env=launch.env(FAKE_CODEX_MODE="hang", FAKE_CODEX_THREAD=session,
                            HELD_SESSION=session), stdout=subprocess.DEVNULL, **popen)


def group(pid):
    return [int(member) for member in subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True,
                                                     timeout=10).stdout.split()]


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
        assert hung.wait(timeout=5) < 0
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
        assert stubborn.wait(timeout=5) == -signal.SIGKILL
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


def r2_kernel_process(pid):
    """Independent Linux identity capture; no production matcher or host binary is involved."""
    folder = Path("/proc") / str(pid)
    before = (folder / "stat").read_bytes().rpartition(b")")[2].split()
    status = (folder / "status").read_bytes()
    raw = (folder / "cmdline").read_bytes()
    after = (folder / "stat").read_bytes().rpartition(b")")[2].split()
    if len(before) < 20 or len(after) < 20 or before[19] != after[19]:
        raise RuntimeError("R2 fixture: unstable physical birth evidence")
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
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None or not all(row["done"].is_set() for row in self.pipe_capture):
            observer = getattr(self, "wait_observer", None)
            if observer is not None:
                observer()
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout,
                                                *(b"".join(row["chunks"]) for row in self.pipe_capture))
            time.sleep(.005)
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
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            code = self.poll()
            if code is not None:
                return code
            if self.native_wait_unavailable:
                raise ChildProcessError("R2 fixture: native wait status unavailable")
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(.005)

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


class R2Custody:
    """Physical fixture custody exists before projection staging and never depends on READY.

    Every possible creation has a reserved slot. A private EOF pipe reaches all actors; only the fixture owns
    its writer. Children announce themselves while gated, before they may fork or execute the stop runner.
    Missing original-instance/slot closure is UNKNOWN, retained, and blocks subsequent actor admission.
    """
    LIMIT = 3.0
    quarantine_report = None

    def __init__(self, folder, quarantine):
        self.folder, self.quarantine = Path(folder), Path(quarantine)
        if R2Custody.quarantine_report is not None or self.quarantine.exists():
            raise R2CleanupUnknown(R2Custody.quarantine_report or json.loads(self.quarantine.read_text()))
        self.folder.mkdir(mode=0o700)
        self.safety_read, self.safety_write = os.pipe()
        self.report_read, self.report_write = os.pipe()
        os.set_blocking(self.report_read, False)
        self.nonce = uuid.uuid4().hex
        self.slots, self.entries, self.gates = {}, {}, {}
        self.stderr_paths = {}
        self.buffer, self.messages, self.errors = b"", [], []
        self.closed, self.report, self.cleanup_hook = False, None, None
        self.control_unknown = False
        self.visited = []

    def admit_check(self):
        if self.closed or R2Custody.quarantine_report is not None or self.quarantine.exists():
            raise RuntimeError("R2 fixture: physical actor admission is closed")

    def plan(self, nodes):
        self.admit_check()
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

    def config(self, nodes, script, path, **extra):
        data = {"nonce": self.nonce, "safety_read": self.safety_read, "report_write": self.report_write,
                "nodes": {slot: {**row, "gate": self.gates[slot][0],
                                  "started": str(self.folder / (slot + ".started"))}
                          for slot, row in nodes.items()},
                "inherited": [self.safety_read, self.report_write, *(self.gates[s][0] for s in nodes)],
                "script": str(script), "config": str(path), "trusted_root": str(ROOT),
                "helper": str(Path(__file__).resolve()), **extra}
        path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def capture(self, slot, pid, process=None, birth=None):
        # Store the physical object/creation slot BEFORE any fallible metadata read or receipt write.
        entry = self.entries.setdefault(slot, {"pid": pid, "process": process, "birth": birth,
                                               "fd": None, "verified_fd": process is not None,
                                               "lost": False, "exit": None})
        if entry["pid"] != pid or (birth is not None and entry["birth"] not in (None, birth)):
            entry["lost"] = True
            raise RuntimeError("R2 fixture: conflicting physical creation identity")
        if entry["fd"] is None and hasattr(os, "pidfd_open"):
            try:
                entry["fd"] = os.pidfd_open(pid)
            except OSError:
                pass  # Numeric cleanup still requires fresh original birth and both UIDs.
        try:
            physical = r2_kernel_process(pid)
            parent = self.slots[slot]["parent"]
            expected_parent = os.getpid() if parent is None else self.entries[parent]["pid"]
            if (physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid() or
                    physical["ppid"] != expected_parent or
                    (entry["birth"] is not None and physical["birth"] != entry["birth"])):
                raise RuntimeError("R2 fixture: physical birth/UID/parent mismatch")
            entry["birth"], entry["verified_fd"] = physical["birth"], True
        except BaseException:
            entry["lost"] = True
            raise
        return process if process is not None else R2OwnedChild(self, slot)

    def launch(self, config, slot, env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, extra=(),
               argv=None, cwd=None, stdin=subprocess.DEVNULL, new_session=True):
        self.admit_check()
        self.slots[slot]["starting"] = True
        self.slots[slot]["permitted"] = True
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
        return self.capture(slot, process.pid, process)

    def stderr_tail(self):
        return "\n".join("%s:\n%s" % (path.name, path.read_text(errors="replace")[-4096:])
                         for path in self.stderr_paths.values())

    def pump(self):
        while True:
            try:
                part = os.read(self.report_read, 4096)
            except BlockingIOError:
                break
            if not part:
                break
            self.buffer += part
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            message = json.loads(line)
            slot = message.get("slot")
            if message.get("nonce") != self.nonce or slot not in self.slots:
                raise RuntimeError("R2 fixture: unplanned control message")
            event = message["event"]
            if event == "hello":
                if not self.slots[slot]["permitted"]:
                    raise RuntimeError("R2 fixture: child appeared without its creation permit")
                self.capture(slot, message["pid"], birth=message["birth"])
                self.slots[slot]["hello"] = True
            elif event == "creation_intent":
                child = message["child"]
                if (slot not in self.entries or not self.slots[slot]["released"] or child not in self.slots or
                        self.slots[child]["parent"] != slot or self.slots[child]["permitted"]):
                    raise RuntimeError("R2 fixture: invalid reserved child creation intent")
                self.slots[child]["permitted"] = True
            elif event == "created":
                child = message["child"]
                if child not in self.slots or self.slots[child]["parent"] != slot or not self.slots[child]["permitted"]:
                    raise RuntimeError("R2 fixture: unexpected child creation")
                self.capture(child, message["child_pid"], birth=message["child_birth"])
            elif event == "running":
                if not self.slots[slot]["released"]:
                    raise RuntimeError("R2 fixture: actor ran before physical admission")
                self.slots[slot]["running"] = True
            elif event == "reaped":
                child = message["child"]
                entry = self.entries[child]
                if (self.slots[child]["parent"] != slot or entry["pid"] != message["child_pid"] or
                        entry["birth"] != message["child_birth"] or message.get("wait_pid") != entry["pid"] or
                        not isinstance(message.get("wait_status"), int) or
                        os.waitstatus_to_exitcode(message["wait_status"]) != message["returncode"]):
                    raise RuntimeError("R2 fixture: conflicting native child wait")
                entry["exit"] = {"proof": "parent_Popen_wait", "returncode": message["returncode"],
                                 "wait_pid": message["wait_pid"], "wait_status": message["wait_status"]}
            elif event == "wait_unavailable":
                child = message["child"]
                entry = self.entries[child]
                if (self.slots[child]["parent"] != slot or entry["pid"] != message["child_pid"] or
                        entry["birth"] != message["child_birth"]):
                    raise RuntimeError("R2 fixture: conflicting unavailable wait")
                entry["wait_status"] = "unavailable"
            elif event == "timeout":
                self.closed = True  # The known runner still requires independent closure; no new actors.
            else:
                raise RuntimeError("R2 fixture: invalid control event")
            self.messages.append(message)

    def await_event(self, slot, field):
        deadline = time.monotonic() + self.LIMIT
        while not self.slots[slot][field]:
            self.pump()
            if time.monotonic() >= deadline:
                raise RuntimeError("R2 fixture: bounded " + field + " handshake failed")
            time.sleep(0.01)

    def release(self, slot):
        self.admit_check()
        if not self.slots[slot]["hello"] or slot not in self.entries or self.entries[slot]["lost"]:
            raise RuntimeError("R2 fixture: physical admission is incomplete")
        child = self.slots[slot].get("child")
        if child is not None:
            self.slots[child]["permitted"] = True
        self.slots[slot]["released"] = True
        os.write(self.gates[slot][1], b"G")

    def observe(self, slot):
        entry = self.entries[slot]
        if entry["exit"] is not None:
            return entry["exit"]
        process = entry["process"]
        if isinstance(process, WitnessedPopen):
            process.poll()
            if process.native_wait_unavailable:
                entry["wait_status"] = "unavailable"
        proof = native_wait_fields(process) if process is not None else None
        if proof is not None:
            entry["exit"] = {"proof": "native_waitpid", **proof}
            return entry["exit"]
        if (process is not None and not isinstance(process, WitnessedPopen) and
                entry.get("wait_status") != "unavailable"):
            try:
                pid, status = os.waitpid(entry["pid"], os.WNOHANG)
            except ChildProcessError:
                entry["wait_status"] = "unavailable"
                pid = 0  # ECHILD is not an invented successful wait or original-instance exit proof.
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                if isinstance(process, WitnessedPopen):
                    process.record_wait(pid, status)
                entry["exit"] = {"proof": "native_waitpid", "wait_pid": pid, "wait_status": status,
                                 "returncode": process.returncode}
                return entry["exit"]
        if entry["fd"] is not None and entry["verified_fd"]:
            poller = select.poll()
            poller.register(entry["fd"], select.POLLIN)
            if poller.poll(0):
                entry["exit"] = {"proof": "original_pidfd_exit"}
                return entry["exit"]
        try:
            physical = r2_kernel_process(entry["pid"])
        except FileNotFoundError:
            if entry["lost"]:
                return None
            try:
                os.kill(entry["pid"], 0)
            except ProcessLookupError:
                entry["exit"] = {"proof": "qualified_namespace_ESRCH"}
                return entry["exit"]
            entry["lost"] = True
            return None
        except (OSError, ValueError, RuntimeError):
            # Exit can occur between the first pidfd poll and a failed /proc read. Consult the original
            # handle again, not the numeric PID or cached return code. No metadata is retried or restored.
            if entry["fd"] is not None and entry["verified_fd"]:
                poller = select.poll()
                poller.register(entry["fd"], select.POLLIN)
                if poller.poll(0):
                    entry["exit"] = {"proof": "original_pidfd_exit"}
                    return entry["exit"]
            entry["lost"] = True
            raise
        if entry["birth"] != physical["birth"]:
            entry["lost"] = True
        elif not entry["lost"] and physical["state"].startswith("Z"):
            entry["exit"] = {"proof": "matching_birth_zombie"}
            return entry["exit"]
        return None

    def kill_owned(self, slot):
        entry = self.entries[slot]
        if self.observe(slot) is not None:
            return
        physical = r2_kernel_process(entry["pid"])
        if (entry["lost"] or entry["birth"] != physical["birth"] or
                physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid()):
            entry["lost"] = True
            raise RuntimeError("R2 fixture: no physical authority after identity loss")
        if entry["fd"] is not None and entry["verified_fd"] and hasattr(signal, "pidfd_send_signal"):
            signal.pidfd_send_signal(entry["fd"], signal.SIGKILL)
        else:
            os.kill(entry["pid"], signal.SIGKILL)  # Fresh birth/UID check; residual numeric race is not hidden.

    def wait_native(self, slot, seconds=2):
        entry = self.entries[slot]
        process = entry["process"]
        if process is None or not 0 < seconds <= self.LIMIT:
            raise RuntimeError("R2 fixture: invalid direct native wait")
        if isinstance(process, WitnessedPopen):
            code = process.wait(timeout=seconds)
            entry["exit"] = {"proof": "native_waitpid", **native_wait_fields(process)}
            return code
        deadline = time.monotonic() + seconds
        while True:
            pid, status = os.waitpid(entry["pid"], os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                if isinstance(process, WitnessedPopen):
                    process.record_wait(pid, status)
                entry["exit"] = {"proof": "native_waitpid", "wait_pid": pid, "wait_status": status,
                                 "returncode": process.returncode}
                return process.returncode
            if time.monotonic() >= deadline:
                raise RuntimeError("R2 fixture: native wait deadline exceeded")
            time.sleep(0.01)

    def close(self):
        if self.report is not None:
            if self.report["state"] == "UNKNOWN":
                raise R2CleanupUnknown(self.report)
            return self.report
        self.closed = True
        deadline = time.monotonic() + self.LIMIT
        # Resolve already permitted creation slots before EOF; never scan unrelated processes for a child.
        while any(row["permitted"] and slot not in self.entries for slot, row in self.slots.items()):
            try:
                self.pump()
            except BaseException as exc:
                self.errors.append("control drain: " + str(exc))
                self.control_unknown = True
                break
            if time.monotonic() >= deadline - 2:
                break
            time.sleep(0.01)
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
        cooperative = time.monotonic() + 0.3
        while True:
            try:
                self.pump()
            except BaseException as exc:
                self.errors.append("control closure: " + str(exc))
                self.control_unknown = True
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
            if not left or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        missing = [slot for slot, row in self.slots.items() if row["permitted"] and slot not in self.entries]
        state = "UNKNOWN" if left or missing or self.buffer or self.control_unknown else "CLOSED_WITH_ERRORS" if self.errors else "CLOSED"
        self.report = {"state": state, "errors": self.errors, "unresolved_slots": sorted(set(left + missing)),
                       "visited": self.visited, "entries": {slot: {"pid": entry["pid"], "birth": entry["birth"],
                       "exit": entry["exit"], **({"wait_status": "unavailable"}
                        if entry.get("wait_status") == "unavailable" else {})}
                        for slot, entry in self.entries.items()},
                       "uncreated_slots": [slot for slot, row in self.slots.items() if not row["permitted"]]}
        if state == "UNKNOWN":
            R2Custody.quarantine_report = self.report  # Latch BEFORE fallible evidence writes.
            try:
                self.quarantine.write_text(json.dumps(self.report, indent=2) + "\n")
                (self.folder / "closure.json").write_text(json.dumps(self.report, indent=2) + "\n")
            except OSError as exc:
                self.errors.append("UNKNOWN retention write: " + str(exc))
            raise R2CleanupUnknown(self.report)
        for entry in self.entries.values():
            if entry["fd"] is not None:
                try:
                    os.close(entry["fd"])
                except OSError as exc:
                    self.errors.append("pidfd close: " + str(exc))
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

    def pending(self, process):
        if str(process.pid) in self.receipts:
            raise RuntimeError("R2 fixture: an existing receipt cannot be renewed")
        self.processes[process.pid] = process
        physical = r2_kernel_process(process.pid)
        if physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid():
            raise RuntimeError("R2 fixture: child is not ours")
        self.receipts[str(process.pid)] = {"state": "PENDING", "birth": physical["birth"],
                                          "digest": None, "argv": None}
        self.census_births[str(process.pid)] = physical["birth"]
        self.save()

    def ready(self, process, argv=None):
        receipt = self.receipts.get(str(process.pid))
        if receipt is None or receipt["state"] != "PENDING":
            raise RuntimeError("R2 fixture: READY requires a known pending Popen")
        physical = r2_kernel_process(process.pid)
        if (process.poll() is not None or physical["birth"] != receipt["birth"] or physical["state"].startswith("Z") or
                physical["uid"] != os.geteuid() or physical["euid"] != os.geteuid()):
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
            out, err = process.communicate(input, timeout=timeout)
        except BaseException:
            process.kill()
            process.wait(timeout=3)
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
        deadline = time.monotonic() + 3
        while not Path(config["nodes"][child_slot]["started"]).exists():
            if child.poll() is not None or time.monotonic() >= deadline:
                emit("timeout")
                return 124
            time.sleep(0.01)
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
    while not Path(config["exit_file"]).exists():
        time.sleep(0.02)
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
        out, err = running.communicate(timeout=20)
        assert running.returncode == 3 and err == "", out + err
        answer = json.loads(out)
        assert answer["state"] == "start_incomplete" and answer["error"] == "the launcher was interrupted"
        assert answer["session"] == thread and answer["exit_code"] == 0
        assert [row["state"] for row in launch.records()] == ["start_incomplete"]
        assert not (logs.parent / ".start.lock").exists() and launch.binding() is None
    finally:
        if running.poll() is None:
            running.kill()
            running.wait(timeout=5)
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
        assert hung.wait(timeout=5) < 0
        assert [row["state"] for row in launch.records()] == ["bound", "stop_failed"]
    finally:
        context.close()
