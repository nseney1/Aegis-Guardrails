"""The auth.json.lock that codex-cli 0.167.0 writes at `codex login`.

Observed 2026-11-07 in dogfood run 1: a real `codex login` into a fresh CODEX_HOME left an empty auth.json.lock,
mode 0600, beside auth.lock, and the team command's login refused it as an unexplained entry. These tests reuse
the native probe suite's real-login layout and add that file.
"""
import json
import os
import sys

import pytest

from tests.integration.test_hierarchy_native_probe import (  # noqa: F401  (probe is a fixture)
    native_probe, owner_auth, probe, real_login)
from tests.integration.test_hierarchy_team import run, sha  # noqa: F401  (run is a fixture)


pytestmark = pytest.mark.skipif(os.name == "nt", reason="the probe drives POSIX process groups")


def login_0167(probe):
    auth = real_login(probe)
    lock = probe.codex_home / "auth.json.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    return auth


def test_a_codex_0167_login_layout_is_accepted_and_its_cleanup_removes_both_locks(probe):
    real = owner_auth(probe)
    probe.plan([{"role": "implementer"}])
    login_0167(probe)
    probe.script_turns()
    report = probe.run(cap=4, OPENAI_API_KEY=None, extra_words=["--auth", "existing"])
    assert report["state"] == "completed" and report["summary"]["passed"] is True, report["summary"]
    assert report["cleanup"]["auth_removed"] is True and "login_left" not in report["cleanup"]
    for name in ("auth.json", "auth.lock", "auth.json.lock", "log", "tmp"):
        assert not os.path.lexists(probe.codex_home / name), name
    assert real.read_text() == '{"auth_mode": "chatgpt", "owner": true}\n'


def test_the_cleanup_command_removes_auth_json_lock_too(probe):
    probe.plan([{"role": "implementer"}])
    login_0167(probe)
    answer = json.loads(probe.invoke("cleanup", "--probe-root", str(probe.root)))
    assert answer["cleanup"]["auth_removed"] is True and answer["failures"] == []
    assert "login_left" not in answer["cleanup"]
    assert sorted(os.listdir(probe.codex_home)) == [".aegis-native-probe"]


def test_auth_json_lock_is_one_of_the_entries_a_codex_login_creates():
    assert "auth.json.lock" in native_probe.EXISTING_LOGIN_ENTRIES
    assert native_probe.LOCK_FILES == ("auth.lock", "auth.json.lock")


@pytest.mark.parametrize("case,message", [
    ("symlink", "auth.json.lock in CODEX_HOME is a symlink: {lock}"),
    ("not-a-file", "auth.json.lock in CODEX_HOME is not a regular file: {lock}"),
    ("hard-link", "auth.json.lock in CODEX_HOME has 2 hard links: {lock}"),
    ("too-large", "auth.json.lock in CODEX_HOME is larger than 4096 bytes (4097): {lock}"),
    ("world-writable", "auth.json.lock in CODEX_HOME is writable by others (mode 0606): {lock}"),
])
def test_an_unsafe_auth_json_lock_is_refused_exactly(probe, case, message):
    real = owner_auth(probe)
    probe.plan([{"role": "implementer"}])
    login_0167(probe)
    lock = probe.codex_home / "auth.json.lock"
    if case == "symlink":
        lock.unlink()
        lock.symlink_to(real)
    elif case == "not-a-file":
        lock.unlink()
        lock.mkdir()
    elif case == "hard-link":
        os.link(lock, probe.tmp / "lock-twin")
    elif case == "too-large":
        lock.write_bytes(b"x" * 4097)
    elif case == "world-writable":
        lock.chmod(0o606)
    with pytest.raises(native_probe.Refusal) as refused:
        native_probe.login_extras(probe.codex_home)
    assert str(refused.value) == message.format(lock=lock)
    assert real.read_text() == '{"auth_mode": "chatgpt", "owner": true}\n'


def test_cleanup_keeps_and_reports_an_auth_json_lock_that_is_not_a_regular_file(probe):
    probe.plan([{"role": "implementer"}])
    login_0167(probe)
    lock = probe.codex_home / "auth.json.lock"
    lock.unlink()
    lock.mkdir()
    fd = os.open(probe.codex_home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    left = []
    try:
        native_probe.remove_login_extras(fd, left)
    finally:
        os.close(fd)
    assert left == ["auth.json.lock"] and lock.is_dir()
    assert not os.path.lexists(probe.codex_home / "auth.lock")


# -- the team command's login: the path that refused in dogfood run 1 ----------------------------------------------

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the team command's tests run on Linux")
def test_team_login_accepts_both_locks_a_codex_0167_login_leaves(run):  # noqa: F811
    run.team("init")
    for name, mode in (("auth.lock", 0o664), ("auth.json.lock", 0o600)):
        (run.codex_home / name).write_bytes(b"")
        (run.codex_home / name).chmod(mode)
    answer = run.team("login")
    assert answer["auth_sha256"] == sha(run.codex_home / "auth.json")
    assert answer["entries"] == [".aegis-team-run", "auth.json", "auth.json.lock", "auth.lock", "log"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the team command's tests run on Linux")
def test_team_login_refuses_a_linked_auth_json_lock(run, tmp_path):  # noqa: F811
    run.team("init")
    outside = tmp_path / "elsewhere"
    outside.write_bytes(b"")
    (run.codex_home / "auth.json.lock").symlink_to(outside)
    answer = run.team("login", expect=2)
    assert answer["error"] == "auth.json.lock in CODEX_HOME is a symlink: %s" % (run.codex_home / "auth.json.lock")
