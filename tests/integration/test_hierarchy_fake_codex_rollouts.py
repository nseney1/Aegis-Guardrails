"""The fake codex's rollout mode: the evidence shape the native probe parses, and its simulated sandbox.

These tests prove the fake writes what a probe reads. They support no claim about how a real Codex
sandbox behaves. PATH holds only the fake and the tools a scripted command needs, and CODEX_HOME and
HOME are temporary folders, so no real codex or real ~/.codex is ever reached.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

import pytest

from tests.integration.hierarchy_fake_wrapper import shell_exec
pytestmark = pytest.mark.skipif(os.name != "posix", reason="the fake Codex uses POSIX shell scripts and process signals")

ROOT = Path(__file__).resolve().parents[2]
FAKE_CODEX = Path(__file__).resolve().with_name("hierarchy_fake_codex.py")
NATIVE = ROOT / "tools" / "hierarchy_native.py"
sys.path.insert(0, str(ROOT / "tools"))
from hierarchy_provision import codex_argv  # noqa: E402

THREAD = "01a19b00-0000-7000-8000-00000000f4c3"
NONCE = "n0nce5a1"


class Fake:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        codex = self.bin / "codex"
        codex.write_text('#!/bin/sh\n%s "$@"\n' % shell_exec("codex", FAKE_CODEX, self.tmp), encoding="utf-8")
        codex.chmod(codex.stat().st_mode | stat.S_IXUSR)
        (self.bin / "sleep").symlink_to(shutil.which("sleep"))
        self.home = tmp_path / "home"
        self.codex_home = tmp_path / "codex-home"
        self.work = tmp_path / "work"
        self.outside = tmp_path / "outside"
        self.extra = tmp_path / "extra"
        self.tmpdir = tmp_path / "tmpdir"
        for folder in (self.home, self.codex_home, self.work / ".git", self.outside, self.extra, self.tmpdir):
            folder.mkdir(parents=True)
        self.script = tmp_path / "script.json"
        self.codex_log = tmp_path / "fake-codex.log"

    def env(self, **extra):
        return {"PATH": str(self.bin), "HOME": str(self.home), "CODEX_HOME": str(self.codex_home),
                "TMPDIR": str(self.tmpdir), "PYTHONDONTWRITEBYTECODE": "1", "FAKE_CODEX_ROLLOUT": "1",
                "FAKE_CODEX_THREAD": THREAD, "FAKE_CODEX_SCRIPT": str(self.script),
                "FAKE_CODEX_LOG": str(self.codex_log), **extra}

    def profile(self, sandbox="workspace-write", **changes):
        value = {"disabled_features": ["apps"], "ignore_user_config": True, "sandbox": sandbox,
                 "approval_policy": "never", "writable_roots": [str(self.extra)] if sandbox == "workspace-write" else [],
                 "network_access": False, "mcp_servers": {}, "cwd": str(self.work), "model": "gpt-6-astra",
                 "effort": "high", "service_tier": "ultrafast", "tmpdir": None, "add_dirs": [],
                 "skip_git_repo_check": False}
        value.update(changes)
        return value

    def write_script(self, *turns):
        self.script.write_text(json.dumps({"turns": list(turns)}), encoding="utf-8")

    def run(self, argv, expect=0, timeout=20, **extra):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=self.work,
                                env=self.env(**extra), stdin=subprocess.DEVNULL)
        assert result.returncode == expect, (result.stdout, result.stderr)
        return result

    def start(self, prompt="probe turn", expect=0, sandbox="workspace-write", **extra):
        return self.run(codex_argv(self.profile(sandbox), [prompt]), expect=expect, **extra)

    def resume(self, prompt="resume turn", expect=0, sandbox="workspace-write", thread=THREAD, **extra):
        return self.run(codex_argv(self.profile(sandbox), ["resume", thread, prompt]), expect=expect, **extra)

    def rollouts(self):
        return sorted((self.codex_home / "sessions").glob("*/*/*/rollout-*.jsonl"))

    def records(self):
        [path] = self.rollouts()
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def events(stdout):
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def kinds(records):
    return [(row["type"], (row.get("payload") or {}).get("type") if row["type"] == "event_msg" else None) for row in records]


def executions(records):
    return [row["payload"]["item"] for row in records if row["type"] == "event_msg"
            and row["payload"]["type"] == "item_completed" and row["payload"]["item"]["type"] == "CommandExecution"]


def attempt(target, nonce=NONCE, **extra):
    return {"command": "printf %s " + nonce + " > " + str(target), "target": str(target), "nonce": nonce, **extra}


@pytest.fixture
def fake(tmp_path):
    return Fake(tmp_path)


def test_a_start_writes_a_dated_rollout_with_the_settings_its_argv_asked_for(fake):
    fake.write_script({"commands": []})
    answer = fake.start(FAKE_CODEX_CLI_VERSION="0.166.0")
    [path] = fake.rollouts()
    day = time.strftime("%Y/%m/%d")
    assert str(path.parent.relative_to(fake.codex_home / "sessions")) == day
    assert path.name.startswith("rollout-" + day.replace("/", "-") + "T") and path.name.endswith("-" + THREAD + ".jsonl")
    records = fake.records()
    catalog = [record for record in records if record["type"] == "response_item"]
    assert [record["payload"] for record in catalog] == [{"type": "additional_tools", "tools": []}]
    records = [record for record in records if record["type"] != "response_item"]
    assert kinds(records) == [("session_meta", None), ("event_msg", "task_started"), ("event_msg", "thread_settings_applied"),
                              ("turn_context", None), ("event_msg", "item_completed"), ("event_msg", "task_complete")]
    meta = records[0]["payload"]
    assert (meta["id"], meta["cli_version"], meta["source"], meta["cwd"]) == (THREAD, "0.166.0", "exec", str(fake.work))
    turn = records[1]["payload"]["turn_id"]
    settings = records[2]["payload"]["thread_settings"]
    assert records[2]["payload"]["thread_id"] == THREAD
    assert (settings["service_tier"], settings["model"], settings["approval_policy"]) == ("ultrafast", "gpt-6-astra", "never")
    context = records[3]["payload"]
    assert context["turn_id"] == turn and records[-1]["payload"]["turn_id"] == turn
    assert (context["model"], context["effort"], context["cwd"]) == ("gpt-6-astra", "high", str(fake.work))
    assert (context["approval_policy"], context["approvals_reviewer"]) == ("never", "user")
    assert context["sandbox_policy"] == {"type": "workspace-write", "writable_roots": [str(fake.extra)], "network_access": False,
                                         "exclude_slash_tmp": True, "exclude_tmpdir_env_var": True}
    assert settings["permission_profile"] == context["permission_profile"]
    profile = context["permission_profile"]
    assert (profile["type"], profile["network"], profile["file_system"]["type"]) == ("managed", "restricted", "restricted")
    entries = [(entry["path"].get("path") or entry["path"]["value"]["kind"], entry["access"]) for entry in profile["file_system"]["entries"]]
    assert entries == [("root", "read"), (str(fake.work), "write"), (str(fake.extra), "write"),
                       (str(fake.work / ".git"), "read"), (str(fake.work / ".agents"), "read"), (str(fake.work / ".codex"), "read"),
                       (str(fake.extra / ".git"), "read"), (str(fake.extra / ".agents"), "read"), (str(fake.extra / ".codex"), "read")]
    stream = events(answer.stdout)
    assert [row["type"] for row in stream] == ["thread.started", "turn.started", "item.completed", "turn.completed"]
    assert stream[0]["thread_id"] == THREAD
    logged = json.loads(fake.codex_log.read_text(encoding="utf-8"))
    assert logged["argv"][-1] == "probe turn" and logged["rollout"] == str(path)


def test_the_existing_reader_accepts_the_fake_rollout(fake):
    fake.write_script({"commands": []})
    fake.start()
    [path] = fake.rollouts()
    result = subprocess.run([sys.executable, "-I", str(NATIVE), "--rollout", str(path), "--cid", THREAD, "inspect"],
                            capture_output=True, text=True, timeout=20, env={"PATH": str(fake.bin), "HOME": str(fake.home)})
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["host"] == "codex-cli" and observed["profile"]["model"] == "gpt-6-astra"
    assert observed["profile"]["sandbox_policy"]["type"] == "workspace-write"


def test_a_writer_sandbox_runs_writes_inside_its_roots_and_refuses_the_rest(fake):
    targets = {"worktree": fake.work / ("in-" + NONCE), "extra_root": fake.extra / ("extra-" + NONCE),
               "outside": fake.outside / ("out-" + NONCE), "git_admin": fake.work / ".git" / ("hooks-" + NONCE),
               "codex_home": fake.codex_home / "config.toml", "tmpdir": fake.tmpdir / ("tmp-" + NONCE)}
    fake.write_script({"commands": [attempt(path) for path in targets.values()]})
    answer = fake.start()
    ran = executions(fake.records())
    assert [item["exit_code"] for item in ran] == [0, 0, 1, 1, 1, 1]
    assert [item["status"] for item in ran] == ["completed", "completed", "failed", "failed", "failed", "failed"]
    for item, (name, path) in zip(ran, targets.items()):
        assert item["command"] == ["/bin/sh", "-c", "printf %s " + NONCE + " > " + str(path)]
        assert item["cwd"] == str(fake.work)
        if name in ("worktree", "extra_root"):
            assert path.read_text(encoding="utf-8") == NONCE and item["aggregated_output"] == ""
        else:
            assert not path.exists()
            assert item["aggregated_output"] == "OSError: [Errno 30] Read-only file system: '%s'\n" % path
    stream = [row["item"] for row in events(answer.stdout) if row["type"] == "item.completed"
              and row["item"]["type"] == "command_execution"]
    assert [(item["exit_code"], item["status"]) for item in stream] == [(item["exit_code"], item["status"]) for item in ran]
    assert stream[2]["command"] == "/bin/sh -c 'printf %s " + NONCE + " > " + str(targets["outside"]) + "'"


def test_a_read_only_sandbox_refuses_every_write_but_runs_reads(fake):
    fake.write_script({"commands": [attempt(fake.work / ("in-" + NONCE)),
                                    {"command": "printf read-ok", "target": None}]})
    fake.start(sandbox="read-only")
    records = fake.records()
    context = [row for row in records if row["type"] == "turn_context"][0]["payload"]
    assert context["sandbox_policy"] == {"type": "read-only"}
    assert [(entry["path"]["type"], entry["access"]) for entry in context["permission_profile"]["file_system"]["entries"]] == [
        ("special", "read")]
    refused, read = executions(records)
    assert refused["exit_code"] == 1 and "Read-only file system" in refused["aggregated_output"]
    assert not (fake.work / ("in-" + NONCE)).exists()
    assert (read["exit_code"], read["aggregated_output"]) == (0, "read-ok")


def test_an_add_dir_and_the_shared_temp_folders_follow_the_sandbox_flags(fake):
    added = fake.tmp / "added"
    added.mkdir()
    fake.write_script({"commands": [attempt(added / NONCE), attempt(fake.tmpdir / NONCE)]})
    argv = [word.replace("exclude_tmpdir_env_var=true", "exclude_tmpdir_env_var=false")
            for word in codex_argv(fake.profile(add_dirs=[str(added)]), ["turn"])]
    fake.run(argv)
    ran = executions(fake.records())
    assert [item["exit_code"] for item in ran] == [0, 0]
    assert (added / NONCE).exists() and (fake.tmpdir / NONCE).exists()
    context = [row for row in fake.records() if row["type"] == "turn_context"][0]["payload"]
    assert context["sandbox_policy"]["exclude_tmpdir_env_var"] is False
    kinds_written = [entry["path"]["value"]["kind"] for entry in context["permission_profile"]["file_system"]["entries"]
                     if entry["path"]["type"] == "special" and entry["access"] == "write"]
    assert kinds_written == ["tmpdir"]


def test_a_declining_model_leaves_no_command_event_and_no_file(fake):
    fake.write_script({"mode": "no-event", "commands": [attempt(fake.work / NONCE)]})
    answer = fake.start()
    records = fake.records()
    assert executions(records) == [] and not (fake.work / NONCE).exists()
    assert records[-1]["payload"]["type"] == "task_complete"
    assert records[-1]["payload"]["last_agent_message"] == "I will not run those commands."
    assert [row["type"] for row in events(answer.stdout)] == ["thread.started", "turn.started", "item.completed", "turn.completed"]


def test_a_wrong_nonce_runs_a_different_command_than_the_one_asked_for(fake):
    fake.write_script({"commands": [attempt(fake.work / ("in-" + NONCE), mode="wrong-nonce", wrong_nonce="b4dn0nce")]})
    fake.start()
    [item] = executions(fake.records())
    assert NONCE not in " ".join(item["command"])
    assert item["command"] == ["/bin/sh", "-c", "printf %s b4dn0nce > " + str(fake.work / "in-b4dn0nce")]
    assert item["exit_code"] == 0 and not (fake.work / ("in-" + NONCE)).exists()
    assert (fake.work / "in-b4dn0nce").read_text(encoding="utf-8") == "b4dn0nce"


def test_a_wrong_nonce_without_a_nonce_is_a_script_error(fake):
    fake.write_script({"mode": "wrong-nonce", "commands": [{"command": "printf x", "target": None}]})
    result = fake.start(expect=2)
    assert result.stderr == "fake codex script error: wrong-nonce needs a nonce\n"


def test_a_lying_turn_reports_a_refusal_for_a_write_that_happened(fake):
    target = fake.outside / ("out-" + NONCE)
    fake.write_script({"commands": [attempt(target, mode="lie")]})
    fake.start()
    [item] = executions(fake.records())
    assert item["exit_code"] == 1 and item["status"] == "failed"
    assert item["aggregated_output"] == "OSError: [Errno 30] Read-only file system: '%s'\n" % target
    assert target.read_text(encoding="utf-8") == NONCE


def test_a_hanging_turn_stays_open_until_stopped_and_a_resume_appends_the_next_turn(fake):
    fake.write_script({"match": "short", "commands": []},
                      {"match": "long", "mode": "hang", "commands": [attempt(fake.work / ("in-" + NONCE))]},
                      {"commands": [attempt(fake.work / "after")]})
    fake.start("short start")
    process = subprocess.Popen(codex_argv(fake.profile(), ["resume", THREAD, "long probe"]), cwd=fake.work, env=fake.env(),
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(executions(fake.records())) < 1:
            time.sleep(0.05)
        assert process.poll() is None
        records = fake.records()
        assert kinds(records)[-4:] == [("event_msg", "task_started"), ("event_msg", "thread_settings_applied"),
                                       ("turn_context", None), ("event_msg", "item_completed")]
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        process.communicate(timeout=5)
    assert process.returncode != 0 and (fake.work / ("in-" + NONCE)).exists() and not (fake.work / "after").exists()
    fake.resume("recovery wake")
    records = fake.records()
    assert len(fake.rollouts()) == 1 and [row["type"] for row in records].count("session_meta") == 1
    started = [row["payload"]["turn_id"] for row in records if kinds([row]) == [("event_msg", "task_started")]]
    completed = [row["payload"]["turn_id"] for row in records if kinds([row]) == [("event_msg", "task_complete")]]
    assert len(set(started)) == 3 and completed == [started[0], started[2]]
    last = [row["payload"] for row in records if row["type"] == "turn_context"][-1]
    assert last["turn_id"] == started[2] and last["sandbox_policy"]["type"] == "workspace-write"
    assert (fake.work / "after").exists()


def test_a_resume_reads_its_settings_from_the_resume_argv(fake):
    fake.write_script({"commands": []})
    fake.start()
    answer = fake.resume(sandbox="read-only")
    contexts = [row["payload"] for row in fake.records() if row["type"] == "turn_context"]
    assert [context["sandbox_policy"]["type"] for context in contexts] == ["workspace-write", "read-only"]
    assert events(answer.stdout)[0] == {"type": "thread.started", "thread_id": THREAD}


def test_a_resume_of_an_unknown_thread_fails_like_codex(fake):
    fake.write_script({"commands": []})
    result = fake.resume(expect=1, thread="01a19b00-0000-7000-8000-0000000dead0")
    assert result.stderr == "Error: no rollout found for thread id 01a19b00-0000-7000-8000-0000000dead0\n"
    assert fake.rollouts() == []


def test_a_resume_with_a_host_plan_runs_the_fake_host_inside_the_turn(fake):
    fake.write_script({"commands": []})
    fake.start()
    servers = {"aegis_mailbox": {"command": "unused", "args": ["--endpoint", "team/lane"]}}
    plan, host_log = fake.tmp / "plan.json", fake.tmp / "host.log"
    plan.write_text(json.dumps({"team/lane": {"exit": 0}}), encoding="utf-8")
    argv = codex_argv(fake.profile(mcp_servers=servers), ["resume", THREAD, "wake"])
    fake.run(argv, FAKE_HOST_PLAN=str(plan), FAKE_HOST_LOG=str(host_log))
    assert json.loads(host_log.read_text(encoding="utf-8"))["endpoint"] == "team/lane"
    assert kinds(fake.records())[-1] == ("event_msg", "task_complete")
    plan.write_text(json.dumps({"team/lane": {"exit": 5}}), encoding="utf-8")
    fake.run(argv, expect=5, FAKE_HOST_PLAN=str(plan), FAKE_HOST_LOG=str(host_log))
    assert kinds(fake.records())[-1] == ("turn_context", None)


def test_rollout_mode_needs_a_codex_home(fake):
    fake.write_script({"commands": []})
    env = fake.env()
    del env["CODEX_HOME"]
    result = subprocess.run(codex_argv(fake.profile(), ["turn"]), capture_output=True, text=True, timeout=20, env=env,
                            cwd=fake.work)
    assert result.returncode == 2 and result.stderr == "fake codex: FAKE_CODEX_ROLLOUT needs CODEX_HOME\n"


def test_without_rollout_mode_the_fake_keeps_its_old_behaviour(fake):
    answer = fake.start(FAKE_CODEX_ROLLOUT="")
    assert not (fake.codex_home / "sessions").exists()
    assert [row["type"] for row in events(answer.stdout)] == ["thread.started", "turn.started", "item.completed", "turn.completed"]


def helper_command(path, nonce=NONCE):
    return "%s -I /probe/helper/native-probe-attempt.py %s %s" % (sys.executable, path, nonce)


def test_a_refused_helper_run_records_the_json_the_helper_prints_for_erofs(fake):
    target = fake.outside / ("out-" + NONCE)
    fake.write_script({"commands": [{"command": helper_command(target), "target": str(target), "nonce": NONCE},
                                    {"command": helper_command(target), "target": str(target), "nonce": NONCE,
                                     "mode": "enoent"},
                                    {"command": helper_command(target), "target": str(target), "mode": "fail"}]})
    fake.start()
    refused, enoent, failed = executions(fake.records())
    assert json.loads(refused["aggregated_output"]) == {
        "ok": False, "path": str(target), "nonce": NONCE, "errno": 30,
        "error": "OSError: [Errno 30] Read-only file system: '%s'" % target}
    assert json.loads(enoent["aggregated_output"])["errno"] == 2
    assert failed["aggregated_output"] == "fake codex: the command failed for another reason\n"
    assert [item["exit_code"] for item in (refused, enoent, failed)] == [1, 1, 1] and not target.exists()


def test_patches_record_file_change_items_and_write_only_where_the_sandbox_allows(fake):
    inside, outside = fake.work / ("in-" + NONCE), fake.outside / ("out-" + NONCE)
    lied, mismatch = fake.outside / "lied", fake.work / "mismatch"
    fake.write_script({"commands": [], "patches": [
        {"path": str(inside), "line": "l " + NONCE}, {"path": str(outside), "line": "l " + NONCE},
        {"path": str(lied), "line": "l " + NONCE, "mode": "lie"}, {"path": str(mismatch), "line": "x", "mode": "mismatch"},
        {"path": str(fake.work / "skipped"), "line": "x", "mode": "no-event"}]})
    fake.start()
    items = [row["payload"]["item"] for row in fake.records() if row["type"] == "event_msg"
             and row["payload"]["type"] == "item_completed" and row["payload"]["item"]["type"] == "FileChange"]
    assert [(item["changes"], item["status"], item.get("stderr")) for item in items] == [
        ([{"path": str(inside), "kind": "add"}], "completed", None),
        ([{"path": str(outside), "kind": "add"}], "failed", "patch rejected: Read-only file system: '%s'\n" % outside),
        ([{"path": str(lied), "kind": "add"}], "failed", "patch rejected: Read-only file system: '%s'\n" % lied),
        ([{"path": str(mismatch), "kind": "add"}], "failed", "Failed to find expected lines in %s\n" % mismatch)]
    assert inside.read_text() == "l %s\n" % NONCE and lied.read_text() == "l %s\n" % NONCE
    assert not outside.exists() and not mismatch.exists() and not (fake.work / "skipped").exists()


@pytest.mark.timing
def test_turn_keys_delay_the_context_change_the_recorded_sandbox_and_drop_the_completion(fake):
    fake.write_script({"commands": [], "context_delay": 0.3, "record_sandbox": "read-only", "incomplete": True})
    started = time.monotonic()
    fake.start()
    assert time.monotonic() - started >= 0.3
    records = fake.records()
    assert kinds(records)[-1] == ("event_msg", "item_completed")
    context = [row for row in records if row["type"] == "turn_context"][0]["payload"]
    assert context["sandbox_policy"] == {"type": "read-only"}


def test_an_unknown_patch_mode_is_a_script_error(fake):
    fake.write_script({"commands": [], "patches": [{"path": "x", "line": "y", "mode": "teleport"}]})
    assert fake.start(expect=2).stderr == "fake codex script error: unknown patch mode 'teleport'\n"
