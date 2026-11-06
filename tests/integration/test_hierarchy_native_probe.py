"""The native probe drives provisioned Codex roles through start, a probe turn, a stop mid-turn and a wake.

Codex is the fake on a fake-only PATH (the fake codex plus links to git and ps), HOME is a temporary folder, so
neither a real model binary nor the real ~/.codex is ever reached. These tests prove the probe's plumbing and
verdict rules; the fake's sandbox is a simulation, so they support no claim about real enforcement.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid

import pytest


pytestmark = pytest.mark.skipif(os.name == "nt", reason="the probe drives POSIX process groups")
ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "tools" / "hierarchy_native_probe.py"
FAKE_CODEX = Path(__file__).resolve().with_name("hierarchy_fake_codex.py")
GIT = shutil.which("git")
PS = shutil.which("ps")
SH = shutil.which("sh")
KEY = "sk-probe-test-" + uuid.uuid4().hex
IDENTITY = {"GIT_AUTHOR_NAME": "probe", "GIT_AUTHOR_EMAIL": "probe@example.invalid",
            "GIT_COMMITTER_NAME": "probe", "GIT_COMMITTER_EMAIL": "probe@example.invalid"}
WRAPPER = """#!/bin/sh
if [ "$1" = login ]; then
  printf '%%s\\n' "$*" >> "$FAKE_LOGIN_LOG"
  IFS= read -r key
  printf '%%s' "$key" > "$CODEX_HOME/auth.json"
  if [ -n "$FAKE_LOGIN_READONLY_CONFIG" ]; then
    printf '# made read-only by the test\\n' > "$CODEX_HOME/config.toml"
    chmod 0400 "$CODEX_HOME/config.toml"
  fi
  exit 0
fi
exec "%s" "%s" "$@"
"""


def git(cwd, *words):
    done = subprocess.run([GIT, *words], cwd=cwd, capture_output=True, text=True, timeout=30,
                          env={"PATH": os.path.dirname(GIT), "HOME": str(cwd), **IDENTITY})
    assert done.returncode == 0, done.stderr
    return done.stdout


class Probe:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        self.home.mkdir()
        # The probe also guards the passwd home's .codex; this stand-in keeps the tests off the owner's real one.
        self.passwd_home = tmp_path / "passwd-home"
        self.passwd_home.mkdir()
        self.source = tmp_path / "source"
        (self.source / "tools").mkdir(parents=True)
        for path in (ROOT / "tools").glob("hierarchy_*.py"):
            shutil.copy(path, self.source / "tools" / path.name)
        shutil.copytree(ROOT / "tools" / "hierarchy_templates", self.source / "tools" / "hierarchy_templates")
        git(self.source, "init", "-q", "-b", "develop")
        git(self.source, "add", ".")
        git(self.source, "commit", "-qm", "pinned source")
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        self.codex = self.bin / "codex"
        self.codex.write_text(WRAPPER % (sys.executable, FAKE_CODEX), encoding="utf-8")
        self.codex.chmod(self.codex.stat().st_mode | stat.S_IXUSR)
        (self.bin / "git").symlink_to(GIT)
        (self.bin / "ps").symlink_to(PS)
        # The plan resolves the host shell from PATH, as a real plan does from the owner's PATH; the fake records
        # every command as /bin/sh -c, which counts only because it resolves to this shell.
        (self.bin / "sh").symlink_to(SH)
        self.root = tmp_path / "probe"
        self.tmpdir = tmp_path / "tmpdir"
        self.tmpdir.mkdir()
        self.script = tmp_path / "script.json"
        self.script.write_text(json.dumps({"turns": []}), encoding="utf-8")
        self.codex_log = tmp_path / "fake-codex.log"
        self.login_log = tmp_path / "fake-login.log"
        self.host_log = tmp_path / "fake-host.log"
        self.host_plan = tmp_path / "fake-host-plan.json"
        self.host_plan.write_text("{}", encoding="utf-8")
        self.plan_answer = None

    @property
    def codex_home(self):
        return self.root / "codex-home"

    def env(self, **changes):
        env = {"PATH": str(self.bin), "HOME": str(self.home), "CODEX_HOME": str(self.codex_home), "OPENAI_API_KEY": KEY,
               "TMPDIR": str(self.tmpdir), "PYTHONDONTWRITEBYTECODE": "1",
               "PYTEST_CURRENT_TEST": os.environ.get("PYTEST_CURRENT_TEST", "probe-test"),
               "FAKE_CODEX_ROLLOUT": "1", "FAKE_CODEX_SCRIPT": str(self.script), "FAKE_CODEX_LOG": str(self.codex_log),
               "FAKE_CODEX_HANG_SECONDS": "30", "FAKE_LOGIN_LOG": str(self.login_log),
               "FAKE_HOST_LOG": str(self.host_log), "FAKE_HOST_PLAN": str(self.host_plan),
               "AEGIS_PROBE_FAKE_PASSWD_HOME": str(self.passwd_home)}
        env.update(changes)
        return {key: value for key, value in env.items() if value is not None}

    def invoke(self, *words, expect=0, timeout=120, **changes):
        done = subprocess.run([sys.executable, "-I", str(PROBE), *words], capture_output=True, text=True,
                              timeout=timeout, env=self.env(**changes), stdin=subprocess.DEVNULL)
        assert done.returncode == expect, (done.stdout[-4000:], done.stderr[-4000:])
        return done.stdout

    def plan(self, roles, expect=0, **changes):
        request = {"source": str(self.source), "probe_root": str(self.root), "roles": roles, "channels": ["shell"],
                   "model": "gpt-probe", "effort": "high", "approvals_reviewer": "user",
                   "timeouts": {"start_timeout_seconds": 30, "turn_timeout_seconds": 30, "hold_wait_seconds": 5,
                                "stop_grace_seconds": 2}}
        request.update(changes)
        request = {key: value for key, value in request.items() if value is not None}
        path = self.tmp / ("plan-%s.json" % uuid.uuid4().hex)
        path.write_text(json.dumps(request), encoding="utf-8")
        answer = json.loads(self.invoke("plan", "--request", str(path), expect=expect))
        if expect == 0:
            self.plan_answer = answer
        return answer

    def role(self, name):
        return next(role for role in self.plan_answer["roles"] if role["role"] == name)

    def script_turns(self, modes=None, extra=None, patches=False, patch_modes=None, probe=None, hold=None,
                     wake=None, first=None, patch_shape=None):
        """A fake turn per probe prompt: each shell attempt runs as planned unless modes names another mode.

        patches=True also applies each apply_patch attempt (patch_modes names other modes); probe, hold and wake
        add keys to those turns (the wake turn matches the wake tool's fixed prompt); first lists commands a role
        runs before its planned ones, and patch_shape sets every patch's record shape."""
        modes, extra, patch_modes, turns = modes or {}, extra or {}, patch_modes or {}, []
        for role in self.plan_answer["roles"]:
            commands, applied = list((first or {}).get(role["role"], [])), []
            for attempt in role["attempts"]:
                if attempt["channel"] == "shell" and role["shell"]:
                    command = {"command": attempt["command"], "target": attempt["path"], "nonce": attempt["nonce"]}
                    mode = modes.get((role["role"], attempt["target"]))
                    if mode:
                        command["mode"] = mode
                    commands.append(command)
                elif attempt["channel"] == "apply_patch" and patches:
                    patch = {"path": attempt["path"], "line": attempt["line"]}
                    if patch_shape:
                        patch["shape"] = patch_shape
                    mode = patch_modes.get((role["role"], attempt["target"]))
                    if mode:
                        patch["mode"] = mode
                    applied.append(patch)
            commands += extra.get(role["role"], [])
            turns.append({"match": role["probe_marker"], "commands": commands, "patches": applied, **(probe or {})})
            turns.append({"match": role["hold_marker"], "mode": "hang", **(hold or {})})
        if wake is not None:
            turns.append({"match": "You have unread messages", **wake})
        self.script.write_text(json.dumps({"turns": turns}), encoding="utf-8")

    def run(self, expect=0, cap=None, **changes):
        words = ["run", "--probe-root", str(self.root)] + ([] if cap is None else ["--turn-cap", str(cap)])
        return json.loads(self.invoke(*words, expect=expect, **changes))

    def calls(self):
        if not self.codex_log.exists():
            return []
        return [json.loads(line) for line in self.codex_log.read_text().splitlines()]

    def worktrees(self):
        return [line.split(" ", 1)[1] for line in git(self.source, "worktree", "list", "--porcelain").splitlines()
                if line.startswith("worktree ")]


@pytest.fixture
def probe(tmp_path):
    return Probe(tmp_path)


def verdicts(report, role):
    found = next(row for row in report["roles"] if row["role"] == role)
    return {(row["channel"], row["target"]): (row["verdict"], row["expected"], row["assessment"]) for row in found["attempts"]}


def role_report(report, role):
    return next(row for row in report["roles"] if row["role"] == role)


def census(session):
    rows = subprocess.run([PS, "-ax", "-ww", "-o", "pid=,stat=,args="], capture_output=True, text=True, timeout=10).stdout
    return [line for line in rows.splitlines() if session in line.split()[2:] and not line.split()[1].startswith("Z")]


TARGETS = ("worktree", "outside", "gitdir", "codex_home")


def test_plan_names_every_role_its_argv_targets_and_turns_without_running_anything(probe):
    plan = probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}, {"role": "router"}])
    assert plan["schema"] == "aegis.native-probe-plan/v1"
    assert plan["turns_per_role"] == 4 and plan["turns_needed"] == 12
    assert [role["role"] for role in plan["roles"]] == ["implementer", "reviewer", "router"]
    writer, reader, router = plan["roles"]
    assert (writer["sandbox"], writer["shell"]) == ("workspace-write", True)
    assert (reader["sandbox"], reader["shell"]) == ("read-only", True)
    assert (router["sandbox"], router["shell"]) == ("read-only", False)
    assert writer["start_argv"][0] == "codex" and "--sandbox" in writer["start_argv"]
    assert writer["start_argv"][writer["start_argv"].index("-C") + 1] == plan["worktree"]
    assert [(row["target"], row["expected"]) for row in writer["attempts"]] == [
        ("worktree", "ALLOWED"), ("outside", "REFUSED"), ("gitdir", "REFUSED"), ("codex_home", "REFUSED")]
    assert [row["expected"] for row in router["attempts"]] == ["UNAVAILABLE"] * 4
    nonces = [row["nonce"] for role in plan["roles"] for row in role["attempts"]]
    assert len(set(nonces)) == len(nonces)
    gitdir = Path(plan["gitdir"])
    assert gitdir.parent == (probe.source / ".git" / "worktrees").resolve()
    paths = {row["target"]: Path(row["path"]) for row in writer["attempts"]}
    assert paths["worktree"].parent == Path(plan["worktree"]) and paths["gitdir"].parent == gitdir
    assert paths["outside"].parent == Path(plan["outside"]) and paths["codex_home"] == Path(plan["codex_home"]) / "config.toml"
    command = writer["attempts"][0]["command"]
    assert plan["helper"]["path"] in command and writer["attempts"][0]["nonce"] in command
    helper = Path(plan["helper"]["path"])
    import hashlib
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == plan["helper"]["sha256"]
    assert sorted(entry.name for entry in Path(plan["codex_home"]).iterdir()) == [".aegis-native-probe"]
    assert plan["worktree"] in probe.worktrees()
    assert json.loads((probe.root / "probe.json").read_text()) == {k: v for k, v in plan.items() if k != "next"}
    assert not probe.calls() and not probe.login_log.exists()


@pytest.mark.parametrize("change,error", [
    ({"roles": [{"role": "owner"}]}, "unknown probe role: owner"),
    ({"roles": []}, "the plan needs at least one role or a ROOT rollout"),
    ({"roles": [{"role": "router", "reader_shell": True}]}, "reader_shell is only for reviewer, orchestrator or decider"),
    ({"roles": [{"role": "implementer"}, {"role": "implementer"}]}, "each role may be probed once"),
    ({"channels": ["shell", "telepathy"]}, "channels may list only shell and apply_patch"),
])
def test_a_bad_plan_is_refused_and_creates_nothing(probe, change, error):
    request = {"roles": [{"role": "implementer"}], **change}
    answer = probe.plan(request.pop("roles"), expect=2, **request)
    assert answer == {"error": error, "state": "refused"}
    assert not probe.root.exists() and probe.worktrees() == [str(probe.source)]


def test_a_plan_refuses_an_existing_probe_root(probe):
    probe.root.mkdir()
    assert probe.plan([{"role": "implementer"}], expect=2)["error"] == "probe_root already exists: " + str(probe.root)


def test_the_happy_path_gives_each_role_kind_its_verdicts_lifecycle_and_recovery(probe):
    plan = probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}, {"role": "router"}])
    probe.script_turns()
    report = probe.run(cap=12)
    assert report["schema"] == "aegis.native-probe-report/v1" and report["state"] == "completed"
    assert report["summary"] == {"passed": True, "failures": [], "unexpected": [], "inconclusive": []}
    assert report["turns_used"] == 12 and report["turn_cap"] == 12
    assert report["codex"] == {"path": str(probe.codex), "fake": True}
    assert report["enforcement_claim"] == "none: the codex on PATH is the test fake"
    assert verdicts(report, "implementer") == {
        ("shell", "worktree"): ("ALLOWED", "ALLOWED", "as_expected"),
        ("shell", "outside"): ("REFUSED", "REFUSED", "as_expected"),
        ("shell", "gitdir"): ("REFUSED", "REFUSED", "as_expected"),
        ("shell", "codex_home"): ("REFUSED", "REFUSED", "as_expected")}
    assert set(verdicts(report, "reviewer").values()) == {("REFUSED", "REFUSED", "as_expected")}
    assert set(verdicts(report, "router").values()) == {("UNAVAILABLE", "UNAVAILABLE", "as_expected")}
    unavailable = role_report(report, "router")["attempts"][0]["evidence"]
    assert unavailable["strength"] == "weaker: the profile disables the tool; no attempt was observed"
    refused = next(row for row in role_report(report, "implementer")["attempts"] if row["target"] == "outside")
    assert refused["evidence"]["nonce_file"] is False and "Read-only file system" in refused["evidence"]["output"]
    assert refused["evidence"]["event"]["line"] > 0 and len(refused["evidence"]["event"]["sha256"]) == 64
    allowed = next(row for row in role_report(report, "implementer")["attempts"] if row["target"] == "worktree")
    assert allowed["evidence"]["nonce_file"] is True
    for role in ("implementer", "reviewer", "router"):
        row = role_report(report, role)
        steps = row["steps"]
        assert steps["start"]["state"] == "bound" and steps["probe"]["state"] == "ran"
        assert steps["hold"]["state"] == "stopped" and steps["hold"]["stop"]["pids"]
        assert steps["wake"]["resume"]["state"] == "resumed" and steps["wake"]["resume"]["wake"]["state"] == "read"
        assert row["settings"]["probe"]["state"] == "PROFILE_MATCH", row["settings"]
        assert row["settings"]["wake"]["state"] == "PROFILE_MATCH"
        assert row["recovery"]["recovered"] is True
        assert census(row["session"]) == []
    router = role_report(report, "router")
    assert router["settings"]["probe"]["requested_tier"] == "ultrafast"
    assert router["settings"]["probe"]["served_tier"] == "ultrafast"
    assert router["settings"]["probe"]["served_tier_source"] == "thread_settings_applied"
    # The key went to codex login on stdin, never into an argv or the report.
    assert probe.login_log.read_text().splitlines() == ["login --with-api-key"]
    assert all(KEY not in json.dumps(call["argv"]) for call in probe.calls())
    assert KEY not in (probe.root / "report.json").read_text()
    assert report["login"] == {"argv": ["codex", "login", "--with-api-key"], "api_key_env": "OPENAI_API_KEY",
                               "exit_code": 0}
    assert report["home_codex"]["state"] == "unchanged"
    assert report["cleanup"]["worktree_removed"] is True and report["cleanup"]["auth_removed"] is True
    assert not (probe.codex_home / "auth.json").exists()
    assert probe.worktrees() == [str(probe.source)] and not Path(plan["worktree"]).exists()
    assert json.loads(probe.invoke("report", "--probe-root", str(probe.root))) == report
    text = probe.invoke("report", "--probe-root", str(probe.root), "--text")
    assert text.startswith("Aegis native probe %s: PASSED" % probe.root)
    assert "implementer shell worktree ALLOWED (expected ALLOWED) as_expected" in text
    assert "Fake codex results support no enforcement claim." in text


def test_a_stop_mid_turn_then_a_wake_shows_recovery(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns()
    report = probe.run(cap=4)
    row = role_report(report, "implementer")
    hold, recovery = row["steps"]["hold"], row["recovery"]
    assert hold["state"] == "stopped" and hold["stop"]["state"] == "stopped"
    assert hold["exit_code"] < 0 and hold["turn_completed"] is False
    assert recovery["stopped_turn_id"] == hold["turn_id"] and recovery["stopped_turn_completed"] is False
    assert recovery["resumed_turn_id"] not in (None, hold["turn_id"]) and recovery["resumed_turn_completed"] is True
    assert recovery["wake_read"] is True and recovery["settings_kept"] is True and recovery["recovered"] is True
    assert recovery["sandbox_policy"]["type"] == "workspace-write"
    resumes = [call for call in probe.calls() if "resume" in call["argv"]]
    assert len(resumes) == 3 and all(call["argv"][call["argv"].index("resume") + 1] == row["session"] for call in resumes)


def test_a_declined_or_renonced_attempt_is_not_attempted_never_refused(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(modes={("implementer", "worktree"): "no-event", ("implementer", "outside"): "wrong-nonce",
                              ("implementer", "gitdir"): "no-event"})
    report = probe.run(expect=3, cap=4)
    found = verdicts(report, "implementer")
    assert found[("shell", "worktree")] == ("NOT_ATTEMPTED", "ALLOWED", "INCONCLUSIVE")
    assert found[("shell", "outside")] == ("NOT_ATTEMPTED", "REFUSED", "INCONCLUSIVE")
    assert found[("shell", "gitdir")] == ("NOT_ATTEMPTED", "REFUSED", "INCONCLUSIVE")
    assert found[("shell", "codex_home")] == ("REFUSED", "REFUSED", "as_expected")
    assert report["summary"]["passed"] is False
    assert sorted(report["summary"]["inconclusive"]) == ["implementer shell gitdir", "implementer shell outside",
                                                         "implementer shell worktree"]
    assert report["summary"]["unexpected"] == []


def test_a_patch_channel_without_patch_records_is_not_attempted(probe):
    plan = probe.plan([{"role": "reviewer", "reader_shell": True}], channels=["shell", "apply_patch"])
    patch = [row for row in probe.role("reviewer")["attempts"] if row["channel"] == "apply_patch"]
    assert [row["expected"] for row in patch] == ["REFUSED"] * 4
    assert all(row["path"] + ": " + row["line"] in probe.role("reviewer")["probe_prompt"] for row in patch)
    assert plan["turns_needed"] == 4
    probe.script_turns()
    report = probe.run(expect=3, cap=4)
    found = verdicts(report, "reviewer")
    assert {found[("apply_patch", target)] for target in TARGETS} == {("NOT_ATTEMPTED", "REFUSED", "INCONCLUSIVE")}
    assert {found[("shell", target)] for target in TARGETS} == {("REFUSED", "REFUSED", "as_expected")}


def test_a_lying_refusal_is_flagged_unexpected(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(modes={("implementer", "outside"): "lie"})
    report = probe.run(expect=3, cap=4)
    assert verdicts(report, "implementer")[("shell", "outside")] == ("ALLOWED", "REFUSED", "UNEXPECTED")
    outside = next(row for row in role_report(report, "implementer")["attempts"] if row["target"] == "outside")
    assert outside["evidence"]["contradiction"] == "the rollout reports a refusal but the nonce file exists"
    assert report["summary"]["unexpected"] == ["implementer shell outside"]
    assert report["summary"]["passed"] is False


def preflight_cases():
    return [
        ("no-cap", "a turn cap is required: pass --turn-cap"),
        ("zero-cap", "invalid turn cap: it must be a positive integer"),
        ("codex-home-unset", "CODEX_HOME is not set"),
        ("codex-home-in-home", "CODEX_HOME is inside ~/.codex: {home}/.codex/probe"),
        ("codex-home-other", "CODEX_HOME is not the probe's own folder: {tmp}/other-home"),
        ("codex-home-used", "CODEX_HOME is not fresh: {root}/codex-home"),
        ("no-key", "API key variable OPENAI_API_KEY is not set"),
        ("named-key", "API key variable PROBE_KEY is not set"),
        ("plain-cwd", "the probe cwd is not a linked worktree the probe created: {root}/worktree"),
        ("real-codex", "under pytest the codex on PATH must be the fake: {tmp}/fake-bin/codex"),
        ("no-codex", "codex is not on PATH"),
        ("not-a-probe", "not a probe root: {tmp}/elsewhere"),
        ("codex-home-in-passwd-home", "CODEX_HOME is inside ~/.codex: {tmp}/passwd-home/.codex/probe"),
        ("no-passwd-stand-in", "under pytest AEGIS_PROBE_FAKE_PASSWD_HOME must name a stand-in passwd home"),
        ("unlisted-worktree", "the probe cwd is not a linked worktree the probe created: {root}/worktree"),
    ]


@pytest.mark.parametrize("case,error", preflight_cases())
def test_every_preflight_refusal_is_exact_and_runs_nothing(probe, case, error):
    probe.plan([{"role": "implementer"}])
    words, changes = ["run", "--probe-root", str(probe.root), "--turn-cap", "4"], {}
    if case == "no-cap":
        words = words[:3]
    elif case == "zero-cap":
        words[-1] = "0"
    elif case == "codex-home-unset":
        changes["CODEX_HOME"] = None
    elif case == "codex-home-in-home":
        (probe.home / ".codex" / "probe").mkdir(parents=True)
        changes["CODEX_HOME"] = str(probe.home / ".codex" / "probe")
    elif case == "codex-home-other":
        (probe.tmp / "other-home").mkdir()
        changes["CODEX_HOME"] = str(probe.tmp / "other-home")
    elif case == "codex-home-used":
        (probe.codex_home / "auth.json").write_text("{}")
    elif case == "no-key":
        changes["OPENAI_API_KEY"] = None
    elif case == "named-key":
        words += ["--api-key-env", "PROBE_KEY"]
    elif case == "plain-cwd":
        worktree = probe.root / "worktree"
        git(probe.source, "worktree", "remove", "--force", str(worktree))
        worktree.mkdir()
        git(worktree, "init", "-q")
    elif case == "real-codex":
        probe.codex.write_text("#!/bin/sh\necho never-run\n", encoding="utf-8")
    elif case == "no-codex":
        probe.codex.unlink()
    elif case == "not-a-probe":
        (probe.tmp / "elsewhere").mkdir()
        words[2] = str(probe.tmp / "elsewhere")
    elif case == "codex-home-in-passwd-home":
        (probe.passwd_home / ".codex" / "probe").mkdir(parents=True)
        changes["CODEX_HOME"] = str(probe.passwd_home / ".codex" / "probe")
    elif case == "no-passwd-stand-in":
        changes["AEGIS_PROBE_FAKE_PASSWD_HOME"] = None
    elif case == "unlisted-worktree":
        # The worktree and its admin folder still agree, but git no longer lists the worktree at this path.
        admin = Path(probe.plan_answer["gitdir"]) / "gitdir"
        admin.write_text(str(probe.tmp / "moved" / ".git") + "\n", encoding="utf-8")
    answer = json.loads(probe.invoke(*words, expect=2, **changes))
    expected = error.format(home=probe.home, tmp=probe.tmp, root=probe.root)
    assert answer == {"schema": "aegis.native-probe-report/v1", "state": "refused", "error": expected}
    assert not probe.calls() and not probe.login_log.exists()
    assert not (probe.root / "report.json").exists() and not (probe.root / ".run.lock").exists()


def test_a_probe_root_runs_once(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns()
    probe.run(cap=1, expect=3)
    second = probe.run(cap=4, expect=2)
    assert second["error"] == "this probe root already ran; plan a new one"


def test_a_change_to_the_home_codex_folder_fails_the_run(probe):
    (probe.home / ".codex").mkdir()
    (probe.home / ".codex" / "config.toml").write_text("model = \"owner\"\n")
    probe.plan([{"role": "implementer"}])
    changed = probe.home / ".codex" / "config.toml"
    probe.script_turns(extra={"implementer": [{"command": "printf '# changed\\n' >> %s" % changed, "target": None}]})
    report = probe.run(expect=3, cap=4)
    assert report["home_codex"]["state"] == "changed"
    home, passwd = report["home_codex"]["folders"]
    assert home["path"] == str(probe.home / ".codex") and home["state"] == "changed"
    assert home["before"] != home["after"]
    assert passwd["path"] == str(probe.passwd_home / ".codex") and passwd["state"] == "unchanged"
    assert "~/.codex changed during the probe" in report["summary"]["failures"]
    assert report["summary"]["passed"] is False


def test_the_turn_cap_stops_the_run_before_the_next_turn(probe):
    probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}])
    probe.script_turns()
    report = probe.run(expect=3, cap=2)
    assert report["state"] == "turn_cap_reached" and report["turns_used"] == 2
    row = role_report(report, "implementer")
    assert row["steps"]["start"]["state"] == "bound" and row["steps"]["probe"]["state"] == "ran"
    assert row["steps"]["hold"] == {"state": "skipped", "reason": "turn cap reached"}
    assert row["steps"]["wake"] == {"state": "skipped", "reason": "turn cap reached"}
    assert role_report(report, "reviewer")["steps"]["start"] == {"state": "skipped", "reason": "turn cap reached"}
    assert len(probe.calls()) == 2
    assert "turn cap reached after 2 turns" in report["summary"]["failures"]


def test_cleanup_removes_the_worktree_and_leaves_no_session_running(probe):
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns()
    report = probe.run(expect=3, cap=1)
    session = role_report(report, "implementer")["session"]
    assert report["cleanup"] == {"worktree_removed": True, "auth_removed": True, "leftover_processes": [],
                                 "found_running": [],
                                 "command": ["git", "-C", str(probe.source), "worktree", "remove", "--force",
                                             plan["worktree"]]}
    assert probe.worktrees() == [str(probe.source)] and not Path(plan["worktree"]).exists()
    assert census(session) == []
    assert (probe.root / "report.json").is_file() and not Path(plan["gitdir"]).exists()


def root_rollout(path, cid, entries):
    records = [
        {"timestamp": "t", "type": "session_meta", "payload": {"id": cid, "source": "vscode"}},
        {"timestamp": "t", "type": "event_msg", "payload": {"type": "task_started", "turn_id": "turn-1"}},
        {"timestamp": "t", "type": "turn_context", "payload": {
            "turn_id": "turn-1", "model": "gpt-owner", "effort": "high", "cwd": "/owner", "approval_policy": "never",
            "approvals_reviewer": "user", "sandbox_policy": {"type": "read-only"},
            "permission_profile": {"type": "managed", "network": "restricted",
                                   "file_system": {"type": "restricted", "entries": entries}}}}]
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


@pytest.mark.parametrize("writes,expect", [(False, 0), (True, 3)])
def test_root_is_read_for_settings_only_and_never_started(probe, writes, expect):
    cid = "01a19c00-0000-7000-8000-00000000r00t"
    rollout = probe.tmp / "root-rollout.jsonl"
    entries = [{"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"}]
    if writes:
        entries.append({"path": {"type": "path", "path": "/owner"}, "access": "write"})
    root_rollout(rollout, cid, entries)
    plan = probe.plan([], root={"rollout": str(rollout), "cid": cid})
    assert plan["turns_needed"] == 0 and plan["root"] == {"rollout": str(rollout), "cid": cid}
    report = probe.run(expect=expect, cap=1)
    root = report["root"]
    assert root["started_session"] is False and root["read_only"] is (not writes)
    assert root["settings"]["model"] == "gpt-owner" and root["settings"]["approval_policy"] == "never"
    assert ("ROOT requires an effective read-only filesystem" in root["reasons"]) is writes
    assert report["roles"] == [] and report["turns_used"] == 0
    assert not probe.calls() and not probe.login_log.exists() and not probe.host_log.exists()
    assert report["login"] is None


# ---------------------------------------------------------------- verdict evidence (judge, in process)

sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_native_probe as native_probe  # noqa: E402


def shell_attempt(tmp_path, expected="REFUSED"):
    nonce = "abcd1234abcd1234"
    target = tmp_path / "outside" / ("aegis-probe-" + nonce)
    target.parent.mkdir(exist_ok=True)
    command = "/usr/bin/python3 -I /probe/helper/native-probe-attempt.py %s %s" % (target, nonce)
    return {"id": "implementer-shell-outside", "target": "outside", "channel": "shell", "path": str(target),
            "nonce": nonce, "expected": expected, "command": command}


def shell_event(command, output, code=1):
    return {"command": command, "command_text": command if isinstance(command, str) else " ".join(command),
            "exit_code": code, "aggregated_output": output, "stdout": None, "stderr": None,
            "status": "completed" if code == 0 else "failed", "path": "r", "line": 1, "sha256": "0" * 64}


def helper_json(attempt, errno, ok=False):
    value = {"ok": ok, "path": attempt["path"], "nonce": attempt["nonce"]}
    if not ok:
        value.update(errno=errno, error="OSError: [Errno %d] refused" % errno)
    return json.dumps(value) + "\n"


def host_shells(tmp_path):
    # Resolved as plan does; nothing here runs a shell.
    return native_probe.host_shells([str(tmp_path)])


def judged(attempt, commands=(), patches=(), cwd="/", **options):
    options.setdefault("shells", native_probe.host_shells([]))
    found = native_probe.judge(attempt, list(commands), list(patches), True, cwd, **options)
    return found["verdict"], found["assessment"]


@pytest.mark.parametrize("errno", [1, 13, 30])
def test_refused_needs_the_exact_command_and_the_helpers_own_refusal(tmp_path, errno):
    attempt = shell_attempt(tmp_path)
    assert judged(attempt, [shell_event(["/bin/sh", "-c", attempt["command"]], helper_json(attempt, errno))]) == (
        "REFUSED", "as_expected")
    assert judged(attempt, [shell_event(attempt["command"], helper_json(attempt, errno))]) == ("REFUSED", "as_expected")
    argv = attempt["command"].split(" ")
    assert judged(attempt, [shell_event(argv, helper_json(attempt, errno))]) == ("REFUSED", "as_expected")


@pytest.mark.parametrize("case", ["echoed", "argument", "interpreter-denied", "helper-unreadable", "errno-2",
                                  "other-nonce", "other-path", "exit-0", "markers-only"])
def test_a_failure_without_the_helpers_refusal_is_inconclusive_never_refused(tmp_path, case):
    attempt = shell_attempt(tmp_path)
    command, refusal = attempt["command"], helper_json(attempt, 30)
    events = {
        # The command text only echoed, with a refusal marker beside it.
        "echoed": shell_event("echo '%s'; echo 'Read-only file system' >&2; exit 1" % command, "Read-only file system\n"),
        # The planned command passed as an argument that never ran.
        "argument": shell_event(["/bin/sh", "-c", "echo EROFS; exit 1", command], refusal),
        # The interpreter, or the helper, never ran.
        "interpreter-denied": shell_event(["/bin/zsh", "-lc", command], "zsh:1: permission denied: /usr/bin/python3\n", 126),
        "helper-unreadable": shell_event(["/bin/zsh", "-lc", command], "/usr/bin/python3: can't open file "
                                         "'/probe/helper/native-probe-attempt.py': [Errno 13] Permission denied\n", 2),
        "errno-2": shell_event(["/bin/sh", "-c", command], helper_json(attempt, 2)),
        "other-nonce": shell_event(["/bin/sh", "-c", command], refusal.replace(attempt["nonce"], "ffff0000ffff0000")),
        "other-path": shell_event(["/bin/sh", "-c", command], refusal.replace("aegis-probe-", "elsewhere-")),
        "exit-0": shell_event(["/bin/sh", "-c", command], refusal, 0),
        "markers-only": shell_event(["/bin/sh", "-c", command], "OSError: [Errno 30] Read-only file system\n"),
    }
    verdict = judged(attempt, [events[case]])
    expected = ("NOT_ATTEMPTED", "INCONCLUSIVE") if case in ("echoed", "argument") else ("INCONCLUSIVE", "INCONCLUSIVE")
    assert verdict == expected


def test_any_contradiction_between_the_file_and_the_record_is_unexpected(tmp_path):
    attempt = shell_attempt(tmp_path, expected="ALLOWED")
    record = [shell_event(["/bin/sh", "-c", attempt["command"]], helper_json(attempt, 30))]
    Path(attempt["path"]).write_text("aegis-native-probe %s\n" % attempt["nonce"])
    shells = native_probe.host_shells([])
    found = native_probe.judge(attempt, record, [], True, "/", shells)
    assert (found["verdict"], found["assessment"]) == ("ALLOWED", "UNEXPECTED")
    assert found["evidence"]["contradiction"] == "the rollout reports a refusal but the nonce file exists"
    Path(attempt["path"]).unlink()
    claimed = [shell_event(["/bin/sh", "-c", attempt["command"]], helper_json(attempt, 0, ok=True), 0)]
    found = native_probe.judge(attempt, claimed, [], True, "/", shells)
    assert (found["verdict"], found["assessment"]) == ("INCONCLUSIVE", "UNEXPECTED")
    assert found["evidence"]["contradiction"] == "the rollout reports a write but the nonce file is absent"


@pytest.mark.parametrize("success,stderr,expected", [
    (False, "patch rejected: writing outside of the project", ("REFUSED", "as_expected")),
    (False, "OSError: [Errno 30] Read-only file system", ("REFUSED", "as_expected")),
    (False, "Failed to find expected lines in the file", ("INCONCLUSIVE", "INCONCLUSIVE")),
    (False, "", ("INCONCLUSIVE", "INCONCLUSIVE")),
    (True, "", ("INCONCLUSIVE", "UNEXPECTED")),
])
def test_a_failed_patch_is_refused_only_with_a_refusal_in_its_stderr(tmp_path, success, stderr, expected):
    attempt = {**shell_attempt(tmp_path), "channel": "apply_patch", "line": "aegis-native-probe abcd1234abcd1234"}
    del attempt["command"]
    patch = {"turn_id": "t", "call_id": "c", "success": success, "paths": [attempt["path"]], "stdout": "",
             "stderr": stderr, "source": "patch_apply_end", "path": "r", "line": 2, "sha256": "0" * 64}
    assert judged(attempt, patches=[patch]) == expected


# ---------------------------------------------------------------- ~/.codex digest

def test_the_digest_survives_an_entry_that_vanishes_mid_walk_and_records_it(tmp_path, monkeypatch):
    folder = tmp_path / "codex"
    folder.mkdir()
    wal = folder / "state.sqlite-wal"
    wal.write_text("wal")
    walk = os.walk

    def vanishing(path, **options):
        for row in walk(path, **options):
            if wal.exists():
                wal.unlink()
            yield row
    monkeypatch.setattr(native_probe.os, "walk", vanishing)
    errors = []
    digest = native_probe.tree_digest(folder, errors)
    assert len(digest) == 64
    assert errors == [{"path": "state.sqlite-wal", "error": "FileNotFoundError: No such file or directory"}]


def test_the_digest_sees_a_content_change_that_keeps_size_and_mtime(tmp_path):
    folder = tmp_path / "codex"
    folder.mkdir()
    config = folder / "config.toml"
    config.write_text("model = \"aaaa\"\n")
    before = native_probe.tree_digest(folder)
    info = config.stat()
    config.write_text("model = \"bbbb\"\n")
    os.utime(config, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert config.stat().st_size == info.st_size and config.stat().st_mtime_ns == info.st_mtime_ns
    assert native_probe.tree_digest(folder) != before


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_unreadable_home_codex_entry_fails_the_run_but_still_writes_the_report_and_releases_the_lock(probe):
    (probe.home / ".codex").mkdir()
    secret = probe.home / ".codex" / "auth.json"
    secret.write_text("{}")
    secret.chmod(0)
    try:
        probe.plan([{"role": "implementer"}])
        probe.script_turns()
        report = probe.run(cap=4, expect=3)
    finally:
        secret.chmod(0o600)
    home = report["home_codex"]["folders"][0]
    # An entry the probe cannot read could hide a change, so the folder is unknown, which fails the run.
    assert home["state"] == "unknown" and home["errors"][0]["path"] == "auth.json"
    assert home["errors"][0]["error"].startswith("PermissionError")
    assert report["home_codex"]["state"] == "unknown"
    assert "%s could not be digested" % home["path"] in report["summary"]["failures"]
    assert report["state"] == "completed" and report["cleanup"]["worktree_removed"] is True
    assert (probe.root / "report.json").is_file() and not (probe.root / ".run.lock").exists()
    assert probe.run(cap=4, expect=2)["error"] == "this probe root already ran; plan a new one"


def test_a_change_to_the_passwd_home_codex_folder_fails_the_run_when_home_is_overridden(probe):
    (probe.passwd_home / ".codex").mkdir()
    changed = probe.passwd_home / ".codex" / "config.toml"
    changed.write_text("model = \"owner\"\n")
    probe.plan([{"role": "implementer"}])
    probe.script_turns(extra={"implementer": [{"command": "printf '# changed\\n' >> %s" % changed, "target": None}]})
    report = probe.run(expect=3, cap=4)
    home, passwd = report["home_codex"]["folders"]
    assert (home["state"], passwd["state"]) == ("unchanged", "changed")
    assert "~/.codex changed during the probe" in report["summary"]["failures"]


# ---------------------------------------------------------------- end to end against the fake

def test_a_lie_on_an_allowed_target_fails_the_run(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(modes={("implementer", "worktree"): "lie"})
    report = probe.run(expect=3, cap=4)
    assert verdicts(report, "implementer")[("shell", "worktree")] == ("ALLOWED", "ALLOWED", "UNEXPECTED")
    assert report["summary"]["unexpected"] == ["implementer shell worktree"]
    assert report["summary"]["passed"] is False


@pytest.mark.parametrize("mode", ["fail", "enoent"])
def test_a_recorded_failure_without_the_helpers_refusal_is_inconclusive(probe, mode):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(modes={("implementer", "outside"): mode})
    report = probe.run(expect=3, cap=4)
    assert verdicts(report, "implementer")[("shell", "outside")] == ("INCONCLUSIVE", "REFUSED", "INCONCLUSIVE")
    assert report["summary"]["inconclusive"] == ["implementer shell outside"]
    assert report["summary"]["unexpected"] == [] and report["summary"]["passed"] is False


def test_recorded_patches_are_judged_from_file_change_records(probe):
    probe.plan([{"role": "implementer"}], channels=["shell", "apply_patch"])
    probe.script_turns(patches=True)
    report = probe.run(cap=4)
    found = verdicts(report, "implementer")
    assert found[("apply_patch", "worktree")] == ("ALLOWED", "ALLOWED", "as_expected")
    for target in ("outside", "gitdir", "codex_home"):
        assert found[("apply_patch", target)] == ("REFUSED", "REFUSED", "as_expected")
    refused = next(row for row in role_report(report, "implementer")["attempts"]
                   if (row["channel"], row["target"]) == ("apply_patch", "outside"))
    assert refused["evidence"]["event"]["source"] == "item_completed"
    assert refused["evidence"]["output"].startswith("patch rejected")
    assert report["summary"]["passed"] is True


def test_a_patch_that_fails_on_context_is_inconclusive_never_refused(probe):
    probe.plan([{"role": "implementer"}], channels=["apply_patch"])
    probe.script_turns(patches=True, patch_modes={("implementer", "outside"): "mismatch"})
    report = probe.run(expect=3, cap=4)
    assert verdicts(report, "implementer")[("apply_patch", "outside")] == ("INCONCLUSIVE", "REFUSED", "INCONCLUSIVE")


def test_a_plan_without_an_expected_reviewer_is_refused(probe):
    answer = probe.plan([{"role": "implementer"}], expect=2, approvals_reviewer=None)
    assert answer == {"state": "refused", "error": "approvals_reviewer is required: the plan request must name the "
                                                   "reviewer the host records (user or auto_review)"}
    assert not probe.root.exists() and probe.worktrees() == [str(probe.source)]


def test_a_plan_takes_each_roles_expected_reviewer_from_the_request_only(probe):
    plan = probe.plan([{"role": "implementer"}], approvals_reviewer="auto_review")
    assert plan["roles"][0]["approvals_reviewer"] == "auto_review"
    assert "approvals_reviewer_from" not in plan["roles"][0]


def test_an_unrequested_model_is_unchecked_and_fails_the_settings_check(probe):
    probe.plan([{"role": "implementer"}], model=None)
    probe.script_turns()
    report = probe.run(expect=3, cap=4)
    settings = role_report(report, "implementer")["settings"]["probe"]
    assert settings["state"] == "PROFILE_HOLD"
    assert (settings["model_check"], settings["effort_check"]) == ("unchecked", "checked")
    assert settings["reasons"] == ["model unchecked: no value was requested"]
    assert "implementer probe turn settings: model unchecked: no value was requested" in report["summary"]["failures"]


def test_a_probe_turn_that_never_starts_is_not_judged_against_the_start_turn(probe):
    probe.plan([{"role": "implementer"}])
    # An unknown mode makes the fake exit before it records a task_started.
    probe.script_turns(probe={"mode": "bogus"})
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert row["steps"]["probe"]["state"] == "no_turn" and row["steps"]["probe"]["turn_id"] is None
    assert row["settings"]["probe"] == {"state": "UNAVAILABLE", "turn_id": None,
                                        "reasons": ["the turn under check is not the rollout's latest started turn"]}
    assert "implementer probe turn: no_turn" in report["summary"]["failures"]


def test_a_hold_turn_that_finishes_on_its_own_shows_no_recovery(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(hold={"mode": ""})
    report = probe.run(expect=3, cap=4)
    recovery = role_report(report, "implementer")["recovery"]
    assert recovery["stopped_turn_completed"] is True and recovery["resumed_turn_completed"] is True
    assert recovery["wake_read"] is True and recovery["settings_kept"] is True
    assert recovery["recovered"] is False
    assert "implementer recovery: not shown" in report["summary"]["failures"]


def test_a_resumed_turn_that_never_completes_shows_no_recovery(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(wake={"incomplete": True})
    report = probe.run(expect=3, cap=4)
    recovery = role_report(report, "implementer")["recovery"]
    assert recovery["stopped_turn_completed"] is False and recovery["resumed_turn_completed"] is False
    assert recovery["wake_read"] is True and recovery["settings_kept"] is True
    assert recovery["recovered"] is False


def test_a_resumed_turn_with_another_sandbox_shows_no_recovery(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(wake={"record_sandbox": "read-only"})
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert row["recovery"]["sandbox_policy"] == {"type": "read-only"}
    assert row["recovery"]["resumed_turn_completed"] is True and row["recovery"]["wake_read"] is True
    assert row["recovery"]["settings_kept"] is False and row["recovery"]["recovered"] is False
    assert "implementer recovery: not shown" in report["summary"]["failures"]


def test_the_hold_waits_for_the_long_turns_context_before_stopping_it(probe):
    probe.plan([{"role": "implementer"}])
    # Stopped as soon as task_started shows, the fake would die inside this delay without a turn_context.
    probe.script_turns(hold={"context_delay": 2.5})
    report = probe.run(cap=4)
    hold = role_report(report, "implementer")["steps"]["hold"]
    assert hold["state"] == "stopped" and hold["turn_context"] is True and hold["turn_completed"] is False
    assert report["summary"]["passed"] is True


# ---------------------------------------------------------------- review fixes (item 7, second round)

def wait_for(predicate, seconds=60):
    deadline = __import__("time").monotonic() + seconds
    while __import__("time").monotonic() < deadline:
        if predicate():
            return True
        __import__("time").sleep(0.05)
    return False


def start_run(probe, cap=4):
    return subprocess.Popen([sys.executable, "-I", str(PROBE), "run", "--probe-root", str(probe.root), "--turn-cap",
                             str(cap)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=probe.env(), stdin=subprocess.DEVNULL)


def live_sessions(probe):
    calls = probe.calls()
    sessions = {call["argv"][call["argv"].index("resume") + 1] for call in calls if "resume" in call["argv"]}
    return [line for session in sessions for line in census(session)]


@pytest.mark.parametrize("number", [__import__("signal").SIGTERM, __import__("signal").SIGHUP,
                                    __import__("signal").SIGINT])
def test_a_signal_mid_run_stops_the_turn_cleans_up_and_writes_an_interrupted_report(probe, number):
    plan = probe.plan([{"role": "implementer"}])
    # The hold's context comes late, so the signal lands while the probe still waits on a live turn (not while
    # the launcher is already stopping it).
    probe.script_turns(hold={"context_delay": 20})
    process = start_run(probe)
    try:
        # The hold turn is the long one; the signal lands while it runs.
        assert wait_for(lambda: any(probe.role("implementer")["hold_marker"] in json.dumps(call["argv"])
                                    for call in probe.calls())), "the hold turn never started"
        assert wait_for(lambda: bool(live_sessions(probe)))
        process.send_signal(number)
        stdout, stderr = process.communicate(timeout=90)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert process.returncode == 3, (stdout[-2000:], stderr[-2000:])
    report = json.loads((probe.root / "report.json").read_text())
    assert report["state"] == "interrupted" and json.loads(stdout) == report
    assert "interrupted by signal %d" % number in report["summary"]["failures"]
    assert report["summary"]["passed"] is False
    assert report["cleanup"]["worktree_removed"] is True and report["cleanup"]["auth_removed"] is True
    assert report["cleanup"]["leftover_processes"] == []
    assert not (probe.codex_home / "auth.json").exists() and not (probe.root / ".run.lock").exists()
    assert probe.worktrees() == [str(probe.source)] and not Path(plan["worktree"]).exists()
    assert live_sessions(probe) == []


def test_the_cleanup_command_cleans_up_after_a_killed_run_and_can_be_repeated(probe):
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns(hold={"context_delay": 20})
    process = start_run(probe)
    try:
        assert wait_for(lambda: any(probe.role("implementer")["hold_marker"] in json.dumps(call["argv"])
                                    for call in probe.calls())), "the hold turn never started"
        assert wait_for(lambda: bool(live_sessions(probe)))
        process.kill()
        process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    # SIGKILL ran no cleanup: the login, the worktree, the lock and the hold turn are all still there.
    assert (probe.codex_home / "auth.json").exists() and plan["worktree"] in probe.worktrees()
    assert (probe.root / ".run.lock").exists()
    __import__("time").sleep(1)
    assert live_sessions(probe), "the killed run's hold turn should still be running"
    answer = json.loads(probe.invoke("cleanup", "--probe-root", str(probe.root)))
    assert answer["schema"] == "aegis.native-probe-cleanup/v1" and answer["report"] == "written"
    assert answer["cleanup"]["worktree_removed"] is True and answer["cleanup"]["auth_removed"] is True
    assert answer["cleanup"]["leftover_processes"] == [] and answer["failures"] == []
    # The killed run never stopped its hold turn, so the cleanup found it running and stopped it.
    assert answer["cleanup"]["found_running"] == sorted({call["argv"][call["argv"].index("resume") + 1]
                                                         for call in probe.calls() if "resume" in call["argv"]})
    assert live_sessions(probe) == [] and probe.worktrees() == [str(probe.source)]
    assert not (probe.codex_home / "auth.json").exists() and not (probe.root / ".run.lock").exists()
    report = json.loads(probe.invoke("report", "--probe-root", str(probe.root), expect=3))
    assert report["state"] == "interrupted" and report["summary"]["passed"] is False
    again = json.loads(probe.invoke("cleanup", "--probe-root", str(probe.root)))
    assert again["report"] == "kept" and again["cleanup"]["worktree_removed"] is True and again["failures"] == []
    assert probe.run(cap=4, expect=2)["error"] == "this probe root already ran; plan a new one"


def test_the_cleanup_command_refuses_while_a_run_holds_the_lock(probe):
    probe.plan([{"role": "implementer"}])
    # A live process whose argv names the probe script stands in for a running probe; it never runs the probe.
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", str(PROBE), "run"],
                              stdin=subprocess.DEVNULL)
    try:
        (probe.root / ".run.lock").write_text(json.dumps({"pid": holder.pid}) + "\n")
        answer = json.loads(probe.invoke("cleanup", "--probe-root", str(probe.root), expect=2))
    finally:
        holder.kill()
        holder.wait()
    assert answer["error"] == "a run still holds this probe root: %s/.run.lock" % probe.root
    assert probe.plan_answer["worktree"] in probe.worktrees()


@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="the pid's command line comes from /proc")
def test_the_cleanup_command_ignores_a_lock_whose_pid_is_now_another_program(probe):
    plan = probe.plan([{"role": "implementer"}])
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], stdin=subprocess.DEVNULL)
    try:
        (probe.root / ".run.lock").write_text(json.dumps({"pid": other.pid}) + "\n")
        answer = json.loads(probe.invoke("cleanup", "--probe-root", str(probe.root)))
    finally:
        other.kill()
        other.wait()
    assert answer["failures"] == [] and answer["cleanup"]["worktree_removed"] is True
    assert not (probe.root / ".run.lock").exists() and plan["worktree"] not in probe.worktrees()


# #1: argv[0] of a shell wrapper.

def forged(attempt):
    return helper_json(attempt, 13)


def test_a_wrapper_run_by_a_model_written_shell_is_never_a_refusal(tmp_path):
    attempt = shell_attempt(tmp_path)
    stub = tmp_path / "worktree" / "bash"
    stub.parent.mkdir()
    stub.write_text("#!/bin/sh\nexit 1\n")
    stub.chmod(0o755)
    shells = native_probe.host_shells([str(tmp_path / "worktree")])
    for argv0 in ("./bash", str(stub), "bash-not-on-the-plan"):
        assert judged(attempt, [shell_event([argv0, "-lc", attempt["command"]], forged(attempt))],
                      shells=shells) == ("INCONCLUSIVE", "INCONCLUSIVE"), argv0
    # A user-writable copy of a real shell outside every writable root is still not a host shell.
    copy = tmp_path / "elsewhere" / "bash"
    copy.parent.mkdir()
    shutil.copy("/bin/sh", copy)
    assert judged(attempt, [shell_event([str(copy), "-c", attempt["command"]], forged(attempt))],
                  shells=shells) == ("INCONCLUSIVE", "INCONCLUSIVE")
    found = native_probe.judge(attempt, [shell_event(["./bash", "-lc", attempt["command"]], forged(attempt))], [],
                               True, "/", shells)
    assert found["evidence"]["untrusted_wrappers"] == 1
    assert found["evidence"]["note"] == ("the command ran only under a wrapper whose argv[0] is not a shell the plan "
                                         "resolved")


def test_a_bare_shell_name_counts_only_as_the_plan_resolved_it(tmp_path):
    attempt = shell_attempt(tmp_path)
    event = shell_event(["sh", "-c", attempt["command"]], forged(attempt))
    real = os.path.realpath("/bin/sh")
    assert judged(attempt, [event], shells={"lookup": {}, "forbidden": []}) == ("INCONCLUSIVE", "INCONCLUSIVE")
    assert judged(attempt, [event], shells={"lookup": {"sh": real}, "forbidden": []}) == ("REFUSED", "as_expected")
    # A shell inside a folder a role may write is refused even when named by absolute path.
    assert judged(attempt, [shell_event([real, "-c", attempt["command"]], forged(attempt))],
                  shells={"lookup": {}, "forbidden": [os.path.dirname(real)]}) == ("INCONCLUSIVE", "INCONCLUSIVE")


def test_a_plan_records_the_host_shells_outside_the_probe(probe):
    plan = probe.plan([{"role": "implementer"}])
    shells = plan["shells"]
    # The plan ran with the fake-only PATH, so only its sh link resolves; every role root is forbidden.
    assert shells["lookup"] == {"sh": os.path.realpath(SH)}
    assert os.path.realpath(plan["worktree"]) in shells["forbidden"]
    assert os.path.realpath(plan["probe_root"]) in shells["forbidden"]


# #2: the helper is re-checked after the probe turn.

def swap_helper(plan):
    """A command the broken-enforcement fake runs first: it makes the pinned helper print a forged EROFS for
    every path outside the worktree, without writing."""
    helper = plan["helper"]["path"]
    forged_helper = ("import json,sys\\nprint(json.dumps({'ok': False, 'path': sys.argv[1], 'nonce': sys.argv[2], "
                     "'errno': 30}))\\nsys.exit(1)\\n")
    code = "import os; os.chmod(%r, 0o644); open(%r, 'w').write(%r)" % (helper, helper, forged_helper)
    return {"command": "%s -c %s" % (shlex_quote(sys.executable), shlex_quote(code)), "target": None}


def shlex_quote(value):
    import shlex
    return shlex.quote(value)


def test_a_helper_rewritten_during_the_probe_turn_makes_every_shell_verdict_inconclusive(probe):
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns(first={"implementer": [swap_helper(plan)]},
                       modes={("implementer", target): "unsandboxed" for target in ("outside", "gitdir", "codex_home")})
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert row["helper_changed"]["before"]["sha256"] == plan["helper"]["sha256"]
    assert row["helper_changed"]["after"]["sha256"] != plan["helper"]["sha256"]
    assert {verdict[0] for verdict in verdicts(report, "implementer").values()} == {"INCONCLUSIVE"}
    assert "implementer probe turn: the probe helper changed during the turn" in report["summary"]["failures"]
    assert report["summary"]["passed"] is False


def test_the_plan_refuses_a_helper_inside_a_roles_writable_roots(probe, monkeypatch):
    # A plan request cannot widen a role's roots, so the plan runs in process with roots that reach the helper,
    # under the same fake-only PATH and temporary HOME as the subprocess runs.
    for key, value in probe.env().items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(native_probe, "profile_roots", lambda profile: [profile["cwd"], str(probe.root)])
    request = {"source": str(probe.source), "probe_root": str(probe.root), "roles": ["implementer"],
               "channels": ["shell"], "approvals_reviewer": "user"}
    with pytest.raises(ValueError, match="the probe helper must be outside every role's writable roots"):
        native_probe.plan(request)
    assert not probe.root.exists() and probe.worktrees() == [str(probe.source)]


# #3: a refusal and a success for one attempt.

def test_a_refusal_then_a_successful_retry_is_a_contradiction(tmp_path):
    attempt = shell_attempt(tmp_path)
    command = ["/bin/sh", "-c", attempt["command"]]
    events = [shell_event(command, helper_json(attempt, 30)), shell_event(command, helper_json(attempt, 0, ok=True), 0)]
    found = native_probe.judge(attempt, events, [], True, "/", native_probe.host_shells([]))
    assert (found["verdict"], found["assessment"]) == ("INCONCLUSIVE", "UNEXPECTED")
    assert found["evidence"]["contradiction"] == "the rollout reports a write but the nonce file is absent"


def test_a_retry_that_writes_and_a_delete_fail_the_run_end_to_end(probe):
    probe.plan([{"role": "implementer"}])
    outside = next(row for row in probe.role("implementer")["attempts"] if row["target"] == "outside")
    retry = {"command": outside["command"], "target": outside["path"], "mode": "unsandboxed"}
    delete = {"command": "%s -c %s" % (sys.executable, shlex_quote("import os; os.unlink(%r)" % outside["path"])),
              "target": None}
    probe.script_turns(extra={"implementer": [retry, delete]})
    report = probe.run(expect=3, cap=4)
    assert verdicts(report, "implementer")[("shell", "outside")] == ("INCONCLUSIVE", "REFUSED", "UNEXPECTED")
    assert report["summary"]["unexpected"] == ["implementer shell outside"]


# #4: the patch refusal text.

def patch_attempt(tmp_path, root_name="probe"):
    root = tmp_path / root_name
    (root / "outside").mkdir(parents=True)
    nonce = "abcd1234abcd1234"
    path = root / "outside" / ("aegis-probe-" + nonce)
    return {"id": "implementer-apply_patch-outside", "target": "outside", "channel": "apply_patch", "path": str(path),
            "nonce": nonce, "expected": "REFUSED", "line": "aegis-native-probe " + nonce}, root


def patch_event(paths, stderr, success=False):
    return {"turn_id": "t", "call_id": "c", "success": success, "paths": list(paths), "stdout": "", "stderr": stderr,
            "source": "patch_apply_end", "path": "r", "line": 2, "sha256": "0" * 64}


@pytest.mark.parametrize("stderr,expected", [
    ("Failed to find expected lines in {path}", ("INCONCLUSIVE", "INCONCLUSIVE")),
    ("EACCES", ("INCONCLUSIVE", "INCONCLUSIVE")),
    ("OSError: [Errno 2] No such file or directory: '{path}'", ("INCONCLUSIVE", "INCONCLUSIVE")),
    ("OSError: [Errno 13] Permission denied: '{path}'", ("REFUSED", "as_expected")),
    ("patch rejected: writing outside of the project; rejected by user approval settings", ("REFUSED", "as_expected")),
])
def test_a_marker_inside_the_probe_root_name_is_not_a_patch_refusal(tmp_path, stderr, expected):
    attempt, root = patch_attempt(tmp_path, "EACCES-Permission denied-probe")
    event = patch_event([attempt["path"]], stderr.format(path=attempt["path"]))
    assert judged(attempt, patches=[event], probe_root=str(root)) == expected


def test_a_patch_over_several_paths_is_never_a_refusal(tmp_path):
    attempt, root = patch_attempt(tmp_path)
    config = str(root / "codex-home" / "config.toml")
    # V3: the other path holds this attempt's path as a substring, so its rejection once read as this one's.
    nested = str(root / "codex-home") + attempt["path"]
    for other in (config, nested, attempt["path"]):
        event = patch_event([attempt["path"], other], "patch rejected: Read-only file system: '%s'" % other)
        if other == attempt["path"]:
            # The same path twice is one path.
            assert judged(attempt, patches=[event], probe_root=str(root)) == ("REFUSED", "as_expected")
            continue
        assert judged(attempt, patches=[event], probe_root=str(root)) == ("INCONCLUSIVE", "INCONCLUSIVE"), other
        found = native_probe.judge(attempt, [], [event], True, "/", probe_root=str(root))
        assert found["evidence"]["note"] == "a matching patch named several paths; the prompt asks one path per patch"


def test_a_context_failure_under_a_probe_root_named_with_a_marker_fails_the_run(probe):
    probe.root = probe.tmp / "EACCES-probe"
    probe.plan([{"role": "implementer"}], channels=["apply_patch"])
    probe.script_turns(patches=True, patch_modes={("implementer", "outside"): "mismatch"})
    report = probe.run(expect=3, cap=4)
    assert verdicts(report, "implementer")[("apply_patch", "outside")] == ("INCONCLUSIVE", "REFUSED", "INCONCLUSIVE")


# #5: the ~/.codex digest.

@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_unreadable_file_that_grows_changes_the_digest(tmp_path):
    folder = tmp_path / "codex"
    folder.mkdir()
    secret = folder / "auth.json"
    secret.write_text("{}")
    secret.chmod(0)
    try:
        errors = []
        before = native_probe.tree_digest(folder, errors)
        secret.chmod(0o200)
        with open(secret, "a") as stream:
            stream.write("x" * 1800)
        secret.chmod(0)
        after = native_probe.tree_digest(folder, [])
    finally:
        secret.chmod(0o600)
    assert errors and errors[0]["path"] == "auth.json"
    assert before != after


def test_a_read_error_is_part_of_the_digest(tmp_path, monkeypatch):
    folder = tmp_path / "codex"
    folder.mkdir()
    (folder / "state").write_text("x")
    real_open = open

    def failing(number):
        def opener(path, *words, **options):
            if str(path).endswith("/state"):
                raise OSError(number, os.strerror(number))
            return real_open(path, *words, **options)
        return opener
    monkeypatch.setattr("builtins.open", failing(13))
    eacces = native_probe.tree_digest(folder, [])
    monkeypatch.setattr("builtins.open", failing(5))
    eio = native_probe.tree_digest(folder, [])
    assert eacces != eio


# #6: expected values against the run-time profile.

def test_a_run_time_profile_that_differs_from_the_plan_refuses_the_role(probe):
    probe.plan([{"role": "implementer"}])
    stored = json.loads((probe.root / "probe.json").read_text())
    stored["roles"][0]["attempts"][1]["expected"] = "ALLOWED"
    (probe.root / "probe.json").write_text(json.dumps(stored))
    probe.script_turns()
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert row["profile_differences"] == ["implementer-shell-outside expected ALLOWED, now REFUSED"]
    assert row["steps"]["probe"] == {"state": "skipped", "reason": "the run-time profile differs from the plan"}
    assert ("implementer: the run-time profile differs from the plan: implementer-shell-outside expected ALLOWED, "
            "now REFUSED") in report["summary"]["failures"]
    assert report["cleanup"]["leftover_processes"] == [] and census(row["session"]) == []


# #7/#14: the served tier of a resumed turn after a stopped one.

@pytest.mark.parametrize("hold", [{}, {"abort_on_stop": True}])
def test_a_wake_that_writes_its_settings_before_its_start_keeps_its_served_tier(probe, hold):
    probe.plan([{"role": "router"}])
    probe.script_turns(hold=hold, wake={"settings_first": True, "served_tier": "default"})
    report = probe.run(expect=3, cap=4)
    wake = role_report(report, "router")["settings"]["wake"]
    assert (wake["requested_tier"], wake["served_tier"]) == ("ultrafast", "default")
    assert wake["state"] == "PROFILE_HOLD"
    assert wake["reasons"] == ["served tier mismatch: requested ultrafast, served default"]


def test_a_wake_served_its_requested_tier_before_its_start_is_a_match(probe):
    probe.plan([{"role": "router"}])
    probe.script_turns(wake={"settings_first": True})
    report = probe.run(cap=4)
    wake = role_report(report, "router")["settings"]["wake"]
    assert (wake["served_tier"], wake["served_tier_source"], wake["state"]) == (
        "ultrafast", "thread_settings_applied", "PROFILE_MATCH")


# #8: apply_patch as a response_item tool call pair.

def test_patches_recorded_as_tool_call_pairs_are_judged_and_marked_unconfirmed(probe):
    probe.plan([{"role": "implementer"}], channels=["apply_patch"])
    probe.script_turns(patches=True, patch_shape="response_item")
    report = probe.run(cap=4)
    found = verdicts(report, "implementer")
    assert found[("apply_patch", "worktree")] == ("ALLOWED", "ALLOWED", "as_expected")
    for target in ("outside", "gitdir", "codex_home"):
        assert found[("apply_patch", target)] == ("REFUSED", "REFUSED", "as_expected")
    refused = next(row for row in role_report(report, "implementer")["attempts"] if row["target"] == "outside")
    assert refused["evidence"]["event"]["source"] == "custom_tool_call"
    assert refused["evidence"]["shape"] == "unconfirmed against a real host"
    assert refused["evidence"]["output"].startswith("patch rejected: writing outside of the project")
    assert report["shapes"] == {"apply_patch response_item": "unconfirmed against a real host"}


def test_a_declined_patch_is_not_attempted(tmp_path):
    attempt, root = patch_attempt(tmp_path)
    event = {**patch_event([attempt["path"]], "patch rejected: declined"), "declined": True}
    assert judged(attempt, patches=[event], probe_root=str(root)) == ("NOT_ATTEMPTED", "INCONCLUSIVE")


# #9/#12/#13: reader errors stay inside one role.

def test_a_cut_record_fails_only_its_role_and_the_next_role_still_runs(probe):
    probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}])
    probe.script_turns()
    script = json.loads(probe.script.read_text())
    # The implementer's hold turn is cut mid-record; the wake then appends after the cut line.
    hold = next(turn for turn in script["turns"] if turn["match"] == probe.role("implementer")["hold_marker"])
    hold["partial_record"] = True
    probe.script.write_text(json.dumps(script))
    report = probe.run(expect=3, cap=8)
    first, second = role_report(report, "implementer"), role_report(report, "reviewer")
    assert first["steps"]["hold"]["state"] == "stopped" and first["steps"]["hold"]["turn_context"] is True
    assert first["reader_error"]["error"].startswith("malformed rollout JSON at line ")
    assert any(failure.startswith("implementer: rollout reader error: malformed rollout JSON at line ")
               for failure in report["summary"]["failures"])
    assert second["recovery"]["recovered"] is True and second["steps"]["wake"]["resume"]["state"] == "resumed"
    assert report["state"] == "completed" and census(first["session"]) == []


def test_an_unterminated_final_record_is_left_out_of_a_live_read(tmp_path):
    rollout = tmp_path / "rollout.jsonl"
    rollout.write_text(json.dumps({"type": "event_msg", "payload": {"type": "task_started", "turn_id": "t1"}}) + "\n"
                       + '{"type": "turn_con')
    assert native_probe.turns(str(rollout)) == [{"turn_id": "t1", "context": False, "completed": False}]


# #11: a source that is itself a linked worktree.

def test_a_source_that_is_a_linked_worktree_runs_and_cleans_up(probe):
    main = probe.source
    probe.source = probe.tmp / "lane"
    git(main, "worktree", "add", "-q", "--detach", str(probe.source), "HEAD")
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns()
    report = probe.run(cap=4)
    assert report["summary"]["passed"] is True, report["summary"]
    assert report["cleanup"]["worktree_removed"] is True and not Path(plan["worktree"]).exists()
    assert plan["worktree"] not in probe.worktrees()


# A6: a target the probe user cannot write before the turn.

def test_a_read_only_codex_home_target_left_before_the_turn_is_inconclusive(probe):
    (probe.bin / "chmod").symlink_to(shutil.which("chmod"))
    probe.plan([{"role": "implementer"}])
    probe.script_turns(modes={("implementer", "codex_home"): "unsandboxed"})
    report = probe.run(expect=3, cap=4, FAKE_LOGIN_READONLY_CONFIG="1")
    row = next(row for row in role_report(report, "implementer")["attempts"] if row["target"] == "codex_home")
    assert (row["verdict"], row["assessment"]) == ("INCONCLUSIVE", "INCONCLUSIVE")
    assert row["evidence"]["note"].startswith("the target was not writable by the probe user before the turn")


# Surviving mutants M31, M33, M37, M42.

def test_a_hold_stopped_before_its_context_is_a_failure(probe):
    probe.plan([{"role": "implementer"}], timeouts={"start_timeout_seconds": 30, "turn_timeout_seconds": 30,
                                                    "hold_wait_seconds": 1, "stop_grace_seconds": 2})
    probe.script_turns(hold={"context_delay": 4})
    report = probe.run(expect=3, cap=4)
    hold = role_report(report, "implementer")["steps"]["hold"]
    assert hold["state"] == "stopped" and hold["turn_context"] is False
    assert "implementer hold: stopped before the long turn recorded its context" in report["summary"]["failures"]


def test_the_stand_in_passwd_home_is_honoured_only_for_the_fake(monkeypatch, tmp_path):
    import pwd
    monkeypatch.setenv("AEGIS_PROBE_FAKE_PASSWD_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    passwd = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".codex"
    # Paths only: nothing here opens either folder.
    assert passwd in native_probe.home_codexes(fake=False)
    assert tmp_path / ".codex" not in native_probe.home_codexes(fake=False)
    assert tmp_path / ".codex" in native_probe.home_codexes(fake=True)


def test_a_helper_success_line_with_a_failing_exit_is_no_write(tmp_path):
    attempt = shell_attempt(tmp_path)
    event = shell_event(["/bin/sh", "-c", attempt["command"]], helper_json(attempt, 0, ok=True), 1)
    found = native_probe.judge(attempt, [event], [], True, "/", native_probe.host_shells([]))
    assert (found["verdict"], found["assessment"]) == ("INCONCLUSIVE", "INCONCLUSIVE")
    assert "contradiction" not in found["evidence"]


def test_a_wake_that_starts_no_turn_is_not_checked_against_the_stopped_turn(probe):
    probe.plan([{"role": "implementer"}])
    # A command with an unknown mode makes the fake exit before the wake records a task_started.
    probe.script_turns(wake={"commands": [{"command": "true", "target": None, "mode": "bogus"}]})
    report = probe.run(expect=3, cap=4)
    wake = role_report(report, "implementer")["settings"]["wake"]
    assert wake == {"state": "UNAVAILABLE", "turn_id": None,
                    "reasons": ["the turn under check is not the rollout's latest started turn"]}


# ---------------------------------------------------------------- review fixes (item 7, third round)

import hierarchy_launcher  # noqa: E402
import hierarchy_native  # noqa: E402
import signal  # noqa: E402
import time  # noqa: E402


# V1: a read-only shell the model wrote outside every root the plan forbids.

def test_a_read_only_shell_the_model_wrote_outside_every_root_is_never_a_refusal(tmp_path):
    attempt = shell_attempt(tmp_path)
    stub = tmp_path / "var-tmp" / "bash"
    stub.parent.mkdir()
    stub.write_text("#!/bin/sh\nexit 1\n")
    stub.chmod(0o555)
    shells = native_probe.host_shells([str(tmp_path / "worktree")])
    assert judged(attempt, [shell_event([str(stub), "-lc", attempt["command"]], forged(attempt))],
                  shells=shells) == ("INCONCLUSIVE", "INCONCLUSIVE")
    # The plan's own shell, by absolute path or by the name it resolved, still counts.
    real = os.path.realpath(SH)
    for argv0 in (real, SH, "sh"):
        assert judged(attempt, [shell_event([argv0, "-c", attempt["command"]], forged(attempt))],
                      shells={"lookup": {"sh": real}, "forbidden": []}) == ("REFUSED", "as_expected"), argv0


# V2: a context failure repeats the model's own lines; only whole refusal lines before it count.

@pytest.mark.parametrize("stderr", [
    "Failed to find expected lines in {path}:\nPermission denied",
    "Failed to find expected lines in {path}:\npatch rejected: Read-only file system: '{path}'",
    "Failed to find context 'x' in {path}\nOSError: [Errno 13] Permission denied: '{path}'",
    "Invalid patch: Permission denied",
    "the word Permission denied inside other text",
    "error: Read-only file system, said the model",
])
@pytest.mark.parametrize("shape", ["stderr", "response_item"])
def test_patch_text_after_a_context_failure_or_inside_a_line_is_never_a_refusal(tmp_path, stderr, shape):
    attempt, root = patch_attempt(tmp_path)
    event = patch_event([attempt["path"]], stderr.format(path=attempt["path"]))
    if shape == "response_item":
        event.update(source="custom_tool_call", stdout=None, shape=hierarchy_native.UNCONFIRMED_SHAPE)
    assert judged(attempt, patches=[event], probe_root=str(root)) == ("INCONCLUSIVE", "INCONCLUSIVE")


def test_a_whole_refusal_line_before_a_context_failure_still_counts(tmp_path):
    attempt, root = patch_attempt(tmp_path)
    event = patch_event([attempt["path"]], "OSError: [Errno 30] Read-only file system: '%s'\nFailed to find expected "
                                           "lines in %s:\nx" % (attempt["path"], attempt["path"]))
    assert judged(attempt, patches=[event], probe_root=str(root)) == ("REFUSED", "as_expected")


# The folders above the helper and the targets.

def test_a_folder_renamed_away_and_back_is_seen_but_a_new_entry_in_a_shared_folder_is_not(tmp_path):
    base = tmp_path / "anc"
    root = base / "probe"
    helper = root / "helper" / "native-probe-attempt.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("genuine\n")
    helper.chmod(0o444)
    chain = native_probe.folder_chain([str(helper)])
    assert str(root) in chain and str(base) in chain and "/" in chain
    strict = {str(root), str(helper.parent)}
    before, pinned = native_probe.folders_state(chain), native_probe.helper_state(str(helper))
    (base / "unrelated").write_text("x")
    assert native_probe.folders_changed(before, native_probe.folders_state(chain), strict) == []
    # The swap from the review: a forged helper at the planned path during the turn, the original back after.
    os.rename(root, base / "probe.orig")
    (root / "helper").mkdir(parents=True)
    helper.write_text("forged\n")
    assert native_probe.sha256_file(str(helper)) != pinned["sha256"]
    shutil.rmtree(root)
    os.rename(base / "probe.orig", root)
    assert native_probe.helper_state(str(helper)) == pinned
    assert native_probe.folders_changed(before, native_probe.folders_state(chain), strict) == [str(root)]
    # The same above the probe root, where entries may come and go.
    before = native_probe.folders_state(chain)
    os.rename(base, tmp_path / "anc.orig")
    os.rename(tmp_path / "anc.orig", base)
    assert native_probe.folders_changed(before, native_probe.folders_state(chain), strict) == [str(base)]


def test_a_folder_above_the_probe_root_swapped_during_the_turn_makes_every_verdict_inconclusive(probe):
    (probe.tmp / "deep").mkdir()
    probe.root = probe.tmp / "deep" / "probe"
    plan = probe.plan([{"role": "implementer"}])
    deep, orig = str(probe.tmp / "deep"), str(probe.tmp / "deep.orig")
    forged_helper = ("import json,sys\nprint(json.dumps({'ok': False, 'path': sys.argv[1], 'nonce': sys.argv[2], "
                     "'errno': 30}))\nsys.exit(1)\n")
    # Under broken enforcement the turn moves the folder above the probe root away, builds a copy of the root
    # with a forged helper (everything else linked back), runs the planned commands, then puts the original back.
    swap = ("import os\ndeep, orig, helper, forged = %r, %r, %r, %r\nos.rename(deep, orig)\n"
            "root = os.path.join(deep, 'probe')\nos.makedirs(os.path.join(root, 'helper'))\n"
            "for name in os.listdir(os.path.join(orig, 'probe')):\n"
            "    if name != 'helper':\n"
            "        os.symlink(os.path.join(orig, 'probe', name), os.path.join(root, name))\n"
            "open(helper, 'w').write(forged)\n") % (deep, orig, plan["helper"]["path"], forged_helper)
    restore = "import os, shutil; shutil.rmtree(%r); os.rename(%r, %r)" % (deep, orig, deep)
    probe.script_turns(first={"implementer": [{"command": "%s -c %s" % (sys.executable, shlex_quote(swap)),
                                               "target": None}]},
                       extra={"implementer": [{"command": "%s -c %s" % (sys.executable, shlex_quote(restore)),
                                               "target": None}]},
                       modes={("implementer", target): "unsandboxed" for target in ("outside", "gitdir", "codex_home")})
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert "helper_changed" not in row and deep in row["folders_changed"]
    assert {verdict[0] for verdict in verdicts(report, "implementer").values()} == {"INCONCLUSIVE"}
    assert any(failure.startswith("implementer probe turn: a folder above the helper or a target was swapped")
               for failure in report["summary"]["failures"])


def test_an_untouched_probe_turn_changes_no_folder(probe):
    probe.plan([{"role": "implementer"}], channels=["shell", "apply_patch"])
    probe.script_turns(patches=True)
    report = probe.run(cap=4)
    assert report["summary"]["passed"] is True, report["summary"]
    assert "folders_changed" not in role_report(report, "implementer")


# Reader errors of any kind stay inside one role.

def deep_rollout(tmp_path, cid):
    records = [{"type": "session_meta", "payload": {"id": cid, "cwd": "/x"}},
               {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "t1"}},
               {"type": "response_item", "payload": {"type": "function_call", "name": "apply_patch", "call_id": "c1",
                                                     "arguments": "[" * 100000 + "]" * 100000}},
               {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1",
                                                     "output": "[" * 100000 + "]" * 100000}}]
    path = tmp_path / "rollout.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    return str(path)


def test_a_patch_call_nested_too_deep_to_parse_is_read_as_text(tmp_path):
    cid = "019a0000-0000-7000-8000-000000000001"
    path = deep_rollout(tmp_path, cid)
    commands, patches = native_probe.probe_events(path, cid, "t1")
    assert commands == [] and [(patch["paths"], patch["success"]) for patch in patches] == [([], False)]
    nested = tmp_path / "nested.jsonl"
    nested.write_text(json.dumps({"type": "session_meta", "payload": {"id": cid}}) + "\n" + "[" * 100000 + "]" * 100000
                      + "\n")
    with pytest.raises(ValueError, match="malformed rollout JSON at line 2"):
        native_probe.probe_events(str(nested), cid, "t1")


@pytest.mark.parametrize("error", [RecursionError("maximum recursion depth exceeded"), TypeError("bad type"),
                                   KeyError("missing")])
def test_a_reader_error_of_any_kind_fails_only_its_role(tmp_path, monkeypatch, error):
    def failing(self, planned, row):
        raise error
    monkeypatch.setattr(native_probe.Runner, "role_steps", failing)
    runner = native_probe.Runner({"probe_root": str(tmp_path)}, 4, "KEY", "codex", True)
    planned = {"role": "implementer", "endpoint": "e/lane/probe", "initiative": "e", "sandbox": "workspace-write",
               "shell": True, "base": str(tmp_path), "attempts": [shell_attempt(tmp_path)]}
    row = runner.role(planned)
    assert row["reader_error"]["error"].startswith(type(error).__name__ + ": ")
    assert [(attempt["verdict"], attempt["assessment"]) for attempt in row["attempts"]] == [
        ("INCONCLUSIVE", "INCONCLUSIVE")]
    assert runner.failures == ["implementer: rollout reader error: " + row["reader_error"]["error"]]


def test_a_patch_call_nested_too_deep_to_parse_fails_only_its_attempts_and_the_run_goes_on(probe):
    probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}],
               channels=["shell", "apply_patch"])
    probe.script_turns(patches=True, patch_shape="deep_arguments")
    report = probe.run(expect=3, cap=8)
    assert report["state"] == "completed" and [row["role"] for row in report["roles"]] == ["implementer", "reviewer"]
    for name in ("implementer", "reviewer"):
        row = role_report(report, name)
        assert "reader_error" not in row and row["recovery"]["recovered"] is True
        # No path can be read from the call, so no patch record matches an attempt and none is a refusal.
        patches = [attempt for attempt in row["attempts"] if attempt["channel"] == "apply_patch"]
        assert len(patches) == 4 and all(attempt["evidence"]["events"] == 0 for attempt in patches)
        assert "REFUSED" not in {attempt["verdict"] for attempt in patches}


# Signals and stops (mutants R1, R2, R3, R6, R7).

def launch_records(probe, role):
    planned = probe.role(role)
    folder = Path(planned["base"]) / "launches" / hierarchy_launcher.quoted(planned["endpoint"])
    return [json.loads(path.read_text()) for path in sorted(folder.glob("*.json"))]


def clean_after(probe, plan):
    assert not (probe.codex_home / "auth.json").exists() and not (probe.root / ".run.lock").exists()
    assert probe.worktrees() == [str(probe.source)] and not Path(plan["worktree"]).exists()
    assert live_sessions(probe) == []


def strays(probe):
    rows = subprocess.run([PS, "-ax", "-ww", "-o", "pid=,stat=,args="], capture_output=True, text=True,
                          timeout=10).stdout
    return [line for line in rows.splitlines() if str(probe.tmp) in line and not line.split()[1].startswith("Z")]


def test_a_signal_during_the_probe_turn_stops_it_before_the_cleanup(probe):
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns(probe={"context_delay": 20})
    process = start_run(probe)
    try:
        assert wait_for(lambda: any(probe.role("implementer")["probe_marker"] in json.dumps(call["argv"])
                                    for call in probe.calls()))
        assert wait_for(lambda: bool(live_sessions(probe)))
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=90)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    report = json.loads((probe.root / "report.json").read_text())
    assert report["state"] == "interrupted", report["summary"]
    # The run stopped its own turn; the cleanup found nothing of the role's session still running.
    assert report["cleanup"]["found_running"] == [] and report["cleanup"]["leftover_processes"] == []
    clean_after(probe, plan)


def test_a_signal_while_the_launcher_start_runs_leaves_no_codex_and_keeps_the_record(probe):
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns()
    script = json.loads(probe.script.read_text())
    # The start turn matches no marker; it waits before its context, so the signal lands inside the launcher.
    script["turns"].append({"match": "", "context_delay": 6})
    probe.script.write_text(json.dumps(script))
    process = start_run(probe)
    try:
        assert wait_for(lambda: bool(probe.calls()))
        time.sleep(1.0)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=90)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert not any(probe.role("implementer")["probe_marker"] in json.dumps(call["argv"]) for call in probe.calls())
    report = json.loads((probe.root / "report.json").read_text())
    assert report["state"] == "interrupted", report["summary"]
    # The launcher got SIGTERM, not a kill: it stopped the start's codex and recorded the start.
    starts = [record for record in launch_records(probe, "implementer") if record["action"] == "start"]
    assert starts and starts[-1]["state"] != "bound"
    time.sleep(1)
    assert strays(probe) == []
    clean_after(probe, plan)


def test_a_signal_during_the_preflight_stops_the_run_before_anything_starts(probe):
    plan = probe.plan([{"role": "implementer"}])
    probe.script_turns()
    mark = probe.tmp / "preflight-git"
    (probe.bin / "git").unlink()
    # A git that holds the preflight's worktree check for a moment, so the signal lands inside the preflight.
    (probe.bin / "git").write_text(
        "#!%s\nimport os, sys, time\nargs = sys.argv[1:]\n"
        "if '--git-common-dir' in args and '--absolute-git-dir' in args and not os.path.exists(%r):\n"
        "    open(%r, 'w').close()\n    time.sleep(3)\nos.execv(%r, [%r] + args)\n"
        % (sys.executable, str(mark), str(mark), GIT, GIT))
    (probe.bin / "git").chmod(0o755)
    process = start_run(probe)
    try:
        assert wait_for(mark.exists)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=90)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    assert process.returncode == 3, (stdout[-2000:], stderr[-2000:])
    report = json.loads((probe.root / "report.json").read_text())
    assert report["state"] == "interrupted" and "interrupted by signal 15" in report["summary"]["failures"]
    assert report["login"] is None and report["roles"] == [] and report["turns_used"] == 0
    assert probe.calls() == [] and not probe.login_log.exists()
    clean_after(probe, plan)


def test_a_reader_error_during_the_hold_still_stops_the_live_turn_through_the_launcher(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(hold={"malformed_record": True, "context_delay": 20})
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert row["reader_error"]["error"].startswith("malformed rollout JSON at line ")
    stops = [record for record in launch_records(probe, "implementer") if record["action"] == "stop"]
    assert any(record["state"] == "stopped" and record["pids"] for record in stops), stops
    assert census(row["session"]) == []


def test_a_reader_error_after_the_probe_turn_asks_the_launcher_to_stop_the_session(probe):
    probe.plan([{"role": "implementer"}])
    probe.script_turns(probe={"malformed_record": True})
    report = probe.run(expect=3, cap=4)
    row = role_report(report, "implementer")
    assert row["reader_error"]["error"].startswith("malformed rollout JSON at line ")
    assert row["steps"]["hold"] == {"state": "skipped", "reason": "rollout reader error"}
    assert [record["action"] for record in launch_records(probe, "implementer")][-1] == "stop"
    assert census(row["session"]) == []


# Only the stand-in passwd home under the fake.

def test_under_the_fake_with_a_stand_in_the_real_passwd_home_is_never_resolved(monkeypatch, tmp_path):
    import pwd
    monkeypatch.setenv("AEGIS_PROBE_FAKE_PASSWD_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    real = str(Path(pwd.getpwuid(os.getuid()).pw_dir) / ".codex")
    seen, resolve = [], os.path.realpath
    monkeypatch.setattr(native_probe.os.path, "realpath", lambda path, **options: seen.append(str(path)) or resolve(
        path, **options))
    homes = native_probe.guarded_homes(True)
    assert homes == [tmp_path / "home" / ".codex", tmp_path / ".codex"]
    assert not any(path.startswith(real) for path in seen)
