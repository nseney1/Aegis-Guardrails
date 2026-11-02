"""ROOT handoff tooling through its public CLI: first-prompt check, launch, lane health.

No test starts a real claude or Codex session: launch and lanes-health read a stub
``claude`` placed first on PATH that serves recorded fixtures.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_root.py"
SESSION = "5daa90d5-59c3-4bc9-ac88-2bd3454167e8"
LAUNCHER_TEXT = ("import hashlib, json, os, subprocess\n" + "x = 1\n" * 400)[:2308]


def run_tool(*args, stdin=b"", env=None, timeout=60):
    proc = subprocess.run([sys.executable, "-B", "-I", str(TOOL), *[str(a) for a in args]], input=stdin,
                          capture_output=True, timeout=timeout, env=env if env is not None else dict(os.environ))
    out = proc.stdout.decode("utf-8")
    return proc.returncode, (json.loads(out) if out.strip() else None), proc.stderr.decode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_transcript(path, records, torn_tail=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(record) + "\n" for record in records)
    if torn_tail is not None:
        body += torn_tail
    path.write_text(body, encoding="utf-8")
    return path


def user_record(content, uuid="u-1", ts="2026-11-02T16:00:01.000Z"):
    return {"type": "user", "uuid": uuid, "timestamp": ts, "sessionId": SESSION,
            "message": {"role": "user", "content": content}}


def header_records():
    return [{"type": "custom-title", "customTitle": "lane", "sessionId": SESSION},
            {"type": "permission-mode", "permissionMode": "auto", "sessionId": SESSION}]


@pytest.fixture
def prompt_file(tmp_path):
    path = tmp_path / "prompt.txt"
    path.write_text("You are a lane.\nDo the brief.\n", encoding="utf-8")
    return path


# --- item 1: first-prompt-check (F-A) --------------------------------------------------------


@pytest.mark.parametrize("shape", ["string", "text_blocks"])
def test_first_prompt_check_accepts_an_exact_first_prompt(tmp_path, prompt_file, shape):
    text = prompt_file.read_text(encoding="utf-8")
    content = text if shape == "string" else [{"type": "text", "text": text}]
    transcript = write_transcript(tmp_path / "t.jsonl", header_records() + [user_record(content)])
    code, out, err = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                              "--prompt-sha256", sha(prompt_file.read_bytes()))
    assert code == 0, (out, err)
    assert out["ok"] is True and out["prompt_sha256_ok"] is True
    assert out["equals_recorded"] is True and out["extra_chars"] == 0 and out["extra_head"] == ""
    assert out["torn_tail"] is False
    assert out["first_user_record"]["line"] == 3 and out["first_user_record"]["uuid"] == "u-1"


def test_first_prompt_check_reports_appended_launcher_text(tmp_path, prompt_file):
    text = prompt_file.read_text(encoding="utf-8")
    transcript = write_transcript(tmp_path / "t.jsonl", [user_record(text + LAUNCHER_TEXT)])
    code, out, _ = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                            "--prompt-sha256", sha(prompt_file.read_bytes()))
    assert code == 2
    assert out["ok"] is False and out["prompt_sha256_ok"] is True
    assert out["equals_recorded"] is False
    assert out["extra_chars"] == 2308
    assert out["extra_head"] == LAUNCHER_TEXT[:120]


def test_first_prompt_check_refuses_a_prompt_that_does_not_rehash(tmp_path, prompt_file):
    text = prompt_file.read_text(encoding="utf-8")
    transcript = write_transcript(tmp_path / "t.jsonl", [user_record(text)])
    code, out, _ = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                            "--prompt-sha256", "0" * 64)
    assert code == 2
    assert out["ok"] is False and out["prompt_sha256_ok"] is False
    assert out["prompt_sha256"] == sha(prompt_file.read_bytes())


def test_first_prompt_check_tolerates_a_torn_last_line(tmp_path, prompt_file):
    text = prompt_file.read_text(encoding="utf-8")
    transcript = write_transcript(tmp_path / "t.jsonl", [user_record(text)], torn_tail='{"type": "assist')
    code, out, err = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                              "--prompt-sha256", sha(prompt_file.read_bytes()))
    assert code == 0, (out, err)
    assert out["torn_tail"] is True and out["equals_recorded"] is True


def test_first_prompt_check_fails_on_a_torn_middle_line(tmp_path, prompt_file):
    text = prompt_file.read_text(encoding="utf-8")
    path = tmp_path / "t.jsonl"
    path.write_text('{"type": "custom-tit\n' + json.dumps(user_record(text)) + "\n", encoding="utf-8")
    code, out, _ = run_tool("first-prompt-check", "--transcript", path, "--prompt", prompt_file,
                            "--prompt-sha256", sha(prompt_file.read_bytes()))
    assert code == 2
    assert "line 1" in out["error"]


def test_first_prompt_check_fails_without_a_user_record(tmp_path, prompt_file):
    transcript = write_transcript(tmp_path / "t.jsonl", header_records())
    code, out, _ = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                            "--prompt-sha256", sha(prompt_file.read_bytes()))
    assert code == 2
    assert out["ok"] is False and out["first_user_record"] is None


# --- stub claude ------------------------------------------------------------------------------

STUB = r'''
import json, os, pathlib, sys
d = pathlib.Path(os.environ["HIERARCHY_STUB_DIR"])
argv = sys.argv[1:]
with (d / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps(argv[:2]) + "\n")
if argv[:2] == ["agents", "--json"]:
    after = d / "agents-after.json"
    source = after if (d / "launched").exists() and after.exists() else d / "agents.json"
    sys.stdout.write(source.read_text() if source.exists() else "[]")
    sys.exit(0)
if argv[:1] == ["logs"]:
    (d / "logs-args.json").write_text(json.dumps(argv))
    logs = d / "logs.txt"
    sys.stdout.write(logs.read_text() if logs.exists() else "")
    sys.exit(0)
if argv[:1] == ["--bg"]:
    stdin = sys.stdin.buffer.read()
    (d / "stdin.bin").write_bytes(stdin)
    (d / "argv.json").write_text(json.dumps(argv))
    (d / "env.json").write_text(json.dumps(sorted(k for k in os.environ if k.startswith("CLAUDE"))))
    (d / "cwd.txt").write_text(os.getcwd())
    cfg = json.loads((d / "launch.json").read_text())
    name = argv[argv.index("-n") + 1]
    records = [{"type": "custom-title", "customTitle": name, "sessionId": cfg["session"]},
               {"type": "user", "uuid": "first", "timestamp": "2026-11-02T16:00:01.000Z", "sessionId": cfg["session"],
                "message": {"role": "user", "content": argv[-1] + stdin.decode()}}]
    if cfg["assistant"]:
        records.append({"type": "assistant", "uuid": "a-1", "timestamp": "2026-11-02T16:00:03.000Z",
                        "sessionId": cfg["session"], "message": {"role": "assistant", "content": []}})
    folder = pathlib.Path(cfg["projects"]) / os.getcwd().replace("/", "-")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / (cfg["session"] + ".jsonl")).write_text("".join(json.dumps(r) + "\n" for r in records))
    (d / "launched").write_text("1")
    short = cfg["session"][:8]
    sys.stdout.write("backgrounded · %s · %s\n  claude agents             list sessions\n"
                     "  claude stop %s      stop this session\n" % (short, name, short))
    sys.exit(0)
sys.exit(9)
'''

DIALOG_SCREEN = ("\x1b[2m·\x1b[0m Entering worktree(/w/.claude/worktrees/lane)   │ permission-root relocation to "
                 "\"/w/.claude/worktrees/lane\" — a model-supplied worktree outside .claude/worktrees/ "
                 "\x1b[1mDo you want to proceed?\x1b[0m ❯ 1.  Yes 2.  No Esc to cancel")


class Stub:
    def __init__(self, tmp_path):
        self.dir = tmp_path / "stub"
        self.dir.mkdir()
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        claude = self.bin / "claude"
        claude.write_text("#!" + sys.executable + " -I\n" + STUB, encoding="utf-8")
        claude.chmod(0o755)
        self.projects = tmp_path / "projects"
        self.projects.mkdir()

    def env(self):
        return {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                "HIERARCHY_STUB_DIR": str(self.dir), "CLAUDE_CODE_SESSION_ID": "parent-session",
                "CLAUDE_PID": "1"}

    def serve(self, name, value):
        (self.dir / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")

    def launched(self):
        return (self.dir / "argv.json").exists()


@pytest.fixture
def stub(tmp_path):
    return Stub(tmp_path)


def agent_row(session, name, state="working", status="busy", **extra):
    return {"pid": 4242, "id": session[:8], "cwd": "/w", "kind": "background", "startedAt": 1793632625309,
            "sessionId": session, "name": name, "status": status, "state": state, **extra}


# --- item 2: launch (F-A, F1) ----------------------------------------------------------------

LANE = "aegis47-live lane x"


def launch_spec(tmp_path, prompt_file, **changes):
    workdir = tmp_path / "workspace"
    workdir.mkdir(exist_ok=True)
    spec = {"name": LANE, "model": "claude-opus-5-5", "effort": "xhigh", "cwd": str(workdir),
            "add_dirs": [str(tmp_path)], "uses_enter_worktree": False,
            "prompt": {"path": str(prompt_file), "sha256": sha(prompt_file.read_bytes())},
            "record_out": str(tmp_path / "launch-record.json"), **changes}
    path = tmp_path / "launch-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path, spec


def launch(stub, spec_path, *extra, stdin=b"import hashlib, json, os, subprocess  # launcher\n"):
    return run_tool("launch", "--spec", spec_path, "--projects-dir", stub.projects, "--poll-s", "0.05",
                    "--wait-s", "5", "--dialog-wait-s", "1", "--min-free-mb", "1", *extra,
                    stdin=stdin, env=stub.env())


def test_launch_records_an_exact_first_prompt_with_no_inherited_stdin(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file, uses_enter_worktree=True)
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True})
    stub.serve("agents-after.json", [agent_row(SESSION, LANE)])
    code, out, err = launch(stub, spec_path)
    assert code == 0, (out, err)
    assert (stub.dir / "stdin.bin").read_bytes() == b""
    assert [key for key in json.loads((stub.dir / "env.json").read_text()) if key.startswith("CLAUDE_")] == []
    assert (stub.dir / "cwd.txt").read_text() == spec["cwd"]
    prompt = prompt_file.read_text(encoding="utf-8")
    assert json.loads((stub.dir / "argv.json").read_text()) == [
        "--bg", "--agent", "claude", "--permission-mode", "auto", "--model", "claude-opus-5-5",
        "--effort", "xhigh", "--add-dir", str(tmp_path), "-n", LANE, prompt]
    record = json.loads(Path(spec["record_out"]).read_text(encoding="utf-8"))
    assert record == out["record"]
    assert record["id"] == SESSION[:8] and record["session"] == SESSION
    assert record["exit"] == 0 and record["stdout"].startswith("backgrounded · " + SESSION[:8])
    assert record["argv"][-1] == "<prompt>" and record["stdin"] == "DEVNULL"
    assert record["uses_enter_worktree"] is True
    assert record["first_prompt_check"]["ok"] is True and record["first_prompt_check"]["extra_chars"] == 0
    assert record["dialog"] is None


def test_launch_refuses_an_existing_record_path_before_launching(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    Path(spec["record_out"]).write_text("{}\n", encoding="utf-8")
    code, out, _ = launch(stub, spec_path)
    assert code == 3
    assert not stub.launched()
    assert Path(spec["record_out"]).read_text(encoding="utf-8") == "{}\n"


def test_launch_refuses_a_name_that_is_already_live(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    stub.serve("agents.json", [agent_row("1dd78e7e-8e0f-45da-8e3a-163c78577481", LANE, state="blocked", status="idle")])
    code, out, _ = launch(stub, spec_path)
    assert code == 3
    assert out["live_sessions"] == ["1dd78e7e-8e0f-45da-8e3a-163c78577481"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()


def test_launch_detects_a_pending_dialog_and_still_writes_the_record(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file, uses_enter_worktree=True)
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": False})
    stub.serve("agents-after.json", [agent_row(SESSION, LANE, state="blocked", status="waiting",
                                               waitingFor="permission prompt")])
    stub.serve("logs.txt", "x" * 9000 + DIALOG_SCREEN + "\n")
    code, out, err = launch(stub, spec_path)
    assert code == 5, (out, err)
    record = json.loads(Path(spec["record_out"]).read_text(encoding="utf-8"))
    dialog = record["dialog"]
    assert "Do you want to proceed?" in dialog["text"] and "permission-root relocation" in dialog["text"]
    assert "\x1b" not in dialog["text"] and len(dialog["text"].encode("utf-8")) <= 4096
    assert dialog["detected_at"].endswith("Z")
    assert record["agents_row"]["state"] == "blocked"
    assert record["first_prompt_check"]["ok"] is True
    assert json.loads((stub.dir / "logs-args.json").read_text()) == ["logs", SESSION[:8]]


def test_launch_plan_prints_the_writes_and_launches_nothing(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    code, out, _ = launch(stub, spec_path, "--plan")
    assert code == 0
    assert out["plan"] is True and out["writes"] == [spec["record_out"]]
    assert out["argv"][-1] == "<prompt>" and out["argv"][:2] == ["claude", "--bg"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()


def test_launch_refuses_a_prompt_that_does_not_rehash(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file, prompt={"path": str(prompt_file), "sha256": "f" * 64})
    code, out, _ = launch(stub, spec_path)
    assert code == 2
    assert not stub.launched() and not Path(spec["record_out"]).exists()


def test_launch_refuses_when_free_space_is_below_the_threshold(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    code, out, _ = run_tool("launch", "--spec", spec_path, "--projects-dir", stub.projects,
                            "--min-free-mb", str(10 ** 12), env=stub.env())
    assert code == 4
    assert "free" in out["error"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()
