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
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_root.py"
SESSION = "5daa90d5-59c3-4bc9-ac88-2bd3454167e8"
LAUNCHER_TEXT = ("import hashlib, json, os, subprocess\n" + "x = 1\n" * 400)[:2308]


def run_tool(*args, stdin=b"", env=None, timeout=60, cwd=None):
    proc = subprocess.run([sys.executable, "-B", "-I", str(TOOL), *[str(a) for a in args]], input=stdin,
                          capture_output=True, timeout=timeout, env=env if env is not None else dict(os.environ),
                          cwd=cwd)
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


# --- T92, T100: check-hashes ------------------------------------------------------------------

FABRICATED = "9f827392a61b2e8b8f0d8b8ec8a6a0a9c2a6b6c1e4e1f1d6bb3d8b5f8f3d2c1a"  # the C7 incident's typed value


@pytest.fixture
def named(tmp_path):
    path = tmp_path / "briefs" / "lane-brief.md"
    path.parent.mkdir()
    path.write_text("# Lane brief\n", encoding="utf-8")
    return path


def check_hashes(path, *extra, cwd=None):
    return run_tool("check-hashes", path, *extra, cwd=cwd)


def test_check_hashes_refuses_a_typed_hash_next_to_a_real_path_naming_the_line(tmp_path, named):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("You are a lane.\nYour brief is %s (sha256 %s).\n" % (named, FABRICATED), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 6, (out, err)
    assert out["ok"] is False and out["tokens"] == 1 and out["checked"] == []
    [miss] = out["unmatched"]
    assert miss["token"] == FABRICATED and miss["line"] == 2
    assert miss["candidates"] == [{"path": str(named), "line": 2, "sha256": sha(named.read_bytes())}]
    assert "line 2" in out["error"]


@pytest.mark.parametrize("layout", ["same_line", "line_above"])
def test_check_hashes_accepts_a_correct_hash_on_the_same_line_or_the_line_above(tmp_path, named, layout):
    real = sha(named.read_bytes())
    body = ("Brief: %s sha256 %s\n" % (named, real) if layout == "same_line"
            else "Brief:\n- path `%s`\n- sha256 `%s`\n" % (named, real))
    prompt = tmp_path / "prompt.txt"
    prompt.write_text(body, encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 0, (out, err)
    line = 1 if layout == "same_line" else 3
    assert out["ok"] is True and out["unmatched"] == []
    assert out["checked"] == [{"token": real, "line": line, "path": str(named),
                               "via": layout}]


def test_check_hashes_refuses_a_hash_whose_path_is_two_lines_up(tmp_path, named):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("%s\n\nsha256 %s\n" % (named, sha(named.read_bytes())), encoding="utf-8")
    code, out, _ = check_hashes(prompt)
    assert code == 6 and out["unmatched"][0]["line"] == 3 and out["unmatched"][0]["candidates"] == []


def test_check_hashes_never_takes_a_relative_or_traversing_path_as_a_candidate(tmp_path, named):
    """T100: a relative path resolves against whatever cwd the checker happens to run in."""
    real = sha(named.read_bytes())
    traversing = "%s/../briefs/%s" % (named.parent, named.name)
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Brief briefs/lane-brief.md (sha256 %s)\nAgain %s (sha256 %s)\n" % (real, traversing, real),
                      encoding="utf-8")
    code, out, err = check_hashes(prompt, cwd=tmp_path)
    assert code == 6, (out, err)
    assert [miss["line"] for miss in out["unmatched"]] == [1, 2]
    assert all(miss["candidates"] == [] for miss in out["unmatched"])
    refused = {(row["line"], row["path"]): row["reason"] for row in out["refused_paths"]}
    assert refused[(1, "briefs/lane-brief.md")].startswith("relative path")
    assert refused[(2, traversing)].startswith("path with '..'")


def test_check_hashes_matches_a_source_file_anywhere(tmp_path, named):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("checkpoint sha256 %s, no path here\n" % sha(named.read_bytes()), encoding="utf-8")
    code, out, _ = check_hashes(prompt)
    assert code == 6
    code, out, err = check_hashes(prompt, "--source", named)
    assert code == 0, (out, err)
    assert out["checked"] == [{"token": sha(named.read_bytes()), "line": 1, "path": str(named), "via": "source"}]
    assert out["sources"] == [{"path": str(named), "sha256": sha(named.read_bytes())}]


@pytest.mark.parametrize("bad", ["relative", "traversal"])
def test_check_hashes_refuses_a_relative_source_or_file_naming_the_argument(tmp_path, named, bad):
    value = "briefs/lane-brief.md" if bad == "relative" else "%s/../briefs/lane-brief.md" % named.parent
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("nothing\n", encoding="utf-8")
    code, out, _ = check_hashes(prompt, "--source", value, cwd=tmp_path)
    assert code == 2, out
    assert "--source" in out["error"] and value in out["error"]
    code, out, _ = check_hashes("prompt.txt", cwd=tmp_path)
    assert code == 2 and "check-hashes file" in out["error"] and "prompt.txt" in out["error"]


def test_check_hashes_counts_only_word_bounded_lowercase_64_hex(tmp_path, named):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("git %s\nupper %s\nlong %s\nnone here\n" % ("a" * 40, "A" * 64, "b" * 65), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 0, (out, err)
    assert out["tokens"] == 0 and out["checked"] == [] and out["unmatched"] == []


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
    if cfg.get("plant"):  # another writer creates the record path while the launch is observed
        pathlib.Path(cfg["plant"]).write_text("{}\n")
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
        # pytest's tmp_path is under /tmp, which launch refuses as a cwd; tests pass this
        # folder through the documented test-only --test-tmp-root seam instead.
        self.tmp_root = tmp_path / "tmp-root"

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
    """Shaped like the real rows recorded in requests/root-c6-*-launch.json: no id (review P2-2)."""
    return {"pid": 4242, "sessionId": session, "name": name, "status": status, "state": state, **extra}


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
                    "--wait-s", "5", "--dialog-wait-s", "1", "--min-free-mb", "1",
                    "--test-tmp-root", stub.tmp_root, *extra, stdin=stdin, env=stub.env())


def test_launch_records_an_exact_first_prompt_with_no_inherited_stdin(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
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
    assert record["uses_enter_worktree"] is False
    assert record["first_prompt_check"]["ok"] is True and record["first_prompt_check"]["extra_chars"] == 0
    assert record["dialog"] is None


def test_launch_refuses_an_existing_record_path_before_launching(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    Path(spec["record_out"]).write_text("{}\n", encoding="utf-8")
    code, out, _ = launch(stub, spec_path)
    assert code == 3
    assert not stub.launched()
    assert Path(spec["record_out"]).read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("problem", ["missing", "read_only"])
def test_launch_refuses_an_unwritable_record_folder_before_launching(tmp_path, stub, prompt_file, problem):
    """P2-3: the record (with its stop command) was lost after the session had started."""
    folder = tmp_path / "records"
    if problem == "read_only":
        if os.geteuid() == 0:
            pytest.skip("root ignores folder permissions")
        folder.mkdir()
        folder.chmod(0o500)
    spec_path, spec = launch_spec(tmp_path, prompt_file, record_out=str(folder / "launch-record.json"))
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True})
    stub.serve("agents-after.json", [agent_row(SESSION, LANE)])
    try:
        code, out, _ = launch(stub, spec_path)
    finally:
        if folder.exists():
            folder.chmod(0o700)
    assert code == 4, out
    assert "record folder is missing or not writable" in out["error"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()
    assert not folder.exists() or list(folder.iterdir()) == []


def test_launch_prints_the_whole_record_when_its_write_fails_after_the_launch(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True,
                               "plant": spec["record_out"]})
    stub.serve("agents-after.json", [agent_row(SESSION, LANE)])
    code, out, _ = launch(stub, spec_path)
    assert code == 3, out
    assert stub.launched() and Path(spec["record_out"]).read_text(encoding="utf-8") == "{}\n"
    assert "a session may be running" in out["error"]
    record = out["record"]
    assert record["session"] == SESSION and record["verdict"] == "launched"
    assert record["stop_command"] == "claude stop " + SESSION[:8]
    assert record["attach_command"] == "claude attach " + SESSION[:8]


def test_launch_refuses_a_name_that_is_already_live(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    stub.serve("agents.json", [agent_row("1dd78e7e-8e0f-45da-8e3a-163c78577481", LANE, state="blocked", status="idle")])
    code, out, _ = launch(stub, spec_path)
    assert code == 3
    assert out["live_sessions"] == ["1dd78e7e-8e0f-45da-8e3a-163c78577481"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()


@pytest.mark.parametrize("where", ["git_checkout", "under_git_checkout", "claude_worktrees", "tmp_root"])
def test_launch_refuses_a_cwd_a_background_session_cannot_trust(tmp_path, stub, prompt_file, where):
    """P2-4, probes E/F: in such a cwd the session stops at a trust prompt before its first record."""
    if where == "git_checkout":
        cwd = clean_repo(tmp_path / "checkout")
    elif where == "under_git_checkout":
        cwd = clean_repo(tmp_path / "checkout") / "sub"
        cwd.mkdir()
    elif where == "claude_worktrees":
        cwd = tmp_path / ".claude" / "worktrees" / "x"
        cwd.mkdir(parents=True)
    else:
        cwd = stub.tmp_root / "lane"
        cwd.mkdir(parents=True)
    spec_path, spec = launch_spec(tmp_path, prompt_file, cwd=str(cwd))
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True})
    for extra in (["--plan"], []):
        code, out, _ = launch(stub, spec_path, *extra)
        assert code == 2, out
        assert out["error"].startswith("refused cwd for a background session")
    assert not stub.launched() and not Path(spec["record_out"]).exists()


def test_launch_refuses_a_cwd_under_tmp_without_the_test_seam(tmp_path, stub, prompt_file):
    cwd = Path(tempfile.mkdtemp(prefix="aegis47-hfix-cwd-", dir="/tmp"))
    try:
        spec_path, spec = launch_spec(tmp_path, prompt_file, cwd=str(cwd))
        code, out, _ = run_tool("launch", "--spec", spec_path, "--plan", env=stub.env())
    finally:
        cwd.rmdir()
    assert code == 2, out
    assert "under /tmp" in out["error"]


def test_launch_refuses_uses_enter_worktree_under_layout_f(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file, uses_enter_worktree=True)
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True})
    code, out, _ = launch(stub, spec_path)
    assert code == 2, out
    assert "uses_enter_worktree" in out["error"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()


def test_launch_detects_a_pending_dialog_and_still_writes_the_record(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
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


def test_launch_reports_a_leaked_first_prompt_and_prints_the_stop_command(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    # The stub closes stdin like the real host, so the leaked transcript is planted where the tool looks
    # and the stub writes its own copy elsewhere.
    transcript = stub.projects / spec["cwd"].replace("/", "-") / (SESSION + ".jsonl")
    write_transcript(transcript, [user_record(prompt_file.read_text(encoding="utf-8") + LAUNCHER_TEXT)])
    stub.serve("launch.json", {"session": SESSION, "projects": str(tmp_path / "elsewhere"), "assistant": True})
    code, out, err = launch(stub, spec_path)
    assert code == 2, (out, err)
    record = json.loads(Path(spec["record_out"]).read_text(encoding="utf-8"))
    assert record["first_prompt_check"]["extra_chars"] == 2308
    assert record["stop_command"] == "claude stop " + SESSION[:8]


def test_launch_refuses_when_free_space_is_below_the_threshold(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    code, out, _ = run_tool("launch", "--spec", spec_path, "--projects-dir", stub.projects,
                            "--min-free-mb", str(10 ** 12), "--test-tmp-root", stub.tmp_root, env=stub.env())
    assert code == 4
    assert "free" in out["error"]
    assert not stub.launched() and not Path(spec["record_out"]).exists()


# --- item 3: lanes-health (F-B, T10, T26) -----------------------------------------------------

NOW = "2026-11-02T17:00:00.000Z"
IDS = {name: "%08x-0000-4000-8000-%012x" % (index + 0xa0000000, index) for index, name in enumerate(
    ["answered", "stalled", "young", "max", "torn", "notice", "norequest", "blocked", "missing"])}


def request(ts, ident, effort="xhigh"):
    return {"type": "api-request", "id": ident, "timestamp": ts, "querySource": "repl_main_thread",
            "sessionId": "s", "params": {"model": "claude-opus-5-5", "output_config": {"effort": effort}}}


def answer(ts, ref):
    return {"type": "assistant", "uuid": "a-" + ref, "requestRef": ref, "timestamp": ts,
            "message": {"role": "assistant", "content": []}}


def queue(ts, operation, content=None):
    record = {"type": "queue-operation", "operation": operation, "timestamp": ts}
    if content is not None:
        record["content"] = content
    return record


@pytest.fixture
def lanes(stub):
    folder = stub.projects / "-home-x-workspace"
    first = user_record("lane prompt", ts="2026-11-02T16:30:00.000Z")
    fixtures = {
        "answered": [first, request("2026-11-02T16:55:00.000Z", "r1"), answer("2026-11-02T16:55:05.000Z", "r1")],
        "stalled": [first, request("2026-11-02T16:35:00.000Z", "r1")],
        "young": [first, request("2026-11-02T16:45:00.000Z", "r1")],
        "max": [first, request("2026-11-02T16:36:40.000Z", "r1", effort="max")],
        "torn": [first, request("2026-11-02T16:58:00.000Z", "r1"), answer("2026-11-02T16:58:30.000Z", "r1")],
        "notice": [first, request("2026-11-02T16:50:00.000Z", "r1"), answer("2026-11-02T16:50:09.000Z", "r1"),
                   queue("2026-11-02T16:51:00.000Z", "enqueue", "<task-notification>subagent done</task-notification>"),
                   queue("2026-11-02T16:52:00.000Z", "enqueue", "nudge from orchestrator"),
                   queue("2026-11-02T16:52:01.000Z", "remove", "nudge from orchestrator")],
        "norequest": [first],
        "blocked": [first, request("2026-11-02T16:58:00.000Z", "r1")],
    }
    for name, records in fixtures.items():
        write_transcript(folder / (IDS[name] + ".jsonl"), records,
                         torn_tail='{"type": "assist' if name == "torn" else None)
    stub.serve("agents.json", [agent_row(IDS["answered"], "lane a", state="blocked", status="idle"),
                               agent_row(IDS["stalled"], "lane b"),
                               agent_row(IDS["blocked"], "lane h", state="blocked", status="waiting",
                                         waitingFor="permission prompt")])
    stub.serve("logs.txt", "spinner " * 50 + DIALOG_SCREEN)
    return stub


def health(stub, *names, extra=()):
    argv = ["lanes-health", "--projects-dir", stub.projects, "--now", NOW, *extra]
    for name in names:
        argv += ["--session", IDS[name] + "=" + name]
    code, out, err = run_tool(*argv, env=stub.env())
    assert code == 0, (out, err)
    return {row["label"]: row for row in out["sessions"]}


def test_lanes_health_reports_answered_open_and_stalled_requests(lanes):
    rows = health(lanes, "answered", "stalled", "young", "max")
    answered = rows["answered"]
    assert answered["open_request_s"] is None and answered["stalled"] is False
    assert answered["last_record_ts"] == "2026-11-02T16:55:05.000Z" and answered["silent_s"] == 295
    assert answered["silent"] is False and answered["effort"] == "xhigh"
    assert answered["agents_state"]["state"] == "blocked" and answered["waiting_on_human"] is False
    stalled = rows["stalled"]
    assert stalled["open_request_s"] == 1500 and stalled["stalled"] is True and stalled["silent"] is True
    assert stalled["agents_state"]["state"] == "working" and stalled["waiting_on_human"] is False
    young = rows["young"]
    assert young["open_request_s"] == 900 and young["stalled"] is False and young["silent"] is False
    assert young["agents_state"] is None
    assert rows["max"]["effort"] == "max" and rows["max"]["open_request_s"] == 1400
    assert rows["max"]["stalled"] is False


def test_lanes_health_thresholds_are_options(lanes):
    rows = health(lanes, "young", extra=["--stall-s", "600", "--silent-s", "60"])
    assert rows["young"]["stalled"] is True and rows["young"]["silent"] is True


def test_lanes_health_tolerates_a_torn_tail_and_counts_enqueued_notices(lanes):
    rows = health(lanes, "torn", "notice", "norequest")
    assert rows["torn"]["torn_tail"] is True and rows["torn"]["open_request_s"] is None
    notices = rows["notice"]["enqueued_notices"]
    assert [n["head"] for n in notices] == ["<task-notification>subagent done</task-notification>"]
    assert notices[0]["timestamp"] == "2026-11-02T16:51:00.000Z"
    assert rows["norequest"]["open_request_s"] is None and rows["norequest"]["effort"] is None
    assert rows["norequest"]["stalled"] is False


def test_lanes_health_flags_a_session_waiting_on_a_human(lanes):
    rows = health(lanes, "blocked", "missing")
    blocked = rows["blocked"]
    assert blocked["waiting_on_human"] is True and blocked["stalled"] is False
    assert blocked["agents_state"]["waitingFor"] == "permission prompt"
    assert "Do you want to proceed?" in blocked["dialog"]["text"] and "\x1b" not in blocked["dialog"]["text"]
    assert json.loads((lanes.dir / "logs-args.json").read_text()) == ["logs", IDS["blocked"][:8]]
    assert rows["missing"]["transcript"] is None and "not found" in rows["missing"]["error"]


def test_lanes_health_matches_a_short_id_by_prefix_and_refuses_an_ambiguous_one(lanes):
    """P2-2: rows carry no id, so a short id matches by sessionId prefix; a prefix of several is refused."""
    code, out, err = run_tool("lanes-health", "--projects-dir", lanes.projects, "--now", NOW,
                              "--session", IDS["blocked"][:8] + "=short", "--session", "a000000=ambiguous",
                              env=lanes.env())
    assert code == 0, (out, err)
    rows = {row["label"]: row for row in out["sessions"]}
    assert rows["short"]["agents_state"]["state"] == "blocked" and rows["short"]["waiting_on_human"] is True
    assert rows["ambiguous"]["agents_state"] is None and "ambiguous" in rows["ambiguous"]["agents_error"]


def test_lanes_health_refuses_a_session_id_that_is_not_an_id(lanes):
    code, out, _ = run_tool("lanes-health", "--projects-dir", lanes.projects, "--session", "*", env=lanes.env())
    assert code == 2


# --- item 4: shared helpers (C2 section 2.1) ---------------------------------------------------


@pytest.fixture(scope="module")
def tool():
    import importlib.util

    spec = importlib.util.spec_from_file_location("hierarchy_root_under_test", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def failure_code(tool, call):
    with pytest.raises(tool.Failure) as caught:
        call()
    return caught.value.code


def leftovers(folder):
    return sorted(p.name for p in folder.iterdir() if p.name.endswith(".tmp"))


def test_read_jsonl_skips_only_a_torn_last_line(tool, tmp_path):
    path = tmp_path / "t.jsonl"
    path.write_text('{"a": 1}\n{"b": 2}\n{"c": ', encoding="utf-8")
    rows, torn = tool.read_jsonl(path)
    assert rows == [(1, {"a": 1}), (2, {"b": 2})] and torn is True
    assert failure_code(tool, lambda: tool.read_jsonl(path, tolerate_torn_tail=False)) == 2
    path.write_text('{"a": 1}\n{"b": \n{"c": 3}\n', encoding="utf-8")
    assert failure_code(tool, lambda: tool.read_jsonl(path)) == 2


def test_atomic_write_is_idempotent_and_refuses_a_differing_target(tool, tmp_path):
    path = tmp_path / "ack.json"
    first = tool.atomic_write_json(path, {"a": 1})
    assert first["written"] is True and json.loads(path.read_text(encoding="utf-8")) == {"a": 1}
    again = tool.atomic_write_json(path, {"a": 1})
    assert again["written"] is False and again["identical"] is True and again["sha256"] == first["sha256"]
    before = path.read_bytes()
    assert failure_code(tool, lambda: tool.atomic_write_json(path, {"a": 2})) == 3
    assert path.read_bytes() == before and leftovers(tmp_path) == []


def test_cas_update_replaces_only_the_bytes_the_caller_read(tool, tmp_path):
    path = tmp_path / "custody.json"
    path.write_text('{"active_root_session": "c4"}\n', encoding="utf-8")
    expected = sha(path.read_bytes())

    def promote(custody):
        custody["active_root_session"] = "c5"
        return custody

    result = tool.cas_update_json(path, expected, promote)
    assert json.loads(path.read_text(encoding="utf-8")) == {"active_root_session": "c5"}
    assert result["previous_sha256"] == expected and result["sha256"] == sha(path.read_bytes())
    stale = path.read_bytes()
    assert failure_code(tool, lambda: tool.cas_update_json(path, expected, promote)) == 2
    assert path.read_bytes() == stale and leftovers(tmp_path) == []


def test_cas_update_refuses_a_change_between_read_and_replace(tool, tmp_path):
    path = tmp_path / "custody.json"
    path.write_text('{"active_root_session": "c4"}\n', encoding="utf-8")
    expected = sha(path.read_bytes())
    concurrent = b'{"active_root_session": "other"}\n'

    def racing(custody):
        path.write_bytes(concurrent)
        return {"active_root_session": "c5"}

    assert failure_code(tool, lambda: tool.cas_update_json(path, expected, racing)) == 2
    assert path.read_bytes() == concurrent and leftovers(tmp_path) == []


def test_free_space_precheck_refuses_below_the_threshold(tool, tmp_path):
    class Stats:
        f_bavail, f_frsize = 100, 1024 * 1024

    target = tmp_path / "missing-folder" / "ack.json"
    assert failure_code(tool, lambda: tool.check_free_space([target], 512, statvfs=lambda _: Stats)) == 4
    assert tool.check_free_space([target], 64, statvfs=lambda _: Stats) is None
    assert not target.parent.exists()


def test_verify_briefs_accepts_a_superset_and_rejects_missing_or_changed_briefs(tool, tmp_path):
    briefs = []
    for name in ("a", "b", "c"):
        path = tmp_path / (name + ".md")
        path.write_text("brief " + name, encoding="utf-8")
        briefs.append({"path": str(path), "sha256": sha(path.read_bytes())})
    ok = tool.verify_briefs([briefs[0]], briefs)
    assert ok["ok"] is True and ok["missing_from_checkpoint"] == []
    missing = tool.verify_briefs([briefs[0]], briefs[1:])
    assert missing["ok"] is False and missing["missing_from_checkpoint"] == [briefs[0]["sha256"]]
    Path(briefs[2]["path"]).write_text("edited", encoding="utf-8")
    changed = tool.verify_briefs([briefs[0]], briefs)
    assert changed["ok"] is False
    assert [row["ok"] for row in changed["rehash"]] == [True, True, False]


# --- item 5: rebind (C2 section 3, F2, F9, T15, T28) -------------------------------------------


def rebind_setup(tmp_path, messages=25):
    from tests.integration.test_hierarchy_handoff import make_root, spec_for
    from tests.integration.test_hierarchy_mailbox import invoke, message

    root, brief = make_root(tmp_path / "alpha", "alpha")
    for index in range(messages):
        invoke(root, "publish", message("alpha/orchestrator", "alpha/front-door", identifier="m-%02d" % index))
    spec = spec_for([(root, brief)])
    path = tmp_path / "rebind-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    acks = tmp_path / "acks"
    acks.mkdir()
    return root, brief, spec, path, acks


def rebind(spec_path, result_out, acks, *extra):
    return run_tool("rebind", "--spec", spec_path, "--result-out", result_out, "--ack-dir", acks,
                    "--min-free-mb", "1", *extra)


def test_rebind_pages_the_whole_inbox_then_acknowledges(tmp_path):
    from tests.integration.test_hierarchy_mailbox import invoke

    root, _, spec, spec_path, acks = rebind_setup(tmp_path)
    code, out, err = rebind(spec_path, tmp_path / "result-1.json", acks)
    assert code == 0, (out, err)
    row = out["entries"][0]
    assert row["ready"] is True and row["generation"] == 2
    assert row["messages_read"] == 25 and row["pages"] == 2 and row["remaining"] == 0
    assert row["briefs"]["ok"] is True
    assert invoke(root, "status")["bindings"]["alpha/front-door"]["ready"] is True
    ack = json.loads(Path(row["ack_request"]).read_text(encoding="utf-8"))
    assert ack == {"endpoint": "alpha/front-door", "session": "new-front-door", "generation": 2,
                   "checkpoint_sha256": row["checkpoint_sha256"]}
    assert json.loads((tmp_path / "result-1.json").read_text(encoding="utf-8")) == out
    again_code, again, _ = rebind(spec_path, tmp_path / "result-2.json", acks)
    assert again_code == 0 and again["entries"][0]["ready"] is True


def test_rebind_does_not_acknowledge_when_a_spec_brief_is_missing_from_the_checkpoint(tmp_path):
    from tests.integration.test_hierarchy_mailbox import invoke

    root, brief, spec, spec_path, acks = rebind_setup(tmp_path, messages=3)
    first = tmp_path / "first-spec.json"
    first.write_text(json.dumps(spec), encoding="utf-8")
    subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "hierarchy_handoff.py"), "--spec", str(first)],
                   capture_output=True, check=True, timeout=60, stdin=subprocess.DEVNULL)
    extra = tmp_path / "alpha" / "extra.md"
    extra.write_text("A brief the checkpoint never carried.\n", encoding="utf-8")
    spec["entries"][0]["briefs"].append({"path": str(extra), "sha256": sha(extra.read_bytes())})
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    code, out, _ = rebind(spec_path, tmp_path / "result.json", acks)
    assert code == 2
    row = out["entries"][0]
    assert row["ready"] is False and row["briefs"]["missing_from_checkpoint"] == [sha(extra.read_bytes())]
    assert invoke(root, "status")["bindings"]["alpha/front-door"]["ready"] is False
    assert list(acks.iterdir()) == []
    # P3-1: exit 2 from rebind still leaves its result written (the documented contract).
    assert json.loads((tmp_path / "result.json").read_text(encoding="utf-8")) == out


def test_rebind_warns_until_custody_records_the_outgoing_stop(tmp_path):
    """P3-9: the spec's outgoing_stopped: true is asserted before the stop; custody is the record."""
    _, _, spec, spec_path, acks = rebind_setup(tmp_path, messages=1)
    custody = tmp_path / "custody.json"
    entry = {"outgoing_root": "d6b2a18b-e242-4ecb-ac63-baab549cf112", "incoming_root": spec["session"]}
    custody.write_text(json.dumps({"active_root_session": spec["session"], "custody_history": [entry]}),
                       encoding="utf-8")
    code, out, err = rebind(spec_path, tmp_path / "result-1.json", acks, "--custody", custody)
    assert code == 0, (out, err)
    assert out["outgoing_stop"] == {"custody": str(custody), "outgoing_root": entry["outgoing_root"],
                                    "verified": False}
    assert len(out["warnings"]) == 1 and "lacks outgoing_stopped" in out["warnings"][0]
    entry["outgoing_stopped"] = {"verified_at": "2026-11-02T17:00:00.000Z", "by": "hierarchy_root.py verify-retired"}
    custody.write_text(json.dumps({"active_root_session": spec["session"], "custody_history": [entry]}),
                       encoding="utf-8")
    code, out, _ = rebind(spec_path, tmp_path / "result-2.json", acks, "--custody", custody)
    assert code == 0 and out["outgoing_stop"]["verified"] is True and out["warnings"] == []


def test_rebind_plan_writes_nothing(tmp_path):
    from tests.integration.test_hierarchy_mailbox import invoke

    root, _, _, spec_path, acks = rebind_setup(tmp_path, messages=1)
    before = invoke(root, "status")["bindings"]["alpha/front-door"]
    code, out, _ = rebind(spec_path, tmp_path / "result.json", acks, "--plan")
    assert code == 0 and out["plan"] is True
    assert out["writes"][0] == str(tmp_path / "result.json")
    assert out["writes"][1] == str(acks / "ack-alpha-front-door-g2.json")
    assert invoke(root, "status")["bindings"]["alpha/front-door"] == before
    assert not (tmp_path / "result.json").exists() and list(acks.iterdir()) == []


# --- item 6 (retire step): verify-retired (F5, T30) --------------------------------------------

OUTGOING = "d6b2a18b-e242-4ecb-ac63-baab549cf112"


def custody_file(tmp_path):
    path = tmp_path / "custody.json"
    path.write_text(json.dumps({"active_root_session": "c9e38364", "custody_history": [
        {"outgoing_root": "69958d8f", "incoming_root": OUTGOING},
        {"outgoing_root": OUTGOING, "incoming_root": "c9e38364"}]}, indent=1) + "\n", encoding="utf-8")
    return path


def finished_pid():
    proc = subprocess.Popen([sys.executable, "-c", "pass"], stdin=subprocess.DEVNULL)
    proc.wait(timeout=30)
    return proc.pid


def retired(stub, pid, custody=None, expect=None):
    argv = ["verify-retired", "--session", OUTGOING, "--pid", pid, "--min-free-mb", "1"]
    if custody is not None:
        argv += ["--custody", custody, "--expect-custody-sha256", expect or sha(custody.read_bytes())]
    return run_tool(*argv, env=stub.env())


def test_verify_retired_refuses_while_the_process_is_alive(tmp_path, stub):
    custody = custody_file(tmp_path)
    before = custody.read_bytes()
    alive = subprocess.Popen(["sleep", "30"], stdin=subprocess.DEVNULL)
    try:
        code, out, err = retired(stub, alive.pid, custody)
    finally:
        alive.kill()
        alive.wait(timeout=30)
    assert code == 2, (out, err)
    assert out["verdict"] == "alive" and out["pid_alive"] is True and out["retired"] is False
    assert out["stop_command"] == "claude stop " + OUTGOING[:8]
    assert custody.read_bytes() == before


def test_verify_retired_records_outgoing_stopped_when_gone(tmp_path, stub):
    custody = custody_file(tmp_path)
    pid = finished_pid()
    code, out, err = retired(stub, pid, custody)
    assert code == 0, (out, err)
    assert out["verdict"] == "retired" and out["pid_alive"] is False and out["agents_listed"] is False
    history = json.loads(custody.read_text(encoding="utf-8"))["custody_history"]
    stopped = history[1]["outgoing_stopped"]
    assert stopped["pid"] == pid and stopped["evidence"] == {"pid_alive": False, "agents_listed": False}
    assert stopped["verified_at"].endswith("Z") and "outgoing_stopped" not in history[0]
    assert out["custody_update"]["sha256"] == sha(custody.read_bytes())


def test_verify_retired_refuses_a_session_still_listed_after_its_pid_is_gone(tmp_path, stub):
    custody = custody_file(tmp_path)
    before = custody.read_bytes()
    stub.serve("agents.json", [agent_row(OUTGOING, "ROOT C5", state="blocked", status="idle")])
    code, out, _ = retired(stub, finished_pid(), custody)
    assert code == 2
    assert out["verdict"] == "listed_but_pid_gone" and out["agents_listed"] is True
    assert custody.read_bytes() == before


def test_verify_retired_refuses_a_short_session_id_before_reading_agents(tmp_path, stub):
    """P2-2: with a short id and rows without id, no row matched and a live session read as retired."""
    custody = custody_file(tmp_path)
    before = custody.read_bytes()
    stub.serve("agents.json", [agent_row(OUTGOING, "ROOT C5", state="blocked", status="idle")])
    code, out, _ = run_tool("verify-retired", "--session", OUTGOING[:8], "--pid", finished_pid(), "--custody", custody,
                            "--expect-custody-sha256", sha(before), "--min-free-mb", "1", env=stub.env())
    assert code == 2, out
    assert "full 36-character session id" in out["error"]
    assert custody.read_bytes() == before
    assert not (stub.dir / "calls.jsonl").exists()


INCOMING ="c9e38364-ac3f-4720-ba74-44318c7bfcac"


def ack_body(packet):
    """The fields transfer cross-checks, shaped like the ACK startup-ack writes."""
    return {"schema": "aegis.claude-root-startup-ack/v1", "incoming": {"session": INCOMING},
            "outgoing": {"session": OUTGOING},
            "observed": {"handoff": {"path": str(packet), "sha256": sha(packet.read_bytes())}},
            "critical_checks": [{"name": "packet_sha256", "ok": True}]}


@pytest.fixture
def rotation(tmp_path):
    files = {}
    for name, body in (("delta", '{"delta": 1}\n'), ("packet", '{"packet": 1}\n'), ("brief", "Root brief.\n")):
        files[name] = tmp_path / (name + (".md" if name == "brief" else ".json"))
        files[name].write_text(body, encoding="utf-8")
    files["ack"] = tmp_path / "ack.json"
    files["ack"].write_text(json.dumps(ack_body(files["packet"])) + "\n", encoding="utf-8")
    brief = {"path": str(files["brief"]), "sha256": sha(files["brief"].read_bytes())}
    prev = {"schema": "aegis.hierarchy-handoff/v1", "host": "claude-code", "session": OUTGOING,
            "outgoing_stopped": True, "entries": [
                {"root": "/m/%s/mailbox" % name, "endpoint": name + "/root", "briefs": [brief],
                 "delivery_dir": "/m/%s/delivery" % name, "completed_checks": ["old check"]}
                for name in ("aegis", "storm")]}
    files["prev"] = tmp_path / "prev-spec.json"
    files["prev"].write_text(json.dumps(prev), encoding="utf-8")
    files["custody"] = tmp_path / "custody.json"
    files["custody"].write_text(json.dumps({
        "active_native_root": OUTGOING, "active_root_session": OUTGOING, "active_root_host": "claude-code",
        "custody_history": [{"outgoing_root": "69958d8f", "incoming_root": OUTGOING}],
        "claude_c5_to_c6_handoff": {"state": "PREPARED_WAITING_ACTUAL_STARTUP_ACK", "incoming_session": INCOMING},
    }, indent=1) + "\n", encoding="utf-8")
    facts = {"outgoing": {"host": "claude-code", "session": OUTGOING, "pid": 4059889, "start_ticks": "123",
                          "label": "C5"},
             "incoming": {"host": "claude-code", "session": INCOMING, "label": "C6"},
             "handoff": {"path": str(files["packet"]), "sha256": sha(files["packet"].read_bytes())},
             "authority": "Owner standing approval for automatic ROOT successors."}
    files["facts"] = tmp_path / "facts.json"
    files["facts"].write_text(json.dumps(facts), encoding="utf-8")
    files["spec_out"] = tmp_path / "root-c5-to-c6-handoff.json"
    files["transfer_out"] = tmp_path / "ROOT-C5-C6-TRANSFER.json"
    return files


def transfer_argv(files, *extra, ack_sha=None, custody_sha=None):
    return [str(a) for a in (
        "transfer", "--facts", files["facts"], "--ack", files["ack"],
        "--ack-sha256", ack_sha or sha(files["ack"].read_bytes()), "--final-delta", files["delta"],
        "--prev-spec", files["prev"], "--spec-out", files["spec_out"],
        "--transfer-out", files["transfer_out"], "--custody", files["custody"],
        "--expect-custody-sha256", custody_sha or sha(files["custody"].read_bytes()),
        "--min-free-mb", "1", *extra)]


def transfer(files, *extra, ack_sha=None, custody_sha=None):
    return run_tool(*transfer_argv(files, *extra, ack_sha=ack_sha, custody_sha=custody_sha))


def test_transfer_writes_spec_and_transfer_and_syncs_every_custody_field(rotation):
    code, out, err = transfer(rotation)
    assert code == 0, (out, err)
    custody = json.loads(rotation["custody"].read_text(encoding="utf-8"))
    assert custody["active_native_root"] == custody["active_root_session"] == INCOMING
    assert custody["active_root_host"] == "claude-code"
    entry = custody["custody_history"][-1]
    assert entry["outgoing_root"] == OUTGOING and entry["incoming_root"] == INCOMING
    assert entry["transfer"] == {"path": str(rotation["transfer_out"]), "sha256": sha(rotation["transfer_out"].read_bytes())}
    assert entry["startup_ack_sha256"] == sha(rotation["ack"].read_bytes())
    assert custody["claude_c5_to_c6_handoff"]["state"].startswith("TRANSFERRED_C6")
    assert custody["claude_c5_to_c6_handoff"]["incoming_session"] == INCOMING
    spec = json.loads(rotation["spec_out"].read_text(encoding="utf-8"))
    prev = json.loads(rotation["prev"].read_text(encoding="utf-8"))
    assert spec["session"] == INCOMING and spec["outgoing_stopped"] is True
    for new, old in zip(spec["entries"], prev["entries"]):
        assert {k: v for k, v in new.items() if k != "completed_checks"} == \
            {k: v for k, v in old.items() if k != "completed_checks"}
        assert new["completed_checks"] != ["old check"]
        assert any(INCOMING in check and sha(rotation["ack"].read_bytes()) in check for check in new["completed_checks"])
    record = json.loads(rotation["transfer_out"].read_text(encoding="utf-8"))
    assert record["schema"] == "aegis.claude-to-claude-root-transfer/v1" and record["state"] == "TRANSFERRED"
    assert record["root_spec"] == {"path": str(rotation["spec_out"]), "sha256": sha(rotation["spec_out"].read_bytes())}
    assert record["outgoing"]["session"] == OUTGOING and record["incoming"]["session"] == INCOMING
    assert out["stop_command"] == "claude stop " + OUTGOING[:8]
    assert "verify-retired" in out["next"]


@pytest.mark.parametrize("bad", ["ack", "custody"])
def test_transfer_writes_nothing_when_a_critical_hash_differs(rotation, bad):
    before = rotation["custody"].read_bytes()
    code, out, _ = transfer(rotation, **{bad + "_sha": "0" * 64})
    assert code == 2
    assert rotation["custody"].read_bytes() == before
    assert not rotation["spec_out"].exists() and not rotation["transfer_out"].exists()


@pytest.mark.parametrize("bad", ["one_key", "schema", "incoming", "outgoing", "handoff_sha256", "failed_check",
                                 "no_checks", "not_json"])
def test_transfer_refuses_an_ack_that_does_not_vouch_for_the_facts(rotation, bad):
    """P2-1: a stale or foreign ACK that merely names the incoming session must not move custody."""
    body = ack_body(rotation["packet"])
    if bad == "one_key":  # the fixture ACK before the fix: only the incoming session
        body = {"incoming": {"session": INCOMING}}
    elif bad == "schema":
        body["schema"] = "aegis.claude-root-rendezvous/v1"
    elif bad == "incoming":
        body["incoming"]["session"], body["note"] = "7e0dc264-eaca-48a3-babe-9a0f6f7f74ba", INCOMING
    elif bad == "outgoing":
        body["outgoing"]["session"] = "7e0dc264-eaca-48a3-babe-9a0f6f7f74ba"
    elif bad == "handoff_sha256":  # an ACK about an earlier packet
        body["observed"]["handoff"]["sha256"] = "0" * 64
    elif bad == "failed_check":
        body["critical_checks"].append({"name": "tools_pin_clean", "ok": False})
    elif bad == "no_checks":
        del body["critical_checks"]
    raw = ("[" + INCOMING + "\n") if bad == "not_json" else json.dumps(body) + "\n"
    rotation["ack"].write_text(raw, encoding="utf-8")
    before = rotation["custody"].read_bytes()
    code, out, _ = transfer(rotation)
    assert code == 2, out
    assert out["error"].startswith("startup ACK does not vouch for this transfer")
    assert rotation["custody"].read_bytes() == before
    assert not rotation["spec_out"].exists() and not rotation["transfer_out"].exists()


@pytest.mark.parametrize("side", ["outgoing", "incoming"])
def test_transfer_refuses_a_short_session_id_in_the_facts(rotation, side):
    facts = json.loads(rotation["facts"].read_text(encoding="utf-8"))
    facts[side]["session"] = facts[side]["session"][:8]
    rotation["facts"].write_text(json.dumps(facts), encoding="utf-8")
    before = rotation["custody"].read_bytes()
    code, out, _ = transfer(rotation)
    assert code == 2 and "full 36-character session id" in out["error"], out
    assert rotation["custody"].read_bytes() == before
    assert not rotation["spec_out"].exists() and not rotation["transfer_out"].exists()


def test_transfer_plan_writes_nothing(rotation):
    before = rotation["custody"].read_bytes()
    code, out, _ = transfer(rotation, "--plan")
    assert code == 0 and out["writes"] == [str(rotation["spec_out"]), str(rotation["transfer_out"]),
                                           str(rotation["custody"])]
    assert rotation["custody"].read_bytes() == before and not rotation["spec_out"].exists()


# --- item 7: startup-ack (C2 section 3, F1, F5, F6, F8) -----------------------------------------


def clean_repo(path):
    path.mkdir()
    for args in (["init", "-q"], ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "base"]):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    return path


@pytest.fixture
def startup(tmp_path, stub):
    files = {"packet": tmp_path / "packet.json", "rendezvous": tmp_path / "rendezvous.json",
             "custody": tmp_path / "custody.json", "out": tmp_path / "ROOT-C6-STARTUP-ACK.json"}
    files["packet"].write_text('{"packet": 1}\n', encoding="utf-8")
    files["rendezvous"].write_text(json.dumps({"schema": "aegis.claude-root-rendezvous/v1",
                                               "state": "WAITING_FOR_ACTUAL_CLAUDE_STARTUP_ACK",
                                               "handoff": {"path": str(files["packet"]),
                                                           "sha256": sha(files["packet"].read_bytes())},
                                               "outgoing_host": "claude-code", "outgoing_session": OUTGOING,
                                               "incoming_host": "claude-code", "incoming_session": None}),
                                   encoding="utf-8")
    files["custody"].write_text(json.dumps({"active_root_session": OUTGOING}), encoding="utf-8")
    files["pin"] = clean_repo(tmp_path / "tools-pin")
    files["source"] = clean_repo(tmp_path / "source")
    files["sources"] = tmp_path / "sources.json"
    files["sources"].write_text(json.dumps([str(files["source"]), str(tmp_path / "deleted-checkout")]), encoding="utf-8")
    write_transcript(stub.projects / "-w" / (INCOMING + ".jsonl"), [
        {"type": "custom-title", "customTitle": "ROOT C6", "sessionId": INCOMING},
        user_record("You are ROOT C6.", uuid="u-first"),
        user_record("<command-name>/goal</command-name> keep working", uuid="u-goal", ts="2026-11-02T16:10:00.000Z"),
        {"type": "user", "uuid": "u-tool", "timestamp": "2026-11-02T16:11:00.000Z",
         "message": {"role": "user", "content": [{"type": "tool_result", "content": "Goal set: quoted"}]}}],
        torn_tail='{"type": "assi')
    return files


def startup_ack(stub, files, *extra, packet_sha=None, rendezvous_sha=None, env=None):
    """rendezvous_sha None hashes the current rendezvous file; False leaves the flag out."""
    environment = {**stub.env(), "CLAUDE_CODE_SESSION_ID": INCOMING, "CLAUDE_PID": str(os.getpid()), **(env or {})}
    if rendezvous_sha is None:
        rendezvous_sha = sha(files["rendezvous"].read_bytes())
    pinned = [] if rendezvous_sha is False else ["--rendezvous-sha256", rendezvous_sha]
    return run_tool("startup-ack", "--packet", files["packet"],
                    "--packet-sha256", packet_sha or sha(files["packet"].read_bytes()),
                    "--rendezvous", files["rendezvous"], *pinned, "--custody", files["custody"],
                    "--tools-pin", files["pin"],
                    "--sources", files["sources"], "--role", "ROOT C6", "--out", files["out"],
                    "--projects-dir", stub.projects, "--min-free-mb", "1", *extra, env=environment)


def test_startup_ack_writes_live_facts_and_observes_missing_sources(stub, startup):
    code, out, err = startup_ack(stub, startup)
    assert code == 0, (out, err)
    ack = json.loads(startup["out"].read_text(encoding="utf-8"))
    assert ack == out["ack"]
    assert ack["schema"] == "aegis.claude-root-startup-ack/v1" and ack["startup_only"] is True
    assert ack["custody_transfer"] is False
    assert all(check["ok"] for check in ack["critical_checks"])
    assert "rendezvous_names_packet" in [check["name"] for check in ack["critical_checks"]]
    assert ack["incoming"]["session"] == INCOMING and ack["outgoing"]["session"] == OUTGOING
    proof = ack["incoming"]["identity_proof"]
    assert proof["transcript_line1"]["sessionId"] == INCOMING and proof["host_process"]["alive"] is True
    assert proof["transcript_first_user_record"]["uuid"] == "u-first"
    assert ack["torn_tail"] is True
    assert [g["uuid"] for g in ack["goal_records"]] == ["u-goal"] and ack["goal_records"][0]["line"] == 3
    sources = {s["path"]: s for s in ack["observed"]["sources_readonly"]}
    assert sources[str(startup["source"])]["present"] is True and sources[str(startup["source"])]["dirty_entries"] == 0
    assert sources[str(startup.get("source").parent / "deleted-checkout")]["present"] is False
    assert ack["observed"]["tools_pin"]["clean"] is True


@pytest.mark.parametrize("break_it", ["packet", "pin", "custody", "identity"])
def test_startup_ack_fails_a_critical_check_and_writes_nothing(stub, startup, break_it):
    kwargs = {}
    if break_it == "packet":
        kwargs["packet_sha"] = "0" * 64
    elif break_it == "pin":
        (startup["pin"] / "stray.txt").write_text("x", encoding="utf-8")
    elif break_it == "custody":
        startup["custody"].write_text(json.dumps({"active_root_session": INCOMING}), encoding="utf-8")
    else:
        kwargs["env"] = {"CLAUDE_CODE_SESSION_ID": OUTGOING}
    code, out, _ = startup_ack(stub, startup, **kwargs)
    assert code == 2
    assert not startup["out"].exists()


@pytest.mark.parametrize("field", ["sha256", "path"])
def test_startup_ack_refuses_a_packet_the_rendezvous_does_not_name(stub, startup, tmp_path, field):
    """P2-1: --packet-sha256 is operator-supplied; the rendezvous file says which packet is meant."""
    rendezvous = json.loads(startup["rendezvous"].read_text(encoding="utf-8"))
    if field == "sha256":  # the rendezvous names a regenerated packet
        rendezvous["handoff"]["sha256"] = "0" * 64
    else:  # same bytes, but the rendezvous names another file (e.g. the previous rotation's packet)
        other = tmp_path / "previous-packet.json"
        other.write_bytes(startup["packet"].read_bytes())
        rendezvous["handoff"]["path"] = str(other)
    startup["rendezvous"].write_text(json.dumps(rendezvous), encoding="utf-8")
    code, out, _ = startup_ack(stub, startup)
    assert code == 2, out
    checks = {check["name"]: check for check in out["critical_checks"]}
    assert checks["rendezvous_names_packet"]["ok"] is False and checks["packet_sha256"]["ok"] is True
    assert not startup["out"].exists()


def test_startup_ack_requires_the_rendezvous_sha256_and_refuses_changed_bytes(stub, startup):
    code, out, err = startup_ack(stub, startup, rendezvous_sha=False)
    assert code == 2 and out is None and "--rendezvous-sha256" in err
    code, out, _ = startup_ack(stub, startup, rendezvous_sha="0" * 64)
    assert code == 2
    assert {c["name"]: c["ok"] for c in out["critical_checks"]}["rendezvous_awaits_this_host"] is False
    assert not startup["out"].exists()


# --- P3-1: what each subcommand leaves behind on exit 2 -----------------------------------------


def test_help_documents_what_exit_2_leaves_behind_per_subcommand():
    proc = subprocess.run([sys.executable, "-B", "-I", str(TOOL), "--help"], capture_output=True, timeout=60,
                          stdin=subprocess.DEVNULL)
    assert proc.returncode == 0
    page = proc.stdout.decode("utf-8")
    assert "What exit 2 leaves behind" in page
    section = page.split("What exit 2 leaves behind", 1)[1].split("\n\n", 1)[0]
    assert "a session may be running; see record.stop_command" in section
    for command in ("launch", "rebind", "transfer", "startup-ack", "verify-retired"):
        assert command in section


def test_exit_2_from_launch_writes_no_record_before_the_launch_and_one_after(tmp_path, stub, prompt_file):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    refused = tmp_path / ".claude" / "worktrees" / "x"
    refused.mkdir(parents=True)
    spec_path, _ = launch_spec(tmp_path, prompt_file, cwd=str(refused), record_out=str(out_dir / "record.json"))
    code, out, _ = launch(stub, spec_path)
    assert code == 2, out
    assert list(out_dir.iterdir()) == [] and not stub.launched()
    spec_path, spec = launch_spec(tmp_path, prompt_file, record_out=str(out_dir / "record.json"))
    stub.serve("launch.json", {"session": SESSION, "projects": str(tmp_path / "elsewhere"), "assistant": True})
    code, out, _ = launch(stub, spec_path, "--wait-s", "0.2")
    assert code == 2, out
    assert [p.name for p in out_dir.iterdir()] == ["record.json"] and stub.launched()
    record = json.loads((out_dir / "record.json").read_text(encoding="utf-8"))
    assert record["verdict"].startswith("first prompt unverified")
    assert record["stop_command"] == "claude stop " + SESSION[:8]


def test_exit_2_from_the_transfer_cas_leaves_spec_and_transfer_written(tool, rotation, monkeypatch, capsys):
    real = tool.file_ref
    raced = []

    def racing_file_ref(path):
        ref = real(path)
        if Path(path) == rotation["transfer_out"]:  # another custody writer between the transfer write and the CAS
            rotation["custody"].write_bytes(rotation["custody"].read_bytes() + b" ")
            raced.append(rotation["custody"].read_bytes())
        return ref

    monkeypatch.setattr(tool, "file_ref", racing_file_ref)
    code = tool.main(transfer_argv(rotation))
    out = json.loads(capsys.readouterr().out)
    assert code == 2, out
    assert "changed" in out["error"] and raced
    assert rotation["spec_out"].exists() and rotation["transfer_out"].exists()
    assert rotation["custody"].read_bytes() == raced[0]


def test_startup_ack_plan_writes_nothing(stub, startup):
    code, out, _ = startup_ack(stub, startup, "--plan")
    assert code == 0 and out["writes"] == [str(startup["out"])]
    assert not startup["out"].exists()


def test_verify_retired_leaves_a_changed_custody_untouched(tmp_path, stub):
    custody = custody_file(tmp_path)
    before = custody.read_bytes()
    code, out, _ = retired(stub, finished_pid(), custody, expect="0" * 64)
    assert code == 2
    assert custody.read_bytes() == before
