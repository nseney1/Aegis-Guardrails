"""ROOT handoff tooling through its public CLI: first-prompt check, launch, lane health.

No test starts a real claude or Codex session: launch and lanes-health read a stub
``claude`` placed first on PATH that serves recorded fixtures.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hierarchy_root.py"
SESSION = "5daa90d5-59c3-4bc9-ac88-2bd3454167e8"
LAUNCHER_TEXT = ("import hashlib, json, os, subprocess\n" + "x = 1\n" * 400)[:2308]


STUB_DISPATCH = (
    "if os.name == 'nt' and os.environ.get('HIERARCHY_STUB_SCRIPT'):\n"
    " original_run = tool.subprocess.run\n"
    " def run(argv, *args, **kwargs):\n"
    "  if argv[0] == 'claude': argv = [sys.executable, '-I', os.environ['HIERARCHY_STUB_SCRIPT'], *argv[1:]]\n"
    "  return original_run(argv, *args, **kwargs)\n"
    " tool.subprocess = types.SimpleNamespace(**{**vars(tool.subprocess), 'run': run})\n")


# D-P3-1: pytest's tmp_path is under /tmp, which launch refuses as a cwd. Tests replace
# TMP_ROOT inside the tool's own process; the command line has no seam that turns it off.
DRIVER = ("import importlib.util, os, sys, types\n"
          "spec = importlib.util.spec_from_file_location('hierarchy_root', sys.argv[1])\n"
          "tool = importlib.util.module_from_spec(spec)\n"
          "spec.loader.exec_module(tool)\n"
          "if sys.argv[2]: tool.TMP_ROOT = sys.argv[2]\n" + STUB_DISPATCH
          + "sys.exit(tool.main(sys.argv[3:]))\n")


def run_tool(*args, stdin=b"", env=None, timeout=60, cwd=None, tmp_root=None):
    head = [sys.executable, "-B", "-I", str(TOOL)] if tmp_root is None and os.name != "nt" else \
        [sys.executable, "-B", "-I", "-c", DRIVER, str(TOOL), str(tmp_root) if tmp_root is not None else ""]
    proc = subprocess.run([*head, *[str(a) for a in args]], input=stdin,
                          capture_output=True, timeout=timeout, env=env if env is not None else dict(os.environ),
                          cwd=cwd)
    out = proc.stdout.decode("utf-8")
    return proc.returncode, (json.loads(out) if out.strip() else None), proc.stderr.decode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def capability_cli(*args, before="", after="", env=None):
    """Run the public command with only the indicated OS boundary replaced."""
    driver = ("import importlib.util, os, shutil, sys, types\n" + before
              + "spec = importlib.util.spec_from_file_location('hierarchy_root', sys.argv[1])\n"
              "tool = importlib.util.module_from_spec(spec)\n"
              "spec.loader.exec_module(tool)\n" + STUB_DISPATCH + after
              + "sys.exit(tool.main(sys.argv[2:]))\n")
    return subprocess.run([sys.executable, "-B", "-I", "-c", driver, str(TOOL), *map(str, args)],
                          capture_output=True, text=True, timeout=30, env=env)


def test_hash_cli_imports_without_statvfs(tmp_path):
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("No hash tokens.\n", encoding="utf-8")
    result = capability_cli("check-hashes", prompt,
                            before="if hasattr(os, 'statvfs'): del os.statvfs\n")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["ok"] is True


@pytest.mark.parametrize("host,expected", [("nt", 0), ("posix", 4)])
def test_render_flushes_the_file_and_preserves_posix_directory_errors(tmp_path, host, expected):
    template = tmp_path / "template.txt"
    template.write_text("A plain prompt.", encoding="utf-8")
    target, flushed = tmp_path / "out.txt", tmp_path / "file-flushed"
    boundary = ("original_open, original_fsync = os.open, os.fsync\n"
                "def open_file(path, flags, *args, **kwargs):\n"
                " if tool.Path(path).is_dir(): raise PermissionError('directory flush unavailable')\n"
                " return original_open(path, flags, *args, **kwargs)\n"
                "def fsync(fd):\n"
                " original_fsync(fd)\n"
                " tool.Path(%r).write_text('flushed')\n"
                "tool.os = types.SimpleNamespace(**{**vars(os), 'name': %r, 'open': open_file, 'fsync': fsync})\n"
                % (str(flushed), host))
    result = capability_cli("render-prompt", "--template", template, "--out", target, after=boundary)
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert target.read_bytes() == template.read_bytes()
    assert flushed.read_text() == "flushed"
    if host == "posix":
        assert "directory flush unavailable" in json.loads(result.stdout)["error"]


def test_launch_disk_refusal_uses_portable_free_bytes(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    result = capability_cli("launch", "--spec", spec_path, "--min-free-mb", "1", env=stub.env(),
                            before="shutil.disk_usage = lambda path: types.SimpleNamespace(free=0)\n",
                            after="tool.TMP_ROOT = %r\n" % str(stub.tmp_root))
    assert result.returncode == 4, (result.stdout, result.stderr)
    answer = json.loads(result.stdout)
    assert answer["free_bytes"] == 0 and answer["path"] == spec["record_out"]
    assert answer["error"].startswith("free space below --min-free-mb")
    assert not stub.launched() and not Path(spec["record_out"]).exists()


@pytest.mark.parametrize("command", ["verify-retired", "startup-ack"])
def test_process_verification_refuses_an_unsupported_host_before_any_probe(tmp_path, stub, startup, command):
    custody = startup["custody"]
    before = custody.read_bytes()
    if command == "verify-retired":
        args = [command, "--session", OUTGOING, "--pid", "123", "--custody", custody,
                "--expect-custody-sha256", sha(before)]
    else:
        args = [command, "--packet", startup["packet"], "--packet-sha256", sha(startup["packet"].read_bytes()),
                "--rendezvous", startup["rendezvous"], "--rendezvous-sha256", sha(startup["rendezvous"].read_bytes()),
                "--custody", custody, "--tools-pin", startup["pin"], "--role", "ROOT", "--out", startup["out"]]
    result = capability_cli(*args, env={**stub.env(), "CLAUDE_PID": "123"}, after=(
        "def forbidden(*args, **kwargs): raise AssertionError('OS process probe must not run')\n"
        "tool.os = types.SimpleNamespace(**{**vars(os), 'name': 'nt', 'kill': forbidden})\n"))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["error"] == "process verification requires a supported POSIX host"
    assert custody.read_bytes() == before and not startup["out"].exists()
    assert not (stub.dir / "calls.jsonl").exists()


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


def git_marker_above(folder):
    """The first .git in folder or any of its parents, walked as untrusted_cwd_reason walks them."""
    resolved = Path(folder).resolve()
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").exists():
            return parent / ".git"
    return None


# T135: a Codex sandbox can leave an empty .git in each writable root that lacks one (/tmp/.git was
# seen), and launch refuses any cwd with a .git in it or above it, so the launch tests failed with
# "cwd is in a git checkout" for a .git they never made. This module's tmp_path is therefore a root
# with no .git above it; a test that builds its own .git below that root still sees the refusal.
TRUSTED_ROOT_CANDIDATES = (Path("/var/tmp"), Path("/dev/shm"))


@pytest.fixture
def tmp_path(tmp_path):
    """Pytest's tmp_path when no .git is in it or above it, else a fresh folder under a clean candidate."""
    found = git_marker_above(tmp_path)
    if found is None:
        yield tmp_path
        return
    checked = ["%s: %s exists" % (tmp_path, found)]
    for candidate in TRUSTED_ROOT_CANDIDATES:
        if not (candidate.is_dir() and os.access(candidate, os.W_OK | os.X_OK)):
            checked.append("%s: missing or not writable" % candidate)
            continue
        marker = git_marker_above(candidate)
        if marker is not None:
            checked.append("%s: %s exists" % (candidate, marker))
            continue
        root = Path(tempfile.mkdtemp(prefix="t135-root-", dir=candidate))
        try:
            yield root
        finally:
            shutil.rmtree(root)
        return
    pytest.fail("T135: no tmp root without a .git in it or above it, so launch would refuse every test cwd as "
                "'cwd is in a git checkout'. Checked: %s. A Codex sandbox can leave an empty .git in each "
                "writable root: remove the stray .git or set TMPDIR under a folder with none above it."
                % "; ".join(checked), pytrace=False)


@pytest.fixture
def prompt_file(tmp_path):
    path = tmp_path / "prompt.txt"
    path.write_bytes(b"You are a lane.\nDo the brief.\n")
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


def observe_transcript(tool, transcript, prompt_file, monkeypatch):
    monkeypatch.setattr(tool, "agents_rows", lambda: [])
    record = {"id": SESSION[:8]}
    spec = {"prompt": {"path": str(prompt_file), "sha256": sha(prompt_file.read_bytes())}}
    args = SimpleNamespace(projects_dir=transcript.parent.parent, wait_s=0, dialog_wait_s=0, poll_s=0)
    tool.observe_launch(record, spec, args, tool.time.monotonic())
    return record


@pytest.mark.parametrize("torn_tail", [None, '{"type":"assist'])
def test_first_prompt_and_launch_preserve_complete_observations(tool, tmp_path, prompt_file,
                                                              monkeypatch, torn_tail):
    text = prompt_file.read_text(encoding="utf-8")
    records = header_records() + [{"type": "assistant"}, user_record([
        {"type": "text", "text": text[:5]}, {"type": "image", "data": "ignored"},
        {"type": "text", "text": text[5:]}]), user_record("later prompt"), {"type": "assistant"}]
    transcript = write_transcript(tmp_path / "projects" / "-workspace" / (SESSION + ".jsonl"),
                                  records, torn_tail=torn_tail)
    digest = sha(prompt_file.read_bytes())
    expected = {"transcript": str(transcript), "prompt": str(prompt_file), "prompt_sha256": digest,
                "expected_sha256": digest, "first_user_record": {
                    "line": 4, "uuid": "u-1", "timestamp": "2026-11-02T16:00:01.000Z"},
                "torn_tail": torn_tail is not None, "prompt_chars": len(text), "first_prompt_chars": len(text),
                "equals_recorded": True, "prompt_sha256_ok": True, "prefix_matches": True,
                "extra_chars": 0, "extra_head": "", "ok": True}
    code, out, err = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                              "--prompt-sha256", digest)
    assert code == 0 and err == ""
    assert tool.encode_json(out) == tool.encode_json(expected)
    observed = observe_transcript(tool, transcript, prompt_file, monkeypatch)
    assert tool.encode_json(observed) == tool.encode_json({
        "id": SESSION[:8], "transcript": str(transcript), "first_prompt_check": expected,
        "first_assistant_line": 3, "agents_row": None, "session": SESSION})


@pytest.mark.parametrize("consumer", ["first-prompt", "launch"])
def test_prompt_observations_refuse_corruption_after_first_matches(tool, tmp_path, prompt_file,
                                                                monkeypatch, consumer):
    transcript = write_transcript(tmp_path / "projects" / "-workspace" / (SESSION + ".jsonl"),
                                  [user_record(prompt_file.read_text(encoding="utf-8")),
                                   {"type": "assistant"}], torn_tail='NOT JSON\n{}\n')
    with pytest.raises(tool.Failure) as caught:
        if consumer == "first-prompt":
            tool.first_prompt_check(transcript, prompt_file, sha(prompt_file.read_bytes()))
        else:
            observe_transcript(tool, transcript, prompt_file, monkeypatch)
    assert caught.value.code == 2
    assert str(caught.value) == "unparsable JSON at line 3 of %s" % transcript


@pytest.mark.parametrize("bad_text", [0, None])
@pytest.mark.parametrize("corrupt", [False, True])
@pytest.mark.parametrize("consumer", ["first-prompt", "launch"])
def test_malformed_first_user_preserves_refusal_and_launch_evidence(tmp_path, stub, prompt_file,
                                                                 bad_text, corrupt, consumer):
    transcript = write_transcript(stub.projects / "-malformed" / (SESSION + ".jsonl"),
                                  [user_record([{"type": "text", "text": bad_text}])],
                                  torn_tail="NOT JSON\n{}\n" if corrupt else None)
    expected = ("unparsable JSON at line 2 of %s" % transcript if corrupt
                else "text block text must be a string")
    if consumer == "first-prompt":
        code, out, err = run_tool("first-prompt-check", "--transcript", transcript, "--prompt", prompt_file,
                                  "--prompt-sha256", sha(prompt_file.read_bytes()))
        assert code == 2 and err == "", (code, out, err)
        assert out == {"ok": False, "error": expected}
    else:
        spec_path, spec = launch_spec(tmp_path, prompt_file)
        stub.serve("launch.json", {"session": SESSION, "projects": str(tmp_path / "elsewhere"),
                                   "assistant": True})
        code, out, err = launch(stub, spec_path)
        assert code == 2 and err == "", (code, out, err)
        assert out["ok"] is False and stub.launched()
        saved = json.loads(Path(spec["record_out"]).read_text(encoding="utf-8"))
        assert saved == out["record"]
        assert saved["observe_error"] == expected
        assert saved["first_prompt_check"] is None
        assert saved["stop_command"] == "claude stop " + SESSION[:8]
        assert saved["attach_command"] == "claude attach " + SESSION[:8]


@pytest.mark.parametrize("consumer", ["first-prompt", "launch"])
def test_prompt_observations_stream_with_bounded_peak_memory(tool, tmp_path, prompt_file,
                                                          monkeypatch, consumer):
    transcript = write_transcript(tmp_path / "projects" / "-workspace" / (SESSION + ".jsonl"),
                                  [user_record(prompt_file.read_text(encoding="utf-8")),
                                   {"type": "assistant"}])
    padding = json.dumps({"type": "progress", "data": "x" * 1024}) + "\n"
    with transcript.open("a", encoding="utf-8") as stream:
        for _ in range(10000):
            stream.write(padding)
    size = transcript.stat().st_size
    tracemalloc.start()
    try:
        if consumer == "first-prompt":
            check = tool.first_prompt_check(transcript, prompt_file, sha(prompt_file.read_bytes()))
        else:
            observed = observe_transcript(tool, transcript, prompt_file, monkeypatch)
            assert observed["first_assistant_line"] == 2
            check = observed["first_prompt_check"]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert check["ok"] is True and check["torn_tail"] is False
    assert size > 10 * 1024 * 1024
    assert peak < size // 10, (consumer, peak, size)


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
    assert "--source" in out["error"] and repr(value) in out["error"]
    code, out, _ = check_hashes("prompt.txt", cwd=tmp_path)
    assert code == 2 and "check-hashes file" in out["error"] and "prompt.txt" in out["error"]


def render(template, *extra, cwd=None):
    return run_tool("render-prompt", "--template", template, *extra, cwd=cwd)


@pytest.fixture
def template(tmp_path):
    path = tmp_path / "prompt.template"
    path.write_bytes(b"You are a lane.\nYour brief is {path:brief} (sha256 {sha256:brief}).\n"
                     b"Template:\n- {path:role}\n- sha256 {sha256:role}\n")
    return path


@pytest.fixture
def role(tmp_path):
    path = tmp_path / "roles" / "lane.md"
    path.parent.mkdir()
    path.write_text("# Shared lane rules\n", encoding="utf-8")
    return path


def test_render_prompt_fills_paths_and_hashes_and_its_output_passes_check_hashes(tmp_path, template, named, role):
    out_path = tmp_path / "rendered" / "prompt.txt"
    out_path.parent.mkdir()
    code, out, err = render(template, "--path", "brief=%s" % named, "--path", "role=%s" % role, "--out", out_path)
    assert code == 0, (out, err)
    expected = ("You are a lane.\nYour brief is %s (sha256 %s).\nTemplate:\n- %s\n- sha256 %s\n"
                % (named, sha(named.read_bytes()), role, sha(role.read_bytes())))
    assert out_path.read_text(encoding="utf-8") == expected
    assert out["out"] == {"path": str(out_path), "sha256": sha(expected.encode("utf-8"))}
    assert out["filled"] == [{"key": "brief", "path": str(named), "sha256": sha(named.read_bytes())},
                             {"key": "role", "path": str(role), "sha256": sha(role.read_bytes())}]
    code, checked, err = check_hashes(out_path)
    assert code == 0 and checked["tokens"] == 2, (checked, err)
    code, printed, _ = render(template, "--path", "brief=%s" % named, "--path", "role=%s" % role)
    assert code == 0 and printed["text"] == expected and printed["out"] is None


@pytest.mark.parametrize("argument", ["--template", "--path", "--out"])
def test_render_prompt_refuses_a_relative_path_naming_the_argument_and_value(tmp_path, template, named, role,
                                                                             argument):
    args = {"--template": str(template), "brief": str(named), "role": str(role), "--out": str(tmp_path / "o.txt")}
    value = "roles/lane.md" if argument == "--path" else ("prompt.template" if argument == "--template" else "o.txt")
    args["role" if argument == "--path" else argument] = value
    code, out, _ = run_tool("render-prompt", "--template", args["--template"], "--path", "brief=" + args["brief"],
                            "--path", "role=" + args["role"], "--out", args["--out"], cwd=tmp_path)
    assert code == 2, out
    assert argument in out["error"] and value in out["error"]
    assert not (tmp_path / "o.txt").exists()


@pytest.mark.parametrize("problem", ["unused_key", "missing_path", "unknown_kind", "duplicate_key", "bad_key"])
def test_render_prompt_refuses_unknown_unused_and_unfilled_keys(tmp_path, template, named, role, problem):
    extra = ["--path", "brief=%s" % named, "--path", "role=%s" % role]
    if problem == "unused_key":
        extra += ["--path", "spare=%s" % named]
    elif problem == "missing_path":
        extra = extra[:2]
    elif problem == "unknown_kind":
        template.write_text(template.read_text(encoding="utf-8") + "md5 {md5:brief}\n", encoding="utf-8")
    elif problem == "duplicate_key":
        extra += ["--path", "brief=%s" % role]
    else:
        extra += ["--path", "=%s" % named]
    out_path = tmp_path / "o.txt"
    code, out, _ = render(template, *extra, "--out", out_path)
    assert code == 2, out
    word = {"unused_key": "unused", "missing_path": "no --path", "unknown_kind": "unknown placeholder",
            "duplicate_key": "twice", "bad_key": "invalid --path key"}[problem]
    assert word in out["error"]
    assert not out_path.exists()


def test_render_prompt_refuses_an_existing_out_file(tmp_path, template, named, role):
    out_path = tmp_path / "o.txt"
    out_path.write_text("keep\n", encoding="utf-8")
    code, out, _ = render(template, "--path", "brief=%s" % named, "--path", "role=%s" % role, "--out", out_path)
    assert code == 3, out
    assert out_path.read_text(encoding="utf-8") == "keep\n"


@pytest.mark.parametrize("problem", ["typed_hash", "hash_far_from_path"])
def test_render_prompt_refuses_output_that_would_fail_check_hashes(tmp_path, named, problem):
    template = tmp_path / "t.template"
    body = ("Brief {path:brief} (sha256 %s)\n" % FABRICATED if problem == "typed_hash"
            else "Brief {path:brief}\n\nsha256 {sha256:brief}\n")
    template.write_text(body, encoding="utf-8")
    out_path = tmp_path / "o.txt"
    code, out, _ = render(template, "--path", "brief=%s" % named, "--out", out_path)
    assert code == 6, out
    assert out["prompt_hashes"]["unmatched"] and not out_path.exists()


STOP_LINE = 'claude stop "${CLAUDE_CODE_SESSION_ID:0:8}" </dev/null'  # the standard T99 c last action


def test_render_prompt_leaves_shell_expansions_alone_and_its_output_passes_check_hashes(tmp_path, named):
    """P2-1: the T99 c stop line parsed as placeholder kind CLAUDE_CODE_SESSION_ID, so no ROOT prompt rendered."""
    template = tmp_path / "t.template"
    template.write_text("Brief {path:brief} (sha256 {sha256:brief})\nLast action: %s\nAlso ${HOME:-/x} {md5:x}\n"
                        % STOP_LINE, encoding="utf-8")
    out_path = tmp_path / "o.txt"
    code, out, _ = render(template, "--path", "brief=%s" % named, "--out", out_path)
    assert code == 2 and "unknown placeholder kind {md5:x}" in out["error"], out
    template.write_text("Brief {path:brief} (sha256 {sha256:brief})\nLast action: %s\nAlso ${HOME:-/x}\n"
                        % STOP_LINE, encoding="utf-8")
    code, out, err = render(template, "--path", "brief=%s" % named, "--out", out_path)
    assert code == 0, (out, err)
    assert out_path.read_text(encoding="utf-8") == ("Brief %s (sha256 %s)\nLast action: %s\nAlso ${HOME:-/x}\n"
                                                     % (named, sha(named.read_bytes()), STOP_LINE))
    code, checked, err = check_hashes(out_path)
    assert code == 0 and checked["tokens"] == 1 and checked["unmatched"] == [], (checked, err)


def test_check_hashes_counts_only_word_bounded_lowercase_64_hex(tmp_path, named):
    """P3-1: a hash with one character dropped, doubled or uppercased passed unchecked; it is now refused."""
    real = sha(named.read_bytes())
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("git %s, prefix %s, %s and %s\nupper %s\nlong %s\nshort %s\nmixed %s\nedges %s %s\nnone\n"
                      % ("a" * 40, real[:8], "9" * 55, "8" * 73, "A" * 64, "b" * 65, "c" * 63, real[:63] + "F",
                         "d" * 56, "e" * 72), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 6, (out, err)
    assert out["ok"] is False and out["tokens"] == 0 and out["checked"] == [] and out["unmatched"] == []
    assert [(row["line"], row["length"]) for row in out["malformed"]] == [(2, 64), (3, 65), (4, 63), (5, 64),
                                                                          (6, 56), (6, 72)]
    assert "malformed hash-like token" in out["error"] and "line 2" in out["error"]


@pytest.mark.parametrize("shape", ["_%s_", "sha256_%s", "**%s**", "sha256:%s"])
def test_check_hashes_treats_underscore_as_a_token_delimiter(tmp_path, named, shape):
    """P3-1: `\\b` let `_<hex>_` (Markdown emphasis) and `sha256_<hex>` hide a typed hash."""
    real = sha(named.read_bytes())
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Brief %s %s\n" % (named, shape % real), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 0, (out, err)
    assert out["checked"] == [{"token": real, "line": 1, "path": str(named), "via": "same_line"}]
    prompt.write_text("Brief %s %s\n" % (named, shape % FABRICATED), encoding="utf-8")
    code, out, _ = check_hashes(prompt)
    assert code == 6 and [miss["token"] for miss in out["unmatched"]] == [FABRICATED], out


def test_check_hashes_accepts_a_repeat_of_a_token_matched_elsewhere_in_the_file(tmp_path, named):
    """P3-2: a later "send ... sha256 <same hash>" exited 6 although the file already verified it."""
    real = sha(named.read_bytes())
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Send sha256 %s first.\n\nBrief %s (sha256 %s)\n\nThen send sha256 %s.\nTyped %s twice %s\n"
                      % (real, named, real, real, FABRICATED, FABRICATED), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 6, (out, err)
    assert out["checked"] == [
        {"token": real, "line": 1, "path": str(named), "via": "repeat", "match_line": 3},
        {"token": real, "line": 3, "path": str(named), "via": "same_line"},
        {"token": real, "line": 5, "path": str(named), "via": "repeat", "match_line": 3}]
    assert [(miss["token"], miss["line"]) for miss in out["unmatched"]] == [(FABRICATED, 6), (FABRICATED, 6)]


@pytest.mark.parametrize("kind", ["symlink", "directory", "missing"])
def test_check_hashes_follows_a_symlinked_candidate_and_refuses_a_directory_or_missing_one(tmp_path, named, kind):
    """P3-4: a folder beside a hash never counts (the review-copy case); symlinks are followed (P3-3)."""
    real = sha(named.read_bytes())
    candidate = tmp_path / {"symlink": "link.md", "directory": "folder", "missing": "gone.md"}[kind]
    if kind == "symlink":
        candidate.symlink_to(named)
    elif kind == "directory":
        candidate.mkdir()
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Brief %s (sha256 %s)\n" % (candidate, real), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    if kind == "symlink":
        assert code == 0, (out, err)
        assert out["checked"] == [{"token": real, "line": 1, "path": str(candidate), "via": "same_line"}]
        return
    assert code == 6, (out, err)
    [miss] = out["unmatched"]
    error = "not a regular file"
    if kind == "missing":
        # Windows' native FileNotFoundError text differs from C's errno message.
        with pytest.raises(FileNotFoundError) as missing:
            candidate.stat()
        assert missing.value.errno == errno.ENOENT
        error = missing.value.strerror
    assert miss["candidates"] == [{"path": str(candidate), "line": 1, "sha256": None, "error": error}]


def test_check_hashes_never_takes_the_last_line_as_the_line_above_line_1(tmp_path, named):
    """P3-4: without the at >= 0 guard, line 1's "line above" would be lines[-1]."""
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("sha256 %s\nmiddle\nBrief %s" % (sha(named.read_bytes()), named), encoding="utf-8")
    code, out, err = check_hashes(prompt)
    assert code == 6, (out, err)
    assert [(miss["line"], miss["candidates"]) for miss in out["unmatched"]] == [(1, [])]


@pytest.mark.parametrize("kind", ["fifo", "directory", "oversized", "symlink"])
def test_check_hashes_and_render_prompt_refuse_a_non_regular_or_oversized_input(tmp_path, named, kind):
    """P3-3: Path.read_bytes() blocked forever on a FIFO and read /dev/zero without bound."""
    target = tmp_path / "input.txt"
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("this host cannot create a POSIX FIFO")
        os.mkfifo(target)
    elif kind == "directory":
        target.mkdir()
    elif kind == "oversized":
        target.write_text("x" * 262145, encoding="utf-8")
    else:
        real = tmp_path / "real.txt"
        real.write_text("Brief {path:brief}\n", encoding="utf-8")
        target.symlink_to(real)
    word = {"fifo": "regular file", "directory": "regular file", "oversized": "exceeds 262144 bytes",
            "symlink": "symlink"}[kind]
    code, out, _ = run_tool("check-hashes", target, timeout=20)
    assert code == 2 and "check-hashes file" in out["error"] and word in out["error"], out
    out_path = tmp_path / "o.txt"
    code, out, _ = run_tool("render-prompt", "--template", target, "--path", "brief=%s" % named, "--out", out_path,
                            timeout=20)
    assert code == 2 and "--template" in out["error"] and word in out["error"], out
    assert not out_path.exists()


# --- stub claude ------------------------------------------------------------------------------

STUB = r'''
import json, os, pathlib, sys
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
d = pathlib.Path(os.environ["HIERARCHY_STUB_DIR"])
argv = sys.argv[1:]
with (d / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps(argv[:2]) + "\n")
if argv[:2] == ["agents", "--json"]:
    after = d / "agents-after.json"
    source = after if (d / "launched").exists() and after.exists() else d / "agents.json"
    sys.stdout.write(source.read_text(encoding="utf-8") if source.exists() else "[]")
    sys.exit(0)
if argv[:1] == ["logs"]:
    (d / "logs-args.json").write_text(json.dumps(argv))
    logs = d / "logs.txt"
    sys.stdout.write(logs.read_text(encoding="utf-8") if logs.exists() else "")
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
    folder = pathlib.Path(cfg["projects"]) / os.getcwd().replace("/", "-").replace("\\", "-").replace(":", "-")
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
        # Launch tests refuse cwds under this folder instead of /tmp (see DRIVER, D-P3-1).
        self.tmp_root = tmp_path / "tmp-root"

    def env(self):
        return {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                "HIERARCHY_STUB_SCRIPT": str(self.bin / "claude"),
                "HIERARCHY_STUB_DIR": str(self.dir), "CLAUDE_CODE_SESSION_ID": "parent-session",
                "CLAUDE_PID": "1"}

    def serve(self, name, value):
        (self.dir / name).write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")

    def launched(self):
        return (self.dir / "argv.json").exists()


@pytest.fixture
def stub(tmp_path):
    return Stub(tmp_path)


@pytest.fixture(params=[False, True], ids=["native", "windows-dispatch"])
def capability_host(request, stub):
    env, before = stub.env(), ""
    if request.param:
        # Replace the driver's reference only; pathlib and subprocess keep the real OS.
        before = "os = types.SimpleNamespace(**{**vars(os), 'name': 'nt'})\n"
        # Without the dispatch shim, no executable host can be reached on this PATH.
        env["PATH"] = str(stub.dir)
    return {"env": env, "before": before}


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
                    *extra, stdin=stdin, env=stub.env(), tmp_root=stub.tmp_root)


def test_launch_has_no_tmp_seam_on_its_command_line(tmp_path, stub, prompt_file):
    """D-P3-1: --test-tmp-root turned the /tmp refusal off in production and left no trace."""
    for argv in (["--help"], ["launch", "--help"]):
        proc = subprocess.run([sys.executable, "-B", "-I", str(TOOL), *argv], capture_output=True, timeout=60,
                              stdin=subprocess.DEVNULL)
        assert proc.returncode == 0 and b"tmp-root" not in proc.stdout and b"Test-only" not in proc.stdout
    spec_path, _ = launch_spec(tmp_path, prompt_file)
    code, out, err = run_tool("launch", "--spec", spec_path, "--plan", "--test-tmp-root", tmp_path, env=stub.env())
    assert code == 2 and out is None and "unrecognized arguments: --test-tmp-root" in err
    assert not stub.launched()


def test_launch_checks_free_space_before_probing_the_record_folder(tmp_path, stub, prompt_file):
    """D-P3-6: exit 4's "checked before the first write" held only while the probe came second."""
    spec_path, spec = launch_spec(tmp_path, prompt_file, record_out=str(tmp_path / "missing" / "record.json"))
    code, out, _ = run_tool("launch", "--spec", spec_path, "--projects-dir", stub.projects,
                            "--min-free-mb", str(10 ** 12), env=stub.env(), tmp_root=stub.tmp_root)
    assert code == 4, out
    assert out["error"].startswith("free space below --min-free-mb")
    assert not stub.launched()


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


def test_launch_refuses_an_unmatched_hash_in_the_prompt_and_starts_nothing(tmp_path, stub, named):
    """T92: the C7 prompt carried a typed hash; launch must refuse before claude is called at all."""
    prompt = tmp_path / "typed-prompt.txt"
    prompt.write_text("You are a lane.\nBrief %s (sha256 %s)\n" % (named, FABRICATED), encoding="utf-8")
    spec_path, spec = launch_spec(tmp_path, prompt)
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True})
    stub.serve("agents-after.json", [agent_row(SESSION, LANE)])
    for extra in (["--plan"], []):
        code, out, _ = launch(stub, spec_path, *extra)
        assert code == 6, out
        assert "nothing launched" in out["error"] and "line 2" in out["error"]
        [miss] = out["prompt_hashes"]["unmatched"]
        assert miss["token"] == FABRICATED and miss["candidates"][0]["sha256"] == sha(named.read_bytes())
    assert not stub.launched() and not Path(spec["record_out"]).exists()
    assert not (stub.dir / "calls.jsonl").exists()


def test_launch_records_every_checked_hash_pair(tmp_path, stub, named):
    source = tmp_path / "checkpoint.json"
    source.write_text('{"checkpoint": 1}\n', encoding="utf-8")
    prompt = tmp_path / "hashed-prompt.txt"
    prompt.write_text("You are a lane.\nBrief %s\n(sha256 %s)\nCheckpoint sha256 %s.\n"
                      % (named, sha(named.read_bytes()), sha(source.read_bytes())), encoding="utf-8")
    spec_path, spec = launch_spec(tmp_path, prompt, hash_sources=[str(source)])
    stub.serve("launch.json", {"session": SESSION, "projects": str(stub.projects), "assistant": True})
    stub.serve("agents-after.json", [agent_row(SESSION, LANE)])
    code, out, _ = launch(stub, spec_path, "--plan")
    assert code == 0 and out["prompt_hashes"]["tokens"] == 2, out
    code, out, err = launch(stub, spec_path)
    assert code == 0, (out, err)
    record = json.loads(Path(spec["record_out"]).read_text(encoding="utf-8"))
    assert record["prompt_hashes"]["checked"] == [
        {"token": sha(named.read_bytes()), "path": str(named), "line": 3, "via": "line_above"},
        {"token": sha(source.read_bytes()), "path": str(source), "line": 4, "via": "source"}]
    assert record["prompt_hashes"]["sources"] == [{"path": str(source), "sha256": sha(source.read_bytes())}]


def test_launch_refuses_a_relative_hash_source(tmp_path, stub, prompt_file):
    spec_path, _ = launch_spec(tmp_path, prompt_file, hash_sources=["checkpoint.json"])
    code, out, _ = launch(stub, spec_path, "--plan")
    assert code == 2 and "hash_sources entry" in out["error"] and "checkpoint.json" in out["error"], out
    assert not stub.launched()


def test_launch_and_check_hashes_refuse_an_unhashable_source_naming_their_own_argument(tmp_path, stub, prompt_file):
    """P3-4, P3-5: launch reported a missing hash_sources entry as "--source ... cannot be hashed"."""
    missing = tmp_path / "missing-checkpoint.json"
    spec_path, spec = launch_spec(tmp_path, prompt_file, hash_sources=[str(missing)])
    for extra in (["--plan"], []):
        code, out, _ = launch(stub, spec_path, *extra)
        assert code == 2, out
        assert out["error"].startswith("hash_sources entry %s cannot be hashed" % missing), out
    assert not stub.launched() and not Path(spec["record_out"]).exists()
    assert not (stub.dir / "calls.jsonl").exists()
    code, out, _ = check_hashes(prompt_file, "--source", missing)
    assert code == 2 and out["error"].startswith("--source %s cannot be hashed" % missing), out


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
        if not hasattr(os, "geteuid"):
            pytest.skip("this test requires POSIX directory permission bits")
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
    root = tempfile.gettempdir() if os.name == "nt" else "/tmp"
    # The default-root refusal runs before launch and does not require an existing cwd.
    cwd = Path(root) / tmp_path.name
    spec_path, spec = launch_spec(tmp_path, prompt_file, cwd=str(cwd))
    code, out, _ = run_tool("launch", "--spec", spec_path, "--plan", env=stub.env())
    assert code == 2, out
    assert "under %s" % Path(root).resolve() in out["error"]


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
    transcript = stub.projects / "leaked-first-prompt" / (SESSION + ".jsonl")
    write_transcript(transcript, [user_record(prompt_file.read_text(encoding="utf-8") + LAUNCHER_TEXT)])
    stub.serve("launch.json", {"session": SESSION, "projects": str(tmp_path / "elsewhere"), "assistant": True})
    code, out, err = launch(stub, spec_path)
    assert code == 2, (out, err)
    record = json.loads(Path(spec["record_out"]).read_text(encoding="utf-8"))
    assert record["first_prompt_check"] is not None, (out, err, record)
    assert record["first_prompt_check"]["extra_chars"] == 2308
    assert record["stop_command"] == "claude stop " + SESSION[:8]


def test_launch_refuses_when_free_space_is_below_the_threshold(tmp_path, stub, prompt_file):
    spec_path, spec = launch_spec(tmp_path, prompt_file)
    code, out, _ = run_tool("launch", "--spec", spec_path, "--projects-dir", stub.projects,
                            "--min-free-mb", str(10 ** 12), env=stub.env(), tmp_root=stub.tmp_root)
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


def test_lanes_health_streams_a_large_transcript_with_bounded_peak_memory(stub, capability_host):
    path = stub.projects / "-large" / (SESSION + ".jsonl")
    path.parent.mkdir(parents=True)
    record = json.dumps(user_record("x" * 1024)) + "\n"
    with path.open("w", encoding="utf-8") as stream:
        for _ in range(10000):
            stream.write(record)
        stream.write(json.dumps(request("2026-11-02T16:35:00.000Z", "last-request")) + "\n")
        stream.write(json.dumps(queue(NOW, "enqueue", "pending notice")) + "\n")
    stub.serve("agents.json", [])
    result = capability_cli("lanes-health", "--projects-dir", stub.projects, "--now", NOW,
                            "--session", SESSION, **capability_host, after=(
        "import atexit, tracemalloc\n"
        "tracemalloc.start()\n"
        "atexit.register(lambda: print(tracemalloc.get_traced_memory()[1], file=sys.stderr))\n"))
    assert result.returncode == 0, (result.stdout, result.stderr)
    calls = stub.dir / "calls.jsonl"
    assert calls.is_file(), result.stdout
    assert [json.loads(line) for line in calls.read_text().splitlines()] == [["agents", "--json"]]
    row = json.loads(result.stdout)["sessions"][0]
    assert row["last_record_ts"] == NOW and row["open_request_id"] == "last-request"
    assert row["stalled"] is True and row["silent"] is False
    assert row["enqueued_notices"] == [{"timestamp": NOW, "head": "pending notice"}]
    peak = int(result.stderr.strip())
    assert path.stat().st_size > 10 * 1024 * 1024
    assert peak < 2 * 1024 * 1024, peak


@pytest.mark.parametrize("tail", [b"", b"\n \t\r\n"])
def test_lanes_health_reports_a_torn_last_nonblank_line(lanes, tail):
    path = lanes.projects / "-home-x-workspace" / (IDS["torn"] + ".jsonl")
    with path.open("ab") as stream:
        stream.write(tail)
    row = health(lanes, "torn")["torn"]
    assert row["torn_tail"] is True and "error" not in row
    assert row["last_record_ts"] == "2026-11-02T16:58:30.000Z"


@pytest.mark.parametrize("later", [b'{"type":"assistant"}', b"also invalid"])
def test_lanes_health_reports_late_corruption_without_partial_activity(lanes, later):
    path = lanes.projects / "-home-x-workspace" / (IDS["stalled"] + ".jsonl")
    with path.open("ab") as stream:
        stream.write(b'\n{"secret-input":\n \t\n' + later + b"\n")
    row = health(lanes, "stalled")["stalled"]
    assert row["error"] == "unparsable JSON at line 4 of %s" % path
    assert row["torn_tail"] is False
    assert row["last_record_ts"] is None and row["open_request_id"] is None
    assert row["enqueued_notices"] == [] and row["stalled"] is False


def test_lanes_health_reports_a_deferred_transcript_read_error(lanes, capability_host):
    result = capability_cli("lanes-health", "--projects-dir", lanes.projects, "--now", NOW,
                            "--session", IDS["stalled"], **capability_host, after=(
        "original_open = open\n"
        "class BrokenTranscript:\n"
        " def __enter__(self): return self\n"
        " def __exit__(self, *args): pass\n"
        " def read(self, *args): raise OSError('transcript read failed')\n"
        " def __iter__(self):\n"
        "  yield b'{\"type\":\"api-request\",\"timestamp\":\"2026-11-02T16:35:00.000Z\"}\\n'\n"
        "  raise OSError('transcript read failed')\n"
        "tool.open = lambda path, *args, **kwargs: (BrokenTranscript() if str(path).endswith('.jsonl')\n"
        "                                         else original_open(path, *args, **kwargs))\n"))
    assert result.returncode == 0, (result.stdout, result.stderr)
    calls = lanes.dir / "calls.jsonl"
    assert calls.is_file(), result.stdout
    assert [json.loads(line) for line in calls.read_text().splitlines()] == [["agents", "--json"]]
    row = json.loads(result.stdout)["sessions"][0]
    assert row["error"] == "transcript read failed" and row["torn_tail"] is False
    assert row["last_record_ts"] is None and row["open_request_id"] is None
    assert row["enqueued_notices"] == [] and row["stalled"] is False


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


@pytest.mark.parametrize("consume_first", [False, True])
def test_read_jsonl_drains_early_reducers_before_returning(tool, tmp_path, consume_first):
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"a":1}\nNOT JSON\n{"b":2}\n{"c":')
    with pytest.raises(tool.Failure) as listed:
        tool.read_jsonl(path)
    with pytest.raises(tool.Failure) as reduced:
        tool.read_jsonl(path, reduce_rows=lambda rows: next(rows, None) if consume_first else None)
    assert reduced.value.code == listed.value.code == 2
    assert str(reduced.value) == str(listed.value) == "unparsable JSON at line 2 of %s" % path


@pytest.mark.parametrize("corrupt", [False, True])
def test_read_jsonl_drains_after_reducer_failures_and_closes_stream(tool, tmp_path, monkeypatch, corrupt):
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"a":1}\n' + (b'NOT JSON\n' if corrupt else b'{"b":2}\n') + b'{}\n')
    opened = []

    def track_open(*args, **kwargs):
        stream = open(*args, **kwargs)
        opened.append(stream)
        return stream

    monkeypatch.setattr(tool, "open", track_open, raising=False)

    def fail(rows):
        next(rows)
        raise TypeError("synthetic reducer failure")

    expected = tool.Failure if corrupt else TypeError
    with pytest.raises(expected) as caught:
        tool.read_jsonl(path, reduce_rows=fail)
    if corrupt:
        assert caught.value.code == 2
        assert str(caught.value) == "unparsable JSON at line 2 of %s" % path
    else:
        assert str(caught.value) == "synthetic reducer failure"
    assert len(opened) == 1 and opened[0].closed


@pytest.mark.parametrize("reduce_rows", [
    lambda rows: rows,
    lambda rows: (row for row in rows),
    lambda rows: map(lambda row: row, rows),
    lambda rows: filter(None, rows),
], ids=["same-iterator", "generator", "map", "filter"])
def test_read_jsonl_refuses_lazy_reducer_results(tool, tmp_path, reduce_rows):
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"a":1}\n{"b":2}\n')
    with pytest.raises(TypeError, match="^reduce_rows must return a materialised value, not an iterator$"):
        tool.read_jsonl(path, reduce_rows=reduce_rows)


@pytest.mark.parametrize("consume_first", [False, True])
@pytest.mark.parametrize("tail", [b'{"c":', b'NOT JSON\n \t\r\n'])
def test_read_jsonl_early_reducers_report_or_refuse_torn_tails(tool, tmp_path, consume_first, tail):
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"a":1}\n{"b":2}\n' + tail)

    def reduce_rows(rows):
        return next(rows, None) if consume_first else None

    expected = (1, {"a": 1}) if consume_first else None
    assert tool.read_jsonl(path, reduce_rows=reduce_rows) == (expected, True)
    with pytest.raises(tool.Failure) as caught:
        tool.read_jsonl(path, tolerate_torn_tail=False, reduce_rows=reduce_rows)
    assert caught.value.code == 2
    assert str(caught.value) == "unparsable JSON at line 3 of %s" % path


@pytest.mark.parametrize("body,expected,torn", [
    (b" \n\t\r\n", [], False),
    (b'\n{"a":1}\r\n\t\n[2]\nnull\ntrue',
     [(2, {"a": 1}), (4, [2]), (5, None), (6, True)], False),
    (b'{"a":1}\n\xff\n \r\n', [(1, {"a": 1})], True),
])
def test_read_jsonl_preserves_line_numbers_values_and_blank_tail(tool, tmp_path, body, expected, torn):
    path = tmp_path / "t.jsonl"
    path.write_bytes(body)
    assert tool.read_jsonl(path) == (expected, torn)
    if torn:
        with pytest.raises(tool.Failure, match="^unparsable JSON at line 2 of ") as caught:
            tool.read_jsonl(path, tolerate_torn_tail=False)
        assert caught.value.code == 2


@pytest.mark.parametrize("middle,refused", [
    ('{"type":"assistant"}\n'.encode("utf-16-be"), True),
    (b"1\x00\n", False),
], ids=["utf16-assistant", "utf16-scalar"])
@pytest.mark.parametrize("consumer", ["list", "health"])
def test_transcript_callers_parse_exactly_the_split_bytes(tool, lanes, middle, refused, consumer):
    path = lanes.projects / "-home-x-workspace" / (IDS["stalled"] + ".jsonl")
    first = request("2026-11-02T16:35:00.000Z", "r1")
    path.write_bytes(json.dumps(first).encode() + b"\n" + middle + b'{"type":"user"}\n')
    error = "unparsable JSON at line 2 of %s" % path
    if consumer == "list":
        if refused:
            with pytest.raises(tool.Failure) as caught:
                tool.read_jsonl(path)
            assert caught.value.code == 2 and str(caught.value) == error
        else:
            assert tool.read_jsonl(path) == ([(1, first), (2, 1), (3, {"type": "user"})], False)
    else:
        row = health(lanes, "stalled")["stalled"]
        if refused:
            assert row["error"] == error and row["torn_tail"] is False
            assert row["last_record_ts"] is None and row["open_request_id"] is None
        else:
            assert "error" not in row and row["torn_tail"] is False
            assert row["open_request_id"] == "r1" and row["stalled"] is True


@pytest.mark.parametrize("consumer", ["list", "health"])
def test_transcript_callers_tolerate_a_live_unterminated_tail(tool, lanes, monkeypatch, consumer):
    path = lanes.projects / "-home-x-workspace" / (IDS["stalled"] + ".jsonl")
    first = request("2026-11-02T16:35:00.000Z", "r1")

    class GrowingTranscript:
        def __init__(self):
            self.lines = iter((json.dumps(first).encode() + b"\n", b'{"type":"assist', b'ant"}\n'))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def __iter__(self):
            return self

        def __next__(self):
            return next(self.lines)

    monkeypatch.setattr(tool, "open", lambda *args, **kwargs: GrowingTranscript(), raising=False)
    if consumer == "list":
        assert tool.read_jsonl(path) == ([(1, first)], True)
        with pytest.raises(tool.Failure) as caught:
            tool.read_jsonl(path, tolerate_torn_tail=False)
        assert caught.value.code == 2
        assert str(caught.value) == "unparsable JSON at line 2 of %s" % path
    else:
        args = tool.build_parser().parse_args(["lanes-health", "--projects-dir", str(lanes.projects),
                                               "--session", IDS["stalled"]])
        row = tool.lane_health(IDS["stalled"], "stalled", [], args, tool.parse_utc(NOW))
        assert row["torn_tail"] is True and "error" not in row
        assert row["open_request_id"] == "r1" and row["stalled"] is True


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
        free = 100 * 1024 * 1024

    target = tmp_path / "missing-folder" / "ack.json"
    assert failure_code(tool, lambda: tool.check_free_space([target], 512, disk_usage=lambda _: Stats)) == 4
    assert tool.check_free_space([target], 64, disk_usage=lambda _: Stats) is None
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
    entry["outgoing_stopped"] = {"verified_at": "2026-11-02T17:00:00.000Z", "by": "hierarchy_root.py verify-retired",
                                 "evidence": {"pid_alive": False, "agents_listed": False}}
    custody.write_text(json.dumps({"active_root_session": spec["session"], "custody_history": [entry]}),
                       encoding="utf-8")
    code, out, _ = rebind(spec_path, tmp_path / "result-2.json", acks, "--custody", custody)
    assert code == 0 and out["outgoing_stop"]["verified"] is True and out["warnings"] == []


@pytest.mark.parametrize("stopped", [True, "pending", {"by": "hierarchy_root.py verify-retired"},
                                     {"by": "by hand", "evidence": {"pid_alive": False, "agents_listed": False}},
                                     {"by": "hierarchy_root.py verify-retired",
                                      "evidence": {"pid_alive": True, "agents_listed": False}}])
def test_rebind_counts_only_a_verify_retired_record_as_the_outgoing_stop(tmp_path, stopped):
    """D-P3-3: a hand-written outgoing_stopped: true read as verified, the P3-9 assertion moved into custody."""
    _, _, spec, spec_path, acks = rebind_setup(tmp_path, messages=1)
    custody = tmp_path / "custody.json"
    custody.write_text(json.dumps({"active_root_session": spec["session"], "custody_history": [
        {"outgoing_root": "d6b2a18b-e242-4ecb-ac63-baab549cf112", "incoming_root": spec["session"],
         "outgoing_stopped": stopped}]}), encoding="utf-8")
    code, out, err = rebind(spec_path, tmp_path / "result.json", acks, "--plan", "--custody", custody)
    assert code == 0, (out, err)
    assert out["outgoing_stop"]["verified"] is False
    assert len(out["warnings"]) == 1 and "verify-retired" in out["warnings"][0]


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


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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


def test_transfer_next_names_the_outgoing_stop_recheck(rotation):
    """D-P3-2: rebind's warning fires on every rotation in the tool's own order; the re-check tells them apart."""
    code, out, err = transfer(rotation)
    assert code == 0, (out, err)
    assert "rebind --plan --spec %s" % rotation["spec_out"] in out["next"]
    assert "--custody %s" % rotation["custody"] in out["next"]
    assert "outgoing_stop.verified: true" in out["next"]


@pytest.mark.parametrize("bad", ["history_not_a_list", "handoff_not_an_object"])
def test_transfer_checks_custody_shapes_before_its_first_write(rotation, bad):
    """D-P3-6: these failed only inside the final CAS, after spec and transfer were written."""
    custody = json.loads(rotation["custody"].read_text(encoding="utf-8"))
    if bad == "history_not_a_list":
        custody["custody_history"] = {}
    else:
        custody["claude_c5_to_c6_handoff"] = "prepared"
    rotation["custody"].write_text(json.dumps(custody), encoding="utf-8")
    before = rotation["custody"].read_bytes()
    code, out, _ = transfer(rotation)
    assert code == 2, out
    assert rotation["custody"].read_bytes() == before
    assert not rotation["spec_out"].exists() and not rotation["transfer_out"].exists()


def help_page(*argv):
    proc = subprocess.run([sys.executable, "-B", "-I", str(TOOL), *argv, "--help"], capture_output=True, timeout=60,
                          stdin=subprocess.DEVNULL)
    assert proc.returncode == 0
    return " ".join(proc.stdout.decode("utf-8").split())


def test_transfer_help_says_the_ack_must_come_from_startup_ack():
    """D-P3-5: ROOTs hand-wrote ACKs; the tempting fix was a hand-written critical_checks entry."""
    for page in (help_page("transfer"), help_page()):
        assert "the ACK startup-ack wrote; hand-written ACKs are refused" in page


def test_help_says_a_launch_without_a_parsed_id_has_no_stop_command():
    """D-P3-6: after a claude --bg timeout a session may run although the record has no stop_command."""
    page = help_page()
    assert "no stop_command" in page and "claude agents" in page
    assert "custody_history is not a list" in page


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


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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
@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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
@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
def test_transfer_accepts_the_ack_startup_ack_writes(stub, startup, rotation):
    """D-P3-4: transfer was tested only with a hand-built ACK; a rename on either side passed both suites.

    Both fixtures use the same tmp_path, so they share packet.json (same bytes) and custody.json
    (rotation's, which still names OUTGOING); the rendezvous names that packet.
    """
    code, out, err = startup_ack(stub, startup)
    assert code == 0, (out, err)
    rotation["ack"] = startup["out"]
    code, out, err = transfer(rotation)
    assert code == 0, (out, err)
    record = json.loads(rotation["transfer_out"].read_text(encoding="utf-8"))
    assert record["incoming"]["startup_ack"] == {"path": str(startup["out"]), "sha256": sha(startup["out"].read_bytes())}


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
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


@pytest.mark.skipif(os.name != "posix", reason="real process verification requires POSIX signal semantics")
def test_verify_retired_leaves_a_changed_custody_untouched(tmp_path, stub):
    custody = custody_file(tmp_path)
    before = custody.read_bytes()
    code, out, _ = retired(stub, finished_pid(), custody, expect="0" * 64)
    assert code == 2
    assert custody.read_bytes() == before
