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
