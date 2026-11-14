"""The active-time meter reads real transcript shapes and never invents the end of a turn."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT


METER = ROOT / "tools" / "hierarchy_meter.py"
SESSION = "01a19a29-d635-7411-8529-9efedafc0881"


def stamp(seconds):
    return "2026-11-02T%02d:%02d:%02d.000Z" % (seconds // 3600, seconds % 3600 // 60, seconds % 60)


def meter(*arguments, expect=0, env=None):
    result = subprocess.run([sys.executable, "-I", str(METER), *arguments], capture_output=True, text=True, timeout=20,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})})
    assert not result.stderr, result.stderr
    assert result.returncode == expect, result.stdout
    return json.loads(result.stdout)


def write_lines(path, rows):
    path.write_text("".join((row if isinstance(row, str) else json.dumps(row)) + "\n" for row in rows), encoding="utf-8")
    return path


def codex_event(seconds, kind):
    return {"timestamp": stamp(seconds), "type": "event_msg", "payload": {"type": kind}}


def claude_prompt(seconds, text="Do the work."):
    return {"type": "user", "timestamp": stamp(seconds), "message": {"role": "user", "content": text}}


def claude_tool_result(seconds):
    return {"type": "user", "timestamp": stamp(seconds),
            "message": {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]}}


def claude_reply(seconds):
    return {"type": "assistant", "timestamp": stamp(seconds), "message": {"role": "assistant", "content": []}}


def run_codex(tmp_path, rows, *flags, expect=0):
    path = write_lines(tmp_path / "rollout.jsonl", rows)
    return meter("--host", "codex-cli", "--session", SESSION, "--transcript", str(path), *flags, expect=expect)


def run_claude(tmp_path, rows, *flags, expect=0):
    path = write_lines(tmp_path / "transcript.jsonl", rows)
    return meter("--host", "claude-code", "--session", SESSION, "--transcript", str(path), *flags, expect=expect)


def test_codex_time_is_the_sum_of_finished_turns_and_idle_time_does_not_count(tmp_path):
    result = run_codex(tmp_path, [
        {"timestamp": stamp(0), "type": "session_meta", "payload": {}},
        codex_event(10, "task_started"), codex_event(70, "token_count"), codex_event(130, "task_complete"),
        codex_event(1000, "task_started"), codex_event(1060, "task_complete")])
    assert result["active_seconds"] == 180
    assert result["turns"] == 2 and result["unknown_intervals"] == []
    assert result["state"] == "ok"


def test_an_aborted_codex_turn_ends_where_it_was_aborted(tmp_path):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(50, "turn_aborted")])
    assert result["active_seconds"] == 50 and result["unknown_intervals"] == []


def test_a_codex_turn_with_no_end_stays_unknown(tmp_path):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(40, "task_complete"),
                                  codex_event(100, "task_started"), codex_event(160, "token_count")])
    assert result["active_seconds"] == 40
    assert result["unknown_intervals"] == [{"started_at": stamp(100), "last_record_at": stamp(160)}]
    assert result["open_turn"] is True


def test_an_earlier_codex_turn_with_no_end_stays_unknown_and_later_turns_still_count(tmp_path):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(30, "token_count"),
                                  codex_event(500, "task_started"), codex_event(520, "task_complete")])
    assert result["active_seconds"] == 20
    assert result["unknown_intervals"] == [{"started_at": stamp(0), "last_record_at": stamp(30)}]
    assert result["open_turn"] is False


def test_claude_time_runs_from_each_prompt_to_its_last_record_and_tool_results_are_not_prompts(tmp_path):
    result = run_claude(tmp_path, [
        claude_prompt(0), claude_reply(10), claude_tool_result(20), claude_reply(90),
        claude_prompt(1000), claude_reply(1030)])
    assert result["active_seconds"] == 120
    assert result["turns"] == 2 and result["open_turn"] is False


def test_bookkeeping_before_the_next_prompt_does_not_extend_the_last_turn_across_idle_time(tmp_path):
    result = run_claude(tmp_path, [
        claude_prompt(0), claude_reply(10),
        {"type": "queue-operation", "timestamp": stamp(900)}, {"type": "attachment", "timestamp": stamp(901)},
        claude_prompt(905), claude_reply(910), {"type": "system", "subtype": "away_summary", "timestamp": stamp(2000)}])
    assert result["active_seconds"] == 15


def test_a_turn_ending_on_a_tool_result_counts_to_that_result(tmp_path):
    assert run_claude(tmp_path, [claude_prompt(0), claude_reply(10), claude_tool_result(40)])["active_seconds"] == 40


def test_a_long_claude_turn_is_counted_in_full(tmp_path):
    assert run_claude(tmp_path, [claude_prompt(0), claude_reply(900)])["active_seconds"] == 900


def test_a_claude_prompt_with_no_reply_stays_unknown(tmp_path):
    result = run_claude(tmp_path, [claude_prompt(0), claude_reply(30), claude_prompt(100)])
    assert result["active_seconds"] == 30
    assert result["unknown_intervals"] == [{"started_at": stamp(100), "last_record_at": stamp(100)}]
    assert result["open_turn"] is True


def test_records_without_timestamps_and_meta_prompts_are_ignored(tmp_path):
    result = run_claude(tmp_path, [
        {"type": "user", "isMeta": True, "timestamp": stamp(0), "message": {"content": "caveat"}},
        claude_prompt(10), {"type": "ai-title", "aiTitle": "x"}, claude_reply(20)])
    assert result["active_seconds"] == 10 and result["turns"] == 1


@pytest.mark.parametrize("seconds,state,code", [(2879, "ok", 0), (2880, "rotate_soon", 0), (3599, "rotate_soon", 0),
                                                (3600, "rotate_now", 3), (4000, "rotate_now", 3)])
def test_a_session_rotates_after_60_active_minutes(tmp_path, seconds, state, code):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(seconds, "task_complete")], expect=code)
    assert result["state"] == state and result["limit"] == 3600


@pytest.mark.parametrize("seconds,state,code", [(4319, "ok", 0), (4320, "rotate_soon", 0), (5399, "rotate_soon", 0),
                                                (5400, "rotate_now", 3), (6000, "rotate_now", 3)])
def test_root_rotates_after_90_active_minutes(tmp_path, seconds, state, code):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(seconds, "task_complete")], "--role", "root", expect=code)
    assert result["state"] == state and result["limit"] == 5400


def test_unknown_time_that_could_reach_the_limit_warns_without_claiming_the_limit_was_hit(tmp_path):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(3600, "token_count")])
    assert result["active_seconds"] == 0 and result["state"] == "rotate_soon"


def test_limits_can_be_set_and_are_validated(tmp_path):
    result = run_codex(tmp_path, [codex_event(0, "task_started"), codex_event(100, "task_complete")],
                       "--limit", "100", expect=3)
    assert result["state"] == "rotate_now"
    assert "invalid limit" in run_codex(tmp_path, [], "--limit", "0", expect=2)["error"]


def test_a_malformed_line_is_counted_not_fatal(tmp_path):
    result = run_codex(tmp_path, ["{truncated", codex_event(0, "task_started"), codex_event(5, "task_complete")])
    assert result["active_seconds"] == 5 and result["malformed_lines"] == 1


def test_the_transcript_is_found_in_each_hosts_real_location(tmp_path):
    claude_home = tmp_path / "claude-home"
    folder = claude_home / "projects" / "-some-project"
    folder.mkdir(parents=True)
    write_lines(folder / (SESSION + ".jsonl"), [claude_prompt(0), claude_reply(7)])
    found = meter("--host", "claude-code", "--session", SESSION, env={"CLAUDE_CONFIG_DIR": str(claude_home)})
    assert found["active_seconds"] == 7 and found["transcript"].endswith(SESSION + ".jsonl")
    codex_home = tmp_path / "codex-home"
    folder = codex_home / "sessions" / "2026" / "11" / "01"
    folder.mkdir(parents=True)
    write_lines(folder / ("rollout-2026-11-01T21-49-55-" + SESSION + ".jsonl"),
                [codex_event(0, "task_started"), codex_event(9, "task_complete")])
    found = meter("--host", "codex-cli", "--session", SESSION, env={"CODEX_HOME": str(codex_home)})
    assert found["active_seconds"] == 9


def test_a_session_with_no_transcript_reports_that_rather_than_zero_time(tmp_path):
    result = meter("--host", "claude-code", "--session", SESSION, env={"CLAUDE_CONFIG_DIR": str(tmp_path)})
    assert result["state"] == "no_transcript" and result["active_seconds"] is None


@pytest.mark.parametrize("arguments,error", [
    (["--host", "gemini", "--session", SESSION], "unsupported host"),
    (["--host", "claude-code", "--session", "../../etc/passwd"], "invalid session"),
    (["--host", "claude-code", "--session", "*"], "invalid session"),
    (["--host", "claude-code", "--session", SESSION, "--transcript", "/no/such/transcript.jsonl"], "transcript unavailable"),
])
def test_bad_requests_fail_as_json(arguments, error):
    assert error in meter(*arguments, expect=2)["error"]


def test_a_real_codex_host_label_also_works(tmp_path):
    path = write_lines(tmp_path / "rollout.jsonl", [codex_event(0, "task_started"), codex_event(3, "task_complete")])
    assert meter("--host", "codex", "--session", SESSION, "--transcript", str(path))["active_seconds"] == 3
    assert Path(path).exists()
