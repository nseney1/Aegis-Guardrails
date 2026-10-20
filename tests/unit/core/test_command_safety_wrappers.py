"""Execution wrappers hide nothing from the guard or the analyzer (R-checks-4).

A command prefixed by a pure execution wrapper (ionice, stdbuf, setsid, busybox, su -c,
env -S) classifies like the unprefixed command, in ``classify_command`` (the pre-tool
guard, fail-open) and in ``CommandAnalyzer`` (the safety gate, fail-closed). The wrapper
list stays open-ended: chrt, taskset, flock, nsenter, watch and script -c are residuals.
"""
from __future__ import annotations

import shlex

import pytest

from aegis_core.command_safety import (
    GUARD_BLOCK,
    GUARD_RECORD,
    REASON_SUDO,
    REASON_UNABLE_TO_PARSE,
    CommandAnalyzer,
    SafetyEvaluation,
    classify_command,
    unwrap_command_stage,
)

RM = "rm-recursive-dangerous"


def _id(command):
    match = classify_command(command)
    return None if match is None else (match.tier, match.id)


WRAPPED = [
    ("ionice rm -rf /", RM),
    ("ionice -c3 rm -rf /", RM),
    ("ionice -c 3 -n 7 rm -rf /", RM),
    ("ionice --class=idle git push --force", "git-push-force"),
    ("ionice --class idle rm -rf ~", RM),
    ("ionice -t -c2 -n0 git reset --hard", "git-reset-hard"),
    ("stdbuf -oL rm -rf /", RM),
    ("stdbuf -o0 -e0 git push --force", "git-push-force"),
    ("stdbuf -i 0 -o L git clean -fdx", "git-clean-force"),
    ("stdbuf --output=L rm -rf ~", RM),
    ("setsid rm -rf /", RM),
    ("setsid -f rm -rf /", RM),
    ("setsid --fork --wait git reset --hard", "git-reset-hard"),
    ("setsid -w mkfs.ext4 /dev/sda1", "mkfs"),
    ("busybox rm -rf /", RM),
    ("busybox sh -c 'rm -rf /'", RM),
    ("busybox dd if=x of=/dev/sda", "dd-device"),
    ("su -c 'rm -rf /'", RM),
    ("su root -c 'git push --force'", "git-push-force"),
    ("su -l root -c 'rm -rf ~'", RM),
    ("su -lc 'rm -rf /' root", RM),
    ("su -lc 'git reset --hard' root", "git-reset-hard"),
    ("su root -c 'ls' -c 'rm -rf /'", RM),
    ("su --command='git reset --hard' root", "git-reset-hard"),
    ("su --command 'rm -rf /'", RM),
    ("su --session-command='rm -rf /' root", RM),
    ("su -s /bin/bash -c 'rm -rf /' root", RM),
    ("sudo su -c 'rm -rf /'", RM),
    ("env -S 'rm -rf /'", RM),
    ("env -S'rm -rf /'", RM),
    ("env -iS 'rm -rf /'", RM),
    ("env --split-string='git push --force'", "git-push-force"),
    ("env --split-string 'git reset --hard'", "git-reset-hard"),
    ("env -S 'git push' --force origin feat", "git-push-force"),
    ("env -iu FOO rm -rf /", RM),
    ("env -uFOO rm -rf /", RM),
    ("sudo -Eu root rm -rf /", RM),
    ("nice ionice -c3 setsid -f stdbuf -oL rm -rf /", RM),
    ("bash -c 'ionice rm -rf /'", RM),
    ("timeout 5 setsid git push -f", "git-push-force"),
    ("ionice -c3 rm -rf / && echo done", RM),
]


@pytest.mark.parametrize("command,rule", WRAPPED, ids=[f"w{i}" for i in range(len(WRAPPED))])
def test_a_wrapped_destructive_command_is_blocked_and_asked(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)
    assert CommandAnalyzer.evaluate(command).is_destructive is True


@pytest.mark.parametrize("command", [
    "setsid bash <<'EOF'\nrm -rf /\nEOF",
    "sudo su - <<'EOF'\nrm -rf /\nEOF",
    "su root <<EOF\nrm -rf /\nEOF",
], ids=["setsid-bash", "sudo-su", "su-root"])
def test_a_heredoc_a_wrapped_shell_reads_is_commands(command):
    assert _id(command) == (GUARD_BLOCK, RM)


@pytest.mark.parametrize("command", [
    "setsid cat <<'EOF'\nrm -rf /\nEOF",
    "su -c 'cat' root <<'EOF'\nrm -rf /\nEOF",
], ids=["setsid-cat", "su-c-cat"])
def test_a_heredoc_a_wrapped_reader_reads_stays_text(command):
    assert classify_command(command) is None


@pytest.mark.parametrize("command", [
    "ionice -c3 make -j4",
    "stdbuf -oL tail -f app.log",
    "setsid -f python worker.py",
    "busybox ls -la",
    "su root",
    "su -",
    "su -c 'ls -la' root",
    "env -S 'ls -la'",
    "env --split-string='echo rm -rf /'",
    "echo 'ionice rm -rf /'",
    "env -iu FOO ls",
])
def test_a_wrapped_harmless_command_is_not_a_match(command):
    assert classify_command(command) is None
    assert CommandAnalyzer.evaluate(command) == SafetyEvaluation(False)


@pytest.mark.parametrize("command", ["ionice", "stdbuf -o", "setsid", "busybox", "su -c", "env -S ''", "env -S", "su --command"])
def test_a_bare_wrapper_does_not_crash_and_is_not_a_match(command):
    assert classify_command(command) is None
    assert CommandAnalyzer.evaluate(command) == SafetyEvaluation(False)


@pytest.mark.parametrize("command", ["env -S \"rm -rf / '\"", "su -c \"rm -rf / '\""], ids=["env-S", "su-c"])
def test_an_unbalanced_quote_inside_a_wrapper_fails_open_for_the_guard_and_closed_for_the_gate(command):
    assert classify_command(command) is None
    assert CommandAnalyzer.evaluate(command) == SafetyEvaluation(True, REASON_UNABLE_TO_PARSE)


def _nested_split_string(levels):
    command = "rm -rf /"
    for _ in range(levels):
        command = "env -S " + shlex.quote(command)
    return command


def test_nested_split_strings_stop_at_the_recursion_clamp():
    assert _id(_nested_split_string(3)) == (GUARD_BLOCK, RM)
    assert classify_command(_nested_split_string(6)) is None


@pytest.mark.parametrize("command", ["sudo su -c 'ls -la'", "sudo ionice -c3 make", "sudo su root"])
def test_sudo_in_front_of_a_wrapper_is_still_recorded(command):
    assert _id(command) == (GUARD_RECORD, "sudo")
    assert CommandAnalyzer.evaluate(command) == SafetyEvaluation(True, REASON_SUDO)


def test_env_split_string_returns_the_inner_command_with_the_remaining_words():
    assert unwrap_command_stage(["env", "-S", "rm -rf", "/"]) == (None, "rm -rf /")
    assert unwrap_command_stage(["env", "-S", "echo", "a;b"]) == (None, "echo 'a;b'")
