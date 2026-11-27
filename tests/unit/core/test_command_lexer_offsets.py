"""Offset prefix matching preserves extraction and both public safety policies."""
from __future__ import annotations

import pytest

from aegis_core.command_safety import (
    BLOCK_SET,
    CommandAnalyzer,
    REASON_GIT_RESET_HARD,
    REASON_POWERSHELL_DELETE,
    SafetyEvaluation,
    classify_command,
    extract_subshell_commands,
)


class SliceCountingCommand(str):
    """Count copied suffixes without measuring wall-clock time."""

    def __new__(cls, value):
        command = super().__new__(cls, value)
        command.suffix_slices = 0
        return command

    def __getitem__(self, key):
        if isinstance(key, slice) and key.stop is None:
            self.suffix_slices += 1
        return super().__getitem__(key)


@pytest.mark.parametrize("count", [1, 32, 16000])
def test_bare_parenthesis_prefix_checks_do_not_copy_suffixes(count):
    command = SliceCountingCommand("Write-Output " + "(Get-Date) " * count)
    assert extract_subshell_commands(command) == []
    assert command.suffix_slices == 0


@pytest.mark.parametrize("verb", ["remove-item", "rm", "del", "erase", "rd", "ri", "format-volume"])
def test_all_powershell_prefixes_match_at_non_boundary_offset(verb):
    assert extract_subshell_commands("x(" + verb + " foo)") == [verb + " foo"]


@pytest.mark.parametrize(
    "command,extracted,guard_id,reason",
    [
        pytest.param("x(Remove-Item foo)", ["Remove-Item foo"], None, "", id="non-boundary"),
        pytest.param("x(Remove-Item -Recurse -Force foo)",
                     ["Remove-Item -Recurse -Force foo"], None, REASON_POWERSHELL_DELETE, id="destructive"),
        pytest.param("x(rEmOvE-iTeM -Recurse -Force foo)",
                     ["rEmOvE-iTeM -Recurse -Force foo"], None, REASON_POWERSHELL_DELETE, id="mixed-case"),
        pytest.param("x(\nRemove-Item -Recurse -Force foo)",
                     ["\nRemove-Item -Recurse -Force foo"], None, REASON_POWERSHELL_DELETE, id="newline"),
        pytest.param("x(\tRemove-Item -Recurse -Force foo)",
                     ["\tRemove-Item -Recurse -Force foo"], None, REASON_POWERSHELL_DELETE, id="tab"),
        pytest.param("echo 'x(Remove-Item -Recurse -Force foo)'", [], None, "", id="single-quoted"),
        pytest.param('echo "x(Remove-Item -Recurse -Force foo)"', [], None, "", id="double-quoted"),
        pytest.param("(echo (Remove-Item -Recurse -Force foo))",
                     ["echo (Remove-Item -Recurse -Force foo)"], None, REASON_POWERSHELL_DELETE, id="nested"),
        pytest.param("x(Remove-Item -Recurse -Force foo", [], None, "", id="unclosed"),
        pytest.param("x(Get-Date)", [], None, "", id="non-boundary-benign"),
        pytest.param("(Get-Date)", ["Get-Date"], None, "", id="boundary-benign"),
        pytest.param("x(Remove-Itemized foo)", [], None, "", id="word-boundary"),
        pytest.param("x($(Get-Date)", ["Get-Date"], None, "", id="unclosed-outer"),
        pytest.param("echo $(git reset --hard) x(Remove-Item -Recurse -Force foo)",
                     ["git reset --hard", "Remove-Item -Recurse -Force foo"],
                     "git-reset-hard", REASON_GIT_RESET_HARD, id="substitution-beside-bare"),
        pytest.param("echo `git reset --hard` x(Get-Date)", ["git reset --hard"],
                     "git-reset-hard", REASON_GIT_RESET_HARD, id="backtick"),
        pytest.param("diff <(git reset --hard) >(Get-Date)", ["git reset --hard", "Get-Date"],
                     "git-reset-hard", REASON_GIT_RESET_HARD, id="process-substitutions"),
    ],
)
def test_extraction_and_public_policy_verdicts_are_preserved(command, extracted, guard_id, reason):
    assert extract_subshell_commands(command) == extracted
    expected_guard = next((rule for rule in BLOCK_SET if rule.id == guard_id), None)
    assert classify_command(command) == expected_guard
    assert CommandAnalyzer.evaluate(command) == SafetyEvaluation(bool(reason), reason)
