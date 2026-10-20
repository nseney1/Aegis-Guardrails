"""Shell comments never switch the destructive-command guard off (R-checks-1).

The lexer has no notion of comments, so a quote inside one (``# it's``) used to open a
quote: ``classify_command`` then failed open on commands the shell runs. The guard now
drops comments first, the way the shell reads them, and keeps its fail-open contract
for real syntax errors. ``CommandAnalyzer`` is not changed: it has no heredoc split, so
it keeps asking (fail closed) when a comment quote breaks its parse.
"""
from __future__ import annotations

import pytest

from aegis_core.command_safety import (
    GUARD_BLOCK,
    REASON_UNABLE_TO_PARSE,
    CommandAnalyzer,
    SafetyEvaluation,
    classify_command,
    strip_shell_comments,
)

RM = "rm-recursive-dangerous"


def _id(command):
    match = classify_command(command)
    return None if match is None else (match.tier, match.id)


# A. A quote-bearing comment on the line or a neighbouring line changes nothing.
@pytest.mark.parametrize("command,rule", [
    ("rm -rf / # it's", RM),
    ("git push --force origin main # don't", "git-push-force"),
    ("git reset --hard # it's", "git-reset-hard"),
    ("echo hi # it's\nrm -rf /", RM),
    ("echo hi # it's\nrm -rf / ; echo '", None),
    ("echo hi # it's\necho $(rm -rf /)", RM),
    ("bash <<EOF # it's\nrm -rf /\nEOF", RM),
    ("cat <<EOF | bash # it's\nrm -rf /\nEOF", RM),
    ("ls; # it's\nrm -rf /", RM),
    ("ls;# it's\nrm -rf /", RM),
    ("echo $(ls # it's\n) ; rm -rf /", RM),
    ("(cd d) # it's\ngit reset --hard", "git-reset-hard"),
], ids=[f"a{i}" for i in range(12)])
def test_a_quote_in_a_comment_does_not_hide_the_command(command, rule):
    without_comment = rule and (GUARD_BLOCK, rule)
    assert _id(command) == without_comment


# B. Anti-regression for shlex commenters="#": a # that is not a comment start stays text
# and a comment ends at its newline.
@pytest.mark.parametrize("command,rule", [
    ("echo foo#bar; rm -rf /", RM),
    ("echo ${x:- # }; rm -rf /", RM),
    ("echo $#; rm -rf /", RM),
    ('echo "a # b"; rm -rf /', RM),
    ("echo hi # note\nrm -rf /", RM),
    ("echo hi # note\ngit push --force origin main", "git-push-force"),
    ("git push origin HEAD:refs/heads/x#y --force", "git-push-force"),
], ids=[f"b{i}" for i in range(7)])
def test_a_hash_that_is_not_a_comment_hides_nothing(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


# C. Text only inside a comment is data.
@pytest.mark.parametrize("command", ["ls # rm -rf /", "rm -rf build # remove /", "# git push --force\nls"])
def test_a_command_inside_a_comment_is_not_a_match(command):
    assert classify_command(command) is None


# D. The fail-open contract is unchanged for real syntax errors.
@pytest.mark.parametrize("command", ["git reset --hard 'unclosed", 'rm -rf / "unclosed', "rm -rf / # it's\necho 'x"])
def test_an_unparseable_command_still_fails_open(command):
    assert classify_command(command) is None


def test_the_analyzer_still_asks_when_a_comment_quote_breaks_its_parse():
    assert CommandAnalyzer.evaluate("ls # it's") == SafetyEvaluation(True, REASON_UNABLE_TO_PARSE)


# E. The stripper itself.
@pytest.mark.parametrize("command,expected", [
    ("ls -la", "ls -la"),
    ("ls # it's", "ls "),
    ("a#b", "a#b"),
    ("echo $#", "echo $#"),
    ("echo ${#x}", "echo ${#x}"),
    ("echo $'it\\'s # x'", "echo $'it\\'s # x'"),
    ("(cd d) # it's", "(cd d) "),
    ("echo hi # c\nls # d", "echo hi \nls "),
    ('echo "a # b" # c', 'echo "a # b" '),
    ("echo 'a # b' # c", "echo 'a # b' "),
    ("echo \\# a", "echo \\# a"),
    ("echo `ls # x`", "echo `ls # x`"),
    ("echo $(ls # it's\n)", "echo $(ls \n)"),
    ("# only", ""),
], ids=[f"e{i}" for i in range(14)])
def test_strip_shell_comments(command, expected):
    assert strip_shell_comments(command) == expected


def test_stripping_a_long_command_does_not_raise():
    long = "echo a # it's\n" * 20_000 + "rm -rf /"
    assert _id(long) == (GUARD_BLOCK, RM)
