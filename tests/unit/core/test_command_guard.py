"""The destructive-command guard (v4.1 spec §2 "Behaviour" 2): ``classify_command`` and
the block and record sets in aegis_core.command_safety.

- The block set holds irreversible operations only; ``aegis hook run pre-tool`` blocks
  them (Claude and Codex exit 2, agy exit 75). The same constant feeds the Codex
  ``aegis.rules`` generator through each rule's ``codex_prefixes``.
- The record set is matched and recorded, never blocked: AD-10 lets agents merge.
- An empty, absent or unparseable command is never a match (fail-open); the safety
  gate's fail-closed defaults are not reused.
"""
from __future__ import annotations

import itertools
import time

import pytest

from aegis_core.command_safety import (
    BLOCK_SET,
    GUARD_BLOCK,
    GUARD_RECORD,
    RECORD_SET,
    GuardRule,
    classify_command,
    split_heredocs,
)

BLOCK_IDS = {
    "git-push-force", "git-push-refspec", "git-reset-hard", "git-clean-force",
    "rm-recursive-dangerous", "mkfs", "dd-device",
}
RECORD_IDS = {
    "git-merge", "gh-pr-merge", "git-add-bulk", "git-push-protected", "sudo", "chmod-777", "sql-destructive",
}


def _id(command):
    match = classify_command(command)
    return None if match is None else (match.tier, match.id)


# ── the sets ─────────────────────────────────────────────────────────────────

def test_the_block_set_is_exactly_the_irreversible_operations_of_the_plan():
    assert {r.id for r in BLOCK_SET} == BLOCK_IDS
    assert all(isinstance(r, GuardRule) and r.tier == GUARD_BLOCK for r in BLOCK_SET)


def test_the_record_set_is_matched_but_never_blocked():
    assert {r.id for r in RECORD_SET} == RECORD_IDS
    assert all(r.tier == GUARD_RECORD for r in RECORD_SET)
    assert all(not r.codex_prefixes for r in RECORD_SET)


def test_every_rule_has_a_unique_id_and_a_reason():
    rules = BLOCK_SET + RECORD_SET
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.reason and r.reason == r.reason.strip() and r.reason.isascii() for r in rules)


def _expansions(pattern):
    positions = [p if isinstance(p, tuple) else (p,) for p in pattern]
    return [" ".join(words) for words in itertools.product(*positions)]


# Codex's prefix_rule matches every command that STARTS with the prefix, whatever follows.
_TRAILERS = ("", " x", " -- x", " -v", " --help", " -n", " --dry-run", " && ls")
# The one documented superset: Codex forbids a git clean dry run written after the forcing
# flag, which deletes nothing and which the hook allows.
_CODEX_ONLY = {("git-clean-force", " -n"), ("git-clean-force", " --dry-run")}


@pytest.mark.parametrize("rule", [r for r in BLOCK_SET if r.codex_prefixes], ids=lambda r: r.id)
def test_every_command_a_codex_prefix_forbids_is_blocked_by_the_hook_as_the_same_rule(rule):
    """The Codex rules are generated from the same constant: a command they forbid (the
    prefix and anything after it) is one the hook blocks for the same reason, except the
    dry runs listed in _CODEX_ONLY, so Codex never forbids more than the guard otherwise."""
    prefixes = [c for pattern in rule.codex_prefixes for c in _expansions(pattern)]
    assert prefixes
    for trailer in _TRAILERS:
        expected = None if (rule.id, trailer) in _CODEX_ONLY else (GUARD_BLOCK, rule.id)
        wrong = [p + trailer for p in prefixes if _id(p + trailer) != expected]
        assert not wrong, (trailer, wrong)


def test_operations_no_argv_prefix_can_express_have_no_codex_prefix():
    by_id = {r.id: r for r in BLOCK_SET}
    assert by_id["git-push-refspec"].codex_prefixes == ()
    assert by_id["dd-device"].codex_prefixes == ()
    assert by_id["git-reset-hard"].codex_prefixes == (("git", "reset", "--hard"),)


# ── block set ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("command,rule", [
    ("git push --force origin feat", "git-push-force"),
    ("git push -f", "git-push-force"),
    ("git push origin feat --force-with-lease", "git-push-force"),
    ("git push --force-with-lease=feat:abc123 origin feat", "git-push-force"),
    ("git push -fu origin feat", "git-push-force"),
    ("git -C ../other push --force", "git-push-force"),
    ("git push origin +feat", "git-push-refspec"),
    ("git push origin +HEAD:refs/heads/feat", "git-push-refspec"),
    ("git reset --hard", "git-reset-hard"),
    ("git reset --hard HEAD~3", "git-reset-hard"),
    ("git clean -f", "git-clean-force"),
    ("git clean -xdf", "git-clean-force"),
    ("git clean --force -d", "git-clean-force"),
    ("rm -rf /", "rm-recursive-dangerous"),
    ("rm -r ~", "rm-recursive-dangerous"),
    ("rm -rf $HOME", "rm-recursive-dangerous"),
    ('rm -rf "$HOME"/', "rm-recursive-dangerous"),
    ("rm -fr ${HOME}/*", "rm-recursive-dangerous"),
    ("rm -rf *", "rm-recursive-dangerous"),
    ("rm -rf .", "rm-recursive-dangerous"),
    ("rm -rf ..", "rm-recursive-dangerous"),
    ("rm -rf ./*", "rm-recursive-dangerous"),
    ("rm -rf ../", "rm-recursive-dangerous"),
    ("rm -R ~/*", "rm-recursive-dangerous"),
    ("rm -rf //", "rm-recursive-dangerous"),
    ("rm -rf /*", "rm-recursive-dangerous"),
    ("rm --recursive --force /", "rm-recursive-dangerous"),
    ("rm -rf -- /", "rm-recursive-dangerous"),
    ("rm -rf build /", "rm-recursive-dangerous"),
    ("rm -rf /home/", "rm-recursive-dangerous"),
    ("mkfs.ext4 /dev/sda1", "mkfs"),
    ("mkfs -t ext4 /dev/sdb", "mkfs"),
    ("/sbin/mkfs.vfat /dev/sdc1", "mkfs"),
    ("dd if=image.iso of=/dev/sdb bs=4M", "dd-device"),
    ("dd of=/dev/disk2 if=image.iso", "dd-device"),
])
def test_block_set_commands_are_blocked(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


@pytest.mark.parametrize("command,rule", [
    # BUG-074: bundled shell flags still unwrap the inner script.
    ('bash -lc "rm -rf /"', "rm-recursive-dangerous"),
    ('sh -ec "git reset --hard"', "git-reset-hard"),
    ('zsh -xic "git push --force"', "git-push-force"),
    ("echo $(git reset --hard)", "git-reset-hard"),
    ("echo `git clean -fd`", "git-clean-force"),
    ("eval git reset --hard", "git-reset-hard"),
    ("sudo rm -rf /", "rm-recursive-dangerous"),
    ("timeout 10 git push -f", "git-push-force"),
    ("env FOO=1 git clean -fd", "git-clean-force"),
    ("cd repo && git reset --hard", "git-reset-hard"),
    ("true; rm -rf ~", "rm-recursive-dangerous"),
    ("ls | xargs rm -rf /", "rm-recursive-dangerous"),
])
def test_wrapped_and_chained_block_set_commands_are_blocked(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


# R-checks-a1: the lexer returns a run of adjacent delimiters (";\n", "\n\n", "&&\n") as
# one token; each command after such a run is still classified.
DELIMITER_RUNS = [
    ("echo a\n\nrm -rf /", "rm-recursive-dangerous"),
    ("echo a;\nrm -rf /", "rm-recursive-dangerous"),
    ("git add x &&\n git push --force origin main", "git-push-force"),
    ("echo a ||\n rm -rf /", "rm-recursive-dangerous"),
    ("a;;rm -rf /", "rm-recursive-dangerous"),
    ("true &\nrm -rf /", "rm-recursive-dangerous"),
    ("ls |\n rm -rf /", "rm-recursive-dangerous"),
    ("git status\n\ngit reset --hard", "git-reset-hard"),
]
DELIMITER_RUNS_HARMLESS = [
    "echo a\n\nls",
    "ls;\n\nls",
    "ls;\n\n\nls",
    "cat f |& tee g",
    "echo 'a;\n\nrm -rf /'",
    "rm -rf build\n\nls",
]


@pytest.mark.parametrize("command,rule", DELIMITER_RUNS, ids=[f"run{i}" for i in range(len(DELIMITER_RUNS))])
def test_a_command_after_a_run_of_delimiters_is_classified(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


@pytest.mark.parametrize("command", DELIMITER_RUNS_HARMLESS, ids=[f"ok{i}" for i in range(len(DELIMITER_RUNS_HARMLESS))])
def test_a_run_of_delimiters_never_splits_quoted_text_or_harmless_commands(command):
    assert classify_command(command) is None


# R-checks-2: git (parse-options) and GNU rm accept any unique prefix of a long option.
@pytest.mark.parametrize("command,rule", [
    ("git push --force-w origin feat", "git-push-force"),
    ("git push --force-with origin feat", "git-push-force"),
    ("git push --force-with-l origin feat", "git-push-force"),
    ("git push origin feat --force-w", "git-push-force"),
    ("git -C ../other push --force-w", "git-push-force"),
    ('bash -lc "git push --force-w origin feat"', "git-push-force"),
    ("git reset --har", "git-reset-hard"),
    ("git reset --h", "git-reset-hard"),
    ("git reset HEAD~1 --har", "git-reset-hard"),
    ("git clean --forc -d", "git-clean-force"),
    ("git clean --f -d", "git-clean-force"),
    ("rm --recurs /", "rm-recursive-dangerous"),
    ("rm --r ~", "rm-recursive-dangerous"),
    # -e takes a pattern: the n of -en, or a -n after -e/--exclude, is that pattern.
    ("git clean -fd -en", "git-clean-force"),
    ("git clean -fen", "git-clean-force"),
    ("git clean -fdx -e build", "git-clean-force"),
    ("git clean -f -e n", "git-clean-force"),
    ("git clean -f -e -n", "git-clean-force"),
    ("git clean -f --exclude -n", "git-clean-force"),
    # after -- a -n is a pathspec; --no-dry-run cancels a dry run
    ("git clean -f -- -n .", "git-clean-force"),
    ("git clean -n --no-dry-run -f", "git-clean-force"),
    ("git clean -f --no-d", "git-clean-force"),
    # a separate -e/--exclude value is read, and a -n that is the value is still the value
    ("git clean -fdx -e .env", "git-clean-force"),
    ("git clean -e x -f", "git-clean-force"),
    ("git clean -fdx --exclude .venv", "git-clean-force"),
    ("git clean -e x -e -n -f", "git-clean-force"),
    ("git clean -f -e .env -- -n", "git-clean-force"),
])
def test_an_abbreviated_long_option_is_the_option_it_abbreviates(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


@pytest.mark.parametrize("command", [
    "git push --",
    "git push origin -- feat",
    "git reset -- file.py",
    "git reset HEAD -- file.py",
    "git clean -n --",
    "rm -r -- build",
    "git push --force-i origin feat",
    "git push --force-if origin feat",
    "git push --follow-tags origin feat",
    "git push --dry origin feat",
    "git reset --soft HEAD~1",
    "git clean -f --d",
    "git clean -f --dry",
    "git clean -fn",
    "git clean -fdn",
    "git clean -f -n",
    "git clean -nfd",
    "git clean -f --e=x -n",
    # git takes the word after -e/--exclude as the pattern, so the -n after it is a dry run
    "git clean -fdx -e .env -n",
    "git clean -e x -fn",
    "git clean -fdx --exclude .venv --dry-run",
])
def test_an_unrelated_prefix_or_a_real_dry_run_is_not_a_match(command):
    assert classify_command(command) is None


def test_delimiter_runs_alone_or_unterminated_fail_open_without_raising():
    assert classify_command(";;;;;") is None
    assert classify_command(";" * 100_000) is None
    assert classify_command("ls;\n\n'x") is None


# R-checks-3: an alias defined on the same git command line is judged by its expansion.
_CHAIN = " ".join(f"-c alias.a{i}=a{i + 1}" for i in range(20))


@pytest.mark.parametrize("command,rule", [
    ("git -c alias.p='push -f' p", "git-push-force"),
    ("git -c alias.p='push --force-with-lease' p origin feat", "git-push-force"),
    ("git -c alias.p=push p -f", "git-push-force"),
    ("git -c alias.P='push -f' p", "git-push-force"),
    ("git -c alias.p='push origin +feat' p", "git-push-refspec"),
    ("git -c alias.r='reset --hard' r", "git-reset-hard"),
    ("git -c alias.c='clean -fdx' c", "git-clean-force"),
    ("git -c alias.p='!git push -f' p", "git-push-force"),
    ("git -c alias.p='!git push' p -f origin feat", "git-push-force"),
    ("git -c alias.a=b -c alias.b='push -f' a", "git-push-force"),
    (f"git {_CHAIN} -c alias.a20='reset --hard' a0", "git-reset-hard"),
    ("sudo git -c alias.p='push -f' p", "git-push-force"),
    ("bash -c \"git -c alias.p='push -f' p\"", "git-push-force"),
    ("PVAL='push -f' git --config-env=alias.p=PVAL p", "git-push-force"),
    ("PVAL='push -f' git --config-env alias.p=PVAL p", "git-push-force"),
    ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0='push -f' git p", "git-push-force"),
    ("GIT_CONFIG_PARAMETERS=\"'alias.p=push -f'\" git p", "git-push-force"),
    ("GIT_CONFIG_PARAMETERS=\"'user.name'='x' 'alias.p'='reset --hard'\" git p", "git-reset-hard"),
    ("git -c alias.reset=status reset --hard", "git-reset-hard"),
], ids=lambda value: value[:40] if value.startswith(("git", "sudo", "bash", "PVAL", "GIT_")) else "")
def test_a_command_line_git_alias_is_judged_by_its_expansion(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


# git hands its -c settings to a ! alias's script through GIT_CONFIG_PARAMETERS, so every
# git the script runs, however nested, expands the outer aliases; its own -c comes later
# and wins.
@pytest.mark.parametrize("command,rule", [
    ("git -c alias.q='push -f' -c alias.p='!git q' p", "git-push-force"),
    ("git -c alias.q='push -f' -c alias.p='!sh -c \"git q\"' p", "git-push-force"),
    ("git -c alias.q=push -c alias.p='!git q' p -f", "git-push-force"),
    ("git -c alias.r='reset --hard' -c alias.q='!git r' -c alias.p='!git q' p", "git-reset-hard"),
], ids=["inherited", "nested-shell", "arguments", "two-levels"])
def test_a_shell_alias_script_expands_the_outer_command_line_aliases(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


@pytest.mark.parametrize("command", [
    "git -c alias.q=status -c alias.p='!git q' p",
    "git -c alias.q='push -f' -c alias.p='!git status' p",
    "git -c alias.q='push -f' -c alias.p='!git -c alias.q=status q' p",
], ids=["harmless-inner", "unused-outer", "inner-overrides"])
def test_a_shell_alias_script_with_no_destructive_git_is_not_a_match(command):
    assert classify_command(command) is None


def _best_of_3(command):
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        assert classify_command(command) is None
        best = min(best, time.perf_counter() - started)
    return best


def _rerunning_shell_alias(k):
    """A ! alias whose script runs the alias itself k times (git would never finish)."""
    return "git -c alias.p='!" + "; ".join(["git p"] * k) + "' p"


@pytest.mark.timing
def test_a_shell_alias_script_that_reruns_its_alias_is_scanned_in_linear_time():
    # A ratio, never an absolute budget; the 20 ms floor keeps timer noise from failing it.
    # Rescanning the script for each of its k stages at every nesting level grows as k**4.
    small = _best_of_3(_rerunning_shell_alias(10))
    large = _best_of_3(_rerunning_shell_alias(20))
    assert large <= 2.5 * max(small, 0.02), (small, large)


def test_a_rerunning_shell_alias_still_finds_its_destructive_git():
    assert _id("git -c alias.q='push -f' -c alias.p='!git p; git p; git q' p") == (GUARD_BLOCK, "git-push-force")


@pytest.mark.parametrize("command", [
    "git -c alias.st=status st",
    "git -c alias.p='push origin feat' p",
    "git -c alias.x='push -f' p",
    "git -c alias.p push",
    "git -c alias.p=p p",
    "git -c alias.p=q -c alias.q=p p",
    "git -c alias.p=\"push 'x\" p",
    "git -c alias.p='!echo push -f' p",
    "git --config-env=alias.p=UNSET p",
])
def test_a_harmless_looping_or_unparseable_git_alias_is_not_a_match(command):
    assert classify_command(command) is None


@pytest.mark.parametrize("target", ["./", ".//", "../", "..//", "~/", "/home/", "/root/", "/"])
def test_trailing_slashes_never_hide_a_dangerous_rm_target(target):
    """BUG-075 for the guard: trailing slashes are normalized away."""
    assert _id(f"rm -rf {target}") == (GUARD_BLOCK, "rm-recursive-dangerous")


@pytest.mark.parametrize("command", [
    "dd of=//dev/sda",
    "dd of=///dev/sda bs=1M",
    "dd if=image.iso of=//dev/sdb bs=4M",
    'dd of="//dev/sda"',
    "dd of=/./dev/sda",
    "dd of=/tmp/../dev/sda",
    "dd of=/dev//sda",
    "dd of=//dev/../dev/sda",
    "dd of=/dev/shm/../sda",
    "dd of=/dev/fd/../sda",
    "yes | dd of=//dev/sda",
    "/bin/dd of=//dev/sda",
    "env dd of=//dev/sda",
    "bash -c 'dd of=//dev/sda'",
])
def test_a_device_path_is_resolved_before_the_dd_device_check(command):
    """R-checks-5: the of= operand is resolved lexically (no filesystem access)."""
    assert _id(command) == (GUARD_BLOCK, "dd-device")


@pytest.mark.parametrize("command", [
    "dd if=/dev/zero of=//dev/null bs=1M count=1",
    "dd of=///dev/null",
    "dd of=/dev//null",
    "dd of=/dev/./null",
    "dd of=/dev/null/",
    "dd of=//dev/stdout",
    "dd of=//dev/fd/1",
    "dd of=//dev/shm/scratch.img",
    "dd of=//tmp/out.img",
    "dd of=/tmp/dev/sda",
    "dd of=//dev",
    "dd of=/dev/",
    "dd of=out.img",
])
def test_a_harmless_dd_target_spelled_with_extra_slashes_or_dots_is_not_a_match(command):
    assert classify_command(command) is None


# ── record set ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("command,rule", [
    ("git merge feature", "git-merge"),
    ("git merge --no-ff lane/x", "git-merge"),
    ("gh pr merge 12 --squash", "gh-pr-merge"),
    ("gh -R owner/repo pr merge 1", "gh-pr-merge"),
    ("git add -A", "git-add-bulk"),
    ("git add .", "git-add-bulk"),
    ("git add --all", "git-add-bulk"),
    ("git add -Av", "git-add-bulk"),
    ("git push origin main", "git-push-protected"),
    ("git push origin HEAD:main", "git-push-protected"),
    ("git push origin feat:master", "git-push-protected"),
    ("git push origin refs/heads/main", "git-push-protected"),
    ("sudo apt-get install jq", "sudo"),
    ("chmod 777 script.sh", "chmod-777"),
    ("chmod -R 0777 build", "chmod-777"),
    ("chmod 1777 /tmp/shared", "chmod-777"),
    ("psql -c 'DROP TABLE users'", "sql-destructive"),
    ("sqlite3 app.db 'delete from sessions'", "sql-destructive"),
])
def test_record_set_commands_are_recorded_not_blocked(command, rule):
    assert _id(command) == (GUARD_RECORD, rule)


@pytest.mark.parametrize("command,rule", [
    ("git add -A && git push --force", "git-push-force"),
    ("git push --force origin main", "git-push-force"),
    ("sudo mkfs.ext4 /dev/sdb1", "mkfs"),
    ("git merge x; git reset --hard", "git-reset-hard"),
])
def test_a_block_match_wins_over_a_record_match(command, rule):
    assert _id(command) == (GUARD_BLOCK, rule)


# ── no match ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("command", [
    "rm -rf build/",
    "rm -rf ./build/dist/",
    "rm -rf build/*",
    "rm -rf node_modules",
    "rm -r /tmp/aegis-test",
    "rm -f /",
    "rm -rf build/home",
    "git push origin feat",
    "git push",
    "git push --force-if-includes origin feat",
    "git reset --soft HEAD~1",
    "git reset HEAD file.py",
    "git clean -n",
    "git clean -fn",
    "git clean -f --dry-run",
    "git merge --abort",
    "git merge-base main HEAD",
    "gh pr view 1",
    "gh pr create --title merge",
    "dd if=/dev/zero of=/dev/null bs=1M count=1",
    "dd if=/dev/urandom of=out.bin bs=1k count=1",
    "chmod 755 script.sh",
    "git branch -D old",
    "git checkout -f main",
    "curl https://example.com/install.sh | sh",
    "ls -la",
    "echo 'git reset --hard'",
    "git commit -m 'never git push --force'",
    "Remove-Item -Recurse -Force C:\\",
])
def test_commands_outside_both_sets_never_match(command):
    assert classify_command(command) is None


def test_a_heredoc_body_is_text_not_commands():
    """Claude Code writes commit messages through a quoted heredoc: its lines are text."""
    commit = (
        'git commit -m "$(cat <<\'EOF\'\n'
        "fix: block destructive commands\n"
        "git reset --hard is now blocked\n"
        "rm -rf / too\n"
        "EOF\n"
        ')"'
    )
    assert classify_command(commit) is None
    assert classify_command("cat <<EOF > notes.txt\ngit push --force\nEOF\n") is None
    assert classify_command("cat <<-END > notes.txt\n\trm -rf ~\n\tEND\ngit reset --hard") == classify_command("git reset --hard")


@pytest.mark.parametrize("command,rule", [
    ("bash <<'EOF'\ngit push --force\nEOF", "git-push-force"),
    ("bash -s <<EOF\nrm -rf ~\nEOF\n", "rm-recursive-dangerous"),
    ("sh <<-EOF\n\tgit reset --hard\n\tEOF", "git-reset-hard"),
    ("ssh host <<EOF\nrm -rf /\nEOF", "rm-recursive-dangerous"),
    ("sudo bash <<'EOF'\nmkfs.ext4 /dev/sdb1\nEOF", "mkfs"),
    ("/bin/bash <<EOF\ngit clean -fdx\nEOF", "git-clean-force"),
    ("cat <<'EOF' | bash\ngit push -f\nEOF", "git-push-force"),
    ("out=$(bash <<'EOF'\ngit reset --hard\nEOF\n)", "git-reset-hard"),
    ("bash<<EOF\ngit push -f\nEOF", "git-push-force"),
])
def test_a_heredoc_a_shell_reads_is_commands(command, rule):
    """A shell (or ssh) runs its heredoc: the body is commands, not text."""
    assert _id(command) == (GUARD_BLOCK, rule)


@pytest.mark.parametrize("command", [
    'echo "a <<EOF"\ngit push -f\n',
    "git commit -m 'uses << EOF'\ngit push -f\n",
    "echo 'it'\\''s <<EOF'\ngit push -f",
    "# see <<EOF\ngit push -f",
    "echo \\<<EOF\ngit push -f",
])
def test_a_heredoc_operator_inside_quotes_or_a_comment_hides_nothing(command):
    assert _id(command) == (GUARD_BLOCK, "git-push-force")


@pytest.mark.parametrize("command", [
    "cat <<EOF > run.sh\ngit push --force\nEOF\nchmod +x run.sh",
    "cat <<EOF > run.sh; bash other.sh\ngit push --force\nEOF",
    "python3 - <<'EOF'\nprint('git push --force')\nEOF",
    "bash -c 'echo hi' <<EOF\ngit push --force\nEOF",
    'git commit -m "$(cat <<\'EOF\'\nfix: say "never" to git push --force\nrm -rf / is blocked\nEOF\n)"',
    "cat <<\\EOF\ngit push --force\nEOF",
    "x=$(( 1 << 2 ))",
    "cat <<<'git push --force'",
])
def test_a_heredoc_body_other_commands_read_stays_text(command):
    assert classify_command(command) is None


def test_a_command_after_a_shell_heredoc_is_still_checked():
    assert _id("bash <<'EOF'\necho hi\nEOF\ngit reset --hard") == (GUARD_BLOCK, "git-reset-hard")


def test_a_command_after_an_unterminated_heredoc_is_text():
    assert classify_command("cat <<EOF\ngit reset --hard") is None


# R-checks-6: a heredoc a SQL client reads is SQL, and a shell-run heredoc is commands;
# both are checked for destructive SQL (record tier). Other heredoc bodies stay data.
@pytest.mark.parametrize("command", [
    "psql <<EOF\nDROP TABLE users;\nEOF\n",
    "psql -d app <<'EOF'\ndelete from sessions;\nEOF",
    "mysql -u root <<SQL\nTRUNCATE TABLE audit_log;\nSQL",
    "sqlite3 app.db <<-EOF\n\tDROP DATABASE x;\n\tEOF",
    "cat <<EOF | psql\nDROP DATABASE prod;\nEOF",
    "docker exec -i db psql -U postgres <<EOF\nDROP TABLE users;\nEOF",
    "psql<<EOF\nDROP TABLE users;\nEOF",
    "/usr/bin/psql.exe <<EOF\nDROP TABLE users;\nEOF",
    "\\psql <<EOF\nDROP TABLE users;\nEOF",
    "PGPASSWORD=x psql -h db <<EOF\nDROP TABLE users;\nEOF",
    "ssh db psql <<EOF\nDROP TABLE users;\nEOF",
    "bash <<'EOF'\npsql -c 'DROP TABLE users'\nEOF",
], ids=[f"sql{i}" for i in range(12)])
def test_destructive_sql_in_a_heredoc_a_client_or_shell_reads_is_recorded(command):
    assert _id(command) == (GUARD_RECORD, "sql-destructive")


@pytest.mark.parametrize("command", [
    "psql <<EOF\nSELECT 1;\nEOF",
    'git commit -m "$(cat <<\'EOF\'\nfix: stop recording DROP TABLE in notes\nEOF\n)"',
    "cat <<EOF > migrate.sql\nDROP TABLE users;\nEOF",
    "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: m.sql\n+DROP TABLE users;\n*** End Patch\nEOF",
], ids=["select", "commit-msg", "cat-to-file", "apply-patch"])
def test_sql_in_a_heredoc_other_commands_read_is_not_recorded(command):
    assert classify_command(command) is None


def test_split_heredocs_keeps_its_two_tuple_and_never_returns_sql_as_a_script():
    assert split_heredocs("psql <<EOF\nDROP TABLE users;\nEOF\n") == ("psql <<EOF\n", [])


@pytest.mark.parametrize("value", [None, "", "   ", "\n", 42, ["git", "reset", "--hard"]])
def test_an_empty_or_absent_command_is_never_a_match(value):
    assert classify_command(value) is None


@pytest.mark.parametrize("command", [
    "git reset --hard 'unclosed",
    "rm -rf / \"unclosed",
    "/usr/bin/x?z -rf /",
])
def test_an_unparseable_command_is_never_a_match(command):
    """The safety gate fails closed on these; the guard fails open."""
    assert classify_command(command) is None


def test_nesting_beyond_the_recursion_clamp_is_never_a_match():
    deep = "eval " * 6 + "git reset --hard"
    assert classify_command(deep) is None
    assert classify_command("eval " * 3 + "git reset --hard") == classify_command("git reset --hard")
