"""Behavioral tests for aegis_core.outcomes.engine: which rules a change touches."""
import os
from pathlib import Path

from aegis_core.yaml_engine.serializer import dump_frontmatter
from aegis_core.taxonomy import RULE_TYPE_DIRS


def _make_rule(workspace, rule_id, target_paths, rule_type='trap'):
    """Create a minimal valid rule file in its type directory."""
    rules_dir = os.path.join(workspace, '.aegis', "rules", RULE_TYPE_DIRS[rule_type])
    os.makedirs(rules_dir, exist_ok=True)
    fm = {
        'id': rule_id,
        'type': rule_type,
        'target_paths': target_paths,
        'hypothesis': f'Test hypothesis for {rule_id}',
        'prediction': f'Test prediction for {rule_id}',
    }
    path = os.path.join(rules_dir, f'{rule_id}.md')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(dump_frontmatter(fm, body="Body text\n"))
    return path


class TestMatchRulesToChanges:
    """Tests for matching rules to changed files (the one loader and the one matcher)."""

    def test_rule_with_matching_target_is_returned(self, tmp_path):
        from aegis_core.outcomes.engine import match_rules_to_changes
        _make_rule(str(tmp_path), 'rule-src', ['src/*.py'])
        result = match_rules_to_changes(str(tmp_path), ['src/foo.py'])
        assert [(r['_name'], r['_path'], r['_matched_files']) for r in result] == [
            ('rule-src', '.aegis/rules/traps/rule-src.md', ['src/foo.py'])
        ]

    def test_empty_changed_files_returns_empty(self, tmp_path):
        from aegis_core.outcomes.engine import match_rules_to_changes
        _make_rule(str(tmp_path), 'rule-any', ['src/*.py'])
        assert match_rules_to_changes(str(tmp_path), []) == []

    def test_only_matching_rules_are_returned(self, tmp_path):
        from aegis_core.outcomes.engine import match_rules_to_changes
        _make_rule(str(tmp_path), 'rule-match', ['src/*.py'])
        _make_rule(str(tmp_path), 'rule-nomatch', ['docs/*.md'], rule_type='invariant')
        result = match_rules_to_changes(str(tmp_path), ['src/bar.py'])
        assert [r['_name'] for r in result] == ['rule-match']

    def test_double_star_matches_nested_directories(self, tmp_path):
        from aegis_core.outcomes.engine import match_rules_to_changes
        _make_rule(str(tmp_path), 'rule-deep', ['src/**/*.py'])
        assert [r['_name'] for r in match_rules_to_changes(str(tmp_path), ['src/sub/deep.py'])] == ['rule-deep']
        assert [r['_name'] for r in match_rules_to_changes(str(tmp_path), ['src/top.py'])] == ['rule-deep']

    def test_absolute_paths_inside_the_workspace_are_made_relative(self, tmp_path):
        from aegis_core.outcomes.engine import match_rules_to_changes
        _make_rule(str(tmp_path), 'rule-src', ['src/*.py'])
        result = match_rules_to_changes(str(tmp_path), [str(tmp_path / 'src' / 'abs.py')])
        assert [(r['_name'], r['_matched_files']) for r in result] == [('rule-src', ['src/abs.py'])]

    def test_broken_and_expired_rules_are_not_matched(self, tmp_path):
        from aegis_core.outcomes.engine import match_rules_to_changes
        _make_rule(str(tmp_path), 'rule-ok', ['src/*.py'])
        traps = tmp_path / '.aegis' / 'rules' / 'traps'
        (traps / 'broken.md').write_text('---\nid: [x\ntarget_paths: [src/*.py]\n---\n', encoding='utf-8')
        (traps / 'old.md').write_text(
            "---\nid: old\ntarget_paths: ['src/*.py']\nexpired_at: '2026-01-01'\n---\n", encoding='utf-8'
        )
        assert [r['_name'] for r in match_rules_to_changes(str(tmp_path), ['src/a.py'])] == ['rule-ok']


# ── Bug 1: Outcome Engine Path ──────────────────────────────────────────

class TestOutcomeEngineExecution:
    """Direct tests for aegis_core.outcomes.engine functions."""

    def testget_changed_files(self, tmp_path):
        import subprocess
        from aegis_core.outcomes.engine import get_changed_files

        def git(*args):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                           cwd=str(tmp_path), check=True, capture_output=True)

        # 1. not a repository: nothing is known
        if subprocess.run(["git", "-C", str(tmp_path), "rev-parse"], capture_output=True).returncode != 0:
            assert get_changed_files(str(tmp_path)) == []

        # 2. one commit: the uncommitted and untracked files
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        git("init", "-q")
        git("add", "-A")
        git("commit", "-q", "-m", "init")
        (tmp_path / "src" / "app.py").write_text("x = 2\n", encoding="utf-8")
        (tmp_path / "untracked.py").write_text("u\n", encoding="utf-8")
        assert get_changed_files(str(tmp_path)) == ["src/app.py", "untracked.py"]

        # 3. later commits: the last commit's files plus uncommitted edits
        git("add", "src/app.py")
        git("commit", "-q", "-m", "two")
        (tmp_path / "src" / "util.py").write_text("y\n", encoding="utf-8")
        git("add", "src/util.py")
        assert get_changed_files(str(tmp_path)) == ["src/app.py", "src/util.py"]

