"""`aegis init` (host-matrix spec §3.2-3.4): the repository plane, seeding, prompts and output.

The host plane (registrations, ~/.aegis/workspaces.json, refusals of user files) is
covered in test_init_hosts.py. Every test runs with an empty HOME (tests/unit/cli/conftest.py).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from aegis_cli.cli import _build_parser, main
from aegis_cli.init import InitCommand, install_rules, packaged_dir, packaged_rules, preset_rules, run_init

STANDARD = {"providence", "destructive-ops", "testing", "cost-optimization", "git-workflow"}
MINIMAL = {"providence", "destructive-ops"}
# Every shipped rule in rules/ and rules/.oracles/ except META.md (D16).
FULL = {
    "cost-optimization", "destructive-ops", "providence", "subagent-delegation",
    "architectural-tenets", "atomic-workstream-protocol", "documentation",
    "feature-specs", "git-workflow", "polyglot-standards", "tdd-protocol", "testing",
}
REPO_ROOT = next(p for p in Path(__file__).resolve().parents if (p / "pyproject.toml").exists())


@pytest.fixture
def project(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    # No host CLI and no aegis-mcp on PATH: nothing here may be detected or run.
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    return root


def _args(root: Path, *flags: str, yes: bool = True, hooks: bool = False,
          rules: "str | None" = "minimal") -> argparse.Namespace:
    """Arguments as the real parser builds them from argv (never a hand-made Namespace)."""
    argv = ["init", "--workspace", str(root)]
    argv += ["--yes"] if yes else []
    argv += [] if hooks else ["--no-hooks"]
    argv += ["--rules", rules] if rules else []
    return _build_parser().parse_args(argv + list(flags))


def _seeded(root: Path) -> set:
    return {p.stem for p in (root / ".aegis" / "rules" / "personas").glob("*.md")}


# ── The one rule-source locator (defense #20) ────────────────────────────────


class TestRuleSourceLocator:
    def test_packaged_rules_come_from_the_shipped_rules_package(self):
        found = packaged_rules()
        assert set(found) == FULL
        for name, path in found.items():
            assert path.name == f"{name}.md"
            assert path.resolve().parent in {REPO_ROOT / "rules", REPO_ROOT / "rules" / ".oracles"}

    def test_a_top_level_rules_package_on_sys_path_is_never_imported_or_read(self, tmp_path, monkeypatch):
        """Release review: the wheel shipped a top-level `rules` package, so a repository's
        own rules/ (first on sys.path under `python -m`) or another distribution's `rules`
        replaced Aegis's rules, and its __init__.py ran."""
        import sys

        marker = tmp_path / "PLANTED_RAN"
        planted = tmp_path / "repo" / "rules"
        planted.mkdir(parents=True)
        (planted / "__init__.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n", encoding="utf-8")
        for name in ("pricing", "providence"):
            (planted / f"{name}.md").write_text("---\nid: planted\n---\n# planted\n", encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path / "repo"))
        monkeypatch.delitem(sys.modules, "rules", raising=False)
        try:
            found = packaged_rules()
            full = {p.stem for p in preset_rules("full")}
        finally:
            if str(planted) in str(getattr(sys.modules.get("rules"), "__file__", "")):
                del sys.modules["rules"]
        assert set(found) == FULL and full == FULL
        assert all(planted not in p.parents for p in found.values())
        assert not marker.exists()

    def test_the_shipped_data_lives_under_aegis_core_in_a_wheel_and_in_the_checkout_here(self, tmp_path):
        """A wheel maps rules/ and skills/ into aegis_core/_data/ (pyproject package-dir);
        a source checkout keeps them at its root, next to pyproject.toml."""
        site = tmp_path / "site" / "aegis_core"
        (site / "_data" / "rules").mkdir(parents=True)
        assert packaged_dir("rules", base=site) == site / "_data" / "rules"
        checkout = tmp_path / "checkout"
        (checkout / "aegis_core").mkdir(parents=True)
        (checkout / "rules").mkdir()
        (checkout / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        assert packaged_dir("rules", base=checkout / "aegis_core") == checkout / "rules"
        # site-packages has no pyproject.toml: a sibling rules/ there is another distribution's.
        other = tmp_path / "other-site"
        (other / "aegis_core").mkdir(parents=True)
        (other / "rules").mkdir()
        assert packaged_dir("rules", base=other / "aegis_core") == other / "aegis_core" / "_data" / "rules"
        assert packaged_dir("skills") in {REPO_ROOT / "skills", REPO_ROOT / "aegis_core" / "_data" / "skills"}

    def test_a_broken_install_without_the_data_is_reported_not_guessed(self, tmp_path, monkeypatch):
        import aegis_cli.init as init_mod

        monkeypatch.setattr(init_mod, "packaged_dir", lambda name, base=None: tmp_path / "missing" / name)
        with pytest.raises(ValueError, match="not found; reinstall aegis-guardrails"):
            preset_rules("minimal")

    @pytest.mark.parametrize("preset, names", [("minimal", MINIMAL), ("standard", STANDARD), ("full", FULL)])
    def test_presets_resolve_through_the_locator(self, preset, names):
        assert {p.stem for p in preset_rules(preset)} == names

    def test_unknown_preset_is_refused(self):
        with pytest.raises(ValueError, match="unknown rule preset"):
            preset_rules("huge")

    def test_install_rules_copies_the_packaged_bytes_flat(self, tmp_path):
        installed = install_rules(tmp_path, preset="standard")
        assert set(installed) == STANDARD
        for name in STANDARD:
            assert (tmp_path / f"{name}.md").read_bytes() == packaged_rules()[name].read_bytes()

    def test_install_rules_keeps_existing_files_unless_forced(self, tmp_path):
        (tmp_path / "providence.md").write_text("mine", encoding="utf-8")
        assert "providence" in install_rules(tmp_path, preset="minimal")
        assert (tmp_path / "providence.md").read_text(encoding="utf-8") == "mine"
        install_rules(tmp_path, preset="minimal", force=True)
        assert (tmp_path / "providence.md").read_bytes() == packaged_rules()["providence"].read_bytes()

    def test_install_rules_dry_run_writes_nothing(self, tmp_path):
        assert set(install_rules(tmp_path / "x", preset="minimal", dry_run=True)) == MINIMAL
        assert not (tmp_path / "x").exists()


# ── Seeding the workspace ────────────────────────────────────────────────────


class TestSeeding:
    @pytest.mark.parametrize("preset, names", [("minimal", MINIMAL), ("standard", STANDARD), ("full", FULL)])
    def test_preset_is_seeded_into_the_persona_rules(self, project, preset, names):
        assert run_init(_args(project, rules=preset)) == 0
        assert _seeded(project) == names

    def test_default_preset_is_standard(self, project):
        assert run_init(_args(project, rules=None)) == 0
        assert _seeded(project) == STANDARD

    def test_seeded_rules_load_without_errors(self, project):
        from aegis_core.rules import load_rules

        assert run_init(_args(project, rules="standard")) == 0
        ruleset = load_rules(project)
        assert not ruleset.errors
        assert {r.id for r in ruleset.rules} == STANDARD | {"no-eval"}  # the one active starter

    def test_an_existing_rule_with_the_same_id_is_never_overwritten_or_duplicated(self, project):
        mine = project / ".aegis" / "rules" / "invariants" / "providence.md"
        mine.parent.mkdir(parents=True)
        mine.write_text("---\nid: providence\nhypothesis: mine\n---\n# Mine\n", encoding="utf-8")
        edited = project / ".aegis" / "rules" / "personas" / "testing.md"
        edited.parent.mkdir(parents=True)
        edited.write_text("my testing rule", encoding="utf-8")

        assert run_init(_args(project, rules="standard")) == 0

        assert not (project / ".aegis" / "rules" / "personas" / "providence.md").exists()
        assert mine.read_text(encoding="utf-8").endswith("# Mine\n")
        assert edited.read_text(encoding="utf-8") == "my testing rule"

    def test_a_symlinked_rules_dir_is_refused_and_nothing_is_written(self, project, tmp_path):
        from conftest import symlink_or_skip

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (project / ".aegis" / "rules").mkdir(parents=True)
        symlink_or_skip(elsewhere, project / ".aegis" / "rules" / "personas", target_is_directory=True)

        assert run_init(_args(project)) == 1

        assert list(elsewhere.iterdir()) == []
        assert not (project / "AGENTS.md").exists()


class TestSeededRulesAreLintClean:
    """What init seeds passes the repository's own lint: `aegis check` and the pre-commit
    hook print nothing about files init just wrote."""

    @pytest.mark.parametrize("preset", ["minimal", "standard", "full"])
    def test_a_fresh_init_leaves_every_check_clean(self, project, preset):
        from aegis_core.verification.checkpoint_checks import run_all_checks

        assert run_init(_args(project, rules=preset)) == 0
        assert run_all_checks(project) == []

    def test_seeded_rules_declare_their_type_and_that_they_target_no_file(self, project):
        from aegis_core.rules import load_rules
        from aegis_core.yaml_engine.frontmatter import split_frontmatter

        assert run_init(_args(project, rules="standard")) == 0
        personas = [r for r in load_rules(project).rules if r.path.startswith(".aegis/rules/personas/")]
        assert {r.id for r in personas} == STANDARD
        for rule in personas:
            assert rule.ok and rule.type == "persona"
            assert rule.meta["type"] == "persona" and rule.meta["target_paths"] == []
            assert rule.target_paths == ()
            packaged = packaged_rules()[rule.id].read_bytes().decode("utf-8").replace("\r\n", "\n")
            # The guidance itself is as shipped (a Windows checkout may hold either line ending).
            assert rule.body.replace("\r\n", "\n") == split_frontmatter(packaged)[2].strip()

    def test_the_output_says_the_seeded_rules_apply_to_no_file_yet(self, project, capsys):
        assert run_init(_args(project, rules="minimal")) == 0
        assert "target_paths" in capsys.readouterr().out

    def test_a_crlf_packaged_rule_is_seeded_with_crlf(self, project, tmp_path, monkeypatch):
        source = tmp_path / "pkg" / "providence.md"
        source.parent.mkdir()
        source.write_bytes(b"---\r\nid: providence\r\ndomain: governance\r\n---\r\n# Body\r\n")
        monkeypatch.setattr("aegis_cli.init.preset_rules", lambda preset: [source])
        installed = install_rules(tmp_path / "out", preset="minimal", rule_type="persona")
        assert installed == ["providence"]
        assert (tmp_path / "out" / "providence.md").read_bytes() == (
            b"---\r\nid: providence\r\ntype: persona\r\ntarget_paths: []\r\ndomain: governance\r\n"
            b"---\r\n# Body\r\n")

    def test_a_declared_type_is_replaced_by_the_seeded_one(self, project, tmp_path, monkeypatch):
        source = tmp_path / "pkg" / "testing.md"
        source.parent.mkdir()
        source.write_bytes(b"---\nid: testing\ntype: trap\ntarget_paths: tests/**\n---\nBody\n")
        monkeypatch.setattr("aegis_cli.init.preset_rules", lambda preset: [source])
        install_rules(tmp_path / "out", preset="minimal", rule_type="persona")
        assert (tmp_path / "out" / "testing.md").read_bytes() == (
            b"---\nid: testing\ntype: persona\ntarget_paths: tests/**\n---\nBody\n")


def _tree(*roots: Path) -> dict:
    out = {}
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            for name in dirs + files:
                p = Path(dirpath, name)
                out[str(p)] = ("link", os.readlink(p)) if p.is_symlink() else (
                    None if p.is_dir() else p.read_bytes())
    return out


class TestHookRefusal:
    """A pre-commit hook init cannot safely write (a link out of the repository, a dangling
    link, a broken Aegis block) stops init before anything is written, with the real reason;
    it was reported as 'skipped (not a git repository)' with status ok."""

    @pytest.fixture
    def hooks(self, project):
        hooks = project / ".git" / "hooks"
        hooks.mkdir(parents=True)
        return hooks

    def _refused(self, project, capsys, *flags, message):
        home = Path.home()
        before = _tree(project, home)
        assert run_init(_args(project, *flags, hooks=True)) == 1
        assert _tree(project, home) == before
        err = capsys.readouterr().err
        assert message in err and "--no-hooks" in err and "Nothing was written." in err
        assert "Use --force" not in err  # init's --force does not apply to the hook
        return err

    def test_a_hook_linked_outside_the_repository(self, project, hooks, tmp_path, capsys):
        from conftest import symlink_or_skip

        outside = tmp_path / "dotfiles" / "pre-commit"
        outside.parent.mkdir()
        outside.write_bytes(b"#!/bin/sh\necho shared\n")
        symlink_or_skip(outside, hooks / "pre-commit")
        err = self._refused(project, capsys, message="outside the repository")
        assert "aegis hook install --force" in err
        assert outside.read_bytes() == b"#!/bin/sh\necho shared\n"

    def test_a_dangling_hook_link(self, project, hooks, tmp_path, capsys):
        from conftest import symlink_or_skip

        symlink_or_skip(tmp_path / "gone", hooks / "pre-commit")
        self._refused(project, capsys, message="dangling")

    def test_an_unterminated_aegis_block(self, project, hooks, capsys):
        (hooks / "pre-commit").write_bytes(b"#!/bin/sh\n# >>> aegis pre-commit >>>\necho half\n")
        self._refused(project, capsys, message="unterminated")

    def test_a_dry_run_reports_it_too(self, project, hooks, tmp_path, capsys):
        from conftest import symlink_or_skip

        symlink_or_skip(tmp_path / "gone", hooks / "pre-commit")
        self._refused(project, capsys, "--dry-run", message="dangling")

    def test_json_reports_refused_not_ok(self, project, hooks, tmp_path, capsys):
        from conftest import symlink_or_skip

        symlink_or_skip(tmp_path / "gone", hooks / "pre-commit")
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--rules", "minimal"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "refused"
        assert any("dangling" in e for e in payload["errors"])

    def test_no_hooks_sets_up_everything_else(self, project, hooks, tmp_path):
        from conftest import symlink_or_skip

        outside = tmp_path / "dotfiles" / "pre-commit"
        outside.parent.mkdir()
        outside.write_bytes(b"#!/bin/sh\n")
        symlink_or_skip(outside, hooks / "pre-commit")
        assert run_init(_args(project, hooks=False)) == 0
        assert (project / "AGENTS.md").is_file()
        assert outside.read_bytes() == b"#!/bin/sh\n"

    @pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                        reason="needs POSIX directory permissions as a non-root user")
    def test_a_read_only_hooks_directory(self, project, hooks, capsys):
        hooks.chmod(0o555)
        try:
            self._refused(project, capsys, message="not a writable directory")
            self._refused(project, capsys, "--dry-run", message="not a writable directory")
        finally:
            hooks.chmod(0o755)

    def test_outside_a_git_repository_the_hook_is_skipped(self, project, capsys):
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--rules", "minimal"]) == 0
        payload = json.loads(capsys.readouterr().out)
        targets = {a["target"]: a["result"] for a in payload["actions"]}
        assert targets["pre-commit hook"] == "skipped (not a git repository)"
        assert targets["prepare-commit-msg hook"] == "skipped (not a git repository)"

    def test_git_repository_installs_and_reports_both_hooks(self, project, hooks, capsys):
        assert run_init(_args(project, "--dry-run", hooks=True)) == 0
        dry_out = capsys.readouterr().out
        assert "Would install pre-commit hook" in dry_out
        assert "Would install prepare-commit-msg hook" in dry_out
        assert not (hooks / "pre-commit").exists() and not (hooks / "prepare-commit-msg").exists()

        assert run_init(_args(project, hooks=True)) == 0
        out = capsys.readouterr().out
        assert (hooks / "pre-commit").is_file() and (hooks / "prepare-commit-msg").is_file()
        assert f"Pre-commit hook installed ({hooks / 'pre-commit'})" in out
        assert f"Prepare-commit-msg hook installed ({hooks / 'prepare-commit-msg'})" in out

    def test_existing_foreign_prepare_commit_msg_hook_is_kept(self, project, hooks, capsys):
        foreign = hooks / "prepare-commit-msg"
        foreign.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--rules", "minimal"]) == 0
        payload = json.loads(capsys.readouterr().out)
        steps = {a["target"]: a for a in payload["actions"]}
        assert steps["pre-commit hook"]["result"] == "installed"
        assert steps["prepare-commit-msg hook"]["result"] == "kept"
        assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho custom\n"

        assert run_init(_args(project, hooks=True)) == 0
        out = capsys.readouterr().out
        assert "Prepare-commit-msg hook kept (existing hook is not Aegis's; left alone)" in out
        assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\necho custom\n"



GIT = shutil.which("git")


def _git(*args: str) -> None:
    subprocess.run([GIT, *args], check=True, capture_output=True, stdin=subprocess.DEVNULL)


@pytest.mark.skipif(GIT is None, reason="needs git")
class TestSharedHooksDirectory:
    """core.hooksPath set to a directory outside the repository (a team or dotfiles hooks
    dir, often global) holds a pre-commit hook that runs in every repository using it.
    init adds no block there; it names --no-hooks and the explicit `aegis hook install`."""

    TEAM_HOOK = b"#!/bin/sh\necho team-hook\n"

    @pytest.fixture(autouse=True)
    def git_on_path(self, project, tmp_path, monkeypatch):
        # core.hooksPath is read through git; the project fixture's PATH holds no binary.
        monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "empty-bin"), os.path.dirname(GIT)]))

    @pytest.fixture
    def shared(self, project, tmp_path):
        _git("init", "-q", str(project))
        shared = tmp_path / "team-hooks"
        shared.mkdir()
        (shared / "pre-commit").write_bytes(self.TEAM_HOOK)
        _git("-C", str(project), "config", "core.hooksPath", str(shared))
        return shared

    def test_init_refuses_and_writes_nothing(self, project, shared, capsys):
        home = Path.home()
        before = _tree(project, home, shared)
        for flags in ((), ("--dry-run",)):
            assert run_init(_args(project, *flags, hooks=True)) == 1
            assert _tree(project, home, shared) == before
            err = capsys.readouterr().err
            assert str(shared) in err and "outside this repository" in err
            assert "--no-hooks" in err and "aegis hook install" in err and "Nothing was written." in err

    def test_no_hooks_sets_up_everything_else(self, project, shared):
        assert run_init(_args(project, hooks=False)) == 0
        assert (project / "AGENTS.md").is_file()
        assert (shared / "pre-commit").read_bytes() == self.TEAM_HOOK

    def test_a_hooks_path_inside_the_repository_still_gets_the_hook(self, project, capsys):
        _git("init", "-q", str(project))
        _git("-C", str(project), "config", "core.hooksPath", ".githooks")
        assert run_init(_args(project, hooks=True)) == 0
        assert "aegis pre-commit" in (project / ".githooks" / "pre-commit").read_text(encoding="utf-8")

    def test_after_aegis_hook_install_there_init_leaves_it_and_succeeds(self, project, shared, capsys):
        """Following the refusal's advice must not leave init refusing forever: the shared
        hook already runs Aegis, so init has nothing to add and does not rewrite it."""
        from aegis_cli.hooks import install_hook

        assert install_hook(project)
        hook = shared / "pre-commit"
        hook_bytes, hook_inode = hook.read_bytes(), os.stat(hook).st_ino
        capsys.readouterr()
        for flags in (("--dry-run",), ()):
            assert run_init(_args(project, *flags, hooks=True)) == 0
            assert (hook.read_bytes(), os.stat(hook).st_ino) == (hook_bytes, hook_inode)
            out = capsys.readouterr().out
            assert f"Pre-commit hook: {hook}" in out and "already runs the Aegis hook" in out
        assert (project / "AGENTS.md").is_file()

    def test_an_older_aegis_block_there_is_still_refused(self, project, shared, capsys):
        from aegis_cli.hooks.management import generate_hook_block

        hook = shared / "pre-commit"
        hook.write_text("#!/bin/sh\n" + generate_hook_block(str(shared / "old" / "python3"), import_root=str(shared)),
                        encoding="utf-8")
        before = _tree(project, shared)
        assert run_init(_args(project, hooks=True)) == 1
        assert _tree(project, shared) == before
        assert "aegis hook install" in capsys.readouterr().err


@pytest.mark.skipif(GIT is None, reason="needs git")
def test_a_hooks_directory_linked_out_of_the_repository_is_named_as_a_link(project, tmp_path, monkeypatch, capsys):
    """Without core.hooksPath, a .git/hooks that is a link to a dotfiles directory is
    refused like a shared hooks path, and the message says what the user actually has."""
    from conftest import symlink_or_skip

    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "empty-bin"), os.path.dirname(GIT)]))
    _git("init", "-q", str(project))
    dotfiles = tmp_path / "dotfiles-hooks"
    dotfiles.mkdir()
    shutil.rmtree(project / ".git" / "hooks")
    symlink_or_skip(dotfiles, project / ".git" / "hooks", target_is_directory=True)
    assert run_init(_args(project, hooks=True)) == 1
    err = capsys.readouterr().err
    assert "core.hooksPath" not in err
    assert f"{project / '.git' / 'hooks'} is a link to {dotfiles.resolve()}" in err
    assert "outside this repository" in err and "--no-hooks" in err
    assert list(dotfiles.iterdir()) == []


class TestRepositoryPlaneChecks:
    """What the writes under .aegis/ need is checked before anything is written: a dry run
    reported success and the real run then died with a raw OSError after writing
    .aegis/config.json, the rules and AGENTS.md."""

    def _refused(self, project, capsys, *flags, message):
        home = Path.home()
        before = _tree(project, home)
        for extra in ((), ("--dry-run",)):
            assert run_init(_args(project, *flags, *extra)) == 1
            assert _tree(project, home) == before
            err = capsys.readouterr().err
            assert message in err and "Nothing was written." in err

    @pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                        reason="needs POSIX directory permissions as a non-root user")
    def test_a_read_only_rules_directory(self, project, capsys):
        personas = project / ".aegis" / "rules" / "personas"
        personas.mkdir(parents=True)
        personas.chmod(0o555)
        try:
            self._refused(project, capsys, message="not a writable directory")
        finally:
            personas.chmod(0o755)

    @pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                        reason="needs POSIX directory permissions as a non-root user")
    def test_a_read_only_aegis_directory(self, project, capsys):
        aegis = project / ".aegis"
        aegis.mkdir()
        aegis.chmod(0o555)
        try:
            self._refused(project, capsys, message="not a writable directory")
        finally:
            aegis.chmod(0o755)

    def test_a_symlinked_state_directory(self, project, tmp_path, capsys):
        from conftest import symlink_or_skip

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (project / ".aegis").mkdir()
        symlink_or_skip(elsewhere, project / ".aegis" / "state", target_is_directory=True)
        self._refused(project, capsys, message="symlink")
        assert list(elsewhere.iterdir()) == []

    def test_a_file_where_a_directory_belongs(self, project, capsys):
        (project / ".aegis").mkdir()
        (project / ".aegis" / "state").write_bytes(b"not a directory\n")
        self._refused(project, capsys, message="not a directory")

    def test_a_write_error_after_the_check_names_what_was_already_written(self, project, capsys, monkeypatch):
        """Only a change between the check and the write gets past the check pass; the
        error is then reported with what init had already done, not as a traceback."""
        import aegis_cli.init as init_mod

        (project / ".git" / "hooks").mkdir(parents=True)

        def disk_error(*args, dry_run=False, **kwargs):
            if dry_run:
                return True
            raise PermissionError(13, "Permission denied", str(project / ".git" / "hooks" / "pre-commit"))

        monkeypatch.setattr(init_mod, "install_hook", disk_error)
        assert run_init(_args(project, hooks=True)) == 1
        err = capsys.readouterr().err
        assert "Permission denied" in err and "pre-commit" in err
        assert "Already written:" in err and "AGENTS.md" in err and ".aegis/config.json" in err
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--rules", "minimal"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "failed"
        assert any("Permission denied" in e for e in payload["errors"])


# ── Prompt, dry run, output ──────────────────────────────────────────────────


def _snapshot(*roots: Path) -> dict:
    out = {}
    for root in roots:
        for dirpath, dirs, files in os.walk(root):
            for name in dirs + files:
                p = Path(dirpath, name)
                out[str(p)] = None if p.is_dir() else p.read_bytes()
    return out


class TestPromptAndDryRun:
    def test_declining_the_prompt_writes_nothing(self, project, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda _: "n")
        home = Path.home()
        before = _snapshot(project, home)
        assert run_init(_args(project, yes=False)) == 0
        assert "Aborted" in capsys.readouterr().out
        assert _snapshot(project, home) == before

    def test_end_of_input_at_the_prompt_is_not_success(self, project, monkeypatch, capsys):
        """`aegis init < /dev/null` in a script that forgot --yes did nothing and exited 0."""
        def eof(_):
            raise EOFError
        monkeypatch.setattr("builtins.input", eof)
        home = Path.home()
        before = _snapshot(project, home)
        assert run_init(_args(project, yes=False)) == 1
        assert _snapshot(project, home) == before
        err = capsys.readouterr().err
        assert "no answer" in err and "--yes" in err

    def test_interrupting_the_prompt_exits_130(self, project, monkeypatch, capsys):
        def interrupt(_):
            raise KeyboardInterrupt
        monkeypatch.setattr("builtins.input", interrupt)
        assert run_init(_args(project, yes=False)) == 130
        assert "Aborted" in capsys.readouterr().out
        assert not (project / ".aegis").exists()

    def test_accepting_the_prompt_proceeds(self, project, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert run_init(_args(project, yes=False)) == 0
        assert "Done!" in capsys.readouterr().out
        assert (project / "AGENTS.md").is_file()

    def test_dry_run_writes_nothing_and_says_what_it_would_do(self, project, capsys):
        home = Path.home()
        before = _snapshot(project, home)
        assert run_init(_args(project, "--dry-run", yes=False, hooks=True)) == 0
        out = capsys.readouterr().out
        assert _snapshot(project, home) == before
        assert "Aegis Guardrails — Workspace Setup" in out
        assert "[DRY-RUN] providence" in out
        assert "AGENTS.md" in out
        assert "Dry run complete. No files were created." in out

    def test_header_and_next_step(self, project, capsys):
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert "Aegis Guardrails — Workspace Setup" in out
        assert "After a session, run: aegis status" in out
        assert "Soma" not in out

    def test_home_directory_is_refused(self, tmp_path, monkeypatch, capsys):
        home = Path.home()
        assert run_init(_args(home)) == 1
        assert "home directory" in capsys.readouterr().err
        assert not (home / ".aegis").exists()
        assert not (home / "AGENTS.md").exists()


class TestPolyglot:
    def test_languages_are_detected_and_drivers_provisioned(self, project, capsys):
        from aegis_core.skills.slots import SlotRegistry

        (project / "Cargo.toml").write_text("[package]\nname = 'rust_app'\n", encoding="utf-8")
        (project / "src").mkdir()
        (project / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert "Detected language(s): Rust" in out
        assert "Configured AST driver (.rs):" in out
        assert SlotRegistry.load(project).get_ast_driver(".rs") is not None
        assert not (project / ".aegis" / "drivers").exists()

    def test_dry_run_only_says_it_would_configure(self, project, capsys):
        (project / "Cargo.toml").write_text("[package]\nname = 'rust_app'\n", encoding="utf-8")
        assert run_init(_args(project, "--dry-run")) == 0
        assert "Would configure AST driver (.rs):" in capsys.readouterr().out
        assert not (project / ".aegis" / "config.json").exists()

    def test_unknown_project_type(self, project, capsys):
        assert run_init(_args(project)) == 0
        assert "Project type: unknown" in capsys.readouterr().out


# ── JSON output (fleet dashboards read it) ───────────────────────────────────


class TestJsonOutput:
    def test_json_result_carries_provenance_and_actions(self, project, capsys):
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks",
                     "--rules", "minimal"]) == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["source"] == "aegis init"
        assert isinstance(payload["aegis_version"], str) and payload["aegis_version"]
        assert payload["checked_at"].endswith("Z") and "T" in payload["checked_at"]
        assert payload["scope"]["workspace"] == str(project.resolve())
        assert payload["scope"]["hosts"] == []
        assert payload["dry_run"] is False
        assert payload["status"] == "ok"
        targets = {a["target"]: a["result"] for a in payload["actions"]}
        assert targets["AGENTS.md"] == "created"
        assert targets["~/.aegis/workspaces.json"] == "added"

    def test_json_dry_run_plans_and_writes_nothing(self, project, capsys):
        assert main(["--json", "init", "--workspace", str(project), "--dry-run"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["dry_run"] is True
        assert not (project / ".aegis").exists()

    def test_json_without_yes_or_dry_run_is_a_usage_error(self, project, capsys):
        assert main(["--json", "init", "--workspace", str(project)]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "--yes or --dry-run" in captured.err
        assert not (project / ".aegis").exists()

    def test_json_refusal_is_reported_as_json(self, project, capsys):
        (project / "AGENTS.md").write_text(
            "<!-- aegis:begin id=bootstrap v=1 sha=000000000000 -->\nmine\n<!-- aegis:end id=bootstrap -->\n",
            encoding="utf-8")
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "refused"
        assert any("edited by hand" in e for e in payload["errors"])


# ── Command line surface ─────────────────────────────────────────────────────


class TestCommandLine:
    def test_parser_contract(self):
        parser = argparse.ArgumentParser()
        InitCommand().configure_parser(parser)
        ns = parser.parse_args(["--host", "antigravity,codex-cli", "--rules", "full", "--dry-run",
                                "--yes", "--force", "--pin", "--no-hooks"])
        assert ns.host == ["codex-cli", "antigravity"]
        assert (ns.rules, ns.dry_run, ns.yes, ns.force, ns.pin, ns.no_hooks) == ("full", True, True, True, True, True)
        defaults = parser.parse_args([])
        assert (defaults.host, defaults.rules, defaults.pin) == (None, "standard", False)
        assert parser.parse_args(["--host", "auto"]).host == "auto"

    def test_execute_delegates_to_run_init(self, monkeypatch):
        seen = []
        monkeypatch.setattr("aegis_cli.init.run_init", lambda a: seen.append(a) or 0)
        ns = argparse.Namespace()
        assert InitCommand().execute(ns) == 0 and seen == [ns]

    @pytest.mark.parametrize("argv, line", [
        (["init", "--platform", "claude"], "aegis init --platform was removed in v4: use aegis init --host"),
        (["init", "--platform=gemini", "--yes"], "aegis init --platform was removed in v4: use aegis init --host"),
        (["init", "--mcp"], "aegis init --mcp was removed in v4: use aegis init --host (no project MCP file is written)"),
        (["init", "--local"], "aegis init --local was removed in v4: rules live in .aegis/rules; use aegis init"),
    ])
    def test_removed_flags_exit_2_with_one_pointer_line(self, project, argv, line, capsys):
        with pytest.raises(SystemExit) as exc:
            main(argv + ["--workspace", str(project)])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == line + "\n"
        assert not (project / ".aegis").exists()

    def test_help_names_every_host_with_its_surfaces_and_aliases(self, capsys):
        from aegis_cli.install_hosts import registrable_hosts

        with pytest.raises(SystemExit):
            main(["init", "--help"])
        # argparse wraps help at spaces and after hyphens; undo both before matching.
        out = re.sub(r"-\s+", "-", " ".join(capsys.readouterr().out.split()))
        for host in registrable_hosts():
            assert host.id in out
            for text in host.surfaces + host.aliases:
                assert text in out, text

    def test_claude_desktop_is_refused_with_the_host_that_covers_its_code_tab(self, project, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["init", "--host", "claude-desktop", "--workspace", str(project)])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "identity only" in err and "use --host claude-code" in err
        assert not (project / ".aegis").exists()

    def test_removed_flags_are_not_in_help(self, capsys):
        with pytest.raises(SystemExit):
            main(["init", "--help"])
        out = capsys.readouterr().out
        assert "--host" in out
        for gone in ("--platform", "--mcp", "--local"):
            assert gone not in out

    @pytest.mark.parametrize("value, message", [
        ("zed", "unknown host 'zed'"),
        ("claude-desktop", "identity only"),
    ])
    def test_bad_host_is_a_usage_error(self, project, value, message, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["init", "--host", value, "--workspace", str(project)])
        assert exc.value.code == 2
        assert message in capsys.readouterr().err

    def test_retired_gemini_cli_exits_2_and_points_at_antigravity(self, project, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["init", "--host", "gemini-cli", "--yes", "--workspace", str(project)])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines()[-1] == (
            "aegis init: error: argument --host: gemini-cli is not supported: Google retired Gemini CLI "
            "for individual Code Assist accounts; use --host antigravity.")
        assert "gemini mcp" not in captured.err
        assert "v4.1" not in captured.err
        assert not (project / ".aegis").exists()


# ── --skills: project the packaged skills for the hosts (v4.1 spec §3) ──────

PACKAGED_SKILLS = sorted(p.parent.name for p in packaged_dir("skills").glob("*/SKILL.md"))


def _projected(root: Path, directory: str) -> list:
    return sorted(p.parent.name for p in (root / directory).glob("*/SKILL.md"))


def _init_json(project: Path, capsys, *flags: str):
    rc = main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks", "--rules", "minimal", *flags])
    return rc, json.loads(capsys.readouterr().out)


class TestInitSkills:
    @pytest.fixture(autouse=True)
    def _no_fsync(self, monkeypatch):
        """os.fsync is the OS durability boundary; these tests check bytes, and the fsyncs
        of 15 or 30 copies per test would double this module's run time on a slow disk
        (the mutation gate's baseline has a fixed budget)."""
        monkeypatch.setattr(os, "fsync", lambda fd: None)

    def test_skills_projects_every_packaged_skill_for_the_selected_hosts(self, project, capsys):
        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code,codex-cli")

        assert rc == 0
        assert len(PACKAGED_SKILLS) == 15
        assert _projected(project, ".claude/skills") == PACKAGED_SKILLS
        assert _projected(project, ".agents/skills") == PACKAGED_SKILLS
        steps = {a["target"]: a for a in payload["actions"]}
        assert steps[".agents/skills"]["result"] == "synced"
        assert steps[".agents/skills"]["detail"] == "codex-cli, unverified: 15 created"
        assert steps[".claude/skills"]["detail"] == "claude-code, unverified: 15 created"
        genesis = (project / ".claude/skills/genesis/SKILL.md").read_text(encoding="utf-8")
        assert genesis.startswith("---\nname: genesis\ndescription: ")

    def test_text_output_names_each_skills_directory(self, project, capsys):
        assert run_init(_args(project, "--skills", "--host", "antigravity")) == 0
        out = capsys.readouterr().out
        assert ".agents/skills: synced (antigravity, unverified: 15 created)" in out

    def test_a_second_init_leaves_the_projected_skills_unchanged(self, project, capsys):
        assert run_init(_args(project, "--skills", "--host", "claude-code")) == 0
        before = {p: p.read_bytes() for p in (project / ".claude").rglob("SKILL.md")}
        capsys.readouterr()

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")

        assert rc == 0
        step = next(a for a in payload["actions"] if a["target"] == ".claude/skills")
        assert (step["result"], step["detail"]) == ("unchanged", "claude-code, unverified: 15 unchanged")
        assert {p: p.read_bytes() for p in (project / ".claude").rglob("SKILL.md")} == before

    def test_without_skills_nothing_is_projected(self, project, capsys):
        rc, payload = _init_json(project, capsys, "--host", "claude-code")
        assert rc == 0
        assert not (project / ".claude").exists()
        assert not any("skills" in a["target"] for a in payload["actions"])

    def test_skills_uses_the_hosts_already_in_the_config(self, project):
        assert run_init(_args(project, "--host", "antigravity")) == 0
        assert not (project / ".agents").exists()

        assert run_init(_args(project, "--skills")) == 0

        assert _projected(project, ".agents/skills") == PACKAGED_SKILLS
        assert not (project / ".claude").exists()

    def test_skills_without_any_host_is_skipped_with_a_pointer(self, project, capsys):
        rc, payload = _init_json(project, capsys, "--skills")

        assert rc == 0
        step = next(a for a in payload["actions"] if a["target"] == "skills")
        assert step["result"] == "skipped" and "--host" in step["detail"]
        assert not (project / ".claude").exists() and not (project / ".agents").exists()

    def test_a_refused_skills_directory_stops_init_before_anything_is_written(self, project, tmp_path, capsys):
        from conftest import symlink_or_skip

        outside = tmp_path / "outside"
        outside.mkdir()
        symlink_or_skip(outside, project / ".claude", target_is_directory=True)

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")

        assert rc == 1 and payload["status"] == "refused"
        assert not (project / ".aegis").exists() and not (project / "AGENTS.md").exists()
        assert list(outside.iterdir()) == []
        assert any(".claude" in e and "symlink" in e and "--skills" in e for e in payload["errors"])

    @pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                        reason="needs POSIX permission bits that apply to this user")
    def test_a_skills_directory_that_cannot_be_written_stops_init_before_anything_is_written(self, project, capsys):
        (project / ".claude").mkdir()
        os.chmod(project / ".claude", 0o555)
        try:
            rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")
        finally:
            os.chmod(project / ".claude", 0o755)

        assert rc == 1 and payload["status"] == "refused"
        assert not (project / ".aegis").exists() and not (project / "AGENTS.md").exists()
        assert list((project / ".claude").iterdir()) == []
        assert payload["errors"][0] == (
            f"skills: .claude/skills/{PACKAGED_SKILLS[0]}/SKILL.md cannot be written "
            f"({project.resolve() / '.claude'} is not a writable directory). Fix it, or re-run without --skills.")

    def test_a_user_s_own_skill_file_is_kept_with_a_warning(self, project, capsys):
        mine = project / ".claude" / "skills" / "genesis" / "SKILL.md"
        mine.parent.mkdir(parents=True)
        mine.write_bytes(b"my genesis\n")

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")

        assert rc == 0
        assert mine.read_bytes() == b"my genesis\n"
        assert any(w.startswith(".claude/skills/genesis/SKILL.md: ") and "marker" in w for w in payload["warnings"])
        step = next(a for a in payload["actions"] if a["target"] == ".claude/skills")
        assert step["detail"] == "claude-code, unverified: 14 created, 1 skipped"

    def test_dry_run_projects_nothing_and_records_no_event(self, project, capsys):
        from aegis_core import events

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code", "--dry-run")

        assert rc == 0 and payload["dry_run"] is True
        step = next(a for a in payload["actions"] if a["target"] == ".claude/skills")
        assert step["detail"] == "claude-code, unverified: 15 created"
        assert not (project / ".claude").exists() and not (project / ".aegis").exists()
        assert events.read(project, "skills_sync").rows == []

    def test_an_aegis_copy_updated_alone_is_reported_synced(self, project, capsys):
        assert run_init(_args(project, "--skills", "--host", "claude-code")) == 0
        target = project / ".claude/skills/genesis/SKILL.md"
        lines = target.read_text(encoding="utf-8").splitlines(True)
        # An older Aegis copy: unedited (its marker matches its text), but not today's text.
        head, old_body = "".join(lines[:4]), "\nAn older genesis.\n"
        sha = hashlib.sha256((head + old_body).encode("utf-8")).hexdigest()[:12]
        target.write_text(head + f"<!-- aegis:skill id=genesis v=1 sha={sha} -->\n" + old_body, encoding="utf-8")
        capsys.readouterr()

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")

        assert rc == 0
        step = next(a for a in payload["actions"] if a["target"] == ".claude/skills")
        assert (step["result"], step["detail"]) == ("synced", "claude-code, unverified: 1 updated, 14 unchanged")
        assert "An older genesis." not in target.read_text(encoding="utf-8")

    def test_skills_with_an_unreadable_config_uses_the_hosts_named_now(self, project, capsys):
        (project / ".aegis").mkdir()
        (project / ".aegis" / "config.json").write_text("{not json", encoding="utf-8")

        rc, payload = _init_json(project, capsys, "--skills", "--host", "codex-cli")

        assert rc == 0
        assert _projected(project, ".agents/skills") == PACKAGED_SKILLS
        assert any("config.json" in w for w in payload["warnings"])

    def test_configured_hosts_without_skills_are_named_in_warnings(self, project, capsys):
        (project / ".aegis").mkdir()
        (project / ".aegis" / "config.json").write_text('{"v": 1, "hosts": ["claude-desktop"]}', encoding="utf-8")

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")

        assert rc == 0
        assert "claude-desktop reads no project skills; nothing to copy for it" in payload["warnings"]

    def test_a_packaged_skill_that_cannot_be_projected_stops_init(self, project, tmp_path, capsys, monkeypatch):
        """The packaged data's location is the installation boundary; point it at a broken copy."""
        from aegis_cli import skills_sync

        source = tmp_path / "source"
        (source / "broken").mkdir(parents=True)
        (source / "broken" / "SKILL.md").write_text("no frontmatter\n", encoding="utf-8")
        monkeypatch.setattr(skills_sync, "packaged_dir", lambda name: source)

        rc, payload = _init_json(project, capsys, "--skills", "--host", "claude-code")

        assert rc == 1 and payload["status"] == "refused"
        assert payload["errors"][0] == ("skills: packaged broken/SKILL.md: skill broken: no readable frontmatter. "
                                        "Fix it, or re-run without --skills.")
        assert not (project / ".aegis").exists() and not (project / ".claude").exists()

    def test_a_caller_s_own_namespace_without_the_option_projects_nothing(self, project, capsys):
        """run_init called with a Namespace built before --skills existed keeps the old behaviour."""
        args = argparse.Namespace(workspace=str(project), yes=True, no_hooks=True, rules="minimal",
                                  host=["claude-code"], json=True)

        assert run_init(args) == 0

        payload = json.loads(capsys.readouterr().out)
        assert not (project / ".claude").exists()
        assert not any("skills" in a["target"] for a in payload["actions"])

    def test_a_real_run_records_an_init_triggered_skills_sync_event(self, project):
        from aegis_core import events

        assert run_init(_args(project, "--skills", "--host", "claude-code")) == 0

        rows = events.read(project, "skills_sync").rows
        assert [(r["result"], r["detail"]["trigger"], r["detail"]["hosts"]) for r in rows] == [
            ("ok", "init", ["claude-code"])]


# ── One active rule out of the box (v4.1 d5) ─────────────────────────────────

ACTIVE = REPO_ROOT / "rules" / "no-eval.md"


def _invariants(root: Path) -> set:
    return {p.stem for p in (root / ".aegis" / "rules" / "invariants").glob("*.md")}


def _check(root: Path, *files: str) -> int:
    try:
        return main(["check", "--workspace", str(root), *files])
    except SystemExit as exc:
        return exc.code


class TestActiveStarterRule:
    """Starter personas apply to no file, so a fresh init used to enforce nothing (field
    report). A new workspace now gets one active, deterministic invariant."""

    def test_the_active_starter_ships_beside_the_guidance_rules_but_in_no_persona_preset(self):
        from aegis_cli.init import packaged_active_rules

        assert packaged_active_rules() == {"no-eval": ACTIVE}
        assert "no-eval" not in packaged_rules()
        assert all("no-eval" not in {p.stem for p in preset_rules(p)} for p in ("minimal", "standard", "full"))

    def test_a_new_workspace_gets_the_no_eval_invariant_as_shipped(self, project):
        from aegis_core.rules import load_rules

        assert run_init(_args(project)) == 0
        seeded = project / ".aegis" / "rules" / "invariants" / "no-eval.md"
        assert seeded.read_bytes() == ACTIVE.read_bytes()
        rule = next(r for r in load_rules(project).rules if r.id == "no-eval")
        assert (rule.ok, rule.type, rule.enforcement) == (True, "invariant", "gate")
        assert rule.target_paths == ("**/*.py",)
        assert rule.meta["forbid_ast"] == {"calls": [{"name": "eval", "builtin": True}, {"name": "exec", "builtin": True}]}
        # The personas still apply to no file: no-eval is the one active rule.
        assert [r.id for r in load_rules(project).rules if r.target_paths] == ["no-eval"]

    @pytest.mark.parametrize("preset", ["minimal", "standard", "full"])
    def test_every_persona_preset_also_seeds_it(self, project, preset):
        assert run_init(_args(project, rules=preset)) == 0
        assert _invariants(project) == {"no-eval"}

    def test_aegis_check_enforces_it_on_day_one(self, project, capsys):
        assert run_init(_args(project)) == 0
        (project / "app.py").write_text("def load(text):\n    return eval(text)\n", encoding="utf-8")
        (project / "ok.py").write_text(
            "import json\n\n\ndef load(text, df, model):\n"
            "    df.eval(\"a + b\")\n    model.eval()\n    return json.loads(text)\n",
            encoding="utf-8",
        )
        capsys.readouterr()
        assert _check(project, "app.py") == 1
        assert "Forbidden call 'eval'" in capsys.readouterr().out
        assert _check(project, "ok.py") == 0

    def test_the_output_names_the_active_rule_and_the_next_step(self, project, capsys):
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert "Active rule in .aegis/rules/invariants/:" in out
        assert "✅ no-eval: bans builtin eval() and exec() in **/*.py (method calls like df.eval() and model.eval() are allowed); aegis check and the pre-commit hook enforce it" in out
        assert "Next: add a rule for your own code with aegis rule create (aegis rule create --help)" in out

    def test_none_active_opts_out_and_keeps_the_standard_personas(self, project, capsys):
        assert run_init(_args(project, rules="none-active")) == 0
        assert _seeded(project) == STANDARD
        assert _invariants(project) == set()
        out = capsys.readouterr().out
        assert "No active rule (--rules none-active): aegis check enforces no rule until one names files." in out
        assert "Next: add a rule for your own code with aegis rule create (aegis rule create --help)" in out

    def test_a_deleted_active_rule_is_never_seeded_again(self, project, capsys):
        assert run_init(_args(project)) == 0
        (project / ".aegis" / "rules" / "invariants" / "no-eval.md").unlink()
        capsys.readouterr()
        assert run_init(_args(project, "--host", "codex-cli", "--dry-run")) == 0
        assert run_init(_args(project)) == 0
        assert _invariants(project) == set()
        assert "no-eval" not in capsys.readouterr().out

    def test_a_workspace_that_already_has_rules_gets_no_new_gate(self, project):
        traps = project / ".aegis" / "rules" / "traps"
        traps.mkdir(parents=True)
        (traps / "mine.md").write_text("---\nid: mine\ntype: trap\ndomain: correctness\nenforcement: advisory\n"
                                       "hypothesis: mine\n---\n# Mine\n", encoding="utf-8")
        assert run_init(_args(project)) == 0
        assert _invariants(project) == set()

    def test_a_rerun_leaves_it_unchanged(self, project, capsys):
        assert run_init(_args(project)) == 0
        before = (project / ".aegis" / "rules" / "invariants" / "no-eval.md").read_bytes()
        capsys.readouterr()
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks"]) == 0
        step = next(a for a in json.loads(capsys.readouterr().out)["actions"]
                    if a["target"] == ".aegis/rules/invariants")
        assert step["result"] == "unchanged"
        assert (project / ".aegis" / "rules" / "invariants" / "no-eval.md").read_bytes() == before

    def test_json_names_the_seeded_and_the_skipped_rule(self, project, tmp_path, capsys):
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks"]) == 0
        steps = {a["target"]: a for a in json.loads(capsys.readouterr().out)["actions"]}
        assert steps[".aegis/rules/invariants"]["result"] == "seeded"
        assert "no-eval" in steps[".aegis/rules/invariants"]["detail"]
        other = tmp_path / "other"
        other.mkdir()
        assert main(["--json", "init", "--workspace", str(other), "--yes", "--no-hooks",
                     "--rules", "none-active"]) == 0
        steps = {a["target"]: a for a in json.loads(capsys.readouterr().out)["actions"]}
        assert steps[".aegis/rules/invariants"]["result"] == "skipped"

    def test_dry_run_plans_it_and_writes_nothing(self, project, capsys):
        assert run_init(_args(project, "--dry-run")) == 0
        assert "[DRY-RUN] no-eval" in capsys.readouterr().out
        assert not (project / ".aegis").exists()

    def test_a_symlinked_invariants_dir_is_refused_and_nothing_is_written(self, project, tmp_path, capsys):
        from conftest import symlink_or_skip

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (project / ".aegis" / "rules").mkdir(parents=True)
        symlink_or_skip(elsewhere, project / ".aegis" / "rules" / "invariants", target_is_directory=True)
        assert run_init(_args(project)) == 1
        assert "symlink" in capsys.readouterr().err
        assert list(elsewhere.iterdir()) == []
        assert not (project / "AGENTS.md").exists()


# ── The CI floor (v4.1 d5) ───────────────────────────────────────────────────

WORKFLOW = REPO_ROOT / ".github" / "workflows"  # this repository's own CI, for the action pins


def _workflow_text() -> str:
    from aegis_cli.init import ci_workflow

    return ci_workflow()


class TestCiWorkflow:
    """`git commit --no-verify` skips the pre-commit hook, so CI is the floor. init prints
    the workflow by default and writes .github/workflows/aegis.yml only with --ci."""

    def test_by_default_the_workflow_is_printed_and_nothing_is_written(self, project, capsys):
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert ("  CI is the floor: git commit --no-verify skips the pre-commit hook, so CI must run "
                "aegis check too.") in out
        assert ("  This repository has no GitHub Actions workflow yet. Save this as .github/workflows/aegis.yml, "
                "or re-run aegis init with --ci to write it:") in out
        for line in _workflow_text().splitlines():
            assert ("      " + line).rstrip() in out.splitlines()
        assert not (project / ".github").exists()

    def test_ci_writes_exactly_the_printed_workflow(self, project, capsys):
        assert run_init(_args(project, "--ci")) == 0
        written = (project / ".github" / "workflows" / "aegis.yml").read_text(encoding="utf-8")
        assert written == _workflow_text()
        out = capsys.readouterr().out
        assert "✅ .github/workflows/aegis.yml: created" in out
        assert "CI is the floor" in out and "commit .github/workflows/aegis.yml" in out
        assert "Save this as" not in out

    def test_the_workflow_runs_aegis_check_with_the_aegis_that_wrote_it(self):
        from aegis_cli import __version__

        text = _workflow_text()
        assert "  pull_request:\n" in text
        assert "fetch-depth: 0" in text  # aegis check diffs the pull request against its base
        assert f"pip install aegis-guardrails=={__version__}" in text
        assert "      - run: aegis check\n" in text
        assert "      - run: aegis check --ci\n" in text
        assert "permissions:\n  contents: read\n" in text
        assert "\t" not in text and text.endswith("\n")

    def test_the_actions_it_uses_are_the_majors_this_repository_runs(self):
        own = "\n".join(p.read_text(encoding="utf-8") for p in WORKFLOW.glob("*.yml"))
        for action in re.findall(r"uses: (actions/[\w-]+)@(v\d+)", _workflow_text()):
            assert re.search(rf"uses: {action[0]}@\w+ # {action[1]}\.", own), action

    def test_an_existing_aegis_yml_is_never_overwritten(self, project, capsys):
        mine = project / ".github" / "workflows" / "aegis.yml"
        mine.parent.mkdir(parents=True)
        mine.write_text("name: mine\n", encoding="utf-8")
        assert run_init(_args(project, "--ci")) == 0
        assert mine.read_text(encoding="utf-8") == "name: mine\n"
        assert ".github/workflows/aegis.yml: kept" in capsys.readouterr().out

    def test_a_workflow_that_runs_aegis_check_is_named_and_no_snippet_printed(self, project, capsys):
        ci = project / ".github" / "workflows" / "ci.yaml"
        ci.parent.mkdir(parents=True)
        ci.write_text("jobs:\n  t:\n    steps:\n      - run: pip install aegis-guardrails && aegis check\n",
                      encoding="utf-8")
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert "✅ CI: .github/workflows/ci.yaml runs aegis check" in out
        assert "Save this as" not in out and "name: Aegis" not in out

    def test_other_workflows_that_never_run_aegis_still_get_the_snippet(self, project, capsys):
        ci = project / ".github" / "workflows" / "ci.yml"
        ci.parent.mkdir(parents=True)
        ci.write_text("jobs:\n  t:\n    steps:\n      - run: pytest\n", encoding="utf-8")
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert "  No GitHub Actions workflow here runs aegis check yet. Save this as .github/workflows/aegis.yml" in out
        assert "      name: Aegis" in out.splitlines()

    def test_ci_dry_run_writes_nothing(self, project, capsys):
        assert run_init(_args(project, "--ci", "--dry-run")) == 0
        assert ".github/workflows/aegis.yml: would create" in capsys.readouterr().out
        assert not (project / ".github").exists()

    def test_a_symlinked_workflows_dir_is_refused_with_ci_and_nothing_is_written(self, project, tmp_path, capsys):
        from conftest import symlink_or_skip

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (project / ".github").mkdir()
        symlink_or_skip(elsewhere, project / ".github" / "workflows", target_is_directory=True)
        assert run_init(_args(project, "--ci")) == 1
        err = capsys.readouterr().err
        assert ".github/workflows" in err and "symlink" in err and "Nothing was written." in err
        assert list(elsewhere.iterdir()) == []
        assert not (project / ".aegis").exists()

    def test_a_file_where_the_workflows_dir_belongs_is_refused_with_ci(self, project, capsys):
        (project / ".github").write_text("not a directory\n", encoding="utf-8")
        assert run_init(_args(project, "--ci")) == 1
        assert "not a directory" in capsys.readouterr().err
        assert not (project / ".aegis").exists()

    def test_json_mode_prints_no_snippet_and_reports_the_step(self, project, tmp_path, capsys):
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks"]) == 0
        payload = json.loads(capsys.readouterr().out)
        step = next(a for a in payload["actions"] if a["target"] == ".github/workflows/aegis.yml")
        assert step["result"] == "suggested" and "--ci" in step["detail"]
        other = tmp_path / "other"
        other.mkdir()
        assert main(["--json", "init", "--workspace", str(other), "--yes", "--no-hooks", "--ci"]) == 0
        payload = json.loads(capsys.readouterr().out)
        step = next(a for a in payload["actions"] if a["target"] == ".github/workflows/aegis.yml")
        assert step["result"] == "created"

    def test_ci_is_in_the_parser_and_off_by_default(self):
        parser = argparse.ArgumentParser()
        InitCommand().configure_parser(parser)
        assert parser.parse_args([]).ci is False
        assert parser.parse_args(["--ci"]).ci is True
        assert parser.parse_args(["--rules", "none-active"]).rules == "none-active"


def test_the_wheel_smoke_expects_the_active_starters_init_seeds():
    """wheel_smoke.py runs only in CI against the built wheel; its list must not drift."""
    import ast as pyast

    from aegis_cli.init import ACTIVE_STARTERS

    tree = pyast.parse((REPO_ROOT / ".github" / "scripts" / "wheel_smoke.py").read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, pyast.Assign)
                and any(getattr(t, "id", None) == "ACTIVE_STARTERS" for t in n.targets))
    assert tuple(pyast.literal_eval(node.value)) == tuple(ACTIVE_STARTERS)


class TestGovernanceHint:
    """R-trust-42: init writes no CODEOWNERS (it cannot tell a valid owner offline); a real run points at
    `aegis doctor --github`, the one place the CODEOWNERS lines and the ruleset come from."""

    CODEOWNERS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")

    def _no_codeowners(self, project: Path) -> None:
        assert not any((project / p).exists() for p in self.CODEOWNERS)

    def test_a_real_run_prints_the_doctor_github_hint_after_the_ci_floor(self, project, capsys):
        assert run_init(_args(project)) == 0
        out = capsys.readouterr().out
        assert "aegis doctor --github" in out and "CODEOWNERS" in out
        assert out.index("CI is the floor") < out.index("aegis doctor --github")
        self._no_codeowners(project)

    def test_json_keeps_its_keys_and_carries_no_hint(self, project, capsys):
        assert main(["--json", "init", "--workspace", str(project), "--yes", "--no-hooks", "--rules", "minimal"]) == 0
        out = capsys.readouterr().out
        assert set(json.loads(out)) == {"source", "aegis_version", "checked_at", "scope", "dry_run", "status",
                                        "actions", "errors", "warnings"}
        assert "doctor --github" not in out
        self._no_codeowners(project)

    def test_a_dry_run_prints_no_hint_and_writes_nothing(self, project, capsys):
        assert run_init(_args(project, "--dry-run")) == 0
        assert "doctor --github" not in capsys.readouterr().out
        assert not (project / ".aegis").exists()
        self._no_codeowners(project)
