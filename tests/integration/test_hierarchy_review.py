"""Root prepares an exact, read-only copy of a candidate and its baseline for an independent reviewer."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, git
from tests.integration.test_hierarchy_provision import Setup


REVIEW = ROOT / "tools" / "hierarchy_review.py"
pytestmark = pytest.mark.skipif(os.name == "nt", reason="read-only folders and symlink fixtures are POSIX only")


def review(*arguments, expect=0):
    result = subprocess.run([sys.executable, "-I", str(REVIEW), *arguments], capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not result.stderr, result.stderr
    assert result.returncode == expect, result.stdout
    return json.loads(result.stdout)


class Repository:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.path = tmp_path / "repository"
        self.path.mkdir()
        git(self.path, "init", "-q", "-b", "develop")
        (self.path / "src").mkdir()
        (self.path / "src" / "app.py").write_text("value = 1\n")
        (self.path / "src" / "removed.py").write_text("gone later\n")
        (self.path / "data.bin").write_bytes(bytes(range(256)))
        (self.path / "lines.txt").write_bytes(b"line one\nline two\n")
        # Attributes that would change or drop files if the copy went through a checkout or an archive.
        (self.path / ".gitattributes").write_text("*.txt text eol=crlf\nsrc/app.py export-ignore\n")
        (self.path / "link").symlink_to("/etc/hostname")
        git(self.path, "add", ".")
        git(self.path, "commit", "-qm", "base commit")
        self.base = git(self.path, "rev-parse", "HEAD")
        self.base_tree = git(self.path, "rev-parse", "HEAD^{tree}")
        (self.path / "src" / "app.py").write_text("value = 2\n")
        (self.path / "src" / "added.py").write_text("new file\n")
        (self.path / "src" / "removed.py").unlink()
        git(self.path, "add", ".")
        git(self.path, "commit", "-qm", "feat: candidate subject")
        self.candidate = git(self.path, "rev-parse", "HEAD")
        self.candidate_tree = git(self.path, "rev-parse", "HEAD^{tree}")
        self.out = tmp_path / "review"

    def prepare(self, *extra, expect=0, out=None, base=None, candidate=None):
        return review("prepare", "--repository", str(self.path), "--base=" + (base or self.base),
                      "--candidate=" + (candidate or self.candidate), "--out", str(out or self.out), *extra, expect=expect)


@pytest.fixture
def repository(tmp_path):
    built = Repository(tmp_path)
    yield built
    for target in (built.out,):
        if target.exists():
            review("remove", "--out", str(target))


def tree_entries(repository_path, commit):
    raw = subprocess.run(["git", "ls-tree", "-r", "-z", "--full-tree", commit], cwd=repository_path, capture_output=True,
                         check=True, timeout=10).stdout
    return dict((row.split(b"\t", 1)[1].decode(), row.split(b"\t", 1)[0].split()) for row in raw.split(b"\0") if row)


@pytest.mark.parametrize("side", ["base", "candidate"])
def test_each_side_holds_the_exact_committed_bytes(repository, side):
    repository.prepare()
    commit = getattr(repository, side)
    entries = tree_entries(repository.path, commit)
    folder = repository.out / side
    found = {str(path.relative_to(folder)) for path in folder.rglob("*") if not path.is_dir()}
    assert found == set(entries)
    for name, (mode, kind, oid) in entries.items():
        assert kind == b"blob"
        blob = subprocess.run(["git", "cat-file", "blob", oid.decode()], cwd=repository.path, capture_output=True, check=True,
                              timeout=10).stdout
        assert (folder / name).read_bytes() == blob, name


def test_the_report_names_the_exact_source(repository):
    result = repository.prepare()
    assert result["base"]["commit"] == repository.base and result["base"]["tree"] == repository.base_tree
    assert result["candidate"]["commit"] == repository.candidate and result["candidate"]["tree"] == repository.candidate_tree
    raw = (repository.out / "manifest.json").read_bytes()
    assert result["manifest_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["changed_files"] == 3


def test_filters_and_attributes_cannot_change_what_is_reviewed(repository):
    repository.prepare()
    assert (repository.out / "base" / "lines.txt").read_bytes() == b"line one\nline two\n"
    assert (repository.out / "base" / "src" / "app.py").read_text() == "value = 1\n"
    assert (repository.out / "candidate" / "src" / "app.py").read_text() == "value = 2\n"


def test_a_symlink_becomes_a_plain_file_holding_its_target(repository):
    repository.prepare()
    copy = repository.out / "base" / "link"
    assert not copy.is_symlink()
    assert copy.read_text() == "/etc/hostname"
    listed = [json.loads(line) for line in (repository.out / "base.files.jsonl").read_text().splitlines()]
    assert next(row for row in listed if row["path"] == "link")["mode"] == "120000"


def test_a_submodule_is_listed_but_not_followed(repository):
    git(repository.path, "update-index", "--add", "--cacheinfo", "160000," + "a" * 40 + ",vendored")
    git(repository.path, "commit", "-qm", "add a submodule entry")
    candidate = git(repository.path, "rev-parse", "HEAD")
    repository.prepare(candidate=candidate)
    assert not (repository.out / "candidate" / "vendored").exists()
    listed = [json.loads(line) for line in (repository.out / "candidate.files.jsonl").read_text().splitlines()]
    assert next(row for row in listed if row["path"] == "vendored") == {"path": "vendored", "mode": "160000", "commit": "a" * 40}
    assert review("verify", "--out", str(repository.out))["ok"] is True


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes")
def test_nothing_in_the_copy_can_be_written(repository):
    repository.prepare()
    for target in (repository.out / "candidate" / "src" / "app.py", repository.out / "changes.diff", repository.out / "manifest.json"):
        with pytest.raises(PermissionError):
            target.write_text("changed")
    for folder in (repository.out, repository.out / "candidate", repository.out / "candidate" / "src", repository.out / ".git"):
        assert not stat.S_IMODE(folder.stat().st_mode) & 0o222
        with pytest.raises(PermissionError):
            (folder / "planted").write_text("x")


def test_the_diff_and_commit_list_show_the_change(repository):
    result = repository.prepare()
    diff = (repository.out / "changes.diff").read_text()
    assert "-value = 1" in diff and "+value = 2" in diff and "src/added.py" in diff and "src/removed.py" in diff
    assert hashlib.sha256(diff.encode()).hexdigest() == result["diff_sha256"]
    commits = (repository.out / "commits.txt").read_text()
    assert repository.candidate in commits and "feat: candidate subject" in commits and repository.base not in commits


def test_repository_settings_cannot_run_code_during_prepare(repository):
    witness = repository.tmp / "code-ran"
    script = repository.tmp / "attack.sh"
    script.write_text("#!/bin/sh\ntouch %s\n" % witness)
    script.chmod(0o700)
    (repository.path / ".gitattributes").write_text("*.py diff=attack\n")
    git(repository.path, "add", ".gitattributes")
    git(repository.path, "commit", "-qm", "attribute a diff driver")
    candidate = git(repository.path, "rev-parse", "HEAD")
    for key, value in (("diff.external", str(script)), ("diff.attack.textconv", str(script)), ("core.fsmonitor", str(script)),
                       ("diff.attack.command", str(script))):
        git(repository.path, "config", key, value)
    repository.prepare(candidate=candidate)
    assert not witness.exists()


def test_the_copy_counts_as_a_git_checkout_for_codex_and_stays_empty(repository):
    repository.prepare()
    inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repository.out / "candidate", capture_output=True,
                            text=True, timeout=10)
    assert inside.stdout.strip() == "true"
    head = subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=repository.out, capture_output=True, timeout=10)
    assert head.returncode != 0
    assert not list((repository.out / ".git").glob("hooks/*"))


@pytest.mark.parametrize("flag, side", [("--expect-base-tree", "base"), ("--expect-candidate-tree", "candidate")])
def test_a_tree_that_is_not_the_expected_one_is_refused_and_leaves_nothing(repository, flag, side):
    result = repository.prepare(flag, "0" * 40, expect=2)
    assert side + " tree" in result["error"]
    assert not list(repository.tmp.glob("review*"))


def test_matching_trees_are_accepted(repository):
    repository.prepare("--expect-base-tree", repository.base_tree, "--expect-candidate-tree", repository.candidate_tree)
    assert (repository.out / "manifest.json").exists()


@pytest.mark.parametrize("arguments, message", [
    ({"base": "develop"}, "invalid base"),
    ({"candidate": "HEAD"}, "invalid candidate"),
    ({"candidate": "--output=/tmp/x"}, "invalid candidate"),
    ({"base": "0" * 40}, "commit is not in the repository"),
])
def test_only_exact_commit_ids_are_accepted(repository, arguments, message):
    assert message in repository.prepare(expect=2, **arguments)["error"]
    assert not repository.out.exists()


def test_an_existing_folder_is_not_overwritten(repository):
    repository.out.mkdir()
    assert "already exists" in repository.prepare(expect=2)["error"]
    repository.out.rmdir()


def test_the_copy_cannot_go_inside_the_repository(repository):
    result = repository.prepare(out=repository.path / "reviews" / "one", expect=2)
    assert "outside the repository" in result["error"]
    assert not (repository.path / "reviews").exists()


def test_a_relative_folder_is_refused(repository):
    assert "absolute" in review("prepare", "--repository", str(repository.path), "--base", repository.base, "--candidate",
                                repository.candidate, "--out", "relative", expect=2)["error"]


def test_a_tree_with_a_path_escape_is_refused(repository):
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repository.path, input="planted\n", capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()
    inner = subprocess.run(["git", "mktree"], cwd=repository.path, input="100644 blob %s\tescaped\n" % blob, capture_output=True,
                           text=True, check=True, timeout=10).stdout.strip()
    tree = subprocess.run(["git", "mktree"], cwd=repository.path, input="040000 tree %s\t..\n" % inner, capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()
    commit = git(repository.path, "commit-tree", tree, "-m", "hostile tree")
    assert "unsafe path" in repository.prepare(candidate=commit, expect=2)["error"]
    assert not (repository.tmp / "escaped").exists()
    assert not repository.out.exists()


def test_an_unchanged_copy_verifies(repository):
    result = repository.prepare()
    checked = review("verify", "--out", str(repository.out), "--expect-manifest", result["manifest_sha256"])
    assert checked["ok"] is True and checked["manifest_sha256"] == result["manifest_sha256"]


def plant_hook(out):
    os.chmod(out / ".git", 0o755)
    (out / ".git" / "hooks").mkdir(exist_ok=True)
    (out / ".git" / "hooks" / "post-checkout").write_text("#!/bin/sh\necho planted\n")


def replace_with_link(out, name):
    """A same-content copy behind a symlink, so every file inside still hashes the same."""
    os.chmod(out, 0o755)
    os.chmod(out / name, 0o755)  # Moving a folder to another parent needs write access to the folder itself.
    moved = out.parent / (out.name + "-moved-" + name.strip("."))
    (out / name).rename(moved)
    (out / name).symlink_to(moved)


def force_write(path, data):
    os.chmod(path.parent, 0o755)
    if path.exists():
        os.chmod(path, 0o644)
    path.write_bytes(data)


@pytest.mark.parametrize("damage, problem", [
    (lambda out: force_write(out / "candidate" / "src" / "app.py", b"value = 3\n"), "candidate/src/app.py"),
    (lambda out: force_write(out / "candidate" / "planted.py", b"x"), "candidate/planted.py"),
    (lambda out: (os.chmod(out / "base" / "src", 0o755), (out / "base" / "src" / "app.py").unlink()), "base/src/app.py"),
    (lambda out: force_write(out / "changes.diff", b"nothing to see"), "changes.diff"),
    (lambda out: force_write(out / "commits.txt", b"nothing to see"), "commits.txt"),
    (lambda out: force_write(out / "candidate.files.jsonl", b""), "candidate.files.jsonl"),
    (lambda out: plant_hook(out), ".git changed"),
    (lambda out: force_write(out / ".git" / "config", b"[core]\n\thooksPath = /tmp\n"), ".git changed"),
    (lambda out: replace_with_link(out, "candidate"), "candidate became a symlink"),
    (lambda out: os.chmod(out / "candidate", 0o755), "candidate is writable"),
    (lambda out: replace_with_link(out, ".git"), ".git became a symlink"),
])
def test_a_changed_copy_fails_verification_and_names_the_change(repository, damage, problem):
    repository.prepare()
    damage(repository.out)
    result = review("verify", "--out", str(repository.out), expect=3)
    assert result["ok"] is False
    assert any(problem in row for row in result["problems"]), result


def test_an_edited_manifest_fails_against_the_recorded_hash(repository):
    recorded = repository.prepare()["manifest_sha256"]
    force_write(repository.out / "manifest.json", (repository.out / "manifest.json").read_bytes() + b" ")
    result = review("verify", "--out", str(repository.out), "--expect-manifest", recorded, expect=3)
    assert any("manifest" in row for row in result["problems"])


def test_verify_refuses_a_folder_it_did_not_make(tmp_path):
    (tmp_path / "other").mkdir()
    assert "no review manifest" in review("verify", "--out", str(tmp_path / "other"), expect=2)["error"]


def test_remove_deletes_a_review_copy(repository):
    repository.prepare()
    assert review("remove", "--out", str(repository.out))["removed"] == str(repository.out)
    assert not repository.out.exists()


def test_remove_refuses_any_other_folder(tmp_path):
    folder = tmp_path / "precious"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep\n")
    assert "no review manifest" in review("remove", "--out", str(folder), expect=2)["error"]
    assert (folder / "keep.txt").exists()


class Reviewer(Setup):
    def role(self, *arguments, **changes):
        return self.add_role("pilot/lane/review", *arguments, **changes)


def test_a_claude_reviewer_can_be_provisioned_on_the_copy(repository, tmp_path):
    setup = Reviewer(tmp_path)
    setup.init()
    repository.prepare()
    role = setup.role(cwd=str(repository.out))
    wake = json.loads(Path(role["wake_profile"]).read_text())
    assert wake["cwd"] == str(repository.out)
    argv = wake["argv"]
    assert "--tools=Read,Glob,Grep" in argv


def test_a_codex_reviewer_can_read_the_copy_only_through_a_read_only_shell(repository, tmp_path):
    setup = Reviewer(tmp_path)
    setup.init()
    repository.prepare()
    role = setup.role("codex-cli", session="review-session", cwd=str(repository.out), reader_shell=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    disabled = [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]
    assert "shell_tool" not in disabled and "multi_agent" in disabled
    assert not any("writable_roots" in word for word in argv)


def test_a_codex_orchestrator_can_read_files_through_a_read_only_shell(tmp_path):
    setup = Reviewer(tmp_path)
    setup.init()
    role = setup.add_role("pilot/orchestrator", "codex-cli", session="orchestrator-session", cwd=str(setup.source), reader_shell=True)
    argv = json.loads(Path(role["wake_profile"]).read_text())["argv"]
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert "shell_tool" not in [argv[index + 1] for index, word in enumerate(argv) if word == "--disable"]


@pytest.mark.parametrize("endpoint, host, session", [
    ("pilot/lane/f2", "codex-cli", "writer-session"),
    ("pilot/front-door", "codex-cli", "front-door-session"),
    ("pilot/lane/review", "claude-code", None),
])
def test_only_a_codex_reader_can_ask_for_a_read_only_shell(repository, tmp_path, endpoint, host, session):
    setup = Reviewer(tmp_path)
    setup.init()
    options = {"session": session} if session else {}
    result = setup.add_role(endpoint, host, cwd=str(setup.source), reader_shell=True, expect=2, **options)
    assert "reader_shell" in result["error"]
