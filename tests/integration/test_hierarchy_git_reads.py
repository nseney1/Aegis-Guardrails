"""Pinned public reads ignore replacement objects and never start a fetch transport."""
import json
import os
import selectors
import shlex
import shutil
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_jobs import JOBS, clean_pytest_recipe, recorded, shop
from tests.integration.test_hierarchy_mailbox import HELPER, git, pilot  # noqa: F401
from tests.integration.test_hierarchy_mailbox_fence import source_call
from tests.integration.test_hierarchy_mailbox_mcp import payload
from tests.integration.test_hierarchy_review import REVIEW, Repository, review


pytestmark = pytest.mark.skipif(os.name == "nt", reason="hierarchy source readers and fixtures are POSIX only")


@pytest.fixture
def repository(tmp_path):
    repo = Repository(tmp_path)
    yield repo
    if repo.out.exists():
        review("remove", "--out", str(repo.out))


def substitute(repo, kind):
    if kind == "commit":
        original, replacement = repo.candidate, repo.base
    elif kind == "tree":
        original, replacement = repo.candidate_tree, repo.base_tree
    else:
        original = git(repo.path, "rev-parse", repo.candidate + ":src/app.py")
        replacement = git(repo.path, "rev-parse", repo.base + ":src/app.py")
    git(repo.path, "replace", original, replacement)


@pytest.mark.parametrize("kind", ["blob", "tree", "commit"])
def test_review_prepares_original_pinned_bytes_despite_replacements(repository, kind):
    substitute(repository, kind)
    result = repository.prepare("--expect-base-tree", repository.base_tree,
                                "--expect-candidate-tree", repository.candidate_tree)
    assert (repository.out / "candidate" / "src" / "app.py").read_bytes() == b"value = 2\n"
    assert (repository.out / "candidate" / "src" / "added.py").read_bytes() == b"new file\n"
    assert "+value = 2" in (repository.out / "changes.diff").read_text()
    assert "feat: candidate subject" in (repository.out / "commits.txt").read_text()
    assert result["candidate"]["tree"] == repository.candidate_tree
    assert review("verify", "--out", str(repository.out), "--expect-manifest", result["manifest_sha256"])["ok"]


def test_replacement_commit_cannot_satisfy_a_false_expected_tree(repository):
    substitute(repository, "commit")
    result = repository.prepare("--expect-candidate-tree", repository.base_tree, expect=2)
    assert result["error"] == "candidate tree is %s, not the expected %s" % (
        repository.candidate_tree, repository.base_tree)
    assert not repository.out.exists()


def test_review_ignores_an_ambient_custom_replacement_namespace(repository, monkeypatch):
    original = git(repository.path, "rev-parse", repository.candidate + ":src/app.py")
    replacement = git(repository.path, "rev-parse", repository.base + ":src/app.py")
    git(repository.path, "update-ref", "refs/custom-replacements/" + original, replacement)
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/custom-replacements/")
    monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "0")
    repository.prepare()
    assert (repository.out / "candidate" / "src" / "app.py").read_bytes() == b"value = 2\n"


@pytest.mark.parametrize("kind", ["blob", "tree", "commit"])
def test_mcp_views_keep_the_original_pinned_bytes(pilot, repository, kind):  # noqa: F811
    root, _ = pilot
    substitute(repository, kind)
    responses = source_call(root, repository.path, [
        ("source_show", {"commit": repository.candidate, "path": "src/app.py"}),
        ("source_grep", {"commit": repository.candidate, "pattern": "value = 2"}),
    ])
    assert payload(responses[1])["lines"] == ["value = 2"]
    assert payload(responses[2])["matches"] == [{"path": "src/app.py", "line": 1, "text": "value = 2"}]


def enable_fetch(repo, tmp_path, transport):
    """A real local transport canary: a fetch must never execute this program."""
    marker = tmp_path / "transport-ran"
    command = tmp_path / "fetch-canary"
    command.write_text("#!/bin/sh\nprintf fetched > %s\nexit 1\n" % shlex.quote(str(marker)))
    command.chmod(0o755)
    settings = {"core.repositoryformatversion": "1", "extensions.partialClone": "origin",
                "remote.origin.promisor": "true", "protocol." + transport + ".allow": "always"}
    if transport == "ext":
        settings["remote.origin.url"] = "ext::" + str(command).replace(" ", "% ")
    else:
        settings["remote.origin.url"] = "file://" + str(tmp_path / "absent-remote")
        settings["remote.origin.uploadpack"] = shlex.quote(str(command))
    for key, value in settings.items():
        git(repo.path, "config", key, value)
    return marker


def remove_object(repo, kind):
    oid = {"commit": repo.candidate, "tree": repo.candidate_tree}.get(kind)
    if oid is None:
        oid = git(repo.path, "rev-parse", repo.candidate + ":src/app.py")
    (repo.path / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
    return oid


@pytest.mark.parametrize("transport", ["ext", "file"])
@pytest.mark.parametrize("kind", ["commit", "tree", "blob"])
def test_review_missing_objects_never_invoke_an_explicitly_allowed_fetch(repository, tmp_path, transport, kind):
    remove_object(repository, kind)
    marker = enable_fetch(repository, tmp_path, transport)
    result = subprocess.run([sys.executable, "-I", str(REVIEW), "prepare", "--repository", str(repository.path),
                             "--base", repository.base, "--candidate", repository.candidate,
                             "--out", str(repository.out)], capture_output=True, text=True, timeout=20)
    assert not marker.exists(), "a pinned review read executed the repository's fetch transport"
    assert result.returncode == 2, result.stdout + result.stderr
    assert "error" in json.loads(result.stdout)
    assert not repository.out.exists()
    assert not list(tmp_path.glob(".pending-*"))


@pytest.mark.parametrize("source", ["parameters", "count"])
def test_ambient_config_cannot_enable_a_review_fetch(repository, tmp_path, monkeypatch, source):
    missing = remove_object(repository, "blob")
    marker = enable_fetch(repository, tmp_path, "ext")
    git(repository.path, "config", "--unset", "protocol.ext.allow")
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "ext:file")
    monkeypatch.setenv("GIT_NO_LAZY_FETCH", "0")
    if source == "parameters":
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'protocol.ext.allow=always'")
    else:
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "protocol.ext.allow")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "always")
    result = repository.prepare(expect=2)
    assert result == {"error": "could not read object " + missing}
    assert not marker.exists()


def readline(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(10), "MCP response did not arrive"
        return json.loads(process.stdout.readline())


@pytest.mark.parametrize("transport", ["ext", "file"])
@pytest.mark.parametrize("name", ["source_show", "source_grep"])
def test_running_mcp_reader_never_fetches_after_promisor_config_changes(pilot, repository, tmp_path,  # noqa: F811
                                                                      monkeypatch, transport, name):
    root, _ = pilot
    # Model Git before 2.44 at the process boundary: it ignores GIT_NO_LAZY_FETCH. The transport policy must still hold.
    real_git = shutil.which("git")
    wrapper = tmp_path / "old-git"
    wrapper.mkdir()
    (wrapper / "git").write_text("#!/bin/sh\nunset GIT_NO_LAZY_FETCH\nexec %s \"$@\"\n" % shlex.quote(real_git))
    (wrapper / "git").chmod(0o755)
    monkeypatch.setenv("PATH", str(wrapper) + os.pathsep + os.environ["PATH"])
    process = subprocess.Popen([sys.executable, "-I", str(HELPER), "--root", str(root), "serve", "--endpoint",
                                "a/lane/review", "--host", "host-one", "--session", "a/lane/review", "--generation", "1",
                                "--source-repo", str(repository.path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n")
        process.stdin.flush()
        assert "result" in readline(process)
        remove_object(repository, "blob")
        marker = enable_fetch(repository, tmp_path, transport)
        arguments = {"commit": repository.candidate, **({"path": "src/app.py"} if name == "source_show"
                                                       else {"pattern": "value"})}
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": name, "arguments": arguments}}) + "\n")
        process.stdin.flush()
        response = payload(readline(process))
        assert not marker.exists(), "a source view executed the repository's explicitly enabled transport"
        expected = "path not found at that commit: src/app.py" if name == "source_show" else "git failed in the source repository"
        assert response == {"error": expected}
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the public job runner reads /proc")
def test_job_export_never_fetches_if_config_changes_after_object_preflight(shop, tmp_path, monkeypatch):
    clean_pytest_recipe(shop, "none")
    shop.request_job("job-1", "pt", paths=["tests/test_app.py"])
    missing = git(shop.checkout, "rev-parse", "HEAD:src/app.py")
    marker, transport = tmp_path / "transport-ran", tmp_path / "transport"
    transport.write_text("#!/bin/sh\nprintf fetched > %s\nexit 1\n" % shlex.quote(str(marker)))
    transport.chmod(0o755)
    wrapper = tmp_path / "git-bin"
    wrapper.mkdir()
    (wrapper / "git").write_text("#!" + sys.executable + "\n" + '''
import json, os, subprocess, sys
from pathlib import Path
real, repo, blob, transport = json.loads(os.environ["AEGIS_GIT_READ_CANARY"])
if sys.argv[-2:] == ["cat-file", "--batch"]:
    for key, value in (("core.repositoryformatversion", "1"), ("extensions.partialClone", "origin"),
                       ("remote.origin.promisor", "true"), ("protocol.ext.allow", "always"),
                       ("remote.origin.url", "ext::" + transport.replace(" ", "% "))):
        subprocess.run([real, "-C", repo, "config", key, value], check=True)
    (Path(repo) / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
os.environ.pop("GIT_NO_LAZY_FETCH", None)
os.execv(real, [real, *sys.argv[1:]])
''')
    (wrapper / "git").chmod(0o755)
    real_git = shutil.which("git")
    monkeypatch.setenv("PATH", str(wrapper) + os.pathsep + os.environ["PATH"])
    env = {**os.environ, **shop.env(),
           "AEGIS_GIT_READ_CANARY": json.dumps([real_git, str(shop.checkout), missing, str(transport)])}
    rows = shop.run_open(env=env)["rows"]
    assert not marker.exists(), "the job exporter started a fetch after preflight"
    assert rows[0]["state"] == "refused", rows
    result = recorded(shop)
    assert "git cat-file did not return the blob of src/app.py" in result["reason"]
    assert result["steps"] == []


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the public job runner reads /proc")
@pytest.mark.parametrize("command", ["source-digest", "run-open"])
@pytest.mark.parametrize("missing_kind", ["tree", "blob"])
@pytest.mark.parametrize("transport", ["ext", "file"])
def test_public_job_reads_do_not_fetch_before_export_preflight(shop, tmp_path, command, missing_kind, transport):
    clean_pytest_recipe(shop, "none")
    shop.request_job("job-1", "pt", paths=["tests/test_app.py"])
    # The transport fixture needs only the selected repository path.
    repo = type("RepositoryPath", (), {"path": shop.checkout})()
    marker = enable_fetch(repo, tmp_path, transport)
    spec = "HEAD^{tree}" if missing_kind == "tree" else "HEAD:src/app.py"
    oid = git(shop.checkout, "rev-parse", spec)
    (shop.checkout / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
    argv = ([sys.executable, "-I", str(JOBS), "source-digest", "--checkout", str(shop.checkout)]
            if command == "source-digest" else shop.argv("run-open", census=[]))
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20, env={**os.environ, **shop.env()})
    assert not marker.exists(), "a job source read executed a configured fetch before export preflight"
    assert result.returncode in (0, 2), result.stdout + result.stderr
    assert not result.stderr
    answer = json.loads(result.stdout)
    if command == "run-open":
        assert answer["rows"][0]["state"] == "refused", answer
        assert recorded(shop)["steps"] == []
    elif result.returncode:
        assert "error" in answer


@pytest.mark.parametrize("kind", ["tree", "commit"])
def test_source_digest_reports_the_original_tree_and_clean_state(repository, kind):
    substitute(repository, kind)
    result = subprocess.run([sys.executable, "-I", str(JOBS), "source-digest", "--checkout", str(repository.path)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    answer = json.loads(result.stdout)
    assert answer["commit"] == repository.candidate and answer["tree"] == repository.candidate_tree
    assert answer["dirty_entries"] == 0


def test_source_digest_preserves_the_owners_global_excludes(repository, tmp_path, monkeypatch):
    home = tmp_path / "global-config-home"
    home.mkdir()
    ignores = home / "ignore"
    ignores.write_text("global-hidden\n")
    (home / ".gitconfig").write_text("[core]\n\texcludesFile = " + str(ignores) + "\n")
    (repository.path / "global-hidden").write_text("ignored worktree data\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    result = subprocess.run([sys.executable, "-I", str(JOBS), "source-digest", "--checkout", str(repository.path)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    assert json.loads(result.stdout)["dirty_entries"] == 0
