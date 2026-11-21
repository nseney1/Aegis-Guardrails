"""Source pages reuse bounded immutable data without changing their public answers."""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import hierarchy_source  # noqa: E402


def git(repository, *arguments):
    return subprocess.run(
        ["git", "-C", str(repository), *arguments], capture_output=True, check=True,
        timeout=15, env=hierarchy_source.object_read_env()).stdout.decode("ascii").strip()


@pytest.fixture
def source(tmp_path, monkeypatch):
    repository = tmp_path / "source"
    repository.mkdir()
    git(repository, "init", "-q")
    git(repository, "config", "core.autocrlf", "false")
    (repository / "page.txt").write_bytes(b"".join(b"line %d\n" % n for n in range(1, 801)))
    (repository / "other.txt").write_bytes(b"other\n")
    (repository / "binary").write_bytes(b"\0binary")
    (repository / "empty").write_bytes(b"")
    (repository / "unicode").write_bytes(("é\n" + "x" * 5000 + "\n").encode() + b"bad\xff")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "source")
    commit = git(repository, "rev-parse", "HEAD")
    views = hierarchy_source.SourceViews(repository)
    calls = []
    real_run = subprocess.run

    def run(argv, **kwargs):
        calls.append(argv)
        return real_run(argv, **kwargs)

    # Replace this module's boundary, never the process-wide subprocess module.
    monkeypatch.setattr(hierarchy_source, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run}))
    return repository, commit, views, calls


def test_eight_pages_read_the_blob_only_once(source):
    repository, commit, views, calls = source
    blob = git(repository, "rev-parse", commit + ":page.txt")
    for start in range(1, 801, 100):
        assert views.call("source_show", {"commit": commit, "path": "page.txt", "start_line": start,
                                          "max_lines": 100}) == {
            "commit": commit, "path": "page.txt", "blob": blob, "start_line": start, "total_lines": 800,
            "lines": ["line %d" % n for n in range(start, start + 100)], "cut_lines": [],
            "next_start_line": start + 100 if start < 701 else None}
    assert sum("blob" in call for call in calls) == 1
    assert len(calls) <= 12


@pytest.mark.skipif(os.name == "nt", reason="source grep uses POSIX pipe selectors")
@pytest.mark.parametrize("pattern,matches", [
    ("line 800", [{"path": "page.txt", "line": 800, "text": "line 800"}]),
    ("absent text", []),
])
def test_grep_uses_the_complete_subprocess_boundary(source, pattern, matches):
    _, commit, views, _ = source
    assert views.call("source_grep", {"commit": commit, "pattern": pattern, "paths": ["page.txt"]}) == {
        "commit": commit, "pattern": pattern, "paths": ["page.txt"],
        "matches": matches, "truncated": False}


def test_cache_is_bounded_and_replaces_the_previous_file(source, monkeypatch):
    _, commit, views, calls = source
    # Raw bytes fit this budget, but the decoded strings and list do not.
    monkeypatch.setattr(hierarchy_source, "MAX_CACHED_BYTES", 16000)
    for path in ("other.txt", "other.txt", "page.txt", "page.txt", "other.txt"):
        views.show({"commit": commit, "path": path})
    assert sum("blob" in call for call in calls) == 4


def test_cache_is_connection_local_and_keyed_by_commit_and_path(source):
    repository, commit, views, calls = source
    assert views.show({"commit": commit, "path": "page.txt"})["lines"][0] == "line 1"
    (repository / "page.txt").write_bytes(b"changed\n")
    git(repository, "add", ".")
    git(repository, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "change")
    changed = git(repository, "rev-parse", "HEAD")
    assert views.show({"commit": changed, "path": "page.txt"})["lines"] == ["changed"]
    assert views.show({"commit": commit, "path": "other.txt"})["lines"] == ["other"]
    assert views.show({"commit": commit, "path": "page.txt"})["lines"][0] == "line 1"
    reads = sum("blob" in call for call in calls)
    fresh = hierarchy_source.SourceViews(repository)
    assert fresh.show({"commit": changed, "path": "page.txt"})["lines"] == ["changed"]
    assert sum("blob" in call for call in calls) == reads + 1


def test_mutating_a_returned_page_cannot_change_cached_source(source):
    _, commit, views, _ = source
    arguments = {"commit": commit, "path": "page.txt", "max_lines": 1}
    page = views.show(arguments)
    page["lines"][0] = "changed"
    page["cut_lines"].append(1)
    again = views.show(arguments)
    assert again["lines"] == ["line 1"] and again["cut_lines"] == []


@pytest.mark.parametrize("arguments,error", [
    ({"start_line": 0}, "start line must be at least 1"),
    ({"start_line": 801}, "start line is past the end of the file"),
    ({"max_lines": 2001}, "max lines must be between 1 and 2000"),
    ({"commit": "HEAD"}, "commit must be a full 40-character commit id"),
    ({"commit": "0" * 40}, "commit not found in the source repository"),
    ({"path": "../outside"}, "path must be relative and stay inside the repository"),
    ({"path": "absent"}, "path not found at that commit: absent"),
    ({"path": "binary"}, "binary file; source_show returns text only"),
])
def test_cached_pages_keep_refusals(source, arguments, error):
    _, commit, views, _ = source
    views.show({"commit": commit, "path": "page.txt"})
    with pytest.raises(ValueError) as exc:
        views.call("source_show", {"commit": commit, "path": "page.txt", **arguments})
    assert str(exc.value) == error


def test_cached_pages_keep_empty_unicode_and_line_limits(source):
    _, commit, views, _ = source
    for _ in range(2):
        assert views.show({"commit": commit, "path": "empty"})["lines"] == []
    for _ in range(2):
        page = views.show({"commit": commit, "path": "unicode"})
        assert page["lines"] == ["é", "x" * 4096, "bad�"]
        assert page["cut_lines"] == [2]
        assert page["total_lines"] == 3 and page["next_start_line"] is None
        assert len(json.dumps(json.dumps(page))) <= 262144


def test_oversized_blob_is_refused_before_reading(source, monkeypatch):
    _, commit, views, calls = source
    monkeypatch.setattr(hierarchy_source, "MAX_BLOB_BYTES", 2)
    with pytest.raises(ValueError, match="^file is larger than 2 bytes$"):
        views.show({"commit": commit, "path": "page.txt"})
    assert not any("blob" in call for call in calls)


def test_blob_timeout_is_a_documented_refusal_and_can_be_read_later(source, monkeypatch):
    _, commit, views, _ = source
    real_run = hierarchy_source.subprocess.run

    def timeout(argv, **kwargs):
        if "blob" in argv:
            raise subprocess.TimeoutExpired(argv, 30)
        return real_run(argv, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(hierarchy_source, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": timeout}))
        with pytest.raises(ValueError, match="^git timed out in the source repository$"):
            views.show({"commit": commit, "path": "page.txt"})
    assert views.show({"commit": commit, "path": "page.txt"})["lines"][0] == "line 1"
