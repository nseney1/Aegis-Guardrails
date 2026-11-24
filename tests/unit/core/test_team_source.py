"""Source views preserve pinned answers and refuse bounded transport failures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, gitsafe_policy, gitsafe_run, team_git, team_host_plan, team_source as source
from tests.helpers_team_git import commit, git

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import hierarchy_source as legacy  # noqa: E402
import hierarchy_absolute as legacy_absolute  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    for path, data in {"page.txt": b"line\n" * 150, "other": b"other\n", "empty": b"",
                       "binary": b"\0binary", "unicode": "é\n".encode() + b"x" * 5000 + b"\nbad\xff"}.items():
        (repo / path).write_bytes(data)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "fixture")
    return repo, git(repo, "rev-parse", "HEAD").decode().strip()


def envelope(error, reason):
    assert error.value.as_dict() == {"status": "refused", "code": 1, "reason": reason,
                                      "next_action": error.value.next_action}
    assert error.value.next_action


@pytest.mark.parametrize("path", ["page.txt", "other", "empty", "unicode"])
def test_show_success_parity_and_detached_pages(repository, path):
    repo, oid = repository
    view, old = source.SourceViews(repo, planned=False), legacy.SourceViews(repo, planned=False)
    args = {"commit": oid, "path": path}
    assert view.show(args) == old.show(args)
    view.show(args)["lines"].append("mutated")
    assert view.show(args) == old.show(args)


@pytest.mark.parametrize("pattern", ["line", "absent", "é"])
def test_grep_success_parity_and_match_cap(repository, pattern):
    repo, oid = repository
    args = {"commit": oid, "pattern": pattern}
    answer = source.SourceViews(repo, planned=False).grep(args)
    if os.name != "nt":
        assert answer == legacy.SourceViews(repo, planned=False).grep(args)
    if pattern == "line":
        assert len(answer["matches"]) == 100
        assert answer["truncated"] is True


@pytest.mark.parametrize("overrides,reason", [
    ({"commit": "HEAD"}, "invalid_commit"), ({"commit": "0" * 40}, "unknown_commit"),
    ({"path": "../outside"}, "invalid_path"), ({"path": "absent"}, "unknown_path"),
    ({"max_lines": 2001}, "invalid_arguments"), ({"path": "binary"}, "binary_file"),
    ({"start_line": 151}, "page_out_of_range"), ({"start_line": True}, "invalid_arguments"),
])
def test_refusal_mapping_and_retry(repository, overrides, reason):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    args = {"commit": oid, "path": "page.txt"}
    before = git(repo, "status", "--porcelain=v1")
    with pytest.raises(source.SourceRefusal) as caught:
        view.show({**args, **overrides})
    envelope(caught, reason)
    with pytest.raises(ValueError):
        legacy.SourceViews(repo, planned=False).show({**args, **overrides})
    assert view.show(args)["lines"] == ["line"] * 150
    assert git(repo, "status", "--porcelain=v1") == before


def test_overflow_is_authorized_typed_refusal_and_retry(repository):
    repo, oid = repository
    (repo / "large").write_bytes((b"needle " + b"x" * 280 + b"\n") * 18000)
    git(repo, "add", "large")
    git(repo, "commit", "-qm", "overflow")
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    view = source.SourceViews(repo, planned=False)
    with pytest.raises(source.SourceRefusal) as caught:
        view.grep({"commit": oid, "pattern": "needle"})
    envelope(caught, "source_grep_output_limit")
    assert not hasattr(caught.value, "stdout")
    assert view.grep({"commit": oid, "pattern": "absent"})["matches"] == []
    assert len(view.grep({"commit": oid, "pattern": "line"})["matches"]) == 100


def test_transport_timeout_is_fixed_and_retries(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    real = gitsafe.run
    def timeout(*args, **kwargs):
        raise gitsafe.GitError("untrusted diagnostic", code="git_timeout")
    monkeypatch.setattr(source, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": timeout}))
    with pytest.raises(source.SourceRefusal) as caught:
        view.show({"commit": oid, "path": "page.txt"})
    envelope(caught, "source_timeout")
    assert "untrusted diagnostic" not in str(caught.value)
    monkeypatch.setattr(source, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": real}))
    assert view.show({"commit": oid, "path": "other"})["lines"] == ["other"]


def test_invalid_requests_do_not_start_git(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    def unexpected(*args, **kwargs):
        pytest.fail("invalid arguments reached Git")
    monkeypatch.setattr(source, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": unexpected}))
    for args in ({"commit": oid, "path": "x" * 1025}, {"commit": oid, "path": "../x"},
                 {"commit": oid, "path": "other", "max_lines": 2001}, []):
        with pytest.raises(source.SourceRefusal):
            view.show(args)


def test_concurrent_cached_reads_remain_pinned(repository):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    def read(index):
        path = "other" if index % 2 else "page.txt"
        return view.show({"commit": oid, "path": path})["lines"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        result = list(pool.map(read, range(12)))
    assert result == [["other"] if i % 2 else ["line"] * 150 for i in range(12)]


def test_blob_limit_is_checked_before_payload_capture(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    monkeypatch.setattr(source, "MAX_BLOB_BYTES", 8)
    real, calls = gitsafe.run, []
    def run(args, *rest, **kwargs):
        calls.append(args)
        return real(args, *rest, **kwargs)
    monkeypatch.setattr(source, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": run}))
    with pytest.raises(source.SourceRefusal) as caught:
        view.show({"commit": oid, "path": "page.txt"})
    envelope(caught, "source_blob_limit")
    assert not any("blob" in args for args in calls)


def test_repository_and_partial_clone_refusals(repository, tmp_path):
    repo, _ = repository
    with pytest.raises(source.SourceRefusal) as caught:
        source.SourceViews(tmp_path, planned=False)
    envelope(caught, "source_repository")
    git(repo, "config", "remote.origin.promisor", "true")
    with pytest.raises(source.SourceRefusal) as caught:
        source.SourceViews(repo, planned=False)
    envelope(caught, "source_partial_clone")


def test_public_read_runner_cannot_mutate_repository(repository):
    repo, _ = repository
    view = source.SourceViews(repo, planned=False)
    with pytest.raises(source.SourceRefusal) as caught:
        view.git("config", "--local", "core.fsync", "all")
    envelope(caught, "invalid_arguments")
    assert git(repo, "config", "--get-regexp", "core").find(b"core.fsync") == -1


@pytest.mark.skipif(os.name == "nt", reason="backslash is a native separator on Windows")
def test_trusted_repository_spelling_keeps_native_path_semantics(repository):
    repo, oid = repository
    renamed = repo.with_name("repository\\name")
    repo.rename(renamed)
    args = {"commit": oid, "path": "other"}
    assert source.SourceViews(renamed).show(args) == legacy.SourceViews(renamed).show(args)


def test_default_host_policy_and_injected_environment_preserve_answers(repository):
    repo, oid = repository
    calls = []
    def environment(values, purpose):
        calls.append(purpose)
        return values
    view = source.SourceViews(repo, child_environment=environment)
    args = {"commit": oid, "path": "other"}
    assert view.show(args) == legacy.SourceViews(repo).show(args)
    assert calls and all(purpose == "no-host" for purpose in calls)
    assert source.TOOL_SPECS == legacy.TOOL_SPECS
    legacy_argv = legacy.SourceViews(repo).argv("cat-file", "-t", oid)
    assert legacy_argv[0] == "git"
    assert legacy_argv[1:] == view.argv("cat-file", "-t", oid)


@pytest.mark.parametrize("mode", ["default", "unplanned", "injected"])
def test_source_git_child_receives_only_sanitized_environment(repository, monkeypatch, tmp_path, mode):
    repo, oid = repository
    excluded = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID")
    startup = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
    traces = {key: str(tmp_path / f"{key}.log") for key in ("GIT_TRACE", "GIT_TRACE2_EVENT", "GIT_TRACE_SETUP")}
    ambient = {**startup, **traces}
    ambient.update(dict.fromkeys(excluded, "fixture-only"))
    ambient["AEGIS_SOURCE_DROP"] = "ambient-only"
    observer = SimpleNamespace(**{**vars(os), "environ": ambient})
    monkeypatch.setattr(team_git, "os", observer)
    monkeypatch.setattr(gitsafe_run, "os", observer)
    expected = dict(gitsafe_policy.BASE_ENV, GIT_PROTOCOL_FROM_USER="0",
                    GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    if os.name == "nt":
        expected.update(startup)
    settings = {"planned": False} if mode == "unplanned" else {}
    if mode == "injected":
        def environment(values, purpose):
            assert purpose == "no-host"
            return {**values, **traces, **dict.fromkeys(excluded, "from-policy"), "OTHER_SETTING": "from-policy"}
        settings = {"planned": True, "child_environment": environment}

    matches = []
    def record(argv, **kwargs):
        matches.append(kwargs["env"] == expected)
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))

    view = source.SourceViews(repo, **settings)
    assert matches and all(matches), "Git initialization received an unexpected environment"
    matches.clear()
    assert view.show({"commit": oid, "path": "other"})["lines"] == ["other"]
    assert matches and all(matches), "Git show received an unexpected environment"
    matches.clear()
    assert view.grep({"commit": oid, "pattern": "other"})["matches"]
    assert matches and all(matches), "Git grep received an unexpected environment"
    assert not any(tmp_path.glob("GIT_*.log"))


@pytest.mark.parametrize("mode", ["default", "unplanned", "injected"])
def test_source_git_child_reads_selected_repository_without_selectors(repository, tmp_path, monkeypatch, mode):
    repo, oid = repository
    other = tmp_path / "alternate"
    other.mkdir()
    git(other, "init", "-q")
    names = gitsafe_policy.LOCAL_ENV | {"GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"}
    selectors = {**dict.fromkeys(names, "fixture"), "GIT_DIR": str(other / ".git")}
    ambient = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    ambient.update(selectors)
    observer = SimpleNamespace(**{**vars(os), "environ": ambient})
    monkeypatch.setattr(team_git, "os", observer)
    monkeypatch.setattr(gitsafe_run, "os", observer)

    def injected(values, purpose):
        return {**values, **{key.lower(): value for key, value in selectors.items()}}

    launches = []
    def record(argv, **kwargs):
        child = kwargs["env"]
        assert {key for key in child if key.upper() in names} == {"GIT_NO_REPLACE_OBJECTS"}
        assert child["GIT_NO_REPLACE_OBJECTS"] == "1"
        launches.append(True)
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))

    view = source.SourceViews(repo, planned=False if mode == "unplanned" else None,
                              child_environment=injected if mode == "injected" else None)
    assert view.show({"commit": oid, "path": "other"})["lines"] == ["other"]
    assert launches


@pytest.mark.parametrize("layer", ["ambient", "injected"])
def test_source_read_accepts_full_environment_input_budget(repository, monkeypatch, layer):
    repo, oid = repository
    ambient = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ}
    def fill(values):
        values = {**values, "GIT_DIR": "discard", "GIT_ALLOW_PROTOCOL": "discard"}
        return {**values, **dict.fromkeys((f"INPUT_{i}" for i in range(512 - len(values))), "discard")}
    if layer == "ambient":
        ambient = fill(ambient)
    monkeypatch.setattr(team_git, "os", SimpleNamespace(**{**vars(os), "environ": ambient}))

    view = source.SourceViews(repo, child_environment=(lambda values, purpose: fill(values)) if layer == "injected" else None)
    assert view.show({"commit": oid, "path": "other"})["lines"] == ["other"]
    values = view.read_environment()
    assert values["GIT_ALLOW_PROTOCOL"] == "" and "GIT_DIR" not in values and "INPUT_0" not in values


def test_windows_source_launches_use_canonical_keys_in_concurrent_reads(repository, monkeypatch, tmp_path):
    repo, oid = repository
    system = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    ambient = {**system, "PATH": os.defpath, "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    monkeypatch.setattr(team_git, "os", SimpleNamespace(**{**vars(os), "name": "nt", "environ": ambient}))
    fixed = dict(gitsafe_policy.BASE_ENV, GIT_PROTOCOL_FROM_USER="0",
                 GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

    def read(directory):
        def environment(values, purpose):
            assert purpose == "no-host"
            return {**values, **dict.fromkeys(map(str.lower, fixed), "discard"),
                    "Temp": str(directory), "tmp": str(directory)}
        view = source.SourceViews(repo, child_environment=environment)
        return view.show({"commit": oid, "path": "other"})["lines"]

    directories = [tmp_path / name for name in ("first", "second")]
    for directory in directories:
        directory.mkdir()
    expected = [{**fixed, **system, "TEMP": str(directory), "TMP": str(directory)} for directory in directories]
    launches = []
    def record(argv, **kwargs):
        launches.append(kwargs["env"])
        return subprocess.Popen(argv, **kwargs)
    monkeypatch.setattr(gitsafe_run, "subprocess", SimpleNamespace(**{**vars(subprocess), "Popen": record}))

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(read, directory) for directory in directories]
        assert [task.result(timeout=60) for task in pending] == [["other"], ["other"]]
    assert all(child in expected for child in launches)
    assert all(child in launches for child in expected)


@pytest.mark.parametrize("case", ["ordinary", "backslash", "dot_component", "path_object", "colon", "comma",
                                 "relative", "parent_component", "long_component", "over_limit"])
def test_public_absolute_validator_matches_legacy(tmp_path, case):
    value = {"ordinary": str(tmp_path / "repository"),
             "backslash": str(tmp_path / "repository\\name"),
             "dot_component": str(tmp_path) + "/./repository",
             "path_object": tmp_path / "repository", "colon": str(tmp_path / "repository:name"),
             "comma": str(tmp_path / "repository,name"), "relative": "repository",
             "parent_component": str(tmp_path) + "/../repository",
             "long_component": tmp_path.anchor + "x" * 256,
             "over_limit": tmp_path.anchor + "x" * (4097 - len(tmp_path.anchor))}[case]
    if case in ("relative", "parent_component", "over_limit"):
        with pytest.raises(ValueError):
            legacy_absolute._absolute(value, "repository")
        with pytest.raises(team_host_plan.HostRefusal) as caught:
            team_host_plan.absolute_path(value, limit=4096)
        assert caught.value.reason == "unsafe_path"
        assert caught.value.code == 1 and caught.value.next_action
        return
    expected = legacy_absolute._absolute(value, "repository")
    assert team_host_plan.absolute_path(value, limit=4096) == expected


def test_non_path_pathlike_is_the_authorized_fail_closed_exception(tmp_path):
    calls = []
    class Pathlike(os.PathLike):
        def __fspath__(self):
            calls.append(True)
            return str(tmp_path)
    value = Pathlike()
    assert legacy_absolute._absolute(value, "repository") == tmp_path
    assert calls == [True]
    calls.clear()
    with pytest.raises(team_host_plan.HostRefusal) as caught:
        team_host_plan.absolute_path(value, limit=4096)
    assert caught.value.reason == "unsafe_path"
    assert caught.value.code == 1 and caught.value.next_action
    assert calls == []


@pytest.mark.parametrize("limit", [None, True, [], 0, -1, 32769])
def test_absolute_path_invalid_limit_has_a_fixed_refusal_and_retries(tmp_path, limit):
    with pytest.raises(team_host_plan.HostRefusal) as caught:
        team_host_plan.absolute_path(tmp_path, limit=limit)
    assert caught.value.reason == "unsafe_path"
    assert caught.value.code == 1 and caught.value.next_action
    assert team_host_plan.absolute_path(tmp_path, limit=4096) == tmp_path


def test_host_plan_default_limit_is_retained(tmp_path):
    value = tmp_path.anchor + "x" * (4097 - len(tmp_path.anchor))
    assert team_host_plan.absolute_path(value) == Path(value)


def test_child_environment_port_cannot_relax_object_read_policy(repository):
    repo, _ = repository
    def environment(values, purpose):
        return {**values, "GIT_NO_REPLACE_OBJECTS": "0", "GIT_NO_LAZY_FETCH": "0",
                "GIT_ALLOW_PROTOCOL": "all", "GIT_CONFIG_GLOBAL": "untrusted", "GIT_CONFIG_NOSYSTEM": "0"}
    values = source.SourceViews(repo, child_environment=environment).read_environment()
    assert values["GIT_NO_REPLACE_OBJECTS"] == "1" and values["GIT_NO_LAZY_FETCH"] == "1"
    assert values["GIT_ALLOW_PROTOCOL"] == ""
    assert values["GIT_CONFIG_GLOBAL"] == os.devnull and values["GIT_CONFIG_NOSYSTEM"] == "1"


@pytest.mark.parametrize("value", [None, {"X": 1}, {1: "X"}, dict.fromkeys(map(str, range(513)), "x"),
                                  {**dict.fromkeys(map(str, range(512)), "x"), "GIT_ALLOW_PROTOCOL": "discard"}],
                         ids=["missing", "non_string_value", "non_string_key", "too_many", "too_many_with_fixed_key"])
def test_child_environment_port_bad_result_is_a_fixed_refusal(repository, value):
    repo, _ = repository
    with pytest.raises(source.SourceRefusal) as caught:
        source.SourceViews(repo, child_environment=lambda values, purpose: value)
    envelope(caught, "invalid_environment")
    assert source.SourceViews(repo).repository == repo


# Command and record expectations here are independent of the structured builder.
GREP_ORACLE = (
    "grep", "-z", "-n", "-I", "-F", "--no-color", "--no-column", "--no-textconv",
    "--no-recurse-submodules", "--full-name", "-f", "-",
)
GREP_INPUT = b"other\n"
GREP_OVERFLOW_ADVICE = (
    "Narrow paths and the fixed string, then retry. Output over the capture cap refuses the whole "
    "result before the post-capture returned-match limit; a capture that fits can still truncate at "
    "that limit. For a known eligible blob, use paged source_show."
)
GREP_BYTE_LIMIT = "🙂" * 256
GREP_CR_LIMIT = GREP_BYTE_LIMIT[:-1] + "\r"
GREP_ROWS = {
    "lf.txt": ("needle", "-literal [x]", "café 雪", GREP_BYTE_LIMIT),
    "crlf.txt": ("before\r", "needle\r", "needle\r\r", GREP_CR_LIMIT),
}


def _install_runner(monkeypatch, run):
    monkeypatch.setattr(source, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": run}))


def _command_tail(argv):
    argv = tuple(argv)
    return argv[argv.index("--literal-pathspecs") + 1:]


def test_sparse_page_offsets_count_toward_cache_admission(repository, monkeypatch):
    repo, _ = repository
    text = "row\n" * 65536 + "last"
    oid = commit(repo, "dense.txt", text.encode())
    args = {"commit": oid, "path": "dense.txt", "start_line": 65536, "max_lines": 2}
    blob = git(repo, "rev-parse", oid + ":dense.txt").decode().strip()
    view = source.SourceViews(repo)
    real, reads = gitsafe.run, []

    def run(argv, *rest, **kwargs):
        if _command_tail(argv) == ("cat-file", "blob", blob):
            reads.append(blob)
        return real(argv, *rest, **kwargs)

    _install_runner(monkeypatch, run)
    text_only = (oid + ":dense.txt", blob, text)
    text_only_bytes = sys.getsizeof(text_only) + sum(map(sys.getsizeof, text_only))
    # Leave room for fixed metadata but less than the sparse offsets need.
    monkeypatch.setattr(source, "MAX_CACHED_BYTES", text_only_bytes + 256)
    expected = {"commit": oid, "path": "dense.txt", "blob": blob, "start_line": 65536,
                "total_lines": 65537, "lines": ["row", "last"], "cut_lines": [], "next_start_line": None}
    for _ in range(2):
        assert view.show(args) == expected
    assert reads == [blob, blob]

    monkeypatch.setattr(source, "MAX_CACHED_BYTES", text_only_bytes + 16384)
    for _ in range(2):
        assert view.show(args) == expected
    assert reads == [blob, blob, blob]


@pytest.mark.parametrize("ending", [b"", b"\n"])
def test_sparse_pages_keep_lf_boundaries_when_cache_entries_alternate(repository, ending):
    repo, _ = repository
    rows = [str(n).encode() for n in range(1, 770)]
    rows[255:258] = ["é🙂\r".encode(), b"", b"bad\xff"]
    rows[511] = b"x" * 5000
    oid = commit(repo, "mixed.txt", b"\n".join(rows) + ending)
    blob = git(repo, "rev-parse", oid + ":mixed.txt").decode().strip()
    view = source.SourceViews(repo)

    def read(start):
        if start == 0:
            return view.show({"commit": oid, "path": "other"})["lines"]
        return view.show({"commit": oid, "path": "mixed.txt", "start_line": start, "max_lines": 2})

    def expected(start):
        if start == 0:
            return ["other"]
        return {"commit": oid, "path": "mixed.txt", "blob": blob, "start_line": start, "total_lines": len(rows),
                "lines": [row.decode("utf-8", errors="replace")[:4096] for row in rows[start - 1:start + 1]],
                "cut_lines": [512] if start in (511, 512) else [],
                "next_start_line": start + 2 if start + 1 < len(rows) else None}

    starts = [255, 256, 257, 0, 258, 511, 512, 0, 513, 768, 769]
    with ThreadPoolExecutor(max_workers=3) as pool:
        pending = [pool.submit(read, start) for start in starts]
        assert [task.result(timeout=15) for task in pending] == [expected(start) for start in starts]
    with pytest.raises(source.SourceRefusal) as caught:
        read(770)
    envelope(caught, "page_out_of_range")
    assert read(769) == expected(769)


def test_warm_source_pages_validate_commit_and_retry_after_refusals(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo)
    real, commands = gitsafe.run, []
    reject_commit = False

    def run(argv, *rest, **kwargs):
        command = _command_tail(argv)
        commands.append(command)
        if reject_commit and command == ("cat-file", "-t", oid):
            return subprocess.CompletedProcess(argv, 1, b"", b"fixture diagnostic")
        return real(argv, *rest, **kwargs)

    _install_runner(monkeypatch, run)
    args = {"commit": oid, "path": "page.txt", "start_line": 150}
    page = view.show(args)
    assert page["lines"] == ["line"]
    commands.clear()
    reject_commit = True
    with pytest.raises(source.SourceRefusal) as caught:
        view.show(args)
    envelope(caught, "unknown_commit")
    assert str(caught.value) == "source refused: unknown_commit"
    reject_commit = False
    assert view.show(args) == page
    assert commands == [("cat-file", "-t", oid)] * 2

    for alternate in ("absent", "other"):
        commands.clear()
        if alternate == "absent":
            with pytest.raises(source.SourceRefusal) as caught:
                view.show({**args, "path": alternate})
            envelope(caught, "unknown_path")
        else:
            assert view.show({"commit": oid, "path": alternate})["lines"] == ["other"]
        assert view.show(args) == page
        assert ("cat-file", "blob", page["blob"]) in commands


@pytest.mark.parametrize("api", ["git", "unchecked", "bounded"])
def test_raw_grep_refuses_before_git(repository, monkeypatch, api):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)

    def unexpected(*args, **kwargs):
        pytest.fail("raw grep reached Git")

    _install_runner(monkeypatch, unexpected)
    canonical = (*GREP_ORACLE, oid, "--", "other")
    commands = (
        canonical,
        ("grep",),
        ("grep", "other"),
        ("grep", "-F", oid),
        ("grep", "-e", "other"),
        ("grep", "-F", "other", "--", "other"),
    )
    for argv in commands:
        for data in (GREP_INPUT, None, b"", b"\n", b"\r\n", b"\n\r\n\n", b"other\nneedle\n"):
            with pytest.raises(source.SourceRefusal) as caught:
                if api == "bounded":
                    view.bounded(list(argv), data, source.MAX_GREP_OUTPUT_BYTES)
                else:
                    view.git(*argv, data=data, check=api == "git")
            envelope(caught, "invalid_arguments")
            assert str(caught.value) == "source refused: invalid_arguments"
            assert caught.value.next_action == "Supply the documented source-view fields and page limits."


@pytest.fixture
def grep_repository(repository):
    repo, _ = repository
    for path, rows in GREP_ROWS.items():
        (repo / path).write_bytes(("\n".join(rows) + "\n").encode("utf-8"))
    git(repo, "add", "lf.txt", "crlf.txt")
    git(repo, "commit", "-qm", "grep fixture")
    oid = git(repo, "rev-parse", "HEAD").decode().strip()
    for path in GREP_ROWS:
        (repo / path).write_bytes(b"needle in the working tree\r\n")
    return repo, oid


@pytest.mark.parametrize("pattern,stdin,locations", [
    pytest.param("\r", b"\r\r\n", [("crlf.txt", n) for n in range(1, 5)], id="cr-only"),
    pytest.param("needle\r", b"needle\r\r\n", [("crlf.txt", 2), ("crlf.txt", 3)], id="trailing-cr"),
    pytest.param("needle\r\r", b"needle\r\r\r\n", [("crlf.txt", 3)], id="two-trailing-crs"),
    pytest.param("needle", b"needle\n", [("crlf.txt", 2), ("crlf.txt", 3), ("lf.txt", 1)], id="plain"),
    pytest.param("-literal [x]", b"-literal [x]\n", [("lf.txt", 2)], id="leading-option"),
    pytest.param("café 雪", "café 雪\n".encode("utf-8"), [("lf.txt", 3)], id="unicode"),
    pytest.param(GREP_BYTE_LIMIT, "🙂".encode("utf-8") * 256 + b"\n", [("lf.txt", 4)], id="byte-ceiling"),
    pytest.param(GREP_CR_LIMIT, "🙂".encode("utf-8") * 255 + b"\r\r\n", [("crlf.txt", 4)], id="cr-ceiling"),
])
def test_structured_grep_preserves_literal_committed_pattern(grep_repository, monkeypatch, pattern, stdin, locations):
    repo, oid = grep_repository
    view = source.SourceViews(repo, planned=False)
    real, seen = gitsafe.run, []

    def run(argv, *rest, **kwargs):
        seen.append((_command_tail(argv), kwargs["stdin"]))
        return real(argv, *rest, **kwargs)

    _install_runner(monkeypatch, run)
    paths = ["lf.txt", "crlf.txt"]
    matches = [{"path": path, "line": line, "text": GREP_ROWS[path][line - 1]} for path, line in locations]
    answer = view.call("source_grep", {"commit": oid, "pattern": pattern, "paths": paths})
    assert answer == {"commit": oid, "pattern": pattern, "paths": paths, "matches": matches, "truncated": False}
    assert seen == [(("cat-file", "-t", oid), None), ((*GREP_ORACLE, oid, "--", *paths), stdin)]


def test_structured_grep_refuses_invalid_request_before_git_then_retries(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    real, seen = gitsafe.run, []

    def run(argv, *rest, **kwargs):
        seen.append(_command_tail(argv))
        return real(argv, *rest, **kwargs)

    _install_runner(monkeypatch, run)
    valid = {"commit": oid, "pattern": "other", "paths": ["other"]}
    for pattern in ("", "\n", "\0", "\ud800", GREP_BYTE_LIMIT + "x"):
        with pytest.raises(source.SourceRefusal) as caught:
            view.grep({**valid, "pattern": pattern})
        envelope(caught, "invalid_arguments")
    for revision in ("HEAD", oid[:7], oid[:39], oid + "0", "A" * 40, "g" * 40):
        with pytest.raises(source.SourceRefusal) as caught:
            view.grep({**valid, "commit": revision})
        envelope(caught, "invalid_commit")
    for path in ("", "../outside", "/other", "a/./b", "a//b", "a\\b", "--cached", "x" * 1025, "\ud800"):
        with pytest.raises(source.SourceRefusal) as caught:
            view.grep({**valid, "paths": [path]})
        envelope(caught, "invalid_path")
    assert seen == []

    absent = ("0" if oid[0] != "0" else "1") + oid[1:]
    with pytest.raises(source.SourceRefusal) as caught:
        view.grep({**valid, "commit": absent})
    envelope(caught, "unknown_commit")
    assert seen == [("cat-file", "-t", absent)]
    assert view.grep(valid) == {**valid, "matches": [{"path": "other", "line": 1, "text": "other"}],
                                "truncated": False}
    assert seen == [("cat-file", "-t", absent), ("cat-file", "-t", oid), (*GREP_ORACLE, oid, "--", "other")]
    assert view.show({"commit": oid, "path": "other"})["lines"] == ["other"]


def test_concurrent_raw_refusals_keep_structured_reads(repository):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)

    def attempt(index):
        if index % 2:
            argv = (*GREP_ORACLE, oid, "--", "other")
            with pytest.raises(source.SourceRefusal) as caught:
                if index % 4 == 1:
                    view.git(*argv, data=GREP_INPUT, check=False)
                else:
                    view.bounded(list(argv), GREP_INPUT, source.MAX_GREP_OUTPUT_BYTES)
            envelope(caught, "invalid_arguments")
            return "refused"
        shown = view.show({"commit": oid, "path": "other"})["lines"]
        matched = view.grep({"commit": oid, "pattern": "other"})["matches"][0]["text"]
        return "read", shown, matched

    with ThreadPoolExecutor(max_workers=3) as pool:
        result = list(pool.map(attempt, range(8)))
    assert result == [("read", ["other"], "other") if index % 2 == 0 else "refused" for index in range(8)]
    assert view.grep({"commit": oid, "pattern": "other", "paths": ["page.txt"]})["matches"] == []


def test_grep_overflow_advice_names_narrowing_paging_and_result_limit(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    original = source.MAX_GREP_OUTPUT_BYTES
    monkeypatch.setattr(source, "MAX_GREP_OUTPUT_BYTES", 500)
    def overflow():
        with pytest.raises(source.SourceRefusal) as caught:
            view.grep({"commit": oid, "pattern": "line", "paths": ["page.txt"]})
        envelope(caught, "source_grep_output_limit")
        assert caught.value.next_action == GREP_OVERFLOW_ADVICE
        assert "\n" not in caught.value.next_action and "line" not in caught.value.next_action
        assert "page.txt" not in str(caught.value) and not hasattr(caught.value, "stdout")
        return caught.value.reason
    assert overflow() == "source_grep_output_limit"
    narrowed = view.grep({"commit": oid, "pattern": "line", "paths": ["other"]})
    assert narrowed == {"commit": oid, "pattern": "line", "paths": ["other"], "matches": [], "truncated": False}
    fixed = view.grep({"commit": oid, "pattern": "other", "paths": ["other"]})
    assert fixed["matches"][0]["text"] == "other" and fixed["truncated"] is False
    page = view.show({"commit": oid, "path": "page.txt", "start_line": 1, "max_lines": 2})
    assert page["lines"] == ["line", "line"] and page["next_start_line"] == 3 and page["total_lines"] == 150
    def attempt(index):
        if index % 2:
            return overflow()
        return view.grep({"commit": oid, "pattern": "other", "paths": ["other"]})["matches"][0]["text"]
    with ThreadPoolExecutor(max_workers=3) as pool:
        concurrent = list(pool.map(attempt, range(6)))
    assert concurrent == ["source_grep_output_limit" if index % 2 else "other" for index in range(6)]
    monkeypatch.setattr(source, "MAX_GREP_OUTPUT_BYTES", original)
    captured = view.grep({"commit": oid, "pattern": "line", "paths": ["page.txt"], "limit": 2})
    assert len(captured["matches"]) == 2 and captured["truncated"] is True
    assert captured["matches"][0]["text"] == "line"
    retry = view.grep({"commit": oid, "pattern": "line", "paths": ["page.txt"], "limit": 150})
    assert len(retry["matches"]) == 150 and retry["truncated"] is False


def test_bounded_list_mutation_does_not_change_the_launched_snapshot(repository, monkeypatch):
    """Custody entry mutates the caller list after an allowed read is validated."""
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    original = ("cat-file", "-t", oid)
    shared = list(original)
    launched = []
    entered, mutated = threading.Event(), threading.Event()

    def custody(*args, **kwargs):
        entered.set()
        assert mutated.wait(5), "list mutation did not arrive before the process boundary"
        return nullcontext()

    def run(argv, *rest, **kwargs):
        launched.append((_command_tail(argv), kwargs["stdin"]))
        return subprocess.CompletedProcess(argv, 0, b"commit\n", b"")

    def change():
        if entered.wait(5):
            shared[:] = ["rev-parse", "--git-dir"]
            mutated.set()

    monkeypatch.setattr(source, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "run": run, "custody": custody}))
    worker = threading.Thread(target=change)
    worker.start()
    try:
        assert view.bounded(shared, b"", 65536) == (b"commit\n", False, 0)
    finally:
        worker.join(5)
    assert worker.is_alive() is False
    assert shared == ["rev-parse", "--git-dir"]
    assert launched == [(original, b"")]


def test_structured_grep_checks_path_count_before_git(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    real, seen = gitsafe.run, []

    def run(argv, *rest, **kwargs):
        seen.append((_command_tail(argv), kwargs["stdin"]))
        return real(argv, *rest, **kwargs)

    _install_runner(monkeypatch, run)
    maximum = ["other"] + ["p" + str(index) for index in range(63)]
    args = {"commit": oid, "pattern": "other"}
    assert len(maximum) == 64
    with pytest.raises(source.SourceRefusal) as caught:
        view.grep({**args, "paths": [*maximum, "extra"]})
    envelope(caught, "invalid_arguments")
    assert seen == []

    for paths in ([], maximum):
        answer = view.grep({**args, "paths": paths})
        assert answer == {**args, "paths": paths, "matches": [{"path": "other", "line": 1, "text": "other"}],
                          "truncated": False}
    assert seen == [
        (("cat-file", "-t", oid), None), ((*GREP_ORACLE, oid, "--"), GREP_INPUT),
        (("cat-file", "-t", oid), None), ((*GREP_ORACLE, oid, "--", *maximum), GREP_INPUT),
    ]


def test_structured_grep_snapshots_path_count_before_validation(repository, monkeypatch):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    paths = ["other"] + ["p" + str(index) for index in range(63)]
    expected = paths.copy()
    validate = source.relative_path

    def append_during_validation(path):
        if len(paths) == 64:
            paths.append("extra")
        return validate(path)

    monkeypatch.setattr(source, "relative_path", append_during_validation)
    answer = view.grep({"commit": oid, "pattern": "other", "paths": paths})
    assert paths == [*expected, "extra"]
    assert answer["paths"] == expected
    assert answer["matches"] == [{"path": "other", "line": 1, "text": "other"}]


def test_non_grep_raw_calls_keep_their_return_types(repository):
    repo, oid = repository
    view = source.SourceViews(repo, planned=False)
    arguments = ("cat-file", "-t", oid)
    result = view.git(*arguments)
    assert isinstance(result, subprocess.CompletedProcess)
    assert (result.stdout, result.returncode) == (b"commit\n", 0)
    assert view.bounded(arguments, b"", 65536) == (b"commit\n", False, 0)
