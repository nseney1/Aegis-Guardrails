"""Target diagnostics use real repositories and isolated user directories."""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from aegis_core import gitsafe, storage_confined
from aegis_core.workspace import target

from tests import helpers_humangate as hg
from aegis_core.workspace.binding import WorkspaceBinding


@pytest.fixture
def target_home(tmp_path, monkeypatch):
    if not storage_confined.descriptor_supported():
        pytest.skip("target identity requires descriptor-confined metadata reads")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for key in list(os.environ):
        if key.startswith("GIT_") and key != "GIT_CONFIG_NOSYSTEM":
            monkeypatch.delenv(key)
        if key.startswith("CLAUDE_CODE_") or key in ("CLAUDECODE", "CLAUDE_PID", "CLAUDE_PROJECT_DIR"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(home)
    return home.resolve()


@pytest.fixture
def target_repo(target_home, tmp_path):
    repo = hg.Repo(tmp_path / "repo", hg.Home(target_home))
    repo.write(".aegis/rules/traps/trap-target.md", "---\nid: trap-target\ntype: trap\n"
               "hypothesis: h\nprediction: p\ntarget_paths: ['*.py']\n---\nBody.\n")
    repo.write("app.py", "x = 1\n")
    repo.commit()
    return repo


def tree(root: Path):
    return sorted((str(p.relative_to(root)), hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in root.rglob("*") if p.is_file())


class Checkout:
    """A linked worktree of ``repo`` (constructing hg.Repo there would run git init)."""

    def __init__(self, repo, root: Path) -> None:
        self.repo, self.root, self.home = repo, root, repo.home

    def head(self) -> str:
        return literal_head(self.root, self.home.env)


def literal_head(root: Path, env=None):
    """The oracle for HEAD, read without revision-name DWIM (``rev-parse HEAD`` falls
    back to refs/HEAD, refs/tags/HEAD... when HEAD's branch is unborn): the exact ref
    a symbolic HEAD names, or the object id a detached HEAD file holds."""
    sym = hg.run_git(root, "symbolic-ref", "-q", "HEAD", env=env, check=False)
    if sym.returncode == 0:
        ref = sym.stdout[:-1]
        rows = hg.run_git(root, "for-each-ref", "--format=%(refname)%00%(objectname)", ref, env=env).stdout
        found = [line.split("\0")[1] for line in rows.splitlines() if line.split("\0")[0] == ref]
        return found[0] if found else None
    raw = hg.run_git(root, "rev-parse", "--git-path", "HEAD", env=env).stdout[:-1]
    path = Path(raw) if os.path.isabs(raw) else root / raw
    return path.read_text(encoding="ascii")[:-1]


def linked(repo, root: Path) -> Checkout:
    repo.git("worktree", "add", "-q", "--detach", str(root))
    return Checkout(repo, root.resolve(strict=True))


def strict_document(wire: str) -> dict:
    """What a strict parser (serde_json) accepts: no lone surrogate escapes."""
    import json

    doc = json.loads(wire)

    def walk(value):
        if isinstance(value, str):
            value.encode("utf-8")  # raises on a lone surrogate
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(key)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(doc)
    return doc


@pytest.fixture
def portable_separate_target_repo(target_repo, tmp_path):
    # A --separate-git-dir checkout has no back-link (unverified); its linked
    # worktree does, and keeps the separate common directory as identity.
    admin = tmp_path / "admin directory"
    target_repo.git("init", "-q", "--separate-git-dir=" + str(admin))
    return linked(target_repo, tmp_path / "portable worktree"), admin.resolve(strict=True)


def test_portable_separate_git_directory_keeps_exact_identity(portable_separate_target_repo, tmp_path):
    from aegis_core.workspace.target import observe_target

    repo, admin = portable_separate_target_repo
    binding = WorkspaceBinding("bound", repo.root, "cli_workspace", "operator")
    before = tree(tmp_path)
    doc = observe_target(binding)
    assert doc["status"] == "observed" and doc["binding"] == binding.as_dict()
    assert doc["repository"] == {"status": "observed", "reason": None,
        "common_dir": str(admin), "worktree_root": str(repo.root)}
    assert doc["head"]["oid"] == repo.head()
    assert tree(tmp_path) == before


@pytest.fixture
def separate_target_repos(target_home, tmp_path):
    repos = []
    for name, admin_name in (("control", "admin"), ("spaced", "admin ")):
        repo = hg.Repo(tmp_path / name, hg.Home(target_home))
        admin = tmp_path / admin_name
        repo.git("init", "-q", "--separate-git-dir=" + str(admin))
        repo.write(".aegis/rules/traps/trap-target.md", "---\nid: trap-target\ntype: trap\n"
                   "hypothesis: h\nprediction: p\ntarget_paths: ['*.py']\n---\nBody.\n")
        repo.write("app.py", "probe = " + repr(name) + "\n")
        repo.commit("owned " + name)
        repos.append((linked(repo, tmp_path / (name + " checkout")), admin.resolve(strict=True)))
    assert repos[0][1].stat().st_ino != repos[1][1].stat().st_ino
    assert repos[0][0].head() != repos[1][0].head()
    return repos


@pytest.mark.skipif(os.name == "nt", reason="Ordinary Windows paths do not preserve distinct 'admin' and 'admin ' directories")
def test_separate_git_directories_keep_exact_identity(separate_target_repos, tmp_path):
    from aegis_core.workspace.target import observe_target

    before = tree(tmp_path)
    for repo, admin in separate_target_repos:
        with gitsafe.scrubbed():
            raw = gitsafe.run(["rev-parse", "--git-common-dir"], repo.root)
        assert raw.returncode == 0 and raw.stdout == os.fsencode(admin) + b"\n"
        doc = observe_target(WorkspaceBinding("bound", repo.root, "cli_workspace", "operator"))
        assert doc["status"] == "observed"
        assert doc["repository"] == {"status": "observed", "reason": None,
            "common_dir": str(admin), "worktree_root": str(repo.root)}
        assert doc["head"]["oid"] == repo.head()
    assert tree(tmp_path) == before


def test_relative_git_paths_use_the_binding_not_process_cwd(target_repo, target_home):
    from aegis_core.workspace.target import observe_target

    assert Path.cwd() == target_home and Path.cwd() != target_repo.root
    with gitsafe.scrubbed():
        result = gitsafe.run(["rev-parse", "--git-common-dir"], target_repo.root)
    assert result.returncode == 0 and result.stdout == b".git\n"
    before = tree(target_repo.root)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert doc["status"] == "observed"
    assert doc["repository"] == {"status": "observed", "reason": None,
        "common_dir": str(target_repo.root / ".git"), "worktree_root": str(target_repo.root)}
    assert doc["head"]["oid"] == literal_head(target_repo.root)
    assert tree(target_repo.root) == before


# A CR or LF that remains after the trailing framing run. Space and TAB stay data.
_EMBEDDED_RECORD_BREAKS = (
    ("line\nbreak", "admin\ninside"),
    ("worktree\r", "admin"),
    ("worktree\n", "admin"),
)


@pytest.mark.parametrize("root_name,admin_name", [
    pytest.param(" worktree ", " admin ", marks=pytest.mark.skipif(
        os.name == "nt", reason="Ordinary Windows filesystem calls normalize trailing spaces in path components")),
    pytest.param("worktree\t", "admin\t", marks=pytest.mark.skipif(
        os.name == "nt", reason="Windows forbids TAB in ordinary path components")),
    pytest.param("line\nbreak", "admin\ninside", marks=pytest.mark.skipif(
        os.name == "nt", reason="Windows forbids LF in ordinary path components")),
    pytest.param("worktree\r", "admin", marks=pytest.mark.skipif(
        os.name == "nt", reason="Windows forbids CR in ordinary path components")),
    pytest.param("worktree\n", "admin", marks=pytest.mark.skipif(
        os.name == "nt", reason="Windows forbids LF in ordinary path components")),
])
def test_git_path_whitespace_is_data(target_home, tmp_path, root_name, admin_name):
    from aegis_core.workspace.target import observe_target

    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    admin = tmp_path / admin_name
    main.git("init", "-q", "--separate-git-dir=" + str(admin))
    main.write("app.py", "x = 1\n")
    main.commit()
    repo = linked(main, tmp_path / root_name)
    expected_head = literal_head(repo.root)
    with gitsafe.scrubbed():
        for flag, expected in (("--git-common-dir", admin), ("--show-toplevel", repo.root)):
            result = gitsafe.run(["rev-parse", flag], repo.root)
            assert result.returncode == 0 and result.stdout == os.fsencode(expected) + b"\n"
    before = tree(tmp_path)
    doc = observe_target(WorkspaceBinding("bound", repo.root, "cli_workspace", "operator"))
    if (root_name, admin_name) in _EMBEDDED_RECORD_BREAKS:
        # Git still reports the path. The selecting record fails closed, so the
        # diagnostic identity stays the existing unknown document.
        assert doc["status"] == "unknown" and doc["reason"] == "unverified_git_link"
        assert doc["binding"]["root"] == str(repo.root)
        assert doc["repository"] == {"status": "unknown", "reason": "unverified_git_link",
                                     "common_dir": None, "worktree_root": None}
        assert doc["head"] == {"status": "unknown", "reason": "unverified_git_link", "oid": None}
    else:
        assert doc["status"] == "observed"
        assert doc["repository"] == {"status": "observed", "reason": None,
            "common_dir": str(admin.resolve(strict=True)), "worktree_root": str(repo.root.resolve(strict=True))}
        assert doc["head"]["oid"] == expected_head
    # Negative control: the separate-git-dir checkout itself has no back-link.
    control = observe_target(WorkspaceBinding("bound", main.root.resolve(), "cli_workspace", "operator"))
    assert control["status"] == "unknown" and control["reason"] == "unverified_git_link"
    assert control["repository"]["common_dir"] is None and control["head"]["oid"] is None
    assert tree(tmp_path) == before


@pytest.mark.parametrize("flag", ["--git-common-dir", "--show-toplevel"])
@pytest.mark.parametrize("case,reason", [
    ("missing_lf", "invalid_git_identity"), ("empty", "invalid_git_identity"),
    ("nul", "invalid_git_identity"), ("missing_directory", "unverified_git_link"),
    ("file", "unverified_git_link"),
])
def test_malformed_git_path_answers_are_unknown(target_repo, monkeypatch, flag, case, reason):
    from aegis_core.workspace.target import observe_target

    root = target_repo.root
    actual = root / ".git" if flag == "--git-common-dir" else root
    replies = {"missing_lf": os.fsencode(actual), "empty": b"\n", "nul": b"bad\0path\n",
               "missing_directory": os.fsencode(root / "missing") + b"\n",
               "file": os.fsencode(root / "app.py") + b"\n"}
    real_run = gitsafe.run
    hits = []

    def run(argv, *args, **kwargs):
        if flag in argv:
            hits.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=replies[case], stderr=b"")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    before = tree(root)
    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert len(hits) == 1  # the injected answer was the one observed
    assert doc["status"] == "unknown" and doc["reason"] == reason
    assert doc["repository"]["status"] == "unknown"
    assert doc["repository"]["common_dir"] is None and doc["repository"]["worktree_root"] is None
    assert doc["head"]["oid"] is None and doc["binding"]["root"] == str(root)
    assert tree(root) == before


@pytest.mark.parametrize("flag", ["--git-common-dir", "--show-toplevel"])
def test_oversized_raw_git_paths_overflow_without_truncation(target_repo, monkeypatch, flag):
    from aegis_core.workspace.target import observe_target

    real_run = gitsafe.run
    hits = []

    def run(argv, *args, **kwargs):
        if flag in argv:
            hits.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=b"/" + b"p" * 4094 + b"\n", stderr=b"")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert len(hits) == 1
    assert doc["status"] == "overflow" and doc["reason"] == "diagnostic_limit_exceeded"
    assert doc["binding"] is None and doc["repository"]["common_dir"] is None
    assert doc["repository"]["worktree_root"] is None and doc["head"]["oid"] is None


def test_expanded_git_path_limit_precedes_head_observation(target_repo, tmp_path, monkeypatch):
    import json
    from aegis_core.workspace.target import observe_target

    # Model the same OS alias boundary as the MCP canonicalization case. Its
    # destination is a real directory with a short filesystem byte length but
    # a JSON-escaped path exceeding the diagnostic's field bound. The fault is
    # injected at the observer's own resolution helper, which every supported
    # Python calls (Path.resolve does not use os.path.realpath before 3.11).
    expanded = tmp_path
    for _ in range(10):
        expanded = expanded / ("\u4e00" * 70)
    expanded.mkdir(parents=True)
    assert len(json.dumps(str(expanded), ensure_ascii=True)) > 4096
    canonical, real_run = target._canonical, gitsafe.run
    heads, faults = [], []

    def resolve(path):
        if os.fspath(path) == str(target_repo.root / ".git"):
            faults.append(path)
            return expanded
        return canonical(path)

    def run(argv, *args, **kwargs):
        if "symbolic-ref" in argv or "show-ref" in argv:
            heads.append(argv)
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(target, "_canonical", resolve)
    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert len(faults) == 1
    assert doc["status"] == "overflow" and doc["reason"] == "diagnostic_limit_exceeded"
    assert doc["binding"] is None and doc["head"]["oid"] is None
    assert heads == []


def test_observer_requires_a_typed_resolved_binding(target_home):
    from aegis_core.workspace.target import observe_target

    for binding in (None, {}, str(target_home), WorkspaceBinding("bound"), WorkspaceBinding("invalid")):
        doc = observe_target(binding)
        assert doc["status"] == "error" and doc["binding"] is None
        assert doc["error"] == "aegis_target requires a server-resolved binding."


@pytest.mark.parametrize("status", ["unbound", "hold", "error"])
def test_nonbound_without_prose_is_still_an_error(target_home, status):
    from aegis_core.workspace.target import observe_target
    from aegis_mcp.projection import is_error_result

    doc = observe_target(WorkspaceBinding(status))
    assert is_error_result(doc)
    assert doc["error"] == "No governed workspace is bound to this call."
    assert doc["binding"]["root"] is None and doc["head"]["oid"] is None


@pytest.mark.parametrize("field,value", [
    ("source", "s" * 63), ("confidence", "c" * 63), ("reason", "r" * 127),
    ("message", "m" * 4095), ("root", Path("/" + "r" * 4094)),
    ("details", tuple((str(i), "v") for i in range(17))),
    ("details", (("k" * 63, "v"),)), ("details", (("k", "v" * 4095),)),
    ("details", (("k", ["v"] * 33),)), ("details", (("k", ["v" * 4095]),)),
    ("details", (("k", {"nested": "unsupported"}),)),
    ("details", ((None, "v"),)), ("details", (("k", [None]),)),
], ids=["source", "confidence", "reason", "message", "root", "detail-count", "detail-key",
        "detail-value", "list-count", "list-item", "recursive-value", "null-key", "null-list-item"])
def test_binding_field_overflow_is_explicit_and_does_not_probe(target_home, monkeypatch, field, value):
    from aegis_core.workspace.target import encode_target, observe_target

    def unexpected(*args, **kwargs):
        pytest.fail("overflow or unbound binding must not start a Git observer")

    monkeypatch.setattr(gitsafe, "run", unexpected)
    args = {"status": "unbound", field: value}
    doc = observe_target(WorkspaceBinding(**args))
    assert doc["status"] == "overflow" and doc["binding"] is None
    assert len(encode_target(doc).encode("utf8")) <= 65536


def test_aggregate_binding_overflow_precedes_git(target_home, monkeypatch):
    import json
    from aegis_core.primitives import TS_FORMAT
    from aegis_core.workspace.target import encode_target, observe_target

    roots = [str(target_home / ("r" * 2200 + str(i))) for i in range(32)]
    binding = WorkspaceBinding("hold", reason="ambiguous_host_roots", details=(("candidates", roots),))
    assert all(len(json.dumps(p)) <= 4096 for p in roots)
    assert len(json.dumps(binding.as_dict())) > 65536  # only the aggregate exceeds the cap
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(args)
        pytest.fail("overflow binding must not start a Git observer")

    monkeypatch.setattr(gitsafe, "run", unexpected)
    doc = observe_target(binding)
    wire = encode_target(doc)
    assert calls == []
    assert doc == {
        "schema": "aegis.target/v1", "status": "overflow", "reason": "diagnostic_limit_exceeded",
        "observed_at": doc["observed_at"], "binding": None,
        "repository": {"status": "unknown", "reason": "diagnostic_limit_exceeded",
                       "common_dir": None, "worktree_root": None},
        "head": {"status": "unknown", "reason": "diagnostic_limit_exceeded", "oid": None},
        "error": "Target diagnostic exceeds its limits.",
    }
    assert json.loads(wire) == doc and wire.endswith("\n") and wire.isascii()
    assert len(wire.encode("utf8")) <= 65536
    # The fixed document's size depends only on TS_FORMAT's fixed-width timestamp.
    assert TS_FORMAT == "%Y-%m-%dT%H:%M:%SZ" and len(wire) == 372


def test_encoder_applies_aggregate_cap_including_newline(target_home):
    import json
    from aegis_core.workspace.target import encode_target, observe_target

    doc = observe_target(WorkspaceBinding("unbound"))
    doc["binding"]["details"] = {"candidates": ["x" * 2200] * 32}
    out = encode_target(doc)
    assert out.isascii() and out.endswith("\n")
    assert len(out.encode("utf8")) <= 65536
    assert json.loads(out)["status"] == "overflow"


@pytest.mark.parametrize("value", ["x" * 4095, "\u4e00" * 683])
def test_error_field_limit_counts_json_escapes(target_home, value):
    import json
    from aegis_core.workspace.target import encode_target, target_error

    out = encode_target(target_error("binding_error", value))
    assert json.loads(out)["status"] == "overflow"


@pytest.mark.parametrize("field", ["common_dir", "worktree_root"])
def test_encoder_refuses_oversized_repository_paths(target_home, field):
    import json
    from aegis_core.workspace.target import encode_target, observe_target

    doc = observe_target(WorkspaceBinding("unbound"))
    doc["repository"][field] = "p" * 4095
    assert json.loads(encode_target(doc))["status"] == "overflow"


@pytest.mark.parametrize("field,value", [("source", "s" * 62), ("confidence", "c" * 62),
                                        ("reason", "r" * 126), ("message", "m" * 4094)])
def test_field_bounds_accept_the_exact_limit(target_home, field, value):
    from aegis_core.workspace.target import observe_target

    doc = observe_target(WorkspaceBinding("unbound", **{field: value}))
    assert doc["status"] == "not_governed" and doc["binding"][field] == value


RULE = ("---\nid: trap-target\ntype: trap\nhypothesis: h\nprediction: p\n"
        "target_paths: ['*.py']\n---\nBody.\n")


def workspace(root: Path) -> Path:
    (root / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    (root / ".aegis" / "rules" / "traps" / "trap-target.md").write_text(RULE, encoding="utf-8")
    return root


def other_repo(tmp_path, target_home, name="other"):
    other = hg.Repo(tmp_path / name, hg.Home(target_home))
    other.write("other.py", "y = 2\n")
    other.commit("other " + name)
    return other


def _git_link_case(case, tmp_path, target_home):
    """(bound root, expected document reason, expected common dir or None)."""
    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    main.write(".aegis/rules/traps/trap-target.md", RULE)
    main.write("app.py", "x = 1\n")
    main.commit()
    if case == "linked_worktree":
        return linked(main, tmp_path / "wt").root, None, main.root / ".git"
    if case == "linked_worktree_relative_links":
        wt = linked(main, tmp_path / "wt").root
        admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
        (wt / ".git").write_bytes(b"gitdir: " + os.fsencode(os.path.relpath(admin, wt)) + b"\n")
        (admin / "gitdir").write_bytes(os.fsencode(os.path.relpath(wt / ".git", admin)) + b"\n")
        return wt, None, main.root / ".git"
    if case == "separate_git_dir_checkout":
        main.git("init", "-q", "--separate-git-dir=" + str(tmp_path / "admin"))
        return main.root, "unverified_git_link", None
    root = workspace(tmp_path / "forged")
    other = other_repo(tmp_path, target_home)
    if case == "forged_pointer_to_main_gitdir":
        (root / ".git").write_bytes(b"gitdir: " + os.fsencode(other.root / ".git") + b"\n")
        return root, "unverified_git_link", None
    if case == "forged_pointer_to_other_worktree":
        theirs = linked(other, tmp_path / "theirs").root
        admin = hg.git(theirs, "rev-parse", "--absolute-git-dir")
        (root / ".git").write_bytes(b"gitdir: " + os.fsencode(admin) + b"\n")
        return root, "unverified_git_link", None
    if case in ("backlink_trailing_space", "backlink_crlf", "backlink_two_newlines", "backlink_missing"):
        wt = linked(main, tmp_path / "wt").root
        admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
        back = os.fsencode(wt / ".git")
        tail = {"backlink_trailing_space": b" \n", "backlink_crlf": b"\r\n",
                "backlink_two_newlines": b"\n\n", "backlink_missing": None}[case]
        if tail is None:
            (admin / "gitdir").unlink()
            return wt, "unverified_git_link", None
        (admin / "gitdir").write_bytes(back + tail)
        # A trailing CR/LF run is Git's framing. A trailing space is part of the name.
        if case in ("backlink_crlf", "backlink_two_newlines"):
            return wt, None, main.root / ".git"
        return wt, "unverified_git_link", None
    if case == "commondir_elsewhere":
        wt = linked(main, tmp_path / "wt").root
        admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
        (admin / "commondir").write_bytes(os.fsencode(other.root / ".git") + b"\n")
        return wt, "unverified_git_link", None
    if case == "dotgit_directory_commondir_elsewhere":
        hg.git(root, "init", "-q")
        (root / ".git" / "commondir").write_bytes(os.fsencode(other.root / ".git") + b"\n")
        return root, "unverified_git_link", None
    if case == "dotgit_symlink":
        os.symlink(other.root / ".git", root / ".git")
        return root, "unverified_git_link", None
    if case == "pointer_to_missing_dir":
        (root / ".git").write_bytes(b"gitdir: " + os.fsencode(tmp_path / "missing") + b"\n")
        return root, "unverified_git_link", None  # Missing original components are refused before Git
    if case == "malformed_pointer":
        (root / ".git").write_bytes(b"not a gitdir pointer\n")
        return root, "not_a_repository", None
    raise AssertionError(case)


def _cr_sibling(path: Path) -> Path:
    """The directory or file whose name is ``path`` plus a trailing CR."""
    return Path(os.fsdecode(os.fsencode(path) + b"\r"))


def _absolute_git_path(root: Path, flag: str) -> Path:
    reported = Path(hg.git(root, "rev-parse", flag))
    return reported.resolve() if reported.is_absolute() else (root / reported).resolve()


@pytest.mark.skipif(os.name == "nt", reason="a CR in a directory name is not a Windows path")
@pytest.mark.parametrize("record", ["gitfile", "commondir", "gitdir"])
def test_crlf_git_records_resolve_the_directory_git_uses(target_home, tmp_path, record):
    """A trailing CRLF record names the plain path, with the CR-suffixed sibling present."""
    from aegis_core.workspace.target import observe_target

    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    main.write("app.py", "x = 1\n")
    main.commit()
    wt = linked(main, tmp_path / "wt").root
    admin = _absolute_git_path(wt, "--absolute-git-dir")
    if record == "gitfile":
        record_path = wt / ".git"
        decoy = _cr_sibling(admin)
        decoy.mkdir()
        (decoy / "HEAD").write_bytes(b"ref: refs/heads/decoy\n")
    elif record == "commondir":
        record_path = admin / "commondir"
        decoy = _cr_sibling(main.root / ".git")
        decoy.mkdir()
        (decoy / "HEAD").write_bytes(b"ref: refs/heads/decoy\n")
    else:
        record_path = admin / "gitdir"
        decoy = _cr_sibling(wt / ".git")
        decoy.write_bytes(b"gitdir: decoy\n")
    raw = record_path.read_bytes()
    assert raw.endswith(b"\n") and not raw.endswith(b"\r\n")
    record_path.write_bytes(raw[:-1] + b"\r\n")
    git_dir = _absolute_git_path(wt, "--absolute-git-dir")
    git_common = _absolute_git_path(wt, "--git-common-dir")
    assert git_dir == admin
    doc = observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
    assert doc["status"] == "observed" and doc["reason"] is None
    assert doc["repository"]["common_dir"] == str(git_common)
    assert doc["repository"]["worktree_root"] == str(wt)
    assert doc["head"]["oid"] == literal_head(wt)
    assert os.fsdecode(b"\r") not in doc["repository"]["common_dir"]


@pytest.mark.parametrize("case", [
    "linked_worktree", "linked_worktree_relative_links", "separate_git_dir_checkout",
    "forged_pointer_to_main_gitdir", "forged_pointer_to_other_worktree", "backlink_trailing_space",
    "backlink_crlf", "backlink_two_newlines", "backlink_missing", "commondir_elsewhere",
    "dotgit_directory_commondir_elsewhere",
    pytest.param("dotgit_symlink", marks=pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges")),
    "pointer_to_missing_dir", "malformed_pointer",
])
def test_git_links_are_verified_before_identity_is_observed(target_home, tmp_path, case):
    from aegis_core.workspace.target import observe_target

    root, reason, common = _git_link_case(case, tmp_path, target_home)
    before = tree(tmp_path)
    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert tree(tmp_path) == before
    assert doc["binding"]["root"] == str(root)
    if reason is None:
        assert doc["status"] == "observed" and doc["reason"] is None
        assert doc["repository"] == {"status": "observed", "reason": None,
            "common_dir": str(common.resolve(strict=True)), "worktree_root": str(root)}
        assert doc["head"]["oid"] == literal_head(root)
    else:
        assert doc["status"] == "unknown" and doc["reason"] == reason
        assert doc["repository"] == {"status": "unknown", "reason": reason,
                                     "common_dir": None, "worktree_root": None}
        assert doc["head"] == {"status": "unknown", "reason": reason, "oid": None}


def test_oversized_git_link_files_are_unverified(target_home, tmp_path):
    from aegis_core.workspace.target import observe_target

    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    main.write("app.py", "x = 1\n")
    main.commit()
    wt = linked(main, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    # Git accepts the padded back-link path; the observer never reads past its bound.
    (admin / "gitdir").write_bytes(b"/" * 9000 + os.fsencode(wt / ".git")[1:] + b"\n")
    assert Path(os.fsdecode((admin / "gitdir").read_bytes()[:-1])).resolve() == wt / ".git"
    doc = observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
    assert doc["status"] == "unknown" and doc["reason"] == "unverified_git_link"
    assert doc["repository"]["common_dir"] is None and doc["head"]["oid"] is None


def test_unborn_branch_reports_repository_without_head(target_home, tmp_path):
    from aegis_core.workspace.target import observe_target

    repo = hg.Repo(tmp_path / "fresh", hg.Home(target_home))
    workspace(repo.root)
    root = repo.root.resolve()
    before = tree(tmp_path)
    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert doc["status"] == "unknown" and doc["reason"] == "head_unresolved"
    assert doc["repository"] == {"status": "observed", "reason": None,
        "common_dir": str(root / ".git"), "worktree_root": str(root)}
    assert doc["head"] == {"status": "unknown", "reason": "head_unresolved", "oid": None}
    assert tree(tmp_path) == before


def test_bound_workspace_outside_git_reports_no_repository(target_home, tmp_path, monkeypatch):
    from aegis_core.workspace.target import observe_target

    root = workspace(tmp_path / "plain").resolve()
    probe = subprocess.run(["git", "rev-parse", "--git-common-dir"], cwd=root, capture_output=True,
                           env={**os.environ, "GIT_CEILING_DIRECTORIES": str(root.parent)})
    assert probe.returncode != 0  # precondition: no repository encloses it
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(root.parent))
    before = tree(tmp_path)
    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert doc["status"] == "unknown" and doc["reason"] == "not_a_repository"
    assert doc["repository"] == {"status": "unknown", "reason": "not_a_repository",
                                 "common_dir": None, "worktree_root": None}
    assert doc["head"]["oid"] is None and doc["binding"]["root"] == str(root)
    assert tree(tmp_path) == before


# ── unrepresentable (non-UTF-8) text ─────────────────────────────────────────

BAD = "bad\udcff"  # a lone surrogate after surrogateescape decoding


@pytest.mark.parametrize("binding", [
    WorkspaceBinding("bound", Path("/ws") / BAD, "pin", "operator"),
    WorkspaceBinding("error", source="pin", reason="pin_missing", message="AEGIS_WORKSPACE is set to /" + BAD),
    WorkspaceBinding("hold", reason="ambiguous_host_roots", message="m", details=(("candidates", ["/a", "/" + BAD]),)),
    WorkspaceBinding("hold", reason="pin_conflicts_with_target", message="m", details=(("pin", "/" + BAD),)),
    WorkspaceBinding("unbound", reason="r" + BAD, message="m"),
], ids=["bound-root", "message", "detail-list-item", "detail-value", "reason"])
def test_unrepresentable_binding_text_fails_closed_without_probing(target_home, monkeypatch, binding):
    from aegis_core.workspace.target import encode_target, observe_target

    calls = []

    def unexpected(*args, **kwargs):
        calls.append(args)
        raise AssertionError("an unrepresentable binding must not start a Git observer")

    monkeypatch.setattr(gitsafe, "run", unexpected)
    doc = strict_document(encode_target(observe_target(binding)))
    assert calls == []
    assert doc["status"] == "error" and doc["reason"] == "path_unrepresentable"
    assert doc["binding"]["root"] is None and doc["binding"]["status"] == binding.status
    assert BAD not in str(doc) and "\\udc" not in encode_target(observe_target(binding))
    assert doc["repository"] == {"status": "unknown", "reason": "path_unrepresentable",
                                 "common_dir": None, "worktree_root": None}
    assert doc["head"]["oid"] is None and isinstance(doc["error"], str)


@pytest.mark.parametrize("field", ["common_dir", "worktree_root"])
def test_unrepresentable_repository_paths_become_unknown(target_home, field):
    from aegis_core.workspace.target import encode_target

    doc = {"schema": "aegis.target/v1", "status": "observed", "reason": None, "observed_at": "t",
           "binding": WorkspaceBinding("bound", Path("/ws"), "pin", "operator").as_dict(),
           "repository": {"status": "observed", "reason": None, "common_dir": "/ws/.git", "worktree_root": "/ws"},
           "head": {"status": "observed", "reason": None, "oid": "a" * 40}}
    doc["repository"][field] = "/" + BAD
    out = strict_document(encode_target(doc))
    assert out["status"] == "unknown" and out["reason"] == "path_unrepresentable"
    assert out["binding"]["root"] == "/ws"
    assert out["repository"] == {"status": "unknown", "reason": "path_unrepresentable",
                                 "common_dir": None, "worktree_root": None}
    assert out["head"] == {"status": "unknown", "reason": "path_unrepresentable", "oid": None}


def test_unrepresentable_error_text_is_replaced(target_home):
    from aegis_core.workspace.target import encode_target, target_error

    out = strict_document(encode_target(target_error("binding_error", "cannot resolve /" + BAD)))
    assert out["status"] == "error" and out["reason"] == "path_unrepresentable"
    assert out["binding"] is None and BAD not in out["error"]


def test_representable_non_ascii_text_is_kept(target_home):
    from aegis_core.workspace.target import encode_target, target_error

    message = "cannot resolve /wörk/\U0001f600"
    out = strict_document(encode_target(target_error("binding_error", message)))
    assert out["reason"] == "binding_error" and out["error"] == message


def non_utf8_dir(parent: Path, name: bytes) -> Path:
    if os.name == "nt":
        pytest.skip("Windows paths are UTF-16; undecodable byte names do not exist")
    path = os.path.join(os.fsencode(parent), name)
    try:
        os.mkdir(path)
    except OSError as exc:  # e.g. APFS rejects invalid UTF-8 names
        pytest.skip(f"filesystem refuses a non-UTF-8 name: {exc}")
    return Path(os.fsdecode(path))


def test_real_non_utf8_bound_root_is_an_error(target_home, tmp_path):
    from aegis_core.workspace.target import encode_target, observe_target

    root = workspace(non_utf8_dir(tmp_path, b"ws\xff"))
    hg.git(root, "init", "-q")
    wire = encode_target(observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator")))
    doc = strict_document(wire)
    assert doc["status"] == "error" and doc["reason"] == "path_unrepresentable"
    assert doc["binding"]["root"] is None and doc["repository"]["common_dir"] is None


def test_real_non_utf8_common_dir_is_unknown(target_home, tmp_path):
    from aegis_core.workspace.target import encode_target, observe_target

    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    admin = non_utf8_dir(tmp_path, b"admin\xff")
    admin.rmdir()
    main.git("init", "-q", "--separate-git-dir=" + str(admin))
    main.write("app.py", "x = 1\n")
    main.commit()
    wt = linked(main, tmp_path / "wt").root
    workspace(wt)
    wire = encode_target(observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator")))
    doc = strict_document(wire)
    assert doc["status"] == "unknown" and doc["reason"] == "path_unrepresentable"
    assert doc["binding"]["root"] == str(wt)
    assert doc["repository"] == {"status": "unknown", "reason": "path_unrepresentable",
                                 "common_dir": None, "worktree_root": None}
    assert doc["head"]["oid"] is None


# ── round 2: literal HEAD, the selecting marker, no-follow reads, decoding ──

def _counting_git(monkeypatch):

    real_run, calls = gitsafe.run, []

    def run(argv, *args, **kwargs):
        calls.append(argv)
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    return calls


@pytest.mark.parametrize("case", [
    "branch", "detached", "unborn", "unborn+refs/tags/HEAD", "unborn+refs/heads/HEAD",
    "unborn+refs/remotes/HEAD", "unborn+refs/HEAD", "unborn+refs/remotes/HEAD/HEAD",
    "unborn+refs/tags/refs/heads/unborn", "branch_to_annotated_tag",
])
def test_head_is_resolved_literally_without_dwim(target_home, tmp_path, monkeypatch, case):
    from aegis_core.workspace.target import observe_target

    repo = hg.Repo(tmp_path / "repo", hg.Home(target_home))
    repo.write("app.py", "x = 1\n")
    first = repo.commit("first")
    repo.write("app.py", "x = 2\n")
    second = repo.commit("second")
    expected = None
    if case == "branch":
        expected = second
    elif case == "detached":
        repo.git("checkout", "-q", "--detach", first)
        expected = first
    elif case.startswith("unborn"):
        repo.git("symbolic-ref", "HEAD", "refs/heads/unborn")
        if "+" in case:
            repo.git("update-ref", case.split("+", 1)[1], first)
            # The DWIM spelling the old observer used really does name a commit here.
            dwim = hg.run_git(repo.root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False)
            assert dwim.stdout.strip() == first or case == "unborn+refs/tags/refs/heads/unborn"
    elif case == "branch_to_annotated_tag":
        repo.git("tag", "-a", "-m", "t", "annotated", first)
        tag = repo.git("rev-parse", "refs/tags/annotated")
        # update-ref refuses a non-commit branch tip; a loose ref file is how one arrives.
        (repo.root / ".git" / "refs" / "heads" / "main").write_text(tag + "\n", encoding="ascii")
        if repo.git("show-ref", "--verify", "--hash", "refs/heads/main") != tag:
            pytest.skip("this Git does not store branches as loose ref files")
    root = repo.root.resolve()
    assert literal_head(root) == expected or case == "branch_to_annotated_tag"
    before = tree(tmp_path)
    calls = _counting_git(monkeypatch)
    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert len(calls) <= 5  # the documented per-observation Git bound
    assert tree(tmp_path) == before
    assert doc["repository"]["status"] == "observed"
    if expected is None:
        assert doc["status"] == "unknown" and doc["reason"] == "head_unresolved"
        assert doc["head"] == {"status": "unknown", "reason": "head_unresolved", "oid": None}
    else:
        assert doc["status"] == "observed"
        assert doc["head"] == {"status": "observed", "reason": None, "oid": expected}


@pytest.mark.parametrize("reply,reason", [
    (b"refs/heads/main", "head_unresolved"), (b"main\n", "head_unresolved"),
    (b"refs/heads/main\nrefs/heads/x\n", "head_unresolved"), (b"refs/heads/\0main\n", "head_unresolved"),
], ids=["missing-lf", "not-under-refs", "two-lines", "nul"])
def test_malformed_symbolic_head_answers_are_unknown(target_repo, monkeypatch, reply, reason):
    from aegis_core.workspace.target import observe_target

    real_run, hits = gitsafe.run, []

    def run(argv, *args, **kwargs):
        if "symbolic-ref" in argv:
            hits.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=reply, stderr=b"")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert len(hits) == 1
    assert doc["head"] == {"status": "unknown", "reason": reason, "oid": None}


def _marker_case(case, tmp_path, target_home):
    """(bound root, expected reason): None means observed."""
    repo = hg.Repo(tmp_path / "repo", hg.Home(target_home))
    repo.write("sub/deep/app.py", "x = 1\n")
    repo.write("ws/app.py", "x = 1\n")
    repo.commit()
    root = repo.root
    if case == "subdirectory_of_plain_repo":
        return root / "sub", None
    if case == "core_worktree_is_the_repo_itself":
        repo.git("config", "core.worktree", str(root))
        return root / "sub", None
    if case == "forged_sub_pointer_with_core_worktree":
        (root / "sub" / ".git").write_bytes(b"gitdir: " + os.fsencode(root / ".git") + b"\n")
        repo.git("config", "core.worktree", str(root))
        return root / "sub", "unverified_git_link"
    if case == "empty_dotgit_directory_ignored_by_git":
        (root / "ws" / ".git").mkdir()
        return root / "ws", "unverified_git_link"
    if case == "partial_dotgit_directory_ignored_by_git":
        (root / "ws" / ".git").mkdir()
        (root / "ws" / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main\n")
        return root / "ws", "unverified_git_link"
    if case == "symlinked_ancestor_marker":
        real = tmp_path / "real-gitdir"
        (root / ".git").rename(real)
        os.symlink(real, root / ".git")
        return root / "sub", "unverified_git_link"
    if case == "ancestor_core_worktree_is_the_parent":
        repo.git("config", "core.worktree", str(tmp_path))
        return root / "sub" / "deep", "unverified_git_link"
    if case == "core_worktree_is_a_subdirectory":
        repo.git("config", "core.worktree", str(root / "sub"))
        return root / "sub" / "deep", "unverified_git_link"
    raise AssertionError(case)


@pytest.mark.parametrize("case", [
    "subdirectory_of_plain_repo", "core_worktree_is_the_repo_itself", "forged_sub_pointer_with_core_worktree",
    "empty_dotgit_directory_ignored_by_git", "partial_dotgit_directory_ignored_by_git",
    pytest.param("symlinked_ancestor_marker", marks=pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges")),
    "ancestor_core_worktree_is_the_parent", "core_worktree_is_a_subdirectory",
])
def test_the_marker_that_selects_the_root_is_the_one_verified(target_home, tmp_path, case):
    from aegis_core.workspace.target import observe_target

    root, reason = _marker_case(case, tmp_path, target_home)
    root = root.resolve()
    before = tree(tmp_path)
    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert tree(tmp_path) == before
    if reason is None:
        repo_root = (tmp_path / "repo").resolve()
        assert doc["status"] == "observed"
        assert doc["repository"] == {"status": "observed", "reason": None,
            "common_dir": str(repo_root / ".git"), "worktree_root": str(repo_root)}
        assert doc["head"]["oid"] == literal_head(repo_root)
    else:
        assert doc["status"] == "unknown" and doc["reason"] == reason
        assert doc["repository"]["common_dir"] is None and doc["head"]["oid"] is None


def _linked_with_symlinked(kind, tmp_path, target_home):
    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    main.write("app.py", "x = 1\n")
    main.commit()
    wt = linked(main, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    victim = admin / "gitdir" if kind == "backlink" else wt / ".git"
    moved = tmp_path / ("moved-" + kind)
    victim.rename(moved)
    os.symlink(moved, victim)
    return wt


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges")
@pytest.mark.parametrize("kind", ["backlink", "dotgit_file"])
def test_symlinked_link_files_are_unverified(target_home, tmp_path, kind):

    wt = _linked_with_symlinked(kind, tmp_path, target_home)
    doc = target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
    assert doc["status"] == "unknown" and doc["reason"] == "unverified_git_link"
    assert doc["head"]["oid"] is None


def test_link_file_swapped_after_lstat_is_unverified(target_home, tmp_path, monkeypatch):

    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    main.write("app.py", "x = 1\n")
    main.commit()
    wt = linked(main, tmp_path / "wt").root
    decoy = tmp_path / "decoy"
    decoy.write_bytes(b"x\n")
    real_lstat, swapped = target._lstat, []

    def lstat(path):
        if os.fspath(path).endswith(os.sep + "gitdir"):
            swapped.append(path)
            return real_lstat(decoy)  # a different regular file than the one opened
        return real_lstat(path)

    control = target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
    assert control["status"] == "observed"
    monkeypatch.setattr(target, "_lstat", lstat)
    doc = target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
    assert swapped and doc["reason"] == "unverified_git_link" and doc["head"]["oid"] is None


@pytest.mark.parametrize("marker,reason", [
    (b"/.git", "path_unrepresentable"),          # Git's common-dir answer
    (b"wt", "path_unrepresentable"),             # Git's toplevel answer (and later reads)
    (b"gitdir: ", "unverified_git_link"),        # never: the prefix is stripped before decoding
    (b"worktrees", "unverified_git_link"),       # the .git pointer of the linked worktree
    (b"/wt/.git", "unverified_git_link"),        # the admin back-link
    (b"refs/heads/", "head_unresolved"),         # the symbolic HEAD
], ids=["common-dir", "toplevel", "prefix", "pointer", "backlink", "symbolic-head"])
def test_undecodable_bytes_are_unrepresentable_not_a_failure(target_home, tmp_path, monkeypatch, marker, reason):

    main = hg.Repo(tmp_path / "main", hg.Home(target_home))
    main.write("app.py", "x = 1\n")
    main.commit()
    wt = linked(main, tmp_path / "wt").root
    real, hits = target._fsdecode, []

    def decode(raw):
        if marker in raw and (marker != b"wt" or not raw.endswith(b".git")):
            hits.append(raw)
            raise UnicodeDecodeError("utf-8", raw, 0, 1, "as on Windows")
        return real(raw)

    monkeypatch.setattr(target, "_fsdecode", decode)
    # The linked worktree's HEAD is detached; the branch checkout has a symbolic HEAD.
    root = main.root.resolve() if marker == b"refs/heads/" else wt
    doc = target.observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    if marker == b"gitdir: ":
        assert hits == [] and doc["status"] == "observed"  # control: the prefix never reaches the decoder
        return
    assert hits  # the injected decode failure was met
    assert doc["status"] == "unknown" and doc["reason"] == reason
    assert doc["head"]["oid"] is None


@pytest.mark.parametrize("case,reason", [
    ("sibling_toplevel", "root_mismatch"), ("missing_lf", "invalid_git_identity"),
    ("two_paths", "unverified_git_link"),
])
def test_root_mismatch_is_distinct_from_malformed_identity(target_repo, tmp_path, monkeypatch, case, reason):
    from aegis_core.workspace.target import observe_target

    sibling = tmp_path / "sibling"
    sibling.mkdir()
    replies = {"sibling_toplevel": os.fsencode(sibling) + b"\n",
               "missing_lf": os.fsencode(target_repo.root),
               "two_paths": os.fsencode(target_repo.root) + b"\n" + os.fsencode(sibling) + b"\n"}
    real_run, hits = gitsafe.run, []

    def run(argv, *args, **kwargs):
        if "--show-toplevel" in argv:
            hits.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=replies[case], stderr=b"")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert len(hits) == 1
    assert doc["status"] == "unknown" and doc["reason"] == reason
    assert doc["repository"]["worktree_root"] is None and doc["head"]["oid"] is None


@pytest.mark.parametrize("site", ["main-head", "linked-head", "commondir", "admin-directory", "worktrees-directory"])
def test_metadata_symlinks_are_refused_and_retry_succeeds(target_repo, tmp_path, site):
    from aegis_core.workspace.target import observe_target

    if os.name == "nt":
        pytest.skip("symlinks require privileges")
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    sites = {"main-head": target_repo.root / ".git" / "HEAD", "linked-head": admin / "HEAD",
             "commondir": admin / "commondir", "admin-directory": admin,
             "worktrees-directory": admin.parent}
    victim = sites[site]
    root = target_repo.root if site == "main-head" else wt
    binding = WorkspaceBinding("bound", root, "cli_workspace", "operator")
    assert observe_target(binding)["status"] == "observed"
    moved = tmp_path / "moved"
    victim.rename(moved)
    try:
        victim.symlink_to(moved, target_is_directory=moved.is_dir())
        doc = observe_target(binding)
        assert doc["reason"] == "unverified_git_link"
        assert doc["head"]["oid"] is None and doc["repository"]["common_dir"] is None
    finally:
        victim.unlink()
        moved.rename(victim)
    assert observe_target(binding)["status"] == "observed"


@pytest.mark.parametrize("site", ["main-head", "linked-head", "commondir", "dotgit", "backlink"])
def test_directory_reparse_attributes_are_refused(target_repo, tmp_path, monkeypatch, site):
    from types import SimpleNamespace

    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    victim = {"main-head": target_repo.root / ".git" / "HEAD", "linked-head": admin / "HEAD",
              "commondir": admin / "commondir", "dotgit": target_repo.root / ".git",
              "backlink": admin / "gitdir"}[site]
    real_lstat = target._lstat

    def lstat(path):
        info = real_lstat(path)
        if Path(path) == victim:
            return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_file_attributes=0x400)
        return info

    monkeypatch.setattr(target, "_lstat", lstat)
    root = target_repo.root if site in ("main-head", "dotgit") else wt
    doc = target.observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert doc["reason"] == "unverified_git_link" and doc["head"]["oid"] is None


def test_all_git_calls_have_bounded_capture_and_a_shared_budget(target_repo, monkeypatch):
    from aegis_core import pathlookup
    from aegis_core.workspace.target import observe_target

    real_run, budgets = gitsafe.run, []

    def run(args, root, **kwargs):
        assert gitsafe.custody_active()
        assert pathlookup.ordinary_root.get() == str(target_repo.root)
        budgets.append(kwargs["timeout"])
        return real_run(args, root, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    token = pathlookup.ordinary_root.set(str(target_repo.root))
    try:
        doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
        assert pathlookup.ordinary_root.get() == str(target_repo.root)
    finally:
        pathlookup.ordinary_root.reset(token)
    assert doc["status"] == "observed"
    assert len(budgets) == 5 and all(0 < later < earlier for earlier, later in zip(budgets, budgets[1:]))


@pytest.mark.parametrize("stage", ["--git-common-dir", "--show-toplevel", "symbolic-ref", "show-ref", "--quiet"])
@pytest.mark.parametrize("code,reason", [("git_output_limit", "diagnostic_limit_exceeded"),
                                       ("git_timeout", "git_timeout"), ("git_failed", "git_unavailable")])
def test_typed_git_failures_and_retry(target_repo, monkeypatch, stage, code, reason):
    from aegis_core.workspace.target import observe_target

    real_run, hits = gitsafe.run, []

    def run(args, root, **kwargs):
        if stage in args:
            hits.append(args)
            raise gitsafe.GitError("secret input must never be echoed", code=code)
        return real_run(args, root, **kwargs)

    binding = WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator")
    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(binding)
    assert len(hits) == 1 and doc["reason"] == reason
    assert doc["head"]["oid"] is None and "secret input" not in str(doc)
    monkeypatch.setattr(gitsafe, "run", real_run)
    assert observe_target(binding)["status"] == "observed"


def test_unsafe_repository_is_distinct_and_stderr_is_not_echoed(target_repo, monkeypatch):
    from aegis_core.workspace.target import observe_target

    def run(args, root, **kwargs):
        return subprocess.CompletedProcess(args, 128, b"", b"fatal: detected dubious ownership in repository at 'secret'\n")

    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert doc["reason"] == "unsafe_repository" and "secret" not in str(doc)


def test_unsupported_descriptor_platform_refuses_without_git(tmp_path, monkeypatch):
    from aegis_core.workspace.target import observe_target

    def unexpected(*args, **kwargs):
        pytest.fail("unsupported platform must not start Git")

    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    monkeypatch.setattr(gitsafe, "run", unexpected)
    doc = observe_target(WorkspaceBinding("bound", tmp_path.resolve(), "cli_workspace", "operator"))
    assert doc["reason"] == "unsupported_platform" and doc["head"]["oid"] is None


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("stage", ["--git-common-dir", "--show-toplevel", "symbolic-ref", "show-ref", "--quiet"])
def test_real_git_capture_overflow_at_every_stage(target_repo, monkeypatch, stream, stage):
    from aegis_core.workspace.target import observe_target

    payload = "x" * 32768
    target_repo.git("config", "target.payload", payload)
    real_run, hits = gitsafe.run, []

    def run(args, root, **kwargs):
        if stage in args:
            hits.append(args)
            command = (["config", "--get", "target.payload"] if stream == "stdout" else
                       [*(["-c", "core.fsync=invalid"] * 200), "rev-parse", "--git-common-dir"])
            return real_run(command, root, **kwargs)
        return real_run(args, root, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    doc = observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert len(hits) == 1
    assert doc["status"] == "overflow" and doc["reason"] == "diagnostic_limit_exceeded"
    assert doc["binding"] is None and payload not in str(doc)


def test_deadline_expiring_during_a_query_stops_subsequent_queries(target_repo, monkeypatch):

    clock, calls, real_run = [100.0], [], gitsafe.run

    def run(args, root, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 10.0
        result = real_run(args, root, **kwargs)
        clock[0] = 111.0
        return result

    monkeypatch.setattr(target, "monotonic", lambda: clock[0])
    monkeypatch.setattr(gitsafe, "run", run)
    doc = target.observe_target(WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator"))
    assert len(calls) == 1 and doc["reason"] == "git_timeout" and doc["head"]["oid"] is None


@pytest.mark.parametrize("component", ["file", "parent", "ancestor"])
def test_concurrent_link_swap_at_metadata_open_is_refused(target_repo, tmp_path, monkeypatch, component):
    from contextlib import contextmanager

    if os.name == "nt":
        pytest.skip("symlinks require privileges")
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    victim = {"file": admin / "commondir", "parent": admin, "ancestor": admin.parent}[component]
    moved = tmp_path / "moved"
    real_descriptor, hits = target._path_descriptor, []

    @contextmanager
    def descriptor(path, *, directory):
        if Path(path) == admin / "commondir" and not directory and not hits:
            hits.append(path)
            victim.rename(moved)
            victim.symlink_to(moved, target_is_directory=moved.is_dir())
        with real_descriptor(path, directory=directory) as handle:
            yield handle

    monkeypatch.setattr(target, "_path_descriptor", descriptor)
    try:
        doc = target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
        assert len(hits) == 1 and doc["reason"] == "unverified_git_link"
        assert doc["head"]["oid"] is None
    finally:
        victim.unlink()
        moved.rename(victim)
    assert target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))["status"] == "observed"


def test_bounded_metadata_read_survives_parent_rename_without_following_replacement(target_repo, tmp_path, monkeypatch):
    from contextlib import contextmanager

    if os.name == "nt":
        pytest.skip("symlinks require privileges")
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    moved, replacement = tmp_path / "moved", tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "commondir").write_bytes(b"do-not-trust\n")
    real_descriptor, hits = target._path_descriptor, []

    @contextmanager
    def descriptor(path, *, directory):
        with real_descriptor(path, directory=directory) as handle:
            if Path(path) == admin / "commondir" and not directory and not hits:
                hits.append(path)
                admin.rename(moved)
                admin.symlink_to(replacement, target_is_directory=True)
            yield handle

    monkeypatch.setattr(target, "_path_descriptor", descriptor)
    try:
        doc = target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))
        assert len(hits) == 1 and doc["reason"] == "unverified_git_link"
        assert doc["head"]["oid"] is None and "do-not-trust" not in str(doc)
    finally:
        admin.unlink()
        moved.rename(admin)
    assert target.observe_target(WorkspaceBinding("bound", wt, "cli_workspace", "operator"))["status"] == "observed"


@pytest.mark.parametrize("value", ["x" * 1000000, ["x" * 2200] * 32], ids=["field", "aggregate"])
def test_encoder_limits_precede_recursive_cleaning(monkeypatch, value):

    doc = target.target_error("binding_error", "m")
    doc["extra"] = value

    def unexpected(*args, **kwargs):
        pytest.fail("over-limit input must be refused before copying or cleaning")

    monkeypatch.setattr(target, "_clean", unexpected)
    import json
    assert json.loads(target.encode_target(doc))["status"] == "overflow"


@pytest.mark.parametrize("root", [Path("relative"), "string-root", Path("/a/../b"), Path("/bad\0root")])
def test_unresolved_bound_root_is_a_typed_refusal(root):
    from aegis_core.workspace.target import observe_target

    doc = observe_target(WorkspaceBinding("bound", root, "cli_workspace", "operator"))
    assert doc["reason"] == "server_binding_required" and doc["binding"] is None


@pytest.mark.parametrize("case", ["missing", "symlink", "regular", "valid-parent", "same-inode"])
def test_original_backlink_components_and_file_identity(target_repo, tmp_path, case):
    if case == "symlink" and os.name == "nt":
        pytest.skip("symlinks require privileges")
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    backlink = admin / "gitdir"
    original = backlink.read_bytes()
    component = wt / "component"
    if case == "symlink":
        component.symlink_to(tmp_path, target_is_directory=True)
    elif case == "regular":
        component.write_bytes(b"not a directory")
    elif case == "valid-parent":
        component.mkdir()
    elif case == "same-inode":
        os.link(wt / ".git", component)
    spelling = os.fsencode(component) + (b"\n" if case == "same-inode" else b"/../.git\n")
    backlink.write_bytes(spelling)
    binding = WorkspaceBinding("bound", wt, "cli_workspace", "operator")
    try:
        doc = target.observe_target(binding)
        if case in ("valid-parent", "same-inode"):
            assert doc["status"] == "observed"
        else:
            assert doc["reason"] == "unverified_git_link"
            assert doc["repository"]["common_dir"] is None and doc["head"]["oid"] is None
    finally:
        backlink.write_bytes(original)
    assert target.observe_target(binding)["status"] == "observed"


@pytest.mark.parametrize("site", ["dotgit", "commondir", "gitdir", "head"])
def test_read_descriptor_must_match_the_pre_read_identity(target_repo, tmp_path, monkeypatch, site):
    from contextlib import contextmanager

    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    victim = {"dotgit": wt / ".git", "commondir": admin / "commondir",
              "gitdir": admin / "gitdir", "head": admin / "HEAD"}[site]
    saved, decoy = tmp_path / "saved", tmp_path / "decoy"
    decoy.write_bytes(victim.read_bytes())
    real_descriptor, hits = target._path_descriptor, []

    @contextmanager
    def descriptor(path, *, directory):
        if Path(path) == victim and not directory:
            hits.append(path)
            victim.rename(saved)
            decoy.rename(victim)
            try:
                with real_descriptor(path, directory=directory) as handle:
                    yield handle
            finally:
                victim.rename(decoy)
                saved.rename(victim)
        else:
            with real_descriptor(path, directory=directory) as handle:
                yield handle

    monkeypatch.setattr(target, "_path_descriptor", descriptor)
    binding = WorkspaceBinding("bound", wt, "cli_workspace", "operator")
    doc = target.observe_target(binding)
    assert hits and doc["reason"] == "unverified_git_link" and doc["head"]["oid"] is None
    monkeypatch.setattr(target, "_path_descriptor", real_descriptor)
    assert target.observe_target(binding)["status"] == "observed"


@pytest.mark.parametrize("namespaced", [True, False], ids=["different-ref", "missing-ref"])
def test_ambient_namespace_cannot_select_the_observed_head(target_repo, monkeypatch, namespaced):
    other = target_repo.head()
    target_repo.write("app.py", "second = True\n")
    expected = target_repo.commit("second")
    if namespaced:
        target_repo.git("update-ref", "refs/namespaces/hidden/refs/heads/main", other)
    monkeypatch.setenv("GIT_NAMESPACE", "hidden")
    # Some Git versions ignore namespaces for show-ref. Check the actual child
    # environment through a test-owned POSIX alias as well as the resulting oid.
    real_run, namespaces = gitsafe.run, []
    command = ["-c", "alias.target-namespace=!printf '%s' \"${GIT_NAMESPACE-UNSET}\"", "target-namespace"]
    assert real_run(command, target_repo.root).stdout == b"hidden"

    def run(args, root, **kwargs):
        namespaces.append(real_run(command, root, **kwargs).stdout)
        return real_run(args, root, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    binding = WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator")
    doc = target.observe_target(binding)
    assert doc["status"] == "observed" and doc["head"]["oid"] == expected
    assert namespaces and all(value == b"" for value in namespaces)
    monkeypatch.delenv("GIT_NAMESPACE")
    assert target.observe_target(binding)["head"]["oid"] == expected


def test_failed_toplevel_never_exposes_repository_or_head(target_repo, monkeypatch):
    real_run, heads = gitsafe.run, []

    def run(args, root, **kwargs):
        if args[0] in ("symbolic-ref", "show-ref") or "--quiet" in args:
            heads.append(args)
        return real_run(args, root, **kwargs)

    binding = WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator")
    target_repo.git("config", "core.bare", "true")
    monkeypatch.setattr(gitsafe, "run", run)
    doc = target.observe_target(binding)
    assert doc["status"] == "unknown" and doc["reason"] == "worktree_unavailable"
    assert doc["repository"] == {"status": "unknown", "reason": "worktree_unavailable",
                                 "common_dir": None, "worktree_root": None}
    assert doc["head"] == {"status": "unknown", "reason": "worktree_unavailable", "oid": None}
    assert heads == []
    target_repo.git("config", "core.bare", "false")
    assert target.observe_target(binding)["status"] == "observed"


@pytest.mark.parametrize("site", ["common-answer", "toplevel-answer", "pointer", "commondir"])
@pytest.mark.parametrize("component", ["missing", "symlink", "regular", "directory", "reparse"])
def test_every_original_repository_path_is_walked_before_collapse(target_repo, tmp_path, monkeypatch, site, component):
    from types import SimpleNamespace

    if component == "symlink" and os.name == "nt":
        pytest.skip("symlinks require privileges")
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    common = target_repo.root / ".git"
    destination = {"common-answer": common, "toplevel-answer": wt,
                   "pointer": admin, "commondir": common}[site]
    child = destination / "component"
    if component in ("directory", "reparse"):
        child.mkdir()
    elif component == "symlink":
        child.symlink_to(tmp_path, target_is_directory=True)
    elif component == "regular":
        child.write_bytes(b"file")
    real_fstat = target._fstat
    if component == "reparse":
        identity = child.stat().st_ino

        def fstat(fd):
            info = real_fstat(fd)
            if info.st_ino == identity:
                return SimpleNamespace(st_mode=info.st_mode, st_dev=info.st_dev,
                                       st_ino=info.st_ino, st_file_attributes=0x400)
            return info

        monkeypatch.setattr(target, "_fstat", fstat)
    spelling = os.fsencode(child) + b"/..\n"
    victim, original = None, None
    if site in ("pointer", "commondir"):
        victim = wt / ".git" if site == "pointer" else admin / "commondir"
        original = victim.read_bytes()
        victim.write_bytes((b"gitdir: " if site == "pointer" else b"") + spelling)
    real_run = gitsafe.run

    def run(args, root, **kwargs):
        flag = "--git-common-dir" if site == "common-answer" else "--show-toplevel"
        if site in ("common-answer", "toplevel-answer") and flag in args:
            return subprocess.CompletedProcess(args, 0, spelling, b"")
        return real_run(args, root, **kwargs)

    monkeypatch.setattr(gitsafe, "run", run)
    binding = WorkspaceBinding("bound", wt, "cli_workspace", "operator")
    try:
        doc = target.observe_target(binding)
        if component == "directory":
            assert doc["status"] == "observed"
        else:
            assert doc["reason"] == "unverified_git_link"
            assert doc["repository"]["common_dir"] is None and doc["head"]["oid"] is None
    finally:
        if victim is not None:
            victim.write_bytes(original)
    monkeypatch.setattr(gitsafe, "run", real_run)
    monkeypatch.setattr(target, "_fstat", real_fstat)
    assert target.observe_target(binding)["status"] == "observed"


@pytest.mark.parametrize("fault", ["open", "fstat", "read", "size", "growth"])
def test_metadata_failure_closes_every_opened_descriptor(target_repo, monkeypatch, fault):
    import errno

    opened, leaves, reads = [], [], []
    real_directory, real_leaf = target._open_directory, target._open_leaf
    real_fstat, real_read = target._fstat, target._read
    victim = target_repo.root / ".git" / "HEAD"
    original = victim.read_bytes()
    if fault == "size":
        victim.write_bytes(b"x" * 8193)

    def directory(parent, name):
        fd = real_directory(parent, name)
        opened.append(fd)
        return fd

    def leaf(parent, name):
        if fault == "open":
            raise OSError(errno.EACCES, "injected metadata open refusal")
        fd = real_leaf(parent, name)
        opened.append(fd)
        leaves.append(fd)
        return fd

    def fstat(fd):
        if fault == "fstat" and fd in leaves:
            raise OSError(errno.EIO, "injected descriptor stat refusal")
        return real_fstat(fd)

    def read(fd, limit):
        reads.append(limit)
        if fault == "read":
            raise OSError(errno.EIO, "injected metadata read refusal")
        if fault == "growth" and len(reads) == 1:
            victim.write_bytes(b"x" * 8193)
        return real_read(fd, limit)

    monkeypatch.setattr(target, "_open_directory", directory)
    monkeypatch.setattr(target, "_open_leaf", leaf)
    monkeypatch.setattr(target, "_fstat", fstat)
    monkeypatch.setattr(target, "_read", read)
    binding = WorkspaceBinding("bound", target_repo.root, "cli_workspace", "operator")
    try:
        doc = target.observe_target(binding)
        assert doc["reason"] == "unverified_git_link" and doc["head"]["oid"] is None
        assert "injected" not in str(doc) and opened
        if fault in ("size", "open", "fstat"):
            assert reads == []
        for fd in set(opened):
            with pytest.raises(OSError) as error:
                os.fstat(fd)
            assert error.value.errno == errno.EBADF
    finally:
        victim.write_bytes(original)
    monkeypatch.setattr(target, "_open_directory", real_directory)
    monkeypatch.setattr(target, "_open_leaf", real_leaf)
    monkeypatch.setattr(target, "_fstat", real_fstat)
    monkeypatch.setattr(target, "_read", real_read)
    assert target.observe_target(binding)["status"] == "observed"


def test_dotdot_checks_the_physical_parent_after_concurrent_reparenting(target_repo, tmp_path, monkeypatch):
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    component, elsewhere = wt / "component", tmp_path / "elsewhere"
    component.mkdir()
    elsewhere.mkdir()
    moved = elsewhere / "component"
    backlink = admin / "gitdir"
    backlink.write_bytes(os.fsencode(component) + b"/../.git\n")
    real_directory, real_leaf, hits = target._open_directory, target._open_leaf, []
    parent_id = (wt.stat().st_dev, wt.stat().st_ino)

    def directory(parent, name):
        fd = real_directory(parent, name)
        if name == "component" and not hits:
            hits.append(name)
            component.rename(moved)
        return fd

    def leaf(parent, name):
        fd = real_leaf(parent, name)
        info = os.fstat(parent)
        if name == ".git" and (info.st_dev, info.st_ino) == parent_id and moved.exists():
            moved.rename(component)
        return fd

    monkeypatch.setattr(target, "_open_directory", directory)
    monkeypatch.setattr(target, "_open_leaf", leaf)
    binding = WorkspaceBinding("bound", wt, "cli_workspace", "operator")
    try:
        doc = target.observe_target(binding)
        assert hits and doc["reason"] == "unverified_git_link" and doc["head"]["oid"] is None
    finally:
        if moved.exists():
            moved.rename(component)
    assert target.observe_target(binding)["status"] == "observed"


def test_admin_disappearing_after_component_validation_is_unverified(target_repo, tmp_path, monkeypatch):
    wt = linked(target_repo, tmp_path / "wt").root
    admin = Path(hg.git(wt, "rev-parse", "--absolute-git-dir"))
    moved = tmp_path / "moved-admin"
    real_canonical, hits = target._canonical, []

    def canonical(path):
        result = real_canonical(path)
        if result == admin and not hits:
            hits.append(path)
            admin.rename(moved)
        return result

    monkeypatch.setattr(target, "_canonical", canonical)
    binding = WorkspaceBinding("bound", wt, "cli_workspace", "operator")
    try:
        doc = target.observe_target(binding)
        assert hits and doc["reason"] == "unverified_git_link" and doc["head"]["oid"] is None
    finally:
        if moved.exists():
            moved.rename(admin)
    assert target.observe_target(binding)["status"] == "observed"
