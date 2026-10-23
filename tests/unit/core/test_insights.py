"""Unit tests for aegis_core.insights edge cases, security boundaries, and clustering."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from aegis_core import insights as core_insights
from aegis_core.errors import PathTraversalError
from aegis_core.insights import (
    KEY_SIZE,
    add_insight,
    capture_suggestion,
    create_link_key,
    dirty_paths,
    has_correction_cue,
    host_capture_status,
    insight_workspace_id,
    insights_path,
    measure_recurrence,
    read_insight_rows,
    read_link_key,
    record_decision,
    record_hook_prompt,
    redact_insight_text,
    review_insights,
    session_hs,
    write_proposal,
)


def _make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "T"], check=True)
    (path / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    (path / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (path / "app.py").write_text("a = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "init"], check=True)
    return path


def test_link_key_refuses_symlinks_and_corrupt_sizes(tmp_path: Path):
    home = tmp_path / "home"
    aegis = home / ".aegis"
    aegis.mkdir(parents=True)
    evil = tmp_path / "evil.key"
    evil.write_bytes(b"x" * KEY_SIZE)
    (aegis / "link.key").symlink_to(evil)

    with pytest.raises(PathTraversalError):
        create_link_key(home)
    assert read_link_key(home) is None

    (aegis / "link.key").unlink()
    (aegis / "link.key").write_bytes(b"short")
    with pytest.raises(ValueError, match="corrupt"):
        create_link_key(home)
    assert read_link_key(home) is None


def test_session_hs_rejects_invalid_inputs(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    create_link_key(home)
    key = read_link_key(home)
    assert key is not None

    assert session_hs("", "valid-id", key) is None
    assert session_hs("claude-code", "", key) is None
    assert session_hs("claude-code", "x" * 129, key) is None
    assert session_hs("claude-code", "bad\x00id", key) is None
    assert session_hs("claude-code", "valid-id", b"short") is None


def test_redaction_truncation_never_leaves_partial_redacted_tag():
    prefix = "A" * 292
    secret = "".join(["ghp_", "1234567890abcdefghijklmnopqrstuvwxyzABCD"])
    out = redact_insight_text(f"{prefix} {secret}", max_len=300)
    assert len(out) <= 300
    assert "".join(["gh", "p_"]) not in out
    assert not out.endswith("[REDACTED")


def test_matches_proposal_and_noise_decision_filtering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _make_repo(tmp_path / "repo")

    seed = add_insight(repo, "Hung child processes stalled the nightly job", paths=["app.py"], kind="reliability",
                       home=home)
    write_proposal(
        repo,
        proposal_id="trap-timeout-required",
        insight_ids=[seed["id"]],
        summary_bullets=["Always pass an explicit timeout parameter to subprocess and network requests."],
        home=home,
    )
    record_decision(repo, decision="noise", insight_ids=[seed["id"]], home=home)

    ins1 = add_insight(
        repo,
        "Stop calling subprocess or network requests without an explicit timeout parameter in app.py",
        paths=["app.py"],
        home=home,
    )
    ins_noise = add_insight(
        repo,
        "No, don't add trailing whitespace in unrelated scratch notes",
        paths=["app.py"],
        home=home,
    )

    record_decision(
        repo,
        decision="noise",
        insight_ids=[ins_noise["id"]],
        home=home,
    )

    rev = review_insights(repo, home=home)
    reviewed_ids = [e["id"] for e in rev["insights"] + rev["suppressed"]]
    assert ins_noise["id"] not in reviewed_ids
    assert ins1["id"] in reviewed_ids
    prop_matches = [e for e in rev["insights"] if e["match"]["status"] == "matches_proposal"]
    assert len(prop_matches) == 1
    assert prop_matches[0]["match"]["rule"] == "trap-timeout-required"


def test_hook_counters_only_mode_records_heartbeat_without_excerpt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _make_repo(tmp_path / "repo")

    res = record_hook_prompt(
        "claude-code",
        {"prompt": "No, stop breaking the build!", "session_id": "s-counters-only", "cwd": str(repo)},
        excerpts=False,
        home=home,
    )
    assert res["event"] == "heartbeat"
    assert res["cue"] is True

    rows = read_insight_rows(repo, home=home)
    assert len(rows) == 1
    assert rows[0]["event"] == "heartbeat"
    assert "text" not in rows[0]


def _neighbours_of(review: dict, insight_id: str) -> list:
    (entry,) = [e for e in review["insights"] if e["id"] == insight_id]
    return entry["neighbours"]


def test_tfidf_neighbours_and_dirty_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = _make_repo(tmp_path / "repo")
    assert dirty_paths(repo) == []
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")
    (repo / "new_file.py").write_text("b = 3\n", encoding="utf-8")
    assert dirty_paths(repo) == ["app.py", "new_file.py"]

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    texts = ("validate path confinement before deletion", "validate path confinement before deleting",
             "configure oauth2 bearer token refresh")
    same, near, other = (add_insight(repo, t, paths=["app.py"], home=home)["id"] for t in texts)
    (only,) = _neighbours_of(review_insights(repo, home=home), same)  # no shared term: not a neighbour
    assert only["id"] == near and only["similarity"] > 0.3
    assert _neighbours_of(review_insights(repo, home=home), other) == []


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
                   cwd=str(cwd), check=True, capture_output=True)


def _stat_dirty(path: Path) -> None:
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))


def test_dirty_paths_never_runs_a_submodule_clean_filter(tmp_path: Path):
    # R-evidence-43: the submodule's own config must not choose a program dirty_paths runs.
    sub_src = tmp_path / "subsrc"
    sub_src.mkdir()
    _git(sub_src, "init", "-q")
    (sub_src / "f.txt").write_text("data\n", encoding="utf-8")
    _git(sub_src, "add", ".")
    _git(sub_src, "commit", "-q", "-m", "sub")
    repo = _make_repo(tmp_path / "repo")
    _git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub_src), "sub")
    _git(repo, "commit", "-q", "-m", "add sub")
    marker = tmp_path / "marker"
    script = tmp_path / "filt.py"
    script.write_text(
        f"import sys\nopen({str(marker)!r}, 'w').close()\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    modules = repo / ".git" / "modules" / "sub"
    _git(repo, "config", "-f", str(modules / "config"), "filter.evil.clean",
         f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}"')
    (modules / "info").mkdir(exist_ok=True)
    (modules / "info" / "attributes").write_text("* filter=evil\n", encoding="utf-8")
    _stat_dirty(repo / "sub" / "f.txt")
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")

    assert dirty_paths(repo) == ["app.py"]
    assert not marker.exists()


def test_dirty_paths_skips_deleted_touched_and_state_files(tmp_path: Path):
    repo = _make_repo(tmp_path / "repo")
    (repo / "gone.py").write_text("g = 1\n", encoding="utf-8")
    (repo / "same.py").write_text("s = 1\n", encoding="utf-8")
    (repo / ".aegis" / "state").mkdir()
    (repo / ".aegis" / "state" / "x.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "add", "-f", ".")
    _git(repo, "commit", "-q", "-m", "more")
    (repo / "gone.py").unlink()
    _stat_dirty(repo / "same.py")
    (repo / ".aegis" / "state" / "x.json").write_text('{"a": 1}\n', encoding="utf-8")

    assert dirty_paths(repo) == []


def test_add_insight_confines_explicit_paths_to_the_workspace(tmp_path: Path):
    home = tmp_path / "home"
    repo = _make_repo(tmp_path / "repo")
    with pytest.raises(PathTraversalError):
        add_insight(repo, "Never touch passwd", paths=["../../etc/passwd"], home=home)
    with pytest.raises(PathTraversalError):
        add_insight(repo, "Never touch passwd", paths=["src/ok.py", str(tmp_path / "outside.py")], home=home)
    assert read_insight_rows(repo, home=home) == []

    row = add_insight(repo, "Keep commas", paths=["src/a,b.py", str(repo.resolve() / "app.py"), " "], home=home)
    assert row["paths"] == ["app.py", "src/a,b.py"]


def test_add_insight_refuses_a_symlink_that_escapes(tmp_path: Path):
    home = tmp_path / "home"
    repo = _make_repo(tmp_path / "repo")
    (tmp_path / "secret.py").write_text("s = 1\n", encoding="utf-8")
    try:
        (repo / "link.py").symlink_to(tmp_path / "secret.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(PathTraversalError):
        capture_suggestion(repo, "Do not follow links", paths=["link.py"], home=home)
    assert read_insight_rows(repo, home=home) == []


def test_add_insight_level_h_requires_explicit_commit_and_matching_insight_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from aegis_core import human_gate
    from tests import helpers_humangate as hg

    if not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    human_key, human_pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, human_pub)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "updated"))
    repo.commit("update rule")
    gov_hash = human_gate.governance_tree_hash(repo.root, "HEAD")
    gov_sha = repo.commit(
        f"chore: approve gov\n\nAegis-Approve: {gov_hash}\n",
        sign_key=human_key,
        allow_empty=True,
    )

    text_a = "Never call subprocess.run without an explicit timeout parameter"
    text_b = "Never deserialize untrusted pickle payloads from network sockets"

    # 1. Governance approval on branch does NOT grant level="H" (neither commit=None nor commit=gov_sha)
    ins_gov_none = add_insight(repo.root, text_a, paths=["src/app.py"], commit=None, base_ref="main", home=home)
    ins_gov_sha = add_insight(repo.root, text_a, paths=["src/app.py"], commit=gov_sha, base_ref="main", home=home)
    assert ins_gov_none["level"] == "cli"
    assert ins_gov_sha["level"] == "cli"

    # 2. Signed commit with Aegis-Approve-Insight: <insight_text_hash(text_a)> grants level="H" ONLY for text_a with commit=sha
    ins_sha = repo.commit(
        f"chore: approve insight\n\n{human_gate.INSIGHT_APPROVE_TRAILER}: {human_gate.insight_text_hash(text_a)}\n",
        sign_key=human_key,
        allow_empty=True,
    )
    ins_ok = add_insight(repo.root, text_a, paths=["src/app.py"], commit=ins_sha, base_ref="main", home=home)
    ins_wrong_text = add_insight(repo.root, text_b, paths=["src/app.py"], commit=ins_sha, base_ref="main", home=home)
    ins_no_commit = add_insight(repo.root, text_a, paths=["src/app.py"], commit=None, base_ref="main", home=home)
    assert ins_ok["level"] == "H"
    assert ins_wrong_text["level"] == "cli"
    assert ins_no_commit["level"] == "cli"


def _ours(command: str = "python3 -I -m aegis_cli.hooks.insights --host claude-code") -> dict:
    return {"matcher": "", "hooks": [{"type": "command", "command": command}]}


def test_merge_insight_hook_replaces_ours_and_keeps_foreign_entries():
    foreign = {"matcher": "", "hooks": [{"type": "command", "command": "echo mine"}]}
    shared = {"matcher": "", "hooks": [{"type": "command", "command": "echo shared"},
                                       {"type": "command", "command": "/py", "args": ["-c", "aegis_cli.hooks.insights"]}]}
    data = {"model": "x", "hooks": {"UserPromptSubmit": [_ours(), foreign, shared]}}
    handler = {"type": "command", "command": "/py", "args": ["-I", "-c", "from aegis_cli.hooks.insights import main"]}
    core_insights.merge_insight_hook(data, handler)
    assert data == {"model": "x", "hooks": {"UserPromptSubmit": [
        foreign, {"matcher": "", "hooks": [{"type": "command", "command": "echo shared"}]},
        {"matcher": "", "hooks": [handler]}]}}
    assert core_insights.INSIGHT_HOOK_MARKER == "aegis_cli.hooks.insights"


@pytest.mark.parametrize("data, where", [
    ({"hooks": ["x"]}, "hooks"),
    ({"hooks": {"UserPromptSubmit": {}}}, "UserPromptSubmit"),
])
def test_merge_insight_hook_refuses_a_wrong_shape(data, where):
    with pytest.raises(ValueError, match=where):
        core_insights.merge_insight_hook(data, {"type": "command", "command": "/py"})


def test_remove_insight_hook_counts_ours_and_drops_emptied_containers():
    data = {"hooks": {"UserPromptSubmit": [_ours(), _ours("/py -c 'from aegis_cli.hooks.insights import main'")],
                      "Stop": []}}
    assert core_insights.remove_insight_hook("claude-code", data) == 2
    assert data == {"hooks": {"Stop": []}}
    data = {"hooks": {"UserPromptSubmit": [_ours()]}}
    assert core_insights.remove_insight_hook("codex-cli", data) == 1 and data == {}


@pytest.mark.parametrize("data", [
    {}, {"hooks": ["x"]}, {"hooks": {"UserPromptSubmit": {}}}, {"hooks": {"UserPromptSubmit": ["x", {"hooks": 3}]}},
])
def test_remove_insight_hook_never_raises_on_odd_shapes(data):
    before = repr(data)
    assert core_insights.remove_insight_hook("claude-code", data) == 0
    assert repr(data) == before


def test_host_capture_status_ignores_a_relative_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(
        '{"hooks": {"UserPromptSubmit": [{"hooks": [{"command": "/py", "args": ["-c", "aegis_cli.hooks.insights", "--excerpts"]}]}]}}',
        encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "relative/dir")
    assert host_capture_status("claude-code", home=home) == {"status": "enabled_excerpts", "excerpts": True}


# ── One workspace, one insights file, whatever the hook's cwd (R-evidence-39) ──

@pytest.fixture
def hook_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    return home


def _insight_texts(workspace: Path, home: Path) -> list:
    return sorted(r["text"] for r in read_insight_rows(workspace, home=home) if r.get("event") == "insight")


def test_a_hook_in_a_subdirectory_writes_the_governed_roots_file(tmp_path: Path, hook_home: Path):
    repo = _make_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    record_hook_prompt("claude-code", {"prompt": "No, stop breaking the parser", "session_id": "s1",
                                       "cwd": str(repo / "src")}, home=hook_home)
    record_hook_prompt("claude-code", {"prompt": "Don't touch the lockfile again", "session_id": "s2",
                                       "cwd": str(repo)}, home=hook_home)
    assert insights_path(repo / "src", home=hook_home) == insights_path(repo, home=hook_home)
    assert _insight_texts(repo, hook_home) == ["Don't touch the lockfile again", "No, stop breaking the parser"]
    assert len(list((hook_home / ".aegis" / "insights").glob("*.jsonl"))) == 1


def test_an_ungoverned_repository_under_home_keeps_the_cwds_own_id(hook_home: Path):
    # A walk-up that went past the git top would reach ~/.aegis, the user plane every user has.
    proj = hook_home / "proj"
    proj.mkdir()
    subprocess.run(["git", "init", "-q", str(proj)], check=True)
    (proj / "sub").mkdir()
    record_hook_prompt("claude-code", {"prompt": "No, wrong file", "cwd": str(proj / "sub")}, home=hook_home)
    assert insight_workspace_id(proj / "sub") != insight_workspace_id(hook_home)
    assert _insight_texts(proj / "sub", hook_home) == ["No, wrong file"]


def test_claude_project_dir_wins_over_the_payload_cwd(tmp_path: Path, hook_home: Path, monkeypatch):
    repo, other = _make_repo(tmp_path / "repo"), _make_repo(tmp_path / "other")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(repo))
    record_hook_prompt("claude-code", {"prompt": "No, revert that", "cwd": str(other)}, home=hook_home)
    assert _insight_texts(repo, hook_home) == ["No, revert that"]
    assert _insight_texts(other, hook_home) == []


def test_a_relative_claude_project_dir_is_ignored(tmp_path: Path, hook_home: Path, monkeypatch):
    repo = _make_repo(tmp_path / "repo")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "repo")
    record_hook_prompt("claude-code", {"prompt": "No, revert that", "cwd": str(repo)}, home=hook_home)
    assert _insight_texts(repo, hook_home) == ["No, revert that"]


def test_a_cwd_that_does_not_exist_falls_back_to_itself(tmp_path: Path, hook_home: Path):
    missing = _make_repo(tmp_path / "repo") / "gone"
    record_hook_prompt("claude-code", {"prompt": "No, wrong file", "cwd": str(missing)}, home=hook_home)
    assert _insight_texts(missing, hook_home) == ["No, wrong file"]


# ── a heartbeat per identified prompt, revisions through inventory rows (R-evidence-40) ──

_RULE_MD = (
    "---\nid: {rid}\ntype: trap\nenforcement: advisory\nhypothesis: Popen hangs.\n"
    "target_paths:\n  - '*.py'\n---\n# {rid}\n\nNever call subprocess.Popen without a timeout.{extra}\n"
)


def _put_rule(repo: Path, rid: str, extra: str = "") -> None:
    (repo / ".aegis" / "rules" / "traps" / f"{rid}.md").write_text(_RULE_MD.format(rid=rid, extra=extra), encoding="utf-8")


def _prompt(repo: Path, home: Path, text: str = "Please run the tests.", session: str = "s-hb", **kw):
    return record_hook_prompt("claude-code", {"prompt": text, "session_id": session, "cwd": str(repo)}, home=home, **kw)


def _events(repo: Path, home: Path, event: str):
    return [r for r in read_insight_rows(repo, home=home) if r.get("event") == event]


@pytest.fixture
def hb_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_a_session_counts_alive_for_a_rule_created_between_its_prompts(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _prompt(repo, hb_home)
    _put_rule(repo, "trap-mid")
    _prompt(repo, hb_home)
    rec = measure_recurrence(repo, "trap-mid", home=hb_home)
    assert (rec["sessions"], rec["status"]) == (1, "ok")


def test_counters_only_cue_prompts_store_a_text_free_heartbeat_each(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    for _ in range(2):
        _prompt(repo, hb_home, "No, stop breaking the build!", excerpts=False)
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["heartbeat", "heartbeat"]
    assert all(r["cue"] is True and "text" not in r for r in rows)


def test_an_unchanged_rule_set_writes_one_inventory_row(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-inv")
    for _ in range(500):
        _prompt(repo, hb_home)
    (inv,) = _events(repo, hb_home, "inventory")
    beats = _events(repo, hb_home, "heartbeat")
    assert len(beats) == 500
    assert all(b["inv"] == inv["inv"] and "revs" not in b for b in beats)
    assert set(inv["revs"]) == {"trap-inv"}
    lines = insights_path(repo, home=hb_home).read_bytes().splitlines()
    assert max(len(line) for line in lines if b'"heartbeat"' in line) <= 200

    _put_rule(repo, "trap-inv", extra=" Revised.")
    _prompt(repo, hb_home)
    assert len(_events(repo, hb_home, "inventory")) == 2


def test_a_heartbeat_whose_inv_has_no_inventory_row_is_not_alive(tmp_path: Path, hb_home: Path):
    from aegis_core.rules import load_rules
    from aegis_core.storage import append_jsonl

    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-orphan")
    rev = load_rules(repo).get("trap-orphan").digest[:16]
    base = {"v": 1, "ts": "2026-10-20T00:00:00Z", "event": "heartbeat", "host": "claude-code"}
    path = insights_path(repo, home=hb_home)
    path.parent.mkdir(parents=True)
    append_jsonl(path, [dict(base, hs="a" * 32, cue=False, inv="0" * 16)])
    assert measure_recurrence(repo, "trap-orphan", home=hb_home)["sessions"] == 0
    append_jsonl(path, [dict(base, hs="b" * 32, revs={"trap-orphan": rev})])
    assert measure_recurrence(repo, "trap-orphan", home=hb_home)["sessions"] == 1


def test_a_workspace_without_rule_files_writes_heartbeats_without_inv(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _prompt(repo, hb_home)
    _prompt(repo, hb_home)
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["heartbeat", "heartbeat"]
    assert all("inv" not in r and "revs" not in r for r in rows)


# ── no session identity, no heartbeat (R-structure-a2) ────────────────────────

def _hook_entry(repo: Path, home: Path, stdin: str):
    import contextlib
    import io

    from aegis_cli.hooks.insights import run_insight_hook

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=stdin, home=home)
    return rc, out.getvalue(), err.getvalue()


def test_a_prompt_without_a_session_writes_nothing(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-nosess")
    for stdin in ("", '{"prompt": "Please run the tests."}', '{"prompt": "Run the linter.", "session_id": "  "}'):
        assert _hook_entry(repo, hb_home, stdin) == (0, "", "")
    assert not (hb_home / ".aegis" / "insights").exists()
    assert read_insight_rows(repo, home=hb_home) == []


def test_a_cue_prompt_without_a_session_writes_only_its_insight(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-nosess")
    record_hook_prompt("claude-code", {"prompt": "No, stop breaking the build!", "cwd": str(repo)}, home=hb_home)
    (row,) = read_insight_rows(repo, home=hb_home)
    assert row["event"] == "insight" and "hs" not in row and set(row["revs"]) == {"trap-nosess"}
    _prompt(repo, hb_home)
    _prompt(repo, hb_home)
    assert len(_events(repo, hb_home, "heartbeat")) == 2


def test_a_corrupt_log_and_no_session_still_exit_zero_silently(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    store = insights_path(repo, home=hb_home)
    store.parent.mkdir(parents=True)
    store.write_bytes(b"\xff{garbage\n")
    assert _hook_entry(repo, hb_home, json.dumps({"prompt": "No, wrong file again", "cwd": str(repo)})) == (0, "", "")
    assert [r["event"] for r in read_insight_rows(repo, home=hb_home)] == ["insight"]


# ── R-evidence-35: the verbatim lint protects human text only, with a 25-character floor ──

@pytest.fixture
def lint_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return _make_repo(tmp_path / "repo"), home


def _propose(repo: Path, home: Path, bullet: str, pid: str = "trap-lint") -> Path:
    member = add_insight(repo, "Keep this member text apart from every bullet", paths=["app.py"], kind="correctness",
                         home=home)
    return write_proposal(repo, proposal_id=pid, insight_ids=[member["id"]], summary_bullets=[bullet], home=home)


def _hook_prompt(repo: Path, home: Path, text: str, session: str = "s-lint") -> dict:
    row = record_hook_prompt("claude-code", {"prompt": text, "session_id": session, "cwd": str(repo)},
                             workspace=repo, home=home)
    assert row.get("event") == "insight", text
    return row


def test_agent_suggestions_never_block_a_proposal(lint_repo):
    repo, home = lint_repo
    capture_suggestion(repo, "e", paths=["app.py"], host="claude-code", session="agent", home=home)
    capture_suggestion(repo, "Address recurring correction cluster", paths=["app.py"], host="claude-code",
                       session="agent", home=home)
    assert _propose(repo, home, "Address recurring correction cluster cluster-ab12cd.").is_file()


def test_a_short_hook_prompt_blocks_only_an_identical_bullet(lint_repo):
    repo, home = lint_repo
    _hook_prompt(repo, home, "revert")
    assert _propose(repo, home, "Always revert partial writes when the update fails.").is_file()
    with pytest.raises(ValueError, match="verbatim H/cli/W2 prompt text"):
        _propose(repo, home, "Revert", pid="trap-lint-2")


def test_a_4_3_upgraded_w2_capture_does_not_protect_its_text(lint_repo):
    repo, home = lint_repo
    from aegis_core.storage import append_jsonl

    append_jsonl(insights_path(repo, home=home), [{
        "v": 1, "ts": "2026-10-20T00:00:00Z", "event": "insight", "id": "ins-0000000000dd", "level": "W2",
        "text": "revert partial writes when the update fails", "paths": ["app.py"], "psrc": "explicit",
        "host": "claude-code", "hs": "a" * 32, "confirmed_by": "ins-000000000001"}])
    assert _propose(repo, home, "Always revert partial writes when the update fails.").is_file()


@pytest.mark.parametrize("bullet", [
    "No, never call shutil.rmtree on unvalidated user paths in src/app.py!",
    "Remember: no, never call shutil.rmtree on unvalidated user paths in src/app.py! Validate first.",
    "never call rmtree",
], ids=["full", "embedded", "short-exact"])
def test_hook_prompts_still_block_verbatim_bullets(lint_repo, bullet):
    repo, home = lint_repo
    _hook_prompt(repo, home, "No, never call shutil.rmtree on unvalidated user paths in src/app.py!")
    _hook_prompt(repo, home, "never call rmtree", session="s-lint-2")
    with pytest.raises(ValueError, match="verbatim"):
        _propose(repo, home, bullet)


def test_cli_text_of_25_characters_or_more_is_protected(lint_repo):
    repo, home = lint_repo
    text = "Validate symlink confinement before opening state files"
    add_insight(repo, text, paths=["app.py"], home=home)
    with pytest.raises(ValueError, match="verbatim H/cli/W2 prompt text"):
        _propose(repo, home, f"Rule: {text}.")
    assert not (repo / ".aegis" / "proposals" / "trap-lint.md").exists()


# ── R-evidence-45: one hook calling convention, a reachable surface, Rule.applies_to ──

def test_the_old_argument_order_of_record_hook_prompt_is_a_type_error(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    payload = {"prompt": "No, stop breaking the build!", "session_id": "s-old", "cwd": str(repo)}
    with pytest.raises(TypeError):
        record_hook_prompt(repo, "claude-code", payload, home=hb_home)
    with pytest.raises(TypeError):
        record_hook_prompt("claude-code", payload, session="s-typed", home=hb_home)
    assert read_insight_rows(repo, home=hb_home) == []


def test_a_hook_whose_recorder_raises_exits_zero_with_the_error_on_stderr(tmp_path: Path, hb_home: Path,
                                                                           monkeypatch: pytest.MonkeyPatch):
    from aegis_cli.hooks import insights as hook

    repo = _make_repo(tmp_path / "repo")

    def broken(*args, **kwargs):
        raise TypeError("recorder broke")

    monkeypatch.setattr(hook, "record_hook_prompt", broken)
    payload = json.dumps({"prompt": "No, stop breaking the build!", "session_id": "s-err", "cwd": str(repo)})
    rc, out, err = _hook_entry(repo, hb_home, payload)
    assert (rc, out) == (0, "") and "aegis insight hook error: recorder broke" in err
    assert read_insight_rows(repo, home=hb_home) == []


def test_hook_stdin_that_is_not_a_json_object_records_no_insight(tmp_path: Path, hb_home: Path,
                                                                   monkeypatch: pytest.MonkeyPatch):
    repo = _make_repo(tmp_path / "repo")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(repo)
    for stdin in ("stop doing that", '["No, stop doing that"]', '"No, stop doing that"'):
        assert _hook_entry(repo, hb_home, stdin) == (0, "", "")
    assert read_insight_rows(repo, home=hb_home) == []


def test_a_payload_without_the_prompt_key_stores_a_heartbeat_only(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    for alias in ("user_prompt", "text", "message", "input"):
        payload = {alias: "No, stop breaking the build!", "session_id": f"s-{alias}", "cwd": str(repo)}
        assert _hook_entry(repo, hb_home, json.dumps(payload)) == (0, "", "")
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["heartbeat"] * 4
    assert all(r["cue"] is False and "text" not in r for r in rows)


def test_the_hook_takes_its_session_and_workspace_from_the_canonical_keys_only(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    payload = {"prompt": "No, stop breaking the build!", "sessionId": "s-alias", "workspace": str(repo),
               "cwd": str(repo)}
    assert _hook_entry(repo, hb_home, json.dumps(payload)) == (0, "", "")
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["insight"] and "hs" not in rows[0]


def _defined_names_referenced_outside(module_file: Path, roots, skip) -> set:
    """Every Name and Attribute identifier used in the Python files under ``roots``, except
    ``module_file`` itself and the nodes in ``skip``."""
    import ast

    seen = set()
    for root in roots:
        for path in root.rglob("*.py"):
            if path.resolve() == module_file.resolve():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            skipped = {id(n) for top in ast.walk(tree) if isinstance(top, ast.FunctionDef) and top.name in skip
                       for n in ast.walk(top)}
            for node in ast.walk(tree):
                if id(node) in skipped:
                    continue
                if isinstance(node, ast.Name):
                    seen.add(node.id)
                elif isinstance(node, ast.Attribute):
                    seen.add(node.attr)
                elif isinstance(node, ast.alias):
                    seen.add(node.name.split(".")[-1])
                elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.isidentifier():
                    seen.add(node.value)  # monkeypatch.setattr(insights, "NAME", ...)
    return seen


def test_every_name_in_insights_all_is_used_outside_the_module():
    repo = Path(__file__).resolve().parents[3]
    roots = [repo / name for name in ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk", "tests")]
    used = _defined_names_referenced_outside(Path(core_insights.__file__), roots,
                                             {"test_every_name_in_insights_all_is_used_outside_the_module"})
    assert sorted(set(core_insights.__all__) - used) == []
    assert all(hasattr(core_insights, name) for name in core_insights.__all__)


def test_dead_insight_names_are_gone():
    for name in ("INSIGHT_LEVELS", "tfidf_cosine", "MAX_EXCERPT_CHARS"):
        assert name not in core_insights.__all__
        assert not hasattr(core_insights, name), name
    assert "hook" not in core_insights.COUNTABLE_LEVELS


_OVERLAP_TEXT = "Stop touching yaml settings in the release scheduler worker"
_YAML_BODY = "Never call yaml.load on configuration files; use yaml.safe_load for parsing settings."


def _overlap_repo(tmp_path: Path, frontmatter: str) -> Path:
    repo = _make_repo(tmp_path / "repo")
    (repo / ".aegis" / "rules" / "traps" / "trap-no-yaml-load.md").write_text(
        f"---\nid: trap-no-yaml-load\ntype: trap\nenforcement: advisory\n{frontmatter}"
        f"hypothesis: Prevent recurring defect in trap-no-yaml-load.\n---\n# trap-no-yaml-load\n\n{_YAML_BODY}\n",
        encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "rule")
    return repo


def _match_of(review: dict, insight_id: str) -> tuple:
    """(matched rule or None, similarity to the closest rule) of one insight in a review."""
    for entry in review["insights"] + review["suppressed"]:
        if entry["id"] == insight_id:
            return entry["match"]["rule"], entry["match"]["similarity"]
    raise AssertionError(f"{insight_id} is not in the review")


def _similarity(repo: Path, home: Path, text: str) -> float:
    """The similarity the review reports for ``text`` against the one rule when it matches."""
    import shutil

    probe = home.parent / "probe-home"
    shutil.rmtree(probe, ignore_errors=True)
    probe.mkdir()
    row = add_insight(repo, text, paths=["src/x.py"], home=probe)
    return _match_of(review_insights(repo, home=probe), row["id"])[1]


def test_a_forbid_ast_rule_does_not_match_an_insight_about_a_test_file(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - '**/*.py'\nforbid_ast:\n  calls: [eval]\n")
    s = _similarity(repo, hb_home, _OVERLAP_TEXT)
    assert 0.15 <= s < 0.30, s  # a shared path is needed for this similarity to match
    src = add_insight(repo, _OVERLAP_TEXT, paths=["src/x.py"], home=hb_home)
    test = add_insight(repo, _OVERLAP_TEXT, paths=["tests/x.py"], home=hb_home)
    review = review_insights(repo, home=hb_home)
    assert _match_of(review, src["id"])[0] == "trap-no-yaml-load"
    assert _match_of(review, test["id"])[0] is None


def test_a_rule_without_target_paths_overlaps_no_insight_path(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "")
    from aegis_core.rules import load_rules

    assert load_rules(repo).get("trap-no-yaml-load").target_paths == ()
    probe = add_insight(repo, _OVERLAP_TEXT, paths=[], home=hb_home)  # no paths: overlaps every rule
    row = add_insight(repo, _OVERLAP_TEXT, paths=["src/x.py"], home=hb_home)
    review = review_insights(repo, home=hb_home)
    assert _match_of(review, probe["id"])[0] == "trap-no-yaml-load"
    assert 0.15 <= _match_of(review, probe["id"])[1] < 0.30
    assert _match_of(review, row["id"])[0] is None


def test_a_rule_scoped_to_src_does_not_overlap_an_insight_about_tests(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    s = _similarity(repo, hb_home, _OVERLAP_TEXT)
    assert 0.15 <= s < 0.30, s
    row = add_insight(repo, _OVERLAP_TEXT, paths=["tests/x.py"], home=hb_home)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None


def test_an_insight_without_paths_overlaps_every_rule(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    row = add_insight(repo, _OVERLAP_TEXT, home=hb_home)  # a clean tree: no dirty paths
    assert row["paths"] == []
    match = _match_of(review_insights(repo, home=hb_home), row["id"])
    assert match[0] == "trap-no-yaml-load" and 0.15 <= match[1] < 0.30


# ── X-w8-carry j: the private directories get their mode through a descriptor ──

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks and mode bits")


@posix_only
def test_a_link_swapped_in_after_the_check_is_never_chmodded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Given ~/.aegis checked as a directory, When a link to another directory replaces it before
    its mode is set, Then the link's target keeps its mode."""
    home = tmp_path / "home"
    aegis = home / ".aegis"
    aegis.mkdir(parents=True, mode=0o755)
    victim = tmp_path / "victim"
    victim.mkdir()
    os.chmod(victim, 0o755)
    real_lstat, swapped = os.lstat, []

    def lstat_then_swap(path, *args, **kwargs):
        found = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == str(aegis) and not swapped:
            swapped.append(True)
            os.rename(aegis, tmp_path / "moved")
            os.symlink(victim, aegis)
        return found

    monkeypatch.setattr(os, "lstat", lstat_then_swap)
    try:
        create_link_key(home)
    except PathTraversalError:
        pass
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o755
    assert not (victim / "link.key").exists()


@posix_only
def test_the_private_directories_end_0o700_and_a_linked_one_is_refused(tmp_path: Path):
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True, mode=0o755)
    os.chmod(home / ".aegis", 0o755)
    create_link_key(home)
    assert stat.S_IMODE(os.stat(home / ".aegis").st_mode) == 0o700
    other = tmp_path / "other"
    victim = tmp_path / "victim"
    victim.mkdir()
    os.chmod(victim, 0o755)
    other.mkdir()
    (other / ".aegis").symlink_to(victim)
    with pytest.raises(PathTraversalError):
        create_link_key(other)
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o755 and list(victim.iterdir()) == []


# ── R-evidence-b2: the similarity thresholds are named once (hand-set, not measured) ──

def test_the_similarity_thresholds_are_named_constants():
    from aegis_core.insights import RECURRENCE_SIM, RULE_MATCH_SIM, RULE_MATCH_SIM_WITH_PATH

    assert (RULE_MATCH_SIM_WITH_PATH, RULE_MATCH_SIM, RECURRENCE_SIM) == (0.15, 0.30, 0.12)


def test_rule_matching_flips_at_the_shared_path_threshold(tmp_path: Path, hb_home: Path,
                                                           monkeypatch: pytest.MonkeyPatch):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    row = add_insight(repo, _OVERLAP_TEXT, paths=["src/x.py"], home=hb_home)
    rule, s = _match_of(review_insights(repo, home=hb_home), row["id"])
    assert rule == "trap-no-yaml-load" and 0 < s < core_insights.RULE_MATCH_SIM
    monkeypatch.setattr(core_insights, "RULE_MATCH_SIM_WITH_PATH", s + 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None
    monkeypatch.setattr(core_insights, "RULE_MATCH_SIM_WITH_PATH", s - 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] == "trap-no-yaml-load"


def test_rule_matching_flips_at_the_no_shared_path_threshold(tmp_path: Path, hb_home: Path,
                                                              monkeypatch: pytest.MonkeyPatch):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    row = add_insight(repo, _OVERLAP_TEXT, paths=["docs/x.md"], home=hb_home)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None
    monkeypatch.setattr(core_insights, "RULE_MATCH_SIM", 0.0001)
    rule, s = _match_of(review_insights(repo, home=hb_home), row["id"])
    assert rule == "trap-no-yaml-load" and s > 0.0001
    monkeypatch.setattr(core_insights, "RULE_MATCH_SIM", s + 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None
    monkeypatch.setattr(core_insights, "RULE_MATCH_SIM", s - 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] == "trap-no-yaml-load"


def test_recurrence_counts_an_insight_at_the_recurrence_threshold(tmp_path: Path, hb_home: Path,
                                                                   monkeypatch: pytest.MonkeyPatch):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-rec")
    _prompt(repo, hb_home, session="s-rec")
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")  # the hook's paths are the dirty set
    _prompt(repo, hb_home, "No, stop adding a scheduler loop around Popen in app.py", session="s-rec")
    monkeypatch.setattr(core_insights, "RECURRENCE_SIM", 0.0001)
    assert measure_recurrence(repo, "trap-rec", home=hb_home)["recurrences"] == 1
    monkeypatch.setattr(core_insights, "RECURRENCE_SIM", 1.01)
    assert measure_recurrence(repo, "trap-rec", home=hb_home)["recurrences"] == 0


def test_an_insight_without_tokens_matches_nothing_and_raises_nothing(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "")
    row = add_insight(repo, "the and of", paths=[], home=hb_home)
    review = review_insights(repo, home=hb_home)
    assert _match_of(review, row["id"]) == (None, 0.0)
    assert {e["id"]: e["neighbours"] for e in review["insights"]} == {row["id"]: []}
