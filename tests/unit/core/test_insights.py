"""Unit tests for aegis_core.insights edge cases, security boundaries, and clustering."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

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
    tfidf_cosine,
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

    write_proposal(
        repo,
        proposal_id="trap-timeout-required",
        rule_type="trap",
        target_paths=["*.py"],
        category="reliability",
        summary_bullets=["Always pass an explicit timeout parameter to subprocess and network requests."],
        home=home,
    )

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
        cluster_id="cluster-noise",
        decision="noise",
        insight_ids=[ins_noise["id"]],
        home=home,
    )

    rev = review_insights(repo, home=home)
    all_clustered_ids = [iid for c in rev["clusters"] for iid in c["insight_ids"]]
    assert ins_noise["id"] not in all_clustered_ids
    assert ins1["id"] in all_clustered_ids
    prop_clusters = [c for c in rev["clusters"] if c["match_status"] == "matches_proposal"]
    assert len(prop_clusters) == 1
    assert prop_clusters[0]["matched_rule"] == "trap-timeout-required"


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
    assert res["recorded"] is False

    rows = read_insight_rows(repo, home=home)
    assert len(rows) == 1
    assert rows[0]["event"] == "heartbeat"
    assert "text" not in rows[0]


def test_tfidf_cosine_and_dirty_paths(tmp_path: Path):
    repo = _make_repo(tmp_path / "repo")
    assert dirty_paths(repo) == []
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")
    (repo / "new_file.py").write_text("b = 3\n", encoding="utf-8")
    assert dirty_paths(repo) == ["app.py", "new_file.py"]

    sim_same = tfidf_cosine("validate path confinement before deletion", "validate path confinement before deleting")
    sim_diff = tfidf_cosine("validate path confinement before deletion", "configure oauth2 bearer token refresh")
    assert sim_same > sim_diff
    assert sim_same > 0.3


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
