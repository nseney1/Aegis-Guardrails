"""Repository-wide lease observation through the public CLI; no checkout or event writes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import time

import pytest

from aegis_cli.cli import main
from aegis_core import gitsafe, team
from tests.unit.cli.test_cli_team import _git, _json, _run, ws  # noqa: F401


def _snapshot(root: Path):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def _branch(root: Path, name: str, path: str):
    _git(root, "checkout", "-qb", name, "main")
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("lane change\n", encoding="utf-8")
    _git(root, "add", path)
    _git(root, "commit", "-qm", name)
    tip = _git(root, "rev-parse", "HEAD")
    _git(root, "checkout", "-q", "main")
    return tip


def test_status_lists_live_expired_and_unreadable_leases_without_writes(ws, capsys):
    tip = _branch(ws, "lane/docs", "docs/guide.md")
    now = int(time.time())
    team.claim(ws, "docs", ["docs/**"], owner="writer@host", branch="lane/docs", now=now)
    team.claim(ws, "core", ["core/**"], branch="main", now=now)
    team.claim(ws, "old", ["old/**"], branch="gone", now=now - 10, ttl_s=1)
    oid = gitsafe.write_blob(ws, b"not a lease\n")
    gitsafe.update_ref(ws, "refs/aegis/lanes/broken", oid, None)
    before = _snapshot(ws)

    rc, payload, err = _json(capsys, "status", "--base", "main")

    assert (rc, err) == (0, "")
    assert payload["schema"] == "aegis.team.status/v1"
    rows = {row["lane"]: row for row in payload["lanes"]}
    assert {lane: row["state"] for lane, row in rows.items()} == {
        "broken": "unreadable", "core": "live", "docs": "live", "old": "expired"}
    assert (rows["docs"]["owner"], rows["docs"]["tip"], rows["docs"]["ahead"], rows["docs"]["behind"]) == (
        "writer@host", tip, 1, 0)
    assert rows["docs"]["expires_at"] and rows["docs"]["check"] is None
    assert rows["old"]["stale"] is True and rows["old"]["branch_state"] == "missing"
    assert rows["broken"]["error"] == "not a JSON lease"
    assert rows["broken"]["tip"] is None and rows["broken"]["ahead"] is None
    assert payload["scope"]["base_commit"] == _git(ws, "rev-parse", "main")
    assert "not liveness proof" in payload["note"]
    assert _snapshot(ws) == before


def test_status_checks_each_branch_tip_not_head_and_does_not_record(ws, capsys):
    good = _branch(ws, "lane/good", "good/change.txt")
    bad = _branch(ws, "lane/bad", "outside/change.txt")
    team.claim(ws, "good", ["good/**"], branch="lane/good")
    team.claim(ws, "bad", ["bad/**"], branch="lane/bad")
    before = _snapshot(ws)

    rc, payload, err = _json(capsys, "status", "--base", "main", "--check")

    assert (rc, err) == (1, "")
    rows = {row["lane"]: row for row in payload["lanes"]}
    assert rows["good"]["check"]["status"] == "pass"
    assert rows["bad"]["check"]["status"] == "fail"
    assert rows["good"]["check"]["scope"]["head"] == good
    assert rows["bad"]["check"]["scope"]["head"] == bad
    assert rows["bad"]["check"]["containment"]["violations"] == ["outside/change.txt"]
    assert rows["good"]["check"]["schema"] == "aegis.check.lane/v1"
    assert rows["good"]["check"]["provenance"]["paths"] == "lease@" + rows["good"]["oid"]
    assert rows["good"]["check"]["containment"]["paths"][0]["source"] == "lease@" + rows["good"]["oid"]
    assert _snapshot(ws) == before


def test_status_tip_checks_ignore_dirty_worktree_shared_policy(ws, capsys):
    _branch(ws, "lane/docs", "outside/change.txt")
    team.claim(ws, "docs", ["docs/**"], branch="lane/docs")
    (ws / ".aegis" / "team.json").write_text('{"v":1,"shared":["outside/**"]}', encoding="utf-8")
    before = _snapshot(ws)

    rc, payload, _ = _json(capsys, "status", "--check")

    assert rc == 1
    verdict = payload["lanes"][0]["check"]
    assert verdict["containment"]["violations"] == ["outside/change.txt"]
    assert verdict["label"] == "self-attested"
    assert verdict["provenance"]["shared"] == "tip@" + verdict["scope"]["head"]
    assert _snapshot(ws) == before


@pytest.mark.parametrize("branch", [None, "gone", "main~1", "HEAD", "main^{commit}"])
def test_missing_or_nonbranch_labels_never_check_head(ws, capsys, branch):
    team.claim(ws, "docs", ["docs/**"], branch=branch)
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 1
    row = payload["lanes"][0]
    assert row["tip"] is None and row["ahead"] is None and row["behind"] is None
    assert row["check"]["status"] == "error"
    assert row["branch_state"] == ("unrecorded" if branch is None else "missing")


def test_status_reports_ahead_and_behind_and_explicit_base(ws, capsys):
    _branch(ws, "lane/docs", "docs/guide.md")
    team.claim(ws, "docs", ["docs/**"], branch="refs/heads/lane/docs")
    (ws / "a.txt").write_text("base changed\n", encoding="utf-8")
    _git(ws, "commit", "-qam", "advance main")
    rc, payload, _ = _json(capsys, "status", "--base", "main")
    assert rc == 0
    row = payload["lanes"][0]
    assert (row["ahead"], row["behind"]) == (1, 1)


def test_status_reports_concurrent_overlap_and_unknown_conflicts(ws, capsys):
    first = team.claim(ws, "a", ["src/**"], branch="main")
    raw = json.loads(gitsafe.read_object(ws, first.oid, team.MAX_LEASE_BYTES))
    raw["lane"] = "b"
    oid = gitsafe.write_blob(ws, json.dumps(raw).encode())
    gitsafe.update_ref(ws, "refs/aegis/lanes/b", oid, None)
    bad = gitsafe.write_blob(ws, b"{}")
    gitsafe.update_ref(ws, "refs/aegis/lanes/unknown", bad, None)
    rc, payload, _ = _json(capsys, "status")
    assert rc == 0
    rows = {row["lane"]: row for row in payload["lanes"]}
    assert rows["a"]["overlaps"] == ["b"] and rows["b"]["overlaps"] == ["a"]
    assert rows["a"]["unknown_overlaps"] == ["unknown"]


def test_status_unknown_or_expired_evidence_is_not_a_passing_check(ws, capsys):
    team.claim(ws, "old", ["old/**"], branch="main", now=int(time.time()) - 10, ttl_s=1)
    oid = gitsafe.write_blob(ws, b"{}")
    gitsafe.update_ref(ws, "refs/aegis/lanes/bad", oid, None)
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 1
    assert [row["check"]["status"] for row in payload["lanes"]] == ["error", "error"]


@pytest.mark.parametrize("raw,reason", [(b'{"v":2}', "its keys are not the v1 lease keys"),
                                       (b"x" * (team.MAX_LEASE_BYTES + 1), "cap")])
def test_malformed_and_oversized_leases_remain_visible(ws, capsys, raw, reason):
    oid = gitsafe.write_blob(ws, raw)
    gitsafe.update_ref(ws, "refs/aegis/lanes/bad", oid, None)
    rc, payload, _ = _json(capsys, "status")
    assert rc == 0
    row, = payload["lanes"]
    assert row["state"] == "unreadable" and reason in row["error"]
    assert row["oid"] == oid and row["stale"] is None


def test_status_shallow_history_is_unknown_and_cannot_pass(ws, capsys):
    tip = _branch(ws, "lane/docs", "docs/guide.md")
    team.claim(ws, "docs", ["docs/**"], branch="lane/docs")
    (ws / ".git" / "shallow").write_text(tip + "\n", encoding="ascii")
    rc, payload, _ = _json(capsys, "status")
    assert rc == 0
    row, = payload["lanes"]
    assert row["ahead"] is None and row["behind"] is None and "shallow" in row["error"]
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 1 and payload["lanes"][0]["check"]["status"] == "error"


def test_status_without_a_default_base_keeps_observation_available(ws, capsys):
    _git(ws, "branch", "-m", "custom")
    team.claim(ws, "docs", ["docs/**"], branch="custom")
    rc, payload, _ = _json(capsys, "status")
    assert rc == 0 and payload["scope"]["base_commit"] is None
    row, = payload["lanes"]
    assert row["tip"] is not None and row["ahead"] is None
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 1 and payload["lanes"][0]["check"]["status"] == "error"


def test_status_from_linked_worktree_observes_the_repository(ws, capsys, tmp_path, monkeypatch):
    tip = _branch(ws, "lane/docs", "docs/guide.md")
    team.claim(ws, "docs", ["docs/**"], branch="lane/docs")
    linked = tmp_path / "linked"
    _git(ws, "worktree", "add", "-q", str(linked), "lane/docs")
    (linked / ".aegis").mkdir(exist_ok=True)
    monkeypatch.chdir(linked)
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 0
    assert payload["lanes"][0]["tip"] == tip


def test_status_tip_check_ignores_replacement_objects(ws, capsys):
    tip = _branch(ws, "lane/docs", "outside/change.txt")
    team.claim(ws, "docs", ["docs/**"], branch="lane/docs")
    _git(ws, "replace", tip, "main")
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 1
    row, = payload["lanes"]
    assert row["ahead"] == 1 and row["check"]["containment"]["violations"] == ["outside/change.txt"]


def test_status_handles_git_timeout_as_unavailable_evidence(ws, capsys, monkeypatch):
    import subprocess

    team.claim(ws, "docs", ["docs/**"], branch="main")
    original = subprocess.run

    def timed_out(argv, *args, **kwargs):
        if "rev-list" in argv:
            raise subprocess.TimeoutExpired(argv, 0.1)
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", timed_out)
    rc, payload, _ = _json(capsys, "status", "--check")
    assert rc == 1
    row, = payload["lanes"]
    assert row["check"]["status"] == "error"
    assert row["error"] == "git rev-list timed out after 10s"


def test_status_invalid_base_is_a_usage_error_with_schema(ws, capsys):
    rc, payload, _ = _json(capsys, "status", "--base", "missing")
    assert rc == 2
    assert payload["schema"] == "aegis.team.status/v1"
    assert payload["error"] == "cannot resolve --base 'missing' to a commit"


@pytest.mark.skipif(os.name == "nt", reason="POSIX local transport canary")
def test_status_never_runs_a_repository_allowed_lazy_fetch(ws, capsys, tmp_path):
    lease = team.claim(ws, "docs", ["docs/**"], branch="main")
    marker = tmp_path / "transport-ran"
    command = tmp_path / "fetch-canary"
    command.write_text("#!/bin/sh\nprintf fetched > " + shlex.quote(str(marker)) + "\nexit 1\n")
    command.chmod(0o755)
    settings = {"core.repositoryformatversion": "1", "extensions.partialClone": "origin",
                "remote.origin.promisor": "true", "protocol.ext.allow": "always",
                "remote.origin.url": "ext::" + str(command).replace(" ", "% ")}
    for key, value in settings.items():
        _git(ws, "config", key, value)
    (ws / ".git" / "objects" / lease.oid[:2] / lease.oid[2:]).unlink()

    rc, payload, _ = _json(capsys, "status")

    assert not marker.exists(), "status executed the repository's fetch transport"
    assert rc == 0 and payload["lanes"][0]["state"] == "unreadable"


def test_status_text_and_empty_repository(ws, capsys):
    rc, out, err = _run(capsys, "status")
    assert (rc, err) == (0, "")
    assert "No lane leases" in out and "not liveness proof" in out
    team.claim(ws, "docs", ["docs/**"], branch="main", owner="writer@host")
    rc, out, err = _run(capsys, "status", "--check")
    assert (rc, err) == (0, "")
    assert "writer@host" in out and "ahead 0" in out and "behind 0" in out and "check pass" in out


def test_schema_ids_are_additive_on_existing_team_actions_and_errors(ws, capsys):
    rc, claim, _ = _json(capsys, "claim", "docs", "--paths", "docs/**")
    assert rc == 0 and claim["schema"] == "aegis.team.claim/v1"
    for args, expected in [(("list",), 0), (("metrics",), 0),
                           (("claim", "docs", "--paths", "docs/**"), 1),
                           (("renew", "docs", "--expect", "bad"), 2)]:
        rc, payload, _ = _json(capsys, *args)
        assert rc == expected
        assert payload["schema"] == "aegis.team." + args[0] + "/v1"
        assert payload["source"] == "aegis team " + args[0]
    assert json.loads(gitsafe.read_object(ws, claim["oid"], team.MAX_LEASE_BYTES))["v"] == 1


@pytest.mark.parametrize("arguments,schema,code", [
    (["--lane", "docs", "--base", "main", "--paths", "docs/**"], "aegis.check.lane/v1", 0),
    (["--lane", "docs", "--base", "missing", "--paths", "docs/**"], "aegis.check.lane/v1", 1),
    (["--partition", "--split", "A=a/**", "--split", "B=b/**"], "aegis.check.partition/v1", 0),
    (["--partition"], "aegis.check.partition/v1", 2),
])
def test_existing_check_json_has_distinct_schema_ids(ws, capsys, arguments, schema, code):
    rc = main(["check", *arguments, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == code
    assert payload["schema"] == schema
